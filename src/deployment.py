"""What the appliance says this service should be running, and the engine built from it.

The deployment used to be two halves from two places: config.json for the guardrail and the turn
shape, and an ApplyConfig push for the vendors. The file is gone. All of it is pushed now, and this
module's job shrank to one sentence — lay the pushed document over the built-in defaults, build an
engine from the result, and swap it in only if it built.

Why the file went. Its half was defended on the grounds that an appliance changing which models it
serves must not be able to change whether the turns are inspected, and that is a real concern. What
it cost was that the guardrail — the AIRS profile, the key, which checkpoints run — could only be
changed by editing a file on the appliance and restarting the service. Operators do not do that;
they open the console. So the boundary moved: the console owns the guardrail, and what protects it
is that every change is a committed, versioned running_config edit rendered in a review diff,
rather than a value this service refused to accept.

The pushed document is cached to disk so a restart does not leave the service mute until the next
push. That cache now holds the vendor keys AND the scan key in the clear, which is why it is
written 0600 into /etc/pretzel-ai — the directory that already holds keys.env, root-only, and not
the repo. The appliance's sealed store is still where they come from; this is a copy with a
lifetime, not a second source of truth.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import tempfile
from typing import Any

from src import config as pa_config
from src.factory import ConfigError, build_engine

log = logging.getLogger("pretzel-ai")

# Beside keys.env rather than beside the code: it holds unsealed keys, and the repo is not where
# those belong. PZ_PRETZEL_AI_STATE overrides it — a developer running the service out of a
# checkout has no /etc/pretzel-ai to write to.
DEFAULT_STATE_PATH = "/etc/pretzel-ai/deployment.json"

# Where each vendor answers. Compiled in rather than configured: all three publish an OpenAI-shaped
# chat-completions endpoint, and which URL that is, is a fact about the vendor. A fourth vendor is a
# change here because it would need this transport to speak its dialect anyway — the appliance
# choosing a URL never bought anything except the chance to get it wrong.
PROVIDER_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/chat/completions",
}

# The engine this service builds today. Agent is configured alongside it and stored, but nothing
# calls an agent turn yet — ToolRuntime is an empty interface and no RPC reaches it — so building a
# second engine would put a configuration nobody can exercise in memory and call it deployed.
# When the agent service lands, its config is already here and this becomes a second build.
ACTIVE_SERVICE = "chat"

# What each service can be asked about at all. Chat has no tools, so two of the four checkpoints
# are not "off" for it — they do not exist, and an operator cannot turn them on.
SERVICE_CHECKPOINTS = {
    "chat": ("prompt", "response"),
    "agent": ("prompt", "response", "tool_call", "tool_result"),
}

# What each guardrail can serve. The gateway builds its scan request from a completion's text
# `content`; `tool_calls` is a sibling of `content` and never reaches the scanner, so the two tool
# checkpoints are not available on that leg however they are configured. src/airs/gateway.py already
# answers NOT_INSPECTED for them — this is the same fact stated where the config is read, so the
# console and the engine agree about what was asked for.
GUARDRAIL_CHECKPOINTS = {
    "none": (),
    "api_application": ("prompt", "response", "tool_call", "tool_result"),
    "ai_gateway": ("prompt", "response"),
}

# The guardrail an operator picks, and what it means to the factory. The LLM leg is not a separate
# choice: there is no gateway on the direct path to defer inspection to, so picking the gateway
# moves the completion onto it as well.
GUARDRAIL_ROUTES = {
    "none":            {"llm": "direct",  "guardrail": "none"},
    "api_application": {"llm": "direct",  "guardrail": "airs"},
    "ai_gateway":      {"llm": "gateway", "guardrail": "gateway"},
}


def state_path() -> str:
    """Where the pushed deployment is cached."""
    return os.environ.get("PZ_PRETZEL_AI_STATE", "").strip() or DEFAULT_STATE_PATH


class Deployment:
    """The current configuration and the engine serving it.

    `engine` is read on every turn and replaced wholesale by `apply`. Replacement is a single
    attribute rebind, so a turn already running keeps the engine it started on and finishes on a
    consistent configuration rather than half of two.
    """

    def __init__(self) -> None:
        self._base = pa_config.defaults()
        self._state_path = state_path()
        self._applied = self._read_state()

        # A configuration that cannot serve is NOT fatal at startup, and this is the one place
        # that has to be true. The appliance delivers the deployment over ApplyConfig, so the
        # service has to be listening to receive it — a fresh install has no vendor keys and no
        # catalog, and a build_engine that raised here would leave the process dead and the only
        # thing that could fix it unable to reach it. So it comes up mute and says so on every
        # turn, which an operator can see, instead of not coming up, which they cannot.
        try:
            merged, credentials = self._resolve()
            self.engine = build_engine(merged, credentials)
        except ConfigError as exc:
            self.engine = None
            log.warning("no working configuration yet (%s) — the assistant will refuse turns "
                        "until the appliance pushes one", exc)

    @property
    def configured(self) -> bool:
        """Whether there is an engine to serve a turn with."""
        return self.engine is not None

    @property
    def version(self) -> int:
        """The running-config version this service last accepted; 0 when it has had no push."""
        return int((self._applied or {}).get("version") or 0)

    def apply(self, document: dict[str, Any]) -> None:
        """Adopt a pushed deployment. Raises if it cannot produce a working engine.

        The engine is built BEFORE anything is kept: a document that cannot serve turns must leave
        the service running the one that could. Only once the new engine exists is it swapped in
        and the document cached.
        """
        merged, credentials = self._resolve(document)
        engine = build_engine(merged, credentials)

        self.engine = engine
        self._applied = document
        self._write_state(document)

    # -- internals ---------------------------------------------------------------------------

    def _resolve(self, applied: dict[str, Any] | None = None):
        """→ (merged config, credentials). The two halves the factory needs."""
        applied = self._applied if applied is None else applied
        config = self._merge(applied)
        return config, pa_config.MultiCredentials(self._keys(applied))

    def _keys(self, applied: dict[str, Any] | None) -> dict[str, str]:
        """Every key this deployment holds, by credential id.

        Pushed wins over the environment. It used to be the other way round, because the
        environment was how a key avoided being written into config.json — a document that no
        longer exists. An env var that outranked the console would mean an operator rotating a key
        in the UI and watching nothing happen.
        """
        keys: dict[str, str] = {}
        for slug in PROVIDER_ENDPOINTS:
            keys[slug] = pa_config.provider_env_key(slug)
        keys["airs"] = pa_config.env_key(pa_config.AIRS_KEY_ENV)
        keys["portkey"] = pa_config.env_key(pa_config.GATEWAY_KEY_ENV)

        applied = applied or {}
        for provider in applied.get("providers") or []:
            if isinstance(provider, dict) and provider.get("api_key"):
                keys[provider["id"]] = provider["api_key"]
        if applied.get("airs_api_key"):
            keys["airs"] = applied["airs_api_key"]
        if applied.get("gateway_api_key"):
            keys["portkey"] = applied["gateway_api_key"]

        return keys

    def _merge(self, applied: dict[str, Any] | None) -> dict[str, Any]:
        """The defaults with the pushed document laid over them."""
        config = copy.deepcopy(self._base)
        if not applied:
            return config

        self._merge_providers(config, applied)
        self._merge_service(config, applied)
        return config

    def _merge_providers(self, config: dict[str, Any], applied: dict[str, Any]) -> None:
        providers = [p for p in (applied.get("providers") or [])
                     if isinstance(p, dict) and p.get("id") in PROVIDER_ENDPOINTS]

        # Only `models` is replaced on the shape block; the system prompt and the caps come from
        # the pushed `shape`, handled separately below.
        #
        # Qualified ids, because the provider half is what selects the endpoint. The vendor itself
        # is sent the bare name — src/llm/catalog.py strips it back off.
        config["gateway"]["models"] = [
            {
                "id": f"{p['id']}/{m['id']}",
                "label": m.get("label") or m["id"],
                **({"token_param": m["token_param"]} if m.get("token_param") else {}),
            }
            for p in providers
            for m in (p.get("models") or [])
            if isinstance(m, dict) and m.get("id")
        ]
        # Whatever the catalog starts with. The appliance does not name a default: which model a
        # conversation opens on is this service's business, and the console picks per conversation.
        models = config["gateway"]["models"]
        config["gateway"]["default_model"] = models[0]["id"] if models else ""

        # The endpoint is ours, not the appliance's. A vendor that needs a different URL needs a
        # transport that speaks its dialect, which is a change here — so letting a console field
        # decide it only ever bought the chance to point "openai" at something that is not OpenAI.
        # The key is resolved in _keys and reaches the transport through `credentials`.
        config["providers"] = {p["id"]: {"url": PROVIDER_ENDPOINTS[p["id"]]} for p in providers}

    def _merge_service(self, config: dict[str, Any], applied: dict[str, Any]) -> None:
        """The pushed entry for the engine this service builds, laid over the defaults.

        An appliance with no entry for it is one that has not been configured yet, not one that
        asked for the defaults — but the defaults are the only honest reading of an absence, and
        they are the safe one: everything inspected, fail-closed.
        """
        entry = next((s for s in (applied.get("services") or [])
                      if isinstance(s, dict) and s.get("service") == ACTIVE_SERVICE), None)
        if not entry:
            # Mute, not open. An appliance nobody has configured yet must not quietly become one
            # that inspects nothing — so the defaults stand, they name a guardrail, and the missing
            # key stops the build. Said in the operator's terms because the message they would
            # otherwise get ("airs: api_key is not configured") names a symptom of the real cause.
            raise ConfigError(
                f"no '{ACTIVE_SERVICE}' service is configured — add one under "
                "Configuration ▸ AI Guardrail")

        kind = str(entry.get("guardrail") or "").strip().lower()
        route = GUARDRAIL_ROUTES.get(kind)
        if route is None:
            raise ConfigError(
                f"service '{ACTIVE_SERVICE}' names guardrail '{kind}', which is not one of "
                f"{', '.join(sorted(GUARDRAIL_ROUTES))}")
        config["route"]["llm"] = route["llm"]
        config["route"]["guardrail"] = route["guardrail"]
        config["route"]["require_guardrail"] = bool(entry.get("gateway_require_verdict", False))

        # A checkpoint is on only where all three agree: the operator asked for it, the service has
        # it at all, and the guardrail can serve it. Intersected here rather than trusted from the
        # console, because the console is not the only thing that can send an ApplyConfig — and a
        # checkpoint the engine cannot honour must not be recorded as one it will.
        available = (set(SERVICE_CHECKPOINTS.get(ACTIVE_SERVICE, ()))
                     & set(GUARDRAIL_CHECKPOINTS.get(kind, ())))
        asked = entry.get("checkpoints") or {}
        config["airs"]["checkpoints"] = {
            name: bool(asked.get(name, True)) and name in available
            for name in ("prompt", "response", "tool_call", "tool_result")
        }
        # Recorded so the log can tell the two apart. A checkpoint chat does not have is not one
        # somebody switched off, and warning about it would be a warning that fires on every
        # correct deployment — which is how a warning stops being read.
        config["airs"]["checkpoints_available"] = sorted(available)

        airs = config["airs"]
        airs["profile_name"] = str(entry.get("airs_profile_name") or "")
        airs["timeout_sec"] = float(entry.get("airs_timeout_sec") or 30)
        airs["fail_open"] = bool(entry.get("airs_fail_open", False))

        shape = config["gateway"]
        shape["system_prompt"] = str(entry.get("system_prompt") or "")
        if entry.get("max_tokens"):
            shape["max_tokens"] = int(entry["max_tokens"])
        # One timeout, taken from the leg that is actually serving the completion.
        timeout = entry.get("gateway_timeout_sec") if route["llm"] == "gateway" else None
        if timeout:
            shape["timeout_sec"] = float(timeout)

    def _read_state(self) -> dict[str, Any] | None:
        try:
            with open(self._state_path) as f:
                document = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("cached deployment at %s is unreadable (%s) — starting from the built-in "
                        "defaults until the appliance pushes one", self._state_path, exc)
            return None
        if not isinstance(document, dict):
            return None
        log.info("restored the deployment pushed at running-config version %s",
                 document.get("version") or "unknown")
        return document

    def _write_state(self, document: dict[str, Any]) -> None:
        """Cache the pushed deployment, 0600, replaced atomically.

        Written through a temporary file in the same directory so a crash mid-write cannot leave a
        half-document behind — the next start would read that as the deployment and serve it.
        """
        directory = os.path.dirname(self._state_path) or "."
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".deployment-", suffix=".json")
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump(document, f, indent=2)
                os.replace(tmp, self._state_path)
            except BaseException:
                # The temp file is ours and nothing else will clean it up.
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        except OSError as exc:
            # Not fatal: the service is already running the new deployment. What is lost is only
            # the ability to come back on it after a restart, and the appliance pushes again then.
            log.warning("could not cache the deployment to %s (%s) — it is live but will not "
                        "survive a restart", self._state_path, exc)
