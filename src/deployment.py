"""What the appliance says this service should be running, and the engine built from it.

Until now the deployment was config.json and nothing else: read once at startup, and to change it
you edited the file and restarted. That is fine for a service somebody runs by hand and wrong for
one that ships inside an appliance — the operator configures the assistant in pretzel's console,
that configuration is committed and versioned there, and it has to arrive here without a restart.

So the document has two halves now, and they come from different places on purpose:

    the base      config.json — the guardrail (route.guardrail, the `airs` block), the benchmark
                  wiring, and the defaults everything falls back to. Local to this service,
                  because it is what this service is, not what an operator chose.
    the applied   pushed over ApplyConfig by mgmtd — which vendors serve turns, their endpoints,
                  their catalogs, how a turn is shaped, and the vendor keys. Owned by the
                  appliance, which holds the running config and the sealed credentials.

`_merge` below is the only place they meet. The applied half overrides the LLM leg and nothing
else: the guardrail is deliberately not pushed, so an appliance changing which models it serves
cannot silently change whether the turns are inspected.

The applied half is cached to disk so a restart of this service does not leave it mute until the
next push. That cache holds the vendor keys in the clear, which is why it is written 0600 and
lives beside config.json — the same file that holds them today. The appliance's sealed store is
still where they come from; this is a copy with a lifetime, not a second source of truth.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import tempfile
from typing import Any

from src.factory import ConfigError, build_engine

log = logging.getLogger("pretzel-ai")

DEFAULT_STATE_NAME = "deployment.json"

# Where each vendor answers. Compiled in rather than configured: all three publish an OpenAI-shaped
# chat-completions endpoint, and which URL that is, is a fact about the vendor. A fourth vendor is a
# change here because it would need this transport to speak its dialect anyway — the appliance
# choosing a URL never bought anything except the chance to get it wrong.
PROVIDER_ENDPOINTS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/chat/completions",
}


def state_path(config_path: str) -> str:
    """Where the pushed deployment is cached. Beside config.json unless told otherwise."""
    override = os.environ.get("PZ_PRETZEL_AI_STATE", "").strip()
    if override:
        return override
    return os.path.join(os.path.dirname(os.path.abspath(config_path)), DEFAULT_STATE_NAME)


class Deployment:
    """The current configuration and the engine serving it.

    `engine` is read on every turn and replaced wholesale by `apply`. Replacement is a single
    attribute rebind, so a turn already running keeps the engine it started on and finishes on a
    consistent configuration rather than half of two.
    """

    def __init__(self, config: dict[str, Any], credentials, config_path: str) -> None:
        self._base = config
        self._credentials = credentials
        self._state_path = state_path(config_path)
        self._applied = self._read_state()

        # A configuration that cannot serve is NOT fatal at startup, and this is the one place
        # that has to be true. The appliance delivers the deployment over ApplyConfig, so the
        # service has to be listening to receive it — a fresh install has no vendor keys and no
        # catalog, and a build_engine that raised here would leave the process dead and the only
        # thing that could fix it unable to reach it. So it comes up mute and says so on every
        # turn, which an operator can see, instead of not coming up, which they cannot.
        try:
            self.engine = build_engine(self._merge(), self._credentials)
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
        merged = self._merge(document)
        engine = build_engine(merged, self._credentials)

        self.engine = engine
        self._applied = document
        self._write_state(document)

    # -- internals ---------------------------------------------------------------------------

    def _merge(self, applied: dict[str, Any] | None = None) -> dict[str, Any]:
        """The base document with the pushed providers laid over its LLM leg."""
        applied = self._applied if applied is None else applied
        config = copy.deepcopy(self._base)
        if not applied:
            return config

        providers = [p for p in (applied.get("providers") or [])
                     if isinstance(p, dict) and p.get("id") in PROVIDER_ENDPOINTS]

        # The appliance's deployment has no gateway in it — vendors, called directly — so the leg is
        # not a choice arriving in the document; it is what the document means.
        route = dict(config.get("route") or {})
        route["llm"] = "direct"
        config["route"] = route

        # `gateway` is where the factory reads the catalog and the turn shape from, on either leg.
        # A wart of the name, not of the arrangement: it has meant "how a completion is shaped"
        # since the direct leg existed, and renaming it is a change to make on its own.
        #
        # Only `models` is replaced. The system prompt, the token cap and the timeout stay whatever
        # config.json says: they are how THIS service shapes a turn, not a statement the appliance
        # makes about the operator's vendor accounts.
        shape = dict(config.get("gateway") or {})
        shape["models"] = [
            {
                # Qualified, because the provider half is what selects the endpoint. The vendor
                # itself is sent the bare name — src/llm/catalog.py strips it back off.
                "id": f"{p['id']}/{m['id']}",
                "label": m.get("label") or m["id"],
                **({"token_param": m["token_param"]} if m.get("token_param") else {}),
            }
            for p in providers
            for m in (p.get("models") or [])
            if isinstance(m, dict) and m.get("id")
        ]
        # Whatever the catalog starts with. The appliance no longer names a default: which model a
        # conversation opens on is this service's business, and the console picks per conversation.
        shape["default_model"] = shape["models"][0]["id"] if shape["models"] else ""
        config["gateway"] = shape

        # The endpoint is ours, not the appliance's. A vendor that needs a different URL needs a
        # transport that speaks its dialect, which is a change here — so letting a console field
        # decide it only ever bought the chance to point "openai" at something that is not OpenAI.
        config["providers"] = {
            p["id"]: {"url": PROVIDER_ENDPOINTS[p["id"]], "api_key": p.get("api_key", "")}
            for p in providers
        }
        return config

    def _read_state(self) -> dict[str, Any] | None:
        try:
            with open(self._state_path) as f:
                document = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("cached deployment at %s is unreadable (%s) — starting from config.json "
                        "until the appliance pushes one", self._state_path, exc)
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
            os.makedirs(directory, exist_ok=True)
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
