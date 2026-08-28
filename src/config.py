"""The appliance config: a single JSON file (config.json at the repo root).

config.json fully owns the gateway — host, port, scheme (tls), path, header names, model list,
system prompt, and the key itself in the `api_key` field. Because it carries a secret it is not in
the repo; config.example.json is the template to copy from.

Key precedence: PZ_PORTKEY_API_KEY in the environment wins (so a deploy can override without
editing the file), otherwise the `api_key` in config.json. Host may be overridden with
PZ_PRETZEL_AI_GATEWAY_HOST for a gateway that is not where config.json points.
"""

import json
import os


class MultiCredentials:
    """One key per credential id, resolved for the process.

    Same `.key(id)` shape as StaticCredentials so nothing downstream cares which it got; the
    difference is that a direct-route appliance holds several keys at once — one per provider —
    while a gateway-route one holds exactly the gateway's.
    """

    def __init__(self, keys):
        self._keys = {k: (v or "") for k, v in (keys or {}).items()}

    def key(self, credential_id=None):
        if credential_id is None:
            # No id asked for: the gateway's, which is the only key a single-route appliance has.
            return next((v for v in self._keys.values() if v), "")
        return self._keys.get(credential_id, "")

    def configured(self):
        """Which ids actually have a key. For the startup log, never the value."""
        return sorted(k for k, v in self._keys.items() if v)


class StaticCredentials:
    """The resolved gateway key, held for the process. Mirrors the old GatewayCredentialService
    interface (`.key(id)`) so GatewayService does not care where the value came from."""

    def __init__(self, key):
        self._key = key or ""

    def key(self, _credential_id=None):
        return self._key


def _providers(config):
    """The `providers` block as {slug: entry}, whichever of the two shapes it arrived in."""
    raw = config.get("providers")
    if isinstance(raw, dict) and isinstance(raw.get("list"), list):
        raw = raw["list"]
    if isinstance(raw, list):
        out = {}
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            slug = str(entry.get("id", "")).strip()
            if slug:
                out[slug] = {k: v for k, v in entry.items() if k != "id"}
        return out
    return raw or {}


def load(config_path):
    """→ (config_document, credentials).

    The whole document, not just the gateway block: `route` decides which transport and which
    guardrail this appliance runs, `airs` holds the scan service, and `providers` the direct
    endpoints. Returning one slice of it was fine when there was one route.

    Secrets are taken OUT of the returned document and handed back through `credentials`, so a
    caller that logs its config — and something always does — cannot log a key with it.
    """
    with open(config_path) as f:
        config = json.load(f)
    if not isinstance(config, dict):
        raise ValueError(f"{config_path}: expected a JSON object at the top level")

    gateway = dict(config.get("gateway") or {})
    keys = {}

    # Environment wins over the file, so a deploy can rotate a key without editing it.
    gateway_key = gateway.pop("api_key", "")
    keys[gateway.get("id", "portkey")] = (
        os.environ.get("PZ_PORTKEY_API_KEY", "").strip() or gateway_key)

    host_override = os.environ.get("PZ_PRETZEL_AI_GATEWAY_HOST", "").strip()
    if host_override:
        gateway["host"] = host_override
    config["gateway"] = gateway

    # The scan service's key stays in its own block rather than in `credentials`: AirsConfig is
    # built from that block whole, and splitting one field out would mean threading it back in.
    airs = dict(config.get("airs") or {})
    if airs or os.environ.get("PANW_AI_SEC_API_KEY"):
        airs["api_key"] = (os.environ.get("PANW_AI_SEC_API_KEY", "").strip()
                           or airs.get("api_key", ""))
        config["airs"] = airs

    # One key per provider, under the provider's own slug, so the direct transport asks for
    # "openai" and gets the OpenAI key.
    #
    # Two shapes are accepted for the same thing. A map keyed by slug is what a hand-written
    # config.json says; a list of {id, url} entries is what the appliance's running-config carries,
    # because a commit merges values into the stored document and a merged map can only ever gain
    # keys — removing a provider would be unexpressible there. Normalised to the map here so
    # nothing downstream has to know which end the config came from.
    providers = {}
    for slug, raw in _providers(config).items():
        entry = dict(raw)
        env_name = f"PZ_{slug.upper().replace('-', '_')}_API_KEY"
        keys[slug] = os.environ.get(env_name, "").strip() or entry.pop("api_key", "")
        providers[slug] = entry
    if providers:
        config["providers"] = providers

    return config, MultiCredentials(keys)
