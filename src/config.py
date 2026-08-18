"""The gateway config: a single JSON file (prisma-airs/config.json).

config.json fully owns the gateway — host, port, scheme (tls), path, header names, model list,
system prompt, and the key itself in the `api_key` field. Because it carries a secret it is not in
the repo; prisma-airs/config.example.json is the template to copy from.

Key precedence: PZ_PORTKEY_API_KEY in the environment wins (so a deploy can override without
editing the file), otherwise the `api_key` in config.json. Host may be overridden with
PZ_PRETZEL_AI_GATEWAY_HOST for a gateway that is not where config.json points.
"""

import json
import os


class StaticCredentials:
    """The resolved gateway key, held for the process. Mirrors the old GatewayCredentialService
    interface (`.key(id)`) so GatewayService does not care where the value came from."""

    def __init__(self, key):
        self._key = key or ""

    def key(self, _credential_id=None):
        return self._key


def load(config_path):
    """→ (gateway_config_dict, credentials)."""
    with open(config_path) as f:
        gw = dict((json.load(f).get("gateway") or {}))

    # Take the key out of the gateway dict so it is never accidentally logged with the rest of it.
    hardcoded = gw.pop("api_key", "")
    key = os.environ.get("PZ_PORTKEY_API_KEY", "").strip() or hardcoded

    host_override = os.environ.get("PZ_PRETZEL_AI_GATEWAY_HOST", "").strip()
    if host_override:
        gw["host"] = host_override

    return gw, StaticCredentials(key)
