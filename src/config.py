"""The defaults this service falls back to, and the credentials it resolves from the environment.

There is no config file any more. Until recently pretzel-ai read config.json at startup: the
guardrail, the turn shape and the direct-provider endpoints lived there, and changing any of them
meant editing a file on the appliance and restarting the service. That is not something an
operator can be asked to do, so all of it moved into the appliance's running config and arrives
over ApplyConfig — see src/deployment.py, which lays the pushed document over what is below.

What stays here is what a document cannot supply:

    DEFAULTS        the values a service with no push yet runs on. Not a configuration anybody
                    deploys — it has no models, so it cannot serve a turn — but a complete enough
                    document that the engine's builder fails on the one thing that is actually
                    missing rather than on a KeyError three layers down.
    credentials     keys taken from the environment. The appliance's sealed store is where they
                    come from in a deployment; the environment is what makes this service runnable
                    on its own, for a developer or a benchmark run with no appliance in front of it.

Precedence changed with the file's removal, and in the direction that matters: a pushed key now
WINS over the environment. It used to be the other way, because the environment was the way to
avoid writing a key into a config document. There is no such document now, and an env var that
outranked the console would mean an operator rotating a key in the UI and watching nothing happen.
"""

import copy
import os

# Where each vendor's key is looked for when nothing has been pushed. The name is the provider slug
# upper-cased — the half of a model id before the slash.
PROVIDER_KEY_ENV = "PZ_{slug}_API_KEY"
AIRS_KEY_ENV = "PANW_AI_SEC_API_KEY"
GATEWAY_KEY_ENV = "PZ_PORTKEY_API_KEY"

# The document a service with no push runs on.
#
# `route.llm` is "direct" and not a choice: the appliance's deployment names vendors, and the
# gateway leg has no configuration source left now that config.json is gone. It stays in the
# vocabulary because factory.py still builds either leg and the benchmark harness still points at
# a gateway when that is what is under test.
#
# The guardrail defaults to inspecting all four checkpoints. A service that came up inspecting
# nothing and waited to be told otherwise would be one push away from a deployment nobody chose;
# defaulting the other way makes the failure mode "the guardrail refuses to build without a key",
# which is loud and correct.
DEFAULTS = {
    "route": {
        "llm": "direct",
        "guardrail": "airs",
        "require_guardrail": False,
    },
    # `gateway` is where the factory reads the catalog and the turn shape from on either leg — a
    # wart of the name, not of the arrangement.
    "gateway": {
        "system_prompt": "",
        "max_tokens": 4096,
        "timeout_sec": 45,
        "models": [],
        "default_model": "",
    },
    "airs": {
        "endpoint": "",
        "profile_name": "",
        "api_key": "",
        "timeout_sec": 30,
        "fail_open": False,
        "checkpoints": {
            "prompt": True,
            "response": True,
            "tool_call": True,
            "tool_result": True,
        },
    },
    "providers": {},
}


class MultiCredentials:
    """One key per credential id, resolved for the process.

    Holds whatever the deployment resolved — a pushed key, or an environment one where nothing was
    pushed. The `.key(id)` shape is what the transports call; they do not care which it was.
    """

    def __init__(self, keys):
        self._keys = {k: (v or "") for k, v in (keys or {}).items()}

    def key(self, credential_id=None):
        if credential_id is None:
            # No id asked for: the only key there is. A single-route deployment has exactly one.
            return next((v for v in self._keys.values() if v), "")
        return self._keys.get(credential_id, "")

    def configured(self):
        """Which ids actually have a key. For the startup log, never the value."""
        return sorted(k for k, v in self._keys.items() if v)


def defaults():
    """A fresh copy of DEFAULTS. Copied because Deployment merges into its base in place."""
    return copy.deepcopy(DEFAULTS)


def env_key(name):
    return os.environ.get(name, "").strip()


def provider_env_key(slug):
    return env_key(PROVIDER_KEY_ENV.format(slug=slug.upper().replace("-", "_")))
