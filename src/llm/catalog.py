"""Which models this appliance may ask for, and what each one needs.

The catalog is a fact about the deployment, not a policy the operator declares: what is reachable
is decided by the accounts wired up behind the gateway or the provider keys on the box. It is
answered over the wire (ListModels) rather than committed to running_config for that reason —
rolling a configuration back does not put a model back in someone's account.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

# Display names for the routing slugs the catalog uses. A slug with no entry is shown as-is rather
# than dropped: a provider connected tomorrow should appear under its own name, not a blank one.
PROVIDER_LABELS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google": "Google",
    "vertex-ai": "Vertex AI",
    "azure-openai": "Azure OpenAI",
    "bedrock": "Bedrock",
}

# The name a model's output cap goes out under. Unset means the old one, which every model before
# the gpt-5 generation took.
DEFAULT_TOKEN_PARAM = "max_tokens"


@dataclass(frozen=True)
class Model:
    """One entry of the catalog."""

    id: str                     # "@openai/gpt-4o-2024-11-20" — sent to the gateway verbatim
    label: str = ""
    provider: str = ""
    token_param: str = DEFAULT_TOKEN_PARAM

    # Only used when the LLM leg bypasses the gateway: which direct endpoint serves this model.
    endpoint: str = ""

    @property
    def slug(self) -> str:
        """The routing slug, or "" for a bare model name."""
        if not self.id.startswith("@") or "/" not in self.id:
            return ""
        return self.id[1:].split("/", 1)[0]

    @property
    def bare(self) -> str:
        """The model name with the routing slug stripped — what a provider's own API expects."""
        return self.id.split("/", 1)[1] if "/" in self.id else self.id

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "label": self.label or self.id, "provider": self.provider}


class Catalog:
    """The models, and the reason an unknown one is refused rather than substituted.

    The console shows which model answered. Quietly serving a different one makes that display a
    lie, so `resolve` returns an error instead of falling back.
    """

    def __init__(self, entries: Iterable[dict[str, Any]], default: str = "") -> None:
        self._models: dict[str, Model] = {}
        for raw in entries:
            model_id = str(raw.get("id", "")).strip()
            if not model_id:
                continue
            provider = str(raw.get("provider", "") or "")
            model = Model(
                id=model_id,
                label=str(raw.get("label", "") or model_id),
                provider=provider,
                token_param=str(raw.get("token_param", "") or DEFAULT_TOKEN_PARAM),
                endpoint=str(raw.get("endpoint", "") or ""))
            if not model.provider:
                model = Model(**{**model.__dict__,
                                 "provider": PROVIDER_LABELS.get(model.slug, model.slug)})
            self._models[model_id] = model

        self._default = default if default in self._models else next(iter(self._models), "")

    def __len__(self) -> int:
        return len(self._models)

    def __iter__(self):
        return iter(self._models.values())

    @property
    def default(self) -> str:
        return self._default

    def get(self, model_id: str) -> Model | None:
        return self._models.get(model_id)

    def resolve(self, requested: str) -> tuple[str, str]:
        """→ (model id, error). An empty request takes the default; an unknown one is refused."""
        if not requested:
            return self._default, "" if self._default else "no model is configured"
        if requested in self._models:
            return requested, ""
        return "", f"unknown model '{requested}'"

    def token_param(self, model_id: str) -> str:
        model = self._models.get(model_id)
        return model.token_param if model else DEFAULT_TOKEN_PARAM

    def as_list(self) -> list[dict[str, str]]:
        return [m.as_dict() for m in self._models.values()]
