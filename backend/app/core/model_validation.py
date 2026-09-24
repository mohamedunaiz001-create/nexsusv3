"""Server-side provider/model validation — Phase 5 fix.

Playground and Battle session creation previously trusted whatever
`model_configs` the frontend sent (provider/model strings typed or
picked in a `<select>`) with zero backend check. That means a stale
frontend cache, a hand-crafted API call, or a provider whose API key
was removed after the page loaded could create a session that fails
only once `/run` actually starts streaming — after the user has
already committed to it.

This validates, at session-creation time:
  1. every `provider` is registered *and configured* (has a usable API
     key / base URL) on the live ProviderRouter — not just a string
     the frontend happens to recognize;
  2. every `model` actually appears in that provider's live
     `list_models()` — the same call the `/models` catalog endpoint
     uses — so a renamed/decommissioned/typo'd model is rejected
     before it ever reaches execution.

Providers whose `list_models()` fails or isn't meaningfully
enumerable (e.g. a custom OpenAI-compatible endpoint that doesn't
expose a model list) only get the provider-level check — we don't
invent a model list to validate against, and we don't punish an
otherwise-configured provider for that.
"""

from dataclasses import dataclass

from app.core.exceptions import AppException


@dataclass
class ModelConfigError:
    provider: str
    model: str
    reason: str


async def validate_model_configs(router, model_configs: list[dict]) -> None:
    """Raises AppException(422) with a clean, itemized error list if any
    (provider, model) pair in `model_configs` isn't actually available
    right now. Returns None (no exception) if every pair checks out."""
    if not model_configs:
        raise AppException("At least one model must be selected", status_code=422)

    configured = set(await router.configured_providers())
    available = set(router.available_providers())

    errors: list[ModelConfigError] = []
    models_by_provider: dict[str, set[str] | None] = {}

    for cfg in model_configs:
        provider = cfg.get("provider")
        model = cfg.get("model")
        if not provider or not model:
            errors.append(
                ModelConfigError(
                    provider or "", model or "", "provider and model are required"
                )
            )
            continue

        if provider not in available:
            errors.append(
                ModelConfigError(provider, model, f"unknown provider '{provider}'")
            )
            continue

        if provider not in configured:
            errors.append(
                ModelConfigError(
                    provider,
                    model,
                    f"provider '{provider}' is not configured (missing API key/URL)",
                )
            )
            continue

        if provider not in models_by_provider:
            client = router.get_client(provider)
            try:
                live_models = await client.list_models()
                models_by_provider[provider] = {
                    m.get("id") for m in live_models if m.get("id")
                }
            except Exception:  # noqa: BLE001
                # Provider doesn't support/allow live listing right now —
                # fall back to provider-level validation only for it.
                models_by_provider[provider] = None

        known_models = models_by_provider[provider]
        if known_models is not None and model not in known_models:
            errors.append(
                ModelConfigError(
                    provider,
                    model,
                    f"model '{model}' is not available for provider '{provider}'",
                )
            )

    if errors:
        raise AppException(
            "One or more selected models are not available: "
            + "; ".join(f"{e.provider}:{e.model} ({e.reason})" for e in errors),
            status_code=422,
        )
