"""
Gemini Multi-Model Fallback Engine
Automatically switches to alternate suitable Gemini models if token quotas,
rate limits (HTTP 429 / ResourceExhausted), or service errors occur.
"""
import logging
from typing import Any, List, Optional
from config.settings import settings

logger = logging.getLogger(__name__)

# Complete fallback hierarchy of compatible models supported by the Gemini API Key
FALLBACK_MODELS: List[str] = [
    "gemini-3.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]


def generate_content_with_fallback(
    client: Any,
    contents: Any,
    preferred_model: Optional[str] = None,
    candidate_models: Optional[List[str]] = None,
    **kwargs: Any
) -> Any:
    """
    Executes generate_content across an automatic fallback chain of suitable Gemini models.
    If a model exceeds rate limits, token quota (HTTP 429 / ResourceExhausted), or returns 503,
    it automatically fails over to the next available model without crashing.
    """
    models_to_try: List[str] = []

    # 1. Start with preferred / default configured model
    initial = preferred_model or getattr(settings, "gemini_model", "gemini-3.5-flash-lite")
    models_to_try.append(initial)

    # 2. Append all fallback options in prioritized sequence
    candidates = candidate_models or getattr(settings, "gemini_fallback_models", FALLBACK_MODELS)
    for m in candidates:
        if m not in models_to_try:
            models_to_try.append(m)

    last_error: Optional[Exception] = None
    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=contents,
                **kwargs
            )
            return response
        except Exception as e:
            err_str = str(e).lower()
            last_error = e
            is_quota_or_transient = any(sig in err_str for sig in [
                "429", "quota", "resourceexhausted", "token", "limit", "rate", "503", "unavailable", "overloaded", "exceeded", "capacity"
            ])
            logger.warning(
                f"[GeminiFallback] Model '{model_name}' failed ({type(e).__name__}): {e}. "
                f"Failing over to next available model in chain..."
            )
            continue

    if last_error:
        raise last_error
    raise RuntimeError("All configured Gemini models in fallback chain failed.")
