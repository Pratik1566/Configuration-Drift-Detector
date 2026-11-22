"""Shared AI provider configuration for Drift Detector."""

import os
import time

import streamlit as st
from google import genai
from google.genai import types


DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


def get_setting(name, default=None):
    """Read a setting from environment variables or Streamlit secrets."""
    value = os.getenv(name)

    if value and value.strip():
        return value.strip()

    try:
        value = st.secrets.get(name)
        if value and str(value).strip():
            return str(value).strip()
    except Exception:
        pass

    return default


def get_ai_provider():
    """Return the configured AI provider."""
    provider = get_setting("AI_PROVIDER", "ollama")

    if not isinstance(provider, str):
        raise ValueError("AI_PROVIDER must be a string.")

    provider = provider.strip().lower()

    if provider not in {"ollama", "gemini"}:
        raise ValueError(f"Unsupported AI provider: {provider}")

    return provider


def generate_with_gemini(
    prompt,
    system_instruction="",
    json_mode=False,
):
    """Generate a response using Gemini with limited retries."""

    api_key = get_setting("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError("Gemini API key is not configured.")

    model = get_setting("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)

    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("Gemini prompt cannot be empty.")

    client = genai.Client(api_key=api_key)

    config_options = {
        "temperature": 0.1,
        "max_output_tokens": 2000,
    }

    if system_instruction:
        config_options["system_instruction"] = system_instruction

    if json_mode:
        config_options["response_mime_type"] = "application/json"

    config = types.GenerateContentConfig(**config_options)

    last_error = None

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
            )

            result = response.text

            if not result or not result.strip():
                raise RuntimeError(
                    "Gemini returned an empty response. "
                    "The request may have been blocked or stopped."
                )

            return result.strip()

        except Exception as exc:
            last_error = exc
            status_code = getattr(exc, "code", None)

            if status_code is None:
                status_code = getattr(exc, "status_code", None)

            retryable = (
                status_code in {429, 500, 502, 503, 504}
                or any(
                    code in str(exc)
                    for code in ("429", "500", "502", "503", "504")
                )
            )

            if not retryable or attempt == 2:
                raise RuntimeError(
                    f"Gemini request failed: {exc}"
                ) from exc

            time.sleep(2 ** (attempt + 1))

    raise RuntimeError(
        f"Gemini failed after 3 attempts: {last_error}"
    ) from last_error