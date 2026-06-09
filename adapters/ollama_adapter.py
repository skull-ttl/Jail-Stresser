"""Ollama adapter: a thin, correct wrapper for a local Ollama server.

Ollama exposes an OpenAI-compatible endpoint at
http://localhost:11434/v1/chat/completions. Two things differ from a bare
OpenAI-style call and trip people up:

  1. The body MUST include a "model" field naming a locally-pulled tag
     (e.g. "qwen3:0.6b"). Get the exact tag from `ollama list`.
  2. You MUST set "stream": false, or Ollama returns newline-delimited JSON
     chunks and a single resp.json() parse fails.

The response comes back under choices[0].message.content, which the default
HTTP extractor already handles - so we only customize the payload builder.

This is just HTTPAdapter with a preset build_payload; keeping it as its own
class makes the CLI clean and documents the Ollama-specific quirks in one place.
"""

from __future__ import annotations

from .http_adapter import HTTPAdapter, _default_extract_text


class OllamaAdapter(HTTPAdapter):
    def __init__(
        self,
        model: str,
        host: str = "http://localhost:11434",
        timeout: float = 120.0,
    ):
        self.model = model
        endpoint = f"{host.rstrip('/')}/v1/chat/completions"

        def build_payload(system_prompt: str, user_message: str) -> dict:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": user_message})
            return {
                "model": self.model,
                "messages": messages,
                "stream": False,   # critical: keep it single-shot JSON
            }

        super().__init__(
            endpoint=endpoint,
            build_payload=build_payload,
            extract_text=_default_extract_text,  # choices[0].message.content
            timeout=timeout,
        )
