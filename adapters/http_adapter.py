"""Generic HTTP adapter for a self-hosted / web-app model endpoint.

This is the "test an app you're running" case: your model is exposed at
something like http://127.0.0.1:6666/model and you POST a prompt to it.

The problem: every home-grown endpoint has a different request/response JSON
shape. One app wants {"prompt": "..."}, another wants
{"messages": [{"role": "user", ...}]}, and the answer comes back under "text"
or "response" or "output" or "choices[0].message.content".

Rather than hardcode one shape, this adapter is *configurable* via two small
functions: `build_payload` turns (system, user) into the request body, and
`extract_text` pulls the reply text out of the response JSON. Sensible defaults
are provided so the common case is zero-config, but you can override per target.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

import requests

from .base import Adapter, TargetResponse


def _default_build_payload(system_prompt: str, user_message: str) -> dict:
    """Default request shape: an OpenAI-ish messages array.

    Many local servers (Ollama's /api/chat, llama.cpp server, LM Studio,
    vLLM's OpenAI-compatible endpoint) accept something close to this.
    """
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})
    return {"messages": messages}


def _default_extract_text(body: dict) -> str:
    """Default response parser: try the most common reply locations in order.

    We walk a list of candidate paths instead of assuming one. If none match,
    we raise so the caller knows the parser needs configuring for this target
    rather than silently returning "" and reporting every probe as ROBUST.
    """
    # OpenAI-compatible: choices[0].message.content
    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        pass
    # Common flat keys
    for key in ("response", "text", "output", "content", "reply", "message"):
        val = body.get(key) if isinstance(body, dict) else None
        if isinstance(val, str):
            return val
    raise ValueError(
        f"Could not find reply text in response JSON. Keys present: "
        f"{list(body.keys()) if isinstance(body, dict) else type(body)}. "
        f"Pass a custom extract_text to HTTPAdapter for this target."
    )


class HTTPAdapter(Adapter):
    def __init__(
        self,
        endpoint: str,
        build_payload: Callable[[str, str], dict] = _default_build_payload,
        extract_text: Callable[[dict], str] = _default_extract_text,
        headers: Optional[dict] = None,
        timeout: float = 60.0,
    ):
        self.endpoint = endpoint
        self.build_payload = build_payload
        self.extract_text = extract_text
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout

    def send(self, system_prompt: str, user_message: str) -> TargetResponse:
        payload = self.build_payload(system_prompt, user_message)
        start = time.perf_counter()
        try:
            resp = requests.post(
                self.endpoint, json=payload, headers=self.headers, timeout=self.timeout
            )
            latency_ms = (time.perf_counter() - start) * 1000
            resp.raise_for_status()
            body = resp.json()
            text = self.extract_text(body)
            return TargetResponse(text=text, latency_ms=latency_ms, raw=body)
        except Exception as e:  # noqa: BLE001 - we deliberately swallow everything
            latency_ms = (time.perf_counter() - start) * 1000
            # Never raise: a dead endpoint or a parse miss becomes an ERROR row,
            # not a crash that loses the rest of the run.
            return TargetResponse(
                text="", latency_ms=latency_ms, error=f"{type(e).__name__}: {e}"
            )

    def send_turns(self, system_prompt: str, user_turns: list) -> list:
        """Multi-turn with real history. Sends each user turn with all prior
        turns and the model's replies in context, returning ONE TargetResponse
        per turn (so the runner can judge after each).

        This builds the messages array itself rather than via build_payload,
        because build_payload only knows (system, user). To stay compatible with
        whatever model field build_payload injects, we extract it from a probe
        payload once and reuse it.
        """
        # Discover any extra fields (e.g. {"model": ...}, {"stream": false}) the
        # configured build_payload adds, by building a throwaway payload and
        # copying everything except its messages.
        sample = self.build_payload(system_prompt, "_")
        extra = {k: v for k, v in sample.items() if k != "messages"}

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        responses = []
        for turn in user_turns:
            messages.append({"role": "user", "content": turn})
            payload = dict(extra)
            payload["messages"] = list(messages)
            start = time.perf_counter()
            try:
                resp = requests.post(self.endpoint, json=payload,
                                     headers=self.headers, timeout=self.timeout)
                latency_ms = (time.perf_counter() - start) * 1000
                resp.raise_for_status()
                body = resp.json()
                text = self.extract_text(body)
                tr = TargetResponse(text=text, latency_ms=latency_ms, raw=body)
            except Exception as e:  # noqa: BLE001
                latency_ms = (time.perf_counter() - start) * 1000
                tr = TargetResponse(text="", latency_ms=latency_ms,
                                    error=f"{type(e).__name__}: {e}")
                responses.append(tr)
                break  # stop the conversation if a turn errors
            responses.append(tr)
            # Append the model's reply so the next turn has real history.
            messages.append({"role": "assistant", "content": text})
        return responses
