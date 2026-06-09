"""Adapter built from a captured cURL request (PUBLIC harness).

Replays the user's real browser request for each payload: same URL, method,
headers (cookie included), and body, substituting the attack text into the
auto-detected injectable field. Handles ANY body format (JSON, multipart/form-
data, urlencoded, raw) via BodyTemplate, and any response shape (SSE/JSON/raw)
via the universal extractor. This is the path for custom apps where detection
and guessing fail.
"""

from __future__ import annotations

import time

import requests

from adapters.base import Adapter, TargetResponse
from core.curl_import import parse_curl, extract_reply, BodyTemplate


class CurlAdapter(Adapter):
    def __init__(self, curl_text: str, probe_hint: str = "hi", timeout: float = 120.0):
        spec = parse_curl(curl_text)
        self.method = spec["method"]
        self.endpoint = spec["url"]          # named 'endpoint' so fuzzer/handshake see it
        self.headers = dict(spec["headers"])
        self.raw_body = spec["body"]
        self.timeout = timeout

        ctype = next((v for k, v in self.headers.items()
                      if k.lower() == "content-type"), "")
        self.body_tpl = BodyTemplate(self.raw_body or "", content_type=ctype,
                                     probe_hint=probe_hint)

    def describe(self) -> str:
        cookie = "yes" if any(k.lower() == "cookie" for k in self.headers) else "no"
        return (f"{self.method} {self.endpoint} | {self.body_tpl.describe()} | "
                f"cookie carried: {cookie}")

    def _headers_for(self, ctype_override):
        h = dict(self.headers)
        if ctype_override:
            # replace whatever content-type header exists (any casing)
            for k in list(h):
                if k.lower() == "content-type":
                    del h[k]
            h["Content-Type"] = ctype_override
        return h

    def send(self, system_prompt: str, user_message: str) -> TargetResponse:
        body, ctype_override = self.body_tpl.build(user_message)
        headers = self._headers_for(ctype_override)
        data = body.encode("utf-8") if isinstance(body, str) else body
        start = time.perf_counter()
        try:
            resp = requests.request(self.method, self.endpoint, data=data,
                                    headers=headers, timeout=self.timeout, stream=False)
            latency = (time.perf_counter() - start) * 1000
            ctype = resp.headers.get("Content-Type", "")
            text = extract_reply(resp.text, ctype)
            if resp.status_code in (401, 403):
                return TargetResponse(text="", latency_ms=latency, raw=resp.text,
                    error=f"HTTP {resp.status_code} (session/cookie may have expired "
                          f"- re-copy the cURL from your browser)")
            if not text and resp.status_code >= 400:
                return TargetResponse(text="", latency_ms=latency, raw=resp.text,
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}")
            return TargetResponse(text=text, latency_ms=latency, raw=resp.text)
        except Exception as e:  # noqa: BLE001
            latency = (time.perf_counter() - start) * 1000
            return TargetResponse(text="", latency_ms=latency,
                                  error=f"{type(e).__name__}: {e}")
