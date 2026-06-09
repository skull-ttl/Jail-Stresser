"""Backend detector: fingerprint the server, report the nameplate honestly.

What this does and does NOT claim:

  SERVER layer (reliable): endpoint paths, error shapes, and response keys are
  deterministic, so we fingerprint the server the way nmap fingerprints a
  service. HIGH/MEDIUM confidence.

  MODEL NAMEPLATE (reliable ONLY when advertised): if the server publishes its
  installed models (Ollama's /api/tags, OpenAI's /v1/models), that list is
  ground truth and we use it. If the server does NOT advertise, the nameplate
  is 'unknown' and we say so. We do NOT ask the model what it is - models
  hallucinate their identity, so that signal is worse than useless in a tool
  meant to be correct. (Behavioral profiling - strict vs permissive - is done
  separately by profile.py, which MEASURES behavior rather than guessing a name.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class Detection:
    host: str
    server: str = "unknown"
    server_confidence: str = "none"
    server_evidence: str = ""
    chat_endpoint: Optional[str] = None
    suggested_adapter: str = "http"
    models_seen: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def nameplate(self) -> str:
        if self.models_seen:
            return ", ".join(self.models_seen[:8])
        return "unknown (server does not advertise its model)"

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  BACKEND DETECTION",
            "=" * 60,
            f"  Host             : {self.host}",
            f"  Server           : {self.server}  (confidence: {self.server_confidence})",
            f"  Evidence         : {self.server_evidence}",
            f"  Chat endpoint    : {self.chat_endpoint}",
            f"  Suggested adapter: {self.suggested_adapter}",
            f"  Model nameplate  : {self.nameplate}",
        ]
        for n in self.notes:
            lines.append(f"  Note             : {n}")
        lines.append("=" * 60)
        return "\n".join(lines)


def _get(url: str, timeout: float):
    try:
        r = requests.get(url, timeout=timeout)
        return r.status_code, r
    except Exception as e:  # noqa: BLE001
        return None, e


def _post(url: str, body: dict, timeout: float):
    try:
        r = requests.post(url, json=body, timeout=timeout)
        return r.status_code, r
    except Exception as e:  # noqa: BLE001
        return None, e


def detect(host: str, timeout: float = 10.0) -> Detection:
    host = host.rstrip("/")
    det = Detection(host=host)

    # Signature 1: Ollama - /api/tags lists installed models (Ollama-native).
    code, resp = _get(f"{host}/api/tags", timeout)
    if code == 200:
        try:
            data = resp.json()
            if isinstance(data, dict) and "models" in data:
                det.server = "ollama"
                det.server_confidence = "high"
                det.server_evidence = "/api/tags returned a models list (Ollama-native)"
                det.chat_endpoint = f"{host}/v1/chat/completions"
                det.suggested_adapter = "ollama"
                det.models_seen = [m.get("name", "?") for m in data.get("models", [])]
                return det
        except Exception:  # noqa: BLE001
            pass

    # Signature 2: OpenAI-compatible - /v1/models (OpenAI convention).
    code, resp = _get(f"{host}/v1/models", timeout)
    if code == 200:
        try:
            data = resp.json()
            if isinstance(data, dict) and "data" in data:
                det.server = "openai-compatible"
                det.server_confidence = "medium"
                det.server_evidence = "/v1/models present (OpenAI API convention)"
                det.chat_endpoint = f"{host}/v1/chat/completions"
                det.suggested_adapter = "http"
                det.models_seen = [m.get("id", "?") for m in data.get("data", [])]
                det.notes.append("Several servers expose /v1/models; verify the "
                                 "response shape if requests fail.")
                return det
        except Exception:  # noqa: BLE001
            pass

    # Signature 3: llama.cpp native - /health.
    code, _ = _get(f"{host}/health", timeout)
    if code == 200:
        det.server = "llama.cpp"
        det.server_confidence = "medium"
        det.server_evidence = "/health responds (llama.cpp server convention)"
        det.chat_endpoint = f"{host}/v1/chat/completions"
        det.suggested_adapter = "http"
        det.notes.append("llama.cpp: nameplate not advertised; model is unknown. "
                          "Older builds use /completion with a different shape.")
        return det

    # Generic fallback: probe common chat paths.
    det.notes.append("No known server signature matched. Probing common chat paths.")
    for path in ("/v1/chat/completions", "/api/chat", "/chat", "/completion", "/generate"):
        code, _ = _post(f"{host}{path}", {}, timeout)
        if code is not None and code != 404:
            det.chat_endpoint = f"{host}{path}"
            det.server_evidence = f"{path} responded with HTTP {code} (route exists)"
            det.notes.append(f"Guessed chat endpoint {path}; nameplate unknown. You "
                             f"may need a custom build_payload/extract_text.")
            break
    if det.chat_endpoint is None:
        det.notes.append("Could not find any chat endpoint. Is the server running "
                         "and reachable at this host/port?")
    return det
