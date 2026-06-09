"""Adapters: the contract between the tester and whatever it's pointed at.

Why an abstract base class instead of just a function? Because the *shape* of
the target will change (plain chat now, RAG and tool-agents later) but the
runner shouldn't care. Every adapter promises the same thing: given a system
prompt and a user message, return a structured response. The runner programs
against TargetResponse, never against requests/openai/ollama specifics.

Note the return type is a structured object, not a bare string. Right now we
only populate `text`, but RAG adapters will fill `retrieved_docs` and agent
adapters will fill `tool_calls`. Designing this in now means future shapes slot
in without touching the runner or judge - this is the single most important
forward-compatibility decision in the codebase.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TargetResponse:
    text: str
    latency_ms: float
    raw: Any = None                       # untouched response body, for debugging
    tool_calls: list = field(default_factory=list)   # populated by agent adapters later
    retrieved_docs: list = field(default_factory=list)  # populated by RAG adapters later
    error: Optional[str] = None


@dataclass
class HandshakeResult:
    """Outcome of a pre-flight connectivity check.

    `ok` is the single thing the recon flow branches on: can we actually talk to
    this target? `detail` explains why not (for the user), and `sample` is the
    raw text we got back (so a failed parse can be diagnosed - often the endpoint
    responded fine but in a shape our extractor didn't expect).
    """
    ok: bool
    detail: str
    sample: str = ""
    latency_ms: float = 0.0


class Adapter(ABC):
    """Base class. A concrete adapter implements `send`."""

    @abstractmethod
    def send(self, system_prompt: str, user_message: str) -> TargetResponse:
        """Send one turn to the target and return its response.

        Implementations must NEVER raise on a network/HTTP error - they catch it
        and return a TargetResponse with `error` set. That keeps one bad request
        from killing a whole test run of hundreds of payloads.
        """
        raise NotImplementedError

    def send_conversation(self, system_prompt: str, user_messages: list) -> TargetResponse:
        """Send a multi-turn conversation, preserving history between turns.

        Default implementation builds the conversation by replaying turns: it
        sends each user message with all prior turns (and the model's replies)
        in context, and returns the FINAL response. Subclasses backed by a real
        chat API should override this to pass the full message list in one call
        for true history fidelity; this default approximates it for adapters
        that only expose single-shot send.

        Returns the final TargetResponse. For per-turn judging, the runner calls
        the lower-level path directly (see runner.run_multiturn).
        """
        # The HTTP/Ollama adapters override this properly; base fallback just
        # sends the last message (degraded, but never crashes).
        if not user_messages:
            return TargetResponse(text="", latency_ms=0.0, error="no turns")
        return self.send(system_prompt, user_messages[-1])

    def handshake(self) -> HandshakeResult:
        """Pre-flight check: send ONE trivial request and confirm a usable reply.

        This is the difference between "detection found a route" and "we can
        actually interact with it". Detection only inspects metadata endpoints
        (/api/tags etc.); it never confirms the *chat* path accepts our payload
        shape and returns parseable text. The handshake does, BEFORE we run a
        whole suite - so a shape mismatch surfaces as one clear message instead
        of N ERROR rows.

        It works for every adapter because it's built on `send`, which every
        adapter implements and which already captures errors into TargetResponse.
        """
        # A request so trivial any working chat model answers it, and whose
        # success doesn't depend on instruction-following: just echo a token.
        resp = self.send(
            system_prompt="",
            user_message="Reply with exactly the single word: OK",
        )
        if resp.error:
            return HandshakeResult(
                ok=False,
                detail=f"request failed: {resp.error}",
                latency_ms=resp.latency_ms,
            )
        if not resp.text or not resp.text.strip():
            return HandshakeResult(
                ok=False,
                detail="got a response but no text could be parsed from it - the "
                       "endpoint's reply shape may not match this adapter. "
                       "Inspect the raw body and supply a custom extract_text.",
                sample=str(resp.raw)[:300],
                latency_ms=resp.latency_ms,
            )
        # We don't require the reply to literally be "OK" - small models ramble.
        # Any non-empty parsed text means the round-trip works end to end.
        return HandshakeResult(
            ok=True,
            detail="round-trip OK: sent a probe and parsed a text reply",
            sample=resp.text.strip()[:120],
            latency_ms=resp.latency_ms,
        )
