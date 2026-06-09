"""Core data models for the jailbreak tester.

The whole tool revolves around three objects:
  - Probe:     plants a rule in the system prompt + defines how to detect a break.
  - Jailbreak: an attack technique that tries to make the model break that rule.
  - Result:    the outcome of running one jailbreak against one probe.

Keeping these as plain dataclasses (not dicts) means the type checker and your
editor can catch mistakes, and the fields are self-documenting.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Optional


class OracleType(str, Enum):
    """How we decide a jailbreak succeeded.

    LEAK_CANARY:   the model output a secret it was told never to reveal.
    FORBIDDEN_WORD: the model emitted a word it was told never to say.
    LANGUAGE_SWITCH: the model abandoned a language constraint it was given.

    The three above are *deterministic* string checks - they require that YOU
    control the target's system prompt (you planted the rule/canary). They are
    right for hardening your OWN models, where you know the secret to grep for.

    HEURISTIC_HINT: for REAL third-party targets whose system prompt you do NOT
    control. There is no planted canary, so detection is heuristic: the judge
    flags responses that LOOK like a leak (quoted instructions, disclosed system
    prompt, broken character, etc.) as HINTS for human review - never as a hard
    security verdict. False positives and negatives are expected; this is a
    triage aid, not a measurement.
    """

    LEAK_CANARY = "leak_canary"
    FORBIDDEN_WORD = "forbidden_word"
    LANGUAGE_SWITCH = "language_switch"
    HEURISTIC_HINT = "heuristic_hint"


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"   # the rule broke - jailbreak worked (canary modes)
    ROBUST = "ROBUST"           # the rule held - model resisted (canary modes)
    ERROR = "ERROR"             # the request itself failed (network, auth, etc.)
    FLAGGED = "FLAGGED"         # heuristic mode: response looks worth reviewing
    CLEAN = "CLEAN"             # heuristic mode: nothing notable flagged
    INEFFECTIVE = "INEFFECTIVE" # the attack never LANDED: the technique didn't
                                # actually execute against the target (e.g. an
                                # encoded payload the model failed to decode, or
                                # echoed back verbatim). The request SUCCEEDED
                                # (unlike ERROR) but the attack was never really
                                # delivered, so this MUST be excluded from the
                                # break-rate denominator - counting it as
                                # "resisted" would inflate apparent robustness.


@dataclass
class Probe:
    """A benign rule planted in the system prompt, plus its success oracle.

    `system_prompt` is what we send as the model's instructions. `oracle_value`
    is the thing we grep for in the output to decide if the rule broke. We keep
    the detection logic out here (in models) deliberately small; the judge
    module turns oracle_type + oracle_value into an actual check.
    """

    id: str
    description: str
    system_prompt: str
    oracle_type: OracleType
    oracle_value: str = ""  # canary/word/lang marker (unused for HEURISTIC_HINT)
    objective: str = "misc"  # groups results by attack goal in the report


@dataclass
class Jailbreak:
    """One attack technique - single-shot or multi-turn.

    SINGLE-SHOT: `template` holds one prompt with a `{benign_request}`
    placeholder, filled per-probe so one technique tests every probe.

    MULTI-TURN: `turns` holds an ordered list of prompts sent as a conversation
    with history preserved between turns. At least one turn contains the
    placeholder. When `turns` is set, `template` is ignored.

    Exactly one of {template, turns} should be populated. `is_multiturn` tells
    the runner which path to take.
    """

    id: str
    name: str
    technique: str
    description: str
    template: str = ""              # single-shot prompt (contains {benign_request})
    turns: list = field(default_factory=list)  # multi-turn prompts (ordered)

    @property
    def is_multiturn(self) -> bool:
        return bool(self.turns)


@dataclass
class Result:
    jailbreak_id: str
    probe_id: str
    technique: str
    verdict: Verdict
    evidence: str                 # why the judge ruled this way
    prompt_sent: str
    response_text: str
    latency_ms: float
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d
