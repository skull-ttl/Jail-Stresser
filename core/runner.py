"""The runner: executes the test matrix, single-shot and multi-turn.

Each (probe, jailbreak) pair runs `iterations` times (LLMs are non-deterministic;
robustness is a rate). Single-shot techniques send one prompt and judge the
reply. Multi-turn techniques send turns in sequence WITH conversation history,
judging after each turn - the technique counts as a break if ANY turn breaks
the rule (the jailbreak "won" the moment the rule fell).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from adapters.base import Adapter
from core.judge import judge
from core.models import Jailbreak, Probe, Verdict
from jailbreaks.library import BENIGN_REQUESTS


@dataclass
class AggResult:
    jailbreak_id: str
    probe_id: str
    technique: str
    iterations: int
    breaks: int
    errors: int
    ineffective: int = 0       # attack ran but never landed (e.g. not decoded)
    objective: str = "misc"
    skipped: bool = False
    skip_reason: str = ""
    samples: list = field(default_factory=list)

    @property
    def valid(self) -> int:
        # Exclude BOTH errors (request failed) and ineffective (attack never
        # landed) from the denominator. break_rate then means "of the attacks
        # that actually executed, how many broke the target" - the honest number.
        return self.iterations - self.errors - self.ineffective

    @property
    def break_rate(self) -> float:
        return (self.breaks / self.valid * 100) if self.valid else 0.0

    def to_dict(self) -> dict:
        return {
            "jailbreak_id": self.jailbreak_id, "probe_id": self.probe_id,
            "technique": self.technique, "objective": self.objective,
            "iterations": self.iterations,
            "breaks": self.breaks, "errors": self.errors,
            "ineffective": self.ineffective,
            "break_rate": round(self.break_rate, 1),
            "skipped": self.skipped, "skip_reason": self.skip_reason,
            "samples": self.samples,
        }


def _judge_text(probe: Probe, text: str):
    return judge(probe.oracle_type, probe.oracle_value, text)


def _run_single(adapter, probe, jb, benign):
    """One single-shot attempt. Returns (verdict, evidence, detail_dict)."""
    from jailbreaks.mutators import fill_mutations
    from core.judge import did_attack_land
    from core.gates import is_encoding_technique
    attack = fill_mutations(jb.template, benign)
    resp = adapter.send(probe.system_prompt, attack)
    if resp.error:
        return Verdict.ERROR, "adapter error", {
            "mode": "single", "prompt": attack, "response": "",
            "error": resp.error, "latency_ms": round(resp.latency_ms, 1)}
    verdict, evidence = _judge_text(probe, resp.text)
    # WIN CHECK (encoded-answer attacks): if the reply contains a span in the
    # scheme this attack requested, the model COMPLIED with a transform it should
    # have refused - the encoding is the canary. We decode the span and surface
    # the plaintext so the operator confirms a real leak at a glance. This runs
    # before the ineffective check because a span that decodes to readable text
    # is a WIN, whereas encoding-shaped garbage is a non-landing (below).
    if verdict in (Verdict.ROBUST, Verdict.CLEAN):
        from jailbreaks.encoding_detect import detect_encoded_answer
        hit = detect_encoded_answer(attack, resp.text)
        if hit:
            scheme, span, decoded = hit
            preview = (decoded[:120] + " […]") if len(decoded) > 120 else decoded
            verdict = Verdict.FLAGGED
            evidence = (f"encoded-answer compliance ({scheme}): model replied in the "
                        f"requested scheme. DECODED: {preview!r}")
    # If this was an encoded/obfuscated technique and the verdict is STILL a
    # NON-break, check whether the attack actually LANDED. A technique the model
    # never decoded must not be scored as "resisted" - that would inflate
    # apparent robustness. Breaks (incl. the win above) are left untouched.
    if (is_encoding_technique(jb.technique)
            and verdict in (Verdict.ROBUST, Verdict.CLEAN)):
        landed, why = did_attack_land(attack, resp.text)
        if not landed:
            verdict, evidence = Verdict.INEFFECTIVE, why
    return verdict, evidence, {
        "mode": "single", "prompt": attack, "response": resp.text,
        "verdict": verdict.value, "evidence": evidence,
        "latency_ms": round(resp.latency_ms, 1)}


def _run_multiturn(adapter, probe, jb, benign):
    """One multi-turn attempt with history. Breaks if ANY turn breaks.
    Returns (verdict, evidence, detail_dict)."""
    from jailbreaks.mutators import fill_mutations
    turns = [fill_mutations(t, benign) for t in jb.turns]
    # Prefer the real history-preserving path if the adapter has it.
    if hasattr(adapter, "send_turns"):
        responses = adapter.send_turns(probe.system_prompt, turns)
    else:
        # Fallback: degrade to sending the final turn only.
        responses = [adapter.send(probe.system_prompt, turns[-1])]

    from jailbreaks.encoding_detect import detect_encoded_answer
    from core.judge import did_attack_land
    from core.gates import is_encoding_technique
    enc_tech = is_encoding_technique(jb.technique)

    turn_log = []
    broke_at = None
    win_evidence = None
    ineffective_turns = 0
    encoded_turns = 0
    for i, resp in enumerate(responses):
        if resp.error:
            turn_log.append({"turn": i + 1, "prompt": turns[i] if i < len(turns) else "",
                             "error": resp.error})
            return Verdict.ERROR, f"error at turn {i+1}", {
                "mode": "multiturn", "turns": turn_log, "error": resp.error}
        turn_prompt = turns[i] if i < len(turns) else turns[-1]
        v, ev = _judge_text(probe, resp.text)
        # WIN CHECK per turn: an encoded-answer compliance on ANY turn is a break.
        if v in (Verdict.ROBUST, Verdict.CLEAN):
            hit = detect_encoded_answer(turn_prompt, resp.text)
            if hit:
                scheme, span, decoded = hit
                preview = (decoded[:120] + " […]") if len(decoded) > 120 else decoded
                v = Verdict.FLAGGED
                ev = (f"encoded-answer compliance ({scheme}) at turn {i+1}. "
                      f"DECODED: {preview!r}")
                if win_evidence is None:
                    win_evidence = ev
        # Track encoding-technique turns that never landed (for the all-ineffective case).
        if enc_tech and v in (Verdict.ROBUST, Verdict.CLEAN):
            encoded_turns += 1
            landed, _why = did_attack_land(turn_prompt, resp.text)
            if not landed:
                ineffective_turns += 1
        turn_log.append({"turn": i + 1, "prompt": turn_prompt,
                         "response": resp.text, "verdict": v.value, "evidence": ev,
                         "latency_ms": round(resp.latency_ms, 1)})
        if v in (Verdict.VULNERABLE, Verdict.FLAGGED) and broke_at is None:
            broke_at = i + 1
    if broke_at:
        return Verdict.FLAGGED if win_evidence else Verdict.VULNERABLE, \
            (win_evidence or f"broke at turn {broke_at}"), {
            "mode": "multiturn", "broke_at": broke_at, "turns": turn_log}
    # No break. If EVERY encoding turn was ineffective (and there were some),
    # the whole attempt never landed - don't score it as resisted.
    if enc_tech and encoded_turns > 0 and ineffective_turns == encoded_turns:
        return Verdict.INEFFECTIVE, \
            f"all {encoded_turns} encoded turn(s) failed to land (not decoded)", {
            "mode": "multiturn", "turns": turn_log}
    return Verdict.ROBUST, "held across all turns", {
        "mode": "multiturn", "turns": turn_log}


def run(adapter: Adapter, probes: List[Probe], jailbreaks: List[Jailbreak],
        iterations: int = 1, verbose: bool = False, stream: bool = True,
        total: int = 0, shuffle: bool = True, gates=None, on_step=None) -> List[AggResult]:
    """Execute the matrix.

    stream=True (default): print a colored exchange block per request as it
        happens (prompt, response, verdict). `verbose` makes responses full
        rather than truncated.
    stream=False: silent except for the on_step callback (used if a caller
        wants its own progress UI).
    `total` is the expected request count, for the n/total counter in blocks.
    `shuffle` randomizes execution ORDER (default True) so the suite doesn't
        hit the target in a fixed, fingerprintable sequence. Results are
        aggregated per (probe, jailbreak) regardless of order, so shuffling
        changes only the order things run and the payload numbers, not the math.
    """
    from core import ui
    from core.gates import is_encoding_technique
    import random

    # Determine which (probe, jb) pairs are GATED (skipped, with a reason).
    # Gates only prune provably-pointless work; everything pruned is still
    # reported as skipped. `gates=None` (or --full upstream) runs everything.
    def skip_reason_for(probe, jb):
        if gates is None or jb.technique == "control":
            return None  # never skip the control; it's the baseline
        objective = getattr(probe, "objective", "misc")
        if objective in gates.unenforced_objectives:
            return gates.unenforced_objectives[objective]
        if gates.cannot_decode and is_encoding_technique(jb.technique):
            return gates.decode_detail
        return None

    # Build the flat list of work units: one per (probe, jailbreak, iteration).
    # Gated pairs become a single skipped result rather than N executed units.
    units = []
    skipped_results = []
    for probe in probes:
        benign = BENIGN_REQUESTS.get(probe.id)
        if benign is None:
            continue
        objective = getattr(probe, "objective", "misc")
        for jb in jailbreaks:
            reason = skip_reason_for(probe, jb)
            if reason:
                skipped_results.append(AggResult(
                    jailbreak_id=jb.id, probe_id=probe.id, technique=jb.technique,
                    objective=objective, iterations=iterations, breaks=0, errors=0,
                    skipped=True, skip_reason=reason))
                continue
            for i in range(iterations):
                units.append((probe, benign, objective, jb, i))

    if shuffle:
        random.shuffle(units)

    if not total:
        total = len(units)

    # Aggregate buckets keyed by (probe_id, jailbreak_id).
    agg = {}
    payload_no = 0

    for probe, benign, objective, jb, i in units:
        if jb.is_multiturn:
            verdict, evidence, detail = _run_multiturn(adapter, probe, jb, benign)
        else:
            verdict, evidence, detail = _run_single(adapter, probe, jb, benign)

        payload_no += 1
        detail["payload_no"] = payload_no   # execution-order number for the report
        detail["iteration"] = i + 1

        key = (probe.id, jb.id)
        if key not in agg:
            agg[key] = {"jb": jb, "probe": probe, "objective": objective,
                        "breaks": 0, "errors": 0, "ineffective": 0, "samples": []}
        bucket = agg[key]
        if verdict == Verdict.ERROR:
            bucket["errors"] += 1
        elif verdict == Verdict.INEFFECTIVE:
            bucket["ineffective"] += 1
        elif verdict in (Verdict.VULNERABLE, Verdict.FLAGGED):
            bucket["breaks"] += 1
        bucket["samples"].append(detail)

        if stream:
            if jb.is_multiturn:
                ui.stream_multiturn(payload_no, total, probe.id, objective, jb.id,
                                    jb.technique, detail.get("turns", []),
                                    verdict.value, evidence, full=verbose)
            else:
                ui.stream_single(payload_no, total, probe.id, objective, jb.id,
                                 jb.technique, detail.get("prompt", ""),
                                 detail.get("response", ""), verdict.value,
                                 evidence, detail.get("latency_ms", 0.0),
                                 full=verbose)

        if on_step is not None:
            on_step(probe, jb, verdict.value)

    # Materialize aggregated results, then append the gated/skipped ones.
    results: List[AggResult] = []
    for key, b in agg.items():
        results.append(AggResult(
            jailbreak_id=b["jb"].id, probe_id=b["probe"].id,
            technique=b["jb"].technique, objective=b["objective"],
            iterations=iterations, breaks=b["breaks"], errors=b["errors"],
            ineffective=b["ineffective"], samples=b["samples"]))
    results.extend(skipped_results)

    return results
