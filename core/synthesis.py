"""Behavioral synthesis: turn raw per-(probe,technique) results into a
characterization of the TARGET. Both the JSON and HTML reports consume this, so
the "what did we learn about this endpoint" logic lives in exactly one place.

This is the recon/mapping payoff: instead of 200 rows, produce a short profile -
which technique families got traction, which channels are closed (target can't
decode), and a per-family x per-objective matrix for the heatmap.

Nothing here makes a security VERDICT. Flags are heuristic hints; the profile
summarizes where to look, not what is "broken". Language stays hedged on purpose.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List


def build_profile(results, target: str = "unknown") -> dict:
    """Return a structured behavioral profile from AggResult list.

    Keys:
      target, totals, by_family, by_objective, matrix (family x objective),
      closed_channels (families that were all-ineffective), top_findings,
      narrative (one-paragraph human synthesis).
    """
    active = [r for r in results if not getattr(r, "skipped", False)]

    # --- aggregate by family (technique) and by objective ---
    fam = defaultdict(lambda: {"breaks": 0, "valid": 0, "ineffective": 0, "total": 0})
    obj = defaultdict(lambda: {"breaks": 0, "valid": 0, "ineffective": 0, "total": 0})
    matrix = defaultdict(lambda: defaultdict(lambda: {"breaks": 0, "valid": 0, "ineffective": 0}))

    for r in active:
        f, o = r.technique, r.objective
        fam[f]["breaks"] += r.breaks; fam[f]["valid"] += r.valid
        fam[f]["ineffective"] += r.ineffective; fam[f]["total"] += r.iterations
        obj[o]["breaks"] += r.breaks; obj[o]["valid"] += r.valid
        obj[o]["ineffective"] += r.ineffective; obj[o]["total"] += r.iterations
        m = matrix[f][o]
        m["breaks"] += r.breaks; m["valid"] += r.valid; m["ineffective"] += r.ineffective

    def rate(d):
        return round(d["breaks"] / d["valid"] * 100, 1) if d["valid"] else 0.0

    by_family = {f: {**v, "flag_rate": rate(v)} for f, v in fam.items()}
    by_objective = {o: {**v, "flag_rate": rate(v)} for o, v in obj.items()}

    # --- closed channels: families where every attempt was ineffective ---
    closed = [f for f, v in fam.items()
              if v["ineffective"] > 0 and v["valid"] == 0]

    # --- top findings: families with any flags, ranked by flag rate ---
    flagged_fams = sorted(
        [(f, rate(v), v["breaks"], v["valid"]) for f, v in fam.items() if v["breaks"] > 0],
        key=lambda x: -x[1])
    top_findings = [{"family": f, "flag_rate": fr, "flagged": b, "of": v}
                    for f, fr, b, v in flagged_fams]

    totals = {
        "pairs": len(active),
        "flagged": sum(r.breaks for r in active),
        "valid": sum(r.valid for r in active),
        "ineffective": sum(r.ineffective for r in active),
        "errors": sum(r.errors for r in active),
        "overall_flag_rate": round(sum(r.breaks for r in active)
                                   / max(1, sum(r.valid for r in active)) * 100, 1),
    }

    # --- one-paragraph narrative (hedged, recon-appropriate) ---
    narrative = _narrate(target, totals, top_findings, closed, by_objective)

    # flatten matrix to plain dict for JSON
    matrix_out = {f: {o: dict(cell) for o, cell in row.items()}
                  for f, row in matrix.items()}

    return {
        "target": target,
        "totals": totals,
        "by_family": by_family,
        "by_objective": by_objective,
        "matrix": matrix_out,
        "closed_channels": closed,
        "top_findings": top_findings,
        "narrative": narrative,
    }


def _narrate(target, totals, top_findings, closed, by_objective) -> str:
    """Compose a short, hedged behavioral summary. No hard verdicts."""
    parts = []
    parts.append(
        f"Swept {totals['pairs']} technique/objective pairs against {target}. "
        f"{totals['flagged']} response(s) flagged for review "
        f"({totals['overall_flag_rate']}% of {totals['valid']} that executed).")

    if totals["ineffective"]:
        parts.append(
            f"{totals['ineffective']} attempt(s) never landed (the target could "
            f"not process the encoded/transformed payload) and were excluded from "
            f"rates rather than counted as resistance.")

    if top_findings:
        lead = top_findings[0]
        fams = ", ".join(f"{t['family']} ({t['flag_rate']}%)" for t in top_findings[:3])
        parts.append(
            f"Families that drew flags: {fams}. The most responsive surface was "
            f"'{lead['family']}' - worth reading those responses first.")
    else:
        parts.append(
            "No technique family drew a flag. The target either resisted the "
            "swept surface or leaked in a form the heuristic judge does not "
            "recognize - review a sample of raw responses to be sure.")

    if closed:
        parts.append(
            f"Closed channel(s): {', '.join(closed)} - the target did not decode "
            f"these, so that delivery path appears inoperable against it.")

    parts.append(
        "These are heuristic hints, not security verdicts: read the flagged "
        "responses to confirm before drawing conclusions.")
    return " ".join(parts)
