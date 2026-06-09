"""Reporting - two consumers, two artifacts:

  1. JSON  (write_json)  - the MACHINE channel. Complete, structured, stable
     keys, every prompt+response+evidence included, plus a `target` field and a
     `behavioral_profile` synthesis block. Designed to be fed to an LLM for
     evaluation or parsed downstream. No decoration.

  2. HTML  (write_html)  - the HUMAN channel. A standalone, self-contained
     forensic-console report: target up top, one-paragraph behavioral profile,
     a family x objective heatmap, per-objective bars, and a collapsible raw
     evidence table. Opens in any browser; no external assets.

  3. Console (print_summary) - the at-a-glance terminal view, now with the
     target line and a compact family x objective heatmap.

Results are grouped BY OBJECTIVE so different attack goals stay separate.
Nothing here makes a hard security verdict; flags are heuristic hints.
"""

from __future__ import annotations

import html as _html
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from core.runner import AggResult
from core.synthesis import build_profile


# ---------------------------------------------------------------- console -----
def print_summary(results: List[AggResult], target: str = "unknown") -> None:
    if not results:
        from core import ui
        ui.warn("No results.")
        return

    from core import ui

    iters = results[0].iterations
    active = [r for r in results if not getattr(r, "skipped", False)]
    total_breaks = sum(r.breaks for r in active)
    total_valid = sum(r.valid for r in active)
    overall = (total_breaks / total_valid * 100) if total_valid else 0.0

    by_obj = {}
    skipped = []
    for r in results:
        if getattr(r, "skipped", False):
            skipped.append(r)
            continue
        techs = by_obj.setdefault(r.objective, {})
        b, v, ineff = techs.get(r.technique, (0, 0, 0))
        techs[r.technique] = (b + r.breaks, v + r.valid, ineff + r.ineffective)

    from core.models import OracleType
    from jailbreaks.probes import PROBES
    heuristic = any(p.oracle_type == OracleType.HEURISTIC_HINT for p in PROBES)

    ui.info(f"Target: [white]{target}[/white]")
    ui.print_objective_tables(by_obj, overall, total_breaks, total_valid, iters,
                              heuristic=heuristic)

    profile = build_profile(results, target=target)
    ui.print_heatmap(profile)

    if skipped:
        ui.print_skipped(skipped)


# ------------------------------------------------------------------- JSON -----
def write_json(results: List[AggResult], out_dir: str = "reports",
               target: str = "unknown") -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(out_dir) / f"run-{ts}.json"
    iters = results[0].iterations if results else 0

    by_obj = defaultdict(list)
    for r in results:
        by_obj[r.objective].append(r.to_dict())

    profile = build_profile(results, target=target)

    payload = {
        "generated_at": ts,
        "target": target,
        "iterations": iters,
        "summary": {
            "pairs": len(results),
            "total_breaks": sum(r.breaks for r in results),
            "total_valid": sum(r.valid for r in results),
            "total_errors": sum(r.errors for r in results),
            "total_ineffective": sum(r.ineffective for r in results),
        },
        "behavioral_profile": profile,
        "by_objective": dict(by_obj),
        "results": [r.to_dict() for r in results],
    }
    path.write_text(json.dumps(payload, indent=2))
    return str(path)


# ------------------------------------------------------------------- HTML -----
def write_html(results: List[AggResult], out_dir: str = "reports",
               target: str = "unknown") -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(out_dir) / f"report-{ts}.html"
    profile = build_profile(results, target=target)
    path.write_text(_render_html(profile, results, ts, target))
    return str(path)


def _heat_color(rate: float, ineffective: bool = False) -> str:
    if ineffective:
        return "#1b3a4b"
    if rate <= 0:
        return "#0e1a12"
    if rate < 34:
        return "#3a2f0b"
    if rate < 67:
        return "#5c3a0b"
    return "#5c160b"


def _mt_prompt(s):
    turns = s.get("turns", [])
    return turns[0].get("prompt", "") if turns else ""


def _mt_resp(s):
    turns = s.get("turns", [])
    return turns[-1].get("response", "") if turns else ""


def _render_html(profile: dict, results, ts: str, target: str) -> str:
    families = sorted(profile["by_family"].keys())
    objectives = sorted(profile["by_objective"].keys())
    matrix = profile["matrix"]
    totals = profile["totals"]

    cell_w, cell_h = 120, 30
    # Size padding to the longest labels so rotated headers and family names
    # never overflow the SVG bounds (the previous fixed 90/200 clipped them).
    longest_obj = max((len(o) for o in objectives), default=0)
    longest_fam = max((len(f) for f in families), default=0)
    import math
    angle = 32  # header rotation in degrees
    # vertical room a rotated label needs ~= its pixel length * sin(angle)
    char_px = 7.0
    pad_t = int(longest_obj * char_px * math.sin(math.radians(angle))) + 28
    pad_l = int(longest_fam * char_px) + 24
    rows_svg = []
    for ri, fam in enumerate(families):
        y = pad_t + ri * cell_h
        rows_svg.append(
            f'<text x="{pad_l-8}" y="{y+cell_h/2+4}" text-anchor="end" '
            f'class="lbl">{_html.escape(fam)}</text>')
        for ci, obj in enumerate(objectives):
            x = pad_l + ci * cell_w
            cell = matrix.get(fam, {}).get(obj, {})
            valid = cell.get("valid", 0)
            ineff = cell.get("ineffective", 0)
            breaks = cell.get("breaks", 0)
            rate = (breaks / valid * 100) if valid else 0.0
            closed = (valid == 0 and ineff > 0)
            color = _heat_color(rate, ineffective=closed)
            label = "n/a" if closed else (f"{rate:.0f}%" if valid else "·")
            rows_svg.append(
                f'<rect x="{x}" y="{y}" width="{cell_w-2}" height="{cell_h-2}" '
                f'fill="{color}" stroke="#0a0f0a"/>'
                f'<text x="{x+cell_w/2}" y="{y+cell_h/2+4}" text-anchor="middle" '
                f'class="cell">{label}</text>')
    # Column headers: anchored at the cell's left edge, rotated up-right from the
    # baseline just above the first row, so long labels rise into the padded
    # top area instead of spilling past the chart's left/top edges.
    for ci, obj in enumerate(objectives):
        x = pad_l + ci * cell_w + 6
        y = pad_t - 6
        rows_svg.append(
            f'<text x="{x}" y="{y}" text-anchor="start" class="colhdr" '
            f'transform="rotate(-{angle} {x} {y})">{_html.escape(obj)}</text>')
    svg_h = pad_t + len(families) * cell_h + 20
    svg_w = pad_l + len(objectives) * cell_w + 20
    heatmap_svg = (f'<svg viewBox="0 0 {svg_w} {svg_h}" width="100%" '
                   f'preserveAspectRatio="xMinYMin meet" class="heat">'
                   + "".join(rows_svg) + "</svg>")

    bars = []
    for obj in objectives:
        v = profile["by_objective"][obj]
        rate = v["flag_rate"]
        bars.append(
            f'<div class="bar-row"><span class="bar-lbl">{_html.escape(obj)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{max(rate,1.5)}%"></span></span>'
            f'<span class="bar-val">{rate:.0f}% '
            f'<em>({v["breaks"]}/{v["valid"]})</em></span></div>')
    bars_html = "".join(bars)

    if profile["top_findings"]:
        findings = "".join(
            f'<li><b>{_html.escape(t["family"])}</b> &mdash; flagged '
            f'{t["flagged"]}/{t["of"]} ({t["flag_rate"]:.0f}%)</li>'
            for t in profile["top_findings"])
    else:
        findings = '<li class="none">No family drew a flag on this run.</li>'

    closed = (", ".join(_html.escape(c) for c in profile["closed_channels"])
              or "none detected")

    rows = []
    for r in results:
        for s in (r.samples or []):
            verdict = s.get("verdict", "")
            if verdict not in ("FLAGGED", "VULNERABLE", "INEFFECTIVE"):
                continue
            prompt = _html.escape((s.get("prompt", "") or _mt_prompt(s))[:300])
            resp = _html.escape((s.get("response", "") or _mt_resp(s))[:300])
            ev = _html.escape(s.get("evidence", ""))
            vclass = verdict.lower()
            rows.append(
                f'<tr class="{vclass}"><td>{_html.escape(r.technique)}</td>'
                f'<td>{_html.escape(r.objective)}</td>'
                f'<td><span class="v {vclass}">{verdict}</span></td>'
                f'<td class="mono">{prompt}</td><td class="mono">{resp}</td>'
                f'<td class="ev">{ev}</td></tr>')
    evidence_rows = "".join(rows) or (
        '<tr><td colspan="6" class="none">No flagged, broken, or ineffective '
        'responses to show.</td></tr>')

    narrative = _html.escape(profile["narrative"])

    return _HTML_TEMPLATE.format(
        target=_html.escape(target), ts=ts,
        pairs=totals["pairs"], flagged=totals["flagged"],
        valid=totals["valid"], ineffective=totals["ineffective"],
        errors=totals["errors"], rate=totals["overall_flag_rate"],
        narrative=narrative, heatmap=heatmap_svg, bars=bars_html,
        findings=findings, closed=closed, evidence=evidence_rows)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JB-RT recon report &mdash; {target}</title>
<style>
  :root {{
    --bg:#070a07; --panel:#0d130d; --ink:#cfe8cf; --dim:#6f8a6f;
    --line:#1c2a1c; --acc:#5ef08a; --amber:#e0a93b; --red:#ff5c4d;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:"SFMono-Regular",ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace;
    font-size:14px; line-height:1.55; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:32px 24px 80px; }}
  header {{ border:1px solid var(--line); background:var(--panel);
    padding:20px 24px; border-radius:8px; position:relative; overflow:hidden; }}
  header::before {{ content:""; position:absolute; inset:0;
    background:repeating-linear-gradient(0deg,transparent 0 3px,rgba(94,240,138,.02) 3px 4px);
    pointer-events:none; }}
  h1 {{ font-size:15px; letter-spacing:3px; margin:0 0 4px; color:var(--acc);
    text-transform:uppercase; }}
  .target {{ font-size:20px; color:var(--ink); word-break:break-all; margin:2px 0; }}
  .meta {{ color:var(--dim); font-size:12px; }}
  section {{ margin-top:28px; }}
  h2 {{ font-size:12px; letter-spacing:2px; text-transform:uppercase;
    color:var(--dim); border-bottom:1px solid var(--line); padding-bottom:6px; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:12px; margin:16px 0; }}
  .stat {{ flex:1; min-width:120px; border:1px solid var(--line);
    background:var(--panel); border-radius:6px; padding:12px 14px; }}
  .stat .n {{ font-size:26px; color:var(--acc); }}
  .stat.amber .n {{ color:var(--amber); }} .stat.red .n {{ color:var(--red); }}
  .stat .k {{ font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }}
  .narrative {{ border-left:3px solid var(--acc); background:var(--panel);
    padding:14px 18px; border-radius:0 6px 6px 0; color:var(--ink); }}
  .heat {{ background:var(--panel); border:1px solid var(--line);
    border-radius:6px; padding:10px; }}
  .heat .lbl {{ fill:var(--ink); font-size:12px; font-family:inherit; }}
  .heat .colhdr {{ fill:var(--dim); font-size:11px; font-family:inherit; }}
  .heat .cell {{ fill:#dfeedf; font-size:11px; font-family:inherit; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin:7px 0; }}
  .bar-lbl {{ width:180px; color:var(--ink); font-size:12px; }}
  .bar-track {{ flex:1; height:14px; background:#0a120a; border:1px solid var(--line);
    border-radius:3px; overflow:hidden; }}
  .bar-fill {{ display:block; height:100%; background:linear-gradient(90deg,var(--amber),var(--red)); }}
  .bar-val {{ width:120px; text-align:right; font-size:12px; color:var(--dim); }}
  .bar-val em {{ color:var(--dim); font-style:normal; }}
  ul.findings {{ list-style:none; padding:0; }}
  ul.findings li {{ padding:8px 12px; border:1px solid var(--line);
    background:var(--panel); border-radius:5px; margin:6px 0; }}
  ul.findings .none, td.none {{ color:var(--dim); }}
  .closed {{ color:var(--amber); }}
  details {{ margin-top:14px; }}
  summary {{ cursor:pointer; color:var(--acc); font-size:12px;
    letter-spacing:1px; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:12px; }}
  th, td {{ text-align:left; padding:7px 9px; border-bottom:1px solid var(--line);
    vertical-align:top; }}
  th {{ color:var(--dim); text-transform:uppercase; font-size:11px; letter-spacing:1px; }}
  td.mono {{ font-size:11px; color:var(--dim); max-width:280px; word-break:break-word; }}
  td.ev {{ color:var(--ink); max-width:220px; word-break:break-word; }}
  .v {{ padding:1px 7px; border-radius:3px; font-size:11px; }}
  .v.flagged {{ background:#3a2f0b; color:var(--amber); }}
  .v.vulnerable {{ background:#5c160b; color:var(--red); }}
  .v.ineffective {{ background:#1b3a4b; color:#7fd0e0; }}
  tr.flagged td {{ background:rgba(224,169,59,.04); }}
  footer {{ margin-top:40px; color:var(--dim); font-size:11px;
    border-top:1px solid var(--line); padding-top:14px; }}
</style></head>
<body><div class="wrap">
  <header>
    <h1>Jailbreak Robustness Tester &mdash; Recon Report</h1>
    <div class="target">{target}</div>
    <div class="meta">generated {ts} &middot; behavioral mapping sweep</div>
  </header>

  <section>
    <h2>Behavioral profile</h2>
    <p class="narrative">{narrative}</p>
    <div class="stats">
      <div class="stat"><div class="n">{pairs}</div><div class="k">pairs swept</div></div>
      <div class="stat amber"><div class="n">{flagged}</div><div class="k">flagged for review</div></div>
      <div class="stat"><div class="n">{valid}</div><div class="k">executed</div></div>
      <div class="stat"><div class="n">{ineffective}</div><div class="k">ineffective</div></div>
      <div class="stat"><div class="n">{rate}%</div><div class="k">flag rate</div></div>
    </div>
  </section>

  <section>
    <h2>Family &times; objective heatmap</h2>
    {heatmap}
    <p class="meta">Cells show flag rate per technique family against each
    extraction objective. <span class="closed">Teal &ldquo;n/a&rdquo;</span> =
    channel closed (target could not decode that family).</p>
  </section>

  <section>
    <h2>Flag rate by objective</h2>
    {bars}
  </section>

  <section>
    <h2>Top findings</h2>
    <ul class="findings">{findings}</ul>
    <p class="meta">Closed channels: <span class="closed">{closed}</span></p>
  </section>

  <section>
    <h2>Evidence</h2>
    <details open><summary>flagged / broken / ineffective responses</summary>
    <table><thead><tr><th>family</th><th>objective</th><th>verdict</th>
      <th>prompt</th><th>response</th><th>why</th></tr></thead>
    <tbody>{evidence}</tbody></table></details>
  </section>

  <footer>
    Heuristic hints, not security verdicts &mdash; flagged responses are triage
    leads to read, not confirmed vulnerabilities. Test only systems you own or
    are authorized to assess.
  </footer>
</div></body></html>"""
