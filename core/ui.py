"""Console UI / eye-candy (presentation only - never touches data).

All rich-based formatting lives here so the rest of the codebase stays plain.
Critical rule: this module decorates CONSOLE output only. It must never inject
color codes or formatting into the JSON report or any data structure - results
stay clean for downstream parsing.

Degrades gracefully: if stdout is piped/redirected, rich auto-disables color,
so reports captured to a file aren't polluted with ANSI escapes.
"""

from __future__ import annotations

from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# Verdict -> color, used consistently everywhere.
_VERDICT_STYLE = {
    "VULNERABLE": "bold red",
    "ROBUST": "bold green",
    "FLAGGED": "bold yellow",
    "CLEAN": "green",
    "ERROR": "dim yellow",
    "INEFFECTIVE": "dim cyan",   # attack never landed (e.g. not decoded) - not a
                                 # resist and not an error; visually muted because
                                 # it's "no real test happened here".
}


# === USER CUSTOM BANNER - DO NOT MODIFY THIS BLOCK ON REWRITES ===
BANNER = r"""
░▀▀█░█▀█░▀█▀░█░░░░░░░█▀▀░▀█▀░█▀▄░█▀▀░█▀▀░█▀▀░█▀▀░█▀▄
░░░█░█▀█░░█░░█░░░▄▄▄░▀▀█░░█░░█▀▄░█▀▀░▀▀█░▀▀█░█▀▀░█▀▄
░▀▀░░▀░▀░▀▀▀░▀▀▀░░░░░▀▀▀░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀
        J A I L B R E A K
            R O B U S T N E S S
                T E S T E R
                
"""
# === END USER CUSTOM BANNER ===


def show_banner(subtitle: str = "LLM jailbreak robustness tester") -> None:
    text = Text(BANNER, style="bold cyan")
    console.print(text)
    console.print(f"  [dim]{subtitle}[/dim]\n")


def info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}")


def good(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}")


def err(msg: str) -> None:
    console.print(f"[red][!][/red] {msg}")


def note(msg: str) -> None:
    console.print(f"    [dim]{msg}[/dim]")


def verdict_text(verdict: str) -> Text:
    return Text(verdict, style=_VERDICT_STYLE.get(verdict, "white"))


def panel(body: str, title: str, style: str = "cyan") -> None:
    console.print(Panel(body, title=title, border_style=style, box=box.ROUNDED))


@contextmanager
def spinner(msg: str):
    """Spinner for slow single operations (recon steps, handshake)."""
    with console.status(f"[cyan]{msg}[/cyan]", spinner="dots"):
        yield


# --- Progress over the test matrix -------------------------------------------
from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                           TimeElapsedColumn, MofNCompleteColumn)


def make_progress() -> Progress:
    """A progress bar sized for the slow per-request grind. Shows what it's
    doing right now plus an n/total counter and elapsed time."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    )


# --- Verdict line (verbose mode) ---------------------------------------------
def print_verdict_line(probe_id, jb_id, technique, mode, it, total_it,
                       verdict, evidence):
    v = verdict_text(verdict)
    console.print(
        f"  [dim]{probe_id}[/dim] · [white]{jb_id}[/white] "
        f"[dim]({technique}, {mode}, {it}/{total_it})[/dim]  ",
        v, f" [dim]{evidence}[/dim]", sep="")


_TRUNC = 220  # default response truncation; -v shows full

# Fixed label column width so everything aligns like the detection panel.
_LABEL_W = 9          # width of the label column ("sent", "reply", ...)
_INDENT = "  "        # left margin for blocks
_HANG = " " * (len(_INDENT) + _LABEL_W + 3)  # exactly matches _field prefix


def _clip(text: str, full: bool) -> str:
    text = (text or "").strip().replace("\n", " ")
    if full or len(text) <= _TRUNC:
        return text
    return text[:_TRUNC] + " […]"


def _field(label: str, value: str, value_style: str = "white") -> None:
    """Print one aligned 'label : value' line with wrapped continuation lines
    hang-indented under the value column (clean detection-panel look)."""
    import textwrap
    from rich.text import Text as _T

    prefix = f"{_INDENT}{label:<{_LABEL_W}} : "
    hang = " " * len(prefix)
    width = max(20, console.width - len(prefix))
    lines = textwrap.wrap(value, width=width) or [""]

    # First line: dim prefix + styled value.
    first = _T()
    first.append(prefix, style="dim")
    first.append(lines[0], style=value_style)
    console.print(first)
    # Continuation lines: hang indent, same value style.
    for cont in lines[1:]:
        t = _T()
        t.append(hang)
        t.append(cont, style=value_style)
        console.print(t)


def stream_single(idx, total, probe_id, objective, jb_id, technique,
                  prompt, response, verdict, evidence, latency_ms, full=False):
    """One aligned single-shot exchange block."""
    vcolor = _VERDICT_STYLE.get(verdict, "white")
    console.print("[dim]" + "─" * 64 + "[/dim]")
    console.print(f"[dim]{idx}/{total}[/dim]  [bold white]{jb_id}[/bold white] "
                  f"[dim]· {technique} · {objective} · {probe_id}[/dim]")
    _field("sent", _clip(prompt, full), "dim")
    _field("reply", _clip(response, full) + f"  ({latency_ms:.0f} ms)", "white")
    _field("verdict", f"{verdict}  ", vcolor)
    # append evidence dim on the verdict line
    console.print(f"{_HANG}[dim]{evidence}[/dim]")


def stream_multiturn(idx, total, probe_id, objective, jb_id, technique,
                     turns_detail, verdict, evidence, full=False):
    """One aligned multi-turn exchange block."""
    vcolor = _VERDICT_STYLE.get(verdict, "white")
    console.print("[dim]" + "─" * 64 + "[/dim]")
    console.print(f"[dim]{idx}/{total}[/dim]  [bold white]{jb_id}[/bold white] "
                  f"[dim]· {technique} · {objective} · {probe_id} · multi-turn[/dim]")
    for t in turns_detail:
        tn = t.get("turn", "?")
        tv = t.get("verdict", "ERR")
        tvcolor = _VERDICT_STYLE.get(tv, "yellow")
        _field(f"turn {tn}", _clip(t.get("prompt", ""), full), "dim")
        if t.get("error"):
            _field("reply", t["error"], "yellow")
        else:
            _field("reply", _clip(t.get("response", ""), full) + f"  [{tv}]", "white")
    _field("verdict", f"{verdict}  ", vcolor)
    console.print(f"{_HANG}[dim]{evidence}[/dim]")


# --- Final per-objective summary table ---------------------------------------
def print_objective_tables(by_obj: dict, overall_rate: float,
                           total_breaks: int, total_valid: int, iters: int,
                           heuristic: bool = False):
    """by_obj: {objective: {technique: (breaks, valid)}}"""
    rate_label = "Flagged for review" if heuristic else "Overall break rate"
    title = ("GENERIC EXTRACTION - REVIEW REQUIRED" if heuristic
             else "JAILBREAK ROBUSTNESS REPORT")
    col_label = "flagged" if heuristic else "break rate"
    header = Text()
    header.append(f"{rate_label}: ", style="bold")
    color = "red" if overall_rate >= 50 else ("yellow" if overall_rate > 0 else "green")
    header.append(f"{overall_rate:.0f}%", style=f"bold {color}")
    header.append(f"   ({total_breaks}/{total_valid} responses, {iters}x each)", style="dim")
    if heuristic:
        header.append("\nThese are HEURISTIC HINTS, not verdicts - read the "
                      "flagged responses yourself (false positives/negatives expected).",
                      style="dim yellow")
    console.print()
    console.print(Panel(header, title=title, border_style="cyan", box=box.DOUBLE))

    for obj in sorted(by_obj):
        techs = by_obj[obj]
        ob_breaks = sum(b for b, v, *_ in techs.values())
        ob_valid = sum(v for b, v, *_ in techs.values())
        ob_ineff = sum((rest[0] if rest else 0) for b, v, *rest in techs.values())
        ob_rate = (ob_breaks / ob_valid * 100) if ob_valid else 0.0
        ocolor = "red" if ob_rate >= 50 else ("yellow" if ob_rate > 0 else "green")

        ineff_note = f"  [dim cyan]+{ob_ineff} ineffective[/dim cyan]" if ob_ineff else ""
        table = Table(box=box.SIMPLE_HEAD, expand=False,
                      title=f"[bold]{obj}[/bold]  "
                            f"[{ocolor}]{ob_rate:.0f}%[/{ocolor}] "
                            f"[dim]({ob_breaks}/{ob_valid})[/dim]{ineff_note}",
                      title_justify="left")
        table.add_column("technique", style="white", no_wrap=True)
        table.add_column(col_label, justify="right")
        table.add_column("bar", justify="left")

        def _rate_of(t):
            b, v = techs[t][0], techs[t][1]
            return (b / v) if v else 0.0

        for tech in sorted(techs, key=lambda t: -_rate_of(t)):
            b, v, *rest = techs[tech]
            ineff = rest[0] if rest else 0
            if v == 0 and ineff > 0:
                # Every attempt was ineffective - the attack never landed even
                # once. Show this explicitly; it is NOT a resist.
                table.add_row(tech,
                              f"[dim cyan]n/a[/dim cyan] [dim]({ineff} ineffective)[/dim]",
                              "[dim cyan]· · · · · · · · · ·[/dim cyan]")
                continue
            rate = (b / v * 100) if v else 0.0
            tcolor = "red" if rate >= 50 else ("yellow" if rate > 0 else "green")
            bar = "█" * int(rate / 10) + "░" * (10 - int(rate / 10))
            ineff_tag = f" [dim cyan]+{ineff} ineff[/dim cyan]" if ineff else ""
            table.add_row(tech,
                          f"[{tcolor}]{rate:.0f}%[/{tcolor}] [dim]({b}/{v})[/dim]{ineff_tag}",
                          f"[{tcolor}]{bar}[/{tcolor}]")
        console.print(table)


def print_skipped(skipped):
    """Show gated/skipped techniques grouped by reason, so it's explicit what
    was NOT tested and why (transparency: pruning never hides silently)."""
    from collections import defaultdict
    by_reason = defaultdict(list)
    for r in skipped:
        by_reason[r.skip_reason].append(f"{r.technique}/{r.probe_id}")
    console.print()
    console.print(Panel(
        Text(f"{len(skipped)} technique-runs skipped by smart gates "
             f"(use --full to force them)", style="yellow"),
        title="SKIPPED (provably-pointless, not silently hidden)",
        border_style="yellow", box=box.ROUNDED))
    for reason, items in by_reason.items():
        console.print(f"  [yellow]reason:[/yellow] {reason}")
        console.print(f"    [dim]{len(items)} run(s): "
                      f"{', '.join(sorted(set(items))[:8])}"
                      f"{' ...' if len(set(items)) > 8 else ''}[/dim]")


def print_fuzz(observations):
    """Render raw fuzz observations - NO verdicts. The operator interprets.
    Groups by layer; shows status/latency/error/response excerpt per case."""
    console.print()
    console.print(Panel(
        Text("Raw endpoint behaviour under edge/malformed input. No verdicts - "
             "interpret these yourself (errors may be fine; leaked traces or "
             "long hangs may not).", style="dim"),
        title="FUZZ / BEHAVIOUR MAP", border_style="magenta", box=box.DOUBLE))

    for layer in ("param", "content"):
        rows = [o for o in observations if o.layer == layer]
        if not rows:
            continue
        title = ("PARAM layer (endpoint/server)" if layer == "param"
                 else "CONTENT layer (model input handling)")
        table = Table(box=box.SIMPLE_HEAD, title=f"[bold]{title}[/bold]",
                      title_justify="left", expand=True)
        table.add_column("case", style="white", no_wrap=True)
        table.add_column("HTTP", justify="right")
        table.add_column("ms", justify="right")
        table.add_column("error / response", overflow="fold")
        for o in rows:
            status = str(o.http_status) if o.http_status is not None else "-"
            scolor = ("green" if o.http_status and 200 <= o.http_status < 300
                      else "red" if o.http_status and o.http_status >= 400 else "white")
            detail = o.error if o.error else o.response_excerpt
            dcolor = "red" if o.error else "dim"
            table.add_row(o.description,
                          f"[{scolor}]{status}[/{scolor}]",
                          f"{o.latency_ms:.0f}",
                          f"[{dcolor}]{detail[:200]}[/{dcolor}]")
        console.print(table)


# --- Compact family x objective heatmap (terminal) ---------------------------
def print_heatmap(profile: dict):
    """Render a compact family x objective heatmap in the terminal from the
    synthesis profile. Green-ish empty, amber/red for flag rate, teal for a
    closed channel (all-ineffective)."""
    families = sorted(profile["by_family"].keys())
    objectives = sorted(profile["by_objective"].keys())
    if not families or not objectives:
        return
    matrix = profile["matrix"]

    # short objective headers (first 6 chars) to keep columns narrow
    short = {o: o[:6] for o in objectives}

    table = Table(box=box.SIMPLE_HEAD, title="[bold]family x objective heatmap[/bold]  "
                  "[dim](flag rate; 'n/a' = channel closed)[/dim]",
                  title_justify="left", expand=False)
    table.add_column("family", style="white", no_wrap=True)
    for o in objectives:
        table.add_column(short[o], justify="right")

    def cell_markup(cell):
        valid = cell.get("valid", 0)
        ineff = cell.get("ineffective", 0)
        breaks = cell.get("breaks", 0)
        if valid == 0 and ineff > 0:
            return "[dim cyan]n/a[/dim cyan]"
        if valid == 0:
            return "[dim]·[/dim]"
        rate = breaks / valid * 100
        color = "red" if rate >= 67 else ("yellow" if rate >= 34 else
                ("green" if rate > 0 else "dim"))
        return f"[{color}]{rate:.0f}%[/{color}]"

    for fam in families:
        row = [fam]
        for o in objectives:
            row.append(cell_markup(matrix.get(fam, {}).get(o, {})))
        table.add_row(*row)
    console.print()
    console.print(table)
