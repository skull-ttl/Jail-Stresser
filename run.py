#!/usr/bin/env python3
"""Jailbreak robustness tester.

Primary usage - give it a host, it detects the backend and runs:

    python run.py http://localhost:11434
    python run.py http://localhost:11434 --filter persona --verbose
    python run.py http://localhost:11434 --detect-only

Overrides:
    python run.py --mock                      # built-in vulnerable target
    python run.py --raw http://host/v1/chat/completions   # skip detection

Ethics / scope: test only systems you own or are authorized to test. The
bundled probes are benign (codeword/word/language rules); the tool measures
robustness to instruction-override, not extraction of harmful content.
"""

from __future__ import annotations

import argparse
import sys

from adapters.curl_adapter import CurlAdapter
from adapters.http_adapter import HTTPAdapter
from adapters.mock_adapter import MockAdapter
from adapters.ollama_adapter import OllamaAdapter
from core import ui
from core.detector import detect
from core.enumerator import enumerate_capabilities
from core.memcheck import check_memory
from core.report import print_summary, write_json, write_html
from core.runner import run
from jailbreaks.library import JAILBREAKS
from jailbreaks.probes import PROBES


def _prompt_for_curl() -> str:
    """Interactively collect a pasted cURL command (multi-line until EOF)."""
    ui.info("Paste the chat request as cURL, then press Ctrl-D (Linux/Mac) or "
            "Ctrl-Z then Enter (Windows).")
    ui.note("Get it from: browser devtools -> Network tab -> send a chat message "
            "-> right-click the request -> Copy -> Copy as cURL.")
    import sys
    try:
        data = sys.stdin.read()
    except KeyboardInterrupt:
        return ""
    return data.strip()


def build_adapter(args):
    """Return (adapter, label) or (None, None) on a fatal setup error."""
    if args.mock:
        return MockAdapter(), "mock (deliberately vulnerable)"

    # cURL import: from a file, or interactively pasted. Highest-priority path
    # because it's the explicit "here is the exact request" case.
    curl_text = None
    if args.curl:
        try:
            curl_text = open(args.curl).read()
        except OSError as e:
            ui.err(f"Could not read cURL file '{args.curl}': {e}")
            return None, None
    elif args.curl_paste:
        curl_text = _prompt_for_curl()
        if not curl_text:
            ui.err("No cURL provided.")
            return None, None
    if curl_text:
        adapter = CurlAdapter(curl_text, timeout=args.timeout)
        return adapter, f"curl: {adapter.describe()}"

    if args.raw:
        return HTTPAdapter(endpoint=args.raw, timeout=args.timeout), f"raw @ {args.raw}"

    with ui.spinner(f"Detecting backend at {args.host} ..."):
        det = detect(args.host, timeout=min(args.timeout, 15.0))
    ui.console.print(det.summary())
    if args.detect_only:
        return None, "detect-only"
    if det.chat_endpoint is None:
        ui.err("No chat endpoint found at this host. Is the server running and "
               "reachable? Try --raw <full-url> if you know the path.")
        return None, None

    if det.suggested_adapter == "ollama" and det.models_seen:
        if args.model and args.model in det.models_seen:
            model = args.model
        elif args.model:
            ui.warn(f"--model '{args.model}' not installed. Detected: "
                    f"{det.models_seen}. Using '{det.models_seen[0]}'.")
            model = det.models_seen[0]
        else:
            model = det.models_seen[0]
        return (OllamaAdapter(model=model, host=args.host, timeout=args.timeout),
                f"auto/ollama:{model} @ {args.host}")

    model = args.model or (det.models_seen[0] if det.models_seen else None)

    def build_payload(system_prompt, user_message, _model=model):
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_message})
        body = {"messages": messages, "stream": False}
        if _model:
            body["model"] = _model
        return body

    return (HTTPAdapter(endpoint=det.chat_endpoint, build_payload=build_payload,
                        timeout=args.timeout),
            f"auto/http:{model or '?'} @ {det.chat_endpoint}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Jailbreak robustness tester")
    ap.add_argument("host", nargs="?",
                    help="Backend host to detect and test, e.g. http://localhost:11434")
    ap.add_argument("--mock", action="store_true",
                    help="Override: run against the built-in vulnerable mock target")
    ap.add_argument("--raw", metavar="URL",
                    help="Override: skip detection and POST verbatim to this exact URL")
    ap.add_argument("--curl", metavar="FILE",
                    help="Build the target from a copied cURL command in FILE "
                         "(browser devtools -> Copy as cURL). Carries cookies/headers.")
    ap.add_argument("--curl-paste", action="store_true",
                    help="Interactively paste a cURL command to define the target")
    ap.add_argument("--detect-only", action="store_true",
                    help="Print the detection report and exit without testing")
    ap.add_argument("--model",
                    help="Force a specific model tag (otherwise the first detected one)")
    ap.add_argument("--json-only", action="store_true",
                    help="Skip the console summary, just write the JSON report")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Print every prompt sent and response received")
    ap.add_argument("--filter",
                    help="Only run jailbreaks whose id or technique contains this string")
    ap.add_argument("--iterations", "-n", type=int, default=1,
                    help="Run each (probe, jailbreak) pair N times for a break rate "
                         "(default 1). N>1 gives a real robustness rate.")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="Per-request timeout in seconds (default 120)")
    ap.add_argument("--skip-handshake", action="store_true",
                    help="Skip the pre-flight connectivity check (not recommended)")
    ap.add_argument("--enumerate", action="store_true",
                    help="Run capability enumeration (recon) before the suite")
    ap.add_argument("--enumerate-only", action="store_true",
                    help="Run capability enumeration and exit, without testing")
    ap.add_argument("--no-banner", action="store_true", help="Suppress the banner")
    ap.add_argument("--no-shuffle", action="store_true",
                    help="Run techniques in fixed file order (default: randomized)")
    ap.add_argument("--full", action="store_true",
                    help="Disable smart gates; run every technique even if a gate "
                         "would prune it as provably pointless")
    ap.add_argument("--fuzz", action="store_true",
                    help="Run baseline edge-value fuzzing (maps endpoint behaviour)")
    ap.add_argument("--fuzz-full", action="store_true",
                    help="Run the full edge-value fuzz set")
    ap.add_argument("--fuzz-only", action="store_true",
                    help="Run fuzzing and exit, without the jailbreak suite")
    args = ap.parse_args()

    if not args.no_banner:
        ui.show_banner()

    if not args.mock and not args.raw and not args.host and not args.curl and not args.curl_paste:
        ap.error("give a HOST to detect (e.g. http://localhost:11434), or use "
                 "--mock / --raw <url> / --curl <file> / --curl-paste")

    adapter, label = build_adapter(args)
    if adapter is None:
        return 0 if label == "detect-only" else 1

    # Pre-flight handshake.
    if not args.mock and not args.skip_handshake:
        with ui.spinner("Handshake: checking we can talk to the target ..."):
            hs = adapter.handshake()
        if hs.ok:
            ui.good(f"{hs.detail} ({hs.latency_ms:.0f} ms)")
            if hs.sample:
                ui.note(f"sample reply: {hs.sample!r}")
        else:
            ui.err(f"Handshake FAILED: {hs.detail}")
            if hs.sample:
                ui.note(f"raw body (truncated): {hs.sample}")
            ui.err("Aborting before the suite. Fix connectivity / payload shape, "
                   "or use --raw. (--skip-handshake to force.)")
            return 1

    # Capability enumeration.
    if args.enumerate or args.enumerate_only:
        with ui.spinner("Enumerating capabilities (self-reported recon) ..."):
            prof = enumerate_capabilities(adapter, verbose=args.verbose)
        ui.console.print(prof.summary())
        if args.enumerate_only:
            return 0

    # Edge-value fuzzing (recon): map endpoint behaviour under malformed/extreme
    # input. Raw observations, no verdicts - operator interprets.
    if args.fuzz or args.fuzz_full or args.fuzz_only:
        from core.fuzzer import run_fuzz
        full_fuzz = args.fuzz_full
        with ui.spinner(f"Fuzzing endpoint ({'full' if full_fuzz else 'baseline'} set) ..."):
            fuzz_obs = run_fuzz(adapter, full=full_fuzz)
        ui.print_fuzz(fuzz_obs)
        # Write fuzz observations to their own JSON.
        import json as _json
        from pathlib import Path as _Path
        from datetime import datetime as _dt, timezone as _tz
        _Path("reports").mkdir(parents=True, exist_ok=True)
        _ts = _dt.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")
        _fp = _Path("reports") / f"fuzz-{_ts}.json"
        _fp.write_text(_json.dumps([o.to_dict() for o in fuzz_obs], indent=2))
        ui.good(f"Fuzz observations written to: {_fp}")
        if args.fuzz_only:
            return 0

    jailbreaks = JAILBREAKS
    if args.filter:
        jailbreaks = [j for j in JAILBREAKS
                      if args.filter.lower() in j.id.lower()
                      or args.filter.lower() in j.technique.lower()]
        if not jailbreaks:
            ui.err(f"No jailbreaks matched '{args.filter}'. "
                   f"Available ids: {[j.id for j in JAILBREAKS]}")
            return 1

    # Memory gate for multi-turn.
    has_multiturn = any(j.is_multiturn for j in jailbreaks)
    if has_multiturn and not args.mock:
        with ui.spinner("Verifying context/memory (gates multi-turn) ..."):
            mem = check_memory(adapter, verbose=args.verbose)
        ui.console.print(mem.summary())
        if not mem.capable:
            before = len(jailbreaks)
            jailbreaks = [j for j in jailbreaks if not j.is_multiturn]
            ui.warn(f"Dropped {before - len(jailbreaks)} multi-turn technique(s) - "
                    f"target lacks reliable memory. Single-shot only.")
            if not jailbreaks:
                ui.err("Nothing left to run. Exiting.")
                return 1

    total = len(PROBES) * len(jailbreaks) * args.iterations
    ui.info(f"Target: [white]{label}[/white]")

    # Smart gates: prune provably-pointless work (control already breaks an
    # objective; target can't decode -> encoding techniques inoperable). Pruned
    # techniques still appear in the report as skipped. --full disables this.
    gates = None
    if not args.full and not args.mock:
        with ui.spinner("Smart gates: checking baseline + decode capability ..."):
            from core.gates import compute_gates
            control_jb = next((j for j in JAILBREAKS if j.technique == "control"), None)
            if control_jb is not None:
                gates = compute_gates(adapter, PROBES, control_jb)
        if gates is not None:
            if gates.unenforced_objectives:
                for obj, reason in gates.unenforced_objectives.items():
                    ui.warn(f"Gate: '{obj}' - {reason}; techniques will be skipped")
            if gates.cannot_decode:
                ui.warn(f"Gate: {gates.decode_detail}")
            if not gates.unenforced_objectives and not gates.cannot_decode:
                ui.good("Gates clear: no objectives unenforced, target can decode")
            ui.note("(use --full to run everything regardless of gates)")

    ui.info(f"Running up to [bold]{len(PROBES)}[/bold] probes x "
            f"[bold]{len(jailbreaks)}[/bold] jailbreaks x "
            f"[bold]{args.iterations}[/bold] iter (gated work is skipped, shown in report)")

    # Default view streams each exchange as a colored block (prompt, response,
    # verdict). -v makes responses full instead of truncated.
    results = run(adapter, PROBES, jailbreaks, iterations=args.iterations,
                  verbose=args.verbose, stream=True, total=total,
                  shuffle=not args.no_shuffle, gates=gates)

    if not args.json_only:
        print_summary(results, target=label)

    path = write_json(results, target=label)
    ui.good(f"JSON (machine/LLM) report: {path}")
    html_path = write_html(results, target=label)
    ui.good(f"HTML (human) report: {html_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
