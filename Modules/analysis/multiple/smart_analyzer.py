#!/usr/bin/python3

import json
import os
import sys
import time
import shutil
import configparser
import subprocess
from datetime import datetime
from datetime import timezone
from urllib.parse import urlparse
import socket

try:
    import requests
except Exception:
    requests = None

try:
    from rich import print
    from rich.panel import Panel
    from rich.table import Table
except Exception:
    print = __builtins__["print"]
    Panel = None
    Table = None


def _read_sc0pe_path():
    try:
        return open(".path_handler", "r").read().strip()
    except Exception:
        return os.getcwd()


def _load_conf(sc0pe_path, path_seperator="/"):
    conf = configparser.ConfigParser()
    conf_path = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf"
    if os.path.exists(conf_path):
        conf.read(conf_path)
    return conf


def _get_ollama_model(conf):
    try:
        return conf["Ollama"]["model"].strip()
    except Exception:
        return "llama3"


def _ollama_endpoint():
    # Ollama default is http://127.0.0.1:11434
    return os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")

def _probe_ollama_http(timeout_s=0.6):
    try:
        parsed = urlparse(_ollama_endpoint())
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 11434
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def _call_ollama_http(model, prompt, timeout_s=120):
    if requests is None:
        raise RuntimeError("requests module not available")
    url = f"{_ollama_endpoint()}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }
    resp = requests.post(url, json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", "").strip()


def _call_ollama_cli(model, prompt, timeout_s=180):
    if not shutil.which("ollama"):
        raise RuntimeError("ollama binary not found")
    proc = subprocess.run(
        ["ollama", "run", model, prompt],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip().splitlines()[:3]
        raise RuntimeError("ollama run failed: " + " | ".join(msg))
    return (proc.stdout or "").strip()


def _safe_get(d, path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _summarize_report(report):
    analysis_type = report.get("analysis_type", "")
    if not analysis_type:
        # Fallbacks for other report formats (Windows/docs/etc.)
        analysis_type = report.get("document_type") or report.get("file_type") or report.get("target_os") or ""
    # Heuristic fallback for Linux static analyzer report format.
    if not analysis_type:
        if isinstance(report, dict) and ("machine_type" in report or "binary_entrypoint" in report or "number_of_sections" in report):
            analysis_type = "LINUX"
    analysis_type = str(analysis_type).upper()
    target = report.get("target_file", report.get("filename", ""))
    decomp = report.get("decompilation", {})
    matched_rules = report.get("matched_rules", [])
    source_summary = report.get("source_summary", {})

    risky_perms = []
    perms = report.get("permissions", [])
    # permissions stored as list of {perm: state}
    for it in perms:
        if isinstance(it, dict):
            for k, v in it.items():
                if str(v).lower() == "risky":
                    risky_perms.append(k)

    category_counts = source_summary.get("category_counts", {}) if isinstance(source_summary, dict) else {}
    top_categories = []
    if isinstance(category_counts, dict):
        top_categories = sorted(category_counts.items(), key=lambda kv: (-int(kv[1]), kv[0].lower()))[:8]

    # Pick top "interesting" findings (prefer non-third_party if present).
    findings = report.get("source_findings", [])
    interesting = []
    if isinstance(findings, list) and findings:
        # Some reports keep "third_party" boolean, some don't.
        def score(f):
            cats = f.get("categories", []) if isinstance(f, dict) else []
            pats = f.get("patterns", []) if isinstance(f, dict) else []
            third = bool(f.get("third_party", False)) if isinstance(f, dict) else False
            # Prefer non-third-party, more categories, more patterns.
            return (1 if third else 2, len(cats), len(pats))

        sorted_findings = sorted([f for f in findings if isinstance(f, dict)], key=score, reverse=True)
        for f in sorted_findings[:10]:
            interesting.append(
                {
                    "file": f.get("file_name", ""),
                    "categories": f.get("categories", [])[:8],
                    "patterns": f.get("patterns", [])[:12],
                }
            )

    doc_urls = report.get("extracted_urls", [])
    doc_encrypted = report.get("is_encrypted", None)
    doc_ole = report.get("is_ole_file", None)

    summary = {
        "analysis_type": analysis_type,
        "target": target,
        "decompilation": decomp,
        "matched_rule_count": len(matched_rules) if isinstance(matched_rules, list) else 0,
        "risky_permissions": risky_perms[:30],
        "top_categories": top_categories,
        "interesting_findings": interesting,
        "document": {
            "is_ole_file": doc_ole,
            "is_encrypted": doc_encrypted,
            "extracted_urls_count": len(doc_urls) if isinstance(doc_urls, list) else 0,
        },
    }
    return summary


def _build_prompt(summary, raw_report):
    # Keep prompt compact; raw report can be huge.
    analysis_type = summary.get("analysis_type", "")
    header = (
        "You are a malware analyst. Analyze the following JSON report summary produced by Qu1cksc0pe.\n"
        "Goal: provide concise, defensible inferences about likely behaviors, risk, and next steps.\n"
        "Rules:\n"
        "- Do not fabricate facts.\n"
        "- If evidence is weak, say so.\n"
        "- Prefer high-signal indicators (dynamic loading, network, persistence, anti-analysis, crypto, macros).\n"
        "- Output format:\n"
        "  1) Overall Assessment (3-6 lines)\n"
        "  2) Key Evidence (bullets)\n"
        "  3) Hypotheses (bullets)\n"
        "  4) Recommended Next Steps (bullets)\n"
    )

    # Include a small subset of raw fields that are useful.
    extra = {
        "analysis_type": analysis_type,
        "matched_rules": raw_report.get("matched_rules", [])[:10] if isinstance(raw_report.get("matched_rules", []), list) else [],
        "manifest": raw_report.get("manifest", {}),
        "decompilation": raw_report.get("decompilation", {}),
        "package_name": raw_report.get("package_name", ""),
        "app_name": raw_report.get("app_name", ""),
        "sdk_version": raw_report.get("sdk_version", ""),
        "main_activity": raw_report.get("main_activity", ""),
    }

    body = json.dumps({"summary": summary, "extra": extra}, indent=2)
    return header + "\nJSON:\n" + body


def _heuristic_fallback(summary):
    at = summary.get("analysis_type", "")
    risky = summary.get("risky_permissions", [])
    cats = summary.get("top_categories", [])
    interesting = summary.get("interesting_findings", [])

    lines = []
    lines.append(f"Overall Assessment: Heuristic analysis (no Ollama response). Type={at}.")
    if risky:
        lines.append(f"- Risky permissions detected: {len(risky)}")
    if cats:
        lines.append("- Top categories: " + ", ".join([f"{k}={v}" for k, v in cats[:6]]))
    if interesting:
        lines.append("- High-signal files (top): " + ", ".join([i.get("file", "") for i in interesting[:5] if i.get("file")]))
    lines.append("Recommended Next Steps:")
    lines.append("- Review top files listed above, focusing on dynamic loading/network/persistence.")
    lines.append("- Extract endpoints (URLs/domains) and correlate with runtime traffic if possible.")
    return "\n".join(lines)


def _print_summary_table(summary):
    if Table is None:
        return
    t = Table(title="AI Analyzer Input Summary")
    t.add_column("Field", style="bold cyan")
    t.add_column("Value", style="bold green")
    t.add_row("Type", str(summary.get("analysis_type", "")))
    t.add_row("Target", str(summary.get("target", ""))[:120])
    decomp = summary.get("decompilation", {})
    if isinstance(decomp, dict) and decomp:
        t.add_row("Decompile", f"attempted={decomp.get('attempted')} success={decomp.get('success')} err={decomp.get('error','')}")
    else:
        t.add_row("Decompile", "-")
    t.add_row("Matched Rules", str(summary.get("matched_rule_count", 0)))
    t.add_row("Risky Perms", str(len(summary.get("risky_permissions", []) or [])))
    print(t)


def main():
    if len(sys.argv) < 2:
        print("Usage: smart_analyzer.py <sc0pe_*_report.json>")
        sys.exit(1)

    report_path = sys.argv[1]
    if not os.path.exists(report_path):
        print(f"[!] Report file not found: {report_path}")
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    sc0pe_path = _read_sc0pe_path()
    path_seperator = "\\" if sys.platform == "win32" else "/"
    conf = _load_conf(sc0pe_path, path_seperator=path_seperator)
    model = _get_ollama_model(conf)

    summary = _summarize_report(report)

    prompt = _build_prompt(summary, report)

    # Warn user early if Ollama is not available.
    has_ollama_http = _probe_ollama_http()
    has_ollama_cli = bool(shutil.which("ollama"))
    if not has_ollama_http and not has_ollama_cli:
        print("[bold cyan][[bold red]![bold cyan]][white] Ollama not found or not reachable. Falling back to heuristic analysis.")
        print("[bold cyan][[bold red]*[bold cyan]][white] Install Ollama or set OLLAMA_HOST (default: http://127.0.0.1:11434).")
        print("[bold cyan][[bold red]*[bold cyan]][white] Heuristic analysis is running, please wait...")
    else:
        print("[bold cyan][[bold red]*[bold cyan]][white] AI query in progress, please wait...")

    engine = "ollama_http"
    text = ""
    try:
        text = _call_ollama_http(model=model, prompt=prompt)
        if not text:
            raise RuntimeError("empty response")
    except Exception:
        engine = "ollama_cli"
        try:
            text = _call_ollama_cli(model=model, prompt=prompt)
        except Exception:
            engine = "heuristic"
            text = _heuristic_fallback(summary)

    # Print AI output
    if Panel is not None:
        print(Panel.fit(text, title="AI Inferences", border_style="bold magenta"))
    else:
        print(text)

    out_obj = {
        "report_file": os.path.abspath(report_path),
        "analysis_type": summary.get("analysis_type", ""),
        "engine": engine,
        "model": model if engine.startswith("ollama") else "",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "output": text,
    }
    out_file = "sc0pe_ai_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=4)
    print(f"\n[bold magenta]>>>[bold white] AI report saved into: [bold blink yellow]{out_file}[white]\n")


if __name__ == "__main__":
    main()
