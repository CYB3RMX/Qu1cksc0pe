#!/usr/bin/python3

import json
import os
import sys
import time
import shutil
import re
import configparser
import subprocess
from datetime import datetime
from datetime import timezone
from urllib.parse import urlparse
import socket
import heapq

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


def _extract_meaningful_strings_from_text(text, max_strings=300, min_len=6, max_len=180):
    """
    Extract a bounded set of "meaningful" strings from temp.txt content.
    Not limited to IoCs; designed to preserve high-signal API/paths/keywords.
    """
    if not isinstance(text, str) or not text:
        return {"total_lines": 0, "kept": 0, "strings": []}

    try:
        max_strings = int(max_strings)
    except Exception:
        max_strings = 300
    try:
        min_len = int(min_len)
    except Exception:
        min_len = 6
    try:
        max_len = int(max_len)
    except Exception:
        max_len = 180

    max_strings = max(50, min(2000, max_strings))
    min_len = max(4, min(32, min_len))
    max_len = max(32, min(500, max_len))

    suspicious_keywords = (
        "powershell", "cmd.exe", "wscript", "cscript", "rundll32", "reg.exe", "schtasks",
        "msxml2", "xmlhttp", "adodb.stream", "shell.application", "createobject",
        "download", "http", "https", "user-agent",
        "hkey_", "hklm", "hkcu", "software\\", "system\\",
        "virtualbox", "vmware", "sandbox", "analysis", "debug",
        "encrypt", "decrypt", "aes", "rsa", "rc4", "base64",
        ".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd",
    )

    def score(s):
        sl = s.lower()
        sc = 0
        # Prefer longer (but cap).
        sc += min(len(s), 120) // 8
        if "\\" in s or "/" in s:
            sc += 3
        if ":" in s and ("\\" in s or "/" in s):
            sc += 2
        if any(k in sl for k in suspicious_keywords):
            sc += 6
        if any(ch in s for ch in ("(", ")", "!", "|", "&", ";")):
            sc += 1
        if s.count(".") >= 2:
            sc += 1
        return sc

    out = []
    seen = set()
    total = 0
    for line in text.splitlines():
        total += 1
        s = line.replace("\x00", "").strip()
        if not s:
            continue
        if len(s) < min_len:
            continue
        if len(s) > max_len:
            s = s[:max_len] + "...<truncated>..."
        # Drop trivial noise.
        if s in ("PK",):
            continue
        if sum(ch.isalnum() for ch in s) < (len(s) // 3):
            continue
        if len(set(s)) <= 2 and len(s) >= 12:
            continue

        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        # keep tuple form for fast top-k selection
        out.append((score(s), len(s), s))

    # Prefer top-k without sorting everything (faster for large temp.txt excerpts).
    top = heapq.nlargest(max_strings, out, key=lambda x: (x[0], x[1], x[2]))
    top.sort(key=lambda x: (-x[0], -x[1], x[2]))
    strings = [s for _, __, s in top]
    return {"total_lines": total, "kept": len(strings), "strings": strings}

def _summarize_meaningful_strings(strings):
    """
    Bucketize extracted strings so the LLM can reason over them easily and
    cite the exact strings as evidence.
    """
    if not isinstance(strings, list):
        strings = []

    buckets = {
        "execution": ("cmd.exe", "powershell", "wscript", "cscript", "rundll32", "mshta", "regsvr32", "schtasks", "shell.run"),
        "network": ("http://", "https://", "user-agent", "xmlhttp", "winhttp", "winsock", "socket", "connect", "download"),
        "persistence": ("currentversion\\run", "runonce", "startup", "schtasks", "service"),
        "registry": ("hkey_", "hkcu", "hklm", "software\\", "system\\"),
        "crypto": ("aes", "rsa", "rc4", "chacha", "decrypt", "encrypt", "base64"),
        "anti_analysis": ("vmware", "virtualbox", "sandbox", "analysis", "debug", "windbg", "ollydbg"),
        "office_macro": ("vbaproject", "thisworkbook", "autoopen", "workbook_open", "document_open", "createobject", "adodb.stream", "msxml2"),
        "file_indicators": (".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".tmp", ".dat", ".bin", ".pdb"),
        "paths": ("c:\\", "\\\\", "/home/", "/tmp/", "appdata", "temp", "system32"),
    }

    hits = {k: 0 for k in buckets}
    examples = {k: [] for k in buckets}

    for s in strings:
        try:
            st = str(s)
        except Exception:
            continue
        sl = st.lower()
        for b, keys in buckets.items():
            if any(k in sl for k in keys):
                hits[b] += 1
                if len(examples[b]) < 6:
                    examples[b].append(st[:220])

    hits = {k: v for k, v in hits.items() if v}
    examples = {k: v for k, v in examples.items() if v}
    return {"bucket_hits": hits, "bucket_examples": examples}


def _read_temp_txt(report_path):
    """
    Best-effort load of temp.txt (strings output) to enrich AI context.
    Reads bounded head+tail bytes to avoid huge prompts.
    """
    cand = []
    envp = (os.environ.get("SC0PE_TEMP_TXT_PATH") or os.environ.get("SC0PE_TEMP_TXT") or "").strip()
    if envp:
        cand.append(envp)
    cand.append(os.path.join(os.getcwd(), "temp.txt"))
    try:
        cand.append(os.path.join(os.path.dirname(os.path.abspath(report_path)), "temp.txt"))
    except Exception:
        pass

    path = ""
    for c in cand:
        if c and os.path.isfile(c):
            path = c
            break

    info = {"present": False, "path": "", "size_bytes": 0, "excerpt": "", "truncated": False}
    if not path:
        return info

    info["present"] = True
    info["path"] = os.path.abspath(path)
    try:
        info["size_bytes"] = os.path.getsize(path)
    except Exception:
        info["size_bytes"] = 0

    max_bytes = int(os.environ.get("SC0PE_TEMP_TXT_MAX_BYTES", str(2 * 1024 * 1024)))  # 2MB
    max_prompt_chars = int(os.environ.get("SC0PE_AI_TEMP_TXT_MAX_CHARS", "12000"))
    if max_bytes < 4096:
        max_bytes = 4096
    if max_prompt_chars < 1000:
        max_prompt_chars = 1000

    head = b""
    tail = b""
    try:
        with open(path, "rb") as f:
            if info["size_bytes"] and info["size_bytes"] > max_bytes:
                half = max_bytes // 2
                head = f.read(half)
                try:
                    f.seek(-half, os.SEEK_END)
                    tail = f.read(half)
                except Exception:
                    tail = b""
                info["truncated"] = True
            else:
                head = f.read(max_bytes)
                tail = b""
    except Exception:
        return info

    def dec(b):
        try:
            return b.decode("utf-8", errors="ignore").replace("\x00", "")
        except Exception:
            return ""

    head_t = dec(head)
    tail_t = dec(tail)
    combined = head_t
    if tail_t:
        combined = head_t + "\n...<snip>...\n" + tail_t

    if len(combined) > max_prompt_chars:
        info["excerpt"] = combined[:max_prompt_chars] + "\n...<truncated>..."
        info["truncated"] = True
    else:
        info["excerpt"] = combined
    return info


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
        "You are a expert malware analyst. Analyze the following JSON report summary produced by Qu1cksc0pe.\n"
        "Goal: provide concise, defensible inferences about likely behaviors, risk, and next steps.\n"
        "Rules:\n"
        "- Do not fabricate facts.\n"
        "- If evidence is weak, say so.\n"
        "- Prefer high-signal indicators (dynamic loading, network, persistence, anti-analysis, crypto, macros).\n"
        "- IMPORTANT: Use temp.txt-derived strings/signals under `summary.temp_txt` as evidence for your conclusions.\n"
        "- Mention exact strings when making claims (e.g., cite `cmd.exe`, `MSXML2.XMLHTTP`, registry paths, etc.).\n"
        "- ALSO: Extract IoCs from the evidence (temp.txt excerpt + meaningful strings + interesting patterns).\n"
        "  Include only IoCs that are explicitly present in evidence strings.\n"
        "- Keep the response concise.\n"
        "- The JSON includes `report_full` which contains the entire report.json content. Use it.\n"
        "- Do NOT output your internal thinking/chain-of-thought. Do not output <think> or <analysis> blocks.\n"
        "- Output format:\n"
        "  1) Overall Assessment (3-6 lines)\n"
        "  2) Key Evidence (bullets)\n"
        "  3) Hypotheses (bullets)\n"
        "  4) Recommended Next Steps (bullets)\n"
        "- IoCs output (machine-readable block at the end):\n"
        "  - Do NOT add a separate prose heading like `5) IoCs`.\n"
        "  - Do NOT use code blocks.\n"
        "  - End your response with exactly these markers and nothing else around them:\n"
        "    <<SC0PE_IOCS_JSON_START>>\n"
        "    {JSON object here}\n"
        "    <<SC0PE_IOCS_JSON_END>>\n"
        "  - The JSON must contain exactly one object with keys:\n"
        "    urls, domains, ips, emails, hashes, registry_keys, file_paths, mutexes, system_commands\n"
        "    Values must be arrays of strings (can be empty). Include ALL keys. No extra keys.\n"
        "  - IMPORTANT for `system_commands`: each array item must be a FULL command line as a single string.\n"
        "    Do NOT split command + arguments into separate array items.\n"
    )

    # Include a small subset of raw fields that are useful.
    isp = raw_report.get("interesting_string_patterns", {})
    if isinstance(isp, dict):
        # keep prompt bounded
        max_keys = int(os.environ.get("SC0PE_AI_INTERESTING_PATTERNS_MAX_KEYS", "25"))
        max_vals = int(os.environ.get("SC0PE_AI_INTERESTING_PATTERNS_MAX_VALUES", "30"))
        if max_keys < 0:
            max_keys = 0
        if max_vals < 0:
            max_vals = 0
        bounded = {}
        for k, v in list(isp.items())[:max_keys]:
            if isinstance(v, list):
                bounded[k] = v[:max_vals]
            else:
                bounded[k] = v
        isp = bounded
    else:
        isp = {}

    # Keep temp.txt evidence compact; large excerpts slow local LLM generation a lot.
    temp_txt_for_llm = summary.get("temp_txt", {})
    if isinstance(temp_txt_for_llm, dict) and temp_txt_for_llm:
        temp_txt_for_llm = dict(temp_txt_for_llm)
        try:
            ex_lim = int(os.environ.get("SC0PE_AI_TEMP_TXT_EXCERPT_CHARS", "2500"))
        except Exception:
            ex_lim = 2500
        if ex_lim <= 0:
            temp_txt_for_llm["excerpt"] = ""
        else:
            ex = temp_txt_for_llm.get("excerpt", "")
            if isinstance(ex, str) and len(ex) > ex_lim:
                temp_txt_for_llm["excerpt"] = ex[:ex_lim] + "\n...<truncated_for_llm>..."

    extra = {
        "analysis_type": analysis_type,
        "matched_rules": raw_report.get("matched_rules", [])[:10] if isinstance(raw_report.get("matched_rules", []), list) else [],
        "manifest": raw_report.get("manifest", {}),
        "decompilation": raw_report.get("decompilation", {}),
        "package_name": raw_report.get("package_name", ""),
        "app_name": raw_report.get("app_name", ""),
        "sdk_version": raw_report.get("sdk_version", ""),
        "main_activity": raw_report.get("main_activity", ""),
        "interesting_string_patterns": isp,
        "temp_txt": temp_txt_for_llm,
    }

    # User requirement: ALWAYS include the full report JSON in the LLM prompt.
    # Minify JSON to reduce tokens and speed up local LLM generation.
    body_obj = {
        "summary": summary,
        "extra": extra,
        "report_full": raw_report,
    }
    body = json.dumps(body_obj, ensure_ascii=True, separators=(",", ":"))
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
    temp = summary.get("temp_txt", {}) if isinstance(summary.get("temp_txt", {}), dict) else {}
    if temp.get("present"):
        ms = temp.get("meaningful_strings", [])
        mcount = len(ms) if isinstance(ms, list) else 0
        t.add_row("temp.txt", f"present size={temp.get('size_bytes',0)}B truncated={temp.get('truncated',False)} meaningful_strings={mcount}")
    else:
        t.add_row("temp.txt", "not found")
    print(t)

_IOCS_START = "<<SC0PE_IOCS_JSON_START>>"
_IOCS_END = "<<SC0PE_IOCS_JSON_END>>"

_CMD_START_TOKENS = {
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "bash", "sh", "zsh", "python", "python3", "wscript", "cscript",
    "rundll32", "reg", "reg.exe", "schtasks", "schtasks.exe", "mshta", "mshta.exe",
}
_CMD_START_SUFFIXES = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf")
_CMD_SEPARATORS = {"&&", "||", "|", ";", "&"}


def _normalize_system_commands(cmds):
    """
    Best-effort: if the model outputs tokenized commands (["cmd.exe", "/c", "whoami"]),
    merge them into full command lines while keeping the original token order.
    If commands already look like full lines, return as-is.
    """
    if not isinstance(cmds, list) or not cmds:
        return []
    toks = []
    for c in cmds:
        if c is None:
            continue
        s = str(c).replace("\x00", "").strip()
        if not s:
            continue
        toks.append(s)
    if not toks:
        return []

    # If most items already contain whitespace, they likely are full command lines.
    has_ws = sum(1 for t in toks if any(ch.isspace() for ch in t))
    if has_ws / max(1, len(toks)) >= 0.6:
        return toks

    def is_cmd_start(t):
        tl = t.lower()
        if tl in _CMD_START_TOKENS:
            return True
        if tl.endswith(_CMD_START_SUFFIXES):
            return True
        if "\\" in t or "/" in t:
            # likely a path to an executable/script
            if any(tl.endswith(s) for s in _CMD_START_SUFFIXES):
                return True
        return False

    out = []
    cur = ""
    for t in toks:
        # Keep commands single-line in UI; preserve visible escapes.
        t_vis = t.replace("\r", "\\r").replace("\n", "\\n").strip()
        if not t_vis:
            continue
        if is_cmd_start(t_vis) and cur:
            out.append(cur.strip())
            cur = t_vis
            continue
        if t_vis in _CMD_SEPARATORS:
            if cur:
                cur = cur.rstrip() + f" {t_vis} "
            else:
                cur = t_vis + " "
            continue
        if not cur:
            cur = t_vis
        else:
            cur += " " + t_vis
    if cur.strip():
        out.append(cur.strip())
    return out


def _extract_llm_iocs(text):
    """
    Parse IoCs from the LLM output.
    Expected format: a JSON object between <<SC0PE_IOCS_JSON_START>> and <<SC0PE_IOCS_JSON_END>>.
    Returns {} on failure.
    """
    if not isinstance(text, str) or not text:
        return {}

    js = ""
    if _IOCS_START in text and _IOCS_END in text:
        try:
            a = text.rfind(_IOCS_START)
            b = text.rfind(_IOCS_END)
            if a >= 0 and b > a:
                mid = text[a + len(_IOCS_START) : b].strip()
                # keep only the first JSON object in this region
                lb = mid.find("{")
                rb = mid.rfind("}")
                if lb >= 0 and rb > lb:
                    js = mid[lb : rb + 1].strip()
        except Exception:
            js = ""

    if not js:
        # Last resort: grab the last {...} region.
        lb = text.rfind("{")
        rb = text.rfind("}")
        if lb >= 0 and rb > lb:
            js = text[lb : rb + 1].strip()

    if not js:
        return {}
    try:
        obj = json.loads(js)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    wanted = ["urls", "domains", "ips", "emails", "hashes", "registry_keys", "file_paths", "mutexes", "system_commands"]
    # Prevent accidentally parsing an unrelated JSON object.
    if not any(k in obj for k in wanted):
        return {}
    if any(k not in wanted for k in obj.keys()):
        return {}
    out = {}
    for k in wanted:
        v = obj.get(k, [])
        if isinstance(v, list):
            out[k] = [str(x) for x in v if str(x).strip()]
        else:
            out[k] = []
    # Drop unexpected keys by reconstructing.
    out["system_commands"] = _normalize_system_commands(out.get("system_commands", []))
    return out


def _strip_llm_iocs_block(text):
    if not isinstance(text, str) or not text:
        return text
    if _IOCS_START in text and _IOCS_END in text:
        a = text.rfind(_IOCS_START)
        b = text.rfind(_IOCS_END)
        if a >= 0 and b > a:
            return (text[:a] + text[b + len(_IOCS_END) :]).strip()
    return text


_THINK_TAG_RE = re.compile(r"<\s*think\s*>.*?<\s*/\s*think\s*>", re.IGNORECASE | re.DOTALL)
_ANALYSIS_TAG_RE = re.compile(r"<\s*analysis\s*>.*?<\s*/\s*analysis\s*>", re.IGNORECASE | re.DOTALL)


def _strip_llm_thinking(text):
    """
    Remove model "thinking"/chain-of-thought content from output for both screen and report.
    Handles common patterns:
      - <think>...</think>
      - <analysis>...</analysis>
      - Leading "Thinking:"/"Analysis:" sections before the numbered output
    """
    if not isinstance(text, str) or not text:
        return text

    t = _THINK_TAG_RE.sub("", text)
    t = _ANALYSIS_TAG_RE.sub("", t)

    # Remove any leftover tag-only lines.
    t = "\n".join(
        ln for ln in t.splitlines()
        if ln.strip().lower() not in ("<think>", "</think>", "<analysis>", "</analysis>")
    )

    # Some models print "Thinking:" blocks in plain text. If present, strip until the expected output begins.
    lines = t.splitlines()
    out = []
    skipping = False

    def is_start_of_output(ln):
        s = (ln or "").strip().lower()
        return s.startswith("1)") or s.startswith("1.") or s.startswith("overall assessment")

    for ln in lines:
        sl = (ln or "").strip().lower()
        if not skipping:
            # Only trigger on explicit headings, to avoid removing legitimate content.
            if (sl.startswith("thinking") or sl.startswith("analysis") or sl.startswith("chain-of-thought") or sl.startswith("thought process")) and (
                ":" in sl or sl.startswith("#")
            ):
                skipping = True
                continue
            out.append(ln)
        else:
            if is_start_of_output(ln):
                skipping = False
                out.append(ln)
            else:
                continue

    return "\n".join(out).strip()


def _strip_trailing_empty_iocs_heading(text):
    """
    Some models still emit a trailing `5) IoCs` line even when IoCs are provided
    only in the machine-readable JSON block (which we strip). Remove that empty
    heading if it is the last non-empty line.
    """
    if not isinstance(text, str) or not text:
        return text
    lines = text.splitlines()
    while lines and lines[-1].strip() == "":
        lines.pop()
    if not lines:
        return ""
    last = lines[-1].strip().lower()
    if last.startswith("5") and "ioc" in last and len(last) <= 40:
        lines.pop()
        while lines and lines[-1].strip() == "":
            lines.pop()
    return "\n".join(lines).strip()


def _print_llm_iocs_panel(llm_iocs):
    if not isinstance(llm_iocs, dict) or not llm_iocs:
        return
    # Render IoCs as a table (separate "textbox" output section).
    wanted = ["system_commands", "urls", "domains", "ips", "emails", "hashes", "registry_keys", "file_paths", "mutexes"]
    any_vals = any(isinstance(llm_iocs.get(k, []), list) and llm_iocs.get(k, []) for k in wanted)
    if not any_vals:
        return

    if Table is None:
        print("\nLLM Extracted IoCs:")
        for k in wanted:
            vals = llm_iocs.get(k, [])
            if isinstance(vals, list) and vals:
                print(f"- {k} ({len(vals)}): {vals[:12]}")
        print("")
        return

    t = Table(title="LLM Extracted IoCs", title_style="bold cyan", title_justify="center", show_lines=False)
    t.add_column("Kind", style="bold cyan", no_wrap=True)
    t.add_column("Count", style="bold green", justify="right", no_wrap=True)
    t.add_column("Values (sample)", style="white")

    for k in wanted:
        vals = llm_iocs.get(k, [])
        if not isinstance(vals, list) or not vals:
            continue
        sample_n = 12
        sample = []
        for v in vals[:sample_n]:
            # Don't let embedded newlines split a single command/value.
            sample.append(str(v).replace("\r", "\\r").replace("\n", "\\n"))
        more = max(0, len(vals) - len(sample))
        cell = "\n".join(sample)
        if more:
            cell += f"\n...(+{more} more)"
        t.add_row(k, str(len(vals)), cell[:4000])

    print("\n")
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

    temp_info = _read_temp_txt(report_path)
    summary = _summarize_report(report)
    # Expose temp.txt excerpt to the LLM (bounded); this is the strings output from the last run.
    max_strings = int(os.environ.get("SC0PE_AI_TEMP_TXT_MAX_STRINGS", "300"))
    min_len = int(os.environ.get("SC0PE_AI_TEMP_TXT_MIN_LEN", "6"))
    max_len = int(os.environ.get("SC0PE_AI_TEMP_TXT_MAX_LEN", "180"))
    meaningful = _extract_meaningful_strings_from_text(
        temp_info.get("excerpt", ""),
        max_strings=max_strings,
        min_len=min_len,
        max_len=max_len,
    ) if temp_info.get("present") else {"total_lines": 0, "kept": 0, "strings": []}

    summary["temp_txt"] = {
        "present": bool(temp_info.get("present")),
        "path": temp_info.get("path", ""),
        "size_bytes": int(temp_info.get("size_bytes", 0) or 0),
        "truncated": bool(temp_info.get("truncated", False)),
        "meaningful_strings_total_lines": int(meaningful.get("total_lines", 0) or 0),
        "meaningful_strings": meaningful.get("strings", []),
        "meaningful_summary": _summarize_meaningful_strings(meaningful.get("strings", [])),
        # Keep excerpt too (bounded) for extra context.
        "excerpt": temp_info.get("excerpt", ""),
    }

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

    # Choose the fastest working engine; don't attempt HTTP if not reachable.
    engine = "heuristic"
    text = ""
    if has_ollama_http and requests is not None:
        engine = "ollama_http"
        try:
            text = _call_ollama_http(model=model, prompt=prompt)
        except Exception:
            text = ""
    if not text and has_ollama_cli:
        engine = "ollama_cli"
        try:
            text = _call_ollama_cli(model=model, prompt=prompt)
        except Exception:
            text = ""
    if not text:
        engine = "heuristic"
        text = _heuristic_fallback(summary)

    # Print AI output
    llm_iocs = _extract_llm_iocs(text)
    text_clean = _strip_llm_iocs_block(text)
    text_clean = _strip_llm_thinking(text_clean)
    text_clean = _strip_trailing_empty_iocs_heading(text_clean)
    if Panel is not None:
        print(Panel.fit(text_clean, title="AI Inferences", border_style="bold magenta"))
    else:
        print(text_clean)

    _print_llm_iocs_panel(llm_iocs)

    out_obj = {
        "report_file": os.path.abspath(report_path),
        "analysis_type": summary.get("analysis_type", ""),
        "llm_extracted_iocs": llm_iocs,
        "temp_txt": {
            "present": bool(temp_info.get("present")),
            "path": temp_info.get("path", ""),
            "size_bytes": int(temp_info.get("size_bytes", 0) or 0),
            "truncated": bool(temp_info.get("truncated", False)),
            "meaningful_strings_count": len(summary.get("temp_txt", {}).get("meaningful_strings", []) or []),
        },
        "engine": engine,
        "model": model if engine.startswith("ollama") else "",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "output": text_clean,
    }
    out_file = "sc0pe_ai_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=4)
    print(f"\n[bold magenta]>>>[bold white] AI report saved into: [bold blink yellow]{out_file}[white]\n")


if __name__ == "__main__":
    main()
