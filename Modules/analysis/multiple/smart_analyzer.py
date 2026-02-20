#!/usr/bin/python3

import json
import os
import sys
import time
import shutil
import re
import configparser
import subprocess
from contextlib import nullcontext
from datetime import datetime
from datetime import timezone
from urllib.parse import urlparse
import socket
import heapq
import hashlib
import ipaddress

try:
    import requests
except Exception:
    requests = None

try:
    from rich import print
    from rich.panel import Panel
    from rich.table import Table
    from rich.console import Console
except Exception:
    print = __builtins__["print"]
    Panel = None
    Table = None
    Console = None

RICH_CONSOLE = Console() if Console is not None else None
_URL_RE = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
_NIX_PATH_RE = re.compile(r"(?:/home/|/tmp/|/etc/|/var/|/usr/)[^\s\"']+")


def _read_sc0pe_path():
    try:
        return open(".path_handler", "r").read().strip()
    except Exception:
        return os.getcwd()


def _load_conf(sc0pe_path, path_seperator="/"):
    conf = configparser.ConfigParser()
    conf_path = f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf"
    if os.path.exists(conf_path):
        conf.read(conf_path, encoding="utf-8-sig")
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


def _env_int(name, default_value, min_value=None, max_value=None):
    val = default_value
    try:
        val = int(os.environ.get(name, str(default_value)))
    except Exception:
        val = default_value
    if min_value is not None and val < min_value:
        val = min_value
    if max_value is not None and val > max_value:
        val = max_value
    return val


def _env_bool(name, default_value=False):
    raw = os.environ.get(name)
    if raw is None:
        return bool(default_value)
    return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")


def _list_ollama_models_http(timeout_s=3):
    if requests is None:
        return []
    url = f"{_ollama_endpoint()}/api/tags"
    resp = requests.get(url, timeout=(2, timeout_s))
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        return []
    models = []
    for item in data.get("models", []) or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name:
            models.append(name)
    return models


def _list_ollama_models_cli(timeout_s=8):
    if not shutil.which("ollama"):
        return []
    proc = subprocess.run(
        ["ollama", "list"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        return []
    lines = (proc.stdout or "").splitlines()
    out = []
    for ln in lines[1:]:
        cols = re.split(r"\s{2,}|\t+", ln.strip())
        if not cols:
            continue
        name = cols[0].strip()
        if name and name.lower() != "name":
            out.append(name)
    return out


def _unique_preserve(items):
    seen = set()
    out = []
    for it in items:
        s = str(it).strip()
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _is_probably_cloud_model(model_name):
    mn = str(model_name).strip().lower()
    return (":cloud" in mn) or ("-cloud" in mn) or mn.endswith(" cloud")


def _extract_model_size_b(model_name):
    """
    Parse model size from names like:
      - gemma3:4b
      - qwen3-coder:32b-instruct
      - model-14b
    Returns 0 if unknown.
    """
    mn = str(model_name).strip().lower()
    m = re.search(r"(\d+(?:\.\d+)?)b\b", mn)
    if not m:
        return 0.0
    try:
        return float(m.group(1))
    except Exception:
        return 0.0


def _rank_model_candidates(candidates, prefer_local=True):
    """
    Keep all candidates, but prioritize likely-successful local models first.
    This avoids spending budget on known failing cloud aliases before local models.
    """
    pref_tokens = (os.environ.get("SC0PE_AI_MODEL_PRIORITY") or "gemma,llama,mistral,qwen,phi").strip().lower()
    pref_list = [x.strip() for x in pref_tokens.split(",") if x.strip()]

    scored = []
    for idx, name in enumerate(candidates):
        mn = str(name).strip()
        lmn = mn.lower()
        cloud_penalty = 1 if (_is_probably_cloud_model(lmn) and prefer_local) else 0
        size_b = _extract_model_size_b(lmn)
        # Unknown sizes are kept mid-priority; huge models are deprioritized.
        size_penalty = 0 if size_b == 0 else (1 if size_b <= 16 else (2 if size_b <= 40 else 3))
        token_rank = 99
        for i, tk in enumerate(pref_list):
            if tk in lmn:
                token_rank = i
                break
        scored.append((cloud_penalty, size_penalty, token_rank, idx, mn))

    scored.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    return [x[-1] for x in scored]


def _call_ollama_http(model, prompt, timeout_s=240, num_predict_override=None, with_meta=False):
    if requests is None:
        raise RuntimeError("requests module not available")
    url = f"{_ollama_endpoint()}/api/generate"
    max_predict = _env_int("SC0PE_AI_OLLAMA_NUM_PREDICT", 700, min_value=128, max_value=4096)
    if num_predict_override is not None:
        try:
            max_predict = int(num_predict_override)
        except Exception:
            pass
    num_ctx = _env_int("SC0PE_AI_OLLAMA_NUM_CTX", 8192, min_value=2048, max_value=65536)
    disable_think = _env_bool("SC0PE_AI_DISABLE_THINK", True)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": max_predict,
            "num_ctx": num_ctx,
            "stop": ["<<SC0PE_IOCS_JSON_END>>"],
        },
    }
    if disable_think:
        payload["think"] = False
    # Use split connect/read timeouts for better diagnostics on slow generations.
    connect_timeout = min(10, max(2, timeout_s // 8))
    resp = requests.post(url, json=payload, timeout=(connect_timeout, timeout_s))
    if resp.status_code >= 400 and disable_think:
        # Some backends may not support the `think` field. Retry once without it.
        fallback_payload = dict(payload)
        fallback_payload.pop("think", None)
        resp = requests.post(url, json=fallback_payload, timeout=(connect_timeout, timeout_s))
    resp.raise_for_status()
    data = resp.json() if resp.content else {}
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(str(data.get("error")).strip())
    meta = {
        "done_reason": str(data.get("done_reason", "") or "").strip().lower(),
        "response_len": 0,
    }
    response_text = str(data.get("response", "") or "").strip()
    meta["response_len"] = len(response_text)
    if response_text:
        return (response_text, meta) if with_meta else response_text
    if str(data.get("thinking", "") or "").strip():
        raise RuntimeError("empty response from model (thinking-only output)")
    raise RuntimeError("empty response from model")


def _call_ollama_cli(model, prompt, timeout_s=420):
    if not shutil.which("ollama"):
        raise RuntimeError("ollama binary not found")
    # Use stdin for large prompts to avoid ARG_MAX / "Argument list too long".
    proc = subprocess.run(
        ["ollama", "run", model],
        input=prompt,
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
    max_prompt_chars = int(os.environ.get("SC0PE_AI_TEMP_TXT_MAX_CHARS", "4000"))
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


def _parse_temp_txt(path):
    """
    Parse temp.txt in a compact way for LLM input:
    - stream file with byte/line limits
    - extract meaningful strings from sampled content
    - extract lightweight IoC candidates
    """
    out = {
        "parsed": False,
        "truncated": False,
        "total_lines": 0,
        "sampled_lines": 0,
        "read_bytes": 0,
        "meaningful_strings_total_lines": 0,
        "meaningful_strings": [],
        "meaningful_summary": {"bucket_hits": {}, "bucket_examples": {}},
        "parsed_iocs": {
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": [],
            "hashes": [],
            "file_paths": [],
        },
    }
    if not path or not os.path.isfile(path):
        return out

    max_bytes = _env_int("SC0PE_AI_TEMP_PARSE_MAX_BYTES", 2 * 1024 * 1024, min_value=64 * 1024, max_value=64 * 1024 * 1024)
    max_lines = _env_int("SC0PE_AI_TEMP_PARSE_MAX_LINES", 12000, min_value=500, max_value=200000)
    sample_cap = _env_int("SC0PE_AI_TEMP_SAMPLE_LINES", 2500, min_value=200, max_value=20000)
    ioc_cap = _env_int("SC0PE_AI_TEMP_IOC_CAP", 40, min_value=5, max_value=500)

    sampled = []
    ioc_sets = {k: set() for k in ("urls", "domains", "ips", "emails", "hashes", "file_paths")}
    read_bytes = 0
    total_lines = 0
    sampled_lines = 0
    truncated = False

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fp:
            for raw_line in fp:
                total_lines += 1
                line = raw_line.replace("\x00", "").strip()
                read_bytes += len(raw_line.encode("utf-8", errors="ignore"))
                if read_bytes > max_bytes or total_lines > max_lines:
                    truncated = True
                    break
                if not line:
                    continue

                # Keep a bounded representative sample for meaningful-string scoring.
                if sampled_lines < sample_cap:
                    sampled.append(line)
                    sampled_lines += 1

                # Lightweight IoC extraction directly from full scan window.
                for m in _URL_RE.findall(line):
                    if len(ioc_sets["urls"]) < ioc_cap:
                        ioc_sets["urls"].add(m)
                for m in _EMAIL_RE.findall(line):
                    if len(ioc_sets["emails"]) < ioc_cap:
                        ioc_sets["emails"].add(m)
                for m in _HASH_RE.findall(line):
                    if len(ioc_sets["hashes"]) < ioc_cap:
                        ioc_sets["hashes"].add(m)
                for m in _WIN_PATH_RE.findall(line):
                    if len(ioc_sets["file_paths"]) < ioc_cap:
                        ioc_sets["file_paths"].add(m)
                for m in _NIX_PATH_RE.findall(line):
                    if len(ioc_sets["file_paths"]) < ioc_cap:
                        ioc_sets["file_paths"].add(m)
                for m in _IP_RE.findall(line):
                    parts = m.split(".")
                    try:
                        ok = all(0 <= int(x) <= 255 for x in parts)
                    except Exception:
                        ok = False
                    if ok and len(ioc_sets["ips"]) < ioc_cap:
                        ioc_sets["ips"].add(m)
                for m in _DOMAIN_RE.findall(line):
                    if len(ioc_sets["domains"]) < ioc_cap:
                        ioc_sets["domains"].add(m.lower())
    except Exception:
        return out

    sample_text = "\n".join(sampled)
    max_strings = _env_int("SC0PE_AI_TEMP_TXT_MAX_STRINGS", 50, min_value=20, max_value=2000)
    min_len = _env_int("SC0PE_AI_TEMP_TXT_MIN_LEN", 6, min_value=4, max_value=64)
    max_len = _env_int("SC0PE_AI_TEMP_TXT_MAX_LEN", 180, min_value=32, max_value=1000)
    meaningful = _extract_meaningful_strings_from_text(sample_text, max_strings=max_strings, min_len=min_len, max_len=max_len)
    meaningful_summary = _summarize_meaningful_strings(meaningful.get("strings", []))

    # Prevent duplicate domains that are part of URLs.
    if ioc_sets["urls"]:
        for u in list(ioc_sets["urls"]):
            try:
                host = u.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0]
                if host:
                    ioc_sets["domains"].add(host.lower())
            except Exception:
                pass

    out.update({
        "parsed": True,
        "truncated": truncated,
        "total_lines": total_lines,
        "sampled_lines": sampled_lines,
        "read_bytes": read_bytes,
        "meaningful_strings_total_lines": int(meaningful.get("total_lines", 0) or 0),
        "meaningful_strings": meaningful.get("strings", []),
        "meaningful_summary": meaningful_summary,
        "parsed_iocs": {k: sorted(v)[:ioc_cap] for k, v in ioc_sets.items()},
    })
    return out


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


def _compact_for_llm(value, depth=0, max_depth=4, max_list_items=50, max_str=260):
    """
    Recursively compact large JSON structures to keep prompt size bounded.
    Preserves structure and samples while adding truncation metadata.
    """
    if depth > max_depth:
        if isinstance(value, (dict, list)):
            try:
                return {"__truncated__": True, "__type__": type(value).__name__, "__size__": len(value)}
            except Exception:
                return {"__truncated__": True, "__type__": type(value).__name__}
        return str(value)[:max_str]

    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[str(k)] = _compact_for_llm(v, depth=depth + 1, max_depth=max_depth, max_list_items=max_list_items, max_str=max_str)
        return out

    if isinstance(value, list):
        if len(value) <= max_list_items:
            return [_compact_for_llm(v, depth=depth + 1, max_depth=max_depth, max_list_items=max_list_items, max_str=max_str) for v in value]
        sampled = value[:max_list_items]
        out = [_compact_for_llm(v, depth=depth + 1, max_depth=max_depth, max_list_items=max_list_items, max_str=max_str) for v in sampled]
        out.append({"__truncated__": True, "__omitted_items__": len(value) - max_list_items})
        return out

    if isinstance(value, str):
        if len(value) > max_str:
            return value[:max_str] + "...<truncated>"
        return value

    return value


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
        "- IMPORTANT: Use parsed temp.txt signals under `summary.temp_txt` as evidence for your conclusions.\n"
        "- Mention exact strings when making claims (e.g., cite `cmd.exe`, `MSXML2.XMLHTTP`, registry paths, etc.).\n"
        "- ALSO: Extract IoCs from the evidence (parsed temp.txt IoCs + meaningful strings + interesting patterns).\n"
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

    # Keep temp.txt evidence compact; avoid shipping large raw excerpts by default.
    temp_txt_for_llm = summary.get("temp_txt", {})
    if isinstance(temp_txt_for_llm, dict) and temp_txt_for_llm:
        temp_txt_for_llm = dict(temp_txt_for_llm)
        include_excerpt = _env_bool("SC0PE_AI_INCLUDE_TEMP_EXCERPT", False)
        try:
            ex_lim = int(os.environ.get("SC0PE_AI_TEMP_TXT_EXCERPT_CHARS", "800"))
        except Exception:
            ex_lim = 800
        if (not include_excerpt) or ex_lim <= 0:
            temp_txt_for_llm["excerpt"] = ""
        else:
            ex = temp_txt_for_llm.get("excerpt", "")
            if isinstance(ex, str) and len(ex) > ex_lim:
                temp_txt_for_llm["excerpt"] = ex[:ex_lim] + "\n...<truncated_for_llm>..."

        # Bound parsed IoCs for prompt size.
        parsed_iocs = temp_txt_for_llm.get("parsed_iocs", {})
        if isinstance(parsed_iocs, dict):
            ioc_max = _env_int("SC0PE_AI_TEMP_IOC_PROMPT_MAX", 20, min_value=5, max_value=200)
            bounded_iocs = {}
            for k, v in parsed_iocs.items():
                if isinstance(v, list):
                    bounded_iocs[k] = v[:ioc_max]
                else:
                    bounded_iocs[k] = []
            temp_txt_for_llm["parsed_iocs"] = bounded_iocs

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

    # Include report JSON with size guard; very large raw JSON can cause empty LLM responses.
    max_report_chars = _env_int("SC0PE_AI_MAX_REPORT_CHARS", 180000, min_value=20000, max_value=2000000)
    compact_list_items = _env_int("SC0PE_AI_COMPACT_MAX_LIST_ITEMS", 40, min_value=5, max_value=500)
    compact_max_str = _env_int("SC0PE_AI_COMPACT_MAX_STR", 220, min_value=80, max_value=4000)
    compact_depth = _env_int("SC0PE_AI_COMPACT_MAX_DEPTH", 4, min_value=2, max_value=10)

    raw_min = json.dumps(raw_report, ensure_ascii=True, separators=(",", ":"))
    raw_len = len(raw_min)
    if raw_len <= max_report_chars:
        report_for_llm = raw_report
        report_meta = {"mode": "full", "original_chars": raw_len, "sha256": hashlib.sha256(raw_min.encode()).hexdigest()}
    else:
        report_for_llm = _compact_for_llm(
            raw_report,
            max_depth=compact_depth,
            max_list_items=compact_list_items,
            max_str=compact_max_str,
        )
        report_meta = {
            "mode": "compact",
            "original_chars": raw_len,
            "max_report_chars": max_report_chars,
            "sha256": hashlib.sha256(raw_min.encode()).hexdigest(),
            "compact_max_list_items": compact_list_items,
            "compact_max_str": compact_max_str,
            "compact_max_depth": compact_depth,
        }

    # Minify JSON to reduce tokens and speed up local LLM generation.
    body_obj = {
        "summary": summary,
        "extra": extra,
        "report_full": report_for_llm,
        "report_meta": report_meta,
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
_NON_DOMAIN_FILELIKE_TLDS = {
    # Config/data/markup
    "xml", "json", "yaml", "yml", "toml", "ini", "conf", "config", "cfg", "csv", "tsv", "txt", "log",
    # Executables/libraries/scripts
    "exe", "dll", "sys", "bin", "dat", "tmp", "ps1", "vbs", "vba", "vbe", "js", "jse", "wsf", "cmd", "bat", "sh", "py", "jar",
    "class", "dex", "apk", "elf", "so", "o", "obj", "pdb",
    # Office/document/archive/media extensions that often appear as filenames
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt", "ods", "odp", "eml", "msg",
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "msi", "msp", "iso",
    "png", "jpg", "jpeg", "gif", "bmp", "tiff", "svg", "ico", "webp",
    "mp3", "wav", "flac", "mp4", "mkv", "avi", "mov",
}
_COMMON_GTLDS_STRICT = {
    # High-frequency gTLDs seen in malware IoCs / threat feeds
    "com", "net", "org", "info", "biz", "name", "pro", "xyz", "top", "site", "online", "store", "shop",
    "app", "dev", "io", "me", "cc", "live", "link", "click", "work", "club", "pw", "win", "host", "space",
    "tech", "cloud", "services", "support", "today", "news", "blog", "agency", "digital", "media", "email",
    "world", "website", "monster", "finance", "trade", "download",
    # Infrastructure / platform
    "gov", "edu", "mil", "int", "arpa",
}
_NAMESPACE_DOMAIN_TOKENS = {
    "system", "microsoft", "mscorlib", "netstandard", "runtime", "visualbasic", "codedom",
    "compiler", "collections", "componentmodel", "configuration", "drawing", "resources",
    "windows", "forms", "interops", "interopservices", "threading", "linq", "sqlclient",
    "diagnostics", "reflections", "serialization", "cryptography", "web", "xml", "data",
    "generic", "point", "bitmap", "icon", "resourcereader",
}
_HEX_PREFIXED_NAMESPACE_RE = re.compile(r"^[0-9a-f]{6,}(system|microsoft|mscorlib|runtime|visualbasic)$", re.IGNORECASE)


def _clean_ioc_value(v):
    s = str(v or "").replace("\x00", "").strip()
    return s.strip(" \t\r\n\"'`[](){}<>.,;")


def _is_valid_domain(d):
    d = str(d or "").strip().lower().rstrip(".")
    if not d or len(d) > 253:
        return False
    if "://" in d or "/" in d or "@" in d or " " in d:
        return False
    parts = d.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    sld = parts[-2] if len(parts) >= 2 else ""
    registrable_label = sld

    # Reject .NET / namespace-like artifacts frequently hallucinated/extracted as domains.
    # Examples: system.core, microsoft.visualbasic, b03f...system.drawing.point
    if not _env_bool("SC0PE_AI_ALLOW_NAMESPACE_DOMAINS", False):
        ns_score = 0
        for p in parts:
            pl = p.lower()
            if pl in _NAMESPACE_DOMAIN_TOKENS or _HEX_PREFIXED_NAMESPACE_RE.fullmatch(pl):
                ns_score += 1
        # Require at least 2 matching labels or nearly all labels to be namespace-like.
        if ns_score >= 2 and ns_score >= max(2, len(parts) - 1):
            return False

    # Optional strict TLD gate to suppress random tokenized false-positives.
    # Allows all ccTLDs (2-letter) and a curated gTLD set by default.
    if _env_bool("SC0PE_AI_STRICT_TLD", True):
        if len(tld) != 2 and tld not in _COMMON_GTLDS_STRICT:
            return False

    # Handle common second-level public suffix patterns like *.com.tr
    if len(parts) >= 3 and sld in {"com", "net", "org", "gov", "edu", "mil", "ac", "co", "or", "ne", "go", "gen", "gob"}:
        registrable_label = parts[-3]
    # Reject file-like pseudo-domains such as sheet1.xml, workbook.xml, theme1.xml.
    # Can be overridden if needed.
    if (not _env_bool("SC0PE_AI_ALLOW_FILELIKE_TLDS", False)) and tld in _NON_DOMAIN_FILELIKE_TLDS:
        return False
    # Strict defaults to reduce FP on random split tokens like "1.cp", "ac.tl", "d.uml".
    allow_short_domains = _env_bool("SC0PE_AI_ALLOW_SHORT_DOMAINS", False)
    if not allow_short_domains:
        min_sld_len = _env_int("SC0PE_AI_MIN_SLD_LEN", 4, min_value=2, max_value=20)
        if len(registrable_label) < min_sld_len:
            return False
        if len(tld) < 2 or len(tld) > 24:
            return False
    for p in parts:
        if not p or len(p) > 63:
            return False
        if p.startswith("-") or p.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", p):
            return False
    return True


def _normalize_domain(d):
    d = str(d or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def _is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(str(ip).strip())
    except Exception:
        return False
    # Keep only routable hosts by default to reduce FP from placeholders/net addrs.
    if not getattr(ip_obj, "is_global", False):
        return False
    s = str(ip_obj)
    if s.endswith(".0") or s.endswith(".255"):
        return False
    return True


def _is_valid_file_path(p):
    p = str(p or "").strip()
    if not p:
        return False
    if re.match(r"^[A-Za-z]:\\", p):
        return True
    if p.startswith("\\\\"):  # UNC path
        return True
    if p.startswith("/"):  # Unix absolute
        return True
    return False


def _sanitize_llm_iocs(iocs):
    if not isinstance(iocs, dict):
        return {}
    wanted = ["urls", "domains", "ips", "emails", "hashes", "registry_keys", "file_paths", "mutexes", "system_commands"]
    out = {k: [] for k in wanted}
    for k in wanted:
        vals = iocs.get(k, [])
        if not isinstance(vals, list):
            continue
        seen = set()
        for raw in vals:
            s = _clean_ioc_value(raw)
            if not s:
                continue
            key = s.lower()
            if key in seen:
                continue
            if k == "urls":
                try:
                    u = urlparse(s)
                except Exception:
                    continue
                if u.scheme not in ("http", "https") or not u.netloc:
                    continue
            elif k == "domains":
                s = _normalize_domain(s)
                if not _is_valid_domain(s):
                    continue
                key = s
            elif k == "ips":
                if not _is_valid_ip(s):
                    continue
            elif k == "emails":
                if _EMAIL_RE.fullmatch(s) is None:
                    continue
            elif k == "hashes":
                if _HASH_RE.fullmatch(s) is None:
                    continue
            elif k == "file_paths":
                if not _is_valid_file_path(s):
                    continue
            seen.add(key)
            out[k].append(s)

    # Derive domains from valid URLs to improve quality.
    dseen = {d.lower() for d in out["domains"]}
    for u in out["urls"]:
        try:
            host = urlparse(u).hostname or ""
        except Exception:
            host = ""
        host = _normalize_domain(host)
        if host and _is_valid_domain(host) and host.lower() not in dseen:
            out["domains"].append(host)
            dseen.add(host.lower())

    out["system_commands"] = _normalize_system_commands(out.get("system_commands", []))
    return out


def _normalize_path_for_compare(p):
    s = str(p or "").strip().strip("\"'")
    if not s:
        return ""
    # Windows drive path
    if re.match(r"^[A-Za-z]:[\\/]", s):
        return s.replace("/", "\\").lower()
    # UNC path
    if s.startswith("\\\\"):
        return s.replace("/", "\\").lower()
    # Unix-like path
    if s.startswith("/"):
        try:
            return os.path.abspath(os.path.expanduser(s))
        except Exception:
            return s
    return s


def _filter_local_analysis_paths(iocs, summary, report_path):
    """
    Remove local analysis-environment paths from LLM IoCs
    (e.g., analyzed sample path on analyst machine).
    """
    if not isinstance(iocs, dict):
        return iocs
    if _env_bool("SC0PE_AI_KEEP_LOCAL_PATHS", False):
        return iocs

    filtered = dict(iocs)
    fp_list = filtered.get("file_paths", [])
    if not isinstance(fp_list, list) or not fp_list:
        return filtered

    exclude = set()
    try:
        tgt = str((summary or {}).get("target", "")).strip()
        if tgt:
            exclude.add(_normalize_path_for_compare(tgt))
    except Exception:
        pass
    try:
        exclude.add(_normalize_path_for_compare(os.path.abspath(report_path)))
    except Exception:
        pass
    try:
        tp = str(((summary or {}).get("temp_txt", {}) or {}).get("path", "")).strip()
        if tp:
            exclude.add(_normalize_path_for_compare(tp))
    except Exception:
        pass

    out_paths = []
    for p in fp_list:
        pn = _normalize_path_for_compare(p)
        if pn in exclude:
            continue
        out_paths.append(p)

    filtered["file_paths"] = out_paths
    return filtered


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
    elif _IOCS_START in text:
        # Best effort for outputs where end marker is missing/truncated.
        try:
            a = text.rfind(_IOCS_START)
            if a >= 0:
                mid = text[a + len(_IOCS_START) :].strip()
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
    return _sanitize_llm_iocs(out)


def _strip_llm_iocs_block(text):
    if not isinstance(text, str) or not text:
        return text
    if _IOCS_START in text and _IOCS_END in text:
        a = text.rfind(_IOCS_START)
        b = text.rfind(_IOCS_END)
        if a >= 0 and b > a:
            return (text[:a] + text[b + len(_IOCS_END) :]).strip()
    if _IOCS_START in text:
        # If end marker is missing (truncated output), remove trailing partial IoC block.
        a = text.rfind(_IOCS_START)
        if a >= 0:
            return text[:a].strip()
    return text


_THINK_TAG_RE = re.compile(r"<\s*think\s*>.*?<\s*/\s*think\s*>", re.IGNORECASE | re.DOTALL)
_ANALYSIS_TAG_RE = re.compile(r"<\s*analysis\s*>.*?<\s*/\s*analysis\s*>", re.IGNORECASE | re.DOTALL)
_THINK_FENCE_RE = re.compile(r"```(?:\w+)?\s*(?:think|thinking|analysis|reasoning)[^\n]*\n.*?\n```", re.IGNORECASE | re.DOTALL)
_FINAL_ANSWER_START_RE = re.compile(r"^\s*(?:\*+\s*)?(?:1[\).\s-]*)?(?:\*+\s*)?overall assessment\b", re.IGNORECASE)


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
    t = _THINK_FENCE_RE.sub("", t)

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
        if s.startswith("1)") or s.startswith("1.") or s.startswith("overall assessment"):
            return True
        # allow markdown headers
        if "overall assessment" in s and s.lstrip("#").strip().startswith("overall"):
            return True
        if "key evidence" in s and s.lstrip("#").strip().startswith("key"):
            return True
        if "hypotheses" in s and s.lstrip("#").strip().startswith("hypoth"):
            return True
        if "recommended next steps" in s and s.lstrip("#").strip().startswith("recommended"):
            return True
        if s.startswith("2)") or s.startswith("2.") or s.startswith("3)") or s.startswith("3.") or s.startswith("4)") or s.startswith("4."):
            return True
        return False

    def is_thinking_header(ln):
        sl = (ln or "").strip().lower()
        if not sl:
            return False
        # Explicit chain-of-thought labels
        keys = (
            "thinking", "analysis", "reasoning", "thought process", "chain-of-thought",
            "chain of thought", "deliberation", "brainstorm", "scratchpad",
        )
        if any(sl.startswith(k) for k in keys):
            # Require a delimiter so we don't strip normal sentences like "analysis shows ..."
            if ":" in sl or sl.startswith("#") or sl.endswith("...") or sl.endswith("…"):
                return True
        # Common phrasing
        if sl.startswith("let's think") or sl.startswith("lets think"):
            return True
        return False

    for ln in lines:
        sl = (ln or "").strip().lower()
        if not skipping:
            # Only trigger on explicit headings, to avoid removing legitimate content.
            if is_thinking_header(ln):
                skipping = True
                continue
            out.append(ln)
        else:
            if is_start_of_output(ln):
                skipping = False
                out.append(ln)
            else:
                continue

    cleaned = "\n".join(out).strip()

    # If the model emitted draft/thinking before the final structured answer,
    # keep only the last "Overall Assessment" block.
    try:
        lines2 = cleaned.splitlines()
        last_start = -1
        for i, ln in enumerate(lines2):
            # Strip markdown emphasis for robust matching.
            plain = ln.replace("**", "").replace("__", "").strip()
            if _FINAL_ANSWER_START_RE.match(plain):
                last_start = i
        if last_start > 0:
            cleaned = "\n".join(lines2[last_start:]).strip()
    except Exception:
        pass

    return cleaned


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


def _llm_output_looks_incomplete(text):
    """
    Heuristic check for truncated/incomplete final answer.
    """
    if not isinstance(text, str):
        return True
    t = text.strip()
    if not t:
        return True
    # If IoC block started but wasn't closed, generation was cut.
    if _IOCS_START in t and _IOCS_END not in t:
        return True
    low = t.lower()
    required = (
        "overall assessment",
        "key evidence",
        "hypotheses",
        "recommended next steps",
    )
    have = sum(1 for r in required if r in low)
    if have < 3:
        return True
    tail = t[-8:]
    bad_endings = ("- **", "- *", "-", "*", ":", "(", "[", "{")
    if any(t.endswith(be) for be in bad_endings):
        return True
    if tail.endswith("**") or tail.endswith("__"):
        return True
    return False


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
    temp_parsed = _parse_temp_txt(temp_info.get("path", "")) if temp_info.get("present") else {}
    summary = _summarize_report(report)
    summary["temp_txt"] = {
        "present": bool(temp_info.get("present")),
        "path": temp_info.get("path", ""),
        "size_bytes": int(temp_info.get("size_bytes", 0) or 0),
        "truncated": bool(temp_info.get("truncated", False) or bool(temp_parsed.get("truncated", False))),
        "parsed": bool(temp_parsed.get("parsed", False)),
        "read_bytes": int(temp_parsed.get("read_bytes", 0) or 0),
        "total_lines": int(temp_parsed.get("total_lines", 0) or 0),
        "sampled_lines": int(temp_parsed.get("sampled_lines", 0) or 0),
        "meaningful_strings_total_lines": int(temp_parsed.get("meaningful_strings_total_lines", 0) or 0),
        "meaningful_strings": temp_parsed.get("meaningful_strings", []),
        "meaningful_summary": temp_parsed.get("meaningful_summary", {"bucket_hits": {}, "bucket_examples": {}}),
        "parsed_iocs": temp_parsed.get("parsed_iocs", {}),
        # Keep excerpt too (bounded) for extra context.
        "excerpt": temp_info.get("excerpt", ""),
    }

    prompt = _build_prompt(summary, report)

    http_timeout_s = _env_int("SC0PE_AI_OLLAMA_HTTP_TIMEOUT", 60, min_value=10, max_value=3600)
    http_probe_timeout_s = _env_int("SC0PE_AI_HTTP_PROBE_TIMEOUT", 20, min_value=5, max_value=300)
    cli_timeout_s = _env_int("SC0PE_AI_OLLAMA_CLI_TIMEOUT", 90, min_value=10, max_value=7200)
    total_budget_s = _env_int("SC0PE_AI_TOTAL_BUDGET", 120, min_value=15, max_value=7200)

    # Warn user early if Ollama is not available.
    has_ollama_http = _probe_ollama_http()
    has_ollama_cli = bool(shutil.which("ollama"))
    status_msg = ""
    if not has_ollama_http and not has_ollama_cli:
        print("[bold cyan][[bold red]![bold cyan]][white] Ollama not found or not reachable. Falling back to heuristic analysis.")
        print("[bold cyan][[bold red]*[bold cyan]][white] Install Ollama or set OLLAMA_HOST (default: http://127.0.0.1:11434).")
        status_msg = "[bold magenta][[bold yellow]*[bold magenta]][bold white] HEURISTIC ANALYSIS IN PROGRESS, PLEASE WAIT..."
    else:
        status_msg = "[bold magenta][[bold yellow]*[bold magenta]][bold white] AI QUERY IN PROGRESS, PLEASE WAIT..."

    if RICH_CONSOLE is None:
        print(status_msg)
    status_ctx = RICH_CONSOLE.status(status_msg, spinner="bouncingBar", spinner_style="bold magenta") if RICH_CONSOLE is not None else nullcontext()
    with status_ctx:
        # Use only the model configured in multiple.conf.
        model_candidates = [model]

        # Choose the fastest working engine/model; don't attempt HTTP if not reachable.
        engine = "heuristic"
        text = ""
        chosen_model = ""
        err_log = []
        deadline = time.time() + total_budget_s
        if has_ollama_http and requests is not None:
            for candidate in model_candidates:
                if text:
                    break
                remain = int(deadline - time.time())
                if remain <= 0:
                    err_log.append("http: budget exhausted")
                    break
                engine = "ollama_http"
                try:
                    # Fast HTTP probe first; if it times out we'll attempt CLI for same model.
                    per_call_timeout = max(10, min(http_timeout_s, http_probe_timeout_s, remain))
                    text, meta = _call_ollama_http(
                        model=candidate,
                        prompt=prompt,
                        timeout_s=per_call_timeout,
                        with_meta=True,
                    )
                    # If response appears truncated (or model says length), do one retry with larger generation budget.
                    if text and (
                        meta.get("done_reason") == "length" or _llm_output_looks_incomplete(text)
                    ):
                        remain_retry = int(deadline - time.time())
                        if remain_retry > 8:
                            retry_predict = _env_int("SC0PE_AI_OLLAMA_RETRY_NUM_PREDICT", 1400, min_value=256, max_value=8192)
                            try:
                                retry_text, retry_meta = _call_ollama_http(
                                    model=candidate,
                                    prompt=prompt,
                                    timeout_s=max(10, min(http_timeout_s, remain_retry)),
                                    num_predict_override=retry_predict,
                                    with_meta=True,
                                )
                                if retry_text and len(retry_text) >= len(text):
                                    text, meta = retry_text, retry_meta
                            except Exception as retry_exc:
                                err_log.append(f"http:{candidate}: retry failed: {str(retry_exc).strip()[:160]}")
                    if text:
                        chosen_model = candidate
                        break
                except Exception as exc:
                    err_msg = str(exc).strip()
                    err_log.append(f"http:{candidate}: {err_msg[:180]}")
                    # If HTTP timed out, try one direct CLI retry for the same model.
                    if (not text) and has_ollama_cli and ("timed out" in err_msg.lower()):
                        remain_cli = int(deadline - time.time())
                        if remain_cli > 10:
                            try:
                                engine = "ollama_cli"
                                per_cli_timeout = max(20, min(cli_timeout_s, remain_cli))
                                text = _call_ollama_cli(model=candidate, prompt=prompt, timeout_s=per_cli_timeout)
                                if text:
                                    chosen_model = candidate
                                    break
                            except Exception as cli_exc:
                                err_log.append(f"cli:{candidate}: {str(cli_exc).strip()[:180]}")
        if not text and has_ollama_cli:
            for candidate in model_candidates:
                remain = int(deadline - time.time())
                if remain <= 0:
                    err_log.append("cli: budget exhausted")
                    break
                engine = "ollama_cli"
                try:
                    per_call_timeout = max(10, min(cli_timeout_s, remain))
                    text = _call_ollama_cli(model=candidate, prompt=prompt, timeout_s=per_call_timeout)
                    if text:
                        chosen_model = candidate
                        break
                except Exception as exc:
                    err_log.append(f"cli:{candidate}: {str(exc).strip()[:180]}")
        if not text:
            engine = "heuristic"
            text = _heuristic_fallback(summary)
            if err_log:
                print("[bold cyan][[bold red]![bold cyan]][white] Ollama call failed; fallback mode enabled.")
                for ln in err_log[:4]:
                    print(f"[bold cyan][[bold red]![bold cyan]][white] {ln}")
                print("[bold cyan][[bold red]*[bold cyan]][white] Verify model name or run: [bold yellow]ollama pull <model>[white]")
        else:
            model = chosen_model or model

    # Print AI output
    llm_iocs = _extract_llm_iocs(text)
    llm_iocs = _filter_local_analysis_paths(llm_iocs, summary, report_path)
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
            "parsed_ioc_counts": {
                k: len(v) for k, v in (summary.get("temp_txt", {}).get("parsed_iocs", {}) or {}).items() if isinstance(v, list)
            },
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
