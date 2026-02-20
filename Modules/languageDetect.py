#!/usr/bin/python3

import os
import re
import json
import configparser
from pathlib import Path
from collections import OrderedDict

try:
    # Module execution (python -m Modules.languageDetect or imported package style)
    from .utils.helpers import err_exit, get_argv, save_report
    from .analysis.multiple.multi import perform_strings
except ImportError:
    # Raw execution fallback (python Modules/languageDetect.py)
    from utils.helpers import err_exit, get_argv, save_report
    from analysis.multiple.multi import perform_strings

try:
    import puremagic as pr
except Exception:
    err_exit("Error: >puremagic< module not found.")

try:
    from rich import print
    from rich.table import Table
except Exception:
    err_exit("Error: >rich< module not found.")

try:
    import requests
except Exception:
    requests = None


TARGET_FILE = str(get_argv(1) or "").strip()
if not TARGET_FILE:
    err_exit("[bold white on red]Target file not found!\n")
EMIT_REPORT = str(get_argv(2, "False")).lower() == "true"
ENABLE_AI_PATTERN_ASSIST = str(get_argv(3, "False")).lower() == "true"

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"


EXTENSION_HINTS = {
    ".go": "Golang",
    ".nim": "Nim",
    ".py": "Python",
    ".zig": "Zig",
    ".cs": "C#",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C",
    ".h": "C",
    ".hpp": "C++",
    ".rs": "Rust",
    ".java": "Java",
    ".js": "JavaScript",
    ".ts": "JavaScript",
}


LANGUAGE_SIGNATURES = OrderedDict(
    {
        "Golang": {
            "strong": [
                "runtime.goexit",
                "runtime.gopanic",
                ".gopclntab",
                ".go.buildinfo",
                ".note.go.buildid",
                "go:build",
            ],
            "weak": [
                "godebug",
                "cgo_enabled",
                "goarch",
                "_cgo_gotypes.go",
            ],
        },
        "Nim": {
            "strong": [
                "nimframe",
                "stdlib_system.nim.c",
                "nim_compiler",
                "main.nim",
            ],
            "weak": [
                "nimtocstringconv",
                "nim.cfg",
                "nimble",
                "nim command",
            ],
        },
        "Python": {
            "strong": [
                "_pyi_procname",
                "py_initialize",
                "py_buildvalue",
                "libpython",
            ],
            "weak": [
                "__main__",
                "py_compile",
                "pydata",
            ],
        },
        "Zig": {
            "strong": [
                "__zig_probe_stack",
                "__zig_return_error",
            ],
            "weak": [
                "zig_debug_color",
            ],
        },
        "C#": {
            "strong": [
                "mscoree.dll",
                "_corexemain",
                "mscorlib",
                "system.runtime",
                "system.private.corelib",
                "</assembly>",
            ],
            "weak": [
                "<security>",
                "</requestedprivileges>",
                "clr",
                "mono",
            ],
        },
        "C++": {
            "strong": [
                "std::",
                "libstdc++.so",
                "cxxabi_",
            ],
            "weak": [
                "glibcxx_",
                "typeinfo for",
                "vtable for",
            ],
        },
        "C": {
            "strong": [
                "__libc_start_main",
                "libc.so",
                "__cxa_finalize",
            ],
            "weak": [
                "glibc_",
                "strcpy",
                "memcpy",
            ],
        },
        "Rust": {
            "strong": [
                "rust_begin_unwind",
                "rust_eh_personality",
                "core::panicking",
            ],
            "weak": [
                "cargo",
                "rustc",
            ],
        },
        "Java": {
            "strong": [
                "java/lang/object",
                "java/lang/string",
                "classloader",
            ],
            "weak": [
                "jvm",
                "jar",
            ],
        },
        "JavaScript": {
            "strong": [
                "node.js",
                "require(",
                "module.exports",
            ],
            "weak": [
                "javascript",
                "npm",
            ],
        },
    }
)


def _safe_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _read_sc0pe_path():
    try:
        p = open(".path_handler", "r").read().strip()
        if p:
            return p
    except Exception:
        pass
    return os.getcwd()


def _load_ai_model():
    env_model = str(os.environ.get("SC0PE_AI_MODEL", "")).strip()
    if env_model:
        return env_model

    conf_path = os.path.join(_read_sc0pe_path(), "Systems", "Multiple", "multiple.conf")
    if os.path.exists(conf_path):
        try:
            conf = configparser.ConfigParser()
            conf.read(conf_path, encoding="utf-8-sig")
            model = str(conf["Ollama"]["model"]).strip()
            if model:
                return model
        except Exception:
            pass
    return "llama3"


def _extract_json_object(text):
    payload = str(text or "").strip()
    if not payload:
        return None
    try:
        return json.loads(payload)
    except Exception:
        pass

    match = re.search(r"\{.*\}", payload, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None


def _query_ollama_json(prompt, num_predict=220, timeout_s=14):
    if requests is None:
        return None, "", "requests_not_available"

    model = _load_ai_model()
    host = str(os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")
    url = f"{host}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.0,
            "num_predict": int(num_predict),
            "num_ctx": 4096,
        },
    }
    connect_timeout = min(8, max(2, int(timeout_s / 3)))
    try:
        resp = requests.post(url, json=payload, timeout=(connect_timeout, timeout_s))
        if resp.status_code >= 400:
            # Some Ollama variants don't accept `think`.
            fallback_payload = dict(payload)
            fallback_payload.pop("think", None)
            resp = requests.post(url, json=fallback_payload, timeout=(connect_timeout, timeout_s))
        resp.raise_for_status()
        data = resp.json() if resp.content else {}
    except Exception as exc:
        return None, model, f"ollama_request_failed:{str(exc).strip()[:120]}"

    response_text = str((data or {}).get("response", "")).strip()
    parsed = _extract_json_object(response_text)
    if not isinstance(parsed, dict):
        return None, model, "invalid_json_response"
    return parsed, model, ""


def _is_executable_or_supported(path):
    ext = Path(path).suffix.lower()
    if ext in EXTENSION_HINTS:
        return True

    try:
        magic_nums = list(pr.magic_file(path))
    except Exception:
        return False

    for item in magic_nums:
        try:
            confidence = float(getattr(item, "confidence", 0.0) or 0.0)
        except Exception:
            confidence = 0.0
        name = _safe_text(getattr(item, "name", "")).lower()
        if confidence < 0.25:
            continue
        if (
            "executable" in name
            or "shared object" in name
            or "dynamic link library" in name
            or "elf" in name
            or "mach-o" in name
            or "pe32" in name
            or ".net" in name
        ):
            return True
    return False


def _collect_strings(path):
    try:
        items = perform_strings(path)
    except Exception as exc:
        err_exit(f"{errorS} strings extraction failed: {exc}\n")

    cleaned = []
    for raw in items:
        text = _safe_text(raw).replace("\x00", "").strip()
        if text:
            cleaned.append(text)
    return cleaned


def _count_pattern_hits(blob, pattern):
    token = str(pattern).strip().lower()
    if not token:
        return 0

    # Boundary-aware matching reduces accidental substring matches.
    if re.fullmatch(r"[a-z0-9_.:-]+", token):
        try:
            return len(re.findall(rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])", blob))
        except re.error:
            return blob.count(token)
    return blob.count(token)


def _get_file_profile(path):
    profile = {
        "is_pe": False,
        "is_elf": False,
        "is_macho": False,
        "is_dotnet": False,
    }
    try:
        magic_items = list(pr.magic_file(path))
    except Exception:
        return profile

    for item in magic_items:
        name = _safe_text(getattr(item, "name", "")).lower()
        if "pe32" in name or "windows executable" in name or "portable executable" in name:
            profile["is_pe"] = True
        if "elf" in name:
            profile["is_elf"] = True
        if "mach-o" in name:
            profile["is_macho"] = True
        if ".net" in name or "clr" in name or "mono/.net assembly" in name or "msil" in name:
            profile["is_dotnet"] = True
    return profile


def _recalc_confidence(rows):
    total_score = sum(float(row.get("score", 0.0)) for row in rows if float(row.get("score", 0.0)) > 0)
    if total_score <= 0:
        for row in rows:
            row["confidence"] = 0.0
        return
    for row in rows:
        row["confidence"] = round((float(row.get("score", 0.0)) * 100.0) / total_score, 2)


def _query_ai_language_adjustments(rows, profile, ext_hint):
    if not rows:
        return [], "", "no_rows"

    payload_rows = []
    for row in rows[:8]:
        payload_rows.append(
            {
                "language": str(row.get("language")),
                "score": round(float(row.get("score", 0.0)), 4),
                "strong_hits": int(row.get("strong_hits", 0)),
                "weak_hits": int(row.get("weak_hits", 0)),
                "pattern_hits": int(row.get("pattern_hits", 0)),
                "extension_hint": bool(row.get("extension_hint")),
                "matched_patterns": list(row.get("matched_patterns", []))[:6],
            }
        )

    prompt_input = {
        "task": "refine_language_scores",
        "file_profile": {
            "is_pe": bool(profile.get("is_pe")),
            "is_elf": bool(profile.get("is_elf")),
            "is_macho": bool(profile.get("is_macho")),
            "is_dotnet": bool(profile.get("is_dotnet")),
        },
        "extension_hint": ext_hint or "",
        "candidates": payload_rows,
    }

    prompt = (
        "You are a malware triage assistant. Refine programming-language scores.\n"
        "Return STRICT JSON only, no markdown, no explanation.\n"
        "Output schema:\n"
        "{\"adjustments\":[{\"language\":\"<name>\",\"multiplier\":<float 0.05..2.5>,\"reason\":\"<short_reason>\"}]}\n"
        "Rules:\n"
        "- If sample is ELF/Mach-O and not dotnet, penalize C# heavily.\n"
        "- Use strong hits more than weak hits.\n"
        "- Keep list short (max 4 adjustments).\n"
        f"INPUT={json.dumps(prompt_input, ensure_ascii=True)}"
    )

    parsed, model, error = _query_ollama_json(prompt, num_predict=180, timeout_s=12)
    if not isinstance(parsed, dict):
        return [], model, error or "no_parsed_response"

    raw_adjustments = parsed.get("adjustments")
    if not isinstance(raw_adjustments, list):
        return [], model, "missing_adjustments"

    known = {str(row.get("language")) for row in rows}
    out = []
    for item in raw_adjustments[:8]:
        if not isinstance(item, dict):
            continue
        lang = str(item.get("language", "")).strip()
        if not lang or lang not in known:
            continue
        try:
            multiplier = float(item.get("multiplier", 1.0))
        except (TypeError, ValueError):
            continue
        multiplier = max(0.05, min(2.5, multiplier))
        reason = str(item.get("reason", "")).strip()[:80] or "llm_refinement"
        out.append({"language": lang, "multiplier": multiplier, "reason": reason})
    return out, model, ""


def _apply_ai_pattern_refinement(rows, profile, ext_hint):
    if not rows:
        return rows, [], {"llm_used": False, "llm_model": "", "llm_error": "no_rows"}

    by_lang = {str(row.get("language")): row for row in rows}
    adjustments = []

    def mul(lang, factor, reason, source="heuristic"):
        row = by_lang.get(lang)
        if not row:
            return
        old = float(row.get("score", 0.0))
        if old <= 0:
            return
        new = old * float(factor)
        row["score"] = new
        adjustments.append(
            {
                "language": lang,
                "from_score": round(old, 2),
                "to_score": round(new, 2),
                "reason": reason,
                "source": source,
            }
        )

    # AI-style disambiguation on binary format signals.
    if bool(profile.get("is_dotnet")):
        mul("C#", 1.85, "dotnet_profile_boost")
        mul("C", 0.65, "dotnet_profile_penalty")
        mul("C++", 0.70, "dotnet_profile_penalty")
    elif bool(profile.get("is_elf")) or bool(profile.get("is_macho")):
        mul("C#", 0.08, "native_binary_penalty_for_csharp")
        mul("C", 1.25, "native_binary_boost_for_c")

    # Extension hint still matters but should not dominate.
    if ext_hint:
        mul(ext_hint, 1.20, "extension_hint_boost")

    csharp = by_lang.get("C#")
    clang = by_lang.get("C")
    if csharp and clang:
        csharp_strong = int(csharp.get("strong_hits", 0))
        csharp_weak = int(csharp.get("weak_hits", 0))
        c_strong = int(clang.get("strong_hits", 0))
        # Prevent weak C# artifacts from defeating strong native-C evidence.
        if (not bool(profile.get("is_dotnet"))) and csharp_strong == 0 and csharp_weak > 0 and c_strong >= 1:
            mul("C#", 0.15, "weak_only_csharp_penalty")
            mul("C", 1.15, "c_evidence_boost")

    llm_used = False
    llm_model = ""
    llm_error = ""
    llm_adjustments, llm_model, llm_error = _query_ai_language_adjustments(rows, profile, ext_hint)
    for adj in llm_adjustments:
        mul(adj["language"], adj["multiplier"], adj["reason"], source="llm")
        llm_used = True

    rows = [row for row in rows if float(row.get("score", 0.0)) > 0]
    rows.sort(key=lambda item: float(item["score"]), reverse=True)
    _recalc_confidence(rows)
    return rows, adjustments, {"llm_used": llm_used, "llm_model": llm_model, "llm_error": llm_error}


def _scan_languages(path, ai_assist=False):
    all_strings = _collect_strings(path)
    blob = "\n".join(all_strings).lower()
    profile = _get_file_profile(path)

    ext = Path(path).suffix.lower()
    ext_hint = EXTENSION_HINTS.get(ext)

    rows = []
    total_score = 0.0
    total_pattern_hits = 0

    for language, signature in LANGUAGE_SIGNATURES.items():
        strong_hits = 0
        weak_hits = 0
        matched_patterns = []

        for pat in signature.get("strong", []):
            count = _count_pattern_hits(blob, pat)
            if count > 0:
                strong_hits += count
                matched_patterns.append(str(pat))

        for pat in signature.get("weak", []):
            count = _count_pattern_hits(blob, pat)
            if count > 0:
                weak_hits += count
                matched_patterns.append(str(pat))

        pattern_hits = strong_hits + weak_hits
        extension_bonus = 40.0 if ext_hint == language else 0.0
        score = (strong_hits * 5.0) + (weak_hits * 2.0) + extension_bonus

        if language == "C#":
            clr_markers = 0
            for marker in ("mscoree.dll", "_corexemain", "mscorlib", "system.private.corelib", "clr", "mono"):
                if _count_pattern_hits(blob, marker) > 0:
                    clr_markers += 1

            if profile["is_elf"] or profile["is_macho"]:
                # Native ELF/Mach-O samples should not win as C# without explicit CLR indicators.
                if clr_markers == 0:
                    score = 0.0
                else:
                    score *= 0.2
            elif profile["is_pe"] and (not profile["is_dotnet"]) and clr_markers == 0:
                score *= 0.3

            if clr_markers > 0:
                score += float(clr_markers * 8)

        elif language == "C":
            if profile["is_elf"] or profile["is_macho"]:
                score += 8.0
            if profile["is_pe"]:
                score += 2.0

        elif language == "C++":
            if profile["is_elf"] and strong_hits == 0 and weak_hits > 0:
                score *= 0.7

        if score <= 0:
            continue

        total_score += score
        total_pattern_hits += pattern_hits
        rows.append(
            {
                "language": language,
                "score": score,
                "pattern_hits": pattern_hits,
                "strong_hits": strong_hits,
                "weak_hits": weak_hits,
                "matched_patterns": matched_patterns[:24],
                "extension_hint": bool(ext_hint == language),
            }
        )

    rows.sort(key=lambda item: float(item["score"]), reverse=True)
    _recalc_confidence(rows)

    ai_adjustments = []
    ai_meta = {"llm_used": False, "llm_model": "", "llm_error": ""}
    if ai_assist:
        rows, ai_adjustments, ai_meta = _apply_ai_pattern_refinement(rows, profile, ext_hint)

    return rows, total_pattern_hits, ext_hint, profile, ai_adjustments, ai_meta


def _render_table(rows):
    lang_table = Table()
    lang_table.add_column("Programming Language", justify="center")
    lang_table.add_column("Confidence", justify="center")
    lang_table.add_column("Pattern Hits", justify="center")
    lang_table.add_column("Matched Signatures (sample)", justify="left")

    for row in rows:
        matched = ", ".join(row["matched_patterns"][:4]) if row["matched_patterns"] else "-"
        lang_table.add_row(
            f"[bold green]{row['language']}[white]",
            f"[bold green]{row['confidence']:.2f}%[white]",
            f"[bold green]{row['pattern_hits']}[white]",
            _safe_text(matched),
        )

    print(lang_table)


def _save_language_report(rows, total_pattern_hits, ext_hint, profile, ai_adjustments, ai_meta):
    report = {
        "target_type": "language_detection",
        "analysis_mode": "signature_fingerprint",
        "filename": TARGET_FILE,
        "primary_language": rows[0]["language"] if rows else "",
        "extension_hint": ext_hint or "",
        "ai_pattern_assist": bool(ENABLE_AI_PATTERN_ASSIST),
        "ai_pattern_adjustment_count": len(ai_adjustments),
        "ai_pattern_adjustments": ai_adjustments[:32],
        "ai_llm_used": bool(ai_meta.get("llm_used")),
        "ai_llm_model": str(ai_meta.get("llm_model") or ""),
        "ai_llm_error": str(ai_meta.get("llm_error") or ""),
        "file_profile": {
            "is_pe": bool(profile.get("is_pe")),
            "is_elf": bool(profile.get("is_elf")),
            "is_macho": bool(profile.get("is_macho")),
            "is_dotnet": bool(profile.get("is_dotnet")),
        },
        "total_detected": len(rows),
        "total_pattern_hits": int(total_pattern_hits),
        "detected_languages": [
            {
                "language": row["language"],
                "confidence": row["confidence"],
                "score": round(float(row["score"]), 2),
                "pattern_hits": int(row["pattern_hits"]),
                "strong_hits": int(row["strong_hits"]),
                "weak_hits": int(row["weak_hits"]),
                "extension_hint": bool(row["extension_hint"]),
                "matched_patterns": row["matched_patterns"][:16],
            }
            for row in rows
        ],
    }
    save_report("language", report)


def LanguageDetect():
    print(f"{infoS} Performing improved language detection. Please wait...")
    rows, total_pattern_hits, ext_hint, profile, ai_adjustments, ai_meta = _scan_languages(
        TARGET_FILE,
        ai_assist=ENABLE_AI_PATTERN_ASSIST,
    )

    if not rows:
        err_exit(f"{errorS} Programming language could not be detected. Target may be obfuscated.\n")

    if ENABLE_AI_PATTERN_ASSIST:
        if bool(ai_meta.get("llm_used")):
            print(f"{infoS} AI query used model: [bold green]{ai_meta.get('llm_model', '-') }[white]")
        else:
            err_text = str(ai_meta.get("llm_error") or "").strip() or "unavailable"
            print(f"{infoS} AI query unavailable ({err_text}); local refinement fallback applied.")

    _render_table(rows)
    if EMIT_REPORT:
        _save_language_report(rows, total_pattern_hits, ext_hint, profile, ai_adjustments, ai_meta)


if not os.path.exists(TARGET_FILE):
    err_exit(f"{errorS} Target file not found.\n")

if _is_executable_or_supported(TARGET_FILE):
    LanguageDetect()
else:
    err_exit(f"{errorS} Please scan executable or supported code/script files.\n")
