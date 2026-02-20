#!/usr/bin/python3

import os
import sys
import re
import json
import configparser

try:
    # Module execution (python -m Modules.packerAnalyzer)
    from .utils.helpers import err_exit, get_argv, save_report
except ImportError:
    # Raw execution (python Modules/packerAnalyzer.py)
    from utils.helpers import err_exit, get_argv, save_report

try:
    from rich import print
    from rich.table import Table
except Exception:
    err_exit("Error: >rich< module not found.")

try:
    import yara  # noqa: F401 - keeps explicit dependency check behavior
except Exception:
    err_exit("Error: >yara< module not found.")

try:
    from tqdm import tqdm
except Exception:
    err_exit("Module: >tqdm< not found.")

try:
    import requests
except Exception:
    requests = None


# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Path variable
sc0pe_path = open(".path_handler", "r").read().strip()

# Ensure `analysis.*` imports resolve when running as a script.
modules_dir = os.path.join(sc0pe_path, "Modules")
if modules_dir not in sys.path:
    sys.path.insert(0, modules_dir)

try:
    from analysis.multiple.multi import yara_rule_scanner
except Exception:
    err_exit("Error: >analysis.multiple.multi< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

# File signatures
file_sigs = {
    "UPX": "UPX0",
    "AsPack": ".aspack",
    "ConfuserEx v0.6.0": "ConfuserEx v0.6.0",
    "UPX!": "UPX!",
    "Confuser v1.9.0.0": "Confuser v1.9.0.0",
    "PEtite": "petite",
    "MPRESS_1": "MPRESS1",
    "MPRESS_2": "MPRESS2H",
}

ai_packer_patterns = {
    "UPX": ["upx0", "upx1", "upx2", "upx!", "ultimate packer for executables"],
    "ASPack": [".aspack", "aspack"],
    "MPRESS": ["mpress1", "mpress2h", "mpress"],
    "PEtite": ["petite"],
    "FSG": ["fsg!", "fsg v"],
    "NSPack": ["nspack"],
    "Themida/WinLicense": ["themida", "winlicense"],
    "VMProtect": ["vmprotect", "vmp0", "vmp1"],
    "Enigma Protector": ["enigma protector", "enigma_"],
}


def _is_true(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


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


def _query_ollama_json(prompt, num_predict=200, timeout_s=12):
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


def _scan_string_signatures(data):
    hits = []
    for pack_name, marker in file_sigs.items():
        if str(marker).encode() in data:
            hits.append({"packer": str(pack_name), "signature": str(marker)})
    return hits


def _ai_pattern_scan(data):
    blob = data.decode("latin-1", errors="ignore").lower()
    candidates = []
    for packer_name, markers in ai_packer_patterns.items():
        matched = []
        marker_hits = 0
        for marker in markers:
            token = str(marker).lower()
            if not token:
                continue
            hit_count = len(re.findall(re.escape(token), blob))
            if hit_count > 0:
                marker_hits += hit_count
                matched.append(token)
        if marker_hits == 0:
            continue

        confidence = min(98.0, 35.0 + (marker_hits * 14.0) + (len(set(matched)) * 6.0))
        candidates.append(
            {
                "packer": str(packer_name),
                "confidence": round(confidence, 2),
                "marker_hits": int(marker_hits),
                "matched_markers": sorted(set(matched))[:8],
            }
        )

    candidates.sort(key=lambda item: float(item["confidence"]), reverse=True)
    return candidates


def _llm_refine_packer_candidates(base_candidates, data):
    model = ""
    if not base_candidates:
        return base_candidates, {"llm_used": False, "llm_model": model, "llm_error": "no_base_candidates"}

    text_blob = data.decode("latin-1", errors="ignore")
    sampled_strings = []
    seen = set()
    for match in re.findall(r"[ -~]{6,120}", text_blob):
        val = str(match).strip()
        if not val:
            continue
        key = val.lower()
        if key in seen:
            continue
        seen.add(key)
        sampled_strings.append(val[:120])
        if len(sampled_strings) >= 36:
            break

    prompt_input = {
        "task": "refine_packer_candidates",
        "base_candidates": [
            {
                "packer": str(item.get("packer")),
                "confidence": float(item.get("confidence", 0)),
                "marker_hits": int(item.get("marker_hits", 0)),
                "matched_markers": list(item.get("matched_markers", []))[:6],
            }
            for item in base_candidates[:8]
        ],
        "sample_strings": sampled_strings,
    }
    prompt = (
        "You are assisting malware packer detection.\n"
        "Return STRICT JSON only.\n"
        "Schema:\n"
        "{\"multipliers\":[{\"packer\":\"<name>\",\"multiplier\":<float 0.2..2.5>,\"reason\":\"<short>\"}],"
        "\"add_candidates\":[{\"packer\":\"<name>\",\"confidence\":<float 15..95>,\"reason\":\"<short>\"}]}\n"
        "No markdown.\n"
        f"INPUT={json.dumps(prompt_input, ensure_ascii=True)}"
    )

    parsed, model, error = _query_ollama_json(prompt, num_predict=170, timeout_s=11)
    if not isinstance(parsed, dict):
        return base_candidates, {"llm_used": False, "llm_model": model, "llm_error": error or "no_parsed_response"}

    candidates = [dict(item) for item in base_candidates]
    by_name = {str(item.get("packer")): item for item in candidates}
    known_packers = set(by_name.keys()) | set(ai_packer_patterns.keys()) | set(file_sigs.keys())
    adjustments = []

    for item in (parsed.get("multipliers") or [])[:10]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("packer", "")).strip()
        if name not in by_name:
            continue
        try:
            mul = float(item.get("multiplier", 1.0))
        except (TypeError, ValueError):
            continue
        mul = max(0.2, min(2.5, mul))
        target = by_name[name]
        old = float(target.get("confidence", 0.0))
        new = max(1.0, min(99.0, old * mul))
        target["confidence"] = round(new, 2)
        adjustments.append(
            {
                "packer": name,
                "from_confidence": round(old, 2),
                "to_confidence": round(new, 2),
                "reason": str(item.get("reason", "")).strip()[:80] or "llm_refinement",
            }
        )

    for item in (parsed.get("add_candidates") or [])[:6]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("packer", "")).strip()
        if not name or name not in known_packers:
            continue
        try:
            conf = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            continue
        conf = max(15.0, min(95.0, conf))
        if name in by_name:
            existing = by_name[name]
            existing["confidence"] = round(max(float(existing.get("confidence", 0.0)), conf), 2)
            continue
        new_item = {
            "packer": name,
            "confidence": round(conf, 2),
            "marker_hits": 0,
            "matched_markers": [],
        }
        candidates.append(new_item)
        by_name[name] = new_item

    candidates.sort(key=lambda item: float(item.get("confidence", 0.0)), reverse=True)
    return candidates, {
        "llm_used": True,
        "llm_model": model,
        "llm_error": "",
        "llm_adjustments": adjustments[:16],
    }


def _run_ai_pattern_scan(data, use_llm=False):
    candidates = _ai_pattern_scan(data)
    meta = {
        "llm_used": False,
        "llm_model": "",
        "llm_error": "",
        "llm_adjustments": [],
    }
    if not use_llm:
        return candidates, meta

    refined, llm_meta = _llm_refine_packer_candidates(candidates, data)
    if isinstance(llm_meta, dict):
        meta.update(llm_meta)
    return refined, meta


def _print_string_hits_table(hits):
    pack_table = Table()
    pack_table.add_column("[bold green]Extracted Strings", justify="center")
    pack_table.add_column("[bold green]Packer Type", justify="center")
    for item in hits:
        pack_table.add_row(f"[bold red]{item['signature']}", f"[bold red]{item['packer']}")
    print(pack_table)


def _print_ai_candidates_table(candidates):
    ai_table = Table(title="AI-Assisted Packer Pattern Candidates", title_style="bold cyan")
    ai_table.add_column("[bold green]Packer", justify="center")
    ai_table.add_column("[bold green]Confidence", justify="center")
    ai_table.add_column("[bold green]Marker Hits", justify="center")
    ai_table.add_column("[bold green]Matched Markers (sample)", justify="left")
    for item in candidates:
        marker_preview = ", ".join(item.get("matched_markers", [])[:4]) or "-"
        ai_table.add_row(
            f"[bold magenta]{item['packer']}[white]",
            f"[bold magenta]{item['confidence']}%[white]",
            f"[bold magenta]{item['marker_hits']}[white]",
            marker_preview,
        )
    print(ai_table)


def _scan_yara(target_file):
    rep = {"matched_rules": []}
    hit = yara_rule_scanner(
        "/Systems/Multiple/Packer_Rules/",
        target_file,
        rep,
        quiet_nomatch=True,
        header_label="",
    )
    if not hit:
        print(f"[bold white on red]There is no rules matched for {target_file}")
    return bool(hit), rep.get("matched_rules", [])


def _single_analyzer(target_file, emit_report=False, enable_ai_assist=False):
    try:
        if not os.path.isfile(target_file):
            err_exit("[bold white on red]Target file not found.")
        data = open(target_file, "rb").read()
    except Exception:
        err_exit("[bold white on red]An error occured while opening the file.")

    print("[bold magenta]>>>[white] Performing [bold green][blink]strings[/blink] [white]based scan...")
    string_hits = _scan_string_signatures(data)
    if not string_hits:
        print("\n[bold white on red]Nothing found.\n")
    else:
        _print_string_hits_table(string_hits)

    ai_candidates = []
    ai_meta = {"llm_used": False, "llm_model": "", "llm_error": "", "llm_adjustments": []}
    if enable_ai_assist:
        print("\n[bold magenta]>>>[white] Performing [bold green][blink]AI-assisted[/blink] [white]packer pattern scan...")
        ai_candidates, ai_meta = _run_ai_pattern_scan(data, use_llm=True)
        if ai_meta.get("llm_used"):
            print(f"{infoS} AI query used model: [bold green]{ai_meta.get('llm_model', '-') }[white]")
        else:
            err_text = str(ai_meta.get("llm_error") or "").strip() or "unavailable"
            print(f"{infoS} AI query unavailable ({err_text}); local refinement fallback applied.")
        if ai_candidates:
            _print_ai_candidates_table(ai_candidates)
        else:
            print("\n[bold white on red]No AI-assisted packer pattern candidate found.\n")

    print("\n[bold magenta]>>>[white] Performing [bold green][blink]YARA Rule[/blink] [white]based scan...")
    yara_hit, matched_rules = _scan_yara(target_file=target_file)

    if emit_report:
        report = {
            "target_type": "packer_detection",
            "analysis_mode": "single",
            "filename": target_file,
            "ai_pattern_assist": bool(enable_ai_assist),
            "ai_llm_used": bool(ai_meta.get("llm_used")),
            "ai_llm_model": str(ai_meta.get("llm_model") or ""),
            "ai_llm_error": str(ai_meta.get("llm_error") or ""),
            "ai_llm_adjustments": list(ai_meta.get("llm_adjustments") or [])[:16],
            "packed": bool(string_hits or yara_hit or ai_candidates),
            "string_hits_count": len(string_hits),
            "string_hits": string_hits,
            "ai_pattern_candidates": ai_candidates,
            "matched_rules": matched_rules,
        }
        save_report("packer", report)


def _multi_analyzer(target_dir, emit_report=False, enable_ai_assist=False):
    answers = Table()
    answers.add_column("[bold green]File Names", justify="center")
    answers.add_column("[bold green]Extracted Strings", justify="center")
    answers.add_column("[bold green]Packer Type", justify="center")

    if not os.path.isdir(target_dir):
        err_exit("[bold white on red]Target folder not found.")

    all_files = os.listdir(target_dir)
    if not all_files:
        print("\n[bold white on red]Nothing found.\n")
        if emit_report:
            save_report(
                "packer",
                {
                    "target_type": "packer_detection",
                    "analysis_mode": "multiscan",
                    "target_folder": target_dir,
                    "files_scanned": 0,
                    "packed_files_count": 0,
                    "packed_files": [],
                    "matched_rules": [],
                },
            )
        return

    packed_files = []
    multipack = 0
    scanned = 0
    llm_limit = max(0, int(os.environ.get("SC0PE_PACKER_AI_MULTI_LLM_MAX_FILES", "3")))
    llm_used_files = 0

    print(
        "[bold red]>>>[white] Qu1cksc0pe scans everything under that folder for malicious things. [bold][blink]Please wait...[/blink]"
    )
    for idx in tqdm(range(0, len(all_files)), desc="Scanning..."):
        current_name = all_files[idx]
        if not current_name:
            continue
        scanme = f"{target_dir}{path_seperator}{current_name}"
        if not os.path.isfile(scanme):
            continue

        scanned += 1
        try:
            mul_data = open(scanme, "rb").read()
        except Exception:
            continue

        per_file_hits = _scan_string_signatures(mul_data)
        ai_meta = {"llm_used": False, "llm_model": "", "llm_error": "", "llm_adjustments": []}
        if enable_ai_assist:
            use_llm = llm_used_files < llm_limit
            ai_candidates, ai_meta = _run_ai_pattern_scan(mul_data, use_llm=use_llm)
            if ai_meta.get("llm_used"):
                llm_used_files += 1
        else:
            ai_candidates = []
        if (not per_file_hits) and (not ai_candidates):
            continue

        multipack += len(per_file_hits)
        packed_files.append(
            {
                "file_name": current_name,
                "full_path": scanme,
                "string_hits_count": len(per_file_hits),
                "string_hits": per_file_hits,
                "ai_pattern_candidates": ai_candidates,
                "ai_llm_used": bool(ai_meta.get("llm_used")),
                "ai_llm_model": str(ai_meta.get("llm_model") or ""),
                "ai_llm_error": str(ai_meta.get("llm_error") or ""),
            }
        )
        for hit in per_file_hits:
            answers.add_row(f"[bold red]{current_name}", f"[bold red]{hit['signature']}", f"[bold red]{hit['packer']}")

    if multipack == 0:
        print("\n[bold white on red]Nothing found.\n")
    else:
        print(answers)
        print(" ")

    if emit_report:
        report = {
            "target_type": "packer_detection",
            "analysis_mode": "multiscan",
            "target_folder": target_dir,
            "ai_pattern_assist": bool(enable_ai_assist),
            "ai_llm_used_files": int(llm_used_files),
            "files_scanned": int(scanned),
            "packed_files_count": len(packed_files),
            "packed_files": packed_files,
            "matched_rules": [],
        }
        save_report("packer", report)


if __name__ == "__main__":
    mode = str(get_argv(1, "")).strip()
    target = str(get_argv(2, "")).strip()
    emit_report = _is_true(get_argv(3, "False"))
    enable_ai_assist = _is_true(get_argv(4, "False"))

    if mode == "--single":
        try:
            _single_analyzer(target_file=target, emit_report=emit_report, enable_ai_assist=enable_ai_assist)
        except KeyboardInterrupt:
            print("\n[bold white on red]Program terminated!\n")
    elif mode == "--multiscan":
        try:
            _multi_analyzer(target_dir=target, emit_report=emit_report, enable_ai_assist=enable_ai_assist)
        except KeyboardInterrupt:
            print("\n[bold white on red]Program terminated!\n")
    else:
        err_exit("[bold white on red]Invalid argument. Use --single or --multiscan.")
