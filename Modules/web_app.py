#!/usr/bin/env python3

import concurrent.futures
import copy
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "webui_uploads"
REPORTS_ROOT = BASE_DIR / "sc0pe_reports"
REPORTS_MAIN_DIR = REPORTS_ROOT / "analysis"
REPORTS_AI_DIR = REPORTS_ROOT / "ai"
REPORTS_VT_DIR = REPORTS_ROOT / "virustotal"
MAX_UPLOAD_MB = 48  # Keep below Qu1cksc0pe large-file interactive prompt threshold.
ANALYSIS_TIMEOUT_SECONDS = 900
MAX_JOB_HISTORY = 150
MAX_PANEL_ITEMS = 240
MAX_TABLE_ROWS = 240
MAX_TABLE_COLS = 14
PYTHON_BIN = sys.executable or "python3"
ENTRYPOINT = BASE_DIR / "qu1cksc0pe.py"


@dataclass(frozen=True)
class AnalysisPreset:
    label: str
    description: str
    args: Tuple[str, ...]
    report_default: bool = False


PRESETS: "OrderedDict[str, AnalysisPreset]" = OrderedDict(
    {
        "analyze": AnalysisPreset(
            label="Standart Analysis",
            description="OS/file type auto-detection with static triage, JSON report, and VirusTotal file lookup.",
            args=("--analyze",),
            report_default=True,
        ),
        "docs": AnalysisPreset(
            label="Document",
            description="Document, macro and VB-family script analysis with report and VirusTotal file lookup.",
            args=("--docs",),
            report_default=True,
        ),
        "archive": AnalysisPreset(
            label="Archive",
            description="Archive inspection with nested IOC/YARA triage, JSON report, optional AI support, and VirusTotal file lookup.",
            args=("--archive",),
            report_default=True,
        ),
        "hashscan": AnalysisPreset(
            label="Hash Scan",
            description="Hash lookup against local malware signature database.",
            args=("--hashscan",),
        ),
        "packer": AnalysisPreset(
            label="Packer Detect",
            description="Packer signature detection for packed binaries with JSON report output.",
            args=("--packer",),
            report_default=True,
        ),
        "resource": AnalysisPreset(
            label="Resource",
            description="Resource section extraction and payload carving.",
            args=("--resource",),
        ),
        "sigcheck": AnalysisPreset(
            label="Signature",
            description="Embedded signature scan and carved object detection.",
            args=("--sigcheck",),
        ),
        "domain": AnalysisPreset(
            label="Domain/IOC",
            description="URL/IP/email extraction with JSON report support.",
            args=("--domain",),
            report_default=True,
        ),
        "lang": AnalysisPreset(
            label="Language",
            description="Programming language fingerprint analysis with JSON report output.",
            args=("--lang",),
            report_default=True,
        ),
        "vtFile": AnalysisPreset(
            label="VirusTotal File",
            description="Query file hash on VirusTotal (requires API key via --key_init).",
            args=("--vtFile",),
            report_default=True,
        ),
    }
)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "webui" / "templates"),
    static_folder=str(BASE_DIR / "webui" / "static"),
)
app.config["SECRET_KEY"] = os.environ.get("SC0PE_WEB_SECRET", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_MAIN_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_AI_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_VT_DIR.mkdir(parents=True, exist_ok=True)

JOB_QUEUE: "queue.Queue[str]" = queue.Queue()
JOBS: Dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
JOB_SEQUENCE = 0
WORKER_THREAD: Optional[threading.Thread] = None


def _ts_to_text(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _trim_text(text: str, max_len: int = 1600) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _normalize_inline_text(text: str) -> str:
    # Compact UI text for cards/tables: remove tabs/newlines and collapse whitespace.
    out = str(text or "")
    out = out.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    out = re.sub(r"\s{2,}", " ", out)
    return out.strip()


def _report_snapshot() -> Dict[Path, int]:
    snap: Dict[Path, int] = {}
    for candidate in BASE_DIR.glob("sc0pe_*_report.json"):
        try:
            snap[candidate] = candidate.stat().st_mtime_ns
        except OSError:
            continue
    return snap


def _detect_new_reports(before: Dict[Path, int]) -> List[Path]:
    changed: List[Tuple[int, Path]] = []
    for candidate in BASE_DIR.glob("sc0pe_*_report.json"):
        try:
            mtime_ns = candidate.stat().st_mtime_ns
        except OSError:
            continue
        if candidate not in before or mtime_ns > before[candidate]:
            changed.append((mtime_ns, candidate))
    changed.sort(key=lambda item: item[0], reverse=True)
    return [item[1] for item in changed]


def _select_report_paths(changed_reports: List[Path], ai_enabled: bool) -> Tuple[Optional[Path], Optional[Path]]:
    if not changed_reports:
        return None, None

    ai_candidates = [path for path in changed_reports if path.name == "sc0pe_ai_report.json"]
    non_ai_candidates = [path for path in changed_reports if path.name != "sc0pe_ai_report.json"]

    ai_report = ai_candidates[0] if ai_candidates else None
    if ai_enabled and non_ai_candidates:
        return non_ai_candidates[0], ai_report
    return changed_reports[0], ai_report


def _report_bucket_dir(bucket: str) -> Path:
    if bucket == "ai":
        return REPORTS_AI_DIR
    if bucket == "vt":
        return REPORTS_VT_DIR
    return REPORTS_MAIN_DIR


def _unique_report_destination(dst_dir: Path, filename: str) -> Path:
    safe_name = Path(str(filename)).name
    dst = dst_dir / safe_name
    if not dst.exists():
        return dst
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return dst_dir / f"{dst.stem}_{stamp}_{uuid.uuid4().hex[:6]}{dst.suffix}"


def _store_generated_report(src_report: Optional[Path], bucket: str) -> str:
    if src_report is None:
        return ""

    src = src_report if src_report.is_absolute() else (BASE_DIR / src_report)
    if not src.exists():
        return ""

    dst_dir = _report_bucket_dir(bucket)
    dst = _unique_report_destination(dst_dir, src.name)
    try:
        shutil.move(str(src), str(dst))
    except Exception:  # noqa: BLE001
        try:
            shutil.copy2(str(src), str(dst))
            src.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            return ""

    try:
        return str(dst.relative_to(BASE_DIR))
    except ValueError:
        return str(dst)


def _resolve_report_path(report_path: str) -> Optional[Path]:
    if not report_path:
        return None

    candidate = Path(report_path)
    if not candidate.is_absolute():
        candidate = BASE_DIR / candidate

    try:
        resolved = candidate.resolve()
        base = BASE_DIR.resolve()
    except OSError:
        return None

    # Keep report resolution limited to project directory.
    if resolved != base and base not in resolved.parents:
        return None
    return resolved


def _load_report_for_job(job: dict) -> dict:
    report_ui = {
        "summary": [],
        "hashes": [],
        "categories": [],
        "windows_api_categories": [],
        "mitre_rows": [],
        "vt_section": {
            "available": False,
            "summary": [],
            "threat_names": [],
            "threat_categories": [],
            "detections": [],
            "error": "",
        },
        "interesting_patterns": [],
        "matched_rules_rows": [],
        "sections": [],
        "metadata": [],
        "extra_panels": [],
        "detailed_panels": [],
        "ai_output": "",
        "ai_iocs": [],
        "ai_context": [],
    }

    out = {
        "report_loaded": False,
        "report_file_label": str(job.get("report_path") or ""),
        "report_load_error": "",
        "report_ui": report_ui,
        "ai_loaded": False,
        "ai_file_label": str(job.get("ai_report_path") or ""),
        "ai_load_error": "",
        "ai_ui": {
            "ai_output": "",
            "ai_iocs": [],
            "ai_context": [],
        },
    }

    resolved = _resolve_report_path(str(job.get("report_path") or ""))
    if not resolved:
        if job.get("report_expected"):
            out["report_load_error"] = "Report path is missing or invalid."
        return out

    out["report_file_label"] = str(resolved.name)
    if not resolved.exists():
        out["report_load_error"] = f"Report file not found: {resolved.name}"
        return out

    try:
        report_data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        out["report_load_error"] = f"Report parse error: {exc}"
        return out

    out["report_loaded"] = True
    out["report_ui"] = build_frontend_payload(report_data)

    ai_resolved = _resolve_report_path(str(job.get("ai_report_path") or ""))
    if ai_resolved:
        out["ai_file_label"] = str(ai_resolved.name)
        if ai_resolved.exists():
            try:
                ai_data = json.loads(ai_resolved.read_text(encoding="utf-8"))
                ai_payload = build_frontend_payload(ai_data)
                out["ai_loaded"] = True
                out["ai_ui"] = {
                    "ai_output": str(ai_payload.get("ai_output") or ""),
                    "ai_iocs": ai_payload.get("ai_iocs") or [],
                    "ai_context": ai_payload.get("ai_context") or [],
                }
            except Exception as exc:  # noqa: BLE001
                out["ai_load_error"] = f"AI report parse error: {exc}"
        else:
            out["ai_load_error"] = f"AI report file not found: {ai_resolved.name}"

    return out


def _fmt_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "-"
    text = _normalize_inline_text(str(value))
    if not text:
        return "-"
    if len(text) > 120:
        return text[:117] + "..."
    return text


def _labelize_key(key: str) -> str:
    normalized = str(key).strip().replace("_", " ")
    return " ".join(part.capitalize() for part in normalized.split())


def _ioc_kind_label(kind: str) -> str:
    normalized = str(kind or "").strip().lower().replace("_", " ").replace("-", " ")
    aliases = {
        "ips": "IP Addresses",
        "ip": "IP Addresses",
        "ip address": "IP Addresses",
        "ip addresses": "IP Addresses",
    }
    if normalized in aliases:
        return aliases[normalized]
    return _labelize_key(kind)


def _count_items(value: object) -> int:
    if isinstance(value, dict):
        total = 0
        for item in value.values():
            if isinstance(item, (list, tuple, set)):
                total += len(item)
            elif isinstance(item, dict):
                total += len(item)
            elif item:
                total += 1
        return total
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, int):
        return value
    return 0


def _is_scalar(value: object) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _safe_panel_text(value: object) -> str:
    if _is_scalar(value):
        return _fmt_value(value)
    return _trim_text(_normalize_inline_text(json.dumps(value, ensure_ascii=False)), 420)


def build_summary(report_data: Optional[dict]) -> List[dict]:
    if not isinstance(report_data, dict):
        return []

    summary: List[dict] = []
    summary.append(
        {
            "label": "Report Type",
            "value": _fmt_value(report_data.get("target_type") or report_data.get("document_type") or "generic"),
        }
    )
    summary.append(
        {
            "label": "Filename",
            "value": _fmt_value(report_data.get("filename") or report_data.get("target_file")),
        }
    )

    for key, label in (("hash_md5", "MD5"), ("hash_sha1", "SHA1"), ("hash_sha256", "SHA256")):
        if report_data.get(key):
            summary.append({"label": label, "value": _fmt_value(report_data.get(key))})

    count_map = (
        ("categories", "Categorized Hits"),
        ("matched_rules", "Matched YARA"),
        ("interesting_string_patterns", "Interesting Patterns"),
        ("detected_languages", "Detected Languages"),
        ("linked_dll", "Linked DLLs"),
        ("libraries", "Libraries"),
        ("attachments", "Attachments"),
        ("embedded_files", "Embedded Files"),
        ("extracted_urls", "Extracted URLs"),
    )
    for key, label in count_map:
        if key in report_data:
            summary.append({"label": label, "value": str(_count_items(report_data.get(key)))})

    # Some analyzers (e.g., Android/JAR source analysis) keep category counts under
    # source_summary.category_counts instead of top-level "categories".
    has_categorized_hits = any(str(item.get("label")) == "Categorized Hits" for item in summary)
    if not has_categorized_hits:
        derived_categories = _extract_categories(report_data)
        if derived_categories:
            total_hits = sum(int(row.get("count") or 0) for row in derived_categories)
            summary.append({"label": "Categorized Hits", "value": str(total_hits)})

    mitre_rows = _extract_mitre_rows(report_data)
    if mitre_rows:
        summary.append({"label": "MITRE Tactics", "value": str(len(mitre_rows))})
        summary.append(
            {
                "label": "MITRE Techniques",
                "value": str(int(report_data.get("mitre_technique_count") or sum(int(t.get("technique_count") or 0) for t in mitre_rows))),
            }
        )
        summary.append(
            {
                "label": "MITRE API Matches",
                "value": str(int(report_data.get("mitre_api_match_count") or sum(int(t.get("score") or 0) for t in mitre_rows))),
            }
        )

    perm_section = _extract_permissions_section(report_data)
    perm_counts = perm_section.get("counts", {}) if isinstance(perm_section, dict) else {}
    dangerous_count = int(perm_counts.get("dangerous") or 0)
    special_count = int(perm_counts.get("special") or 0)
    if dangerous_count > 0:
        summary.append({"label": "Dangerous Perms", "value": str(dangerous_count)})
    if special_count > 0:
        summary.append({"label": "Special Perms", "value": str(special_count)})

    return summary[:12]


def _render_inline(value: object, max_items: int = 6, depth: int = 0) -> str:
    if _is_scalar(value):
        return _fmt_value(value)

    if depth >= 2:
        nested_count = _count_items(value)
        if nested_count > 0:
            return f"{nested_count} item"
        if isinstance(value, dict):
            return f"{len(value)} key"
        if isinstance(value, list):
            return f"{len(value)} item"
        return "-"

    if isinstance(value, list):
        parts = [_render_inline(item, max_items=3, depth=depth + 1) for item in value[:max_items]]
        parts = [part for part in parts if part and part != "-"]
        suffix = ""
        if len(value) > max_items:
            suffix = f" (+{len(value) - max_items} more)"
        return _trim_text(_normalize_inline_text(", ".join(parts) + suffix), 220)

    if isinstance(value, dict):
        pairs: List[str] = []
        items = list(value.items())
        for key, item in items[:max_items]:
            rendered = _render_inline(item, max_items=3, depth=depth + 1)
            if rendered and rendered != "-":
                pairs.append(f"{_labelize_key(str(key))}: {rendered}")
        suffix = ""
        if len(items) > max_items:
            suffix = f" (+{len(items) - max_items} more)"
        return _trim_text(_normalize_inline_text("; ".join(pairs) + suffix), 220)

    return _fmt_value(value)


def _serialize_entry(value: object) -> str:
    return _render_inline(value)


def _has_meaningful_golang_data(value: object) -> bool:
    if not isinstance(value, dict):
        return bool(value)

    if bool(value.get("detected")):
        return True
    if bool(value.get("analysis_performed")):
        return True
    try:
        if int(value.get("total_findings") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    if isinstance(value.get("go_sections"), list) and len(value.get("go_sections") or []) > 0:
        return True
    if isinstance(value.get("findings_by_category"), dict) and _count_items(value.get("findings_by_category")) > 0:
        return True
    if isinstance(value.get("finding_counts"), dict) and _count_items(value.get("finding_counts")) > 0:
        return True
    if str(value.get("error") or "").strip():
        return True
    return False


def _preview_items(value: object, limit: int = 18) -> List[str]:
    if isinstance(value, list):
        return [_serialize_entry(item) for item in value[:limit]]

    if isinstance(value, dict):
        preview: List[str] = []
        for key, item in list(value.items())[:limit]:
            if isinstance(item, (list, tuple, set, dict)):
                preview.append(f"{key}: {_count_items(item)} item")
            else:
                preview.append(f"{key}: {_fmt_value(item)}")
        return preview

    if value is None:
        return []

    return [_fmt_value(value)]


def _extract_categories(report_data: dict) -> List[dict]:
    merged: Dict[str, int] = {}

    def _merge_counts(cat_obj: object) -> None:
        if not isinstance(cat_obj, dict):
            return
        for key, value in cat_obj.items():
            count = _count_items(value)
            if count <= 0:
                continue
            name = str(key).strip()
            if not name:
                continue
            merged[name] = merged.get(name, 0) + int(count)

    # Generic analyzer format (Windows/Linux/etc.).
    _merge_counts(report_data.get("categories"))

    # Android/JAR source scanner format.
    source_summary = report_data.get("source_summary")
    if isinstance(source_summary, dict):
        _merge_counts(source_summary.get("category_counts"))

    # Last-resort derivation from source findings when summary counts are absent.
    if not merged:
        findings = report_data.get("source_findings")
        if isinstance(findings, list):
            for item in findings:
                if not isinstance(item, dict):
                    continue
                cats = item.get("categories")
                if not isinstance(cats, list):
                    continue
                for cat in cats:
                    cname = str(cat).strip()
                    if not cname:
                        continue
                    merged[cname] = merged.get(cname, 0) + 1

    rows = [{"name": name, "count": count} for name, count in merged.items() if count > 0]
    rows.sort(key=lambda row: row["count"], reverse=True)
    return rows


def _extract_interesting_patterns(report_data: dict) -> List[str]:
    raw = report_data.get("interesting_string_patterns")
    if not isinstance(raw, list):
        return []

    values: List[str] = []
    seen = set()
    for item in raw:
        candidate = ""
        if isinstance(item, dict):
            # Explicitly ignore "suspicious" marker in UI output.
            candidate = _normalize_inline_text(str(item.get("value") or ""))
        elif item is not None:
            candidate = _normalize_inline_text(str(item))

        if not candidate:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        values.append(candidate)
    return values[:200]


def _extract_source_pattern_rows(report_data: dict) -> List[dict]:
    raw = report_data.get("source_findings")
    if not isinstance(raw, list):
        return []

    rows: List[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        file_name = _normalize_inline_text(str(item.get("file_name") or item.get("file") or ""))
        categories_raw = item.get("categories")
        patterns_raw = item.get("patterns")

        categories: List[str] = []
        if isinstance(categories_raw, list):
            seen_cat = set()
            for cat in categories_raw:
                cname = _normalize_inline_text(str(cat or ""))
                if not cname:
                    continue
                key = cname.lower()
                if key in seen_cat:
                    continue
                seen_cat.add(key)
                categories.append(cname)

        patterns: List[str] = []
        if isinstance(patterns_raw, list):
            seen_pat = set()
            for pat in patterns_raw:
                pname = _normalize_inline_text(str(pat or ""))
                if not pname:
                    continue
                key = pname.lower()
                if key in seen_pat:
                    continue
                seen_pat.add(key)
                patterns.append(pname)

        if not file_name and not patterns:
            continue

        rows.append(
            {
                "file_name": file_name or "-",
                "categories": categories[:12],
                "patterns": patterns[:40],
                "pattern_count": len(patterns),
            }
        )

    rows.sort(key=lambda row: (int(row.get("pattern_count") or 0), len(row.get("categories") or [])), reverse=True)
    return rows[:120]


def _extract_matched_rules(report_data: dict) -> List[dict]:
    raw = report_data.get("matched_rules")
    if not isinstance(raw, list):
        return []

    merged: Dict[str, dict] = {}

    def ensure_rule(rule_name: str) -> dict:
        key = _normalize_inline_text(str(rule_name or "unknown_rule"))
        if key not in merged:
            merged[key] = {
                "name": key,
                "count": 0,
                "samples": [],
                "sample_set": set(),
            }
        return merged[key]

    for entry in raw:
        if isinstance(entry, str):
            normalized_entry = _normalize_inline_text(entry)
            row = ensure_rule(normalized_entry)
            row["count"] += 1
            if normalized_entry not in row["sample_set"]:
                row["sample_set"].add(normalized_entry)
                row["samples"].append({"pattern": normalized_entry, "offset": ""})
            continue

        if not isinstance(entry, dict):
            continue

        for rule_name, hits in entry.items():
            row = ensure_rule(rule_name)

            if isinstance(hits, list):
                if not hits:
                    continue
                for hit in hits:
                    pattern = ""
                    offset = ""
                    if isinstance(hit, dict):
                        pattern = str(hit.get("matched_pattern") or hit.get("pattern") or "").strip()
                        offset = _normalize_inline_text(str(hit.get("offset") or ""))
                    elif hit is not None:
                        pattern = _normalize_inline_text(str(hit))
                    pattern = _normalize_inline_text(pattern)

                    if not pattern:
                        continue
                    row["count"] += 1
                    key = f"{offset}|{pattern}"
                    if key not in row["sample_set"]:
                        row["sample_set"].add(key)
                        row["samples"].append({"pattern": pattern, "offset": offset})
            elif hits:
                pattern = _normalize_inline_text(str(hits))
                if pattern:
                    row["count"] += 1
                    if pattern not in row["sample_set"]:
                        row["sample_set"].add(pattern)
                        row["samples"].append({"pattern": pattern, "offset": ""})

    rows: List[dict] = []
    for row in merged.values():
        rows.append(
            {
                "name": row["name"],
                "count": int(row["count"]),
                "samples": row["samples"][:16],
            }
        )
    rows.sort(key=lambda item: item["count"], reverse=True)
    return rows


def _extract_mitre_rows(report_data: dict) -> List[dict]:
    raw = report_data.get("mitre_attack")
    if not isinstance(raw, dict):
        return []

    tactic_rows: List[dict] = []
    for tactic, techniques_raw in raw.items():
        tactic_name = _normalize_inline_text(str(tactic or ""))
        if not tactic_name:
            continue
        if not isinstance(techniques_raw, list):
            continue

        techniques: List[dict] = []
        total_score = 0
        for item in techniques_raw:
            if not isinstance(item, dict):
                continue
            technique_name = _normalize_inline_text(str(item.get("technique") or ""))
            if not technique_name:
                continue

            matched_apis: List[str] = []
            seen_api = set()
            api_raw = item.get("matched_apis")
            if isinstance(api_raw, list):
                for api in api_raw:
                    api_name = _normalize_inline_text(str(api or ""))
                    if not api_name:
                        continue
                    k = api_name.lower()
                    if k in seen_api:
                        continue
                    seen_api.add(k)
                    matched_apis.append(api_name)

            score = int(item.get("score") or len(matched_apis))
            if score <= 0:
                continue
            total_score += score
            techniques.append(
                {
                    "technique": technique_name,
                    "score": score,
                    "matched_apis": matched_apis[:24],
                }
            )

        if not techniques:
            continue

        techniques.sort(key=lambda row: row["score"], reverse=True)
        tactic_rows.append(
            {
                "tactic": tactic_name,
                "technique_count": len(techniques),
                "score": total_score,
                "techniques": techniques[:80],
            }
        )

    tactic_rows.sort(key=lambda row: (int(row.get("score") or 0), int(row.get("technique_count") or 0)), reverse=True)
    return tactic_rows[:24]


def _extract_permissions_section(report_data: dict) -> dict:
    out = {
        "available": False,
        "counts": {"dangerous": 0, "special": 0, "info": 0},
        "rows": [],
    }
    if not isinstance(report_data, dict):
        return out

    raw = report_data.get("permissions")
    if not isinstance(raw, list):
        summary = report_data.get("permission_summary")
        if isinstance(summary, dict):
            out["counts"] = {
                "dangerous": int(summary.get("dangerous") or 0),
                "special": int(summary.get("special") or 0),
                "info": int(summary.get("info") or 0),
            }
            out["available"] = any(int(v) > 0 for v in out["counts"].values())
        return out

    state_rank = {"dangerous": 3, "special": 2, "info": 1}
    merged: Dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        for perm_name, state_raw in item.items():
            perm = _normalize_inline_text(str(perm_name or ""))
            if not perm:
                continue

            state = _normalize_inline_text(str(state_raw or "")).lower()
            if state in ("risky", "dangerous"):
                norm_state = "dangerous"
            elif state == "special":
                norm_state = "special"
            else:
                norm_state = "info"

            prev = merged.get(perm)
            if not prev or state_rank[norm_state] > state_rank[prev]:
                merged[perm] = norm_state

    if not merged:
        summary = report_data.get("permission_summary")
        if isinstance(summary, dict):
            out["counts"] = {
                "dangerous": int(summary.get("dangerous") or 0),
                "special": int(summary.get("special") or 0),
                "info": int(summary.get("info") or 0),
            }
            out["available"] = any(int(v) > 0 for v in out["counts"].values())
        return out

    rows = []
    counts = {"dangerous": 0, "special": 0, "info": 0}
    for perm, state in merged.items():
        counts[state] += 1
        rows.append({"name": perm, "state": state, "state_label": state.capitalize()})

    rows.sort(key=lambda row: (-state_rank.get(str(row.get("state")), 0), str(row.get("name", "")).lower()))

    out["counts"] = counts
    out["rows"] = rows[:200]
    out["available"] = True
    return out


def _build_detailed_panels(report_data: dict) -> List[dict]:
    panels: List[dict] = []
    for key, value in report_data.items():
        title = _labelize_key(str(key))

        if _is_scalar(value):
            continue

        if isinstance(value, list):
            if not value:
                continue

            if all(isinstance(item, dict) for item in value):
                col_set = OrderedDict()
                for row in value:
                    for col_key in row.keys():
                        col_set[str(col_key)] = True
                        if len(col_set) >= MAX_TABLE_COLS:
                            break
                    if len(col_set) >= MAX_TABLE_COLS:
                        break
                columns = list(col_set.keys())
                rows: List[List[str]] = []
                for row in value[:MAX_TABLE_ROWS]:
                    rows.append([_safe_panel_text(row.get(col)) for col in columns])

                panels.append(
                    {
                        "title": title,
                        "kind": "table",
                        "count": len(value),
                        "columns": columns,
                        "rows": rows,
                    }
                )
            else:
                items = [_safe_panel_text(item) for item in value[:MAX_PANEL_ITEMS]]
                panels.append(
                    {
                        "title": title,
                        "kind": "list",
                        "count": len(value),
                        "items": items,
                    }
                )
            continue

        if isinstance(value, dict):
            if not value:
                continue

            kv_rows: List[dict] = []
            for sub_key, sub_value in list(value.items())[:MAX_PANEL_ITEMS]:
                kv_rows.append({"key": str(sub_key), "value": _safe_panel_text(sub_value)})

            panels.append(
                {
                    "title": title,
                    "kind": "kv",
                    "count": len(value),
                    "rows": kv_rows,
                }
            )

    return panels


def _build_vt_section(report_data: dict) -> dict:
    empty = {
        "available": False,
        "summary": [],
        "threat_names": [],
        "threat_categories": [],
        "detections": [],
        "error": "",
    }

    vt_data: Optional[dict] = None
    nested = report_data.get("virustotal_file")
    if isinstance(nested, dict):
        vt_data = nested
    elif str(report_data.get("analysis_type") or "").strip().lower() == "vt_file":
        vt_data = report_data
    elif str(report_data.get("target_type") or "").strip().lower() == "virustotal_file":
        vt_data = report_data

    if not isinstance(vt_data, dict):
        return empty

    if str(vt_data.get("status") or "").strip().lower() == "unavailable":
        out = dict(empty)
        out["error"] = _fmt_value(vt_data.get("error") or "VirusTotal data is unavailable.")
        return out

    summary: List[dict] = []
    summary_fields = (
        ("Threat Label", "threat_label"),
        ("Detections", "detection_count"),
        ("Engines", "engine_count"),
        ("MD5", "hash_md5"),
        ("Generated At", "generated_at"),
    )
    for label, key in summary_fields:
        if key not in vt_data:
            continue
        value = vt_data.get(key)
        if value in ("", None):
            continue
        summary.append({"label": label, "value": _fmt_value(value)})

    threat_names: List[dict] = []
    for item in vt_data.get("threat_names") or []:
        if not isinstance(item, dict):
            continue
        value = _fmt_value(item.get("value"))
        if value == "-":
            continue
        threat_names.append({"value": value, "count": int(item.get("count") or 0)})

    threat_categories: List[dict] = []
    for item in vt_data.get("threat_categories") or []:
        if not isinstance(item, dict):
            continue
        value = _fmt_value(item.get("value"))
        if value == "-":
            continue
        threat_categories.append({"value": value, "count": int(item.get("count") or 0)})

    detections: List[dict] = []
    for item in vt_data.get("detections") or []:
        if not isinstance(item, dict):
            continue
        engine = _fmt_value(item.get("engine"))
        result = _fmt_value(item.get("result"))
        if engine == "-" or result == "-":
            continue
        detections.append(
            {
                "engine": engine,
                "result": result,
                "category": _fmt_value(item.get("category")),
                "method": _fmt_value(item.get("method")),
            }
        )

    return {
        "available": bool(summary or threat_names or threat_categories or detections),
        "summary": summary[:8],
        "threat_names": threat_names[:12],
        "threat_categories": threat_categories[:12],
        "detections": detections[:80],
        "error": "",
    }


def build_frontend_payload(report_data: Optional[dict]) -> dict:
    if not isinstance(report_data, dict):
        return {
            "summary": [],
            "hashes": [],
            "categories": [],
            "permissions_section": {"available": False, "counts": {"dangerous": 0, "special": 0, "info": 0}, "rows": []},
            "windows_api_categories": [],
            "mitre_rows": [],
            "vt_section": {
                "available": False,
                "summary": [],
                "threat_names": [],
                "threat_categories": [],
                "detections": [],
                "error": "",
            },
            "interesting_patterns": [],
            "source_pattern_rows": [],
            "matched_rules_rows": [],
            "sections": [],
            "metadata": [],
            "extra_panels": [],
            "detailed_panels": [],
            "ai_output": "",
            "ai_iocs": [],
            "ai_context": [],
        }

    hashes: List[dict] = []
    consumed_keys = {
        "target_type",
        "document_type",
        "filename",
        "target_file",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "imphash",
        "categories",
        "matched_rules",
        "interesting_string_patterns",
        "virustotal_file",
        "mitre_attack",
        "mitre_technique_count",
        "mitre_api_match_count",
        "permissions",
        "permission_summary",
    }

    ai_output = ""
    ai_iocs: List[dict] = []
    ai_context: List[dict] = []
    vt_section = _build_vt_section(report_data)
    if isinstance(report_data.get("output"), str):
        ai_output = report_data.get("output", "").strip()
        consumed_keys.add("output")

    if isinstance(report_data.get("llm_extracted_iocs"), dict):
        consumed_keys.add("llm_extracted_iocs")
        ioc_dict = report_data.get("llm_extracted_iocs") or {}
        for kind, values in ioc_dict.items():
            if isinstance(values, list):
                if len(values) == 0:
                    continue
                ai_iocs.append(
                    {
                        "kind": _ioc_kind_label(str(kind)),
                        "count": len(values),
                        "values": [_fmt_value(v) for v in values[:40]],
                    }
                )
            elif values:
                ai_iocs.append(
                    {
                        "kind": _ioc_kind_label(str(kind)),
                        "count": 1,
                        "values": [_fmt_value(values)],
                    }
                )

    for key in ("analysis_type", "engine", "model", "generated_at", "report_file"):
        value = report_data.get(key)
        if value:
            ai_context.append({"label": _labelize_key(key), "value": _fmt_value(value)})
            consumed_keys.add(key)

    windows_api_categories: List[dict] = []
    categories_obj = report_data.get("categories")
    if isinstance(categories_obj, dict):
        for cat_name, cat_values in categories_obj.items():
            if not isinstance(cat_values, list) or not cat_values:
                continue
            if all(isinstance(item, str) for item in cat_values):
                windows_api_categories.append(
                    {
                        "name": str(cat_name),
                        "count": len(cat_values),
                        "apis": [str(api) for api in cat_values[:60]],
                    }
                )
        windows_api_categories.sort(key=lambda row: row["count"], reverse=True)

    interesting_patterns = _extract_interesting_patterns(report_data)
    source_pattern_rows = _extract_source_pattern_rows(report_data)
    matched_rules_rows = _extract_matched_rules(report_data)
    mitre_rows = _extract_mitre_rows(report_data)
    permissions_section = _extract_permissions_section(report_data)

    for key, label in (("hash_md5", "MD5"), ("hash_sha1", "SHA1"), ("hash_sha256", "SHA256"), ("imphash", "Imphash")):
        if report_data.get(key):
            hashes.append({"label": label, "value": str(report_data.get(key))})
            consumed_keys.add(key)

    sections: List[dict] = []
    interesting_keys = (
        ("linked_dll", "Linked DLLs"),
        ("libraries", "Libraries"),
        ("dynamic_libraries", "Dynamic Libraries"),
        ("attachments", "Attachments"),
        ("embedded_files", "Embedded Files"),
        ("extracted_urls", "Extracted URLs"),
        ("segments", "Segments"),
        ("sections", "Sections"),
    )

    for key, title in interesting_keys:
        if key not in report_data:
            continue
        value = report_data.get(key)
        count = _count_items(value)
        if count == 0:
            continue
        consumed_keys.add(key)
        sections.append(
            {
                "title": title,
                "count": count,
                "items": _preview_items(value),
            }
        )

    if "golang" in report_data and not _has_meaningful_golang_data(report_data.get("golang")):
        consumed_keys.add("golang")

    metadata: List[dict] = []
    extra_panels: List[dict] = []
    for key, value in report_data.items():
        if key in consumed_keys:
            continue

        if isinstance(value, (str, int, float, bool)):
            if value in ("", None):
                continue
            metadata.append({"label": _labelize_key(str(key)), "value": _fmt_value(value)})
            continue

        if isinstance(value, list):
            if not value:
                continue
            extra_panels.append(
                {
                    "title": _labelize_key(str(key)),
                    "count": len(value),
                    "items": _preview_items(value, limit=24),
                }
            )
            continue

        if isinstance(value, dict):
            if not value:
                continue
            extra_panels.append(
                {
                    "title": _labelize_key(str(key)),
                    "count": _count_items(value) or len(value),
                    "items": _preview_items(value, limit=24),
                }
            )

    metadata = metadata[:16]

    return {
        "summary": build_summary(report_data),
        "hashes": hashes,
        "categories": _extract_categories(report_data),
        "permissions_section": permissions_section,
        "windows_api_categories": windows_api_categories,
        "mitre_rows": mitre_rows,
        "vt_section": vt_section,
        "interesting_patterns": interesting_patterns,
        "source_pattern_rows": source_pattern_rows,
        "matched_rules_rows": matched_rules_rows,
        "sections": sections,
        "metadata": metadata,
        "extra_panels": extra_panels,
        "detailed_panels": _build_detailed_panels(report_data),
        "ai_output": ai_output,
        "ai_iocs": ai_iocs,
        "ai_context": ai_context,
    }


def _vt_api_key_path() -> Path:
    return Path.home() / "sc0pe_Base" / "sc0pe_VT_apikey.txt"


def _load_vt_api_key() -> str:
    key_file = _vt_api_key_path()
    if not key_file.exists():
        raise RuntimeError("VirusTotal API key not found. Run: python3 qu1cksc0pe.py --key_init")
    key = key_file.read_text(encoding="utf-8").splitlines()[0].strip()
    if not key:
        raise RuntimeError("VirusTotal API key file is empty. Run: python3 qu1cksc0pe.py --key_init")
    if len(key) != 64:
        raise RuntimeError("VirusTotal API key looks invalid (expected 64 chars).")
    return key


def _md5_file(path: Path) -> str:
    md5 = hashlib.md5()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            md5.update(chunk)
    return md5.hexdigest()


def _build_vt_report(vt_data: dict, sample_path: Path, target_hash: str) -> dict:
    data = vt_data.get("data") or {}
    attrs = data.get("attributes") or {}
    threat_class = attrs.get("popular_threat_classification") or {}

    threat_categories = []
    for item in threat_class.get("popular_threat_category") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        threat_categories.append({"value": value, "count": int(item.get("count") or 0)})

    threat_names = []
    for item in threat_class.get("popular_threat_name") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        threat_names.append({"value": value, "count": int(item.get("count") or 0)})

    detections = []
    last_results = attrs.get("last_analysis_results") or {}
    if isinstance(last_results, dict):
        for engine, row in last_results.items():
            if not isinstance(row, dict):
                continue
            result = row.get("result")
            if result is None:
                continue
            detections.append(
                {
                    "engine": str(engine),
                    "result": str(result),
                    "category": str(row.get("category") or ""),
                    "method": str(row.get("method") or ""),
                }
            )
    detections.sort(key=lambda item: item["engine"].lower())

    ids_reports = []
    for row in attrs.get("crowdsourced_ids_results") or []:
        if not isinstance(row, dict):
            continue
        alert_ctx = row.get("alert_context") or []
        if isinstance(alert_ctx, list) and alert_ctx:
            ctx = alert_ctx[0] if isinstance(alert_ctx[0], dict) else {}
        else:
            ctx = {}
        ids_reports.append(
            {
                "severity": str(row.get("alert_severity") or ""),
                "rule_category": str(row.get("rule_category") or ""),
                "rule_source": str(row.get("rule_source") or ""),
                "src_ip": str(ctx.get("src_ip") or ""),
                "src_port": str(ctx.get("src_port") or ""),
                "dest_ip": str(ctx.get("dest_ip") or ""),
                "dest_port": str(ctx.get("dest_port") or ""),
            }
        )

    return {
        "analysis_type": "vt_file",
        "filename": sample_path.name,
        "hash_md5": target_hash,
        "target_type": "virustotal_file",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threat_label": str(threat_class.get("suggested_threat_label") or ""),
        "detection_count": len(detections),
        "engine_count": len(last_results) if isinstance(last_results, dict) else 0,
        "last_analysis_stats": attrs.get("last_analysis_stats") or {},
        "threat_categories": threat_categories,
        "threat_names": threat_names,
        "detections": detections,
        "ids_reports": ids_reports,
        "ids_stats": attrs.get("crowdsourced_ids_stats") or {},
    }


def execute_vtfile_scan(sample_path: Path, command_display: str) -> dict:
    started = time.perf_counter()
    try:
        api_key = _load_vt_api_key()
    except Exception as exc:  # noqa: BLE001
        return {
            "exit_code": 2,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": str(exc),
        }

    target_hash = _md5_file(sample_path)
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{target_hash}",
            headers={"x-apikey": api_key},
            timeout=60,
        )
    except requests.RequestException as exc:
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": f"VirusTotal request failed: {exc}",
        }

    if resp.status_code == 404:
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": "VirusTotal has no report for this file hash yet.",
        }

    if not resp.ok:
        detail = _trim_text(resp.text or "", 600)
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": f"VirusTotal API error ({resp.status_code}): {detail}",
        }

    try:
        vt_data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return {
            "exit_code": 1,
            "timed_out": False,
            "duration": round(time.perf_counter() - started, 2),
            "command_display": command_display,
            "report_expected": True,
            "report_path": "",
            "ai_report_path": "",
            "error_message": f"Failed to parse VirusTotal response: {exc}",
        }

    report = _build_vt_report(vt_data, sample_path, target_hash)
    report_name = f"sc0pe_vt_{target_hash[:12]}_report.json"
    report_path = _unique_report_destination(_report_bucket_dir("vt"), report_name)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    try:
        rel_report_path = str(report_path.relative_to(BASE_DIR))
    except ValueError:
        rel_report_path = str(report_path)

    return {
        "exit_code": 0,
        "timed_out": False,
        "duration": round(time.perf_counter() - started, 2),
        "command_display": command_display,
        "report_expected": True,
        "report_path": rel_report_path,
        "report_data": report,
        "ai_report_path": "",
        "error_message": "",
    }


def _load_json_from_report(report_path: str) -> Optional[dict]:
    resolved = _resolve_report_path(report_path)
    if not resolved or not resolved.exists():
        return None
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    return data


def _embed_vt_result_into_main_report(main_report_path: str, vt_result: dict) -> None:
    resolved = _resolve_report_path(main_report_path)
    if not resolved or not resolved.exists():
        return

    try:
        main_data = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return
    if not isinstance(main_data, dict):
        return

    exit_code_raw = vt_result.get("exit_code")
    try:
        vt_exit_code = int(exit_code_raw) if exit_code_raw is not None else 1
    except (TypeError, ValueError):
        vt_exit_code = 1

    vt_payload: Optional[dict] = None
    if isinstance(vt_result.get("report_data"), dict):
        vt_payload = vt_result.get("report_data")

    vt_report_path = str(vt_result.get("report_path") or "")
    if vt_payload is None and vt_exit_code == 0 and vt_report_path:
        vt_payload = _load_json_from_report(vt_report_path)

    if not isinstance(vt_payload, dict):
        base_error = str(vt_result.get("error_message") or "").strip()
        if not base_error and vt_exit_code == 0:
            base_error = "VirusTotal scan finished but report payload could not be loaded."
        vt_payload = {
            "status": "unavailable",
            "error": base_error or "VirusTotal lookup did not return a report.",
        }

    main_data["virustotal_file"] = vt_payload
    try:
        resolved.write_text(json.dumps(main_data, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001
        return


def execute_preset(sample_path: Path, preset: AnalysisPreset, enable_ai: bool) -> dict:
    command_display = f"{PYTHON_BIN} {ENTRYPOINT} --file {sample_path} {' '.join(preset.args)}"
    if preset.args == ("--vtFile",):
        return execute_vtfile_scan(sample_path=sample_path, command_display=command_display)

    vt_enabled_presets = {("--analyze",), ("--docs",), ("--archive",)}
    vt_future: Optional[concurrent.futures.Future] = None
    vt_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
    vt_result: Optional[dict] = None
    if preset.args in vt_enabled_presets:
        vt_command_display = f"{PYTHON_BIN} {ENTRYPOINT} --file {sample_path} --vtFile"
        vt_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        vt_future = vt_executor.submit(
            execute_vtfile_scan,
            sample_path=sample_path,
            command_display=vt_command_display,
        )

    before_reports = _report_snapshot()
    started = time.perf_counter()

    command = [PYTHON_BIN, str(ENTRYPOINT), "--file", str(sample_path), *preset.args]
    report_expected = bool(preset.report_default or enable_ai)
    if report_expected:
        command.append("--report")
    if enable_ai:
        command.append("--ai")

    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")

    timed_out = False
    completed = None
    try:
        completed = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ANALYSIS_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        completed = subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=_to_text(exc.stdout),
            stderr=_to_text(exc.stderr) + "\nAnalysis timed out.",
        )

    duration = round(time.perf_counter() - started, 2)
    changed_reports = _detect_new_reports(before_reports)
    report_path, ai_report_path = _select_report_paths(changed_reports, ai_enabled=enable_ai)
    stored_report_path = _store_generated_report(report_path, bucket="main")
    stored_ai_report_path = _store_generated_report(ai_report_path, bucket="ai")

    log_output = "\n".join(
        part for part in (_to_text(completed.stdout).strip(), _to_text(completed.stderr).strip()) if part
    ).strip()

    error_message = ""
    if timed_out:
        error_message = "Analysis timed out."
    elif completed.returncode != 0:
        error_message = _trim_text(log_output or "Analyzer process failed.")
    elif report_expected and not stored_report_path:
        error_message = "Analysis finished but no report file was produced."

    if vt_future is not None:
        try:
            vt_result = vt_future.result()
        except Exception as exc:  # noqa: BLE001
            vt_result = {
                "exit_code": 1,
                "timed_out": False,
                "duration": 0.0,
                "command_display": "",
                "report_expected": True,
                "report_path": "",
                "ai_report_path": "",
                "error_message": f"VirusTotal background scan error: {exc}",
            }
        finally:
            if vt_executor is not None:
                vt_executor.shutdown(wait=False)

    if preset.args in vt_enabled_presets and stored_report_path and isinstance(vt_result, dict):
        _embed_vt_result_into_main_report(stored_report_path, vt_result)

    return {
        "exit_code": int(completed.returncode),
        "timed_out": timed_out,
        "duration": duration,
        "command_display": " ".join(_to_text(item) for item in command),
        "report_expected": report_expected,
        "report_path": stored_report_path,
        "ai_report_path": stored_ai_report_path,
        "error_message": error_message,
    }


def _prune_history_locked() -> None:
    if len(JOBS) <= MAX_JOB_HISTORY:
        return

    removable = [
        (job_id, job)
        for job_id, job in JOBS.items()
        if job.get("status") in {"completed", "failed"}
    ]
    removable.sort(key=lambda pair: float(pair[1].get("finished_at") or 0.0))

    target_remove_count = max(0, len(JOBS) - MAX_JOB_HISTORY)
    for job_id, _job in removable[:target_remove_count]:
        JOBS.pop(job_id, None)


def _queue_worker() -> None:
    while True:
        job_id = JOB_QUEUE.get()
        sample_to_cleanup: Optional[Path] = None
        try:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    continue
                job["status"] = "running"
                job["started_at"] = time.time()
                job["updated_at"] = time.time()
                preset_key = str(job["preset_key"])
                enable_ai = bool(job["enable_ai"])
                sample_to_cleanup = Path(str(job["sample_path"]))

            preset = PRESETS.get(preset_key)
            if preset is None:
                result = {
                    "exit_code": 2,
                    "timed_out": False,
                    "duration": 0.0,
                    "command_display": "",
                    "report_expected": False,
                    "report_path": "",
                    "ai_report_path": "",
                    "error_message": "Invalid analysis mode.",
                }
            else:
                result = execute_preset(
                    sample_path=sample_to_cleanup,
                    preset=preset,
                    enable_ai=enable_ai,
                )

            now_ts = time.time()
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    continue

                job["exit_code"] = int(result["exit_code"])
                job["timed_out"] = bool(result["timed_out"])
                job["duration"] = float(result["duration"])
                job["command_display"] = str(result["command_display"])
                job["report_expected"] = bool(result["report_expected"])
                job["report_path"] = str(result["report_path"])
                job["ai_report_path"] = str(result.get("ai_report_path") or "")
                job["error_message"] = str(result.get("error_message") or "")
                job["finished_at"] = now_ts
                job["updated_at"] = now_ts

                if result["exit_code"] == 0 and not result["timed_out"]:
                    job["status"] = "completed"
                else:
                    job["status"] = "failed"

                _prune_history_locked()

        except Exception as exc:  # noqa: BLE001
            now_ts = time.time()
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error_message"] = f"Worker error: {exc}"
                    job["finished_at"] = now_ts
                    job["updated_at"] = now_ts
        finally:
            if sample_to_cleanup:
                try:
                    sample_to_cleanup.unlink(missing_ok=True)
                except OSError:
                    pass
            JOB_QUEUE.task_done()


def _ensure_worker() -> None:
    global WORKER_THREAD
    if WORKER_THREAD and WORKER_THREAD.is_alive():
        return
    WORKER_THREAD = threading.Thread(target=_queue_worker, daemon=True, name="sc0pe-web-worker")
    WORKER_THREAD.start()


def _queue_stats() -> dict:
    with JOBS_LOCK:
        queued = sum(1 for job in JOBS.values() if job.get("status") == "queued")
        running = sum(1 for job in JOBS.values() if job.get("status") == "running")
        return {
            "queued": queued,
            "running": running,
            "total": len(JOBS),
        }


def _job_list_snapshot(limit: int = 50) -> List[dict]:
    with JOBS_LOCK:
        jobs_sorted = sorted(JOBS.values(), key=lambda item: int(item.get("sequence", 0)), reverse=True)
        queued_sorted = sorted(
            (item for item in JOBS.values() if item.get("status") == "queued"),
            key=lambda item: int(item.get("sequence", 0)),
        )
        queue_pos_map = {str(item.get("id")): idx + 1 for idx, item in enumerate(queued_sorted)}

        rows: List[dict] = []
        for item in jobs_sorted[:limit]:
            job_id = str(item.get("id"))
            rows.append(
                {
                    "id": job_id,
                    "sample_name": str(item.get("sample_name", "-")),
                    "preset_label": str(item.get("preset_label", "-")),
                    "status": str(item.get("status", "queued")),
                    "duration": item.get("duration"),
                    "queue_position": queue_pos_map.get(job_id),
                    "created_at_text": _ts_to_text(item.get("created_at")),
                    "started_at_text": _ts_to_text(item.get("started_at")),
                    "finished_at_text": _ts_to_text(item.get("finished_at")),
                }
            )

    return rows


def _job_snapshot(job_id: str) -> Optional[dict]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None

        snapshot = copy.deepcopy(job)
        queued_jobs = [item for item in JOBS.values() if item.get("status") == "queued"]

        if snapshot.get("status") == "queued":
            ahead = sum(1 for item in queued_jobs if int(item.get("sequence", 0)) < int(snapshot.get("sequence", 0)))
            snapshot["queue_position"] = ahead + 1
        elif snapshot.get("status") == "running":
            snapshot["queue_position"] = 0
        else:
            snapshot["queue_position"] = None

        snapshot["queued_total"] = len(queued_jobs)
        snapshot["running_total"] = sum(1 for item in JOBS.values() if item.get("status") == "running")

    snapshot["created_at_text"] = _ts_to_text(snapshot.get("created_at"))
    snapshot["started_at_text"] = _ts_to_text(snapshot.get("started_at"))
    snapshot["finished_at_text"] = _ts_to_text(snapshot.get("finished_at"))
    return snapshot


_ensure_worker()


@app.get("/")
def index():
    return render_template(
        "index.html",
        presets=PRESETS,
        max_upload_mb=MAX_UPLOAD_MB,
        queue_stats=_queue_stats(),
        recent_jobs=_job_list_snapshot(limit=8),
    )


@app.post("/analyze")
def run_analysis_route():
    global JOB_SEQUENCE

    sample = request.files.get("sample")
    preset_key = (request.form.get("preset") or "").strip()
    enable_ai = (request.form.get("enable_ai") or "").strip().lower() in {"1", "true", "on", "yes"}

    if sample is None or not sample.filename:
        flash("Please select a file.", "error")
        return redirect(url_for("index"))

    preset = PRESETS.get(preset_key)
    if preset is None:
        flash("Invalid analysis mode selected.", "error")
        return redirect(url_for("index"))

    safe_name = secure_filename(sample.filename)
    if not safe_name:
        flash("Invalid file name.", "error")
        return redirect(url_for("index"))

    unique_name = f"{uuid.uuid4().hex[:10]}_{safe_name}"
    sample_path = UPLOAD_DIR / unique_name
    sample.save(sample_path)

    job_id = uuid.uuid4().hex
    now_ts = time.time()
    with JOBS_LOCK:
        JOB_SEQUENCE += 1
        JOBS[job_id] = {
            "id": job_id,
            "sequence": JOB_SEQUENCE,
            "status": "queued",
            "sample_name": safe_name,
            "sample_path": str(sample_path),
            "preset_key": preset_key,
            "preset_label": preset.label,
            "enable_ai": enable_ai,
            "created_at": now_ts,
            "updated_at": now_ts,
            "started_at": None,
            "finished_at": None,
            "duration": None,
            "exit_code": None,
            "timed_out": False,
            "command_display": "",
            "report_expected": bool(preset.report_default or enable_ai),
            "report_path": "",
            "ai_report_path": "",
            "error_message": "",
        }

    JOB_QUEUE.put(job_id)
    return redirect(url_for("job_result", job_id=job_id))


@app.get("/jobs")
def jobs_dashboard():
    return render_template(
        "jobs.html",
        jobs=_job_list_snapshot(limit=100),
        queue_stats=_queue_stats(),
        auto_refresh=True,
        refresh_seconds=2,
    )


@app.get("/api/jobs")
def jobs_api():
    return jsonify(
        {
            "queue": _queue_stats(),
            "jobs": _job_list_snapshot(limit=100),
        }
    )


@app.get("/jobs/<job_id>")
def job_result(job_id: str):
    job = _job_snapshot(job_id)
    if not job:
        return redirect(url_for("index"))

    report_view = _load_report_for_job(job)
    job["report_loaded"] = bool(report_view["report_loaded"])
    job["report_file_label"] = str(report_view["report_file_label"])
    job["report_load_error"] = str(report_view["report_load_error"])
    job["report_ui"] = report_view["report_ui"]
    job["ai_loaded"] = bool(report_view["ai_loaded"])
    job["ai_file_label"] = str(report_view["ai_file_label"])
    job["ai_load_error"] = str(report_view["ai_load_error"])
    job["ai_ui"] = report_view["ai_ui"]

    auto_refresh = job.get("status") in {"queued", "running"}
    return render_template(
        "result.html",
        job=job,
        auto_refresh=auto_refresh,
        refresh_seconds=2,
    )


@app.errorhandler(413)
def file_too_large(_error):
    flash(f"File is too large. Maximum: {MAX_UPLOAD_MB} MB.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
