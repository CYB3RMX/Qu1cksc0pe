#!/usr/bin/python3

import re
import sys
import ipaddress
from urllib.parse import urlparse
from collections import OrderedDict

try:
   # by default, assume we're running as a module, inside a package
   from .utils.helpers import err_exit, get_argv, save_report
   from .analysis.multiple.multi import perform_strings
except ImportError:
   # fallback for running as "raw" Python file
   from utils.helpers import err_exit, get_argv, save_report
   from analysis.multiple.multi import perform_strings

# Module for colors
try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

# Target file / options
target_file = get_argv(1)
if not target_file:
   err_exit("[bold white on red]Target file not found!\n")
emit_report = str(get_argv(2, "False")).lower() == "true"

# Compatibility
strings_param = "--all"
if sys.platform == "win32":
   strings_param = "-a"
elif sys.platform == "darwin":
   strings_param = "-a"
else:
   pass

# All strings
allStrings = perform_strings(target_file)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Regex zone (Thanks to: https://github.com/dwisiswant0 for regex strings)
regex_dict = {
   "Amazon_AWS_Access_Key_ID": r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
   "Amazon_AWS_S3_Bucket": r"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
   "Discord_Attachments": r"((media|cdn)\.)?(discordapp\.net\/attachments|discordapp\.com\/attachments)\/.+[a-z]",
   "Discord_BOT_Token": r"((?:N|M|O)[a-zA-Z0-9]{23}\\.[a-zA-Z0-9-_]{6}\\.[a-zA-Z0-9-_]{27})$",
   "Facebook_Secret_Key": r"([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K]|[f|F][b|B])(.{0,20})?['\"][0-9a-f]{32}",
   "Bitcoin_Wallet_Address": r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
   "Firebase": r"[a-z0-9.-]+\\.firebaseio\\.com",
   "GitHub": r"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
   "Google_API_Key": r"AIza[0-9A-Za-z\\-_]{35}",
   "Heroku_API_Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
   "IP_Address": r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$",
   "URL": r"http[s]?://[a-zA-Z0-9./@?=_%:-]*",
   "Monero_Wallet_Address": r"4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}",
   "Mac_Address": r"(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\\.]){2}[0-9A-Fa-f]{4})$",
   "Mailto": r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+",
   "Onion": r"([a-z2-7]{16}|[a-z2-7]{56}).onion",
   "Telegram_BOT_Token": r"\d{9}:[0-9A-Za-z_-]{35}",
}

_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
_NIX_PATH_RE = re.compile(r"(?:/home/|/tmp/|/etc/|/var/|/usr/|/system/)[^\s\"']+")
_PRINTF_PLACEHOLDER_RE = re.compile(
   r"%(?:\d+\$)?[-+0# ]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|L|z|j|t)?[diuoxXfFeEgGaAcspn]"
)
_NON_DOMAIN_FILELIKE_TLDS = {
   "xml", "json", "yaml", "yml", "toml", "ini", "conf", "config", "cfg", "csv", "tsv", "txt", "log",
   "db",
   "exe", "dll", "sys", "bin", "dat", "tmp", "ps1", "vbs", "vba", "vbe", "js", "jse", "wsf", "cmd", "bat", "sh", "py", "jar",
   "class", "dex", "apk", "elf", "so", "o", "obj", "pdb",
   "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt", "ods", "odp", "eml", "msg",
   "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "msi", "msp", "iso",
   "png", "jpg", "jpeg", "gif", "bmp", "tiff", "svg", "ico", "webp",
   "mp3", "wav", "flac", "mp4", "mkv", "avi", "mov", "html", "htm", "crt",
}
_COMMON_GTLDS_STRICT = {
   "com", "net", "org", "info", "biz", "name", "pro", "xyz", "top", "site", "online", "store", "shop",
   "app", "dev", "io", "me", "cc", "live", "link", "click", "work", "club", "pw", "win", "host", "space",
   "tech", "cloud", "services", "support", "today", "news", "blog", "agency", "digital", "media", "email",
   "world", "website", "monster", "finance", "trade", "download", "onion",
}
_BLOCKED_SAMPLE_DOMAINS = {"example.com", "example.org", "example.net", "curl.se"}
_BLOCKED_DOMAIN_SUFFIXES = {"hostcli.com", "pool.ntp.org"}
_PL_NOISE_SLD = {"default", "system", "bind", "pymake", "ipv6", "port"}
_NON_DOMAIN_NAMESPACE_TOKENS = {
   "text", "data", "bss", "ro", "rel", "rela", "got", "plt", "init", "fini",
   "dyn", "sym", "str", "tab", "eh", "frame", "interp", "note", "comment",
   "debug", "gnu", "arm", "attributes", "tls", "ctors", "dtors",
}
_HASH_HINT_WORDS = (
   "md5",
   "sha1",
   "sha-1",
   "sha256",
   "sha-256",
   "sha512",
   "sha-512",
   "hash",
   "digest",
   "checksum",
   "imphash",
   "ssdeep",
)


def _normalize_domain(value):
   domain = str(value or "").strip().lower().rstrip(".")
   if domain.startswith("www."):
      domain = domain[4:]
   return domain


def _is_valid_domain(value):
   domain = _normalize_domain(value)
   if not domain or len(domain) > 253:
      return False
   if domain in _BLOCKED_SAMPLE_DOMAINS:
      return False
   for blocked_suffix in _BLOCKED_DOMAIN_SUFFIXES:
      if domain == blocked_suffix or domain.endswith("." + blocked_suffix):
         return False
   if "://" in domain or "/" in domain or "@" in domain or " " in domain or "%" in domain:
      return False

   parts = domain.split(".")
   if len(parts) < 2:
      return False
   namespace_hits = sum(1 for p in parts if p in _NON_DOMAIN_NAMESPACE_TOKENS)
   if len(parts) >= 3 and namespace_hits >= 2 and namespace_hits >= (len(parts) - 1):
      return False

   tld = parts[-1]
   sld = parts[-2]

   if len(tld) < 2 or len(tld) > 24:
      return False
   if len(sld) < 3:
      return False
   if tld == "pl" and sld in _PL_NOISE_SLD:
      return False
   if tld in _NON_DOMAIN_FILELIKE_TLDS:
      return False
   if len(tld) != 2 and tld not in _COMMON_GTLDS_STRICT:
      return False

   for part in parts:
      if not part or len(part) > 63:
         return False
      if part.startswith("-") or part.endswith("-"):
         return False
      if not re.fullmatch(r"[a-z0-9-]+", part):
         return False
   return True


def _is_valid_ip(value):
   try:
      ipaddress.ip_address(str(value or "").strip())
      return True
   except Exception:
      return False


def _is_valid_url(value):
   url = str(value or "").strip()
   if not url:
      return False
   if _PRINTF_PLACEHOLDER_RE.search(url):
      return False

   try:
      parsed = urlparse(url)
   except Exception:
      return False
   if parsed.scheme not in ("http", "https"):
      return False
   if not parsed.netloc:
      return False

   host = _normalize_domain(parsed.hostname or "")
   if not host:
      return False
   if "%" in host or "{" in host or "}" in host:
      return False
   if not (_is_valid_domain(host) or _is_valid_ip(host)):
      return False
   return True


def _dedupe_preserve(values):
   seen = set()
   out = []
   for raw in values:
      value = str(raw).strip()
      if not value:
         continue
      key = value.lower()
      if key in seen:
         continue
      seen.add(key)
      out.append(value)
   return out


def _build_llm_style_iocs(findings):
   iocs = {}

   urls = [u for u in _dedupe_preserve(findings.get("URL", [])) if _is_valid_url(u)]
   ips = _dedupe_preserve(findings.get("IP_Address", []))
   emails = _dedupe_preserve(findings.get("Mailto", []))
   if urls:
      iocs["urls"] = urls[:100]
   if ips:
      iocs["ips"] = ips[:100]
   if emails:
      iocs["emails"] = emails[:100]

   domains = []
   for url in urls:
      try:
         host = (urlparse(url).hostname or "").strip().lower()
      except Exception:
         host = ""
      host = _normalize_domain(host)
      if _is_valid_domain(host):
         domains.append(host)
   for line in allStrings:
      for match in _DOMAIN_RE.findall(str(line)):
         candidate = _normalize_domain(match)
         if _is_valid_domain(candidate):
            domains.append(candidate)
   domains = _dedupe_preserve(domains)
   if domains:
      iocs["domains"] = domains[:100]

   hashes = []
   file_paths = []
   for line in allStrings:
      text = str(line)
      text_norm = text.strip()
      text_lower = text_norm.lower()
      has_hash_hint = any(hint in text_lower for hint in _HASH_HINT_WORDS)
      for hv in _HASH_RE.findall(text):
         if not _is_probable_hash(hv, text_norm, has_hash_hint):
            continue
         hashes.append(hv)
      for fp in _WIN_PATH_RE.findall(text):
         file_paths.append(fp)
      for fp in _NIX_PATH_RE.findall(text):
         file_paths.append(fp)
   hashes = _dedupe_preserve(hashes)
   file_paths = _dedupe_preserve(file_paths)
   if hashes:
      iocs["hashes"] = hashes[:100]
   if file_paths:
      iocs["file_paths"] = file_paths[:100]

   return iocs


def _is_probable_hash(value, _line_text, has_hash_hint):
   h = str(value or "").strip()
   if not h:
      return False

   lower = h.lower()
   # In binary/string dumps, random 64-hex constants are frequent.
   # Only keep hashes when the same line has explicit hash context.
   if not has_hash_hint:
      return False

   # Drop obvious placeholders and synthetic constants.
   if len(set(lower)) < 6:
      return False
   if re.fullmatch(r"(.)\1+", lower):
      return False

   # Reject repeated short blocks such as 5c3c5c3c... or ababab...
   for block_len in (1, 2, 4, 8):
      if len(lower) % block_len != 0:
         continue
      block = lower[:block_len]
      if block * (len(lower) // block_len) == lower:
         return False

   # Reject if one hex character dominates too much (placeholder-like).
   most_common = max(lower.count(ch) for ch in set(lower))
   if (most_common / len(lower)) >= 0.34:
      return False

   return True

# Main function
def RegexScanner():
   counter = 0
   findings = OrderedDict((k, []) for k in regex_dict.keys())
   seen = {k: set() for k in regex_dict.keys()}
   print(f"{infoS} Qu1cksc0pe is analyzing this file for possible domain and interesting strings. Please wait...\n")
   for key in regex_dict:
      for targ in allStrings:
         try:
            match = re.search(str(regex_dict[key]), str(targ))
            if match:
               matched_value = str(match[0]).strip()
               if not matched_value:
                  continue
               if matched_value in seen[key]:
                  continue
               seen[key].add(matched_value)
               findings[key].append(matched_value)
               print(f"[bold cyan][[bold red]{key}[bold cyan]]>[white] {matched_value}")
               counter += 1
         except:
            continue
   if counter == 0:
      print(f"{errorS} There is no possible domain strings found.")
   if emit_report:
      llm_extracted_iocs = _build_llm_style_iocs(findings)
      report = {
         "target_type": "domain_ioc",
         "filename": target_file,
         "extracted_urls": findings.get("URL", []),
         "extracted_ips": findings.get("IP_Address", []),
         "extracted_emails": findings.get("Mailto", []),
         "llm_extracted_iocs": llm_extracted_iocs,
         "ioc_matches": [
            {
               "kind": key,
               "count": len(values),
               "values": values,
            }
            for key, values in findings.items()
            if values
         ],
      }
      save_report("domain", report)

#Execution zone
RegexScanner()
