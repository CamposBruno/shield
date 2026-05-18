#!/usr/bin/env python3
"""Scan a GitHub repo + its dependencies against the OpenSourceMalware API."""

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

API_BASE = "https://api.opensourcemalware.com/functions/v1"
API_URL = f"{API_BASE}/check-malicious"
SUBMIT_URL = "https://zyqmpfcrijqmwyzbkubf.supabase.co/functions/v1/submit-threat-report"
TOKEN = os.environ.get("OSM_TOKEN")
if not TOKEN:
    sys.exit("OSM_TOKEN environment variable is required")

MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024


def osm_check(report_type, resource_identifier, ecosystem=None):
    params = {"report_type": report_type, "resource_identifier": resource_identifier}
    if ecosystem:
        params["ecosystem"] = ecosystem
    url = f"{API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e), "malicious": None, "scan_count": 0}


def osm_submit(payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SUBMIT_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "ignore")
        except Exception:
            body = ""
        return e.code, {"error": str(e), "body": body}
    except Exception as e:
        return None, {"error": str(e)}


def _parse_github_url(url):
    m = re.match(r"^https?://github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", url.strip())
    if not m:
        raise ValueError(f"Not a github.com repo URL: {url}")
    return m.group(1), m.group(2)


def _safe_extract(tar, dest):
    """Extract a tar safely: refuse absolute paths, traversal, symlinks, devices."""
    dest_real = os.path.realpath(dest)
    members = []
    total = 0
    for m in tar.getmembers():
        if m.issym() or m.islnk() or m.isdev() or m.isfifo():
            continue
        name = m.name.lstrip("/").replace("\\", "/")
        if ".." in name.split("/"):
            continue
        target = os.path.realpath(os.path.join(dest_real, name))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            continue
        if m.isfile():
            total += m.size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError(
                    f"tarball exceeds decompressed cap ({MAX_EXTRACTED_BYTES} bytes)"
                )
        m.mode = 0o600 if m.isfile() else 0o700
        members.append(m)
    # Python 3.12+: extra hardening via filter
    kwargs = {"members": members}
    if hasattr(tarfile, "data_filter"):
        kwargs["filter"] = "data"
    tar.extractall(dest_real, **kwargs)


def fetch_repo(url, dest):
    """Download the default-branch tarball over HTTPS. No git involved."""
    owner, repo = _parse_github_url(url)
    tarball = f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
    req = urllib.request.Request(tarball, headers={"User-Agent": "osm-scan"})
    tar_path = os.path.join(os.path.dirname(dest), "src.tar.gz")
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(tar_path, "wb") as out:
            written = 0
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise ValueError(
                        f"tarball exceeds download cap ({MAX_DOWNLOAD_BYTES} bytes)"
                    )
                out.write(chunk)
        os.makedirs(dest, exist_ok=True)
        with tarfile.open(tar_path, "r:gz") as t:
            _safe_extract(t, dest)
    finally:
        if os.path.exists(tar_path):
            os.remove(tar_path)


def deps_from_package_json(path):
    data = json.loads(path.read_text())
    out = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name in (data.get(key) or {}):
            out.append(("npm", name))
    return out


def deps_from_requirements(path):
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[<>=!~;\[\s]", line, 1)[0].strip()
        if name:
            out.append(("PyPI", name))
    return out


def collect_deps(repo_dir):
    deps = []
    for pj in Path(repo_dir).rglob("package.json"):
        if "node_modules" in pj.parts:
            continue
        try:
            deps.extend(deps_from_package_json(pj))
        except Exception:
            pass
    for rq in Path(repo_dir).rglob("requirements*.txt"):
        try:
            deps.extend(deps_from_requirements(rq))
        except Exception:
            pass
    # de-dup
    return sorted(set(deps))


SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__", ".venv", "venv", ".next", ".nuxt", "target"}
BIN_EXTS = {".png",".jpg",".jpeg",".gif",".webp",".ico",".svg",".woff",".woff2",".ttf",".otf",".eot",
            ".zip",".tar",".gz",".bz2",".xz",".7z",".rar",".exe",".dll",".so",".dylib",".bin",
            ".pdf",".mp3",".mp4",".mov",".wav",".flac",".ogg",".class",".jar",".wasm",".map",".lock",".snap"}
MAX_BYTES = 1_000_000
HOOK_NAMES = {
    "applypatch-msg","pre-applypatch","post-applypatch","pre-commit","pre-merge-commit",
    "prepare-commit-msg","commit-msg","post-commit","pre-rebase","post-checkout","post-merge",
    "pre-push","pre-receive","update","proc-receive","post-receive","post-update",
    "reference-transaction","push-to-checkout","pre-auto-gc","post-rewrite",
    "sendemail-validate","fsmonitor-watchman","p4-changelist","p4-prepare-changelist",
    "p4-post-changelist","p4-pre-submit",
}

JS_TS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}


def _scope_any(rel, fn, ext):
    return True


def _scope_js_ts_like(rel, fn, ext):
    return ext in JS_TS_EXTS or fn == "package.json" or ext == ".json"


def _scope_py(rel, fn, ext):
    return ext == ".py"


def _scope_gitattributes(rel, fn, ext):
    return fn == ".gitattributes"


def _scope_gitconfig(rel, fn, ext):
    parts = Path(rel).parts
    return fn in {".gitconfig", "config"} and any(p == ".git" or p.startswith(".git") for p in parts) \
        or fn == ".gitconfig"


# (severity, description, compiled_regex, scope_predicate)
# Each rule is anchored to a real invocation context AND scoped to file types
# where the pattern is meaningful, so the rule's own description/regex source
# cannot match itself.
CONTENT_RULES = [
    ("high", "curl/wget piped to shell",
        re.compile(rb"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:bash|sh|zsh)\b"),
        _scope_any),
    ("high", "PowerShell stealth/IEX/EncodedCommand",
        re.compile(
            rb"(?:^|[\s;&|`>(])powershell(?:\.exe)?\s+[^\n]{0,300}?"
            rb"(?:-w(?:indowstyle)?\s+hidden\b|-e(?:c|nc(?:odedcommand)?)\b|"
            rb"invoke-expression\s*[\(\"']|\biex\s*[\(\"']|start-process\s+\S)",
            re.I),
        _scope_any),
    ("high", "shell:true in child process options",
        re.compile(rb"[{,]\s*['\"]?shell['\"]?\s*:\s*true\b"),
        _scope_js_ts_like),
    ("high", "base64 piped to shell",
        re.compile(rb"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,200}\|\s*(?:bash|sh)\b"),
        _scope_any),
    ("medium", "subprocess with shell=True",
        re.compile(rb"\bsubprocess\.[A-Za-z_]+\s*\([^)]{0,400}shell\s*=\s*True", re.S),
        _scope_py),
    ("medium", "os.system / os.popen",
        re.compile(rb"\bos\.(?:system|popen)\s*\("),
        _scope_py),
    ("medium", ".gitattributes smudge/clean filter (non-lfs)",
        re.compile(rb"(?m)^\s*\S+\s+.*\bfilter=(?!lfs\b)\S+"),
        _scope_gitattributes),
    ("medium", "core.hooksPath override",
        re.compile(rb"(?im)^\s*hooksPath\s*="),
        _scope_gitconfig),
]
LIFECYCLE_KEYS = {"preinstall","install","postinstall","prepare","prepublish","prepublishOnly","preuninstall","postuninstall"}
LIFECYCLE_BAD = re.compile(r"curl\b|wget\b|\bnode\s+-e\b|child_process|\beval\b|powershell|base64\s+-d|--decode\b|nc\s+-e|/dev/tcp/", re.I)
OBFUSCATOR_TOKEN = re.compile(rb"_0x[0-9a-fA-F]{4,}")
EVAL_RE = re.compile(rb"\beval\s*\(")
URL_RE = re.compile(rb"https?://[^\s'\"\\)<>]+")
FETCHY_RE = re.compile(rb"\b(?:axios|fetch|XMLHttpRequest|\.get|\.post|request\s*\()")


def _looks_binary(blob):
    return b"\x00" in blob[:4096]


def _scan_text_content(rel_path, blob, fn, ext):
    findings = []
    for sev, desc, rx, scope in CONTENT_RULES:
        if not scope(rel_path, fn, ext):
            continue
        if rx.search(blob):
            findings.append((sev, desc, rel_path))
    # Obfuscator heuristic — JS/TS only (hex-ish identifiers occur naturally
    # in regex sources and crypto libs in other languages).
    if ext in JS_TS_EXTS and len(OBFUSCATOR_TOKEN.findall(blob)) >= 10:
        findings.append(("high", "JS obfuscator pattern (_0x… identifiers)", rel_path))
    # Remote-eval: only meaningful in JS/TS, and only when eval, a URL, and a
    # fetch primitive sit within ~400 chars of each other (i.e. plausibly the
    # same logical block), not merely co-occurring in a large file.
    if ext in JS_TS_EXTS:
        for m in EVAL_RE.finditer(blob):
            window = blob[max(0, m.start() - 400): m.end() + 400]
            if URL_RE.search(window) and FETCHY_RE.search(window):
                findings.append(("high", "eval() alongside remote URL fetch", rel_path))
                break
    return findings


def _scan_package_json(rel_path, data):
    findings = []
    scripts = data.get("scripts") or {}
    if not isinstance(scripts, dict):
        return findings
    for k, v in scripts.items():
        if not isinstance(v, str):
            continue
        if k in LIFECYCLE_KEYS and LIFECYCLE_BAD.search(v):
            findings.append(("high", f"lifecycle script '{k}' runs suspicious command", rel_path))
    return findings


def scan_local(repo_dir):
    findings = []
    root = Path(repo_dir)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        # committed git hook directories
        low = os.path.basename(dirpath).lower()
        parent_match = ("hooks" in Path(dirpath).parts) or low in {".githooks", "githooks"}
        for fn in filenames:
            full = Path(dirpath) / fn
            rel = str(full.relative_to(root))
            ext = full.suffix.lower()

            if parent_match and fn in HOOK_NAMES and not fn.endswith(".sample"):
                findings.append(("high", f"committed git hook '{fn}'", rel))

            if ext in BIN_EXTS:
                continue
            try:
                if full.stat().st_size > MAX_BYTES:
                    continue
                blob = full.read_bytes()
            except OSError:
                continue
            if _looks_binary(blob):
                continue

            findings.extend(_scan_text_content(rel, blob, fn, ext))

            if fn == "package.json":
                try:
                    findings.extend(_scan_package_json(rel, json.loads(blob.decode("utf-8", "ignore"))))
                except Exception:
                    pass
    return findings


def verdict(api_results, local_findings):
    if any(r.get("malicious") is True for r in api_results):
        return "UNSAFE"
    if any(sev == "high" for sev, *_ in local_findings):
        return "UNSAFE"
    api_all_known_clean = all(
        r.get("malicious") is False and (r.get("scan_count") or 0) > 0
        for r in api_results
    )
    if api_all_known_clean and not local_findings:
        return "SAFE"
    return "NEEDS INVESTIGATION"


TAG_MAP = {
    "curl/wget piped to shell": "remote-shell",
    "base64 piped to shell": "obfuscated-shell",
    "PowerShell stealth/IEX/EncodedCommand": "powershell-stealth",
    "shell:true in child process options": "child-process",
    "subprocess with shell=True": "child-process",
    "os.system / os.popen": "child-process",
    "JS obfuscator pattern (_0x… identifiers)": "obfuscated-code",
    "eval() alongside remote URL fetch": "remote-eval",
    ".gitattributes smudge/clean filter (non-lfs)": "git-filter",
    "core.hooksPath override": "git-hooks",
}


def build_report(url, repo_res, dep_results, local_findings):
    high = [f for f in local_findings if f[0] == "high"]
    med = [f for f in local_findings if f[0] == "medium"]
    bad_pkgs = [r for r in dep_results if r.get("malicious") is True]

    if any("git hook" in f[1] or "lifecycle script" in f[1] for f in high):
        severity = "critical"
    elif high:
        severity = "high"
    else:
        severity = "medium"

    lines = [f"Automated scan of {url} flagged this repository as UNSAFE."]
    if bad_pkgs:
        names = ", ".join(f"{r.get('ecosystem')}:{r.get('resource_identifier')}" for r in bad_pkgs)
        lines.append(f"Ships known-malicious dependencies: {names}.")
    if high:
        lines.append(f"{len(high)} high-severity local indicator(s):")
        for sev, desc, rel in high[:10]:
            lines.append(f" - {desc} ({rel})")
        if len(high) > 10:
            lines.append(f" - ... and {len(high) - 10} more")
    if med:
        lines.append(f"Plus {len(med)} medium-severity indicator(s).")

    tags = set()
    for _, desc, _ in local_findings:
        for k, v in TAG_MAP.items():
            if desc.startswith(k) or k in desc:
                tags.add(v)
    if "committed git hook" in " ".join(f[1] for f in local_findings):
        tags.add("git-hooks")
    if "lifecycle script" in " ".join(f[1] for f in local_findings):
        tags.add("npm-lifecycle")

    payload = {
        "report_type": "repository",
        "resource_identifier": url,
        "threat_description": "\n".join(lines),
        "severity_level": severity,
        "evidence_references": url,
        "tags": sorted(tags) or ["automated-scan"],
    }
    return payload


def _should_submit(verdict_str, args):
    if verdict_str != "UNSAFE":
        return False
    if args.no_report:
        return False
    if args.report:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        ans = input("Submit this finding to opensourcemalware.com? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def main():
    ap = argparse.ArgumentParser(description="Scan a GitHub repo for malware via OpenSourceMalware.")
    ap.add_argument("url", help="GitHub repo HTTPS URL")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--report", action="store_true", help="Submit a threat report if UNSAFE (no prompt)")
    g.add_argument("--no-report", action="store_true", help="Never submit, never prompt")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="osm_")
    repo_dir = os.path.join(tmp, "repo")
    try:
        print("[*] Checking repository against OpenSourceMalware ...")
        repo_res = osm_check("repository", args.url)
        print(f"    repo: malicious={repo_res.get('malicious')} "
              f"severity={repo_res.get('scan_severity')} "
              f"scans={repo_res.get('scan_count')}")

        if repo_res.get("malicious") is True:
            osm_link = (
                "https://opensourcemalware.com/repository/"
                + urllib.parse.quote(args.url, safe="")
            )
            print()
            print("=== VERDICT: UNSAFE ===")
            print(f"[*] Trusting OpenSourceMalware verdict for {args.url}; skipping local scan.")
            print(f"    see details at: {osm_link}")
            sys.exit(2)

        print(f"[*] Downloading tarball {args.url} ...")
        try:
            fetch_repo(args.url, repo_dir)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)

        print("[*] Collecting dependencies ...")
        deps = collect_deps(repo_dir)
        print(f"    found {len(deps)} unique dependencies")

        dep_results = []
        for eco, name in deps:
            r = osm_check("package", name, eco)
            dep_results.append(r)
            flag = "!" if r.get("malicious") else (" " if r.get("scan_count") else "?")
            print(f"    [{flag}] {eco}:{name} "
                  f"malicious={r.get('malicious')} scans={r.get('scan_count')}")

        print("[*] Static scan for hooks / suspicious scripts / child-process spawns ...")
        local = scan_local(repo_dir)
        if not local:
            print("    no local indicators")
        else:
            highs = sum(1 for s, *_ in local if s == "high")
            meds = sum(1 for s, *_ in local if s == "medium")
            print(f"    {highs} HIGH, {meds} MEDIUM findings")
            for sev, desc, rel in local[:50]:
                print(f"    [{sev.upper()}] {desc}  ({rel})")
            if len(local) > 50:
                print(f"    ... {len(local) - 50} more")

        v = verdict([repo_res] + dep_results, local)
        print()
        print(f"=== VERDICT: {v} ===")

        if _should_submit(v, args):
            payload = build_report(args.url, repo_res, dep_results, local)
            print(f"[*] Submitting threat report (severity={payload['severity_level']}, "
                  f"tags={payload['tags']}) ...")
            status, resp = osm_submit(payload)
            if status in (200, 201):
                print(f"    submitted: threat_id={resp.get('threat_id')} status={resp.get('status')}")
            else:
                print(f"    submit failed: HTTP {status} {resp}")

        sys.exit(0 if v == "SAFE" else (2 if v == "UNSAFE" else 1))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
