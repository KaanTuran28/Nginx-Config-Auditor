#!/usr/bin/env python3
"""Static security auditor for nginx configuration files.

Regex-based (not a full nginx-config-grammar parser) — flags common
hardening gaps: version disclosure, directory listing, deprecated TLS
protocols, weak cipher suites, missing security response headers, unguarded
access to dotfiles, and unlimited request body size.
"""

import argparse
import json
import re
import sys
from pathlib import Path

DEPRECATED_TLS_PROTOCOLS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "MD5", "NULL", "EXPORT")
RECOMMENDED_HEADERS = ("X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security")

DOTFILE_DENY_RE = re.compile(r"location\s+~\s*/\\?\.[^\s{]*\s*\{[^}]*deny\s+all", re.IGNORECASE | re.DOTALL)


def line_of(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def find_weak_cipher_hits(ciphers_value: str) -> list:
    included_tokens = [t.strip() for t in ciphers_value.split(":") if t.strip() and not t.strip().startswith("!")]
    hits = set()
    for token in included_tokens:
        upper = token.upper().lstrip("+")
        for keyword in WEAK_CIPHER_KEYWORDS:
            if keyword in upper:
                hits.add(keyword)
    return sorted(hits)


def finding(severity: str, line, check: str, reason: str, recommendation: str) -> dict:
    return {"severity": severity, "line": line, "check": check, "reason": reason, "recommendation": recommendation}


def audit(text: str) -> list:
    findings = []

    m = re.search(r"server_tokens\s+(on|off)\s*;", text, re.IGNORECASE)
    if not m or m.group(1).lower() == "on":
        findings.append(finding(
            "MEDIUM", line_of(text, m.start()) if m else None, "server_tokens_enabled",
            "server_tokens is not set to off (or missing, which defaults to on) — the Server response "
            "header discloses the nginx version, helping an attacker fingerprint known CVEs.",
            "Add 'server_tokens off;' in the http (or server) block.",
        ))

    for m in re.finditer(r"autoindex\s+on\s*;", text, re.IGNORECASE):
        findings.append(finding(
            "HIGH", line_of(text, m.start()), "autoindex_enabled",
            "autoindex on generates a directory listing for any request with no matching index file, "
            "potentially exposing files never meant to be public.",
            "Remove autoindex, or set it to off, and serve an explicit index/file list instead.",
        ))

    for m in re.finditer(r"ssl_protocols\s+([^;]+);", text, re.IGNORECASE):
        protocols = {p.strip().upper() for p in m.group(1).split()}
        deprecated = sorted(protocols & DEPRECATED_TLS_PROTOCOLS)
        if deprecated:
            findings.append(finding(
                "HIGH", line_of(text, m.start()), "deprecated_tls_protocol",
                f"ssl_protocols enables deprecated/insecure protocol(s): {', '.join(deprecated)}.",
                "Set ssl_protocols to TLSv1.2 and TLSv1.3 only.",
            ))

    for m in re.finditer(r"ssl_ciphers\s+([^;]+);", text, re.IGNORECASE):
        weak_hits = find_weak_cipher_hits(m.group(1))
        if weak_hits:
            findings.append(finding(
                "MEDIUM", line_of(text, m.start()), "weak_cipher_suite",
                f"ssl_ciphers includes weak/broken cipher keyword(s): {', '.join(weak_hits)}.",
                "Use a modern cipher list, e.g. ECDHE+AESGCM, and explicitly exclude weak ciphers "
                "(!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP).",
            ))

    for header in RECOMMENDED_HEADERS:
        if not re.search(rf"add_header\s+{re.escape(header)}\b", text, re.IGNORECASE):
            findings.append(finding(
                "MEDIUM", None, "missing_security_header",
                f'No "add_header {header}" directive found anywhere in this file.',
                f'Add "add_header {header} ...;" in the server or location block.',
            ))

    if not DOTFILE_DENY_RE.search(text):
        findings.append(finding(
            "MEDIUM", None, "dotfile_access_not_blocked",
            "No location block denying access to dotfiles (e.g. .git, .env, .htaccess) was found — if any "
            "such file ends up in the web root, it would be served as-is.",
            'Add: location ~ /\\. { deny all; }',
        ))

    m = re.search(r"client_max_body_size\s+0\s*;", text, re.IGNORECASE)
    if m:
        findings.append(finding(
            "LOW", line_of(text, m.start()), "unlimited_body_size",
            "client_max_body_size 0 removes the request body size limit entirely — a large-payload "
            "denial-of-service vector.",
            "Set an explicit, reasonable limit (e.g. 10m) appropriate to the application.",
        ))

    return findings


def build_report(results: list) -> str:
    all_findings = [(f, source) for source, findings in results for f in findings]
    high = [f for f, _ in all_findings if f["severity"] == "HIGH"]
    medium = [f for f, _ in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f, _ in all_findings if f["severity"] == "LOW"]

    lines = [
        "# Nginx Configuration Security Audit",
        "",
        f"- **Files scanned:** {len(results)}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW",
        "",
    ]
    if all_findings:
        lines += ["| Severity | File | Line | Check | Reason |", "|---|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f, source in sorted(all_findings, key=lambda pair: order[pair[0]["severity"]]):
            line_no = f["line"] if f["line"] is not None else "-"
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {source} | {line_no} | {f['check']} | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(results: list) -> str:
    all_findings = [f for _, findings in results for f in findings]
    payload = {
        "files_scanned": len(results),
        "summary": {
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
        },
        "results": [{"file": source, "findings": findings} for source, findings in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def collect_conf_files(path: Path) -> list:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.conf"))


def main():
    parser = argparse.ArgumentParser(description="Static security audit of nginx configuration file(s).")
    parser.add_argument("--path", required=True, help="Path to a config file or a directory to scan recursively.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    files = collect_conf_files(target)
    results = [(str(f), audit(f.read_text(encoding="utf-8"))) for f in files]

    report = build_json_report(results) if args.format == "json" else build_report(results)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    all_findings = [f for _, findings in results for f in findings]
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"Scanned {len(files)} file(s): {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
