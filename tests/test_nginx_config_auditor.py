import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nginx_config_auditor import (
    audit,
    build_json_report,
    build_report,
    collect_conf_files,
    find_weak_cipher_hits,
    main,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_configs"


def audit_sample(name):
    return audit((SAMPLES / name).read_text(encoding="utf-8"))


def checks_in(findings):
    return [f["check"] for f in findings]


def test_find_weak_cipher_hits_ignores_excluded_tokens():
    assert find_weak_cipher_hits("HIGH:!aNULL:!MD5:!RC4") == []


def test_find_weak_cipher_hits_flags_bare_rc4():
    assert find_weak_cipher_hits("HIGH:!aNULL:!MD5:RC4") == ["RC4"]


def test_find_weak_cipher_hits_flags_multiple():
    assert find_weak_cipher_hits("DES:EXPORT") == ["DES", "EXPORT"]


def test_server_tokens_on_flagged_medium():
    findings = audit("server_tokens on;")
    assert any(f["check"] == "server_tokens_enabled" and f["severity"] == "MEDIUM" for f in findings)


def test_server_tokens_missing_flagged_medium():
    findings = audit("server { listen 80; }")
    assert any(f["check"] == "server_tokens_enabled" for f in findings)


def test_server_tokens_off_not_flagged():
    findings = audit("server_tokens off;")
    assert not any(f["check"] == "server_tokens_enabled" for f in findings)


def test_autoindex_on_flagged_high():
    findings = audit("location /files/ { autoindex on; }")
    assert any(f["check"] == "autoindex_enabled" and f["severity"] == "HIGH" for f in findings)


def test_autoindex_off_not_flagged():
    findings = audit("location /files/ { autoindex off; }")
    assert not any(f["check"] == "autoindex_enabled" for f in findings)


def test_deprecated_tls_protocol_flagged_high():
    findings = audit("ssl_protocols TLSv1 TLSv1.1 TLSv1.2;")
    tls_findings = [f for f in findings if f["check"] == "deprecated_tls_protocol"]
    assert len(tls_findings) == 1
    assert tls_findings[0]["severity"] == "HIGH"
    assert "TLSV1" in tls_findings[0]["reason"]


def test_modern_tls_protocols_only_not_flagged():
    findings = audit("ssl_protocols TLSv1.2 TLSv1.3;")
    assert not any(f["check"] == "deprecated_tls_protocol" for f in findings)


def test_weak_ssl_ciphers_flagged_medium():
    findings = audit("ssl_ciphers HIGH:!aNULL:!MD5:RC4;")
    assert any(f["check"] == "weak_cipher_suite" and f["severity"] == "MEDIUM" for f in findings)


def test_strong_ssl_ciphers_not_flagged():
    findings = audit("ssl_ciphers HIGH:!aNULL:!MD5:!RC4;")
    assert not any(f["check"] == "weak_cipher_suite" for f in findings)


def test_missing_security_headers_each_flagged():
    findings = audit("server { listen 80; }")
    checks = checks_in(findings)
    assert checks.count("missing_security_header") == 3


def test_present_security_headers_not_flagged():
    text = (
        'add_header X-Frame-Options "SAMEORIGIN";\n'
        'add_header X-Content-Type-Options "nosniff";\n'
        'add_header Strict-Transport-Security "max-age=31536000";\n'
    )
    findings = audit(text)
    assert not any(f["check"] == "missing_security_header" for f in findings)


def test_dotfile_access_not_blocked_flagged_when_absent():
    findings = audit("server { location / { root /var/www; } }")
    assert any(f["check"] == "dotfile_access_not_blocked" for f in findings)


def test_dotfile_access_blocked_not_flagged():
    text = "location ~ /\\.(?!well-known) {\n    deny all;\n}\n"
    findings = audit(text)
    assert not any(f["check"] == "dotfile_access_not_blocked" for f in findings)


def test_unlimited_body_size_flagged_low():
    findings = audit("client_max_body_size 0;")
    assert any(f["check"] == "unlimited_body_size" and f["severity"] == "LOW" for f in findings)


def test_limited_body_size_not_flagged():
    findings = audit("client_max_body_size 10m;")
    assert not any(f["check"] == "unlimited_body_size" for f in findings)


def test_insecure_example_flags_expected_checks():
    findings = audit_sample("insecure_example.conf")
    checks = set(checks_in(findings))
    assert checks == {
        "server_tokens_enabled",
        "autoindex_enabled",
        "deprecated_tls_protocol",
        "weak_cipher_suite",
        "missing_security_header",
        "dotfile_access_not_blocked",
        "unlimited_body_size",
    }
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    assert (high, medium, low) == (2, 6, 1)


def test_hardened_example_has_no_findings():
    assert audit_sample("hardened_example.conf") == []


def test_collect_conf_files_on_directory():
    files = collect_conf_files(SAMPLES)
    names = {f.name for f in files}
    assert names == {"insecure_example.conf", "hardened_example.conf"}


def test_collect_conf_files_on_single_file():
    assert len(collect_conf_files(SAMPLES / "hardened_example.conf")) == 1


def test_build_report_lists_findings_in_markdown_table():
    results = [("insecure_example.conf", audit_sample("insecure_example.conf"))]
    report = build_report(results)
    assert "HIGH" in report
    assert "autoindex_enabled" in report


def test_build_report_clean_says_no_issues():
    results = [("hardened_example.conf", audit_sample("hardened_example.conf"))]
    report = build_report(results)
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    results = [("insecure_example.conf", audit_sample("insecure_example.conf"))]
    payload = json.loads(build_json_report(results))
    assert payload["files_scanned"] == 1
    assert payload["summary"]["high"] == 2


def run_main(monkeypatch, tmp_path, target_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["nginx_config_auditor.py", "--path", str(target_path), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_insecure_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.conf", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_hardened_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "hardened_example.conf", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.conf", []) == 0
