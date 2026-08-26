# Nginx Configuration Security Audit

- **Files scanned:** 1
- **Findings:** 2 HIGH, 6 MEDIUM, 1 LOW

| Severity | File | Line | Check | Reason |
|---|---|---|---|---|
| HIGH | sample_configs\insecure_example.conf | 14 | autoindex_enabled | autoindex on generates a directory listing for any request with no matching index file, potentially exposing files never meant to be public. |
| HIGH | sample_configs\insecure_example.conf | 8 | deprecated_tls_protocol | ssl_protocols enables deprecated/insecure protocol(s): TLSV1, TLSV1.1. |
| MEDIUM | sample_configs\insecure_example.conf | 2 | server_tokens_enabled | server_tokens is not set to off (or missing, which defaults to on) — the Server response header discloses the nginx version, helping an attacker fingerprint known CVEs. |
| MEDIUM | sample_configs\insecure_example.conf | 9 | weak_cipher_suite | ssl_ciphers includes weak/broken cipher keyword(s): RC4. |
| MEDIUM | sample_configs\insecure_example.conf | - | missing_security_header | No "add_header X-Frame-Options" directive found anywhere in this file. |
| MEDIUM | sample_configs\insecure_example.conf | - | missing_security_header | No "add_header X-Content-Type-Options" directive found anywhere in this file. |
| MEDIUM | sample_configs\insecure_example.conf | - | missing_security_header | No "add_header Strict-Transport-Security" directive found anywhere in this file. |
| MEDIUM | sample_configs\insecure_example.conf | - | dotfile_access_not_blocked | No location block denying access to dotfiles (e.g. .git, .env, .htaccess) was found — if any such file ends up in the web root, it would be served as-is. |
| LOW | sample_configs\insecure_example.conf | 11 | unlimited_body_size | client_max_body_size 0 removes the request body size limit entirely — a large-payload denial-of-service vector. |
