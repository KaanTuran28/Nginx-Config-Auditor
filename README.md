# Nginx Config Auditor

![CI](https://github.com/KaanTuran28/Nginx-Config-Auditor/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static security auditor for nginx configuration files — the hardening checklist a security review would apply by hand, run automatically over `nginx.conf`.

### Overview

- **`server_tokens`** not explicitly `off` (missing defaults to `on`) — leaks the nginx version in the `Server` header.
- **`autoindex on`** — generates a directory listing for any request with no matching index.
- **Deprecated TLS protocols** — `SSLv2`/`SSLv3`/`TLSv1`/`TLSv1.1` enabled via `ssl_protocols`.
- **Weak cipher suites** — `RC4`/`DES`/`MD5`/`NULL`/`EXPORT` present in `ssl_ciphers` as a genuine inclusion (correctly ignores `!MD5`/`!RC4`-style OpenSSL exclusions, so a properly hardened cipher string isn't falsely flagged).
- **Missing security headers** — no `add_header` for `X-Frame-Options`, `X-Content-Type-Options`, or `Strict-Transport-Security` anywhere in the file.
- **Unguarded dotfiles** — no `location ~ /\.` block denying access to `.git`/`.env`/`.htaccess`-style files.
- **Unlimited body size** — `client_max_body_size 0` (a large-payload DoS vector).

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd Nginx-Config-Auditor
pip install -e .
```

This installs a `nginx-config-auditor` command. You can also run the script directly with `python nginx_config_auditor.py` without installing.

### Usage

```bash
nginx-config-auditor --path /etc/nginx/nginx.conf --output report.md
nginx-config-auditor --path /etc/nginx/conf.d --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--path` | *(required)* | A single config file, or a directory to scan recursively for `*.conf` |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

### CI Integration

Run this against the nginx config in your repo before it's deployed:

```bash
nginx-config-auditor --path nginx.conf --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit nginx configuration
  run: nginx-config-auditor --path nginx.conf --fail-on high
```

### Example Output

[`sample_configs/insecure_example.conf`](./sample_configs/insecure_example.conf) demonstrates every check above; [`sample_configs/hardened_example.conf`](./sample_configs/hardened_example.conf) is its fixed counterpart and produces **zero findings**. See [`sample_report.md`](./sample_report.md) — real output from scanning `insecure_example.conf`: 2 HIGH, 6 MEDIUM, 1 LOW.

### Limitations

Regex-based, not a full nginx-config-grammar parser — it won't resolve `include` directives across files, doesn't understand variables/maps, and the "missing security header" checks are whole-file presence checks (a header added in one server block doesn't prove it applies to every `location` that needs it). Treat it as a fast hardening-checklist pass, not a substitute for a manual review of a complex, multi-file config.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
Nginx-Config-Auditor/
├── nginx_config_auditor.py
├── pyproject.toml
├── sample_configs/
│   ├── insecure_example.conf
│   └── hardened_example.conf
├── sample_report.md
├── tests/
│   └── test_nginx_config_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Nginx yapılandırma dosyaları için statik bir güvenlik denetleyicisi — bir güvenlik incelemesinin elle uygulayacağı sertleştirme (hardening) kontrol listesi, `nginx.conf` üzerinde otomatik olarak çalıştırılır.

### Genel Bakış

- **`server_tokens`** değerinin açıkça `off` olmaması (eksikse varsayılan olarak `on`) — `Server` header'ında nginx sürümünü sızdırır.
- **`autoindex on`** — eşleşen bir index bulunmayan her istek için bir dizin listesi (directory listing) üretir.
- **Kullanımdan kaldırılmış (deprecated) TLS protokolleri** — `ssl_protocols` üzerinden etkinleştirilmiş `SSLv2`/`SSLv3`/`TLSv1`/`TLSv1.1`.
- **Zayıf cipher suite'ler** — `ssl_ciphers` içinde gerçek bir dahil etme (inclusion) olarak bulunan `RC4`/`DES`/`MD5`/`NULL`/`EXPORT` (doğru şekilde `!MD5`/`!RC4` tarzı OpenSSL hariç tutmalarını göz ardı eder, böylece düzgün sertleştirilmiş bir cipher string'i yanlışlıkla işaretlenmez).
- **Eksik güvenlik header'ları** — dosyanın hiçbir yerinde `X-Frame-Options`, `X-Content-Type-Options` veya `Strict-Transport-Security` için `add_header` bulunmaması.
- **Korunmasız dotfile'lar** — `.git`/`.env`/`.htaccess` tarzı dosyalara erişimi reddeden bir `location ~ /\.` bloğunun bulunmaması.
- **Sınırsız gövde boyutu** — `client_max_body_size 0` (büyük payload'lı bir DoS vektörü).

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Nginx-Config-Auditor
pip install -e .
```

Bu, bir `nginx-config-auditor` komutu kurar. Kurulum yapmadan doğrudan `python nginx_config_auditor.py` ile de scripti çalıştırabilirsiniz.

### Kullanım

```bash
nginx-config-auditor --path /etc/nginx/nginx.conf --output report.md
nginx-config-auditor --path /etc/nginx/conf.d --format json --output report.json
```

| Bayrak (Flag) | Varsayılan | Açıklama |
|---|---|---|
| `--path` | *(zorunlu)* | Tek bir yapılandırma dosyası, veya `*.conf` için recursive olarak taranacak bir dizin |
| `--output` | `sample_report.md` | Raporun yazılacağı dosya yolu |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium`, veya `high` — bu ciddiyet seviyesinde veya üzerinde bir bulgu varsa çıkış kodu `1` olur |

### CI Entegrasyonu

Repo'nuzdaki nginx yapılandırmasına karşı, deploy edilmeden önce bunu çalıştırın:

```bash
nginx-config-auditor --path nginx.conf --fail-on high
```

```yaml
# GitHub Actions step
- name: Audit nginx configuration
  run: nginx-config-auditor --path nginx.conf --fail-on high
```

### Örnek Çıktı

[`sample_configs/insecure_example.conf`](./sample_configs/insecure_example.conf) yukarıdaki her kontrolü örnekler; [`sample_configs/hardened_example.conf`](./sample_configs/hardened_example.conf) ise düzeltilmiş karşılığıdır ve **sıfır bulgu** üretir. `insecure_example.conf` taramasından gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın: 2 HIGH, 6 MEDIUM, 1 LOW.

### Sınırlamalar

Regex tabanlıdır, tam bir nginx-config-grameri ayrıştırıcısı değildir — dosyalar arası `include` direktiflerini çözümlemez, değişkenleri/map'leri anlamaz ve "eksik güvenlik header'ı" kontrolleri dosya-geneli varlık kontrolleridir (bir server bloğuna eklenen bir header'ın, buna ihtiyaç duyan her `location` için geçerli olduğunu kanıtlamaz). Bunu, karmaşık, çok dosyalı bir yapılandırmanın manuel incelemesinin yerine değil, hızlı bir sertleştirme kontrol listesi geçişi olarak değerlendirin.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
Nginx-Config-Auditor/
├── nginx_config_auditor.py
├── pyproject.toml
├── sample_configs/
│   ├── insecure_example.conf
│   └── hardened_example.conf
├── sample_report.md
├── tests/
│   └── test_nginx_config_auditor.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
