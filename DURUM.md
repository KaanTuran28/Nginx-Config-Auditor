# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: nginx yapılandırma dosyalarını statik denetleyen CLI aracı — `server_tokens`, `autoindex on`, deprecated TLS protokolleri (SSLv3/TLSv1/TLSv1.1), zayıf cipher suite'ler, eksik güvenlik header'ları (X-Frame-Options/X-Content-Type-Options/Strict-Transport-Security), korumasız dotfile erişimi (.git/.env), sınırsız `client_max_body_size 0`.
- Dikkat edilen bir detay: `ssl_ciphers` denetimi, OpenSSL'in `!MD5`/`!RC4` gibi HARİÇ TUTMA söz dizimini doğru ayırt ediyor — yani düzgün sertleştirilmiş bir cipher string'i (`HIGH:!aNULL:!MD5:!RC4`) yanlışlıkla "zayıf" diye işaretlemiyor, sadece gerçekten dahil edilmiş zayıf bir cipher (bare `RC4`) varsa uyarıyor. Bu, testte ayrıca doğrulandı.
- Dosya: `nginx_config_auditor.py`, 2 örnek yapılandırma (`insecure_example.conf` — 7 farklı kontrolü gösteriyor, `hardened_example.conf` — 0 bulgu), `tests/test_nginx_config_auditor.py` (28 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 28/28 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI her iki örneğe karşı gerçekten çalıştırıldı: `insecure_example.conf` → 2 HIGH + 6 MEDIUM + 1 LOW, `hardened_example.conf` → 0 bulgu. `sample_report.md` gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Nginx-Config-Auditor` adıyla repo aç, git init + push.
