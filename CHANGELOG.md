# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

---

## [1.1.0] — 2026-03-29

### Added
- `ioc-pipeline/enrichment/virustotal.py` — Full async VirusTotal v3 client (IP, domain, hash, URL)
- `ioc-pipeline/enrichment/enricher.py` — CLI enrichment entry point with cache + verdict integration
- `wazuh-integration/parsers/ioc_extractor.py` — Regex-based IOC extractor (IP, hash, domain, URL, email)
- `pipeline/main.py` — Full pipeline entry point (file mode + webhook mode)
- `samples/sample_alert.json` — Realistic SSH brute-force Wazuh alert for testing
- `tests/` — Full pytest test suite: ioc_extractor, verdict_engine, alert_normaliser, triage_engine
- `tests/conftest.py` — Shared fixtures (sample_alert_raw, sample_config)
- `docker-compose.yml` — Full stack: pipeline + Prometheus + Grafana
- `Dockerfile` — Python 3.11-slim production image
- `.github/workflows/ci.yml` — GitHub Actions CI: tests, lint (flake8), security scan (bandit)
- `memory-analysis/volatility-plugins/pslist_wrapper.py` — Volatility 3 pslist wrapper
- `memory-analysis/volatility-plugins/malfind_wrapper.py` — Volatility 3 malfind wrapper with risk annotation
- `config/prometheus.yml` — Prometheus scrape config for the pipeline
- `CHANGELOG.md` — This file

### Fixed
- `report-generator/templates/` and `report-generator/output/` were empty directories (added README placeholders)
- `memory-analysis/samples/` was empty (added usage README)
- `wazuh-integration/config/` was empty (added `wazuh_config.yml`)

---

## [1.0.0] — 2026-03-28

### Initial Release
- Wazuh alert ingestor and normaliser
- IOC enrichment pipeline (AbuseIPDB, Shodan)
- Composite verdict engine
- SOAR triage engine + responder
- SOAR playbooks (malicious_ip, malicious_hash, suspicious_ip)
- NIST 800-61 PDF report generator
- Grafana dashboard JSON + provisioning
- Volatility 3 memory analysis dispatcher
- SQLite IOC cache
- Project README, LICENSE, CONTRIBUTING, .gitignore
