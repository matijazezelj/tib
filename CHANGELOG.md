# Changelog

## [0.1.0] — 2026-05-29

### Added
- CISA KEV catalog sync (free, no API key required)
- EPSS score fetch via first.org API for all CVEs in environment
- VIB integration — cross-reference running CVEs against KEV and EPSS
- VictoriaMetrics storage for all threat intelligence metrics
- Grafana dashboard: KEV matches in environment, EPSS scores, exploitability tables with NVD links
- SQLite local cache for KEV and EPSS data
