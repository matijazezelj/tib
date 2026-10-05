# Changelog

## [Unreleased]

### Added
- `BIND_ADDR` setting controlling which interface the published ports bind to

### Changed
- EPSS now loads from the published bulk CSV snapshot instead of the per-CVE
  first.org API — one request for the full corpus, and no longer dependent on
  VIB being configured or reachable
- `tib_feed_entries_total{feed="epss"}` now reports the size of the published
  feed rather than the number of environment CVEs that carried a score
- The collector waits for VictoriaMetrics to accept traffic before its first
  sync, and retries transient feed and ingest failures

### Fixed
- The KEV and EPSS tables on the overview dashboard showed a single row however many matches existed (5 KEV matches, 1 row). Grafana returned one frame per
  series and the table displayed only the first; the `merge` transformation joins them. The `Value` column override is now keyed by metric name so the "Active"
  and "EPSS Score" formatting still applies after the merge.
- The KEV headline said "4" while the table beneath it listed two CVEs. It counted `(CVE, image, severity)` rows, so one CVE on three images, or one image with several
  affected packages, inflated it. New gauges `tib_kev_distinct_cves` (headline) and `tib_kev_affected_images` (distinct images) answer the two questions people actually ask, and
  `tib_vib_cve_rows_correlated` shows how much VIB data a correlation used. The dashboard now charts the distinct counts.
- Metric label escaping applied backslash escaping last, re-escaping the
  backslash added for a quote. VictoriaMetrics answered 204 and dropped the
  line, so any metric with a quote in a label silently never arrived
- EPSS never synced at all when VIB was unconfigured, leaving the EPSS panels
  and feed metrics permanently empty
- `tib_kev_matches_in_environment` counted one match per affected package
  rather than per CVE, so the headline stat disagreed with the table beneath it
- The startup sync could push before VictoriaMetrics was listening, discarding
  the entire first sync and leaving the dashboard empty until the next interval
- `make clean` left the built image behind; it removed `tib-collector`, but
  compose builds `tib-tib-collector`
- README documented the Grafana admin password default as auto-generated when
  it is `changeme`

### Security
- Grafana and VictoriaMetrics published their ports with no host IP, binding to
  0.0.0.0 and exposing them to the LAN. VictoriaMetrics has no authentication,
  so the CVE data was readable and its metrics endpoint writable by anything on
  the network. Both now bind to 127.0.0.1 unless `BIND_ADDR` says otherwise

## [0.1.0] — 2026-05-29

### Added
- CISA KEV catalog sync (free, no API key required)
- EPSS score fetch via first.org API for all CVEs in environment
- VIB integration — cross-reference running CVEs against KEV and EPSS
- VictoriaMetrics storage for all threat intelligence metrics
- Grafana dashboard: KEV matches in environment, EPSS scores, exploitability tables with NVD links
- SQLite local cache for KEV and EPSS data
