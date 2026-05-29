# Contributing

PRs and issues welcome. Ground rules:

1. **One concern per PR.** Collector changes separate from dashboard changes.
2. **No new external API dependencies** without a discussion issue first. TIB's value is zero-account-required feeds.
3. **Test with real data.** CISA KEV and EPSS APIs are public — spin up `make up` and verify metrics appear before opening a PR.
4. **Dashboard changes:** export the updated JSON from Grafana and replace `grafana/dashboards/tib-overview.json`.

## Dev setup

```bash
cp .env.example .env
make up
docker logs -f tib-collector
```
