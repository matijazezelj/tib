"""
TIB Collector — Threat Intelligence in a Box

Syncs CISA KEV + EPSS threat feeds, cross-references against VIB CVE metrics,
and pushes correlation results to VictoriaMetrics.
"""

import csv
import gzip
import io
import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import schedule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("tib")

# ── Config ────────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://tib-victoriametrics:8428")
VIB_VICTORIAMETRICS_URL = os.environ.get("VIB_VICTORIAMETRICS_URL", "")
SYNC_INTERVAL_HOURS = float(os.environ.get("SYNC_INTERVAL_HOURS", "6"))
SYNC_ON_STARTUP = os.environ.get("SYNC_ON_STARTUP", "true").lower() == "true"
DB_PATH = Path(os.environ.get("DB_PATH", "/data/tib.db"))

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "TIB/0.1 (Threat Intelligence in a Box)"


# ── Database ──────────────────────────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware TEXT,
            synced_at TEXT
        );

        CREATE TABLE IF NOT EXISTS epss (
            cve_id TEXT PRIMARY KEY,
            score REAL,
            percentile REAL,
            synced_at TEXT
        );

        CREATE TABLE IF NOT EXISTS feed_meta (
            feed TEXT PRIMARY KEY,
            last_synced TEXT,
            entry_count INTEGER
        );
    """)
    conn.commit()
    return conn


# ── CISA KEV sync ─────────────────────────────────────────────────────────────

def sync_kev(conn: sqlite3.Connection) -> int:
    logger.info("Syncing CISA KEV catalog...")
    try:
        r = SESSION.get(CISA_KEV_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error("KEV fetch failed: %s", e)
        return 0

    vulns = data.get("vulnerabilities", [])
    now = datetime.now(timezone.utc).isoformat()

    conn.executemany(
        """INSERT OR REPLACE INTO kev
           (cve_id, vendor_project, product, vulnerability_name, date_added,
            short_description, required_action, due_date, known_ransomware, synced_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                v.get("cveID"),
                v.get("vendorProject"),
                v.get("product"),
                v.get("vulnerabilityName"),
                v.get("dateAdded"),
                v.get("shortDescription"),
                v.get("requiredAction"),
                v.get("dueDate"),
                v.get("knownRansomwareCampaignUse", "Unknown"),
                now,
            )
            for v in vulns
        ],
    )
    conn.execute(
        "INSERT OR REPLACE INTO feed_meta (feed, last_synced, entry_count) VALUES (?,?,?)",
        ("cisa-kev", now, len(vulns)),
    )
    conn.commit()
    logger.info("KEV synced: %d entries", len(vulns))
    return len(vulns)


# ── EPSS sync ─────────────────────────────────────────────────────────────────

def sync_epss_for_cves(conn: sqlite3.Connection, cve_ids: list[str]) -> int:
    """Fetch EPSS scores for a specific list of CVEs (API supports up to 100 per call)."""
    if not cve_ids:
        return 0

    now = datetime.now(timezone.utc).isoformat()
    fetched = 0
    chunk_size = 100

    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        try:
            r = SESSION.get(
                EPSS_API_URL,
                params={"cve": ",".join(chunk), "envelope": "true"},
                timeout=30,
            )
            r.raise_for_status()
            data = r.json().get("data", [])
        except Exception as e:
            logger.warning("EPSS fetch failed for chunk: %s", e)
            continue

        conn.executemany(
            "INSERT OR REPLACE INTO epss (cve_id, score, percentile, synced_at) VALUES (?,?,?,?)",
            [(d["cve"], float(d["epss"]), float(d["percentile"]), now) for d in data],
        )
        fetched += len(data)

    conn.execute(
        "INSERT OR REPLACE INTO feed_meta (feed, last_synced, entry_count) VALUES (?,?,?)",
        ("epss", now, fetched),
    )
    conn.commit()
    return fetched


# ── VIB integration ───────────────────────────────────────────────────────────

def fetch_vib_cves() -> list[dict]:
    """Query VIB's VictoriaMetrics for current CVE metrics."""
    if not VIB_VICTORIAMETRICS_URL:
        return []

    try:
        r = SESSION.get(
            f"{VIB_VICTORIAMETRICS_URL}/api/v1/query",
            params={"query": "last_over_time(vib_cve_info[8h])"},
            timeout=15,
        )
        r.raise_for_status()
        result = r.json().get("data", {}).get("result", [])
    except Exception as e:
        logger.warning("Could not reach VIB VictoriaMetrics: %s", e)
        return []

    cves = []
    for series in result:
        labels = series.get("metric", {})
        cves.append({
            "cve_id": labels.get("cve_id", ""),
            "image": labels.get("image", ""),
            "package": labels.get("package", ""),
            "severity": labels.get("severity", ""),
            "has_fix": labels.get("has_fix", ""),
        })
    return cves


# ── Metric helpers ────────────────────────────────────────────────────────────

def _safe_label(s: str) -> str:
    return str(s).replace('"', '\\"').replace("\n", "").replace("\\", "\\\\")


def _ts_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def push_metrics(conn: sqlite3.Connection, vib_cves: list[dict]) -> None:
    lines = []
    ts = _ts_ms()
    now_iso = datetime.now(timezone.utc).isoformat()

    # Feed sizes
    for row in conn.execute("SELECT feed, entry_count, last_synced FROM feed_meta"):
        feed, count, last_synced = row
        lines.append(f'tib_feed_entries_total{{feed="{_safe_label(feed)}"}} {count} {ts}')
        try:
            last_ts = int(datetime.fromisoformat(last_synced).timestamp() * 1000)
            lines.append(f'tib_last_sync_timestamp{{feed="{_safe_label(feed)}"}} {last_ts} {ts}')
        except Exception:
            pass

    kev_total = conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    lines.append(f"tib_kev_total {kev_total} {ts}")

    if not vib_cves:
        lines.append(f"tib_kev_matches_in_environment 0 {ts}")
        _push_lines(lines)
        return

    vib_cve_ids = list({c["cve_id"] for c in vib_cves if c["cve_id"]})

    # Fetch EPSS for all current VIB CVEs
    sync_epss_for_cves(conn, vib_cve_ids)

    # Cross-reference: which VIB CVEs are in KEV?
    kev_matches = 0
    for cve in vib_cves:
        cve_id = cve["cve_id"]
        if not cve_id:
            continue

        kev_row = conn.execute(
            "SELECT vendor_project, product, due_date, known_ransomware FROM kev WHERE cve_id=?",
            (cve_id,),
        ).fetchone()

        epss_row = conn.execute(
            "SELECT score, percentile FROM epss WHERE cve_id=?", (cve_id,)
        ).fetchone()

        if epss_row:
            score, percentile = epss_row
            lines.append(
                f'tib_cve_epss_score{{cve_id="{_safe_label(cve_id)}",'
                f'image="{_safe_label(cve["image"])}",'
                f'severity="{_safe_label(cve["severity"])}"}} {score:.6f} {ts}'
            )
            lines.append(
                f'tib_cve_epss_percentile{{cve_id="{_safe_label(cve_id)}",'
                f'image="{_safe_label(cve["image"])}"}} {percentile:.6f} {ts}'
            )

        if kev_row:
            vendor, product, due_date, ransomware = kev_row
            kev_matches += 1
            lines.append(
                f'tib_kev_match{{cve_id="{_safe_label(cve_id)}",'
                f'image="{_safe_label(cve["image"])}",'
                f'severity="{_safe_label(cve["severity"])}",'
                f'vendor="{_safe_label(vendor or "")}",'
                f'product="{_safe_label(product or "")}",'
                f'due_date="{_safe_label(due_date or "")}",'
                f'ransomware="{_safe_label(ransomware or "Unknown")}"}} 1 {ts}'
            )

    lines.append(f"tib_kev_matches_in_environment {kev_matches} {ts}")
    _push_lines(lines)
    logger.info("Metrics pushed — KEV matches in environment: %d", kev_matches)


def _push_lines(lines: list[str]) -> None:
    if not lines:
        return
    payload = "\n".join(lines) + "\n"
    try:
        requests.post(
            f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
            data=payload,
            headers={"Content-Type": "text/plain"},
            timeout=10,
        ).raise_for_status()
    except Exception as e:
        logger.error("Failed to push metrics: %s", e)


# ── Main sync cycle ───────────────────────────────────────────────────────────

def run_sync(conn: sqlite3.Connection) -> None:
    logger.info("─── TIB sync starting ───")
    sync_kev(conn)

    vib_cves = fetch_vib_cves()
    if vib_cves:
        logger.info("Retrieved %d CVEs from VIB", len(vib_cves))
    else:
        logger.info("VIB not configured or unreachable — skipping correlation")

    push_metrics(conn, vib_cves)
    logger.info("─── TIB sync complete ───")


def main() -> None:
    conn = init_db()

    if "--once" in sys.argv:
        run_sync(conn)
        return

    logger.info("TIB collector starting (interval=%.1fh)", SYNC_INTERVAL_HOURS)

    if SYNC_ON_STARTUP:
        run_sync(conn)

    schedule.every(SYNC_INTERVAL_HOURS).hours.do(run_sync, conn)

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
