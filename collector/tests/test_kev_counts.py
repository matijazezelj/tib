import os
import sqlite3
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import collector  # noqa: E402


def make_db(kev_ids):
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE kev (cve_id TEXT PRIMARY KEY, vendor_project TEXT, product TEXT, vulnerability_name TEXT,
                          date_added TEXT, short_description TEXT, required_action TEXT, due_date TEXT,
                          known_ransomware TEXT, notes TEXT);
        CREATE TABLE epss (cve_id TEXT PRIMARY KEY, score REAL, percentile REAL);
        CREATE TABLE feed_meta (feed TEXT PRIMARY KEY, last_synced TEXT, entry_count INTEGER);
        """
    )
    for cid in kev_ids:
        conn.execute(
            "INSERT INTO kev (cve_id, vendor_project, product, due_date, known_ransomware) VALUES (?,?,?,?,?)",
            (cid, "Vendor", "Product", "2026-09-16", "Unknown"),
        )
    return conn


def run(conn, cves):
    pushed = []
    with mock.patch.object(collector, "_push_lines", side_effect=lambda ls: pushed.extend(ls)):
        collector.push_metrics(conn, cves)
    return {line.split(" ")[0]: float(line.split(" ")[1]) for line in pushed if line.startswith("tib_kev_") or line.startswith("tib_vib_")}


def row(cve, image, sev="HIGH", pkg="p"):
    return {"cve_id": cve, "image": image, "package": pkg, "severity": sev, "has_fix": "true"}


class TestKevCounts(unittest.TestCase):
    def test_one_cve_on_two_images_is_one_cve_two_images(self):
        conn = make_db(["CVE-1"])
        m = run(conn, [row("CVE-1", "a"), row("CVE-1", "b")])
        self.assertEqual(m["tib_kev_distinct_cves"], 1)
        self.assertEqual(m["tib_kev_affected_images"], 2)
        self.assertEqual(m["tib_kev_matches_in_environment"], 2)

    def test_many_packages_of_one_cve_are_not_multiplied(self):
        conn = make_db(["CVE-1"])
        m = run(conn, [row("CVE-1", "a", pkg=p) for p in ("chromium", "chromium-common", "chromium-driver")])
        self.assertEqual(m["tib_kev_distinct_cves"], 1)
        self.assertEqual(m["tib_kev_affected_images"], 1)

    def test_non_kev_cves_do_not_count(self):
        conn = make_db(["CVE-1"])
        m = run(conn, [row("CVE-1", "a"), row("CVE-2", "a"), row("CVE-3", "b")])
        self.assertEqual(m["tib_kev_distinct_cves"], 1)

    def test_the_two_cves_three_images_case_from_a_real_lab(self):
        """Two exploited CVEs across three images: the headline 'matches' number is
        (cve,image) rows (3), which is why it disagreed with 'two CVEs'."""
        conn = make_db(["CVE-A", "CVE-B"])
        cves = [row("CVE-A", "img1", "MEDIUM"), row("CVE-A", "img2", "MEDIUM"), row("CVE-B", "img3", "HIGH", pkg="x"), row("CVE-B", "img3", "HIGH", pkg="y")]
        m = run(conn, cves)
        self.assertEqual(m["tib_kev_distinct_cves"], 2)
        self.assertEqual(m["tib_kev_affected_images"], 3)  # img1, img2, img3

    def test_one_image_with_several_kev_cves_is_one_affected_image(self):
        conn = make_db(["CVE-1", "CVE-2", "CVE-3"])
        m = run(conn, [row("CVE-1", "a"), row("CVE-2", "a"), row("CVE-3", "a")])
        self.assertEqual(m["tib_kev_distinct_cves"], 3)
        self.assertEqual(m["tib_kev_affected_images"], 1)

    def test_correlation_input_size_is_exported(self):
        conn = make_db(["CVE-1"])
        m = run(conn, [row("CVE-1", "a"), row("CVE-9", "a")])
        self.assertEqual(m["tib_vib_cve_rows_correlated"], 2)

    def test_empty_vib_exports_zeros_for_every_gauge(self):
        conn = make_db(["CVE-1"])
        m = run(conn, [])
        for k in ("tib_kev_matches_in_environment", "tib_kev_distinct_cves", "tib_kev_affected_images", "tib_vib_cve_rows_correlated"):
            self.assertEqual(m[k], 0, k)


if __name__ == "__main__":
    unittest.main()
