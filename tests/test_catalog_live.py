import os
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.catalog import build_catalog
from haloce_catalog.reports import generate_reports


LIVE_ROOT = Path(os.environ["HALOCE_INSTALL_ROOT"]) if "HALOCE_INSTALL_ROOT" in os.environ else None


@unittest.skipUnless(LIVE_ROOT is not None and LIVE_ROOT.exists(), "HALOCE_INSTALL_ROOT is not available")
class LiveCatalogTests(unittest.TestCase):
    def test_builds_catalog_from_nix_haloce_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = Path(tmp) / "catalog.db"
            report_dir = root / "reports"
            assert LIVE_ROOT is not None
            result = build_catalog(LIVE_ROOT, db_path, static_depth="none")
            reports = generate_reports(db_path, report_dir)
            self.assertEqual(result["errors"], [])
            self.assertGreaterEqual(result["binaries_inserted"], 20)
            self.assertEqual(
                set(reports),
                {
                    "manifest_json",
                    "coverage_json",
                    "gates_json",
                    "specs_json",
                    "tests_json",
                    "catalog_markdown",
                    "coverage_markdown",
                    "specs_markdown",
                    "tests_markdown",
                },
            )
            for report_path in reports.values():
                self.assertTrue(report_path.exists(), report_path)

            manifest = json.loads(reports["manifest_json"].read_text(encoding="utf-8"))
            gates = json.loads(reports["gates_json"].read_text(encoding="utf-8"))
            tests = json.loads(reports["tests_json"].read_text(encoding="utf-8"))
            self.assertGreaterEqual(manifest["summary"]["included"], 2)
            self.assertIn("catalog-complete", gates)
            self.assertEqual(tests["schema_version"], 1)

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            haloce = conn.execute("SELECT * FROM binaries WHERE filename = 'haloce.exe'").fetchone()
            self.assertIsNotNone(haloce)
            self.assertEqual(haloce["scope"], "included")
            self.assertEqual(haloce["machine"], "i386")
            ranges = conn.execute(
                "SELECT COUNT(*) FROM executable_ranges WHERE binary_id = ?",
                (haloce["id"],),
            ).fetchone()[0]
            self.assertGreater(ranges, 0)
            byte_classes = conn.execute(
                "SELECT COUNT(*) FROM executable_byte_classes WHERE binary_id = ?",
                (haloce["id"],),
            ).fetchone()[0]
            self.assertGreater(byte_classes, 0)
            conn.close()


if __name__ == "__main__":
    unittest.main()
