import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.catalog import build_catalog


LIVE_ROOT = Path(os.environ["HALOCE_INSTALL_ROOT"]) if "HALOCE_INSTALL_ROOT" in os.environ else None


@unittest.skipUnless(LIVE_ROOT is not None and LIVE_ROOT.exists(), "HALOCE_INSTALL_ROOT is not available")
class LiveCatalogTests(unittest.TestCase):
    def test_builds_catalog_from_nix_haloce_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            assert LIVE_ROOT is not None
            result = build_catalog(LIVE_ROOT, db_path, static_depth="none")
            self.assertEqual(result["errors"], [])
            self.assertGreaterEqual(result["binaries_inserted"], 20)

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


if __name__ == "__main__":
    unittest.main()
