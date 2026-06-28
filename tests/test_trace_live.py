import os
import shutil
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.catalog import build_catalog
from haloce_catalog.coverage import prove_halo_trace


LIVE_ROOT = Path(os.environ["HALOCE_INSTALL_ROOT"]) if "HALOCE_INSTALL_ROOT" in os.environ else None
LIVE_APP = Path(os.environ["HALOCE_REFERENCE_APP"]) if "HALOCE_REFERENCE_APP" in os.environ else None
RUN_LIVE_TRACE = os.environ.get("HALOCE_RUN_LIVE_TRACE_PROOF") == "1"


@unittest.skipUnless(RUN_LIVE_TRACE, "set HALOCE_RUN_LIVE_TRACE_PROOF=1 to run Wine/DynamoRIO proof")
@unittest.skipUnless(LIVE_ROOT is not None and LIVE_ROOT.exists(), "HALOCE_INSTALL_ROOT is not available")
@unittest.skipUnless(LIVE_APP is not None and LIVE_APP.exists(), "HALOCE_REFERENCE_APP is not available")
@unittest.skipUnless(shutil.which("halo-trace-run") is not None, "halo-trace-run is not on PATH")
class LiveHaloTraceProofTests(unittest.TestCase):
    def test_client_startup_trace_records_blocks_cfg_edges_and_call_edges(self):
        assert LIVE_ROOT is not None
        assert LIVE_APP is not None
        haloce = next(LIVE_ROOT.glob("drive_c/**/haloce.exe"), None)
        self.assertIsNotNone(haloce)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "client-startup.jsonl"
            build = build_catalog(LIVE_ROOT, db_path, static_depth="none")
            self.assertEqual(build["errors"], [])

            result = prove_halo_trace(
                db_path,
                log_path,
                "client-startup-live-proof",
                [str(LIVE_APP), "-window"],
                expected_filename="haloce.exe",
                arch="auto",
                timeout_seconds=int(os.environ.get("HALOCE_LIVE_TRACE_TIMEOUT", "45")),
                allow_timeout=True,
            )

        self.assertTrue(result["ok"], result["failures"])
        self.assertGreater(result["mapped"]["blocks"], 0)
        self.assertGreater(result["mapped"]["cfg_edges"], 0)
        self.assertGreater(result["mapped"]["call_edges"], 0)


if __name__ == "__main__":
    unittest.main()
