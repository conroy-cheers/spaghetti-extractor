import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog.db import connect, initialize
from haloce_catalog.oracle import REQUIRED_ORACLE_PROCESS_SUITES, run_oracle_process_test
from haloce_catalog.reports import gates_json


class OracleRunnerTests(unittest.TestCase):
    def test_run_oracle_process_test_records_passing_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            artifact_dir = root / "oracle"
            conn = connect(db_path)
            initialize(conn)

            result = run_oracle_process_test(
                conn,
                suite_id="client-startup",
                test_id="client-startup-python-smoke",
                command=[sys.executable, "-c", "import os; print('oracle-ok:' + os.environ['HALO_TEST'])"],
                artifact_dir=artifact_dir,
                env={"HALO_TEST": "yes"},
                stdout_contains=("oracle-ok:yes",),
                timeout_seconds=10,
            )
            gate = gates_json(conn)["oracle-complete"]
            row = conn.execute("SELECT * FROM oracle_test_cases WHERE label = ?", (result["label"],)).fetchone()
            fixture_exists = Path(row["fixture_path"]).exists()
            fixture_returncode = json.loads(Path(row["fixture_path"]).read_text())["returncode"]
            conn.close()

        self.assertEqual(result["status"], "pass")
        self.assertEqual(row["status"], "pass")
        self.assertTrue(fixture_exists)
        self.assertEqual(fixture_returncode, 0)
        self.assertEqual(gate["status"], "open")
        self.assertNotIn("client-startup", gate["missing_black_box_suites"])
        self.assertEqual(gate["auditable_passing_cases"], 1)

    def test_run_oracle_process_test_records_failed_expectations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            result = run_oracle_process_test(
                conn,
                suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                test_id="missing-stdout",
                command=[sys.executable, "-c", "print('different-output')"],
                artifact_dir=root / "oracle",
                stdout_contains=("expected-output",),
            )
            row = conn.execute("SELECT status, evidence FROM oracle_test_cases WHERE label = ?", (result["label"],)).fetchone()
            conn.close()

        self.assertEqual(result["status"], "fail")
        self.assertEqual(row["status"], "fail")
        self.assertIn("stdout did not contain", row["evidence"])
        self.assertTrue(result["failures"])

    def test_run_oracle_process_test_records_timeouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            result = run_oracle_process_test(
                conn,
                suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                test_id="timeout",
                command=[sys.executable, "-c", "import time; time.sleep(5)"],
                artifact_dir=root / "oracle",
                timeout_seconds=0.1,
            )
            conn.close()

        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["timed_out"])
        self.assertTrue(any("timed out" in failure for failure in result["failures"]))

    def test_run_oracle_process_test_auto_offscreen_uses_existing_display(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            result = run_oracle_process_test(
                conn,
                suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                test_id="existing-display",
                command=[sys.executable, "-c", "import os; print('display=' + os.environ['DISPLAY'])"],
                artifact_dir=root / "oracle",
                env={"DISPLAY": ":44"},
                stdout_contains=("display=:44",),
                offscreen_display="auto",
            )
            conn.close()

        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["offscreen_display"]["used"])
        self.assertEqual(result["offscreen_display"]["reason"], "existing-display")
        self.assertEqual(result["offscreen_display"]["display"], ":44")

    def test_run_oracle_process_test_records_missing_xvfb_for_forced_offscreen(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            with mock.patch("haloce_catalog.oracle.shutil.which", return_value=None):
                result = run_oracle_process_test(
                    conn,
                    suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                    test_id="missing-xvfb",
                    command=[sys.executable, "-c", "raise SystemExit(99)"],
                    artifact_dir=root / "oracle",
                    offscreen_display="x11",
                )
            row = conn.execute("SELECT status, evidence FROM oracle_test_cases WHERE label = ?", (result["label"],)).fetchone()
            conn.close()

        self.assertEqual(result["status"], "fail")
        self.assertIsNone(result["returncode"])
        self.assertIn("Xvfb was not found", result["failures"][0])
        self.assertEqual(row["status"], "fail")
        self.assertIn("Xvfb was not found", row["evidence"])


if __name__ == "__main__":
    unittest.main()
