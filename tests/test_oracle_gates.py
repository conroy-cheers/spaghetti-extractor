import tempfile
import unittest
from pathlib import Path

from haloce_catalog.db import connect, initialize
from haloce_catalog.oracle import (
    REQUIRED_ORACLE_PRIVATE_SUITES,
    REQUIRED_ORACLE_PROCESS_SUITES,
    record_oracle_test_case,
)
from haloce_catalog.reports import gates_json


class OracleGateTests(unittest.TestCase):
    def test_oracle_gate_requires_process_suites_and_private_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            gate = gates_json(conn)["oracle-complete"]
            self.assertEqual(gate["status"], "open")
            self.assertEqual(gate["missing_black_box_suites"], list(REQUIRED_ORACLE_PROCESS_SUITES))
            self.assertEqual(gate["missing_private_harness_suites"], list(REQUIRED_ORACLE_PRIVATE_SUITES))

            with conn:
                for suite_id in REQUIRED_ORACLE_PROCESS_SUITES:
                    record_oracle_test_case(
                        conn,
                        suite_id=suite_id,
                        test_id=f"{suite_id}-smoke",
                        case_kind="black_box_process",
                        status="pass",
                        evidence=f"{suite_id} original binary process suite passed",
                        command=f"private/oracle/run-suite {suite_id}",
                        fixture_path=f"private/oracle/artifacts/{suite_id}.json",
                    )

            gate = gates_json(conn)["oracle-complete"]
            self.assertEqual(gate["status"], "open")
            self.assertEqual(gate["passed_black_box_suites"], len(REQUIRED_ORACLE_PROCESS_SUITES))
            self.assertEqual(gate["missing_black_box_suites"], [])
            self.assertEqual(gate["missing_private_harness_suites"], list(REQUIRED_ORACLE_PRIVATE_SUITES))

            with conn:
                for suite_id in REQUIRED_ORACLE_PRIVATE_SUITES:
                    record_oracle_test_case(
                        conn,
                        suite_id=suite_id,
                        test_id=f"{suite_id}-coverage",
                        case_kind="private_harness",
                        status="pass",
                        evidence=f"{suite_id} original PE harness passed",
                        trace_log=f"private/traces/{suite_id}.jsonl",
                    )

            gate = gates_json(conn)["oracle-complete"]
            conn.close()

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["passed_private_harness_suites"], len(REQUIRED_ORACLE_PRIVATE_SUITES))
        self.assertEqual(gate["failed_or_planned_cases"], 0)
        self.assertEqual(gate["incomplete_passing_cases"], 0)

    def test_oracle_gate_requires_auditable_passing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            with conn:
                record_oracle_test_case(
                    conn,
                    suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                    test_id="startup-unproven",
                    case_kind="black_box_process",
                    status="pass",
                    evidence="missing command and artifact should not satisfy the gate",
                )

            gate = gates_json(conn)["oracle-complete"]
            conn.close()

        self.assertEqual(gate["status"], "open")
        self.assertIn(REQUIRED_ORACLE_PROCESS_SUITES[0], gate["missing_black_box_suites"])
        self.assertEqual(gate["passing_cases"], 1)
        self.assertEqual(gate["auditable_passing_cases"], 0)
        self.assertEqual(gate["incomplete_passing_cases"], 1)

    def test_oracle_gate_ignores_failed_or_planned_cases_for_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            with conn:
                record_oracle_test_case(
                    conn,
                    suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                    test_id="startup-failed",
                    case_kind="black_box_process",
                    status="fail",
                    evidence="failed runs must remain visible but cannot satisfy the gate",
                )
                record_oracle_test_case(
                    conn,
                    suite_id=REQUIRED_ORACLE_PRIVATE_SUITES[0],
                    test_id="harness-planned",
                    case_kind="private_harness",
                    status="planned",
                    evidence="planned private harness is not oracle proof",
                )

            gate = gates_json(conn)["oracle-complete"]
            conn.close()

        self.assertEqual(gate["status"], "open")
        self.assertIn(REQUIRED_ORACLE_PROCESS_SUITES[0], gate["missing_black_box_suites"])
        self.assertIn(REQUIRED_ORACLE_PRIVATE_SUITES[0], gate["missing_private_harness_suites"])
        self.assertEqual(gate["failed_or_planned_cases"], 2)
        self.assertEqual(len(gate["failed_or_planned_samples"]), 2)

    def test_record_oracle_test_case_validates_suite_kind_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            with self.assertRaisesRegex(ValueError, "unknown oracle case kind"):
                record_oracle_test_case(
                    conn,
                    suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                    test_id="bad-kind",
                    case_kind="process",
                )
            with self.assertRaisesRegex(ValueError, "unknown oracle test status"):
                record_oracle_test_case(
                    conn,
                    suite_id=REQUIRED_ORACLE_PROCESS_SUITES[0],
                    test_id="bad-status",
                    case_kind="black_box_process",
                    status="unknown",
                )
            with self.assertRaisesRegex(ValueError, "is not required"):
                record_oracle_test_case(
                    conn,
                    suite_id="private-internal-harness",
                    test_id="wrong-kind-suite",
                    case_kind="black_box_process",
                )
            with self.assertRaisesRegex(ValueError, "is not required"):
                record_oracle_test_case(
                    conn,
                    suite_id="client-startup",
                    test_id="wrong-private-suite",
                    case_kind="private_harness",
                )
            conn.close()


if __name__ == "__main__":
    unittest.main()
