import json
import sys
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.db import connect, initialize
from haloce_catalog.harness import (
    record_internal_harness_run,
    run_internal_harness,
    upsert_internal_harness,
)
from haloce_catalog.labels import ensure_label, ensure_oracle_mapping
from haloce_catalog.reports import gates_json
from haloce_catalog.util import utc_now


class InternalHarnessTests(unittest.TestCase):
    def test_upsert_internal_harness_requires_oracle_mapping_for_function_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(Path(tmp) / "catalog.db")
            initialize(conn)
            created = utc_now()
            with conn:
                ensure_label(conn, "fn_without_mapping", "function", "function without mapping", created_at=created)

            with self.assertRaisesRegex(ValueError, "no private oracle mapping"):
                upsert_internal_harness(
                    conn,
                    target_label="fn_without_mapping",
                    harness_id="unmapped-probe",
                    harness_kind="function",
                )
            conn.close()

    def test_run_internal_harness_records_artifacts_and_private_oracle_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = connect(root / "catalog.db")
            initialize(conn)
            target_label = self._seed_target(conn)

            with conn:
                harness = upsert_internal_harness(
                    conn,
                    target_label=target_label,
                    harness_id="function-state-probe",
                    harness_kind="function",
                    command_template="private/harness function-state-probe",
                    input_contract="seeded deterministic state",
                    expected_observation="prints harness-ok",
                    risk="private original-code call glue",
                )

            result = run_internal_harness(
                conn,
                harness_label=harness["label"],
                test_id="function-state-probe-pass",
                command=[sys.executable, "-c", "print('harness-ok')"],
                artifact_dir=root / "harness-artifacts",
                stdout_contains=("harness-ok",),
            )
            gate = gates_json(conn)["oracle-complete"]
            row = conn.execute(
                "SELECT * FROM internal_harness_runs WHERE label = ?",
                (result["label"],),
            ).fetchone()
            oracle = conn.execute(
                """
                SELECT * FROM oracle_test_cases
                WHERE suite_id = 'private-internal-harness'
                  AND test_id = 'function-state-probe-pass'
                """
            ).fetchone()
            artifact = json.loads(Path(row["fixture_path"]).read_text(encoding="utf-8"))
            conn.close()

        self.assertEqual(result["status"], "pass")
        self.assertEqual(row["status"], "pass")
        self.assertEqual(oracle["status"], "pass")
        self.assertEqual(artifact["oracle_mapping"]["module_sha256"], "a" * 64)
        self.assertEqual(gate["missing_private_harness_suites"], [])
        self.assertEqual(gate["auditable_passing_cases"], 1)

    def test_failed_internal_harness_does_not_satisfy_private_oracle_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = connect(root / "catalog.db")
            initialize(conn)
            target_label = self._seed_target(conn)
            with conn:
                harness = upsert_internal_harness(
                    conn,
                    target_label=target_label,
                    harness_id="failure-probe",
                    harness_kind="function",
                )

            result = run_internal_harness(
                conn,
                harness_label=harness["label"],
                test_id="function-state-probe-fail",
                command=[sys.executable, "-c", "print('wrong')"],
                artifact_dir=root / "harness-artifacts",
                stdout_contains=("harness-ok",),
            )
            gate = gates_json(conn)["oracle-complete"]
            conn.close()

        self.assertEqual(result["status"], "fail")
        self.assertEqual(gate["missing_private_harness_suites"], ["private-internal-harness"])

    def test_record_internal_harness_run_records_external_private_harness_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(Path(tmp) / "catalog.db")
            initialize(conn)
            target_label = self._seed_target(conn)
            with conn:
                harness = upsert_internal_harness(
                    conn,
                    target_label=target_label,
                    harness_id="external-probe",
                    harness_kind="function",
                )
                result = record_internal_harness_run(
                    conn,
                    harness_label=harness["label"],
                    test_id="external-probe-pass",
                    status="pass",
                    evidence="external harness executed original PE function by stable label",
                    command="private/harness external-probe",
                    trace_log="private/traces/external-probe.jsonl",
                    returncode=0,
                )
            gate = gates_json(conn)["oracle-complete"]
            conn.close()

        self.assertEqual(result["status"], "pass")
        self.assertEqual(gate["missing_private_harness_suites"], [])

    def _seed_target(self, conn) -> str:
        created = utc_now()
        target_label = "fn_target_state_probe"
        with conn:
            ensure_label(conn, target_label, "function", "target state probe", created_at=created)
            ensure_oracle_mapping(
                conn,
                label=target_label,
                entity_type="function",
                binary_id=None,
                module_sha256="a" * 64,
                rva_start=0x1234,
                rva_end=0x1250,
                private={"purpose": "unit test target"},
            )
        return target_label


if __name__ == "__main__":
    unittest.main()
