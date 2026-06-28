import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.cli import main
from haloce_catalog.db import connect, initialize
from haloce_catalog.mutation import REQUIRED_MUTATION_KINDS, record_mutation_test_case
from haloce_catalog.reports import gates_json


class MutationGateTests(unittest.TestCase):
    def test_mutation_gate_requires_all_representative_kinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            gate = gates_json(conn)["mutation-effective"]
            self.assertEqual(gate["status"], "open")
            self.assertEqual(gate["missing_mutation_kinds"], list(REQUIRED_MUTATION_KINDS))

            with conn:
                for mutation_kind in REQUIRED_MUTATION_KINDS:
                    record_mutation_test_case(
                        conn,
                        mutation_kind=mutation_kind,
                        target_label=f"target_{mutation_kind}",
                        test_id=f"{mutation_kind}-negative",
                        status="killed",
                        evidence=f"{mutation_kind} candidate fails the detailed tests",
                        command=f"private/mutation/run {mutation_kind}",
                    )

            gate = gates_json(conn)["mutation-effective"]
            conn.close()

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["missing_mutation_kinds"], [])
        self.assertEqual(gate["covered_mutation_kinds"], sorted(REQUIRED_MUTATION_KINDS))
        self.assertEqual(gate["killed_cases"], len(REQUIRED_MUTATION_KINDS))
        self.assertEqual(gate["unresolved_cases"], 0)

    def test_mutation_gate_ignores_unresolved_cases_for_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            with conn:
                record_mutation_test_case(
                    conn,
                    mutation_kind=REQUIRED_MUTATION_KINDS[0],
                    test_id="planned-mutation",
                    status="planned",
                    evidence="planned mutation run is not effectiveness proof",
                )
                record_mutation_test_case(
                    conn,
                    mutation_kind=REQUIRED_MUTATION_KINDS[1],
                    test_id="survived-mutation",
                    status="survived",
                    evidence="surviving mutation must keep the gate open",
                )

            gate = gates_json(conn)["mutation-effective"]
            conn.close()

        self.assertEqual(gate["status"], "open")
        self.assertIn(REQUIRED_MUTATION_KINDS[0], gate["missing_mutation_kinds"])
        self.assertIn(REQUIRED_MUTATION_KINDS[1], gate["missing_mutation_kinds"])
        self.assertEqual(gate["unresolved_cases"], 2)
        self.assertEqual(len(gate["unresolved_samples"]), 2)

    def test_record_mutation_test_case_validates_kind_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            with self.assertRaisesRegex(ValueError, "unknown mutation kind"):
                record_mutation_test_case(
                    conn,
                    mutation_kind="changed_color_palette",
                    test_id="bad-kind",
                )
            with self.assertRaisesRegex(ValueError, "unknown mutation test status"):
                record_mutation_test_case(
                    conn,
                    mutation_kind=REQUIRED_MUTATION_KINDS[0],
                    test_id="bad-status",
                    status="pass",
                )
            conn.close()

    def test_run_json_mutation_test_records_killed_and_survived(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            expected_json = root / "expected.json"
            killed_script = root / "killed.py"
            survived_script = root / "survived.py"
            expected_json.write_text(json.dumps({"ok": True, "score": 42}), encoding="utf-8")
            killed_script.write_text('import json; print(json.dumps({"ok": True, "score": 41}))\n', encoding="utf-8")
            survived_script.write_text('import json; print(json.dumps({"ok": True, "score": 42}))\n', encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                killed_status = main(
                    [
                        "run-json-mutation-test",
                        "--db",
                        str(db_path),
                        "--mutation-kind",
                        REQUIRED_MUTATION_KINDS[0],
                        "--test-id",
                        "killed-json-mutant",
                        "--expected-json",
                        str(expected_json),
                        "--artifact-dir",
                        str(root / "mutation"),
                        "--report-dir",
                        str(root / "reports"),
                        "--",
                        sys.executable,
                        str(killed_script),
                    ]
                )
            killed_payload = json.loads(output.getvalue())
            self.assertEqual(killed_status, 0)
            self.assertEqual(killed_payload["mutation_test_case"]["status"], "killed")
            self.assertEqual(killed_payload["mutation_test_case"]["comparison"]["status"], "fail")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                survived_status = main(
                    [
                        "run-json-mutation-test",
                        "--db",
                        str(db_path),
                        "--mutation-kind",
                        REQUIRED_MUTATION_KINDS[1],
                        "--test-id",
                        "survived-json-mutant",
                        "--expected-json",
                        str(expected_json),
                        "--artifact-dir",
                        str(root / "mutation"),
                        "--report-dir",
                        str(root / "reports"),
                        "--",
                        sys.executable,
                        str(survived_script),
                    ]
                )
            survived_payload = json.loads(output.getvalue())
            self.assertEqual(survived_status, 1)
            self.assertEqual(survived_payload["mutation_test_case"]["status"], "survived")
            self.assertEqual(survived_payload["mutation_test_case"]["comparison"]["status"], "pass")

            conn = connect(db_path)
            gate = gates_json(conn)["mutation-effective"]
            conn.close()

        self.assertIn(REQUIRED_MUTATION_KINDS[0], gate["covered_mutation_kinds"])
        self.assertIn(REQUIRED_MUTATION_KINDS[1], gate["missing_mutation_kinds"])
        self.assertEqual(gate["unresolved_cases"], 1)


if __name__ == "__main__":
    unittest.main()
