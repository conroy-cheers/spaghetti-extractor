import tempfile
import unittest
from pathlib import Path

from haloce_catalog.catalog import build_catalog, resolve_install_root
from haloce_catalog.data_state import record_data_state_test_case, upsert_data_structure
from haloce_catalog.db import connect
from haloce_catalog.mutation import record_mutation_test_case
from haloce_catalog.oracle import record_oracle_test_case
from haloce_catalog.reports import gates_json, manifest_json
from haloce_catalog.roles import classify_pe
from haloce_catalog.target import load_target_config


class TargetConfigTests(unittest.TestCase):
    def test_custom_target_config_drives_roles_and_gate_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "install"
            install_root.mkdir()
            target_path = root / "toy.toml"
            target_path.write_text(
                """
[project]
id = "toy"
name = "Toy Target"

[env]
install_root = "TOY_INSTALL_ROOT"

[[binary_rules]]
names = [ "toy.exe" ]
role = "closed_runtime"
scope = "included"
reason = "toy executable"

[[trace_targets]]
id = "startup"
executable = "toy.exe"
expected_filename = "toy.exe"

[gates]
oracle_process_suites = [ "toy-startup" ]
oracle_private_suites = [ "toy-private-harness" ]
mutation_kinds = [ "toy_wrong_return" ]

[data_state]
round_trip_kinds = [ "document" ]
transition_kinds = [ "mode" ]
""",
                encoding="utf-8",
            )
            target = load_target_config(target_path)
            db_path = root / "catalog.db"

            result = build_catalog(install_root, db_path, target_config=target)
            conn = connect(db_path)
            manifest = manifest_json(conn)
            document = upsert_data_structure(
                conn,
                name="toy_doc",
                structure_kind="document",
                spec_status="complete",
                fixture_status="complete",
            )
            with conn:
                for case_kind in ("fixture", "malformed_input", "round_trip"):
                    record_data_state_test_case(
                        conn,
                        data_structure_label_value=document["label"],
                        case_kind=case_kind,
                        test_id=f"toy-doc-{case_kind}",
                        status="pass",
                        evidence="custom target data case",
                        round_trip_kinds={"document"},
                    )
                record_oracle_test_case(
                    conn,
                    suite_id="toy-startup",
                    test_id="toy-startup-smoke",
                    case_kind="black_box_process",
                    status="pass",
                    evidence="toy process oracle passed",
                    command="toy.exe",
                    fixture_path="private/toy/result.json",
                    required_process_suites=("toy-startup",),
                    required_private_suites=("toy-private-harness",),
                )
                record_oracle_test_case(
                    conn,
                    suite_id="toy-private-harness",
                    test_id="toy-private-smoke",
                    case_kind="private_harness",
                    status="pass",
                    evidence="toy private harness passed",
                    command="private/toy-harness",
                    required_process_suites=("toy-startup",),
                    required_private_suites=("toy-private-harness",),
                )
                record_mutation_test_case(
                    conn,
                    mutation_kind="toy_wrong_return",
                    test_id="toy-mutant",
                    status="killed",
                    evidence="toy wrong return mutant failed tests",
                    required_mutation_kinds=("toy_wrong_return",),
                )
            gates = gates_json(conn)
            conn.close()

            self.assertEqual(result["target_project_id"], "toy")
            self.assertEqual(resolve_install_root(str(install_root), target), install_root.resolve())
            self.assertEqual(classify_pe("bin/toy.exe", target).scope, "included")
            self.assertEqual(classify_pe("bin/other.exe", target).scope, "candidate")
            self.assertEqual(manifest["target"]["id"], "toy")
            self.assertEqual(gates["oracle-complete"]["missing_black_box_suites"], [])
            self.assertEqual(gates["oracle-complete"]["missing_private_harness_suites"], [])
            self.assertEqual(gates["mutation-effective"]["missing_mutation_kinds"], [])
            self.assertEqual(gates["data-state-complete"]["status"], "pass")

    def test_external_module_rules_require_explicit_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_path = root / "toy.toml"
            target_path.write_text(
                """
[project]
id = "toy"
name = "Toy Target"

[[binary_rules]]
names = [ "toy.exe" ]
role = "closed_runtime"
scope = "included"
reason = "toy executable"

[[external_modules]]
names = [ "KERNEL32.dll" ]
kind = "os_component"
source = "Windows system API provider"
reason = "external operating-system dependency"
""",
                encoding="utf-8",
            )

            target = load_target_config(target_path)

        self.assertEqual(target.external_module_rules[0].names, ("KERNEL32.dll",))
        self.assertEqual(target.external_module_rules[0].kind, "os_component")
        self.assertEqual(target.external_module_rules[0].source, "Windows system API provider")

    def test_external_module_rules_fail_without_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            target_path = Path(tmp) / "toy.toml"
            target_path.write_text(
                """
[project]
id = "toy"
name = "Toy Target"

[[external_modules]]
names = [ "mystery.dll" ]
kind = "source_available_dependency"
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "source"):
                load_target_config(target_path)


if __name__ == "__main__":
    unittest.main()
