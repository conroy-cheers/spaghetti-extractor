import tempfile
import unittest
from pathlib import Path

from haloce_catalog.data_state import (
    required_data_state_cases,
    record_data_state_test_case,
    upsert_data_structure,
)
from haloce_catalog.db import connect, initialize
from haloce_catalog.reports import gates_json


class DataStateGateTests(unittest.TestCase):
    def test_required_cases_follow_structure_kind(self):
        self.assertEqual(required_data_state_cases("map"), ("fixture", "malformed_input", "round_trip"))
        self.assertEqual(required_data_state_cases("profile_config"), ("fixture", "malformed_input", "round_trip"))
        self.assertEqual(required_data_state_cases("network_state_machine"), ("fixture", "malformed_input", "transition"))
        self.assertEqual(required_data_state_cases("unknown"), ("fixture", "malformed_input"))

    def test_data_state_gate_requires_specs_fixtures_and_required_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            map_structure = upsert_data_structure(
                conn,
                name="cache_file_header",
                structure_kind="map",
                spec_status="draft",
                fixture_status="missing",
                description="Halo cache-file header behavior",
            )
            machine_structure = upsert_data_structure(
                conn,
                name="server_connection_state",
                structure_kind="network_state_machine",
                spec_status="complete",
                fixture_status="complete",
            )

            gate = gates_json(conn)["data-state-complete"]
            self.assertEqual(gate["status"], "open")
            self.assertEqual(gate["known_data_structures"], 2)
            self.assertEqual(gate["incomplete_specs"], 1)
            self.assertEqual(gate["incomplete_fixtures"], 1)
            self.assertEqual(gate["required_test_cases"], 6)
            self.assertEqual(gate["missing_required_test_cases"], 6)

            conn.execute(
                "UPDATE data_structures SET spec_status = 'complete', fixture_status = 'complete' WHERE label = ?",
                (map_structure["label"],),
            )
            with conn:
                for structure in (map_structure, machine_structure):
                    for case_kind in structure["required_case_kinds"]:
                        record_data_state_test_case(
                            conn,
                            data_structure_label_value=structure["label"],
                            case_kind=case_kind,
                            test_id=f"{structure['name']}-{case_kind}",
                            status="pass",
                            evidence=f"{case_kind} behavior fixture is asserted",
                            fixture_path=f"private/fixtures/{structure['name']}/{case_kind}.json",
                        )

            gate = gates_json(conn)["data-state-complete"]
            conn.close()

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["complete_specs"], 2)
        self.assertEqual(gate["complete_fixtures"], 2)
        self.assertEqual(gate["passed_required_test_cases"], 6)
        self.assertEqual(gate["missing_required_test_cases"], 0)

    def test_data_state_gate_does_not_pass_for_empty_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            gate = gates_json(conn)["data-state-complete"]
            conn.close()

        self.assertEqual(gate["status"], "open")
        self.assertEqual(gate["known_data_structures"], 0)

    def test_record_data_state_test_case_validates_structure_case_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            structure = upsert_data_structure(
                conn,
                name="controls_profile",
                structure_kind="profile",
                spec_status="complete",
                fixture_status="complete",
            )

            with self.assertRaisesRegex(ValueError, "unknown data-state test status"):
                record_data_state_test_case(
                    conn,
                    data_structure_label_value=structure["label"],
                    case_kind="fixture",
                    test_id="bad-status",
                    status="unknown",
                )
            with self.assertRaisesRegex(ValueError, "is not required"):
                record_data_state_test_case(
                    conn,
                    data_structure_label_value=structure["label"],
                    case_kind="transition",
                    test_id="bad-case",
                )
            with self.assertRaisesRegex(ValueError, "unknown data structure label"):
                record_data_state_test_case(
                    conn,
                    data_structure_label_value="data_missing",
                    case_kind="fixture",
                    test_id="bad-structure",
                )
            conn.close()


if __name__ == "__main__":
    unittest.main()
