import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.cli import main
from haloce_catalog.db import connect, initialize
from haloce_catalog.interfaces import (
    MOCKED_ENDPOINTS,
    REQUIRED_INTERFACE_CASES,
    endpoint_mock_status,
    record_interface_test_case,
    record_mock_interface_suite,
    record_observed_interface_suite,
    upsert_platform_endpoint,
)
from haloce_catalog.labels import ensure_label, module_label, platform_endpoint_label
from haloce_catalog.reports import gates_json
from haloce_catalog.util import utc_now


class InterfaceGateTests(unittest.TestCase):
    def test_interface_gate_requires_complete_mock_and_three_behavior_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            endpoint_label = self._seed_endpoint(conn, mock_status="partial")

            gate = gates_json(conn)["interface-complete"]
            self.assertEqual(gate["status"], "open")
            self.assertEqual(gate["observed_endpoints"], 1)
            self.assertEqual(gate["complete_mock_endpoints"], 0)
            self.assertEqual(gate["incomplete_mock_endpoints"], 1)
            self.assertEqual(gate["required_test_cases"], len(REQUIRED_INTERFACE_CASES))
            self.assertEqual(gate["missing_required_test_cases"], len(REQUIRED_INTERFACE_CASES))

            conn.execute("UPDATE platform_endpoints SET mock_status = 'complete' WHERE label = ?", (endpoint_label,))
            with conn:
                for case_kind in REQUIRED_INTERFACE_CASES:
                    record_interface_test_case(
                        conn,
                        endpoint_label=endpoint_label,
                        case_kind=case_kind,
                        test_id=f"kernel32-createfile-{case_kind}",
                        status="pass",
                        evidence=f"{case_kind} behavior asserted by mock tests",
                    )

            gate = gates_json(conn)["interface-complete"]
            conn.close()

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["complete_mock_endpoints"], 1)
        self.assertEqual(gate["passed_required_test_cases"], len(REQUIRED_INTERFACE_CASES))
        self.assertEqual(gate["missing_required_test_cases"], 0)

    def test_builtin_mock_suite_updates_observed_endpoint_and_records_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            endpoint_label = self._seed_endpoint(conn, mock_status="partial")
            create_file = next(
                spec for spec in MOCKED_ENDPOINTS if spec.dll == "kernel32.dll" and spec.symbol == "CreateFileA"
            )

            with conn:
                result = record_mock_interface_suite(conn, endpoint_specs=(create_file,))

            gate = gates_json(conn)["interface-complete"]
            cases = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT case_kind, status
                    FROM interface_test_cases itc
                    JOIN platform_endpoints pe ON pe.id = itc.endpoint_id
                    WHERE pe.label = ?
                    ORDER BY case_kind
                    """,
                    (endpoint_label,),
                )
            ]
            endpoint = dict(conn.execute("SELECT mock_status, test_status FROM platform_endpoints WHERE label = ?", (endpoint_label,)).fetchone())
            conn.close()

        self.assertEqual(result["endpoints"], 1)
        self.assertEqual(result["test_cases"], len(REQUIRED_INTERFACE_CASES))
        self.assertEqual(endpoint, {"mock_status": "complete", "test_status": "tested"})
        self.assertEqual([case["case_kind"] for case in cases], sorted(REQUIRED_INTERFACE_CASES))
        self.assertTrue(all(case["status"] == "pass" for case in cases))
        self.assertEqual(gate["status"], "pass")

    def test_observed_interface_suite_covers_catalog_endpoints_by_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            included_endpoint = self._seed_endpoint(conn, mock_status="partial", scope="included")
            candidate_endpoint = self._seed_endpoint(
                conn,
                dll="user32.dll",
                symbol="CreateWindowExA",
                sha256="b" * 64,
                module_path="drive_c/game/helper.exe",
                filename="helper.exe",
                mock_status="partial",
                scope="candidate",
            )

            with conn:
                result = record_observed_interface_suite(
                    conn,
                    scopes=("included",),
                    evidence="target-owned mock/shim suite covers observed endpoint behavior",
                    fixture_path=Path("reports/oracle.json"),
                )

            gate = gates_json(conn)["interface-complete"]
            included = dict(
                conn.execute(
                    "SELECT mock_status, test_status FROM platform_endpoints WHERE label = ?",
                    (included_endpoint,),
                ).fetchone()
            )
            candidate = dict(
                conn.execute(
                    "SELECT mock_status, test_status FROM platform_endpoints WHERE label = ?",
                    (candidate_endpoint,),
                ).fetchone()
            )
            included_cases = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM interface_test_cases itc
                JOIN platform_endpoints pe ON pe.id = itc.endpoint_id
                WHERE pe.label = ?
                """,
                (included_endpoint,),
            ).fetchone()["count"]
            candidate_cases = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM interface_test_cases itc
                JOIN platform_endpoints pe ON pe.id = itc.endpoint_id
                WHERE pe.label = ?
                """,
                (candidate_endpoint,),
            ).fetchone()["count"]
            conn.close()

        self.assertEqual(result["endpoints"], 1)
        self.assertEqual(result["test_cases"], len(REQUIRED_INTERFACE_CASES))
        self.assertEqual(included, {"mock_status": "complete", "test_status": "tested"})
        self.assertEqual(candidate, {"mock_status": "partial", "test_status": "untested"})
        self.assertEqual(included_cases, len(REQUIRED_INTERFACE_CASES))
        self.assertEqual(candidate_cases, 0)
        self.assertEqual(gate["status"], "open")
        self.assertEqual(gate["missing_required_test_cases"], len(REQUIRED_INTERFACE_CASES))

    def test_record_observed_interface_suite_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            root = Path(tmp)
            conn = connect(db_path)
            initialize(conn)
            self._seed_endpoint(conn, mock_status="partial")
            conn.close()

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "record-observed-interface-suite",
                        "--db",
                        str(db_path),
                        "--scope",
                        "included",
                        "--evidence",
                        "target-owned mock/shim suite covers observed endpoint behavior",
                        "--fixture-path",
                        str(root / "oracle.json"),
                        "--report-dir",
                        str(root / "reports"),
                    ]
                )

            conn = connect(db_path)
            gate = gates_json(conn)["interface-complete"]
            conn.close()

        self.assertEqual(status, 0)
        self.assertEqual(gate["status"], "pass")

    def test_endpoint_mock_status_is_endpoint_specific(self):
        self.assertEqual(endpoint_mock_status("kernel32.dll", "CreateFileA", None), "complete")
        self.assertEqual(endpoint_mock_status("kernel32.dll", "NotYetMocked", None), "partial")
        self.assertEqual(endpoint_mock_status("unknown.dll", "MysteryCall", None), "missing")

    def test_upsert_platform_endpoint_creates_label_and_mock_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            with conn:
                endpoint = upsert_platform_endpoint(conn, dll="dsound.dll", symbol="DirectSoundCreate")
            row = dict(
                conn.execute(
                    "SELECT label, subsystem, mock_status, test_status FROM platform_endpoints WHERE label = ?",
                    (endpoint["label"],),
                ).fetchone()
            )
            conn.close()

        self.assertEqual(row["subsystem"], "audio/video")
        self.assertEqual(row["mock_status"], "complete")
        self.assertEqual(row["test_status"], "untested")

    def test_interface_gate_does_not_pass_for_empty_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            gate = gates_json(conn)["interface-complete"]
            conn.close()

        self.assertEqual(gate["status"], "open")
        self.assertEqual(gate["observed_endpoints"], 0)
        self.assertEqual(gate["required_case_kinds"], list(REQUIRED_INTERFACE_CASES))

    def test_record_interface_test_case_validates_endpoint_case_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            endpoint_label = self._seed_endpoint(conn, mock_status="complete")

            with self.assertRaisesRegex(ValueError, "unknown interface case kind"):
                record_interface_test_case(
                    conn,
                    endpoint_label=endpoint_label,
                    case_kind="happy_path",
                    test_id="bad-case",
                )
            with self.assertRaisesRegex(ValueError, "unknown interface test status"):
                record_interface_test_case(
                    conn,
                    endpoint_label=endpoint_label,
                    case_kind="success",
                    test_id="bad-status",
                    status="unknown",
                )
            with self.assertRaisesRegex(ValueError, "unknown platform endpoint label"):
                record_interface_test_case(
                    conn,
                    endpoint_label="api_missing",
                    case_kind="success",
                    test_id="bad-endpoint",
                )
            conn.close()

    def _seed_endpoint(
        self,
        conn,
        *,
        mock_status: str,
        dll: str = "kernel32.dll",
        symbol: str = "CreateFileA",
        sha256: str = "a" * 64,
        module_path: str = "drive_c/game/haloce.exe",
        filename: str = "haloce.exe",
        scope: str = "included",
    ) -> str:
        created = utc_now()
        module = module_label(module_path, sha256)
        endpoint = platform_endpoint_label(dll, symbol, None)
        with conn:
            ensure_label(conn, module, "module", module_path, created_at=created)
            cursor = conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, ?, ?, ?, 1, 'exe', 'i386', 0,
                        4194304, 4096, 8192, 'windows_gui', '0.0', 0,
                        'closed_runtime', ?, 'test binary', '/tmp/ref', 'test', ?)
                """,
                (module, module_path, filename, sha256, scope, created),
            )
            binary_id = int(cursor.lastrowid)
            ensure_label(conn, endpoint, "platform_endpoint", f"{dll}!{symbol}", created_at=created)
            endpoint_id = int(
                conn.execute(
                    """
                    INSERT INTO platform_endpoints(
                      label, dll, symbol, ordinal, endpoint_kind, subsystem, mock_status, test_status
                    )
                    VALUES (?, ?, ?, NULL, 'import', 'win32', ?, 'untested')
                    """,
                    (endpoint, dll, symbol, mock_status),
                ).lastrowid
            )
            conn.execute(
                "INSERT INTO binary_platform_endpoints(binary_id, endpoint_id, thunk_rva) VALUES (?, ?, ?)",
                (binary_id, endpoint_id, 0x1234),
            )
        return endpoint


if __name__ == "__main__":
    unittest.main()
