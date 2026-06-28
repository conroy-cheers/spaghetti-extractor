import tempfile
import unittest
from pathlib import Path

from haloce_catalog.db import connect, initialize
from haloce_catalog.labels import ensure_label, module_label, test_run_label as make_test_run_label
from haloce_catalog.reports import REQUIRED_TOOL_VERSION_KEYS, gates_json
from haloce_catalog.util import json_dumps, utc_now


class ReproducibleGateTests(unittest.TestCase):
    def test_reproducible_gate_requires_metadata_tools_hashes_and_test_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            gate = gates_json(conn)["reproducible"]
            self.assertEqual(gate["status"], "open")
            self.assertTrue(gate["missing_metadata"])
            self.assertTrue(gate["missing_test_runs"])

            self._seed_reproducible_catalog(conn)
            gate = gates_json(conn)["reproducible"]
            conn.close()

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["missing_metadata"], [])
        self.assertEqual(gate["missing_tool_versions"], [])
        self.assertEqual(gate["binary_hashes"], 1)
        self.assertEqual(gate["test_runs"], 1)

    def test_reproducible_gate_rejects_missing_tool_versions_and_empty_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)

            self._seed_reproducible_catalog(
                conn,
                tool_versions={key: "tool 1.0" for key in REQUIRED_TOOL_VERSION_KEYS if key != "frida"},
                test_run_provenance={},
            )
            gate = gates_json(conn)["reproducible"]
            conn.close()

        self.assertEqual(gate["status"], "open")
        self.assertEqual(gate["missing_tool_versions"], ["frida"])
        self.assertTrue(any(item["issue"] == "empty provenance_json" for item in gate["test_run_issues"]))

    def _seed_reproducible_catalog(
        self,
        conn,
        *,
        tool_versions: dict[str, str] | None = None,
        test_run_provenance: dict[str, object] | None = None,
    ) -> None:
        created = utc_now()
        tool_versions = tool_versions or {key: "tool 1.0" for key in REQUIRED_TOOL_VERSION_KEYS}
        metadata = {
            "catalog_version": "test",
            "created_at": created,
            "install_root": "/nix/store/reference/basePackage",
            "tool_versions": json_dumps(tool_versions),
            "nix_haloce_reference_package": "/nix/store/reference",
            "nix_haloce_source_info": json_dumps(
                {
                    "rev": "783751ea24d85732012e53065aee2618f22061b7",
                    "narHash": "sha256-example",
                    "type": "git",
                }
            ),
        }
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                sorted(metadata.items()),
            )
            module = module_label("drive_c/game/haloce.exe", "a" * 64)
            ensure_label(conn, module, "module", "drive_c/game/haloce.exe", created_at=created)
            conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, 'drive_c/game/haloce.exe', 'haloce.exe', ?, 1, 'exe', 'i386', 0,
                        4194304, 4096, 8192, 'windows_gui', '0.0', 0,
                        'closed_runtime', 'included', 'test binary', '/nix/store/reference', 'test', ?)
                """,
                (module, "a" * 64, created),
            )
            test_label = make_test_run_label("trace-proof", "halo-trace", created)
            ensure_label(conn, test_label, "test", "trace-proof", created_at=created)
            conn.execute(
                """
                INSERT INTO test_runs(
                  label, test_id, suite, command, status, started_at, finished_at,
                  tool_versions_json, provenance_json
                )
                VALUES (?, 'trace-proof', 'halo-trace', 'ingest-halo-trace', 'imported', ?, ?, ?, ?)
                """,
                (
                    test_label,
                    created,
                    created,
                    json_dumps({"haloce_catalog": "test", "python": "3.13"}),
                    json_dumps(
                        test_run_provenance
                        if test_run_provenance is not None
                        else {"nix_haloce_source_info": {"rev": "783751ea24d85732012e53065aee2618f22061b7"}}
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
