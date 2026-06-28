import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.coverage import ingest_halo_trace
from haloce_catalog.db import connect, initialize
from haloce_catalog.labels import ensure_label, ensure_oracle_mapping, module_label, platform_endpoint_label
from haloce_catalog.reports import gates_json
from haloce_catalog.util import utc_now


class LabelAndTraceTests(unittest.TestCase):
    def test_platform_endpoint_label_keeps_symbol_hint_without_ordinal(self):
        label = platform_endpoint_label("kernel32.dll", "CreateFileA", None)

        self.assertIn("kernel32_dll_createfilea", label)

    def test_custom_trace_ingest_writes_labelled_blocks_edges_and_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            log_path = Path(tmp) / "trace.jsonl"
            module_sha = "a" * 64
            module = self._seed_binary(db_path, module_sha)
            records = [
                {
                    "kind": "module",
                    "test_id": "trace-smoke",
                    "pid": 100,
                    "module_name": "haloce.exe",
                    "module_sha256": module_sha,
                    "drcov_module_id": 0,
                },
                {
                    "kind": "block",
                    "test_id": "trace-smoke",
                    "pid": 100,
                    "module_sha256": module_sha,
                    "rva_block": 0x1000,
                    "size": 5,
                },
                {
                    "kind": "cfg_edge",
                    "test_id": "trace-smoke",
                    "pid": 100,
                    "module_sha256": module_sha,
                    "rva_edge_from": 0x1000,
                    "rva_edge_to": 0x1010,
                },
                {
                    "kind": "call_edge",
                    "test_id": "trace-smoke",
                    "pid": 100,
                    "module_sha256": module_sha,
                    "caller_rva": 0x1000,
                    "callee_module_sha256": module_sha,
                    "callee_rva": 0x2000,
                },
            ]
            log_path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

            result = ingest_halo_trace(db_path, log_path)

            self.assertEqual(result, {"modules": 1, "blocks": 1, "cfg_edges": 1, "call_edges": 1, "value_traces": 0})
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            for table in ["coverage_blocks", "coverage_edges", "coverage_call_edges"]:
                row = conn.execute(f"SELECT label FROM {table}").fetchone()
                self.assertIsNotNone(row)
                label = conn.execute("SELECT * FROM labels WHERE label = ?", (row["label"],)).fetchone()
                self.assertIsNotNone(label)
                mapping = conn.execute("SELECT * FROM oracle_mappings WHERE label = ?", (row["label"],)).fetchone()
                self.assertIsNotNone(mapping)
            gates = gates_json(conn)
            self.assertEqual(gates["catalog-complete"]["unlabeled_entities"], 0)
            self.assertEqual(module, conn.execute("SELECT label FROM binaries").fetchone()["label"])
            conn.close()

    def _seed_binary(self, db_path: Path, sha256: str) -> str:
        conn = connect(db_path)
        initialize(conn)
        label = module_label("drive_c/game/haloce.exe", sha256)
        created = utc_now()
        with conn:
            ensure_label(conn, label, "module", "drive_c/game/haloce.exe", created_at=created)
            cursor = conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, 'drive_c/game/haloce.exe', 'haloce.exe', ?, 1, 'exe', 'i386', 0,
                        4194304, 4096, 8192, 'windows_gui', '0.0', 0,
                        'closed_runtime', 'included', 'test binary', '/tmp/ref', 'test', ?)
                """,
                (label, sha256, created),
            )
            ensure_oracle_mapping(
                conn,
                label=label,
                entity_type="module",
                binary_id=int(cursor.lastrowid),
                module_sha256=sha256,
                rva_start=0,
                rva_end=8192,
            )
        conn.close()
        return label


if __name__ == "__main__":
    unittest.main()
