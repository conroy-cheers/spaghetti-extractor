import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from haloce_catalog.db import connect, initialize
from haloce_catalog.ghidra import run_ghidra_export
from haloce_catalog.labels import basic_block_label, ensure_label, ensure_oracle_mapping, function_label, module_label
from haloce_catalog.util import utc_now


class GhidraExportTests(unittest.TestCase):
    def test_headless_export_runs_script_and_imports_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            script_path = tmp_path / "tools" / "ghidra"
            script_path.mkdir(parents=True)
            (script_path / "HaloCatalogExport.java").write_text("// test script\n", encoding="utf-8")
            reference_root = tmp_path / "reference"
            binary_relpath = Path("drive_c/game/haloce.exe")
            binary_path = reference_root / binary_relpath
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"MZ")
            sha256 = "b" * 64
            self._seed_binary(db_path, binary_relpath.as_posix(), reference_root, sha256)
            self._seed_existing_block(db_path, binary_relpath.as_posix(), sha256)
            self._seed_existing_alignment_block(db_path, binary_relpath.as_posix(), sha256)

            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                self.assertEqual(kwargs["check"], False)
                self.assertEqual(kwargs["text"], True)
                self.assertEqual(kwargs["timeout"], 15)
                self.assertIn("-scriptPath", command)
                self.assertEqual(command[command.index("-scriptPath") + 1], str(script_path.resolve()))
                self.assertIn("-postScript", command)
                script_index = command.index("-postScript")
                self.assertEqual(command[script_index + 1], "HaloCatalogExport.java")
                out_json = Path(command[script_index + 2])
                self.assertEqual(command[script_index + 3], sha256)
                self.assertEqual(command[-1], "-deleteProject")
                out_json.write_text(
                    json.dumps(
                        {
                            "schema_version": "1",
                            "binary_sha256": sha256,
                            "program_name": "haloce.exe",
                            "image_base": 0x400000,
                            "functions": [
                                {
                                    "rva": 0x1000,
                                    "name": "entry",
                                    "calling_convention": "__stdcall",
                                    "signature": "unknown",
                                    "subsystem": "unknown",
                                    "purity": "unknown",
                                    "side_effects": "unknown",
                                    "confidence": "high",
                                    "rva_end": 0x1010,
                                    "decompiler": {
                                        "status": "success",
                                        "c": "int entry(void) { return 1; }",
                                    },
                                    "variables": [
                                        {"name": "local_counter", "kind": "local", "data_type": "int"}
                                    ],
                                    "inferred_types": {"return": "int"},
                                    "stack_refs": [{"name": "local_counter", "stack_offset": -4}],
                                    "global_refs": [{"from_rva": 0x1001, "to_rva": 0x3000}],
                                    "strings": [{"from_rva": 0x1002, "to_rva": 0x3010, "value": "hello"}],
                                    "callsites": [{"caller_rva": 0x1004, "callee_rva": 0x2000}],
                                    "instructions": [
                                        {"rva": 0x1000, "mnemonic": "push", "operand_count": 1},
                                        {"rva": 0x1001, "mnemonic": "mov", "operand_count": 2},
                                    ],
                                    "pcode": [
                                        {"rva": 0x1000, "op": "COPY EAX, 1"},
                                    ],
                                },
                                {
                                    "rva": 0x1020,
                                    "name": "next_function",
                                    "confidence": "high",
                                    "rva_end": 0x1030,
                                    "decompiler": {
                                        "status": "success",
                                        "c": "void next_function(void) {}",
                                    },
                                },
                            ],
                            "basic_blocks": [
                                {
                                    "rva_start": 0x1000,
                                    "rva_end": 0x1005,
                                    "function_rva": 0x1000,
                                    "instructions": [
                                        {"rva": 0x1000, "mnemonic": "push", "operand_count": 1},
                                    ],
                                    "pcode": [{"rva": 0x1000, "op": "COPY EAX, 1"}],
                                    "data_flow": {"global_refs": [{"to_rva": 0x3000}]},
                                    "xrefs": {"successors": [{"to_rva": 0x1005}]},
                                    "semantic_summary": "Entry prologue block.",
                                    "classification": "code",
                                    "confidence": "high",
                                }
                            ],
                            "cfg_edges": [
                                {
                                    "from_rva": 0x1000,
                                    "to_rva": 0x1005,
                                    "edge_type": "FALL_THROUGH",
                                    "confidence": "high",
                                }
                            ],
                            "call_edges": [
                                {
                                    "caller_rva": 0x1000,
                                    "callee_rva": 0x2000,
                                    "call_type": "UNCONDITIONAL_CALL",
                                    "confidence": "high",
                                }
                            ],
                            "data_refs": [
                                {
                                    "from_rva": 0x1010,
                                    "to_rva": 0x3000,
                                    "ref_type": "DATA",
                                    "confidence": "medium",
                                }
                            ],
                            "globals": [
                                {
                                    "rva": 0x3000,
                                    "rva_end": 0x3004,
                                    "name": "g_player_state",
                                    "data_type": "uint32_t",
                                    "symbol_type": "LABEL",
                                    "subsystem": "stateful engine logic",
                                    "confidence": "high",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

            with patch("haloce_catalog.ghidra.subprocess.run", side_effect=fake_run):
                result = run_ghidra_export(
                    db_path,
                    out_dir=tmp_path / "exports",
                    project_dir=tmp_path / "projects",
                    analyze_headless="fakeAnalyzeHeadless",
                    script_path=script_path,
                    filenames=["haloce.exe"],
                    timeout_seconds=15,
                )

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], "fakeAnalyzeHeadless")
            self.assertEqual(result["selected"], 1)
            self.assertEqual(result["exported"], 1)
            self.assertEqual(result["failures"], [])
            self.assertEqual(
                result["imported"],
                {
                    "functions": 1,
                    "function_semantics": 2,
                    "basic_blocks": 1,
                    "block_semantics": 1,
                    "block_function_backfills": 2,
                    "block_alignment_classifications": 1,
                    "cfg_edges": 1,
                    "call_edges": 1,
                    "data_refs": 1,
                    "globals": 1,
                },
            )

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            for table in [
                "functions",
                "function_semantics",
                "basic_blocks",
                "block_semantics",
                "cfg_edges",
                "call_edges",
                "data_refs",
                "globals",
            ]:
                expected = 3 if table == "basic_blocks" else 2 if table in {"functions", "function_semantics"} else 1
                self.assertEqual(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], expected)
            self.assertEqual(conn.execute("SELECT count(*) FROM basic_blocks WHERE function_id IS NULL").fetchone()[0], 0)
            self.assertEqual(
                conn.execute(
                    "SELECT classification FROM basic_blocks WHERE rva_start = 0x1010 AND rva_end = 0x1020"
                ).fetchone()[0],
                "padding/alignment",
            )
            function_semantics = conn.execute("SELECT * FROM function_semantics").fetchone()
            self.assertEqual(function_semantics["decompiler_status"], "success")
            self.assertIn("return 1", function_semantics["decompiled_c"])
            block_semantics = conn.execute("SELECT * FROM block_semantics").fetchone()
            self.assertIn("Entry prologue", block_semantics["semantic_summary"])
            self.assertIn("COPY EAX", block_semantics["pcode_json"])
            self.assertEqual(
                conn.execute("SELECT count(*) FROM oracle_mappings WHERE entity_type = 'function'").fetchone()[0],
                1,
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM oracle_mappings WHERE entity_type = 'global'").fetchone()[0],
                1,
            )
            conn.close()

    def _seed_binary(self, db_path: Path, relpath: str, source_root: Path, sha256: str) -> None:
        conn = connect(db_path)
        initialize(conn)
        label = module_label(relpath, sha256)
        created = utc_now()
        with conn:
            ensure_label(conn, label, "module", relpath, created_at=created)
            cursor = conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, ?, ?, ?, 2, 'exe', 'i386', 0, 4194304, 4096, 8192,
                        'windows_gui', '0.0', 0, 'closed_runtime', 'included',
                        'test binary', ?, 'test', ?)
                """,
                (label, relpath, Path(relpath).name, sha256, str(source_root), created),
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
            seed_function_label = function_label(label, 0x1000, "pe-entrypoint", "entrypoint")
            ensure_label(conn, seed_function_label, "function", f"{label}:entrypoint", "existing PE entrypoint")
            conn.execute(
                """
                INSERT INTO functions(label, binary_id, rva, name, source)
                VALUES (?, ?, 0x1000, 'entrypoint', 'pe-entrypoint')
                """,
                (seed_function_label, int(cursor.lastrowid)),
            )
        conn.close()

    def _seed_existing_block(self, db_path: Path, relpath: str, sha256: str) -> None:
        conn = connect(db_path)
        initialize(conn)
        binary_label = module_label(relpath, sha256)
        block_label = basic_block_label(binary_label, 0x1001, 0x1003, "capstone-linear")
        with conn:
            binary = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            self.assertIsNotNone(binary)
            ensure_label(conn, block_label, "basic_block", f"{binary_label}:block", "existing static block")
            conn.execute(
                """
                INSERT INTO basic_blocks(
                  label, binary_id, function_id, rva_start, rva_end, size,
                  source, classification, confidence
                )
                VALUES (?, ?, NULL, 0x1001, 0x1003, 2, 'capstone-linear', 'code', 'low')
                """,
                (block_label, int(binary["id"])),
            )
        conn.close()

    def _seed_existing_alignment_block(self, db_path: Path, relpath: str, sha256: str) -> None:
        conn = connect(db_path)
        initialize(conn)
        binary_label = module_label(relpath, sha256)
        block_label = basic_block_label(binary_label, 0x1010, 0x1020, "capstone-linear")
        with conn:
            binary = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            self.assertIsNotNone(binary)
            ensure_label(conn, block_label, "basic_block", f"{binary_label}:alignment", "existing static alignment block")
            conn.execute(
                """
                INSERT INTO basic_blocks(
                  label, binary_id, function_id, rva_start, rva_end, size,
                  source, classification, confidence
                )
                VALUES (?, ?, NULL, 0x1010, 0x1020, 16, 'capstone-linear', 'code', 'low')
                """,
                (block_label, int(binary["id"])),
            )
        conn.close()


if __name__ == "__main__":
    unittest.main()
