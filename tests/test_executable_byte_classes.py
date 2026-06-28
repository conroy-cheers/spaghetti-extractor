import tempfile
import unittest
from pathlib import Path

from haloce_catalog.byteclasses import rebuild_executable_byte_classes
from haloce_catalog.db import connect, initialize
from haloce_catalog.labels import (
    basic_block_label,
    coverage_block_label,
    ensure_label,
    ensure_oracle_mapping,
    executable_byte_class_label,
    executable_range_label,
    global_label,
    module_label,
    static_cross_check_label,
    test_run_label as make_test_run_label,
    waiver_label,
)
from haloce_catalog.reports import gates_json
from haloce_catalog.util import utc_now


class ExecutableByteClassTests(unittest.TestCase):
    def test_rebuild_splits_static_dynamic_waiver_and_residual_unknowns(self):
        with self._database() as conn:
            binary_id, binary_label, module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1020)
            self._insert_basic_block(conn, binary_id, binary_label, 0x1000, 0x1005)
            self._insert_coverage_block(conn, binary_id, binary_label, module_sha, 0x1008, 0x100C)
            self._insert_waiver(conn, binary_id, binary_label, 0x1010, 0x1020, "proven-padding-data")

            with conn:
                result = rebuild_executable_byte_classes(conn, binary_id)
            rows = self._byte_class_rows(conn)
            gates = gates_json(conn)

        self.assertEqual(result, {"binaries": 1, "byte_classes": 5})
        self.assertEqual(
            [(row["rva_start"], row["rva_end"], row["classification"], row["source"]) for row in rows],
            [
                (0x1000, 0x1005, "code", "ghidra"),
                (0x1005, 0x1008, "unknown", "executable-range"),
                (0x1008, 0x100C, "code", "dynamic-coverage"),
                (0x100C, 0x1010, "unknown", "executable-range"),
                (0x1010, 0x1020, "padding/alignment", "waiver"),
            ],
        )
        self.assertEqual(gates["catalog-complete"]["unknown_executable_bytes"], 7)
        self.assertEqual(gates["catalog-complete"]["executable_partition_issues"], [])

    def test_rebuild_classifies_ghidra_defined_data_inside_executable_ranges(self):
        with self._database() as conn:
            binary_id, binary_label, module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1020)
            self._insert_basic_block(conn, binary_id, binary_label, 0x1000, 0x1008)
            self._insert_global_data(conn, binary_id, binary_label, module_sha, 0x1008, 0x1018)

            with conn:
                result = rebuild_executable_byte_classes(conn, binary_id)
            rows = self._byte_class_rows(conn)

        self.assertEqual(result, {"binaries": 1, "byte_classes": 3})
        self.assertEqual(
            [(row["rva_start"], row["rva_end"], row["classification"], row["source"]) for row in rows],
            [
                (0x1000, 0x1008, "code", "ghidra"),
                (0x1008, 0x1018, "jump/data table", "ghidra-data"),
                (0x1018, 0x1020, "unknown", "executable-range"),
            ],
        )

    def test_rebuild_preserves_padding_blocks_as_padding_byte_classes(self):
        with self._database() as conn:
            binary_id, binary_label, _module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1010)
            self._insert_basic_block(
                conn,
                binary_id,
                binary_label,
                0x1000,
                0x1004,
                classification="padding/alignment",
                source="capstone-linear",
            )

            with conn:
                rebuild_executable_byte_classes(conn, binary_id)
            rows = self._byte_class_rows(conn)

        self.assertEqual(
            [(row["rva_start"], row["rva_end"], row["classification"], row["source"]) for row in rows],
            [
                (0x1000, 0x1004, "padding/alignment", "capstone-linear"),
                (0x1004, 0x1010, "unknown", "executable-range"),
            ],
        )

    def test_rebuild_ignores_ghidra_defined_data_that_overlaps_code_blocks(self):
        with self._database() as conn:
            binary_id, binary_label, module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1020)
            self._insert_basic_block(conn, binary_id, binary_label, 0x1000, 0x1010)
            self._insert_global_data(conn, binary_id, binary_label, module_sha, 0x1008, 0x1018)

            with conn:
                rebuild_executable_byte_classes(conn, binary_id)
            rows = self._byte_class_rows(conn)

        self.assertEqual(
            [(row["rva_start"], row["rva_end"], row["classification"], row["source"]) for row in rows],
            [
                (0x1000, 0x1010, "code", "ghidra"),
                (0x1010, 0x1020, "unknown", "executable-range"),
            ],
        )

    def test_catalog_gate_passes_when_byte_partition_has_no_unknowns_or_gaps(self):
        with self._database() as conn:
            binary_id, binary_label, _module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1010)
            self._insert_basic_block(conn, binary_id, binary_label, 0x1000, 0x1008)
            self._insert_waiver(conn, binary_id, binary_label, 0x1008, 0x1010, "proven-padding-data")
            self._insert_static_cross_checks(conn, binary_id, binary_label)

            with conn:
                rebuild_executable_byte_classes(conn, binary_id)
            gates = gates_json(conn)

        self.assertEqual(gates["catalog-complete"]["unknown_executable_bytes"], 0)
        self.assertEqual(gates["catalog-complete"]["executable_partition_issues"], [])
        self.assertEqual(gates["catalog-complete"]["status"], "pass")

    def test_catalog_gate_reports_stale_missing_byte_partition(self):
        with self._database() as conn:
            binary_id, binary_label, _module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1010)

            issues = gates_json(conn)["catalog-complete"]["executable_partition_issues"]

        self.assertEqual(issues[0]["partition"], "executable_byte_classes")
        self.assertEqual(issues[0]["kind"], "gap")
        self.assertEqual((issues[0]["rva_start"], issues[0]["rva_end"]), (0x1000, 0x1010))

    def test_catalog_gate_reports_overlapping_byte_partition_rows(self):
        with self._database() as conn:
            binary_id, binary_label, _module_sha = self._seed_binary(conn)
            self._insert_executable_range(conn, binary_id, binary_label, 0x1000, 0x1010)
            self._insert_byte_class(conn, binary_id, binary_label, 0x1000, 0x1008, "code", "manual-a")
            self._insert_byte_class(conn, binary_id, binary_label, 0x1004, 0x1010, "code", "manual-b")

            issues = gates_json(conn)["catalog-complete"]["executable_partition_issues"]

        overlap = [issue for issue in issues if issue["kind"] == "overlap"]
        self.assertEqual(len(overlap), 1)
        self.assertEqual(overlap[0]["partition"], "executable_byte_classes")
        self.assertEqual((overlap[0]["rva_start"], overlap[0]["rva_end"]), (0x1004, 0x1008))

    def _database(self):
        directory = tempfile.TemporaryDirectory()
        conn = connect(Path(directory.name) / "catalog.db")
        initialize(conn)
        self.addCleanup(conn.close)
        self.addCleanup(directory.cleanup)
        return conn

    def _seed_binary(self, conn):
        module_sha = "1" * 64
        binary_label = module_label("drive_c/game/haloce.exe", module_sha)
        created = utc_now()
        with conn:
            ensure_label(conn, binary_label, "module", "drive_c/game/haloce.exe", created_at=created)
            cursor = conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, 'drive_c/game/haloce.exe', 'haloce.exe', ?, 4096, 'exe', 'i386', 0,
                        4194304, 4096, 12288, 'windows_gui', '0.0', 0,
                        'closed_runtime', 'included', 'test binary', '/tmp/ref', 'test', ?)
                """,
                (binary_label, module_sha, created),
            )
            binary_id = int(cursor.lastrowid)
        return binary_id, binary_label, module_sha

    def _insert_executable_range(self, conn, binary_id, binary_label, rva_start, rva_end):
        label = executable_range_label(binary_label, rva_start, rva_end, "unknown")
        size = rva_end - rva_start
        with conn:
            ensure_label(conn, label, "executable_range", f"{binary_label}:.text", "test executable range")
            conn.execute(
                """
                INSERT INTO sections(
                  binary_id, name, virtual_address, virtual_size, raw_pointer, raw_size,
                  characteristics, flags, sha256, entropy
                )
                VALUES (?, '.text', ?, ?, 512, ?, 1610612768, 'code execute read', NULL, 1.0)
                """,
                (binary_id, rva_start, size, size),
            )
            conn.execute(
                """
                INSERT INTO executable_ranges(
                  label, binary_id, rva_start, rva_end, file_offset_start, file_offset_end,
                  classification, evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, 'unknown', 'test executable range')
                """,
                (label, binary_id, rva_start, rva_end, 512, 512 + size),
            )

    def _insert_basic_block(
        self,
        conn,
        binary_id,
        binary_label,
        rva_start,
        rva_end,
        *,
        classification="code",
        source="ghidra",
    ):
        label = basic_block_label(binary_label, rva_start, rva_end, source)
        with conn:
            ensure_label(conn, label, "basic_block", f"{binary_label}:block", "test block")
            conn.execute(
                """
                INSERT INTO basic_blocks(
                  label, binary_id, rva_start, rva_end, size, source, classification, confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'high')
                """,
                (label, binary_id, rva_start, rva_end, rva_end - rva_start, source, classification),
            )

    def _insert_coverage_block(self, conn, binary_id, binary_label, module_sha, rva_start, rva_end):
        started = utc_now()
        test_label = make_test_run_label("dynamic-proof", "halo-trace", started)
        coverage_label = coverage_block_label(test_label, binary_label, rva_start, rva_end)
        with conn:
            ensure_label(conn, test_label, "test", "dynamic-proof", "test coverage run", created_at=started)
            test_cursor = conn.execute(
                """
                INSERT INTO test_runs(
                  label, test_id, suite, command, status, started_at, finished_at,
                  tool_versions_json, provenance_json
                )
                VALUES (?, 'dynamic-proof', 'halo-trace', 'trace', 'imported', ?, ?, '{}', '{}')
                """,
                (test_label, started, started),
            )
            module_cursor = conn.execute(
                """
                INSERT INTO observed_modules(
                  test_run_id, drcov_module_id, path, base, end, entry, preferred_base, sha256, binary_id
                )
                VALUES (?, 0, 'haloce.exe', 4194304, 4206592, 4198400, 4194304, ?, ?)
                """,
                (int(test_cursor.lastrowid), module_sha, binary_id),
            )
            ensure_label(conn, coverage_label, "coverage_block", "dynamic-proof:block", "test coverage block")
            conn.execute(
                """
                INSERT INTO coverage_blocks(
                  label, test_run_id, observed_module_id, binary_id, rva_start, rva_end, size, source_log
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'trace.jsonl')
                """,
                (
                    coverage_label,
                    int(test_cursor.lastrowid),
                    int(module_cursor.lastrowid),
                    binary_id,
                    rva_start,
                    rva_end,
                    rva_end - rva_start,
                ),
            )

    def _insert_global_data(self, conn, binary_id, binary_label, module_sha, rva_start, rva_end):
        label = global_label(binary_label, rva_start, f"data_{rva_start:x}")
        with conn:
            ensure_label(conn, label, "global", f"{binary_label}:data", "test Ghidra data")
            ensure_oracle_mapping(
                conn,
                label=label,
                entity_type="global",
                binary_id=binary_id,
                module_sha256=module_sha,
                rva_start=rva_start,
                rva_end=rva_end,
                private={"source": "ghidra", "data_type": "dword[4]"},
            )
            conn.execute(
                """
                INSERT INTO globals(label, binary_id, rva, name, data_type, subsystem, confidence)
                VALUES (?, ?, ?, ?, 'dword[4]', 'unknown', 'medium')
                """,
                (label, binary_id, rva_start, f"data_{rva_start:x}"),
            )

    def _insert_waiver(self, conn, binary_id, binary_label, rva_start, rva_end, category):
        label = waiver_label(binary_label, rva_start, rva_end, category, "test waiver")
        with conn:
            ensure_label(conn, label, "waiver", f"{binary_label}:waiver", "test waiver")
            conn.execute(
                """
                INSERT INTO waivers(
                  label, binary_id, rva_start, rva_end, category, reason, evidence,
                  reviewer, revalidation_trigger, created_at
                )
                VALUES (?, ?, ?, ?, ?, 'test waiver', 'unit test evidence', 'tests', 'hash changes', ?)
                """,
                (label, binary_id, rva_start, rva_end, category, utc_now()),
            )

    def _insert_byte_class(self, conn, binary_id, binary_label, rva_start, rva_end, classification, source):
        label = executable_byte_class_label(binary_label, rva_start, rva_end, classification, source)
        with conn:
            ensure_label(conn, label, "executable_byte_class", f"{binary_label}:{classification}", "manual test row")
            conn.execute(
                """
                INSERT INTO executable_byte_classes(
                  label, binary_id, rva_start, rva_end, classification, source, evidence, confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, 'manual test row', 'high')
                """,
                (label, binary_id, rva_start, rva_end, classification, source),
            )

    def _insert_static_cross_checks(self, conn, binary_id, binary_label):
        for tool in ("llvm-readobj", "rizin"):
            checked = utc_now()
            label = static_cross_check_label(binary_label, tool, checked)
            with conn:
                ensure_label(conn, label, "static_cross_check", f"{binary_label}:{tool}", "unit test cross-check")
                conn.execute(
                    """
                    INSERT INTO static_cross_checks(
                      label, binary_id, tool, status, checked_at, command,
                      section_count, executable_section_count, evidence_json
                    )
                    VALUES (?, ?, ?, 'pass', ?, ?, 1, 1, '{}')
                    """,
                    (label, binary_id, tool, checked, f"{tool} haloce.exe"),
                )

    def _byte_class_rows(self, conn):
        return conn.execute(
            """
            SELECT rva_start, rva_end, classification, source
            FROM executable_byte_classes
            ORDER BY rva_start, rva_end
            """
        ).fetchall()


if __name__ == "__main__":
    unittest.main()
