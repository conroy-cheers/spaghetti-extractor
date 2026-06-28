import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog.db import connect, initialize
from haloce_catalog.labels import (
    ensure_label,
    executable_byte_class_label,
    executable_range_label,
    module_label,
)
from haloce_catalog.reports import gates_json
from haloce_catalog.pe import BlockCandidate, EdgeCandidate, _split_blocks_at_edge_targets, mapped_section_size
from haloce_catalog.static_crosscheck import (
    ToolSection,
    compare_sections,
    parse_llvm_readobj_sections,
    parse_rizin_sections,
    run_static_cross_checks,
)
from haloce_catalog.util import utc_now


class StaticCrossCheckTests(unittest.TestCase):
    def test_mapped_section_size_excludes_raw_file_alignment_tail(self):
        self.assertEqual(mapped_section_size(0x1064, 0x1200), 0x1064)
        self.assertEqual(mapped_section_size(0, 0x1200), 0x1200)
        self.assertEqual(mapped_section_size(0x1400, 0x1200), 0x1400)

    def test_linear_block_discovery_splits_blocks_at_branch_targets(self):
        blocks = [
            BlockCandidate(0x1000, 0x1010, "capstone-linear", "code", "low"),
            BlockCandidate(0x1010, 0x1012, "capstone-linear", "padding/alignment", "medium"),
        ]
        edges = [EdgeCandidate(0x1002, 0x1008, "branch", "capstone-linear", "low")]

        split = _split_blocks_at_edge_targets(blocks, edges)

        self.assertEqual(
            [(block.rva_start, block.rva_end, block.classification) for block in split],
            [
                (0x1000, 0x1008, "code"),
                (0x1008, 0x1010, "code"),
                (0x1010, 0x1012, "padding/alignment"),
            ],
        )

    def test_run_static_cross_checks_records_llvm_and_rizin_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary_path = root / "haloce.exe"
            binary_path.write_bytes(b"MZ")
            db_path = root / "catalog.db"
            self._seed_catalog(db_path, root)

            def fake_run(command, **kwargs):
                if command[0] == "llvm-readobj":
                    return subprocess.CompletedProcess(command, 0, stdout=_LLVM_SECTIONS, stderr="")
                if command[0] == "rizin":
                    return subprocess.CompletedProcess(command, 0, stdout=_rizin_sections(0x400000), stderr="")
                raise AssertionError(command)

            with mock.patch("haloce_catalog.static_crosscheck.subprocess.run", side_effect=fake_run):
                result = run_static_cross_checks(db_path, tools=("llvm-readobj", "rizin"))

            conn = connect(db_path)
            checks = [dict(row) for row in conn.execute("SELECT tool, status FROM static_cross_checks ORDER BY tool")]
            gate = gates_json(conn)["catalog-complete"]
            conn.close()

        self.assertEqual(result["checks"], 2)
        self.assertEqual(result["passed"], 2)
        self.assertEqual(checks, [{"tool": "llvm-readobj", "status": "pass"}, {"tool": "rizin", "status": "pass"}])
        self.assertEqual(gate["static_cross_checks"]["status"], "pass")
        self.assertEqual(gate["static_cross_checks"]["missing_required_checks"], 0)
        self.assertEqual(gate["status"], "pass")

    def test_run_static_cross_checks_records_mismatches_as_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "haloce.exe").write_bytes(b"MZ")
            db_path = root / "catalog.db"
            self._seed_catalog(db_path, root)

            bad_llvm = _LLVM_SECTIONS.replace("RawDataSize: 16", "RawDataSize: 8")
            with mock.patch(
                "haloce_catalog.static_crosscheck.subprocess.run",
                return_value=subprocess.CompletedProcess(["llvm-readobj"], 0, stdout=bad_llvm, stderr=""),
            ):
                result = run_static_cross_checks(db_path, tools=("llvm-readobj",))

            conn = connect(db_path)
            row = conn.execute("SELECT status, evidence_json FROM static_cross_checks").fetchone()
            gate = gates_json(conn)["catalog-complete"]
            conn.close()

        self.assertEqual(result["failed"], 1)
        self.assertEqual(row["status"], "fail")
        evidence = json.loads(row["evidence_json"])
        self.assertEqual(evidence["mismatches"][0]["fields"]["raw_size"], {"catalog": 16, "tool": 8})
        self.assertEqual(gate["static_cross_checks"]["status"], "open")
        self.assertGreaterEqual(gate["static_cross_checks"]["missing_required_checks"], 1)

    def test_static_cross_check_gate_uses_latest_status_per_binary_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "haloce.exe").write_bytes(b"MZ")
            db_path = root / "catalog.db"
            self._seed_catalog(db_path, root)

            bad_llvm = _LLVM_SECTIONS.replace("RawDataSize: 16", "RawDataSize: 8")
            with mock.patch(
                "haloce_catalog.static_crosscheck.subprocess.run",
                return_value=subprocess.CompletedProcess(["llvm-readobj"], 0, stdout=bad_llvm, stderr=""),
            ):
                run_static_cross_checks(db_path, tools=("llvm-readobj",))
            with mock.patch(
                "haloce_catalog.static_crosscheck.subprocess.run",
                return_value=subprocess.CompletedProcess(["llvm-readobj"], 0, stdout=_LLVM_SECTIONS, stderr=""),
            ):
                run_static_cross_checks(db_path, tools=("llvm-readobj",))
            with mock.patch(
                "haloce_catalog.static_crosscheck.subprocess.run",
                return_value=subprocess.CompletedProcess(["rizin"], 0, stdout=_rizin_sections(0x400000), stderr=""),
            ):
                run_static_cross_checks(db_path, tools=("rizin",))

            conn = connect(db_path)
            gate = gates_json(conn)["catalog-complete"]["static_cross_checks"]
            conn.close()

        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["missing_required_checks"], 0)
        self.assertEqual(gate["failure_samples"], [])
        self.assertEqual(gate["static_cross_checks"], 3)
        self.assertEqual(gate["latest_static_cross_checks"], 2)

    def test_section_parsers_and_comparison(self):
        llvm = parse_llvm_readobj_sections(_LLVM_SECTIONS)
        rizin = parse_rizin_sections(_rizin_sections(0x400000), image_base=0x400000)
        catalog = [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x10,
                "raw_size": 16,
                "executable": True,
            }
        ]

        self.assertEqual((llvm[0].name, llvm[0].rva, llvm[0].virtual_size, llvm[0].raw_size), (".text", 0x1000, 0x10, 16))
        self.assertEqual((rizin[0].name, rizin[0].rva, rizin[0].raw_size, rizin[0].executable), (".text", 0x1000, 16, True))
        self.assertEqual(compare_sections(catalog, llvm, strict_virtual_size=True)["mismatches"], [])
        self.assertEqual(compare_sections(catalog, rizin, strict_virtual_size=False)["mismatches"], [])

    def test_comparison_matches_duplicate_names_by_name_and_rva(self):
        catalog = [
            {
                "name": "BINKYUY2",
                "virtual_address": 0x32000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "executable": True,
            },
            {
                "name": "BINKYUY2",
                "virtual_address": 0x33000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "executable": True,
            },
        ]
        observed = [
            ToolSection("BINKYUY2", 0x32000, 0x200, 0x200, True),
            ToolSection("BINKYUY2", 0x33000, 0x200, 0x200, True),
        ]

        evidence = compare_sections(catalog, observed, strict_virtual_size=True)

        self.assertEqual(evidence["missing"], [])
        self.assertEqual(evidence["extra"], [])
        self.assertEqual(evidence["mismatches"], [])

    def test_comparison_normalizes_rizin_duplicate_section_suffixes(self):
        catalog = [
            {
                "name": "BINKYUY2",
                "virtual_address": 0x33000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "executable": True,
            }
        ]
        observed = [ToolSection("BINKYUY2_0x2c200", 0x33000, 0x200, None, True)]

        evidence = compare_sections(catalog, observed, strict_virtual_size=False)

        self.assertEqual(evidence["missing"], [])
        self.assertEqual(evidence["extra"], [])
        self.assertEqual(evidence["mismatches"], [])

    def test_comparison_normalizes_known_coff_long_section_name_aliases(self):
        catalog = [
            {
                "name": "/4",
                "virtual_address": 0x1000,
                "virtual_size": 0x20,
                "raw_size": 0x200,
                "executable": False,
            }
        ]
        observed = [ToolSection(".eh_frame", 0x1000, 0x200, 0x20, False)]

        evidence = compare_sections(catalog, observed, strict_virtual_size=True)

        self.assertEqual(evidence["missing"], [])
        self.assertEqual(evidence["extra"], [])
        self.assertEqual(evidence["mismatches"], [])

    def test_comparison_allows_rva_match_for_blank_tool_long_section_names(self):
        catalog = [
            {
                "name": "/4",
                "virtual_address": 0x4DE000,
                "virtual_size": 0x89000,
                "raw_size": 0x88200,
                "executable": False,
            }
        ]
        observed = [ToolSection("", 0x4DE000, 0x88200, None, False)]

        evidence = compare_sections(catalog, observed, strict_virtual_size=False)

        self.assertEqual(evidence["missing"], [])
        self.assertEqual(evidence["extra"], [])
        self.assertEqual(evidence["mismatches"], [])

    def _seed_catalog(self, db_path: Path, root: Path) -> None:
        conn = connect(db_path)
        initialize(conn)
        created = utc_now()
        sha = "a" * 64
        module = module_label("haloce.exe", sha)
        with conn:
            ensure_label(conn, module, "module", "haloce.exe", created_at=created)
            binary_id = int(
                conn.execute(
                    """
                    INSERT INTO binaries(
                      label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                      entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                      role, scope, role_reason, source_root, catalog_version, discovered_at
                    )
                    VALUES (?, 'haloce.exe', 'haloce.exe', ?, 2, 'exe', 'i386', 0,
                            4194304, 4096, 8192, 'windows_gui', '0.0', 0,
                            'closed_runtime', 'included', 'test binary', ?, 'test', ?)
                    """,
                    (module, sha, str(root), created),
                ).lastrowid
            )
            conn.execute(
                """
                INSERT INTO sections(
                  binary_id, name, virtual_address, virtual_size, raw_pointer, raw_size,
                  characteristics, flags, sha256, entropy
                )
                VALUES (?, '.text', 4096, 16, 512, 16, 1610612768, 'code,execute,read', ?, 1.0)
                """,
                (binary_id, sha),
            )
            range_label = executable_range_label(module, 0x1000, 0x1010, "unknown")
            ensure_label(conn, range_label, "executable_range", "text", "test range")
            range_id = int(
                conn.execute(
                    """
                    INSERT INTO executable_ranges(
                      label, binary_id, rva_start, rva_end, file_offset_start, file_offset_end,
                      classification, evidence
                    )
                    VALUES (?, ?, 4096, 4112, 512, 528, 'unknown', 'test range')
                    """,
                    (range_label, binary_id),
                ).lastrowid
            )
            byte_label = executable_byte_class_label(module, 0x1000, 0x1010, "code", "test")
            ensure_label(conn, byte_label, "executable_byte_class", "text code", "unit test")
            conn.execute(
                """
                INSERT INTO executable_byte_classes(
                  label, binary_id, executable_range_id, rva_start, rva_end,
                  classification, source, evidence, confidence
                )
                VALUES (?, ?, ?, 4096, 4112, 'code', 'test', 'unit test', 'high')
                """,
                (byte_label, binary_id, range_id),
            )
        conn.close()


_LLVM_SECTIONS = """
File: haloce.exe
Format: COFF-i386
Sections [
  Section {
    Name: .text (2E 74 65 78 74 00 00 00)
    VirtualSize: 0x10
    VirtualAddress: 0x1000
    RawDataSize: 16
    Characteristics [ (0x60000020)
      IMAGE_SCN_CNT_CODE (0x20)
      IMAGE_SCN_MEM_EXECUTE (0x20000000)
      IMAGE_SCN_MEM_READ (0x40000000)
    ]
  }
]
"""


def _rizin_sections(image_base: int) -> str:
    return json.dumps(
        [
            {
                "name": ".text",
                "size": 16,
                "vsize": 4096,
                "perm": "-r-x",
                "flags": ["CNT_CODE"],
                "paddr": 512,
                "vaddr": image_base + 0x1000,
            }
        ]
    )


if __name__ == "__main__":
    unittest.main()
