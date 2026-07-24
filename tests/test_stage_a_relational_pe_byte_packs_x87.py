from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

if "tests" not in sys.modules:
    tests_package = types.ModuleType("tests")
    tests_package.__path__ = [str(Path(__file__).parent)]
    sys.modules["tests"] = tests_package

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_x87 import (
    relational_interpreter_x87_bundle_sources,
    relational_interpreter_x87_module_inventory,
)
from spaghetti_extractor.relational.lean.pe_byte_packs import (
    PEBytePackGenerationError,
    generate_pe_byte_pack_bundle,
    load_pe_byte_pack_inventory,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from tests.test_stage_a_relational_interpreter_x87_generation import (
    _row,
    _write_machine,
)
from tests.test_stage_a_relational_pe_byte_packs import _pe32_image


_AXIOMS = re.compile(r"depends on axioms: \[([^\]]*)\]")


def _pack_inventory(root: Path, pe_path: Path, *, standalone: bool):
    return generate_pe_byte_pack_bundle(
        pe_path=pe_path,
        out_dir=root,
        module_prefix="X87PackFixture",
        namespace="StageA.GeneratedRelational.PackFixture",
        pack_size=64 * 1024,
        chunk_size=1024,
        standalone=standalone,
        authoritative_module="X87PackFixturePE",
        authoritative_bytes_name="peBytes",
        authoritative_pe_name="pe",
        runtime_binding_prefix="source",
    )


class StageARelationalPEBytePackX87Tests(unittest.TestCase):
    def test_large_pe_x87_shard_imports_only_the_intersecting_pack(self) -> None:
        code = bytearray((index * 29 + 7) % 256 for index in range(132 * 1024))
        code[100:102] = b"\xd9\xe8"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe_path = root / "large.exe"
            pe_path.write_bytes(_pe32_image(bytes(code)))
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row(start=0x1000 + 100)])
            inventory = _pack_inventory(root, pe_path, standalone=False)
            source_size = inventory.source_size
            reloaded = load_pe_byte_pack_inventory(
                root / "pe-byte-packs.json", pe_path=pe_path
            )
            sources = relational_interpreter_x87_bundle_sources(
                machine,
                source_module="StageA.X87PackFixturePE",
                pe_name=inventory.qualified_pe_name,
                module_prefix="GeneratedPackX87Schedule",
                definition_prefix="checkedPackX87Schedule",
                pe_byte_pack_inventory=reloaded,
            )
            module_inventory = relational_interpreter_x87_module_inventory(
                machine,
                source_module="StageA.X87PackFixturePE",
                pe_name=inventory.qualified_pe_name,
                module_prefix="GeneratedPackX87Schedule",
                definition_prefix="checkedPackX87Schedule",
                pe_byte_pack_inventory=reloaded,
            )

        schedule = sources["GeneratedPackX87Schedule0000"]
        self.assertGreater(source_size, 100 * 1024)
        self.assertIn(
            f"import StageA.{inventory.packs[0].certificate_module}", schedule
        )
        for pack in inventory.packs[1:]:
            self.assertNotIn(f"import StageA.{pack.certificate_module}", schedule)
        self.assertNotIn("import StageA.X87PackFixturePE", schedule)
        self.assertIn("readExactSectionRvaSpan_eq_pack_of_checked", schedule)
        self.assertIn("exactScheduleRvaBytes_eq_readExactSectionRvaSpan", schedule)
        self.assertIn("sourceImportsParsed", schedule)
        self.assertIn("ordinaryExecutableWithImportsChecked", schedule)
        exact = schedule.split("theorem checkedPackX87Schedule0000ExactPEBytes", 1)[
            1
        ].split("theorem checkedPackX87Schedule0000SemanticClasses", 1)[0]
        self.assertNotIn("by decide +kernel", exact)
        self.assertNotIn("parsePE32Tree", schedule)
        self.assertNotIn("parseImports ", schedule)
        self.assertLess(len(schedule.encode()), 24_000)
        self.assertEqual(reloaded.payload(), inventory.payload())
        self.assertEqual(
            module_inventory["pe_byte_packs"]["pack_modules"],
            [inventory.packs[0].certificate_module],
        )

    def test_pack_aware_x87_generation_fails_closed_on_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(_pe32_image(b"\xd9\xee" + b"\x90" * 64))
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row(start=0x1000)])
            inventory = _pack_inventory(root, pe_path, standalone=False)
            with self.assertRaises(StageAInputError):
                relational_interpreter_x87_bundle_sources(
                    machine,
                    source_module="StageA.X87PackFixturePE",
                    pe_name=inventory.qualified_pe_name,
                    pe_byte_pack_inventory=inventory,
                )

            payload = json.loads((root / "pe-byte-packs.json").read_text())
            payload["packs"][0]["raw_offset"] = 1
            (root / "tampered.json").write_text(json.dumps(payload))
            with self.assertRaisesRegex(
                PEBytePackGenerationError, "contiguous and zero based"
            ):
                load_pe_byte_pack_inventory(
                    root / "tampered.json", pe_path=pe_path
                )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_pack_aware_x87_exact_bytes_are_kernel_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(_pe32_image(b"\xd9\xe8" + b"\x90" * 2046))
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row(start=0x1000)])
            inventory = _pack_inventory(root, pe_path, standalone=True)
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            for module in source_root.glob("*.lean"):
                destination = root / "StageA" / module.name
                if not destination.exists():
                    shutil.copyfile(module, destination)
            source = relational_interpreter_x87_bundle_sources(
                machine,
                source_module="StageA.X87PackFixturePE",
                pe_name=inventory.qualified_pe_name,
                module_prefix="GeneratedPackX87Schedule",
                definition_prefix="checkedPackX87Schedule",
                pe_byte_pack_inventory=inventory,
            )["GeneratedPackX87Schedule0000"]
            (root / "StageA/GeneratedPackX87Schedule0000.lean").write_text(
                source, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedPackX87Schedule0000"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertIn("checkedPackX87Schedule0000ExactPEBytes", result["stdout"])
        observed: set[str] = set()
        for match in _AXIOMS.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
