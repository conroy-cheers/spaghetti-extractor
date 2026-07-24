from __future__ import annotations

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

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.pe_byte_packs import (
    PEBytePackSpan,
    generate_pe_byte_pack_bundle,
    generate_pe_byte_pack_schedule,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from tests.test_stage_a_relational_pe_byte_packs import _pe32_image


_AXIOMS = re.compile(r"depends on axioms: \[([^\]]*)\]")


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalPEBytePackKernelTests(unittest.TestCase):
    def test_local_and_cross_pack_exact_bytes_are_kernel_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(
                _pe32_image(bytes(index % 251 for index in range(2048)))
            )
            inventory = generate_pe_byte_pack_bundle(
                pe_path=pe_path,
                out_dir=root,
                module_prefix="KernelFixture",
                pack_size=1024,
                chunk_size=256,
            )
            generate_pe_byte_pack_schedule(
                inventory,
                out_dir=root,
                module_name="KernelFixtureSchedule",
                spans=(
                    PEBytePackSpan("crossing", 0x1000 + 508, 16),
                    PEBytePackSpan("local", 0x1000 + 100, 7),
                ),
            )
            result = _run_lean_relational(root, bundle="KernelFixtureSchedule")

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertIn("crossingExactRvaBytes", result["stdout"])
        self.assertIn("localExactRvaBytes", result["stdout"])
        observed: set[str] = set()
        for match in _AXIOMS.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
