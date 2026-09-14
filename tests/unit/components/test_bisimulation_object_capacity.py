"""Real addressed C objects exercise the contextual checker's encoding capacity."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_execution import property_checker_command
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class ObjectCapacityTests(unittest.TestCase):
    def test_region_can_address_more_than_1024_distinct_c_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "objects.c"
            source.write_text("extern unsigned nondet(void);\nint main(void) {\n" +
                "\n".join(f"  unsigned cell_{i}={i}U;" for i in range(1100)) +
                "\n  unsigned *cells[]={" + ",".join(f"&cell_{i}" for i in range(1100)) + "};\n"
                "  unsigned index=nondet(); __CPROVER_assume(index<1100U);\n"
                '  __CPROVER_assert(*cells[index]==index,"selected object retains its value");\n}\n')
            arguments = property_checker_command([])["assertion_arguments"]
            arguments = ["main" if x == "$PROPERTY_FUNCTION" else
                         "main.assertion.1" if x == "$PROPERTY_ID" else x for x in arguments]
            checker = shutil.which("cbmc")
            result = run_cbmc_properties(command=[checker, str(source), *arguments], timeout_seconds=30)
            self.assertEqual(result["status"], "satisfied", result.get("detail"))
            old = list(arguments)
            old[old.index("--object-bits") + 1] = "10"
            result = run_cbmc_properties(command=[checker, str(source), *old], timeout_seconds=30)
            self.assertEqual(result["code"], "cbmc_object_limit", result.get("detail"))
