"""Independently exercise a proposed reference/frame contract on PE32 Wine.

Use original production runtime bodies and actual allocation API calls. These
finite tests do not prove a trusted contract or authorize a lifted component.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source


TESTKIT = {
    "fixtures": ["compiler", "headless-wine"],
    "resources": ["tests/fixtures/native/issued_reference_contract.c"],
}

_PRELUDE = """
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void require(int condition, const char *message) {
  if (!condition) { fprintf(stderr, "CONTRACT MISMATCH: %s\\n", message); exit(42); }
}
#define __CPROVER_assert(c,m) require((c),(m))
"""


class IssuedReferenceContractTests(unittest.TestCase):
    def test_actual_api_frames_and_independent_negative_controls(self):
        compiler = fixture("compiler") / "bin/i686-w64-mingw32-gcc"
        runner = fixture("headless-wine") / "bin/spaghetti-headless-wine"
        body = (Path(__file__).parents[2] / "fixtures/native/issued_reference_contract.c").read_text()
        source = _PRELUDE + allocation_fixture_source(
            body, domain=3, object_id=1, extent_mode=1,
            identity="cleanup.scratch", minimum_extent=0,
            native_admission=True,
        )
        errors = {
            1: "cached reference versus original native resolver",
            2: "fresh allocation preserves old contents",
            3: "released reference expires without dereferencing freed storage",
            4: "allocation and release outcome order",
            5: "birth zero initialization does not erase a later alias write",
            6: "allocation result contract binds identity extent permissions and fresh generation",
            7: "issued-object offsets preserve address and current contents",
            8: "failed allocation has no native read or write admission",
            9: "native range extent rejects a crossing write",
        }
        with tempfile.TemporaryDirectory(prefix="issued-reference-contract-") as temporary:
            root = Path(temporary)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "fixture.c").write_text(source)
            compiled = subprocess.run(
                [str(compiler), "-std=c11", "-O1", str(root / "fixture.c"), "-o", str(root / "fixture.exe")],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root / "wine-prefix"), WINEDEBUG="-all",
                               WINEDLLOVERRIDES="mscoree,mshtml,winemenubuilder.exe=")
            for mutation in range(10):
                # A failed launch must stop the sequence: running the remaining
                # cases against an unfinished Wine prefix obscures the failure.
                result = subprocess.run(
                    [str(runner), str(root / "fixture.exe"), str(mutation)],
                    capture_output=True, text=True, timeout=60, env=environment,
                )
                with self.subTest(mutation=mutation):
                    self.assertEqual(result.returncode, 0 if mutation == 0 else 42, result.stderr)
                    if mutation:
                        self.assertIn("CONTRACT MISMATCH: " + errors[mutation], result.stderr)
                    else:
                        self.assertIn("PE32 runtime comparison passed", result.stdout)
