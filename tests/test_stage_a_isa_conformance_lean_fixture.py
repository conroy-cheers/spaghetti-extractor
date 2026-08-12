from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.isa_conformance import ISAConformanceError
from spaghetti_extractor.isa_conformance_lean import (
    LEAN_KERNEL_CACHE_ENV,
    run_lean_isa_conformance,
)
from tests.test_stage_a_isa_conformance_unicorn import _corpus


class StageAISAConformanceLeanFixtureTests(unittest.TestCase):
    def test_missing_shared_kernel_fails_with_supported_command(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                ISAConformanceError,
                r"nix run \.#test -- affected",
            ):
                run_lean_isa_conformance(_corpus())

    def test_incomplete_shared_kernel_names_missing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {LEAN_KERNEL_CACHE_ENV: temporary},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    ISAConformanceError,
                    r"StageA/X87\.olean",
                ):
                    run_lean_isa_conformance(_corpus())

    def test_explicit_cache_takes_precedence_over_environment(self) -> None:
        with tempfile.TemporaryDirectory() as explicit:
            with mock.patch.dict(
                os.environ,
                {LEAN_KERNEL_CACHE_ENV: str(Path(explicit) / "environment")},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    ISAConformanceError,
                    re.escape(str(Path(explicit))) + r".*StageA/X87\.olean",
                ):
                    run_lean_isa_conformance(
                        _corpus(), kernel_cache=Path(explicit)
                    )


if __name__ == "__main__":
    unittest.main()
