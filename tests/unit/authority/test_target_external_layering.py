from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class TargetExternalLayeringTests(unittest.TestCase):
    def _run_isolated(self, source: str) -> None:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(ROOT / "src"), *sys.path]
        )
        result = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(source)],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_record_modules_do_not_import_checker_modules(self) -> None:
        self._run_isolated(
            """
            import sys
            import spaghetti_extractor.authority.external_site_records
            import spaghetti_extractor.authority.target_certificate_records

            assert "spaghetti_extractor.authority.external_site_checker" not in sys.modules
            assert "spaghetti_extractor.authority.target_certificate_checker" not in sys.modules
            """
        )

    def test_authority_data_consumers_do_not_import_checker_modules(self) -> None:
        self._run_isolated(
            """
            import sys
            import spaghetti_extractor.authority.callbacks
            import spaghetti_extractor.authority.final_authority
            import spaghetti_extractor.authority.inductive
            import spaghetti_extractor.authority.root_closure

            assert "spaghetti_extractor.authority.external_site_checker" not in sys.modules
            assert "spaghetti_extractor.authority.target_certificate_checker" not in sys.modules
            """
        )

    def test_phase_modules_are_explicit_checker_dependencies(self) -> None:
        self._run_isolated(
            """
            import sys
            from spaghetti_extractor.authority.external_site_checker import (
                CANONICAL_EXTERNAL_SITES_PHASE_V3,
            )
            from spaghetti_extractor.authority.target_certificate_checker import (
                INDIRECT_TARGET_CERTIFICATES_PHASE_V3,
            )

            assert CANONICAL_EXTERNAL_SITES_PHASE_V3.name == "canonical-external-sites-v3"
            assert INDIRECT_TARGET_CERTIFICATES_PHASE_V3.name == "indirect-target-certificates-v3"
            assert "spaghetti_extractor.authority.external_site_checker" in sys.modules
            assert "spaghetti_extractor.authority.target_certificate_checker" in sys.modules
            """
        )


if __name__ == "__main__":
    unittest.main()
