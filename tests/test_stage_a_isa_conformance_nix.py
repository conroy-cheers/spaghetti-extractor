from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.isa_conformance_nix import (
    _isa_conformance_nix_expression,
    stage_a_check_isa_conformance_nix,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageAISAConformanceNixTests(unittest.TestCase):
    def test_expression_uses_explicit_nixpkgs_config_and_optional_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus.json"
            corpus.write_text("{}", encoding="utf-8")
            evaluator = root / "evaluator.nix"
            evaluator.write_text("{}", encoding="utf-8")

            unicorn = _isa_conformance_nix_expression(
                corpus=corpus,
                backend="unicorn",
                bochs_runner=None,
                with_forms=False,
                evaluator=evaluator,
                flake_root=root,
                content_addressed=True,
            )
            self.assertIn("config = {};", unicorn)
            self.assertIn("kernelCache = null;", unicorn)
            self.assertIn("contentAddressed = true;", unicorn)

            lean = _isa_conformance_nix_expression(
                corpus=corpus,
                backend="lean",
                bochs_runner=None,
                with_forms=True,
                evaluator=evaluator,
                flake_root=root,
                content_addressed=False,
            )
            self.assertIn('packages."isa-kernel"', lean)
            self.assertIn("withForms = true;", lean)

    def test_rejects_non_lean_forms_before_nix(self):
        with self.assertRaisesRegex(
            StageAInputError, "--forms-out is valid only"
        ):
            stage_a_check_isa_conformance_nix(
                corpus=Path("/missing"),
                backend="unicorn",
                out=Path("/unused"),
                forms_out=Path("/unused-forms"),
            )

    def test_copies_nix_outputs_and_records_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus.json"
            corpus.write_text("{}", encoding="utf-8")
            evaluator = root / "evaluator.nix"
            evaluator.write_text("{}", encoding="utf-8")
            (root / "flake.lock").write_text("{}", encoding="utf-8")
            store = root / "store-output"
            store.mkdir()
            (store / "report.json").write_text(
                '{"format":"stage-a-isa-conformance-report-v2"}\n',
                encoding="utf-8",
            )
            (store / "forms.json").write_text(
                '{"format":"stage-a-lean-isa-semantic-forms-v1"}\n',
                encoding="utf-8",
            )
            result = {
                "format": "stage-a-isa-conformance-check-v1",
                "status": "pass",
                "proof_authority": False,
                "closes_stage_a_proof": False,
                "out": str(store / "report.json"),
                "forms_out": str(store / "forms.json"),
            }
            (store / "result.json").write_text(
                json.dumps(result), encoding="utf-8"
            )
            process = type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(
                        [
                            {
                                "drvPath": "/nix/store/test.drv",
                                "outputs": {"out": str(store)},
                            }
                        ]
                    ),
                    "stderr": "",
                },
            )()
            out = root / "copied" / "report.json"
            forms = root / "copied" / "forms.json"

            with (
                patch(
                    "spaghetti_extractor.isa_conformance_nix."
                    "_isa_conformance_nix_evaluator",
                    return_value=evaluator,
                ),
                patch(
                    "spaghetti_extractor.isa_conformance_nix."
                    "find_flake_root",
                    return_value=root,
                ),
                patch(
                    "spaghetti_extractor.isa_conformance_nix."
                    "nix_build_expression",
                    return_value=["nix", "build"],
                ),
                patch(
                    "spaghetti_extractor.isa_conformance_nix.subprocess.run",
                    return_value=process,
                ),
            ):
                actual = stage_a_check_isa_conformance_nix(
                    corpus=corpus,
                    backend="lean",
                    out=out,
                    forms_out=forms,
                )

            self.assertTrue(out.is_file())
            self.assertTrue(forms.is_file())
            self.assertEqual(actual["out"], str(out))
            self.assertEqual(actual["forms_out"], str(forms))
            self.assertEqual(
                actual["nix"]["drv_path"], "/nix/store/test.drv"
            )
            self.assertTrue(actual["nix"]["content_addressed"])


if __name__ == "__main__":
    unittest.main()
