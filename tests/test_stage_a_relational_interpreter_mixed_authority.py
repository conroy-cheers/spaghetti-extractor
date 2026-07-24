from __future__ import annotations

import dataclasses
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_authority import (
    INTERPRETER_MIXED_AUTHORITY_MODULE,
    InterpreterMixedAuthorityGenerationError,
    InterpreterMixedAuthoritySpec,
    relational_interpreter_mixed_authority_source,
    write_relational_interpreter_mixed_authority,
)


class StageARelationalInterpreterMixedAuthorityTests(unittest.TestCase):
    def test_source_binds_exact_kernel_data_without_copying_candidate(self) -> None:
        spec = InterpreterMixedAuthoritySpec()
        source = relational_interpreter_mixed_authority_source(spec)

        self.assertIn(
            "import StageA.GeneratedInterpreterKernelDataBundle", source
        )
        self.assertIn("def generatedCandidateNativeWorldProgram", source)
        self.assertIn("def generatedExactNativeCandidateAuthority", source)
        self.assertIn(
            "StageA.GeneratedRelational.InterpreterKernelData."
            "generatedInterpreterKernelDataCertificate",
            source,
        )
        self.assertIn("decide +kernel", source)
        self.assertNotIn("ByteTree", source)
        self.assertNotIn("candidateBytes", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide", "status"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writer_is_deterministic_and_honors_output_module(self) -> None:
        spec = InterpreterMixedAuthoritySpec(output_module="ExactCandidateBinding")
        expected = relational_interpreter_mixed_authority_source(spec)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_relational_interpreter_mixed_authority(root, spec)
            first_bytes = first.read_bytes()
            second = write_relational_interpreter_mixed_authority(root, spec)

            self.assertEqual(first, root / "StageA/ExactCandidateBinding.lean")
            self.assertEqual(first_bytes, second.read_bytes())
            self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_rejects_noncanonical_lean_identifiers(self) -> None:
        base = InterpreterMixedAuthoritySpec()
        invalid = {
            "kernel_data_module": "GeneratedKernelData",
            "kernel_data_namespace": "StageA.Bad-Namespace",
            "output_module": "StageA.BadOutput",
            "namespace": "StageA.Bad Namespace",
            "candidate_pe": "candidate.pe",
            "imports": "def",
        }
        for field, value in invalid.items():
            with self.subTest(field=field):
                spec = dataclasses.replace(base, **{field: value})
                with self.assertRaises(InterpreterMixedAuthorityGenerationError):
                    relational_interpreter_mixed_authority_source(spec)

    def test_default_spec_matches_the_generated_gnu_kernel_data_interface(
        self,
    ) -> None:
        root = Path(__file__).parents[1]
        generated = (
            root
            / "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-data-v1/StageA"
        )
        base_path = generated / "GeneratedInterpreterKernelDataBase.lean"
        bundle_path = generated / "GeneratedInterpreterKernelDataBundle.lean"
        if not base_path.is_file() or not bundle_path.is_file():
            self.skipTest("GNU interpreter-kernel-data build artifact is absent")

        spec = InterpreterMixedAuthoritySpec()
        base_source = base_path.read_text(encoding="utf-8")
        bundle_source = bundle_path.read_text(encoding="utf-8")
        base_names = (
            spec.candidate_pe,
            spec.import_certificate,
            spec.imports,
            spec.relocations,
            spec.table_rva,
            spec.count_rva,
            spec.pe_parsed,
            spec.imports_parsed,
            spec.relocations_parsed,
        )
        for name in base_names:
            self.assertRegex(base_source, rf"\b{re.escape(name)}\b")
        for name in (spec.semantic_records, spec.table_certificate):
            self.assertRegex(bundle_source, rf"\b{re.escape(name)}\b")

        source = relational_interpreter_mixed_authority_source(spec)
        self.assertIn(f"import {spec.kernel_data_module}", source)
        self.assertEqual(spec.output_module, INTERPRETER_MIXED_AUTHORITY_MODULE)


if __name__ == "__main__":
    unittest.main()
