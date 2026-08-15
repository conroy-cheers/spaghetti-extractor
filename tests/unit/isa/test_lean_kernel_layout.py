from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from spaghetti_extractor.extraction.isa_requirements import (
    extract_lean_instruction_forms_side,
)
from spaghetti_extractor.isa.semantic_forms import (
    LEAN_SEMANTIC_FORM_CLASSIFIER_MODULES,
    PYTHON_RESOURCES,
    lean_semantic_form_classifier_sha256,
)
from spaghetti_extractor.extraction.schema import ISA_FORM_EXTRACTION_MODULES
from spaghetti_extractor.util import sha256_file


ROOT = Path(__file__).resolve().parents[3]
LEAN_ROOT = ROOT / "src" / "spaghetti_extractor" / "lean" / "SpaghettiExtractor/ISA"
NIX_ROOT = ROOT / "nix"
TESTKIT = {
    "resources": (
        "nix/isa-conformance-kernel.nix",
        "nix/isa-semantic-kernel.nix",
    ),
}


class LeanKernelLayoutTests(unittest.TestCase):
    def test_form_extraction_creates_the_nested_lean_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "fixture.exe"
            binary.write_bytes(b"fixture")

            def checked_graph(lean_dir, *, bundle):
                self.assertTrue(
                    (Path(lean_dir) / "SpaghettiExtractor/ISA").is_dir()
                )
                return {"status": "checked"}

            with (
                mock.patch(
                    "spaghetti_extractor.build_support.lean_runner.run_lean_module_graph",
                    side_effect=checked_graph,
                ),
                mock.patch(
                    "spaghetti_extractor.extraction.isa_requirements.parse_pe_image",
                    return_value=object(),
                ),
                mock.patch(
                    "spaghetti_extractor.extraction.isa_requirements.shutil.which",
                    return_value="lean",
                ),
                mock.patch(
                    "spaghetti_extractor.extraction.isa_requirements.subprocess.run",
                    return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
                ),
            ):
                rows, evidence = extract_lean_instruction_forms_side(
                    binary=binary,
                    request={
                        "side": "original",
                        "binary_sha256": sha256_file(binary),
                        "regions": [],
                    },
                )

            self.assertEqual(rows, {})
            self.assertEqual(evidence["status"], "lean_extracted_untrusted")

    def test_kernel_is_split_at_stable_dependency_boundaries(self):
        expected_imports = {
            "Bytes.lean": ("import Std",),
            "PE32.lean": ("import SpaghettiExtractor.ISA.Bytes",),
            "Machine.lean": ("import SpaghettiExtractor.ISA.PE32", "import SpaghettiExtractor.ISA.X87"),
            "Decode.lean": ("import SpaghettiExtractor.ISA.Machine",),
            "Semantics.lean": ("import SpaghettiExtractor.ISA.Decode",),
        }
        self.assertFalse((LEAN_ROOT / "Formal.lean").exists())
        for name, imports in expected_imports.items():
            source = (LEAN_ROOT / name).read_text(encoding="utf-8")
            for imported in imports:
                self.assertIn(imported, source)
            self.assertIn("namespace SpaghettiExtractor.ISA.Formal", source)

        qualification = (LEAN_ROOT / "ISAQualification.lean").read_text(
            encoding="utf-8"
        )
        conformance = (LEAN_ROOT / "ISAConformance.lean").read_text(
            encoding="utf-8"
        )
        self.assertIn("import SpaghettiExtractor.ISA.Decode", qualification)
        self.assertNotIn("import SpaghettiExtractor.ISA.Semantics", qualification)
        self.assertIn("import SpaghettiExtractor.ISA.Semantics", conformance)

        conformance_wiring = (
            NIX_ROOT / "isa-conformance-kernel.nix"
        ).read_text(encoding="utf-8")
        semantic_wiring = (
            NIX_ROOT / "isa-semantic-kernel.nix"
        ).read_text(encoding="utf-8")
        for name in ("Bytes", "PE32", "Machine", "Decode", "Semantics"):
            self.assertIn(f'"{name}"', conformance_wiring)
            self.assertIn(f'"{name}.lean"', semantic_wiring)
        self.assertNotIn('"Formal"', conformance_wiring)
        self.assertNotIn('"Formal.lean"', semantic_wiring)

    def test_form_extraction_uses_only_the_decoder_kernel_closure(self):
        self.assertEqual(
            ISA_FORM_EXTRACTION_MODULES,
            LEAN_SEMANTIC_FORM_CLASSIFIER_MODULES + ("ISAInventory",),
        )
        self.assertNotIn("Formal", ISA_FORM_EXTRACTION_MODULES)
        self.assertNotIn("Semantics", ISA_FORM_EXTRACTION_MODULES)
        self.assertNotIn("ISAConformance", ISA_FORM_EXTRACTION_MODULES)
        self.assertEqual(
            PYTHON_RESOURCES,
            tuple(
                f"src/spaghetti_extractor/lean/SpaghettiExtractor/ISA/{module}.lean"
                for module in LEAN_SEMANTIC_FORM_CLASSIFIER_MODULES
            ),
        )

    def test_retired_whole_program_kernel_is_absent(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(LEAN_ROOT.glob("*.lean"))
        )
        for declaration in (
            "def runImage",
            "def StrongRefines",
            "structure ProofBundle",
            "def checkProofBundle",
            "def StrongTraceRefines",
            "def ExactImageStrongRefinement",
        ):
            self.assertNotIn(declaration, sources)
        semantics = (LEAN_ROOT / "Semantics.lean").read_text(encoding="utf-8")
        self.assertIn("def executeInstruction ", semantics)
        self.assertNotIn("def executeCode", semantics)

    def test_classifier_identity_excludes_executor_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary)
            for name in (
                "X87.lean",
                "Bytes.lean",
                "PE32.lean",
                "Machine.lean",
                "Decode.lean",
                "ISAQualification.lean",
            ):
                (copied / name).write_bytes((LEAN_ROOT / name).read_bytes())
            before = lean_semantic_form_classifier_sha256(copied)
            (copied / "Semantics.lean").write_text(
                "executor-only change\n", encoding="utf-8"
            )
            after = lean_semantic_form_classifier_sha256(copied)
            self.assertEqual(after, before)
            with (copied / "Decode.lean").open("a", encoding="utf-8") as source:
                source.write("\nclassifier change\n")
            self.assertNotEqual(
                lean_semantic_form_classifier_sha256(copied), before
            )


if __name__ == "__main__":
    unittest.main()
