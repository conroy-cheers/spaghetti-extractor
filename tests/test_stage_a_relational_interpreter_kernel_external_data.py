from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_LEAN_FILENAME,
    ExactRange,
    InterpreterKernelPlan,
    RelationalInterpreterKernelGenerationError,
    relational_interpreter_kernel_source,
    write_relational_interpreter_kernel_bundle,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_EXTERNAL_OPTIONS = {
    "candidate_data_module": "StageA.ExternalKernelDataFixture",
    "candidate_data_namespace": "StageA.ExternalKernelData",
    "candidate_bytes_symbol": "exactCandidateBytes",
    "candidate_pe_symbol": "exactCandidatePe",
}


def _plan(*, candidate_size: int = 4096) -> InterpreterKernelPlan:
    return InterpreterKernelPlan(
        candidate_bytes=bytes(index % 251 for index in range(candidate_size)),
        program_manifest_bytes=b"program-manifest",
        engine_layout_bytes=b"engine-layout",
        engine_layout_range=ExactRange("engine_layout", 0x2200, b"engine-layout"),
        compiled_program_ranges=(
            ExactRange("compiled_program", 0x2000, b"compiled-program"),
        ),
        program_transfer_count=1,
        functions=(),
        unbound_executable_ranges=(),
        issues=(),
        native_build_manifest_sha256="a" * 64,
    )


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


class StageARelationalInterpreterKernelExternalDataTests(unittest.TestCase):
    def test_default_mode_keeps_embedded_candidate_bytes(self) -> None:
        plan = _plan()

        generated = relational_interpreter_kernel_source(plan)

        self.assertEqual(
            generated,
            relational_interpreter_kernel_source(
                plan,
                candidate_data_module=None,
                candidate_data_namespace=None,
                candidate_bytes_symbol=None,
                candidate_pe_symbol=None,
            ),
        )
        self.assertTrue(
            generated.startswith("import StageA.RelationalInterpreterKernel\n")
        )
        self.assertIn("def generatedKernelCandidateBytesChunk0", generated)
        self.assertNotIn("def generatedKernelCandidatePe : PE32", generated)
        self.assertIn("exists pe imports,", generated)

    def test_external_mode_imports_and_aliases_exact_candidate_data(self) -> None:
        plan = _plan()

        generated = relational_interpreter_kernel_source(
            plan, **_EXTERNAL_OPTIONS
        )

        self.assertIn("import StageA.ExternalKernelDataFixture", generated)
        self.assertIn(
            "def generatedKernelCandidateBytes : ByteTree :=\n"
            "  StageA.ExternalKernelData.exactCandidateBytes",
            generated,
        )
        self.assertIn(
            "def generatedKernelCandidatePe : PE32 :=\n"
            "  StageA.ExternalKernelData.exactCandidatePe",
            generated,
        )
        self.assertNotIn("generatedKernelCandidateBytesChunk", generated)
        self.assertLess(
            len(generated), len(relational_interpreter_kernel_source(plan))
        )
        self.assertIn(
            "parsePE32Tree generatedKernelCandidateBytes =\n"
            "      some generatedKernelCandidatePe",
            generated,
        )
        self.assertIn(
            "generatedKernelArtifactBinding.checked "
            "generatedKernelCandidatePe = true",
            generated,
        )
        self.assertIn(
            "candidatePeSha256 := "
            f'"{hashlib.sha256(plan.candidate_bytes).hexdigest()}"',
            generated,
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{re.escape(marker)}\b", generated))
        self.assertNotIn('"status"', generated)

    def test_external_mode_requires_all_names_and_rejects_injection(self) -> None:
        plan = _plan()
        for missing in _EXTERNAL_OPTIONS:
            options = dict(_EXTERNAL_OPTIONS)
            del options[missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(
                RelationalInterpreterKernelGenerationError,
                "requires module, namespace, bytes symbol, and PE symbol",
            ):
                relational_interpreter_kernel_source(plan, **options)

        invalid_values = {
            "candidate_data_module": "Other.ExternalKernelData",
            "candidate_data_namespace": "StageA.External; axiom escape : False",
            "candidate_bytes_symbol": "bytes.value",
            "candidate_pe_symbol": "pe\naxiom escape : False",
        }
        for name, value in invalid_values.items():
            options = {**_EXTERNAL_OPTIONS, name: value}
            with self.subTest(name=name), self.assertRaises(
                RelationalInterpreterKernelGenerationError
            ):
                relational_interpreter_kernel_source(plan, **options)

    def test_bundle_writer_forwards_external_data_binding(self) -> None:
        plan = _plan()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch(
                "spaghetti_extractor.relational.lean.interpreter_kernel."
                "build_relational_interpreter_kernel_plan",
                return_value=plan,
            ):
                returned = write_relational_interpreter_kernel_bundle(
                    out=output,
                    **_EXTERNAL_OPTIONS,
                )

            generated = (output / INTERPRETER_KERNEL_LEAN_FILENAME).read_text(
                encoding="utf-8"
            )

        self.assertIs(returned, plan)
        self.assertIn("import StageA.ExternalKernelDataFixture", generated)
        self.assertNotIn("generatedKernelCandidateBytesChunk", generated)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_external_mode_generated_module_elaborates(self) -> None:
        plan = _plan(candidate_size=4)
        generated = relational_interpreter_kernel_source(
            plan, **_EXTERNAL_OPTIONS
        )
        repository = Path(__file__).parents[1]
        source_root = repository / "src/spaghetti_extractor/lean/StageA"

        with tempfile.TemporaryDirectory() as temporary:
            lean_root = Path(temporary)
            stage_a = lean_root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernel"
            )
            (stage_a / "ExternalKernelDataFixture.lean").write_text(
                _EXTERNAL_DATA_FIXTURE, encoding="utf-8"
            )
            (stage_a / INTERPRETER_KERNEL_LEAN_FILENAME).write_text(
                generated, encoding="utf-8"
            )

            result = _run_lean_relational(
                lean_root, bundle="GeneratedRelationalInterpreterKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])


_EXTERNAL_DATA_FIXTURE = r"""import StageA.RelationalInterpreterKernel

namespace StageA.ExternalKernelData

open StageA.Formal

def exactCandidateBytes : ByteTree := ByteTree.ofBytes [77, 90, 0, 0]

def exactCandidatePe : PE32 := {
  bytes := exactCandidateBytes
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 4
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

end StageA.ExternalKernelData
"""
