from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.relational.lean.artifact_byte_packs import (
    ExternalArtifactBytesBinding,
    generate_artifact_byte_pack_bundle,
)
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
_CANDIDATE_OPTIONS = {
    "candidate_data_module": "StageA.ExternalKernelDataFixture",
    "candidate_data_namespace": "StageA.ExternalKernelData",
    "candidate_bytes_symbol": "exactCandidateBytes",
    "candidate_pe_symbol": "exactCandidatePe",
}


def _plan() -> InterpreterKernelPlan:
    return InterpreterKernelPlan(
        candidate_bytes=b"MZ\0\0",
        program_manifest_bytes=b"program-manifest-exact-bytes",
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


class StageARelationalInterpreterKernelExternalArtifactTests(unittest.TestCase):
    def test_external_artifacts_replace_literals_without_replacing_checks(self) -> None:
        plan = _plan()
        program = ExternalArtifactBytesBinding(
            "StageA.ProgramArtifact", "StageA.External.Program", "programBytes"
        )
        compiled = ExternalArtifactBytesBinding(
            "StageA.CompiledArtifact", "StageA.External.Compiled", "compiledBytes"
        )
        layout = ExternalArtifactBytesBinding(
            "StageA.LayoutArtifact", "StageA.External.Layout", "layoutBytes"
        )

        generated = relational_interpreter_kernel_source(
            plan,
            program_manifest_data=program,
            compiled_program_data=compiled,
            engine_layout_data=layout,
        )

        for binding in (program, compiled, layout):
            self.assertIn(f"import {binding.module}", generated)
            self.assertIn(binding.qualified_bytes_name, generated)
        self.assertIn(
            "def generatedKernelProgramManifestBytes : Bytes :=\n"
            "  StageA.External.Program.programBytes",
            generated,
        )
        self.assertIn(
            "KernelSHA256.checkedHex binding.programManifestBytes",
            (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernel.lean"
            ).read_text(),
        )
        self.assertIn(
            "binding.compiledProgramBytes ==\n"
            "      binding.compiledProgramRanges.flatMap",
            (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernel.lean"
            ).read_text(),
        )

    def test_wrong_external_binding_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            RelationalInterpreterKernelGenerationError,
            "must be an ExternalArtifactBytesBinding",
        ):
            relational_interpreter_kernel_source(
                _plan(), program_manifest_data={"bytes": "unchecked"}  # type: ignore[arg-type]
            )

    def test_bundle_writer_forwards_external_artifact_bindings(self) -> None:
        binding = ExternalArtifactBytesBinding(
            "StageA.ProgramArtifact", "StageA.External.Program", "programBytes"
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch(
                "spaghetti_extractor.relational.lean.interpreter_kernel."
                "build_relational_interpreter_kernel_plan",
                return_value=_plan(),
            ):
                write_relational_interpreter_kernel_bundle(
                    out=output, program_manifest_data=binding
                )
            generated = (output / INTERPRETER_KERNEL_LEAN_FILENAME).read_text()

        self.assertIn(f"import {binding.module}", generated)
        self.assertIn(binding.qualified_bytes_name, generated)

    def test_bundle_writer_externalizes_all_exact_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch(
                "spaghetti_extractor.relational.lean.interpreter_kernel."
                "build_relational_interpreter_kernel_plan",
                return_value=_plan(),
            ):
                write_relational_interpreter_kernel_bundle(
                    out=output,
                    externalize_artifacts=True,
                    artifact_pack_size=8,
                )
            generated = (output / INTERPRETER_KERNEL_LEAN_FILENAME).read_text()
            aggregate = json.loads(
                (output / "artifact-byte-pack-inventories.json").read_text()
            )

        self.assertEqual(len(aggregate["artifacts"]), 3)
        for prefix in (
            "GeneratedKernelProgramManifest",
            "GeneratedKernelCompiledProgram",
            "GeneratedKernelEngineLayout",
        ):
            self.assertIn(f"import StageA.{prefix}Artifact", generated)
        self.assertNotIn("program-manifest-exact-bytes", generated)

    def test_bundle_writer_rejects_mixed_automatic_and_explicit_bindings(self) -> None:
        binding = ExternalArtifactBytesBinding(
            "StageA.ProgramArtifact", "StageA.External.Program", "programBytes"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with patch(
                "spaghetti_extractor.relational.lean.interpreter_kernel."
                "build_relational_interpreter_kernel_plan",
                return_value=_plan(),
            ), self.assertRaisesRegex(
                RelationalInterpreterKernelGenerationError,
                "cannot be combined",
            ):
                write_relational_interpreter_kernel_bundle(
                    out=temporary,
                    externalize_artifacts=True,
                    program_manifest_data=binding,
                )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_external_artifact_hashes_and_range_concatenation_elaborate(self) -> None:
        plan = _plan()
        repository = Path(__file__).parents[1]
        source_root = repository / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (
                "RelationalInterpreterKernel",
                "RelationalArtifactBytePacks",
            ):
                _copy_module_closure(source_root, stage_a, module)
            (stage_a / "ExternalKernelDataFixture.lean").write_text(
                _EXTERNAL_CANDIDATE_FIXTURE, encoding="utf-8"
            )

            bindings: dict[str, ExternalArtifactBytesBinding] = {}
            for role, data in (
                ("Program", plan.program_manifest_bytes),
                ("Compiled", plan.compiled_program_bytes),
                ("Layout", plan.engine_layout_bytes),
            ):
                artifact = root / f"{role.lower()}.bin"
                artifact.write_bytes(data)
                inventory = generate_artifact_byte_pack_bundle(
                    artifact_path=artifact,
                    out_dir=root,
                    module_prefix=f"{role}Fixture",
                    namespace=f"StageA.GeneratedRelational.{role}Fixture",
                    pack_size=8,
                    chunk_size=4,
                    standalone=False,
                )
                bindings[role] = inventory.binding

            generated = relational_interpreter_kernel_source(
                plan,
                **_CANDIDATE_OPTIONS,
                program_manifest_data=bindings["Program"],
                compiled_program_data=bindings["Compiled"],
                engine_layout_data=bindings["Layout"],
            )
            (stage_a / INTERPRETER_KERNEL_LEAN_FILENAME).write_text(
                generated, encoding="utf-8"
            )
            (stage_a / "ExternalArtifactKernelConsumer.lean").write_text(
                _consumer_source(plan), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="ExternalArtifactKernelConsumer"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])


def _consumer_source(plan: InterpreterKernelPlan) -> str:
    return f"""import StageA.GeneratedRelationalInterpreterKernel

namespace StageA.GeneratedRelational.InterpreterKernel

open StageA.Relational.InterpreterKernel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem exactProgramManifestHash :
    KernelSHA256.checkedHex generatedKernelProgramManifestBytes
      \"{hashlib.sha256(plan.program_manifest_bytes).hexdigest()}\" = true := by
  decide

theorem exactCompiledProgramHash :
    KernelSHA256.checkedHex generatedKernelCompiledProgramBytes
      \"{hashlib.sha256(plan.compiled_program_bytes).hexdigest()}\" = true := by
  decide

theorem exactCompiledRangeConcatenation :
    generatedKernelCompiledProgramBytes =
      generatedKernelCompiledProgramRanges.flatMap (fun range => range.bytes) := by
  decide

theorem exactEngineLayoutRange :
    generatedKernelEngineLayoutRange.bytes =
      generatedKernelEngineLayoutBytes := by
  decide

#print axioms exactProgramManifestHash
#print axioms exactCompiledProgramHash
#print axioms exactCompiledRangeConcatenation
#print axioms exactEngineLayoutRange

end StageA.GeneratedRelational.InterpreterKernel
"""


_EXTERNAL_CANDIDATE_FIXTURE = r"""import StageA.RelationalInterpreterKernel

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


if __name__ == "__main__":
    unittest.main()
