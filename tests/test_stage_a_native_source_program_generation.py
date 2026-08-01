from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.native_source_program import (
    NATIVE_SOURCE_PROGRAM_MODULE,
    NativeSourceProgramGenerationError,
    NativeSourceProgramSpec,
    native_source_program_source,
    write_native_source_program,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


def _spec(**changes: str) -> NativeSourceProgramSpec:
    base = NativeSourceProgramSpec(
        decoded_original_module="StageA.NativeSourceProgramDecodedFixture",
        decoded_original_program=(
            "StageA.NativeSourceProgramDecodedFixture.originalProgram"
        ),
        decoded_original_side=(
            "StageA.NativeSourceProgramDecodedFixture.originalProgramSide"
        ),
        original_pe="StageA.NativeSourceProgramDecodedFixture.pe",
        decoded_original_pe_exact=(
            "StageA.NativeSourceProgramDecodedFixture.originalProgramPeExact"
        ),
        semantic_program_module="StageA.GeneratedSemanticInterpreterProgram",
        semantic_program_records=(
            "StageA.GeneratedRelational.semanticInterpreterProgramRecords"
        ),
        semantic_program_records_unique=(
            "StageA.GeneratedRelational.semanticInterpreterProgramSourceRvasUnique"
        ),
        normalization_module=(
            "StageA.GeneratedNativeSourceNormalizationBundle"
        ),
        ordinary_record_bindings=(
            "StageA.GeneratedRelational.exactNormalizedOrdinaryRecordBindings"
        ),
        x87_schedule_module="StageA.GeneratedNativeSourceX87ScheduleBundle",
        x87_witnesses=(
            "StageA.GeneratedRelational.checkedNativeSourceX87BundleWitnesses"
        ),
        x87_source_rvas=(
            "StageA.GeneratedRelational.checkedNativeSourceX87BundleSourceRvas"
        ),
        x87_source_rvas_nodup=(
            "StageA.GeneratedRelational.checkedNativeSourceX87BundleSourceRvasNodup"
        ),
    )
    return dataclasses.replace(base, **changes)


class StageANativeSourceProgramGenerationTests(unittest.TestCase):
    def test_source_assembles_checked_generic_program_and_bindings(self) -> None:
        source = native_source_program_source(_spec())

        for required in (
            "import StageA.NativeSourceProgramDecodedFixture",
            "import StageA.GeneratedSemanticInterpreterProgram",
            "import StageA.GeneratedNativeSourceNormalizationBundle",
            "import StageA.GeneratedNativeSourceX87ScheduleBundle",
            "import StageA.RelationalSourceInterpreterKernel",
            "exactX87Provider",
            "def generatedNativeSourceProgram : Program",
            "ExactBindingPartition",
            "exactNormalizedOrdinaryRecordBindings",
            "semanticInterpreterProgramSourceRvasUnique",
            "exactX87Provider_execute",
            ".toExactBinding",
            "ExactBinding",
        ):
            self.assertIn(required, source)

        self.assertEqual(source.count("native_decide"), 1)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_all_submitted_names_are_validated_fail_closed(self) -> None:
        malformed = {
            "decoded_original_module": "OriginalProvider",
            "semantic_program_module": "StageA.Valid\naxiom bad : False",
            "normalization_module": "StageA.Bad-Module",
            "x87_schedule_module": "StageA.Valid -- comment",
            "namespace": "StageA.Generated; end StageA",
            "decoded_original_program": "provider.program()",
            "decoded_original_side": "by rfl",
            "original_pe": "provider.pe\n#eval 1",
            "decoded_original_pe_exact": "provider.sorry",
            "semantic_program_records": "[record]",
            "semantic_program_records_unique": "proof term",
            "ordinary_record_bindings": "bindings; axiom injected : False",
            "x87_witnesses": "requirements.witnesses -- accepted",
            "x87_source_rvas": "requirements.native_decide",
            "x87_source_rvas_nodup": "by native_decide",
            "output_module": "../Escaped",
            "program_name": "StageA.program",
            "binding_name": "sorry",
        }
        for field, value in malformed.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    NativeSourceProgramGenerationError,
                    "canonical",
                ):
                    native_source_program_source(_spec(**{field: value}))

        with self.assertRaisesRegex(
            NativeSourceProgramGenerationError,
            "distinct",
        ):
            native_source_program_source(
                _spec(binding_name="generatedNativeSourceProgram")
            )

    def test_writer_is_deterministic_and_uses_configured_module(self) -> None:
        spec = _spec(
            output_module="GeneratedAlternateNativeSourceProgram",
            binding_name="generatedAlternateNativeSourceBinding",
        )
        expected = native_source_program_source(spec).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_native_source_program(root, spec)
            first_bytes = first.read_bytes()
            second = write_native_source_program(root, spec)
            second_bytes = second.read_bytes()

        self.assertEqual(first.name, "GeneratedAlternateNativeSourceProgram.lean")
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected)

    def test_world_program_can_remain_external_environment_polymorphic(self) -> None:
        source = native_source_program_source(
            _spec(parameterize_world_program=True)
        )

        self.assertIn(
            "def generatedNativeSourceProgram (worldProgram : DecodedWorldProgram)",
            source,
        )
        self.assertIn(
            "ExactBindingPartition StageA.NativeSourceProgramDecodedFixture.pe "
            "generatedNativeSourceProgram worldProgram",
            source,
        )
        self.assertIn(
            "(originalSide : worldProgram.candidate = false)", source
        )
        self.assertIn(
            "(originalPeExact : worldProgram.context.originalPe = "
            "StageA.NativeSourceProgramDecodedFixture.pe)",
            source,
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_minimal_generated_program_compiles_without_sorry(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceInterpreterKernel",
            )
            (stage_a / "NativeSourceProgramDecodedFixture.lean").write_text(
                _DECODED_ORIGINAL_FIXTURE,
                encoding="ascii",
            )
            (stage_a / "GeneratedSemanticInterpreterProgram.lean").write_text(
                _SEMANTIC_PROGRAM_FIXTURE,
                encoding="ascii",
            )
            (
                stage_a / "GeneratedNativeSourceNormalizationBundle.lean"
            ).write_text(_NORMALIZATION_FIXTURE, encoding="ascii")
            (
                stage_a / "GeneratedNativeSourceX87ScheduleBundle.lean"
            ).write_text(_X87_FIXTURE, encoding="ascii")
            generated = write_native_source_program(root, _spec())
            self.assertEqual(
                generated.name,
                f"{NATIVE_SOURCE_PROGRAM_MODULE}.lean",
            )
            result = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_PROGRAM_MODULE,
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertIn("generatedNativeSourceExactBindingPartition", output)
        self.assertIn("generatedNativeSourceExactBinding", output)


_DECODED_ORIGINAL_FIXTURE = r"""import StageA.RelationalSourceInterpreterKernel

namespace StageA.NativeSourceProgramDecodedFixture

open StageA.Formal
open StageA.Relational

def pe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := 4194304
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 1
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := {
    entries := .leaf []
    originalAddresses := .leaf []
    candidateAddresses := .leaf []
  }
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def environment : WorldExternalEnvironment := {
  result := fun _ event => { state := event.state, world := event.world }
}

def originalProgram : DecodedWorldProgram := {
  candidate := false
  context := context
  regions := []
  externalCallSites := []
  environment := environment
}

theorem originalProgramSide : originalProgram.candidate = false := by rfl

theorem originalProgramPeExact : originalProgram.context.originalPe = pe := by
  rfl

end StageA.NativeSourceProgramDecodedFixture
"""


_SEMANTIC_PROGRAM_FIXTURE = r"""import StageA.RelationalSourceInterpreterKernel

namespace StageA.GeneratedRelational

open StageA.Relational.Interpreter

def semanticInterpreterProgramRecords : List ProgramRecord := []

theorem semanticInterpreterProgramSourceRvasUnique :
    (semanticInterpreterProgramRecords.map
      (fun record => record.sourceRva)).Nodup := by
  decide

end StageA.GeneratedRelational
"""


_NORMALIZATION_FIXTURE = r"""import StageA.NativeSourceProgramDecodedFixture
import StageA.RelationalSourceInterpreterKernel

namespace StageA.GeneratedRelational

def exactNormalizedOrdinaryRecordBindings : List
    (StageA.Relational.SourceWorld.InterpreterKernel.ExactOrdinaryRecordBinding
      StageA.NativeSourceProgramDecodedFixture.pe) := []

end StageA.GeneratedRelational
"""


_X87_FIXTURE = r"""import StageA.NativeSourceProgramDecodedFixture
import StageA.RelationalSourceInterpreterKernel

namespace StageA.GeneratedRelational

open StageA.Relational.InterpreterX87

def checkedNativeSourceX87BundleWitnesses :
    List (ExactInterpreterX87ScheduleWitness
      StageA.NativeSourceProgramDecodedFixture.pe) := []

def checkedNativeSourceX87BundleSourceRvas : List Nat :=
  checkedNativeSourceX87BundleWitnesses.map
    (fun witness => witness.schedule.sourceRva)

theorem checkedNativeSourceX87BundleSourceRvasNodup :
    checkedNativeSourceX87BundleSourceRvas.Nodup := by
  decide

end StageA.GeneratedRelational
"""


if __name__ == "__main__":
    unittest.main()
