from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
    _lean_relocations,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalInterpreterMixedContextKernelTests(unittest.TestCase):
    def test_tiny_original_and_native_candidate_authorities_compile(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe_path = root / "tiny.exe"
            pe_bytes = pe32_image(b"\xc3" + b"\0" * 63)
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                byte_tree = _lean_byte_tree_definitions("tinyBytes", pe_bytes)
                pe_literal = _lean_pe(binary, "tinyBytes")
                imports_literal = _lean_import_certificate(binary)
                relocations_literal = _lean_relocations(binary)
            finally:
                binary.pe.close()

            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterMixedContext"
            )
            (stage_a / "RelationalInterpreterMixedContextKernel.lean").write_text(
                _KERNEL_FIXTURE.format(
                    byte_tree=byte_tree,
                    pe_literal=pe_literal,
                    imports_literal=imports_literal,
                    relocations_literal=relocations_literal,
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedContextKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("tinyOriginalSource", output)
        self.assertIn("tinyCandidateAuthority", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterMixedContext

namespace StageA.Relational.InterpreterMixedContextKernel

set_option maxRecDepth 1000000

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeWorld

{byte_tree}

def tinyPe : PE32 :=
  {pe_literal}

def tinyImportCertificate : ImportTableCertificate :=
  {imports_literal}

def tinyRelocations : List BaseRelocation :=
  {relocations_literal}

def oneCheck : IndexedBoolCertificate := {{
  ranges := [{{ start := 0, size := 1 }}]
}}

def tinyCodeMap : OriginalCodeMap := {{
  entries := .leaf [{{ id := 0, regionIndex := 0, rva := 0x1000 }}]
  addresses := .leaf [{{ targetId := 0, kind := .canonical }}]
}}

def tinyCodeMapCertificate :
    OriginalCodeMapCertificate tinyPe tinyImportCertificate.imports tinyCodeMap := {{
  entriesStructurallyValid := by native_decide
  addressesStructurallyValid := by native_decide
  entryChecks := oneCheck
  entryChecksValid := by native_decide
  addressCountExact := by native_decide
  addressChecks := oneCheck
  addressChecksValid := by native_decide
  roundTripChecks := oneCheck
  roundTripChecksValid := by native_decide
  aliasChecks := oneCheck
  aliasChecksValid := by native_decide
}}

def tinyOriginalContext : OriginalDecodedStaticContext := {{
  pe := tinyPe
  importCertificate := tinyImportCertificate
  relocations := tinyRelocations
  codeMap := tinyCodeMap
  regions := .leaf [{{
    id := 0
    span := {{ start := 0x1000, size := 1 }}
    root := true
    targets := []
  }}]
}}

def tinyOriginalAuthority :
    ExactOriginalDecodedAuthority tinyOriginalContext := {{
  peParsed := by native_decide
  importsParsed := by native_decide
  relocationsParsed := by native_decide
  loaderImageValid := by native_decide
  codeMap := tinyCodeMapCertificate
  regionsStructurallyValid := by native_decide
  sourceChecks := oneCheck
  sourceChecksValid := by native_decide
  machineContractsValid := by native_decide
}}

theorem tinyOriginalSource :
    exists source, tinyOriginalContext.source? 0 = some source := by
  exact tinyOriginalAuthority.source_exists 0 (by decide)

def blockingEnvironment : NativeWorldEnvironment := {{
  action := fun _ _ _ => .blocked (.unclassifiedNativeFault 0)
}}

def tinyCandidate : ExactNativeWorldProgram := {{
  pe := tinyPe
  imports := tinyImportCertificate.imports
  environment := blockingEnvironment
}}

def tinyTableCertificate : ProgramTableCertificate tinyCandidate.pe
    tinyCandidate.imports tinyRelocations 0x1020 0x1010 [] := {{
  transferCount := 0
  countDecoded := by native_decide
  relocationsParsed := by native_decide
  shards := []
  shardsCover := by native_decide
  semanticRecordsExact := by native_decide
  sourceRvasUnique := by simp
}}

def tinyCandidateAuthority : ExactNativeCandidateAuthority tinyCandidate := {{
  importCertificate := tinyImportCertificate
  relocations := tinyRelocations
  tableRva := 0x1020
  countRva := 0x1010
  semanticRecords := []
  peParsed := by native_decide
  importsBound := rfl
  importsParsed := by native_decide
  relocationsParsed := by native_decide
  loaderImageValid := by native_decide
  table := tinyTableCertificate
}}

def exactMixedRelation : MixedRelationContract := {{
  worldsRelated := Eq
  launchStatesRelated := fun originalWorld candidateWorld original candidate =>
    originalWorld = candidateWorld /\ original = candidate
  runtimeStatesRelated := fun originalWorld candidateWorld original candidate =>
    originalWorld = candidateWorld /\ original = candidate
  valuesRelated := fun originalWorld candidateWorld original candidate =>
    originalWorld = candidateWorld /\ original = candidate
  callbackTargetsRelated := Eq
}}

example : exactMixedRelation.eventObservationsRelated none none := trivial

example (reason : ExecutionBlock) :
    ¬ exactMixedRelation.eventObservationsRelated
      (some (.proofBlocked reason)) none :=
  exactMixedRelation.proofBlocked_left_is_unrelated reason none

#print axioms tinyOriginalSource
#print axioms tinyCandidateAuthority
#print axioms MixedRelationContract.proofBlocked_left_is_unrelated

end StageA.Relational.InterpreterMixedContextKernel
"""


if __name__ == "__main__":
    unittest.main()
