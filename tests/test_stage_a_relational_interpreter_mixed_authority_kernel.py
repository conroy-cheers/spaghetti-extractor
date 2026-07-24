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
from spaghetti_extractor.relational.lean.interpreter_mixed_authority import (
    InterpreterMixedAuthoritySpec,
    write_relational_interpreter_mixed_authority,
)
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
class StageARelationalInterpreterMixedAuthorityKernelTests(unittest.TestCase):
    def test_generated_exact_candidate_authority_compiles(self) -> None:
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
            (stage_a / "GeneratedTinyInterpreterKernelData.lean").write_text(
                _TINY_KERNEL_DATA.format(
                    byte_tree=byte_tree,
                    pe_literal=pe_literal,
                    imports_literal=imports_literal,
                    relocations_literal=relocations_literal,
                ),
                encoding="utf-8",
            )
            spec = InterpreterMixedAuthoritySpec(
                kernel_data_module="StageA.GeneratedTinyInterpreterKernelData",
                kernel_data_namespace="StageA.GeneratedRelational.TinyKernelData",
                output_module="GeneratedTinyInterpreterMixedAuthority",
                namespace="StageA.GeneratedRelational.TinyMixedAuthority",
            )
            write_relational_interpreter_mixed_authority(root, spec)
            (stage_a / "GeneratedTinyMixedAuthorityAudit.lean").write_text(
                _AUDIT,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="GeneratedTinyMixedAuthorityAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertIn("generatedExactNativeCandidateAuthority", output)


_TINY_KERNEL_DATA = r"""import StageA.RelationalInterpreterKernelData

namespace StageA.GeneratedRelational.TinyKernelData

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelData

set_option maxRecDepth 1000000

{byte_tree}

def generatedInterpreterKernelCandidatePe : PE32 :=
  {pe_literal}

def generatedInterpreterKernelImportCertificate : ImportTableCertificate :=
  {imports_literal}

def generatedInterpreterKernelImports : List PEImport :=
  generatedInterpreterKernelImportCertificate.imports

def generatedInterpreterKernelRelocations : List BaseRelocation :=
  {relocations_literal}

def generatedInterpreterKernelTableRva : Nat := 0x1020
def generatedInterpreterKernelCountRva : Nat := 0x1010
def semanticInterpreterProgramRecords : List ProgramRecord := []

theorem generatedInterpreterKernelCandidateParsed :
    parsePE32Tree generatedInterpreterKernelCandidatePe.bytes =
      some generatedInterpreterKernelCandidatePe := by
  decide +kernel

theorem generatedInterpreterKernelImportsChecked :
    importTableValid generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImportCertificate = true := by
  decide +kernel

theorem generatedInterpreterKernelRelocationsParsed :
    parseRelocations generatedInterpreterKernelCandidatePe =
      some generatedInterpreterKernelRelocations := by
  decide +kernel

def generatedInterpreterKernelDataCertificate :
    ProgramTableCertificate generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
      semanticInterpreterProgramRecords := {{
  transferCount := 0
  countDecoded := by decide +kernel
  relocationsParsed := generatedInterpreterKernelRelocationsParsed
  shards := []
  shardsCover := by decide +kernel
  semanticRecordsExact := by decide +kernel
  sourceRvasUnique := by simp [semanticInterpreterProgramRecords]
}}

end StageA.GeneratedRelational.TinyKernelData
"""


_AUDIT = r"""import StageA.GeneratedTinyInterpreterMixedAuthority

namespace StageA.GeneratedRelational.TinyMixedAuthorityAudit

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.TinyKernelData
open StageA.GeneratedRelational.TinyMixedAuthority

def blockingEnvironment : NativeWorldEnvironment := {
  action := fun _ _ _ => .blocked (.unclassifiedNativeFault 0)
}

#print axioms generatedCandidateNativeWorldProgram
#print axioms generatedCandidateNativeWorldLoaderImageValid
#print axioms generatedExactNativeCandidateAuthority

example :
    (generatedCandidateNativeWorldProgram blockingEnvironment).imports =
      generatedInterpreterKernelImports := by
  rfl

end StageA.GeneratedRelational.TinyMixedAuthorityAudit
"""


if __name__ == "__main__":
    unittest.main()
