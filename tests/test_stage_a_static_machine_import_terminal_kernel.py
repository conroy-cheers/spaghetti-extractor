from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.static_machine_import_contracts import (
    plan_static_machine_import_contracts,
    write_static_machine_import_contracts,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.test_stage_a_static_machine_import_contracts import _write_fixture


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
class StageAStaticMachineImportTerminalKernelTests(unittest.TestCase):
    def test_direct_terminal_boundary_and_mutations_are_kernel_checked(self) -> None:
        self._compile_terminal_fixture(via_thunk=False)

    def test_thunk_terminal_boundary_and_mutations_are_kernel_checked(self) -> None:
        self._compile_terminal_fixture(via_thunk=True)

    def _compile_terminal_fixture(self, *, via_thunk: bool) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=via_thunk)
            profile_path = fixture.plan_arguments["profile_paths"][0]
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile["machine_import_signatures"][0]["disposition"] = "terminates"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)
            self.assertTrue(plan.complete, plan.to_json())

            stage_a = root / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            _copy_module_closure(
                source_root, stage_a, "RelationalStaticMachineImportContracts"
            )

            pe_path = fixture.plan_arguments["original_pe"]
            pe_bytes = Path(pe_path).read_bytes()
            binary = _parse_stage_a_pe(Path(pe_path))
            try:
                pe_source = _EXACT_PE_MODULE.format(
                    byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                )
            finally:
                binary.pe.close()
            (stage_a / "GeneratedStaticMachineImportFixturePE.lean").write_text(
                pe_source, encoding="utf-8"
            )

            generated_root = root / "generated"
            generated, _report = write_static_machine_import_contracts(
                generated_root, plan, fixture.bindings
            )
            shutil.copyfile(
                generated, stage_a / "GeneratedStaticMachineImportContracts.lean"
            )
            (stage_a / "StaticMachineImportTerminalKernel.lean").write_text(
                _TERMINAL_KERNEL_MODULE,
                encoding="utf-8",
            )

            result = _run_lean_relational(
                root / "lean", bundle="StaticMachineImportTerminalKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)


_EXACT_PE_MODULE = r"""import StageA.Formal

namespace StageA.Generated.StaticMachineImportFixturePE

open StageA.Formal

{byte_tree}

def originalPe : PE32 := {pe_literal}

def originalImportCertificate : ImportTableCertificate := {imports_literal}

end StageA.Generated.StaticMachineImportFixturePE
"""


_TERMINAL_KERNEL_MODULE = r"""import StageA.GeneratedStaticMachineImportContracts

namespace StageA.Relational.StaticMachineImportTerminalKernel

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.GeneratedRelational.StaticMachineImports

set_option maxRecDepth 1000000

def terminalContextWith
    (contracts : List MachineImportCallContract) : StaticProofContext := {
  originalPe := StageA.Generated.StaticMachineImportFixturePE.originalPe
  candidatePe := StageA.Generated.StaticMachineImportFixturePE.originalPe
  originalImportCertificate :=
    StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate
  candidateImportCertificate :=
    StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate
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
  machineImportCallContracts := contracts
}

def checkedBoundary : StaticMachineImportBoundary :=
  generatedMachineImportBoundaries.head?.get (by decide)

def checkedBinding : StaticMachineImportTerminalBoundaryBinding := {
  boundary := checkedBoundary
}

theorem checkedTerminalBoundaryAccepted :
    checkedBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      generatedMachineImportSignatures generatedMachineImportBoundaries
      generatedMachineImportBoundaryCallContracts = true := by
  decide

def returningSignatures : List StaticMachineImportSignature :=
  generatedMachineImportSignatures.map fun signature =>
    { signature with disposition := .returns }

def protocolSignatures : List StaticMachineImportSignature :=
  generatedMachineImportSignatures.map fun signature =>
    { signature with disposition := .protocol }

def resolvedFor (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) :
    List StaticMachineImportResolvedBoundary :=
  (staticMachineImportBoundaryContracts? signatures boundaries).getD []

def contractsFor (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) :
    List MachineImportCallContract :=
  (resolvedFor signatures boundaries).map (·.contract)

theorem returningRouteRemainsValidated :
    checkedBoundary.valid
      StageA.Generated.StaticMachineImportFixturePE.originalPe
      StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate.imports
      returningSignatures = true := by
  decide

theorem protocolRouteRemainsValidated :
    checkedBoundary.valid
      StageA.Generated.StaticMachineImportFixturePE.originalPe
      StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate.imports
      protocolSignatures = true := by
  decide

theorem returningBoundaryRejected :
    checkedBinding.valid (terminalContextWith
        (contractsFor returningSignatures generatedMachineImportBoundaries))
      returningSignatures generatedMachineImportBoundaries
      (resolvedFor returningSignatures generatedMachineImportBoundaries) = false := by
  decide

theorem protocolBoundaryRejected :
    checkedBinding.valid (terminalContextWith
        (contractsFor protocolSignatures generatedMachineImportBoundaries))
      protocolSignatures generatedMachineImportBoundaries
      (resolvedFor protocolSignatures generatedMachineImportBoundaries) = false := by
  decide

theorem duplicateBoundaryRejected :
    checkedBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      generatedMachineImportSignatures
      (checkedBoundary :: generatedMachineImportBoundaries)
      generatedMachineImportBoundaryCallContracts = false := by
  decide

theorem duplicateSignatureRejected :
    checkedBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      (generatedMachineImportSignatures.head?.get (by decide) ::
        generatedMachineImportSignatures)
      generatedMachineImportBoundaries
      generatedMachineImportBoundaryCallContracts = false := by
  decide

theorem duplicateInventoryRejected :
    checkedBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      generatedMachineImportSignatures generatedMachineImportBoundaries
      (generatedMachineImportBoundaryCallContracts.head?.get (by decide) ::
        generatedMachineImportBoundaryCallContracts) = false := by
  decide

theorem duplicateContextContractRejected :
    checkedBinding.valid
      (terminalContextWith
        (generatedMachineImportBoundaryContracts.head?.get (by decide) ::
          generatedMachineImportBoundaryContracts))
      generatedMachineImportSignatures generatedMachineImportBoundaries
      generatedMachineImportBoundaryCallContracts = false := by
  decide

def wrongSourceRoute : StaticMachineImportBoundaryRoute :=
  match checkedBoundary.route with
  | .direct span => .direct { span with start := span.start + 1 }
  | .viaThunk caller thunk =>
      .viaThunk { caller with start := caller.start + 1 } thunk
  | route => route

def wrongSourceBinding : StaticMachineImportTerminalBoundaryBinding := {
  boundary := { checkedBoundary with route := wrongSourceRoute }
}

def wrongExecutionSourceBinding : StaticMachineImportTerminalBoundaryBinding := {
  boundary := {
    checkedBoundary with
    executionSourceRva := checkedBoundary.executionSourceRva + 1
  }
}

def wrongContinuationBinding : StaticMachineImportTerminalBoundaryBinding := {
  boundary := {
    checkedBoundary with continuationRva := checkedBoundary.continuationRva + 1
  }
}

theorem wrongSourceRejected :
    wrongSourceBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      generatedMachineImportSignatures generatedMachineImportBoundaries
      generatedMachineImportBoundaryCallContracts = false := by
  decide

theorem wrongExecutionSourceRejected :
    wrongExecutionSourceBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      generatedMachineImportSignatures generatedMachineImportBoundaries
      generatedMachineImportBoundaryCallContracts = false := by
  decide

theorem wrongContinuationRejected :
    wrongContinuationBinding.valid
      (terminalContextWith generatedMachineImportBoundaryContracts)
      generatedMachineImportSignatures generatedMachineImportBoundaries
      generatedMachineImportBoundaryCallContracts = false := by
  decide

def unvalidatedBoundary : StaticMachineImportBoundary := {
  checkedBoundary with
  instructionRva :=
    checkedBoundary.sourceSpan.start + checkedBoundary.sourceSpan.size
}

def unvalidatedBoundaries : List StaticMachineImportBoundary :=
  [unvalidatedBoundary]

def unvalidatedInventory : List StaticMachineImportResolvedBoundary :=
  resolvedFor generatedMachineImportSignatures unvalidatedBoundaries

def unvalidatedBinding : StaticMachineImportTerminalBoundaryBinding := {
  boundary := unvalidatedBoundary
}

theorem unvalidatedRouteIsInvalid :
    unvalidatedBoundary.valid
      StageA.Generated.StaticMachineImportFixturePE.originalPe
      StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate.imports
      generatedMachineImportSignatures = false := by
  decide

theorem unvalidatedRouteRejected :
    unvalidatedBinding.valid
      (terminalContextWith
        (contractsFor generatedMachineImportSignatures unvalidatedBoundaries))
      generatedMachineImportSignatures unvalidatedBoundaries
      unvalidatedInventory = false := by
  decide

#print axioms checkedTerminalBoundaryAccepted
#print axioms returningRouteRemainsValidated
#print axioms protocolRouteRemainsValidated
#print axioms returningBoundaryRejected
#print axioms protocolBoundaryRejected
#print axioms duplicateBoundaryRejected
#print axioms duplicateSignatureRejected
#print axioms duplicateInventoryRejected
#print axioms duplicateContextContractRejected
#print axioms wrongSourceRejected
#print axioms wrongExecutionSourceRejected
#print axioms wrongContinuationRejected
#print axioms unvalidatedRouteIsInvalid
#print axioms unvalidatedRouteRejected

end StageA.Relational.StaticMachineImportTerminalKernel
"""


if __name__ == "__main__":
    unittest.main()
