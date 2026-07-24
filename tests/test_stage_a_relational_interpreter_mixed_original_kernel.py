from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from pe_fixtures import pe32_import_image
from test_stage_a_relational_interpreter_mixed_original import (
    _pe32_predecessor_bounded_table_image,
    _pe32_register_code_pointer_image,
    _pe32_state_independent_false_edge_image,
    _pe32_static_indirect_image,
    _predecessor_bounded_table_rows,
    _register_code_pointer_rows,
    _state_independent_false_edge_rows,
    _static_indirect_rows,
)
from test_stage_a_mixed_original_register_control_provenance import (
    _import_crossing_image,
    _import_crossing_rows,
)

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
    _lean_relocations,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    InterpreterMixedOriginalSpec,
    OriginalIATImport,
    OriginalImportIdentity,
    OriginalModuleBindings,
    OriginalPERecoveryInput,
    OriginalRegisterControlCallContractProposal,
    QualifiedLeanSymbol,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = RELATIONAL_APPROVED_AXIOMS


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
class StageARelationalInterpreterMixedOriginalKernelTests(unittest.TestCase):
    def test_state_independent_false_edge_is_exactly_redecoded_in_kernel(
        self,
    ) -> None:
        results: dict[bool, dict[str, object]] = {}
        for exact_guard_false in (True, False):
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
                    "RelationalInterpreterOriginalCarrierBinding",
                )
                pe_path = root / "false-edge.exe"
                pe_bytes = _pe32_state_independent_false_edge_image(
                    exact_guard_false=exact_guard_false
                )
                pe_path.write_bytes(pe_bytes)
                binary = _parse_stage_a_pe(pe_path)
                try:
                    original_module = _TINY_ORIGINAL.format(
                        byte_tree=_lean_byte_tree_definitions(
                            "originalBytes", pe_bytes
                        ),
                        pe_literal=_lean_pe(binary, "originalBytes"),
                        imports_literal=_lean_import_certificate(binary),
                        relocations_literal=_lean_relocations(binary),
                    )
                finally:
                    binary.pe.close()
                (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                    original_module, encoding="utf-8"
                )
                state_machine = root / "state-machine.jsonl"
                state_machine.write_text(
                    "".join(
                        json.dumps(row) + "\n"
                        for row in _state_independent_false_edge_rows()
                    ),
                    encoding="utf-8",
                )
                spec = InterpreterMixedOriginalSpec(
                    bindings=OriginalModuleBindings(
                        module="StageA.GeneratedTinyOriginalPE",
                        namespace="StageA.GeneratedRelational.TinyOriginalPE",
                    ),
                    entry_rva=0x1000,
                    recovery_pe=OriginalPERecoveryInput(
                        pe_path, hashlib.sha256(pe_bytes).hexdigest()
                    ),
                )
                plan = plan_interpreter_mixed_original(state_machine, spec)
                self.assertTrue(plan.complete, plan.blockers)
                self.assertEqual(
                    len(plan.state_independent_false_edge_cuts), 1
                )
                write_relational_interpreter_mixed_original(root, plan)
                (stage_a / "GeneratedMixedOriginalFalseEdgeAudit.lean").write_text(
                    _FALSE_EDGE_AUDIT, encoding="utf-8"
                )
                results[exact_guard_false] = _run_lean_relational(
                    root, bundle="GeneratedMixedOriginalFalseEdgeAudit"
                )

        accepted = results[True]
        self.assertEqual(accepted["status"], "checked", accepted)
        output = str(accepted["stdout"]) + str(accepted["stderr"])
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        self.assertIn(
            "generatedOriginalStateIndependentFalseEdgeCut0Impossible", output
        )
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 2, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

        rejected = results[False]
        self.assertEqual(rejected["status"], "failed", rejected)

    def test_tiny_generated_authority_launch_and_reachability_compile(self) -> None:
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
                "RelationalInterpreterOriginalCarrierBinding",
            )
            pe_path = root / "tiny.exe"
            iat_rva = 0x2040
            iat_va = 0x400000 + iat_rva
            pe_bytes = pe32_import_image(
                b"\xff\x15" + iat_va.to_bytes(4, "little")
                + b"\x90\x90\x90\xc3",
                symbol="TestImport",
            )
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                original_module = _TINY_ORIGINAL.format(
                    byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
                entry_rva = binary.entrypoint_rva
            finally:
                binary.pe.close()
            (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                original_module, encoding="utf-8"
            )
            (stage_a / "GeneratedTinyMachineContracts.lean").write_text(
                _TINY_MACHINE_CONTRACTS, encoding="utf-8"
            )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(
                    json.dumps(row) + "\n"
                    for row in (
                        {
                            "original": {
                                "rva_start": entry_rva,
                                "rva_end": entry_rva + 6,
                                "size": 6,
                            },
                            "outcome": {
                                "kind": "fallthrough",
                                "target_rva": entry_rva + 6,
                            },
                            "edge_conditions": [
                                {
                                    "target_rva": entry_rva + 6,
                                    "condition": {"op": "true"},
                                }
                            ],
                            "ordered_events": [
                                {
                                    "kind": "indirect_call",
                                    "instruction_rva": entry_rva,
                                    "return_rva": entry_rva + 6,
                                    "target": {
                                        "op": "load",
                                        "width": 4,
                                        "address": {
                                            "op": "const",
                                            "width": 32,
                                            "value": iat_va,
                                        },
                                    },
                                }
                            ],
                            "external_events": [],
                        },
                        {
                            "original": {
                                "rva_start": entry_rva + 9,
                                "rva_end": entry_rva + 10,
                                "size": 1,
                            },
                            "outcome": {"kind": "return"},
                            "edge_conditions": [],
                            "ordered_events": [],
                            "external_events": [],
                        },
                    )
                ),
                encoding="utf-8",
            )
            spec = InterpreterMixedOriginalSpec(
                bindings=OriginalModuleBindings(
                    module="StageA.GeneratedTinyOriginalPE",
                    namespace="StageA.GeneratedRelational.TinyOriginalPE",
                    machine_import_call_contracts=QualifiedLeanSymbol(
                        module="StageA.GeneratedTinyMachineContracts",
                        namespace=(
                            "StageA.GeneratedRelational.TinyMachineContracts"
                        ),
                        symbol="contracts",
                    ),
                ),
                entry_rva=entry_rva,
                iat_imports=(
                    OriginalIATImport(
                        iat_va=iat_va,
                        iat_rva=iat_rva,
                        identity=OriginalImportIdentity(
                            "KERNEL32.dll", "TestImport"
                        ),
                    ),
                ),
                recovery_pe=OriginalPERecoveryInput(
                    pe_path, hashlib.sha256(pe_bytes).hexdigest()
                ),
            )
            plan = plan_interpreter_mixed_original(state_machine, spec)
            self.assertTrue(plan.complete, plan.blockers)
            self.assertEqual(plan.regions[1].alias_rvas, (entry_rva + 6,))
            write_relational_interpreter_mixed_original(root, plan)
            (stage_a / "GeneratedMixedOriginalAudit.lean").write_text(
                _AUDIT, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedMixedOriginalAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        self.assertIn("generatedExactOriginalDecodedAuthority", output)
        self.assertIn("generatedExactOriginalDecodedReachability", output)
        self.assertIn("generatedOriginalLaunchFrameCountChecked", output)
        self.assertIn("generatedOriginalIATCallSiteBindingsChecked", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_static_indirect_bindings_are_checked_from_exact_pe_semantics(self) -> None:
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
                "RelationalInterpreterOriginalCarrierBinding",
            )
            pe_path = root / "static-indirect.exe"
            pe_bytes = _pe32_static_indirect_image()
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                original_module = _TINY_ORIGINAL.format(
                    byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
                entry_rva = binary.entrypoint_rva
            finally:
                binary.pe.close()
            (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                original_module, encoding="utf-8"
            )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(json.dumps(row) + "\n" for row in _static_indirect_rows()),
                encoding="utf-8",
            )
            spec = InterpreterMixedOriginalSpec(
                bindings=OriginalModuleBindings(
                    module="StageA.GeneratedTinyOriginalPE",
                    namespace="StageA.GeneratedRelational.TinyOriginalPE",
                ),
                entry_rva=entry_rva,
                recovery_pe=OriginalPERecoveryInput(
                    pe_path, hashlib.sha256(pe_bytes).hexdigest()
                ),
            )
            plan = plan_interpreter_mixed_original(state_machine, spec)
            self.assertTrue(plan.complete, plan.blockers)
            self.assertEqual(plan.reachable_target_ids, (0, 1, 2, 3, 4))
            write_relational_interpreter_mixed_original(root, plan)
            (stage_a / "GeneratedMixedOriginalStaticIndirectAudit.lean").write_text(
                _STATIC_INDIRECT_AUDIT, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedMixedOriginalStaticIndirectAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        self.assertIn("generatedOriginalStaticIndirect0Checked", output)
        self.assertIn("generatedOriginalStaticIndirect1Closed", output)
        self.assertIn("generatedOriginalStaticIndirect2Closed", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 6, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_predecessor_table_bound_is_kernel_checked_from_exact_edge(self) -> None:
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
                "RelationalInterpreterOriginalCarrierBinding",
            )
            pe_path = root / "predecessor-table.exe"
            pe_bytes = _pe32_predecessor_bounded_table_image(rewrite_index=True)
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                original_module = _TINY_ORIGINAL.format(
                    byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
                entry_rva = binary.entrypoint_rva
            finally:
                binary.pe.close()
            (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                original_module, encoding="utf-8"
            )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(
                    json.dumps(row) + "\n"
                    for row in _predecessor_bounded_table_rows(rewrite_index=True)
                ),
                encoding="utf-8",
            )
            spec = InterpreterMixedOriginalSpec(
                bindings=OriginalModuleBindings(
                    module="StageA.GeneratedTinyOriginalPE",
                    namespace="StageA.GeneratedRelational.TinyOriginalPE",
                ),
                entry_rva=entry_rva,
                recovery_pe=OriginalPERecoveryInput(
                    pe_path, hashlib.sha256(pe_bytes).hexdigest()
                ),
            )
            plan = plan_interpreter_mixed_original(state_machine, spec)
            self.assertTrue(plan.complete, plan.blockers)
            write_relational_interpreter_mixed_original(root, plan)
            (stage_a / "GeneratedMixedOriginalPredecessorAudit.lean").write_text(
                _PREDECESSOR_TABLE_AUDIT, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedMixedOriginalPredecessorAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        self.assertIn("Predecessor0BoundClosed", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_register_code_pointer_provenance_is_kernel_checked(self) -> None:
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
                "RelationalInterpreterOriginalCarrierBinding",
            )
            pe_path = root / "register-code-pointer.exe"
            pe_bytes = _pe32_register_code_pointer_image()
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                original_module = _TINY_ORIGINAL.format(
                    byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
                entry_rva = binary.entrypoint_rva
            finally:
                binary.pe.close()
            (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                original_module, encoding="utf-8"
            )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(
                    json.dumps(row) + "\n" for row in _register_code_pointer_rows()
                ),
                encoding="utf-8",
            )
            spec = InterpreterMixedOriginalSpec(
                bindings=OriginalModuleBindings(
                    module="StageA.GeneratedTinyOriginalPE",
                    namespace="StageA.GeneratedRelational.TinyOriginalPE",
                ),
                entry_rva=entry_rva,
                recovery_pe=OriginalPERecoveryInput(
                    pe_path, hashlib.sha256(pe_bytes).hexdigest()
                ),
            )
            plan = plan_interpreter_mixed_original(state_machine, spec)
            self.assertTrue(plan.complete, plan.blockers)
            write_relational_interpreter_mixed_original(root, plan)
            (stage_a / "GeneratedMixedOriginalRegisterAudit.lean").write_text(
                _REGISTER_PROVENANCE_AUDIT, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedMixedOriginalRegisterAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        self.assertIn("generatedOriginalStaticIndirect0Seed0Checked", output)
        self.assertIn("generatedOriginalStaticIndirect0Preserve0Checked", output)
        self.assertIn("generatedOriginalStaticIndirect0Edge1Checked", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 8, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_import_register_survives_checked_call_return_in_kernel(self) -> None:
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
                "RelationalInterpreterOriginalCarrierBinding",
            )
            pe_path = root / "register-import-crossing.exe"
            pe_bytes = _import_crossing_image()
            pe_path.write_bytes(pe_bytes)
            binary = _parse_stage_a_pe(pe_path)
            try:
                original_module = _TINY_ORIGINAL.format(
                    byte_tree=_lean_byte_tree_definitions("originalBytes", pe_bytes),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
                entry_rva = binary.entrypoint_rva
            finally:
                binary.pe.close()
            (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                original_module, encoding="utf-8"
            )
            (stage_a / "GeneratedTinyMachineContracts.lean").write_text(
                _TINY_MACHINE_CONTRACTS, encoding="utf-8"
            )
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(
                "".join(json.dumps(row) + "\n" for row in _import_crossing_rows()),
                encoding="utf-8",
            )
            identity = OriginalImportIdentity("KERNEL32.dll", "TestImport")
            spec = InterpreterMixedOriginalSpec(
                bindings=OriginalModuleBindings(
                    module="StageA.GeneratedTinyOriginalPE",
                    namespace="StageA.GeneratedRelational.TinyOriginalPE",
                    machine_import_call_contracts=QualifiedLeanSymbol(
                        module="StageA.GeneratedTinyMachineContracts",
                        namespace=(
                            "StageA.GeneratedRelational.TinyMachineContracts"
                        ),
                        symbol="contracts",
                    ),
                ),
                entry_rva=entry_rva,
                iat_imports=(OriginalIATImport(
                    iat_va=0x402040,
                    iat_rva=0x2040,
                    identity=identity,
                ),),
                recovery_pe=OriginalPERecoveryInput(
                    pe_path, hashlib.sha256(pe_bytes).hexdigest()
                ),
                register_control_call_contracts=(
                    OriginalRegisterControlCallContractProposal(
                        contract_id=7,
                        source_rva=0x1000,
                        instruction_rva=0x1006,
                        continuation_rva=0x1008,
                        preserved_registers=("ebx", "esi", "edi", "ebp"),
                        import_identity=identity,
                        return_register="eax",
                        machine_contract_id=0,
                        arity_kind="fixed",
                        argument_words=0,
                    ),
                ),
            )
            plan = plan_interpreter_mixed_original(state_machine, spec)
            self.assertTrue(plan.complete, plan.blockers)
            write_relational_interpreter_mixed_original(root, plan)
            (stage_a / "GeneratedMixedOriginalImportRegisterAudit.lean").write_text(
                _IMPORT_REGISTER_PROVENANCE_AUDIT, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedMixedOriginalImportRegisterAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("_native.native_decide", output)
        self.assertIn("generatedOriginalStaticIndirect0Seed0Closed", output)
        self.assertIn("generatedOriginalStaticIndirect0Edge0Checked", output)
        self.assertIn("generatedOriginalStaticIndirect0Closed", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 5, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_TINY_ORIGINAL = r"""import StageA.RelationalInterpreterMixedOriginal

namespace StageA.GeneratedRelational.TinyOriginalPE

open StageA.Formal StageA.Relational

set_option maxRecDepth 1000000

{byte_tree}

def originalPe : PE32 :=
  {pe_literal}

def originalImportCertificate : ImportTableCertificate :=
  {imports_literal}

def originalRelocations : List BaseRelocation :=
  {relocations_literal}

theorem originalParsed : parsePE32Tree originalPe.bytes = some originalPe := by
  decide +kernel

theorem originalImportsChecked :
    importTableValid originalPe originalImportCertificate = true := by
  decide +kernel

theorem originalRelocationsParsed :
    parseRelocations originalPe = some originalRelocations := by
  decide +kernel

end StageA.GeneratedRelational.TinyOriginalPE
"""


_TINY_MACHINE_CONTRACTS = r"""import StageA.RelationalDecode

namespace StageA.GeneratedRelational.TinyMachineContracts

open StageA.Relational

def testImport : MachineImportCallContract := {
  id := 0
  imported := {
    dll := [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108]
    name := .symbol [84, 101, 115, 116, 73, 109, 112, 111, 114, 116]
  }
  stackArgumentOffsets := []
  stackResultDelta := 0
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax, .ecx, .edx]
  disposition := .returns
  memoryEffect := .none
  worldEffect := .none
}

def contracts : List MachineImportCallContract := [testImport]

end StageA.GeneratedRelational.TinyMachineContracts
"""


_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedOriginal

open StageA.GeneratedRelational.InterpreterMixedOriginal

#print axioms generatedExactOriginalDecodedAuthority
#print axioms generatedExactOriginalCodeMapCertificate
#print axioms generatedDirectExactOriginalDecodedLaunchRoot
#print axioms generatedExactOriginalDecodedReachability
#print axioms generatedOriginalStateMachineImportsBound
#print axioms generatedOriginalMachineContractsCoverImports
#print axioms generatedOriginalLaunchFrameCountChecked
#print axioms generatedOriginalIATCallSiteBindingsChecked
"""


_FALSE_EDGE_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedOriginal

open StageA.GeneratedRelational.InterpreterMixedOriginal

#print axioms generatedOriginalStateIndependentFalseEdgeCut0Checked
#print axioms generatedOriginalStateIndependentFalseEdgeCut0Impossible
"""


_STATIC_INDIRECT_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedOriginal

open StageA.GeneratedRelational.InterpreterMixedOriginal

#print axioms generatedExactOriginalDecodedAuthority
#print axioms generatedExactOriginalDecodedReachability
#print axioms generatedOriginalStaticIndirect0IndexUniversallyBounded
#print axioms generatedOriginalStaticIndirect0Checked
#print axioms generatedOriginalStaticIndirect1Checked
#print axioms generatedOriginalStaticIndirect1Closed
#print axioms generatedOriginalStaticIndirect2Checked
#print axioms generatedOriginalStaticIndirect2RelocationChecked
#print axioms generatedOriginalStaticIndirect2BindingChecked
#print axioms generatedOriginalStaticIndirect2Closed
"""


_PREDECESSOR_TABLE_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedOriginal

open StageA.GeneratedRelational.InterpreterMixedOriginal

#print axioms generatedExactOriginalDecodedAuthority
#print axioms generatedExactOriginalDecodedReachability
#print axioms generatedOriginalStaticIndirect0Predecessor0PreconditionComputed
#print axioms generatedOriginalStaticIndirect0Predecessor0BoundClosed
#print axioms generatedOriginalStaticIndirect0Checked
#print axioms generatedOriginalStaticIndirect0Closed
"""


_REGISTER_PROVENANCE_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedOriginal

open StageA.GeneratedRelational.InterpreterMixedOriginal

#print axioms generatedExactOriginalDecodedAuthority
#print axioms generatedExactOriginalDecodedReachability
#print axioms generatedOriginalStaticIndirect0Seed0InventoryChecked
#print axioms generatedOriginalStaticIndirect0Seed0RelocationChecked
#print axioms generatedOriginalStaticIndirect0Seed0Checked
#print axioms generatedOriginalStaticIndirect0Preserve0Checked
#print axioms generatedOriginalStaticIndirect0Edge0Checked
#print axioms generatedOriginalStaticIndirect0Edge1Checked
#print axioms generatedOriginalStaticIndirect0Checked
#print axioms generatedOriginalStaticIndirect0Closed
"""


_IMPORT_REGISTER_PROVENANCE_AUDIT = r"""import StageA.GeneratedRelationalInterpreterMixedOriginal

open StageA.GeneratedRelational.InterpreterMixedOriginal

#print axioms generatedOriginalStaticIndirect0Seed0InventoryChecked
#print axioms generatedOriginalStaticIndirect0Seed0Checked
#print axioms generatedOriginalStaticIndirect0Seed0Closed
#print axioms generatedOriginalStaticIndirect0Edge0Checked
#print axioms generatedOriginalStaticIndirect0Checked
#print axioms generatedOriginalStaticIndirect0Closed
"""


if __name__ == "__main__":
    unittest.main()
