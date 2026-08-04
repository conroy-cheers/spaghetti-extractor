from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_execution import (
    GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE,
    GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT,
    GnuHelloSourceExecutionGenerationError,
    assemble_gnu_hello_source_execution_spec,
    gnu_hello_source_execution_audit_source,
    gnu_hello_source_execution_source,
    write_gnu_hello_source_execution,
    write_gnu_hello_source_execution_from_artifacts,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_FIXTURE_MODULE = "StageA.GnuHelloSourceExecutionFixture"
_FIXTURE_NAMESPACE = "StageA.GnuHelloSourceExecutionFixture"
_STACK_MODULE = "StageA.GeneratedRelationalOriginalStackDynamicControlClosure"
_STACK_NAMESPACE = (
    "StageA.GeneratedRelational.OriginalStackDynamicControlClosure"
)


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fact(symbol: str, *, module: str = _FIXTURE_MODULE,
          namespace: str = _FIXTURE_NAMESPACE) -> dict[str, str]:
    return {"module": module, "namespace": namespace, "symbol": symbol}


def _keys() -> list[tuple[str, int, int]]:
    rows = [
        *(('writable_static_slot', 0x1000 + index * 4, 100 + index)
          for index in range(19)),
        *(('register_target', 0x2000 + index * 4, 200 + index)
          for index in range(9)),
        *(('stack_dynamic', 0x3000 + index * 4, 300 + index)
          for index in range(3)),
    ]
    return sorted(rows)


def _static_fact(category: str, index: int) -> dict[str, str]:
    if category != "stack_dynamic":
        return _fact(f"staticAuthority_{category}_{index}")
    symbols = (
        "generatedOriginalStackDynamicClosure0StackAuthority",
        "generatedOriginalStackDynamicClosure1EmptyIndexedAuthority",
        "generatedOriginalStackDynamicClosure2SiteEvidence",
    )
    return _fact(
        symbols[index], module=_STACK_MODULE, namespace=_STACK_NAMESPACE
    )


def _fixture_artifacts(root: Path) -> dict[str, Path]:
    state_hash = "1" * 64
    original_hash = "2" * 64
    writable_rows = []
    register_rows = []
    stack_rows = []
    blockers = []

    for category, source_rva, target_id in _keys():
        if category == "writable_static_slot":
            local_index = len(writable_rows)
            blockers.append({
                "reason_code": "unresolved_indirect_control",
                "rva": source_rva,
                "detail": f"static_pointer_slot at 0x{source_rva:x}: fixture",
            })
            writable_rows.append({
                "site_id": local_index,
                "source_rva": source_rva,
                "source_target_id": target_id,
                "authorizing_lean_term": _static_fact(category, local_index),
            })
        elif category == "register_target":
            local_index = len(register_rows)
            blockers.append({
                "reason_code": "unresolved_indirect_control",
                "rva": source_rva,
                "detail": f"register_function_pointer at 0x{source_rva:x}: fixture",
            })
            register_rows.append({
                "site_id": local_index,
                "source_rva": source_rva,
                "source_target_id": target_id,
                "authorizing_lean_term": _static_fact(category, local_index),
            })
        else:
            local_index = len(stack_rows)
            modes = (
                "finite_stack_target",
                "empty_indexed_source",
                "uninhabited_dynamic_source",
            )
            blockers.append({
                "reason_code": "unresolved_indirect_control",
                "rva": source_rva,
                "detail": f"stack_or_dynamic_pointer at 0x{source_rva:x}: fixture",
            })
            stack_rows.append({
                "source_rva": source_rva,
                "source_target_id": target_id,
                "closure_mode": modes[local_index],
                "static_authority": "lean_checked",
            })

    plan = _write_json(root / "mixed-original.json", {
        "format": "stage-a-interpreter-mixed-original-v1",
        "state_machine_sha256": state_hash,
        "blockers": blockers,
    })
    writable = _write_json(root / "writable.json", {
        "format": "stage-a-relocated-writable-static-pointer-slot-authorities-v2",
        "inputs": {
            "mixed_original_plan_sha256": _sha(plan),
            "state_machine_sha256": state_hash,
            "original_sha256": original_hash,
        },
        "sites": writable_rows,
    })
    register = _write_json(root / "register.json", {
        "format": "stage-a-register-indirect-control-authorities-v1",
        "inputs": {
            "mixed_original_plan_sha256": _sha(plan),
            "writable_slot_report_sha256": _sha(writable),
            "state_machine_sha256": state_hash,
            "original_sha256": original_hash,
        },
        "blockers": [],
        "sites": register_rows,
    })
    stack = _write_json(root / "stack.json", {
        "format": "stage-a-original-stack-dynamic-control-closure-v1",
        "inputs": {
            "state_machine_sha256": state_hash,
            "original_pe_sha256": original_hash,
        },
        "sites": stack_rows,
    })
    artifact_paths = {
        "mixed_original_plan": plan,
        "writable_authority_report": writable,
        "register_authority_report": register,
        "stack_dynamic_authority_report": stack,
    }
    manifest = {
        "format": GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT,
        "inputs": {name: _sha(path) for name, path in artifact_paths.items()},
        "facts": {
            name: _fact(name)
            for name in (
                "project",
                "combined_invariant",
                "target_ids",
                "target_ids_unique",
                "reachability_projection",
                "target_round_trips",
                "invariant_at_launch",
                "exact_binding",
                "instruction_semantics_adequate",
                "program_record_kernel_matches",
                "launch_realizable",
            )
        },
        "frontiers": [],
    }
    family_indices = {
        "writable_static_slot": 0,
        "register_target": 0,
        "stack_dynamic": 0,
    }
    for frontier_index, (category, source_rva, target_id) in enumerate(_keys()):
        family_index = family_indices[category]
        family_indices[category] += 1
        manifest["frontiers"].append({
            "category": category,
            "source_rva": source_rva,
            "source_target_id": target_id,
            "static_authority": _static_fact(category, family_index),
            "target_membership": _fact(f"targetMembership_{frontier_index}"),
            "running_target_membership": _fact(
                f"runningTargetMembership_{frontier_index}"
            ),
            "callback_target_membership": _fact(
                f"callbackTargetMembership_{frontier_index}"
            ),
        })
    evidence = _write_json(root / "evidence.json", manifest)
    return {**artifact_paths, "evidence_manifest": evidence}


def _assemble(paths: dict[str, Path]):
    return assemble_gnu_hello_source_execution_spec(
        paths["mixed_original_plan"],
        paths["writable_authority_report"],
        paths["register_authority_report"],
        paths["stack_dynamic_authority_report"],
        paths["evidence_manifest"],
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


class StageAGnuHelloSourceExecutionGenerationTests(unittest.TestCase):
    def test_emits_combined_invariant_family_and_all_frontier_projections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec = _assemble(_fixture_artifacts(Path(temporary)))
        source = gnu_hello_source_execution_source(spec)
        audit = gnu_hello_source_execution_audit_source(spec)

        self.assertIn("CheckedOriginalInvariantFamilyEvidence", source)
        self.assertIn("generatedOriginalInvariantFamilyEvidence", source)
        self.assertIn("reachabilityProjection :=", source)
        self.assertIn("generatedOriginalInvariantAtLaunch", source)
        self.assertIn("generatedSourceExecutionDomainAt", source)
        self.assertIn("CheckedNativeSourcePE32ConsoleLaunch", source)
        self.assertIn("generatedCheckedNativeSourceLaunchFamily", source)
        self.assertIn("CheckedNativeSourceLaunchFamily", source)
        self.assertIn("source := fun sourceRoot sourceLaunch =>", source)
        self.assertIn("realizable :=", source)
        self.assertIn("programRecordKernelMatchesDecodedSemantics :=", source)
        self.assertNotIn("generatedOriginalRoot", source)
        self.assertNotIn("CheckedOriginalReachabilityFamilyEvidence", source)
        self.assertNotIn("CheckedOriginalExecutionEvidence", source)
        self.assertNotIn("RootedOriginalWorldExecutionInvariant", source)
        self.assertNotIn("WorldExecution.IsProgramEntry", source)
        self.assertNotIn("entryReachable :=", source)
        self.assertEqual(source.count("RunningTargetMembership\n"), 31)
        self.assertEqual(source.count("CallbackTargetMembership\n"), 31)
        self.assertEqual(audit.count("#print axioms"), 6 + 31 * 2)
        self.assertNotIn("#print axioms", source)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_missing_static_or_one_sided_frontier_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            register = json.loads(paths["register_authority_report"].read_text())
            register["sites"].pop()
            _write_json(paths["register_authority_report"], register)
            with self.assertRaisesRegex(
                GnuHelloSourceExecutionGenerationError,
                "must contain 9 sites",
            ):
                _assemble(paths)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            manifest = json.loads(paths["evidence_manifest"].read_text())
            manifest["frontiers"].pop()
            _write_json(paths["evidence_manifest"], manifest)
            with self.assertRaisesRegex(
                GnuHelloSourceExecutionGenerationError,
                "missing combined-invariant running/callback frontier projections",
            ):
                _assemble(paths)

    def test_incomplete_writer_emits_no_proof_and_names_the_missing_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            manifest = json.loads(paths["evidence_manifest"].read_text())
            manifest["frontiers"] = manifest["frontiers"][:-1]
            _write_json(paths["evidence_manifest"], manifest)
            result = write_gnu_hello_source_execution_from_artifacts(
                root / "out", **paths
            )
            report = json.loads(result.manifest.read_text())

        self.assertFalse(result.launch_family_complete)
        self.assertFalse(report["launch_family_complete"])
        self.assertFalse(report["acceptance_authority"])
        self.assertEqual(
            report["blockers"][0]["reason_code"],
            "source_launch_family_incomplete",
        )
        self.assertIn("combined-invariant", report["blockers"][0]["detail"])
        self.assertIsNone(result.proof)
        self.assertIsNone(result.audit)

    def test_old_entry_reachability_and_rooted_frontier_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            manifest = json.loads(paths["evidence_manifest"].read_text())
            manifest["facts"].pop("combined_invariant")
            manifest["facts"].pop("reachability_projection")
            manifest["facts"].pop("invariant_at_launch")
            manifest["facts"]["entry_reachable"] = _fact("entry_reachable")
            manifest["facts"]["step_closed"] = _fact("step_closed")
            for index, frontier in enumerate(manifest["frontiers"]):
                frontier["rooted_invariant"] = _fact(f"rootedInvariant_{index}")
            _write_json(paths["evidence_manifest"], manifest)
            result = write_gnu_hello_source_execution_from_artifacts(
                root / "out", **paths
            )
            report = json.loads(result.manifest.read_text())

        self.assertFalse(result.launch_family_complete)
        self.assertEqual(
            report["launch_scope"], "all_checked_pe32_console_launches"
        )
        self.assertIn("combined_invariant", report["blockers"][0]["detail"])
        self.assertIn("invariant_at_launch", report["blockers"][0]["detail"])
        self.assertIsNone(result.proof)
        self.assertIsNone(result.audit)

    def test_exact_artifact_hashes_and_authority_terms_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            writable = json.loads(paths["writable_authority_report"].read_text())
            writable["inputs"]["mixed_original_plan_sha256"] = "f" * 64
            _write_json(paths["writable_authority_report"], writable)
            with self.assertRaisesRegex(
                GnuHelloSourceExecutionGenerationError,
                "does not bind the exact mixed-original plan",
            ):
                _assemble(paths)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            manifest = json.loads(paths["evidence_manifest"].read_text())
            manifest["frontiers"][0]["static_authority"] = _fact("wrong")
            _write_json(paths["evidence_manifest"], manifest)
            with self.assertRaisesRegex(
                GnuHelloSourceExecutionGenerationError,
                "static authority must be",
            ):
                _assemble(paths)

    def test_writer_is_byte_reproducible_and_reports_family_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = _assemble(_fixture_artifacts(root))
            first = write_gnu_hello_source_execution(root / "out", spec)
            first_bytes = (
                first.proof.read_bytes(),
                first.audit.read_bytes(),
                first.manifest.read_bytes(),
            )
            second = write_gnu_hello_source_execution(root / "out", spec)
            second_bytes = (
                second.proof.read_bytes(),
                second.audit.read_bytes(),
                second.manifest.read_bytes(),
            )
            report = json.loads(first.manifest.read_text())

        self.assertEqual(first_bytes, second_bytes)
        self.assertTrue(report["launch_family_complete"])
        self.assertEqual(
            report["launch_scope"], "all_checked_pe32_console_launches"
        )
        self.assertFalse(report["acceptance_authority"])
        self.assertEqual(report["counts"]["frontiers"], 31)
        self.assertIn("invariant_family_evidence", report["lean"])
        self.assertIn("launch_family", report["lean"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_launch_family_elaborates_against_kernel(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _fixture_artifacts(root)
            spec = _assemble(paths)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalNativeSource")
            _copy_module_closure(
                source_root, stage_a, "RelationalSourceExecutionDomain"
            )
            (stage_a / "GnuHelloSourceExecutionFixture.lean").write_text(
                _fixture_lean(), encoding="utf-8"
            )
            (stage_a / "GeneratedRelationalOriginalStackDynamicControlClosure.lean").write_text(
                _stack_fixture_lean(), encoding="ascii"
            )
            write_gnu_hello_source_execution(root, spec)
            result = _run_lean_relational(
                root, bundle=GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE
            )

        self.assertEqual(result["status"], "unchecked_marker", result)
        self.assertIn("GnuHelloSourceExecutionFixture.lean", result["stderr"])
        self.assertNotIn("GeneratedGnuHelloSourceExecution.lean", result["stderr"])
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("generatedCheckedNativeSourceLaunchFamily", output)


def _fixture_lean() -> str:
    static = []
    frontier = []
    family_indices = {"writable_static_slot": 0, "register_target": 0}
    for index, (category, _rva, target_id) in enumerate(_keys()):
        if category != "stack_dynamic":
            family = family_indices[category]
            family_indices[category] += 1
            static.append(f"axiom staticAuthority_{category}_{family} : Nat")
        frontier.append(f"""def targetMembership_{index} (_world : RelationalWorld)
    (_state : StageA.Formal.MachineState) : Prop := True

theorem runningTargetMembership_{index}
    {{state : StageA.Formal.MachineState}} {{calls : List Nat}}
    {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    (_holds : combined_invariant.holds
      (.running {target_id} state calls eventIndex world)) :
    targetMembership_{index} world state := by
  trivial

theorem callbackTargetMembership_{index}
    {{state : StageA.Formal.MachineState}} {{calls : List Nat}}
    {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    {{callbacks : List WorldExternalCallbackRuntime}}
    (_holds : combined_invariant.holds
      (.callbackRunning {target_id} state calls eventIndex world callbacks)) :
    targetMembership_{index} world state := by
  trivial""")
    return f"""import StageA.RelationalNativeSource
import StageA.RelationalSourceExecutionDomain

namespace {_FIXTURE_NAMESPACE}

open StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.NativeSource

noncomputable section

axiom project : NativeSourceProject
abbrev program : DecodedWorldProgram := project.program.worldProgram
axiom combined_invariant : OriginalWorldExecutionInvariant program
axiom target_ids : List Nat
axiom target_ids_unique : target_ids.Nodup
axiom reachability_projection : forall execution,
  combined_invariant.holds execution ->
    OriginalExecutionReachable target_ids execution
axiom target_round_trips : forall targetId,
  targetId ∈ target_ids -> exists eip,
    And (program.canonicalRawEip? targetId = some eip)
      (program.resolveRawEip eip = some targetId)
axiom invariant_at_launch : forall sourceRoot,
  CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
    combined_invariant.holds sourceRoot.toWorldExecution
axiom exact_binding :
  ExactBinding program.context.originalPe project.program
axiom instruction_semantics_adequate : program.InstructionSemanticsAdequate
axiom program_record_kernel_matches : forall root
    (domain : CheckedExecutionDomain program root),
  ProgramRecordKernelMatchesDecodedSemantics project.program domain
axiom launch_realizable : exists sourceRoot,
  CheckedNativeSourcePE32ConsoleLaunch project sourceRoot

{chr(10).join(static)}

{chr(10).join(frontier)}

end
end {_FIXTURE_NAMESPACE}
"""


def _stack_fixture_lean() -> str:
    return f"""namespace {_STACK_NAMESPACE}

axiom generatedOriginalStackDynamicClosure0StackAuthority : Nat
axiom generatedOriginalStackDynamicClosure1EmptyIndexedAuthority : Nat
axiom generatedOriginalStackDynamicClosure2SiteEvidence : Nat

end {_STACK_NAMESPACE}
"""


if __name__ == "__main__":
    unittest.main()
