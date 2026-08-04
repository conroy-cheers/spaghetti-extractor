from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_original_execution_evidence import (
    GNU_HELLO_ORIGINAL_EXECUTION_EVIDENCE_FORMAT,
    generate_gnu_hello_original_execution_evidence,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_execution import (
    GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE,
    GnuHelloSourceExecutionGenerationError,
    write_gnu_hello_source_execution_from_artifacts,
)
from spaghetti_extractor.relational.lean.original_execution_evidence import (
    ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
    LeanRef,
    OriginalExecutionEvidenceError,
    OriginalExecutionEvidenceSpec,
    TargetEffect,
    TargetPreservation,
    generate_original_execution_evidence,
)


_FIXTURE_MODULE = "StageA.OriginalExecutionEvidenceFixture"
_FIXTURE_NAMESPACE = "StageA.OriginalExecutionEvidenceFixture"
_STACK_MODULE = "StageA.GeneratedRelationalOriginalStackDynamicControlClosure"
_STACK_NAMESPACE = (
    "StageA.GeneratedRelational.OriginalStackDynamicControlClosure"
)
_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_TARGET_IDS = (7, 8, 9)


def _write(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ref(symbol: str, *, module: str = _FIXTURE_MODULE,
         namespace: str = _FIXTURE_NAMESPACE) -> dict[str, str]:
    return {"module": module, "declaration": f"{namespace}.{symbol}"}


def _fact(symbol: str, *, module: str = _FIXTURE_MODULE,
          namespace: str = _FIXTURE_NAMESPACE) -> dict[str, str]:
    return {"module": module, "namespace": namespace, "symbol": symbol}


def _keys() -> list[tuple[str, int, int]]:
    return sorted(
        [
            *(
                ("writable_static_slot", 0x1000 + index * 4, 7)
                for index in range(19)
            ),
            *(
                ("register_target", 0x2000 + index * 4, 7)
                for index in range(9)
            ),
            *(
                ("stack_dynamic", 0x3000 + index * 4, 7)
                for index in range(3)
            ),
        ]
    )


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


def _as_ref(fact: dict[str, str]) -> dict[str, str]:
    return {
        "module": fact["module"],
        "declaration": f"{fact['namespace']}.{fact['symbol']}",
    }


def _artifacts(root: Path) -> dict[str, Path]:
    state_hash = "1" * 64
    original_hash = "2" * 64
    blockers: list[dict[str, object]] = []
    writable_rows: list[dict[str, object]] = []
    register_rows: list[dict[str, object]] = []
    stack_rows: list[dict[str, object]] = []
    frontiers: list[dict[str, object]] = []
    family_indices = {
        "writable_static_slot": 0,
        "register_target": 0,
        "stack_dynamic": 0,
    }
    for frontier_index, (category, rva, target_id) in enumerate(_keys()):
        family_index = family_indices[category]
        family_indices[category] += 1
        static = _static_fact(category, family_index)
        if category == "writable_static_slot":
            detail = f"static_pointer_slot at 0x{rva:x}: fixture"
            writable_rows.append(
                {
                    "site_id": family_index,
                    "source_rva": rva,
                    "source_target_id": target_id,
                    "authorizing_lean_term": static,
                }
            )
        elif category == "register_target":
            detail = f"register_function_pointer at 0x{rva:x}: fixture"
            register_rows.append(
                {
                    "site_id": family_index,
                    "source_rva": rva,
                    "source_target_id": target_id,
                    "authorizing_lean_term": static,
                }
            )
        else:
            detail = f"stack_or_dynamic_pointer at 0x{rva:x}: fixture"
            stack_rows.append(
                {
                    "source_rva": rva,
                    "source_target_id": target_id,
                    "closure_mode": (
                        "finite_stack_target",
                        "empty_indexed_source",
                        "uninhabited_dynamic_source",
                    )[family_index],
                    "static_authority": "lean_checked",
                }
            )
        blockers.append(
            {
                "reason_code": "unresolved_indirect_control",
                "rva": rva,
                "detail": detail,
            }
        )
        frontiers.append(
            {
                "category": category,
                "source_rva": rva,
                "source_target_id": target_id,
                "static_authority": _as_ref(static),
                "target_membership": _ref(
                    f"targetMembership_{frontier_index}"
                ),
                "running_target_membership": _ref(
                    f"runningTargetMembership_{frontier_index}"
                ),
                "callback_target_membership": _ref(
                    f"callbackTargetMembership_{frontier_index}"
                ),
            }
        )

    plan = _write(
        root / "mixed.json",
        {
            "format": "stage-a-interpreter-mixed-original-v1",
            "state_machine_sha256": state_hash,
            "blockers": blockers,
        },
    )
    writable = _write(
        root / "writable.json",
        {
            "format": (
                "stage-a-relocated-writable-static-pointer-slot-authorities-v2"
            ),
            "inputs": {
                "mixed_original_plan_sha256": _sha(plan),
                "state_machine_sha256": state_hash,
                "original_sha256": original_hash,
            },
            "sites": writable_rows,
        },
    )
    register = _write(
        root / "register.json",
        {
            "format": "stage-a-register-indirect-control-authorities-v1",
            "inputs": {
                "mixed_original_plan_sha256": _sha(plan),
                "writable_slot_report_sha256": _sha(writable),
                "state_machine_sha256": state_hash,
                "original_sha256": original_hash,
            },
            "blockers": [],
            "sites": register_rows,
        },
    )
    stack = _write(
        root / "stack.json",
        {
            "format": "stage-a-original-stack-dynamic-control-closure-v1",
            "inputs": {
                "state_machine_sha256": state_hash,
                "original_pe_sha256": original_hash,
            },
            "sites": stack_rows,
        },
    )
    combined = _write(
        root / "combined.json",
        {
            "format": (
                "stage-a-original-combined-execution-inventory-declarations-v1"
            ),
            "counts": {"reachable_targets": len(_TARGET_IDS)},
            "lean": {
                "module": _FIXTURE_MODULE,
                "inventory": f"{_FIXTURE_NAMESPACE}.inventory",
                "original_context": f"{_FIXTURE_NAMESPACE}.originalContext",
            },
        },
    )
    effects = _write(
        root / "effects.json",
        {
            "format": (
                "stage-a-gnu-hello-source-transition-index-declarations-v1"
            ),
            "targets": [
                {
                    "target_id": target_id,
                    "source_rva": 0x401000 + index * 0x10,
                    "kind": "ordinary",
                    "evidence": {
                        "checked_effect": _ref(f"ordinaryEffect{target_id}")
                    },
                }
                for index, target_id in enumerate(_TARGET_IDS)
            ],
        },
    )
    transition = _write(
        root / "transition.json",
        {
            "format": "stage-a-gnu-hello-source-transition-index-v1",
            "counts": {"targets": len(_TARGET_IDS)},
            "modules": ["GeneratedGnuHelloSourceTransitionIndex"],
            "exports": {
                "concrete_exact_binding": (
                    f"{_FIXTURE_NAMESPACE}.exactBinding"
                ),
                "active_target_transition_index": (
                    f"{_FIXTURE_NAMESPACE}.transitionIndex"
                ),
                "active_target_ids_exact": (
                    f"{_FIXTURE_NAMESPACE}.targetIdsExact"
                ),
            },
        },
    )
    declarations = {
        name: _ref(name)
        for name in (
            "source_program",
            "target_ids_exact",
            "instruction_semantics_adequate",
            "protocol_responses",
            "project",
            "launch_inventory_holds",
            "launch_realizable",
            "compatibility_program_record_kernel_matches",
        )
    }
    authority = _write(
        root / "preservation.json",
        {
            "format": ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
            "namespace": (
                "StageA.GeneratedRelational.GnuHelloOriginalExecutionEvidence"
            ),
            "module_prefix": "GeneratedGnuHelloOriginalExecutionEvidence",
            "shard_size": 2,
            "inputs": {
                "combined_inventory_manifest": _sha(combined),
                "source_target_effect_declarations": _sha(effects),
                "transition_index_manifest": _sha(transition),
            },
            "declarations": declarations,
            "targets": [
                {
                    "target_id": target_id,
                    "certificate": _ref(f"certificate{target_id}"),
                    "preservation_cases": _ref(
                        f"preservationCases{target_id}"
                    ),
                }
                for target_id in _TARGET_IDS
            ],
            "frontiers": frontiers,
        },
    )
    return {
        "combined_inventory_manifest": combined,
        "source_target_effect_declarations": effects,
        "transition_index_manifest": transition,
        "preservation_inputs": authority,
        "mixed_original_plan": plan,
        "writable_authority_report": writable,
        "register_authority_report": register,
        "stack_dynamic_authority_report": stack,
    }


def _generate(root: Path, paths: dict[str, Path]):
    return generate_gnu_hello_original_execution_evidence(
        root / "out", **paths
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


class StageAGnuHelloOriginalExecutionEvidenceTests(unittest.TestCase):
    def test_generic_producer_composes_multiple_provider_shards(self) -> None:
        ref = lambda name: LeanRef(
            _FIXTURE_MODULE, f"{_FIXTURE_NAMESPACE}.{name}"
        )
        targets = tuple(
            TargetPreservation(
                target_id=target_id,
                effect=TargetEffect(
                    kind="ordinary", ordinary_checked=ref(f"effect{target_id}")
                ),
                certificate=ref(f"certificate{target_id}"),
                cases=ref(f"cases{target_id}"),
            )
            for target_id in (1, 2, 3)
        )
        base = ref("base")
        spec = OriginalExecutionEvidenceSpec(
            namespace="StageA.GeneratedRelational.GenericOriginalExecution",
            module_prefix="GeneratedGenericOriginalExecution",
            shard_size=1,
            source_program=base,
            original_context=base,
            inventory=base,
            exact_binding=base,
            transition_index=base,
            target_ids_exact=base,
            instruction_semantics_adequate=base,
            protocol_responses=base,
            project=base,
            launch_inventory_holds=base,
            launch_realizable=base,
            compatibility_program_record_kernel_matches=base,
            targets=targets,
            frontiers=(),
            input_hashes=(("input", "a" * 64),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = generate_original_execution_evidence(temporary, spec)
            index = next(
                path for path in result.modules if path.stem.endswith("TargetIndex")
            ).read_text(encoding="ascii")
            shards = [
                path.read_text(encoding="ascii")
                for path in result.modules
                if "TargetShard" in path.stem
            ]

        self.assertEqual(result.shard_count, 3)
        self.assertIn("generatedShardCertificates0000", index)
        self.assertIn("generatedShardCertificates0001", index)
        self.assertIn("generatedShardCertificates0002", index)
        self.assertIn("List.mem_append", index)
        self.assertEqual(
            sum("def generatedShardCertificates" in shard for shard in shards),
            3,
        )
        with self.assertRaisesRegex(
            OriginalExecutionEvidenceError, "sorted and duplicate-free"
        ):
            replace(spec, targets=(targets[0], targets[0])).validate()

    def test_emits_complete_sharded_proof_and_source_execution_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = _generate(root, _artifacts(root))
            manifest = json.loads(result.manifest.read_text())
            evidence = json.loads(result.source_execution_evidence.read_text())
            sources = "\n".join(
                path.read_text(encoding="ascii") for path in result.proof.modules
            )

        self.assertEqual(
            manifest["format"], GNU_HELLO_ORIGINAL_EXECUTION_EVIDENCE_FORMAT
        )
        self.assertEqual(manifest["counts"]["targets"], len(_TARGET_IDS))
        self.assertEqual(manifest["counts"]["target_shards"], 2)
        self.assertEqual(manifest["counts"]["frontiers"], 31)
        self.assertFalse(manifest["acceptance_authority"])
        self.assertEqual(
            evidence["format"],
            "stage-a-gnu-hello-source-execution-evidence-v2",
        )
        self.assertEqual(len(evidence["frontiers"]), 31)
        self.assertIn("CheckedOriginalTargetPreservationProvider", sources)
        self.assertIn("generatedCombinedTargetStepIndex", sources)
        self.assertIn("generatedAwaitingExternalPreservation", sources)
        self.assertIn("generatedInvariantAtLaunch", sources)
        self.assertIn("generatedCheckedNativeSourceLaunchFamily", sources)
        for forbidden in ("axiom ", "sorry", "admit", "native_decide"):
            self.assertNotIn(forbidden, sources)

    def test_is_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            first = _generate(root, paths)
            first_bytes = {
                path.relative_to(root / "out"): path.read_bytes()
                for path in (
                    *first.proof.modules,
                    first.proof.audit,
                    first.proof.manifest,
                    first.source_execution_evidence,
                    first.manifest,
                )
            }
            second = _generate(root, paths)
            second_bytes = {
                path.relative_to(root / "out"): path.read_bytes()
                for path in (
                    *second.proof.modules,
                    second.proof.audit,
                    second.proof.manifest,
                    second.source_execution_evidence,
                    second.manifest,
                )
            }
        self.assertEqual(first_bytes, second_bytes)

    def test_missing_target_effect_or_preservation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            authority = json.loads(paths["preservation_inputs"].read_text())
            authority["targets"] = []
            _write(paths["preservation_inputs"], authority)
            with self.assertRaisesRegex(
                OriginalExecutionEvidenceError,
                "missing target preservation evidence",
            ):
                _generate(root, paths)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            effects = json.loads(
                paths["source_target_effect_declarations"].read_text()
            )
            effects["targets"][0]["evidence"].pop("checked_effect")
            _write(paths["source_target_effect_declarations"], effects)
            authority = json.loads(paths["preservation_inputs"].read_text())
            authority["inputs"]["source_target_effect_declarations"] = _sha(
                paths["source_target_effect_declarations"]
            )
            _write(paths["preservation_inputs"], authority)
            with self.assertRaisesRegex(
                OriginalExecutionEvidenceError,
                "omits checked effect evidence",
            ):
                _generate(root, paths)

    def test_corrupted_binding_and_external_evidence_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            authority = json.loads(paths["preservation_inputs"].read_text())
            authority["inputs"]["transition_index_manifest"] = "f" * 64
            _write(paths["preservation_inputs"], authority)
            with self.assertRaisesRegex(
                OriginalExecutionEvidenceError,
                "do not bind exact transition_index_manifest",
            ):
                _generate(root, paths)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            authority = json.loads(paths["preservation_inputs"].read_text())
            authority["declarations"].pop("protocol_responses")
            _write(paths["preservation_inputs"], authority)
            with self.assertRaisesRegex(
                OriginalExecutionEvidenceError,
                "preservation declarations fields differ",
            ):
                _generate(root, paths)

    def test_frontier_omission_is_rejected_by_existing_gnu_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            authority = json.loads(paths["preservation_inputs"].read_text())
            authority["frontiers"].pop()
            _write(paths["preservation_inputs"], authority)
            with self.assertRaisesRegex(
                GnuHelloSourceExecutionGenerationError,
                "missing combined-invariant running/callback frontier projections",
            ):
                _generate(root, paths)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_evidence_elaborates_and_audit_exposes_only_fixture_axioms(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = _artifacts(root)
            result = _generate(root, paths)
            stage_a = root / "out/StageA"
            for module in (
                "RelationalNativeSourceLaunchFamily",
                "RelationalOriginalTargetPreservation",
                "RelationalOriginalCombinedAwaitingExternalPreservation",
            ):
                _copy_module_closure(source_root, stage_a, module)
            (stage_a / "OriginalExecutionEvidenceFixture.lean").write_text(
                _fixture_lean(), encoding="ascii"
            )
            (stage_a / "GeneratedGnuHelloSourceTransitionIndex.lean").write_text(
                "import StageA.OriginalExecutionEvidenceFixture\n",
                encoding="ascii",
            )
            (stage_a / "GeneratedRelationalOriginalStackDynamicControlClosure.lean").write_text(
                _stack_fixture_lean(), encoding="ascii"
            )
            compatibility = write_gnu_hello_source_execution_from_artifacts(
                root / "out",
                mixed_original_plan=paths["mixed_original_plan"],
                writable_authority_report=paths["writable_authority_report"],
                register_authority_report=paths["register_authority_report"],
                stack_dynamic_authority_report=paths[
                    "stack_dynamic_authority_report"
                ],
                evidence_manifest=result.source_execution_evidence,
            )
            self.assertTrue(compatibility.launch_family_complete)
            completed = _run_lean_relational(
                root / "out", bundle=GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE
            )

        output = completed["stdout"] + completed["stderr"]
        self.assertEqual(completed["status"], "unchecked_marker", completed)
        self.assertIn("OriginalExecutionEvidenceFixture", output)
        self.assertNotIn("GeneratedGnuHelloOriginalExecutionEvidence.lean:", output)
        self.assertNotIn("GeneratedGnuHelloSourceExecution.lean:", output)
        self.assertNotIn("sorryAx", output)
        self.assertIn("generatedCheckedNativeSourceLaunchFamily", output)

def _fixture_lean() -> str:
    frontier_defs: list[str] = []
    static_defs: list[str] = []
    family_indices = {"writable_static_slot": 0, "register_target": 0}
    for index, (category, _rva, target_id) in enumerate(_keys()):
        if category != "stack_dynamic":
            family = family_indices[category]
            family_indices[category] += 1
            static_defs.append(
                f"axiom staticAuthority_{category}_{family} : Nat"
            )
        frontier_defs.append(
            f"""def targetMembership_{index} (_world : RelationalWorld)
    (_state : MachineState) : Prop := True

theorem runningTargetMembership_{index}
    {{state : MachineState}} {{calls : List Nat}} {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    (_holds : inventory.Holds
      (.running {target_id} state calls eventIndex world)) :
    targetMembership_{index} world state := by
  trivial

theorem callbackTargetMembership_{index}
    {{state : MachineState}} {{calls : List Nat}} {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    {{callbacks : List WorldExternalCallbackRuntime}}
    (_holds : inventory.Holds
      (.callbackRunning {target_id} state calls eventIndex world callbacks)) :
    targetMembership_{index} world state := by
  trivial"""
        )
    target_defs = "\n\n".join(
        f"""axiom targetEquality{target_id} :
  ExactBoundTargetStepEquality exactBinding {target_id}
def certificate{target_id} : ActiveTargetTransitionCertificate exactBinding :=
  ActiveTargetTransitionCertificate.ofExactBound targetEquality{target_id}

axiom ordinaryRecord{target_id} : ProgramRecord
axiom ordinaryPath{target_id} : ExactNormalizedTransferPath
axiom ordinaryTransfer{target_id} : SemanticTransfer
axiom ordinaryRegion{target_id} : RegionRelation
axiom ordinaryBinding{target_id} : ExactOrdinaryTargetBinding ordinaryPe
  source_program {target_id} {0x401000 + index * 0x10}
  ordinaryRecord{target_id} ordinaryPath{target_id} ordinaryTransfer{target_id}
  ordinaryRegion{target_id}
axiom ordinaryDecoded{target_id} :
  ExactDecodedOrdinaryTargetEvaluator ordinaryBinding{target_id}
axiom ordinaryEffect{target_id} :
  CheckedOrdinaryTargetEffect ordinaryBinding{target_id}
    ordinaryDecoded{target_id}

axiom preservationCases{target_id} :
  forall invocation : OriginalTargetInvocation {target_id},
    inventory.Holds invocation.execution ->
      CheckedOriginalTargetPreservationCase originalContext inventory
        (CheckedOriginalTargetEffect.ofOrdinary ordinaryEffect{target_id}
          instruction_semantics_adequate) invocation"""
        for index, target_id in enumerate(_TARGET_IDS)
    )
    certificates = ", ".join(
        f"certificate{target_id}" for target_id in _TARGET_IDS
    )
    return f"""import StageA.RelationalNativeSourceLaunchFamily
import StageA.RelationalOriginalTargetPreservation
import StageA.RelationalOriginalCombinedAwaitingExternalPreservation

namespace {_FIXTURE_NAMESPACE}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting
open StageA.Relational.SourceWorld.ProgramCertificate

noncomputable section

axiom project : NativeSourceProject
abbrev source_program : Program := project.program
abbrev worldProgram : DecodedWorldProgram := source_program.worldProgram
axiom originalContext : OriginalDecodedStaticContext
axiom inventory : OriginalCombinedExecutionInventory worldProgram originalContext
axiom exactBinding : ExactBinding worldProgram.context.originalPe source_program
axiom instruction_semantics_adequate :
  worldProgram.InstructionSemanticsAdequate

axiom ordinaryPe : PE32

{target_defs}

def transitionIndex : ActiveTargetTransitionIndex exactBinding where
  certificates := [{certificates}]
  targetIdsUnique := by
    simp [{certificates}, ActiveTargetTransitionCertificate.ofExactBound]
axiom target_ids_exact :
  transitionIndex.certificates.map (fun item => item.targetId) =
    inventory.reachableTargets.targetIds

axiom protocol_responses : CheckedOriginalCombinedMachineProtocolResponses
  worldProgram originalContext inventory
axiom launch_inventory_holds : forall sourceRoot,
  CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
    inventory.Holds sourceRoot.toWorldExecution
axiom launch_realizable : exists sourceRoot,
  CheckedNativeSourcePE32ConsoleLaunch project sourceRoot
axiom compatibility_program_record_kernel_matches : forall root
    (domain : CheckedExecutionDomain worldProgram root),
  ProgramRecordKernelMatchesDecodedSemantics source_program domain

{chr(10).join(static_defs)}

{chr(10).join(frontier_defs)}

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
