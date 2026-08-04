from __future__ import annotations

import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_target import (
    x87_replay_bridge_target_lean_sources,
)
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_runtime import (
    X87_REPLAY_FIXED_TEMPLATE_AUTHORIZING_THEOREM,
    X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE,
    X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES,
    X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS,
    X87ReplayBridgeRuntimeGenerationError,
    X87ReplayBridgeRuntimePlan,
    X87ReplayRelocatedOperandPlan,
    X87ReplayRuntimeTargetPlan,
    _runtime_target,
    x87_replay_bridge_runtime_lean_sources,
)
from tests.test_stage_a_relational_interpreter_x87_replay_bridge_target_kernel import (
    _copy_module_closure,
    _synthetic_candidate_data_base_source,
    _synthetic_candidate_relocations_source,
    _synthetic_generated_plan,
)


_IMAGE_BASE = 0x400000
_BRIDGE_RVA = 0x2000
_INSTRUCTION_RVA = _BRIDGE_RVA + 52


class _FakePE:
    def __init__(self, chunks: dict[int, bytes]) -> None:
        self._chunks = chunks

    def get_data(self, rva: int, size: int) -> bytes:
        for start, data in self._chunks.items():
            offset = rva - start
            if 0 <= offset and offset + size <= len(data):
                return data[offset : offset + size]
        return b""


def _bridge_body(instruction: bytes) -> bytes:
    body = bytearray(176)
    body[0:5] = b"\x55\x53\x56\x57\xa1"
    body[9:52] = bytes.fromhex(
        "89600cdd60148b40048b58048b48088b70108b78148b68188b601c"
        "ffb0f0000000ff308b500c589d909090"
    )
    body[52 : 52 + len(instruction)] = instruction
    body[52 + len(instruction) : 72] = b"\x90" * (20 - len(instruction))
    body[72:75] = b"\x9c\x50\xa1"
    body[79:176] = bytes.fromhex(
        "ddb0800000008b50088b0c24890a0f9242200f9a42300f9442240f984228"
        "0f90422c8b5c24048b48048b89f000000081e12af3ffff81e3d50c000009"
        "d9898af0000000"
        "90909090909090909090"
        "c74010000000008b600cfc5f5e5b5dc390909090"
    )
    return bytes(body)


def _runtime_inputs(
    *, relocated: bool = True
) -> tuple[SimpleNamespace, dict[int, int], dict, dict, dict]:
    instruction = bytearray(b"\xd8\x25\x00\x00\x00\x00")
    target_rva = 0x3900
    struct.pack_into("<I", instruction, 2, _IMAGE_BASE + target_rva)
    binary = SimpleNamespace(
        image_base=_IMAGE_BASE,
        pe=_FakePE({_INSTRUCTION_RVA: bytes(instruction)}),
    )
    descriptor = {
        "id": 0,
        "descriptor_rva": 0x3000,
        "bridge_target_rva": _BRIDGE_RVA,
        "instruction_bytes": bytes(instruction).hex(),
    }
    mapping = {
        "descriptor_id": 0,
        "bridge_target_rva": _BRIDGE_RVA,
        "instruction_rva": _INSTRUCTION_RVA,
        "instruction_path_bytes": bytes(instruction).hex(),
        "bridge_body_bytes": _bridge_body(bytes(instruction)).hex(),
    }
    replay = {
        "format": "stage-b-native-exact-x87-command-replay-program-v1",
        "id": 0,
        "image_base": _IMAGE_BASE,
        "rva_start": 0x7000,
        "instruction_bytes": bytes(instruction).hex(),
        "base_relocation": None,
    }
    relocation_counts: dict[int, int] = {}
    if relocated:
        replay["base_relocation"] = {
            "kind": "highlow",
            "type": 3,
            "width": 4,
            "operand_byte_offset": 2,
            "source_rva": 0x7002,
            "target_rva": target_rva,
        }
        relocation_counts[_INSTRUCTION_RVA + 2] = 1
    return binary, relocation_counts, descriptor, mapping, replay


def _synthetic_runtime_sources() -> tuple[
    bytes,
    int,
    dict[str, str],
    dict[str, str],
    str,
]:
    image, target_plan = _synthetic_generated_plan()
    mapping = target_plan.table.frame_mappings[0]
    image_bytes = bytearray(image)
    descriptor = target_plan.table.descriptors[0]
    runtime_plan = X87ReplayBridgeRuntimePlan(
        candidate_path=Path("synthetic.exe"),
        candidate_sha256=target_plan.candidate_sha256,
        candidate_size=len(image_bytes),
        target_plan_sha256="22" * 32,
        native_engine_plan_sha256="33" * 32,
        targets=(
            X87ReplayRuntimeTargetPlan(
                descriptor_id=descriptor.id,
                descriptor_rva=descriptor.descriptor_rva,
                bridge_target_rva=descriptor.bridge_target_rva,
                instruction_rva=mapping.instruction_rva,
                instruction_bytes=descriptor.instruction_bytes,
                operand=None,
            ),
        ),
    )
    target_sources = x87_replay_bridge_target_lean_sources(
        target_plan,
        candidate_data_module="SyntheticX87ReplayCandidateDataBase",
        relocation_data_module="SyntheticX87ReplayCandidateRelocations",
        pack_size=1,
    )
    runtime_sources = x87_replay_bridge_runtime_lean_sources(
        runtime_plan,
        pack_size=1,
    )
    candidate_replay = """import StageA.SyntheticX87ReplayCandidateDataBase
import StageA.RelationalInterpreterX87

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterX87

def originalPe : PE32 :=
  InterpreterKernelData.generatedInterpreterKernelCandidatePe

namespace CandidateX87Replay

def checkedInterpreterX87CandidateReplayBundleHandler : CandidateReplayHandler :=
  reviewedExpectedCandidateReplay originalPe

def checkedInterpreterX87CandidateReplayBundleExactInventory : True :=
  True.intro

end CandidateX87Replay
end StageA.GeneratedRelational
"""
    return (
        bytes(image_bytes),
        mapping.instruction_rva,
        target_sources,
        runtime_sources,
        candidate_replay,
    )


def _check_synthetic_runtime_bundle(
    image: bytes,
    target_sources: dict[str, str],
    runtime_sources: dict[str, str],
    candidate_replay: str,
) -> dict:
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
            "RelationalInterpreterKernelX87Execution",
        )
        (stage_a / "SyntheticX87ReplayCandidateDataBase.lean").write_text(
            _synthetic_candidate_data_base_source(image),
            encoding="ascii",
        )
        (stage_a / "SyntheticX87ReplayCandidateRelocations.lean").write_text(
            _synthetic_candidate_relocations_source(),
            encoding="ascii",
        )
        (
            stage_a / "GeneratedInterpreterX87CandidateReplayBundle.lean"
        ).write_text(candidate_replay, encoding="ascii")
        for filename, source in target_sources.items():
            (stage_a / filename).write_text(source, encoding="utf-8")
        for filename, source in runtime_sources.items():
            (stage_a / filename).write_text(source, encoding="ascii")
        return _run_lean_relational(
            root,
            bundle="GeneratedRelationalInterpreterX87ReplayBridgeRuntime",
        )


class StageAX87ReplayBridgeRuntimeTests(unittest.TestCase):
    def test_exact_relocated_operand_is_bound(self) -> None:
        binary, relocations, descriptor, mapping, replay = _runtime_inputs()
        target = _runtime_target(
            binary=binary,
            relocation_counts=relocations,
            descriptor=descriptor,
            mapping=mapping,
            replay=replay,
            expected_id=0,
        )

        self.assertIsNotNone(target.operand)
        assert target.operand is not None
        self.assertEqual(target.operand.candidate_operand_rva, _INSTRUCTION_RVA + 2)

    def test_missing_relocation_fails_closed_at_operand(self) -> None:
        binary, _, descriptor, mapping, replay = _runtime_inputs()
        with self.assertRaisesRegex(
            X87ReplayBridgeRuntimeGenerationError,
            "candidate relocation is not exact",
        ):
            _runtime_target(
                binary=binary,
                relocation_counts={},
                descriptor=descriptor,
                mapping=mapping,
                replay=replay,
                expected_id=0,
            )

    def test_unbound_relocation_fails_closed(self) -> None:
        binary, _, descriptor, mapping, replay = _runtime_inputs(relocated=False)
        with self.assertRaisesRegex(
            X87ReplayBridgeRuntimeGenerationError,
            "unbound candidate relocation",
        ):
            _runtime_target(
                binary=binary,
                relocation_counts={_INSTRUCTION_RVA + 2: 1},
                descriptor=descriptor,
                mapping=mapping,
                replay=replay,
                expected_id=0,
            )

    def test_ambiguous_relocation_fails_closed(self) -> None:
        binary, _, descriptor, mapping, replay = _runtime_inputs()
        with self.assertRaisesRegex(
            X87ReplayBridgeRuntimeGenerationError,
            "candidate relocation is not exact",
        ):
            _runtime_target(
                binary=binary,
                relocation_counts={_INSTRUCTION_RVA + 2: 2},
                descriptor=descriptor,
                mapping=mapping,
                replay=replay,
                expected_id=0,
            )

    def test_malformed_bridge_template_fails_closed(self) -> None:
        binary, relocations, descriptor, mapping, replay = _runtime_inputs()
        body = bytearray.fromhex(mapping["bridge_body_bytes"])
        body[9] = 0x85
        mapping["bridge_body_bytes"] = bytes(body).hex()
        with self.assertRaisesRegex(
            X87ReplayBridgeRuntimeGenerationError,
            "bridge template is not exact",
        ):
            _runtime_target(
                binary=binary,
                relocation_counts=relocations,
                descriptor=descriptor,
                mapping=mapping,
                replay=replay,
                expected_id=0,
            )

    def test_generated_inventory_is_compact_and_lean_checked(self) -> None:
        targets = []
        for descriptor_id in range(313):
            operand = None
            if descriptor_id < 23:
                operand = X87ReplayRelocatedOperandPlan(
                    descriptor_id=descriptor_id,
                    byte_offset=2,
                    original_operand_rva=0x7002 + descriptor_id * 8,
                    candidate_operand_rva=0x8002 + descriptor_id * 8,
                    target_rva=0x9000 + descriptor_id * 4,
                )
            targets.append(
                X87ReplayRuntimeTargetPlan(
                    descriptor_id=descriptor_id,
                    descriptor_rva=0xA000 + descriptor_id * 36,
                    bridge_target_rva=0x10000 + descriptor_id * 176,
                    instruction_rva=0x30000 + descriptor_id * 16,
                    instruction_bytes=b"\xd9\xe8",
                    operand=operand,
                )
            )
        plan = X87ReplayBridgeRuntimePlan(
            candidate_path=Path("candidate.exe"),
            candidate_sha256="11" * 32,
            candidate_size=1234,
            target_plan_sha256="22" * 32,
            native_engine_plan_sha256="33" * 32,
            targets=tuple(targets),
        )

        sources = x87_replay_bridge_runtime_lean_sources(plan, pack_size=32)
        text = "\n".join(sources.values())
        for source in sources.values():
            source.encode("ascii")
        bundle = sources[
            "GeneratedRelationalInterpreterX87ReplayBridgeRuntime.lean"
        ]

        self.assertEqual(len(sources), 11)
        self.assertLess(len(bundle), 250_000)
        self.assertEqual(text.count("operandChecked := by decide +kernel"), 313)
        self.assertEqual(text.count("layoutChecked := by decide +kernel"), 313)
        self.assertEqual(
            text.count(
                "def generatedX87ReplayBridgeFixedTemplateStaticExecution"
            ),
            313,
        )
        self.assertEqual(
            text.count(
                "exactNativeX87ReplayFixedTemplateStaticExecutionOfIsSome"
            ),
            313,
        )
        self.assertIn(
            "def generatedX87ReplayBridgeFixedTemplateStaticInventory", bundle
        )
        self.assertNotIn(
            "GeneratedX87ReplayBridgeFixedTemplateTargetCheck", text
        )
        self.assertNotIn(
            "GeneratedX87ReplayBridgeFixedTemplateCheckPack", text
        )
        self.assertNotIn("executeIsSome", text)
        self.assertNotIn(
            "forall source : ExactNativeX87ReplaySourceFrame", text
        )
        self.assertEqual(text.count(".relocated {"), 23)
        self.assertIn("relocatedOperandCount := 23", bundle)
        self.assertIn("relocatedOperandsExact := by decide +kernel", bundle)
        self.assertEqual(
            text.count("theorem generatedX87ReplayBridgeRunForSourceFrame"), 1
        )
        self.assertEqual(
            text.count("theorem generatedX87ReplayBridgeSourceFrameEntails"), 1
        )
        self.assertEqual(
            text.count("def GeneratedX87ReplayBridgeKernelExecutionGoal"), 1
        )
        self.assertEqual(
            text.count(
                "theorem generatedX87ReplayBridgeKernelExecution\n"
            ),
            1,
        )
        self.assertEqual(
            text.count(
                "theorem generatedX87ReplayBridgeKernelExecutionClosed"
            ),
            1,
        )
        self.assertEqual(
            text.count(
                "def GeneratedX87ReplayBridgeFixedTemplateChecks\n"
            ),
            1,
        )
        self.assertEqual(
            text.count("def generatedX87ReplayBridgeFixedTemplateExecutor"), 1
        )
        # The only finite elimination builds the static decode inventory.
        self.assertEqual(bundle.count("List.mem_cons.mp member"), 313)
        self.assertNotIn("pack0000 :", bundle)
        self.assertNotIn("pack0009 :", bundle)
        self.assertIn(
            "staticInventory := "
            "generatedX87ReplayBridgeFixedTemplateStaticInventory",
            bundle,
        )
        self.assertIn(
            "theorem generatedX87ReplayBridgeTemplateExecutionClosed",
            bundle,
        )
        self.assertIn(
            "generatedX87ReplayBridgeFixedTemplateExecutor carrier checked",
            bundle,
        )
        self.assertIn(
            "(checked : GeneratedX87ReplayBridgeFixedTemplateChecksGoal carrier)",
            bundle,
        )
        self.assertIn(
            "import StageA.RelationalInterpreterKernelX87Execution", bundle
        )
        for filename, source in sources.items():
            if "RuntimePack" in filename:
                self.assertIn(
                    "import StageA.RelationalInterpreterKernelX87Execution",
                    source,
                )
        self.assertIn(
            "import StageA.GeneratedInterpreterX87CandidateReplayBundle", bundle
        )
        self.assertIn(
            "generatedX87ReplayBridgeHandlerInventoryCorrespondence", bundle
        )
        self.assertIn(
            "generatedX87ReplayBridgeHandlerMatchesSemanticInventory", bundle
        )
        self.assertIn("generatedX87ReplayBridgeSemanticInventory", bundle)
        self.assertIn("GeneratedX87ReplayBridgeSourceFrameGoal", bundle)
        self.assertNotIn("sourceInvariant", bundle)
        self.assertNotIn("RuntimeGoal program", bundle)
        self.assertNotIn("staticCertificate :=", bundle)
        self.assertNotIn('"status"', text)

        payload = plan.payload()
        self.assertEqual(payload["status"], "complete")
        self.assertEqual(
            payload["diagnostic_status"], "kernel_execution_closed"
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertTrue(payload["static_evidence"])
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES),
        )
        self.assertEqual(
            payload["assumed_source_frame_fields"],
            list(X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS),
        )
        self.assertEqual(
            payload["remaining_program_binding_fields"],
            list(X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES),
        )
        self.assertEqual(
            payload["remaining_fixed_template_fields"],
            list(X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES),
        )
        self.assertEqual(payload["remaining_program_binding_fields"], [])
        self.assertEqual(payload["remaining_fixed_template_fields"], [])
        self.assertEqual(
            payload["remaining_executor_fields"],
            list(X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES),
        )
        self.assertEqual(payload["remaining_proof_premises"], [])
        self.assertEqual(payload["remaining_executor_fields"], [])
        self.assertEqual(
            payload["checked_execution_type"],
            X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE,
        )
        self.assertTrue(payload["checked_bundle_inhabited"])
        self.assertEqual(
            payload["x87_semantics_profile"],
            "arbitrary-shared-deterministic-stage-a-x87-semantics",
        )
        self.assertEqual(
            payload["fault_profile"],
            "checked-fault-free-singleton",
        )
        self.assertIn(
            "non-x87-fields+memory-effects+physical-x87-frame",
            payload["post_state_contract"],
        )
        self.assertEqual(
            payload["authorizing_theorem"],
            X87_REPLAY_FIXED_TEMPLATE_AUTHORIZING_THEOREM,
        )
        self.assertEqual(payload["authorizing_theorem_premises"], [])
        self.assertTrue(payload["checked_bundle_inhabited"])
        self.assertEqual(len(payload["required_checked_target_terms"]), 313)
        self.assertTrue(
            payload["required_checked_target_terms"][0].endswith(
                "FixedTemplateStaticExecution0000"
            )
        )
        self.assertTrue(
            payload["required_checked_target_terms"][-1].endswith(
                "FixedTemplateStaticExecution0312"
            )
        )
        self.assertIn("executeKernelReduction", payload["conditional_theorem"])
        self.assertIn(
            "exactNativeX87ReplayFixedTemplateCertificate_isSome",
            payload["checked_executor"],
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bridge checks")
    def test_generated_runtime_bundle_is_kernel_checked(self) -> None:
        image, _instruction_rva, target_sources, runtime_sources, replay = (
            _synthetic_runtime_sources()
        )
        result = _check_synthetic_runtime_bundle(
            image,
            target_sources,
            runtime_sources,
            replay,
        )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        for theorem in (
            "generatedX87ReplayBridgeFixedTemplateStaticInventory",
            "generatedX87ReplayBridgeFixedTemplateExecutor",
            "generatedX87ReplayBridgeKernelExecution",
            "generatedX87ReplayBridgeKernelExecutionClosed",
            "generatedX87ReplayBridgeTemplateExecution",
            "generatedX87ReplayBridgeTemplateExecutionClosed",
        ):
            self.assertIn(theorem, result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bridge checks")
    def test_corrupted_candidate_execution_cannot_reach_checked_bundle(self) -> None:
        image, instruction_rva, target_sources, runtime_sources, replay = (
            _synthetic_runtime_sources()
        )
        corrupted = bytearray(image)
        corrupted[instruction_rva] ^= 0x01

        result = _check_synthetic_runtime_bundle(
            bytes(corrupted),
            target_sources,
            runtime_sources,
            replay,
        )

        self.assertEqual(result["status"], "failed", result)
        failed = " ".join(result["failed_command"])
        self.assertIn(
            "GeneratedRelationalInterpreterX87ReplayBridgeTargetPack0000.lean",
            failed,
        )
        self.assertNotIn(
            "GeneratedRelationalInterpreterX87ReplayBridgeRuntime.lean",
            failed,
        )
        self.assertIn(
            "Tactic `decide` proved that the proposition", result["stdout"]
        )
        self.assertIn(
            "generatedX87ReplayBridgeFrameMapping0000.checked",
            result["stdout"],
        )
        self.assertIn("is false", result["stdout"])

    def test_runtime_kernel_has_no_unchecked_proof_escape(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterX87ReplayBridgeRuntime.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for field in (
            "exactIndirectCall",
            "eventFreeBridge",
            "eventFreeCallAndBridge",
            "ExactComputedNestedNativeWorldSegment",
            "ExactNativeX87ReplayBridgeKernelReduction",
            "ExactNativeX87ReplayBridgeKernelExecution",
            "ExactNativeX87ReplayBridgeTemplateRun",
            "NativeX87ReplayFixedTemplateSchedule",
            "decodeNativeX87ReplaySchedule?",
            "nativeX87ReplayFixedTemplateSchedule?",
            "nativeX87ReplayOpcodeLead",
            "entryTrampoline",
            "x87Instruction",
            "captureTrampoline",
            "returnToContinuation",
            "returnShape",
            "targetCell",
            "activeFrame",
            "parentFrame",
            "privateStack",
            "x87InputOutput",
            "relocatedOperandsExact",
        ):
            self.assertIn(field, source)
        self.assertNotRegex(source, r"\brunForTarget\s*:")

        generator = (
            root
            / "src/spaghetti_extractor/relational/lean"
            / "interpreter_x87_replay_bridge_runtime.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('target_payload.get("status")', generator)

    def test_source_frame_admission_covers_bridge_aliasing_hazards(self) -> None:
        assumptions = set(X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS)
        self.assertTrue(
            {
                "source_frame.candidateRegisters",
                "source_frame.popFlagsCpl3",
                "source_frame.inputOutputAlias",
                "source_frame.frameAddressNonzero",
                "source_frame.inputX87FrameAddressValid",
                "source_frame.outputX87FrameAddressValid",
                "source_frame.representationDisjointImage",
                "source_frame.frameDisjointImage",
                "source_frame.frameDisjointOperand",
                "source_frame.privateStackPointerNonzero",
                "source_frame.privateStackDisjointFrame",
                "source_frame.privateStackDisjointRepresentation",
                "source_frame.privateStackDisjointOperand",
                "source_frame.privateStackDisjointImage",
                "source_frame.logicalScratchDisjointFrame",
                "source_frame.logicalScratchDisjointPrivateStack",
                "source_frame.logicalScratchDisjointRepresentation",
                "source_frame.logicalScratchDisjointOperand",
                "source_frame.logicalScratchDisjointImage",
                "source_frame.operandDisjointRepresentation",
                "source_frame.operandDisjointRuntimeCells",
            }.issubset(assumptions)
        )

        root = Path(__file__).resolve().parents[1]
        source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterX87ReplayBridgeTarget.lean"
        ).read_text(encoding="utf-8")
        for field in (
            "inputOutputAlias",
            "frameAddressNonzero",
            "inputX87FrameAddressValid",
            "outputX87FrameAddressValid",
            "representationDisjointImage",
            "frameDisjointImage",
            "frameDisjointOperand",
            "privateStackPointerNonzero",
            "privateStackDisjointFrame",
            "privateStackDisjointRepresentation",
            "privateStackDisjointOperand",
            "privateStackDisjointImage",
            "logicalScratchDisjointFrame",
            "logicalScratchDisjointPrivateStack",
            "logicalScratchDisjointRepresentation",
            "logicalScratchDisjointOperand",
            "logicalScratchDisjointImage",
            "operandDisjointRepresentation",
            "operandDisjointRuntimeCells",
        ):
            self.assertRegex(source, rf"\n  {field}\s*:")

        runtime_source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterX87ReplayBridgeRuntime.lean"
        ).read_text(encoding="utf-8")
        self.assertRegex(runtime_source, r"\n  popFlagsCpl3\s*:")
        self.assertIn("cpl3PopFlagsSourceFrameChecked", runtime_source)

    def test_gnu_phase_is_isolated_from_acceptance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lane = (root / "targets/gnu-hello/default.nix").read_text(encoding="utf-8")
        phase = lane[
            lane.index("x87ReplayBridgeRuntimeLean =") :
            lane.index(
                "x87KernelExecutionLean =",
                lane.index("x87ReplayBridgeRuntimeLean ="),
            )
        ]
        self.assertIn("x87-replay-bridge-runtime-sources", phase)
        self.assertIn(".counts.runtime_targets == $targetCount", phase)
        self.assertIn(".counts.relocated_operands > 0", phase)
        self.assertIn('.status == "complete"', phase)
        self.assertIn(
            '.diagnostic_status == "kernel_execution_closed"',
            phase,
        )
        self.assertIn("(.acceptance_authority | not)", phase)
        acceptance = lane[
            lane.index("acceptanceLean =") : lane.index("finalProofSources =")
        ]
        self.assertNotIn("x87ReplayBridgeRuntime", acceptance)


if __name__ == "__main__":
    unittest.main()
