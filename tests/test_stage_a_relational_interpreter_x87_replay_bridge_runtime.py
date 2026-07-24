from __future__ import annotations

import re
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_runtime import (
    X87ReplayBridgeRuntimeGenerationError,
    X87ReplayBridgeRuntimePlan,
    X87ReplayRelocatedOperandPlan,
    X87ReplayRuntimeTargetPlan,
    _runtime_target,
    x87_replay_bridge_runtime_lean_sources,
)


_IMAGE_BASE = 0x400000
_INSTRUCTION_RVA = 0x1200
_BRIDGE_RVA = 0x2000
_FAILURE_RVA = 0x2600


class _FakePE:
    def __init__(self, chunks: dict[int, bytes]) -> None:
        self._chunks = chunks

    def get_data(self, rva: int, size: int) -> bytes:
        for start, data in self._chunks.items():
            offset = rva - start
            if 0 <= offset and offset + size <= len(data):
                return data[offset : offset + size]
        return b""


def _bridge_body() -> bytes:
    body = bytearray(248)
    body[75:77] = b"\x0f\x84"
    struct.pack_into("<i", body, 77, _FAILURE_RVA - (_BRIDGE_RVA + 81))
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
        "instruction_path_bytes": (bytes(instruction) + b"\xe9\0\0\0\0").hex(),
        "bridge_body_bytes": _bridge_body().hex(),
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
        self.assertEqual(target.failure_rva, _FAILURE_RVA)

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
        body[76] = 0x85
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
                    bridge_target_rva=0x10000 + descriptor_id * 248,
                    instruction_rva=0x30000 + descriptor_id * 16,
                    instruction_bytes=b"\xd9\xe8",
                    failure_rva=_FAILURE_RVA,
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
        bundle = sources[
            "GeneratedRelationalInterpreterX87ReplayBridgeRuntime.lean"
        ]

        self.assertEqual(len(sources), 11)
        self.assertEqual(text.count("operandChecked := by decide +kernel"), 313)
        self.assertEqual(text.count("layoutChecked := by decide +kernel"), 313)
        self.assertEqual(text.count(".relocated {"), 23)
        self.assertIn("relocatedOperandCount := 23", bundle)
        self.assertIn("relocatedOperandsExact := by decide +kernel", bundle)
        self.assertEqual(
            text.count("theorem generatedX87ReplayBridgeRuntimeGoals"), 1
        )
        self.assertEqual(
            text.count("theorem generatedX87ReplayBridgeExecutionRefinement"), 1
        )
        self.assertEqual(
            text.count("def GeneratedX87ReplayBridgeKernelExecutionGoal"), 1
        )
        self.assertEqual(
            text.count("theorem generatedX87ReplayBridgeKernelExecution"), 1
        )
        self.assertIn(
            "import StageA.RelationalInterpreterKernelX87Execution", bundle
        )
        self.assertEqual(text.count("RuntimeGoal program"), 1)
        self.assertNotIn('"status"', text)

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

    def test_gnu_phase_is_isolated_from_acceptance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lane = (root / "nix/gnu-hello-roundtrip.nix").read_text(encoding="utf-8")
        phase = lane[
            lane.index("x87ReplayBridgeRuntimeLean =") :
            lane.index("kernelBlockLean =", lane.index("x87ReplayBridgeRuntimeLean ="))
        ]
        self.assertIn("x87-replay-bridge-runtime-sources", phase)
        self.assertIn(".counts.runtime_targets == 313", phase)
        self.assertIn(".counts.relocated_operands == 23", phase)
        self.assertNotIn(".status ==", phase)
        acceptance = lane[
            lane.index("acceptanceLean =") : lane.index("finalProofSources =")
        ]
        self.assertNotIn("x87ReplayBridgeRuntime", acceptance)


if __name__ == "__main__":
    unittest.main()
