from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

import capstone

from pe_fixtures import pe32_import_image
from spaghetti_extractor.relational.lean.internal_direct_call_mixed_original_integration import (
    DirectCallMixedOriginalFiniteEvidenceBinding,
    InternalDirectCallMixedOriginalIntegrationError,
    direct_call_mixed_original_finite_evidence_source,
)
from spaghetti_extractor.relational.lean.internal_direct_call_summary_proposal import (
    FiniteDirectCallEvidenceRequest,
    InternalDirectCallSummaryProposalError,
    construct_finite_direct_call_evidence_proposal,
)


IMAGE_BASE = 0x400000
CALLER_RVA = 0x1000
CALLSITE_RVA = 0x1007
CONTINUATION_RVA = 0x100C
CALLEE_RVA = 0x1010
CODE_TARGET_RVA = 0x1030
STATIC_SLOT_RVA = 0x2100


def _instructions(code: bytes, rva: int) -> list[dict[str, Any]]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return [
        {
            "bytes": instruction.bytes.hex(),
            "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str,
            "rva": instruction.address - IMAGE_BASE,
            "size": instruction.size,
        }
        for instruction in decoder.disasm(code, IMAGE_BASE + rva)
    ]


def _row(
    rva: int,
    code: bytes,
    *,
    memory_events: list[dict[str, Any]] | None = None,
    external_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "external_events": external_events or [],
        "function": "fixture",
        "instructions": _instructions(code, rva),
        "memory_events": memory_events or [],
        "original": {
            "rva_end": rva + len(code),
            "rva_start": rva,
            "size": len(code),
        },
    }


def _stack(offset: int) -> dict[str, Any]:
    if offset == 0:
        return {"name": "esp", "op": "reg", "width": 32}
    return {
        "args": [
            {"op": "const", "value": offset, "width": 32},
            {"name": "esp", "op": "reg", "width": 32},
        ],
        "op": "add32",
    }


def _write_fixture(
    root: Path,
    *,
    redirected_slot: bool = False,
    cycle: bool = False,
    missing_edge: bool = False,
    external_boundary: bool = False,
) -> tuple[Path, Path, Path]:
    code = bytearray(b"\x90" * 0x31)
    code[0:7] = b"\xc7\x04\x24" + (IMAGE_BASE + CODE_TARGET_RVA).to_bytes(4, "little")
    code[7:12] = b"\xe8" + (CALLEE_RVA - CONTINUATION_RVA).to_bytes(
        4, "little", signed=True
    )
    code[12] = 0xC3
    slot_rva = STATIC_SLOT_RVA + (4 if redirected_slot else 0)
    if cycle:
        callee = b"\xeb\xfe"
    elif missing_edge:
        callee = b"\xe9" + (0x1020 - (CALLEE_RVA + 5)).to_bytes(
            4, "little", signed=True
        )
    else:
        callee = (
            b"\x8b\x44\x24\x04"
            + b"\xa3"
            + (IMAGE_BASE + slot_rva).to_bytes(4, "little")
            + b"\xc3"
        )
    code[CALLEE_RVA - 0x1000 : CALLEE_RVA - 0x1000 + len(callee)] = callee
    code[CODE_TARGET_RVA - 0x1000] = 0xC3

    image = bytearray(pe32_import_image(bytes(code), symbol="Tick"))
    second_section_header = 0x80 + 4 + 20 + 224 + 40
    characteristics_offset = second_section_header + 36
    characteristics = struct.unpack_from("<I", image, characteristics_offset)[0]
    struct.pack_into("<I", image, characteristics_offset, characteristics | 0x80000000)
    pe = root / "fixture.exe"
    pe.write_bytes(image)

    caller = _row(
        CALLER_RVA,
        bytes(code[:12]),
        memory_events=[
            {
                "address": _stack(0),
                "kind": "write",
                "value": {
                    "op": "const",
                    "value": IMAGE_BASE + CODE_TARGET_RVA,
                    "width": 32,
                },
                "width": 4,
            }
        ],
        external_events=[
            {
                "kind": "internal_call",
                "return_rva": CONTINUATION_RVA,
                "target_rva": CALLEE_RVA,
            }
        ],
    )
    callee_events: list[dict[str, Any]] = []
    if not cycle and not missing_edge:
        callee_events = [
            {"address": _stack(4), "kind": "read", "width": 4},
            {
                "address": {
                    "op": "const",
                    "value": IMAGE_BASE + slot_rva,
                    "width": 32,
                },
                "kind": "write",
                "value": {
                    "address": _stack(4),
                    "op": "load",
                    "width": 4,
                },
                "width": 4,
            },
        ]
    rows = [
        caller,
        _row(CONTINUATION_RVA, b"\xc3"),
        _row(CALLEE_RVA, callee, memory_events=callee_events),
        _row(CODE_TARGET_RVA, b"\xc3"),
    ]
    state = root / "state-machine.jsonl"
    state.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    boundaries = []
    signatures = []
    if external_boundary:
        signatures = [{"id": 9}]
        boundaries = [
            {
                "continuation_rva": CONTINUATION_RVA,
                "id": 3,
                "instruction_rva": CALLSITE_RVA,
                "route": "framed_thunk_tail",
                "signature_id": 9,
                "source_rva": CALLER_RVA,
                "source_size": 12,
            }
        ]
    report = root / "machine-import-contract-report.json"
    report.write_text(
        json.dumps(
            {
                "boundaries": boundaries,
                "format": "stage-a-static-machine-import-contracts-v1",
                "inputs": {
                    "original_sha256": hashlib.sha256(pe.read_bytes()).hexdigest(),
                    "state_machine_sha256": hashlib.sha256(
                        state.read_bytes()
                    ).hexdigest(),
                },
                "required_imports": [{"dll": "kernel32.dll", "symbol": "Tick"}],
                "signatures": signatures,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return pe, state, report


def _request() -> FiniteDirectCallEvidenceRequest:
    return FiniteDirectCallEvidenceRequest(
        callsite_rva=CALLSITE_RVA,
        caller_rva=CALLER_RVA,
        argument_code_target_rva=CODE_TARGET_RVA,
        static_slot_rva=STATIC_SLOT_RVA,
    )


class StageAFiniteDirectCallEvidenceTests(unittest.TestCase):
    def test_exact_acyclic_copy_proposes_ranked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, state, report = _write_fixture(Path(temporary))
            plan = construct_finite_direct_call_evidence_proposal(
                pe, state, report, _request()
            )

        self.assertEqual(plan.blockers, ())
        self.assertIsNotNone(plan.proposal)
        assert plan.proposal is not None
        self.assertEqual(plan.proposal.callee_rva, CALLEE_RVA)
        self.assertEqual(plan.proposal.return_rvas, (CALLEE_RVA,))
        self.assertEqual(
            [(row.rva, row.rank) for row in plan.proposal.ranks],
            [(CALLEE_RVA, 0)],
        )
        payload = plan.to_json()
        self.assertFalse(payload["artifact_role"]["acceptance_authority"])
        self.assertFalse(payload["artifact_role"]["proof_status_emitted"])

    def test_missing_edge_redirected_slot_cycle_and_external_step_fail_closed(
        self,
    ) -> None:
        cases = (
            ("missing_edge", "missing_finite_call_edge_target"),
            ("redirected_slot", "frame_argument_static_write_not_unique"),
            ("cycle", "non_decreasing_scc_requires_checked_ranking"),
            ("external_boundary", "external_or_nested_world_execution_required"),
        )
        for option, category in cases:
            with (
                self.subTest(option=option),
                tempfile.TemporaryDirectory() as temporary,
            ):
                pe, state, report = _write_fixture(Path(temporary), **{option: True})
                plan = construct_finite_direct_call_evidence_proposal(
                    pe, state, report, _request()
                )
                self.assertIsNone(plan.proposal)
                self.assertIn(category, {item.category for item in plan.blockers})

    def test_stale_state_machine_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, state, report = _write_fixture(Path(temporary))
            rows = state.read_text(encoding="utf-8").splitlines()
            first = json.loads(rows[0])
            first["instructions"][0]["bytes"] = "90" * 7
            rows[0] = json.dumps(first, sort_keys=True)
            state.write_text("\n".join(rows) + "\n", encoding="utf-8")
            report_payload = json.loads(report.read_text(encoding="utf-8"))
            report_payload["inputs"]["state_machine_sha256"] = hashlib.sha256(
                state.read_bytes()
            ).hexdigest()
            report.write_text(json.dumps(report_payload), encoding="utf-8")
            with self.assertRaisesRegex(
                InternalDirectCallSummaryProposalError, "does not match the PE"
            ):
                construct_finite_direct_call_evidence_proposal(
                    pe, state, report, _request()
                )

    def test_generated_module_exports_only_terms_derived_from_checked_package(
        self,
    ) -> None:
        source = direct_call_mixed_original_finite_evidence_source(
            DirectCallMixedOriginalFiniteEvidenceBinding(
                context="StageA.Fixture.context",
                evidence_term="StageA.Fixture.finiteEvidence",
                source_target_id=1,
                callee_target_id=2,
                continuation_target_id=3,
                edge_index=4,
                contract_id=5,
                source_rva=CALLER_RVA,
                callsite_rva=CALLSITE_RVA,
                call_instruction_size=5,
                callee_rva=CALLEE_RVA,
                continuation_rva=CONTINUATION_RVA,
                argument_original_offset=4,
                argument_candidate_offset=4,
                argument_code_target_id=6,
                static_slot_original_address=IMAGE_BASE + STATIC_SLOT_RVA,
                static_slot_candidate_address=IMAGE_BASE + STATIC_SLOT_RVA,
                static_slot_code_target_id=6,
                registers=("eax",),
                imports=("StageA.Fixture",),
                namespace="StageA.Generated.FiniteCall",
            )
        )
        for name in (
            "generatedIntegratedSummaryPremises",
            "generatedExactDirectCallEntry",
            "generatedOperationalCallReturnCompleteness",
            "generatedCheckedFiniteCallRegionExecutionForSource",
            "generatedFiniteReturningExecutionForSource",
            "generatedRuntimeFrameArgumentStaticWrite",
            "generatedArgumentToStaticSlot",
            "generatedCheckedDirectCallRegisterControlContract",
        ):
            self.assertIn(name, source)
        self.assertNotIn("proof_status", source)
        self.assertNotIn("native_decide", source)

    def test_generated_binding_rejects_relation_or_instruction_mismatch(self) -> None:
        base = DirectCallMixedOriginalFiniteEvidenceBinding(
            context="StageA.Fixture.context",
            evidence_term="StageA.Fixture.finiteEvidence",
            source_target_id=1,
            callee_target_id=2,
            continuation_target_id=3,
            edge_index=4,
            contract_id=5,
            source_rva=CALLER_RVA,
            callsite_rva=CALLSITE_RVA,
            call_instruction_size=5,
            callee_rva=CALLEE_RVA,
            continuation_rva=CONTINUATION_RVA,
            argument_original_offset=4,
            argument_candidate_offset=4,
            argument_code_target_id=6,
            static_slot_original_address=IMAGE_BASE + STATIC_SLOT_RVA,
            static_slot_candidate_address=IMAGE_BASE + STATIC_SLOT_RVA,
            static_slot_code_target_id=7,
            registers=("eax",),
            imports=("StageA.Fixture",),
            namespace="StageA.Generated.FiniteCall",
        )
        with self.assertRaisesRegex(
            InternalDirectCallMixedOriginalIntegrationError, "same code target"
        ):
            direct_call_mixed_original_finite_evidence_source(base)


if __name__ == "__main__":
    unittest.main()
