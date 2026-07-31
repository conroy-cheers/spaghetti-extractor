from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import capstone
from pe_fixtures import pe32_import_image

from spaghetti_extractor.relational.lean.internal_direct_call_summary_proposal import (
    construct_internal_direct_call_summary_proposals,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    INTERPRETER_MIXED_DIRECT_CALL_AUTHORITY_FORMAT,
    InterpreterMixedOriginalGenerationError,
    InterpreterMixedOriginalSpec,
    MixedOriginalDirectCallSummaryRequestPlan,
    OriginalIATImport,
    OriginalImportIdentity,
    OriginalModuleBindings,
    OriginalPERecoveryInput,
    OriginalRegisterControlCallContractProposal,
    QualifiedLeanSymbol,
    augment_direct_call_summary_requests_from_runtime_value_carry_hints,
    derive_direct_call_summary_requests_from_register_authority,
    derive_mixed_original_direct_call_summary_requests,
    load_checked_direct_call_summary_contract_proposals,
    load_checked_stack_finite_origin_call_entry_authorities,
    plan_interpreter_mixed_original,
    stage_finite_origin_entry_requests,
    write_relational_interpreter_mixed_original_base,
    write_relational_interpreter_mixed_original_final,
)
from spaghetti_extractor.relational.direct_call_proposal_ir import (
    DirectCallSummaryRequest,
)
IMAGE_BASE = 0x400000
IAT_RVA = 0x2040
ENTRY_RVA = 0x1000
CALLSITE_RVA = 0x1006
CONTINUATION_RVA = 0x100B
INDIRECT_CALL_RVA = CONTINUATION_RVA
INDIRECT_CONTINUATION_RVA = 0x100D
CALLEE_RVA = 0x1030


def _instructions(code: bytes, start: int) -> list[dict[str, Any]]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return [
        {
            "bytes": instruction.bytes.hex(),
            "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str,
            "rva": instruction.address - IMAGE_BASE,
            "size": instruction.size,
        }
        for instruction in decoder.disasm(code, IMAGE_BASE + start)
    ]


def _row(
    start: int,
    code: bytes,
    *,
    function: str,
    internal_call: tuple[int, int] | None = None,
) -> dict[str, Any]:
    events = []
    if internal_call is not None:
        events.append({
            "kind": "internal_call",
            "return_rva": internal_call[1],
            "target_rva": internal_call[0],
        })
    return {
        "external_events": events,
        "function": function,
        "instructions": _instructions(code, start),
        "memory_events": [],
        "original": {
            "rva_end": start + len(code),
            "rva_start": start,
            "size": len(code),
        },
    }


def _write_artifacts(
    root: Path,
    code: bytes,
    rows: list[dict[str, Any]],
) -> tuple[Path, Path, Path]:
    pe = root / "fixture.exe"
    pe.write_bytes(pe32_import_image(code, symbol="Tick", iat_offset=0x40))
    state = root / "state-machine.jsonl"
    state.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = root / "machine-import-contract-report.json"
    report.write_text(json.dumps({
        "boundaries": [],
        "exact_inventory_matches": True,
        "format": "stage-a-static-machine-import-contracts-v1",
        "inputs": {
            "original_sha256": hashlib.sha256(pe.read_bytes()).hexdigest(),
            "state_machine_sha256": hashlib.sha256(state.read_bytes()).hexdigest(),
        },
        "required_imports": [{"dll": "kernel32.dll", "symbol": "Tick"}],
        "signatures": [],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pe, state, report


def _fixture(root: Path) -> tuple[Path, Path, Path, InterpreterMixedOriginalSpec]:
    code = bytearray(b"\x90" * 0x31)
    code[0:6] = b"\x8b\x1d" + (IMAGE_BASE + IAT_RVA).to_bytes(4, "little")
    displacement = CALLEE_RVA - CONTINUATION_RVA
    code[6:11] = b"\xe8" + displacement.to_bytes(4, "little", signed=True)
    code[11:13] = b"\xff\xd3"
    code[13] = 0xC3
    code[0x30] = 0xC3

    caller = _row(
        ENTRY_RVA,
        bytes(code[:11]),
        function="caller",
        internal_call=(CALLEE_RVA, CONTINUATION_RVA),
    )
    caller.update({
        "edge_conditions": [
            {"target_rva": CONTINUATION_RVA, "condition": {"op": "true"}},
            {"target_rva": CALLEE_RVA, "condition": {"op": "true"}},
        ],
        "format": "stage-a-semantic-transfer-contract-v1",
        "ordered_events": [{
            "instruction_rva": CALLSITE_RVA,
            "kind": "internal_call",
            "return_rva": CONTINUATION_RVA,
            "target_rva": CALLEE_RVA,
        }],
        "outcome": {"kind": "fallthrough", "target_rva": CONTINUATION_RVA},
        "stage_b_format": "stage-b-state-machine-transfer-v1",
    })
    indirect = _row(
        INDIRECT_CALL_RVA,
        bytes(code[11:13]),
        function="caller",
    )
    indirect.update({
        "edge_conditions": [{
            "target_rva": INDIRECT_CONTINUATION_RVA,
            "condition": {"op": "true"},
        }],
        "format": "stage-a-semantic-transfer-contract-v1",
        "ordered_events": [{
            "instruction_rva": INDIRECT_CALL_RVA,
            "kind": "indirect_call",
            "return_rva": INDIRECT_CONTINUATION_RVA,
            "target": {"name": "ebx", "op": "reg", "width": 32},
        }],
        "outcome": {
            "kind": "fallthrough",
            "target_rva": INDIRECT_CONTINUATION_RVA,
        },
        "stage_b_format": "stage-b-state-machine-transfer-v1",
    })

    def returned(rva: int, offset: int, function: str) -> dict[str, object]:
        row = _row(rva, bytes(code[offset : offset + 1]), function=function)
        row.update({
            "edge_conditions": [],
            "format": "stage-a-semantic-transfer-contract-v1",
            "ordered_events": [],
            "outcome": {"kind": "return"},
            "stage_b_format": "stage-b-state-machine-transfer-v1",
        })
        return row

    rows = [
        caller,
        indirect,
        returned(INDIRECT_CONTINUATION_RVA, 13, "caller"),
        returned(CALLEE_RVA, 0x30, "callee"),
    ]
    pe, state, report = _write_artifacts(root, bytes(code), rows)
    spec = InterpreterMixedOriginalSpec(
        bindings=OriginalModuleBindings(
            module="StageA.GeneratedFixtureOriginalPE",
            namespace="StageA.Generated.FixtureOriginalPE",
            machine_import_call_contracts=QualifiedLeanSymbol(
                module="StageA.GeneratedFixtureMachineContracts",
                namespace="StageA.Generated.FixtureMachineContracts",
                symbol="contracts",
            ),
        ),
        entry_rva=ENTRY_RVA,
        iat_imports=(OriginalIATImport(
            iat_va=IMAGE_BASE + IAT_RVA,
            iat_rva=IAT_RVA,
            identity=OriginalImportIdentity("KERNEL32.dll", "Tick"),
        ),),
        recovery_pe=OriginalPERecoveryInput(
            pe,
            hashlib.sha256(pe.read_bytes()).hexdigest(),
        ),
    )
    return pe, state, report, spec


def _authority_report(
    path: Path,
    pe: Path,
    state: Path,
    *,
    include_term: bool,
) -> None:
    term = (
        {
            "module": "StageA.GeneratedFixtureDirectCallAuthority",
            "namespace": "StageA.Generated.FixtureDirectCallAuthority",
            "symbol": "checkedContract",
        }
        if include_term
        else None
    )
    path.write_text(json.dumps({
        "contracts": [{
            "authorizing_lean_term": term,
            "callsite_rva": CALLSITE_RVA,
            "continuation_rva": CONTINUATION_RVA,
            "contract_id": 17,
            "preserved_registers": ["ebx"],
            "callee_preserved_registers": ["ebx"],
            "target_carried_registers": [],
            "source_rva": ENTRY_RVA,
        }],
        "format": INTERPRETER_MIXED_DIRECT_CALL_AUTHORITY_FORMAT,
        "inputs": {
            "original_sha256": hashlib.sha256(pe.read_bytes()).hexdigest(),
            "state_machine_sha256": hashlib.sha256(state.read_bytes()).hexdigest(),
        },
        "status": "checked" if include_term else "accepted",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class StageAMixedOriginalDirectCallSpliceTests(unittest.TestCase):
    def test_finite_origin_requests_are_stratified_by_checked_entries(
        self,
    ) -> None:
        plan = MixedOriginalDirectCallSummaryRequestPlan(
            state_machine_sha256="2" * 64,
            requests=(
                DirectCallSummaryRequest(
                    callsite_rva=0x1010,
                    caller_rva=0x1000,
                    registers=("ebx",),
                ),
            ),
            chains=(),
            frontiers=(),
            finite_origin_entry_requests=(
                DirectCallSummaryRequest(
                    callsite_rva=0x1020,
                    caller_rva=0x1018,
                    registers=("ebx",),
                ),
                DirectCallSummaryRequest(
                    callsite_rva=0x1040,
                    caller_rva=0x1038,
                    registers=("esi",),
                ),
            ),
        )

        staged = stage_finite_origin_entry_requests(
            plan,
            available_instruction_rvas=(0x1020,),
        )

        self.assertEqual(staged.requests, plan.requests)
        self.assertEqual(
            [request.callsite_rva
             for request in staged.finite_origin_entry_requests],
            [0x1020],
        )
        self.assertEqual(len(staged.frontiers), 1)
        self.assertEqual(
            staged.frontiers[0]["reason_code"],
            "finite_origin_entry_deferred_until_checked",
        )
        self.assertEqual(staged.frontiers[0]["callsite_rva"], 0x1040)

    def test_runtime_value_carry_hints_merge_frame_words_and_keep_indirect_frontier(
        self,
    ) -> None:
        original_sha256 = "1" * 64
        plan = MixedOriginalDirectCallSummaryRequestPlan(
            state_machine_sha256="2" * 64,
            requests=(
                DirectCallSummaryRequest(
                    callsite_rva=0x105A,
                    caller_rva=0x1040,
                    registers=("ebx",),
                ),
            ),
            chains=(),
            frontiers=(),
        )
        proposal_ir = SimpleNamespace(
            target_ids_by_rva={
                0x1030: 0,
                0x1040: 1,
                0x1060: 2,
                0x1070: 3,
            },
            direct_call_sites=(
                SimpleNamespace(
                    callsite_rva=0x105A,
                    source_rva=0x1040,
                    source_target_id=1,
                    continuation_rva=0x1060,
                    continuation_target_id=2,
                    edge_index=7,
                ),
            ),
            stack_dynamic_control=SimpleNamespace(
                indirect_sites=(
                    SimpleNamespace(
                        source_rva=0x1030,
                        instruction_rva=0x1038,
                        is_call=True,
                        continuation_rva=0x1040,
                    ),
                ),
            ),
        )
        location = {
            "kind": "frame_word",
            "register": "esp",
            "offset": 32,
        }
        hints = {
            "format": "stage-a-stack-dynamic-closure-hints-v2",
            "original_sha256": original_sha256,
            "runtime_value_carry_routes": [{
                "stable_id": "fixture.callback",
                "facts": [
                    {"target_rva": rva, "location": location}
                    for rva in (0x1030, 0x1040, 0x1060)
                ],
                "transfers": [
                    {
                        "kind": "call_frame_word_preserve",
                        "source_rva": 0x1030,
                        "target_rva": 0x1040,
                    },
                    {
                        "kind": "call_frame_word_preserve",
                        "source_rva": 0x1040,
                        "target_rva": 0x1060,
                    },
                ],
            }],
        }

        augmented = (
            augment_direct_call_summary_requests_from_runtime_value_carry_hints(
                plan,
                hints,
                proposal_ir,
                original_sha256=original_sha256,
            )
        )

        self.assertEqual(len(augmented.requests), 1)
        self.assertEqual(augmented.requests[0].registers, ("ebx",))
        self.assertEqual(
            augmented.requests[0].caller_frame_word_offsets,
            (32,),
        )
        self.assertEqual(len(augmented.chains), 1)
        self.assertEqual(
            augmented.chains[0]["caller_frame_word_offset"],
            32,
        )
        self.assertEqual(len(augmented.frontiers), 1)
        self.assertEqual(
            augmented.frontiers[0]["reason_code"],
            "caller_frame_word_requires_finite_origin_entry_authority",
        )
        self.assertEqual(augmented.frontiers[0]["instruction_rva"], 0x1038)

    def test_checked_stack_entry_emits_exact_finite_origin_frame_request(
        self,
    ) -> None:
        original_sha256 = "1" * 64
        state_machine_sha256 = "2" * 64
        plan = MixedOriginalDirectCallSummaryRequestPlan(
            state_machine_sha256=state_machine_sha256,
            requests=(),
            chains=(),
            frontiers=(),
        )
        proposal_ir = SimpleNamespace(
            target_ids_by_rva={
                8243: 292,
                8256: 293,
                82848: 5621,
            },
            direct_call_sites=(),
            stack_dynamic_control=SimpleNamespace(
                indirect_sites=(
                    SimpleNamespace(
                        source_rva=8243,
                        instruction_rva=8252,
                        is_call=True,
                        continuation_rva=8256,
                    ),
                ),
            ),
        )
        location = {
            "kind": "frame_word",
            "register": "esp",
            "offset": 32,
        }
        hints = {
            "format": "stage-a-stack-dynamic-closure-hints-v2",
            "original_sha256": original_sha256,
            "runtime_value_carry_routes": [{
                "stable_id": "gnu.original.callback-stack-slot",
                "facts": [
                    {"target_rva": 8243, "location": location},
                    {"target_rva": 8256, "location": location},
                ],
                "transfers": [{
                    "kind": "call_frame_word_preserve",
                    "source_rva": 8243,
                    "target_rva": 8256,
                }],
            }],
        }
        term = {
            "module": "StageA.GeneratedStackAuthority",
            "namespace": "StageA.Generated.StackAuthority",
            "symbol": "checkedStackEntry",
        }
        entry_term = {
            "module": "StageA.GeneratedStackCallEntry",
            "namespace": "StageA.Generated.StackCallEntry",
            "symbol": "checkedIndirectExit",
        }
        stack_authority = {
            "format": (
                "stage-a-checked-stack-finite-origin-call-entry-authorities-v1"
            ),
            "inputs": {
                "original_sha256": original_sha256,
                "state_machine_sha256": state_machine_sha256,
            },
            "entries": [{
                "source_rva": 8243,
                "instruction_rva": 8252,
                "continuation_rva": 8256,
                "source_target_id": 292,
                "continuation_target_id": 293,
                "callee_target_id": 5621,
                "callee_rva": 82848,
                "caller_frame_word_offset": 32,
                "static_stack_authority_term": term,
                "static_stack_authority_kernel_check": {
                    "status": "checked",
                    "module": term["module"],
                    "source_sha256": "3" * 64,
                    "olean_sha256": "4" * 64,
                    "term": term,
                },
                "indirect_exit_authority_module": entry_term["module"],
                "indirect_exit_authority_term": entry_term,
                "indirect_exit_authority_kernel_check": {
                    "status": "checked",
                    "module": entry_term["module"],
                    "source_sha256": "5" * 64,
                    "olean_sha256": "6" * 64,
                    "term": entry_term,
                },
                "indirect_exit_certificate_exact_term": (
                    "StageA.Generated.StackCallEntry."
                    "checkedIndirectExitExact"
                ),
                "certificate_constructor": (
                    "StageA.Relational.IndirectExitAdapters."
                    "checkedStackFixedIndirectCertificate"
                ),
            }],
        }

        augmented = (
            augment_direct_call_summary_requests_from_runtime_value_carry_hints(
                plan,
                hints,
                proposal_ir,
                original_sha256=original_sha256,
                checked_stack_entry_authority=stack_authority,
            )
        )
        authorities = load_checked_stack_finite_origin_call_entry_authorities(
            stack_authority,
            original_sha256=original_sha256,
            state_machine_sha256=state_machine_sha256,
        )

        self.assertEqual(augmented.frontiers, ())
        self.assertEqual(len(augmented.finite_origin_entry_requests), 1)
        request = augmented.finite_origin_entry_requests[0]
        self.assertEqual(request.callsite_rva, 8252)
        self.assertEqual(request.caller_rva, 8243)
        self.assertEqual(request.registers, ())
        self.assertEqual(request.caller_frame_word_offsets, (32,))
        call = augmented.chains[0]["required_finite_origin_calls"][0]
        self.assertEqual(call["source_target_id"], 292)
        self.assertEqual(call["continuation_target_id"], 293)
        self.assertEqual(call["callee_target_id"], 5621)
        self.assertEqual(
            call["certificate_constructor"],
            "StageA.Relational.IndirectExitAdapters."
            "checkedStackFixedIndirectCertificate",
        )
        self.assertEqual(len(authorities), 1)
        self.assertEqual(authorities[0].target_ids, (5621,))
        self.assertEqual(
            authorities[0].indirect_exit_authority_term,
            "StageA.Generated.StackCallEntry.checkedIndirectExit",
        )

    def test_uncompiled_stack_entry_does_not_create_finite_origin_request(
        self,
    ) -> None:
        original_sha256 = "1" * 64
        state_machine_sha256 = "2" * 64
        plan = MixedOriginalDirectCallSummaryRequestPlan(
            state_machine_sha256=state_machine_sha256,
            requests=(),
            chains=(),
            frontiers=(),
        )
        proposal_ir = SimpleNamespace(
            target_ids_by_rva={8243: 292, 8256: 293, 82848: 5621},
            direct_call_sites=(),
            stack_dynamic_control=SimpleNamespace(
                indirect_sites=(
                    SimpleNamespace(
                        source_rva=8243,
                        instruction_rva=8252,
                        is_call=True,
                        continuation_rva=8256,
                    ),
                ),
            ),
        )
        location = {
            "kind": "frame_word",
            "register": "esp",
            "offset": 32,
        }
        hints = {
            "format": "stage-a-stack-dynamic-closure-hints-v2",
            "original_sha256": original_sha256,
            "runtime_value_carry_routes": [{
                "stable_id": "gnu.original.callback-stack-slot",
                "facts": [
                    {"target_rva": 8243, "location": location},
                    {"target_rva": 8256, "location": location},
                ],
                "transfers": [{
                    "kind": "call_frame_word_preserve",
                    "source_rva": 8243,
                    "target_rva": 8256,
                }],
            }],
        }
        term = {
            "module": "StageA.GeneratedStackAuthority",
            "namespace": "StageA.Generated.StackAuthority",
            "symbol": "checkedStackEntry",
        }
        stack_authority = {
            "format": (
                "stage-a-checked-stack-finite-origin-call-entry-authorities-v1"
            ),
            "inputs": {
                "original_sha256": original_sha256,
                "state_machine_sha256": state_machine_sha256,
            },
            "entries": [{
                "source_rva": 8243,
                "instruction_rva": 8252,
                "continuation_rva": 8256,
                "source_target_id": 292,
                "continuation_target_id": 293,
                "callee_target_id": 5621,
                "callee_rva": 82848,
                "caller_frame_word_offset": 32,
                "static_stack_authority_term": term,
                "static_stack_authority_kernel_check": {
                    "status": "generated",
                    "module": term["module"],
                    "source_sha256": "3" * 64,
                    "olean_sha256": "4" * 64,
                    "term": term,
                },
                "certificate_constructor": (
                    "StageA.Relational.IndirectExitAdapters."
                    "checkedStackFixedIndirectCertificate"
                ),
            }],
        }

        with self.assertRaisesRegex(
            InterpreterMixedOriginalGenerationError,
            "was not kernel-compiled",
        ):
            augment_direct_call_summary_requests_from_runtime_value_carry_hints(
                plan,
                hints,
                proposal_ir,
                original_sha256=original_sha256,
                checked_stack_entry_authority=stack_authority,
            )

    def test_exact_register_authority_inventory_drives_deduplicated_requests(
        self,
    ) -> None:
        original_sha256 = "1" * 64
        state_machine_sha256 = "2" * 64
        machine_import_report_sha256 = "3" * 64
        machine_report = {
            "format": "stage-a-static-machine-import-contracts-v1",
            "inputs": {
                "original_sha256": original_sha256,
                "state_machine_sha256": state_machine_sha256,
            },
            "boundaries": [{
                "id": 7,
                "instruction_rva": 0x1020,
                "route": "via_thunk",
            }],
        }
        repeated_call = {
            "kind": "internal_call",
            "instruction_rva": 0x1010,
            "source_rva": 0x1000,
            "callee_target_id": 11,
        }
        import_thunk_call = {
            "kind": "internal_call",
            "instruction_rva": 0x1020,
            "source_rva": 0x1015,
            "callee_target_id": 12,
        }
        finite_origin_call = {
            "kind": "target_call",
            "instruction_rva": 0x1008,
            "source_rva": 0x1000,
            "source_target_id": 4,
            "continuation_rva": 0x100A,
            "continuation_target_id": 5,
            "callee_target_id": None,
        }
        authority_report = {
            "format": "stage-a-register-indirect-control-authorities-v1",
            "inputs": {
                "original_sha256": original_sha256,
                "state_machine_sha256": state_machine_sha256,
                "machine_import_report_sha256": machine_import_report_sha256,
            },
            "sites": [
                {
                    "site_id": 0,
                    "source_rva": 0x1030,
                    "instruction_rva": 0x1034,
                    "target_register": "ebx",
                    "carries": [
                        finite_origin_call,
                        repeated_call,
                        import_thunk_call,
                    ],
                },
                {
                    "site_id": 1,
                    "source_rva": 0x1040,
                    "instruction_rva": 0x1044,
                    "target_register": "ebx",
                    "carries": [repeated_call],
                },
            ],
        }

        requests = derive_direct_call_summary_requests_from_register_authority(
            authority_report,
            machine_report,
            original_sha256=original_sha256,
            state_machine_sha256=state_machine_sha256,
            machine_import_report_sha256=machine_import_report_sha256,
        )

        self.assertEqual(len(requests.requests), 1)
        self.assertEqual(requests.requests[0].callsite_rva, 0x1010)
        self.assertEqual(requests.requests[0].caller_rva, 0x1000)
        self.assertEqual(requests.requests[0].registers, ("ebx",))
        self.assertEqual(len(requests.finite_origin_entry_requests), 1)
        self.assertEqual(
            requests.finite_origin_entry_requests[0].callsite_rva,
            0x1008,
        )
        self.assertEqual(
            requests.chains[0]["required_finite_origin_calls"],
            [{
                "callsite_rva": 0x1008,
                "caller_rva": 0x1000,
                "callee_target_id": None,
                "source_target_id": 4,
                "continuation_rva": 0x100A,
                "continuation_target_id": 5,
            }],
        )
        self.assertEqual(
            requests.chains[0]["machine_import_carries"],
            [{
                "instruction_rva": 0x1020,
                "boundary_ids": [7],
                "routes": ["via_thunk"],
            }],
        )
        self.assertEqual(requests.frontiers, ())

    def test_register_authority_inventory_hash_mismatch_fails_closed(
        self,
    ) -> None:
        machine_report = {
            "format": "stage-a-static-machine-import-contracts-v1",
            "inputs": {
                "original_sha256": "1" * 64,
                "state_machine_sha256": "2" * 64,
            },
            "boundaries": [],
        }
        authority_report = {
            "format": "stage-a-register-indirect-control-authorities-v1",
            "inputs": {
                "original_sha256": "1" * 64,
                "state_machine_sha256": "2" * 64,
                "machine_import_report_sha256": "0" * 64,
            },
            "sites": [],
        }

        with self.assertRaisesRegex(
            InterpreterMixedOriginalGenerationError,
            "machine_import_report_sha256 does not match",
        ):
            derive_direct_call_summary_requests_from_register_authority(
                authority_report,
                machine_report,
                original_sha256="1" * 64,
                state_machine_sha256="2" * 64,
                machine_import_report_sha256="3" * 64,
            )

    def test_exact_fixture_splices_only_a_named_semantic_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, machine_report, spec = _fixture(root)
            initial = plan_interpreter_mixed_original(state, spec)
            self.assertFalse(initial.complete)

            request_plan = derive_mixed_original_direct_call_summary_requests(initial)
            self.assertEqual(request_plan.frontiers, ())
            self.assertEqual(len(request_plan.requests), 1)
            request = request_plan.requests[0]
            self.assertEqual(request.callsite_rva, CALLSITE_RVA)
            self.assertEqual(request.caller_rva, ENTRY_RVA)
            self.assertEqual(request.registers, ("ebx",))

            proposal = construct_internal_direct_call_summary_proposals(
                pe, state, machine_report, request_plan.requests
            )
            self.assertEqual(proposal.blockers, ())
            self.assertEqual(len(proposal.proposals), 1)
            self.assertEqual(
                proposal.proposals[0].tree.certificate.callee_entry.original.start,
                CALLEE_RVA,
            )

            base_paths = write_relational_interpreter_mixed_original_base(root, initial)
            base = next(
                path for path in base_paths
                if path.name == "GeneratedRelationalInterpreterMixedOriginalBase.lean"
            ).read_text(encoding="utf-8")
            self.assertNotIn("ExactOriginalDecodedReachability", base)

            report = root / "direct-call-authority.json"
            _authority_report(report, pe, state, include_term=False)
            self.assertEqual(
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(pe.read_bytes()).hexdigest(),
                    state_machine_sha256=hashlib.sha256(state.read_bytes()).hexdigest(),
                ),
                (),
            )
            with self.assertRaises(InterpreterMixedOriginalGenerationError):
                OriginalRegisterControlCallContractProposal(
                    contract_id=17,
                    source_rva=ENTRY_RVA,
                    instruction_rva=CALLSITE_RVA,
                    continuation_rva=CONTINUATION_RVA,
                    preserved_registers=("ebx",),
                    origin="checked_direct_call_summary",
                ).validate("fixture")

            _authority_report(report, pe, state, include_term=True)
            contracts = load_checked_direct_call_summary_contract_proposals(
                report,
                original_sha256=hashlib.sha256(pe.read_bytes()).hexdigest(),
                state_machine_sha256=hashlib.sha256(state.read_bytes()).hexdigest(),
            )
            final = plan_interpreter_mixed_original(
                state,
                dataclasses.replace(spec, register_control_call_contracts=contracts),
            )
            self.assertTrue(final.complete, final.blockers)
            final_paths = write_relational_interpreter_mixed_original_final(root, final)
            facade = next(
                path for path in final_paths
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            ).read_text(encoding="utf-8")
            generated_final = "\n".join(
                path.read_text(encoding="utf-8")
                for path in final_paths
                if path.suffix == ".lean"
            )
            self.assertIn("GeneratedFixtureDirectCallAuthority", generated_final)
            self.assertIn("checkedContract", generated_final)
            self.assertIn("ExactOriginalDecodedReachability", facade)

    def test_authority_report_hash_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, _machine_report, _spec = _fixture(root)
            report = root / "direct-call-authority.json"
            _authority_report(report, pe, state, include_term=True)
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["inputs"]["state_machine_sha256"] = "0" * 64
            report.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError,
                "state_machine_sha256 does not match",
            ):
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(pe.read_bytes()).hexdigest(),
                    state_machine_sha256=hashlib.sha256(state.read_bytes()).hexdigest(),
                )

    def test_caller_frame_authority_is_not_loaded_as_register_control(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, _machine_report, _spec = _fixture(root)
            report = root / "direct-call-authority.json"
            _authority_report(report, pe, state, include_term=True)
            payload = json.loads(report.read_text(encoding="utf-8"))
            contract = payload["contracts"][0]
            contract["origin"] = (
                "checked_direct_call_caller_frame_word_summary"
            )
            contract["preserved_registers"] = []
            contract["preserved_caller_frame_word_offsets"] = [32]
            contract["caller_frame_word_authorizing_lean_term"] = (
                contract["authorizing_lean_term"]
            )
            report.write_text(json.dumps(payload), encoding="utf-8")

            self.assertEqual(
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(
                        pe.read_bytes()
                    ).hexdigest(),
                    state_machine_sha256=hashlib.sha256(
                        state.read_bytes()
                    ).hexdigest(),
                ),
                (),
            )

            del contract["caller_frame_word_authorizing_lean_term"]
            report.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError,
                "no exact caller-frame authority term",
            ):
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(
                        pe.read_bytes()
                    ).hexdigest(),
                    state_machine_sha256=hashlib.sha256(
                        state.read_bytes()
                    ).hexdigest(),
                )

    def test_finite_origin_caller_frame_authority_uses_dedicated_term(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, _machine_report, _spec = _fixture(root)
            report = root / "direct-call-authority.json"
            _authority_report(report, pe, state, include_term=True)
            payload = json.loads(report.read_text(encoding="utf-8"))
            contract = payload["contracts"][0]
            contract["origin"] = (
                "checked_finite_origin_call_caller_frame_word_summary"
            )
            contract["preserved_registers"] = []
            contract["finite_target_ids"] = [3]
            contract["preserved_caller_frame_word_offsets"] = [32]
            contract["caller_frame_word_authorizing_lean_term"] = (
                contract["authorizing_lean_term"]
            )
            report.write_text(json.dumps(payload), encoding="utf-8")

            self.assertEqual(
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(
                        pe.read_bytes()
                    ).hexdigest(),
                    state_machine_sha256=hashlib.sha256(
                        state.read_bytes()
                    ).hexdigest(),
                ),
                (),
            )

            contract["caller_frame_word_authorizing_lean_term"] = {
                "module": "StageA.Other",
                "namespace": "StageA.Other",
                "symbol": "wrong",
            }
            report.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError,
                "no exact caller-frame authority term",
            ):
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(
                        pe.read_bytes()
                    ).hexdigest(),
                    state_machine_sha256=hashlib.sha256(
                        state.read_bytes()
                    ).hexdigest(),
                )

    def test_finite_authority_requires_its_checked_target_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, _machine_report, _spec = _fixture(root)
            report = root / "direct-call-authority.json"
            _authority_report(report, pe, state, include_term=True)
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["contracts"][0]["origin"] = (
                "checked_finite_origin_call_summary"
            )
            payload["contracts"][0]["finite_target_ids"] = [3]
            payload["contracts"][0]["target_carried_registers"] = ["ebx"]
            report.write_text(json.dumps(payload), encoding="utf-8")
            contracts = load_checked_direct_call_summary_contract_proposals(
                report,
                original_sha256=hashlib.sha256(pe.read_bytes()).hexdigest(),
                state_machine_sha256=hashlib.sha256(state.read_bytes()).hexdigest(),
            )
            self.assertEqual(contracts[0].finite_target_ids, (3,))

            del payload["contracts"][0]["finite_target_ids"]
            report.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError,
                "requires exactly one checked target",
            ):
                load_checked_direct_call_summary_contract_proposals(
                    report,
                    original_sha256=hashlib.sha256(pe.read_bytes()).hexdigest(),
                    state_machine_sha256=hashlib.sha256(state.read_bytes()).hexdigest(),
                )


if __name__ == "__main__":
    unittest.main()
