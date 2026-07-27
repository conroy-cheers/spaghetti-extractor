from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

import capstone

from spaghetti_extractor.relational.lean.internal_direct_call_register_summary import (
    InternalDirectCallRegisterSummaryLeanBindings,
    LeanFiniteOriginTailTarget,
)
from spaghetti_extractor.relational.lean.common import (
    _lean_import_certificate,
    _lean_pe,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.internal_direct_call_summary_proposal import (
    DirectCallSummaryRequest,
    FiniteOriginCallAuthorityBinding,
    InternalDirectCallSummaryProposalError,
    InternalDirectCallSummarySourceBindings,
    construct_internal_direct_call_summary_proposals,
    discover_internal_direct_call_sites,
    write_internal_direct_call_summary_proposals,
)
from tests.pe_fixtures import pe32_image, pe32_import_image
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.test_stage_a_internal_direct_call_register_summary_kernel import (
    _copy_module_closure,
)


IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    function: str = "fixture",
    memory_writes: int = 0,
    internal_call: tuple[int, int] | None = None,
    outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    if internal_call is not None:
        events.append({
            "kind": "internal_call",
            "target_rva": internal_call[0],
            "return_rva": internal_call[1],
        })
    row = {
        "external_events": events,
        "function": function,
        "instructions": _instructions(code, start),
        "memory_events": [
            {"kind": "write", "width": 4, "address": {"op": "reg", "name": "esp"}}
            for _ in range(memory_writes)
        ],
        "original": {
            "rva_end": start + len(code),
            "rva_start": start,
            "size": len(code),
        },
    }
    if outcome is not None:
        row["outcome"] = outcome
    return row


def _write_artifacts(
    root: Path,
    code: bytes,
    rows: list[dict[str, Any]],
    *,
    imported: bool = False,
    boundaries: list[dict[str, Any]] | None = None,
    signatures: list[dict[str, Any]] | None = None,
) -> tuple[Path, Path, Path]:
    pe = root / "fixture.exe"
    pe.write_bytes(
        pe32_import_image(code, symbol="Tick", iat_offset=0x40)
        if imported else pe32_image(code)
    )
    state = root / "state-machine.jsonl"
    state.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = root / "machine-import-contract-report.json"
    report.write_text(json.dumps({
        "boundaries": boundaries or [],
        "exact_inventory_matches": True,
        "format": "stage-a-static-machine-import-contracts-v1",
        "inputs": {
            "original_sha256": _sha256(pe),
            "state_machine_sha256": _sha256(state),
        },
        "required_imports": (
            [{"dll": "kernel32.dll", "symbol": "Tick"}] if imported else []
        ),
        "signatures": signatures or [],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pe, state, report


def _push_pop_fixture(root: Path) -> tuple[Path, Path, Path]:
    code = bytearray(b"\x90" * 0x1C)
    code[0:5] = b"\xE8\x0B\x00\x00\x00"
    code[5:6] = b"\xC3"
    code[0x10:0x13] = b"\x56\xEB\x00"
    code[0x13:0x1A] = b"\xBE\x00\x00\x00\x00\xEB\x00"
    code[0x1A:0x1C] = b"\x5E\xC3"
    rows = [
        _row(TEXT_RVA, bytes(code[0:5]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5)),
        _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
        _row(TEXT_RVA + 0x10, bytes(code[0x10:0x13]), memory_writes=1),
        _row(TEXT_RVA + 0x13, bytes(code[0x13:0x1A])),
        _row(TEXT_RVA + 0x1A, bytes(code[0x1A:0x1C])),
    ]
    return _write_artifacts(root, bytes(code), rows)


def _checked_continue_fixture(root: Path) -> tuple[Path, Path, Path]:
    code = bytearray(b"\x90" * 0x1F)
    code[0:5] = b"\xE8\x0B\x00\x00\x00"
    code[5:6] = b"\xC3"
    code[0x10:0x1E] = bytes.fromhex(
        "31d2"          # xor edx, edx
        "b808000000"    # mov eax, 8
        "b902000000"    # mov ecx, 2
        "f7f1"          # div ecx
    )
    code[0x1E:0x1F] = b"\xC3"
    rows = [
        _row(
            TEXT_RVA,
            bytes(code[0:5]),
            internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
        ),
        _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
        _row(
            TEXT_RVA + 0x10,
            bytes(code[0x10:0x1E]),
            outcome={
                "kind": "fallthrough",
                "target_rva": TEXT_RVA + 0x1E,
            },
        ),
        _row(TEXT_RVA + 0x1E, bytes(code[0x1E:0x1F])),
    ]
    return _write_artifacts(root, bytes(code), rows)


def _external_tail_fixture(
    root: Path, *, argument_words: int = 0
) -> tuple[Path, Path, Path]:
    code = bytearray(b"\x90" * 0x76)
    code[0:5] = b"\xE8\x0B\x00\x00\x00"
    code[5:6] = b"\xC3"
    code[0x10:0x18] = b"\x53\x83\xEC\x04\x89\xC3\xEB\x00"
    code[0x18:0x21] = b"\x83\xC4\x04\x5B\xE9\x0F\x00\x00\x00"
    code[0x30:0x38] = b"\x53\x83\xEC\x04\x89\xCB\xEB\x00"
    code[0x38:0x41] = b"\x83\xC4\x04\x5B\xE9\x1F\x00\x00\x00"
    code[0x60:0x66] = b"\xFF\x25" + struct.pack("<I", 0x402040)
    code[0x70:0x75] = b"\xE8\xBB\xFF\xFF\xFF"
    code[0x75:0x76] = b"\xC3"
    rows = [
        _row(
            TEXT_RVA,
            bytes(code[0:5]),
            internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
        ),
        _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
        _row(
            TEXT_RVA + 0x10,
            bytes(code[0x10:0x18]),
            memory_writes=1,
        ),
        _row(TEXT_RVA + 0x18, bytes(code[0x18:0x21])),
        _row(
            TEXT_RVA + 0x30,
            bytes(code[0x30:0x38]),
            memory_writes=1,
        ),
        _row(TEXT_RVA + 0x38, bytes(code[0x38:0x41])),
        _row(TEXT_RVA + 0x60, bytes(code[0x60:0x66])),
        _row(
            TEXT_RVA + 0x70,
            bytes(code[0x70:0x75]),
            internal_call=(TEXT_RVA + 0x30, TEXT_RVA + 0x75),
        ),
        _row(TEXT_RVA + 0x75, bytes(code[0x75:0x76])),
    ]
    boundary = {
        "argument_evidence": "declarative_fixed_abi_plus_exact_decode",
        "argument_words": argument_words,
        "continuation_rva": TEXT_RVA + 0x75,
        "execution_source_rva": TEXT_RVA + 0x60,
        "id": 7,
        "import": {"dll": "kernel32.dll", "symbol": "Tick"},
        "instruction_rva": TEXT_RVA + 0x70,
        "route": "framed_thunk_tail",
        "signature_id": 3,
        "source_rva": TEXT_RVA + 0x70,
        "source_size": 5,
        "frame_entry_rva": TEXT_RVA + 0x10,
        "frame_entry_size": 8,
        "tail_rva": TEXT_RVA + 0x38,
        "tail_size": 9,
        "thunk_rva": TEXT_RVA + 0x60,
        "thunk_size": 6,
    }
    signature = {
        "abi": "cdecl",
        "arity": {"kind": "fixed", "words": argument_words},
        "callback_mode": "none",
        "disposition": "returns",
        "id": 3,
        "import": {"dll": "kernel32.dll", "symbol": "Tick"},
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
    }
    return _write_artifacts(
        root,
        bytes(code),
        rows,
        imported=True,
        boundaries=[boundary],
        signatures=[signature],
    )


class StageAInternalDirectCallSummaryProposalTests(unittest.TestCase):
    def test_constructs_deterministic_push_pop_register_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, state, report = _push_pop_fixture(Path(temporary))
            request = DirectCallSummaryRequest(TEXT_RVA, ("esi",))
            first = construct_internal_direct_call_summary_proposals(
                pe, state, report, [request]
            )
            second = construct_internal_direct_call_summary_proposals(
                pe, state, report, [request]
            )

            self.assertEqual(first.to_json(), second.to_json())
            self.assertEqual(first.blockers, ())
            certificate = first.proposals[0].tree.certificate
            self.assertEqual(certificate.requested_registers, ("esi", "esp"))
            self.assertEqual(
                certificate.stack_witnesses[0].restore_region_ids,
                (TEXT_RVA + 0x1A,),
            )
            self.assertEqual(certificate.stack_witnesses[0].original_frame_bytes, 4)
            self.assertNotIn('"status"', json.dumps(first.to_json()))

    def test_checked_continue_has_one_success_continuation_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, state, report = _checked_continue_fixture(Path(temporary))

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )

            self.assertEqual(plan.blockers, ())
            certificate = plan.proposals[0].tree.certificate
            self.assertIn(
                (TEXT_RVA + 0x10, TEXT_RVA + 0x1E, "direct"),
                tuple(
                    (edge.source_region_id, edge.target_region_id, edge.kind)
                    for edge in certificate.edges
                ),
            )
            self.assertEqual(
                tuple(region.region_id for region in certificate.callee_regions),
                (TEXT_RVA + 0x10, TEXT_RVA + 0x1E),
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_checked_continue_source_is_checked_by_lean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            inputs.mkdir()
            pe, state, report = _checked_continue_fixture(inputs)
            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA",
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            binary = _parse_stage_a_pe(pe)
            try:
                bytes_literal = ", ".join(hex(value) for value in pe.read_bytes())
                pe_term = _lean_pe(binary, "fixtureBytes")
            finally:
                binary.pe.close()
            (stage_a / "InternalCallProposalFixture.lean").write_text(f"""
import StageA.RelationalInternalDirectCallRegisterSummary

namespace StageA.Generated.ProposalFixture

open StageA.Formal StageA.Relational

def fixtureBytes : ByteTree := ByteTree.ofBytes [{bytes_literal}]
def pe : PE32 := {pe_term}
def imports : List PEImport := []

end StageA.Generated.ProposalFixture
""", encoding="utf-8")
            bindings = InternalDirectCallSummarySourceBindings(
                checker=InternalDirectCallRegisterSummaryLeanBindings(
                    original_pe="StageA.Generated.ProposalFixture.pe",
                    candidate_pe="StageA.Generated.ProposalFixture.pe",
                    original_imports="StageA.Generated.ProposalFixture.imports",
                    candidate_imports="StageA.Generated.ProposalFixture.imports",
                    imports=("StageA.InternalCallProposalFixture",),
                )
            )
            (
                stage_a
                / "GeneratedRelationalInternalDirectCallRegisterSummary.lean"
            ).write_text(plan.source(0, bindings), encoding="utf-8")

            result = _run_lean_relational(
                root,
                bundle="GeneratedRelationalInternalDirectCallRegisterSummary",
            )

            self.assertEqual(result["status"], "checked", result)
            output = result["stdout"] + result["stderr"]
            self.assertNotIn("sorryAx", output)

    def test_constructs_returning_finite_origin_indirect_call_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x21)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x12] = b"\xFF\xD0"
            code[0x12:0x13] = b"\xC3"
            code[0x20:0x21] = b"\xC3"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x12]),
                    outcome={
                        "kind": "indirect_call",
                        "target": {"op": "reg", "name": "eax"},
                        "return_rva": TEXT_RVA + 0x12,
                    },
                ),
                _row(TEXT_RVA + 0x12, bytes(code[0x12:0x13])),
                _row(TEXT_RVA + 0x20, bytes(code[0x20:0x21]), function="target"),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)
            authority = FiniteOriginCallAuthorityBinding(
                source_rva=TEXT_RVA + 0x10,
                instruction_rva=TEXT_RVA + 0x10,
                continuation_rva=TEXT_RVA + 0x12,
                continuation_target_id=91,
                internal_targets=(
                    LeanFiniteOriginTailTarget(77, TEXT_RVA + 0x20),
                ),
                internal_target_rvas=(TEXT_RVA + 0x20,),
                authority_module="StageA.Generated.FiniteOriginAuthority",
                indirect_exit_authority_term=(
                    "StageA.Generated.FiniteOriginAuthority.checkedExit"
                ),
                indirect_exit_certificate_exact_term=(
                    "StageA.Generated.FiniteOriginAuthority.checkedExitExact"
                ),
            )

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
                finite_origin_call_authorities=(authority,),
            )

            self.assertEqual(plan.blockers, ())
            tree = plan.proposals[0].tree
            dependency = tree.certificate.finite_origin_call_dependencies[0]
            self.assertEqual(dependency.source_region_id, TEXT_RVA + 0x10)
            self.assertEqual(
                dependency.continuation_region_id,
                TEXT_RVA + 0x12,
            )
            self.assertEqual(dependency.continuation_target_id, 91)
            self.assertEqual(len(tree.nested), 1)
            child = tree.nested[0].certificate
            self.assertEqual(child.entry_kind, "finite_origin_call")
            self.assertEqual(child.entry_dependency_id, TEXT_RVA + 0x10)
            self.assertEqual(child.entry_target_id, 77)
            self.assertEqual(child.callee_entry.region_id, TEXT_RVA + 0x20)
            self.assertIn(".finiteOriginCall", tree.lean())
            proposal_source = plan.source(
                0,
                InternalDirectCallSummarySourceBindings(
                    checker=InternalDirectCallRegisterSummaryLeanBindings(
                        original_pe="StageA.Generated.ProposalFixture.pe",
                        candidate_pe="StageA.Generated.ProposalFixture.pe",
                        original_imports=(
                            "StageA.Generated.ProposalFixture.imports"
                        ),
                        candidate_imports=(
                            "StageA.Generated.ProposalFixture.imports"
                        ),
                    )
                ),
            )
            self.assertIn(
                "generatedFiniteOriginCallAuthorityBound0000",
                proposal_source,
            )
            self.assertIn(
                "generatedFiniteOriginCallAuthorityComponent0000Dependencies",
                proposal_source,
            )
            self.assertIn(
                "generatedFiniteOriginCallAuthorityComponent0000Targets",
                proposal_source,
            )
            self.assertIn(
                "Certificate.finiteOriginCallAuthorityBound_of_components",
                proposal_source,
            )
            self.assertNotIn(
                "generatedFiniteOriginCallAuthority0000\n"
                "      StageA.Generated.ProposalFixture.pe "
                "StageA.Generated.ProposalFixture.pe\n"
                "      StageA.Generated.ProposalFixture.imports "
                "StageA.Generated.ProposalFixture.imports = true := by\n"
                "  set_option maxRecDepth 100000 in\n"
                "  decide",
                proposal_source,
            )

    def test_constructs_root_finite_origin_indirect_call_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x11)
            code[0:2] = b"\xFF\xD0"
            code[2:3] = b"\xC3"
            code[0x10:0x11] = b"\xC3"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:2]),
                    outcome={
                        "kind": "indirect_call",
                        "target": {"op": "reg", "name": "eax"},
                        "return_rva": TEXT_RVA + 2,
                    },
                ),
                _row(TEXT_RVA + 2, bytes(code[2:3]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x11]),
                    function="target",
                ),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)
            authority = FiniteOriginCallAuthorityBinding(
                source_rva=TEXT_RVA,
                instruction_rva=TEXT_RVA,
                continuation_rva=TEXT_RVA + 2,
                continuation_target_id=91,
                internal_targets=(
                    LeanFiniteOriginTailTarget(77, TEXT_RVA + 0x10),
                ),
                internal_target_rvas=(TEXT_RVA + 0x10,),
                authority_module="StageA.Generated.FiniteOriginAuthority",
                indirect_exit_authority_term=(
                    "StageA.Generated.FiniteOriginAuthority.checkedExit"
                ),
                indirect_exit_certificate_exact_term=(
                    "StageA.Generated.FiniteOriginAuthority.checkedExitExact"
                ),
            )

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                (),
                finite_origin_entry_requests=(
                    DirectCallSummaryRequest(TEXT_RVA, ("ebx",)),
                ),
                finite_origin_call_authorities=(authority,),
            )

        self.assertEqual(plan.blockers, ())
        self.assertEqual(len(plan.proposals), 1)
        proposal = plan.proposals[0]
        self.assertEqual(proposal.entry_authority, authority)
        self.assertEqual(proposal.tree.certificate.entry_kind, "finite_origin_call")
        self.assertEqual(
            proposal.tree.certificate.entry_dependency_id,
            TEXT_RVA,
        )
        self.assertEqual(proposal.tree.certificate.entry_target_id, 77)
        self.assertEqual(
            proposal.tree.certificate.callee_entry.region_id,
            TEXT_RVA + 0x10,
        )
        self.assertEqual(
            proposal.to_json()["entry_authority"]["internal_target_ids"],
            [77],
        )

    def test_finite_origin_call_authority_rejects_duplicate_target_ids(self) -> None:
        authority = FiniteOriginCallAuthorityBinding(
            source_rva=TEXT_RVA,
            instruction_rva=TEXT_RVA,
            continuation_rva=TEXT_RVA + 2,
            continuation_target_id=91,
            internal_targets=(
                LeanFiniteOriginTailTarget(77, TEXT_RVA + 0x10),
                LeanFiniteOriginTailTarget(77, TEXT_RVA + 0x20),
            ),
            internal_target_rvas=(TEXT_RVA + 0x10, TEXT_RVA + 0x20),
            authority_module="StageA.Generated.FiniteOriginAuthority",
            indirect_exit_authority_term=(
                "StageA.Generated.FiniteOriginAuthority.checkedExit"
            ),
            indirect_exit_certificate_exact_term=(
                "StageA.Generated.FiniteOriginAuthority.checkedExitExact"
            ),
        )

        with self.assertRaisesRegex(
            InternalDirectCallSummaryProposalError,
            "duplicate target IDs",
        ):
            authority.checked()

    def test_later_local_spill_does_not_replace_entry_register_save(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x21)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x1C] = (
                b"\x53"
                b"\x83\xEC\x10"
                b"\x89\xC3"
                b"\x89\x5C\x24\x08"
                b"\xEB\x00"
            )
            code[0x1C:0x21] = b"\x83\xC4\x10\x5B\xC3"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x1C]),
                    memory_writes=2,
                ),
                _row(TEXT_RVA + 0x1C, bytes(code[0x1C:0x21])),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )

            self.assertEqual(plan.blockers, ())
            witness = plan.proposals[0].tree.certificate.stack_witnesses[0]
            self.assertEqual(witness.original_frame_bytes, 20)
            self.assertEqual(witness.original_save_offset, 4)
            self.assertEqual(
                witness.restore_region_ids,
                (TEXT_RVA + 0x1C,),
            )

    def test_constructs_multi_frame_witness_across_exact_direct_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x56)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x18] = b"\x53\x83\xEC\x04\x89\xC3\xEB\x00"
            code[0x18:0x21] = (
                b"\x83\xC4\x04\x5B\xE9\x0F\x00\x00\x00"
            )
            code[0x30:0x38] = b"\x53\x83\xEC\x04\x89\xCB\xEB\x00"
            code[0x38:0x3D] = b"\x83\xC4\x04\x5B\xC3"
            code[0x50:0x55] = b"\xE8\xDB\xFF\xFF\xFF"
            code[0x55:0x56] = b"\xC3"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x18]),
                    memory_writes=1,
                ),
                _row(TEXT_RVA + 0x18, bytes(code[0x18:0x21])),
                _row(
                    TEXT_RVA + 0x30,
                    bytes(code[0x30:0x38]),
                    memory_writes=1,
                ),
                _row(TEXT_RVA + 0x38, bytes(code[0x38:0x3D])),
                _row(
                    TEXT_RVA + 0x50,
                    bytes(code[0x50:0x55]),
                    internal_call=(TEXT_RVA + 0x30, TEXT_RVA + 0x55),
                ),
                _row(TEXT_RVA + 0x55, bytes(code[0x55:0x56])),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )

            self.assertEqual(plan.blockers, ())
            certificate = plan.proposals[0].tree.certificate
            self.assertIn(
                (TEXT_RVA + 0x18, TEXT_RVA + 0x30, "direct_tail"),
                tuple(
                    (edge.source_region_id, edge.target_region_id, edge.kind)
                    for edge in certificate.edges
                ),
            )
            witness = certificate.stack_witnesses[0]
            self.assertEqual(witness.restore_region_ids, (TEXT_RVA + 0x18,))
            self.assertEqual(len(witness.additional_frames), 1)
            self.assertEqual(
                witness.additional_frames[0].save_region_id,
                TEXT_RVA + 0x30,
            )
            self.assertEqual(
                witness.additional_frames[0].restore_region_ids,
                (TEXT_RVA + 0x38,),
            )
            self.assertIn(".directTail", plan.proposals[0].tree.lean())

    def test_constructs_checked_external_tail_after_multiple_frames(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, state, report = _external_tail_fixture(Path(temporary))

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )

            self.assertEqual(plan.blockers, ())
            proposal = plan.proposals[0]
            certificate = proposal.tree.certificate
            self.assertEqual(proposal.machine_import_boundary_ids, ())
            self.assertEqual(proposal.machine_import_tail_signature_ids, (3,))
            self.assertEqual(
                tuple(
                    (
                        edge.source_region_id,
                        edge.target_region_id,
                        edge.kind,
                    )
                    for edge in certificate.edges
                    if edge.kind == "machine_import_tail"
                ),
                ((TEXT_RVA + 0x38, TEXT_RVA + 0x60, "machine_import_tail"),),
            )
            self.assertEqual(
                certificate.machine_import_tail_dependencies[0].source_region_id,
                TEXT_RVA + 0x60,
            )
            self.assertIn(".machineImportTail", proposal.tree.lean())

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_external_tail_source_is_checked_by_lean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            inputs.mkdir()
            argument_words = 1
            pe, state, report = _external_tail_fixture(
                inputs, argument_words=argument_words
            )
            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )
            self.assertEqual(plan.blockers, ())

            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA",
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            binary = _parse_stage_a_pe(pe)
            try:
                bytes_literal = ", ".join(hex(value) for value in pe.read_bytes())
                pe_term = _lean_pe(binary, "fixtureBytes")
                imports_term = _lean_import_certificate(binary)
            finally:
                binary.pe.close()
            (stage_a / "ExternalTailProposalFixture.lean").write_text(f"""
import StageA.RelationalInternalDirectCallRegisterSummary

namespace StageA.Generated.ExternalTailProposalFixture

open StageA.Formal StageA.Relational

def fixtureBytes : ByteTree := ByteTree.ofBytes [{bytes_literal}]
def pe : PE32 := {pe_term}
def importCertificate : ImportTableCertificate := {imports_term}
def imports : List PEImport := importCertificate.imports

end StageA.Generated.ExternalTailProposalFixture
""", encoding="utf-8")
            dll = ", ".join(str(value) for value in b"kernel32.dll")
            symbol = ", ".join(str(value) for value in b"Tick")
            imported = (
                f"{{ dll := [{dll}], name := (.symbol [{symbol}]) }}"
            )
            (stage_a / "ExternalTailStaticImports.lean").write_text(f"""
import StageA.ExternalTailProposalFixture

namespace StageA.Generated.ExternalTailStaticImports

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts

def generatedRequiredImports : List ExternalTarget := [{imported}]
def generatedMachineImportSignatures : List StaticMachineImportSignature := [
  {{ id := 3, imported := {imported}, abi := .cdecl,
     arity := .fixed {argument_words},
     resultRegisterRelations := [], disposition := .returns,
     memoryEffect := .none, memoryFootprints := [], worldEffect := .none,
     callbackMode := .none }}
]
def generatedMachineImportBoundaries : List StaticMachineImportBoundary := []

end StageA.Generated.ExternalTailStaticImports
""", encoding="utf-8")
            bindings = InternalDirectCallSummarySourceBindings(
                checker=InternalDirectCallRegisterSummaryLeanBindings(
                    original_pe=(
                        "StageA.Generated.ExternalTailProposalFixture.pe"
                    ),
                    candidate_pe=(
                        "StageA.Generated.ExternalTailProposalFixture.pe"
                    ),
                    original_imports=(
                        "StageA.Generated.ExternalTailProposalFixture.imports"
                    ),
                    candidate_imports=(
                        "StageA.Generated.ExternalTailProposalFixture.imports"
                    ),
                    imports=(
                        "StageA.ExternalTailProposalFixture",
                        "StageA.ExternalTailStaticImports",
                    ),
                ),
                static_import_module="StageA.ExternalTailStaticImports",
                static_import_namespace=(
                    "StageA.Generated.ExternalTailStaticImports"
                ),
            )
            (stage_a / "GeneratedRelationalInternalDirectCallRegisterSummary.lean").write_text(
                plan.source(0, bindings),
                encoding="utf-8",
            )

            result = _run_lean_relational(
                root,
                bundle="GeneratedRelationalInternalDirectCallRegisterSummary",
            )

            self.assertEqual(result["status"], "checked", result)
            output = result["stdout"] + result["stderr"]
            self.assertNotIn("sorryAx", output)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_constructed_push_pop_source_is_checked_by_lean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            inputs.mkdir()
            pe, state, report = _push_pop_fixture(inputs)
            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("esi",))],
            )
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA",
                stage_a,
                "RelationalInternalDirectCallRegisterSummary",
            )
            binary = _parse_stage_a_pe(pe)
            try:
                bytes_literal = ", ".join(hex(value) for value in pe.read_bytes())
                pe_term = _lean_pe(binary, "fixtureBytes")
            finally:
                binary.pe.close()
            (stage_a / "InternalCallProposalFixture.lean").write_text(f"""
import StageA.RelationalInternalDirectCallRegisterSummary

namespace StageA.Generated.ProposalFixture

open StageA.Formal StageA.Relational

def fixtureBytes : ByteTree := ByteTree.ofBytes [{bytes_literal}]
def pe : PE32 := {pe_term}
def imports : List PEImport := []

end StageA.Generated.ProposalFixture
""", encoding="utf-8")
            bindings = InternalDirectCallSummarySourceBindings(
                checker=InternalDirectCallRegisterSummaryLeanBindings(
                    original_pe="StageA.Generated.ProposalFixture.pe",
                    candidate_pe="StageA.Generated.ProposalFixture.pe",
                    original_imports="StageA.Generated.ProposalFixture.imports",
                    candidate_imports="StageA.Generated.ProposalFixture.imports",
                    imports=("StageA.InternalCallProposalFixture",),
                )
            )
            (stage_a / "GeneratedRelationalInternalDirectCallRegisterSummary.lean").write_text(
                plan.source(0, bindings), encoding="utf-8"
            )

            result = _run_lean_relational(
                root, bundle="GeneratedRelationalInternalDirectCallRegisterSummary"
            )

            self.assertEqual(result["status"], "checked", result)
            output = result["stdout"] + result["stderr"]
            self.assertNotIn("sorryAx", output)
            self.assertRegex(
                output,
                re.compile(
                    r"generatedInternalDirectCallRegisterSummaryStructuralEvidence.*"
                    r"depends on axioms",
                    re.DOTALL,
                ),
            )
            self.assertIn("NotAcceptanceAuthority", output)

    def test_recursively_constructs_nested_direct_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x21)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x15] = b"\xE8\x0B\x00\x00\x00"
            code[0x15:0x16] = b"\xC3"
            code[0x20:0x21] = b"\xC3"
            rows = [
                _row(TEXT_RVA, bytes(code[0:5]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5)),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(TEXT_RVA + 0x10, bytes(code[0x10:0x15]), internal_call=(TEXT_RVA + 0x20, TEXT_RVA + 0x15)),
                _row(TEXT_RVA + 0x15, bytes(code[0x15:0x16])),
                _row(TEXT_RVA + 0x20, bytes(code[0x20:0x21]), function="leaf"),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe, state, report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )

            self.assertEqual(plan.blockers, ())
            tree = plan.proposals[0].tree
            self.assertEqual(tree.certificate.dependency_depth, 1)
            self.assertEqual(len(tree.nested), 1)
            self.assertEqual(tree.nested[0].certificate.requested_registers, ("ebx", "esp"))
            self.assertEqual(
                plan.proposals[0].nested_callsite_rvas,
                (TEXT_RVA + 0x10,),
            )

    def test_grounds_direct_import_and_emits_checked_lookup_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x17)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x16] = b"\xFF\x15" + struct.pack("<I", 0x402040)
            code[0x16:0x17] = b"\xC3"
            rows = [
                _row(TEXT_RVA, bytes(code[0:5]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5)),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(TEXT_RVA + 0x10, bytes(code[0x10:0x16])),
                _row(TEXT_RVA + 0x16, bytes(code[0x16:0x17])),
            ]
            boundary = {
                "argument_evidence": "exact",
                "argument_words": 0,
                "continuation_rva": TEXT_RVA + 0x16,
                "execution_source_rva": TEXT_RVA + 0x10,
                "id": 7,
                "import": {"dll": "kernel32.dll", "symbol": "Tick"},
                "instruction_rva": TEXT_RVA + 0x10,
                "route": "direct",
                "signature_id": 3,
                "source_rva": TEXT_RVA + 0x10,
                "source_size": 6,
            }
            signature = {
                "abi": "cdecl",
                "arity": {"kind": "fixed", "words": 0},
                "callback_mode": "none",
                "disposition": "returns",
                "id": 3,
                "import": {"dll": "kernel32.dll", "symbol": "Tick"},
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }
            pe, state, report = _write_artifacts(
                root,
                bytes(code),
                rows,
                imported=True,
                boundaries=[boundary],
                signatures=[signature],
            )
            plan = construct_internal_direct_call_summary_proposals(
                pe, state, report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )
            bindings = InternalDirectCallSummarySourceBindings(
                checker=InternalDirectCallRegisterSummaryLeanBindings(
                    original_pe="Fixture.pe",
                    candidate_pe="Fixture.pe",
                    original_imports="Fixture.imports",
                    candidate_imports="Fixture.imports",
                    imports=("StageA.Fixture",),
                ),
                static_import_module="StageA.GeneratedStaticImports",
                static_import_namespace="StageA.Generated.StaticImports",
            )

            self.assertEqual(plan.blockers, ())
            self.assertEqual(plan.proposals[0].machine_import_boundary_ids, (7,))
            source = plan.source(0, bindings)
            self.assertIn("import StageA.GeneratedStaticImports", source)
            self.assertIn("generatedSummaryMachineImportBoundary7", source)
            self.assertIn(".find? (fun boundary => boundary.id == 7)", source)
            self.assertNotIn("proposal_status", source)

    def test_recovers_mask_bounded_immutable_indirect_jump_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x48)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            table_va = IMAGE_BASE + TEXT_RVA + 0x40
            code[0x10:0x1A] = (
                b"\x83\xE0\x01\xFF\x24\x85" + struct.pack("<I", table_va)
            )
            code[0x20:0x22] = b"\xEB\x02"
            code[0x22:0x24] = b"\xEB\x00"
            code[0x24:0x25] = b"\xC3"
            code[0x40:0x48] = struct.pack(
                "<II",
                IMAGE_BASE + TEXT_RVA + 0x20,
                IMAGE_BASE + TEXT_RVA + 0x22,
            )
            index = {
                "op": "and32",
                "args": [
                    {"op": "reg", "name": "eax"},
                    {"op": "const", "value": 1},
                ],
            }
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x1A]),
                    outcome={
                        "kind": "indirect_jump",
                        "target": {
                            "op": "load",
                            "width": 4,
                            "address": {
                                "op": "add32",
                                "args": [
                                    {"op": "const", "value": table_va},
                                    {
                                        "op": "mul32",
                                        "args": [
                                            index,
                                            {"op": "const", "value": 4},
                                        ],
                                    },
                                ],
                            },
                        },
                    },
                ),
                _row(TEXT_RVA + 0x20, bytes(code[0x20:0x22])),
                _row(TEXT_RVA + 0x22, bytes(code[0x22:0x24])),
                _row(TEXT_RVA + 0x24, bytes(code[0x24:0x25])),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("esi",))],
            )

            self.assertEqual(plan.blockers, ())
            dependency = (
                plan.proposals[0].tree.certificate.finite_indirect_dependencies[0]
            )
            self.assertEqual(dependency.upper_exclusive, 2)
            self.assertEqual(
                dependency.entry_target_region_ids,
                (TEXT_RVA + 0x20, TEXT_RVA + 0x22),
            )
            self.assertIn(".finiteIndirect", plan.proposals[0].tree.lean())

    def test_recovers_constant_valued_indirect_jump_as_exact_internal_edge(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x23)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            target_va = IMAGE_BASE + TEXT_RVA + 0x20
            code[0x10:0x17] = b"\xB8" + struct.pack("<I", target_va) + b"\xFF\xE0"
            code[0x20:0x22] = b"\xEB\x00"
            code[0x22:0x23] = b"\xC3"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x17]),
                    outcome={
                        "kind": "indirect_jump",
                        "target": {"op": "const", "value": target_va},
                    },
                ),
                _row(TEXT_RVA + 0x20, bytes(code[0x20:0x22])),
                _row(TEXT_RVA + 0x22, bytes(code[0x22:0x23])),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("esi",))],
            )

            self.assertEqual(plan.blockers, ())
            certificate = plan.proposals[0].tree.certificate
            self.assertEqual(certificate.finite_indirect_dependencies, ())
            self.assertIn(
                (TEXT_RVA + 0x10, TEXT_RVA + 0x20, "constant_indirect"),
                tuple(
                    (edge.source_region_id, edge.target_region_id, edge.kind)
                    for edge in certificate.edges
                ),
            )
            self.assertIn(".constantIndirect", plan.proposals[0].tree.lean())

    def test_constant_valued_indirect_jump_to_noncode_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x17)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            target_va = IMAGE_BASE + 0x3000
            code[0x10:0x17] = b"\xB8" + struct.pack("<I", target_va) + b"\xFF\xE0"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(
                    TEXT_RVA + 0x10,
                    bytes(code[0x10:0x17]),
                    outcome={
                        "kind": "indirect_jump",
                        "target": {"op": "const", "value": target_va},
                    },
                ),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("esi",))],
            )

            self.assertEqual(plan.proposals, ())
            self.assertEqual(
                plan.blockers[0].category,
                "constant_indirect_target_not_executable",
            )

    def test_reports_interface_mismatches_without_claiming_rejection(self) -> None:
        cases: list[tuple[str, bytes, list[dict[str, Any]], str]] = []

        indirect = b"\xFF\xD0\xC3"
        cases.append((
            "indirect",
            indirect,
            [_row(TEXT_RVA, indirect[:2]), _row(TEXT_RVA + 2, indirect[2:])],
            "requested_site_is_not_internal_direct_call",
        ))

        recursion = bytearray(b"\x90" * 0x16)
        recursion[0:5] = b"\xE8\x0B\x00\x00\x00"
        recursion[5:6] = b"\xC3"
        recursion[0x10:0x15] = b"\xE8\xFB\xFF\xFF\xFF"
        recursion[0x15:0x16] = b"\xC3"
        cases.append((
            "recursion",
            bytes(recursion),
            [
                _row(TEXT_RVA, bytes(recursion[0:5]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5)),
                _row(TEXT_RVA + 5, bytes(recursion[5:6]), function="caller"),
                _row(TEXT_RVA + 0x10, bytes(recursion[0x10:0x15]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 0x15)),
                _row(TEXT_RVA + 0x15, bytes(recursion[0x15:0x16])),
            ],
            "recursive_call_requires_checked_finite_invariant",
        ))

        no_return = bytearray(b"\x90" * 0x12)
        no_return[0:5] = b"\xE8\x0B\x00\x00\x00"
        no_return[5:6] = b"\xC3"
        no_return[0x10:0x12] = b"\xEB\xFE"
        cases.append((
            "no-return",
            bytes(no_return),
            [
                _row(TEXT_RVA, bytes(no_return[0:5]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5)),
                _row(TEXT_RVA + 5, bytes(no_return[5:6]), function="caller"),
                _row(TEXT_RVA + 0x10, bytes(no_return[0x10:0x12])),
            ],
            "callee_has_no_complete_return_inventory",
        ))

        for label, code, rows, category in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                pe, state, report = _write_artifacts(Path(temporary), code, rows)
                request_rva = TEXT_RVA if label != "indirect" else TEXT_RVA
                plan = construct_internal_direct_call_summary_proposals(
                    pe, state, report,
                    [DirectCallSummaryRequest(request_rva, ("ebx",))],
                )
                self.assertEqual(plan.proposals, ())
                self.assertEqual(plan.blockers[0].category, category)
                self.assertTrue(plan.blockers[0].next_action)
                self.assertNotIn("status", plan.blockers[0].to_json())

    def test_identity_register_allows_exact_interior_write_and_overlap_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x19)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x12] = b"\xEB\x00"
            code[0x12:0x18] = b"\x89\x18\xEB\x02\x90\x90"
            code[0x18:0x19] = b"\xC3"
            rows = [
                _row(TEXT_RVA, bytes(code[0:5]), internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5)),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(TEXT_RVA + 0x10, bytes(code[0x10:0x12])),
                _row(TEXT_RVA + 0x12, bytes(code[0x12:0x16]), memory_writes=1),
                _row(TEXT_RVA + 0x18, bytes(code[0x18:0x19])),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)
            plan = construct_internal_direct_call_summary_proposals(
                pe, state, report,
                [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
            )
            self.assertEqual(plan.blockers, ())
            self.assertEqual(len(plan.proposals), 1)

            values = [json.loads(line) for line in state.read_text().splitlines()]
            values[3]["original"]["rva_start"] = TEXT_RVA + 0x11
            values[3]["original"]["rva_end"] = TEXT_RVA + 0x15
            for instruction in values[3]["instructions"]:
                instruction["rva"] -= 1
            state.write_text(
                "".join(json.dumps(value) + "\n" for value in values),
                encoding="utf-8",
            )
            payload = json.loads(report.read_text())
            payload["inputs"]["state_machine_sha256"] = _sha256(state)
            report.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                InternalDirectCallSummaryProposalError,
                "does not match the PE|overlap",
            ):
                construct_internal_direct_call_summary_proposals(
                    pe, state, report,
                    [DirectCallSummaryRequest(TEXT_RVA, ("ebx",))],
                )

    def test_stack_saved_register_inventories_protected_write_regions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytearray(b"\x90" * 0x1E)
            code[0:5] = b"\xE8\x0B\x00\x00\x00"
            code[5:6] = b"\xC3"
            code[0x10:0x13] = b"\x56\xEB\x00"
            code[0x13:0x1C] = b"\x89\x18\xBE\x00\x00\x00\x00\xEB\x00"
            code[0x1C:0x1E] = b"\x5E\xC3"
            rows = [
                _row(
                    TEXT_RVA,
                    bytes(code[0:5]),
                    internal_call=(TEXT_RVA + 0x10, TEXT_RVA + 5),
                ),
                _row(TEXT_RVA + 5, bytes(code[5:6]), function="caller"),
                _row(TEXT_RVA + 0x10, bytes(code[0x10:0x13]), memory_writes=1),
                _row(
                    TEXT_RVA + 0x13,
                    bytes(code[0x13:0x1C]),
                    memory_writes=1,
                ),
                _row(TEXT_RVA + 0x1C, bytes(code[0x1C:0x1E])),
            ]
            pe, state, report = _write_artifacts(root, bytes(code), rows)

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [DirectCallSummaryRequest(TEXT_RVA, ("esi",))],
            )

            self.assertEqual(plan.blockers, ())
            witness = plan.proposals[0].tree.certificate.stack_witnesses[0]
            self.assertEqual(
                witness.protected_write_region_ids,
                (TEXT_RVA + 0x13,),
            )
            self.assertIn(
                f"protectedWriteRegionIds := [{TEXT_RVA + 0x13}]",
                plan.proposals[0].tree.lean(),
            )

    def test_frame_only_request_accounts_for_architectural_call_push(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pe, state, report = _push_pop_fixture(Path(temporary))

            plan = construct_internal_direct_call_summary_proposals(
                pe,
                state,
                report,
                [
                    DirectCallSummaryRequest(
                        TEXT_RVA,
                        (),
                        caller_rva=TEXT_RVA,
                        caller_frame_word_offsets=(32,),
                    )
                ],
            )

        self.assertEqual(plan.blockers, ())
        self.assertEqual(len(plan.proposals), 1)
        certificate = plan.proposals[0].tree.certificate
        # ESP is always included as the architectural call/return frame
        # register even when the external request names only caller memory.
        self.assertEqual(certificate.requested_registers, ("esp",))
        self.assertEqual(
            tuple(
                (word.original_offset, word.candidate_offset)
                for word in certificate.caller_frame_words
            ),
            ((36, 36),),
        )
        self.assertIn(
            "callerFrameWords := "
            "[{ originalOffset := 36, candidateOffset := 36 }]",
            plan.proposals[0].tree.lean(),
        )

    def test_discovery_and_writer_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe, state, report = _push_pop_fixture(root)
            self.assertEqual(
                discover_internal_direct_call_sites(pe, state, report),
                (TEXT_RVA,),
            )
            plan = construct_internal_direct_call_summary_proposals(
                pe, state, report,
                [DirectCallSummaryRequest(TEXT_RVA, ("esi",))],
            )
            artifact, sources = write_internal_direct_call_summary_proposals(
                root / "out", plan
            )
            self.assertTrue(artifact.is_file())
            self.assertEqual(sources, ())
            self.assertEqual(json.loads(artifact.read_text())["format"], (
                "stage-a-internal-direct-call-summary-proposals-v1"
            ))


if __name__ == "__main__":
    unittest.main()
