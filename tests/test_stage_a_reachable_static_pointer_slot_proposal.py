from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.reachable_static_pointer_slot_proposal import (
    ReachableStaticPointerSlotProposalError,
    construct_reachable_static_pointer_slot_proposal,
    write_reachable_static_pointer_slot_proposal,
)
from tests.test_stage_a_nullable_code_pointer_table import DATA_RVA, TEXT_RVA
from tests.test_stage_a_reachable_static_pointer_slot_kernel import _fixture_pe


IMAGE_BASE = 0x18000000
SLOT_A_RVA = DATA_RVA + 0x20
SLOT_B_RVA = SLOT_A_RVA + 4
SLOT_A_VA = IMAGE_BASE + SLOT_A_RVA
SLOT_B_VA = IMAGE_BASE + SLOT_B_RVA


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expression_load(address: int) -> dict[str, object]:
    return {
        "op": "load",
        "width": 4,
        "address": {"op": "const", "value": address, "width": 32},
    }


def _record(
    rva: int,
    encoded: bytes,
    outcome: dict[str, object],
    *,
    edges: list[dict[str, object]] | None = None,
    memory_events: list[dict[str, object]] | None = None,
    register_writes: list[dict[str, object]] | None = None,
    external_events: list[dict[str, object]] | None = None,
    instruction_sizes: tuple[int, ...] | None = None,
) -> dict[str, object]:
    sizes = instruction_sizes or (len(encoded),)
    if sum(sizes) != len(encoded):
        raise ValueError("instruction sizes must cover the exact encoded span")
    instructions: list[dict[str, object]] = []
    cursor = 0
    for size in sizes:
        instructions.append({
            "bytes": encoded[cursor : cursor + size].hex(),
            "mnemonic": "fixture",
            "op_str": "",
            "rva": rva + cursor,
            "size": size,
        })
        cursor += size
    return {
        "edge_conditions": edges or [],
        "external_events": external_events or [],
        "format": "stage-a-semantic-transfer-contract-v1",
        "instructions": instructions,
        "memory_events": memory_events or [],
        "original": {
            "rva_end": rva + len(encoded),
            "rva_start": rva,
            "size": len(encoded),
        },
        "outcome": outcome,
        "register_writes": register_writes or [],
    }


def _two_slot_rows() -> list[dict[str, object]]:
    first = b"\xff\x25" + SLOT_A_VA.to_bytes(4, "little")
    second = b"\xff\x25" + SLOT_B_VA.to_bytes(4, "little")
    return [
        _record(
            TEXT_RVA,
            first,
            {"kind": "indirect_jump", "target": _expression_load(SLOT_A_VA)},
        ),
        _record(
            TEXT_RVA + len(first),
            second,
            {"kind": "indirect_jump", "target": _expression_load(SLOT_B_VA)},
        ),
    ]


def _write_artifacts(
    root: Path,
    *,
    pe_bytes: bytes,
    rows: list[dict[str, object]],
    targets: list[list[int]] | None = None,
    reachable: list[int] | None = None,
) -> tuple[Path, Path, Path, Path]:
    pe = root / "fixture.exe"
    state = root / "state-machine.jsonl"
    mixed = root / "mixed-original-plan.json"
    binding = root / "authority-binding.json"
    pe.write_bytes(pe_bytes)
    state.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    reachable_ids = list(range(len(rows))) if reachable is None else reachable
    mixed.write_text(
        json.dumps(
            {
                "format": "stage-a-interpreter-mixed-original-v1",
                "reachable_target_ids": reachable_ids,
                "state_machine_sha256": _sha256(state),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    successor_ids = targets or [[] for _ in rows]
    binding.write_text(
        json.dumps(
            {
                "code_map": {
                    "entries": [
                        {
                            "aliases": [],
                            "region_index": index,
                            "rva": row["original"]["rva_start"],
                            "target_id": index,
                        }
                        for index, row in enumerate(rows)
                    ],
                    "regions": [
                        {
                            "region_index": index,
                            "root": index in reachable_ids,
                            "rva": row["original"]["rva_start"],
                            "size": row["original"]["size"],
                            "targets": successor_ids[index],
                        }
                        for index, row in enumerate(rows)
                    ],
                },
                "format": "stage-a-exact-original-decoded-authority-binding-v1",
                "inputs": {
                    "mixed_original_plan_sha256": _sha256(mixed),
                    "original_pe_sha256": _sha256(pe),
                    "state_machine_sha256": _sha256(state),
                },
                "lean": {
                    "authority_name": "originalAuthority",
                    "context_name": "originalContext",
                    "module": "StageA.GeneratedReachableSlotFixture",
                    "namespace": "StageA.GeneratedReachableSlotFixture",
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return pe, state, mixed, binding


class StageAReachableStaticPointerSlotProposalTests(unittest.TestCase):
    def test_two_unrelated_slots_partition_exact_indirect_sites(self) -> None:
        rows = _two_slot_rows()
        code = bytes.fromhex(rows[0]["instructions"][0]["bytes"]) + bytes.fromhex(
            rows[1]["instructions"][0]["bytes"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            paths = _write_artifacts(
                Path(temporary),
                pe_bytes=_fixture_pe(
                    code=code, slot_word=0, other_slot_word=0
                ),
                rows=rows,
            )
            first = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_A_RVA
            )
            second = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_B_RVA
            )

            self.assertEqual(first.blockers, ())
            self.assertEqual(second.blockers, ())
            self.assertIsNotNone(first.proposal)
            self.assertIsNotNone(second.proposal)
            assert first.proposal is not None and second.proposal is not None
            self.assertEqual(
                tuple(item.source_target_id for item in first.proposal.indirect_slot_sites or ()),
                (0,),
            )
            self.assertEqual(
                tuple(item.source_target_id for item in second.proposal.indirect_slot_sites or ()),
                (1,),
            )
            self.assertEqual(first.proposal.regions, ())
            self.assertEqual(first.proposal.allowed_target_ids, ())

            report, source = write_reachable_static_pointer_slot_proposal(
                Path(temporary) / "out", first
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertNotIn("status", payload)
            self.assertFalse(payload["artifact_role"]["acceptance_authority"])
            self.assertFalse(payload["artifact_role"]["proof_status_emitted"])
            self.assertIsNotNone(source)

    def test_initially_zero_slot_without_writers_is_proposed(self) -> None:
        rows = [_record(TEXT_RVA, b"\xc3", {"kind": "return"})]
        with tempfile.TemporaryDirectory() as temporary:
            paths = _write_artifacts(
                Path(temporary), pe_bytes=_fixture_pe(), rows=rows
            )
            plan = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_A_RVA
            )
            self.assertEqual(plan.blockers, ())
            self.assertIsNotNone(plan.proposal)
            assert plan.proposal is not None
            self.assertEqual(plan.proposal.regions, ())
            self.assertEqual(plan.proposal.indirect_slot_sites, ())

    def test_exact_guard_and_code_target_writer_are_derived(self) -> None:
        branch = (
            b"\x83\x3d"
            + SLOT_A_VA.to_bytes(4, "little")
            + b"\x00\x75\x01"
        )
        ret = b"\xc3"
        indirect = b"\xff\x25" + SLOT_A_VA.to_bytes(4, "little")
        zero = {
            "op": "eq",
            "args": [
                _expression_load(SLOT_A_VA),
                {"op": "const", "value": 0, "width": 32},
            ],
        }
        rows = [
            _record(
                TEXT_RVA,
                branch,
                {
                    "kind": "branch",
                    "condition": zero,
                    "true_target_rva": TEXT_RVA + 9,
                    "false_target_rva": TEXT_RVA + 10,
                },
                edges=[
                    {"condition": zero, "target_rva": TEXT_RVA + 9},
                    {
                        "condition": {"op": "not", "args": [zero]},
                        "target_rva": TEXT_RVA + 10,
                    },
                ],
                instruction_sizes=(7, 2),
            ),
            _record(TEXT_RVA + 9, ret, {"kind": "return"}),
            _record(
                TEXT_RVA + 10,
                indirect,
                {"kind": "indirect_jump", "target": _expression_load(SLOT_A_VA)},
            ),
        ]
        code = branch + ret + indirect
        with tempfile.TemporaryDirectory() as temporary:
            paths = _write_artifacts(
                Path(temporary),
                pe_bytes=_fixture_pe(code=code),
                rows=rows,
                targets=[[1, 2], [], []],
            )
            plan = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_A_RVA
            )
            self.assertEqual(plan.blockers, ())
            assert plan.proposal is not None
            self.assertEqual(
                tuple(
                    (item.source_target_id, item.nonzero_target_id)
                    for item in plan.proposal.guarded_nonzero_edges or ()
                ),
                ((0, 2),),
            )
            self.assertEqual(
                tuple(
                    item.source_target_id
                    for item in plan.proposal.indirect_slot_sites or ()
                ),
                (2,),
            )

        writer = (
            b"\xc7\x05"
            + SLOT_A_VA.to_bytes(4, "little")
            + (IMAGE_BASE + TEXT_RVA).to_bytes(4, "little")
            + b"\xc3"
        )
        writer_rows = [
            _record(
                TEXT_RVA,
                writer,
                {"kind": "return"},
                memory_events=[{
                    "address": {"op": "const", "value": SLOT_A_VA, "width": 32},
                    "kind": "write",
                    "value": {
                        "op": "const",
                        "value": IMAGE_BASE + TEXT_RVA,
                        "width": 32,
                    },
                    "width": 4,
                }],
                instruction_sizes=(10, 1),
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            paths = _write_artifacts(
                Path(temporary),
                pe_bytes=_fixture_pe(code=writer),
                rows=writer_rows,
            )
            plan = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_A_RVA
            )
            self.assertEqual(plan.blockers, ())
            assert plan.proposal is not None
            self.assertEqual(plan.proposal.allowed_target_ids, (0,))
            self.assertEqual(len(plan.proposal.regions or ()), 1)
            classification = plan.proposal.regions[0].writes[0]
            self.assertEqual(classification.kind, "slot_code_target")
            self.assertEqual(classification.target_id, 0)

    def test_dynamic_and_call_frame_writers_fail_closed(self) -> None:
        slot_write = b"\xa3" + SLOT_A_VA.to_bytes(4, "little")
        stack_value = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 4, "width": 32},
                    {"op": "reg", "name": "esp", "width": 32},
                ],
            },
        }
        rows = [
            _record(
                TEXT_RVA,
                slot_write,
                {"kind": "return"},
                memory_events=[
                    {
                        "address": {"op": "const", "value": SLOT_A_VA, "width": 32},
                        "kind": "write",
                        "value": stack_value,
                        "width": 4,
                    },
                    {
                        "address": {"op": "reg", "name": "eax", "width": 32},
                        "kind": "write",
                        "value": {"op": "const", "value": 0, "width": 32},
                        "width": 4,
                    },
                ],
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            paths = _write_artifacts(
                Path(temporary), pe_bytes=_fixture_pe(code=slot_write), rows=rows
            )
            plan = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_A_RVA
            )
            self.assertIsNone(plan.proposal)
            self.assertEqual(
                {item.category for item in plan.blockers},
                {
                    "call_frame_writer_provenance_required",
                    "dynamic_write_may_alias_slot",
                },
            )

    def test_hash_and_exact_instruction_mutations_are_rejected(self) -> None:
        rows = _two_slot_rows()
        code = b"".join(
            bytes.fromhex(row["instructions"][0]["bytes"]) for row in rows
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = list(_write_artifacts(
                root,
                pe_bytes=_fixture_pe(
                    code=code, slot_word=0, other_slot_word=0
                ),
                rows=rows,
            ))
            paths[0].write_bytes(_fixture_pe(
                code=b"\x90" + code[1:], slot_word=0, other_slot_word=0
            ))
            with self.assertRaisesRegex(
                ReachableStaticPointerSlotProposalError,
                "original_pe_sha256",
            ):
                construct_reachable_static_pointer_slot_proposal(
                    *paths, SLOT_A_RVA
                )

        mismatched_rows = _two_slot_rows()
        mismatched_rows[0]["outcome"] = {
            "kind": "indirect_jump",
            "target": _expression_load(SLOT_B_VA),
        }
        with tempfile.TemporaryDirectory() as temporary:
            paths = _write_artifacts(
                Path(temporary),
                pe_bytes=_fixture_pe(
                    code=code, slot_word=0, other_slot_word=0
                ),
                rows=mismatched_rows,
            )
            plan = construct_reachable_static_pointer_slot_proposal(
                *paths, SLOT_A_RVA
            )
            self.assertIsNone(plan.proposal)
            self.assertIn(
                "state_machine_indirect_target_mismatch",
                {item.category for item in plan.blockers},
            )


if __name__ == "__main__":
    unittest.main()
