from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.artifact_formats import SOURCE_TRANSITION_DECLARATIONS_FORMAT
from spaghetti_extractor.relational.lean.runtime_memory_access_proposal import (
    RUNTIME_MEMORY_ACCESS_PROPOSAL_FORMAT,
    RUNTIME_MEMORY_PARTITION_CHECK_INPUTS_FORMAT,
    RuntimeMemoryAccessProposalError,
    generate_runtime_memory_access_proposal,
)


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="ascii",
    )
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reg(name: str) -> dict[str, object]:
    return {"name": name, "op": "reg", "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _add(left: object, right: object) -> dict[str, object]:
    return {"args": [left, right], "op": "add32", "width": 32}


def _sub(left: object, right: object) -> dict[str, object]:
    return {"args": [left, right], "op": "sub32", "width": 32}


def _write(address: object, width: int) -> dict[str, object]:
    return {
        "address": address,
        "kind": "write",
        "value": _const(0),
        "width": width,
    }


def _ordinary_row(rva: int, writes: list[dict[str, object]]) -> dict[str, Any]:
    return {
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "original": {"rva_end": rva + 1, "rva_start": rva, "size": 1},
        "memory_events": writes,
        "ordered_events": [],
        "fpu_state": None,
    }


def _x87_row(rva: int, writes: list[dict[str, object]]) -> dict[str, Any]:
    return {
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "original": {"rva_end": rva + 2, "rva_start": rva, "size": 2},
        "fpu_state": {"model": "exact-x87-schedule"},
        "instruction_effect_schedule": {
            "records": [
                {
                    "effects": {
                        "memory_events": writes,
                        "ordered_events": [],
                    },
                    "instruction_class": "x87_singleton_checked_replay",
                    "rva_start": rva,
                }
            ]
        },
    }


def _ref(name: str) -> dict[str, str]:
    return {
        "declaration": f"StageA.GeneratedEffects.{name}",
        "module": "StageA.GeneratedEffects",
    }


def _target(target_id: int, rva: int, kind: str) -> dict[str, object]:
    evidence = (
        {"checked_effect": _ref(f"checked{target_id}")}
        if kind == "ordinary"
        else {
            "facts": _ref(f"facts{target_id}"),
            "successful_components": _ref(f"components{target_id}"),
        }
    )
    return {
        "evidence": evidence,
        "kind": kind,
        "source_rva": rva,
        "target_id": target_id,
    }


def _fixture(
    root: Path,
    rows: list[dict[str, Any]],
    kinds: list[str],
    *,
    static_bindings: list[dict[str, object]] | None = None,
) -> dict[str, Path]:
    state = _write_jsonl(root / "state-machine.jsonl", rows)
    targets = [
        _target(index, row["original"]["rva_start"], kinds[index])
        for index, row in enumerate(rows)
    ]
    declarations = _write_json(
        root / "source-target-effect-declarations.json",
        {
            "format": SOURCE_TRANSITION_DECLARATIONS_FORMAT,
            "imports": ["StageA.GeneratedEffects"],
            "module_prefix": "GeneratedGnuHelloSourceTransitionIndex",
            "namespace": "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex",
            "original_pe": _ref("originalPe"),
            "original_pe_exact": _ref("originalPeExact"),
            "original_side": _ref("originalSide"),
            "shard_span": 64,
            "source_program_constructor": _ref("sourceProgramConstructor"),
            "targets": targets,
            "world_program": _ref("worldProgram"),
        },
    )
    mixed = _write_json(
        root / "interpreter-mixed-original-plan.json",
        {
            "counts": {
                "reachable_targets": len(targets),
                "regions": len(targets),
            },
            "format": "stage-a-interpreter-mixed-original-v1",
            "reachable_target_ids": list(range(len(targets))),
            "state_machine_sha256": _sha256(state),
            "static_data_bindings": static_bindings or [],
        },
    )
    return {
        "mixed_original_plan": mixed,
        "source_target_effect_declarations": declarations,
        "state_machine": state,
    }


def _generate(root: Path, artifacts: dict[str, Path]):
    generated = generate_runtime_memory_access_proposal(
        root / "out", **artifacts
    )
    proposal = json.loads(generated.proposal.read_text(encoding="ascii"))
    check = json.loads(generated.check_inputs.read_text(encoding="ascii"))
    return generated, proposal, check


class RuntimeMemoryAccessProposalTests(unittest.TestCase):
    def test_esp_ebp_stack_ranges_keep_runtime_aliasing_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _fixture(
                root,
                [
                    _ordinary_row(
                        0x1000,
                        [
                            _write(_sub(_reg("esp"), _const(4)), 4),
                            _write(_add(_reg("ebp"), _const(0xFFFFFFF8)), 8),
                        ],
                    )
                ],
                ["ordinary"],
            )
            generated, proposal, check = _generate(root, artifacts)

            writes = proposal["targets"][0]["writes"]
            self.assertEqual(
                [write["provenance"]["class"] for write in writes],
                ["stack_range", "stack_range"],
            )
            self.assertEqual(
                [write["provenance"]["base_register"] for write in writes],
                ["esp", "ebp"],
            )
            self.assertEqual(
                [write["provenance"]["signed_offset"] for write in writes],
                [-4, -8],
            )
            alias = proposal["targets"][0]["aliasing_obligations"]
            self.assertEqual(alias[0]["relation"], "runtime_base_relation_required")
            self.assertFalse(alias[0]["disjointness_assumed"])
            self.assertTrue(
                writes[0]["checker_obligations"]["protected_static_words"][
                    "required_for_each_exact_protected_word"
                ]
            )
            self.assertEqual(generated.blocked_write_count, 0)
            self.assertTrue(check["ready_for_lean_check"])

    def test_concrete_static_wraparound_and_headroom_are_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            address = (1 << 32) - 2
            artifacts = _fixture(
                root,
                [_ordinary_row(0x1100, [_write(_const(address), 4)])],
                ["ordinary"],
                static_bindings=[
                    {"rva": 0, "size": 2, "va": address}
                ],
            )
            generated, proposal, check = _generate(root, artifacts)

            write = proposal["targets"][0]["writes"][0]
            self.assertEqual(write["provenance"]["class"], "image_static_slot")
            self.assertTrue(write["provenance"]["wraparound"]["footprint_wraps"])
            self.assertFalse(
                write["provenance"]["headroom"]["footprint_within_binding"]
            )
            reasons = {item["reason_code"] for item in proposal["blockers"]}
            self.assertEqual(
                reasons,
                {
                    "concrete_write_footprint_wraparound",
                    "static_binding_headroom_insufficient",
                },
            )
            self.assertEqual(generated.blocked_write_count, 1)
            self.assertFalse(check["ready_for_lean_check"])

    def test_dynamic_range_has_exact_offset_bounds_and_headroom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _fixture(
                root,
                [_ordinary_row(0x1200, [_write(_add(_reg("eax"), _const(12)), 2)])],
                ["ordinary"],
            )
            _, proposal, _ = _generate(root, artifacts)

            provenance = proposal["targets"][0]["writes"][0]["provenance"]
            self.assertEqual(provenance["class"], "dynamic_range")
            self.assertEqual(provenance["signed_offset"], 12)
            self.assertEqual(provenance["headroom"]["bytes_from_base"], 14)
            self.assertEqual(
                provenance["wraparound"]["base_max_inclusive"],
                (1 << 32) - 14,
            )
            self.assertEqual(provenance["wraparound"]["base_min_inclusive"], 0)

    def test_declared_static_slot_is_exact_but_still_needs_word_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            slot_va = 0x402000
            artifacts = _fixture(
                root,
                [_ordinary_row(0x1300, [_write(_const(slot_va + 4), 4)])],
                ["ordinary"],
                static_bindings=[
                    {"rva": 0x2000, "size": 16, "va": slot_va}
                ],
            )
            _, proposal, _ = _generate(root, artifacts)

            write = proposal["targets"][0]["writes"][0]
            self.assertEqual(write["provenance"]["class"], "image_static_slot")
            self.assertEqual(write["provenance"]["binding_offset"], 4)
            self.assertFalse(
                proposal["protected_static_word_policy"]
                ["disjointness_assumed_from_provenance"]
            )
            self.assertEqual(
                write["checker_obligations"]["protected_static_words"]
                ["accepted_resolutions"],
                ["checked_byte_range_disjointness", "explicit_related_update"],
            )
            self.assertTrue(proposal["ready_for_lean_check"])

    def test_x87_schedule_preserves_ten_byte_store_width(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _fixture(
                root,
                [_x87_row(0x1400, [_write(_sub(_reg("ebp"), _const(10)), 10)])],
                ["x87"],
            )
            _, proposal, _ = _generate(root, artifacts)

            write = proposal["targets"][0]["writes"][0]
            self.assertEqual(write["source"], "x87_instruction_schedule")
            self.assertEqual(write["width"], 10)
            self.assertEqual(write["provenance"]["signed_offset"], -10)
            self.assertEqual(write["provenance"]["headroom"]["bytes_before_base"], 10)
            self.assertEqual(
                write["checker_obligations"]["protected_static_words"]
                ["footprint_width"],
                10,
            )

    def test_unknown_two_base_write_is_an_explicit_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _fixture(
                root,
                [_ordinary_row(0x1500, [_write(_add(_reg("eax"), _reg("ecx")), 4)])],
                ["ordinary"],
            )
            generated, proposal, check = _generate(root, artifacts)

            write = proposal["targets"][0]["writes"][0]
            self.assertEqual(write["provenance"]["class"], "unknown")
            self.assertEqual(
                proposal["blockers"][0]["reason_code"],
                "unknown_write_address_provenance",
            )
            self.assertEqual(generated.blocked_write_count, 1)
            self.assertFalse(check["ready_for_lean_check"])

    def test_no_write_target_is_deterministic_and_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _fixture(
                root,
                [_ordinary_row(0x1600, [])],
                ["ordinary"],
            )
            first = generate_runtime_memory_access_proposal(
                root / "first", **artifacts
            )
            second = generate_runtime_memory_access_proposal(
                root / "second", **artifacts
            )
            first_proposal = json.loads(first.proposal.read_text(encoding="ascii"))
            second_proposal = json.loads(second.proposal.read_text(encoding="ascii"))
            check = json.loads(first.check_inputs.read_text(encoding="ascii"))

            self.assertEqual(first_proposal, second_proposal)
            self.assertEqual(first.write_count, 0)
            self.assertEqual(first.ready_target_count, 1)
            self.assertEqual(first_proposal["format"], RUNTIME_MEMORY_ACCESS_PROPOSAL_FORMAT)
            self.assertEqual(
                check["format"], RUNTIME_MEMORY_PARTITION_CHECK_INPUTS_FORMAT
            )
            self.assertEqual(first_proposal["targets"][0]["writes"], [])
            self.assertFalse(first_proposal["artifact_role"]["proof_authority"])
            self.assertFalse(check["artifact_role"]["proof_authority"])
            self.assertEqual(
                first_proposal["targets"][0]["requirement_sha256"],
                check["targets"][0]["requirement_sha256"],
            )

    def test_conflicting_normalized_write_inventories_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = _ordinary_row(0x1680, [_write(_reg("eax"), 4)])
            row["ordered_events"] = [
                {
                    **_write(_reg("ecx"), 4),
                    "family": "memory",
                    "instruction_rva": 0x1680,
                }
            ]
            artifacts = _fixture(root, [row], ["ordinary"])
            _, proposal, check = _generate(root, artifacts)

            self.assertEqual(len(proposal["targets"][0]["writes"]), 2)
            self.assertEqual(
                proposal["blockers"][0]["reason_code"],
                "ambiguous_normalized_write_inventory",
            )
            self.assertFalse(check["ready_for_lean_check"])

    def test_stale_mixed_plan_state_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _fixture(
                root,
                [_ordinary_row(0x1700, [])],
                ["ordinary"],
            )
            mixed = json.loads(
                artifacts["mixed_original_plan"].read_text(encoding="ascii")
            )
            mixed["state_machine_sha256"] = "0" * 64
            _write_json(artifacts["mixed_original_plan"], mixed)

            with self.assertRaisesRegex(
                RuntimeMemoryAccessProposalError,
                "not bound to the exact state machine",
            ):
                generate_runtime_memory_access_proposal(
                    root / "out", **artifacts
                )


if __name__ == "__main__":
    unittest.main()
