from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.memory_version_graph_v2 import (
    MemoryVersionGraphV2,
    MemoryVersionGraphV2Error,
    check_memory_version_graph_v2,
    derive_memory_version_graph_v2,
)
from spaghetti_extractor.transition_summary_v2 import derive_transition_summary_v2


PE_SHA256 = "c" * 64


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    memory_events: list[dict[str, object]] | None = None,
    targets: list[int] | None = None,
    outcome: str = "direct_jump",
) -> dict[str, object]:
    events = list(memory_events or [])
    direct_targets = list(targets or [])
    semantics = {
        "pre_state": {
            "registers": {"eax": _reg("eax"), "esp": _reg("esp")},
            "flags": {},
            "memory": {
                "op": "memory",
                "name": "mem0",
                "address_width": 32,
                "value_width": 8,
            },
        },
        "register_writes": [],
        "flag_writes": [],
        "memory_events": events,
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "outcome": {
            "kind": outcome,
            **({"target_rva": direct_targets[0]} if len(direct_targets) == 1 else {}),
        },
        "stack_delta": {"status": "derived", "net_bytes": 0},
        "counts": {
            "register_writes": 0,
            "flag_writes": 0,
            "memory_events": len(events),
            "external_events": 0,
            "faults": 0,
            "ordered_events": 0,
            "edge_conditions": 0,
        },
    }
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva & 0xf:x}" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": semantics,
        "control": {
            "kind": outcome,
            "direct_targets": direct_targets,
            "has_indirect_target": outcome in {"indirect_call", "indirect_jump"},
        },
    }


def _read(address: object, *, rva: int) -> dict[str, object]:
    return {
        "kind": "read",
        "width": 4,
        "instruction_rva": rva,
        "address": address,
    }


def _write(address: object, *, rva: int) -> dict[str, object]:
    return {
        "kind": "write",
        "width": 4,
        "instruction_rva": rva,
        "address": address,
        "value": _reg("eax"),
    }


def _binary(units: list[dict[str, object]]) -> BinaryBinding:
    return BinaryBinding(PE_SHA256, machine_ir_sha256(units))


class MemoryVersionGraphV2Tests(unittest.TestCase):
    def test_overlapping_ranges_share_component_and_branch_join_merges(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                memory_events=[_write(_const(0x401000), rva=0x1001)],
                targets=[0x1100, 0x1200],
                outcome="conditional_branch",
            ),
            _unit(
                "left",
                0x1100,
                memory_events=[_write(_const(0x401002), rva=0x1101)],
                targets=[0x1300],
            ),
            _unit(
                "right",
                0x1200,
                memory_events=[_read(_const(0x401000), rva=0x1201)],
                targets=[0x1300],
            ),
            _unit(
                "join",
                0x1300,
                memory_events=[_read(_const(0x401000), rva=0x1301)],
                outcome="return",
            ),
        ]
        binary = _binary(units)
        summaries = [derive_transition_summary_v2(row, binary=binary) for row in units]

        graph = derive_memory_version_graph_v2(
            units=units,
            binary=binary,
            transition_summaries=summaries,
        )

        self.assertEqual(graph.status, "complete")
        self.assertEqual(len(graph.alias_components), 1)
        self.assertEqual(
            {(row.start, row.end) for row in graph.alias_components[0].ranges},
            {(0x401000, 0x401004), (0x401002, 0x401006)},
        )
        join_merges = [row for row in graph.merges if row.cutpoint.unit_id == "join"]
        self.assertEqual(len(join_merges), 1)
        self.assertEqual(
            [row.predecessor_unit_id for row in join_merges[0].incoming],
            ["left", "right"],
        )
        self.assertEqual(
            check_memory_version_graph_v2(
                graph,
                units=units,
                binary=binary,
                transition_summaries=summaries,
            ),
            graph,
        )

    def test_unknown_write_kills_all_affected_components_and_is_incomplete(self) -> None:
        units = [
            _unit(
                "known-a",
                0x1000,
                memory_events=[_write(_const(0x401000), rva=0x1001)],
                targets=[0x1100],
            ),
            _unit(
                "known-b",
                0x1100,
                memory_events=[_write(_const(0x402000), rva=0x1101)],
                targets=[0x1200],
            ),
            _unit(
                "unknown",
                0x1200,
                memory_events=[_write(_reg("eax"), rva=0x1201)],
                outcome="return",
            ),
        ]
        graph = derive_memory_version_graph_v2(
            units=units,
            binary=_binary(units),
            unknown_alias_policy="fail_closed",
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertEqual(len(graph.alias_components), 3)
        self.assertEqual(
            sum(row.contains_unknown_address for row in graph.alias_components),
            1,
        )
        self.assertEqual(len(graph.unknown_write_kills), 1)
        self.assertEqual(
            {row.code for row in graph.issues},
            {"unknown_write_alias"},
        )
        self.assertEqual(
            graph.unknown_write_kills[0].affected_scope,
            "all_components",
        )
        self.assertEqual(graph.unknown_write_kills[0].affected_component_ids, ())

    def test_stack_relative_write_does_not_kill_concrete_components(self) -> None:
        stack_address = {
            "op": "add32",
            "args": [_reg("esp"), _const(8)],
        }
        units = [
            _unit(
                "global",
                0x1000,
                memory_events=[_write(_const(0x401000), rva=0x1001)],
                targets=[0x1100],
            ),
            _unit(
                "stack",
                0x1100,
                memory_events=[_write(stack_address, rva=0x1101)],
                outcome="return",
            ),
        ]

        graph = derive_memory_version_graph_v2(
            units=units,
            binary=_binary(units),
        )

        self.assertEqual(graph.status, "complete")
        self.assertEqual(
            {row.address_class for row in graph.alias_components},
            {"concrete", "stack_frame"},
        )
        self.assertEqual(len(graph.unknown_write_kills), 1)
        kill = graph.unknown_write_kills[0]
        stack_component = next(
            row for row in graph.alias_components
            if row.address_class == "stack_frame"
        )
        self.assertEqual(kill.affected_scope, "finite_components")
        self.assertEqual(kill.affected_component_ids, (stack_component.component_id,))

    def test_sparse_graph_does_not_form_unit_component_cartesian_product(self) -> None:
        unit_count = 200
        units = [
            _unit(
                f"unit-{index}",
                0x1000 + index * 0x10,
                memory_events=[
                    _write(_const(0x500000 + index * 0x10), rva=0x1001 + index * 0x10)
                ],
                targets=(
                    [0x1000 + (index + 1) * 0x10]
                    if index + 1 < unit_count
                    else []
                ),
                outcome="direct_jump" if index + 1 < unit_count else "return",
            )
            for index in range(unit_count)
        ]
        units.append(
            _unit(
                "unknown-write",
                0x3000,
                memory_events=[_write(_reg("eax"), rva=0x3001)],
                outcome="return",
            )
        )

        graph = derive_memory_version_graph_v2(
            units=units,
            binary=_binary(units),
            unknown_alias_policy="fail_closed",
        )

        self.assertEqual(len(graph.alias_components), unit_count + 1)
        self.assertEqual(len(graph.access_versions), unit_count + 1)
        self.assertEqual(len(graph.versions), 2 * (unit_count + 1))
        self.assertEqual(len(graph.merges), 0)
        self.assertEqual(len(graph.unknown_write_kills), 1)
        self.assertLess(
            len(graph.access_versions),
            len(units) * len(graph.alias_components),
        )

    def test_loop_carried_memory_uses_a_self_referential_merge(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                memory_events=[_write(_const(0x401000), rva=0x1001)],
                targets=[0x1100],
            ),
            _unit(
                "loop",
                0x1100,
                memory_events=[_read(_const(0x401000), rva=0x1101)],
                targets=[0x1100],
            ),
        ]

        graph = derive_memory_version_graph_v2(
            units=units,
            binary=_binary(units),
        )

        self.assertEqual(graph.status, "complete")
        loop_merges = [
            row for row in graph.merges if row.cutpoint.unit_id == "loop"
        ]
        self.assertEqual(len(loop_merges), 1)
        merge = loop_merges[0]
        self.assertEqual(
            [row.predecessor_unit_id for row in merge.incoming],
            ["entry", "loop"],
        )
        self.assertEqual(
            next(row.version_id for row in merge.incoming if row.predecessor_unit_id == "loop"),
            merge.merge_id,
        )

    def test_merge_all_policy_is_explicit_but_still_non_authorizing(self) -> None:
        units = [
            _unit(
                "mixed",
                0x1000,
                memory_events=[
                    _write(_const(0x401000), rva=0x1001),
                    _write(_const(0x402000), rva=0x1002),
                    _write(_reg("eax"), rva=0x1003),
                ],
                outcome="return",
            )
        ]
        graph = derive_memory_version_graph_v2(
            units=units,
            binary=_binary(units),
            unknown_alias_policy="merge_all",
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertEqual(len(graph.alias_components), 1)
        payload = graph.to_payload()
        self.assertEqual(payload["partition_authority"], "optimization_only")
        self.assertTrue(payload["alias_components"][0]["contains_unknown_address"])

    def test_stale_summary_and_corrupt_partition_are_rejected(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                memory_events=[_write(_const(0x401000), rva=0x1001)],
                outcome="return",
            )
        ]
        binary = _binary(units)
        summary = derive_transition_summary_v2(units[0], binary=binary)
        graph = derive_memory_version_graph_v2(
            units=units,
            binary=binary,
            transition_summaries=[summary],
        )
        changed = copy.deepcopy(units)
        changed[0]["semantics"]["memory_events"][0]["address"]["value"] = 0x403000

        with self.assertRaises(MemoryVersionGraphV2Error):
            derive_memory_version_graph_v2(
                units=changed,
                binary=binary,
                transition_summaries=[summary],
            )

        corrupt = copy.deepcopy(graph.to_payload())
        corrupt["alias_components"][0]["ranges"][0]["end"] += 1
        with self.assertRaises(MemoryVersionGraphV2Error):
            check_memory_version_graph_v2(
                corrupt,
                units=units,
                binary=binary,
                transition_summaries=[summary],
            )

    def test_indirect_control_remains_an_explicit_frontier(self) -> None:
        unit = _unit("dispatch", 0x1000, outcome="indirect_jump")
        unit["semantics"]["outcome"]["target"] = _reg("eax")
        graph = derive_memory_version_graph_v2(
            units=[unit],
            binary=_binary([unit]),
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertIn(
            "indirect_control_requires_target_certificate",
            {row.code for row in graph.issues},
        )

    def test_incomplete_transition_summary_cannot_yield_complete_memory_graph(self) -> None:
        unit = _unit(
            "entry",
            0x1000,
            memory_events=[_write(_const(0x401000), rva=0x1001)],
            outcome="return",
        )
        unit["semantics"]["memory_events"][0]["value"] = {
            "op": "unsupported",
            "reason": "fixture",
        }
        graph = derive_memory_version_graph_v2(
            units=[unit],
            binary=_binary([unit]),
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertIn(
            "transition_summary_incomplete",
            {row.code for row in graph.issues},
        )


if __name__ == "__main__":
    unittest.main()
