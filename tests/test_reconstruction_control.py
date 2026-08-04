from __future__ import annotations

import json
import unittest
from typing import Any

from spaghetti_extractor.reconstruction_control import (
    derive_rooted_reachable_units,
    propose_semantic_clusters,
    recover_static_pe32_jump_table_inventory,
)


IMAGE_BASE = 0x400000
TABLE_RVA = 0x2000


def _constant(value: int) -> dict[str, Any]:
    return {"op": "constant", "value": value}


def _index() -> dict[str, Any]:
    return {"op": "input_reg", "reg": "eax"}


def _table_expression() -> dict[str, Any]:
    return {
        "op": "load",
        "width": 4,
        "address": {
            "op": "add",
            "left": _constant(IMAGE_BASE + TABLE_RVA),
            "right": {
                "op": "mul",
                "left": _index(),
                "right": _constant(4),
            },
        },
    }


def _guarded_predecessor(upper_exclusive: int) -> dict[str, Any]:
    return {
        "source_unit_id": "guard",
        "edge_kind": "fallthrough",
        "guard": {
            "op": "unsigned_less",
            "left": _index(),
            "right": _constant(upper_exclusive),
        },
        "instructions": [
            {
                "mnemonic": "cmp",
                "operands": [
                    {"kind": "register", "name": "eax", "width_bits": 32},
                    {
                        "kind": "immediate",
                        "value": upper_exclusive - 1,
                        "width_bits": 32,
                    },
                ],
            },
            {
                "mnemonic": "ja",
                "operands": [
                    {"kind": "immediate", "value": IMAGE_BASE + 0x1700}
                ],
            },
        ],
    }


def _sections(*, writable_table: bool = False) -> list[dict[str, Any]]:
    return [
        {
            "name": ".text",
            "rva_start": 0x1000,
            "rva_end": 0x1800,
            "readable": True,
            "writable": False,
            "executable": True,
        },
        {
            "name": ".rdata" if not writable_table else ".data",
            "rva_start": TABLE_RVA,
            "rva_end": 0x2400,
            "readable": True,
            "writable": writable_table,
            "executable": False,
        },
    ]


def _reader(table_bytes: bytes):
    def read_rva(rva: int, size: int) -> bytes:
        if not TABLE_RVA <= rva <= TABLE_RVA + len(table_bytes):
            return b""
        offset = rva - TABLE_RVA
        return table_bytes[offset : offset + size]

    return read_rva


def _table_bytes(target_rvas: list[int]) -> bytes:
    return b"".join(
        (IMAGE_BASE + target_rva).to_bytes(4, "little")
        for target_rva in target_rvas
    )


class StaticPE32JumpTableTests(unittest.TestCase):
    def test_recovers_guarded_36_entry_inventory_deterministically(self) -> None:
        target_rvas = [0x1100 + (index % 6) * 0x10 for index in range(36)]
        kwargs = {
            "target_expression": _table_expression(),
            "predecessor_evidence": [_guarded_predecessor(36)],
            "image_base": IMAGE_BASE,
            "sections": _sections(),
            "read_rva": _reader(_table_bytes(target_rvas)),
            "valid_target_rvas": set(target_rvas),
        }

        first = recover_static_pe32_jump_table_inventory(**kwargs)
        second = recover_static_pe32_jump_table_inventory(**kwargs)

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(first["status"], "recovered")
        self.assertEqual(first["closure"], "checked_finite_target_inventory")
        self.assertEqual(first["index"]["upper_exclusive"], 36)
        self.assertEqual(
            first["index"]["bound_evidence"],
            [
                {
                    "source_unit_id": "guard",
                    "upper_exclusive": 36,
                    "sources": ["guard", "instructions"],
                }
            ],
        )
        self.assertEqual(first["table"]["entry_count"], 36)
        self.assertEqual(len(first["entries"]), 36)
        self.assertEqual(first["target_rvas"], sorted(set(target_rvas)))

    def test_recovers_machine_ir_add32_mul32_and_masked_byte_index(self) -> None:
        target_rvas = [0x1100 + (index % 3) * 0x10 for index in range(36)]
        index = {
            "op": "and32",
            "args": [
                {"op": "const", "value": 255, "width": 32},
                {"op": "reg", "name": "eax", "width": 32},
            ],
        }
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": IMAGE_BASE + TABLE_RVA, "width": 32},
                    {
                        "op": "mul32",
                        "args": [index, {"op": "const", "value": 4, "width": 32}],
                    },
                ],
            },
        }
        predecessor = {
            "source_unit_id": "guard",
            "edge_kind": "fallthrough",
            "instructions": [
                {
                    "mnemonic": "cmp",
                    "operands": [
                        {"kind": "register", "name": "al", "width_bits": 8},
                        {"kind": "immediate", "value": 35, "width_bits": 8},
                    ],
                },
                {"mnemonic": "ja", "operands": []},
            ],
        }

        result = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[predecessor],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            valid_target_rvas=set(target_rvas),
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["upper_exclusive"], 36)
        self.assertEqual(result["table"]["expression_form"], "multiply_4")

    def test_unresolved_or_ambiguous_bounds_do_not_read_a_table(self) -> None:
        reads = []

        def reader(rva: int, size: int) -> bytes:
            reads.append((rva, size))
            return b""

        missing = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=reader,
        )
        ambiguous = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[
                _guarded_predecessor(36),
                {**_guarded_predecessor(35), "source_unit_id": "other-guard"},
            ],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=reader,
        )

        self.assertEqual(missing["status"], "incomplete")
        self.assertEqual(missing["failure"]["code"], "missing_predecessor_evidence")
        self.assertEqual(ambiguous["failure"]["code"], "ambiguous_index_bound")
        self.assertEqual(missing["target_rvas"], [])
        self.assertEqual(ambiguous["target_rvas"], [])
        self.assertEqual(reads, [])

    def test_writable_table_and_invalid_target_fail_closed(self) -> None:
        targets = [0x1100, 0x1110]
        writable = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[_guarded_predecessor(2)],
            image_base=IMAGE_BASE,
            sections=_sections(writable_table=True),
            read_rva=_reader(_table_bytes(targets)),
            valid_target_rvas=targets,
        )
        invalid_target = recover_static_pe32_jump_table_inventory(
            target_expression=_table_expression(),
            predecessor_evidence=[_guarded_predecessor(2)],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(
                _table_bytes([targets[0]]) + (IMAGE_BASE + TABLE_RVA).to_bytes(4, "little")
            ),
            valid_target_rvas=targets,
        )

        self.assertEqual(writable["failure"]["code"], "writable_table")
        self.assertEqual(writable["entries"], [])
        self.assertEqual(invalid_target["failure"]["code"], "invalid_table_target")
        self.assertEqual(invalid_target["entries"], [])


class RootedReachabilityTests(unittest.TestCase):
    def test_unreachable_is_reported_only_after_complete_closure(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "child", "isolated"],
            roots=["root"],
            direct_edges=[
                {"source_unit_id": "root", "target_unit_id": "child"}
            ],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reachable_units"], ["child", "root"])
        self.assertEqual(result["potential_units"], [])
        self.assertEqual(result["unreachable_units"], ["isolated"])

    def test_unresolved_edge_from_unreachable_unit_does_not_block_closure(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "isolated"],
            roots=["root"],
            direct_edges=[
                {"source_unit_id": "isolated", "target_unit_id": "missing"}
            ],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["potential_units"], [])
        self.assertEqual(result["unreachable_units"], ["isolated"])
        self.assertEqual(result["frontiers"], [])
        self.assertEqual(result["issues"], [])

    def test_unresolved_edge_from_unknown_unit_remains_incomplete(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            direct_edges=[
                {"source_unit_id": "missing", "target_unit_id": "root"}
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["frontiers"], [])
        self.assertEqual(
            result["issues"],
            [
                {
                    "code": "unresolved_direct_edge",
                    "source_unit_id": "missing",
                }
            ],
        )

    def test_unresolved_frontiers_retain_distinct_target_locations(self) -> None:
        result = derive_rooted_reachable_units(
            units=[{"id": "root", "rva": 0x1000}],
            roots=["root"],
            internal_call_edges=[
                {
                    "kind": "internal_call",
                    "source_unit_id": "root",
                    "source_rva": 0x1004,
                    "source_event_index": 0,
                    "target_rva": 0x2000,
                },
                {
                    "kind": "internal_call",
                    "source_unit_id": "root",
                    "source_rva": 0x1004,
                    "source_event_index": 1,
                    "target_rva": 0x3000,
                },
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["frontiers"]), 2)
        self.assertEqual(
            [
                {
                    key: frontier[key]
                    for key in (
                        "source_rva",
                        "source_event_index",
                        "target_rva",
                    )
                }
                for frontier in result["frontiers"]
            ],
            [
                {
                    "source_rva": 0x1004,
                    "source_event_index": 0,
                    "target_rva": 0x2000,
                },
                {
                    "source_rva": 0x1004,
                    "source_event_index": 1,
                    "target_rva": 0x3000,
                },
            ],
        )

    def test_calls_and_finite_indirect_targets_extend_reachability(self) -> None:
        units = [
            {"id": "root", "rva": 0x1000},
            {"id": "dispatch", "rva": 0x1010},
            {"id": "continuation", "rva": 0x1020},
            {"id": "callee", "rva": 0x1100},
            {"id": "case", "rva": 0x1200},
            {"id": "unreachable", "rva": 0x1300},
        ]
        result = derive_rooted_reachable_units(
            units=units,
            roots=(unit_id for unit_id in ["root"]),
            direct_edges=[
                {"source_unit_id": "root", "target_unit_id": "dispatch"},
                {
                    "source_unit_id": "dispatch",
                    "target_unit_id": "continuation",
                },
            ],
            internal_call_edges=[
                {"source_unit_id": "dispatch", "target_rva": 0x1100}
            ],
            recovered_indirect_targets=[
                {
                    "id": "exit:table",
                    "source_unit_id": "callee",
                    "kind": "indirect_jump",
                    "status": "recovered",
                    "target_rvas": [0x1200],
                }
            ],
            indirect_exits=[
                {
                    "id": "exit:table",
                    "source_unit_id": "callee",
                    "kind": "indirect_jump",
                },
                {
                    "id": "exit:unknown",
                    "source_unit_id": "case",
                    "kind": "indirect_call",
                    "target_expression": {"op": "input_reg", "reg": "edx"},
                },
                {
                    "id": "exit:unreachable",
                    "source_unit_id": "unreachable",
                    "kind": "indirect_jump",
                },
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["reachable_units"],
            ["callee", "case", "continuation", "dispatch", "root"],
        )
        self.assertEqual(result["potential_units"], ["unreachable"])
        self.assertEqual(result["unreachable_units"], [])
        self.assertEqual(
            {
                (edge["kind"], edge["source_unit_id"], edge["target_unit_id"])
                for edge in result["edges"]
            },
            {
                ("direct", "root", "dispatch"),
                ("direct", "dispatch", "continuation"),
                ("internal_call", "dispatch", "callee"),
                ("recovered_indirect", "callee", "case"),
            },
        )
        self.assertEqual(
            [frontier["id"] for frontier in result["frontiers"]],
            ["exit:unknown"],
        )
        self.assertEqual(result["frontiers"][0]["reason"], "unresolved_indirect_exit")

    def test_partially_resolved_indirect_inventory_adds_no_edges(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "known"],
            roots=["root"],
            recovered_indirect_targets=[
                {
                    "id": "exit:partial",
                    "source_unit_id": "root",
                    "status": "recovered",
                    "target_unit_ids": ["known", "missing"],
                }
            ],
            indirect_exits=[
                {
                    "id": "exit:partial",
                    "source_unit_id": "root",
                    "kind": "indirect_jump",
                }
            ],
        )

        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["potential_units"], ["known"])
        self.assertEqual(result["unreachable_units"], [])
        self.assertEqual(result["edges"], [])
        self.assertEqual(len(result["frontiers"]), 1)
        self.assertEqual(result["frontiers"][0]["id"], "exit:partial")


class SemanticClusterTests(unittest.TestCase):
    def test_loop_scc_and_maximal_chains_stop_at_cutpoints(self) -> None:
        unit_ids = [
            "root",
            "work",
            "call",
            "continuation",
            "callee",
            "loop-a",
            "loop-b",
            "after-loop",
            "chain-a",
            "chain-b",
            "chain-c",
            "indirect",
            "unreachable",
        ]
        result = propose_semantic_clusters(
            units=unit_ids,
            reachable_units=(
                unit_id for unit_id in unit_ids if unit_id != "unreachable"
            ),
            roots=["root", "chain-a", "callee", "indirect"],
            direct_edges=[
                {"source_unit_id": "root", "target_unit_id": "work"},
                {"source_unit_id": "work", "target_unit_id": "call"},
                {"source_unit_id": "call", "target_unit_id": "continuation"},
                {
                    "source_unit_id": "continuation",
                    "target_unit_id": "loop-a",
                },
                {"source_unit_id": "loop-a", "target_unit_id": "loop-b"},
                {"source_unit_id": "loop-b", "target_unit_id": "loop-a"},
                {
                    "source_unit_id": "loop-b",
                    "target_unit_id": "after-loop",
                },
                {"source_unit_id": "chain-a", "target_unit_id": "chain-b"},
                {"source_unit_id": "chain-b", "target_unit_id": "chain-c"},
            ],
            internal_call_edges=[
                {"source_unit_id": "call", "target_unit_id": "callee"}
            ],
            external_exits=[{"source_unit_id": "after-loop"}, "chain-c"],
            fault_exits=[{"source_unit_id": "callee"}],
            indirect_exits=[{"source_unit_id": "indirect"}],
            max_cluster_units=4,
        )

        by_members = {
            tuple(cluster["unit_ids"]): cluster for cluster in result["clusters"]
        }
        self.assertEqual(result["status"], "complete")
        self.assertEqual(by_members[("loop-a", "loop-b")]["kind"], "loop_scc")
        self.assertIn(("root", "work", "call"), by_members)
        self.assertNotIn("continuation", by_members[("root", "work", "call")]["unit_ids"])
        self.assertIn(("chain-a", "chain-b", "chain-c"), by_members)
        self.assertEqual(result["excluded_unit_ids"], ["unreachable"])
        self.assertEqual(
            {(row["source_unit_id"], row["kind"]) for row in result["cutpoints"]},
            {
                ("after-loop", "external"),
                ("call", "call"),
                ("callee", "fault"),
                ("chain-c", "external"),
                ("indirect", "indirect"),
            },
        )

    def test_size_bound_splits_chains_but_not_loop_sccs(self) -> None:
        chain = propose_semantic_clusters(
            units=["a", "b", "c"],
            direct_edges=[
                {"source_unit_id": "a", "target_unit_id": "b"},
                {"source_unit_id": "b", "target_unit_id": "c"},
            ],
            max_cluster_units=2,
        )
        oversized_loop = propose_semantic_clusters(
            units=["a", "b", "c"],
            direct_edges=[
                {"source_unit_id": "a", "target_unit_id": "b"},
                {"source_unit_id": "b", "target_unit_id": "c"},
                {"source_unit_id": "c", "target_unit_id": "a"},
            ],
            max_cluster_units=2,
        )

        self.assertEqual(
            [cluster["unit_ids"] for cluster in chain["clusters"]],
            [["a", "b"], ["c"]],
        )
        self.assertEqual(chain["status"], "complete")
        self.assertEqual(oversized_loop["status"], "incomplete")
        self.assertEqual(oversized_loop["clusters"], [])
        self.assertEqual(oversized_loop["unclustered_unit_ids"], ["a", "b", "c"])
        self.assertEqual(oversized_loop["issues"][0]["code"], "oversized_loop_scc")


if __name__ == "__main__":
    unittest.main()
