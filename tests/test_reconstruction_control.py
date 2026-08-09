from __future__ import annotations

import json
import unittest
from hashlib import sha256
from typing import Any

from spaghetti_extractor.reconstruction_control import (
    classify_overlapping_instruction_starts,
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

    def test_recovers_immutable_byte_remapped_index(self) -> None:
        target_rvas = [0x1100, 0x1110, 0x1120]
        remap_rva = TABLE_RVA + len(target_rvas) * 4
        remap_values = bytes([2, 0, 1, 2, 1])
        image = _table_bytes(target_rvas) + remap_values
        index = {
            "op": "or32",
            "args": [
                {
                    "op": "and32",
                    "args": [
                        {"op": "const", "value": 0, "width": 32},
                        {"op": "const", "value": 0xFFFFFF00, "width": 32},
                    ],
                },
                {
                    "op": "and32",
                    "args": [
                        {
                            "op": "and32",
                            "args": [
                                {"op": "const", "value": 255, "width": 32},
                                {
                                    "op": "load",
                                    "width": 1,
                                    "address": {
                                        "op": "add32",
                                        "args": [
                                            {
                                                "op": "const",
                                                "value": IMAGE_BASE + remap_rva,
                                                "width": 32,
                                            },
                                            {"op": "reg", "name": "ecx", "width": 32},
                                        ],
                                    },
                                },
                            ],
                        },
                        {"op": "const", "value": 255, "width": 32},
                    ],
                },
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
                        {"kind": "register", "name": "ecx", "width_bits": 32},
                        {"kind": "immediate", "value": 4, "width_bits": 32},
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
            read_rva=_reader(image),
            valid_target_rvas=set(target_rvas),
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["upper_exclusive"], 3)
        self.assertEqual(result["index"]["remap"]["source_upper_exclusive"], 5)
        self.assertEqual(result["index"]["remap"]["possible_values"], [0, 1, 2])
        self.assertEqual(
            result["index"]["remap"]["bytes_sha256"],
            sha256(remap_values).hexdigest(),
        )
        self.assertEqual(result["table"]["entry_count"], 3)

        writable = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[predecessor],
            image_base=IMAGE_BASE,
            sections=_sections(writable_table=True),
            read_rva=_reader(image),
            valid_target_rvas=set(target_rvas),
        )
        self.assertEqual(writable["status"], "incomplete")
        self.assertEqual(writable["failure"]["code"], "writable_index_remap")

    def test_recovers_wrapped_sparse_finite_index_domain(self) -> None:
        target_rvas = [0x1100, 0x1110, 0x1120, 0x1130]
        index = {"op": "reg", "name": "ecx", "width": 32}
        table_address = IMAGE_BASE + TABLE_RVA + 16
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": table_address, "width": 32},
                    {
                        "op": "mul32",
                        "args": [index, {"op": "const", "value": 4, "width": 32}],
                    },
                ],
            },
        }
        values = [0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF]
        domain = {
            "format": "stage-a-finite-u32-expression-domain-v1",
            "status": "complete",
            "source_unit_id": "dispatch",
            "expression_sha256": sha256(
                json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "values": values,
        }

        result = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            finite_index_domain=domain,
            valid_target_rvas=target_rvas,
        )

        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["index"]["values"], values)
        self.assertIsNone(result["index"]["upper_exclusive"])
        self.assertEqual(result["table"]["rva_start"], TABLE_RVA)
        self.assertEqual(result["table"]["rva_end"], TABLE_RVA + 16)
        self.assertTrue(result["table"]["contiguous"])
        self.assertEqual(
            result["table"]["bytes_sha256"],
            sha256(_table_bytes(target_rvas)).hexdigest(),
        )
        self.assertEqual(result["target_rvas"], target_rvas)

        malformed = recover_static_pe32_jump_table_inventory(
            target_expression=expression,
            predecessor_evidence=[],
            image_base=IMAGE_BASE,
            sections=_sections(),
            read_rva=_reader(_table_bytes(target_rvas)),
            finite_index_domain={**domain, "expression_sha256": "0" * 64},
        )
        self.assertEqual(
            malformed["failure"]["code"],
            "invalid_finite_index_domain",
        )

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

    def test_partial_rva_binding_cannot_be_hidden_by_known_unit_ids(self) -> None:
        result = derive_rooted_reachable_units(
            units=[
                {"id": "root", "rva": 0x1000},
                {"id": "known", "rva": 0x1100},
            ],
            roots=["root"],
            recovered_indirect_targets=[
                {
                    "id": "exit:partial-rvas",
                    "source_unit_id": "root",
                    "status": "recovered",
                    "target_rvas": [0x1100, 0x1200],
                    "target_unit_ids": ["known"],
                }
            ],
            indirect_exits=[
                {
                    "id": "exit:partial-rvas",
                    "source_unit_id": "root",
                    "kind": "indirect_jump",
                }
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["edges"], [])
        self.assertEqual(
            [frontier["id"] for frontier in result["frontiers"]],
            ["exit:partial-rvas"],
        )

    def test_finite_external_target_closes_exit_without_internal_edge(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "continuation", "unreachable"],
            roots=["root"],
            direct_edges=[{
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
            recovered_indirect_targets=[{
                "id": "exit:external",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "import": {
                        "dll": "user32.dll",
                        "symbol": "ShowWindow",
                    },
                }],
            }],
            indirect_exits=[{
                "id": "exit:external",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])
        self.assertEqual(result["reachable_units"], ["continuation", "root"])
        self.assertEqual(result["unreachable_units"], ["unreachable"])
        self.assertEqual(
            result["edges"],
            [{
                "kind": "direct",
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
        )

    def test_profile_bound_interface_method_closes_external_exit(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "continuation"],
            roots=["root"],
            direct_edges=[{
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
            recovered_indirect_targets=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "external_protocol": {
                        "kind": "pe32-interface-method",
                        "profile_id": "fixture",
                        "profile_sha256": "a" * 64,
                        "interface_id": "IThing",
                        "method": "Release",
                        "slot": 2,
                        "offset": 8,
                    },
                    "abi": {
                        "template": "pe32-stdcall-v1",
                        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                        "clobbered_registers": ["eax", "ecx", "edx"],
                        "callee_cleanup": True,
                    },
                    "argument_words": 1,
                    "out_interfaces": [],
                }],
            }],
            indirect_exits=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])

    def test_profile_bound_resolved_export_closes_external_exit(self) -> None:
        target = {"dll": "user32.dll", "symbol": "MessageBoxA"}
        abi = {
            "template": "pe32-stdcall-v1",
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
            "callee_cleanup": True,
        }
        contract = {
            "id": "user32.dll!MessageBoxA",
            "import": target,
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 4},
            "disposition": "returns",
            "effect_model": {
                "kind": "exact_native_dll_callthrough_v1",
                "prerequisites": {
                    "same_pinned_dll_implementation": True,
                    "exact_machine_arguments": True,
                    "candidate_address_space_used_directly": True,
                },
            },
            "memory_effect": "nativeCallthrough",
            "memory_footprints": [],
            "world_effect": "nativeCallthrough",
            "callback_effect": "none",
            "result_register_relations": [
                {"register": "eax", "relation": "exact"}
            ],
        }
        result = derive_rooted_reachable_units(
            units=["root", "continuation"],
            roots=["root"],
            direct_edges=[{
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
            recovered_indirect_targets=[{
                "id": "exit:resolved-export",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "external_protocol": {
                        "kind": "pe32-resolved-export",
                        "profile_id": "fixture",
                        "profile_sha256": "c" * 64,
                        "target_id": 1,
                        "resolver_import": {
                            "dll": "kernel32.dll",
                            "symbol": "GetProcAddress",
                        },
                        "loader_import": {
                            "dll": "kernel32.dll",
                            "symbol": "LoadLibraryA",
                        },
                        "module": "user32.dll",
                        "name": "MessageBoxA",
                        "target": target,
                        "transfer_kind": "call",
                        "machine_contract": contract,
                    },
                    "abi": abi,
                    "argument_words": 4,
                    "out_interfaces": [],
                }],
            }],
            indirect_exits=[{
                "id": "exit:resolved-export",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])

    def test_malformed_interface_method_target_remains_frontier(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "external_protocol": {
                        "kind": "pe32-interface-method",
                        "profile_id": "fixture",
                        "profile_sha256": "a" * 64,
                        "interface_id": "IThing",
                        "method": "Release",
                        "slot": 2,
                        "offset": 12,
                    },
                    "abi": {"template": "pe32-stdcall-v1"},
                    "argument_words": 1,
                }],
            }],
            indirect_exits=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["frontiers"]), 1)

    def test_profile_bound_operation_closes_external_exit(self) -> None:
        target = {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": "fixture",
                "profile_sha256": "b" * 64,
                "operation_id": "surface.blt",
                "transfer_kind": "call",
                "selectors": [{
                    "kind": "table_slot",
                    "operation_id": "surface.blt",
                    "view_id": "ISurface",
                    "slot": 7,
                }],
                "environment_contract_id": "surface.blt.environment",
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 6,
            "output_rules": [],
            "environment_contract": {
                "format": "stage-a-external-operation-contract-v1",
                "id": "surface.blt.environment",
                "status": "complete",
                "memory_footprints": [],
                "world_effects": [],
            },
        }
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])

    def test_malformed_operation_abi_remains_frontier(self) -> None:
        target = {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": "fixture",
                "profile_sha256": "b" * 64,
                "operation_id": "surface.blt",
                "transfer_kind": "call",
                "selectors": [{
                    "kind": "table_slot",
                    "operation_id": "surface.blt",
                    "view_id": "ISurface",
                    "slot": 7,
                }],
                "environment_contract_id": "surface.blt.environment",
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": [],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 6,
            "output_rules": [],
            "environment_contract": {
                "format": "stage-a-external-operation-contract-v1",
                "id": "surface.blt.environment",
                "status": "complete",
                "memory_footprints": [],
                "world_effects": [],
            },
        }
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "incomplete")

    def test_malformed_operation_environment_contract_remains_frontier(self) -> None:
        target = {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": "fixture",
                "profile_sha256": "b" * 64,
                "operation_id": "surface.lock",
                "transfer_kind": "call",
                "selectors": [{
                    "kind": "table_slot",
                    "operation_id": "surface.lock",
                    "view_id": "ISurface",
                    "slot": 25,
                }],
                "environment_contract_id": "surface.lock.environment",
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 2,
            "output_rules": [],
            "environment_contract": {
                "format": "stage-a-external-operation-contract-v1",
                "id": "surface.lock.environment",
                "status": "complete",
                "memory_footprints": [{
                    "access": "write",
                    "base_argument": 2,
                    "offset": 0,
                    "size": {"kind": "fixed", "bytes": 4},
                    "nullable": False,
                }],
                "world_effects": [],
            },
        }
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["frontiers"]), 1)

        target["environment_contract"] = {
            "format": "stage-a-external-operation-contract-v1",
            "id": "surface.lock.environment",
            "status": "incomplete",
            "blockers": ["external_memory_footprint_not_authored"],
            "memory_footprints": [],
            "world_effects": [],
        }
        incomplete_contract = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )
        self.assertEqual(incomplete_contract["status"], "incomplete")
        self.assertEqual(len(incomplete_contract["frontiers"]), 1)


class OverlappingInstructionStartTests(unittest.TestCase):
    def test_excludes_untargeted_speculative_start_inside_reached_instruction(self) -> None:
        result = classify_overlapping_instruction_starts(
            units=[
                {
                    "id": "rooted",
                    "rva": 0x1000,
                    "instructions": [{
                        "rva_start": 0x1000,
                        "rva_end": 0x1005,
                        "instruction_sha256": "a" * 64,
                    }],
                },
                {"id": "speculative", "rva": 0x1002, "instructions": []},
            ],
            reachable_unit_ids=["rooted"],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [row["unit_id"] for row in result["excluded_units"]],
            ["speculative"],
        )
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(
            result["excluded_units"][0]["instruction_evidence"][0][
                "instruction_sha256"
            ],
            "a" * 64,
        )

    def test_independently_targeted_inner_start_fails_closed(self) -> None:
        result = classify_overlapping_instruction_starts(
            units=[
                {
                    "id": "rooted",
                    "rva": 0x1000,
                    "instructions": [{
                        "rva_start": 0x1000,
                        "rva_end": 0x1005,
                        "instruction_sha256": "a" * 64,
                    }],
                },
                {"id": "inner", "rva": 0x1002, "instructions": []},
            ],
            reachable_unit_ids=["rooted"],
            target_sources={0x1002: ["direct_control"]},
        )

        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["excluded_units"], [])
        self.assertEqual(result["conflicts"][0]["unit_id"], "inner")
        self.assertEqual(
            result["conflicts"][0]["target_sources"], ["direct_control"]
        )


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
