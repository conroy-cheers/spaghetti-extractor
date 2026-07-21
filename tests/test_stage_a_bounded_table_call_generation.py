from __future__ import annotations

import copy
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.analyses.control import (
    _attach_reverse_sentinel_table_source_invariants,
    _attach_reverse_sentinel_table_value_targets,
    _bounded_immutable_code_pointer_table_call_inputs,
    _immutable_code_pointer_table_call_candidates,
    _relational_product_graph,
)
from spaghetti_extractor.relational.lean.composition import (
    _lean_bounded_immutable_code_pointer_table_call_claim,
    _write_relational_product_graph_modules,
)
from spaghetti_extractor.stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
)


class StageABoundedTableCallGenerationTests(unittest.TestCase):
    @staticmethod
    def _input_register(register: str) -> dict[str, Any]:
        return {"op": "input_reg", "reg": register}

    @staticmethod
    def _constant(value: int) -> dict[str, Any]:
        return {"op": "constant", "value": value}

    @classmethod
    def _register_arithmetic(
        cls, operation: str, register: str, value: int,
    ) -> dict[str, Any]:
        return {
            "op": operation,
            "left": cls._input_register(register),
            "right": cls._constant(value),
        }

    @classmethod
    def _zero_test(cls, expression: dict[str, Any]) -> dict[str, Any]:
        return {
            "op": "equal",
            "left": expression,
            "right": cls._constant(0),
        }

    @classmethod
    def _nonzero_test(cls, expression: dict[str, Any]) -> dict[str, Any]:
        return {"op": "not", "value": cls._zero_test(expression)}

    @staticmethod
    def _target(
        base: int, index: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": index or {"op": "input_reg", "reg": "eax"},
                    "amount": 2,
                },
                "right": {"op": "constant", "value": base},
            },
        }

    @staticmethod
    def _reverse_sentinel_image(data_rva: int, *, empty: bool) -> bytes:
        image_base = 0x400000
        image = bytearray(_pe32_image_with_immutable_indirect_call(
            data_rva, callee_rva=0x1030,
        ))
        table_words = [0xFFFFFFFF]
        if not empty:
            table_words.append(image_base + 0x1030)
        table_words.append(0)
        table = struct.pack(
            "<" + "I" * len(table_words), *table_words
        )

        section_table = 0x80 + 4 + 20 + 224
        rdata_section = section_table + 40
        struct.pack_into("<I", image, rdata_section + 8, len(table))
        image[0x400:0x400 + len(table)] = table

        first_relocation_size = struct.unpack_from("<I", image, 0x604)[0]
        data_relocation = 0x600 + first_relocation_size
        struct.pack_into(
            "<H", image, data_relocation + 8,
            0 if empty else 0x3004,
        )
        return bytes(image)

    @classmethod
    def _reverse_sentinel_fixture(
        cls, root: Path, *, empty: bool = False,
    ) -> tuple[StageABinary, StageABinary, dict[str, Any], list[dict[str, Any]]]:
        original_path = root / "original.exe"
        candidate_path = root / "candidate.exe"
        original_path.write_bytes(cls._reverse_sentinel_image(0x2000, empty=empty))
        candidate_path.write_bytes(cls._reverse_sentinel_image(0x3000, empty=empty))
        original = _parse_stage_a_pe(original_path)
        candidate = _parse_stage_a_pe(candidate_path)

        region_rvas = [
            0x1000, 0x101D, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070,
        ]
        targets = [
            {
                "id": index,
                "region_index": index,
                "original_rva": rva,
                "candidate_rva": rva,
                "original_aliases": [],
                "candidate_aliases": [],
            }
            for index, rva in enumerate(region_rvas)
        ]
        region_names = [
            "table-call", "continuation", "callee", "scanner-setup",
            "reverse-decrement", "nonzero-gate", "sentinel-scanner",
        ]
        entry_count = 0 if empty else 1
        shifted_index = cls._register_arithmetic("sub", "eax", 1)
        regions = [
            {
                "id": name,
                "numeric_id": index,
                "function_id": "reverse-sentinel-table-call",
                "root": index == 3,
                "original": {"rva_start": region_rvas[index]},
                "candidate": {"rva_start": region_rvas[index]},
                "bounds": ([{
                    "original": "eax",
                    "candidate": "eax",
                    "original_expression": shifted_index,
                    "candidate_expression": shifted_index,
                    "unsigned_lt": entry_count,
                    "expression_source": (
                        "lean_checked_reverse_sentinel_table_source_invariant"
                    ),
                }] if index == 0 else []),
                "input_relations": ([{
                    "original": "eax",
                    "candidate": "eax",
                    "relation": "exact",
                }] if index == 0 and not empty else []),
                "code_targets": [targets[index]],
            }
            for index, name in enumerate(region_names)
        ]
        table_size = 8 if empty else 12
        contract = {
            "code_targets": targets,
            "value_targets": [{
                "id": 0,
                "original_value": original.image_base + 0x2000,
                "candidate_value": candidate.image_base + 0x3000,
                "original_relocation_rva": 0x2000,
                "candidate_relocation_rva": 0x3000,
                "mapped_size": table_size,
                "relocation_offsets": [] if empty else [4],
            }],
            "regions": regions,
        }

        original_index = cls._input_register("eax")
        candidate_index = cls._input_register("eax")
        original_decrement = cls._register_arithmetic("sub", "eax", 1)
        candidate_decrement = cls._register_arithmetic("sub", "eax", 1)
        original_scan_index = cls._register_arithmetic("add", "ecx", 1)
        candidate_scan_index = cls._register_arithmetic("add", "ecx", 1)
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_call",
                    "continuation": 1,
                    "target": cls._target(
                        original.image_base + 0x2000, original_index,
                    ),
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_call",
                    "continuation": 1,
                    "target": cls._target(
                        candidate.image_base + 0x3000, candidate_index,
                    ),
                }},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
            {
                "original_ir": {
                    "registers": {
                        "eax": {
                            "op": "read32",
                            "address": cls._constant(
                                original.image_base + 0x2000
                            ),
                        },
                        "ecx": cls._constant(0),
                    },
                    "outcome": {"op": "jump", "target": 6},
                },
                "candidate_ir": {
                    "registers": {
                        "eax": {
                            "op": "read32",
                            "address": cls._constant(
                                candidate.image_base + 0x3000
                            ),
                        },
                        "ecx": cls._constant(0),
                    },
                    "outcome": {"op": "jump", "target": 6},
                },
            },
            {
                "original_ir": {
                    "registers": {"eax": original_decrement},
                    "outcome": {
                        "op": "branch",
                        "condition": cls._nonzero_test(original_decrement),
                        "taken": 0,
                        "fallthrough": 1,
                    },
                },
                "candidate_ir": {
                    "registers": {"eax": candidate_decrement},
                    "outcome": {
                        "op": "branch",
                        "condition": cls._nonzero_test(candidate_decrement),
                        "taken": 0,
                        "fallthrough": 1,
                    },
                },
            },
            {
                "original_ir": {"outcome": {
                    "op": "branch",
                    "condition": cls._zero_test(original_index),
                    "taken": 1,
                    "fallthrough": 0,
                }},
                "candidate_ir": {"outcome": {
                    "op": "branch",
                    "condition": cls._zero_test(candidate_index),
                    "taken": 1,
                    "fallthrough": 0,
                }},
            },
            {
                "original_ir": {
                    "registers": {
                        "ecx": original_scan_index,
                        "eax": cls._input_register("ecx"),
                        "edx": cls._target(
                            original.image_base + 0x2000,
                            original_scan_index,
                        ),
                    },
                    "outcome": {
                        "op": "branch",
                        "condition": cls._zero_test(cls._input_register("edx")),
                        "taken": 6,
                        "fallthrough": 5,
                    },
                },
                "candidate_ir": {
                    "registers": {
                        "ecx": candidate_scan_index,
                        "eax": cls._input_register("ecx"),
                        "edx": cls._target(
                            candidate.image_base + 0x3000,
                            candidate_scan_index,
                        ),
                    },
                    "outcome": {
                        "op": "branch",
                        "condition": cls._zero_test(cls._input_register("edx")),
                        "taken": 6,
                        "fallthrough": 5,
                    },
                },
            },
        ]
        return original, candidate, contract, behaviors

    @classmethod
    def _fixture(
        cls, root: Path,
    ) -> tuple[StageABinary, StageABinary, dict[str, Any], list[dict[str, Any]]]:
        original_path = root / "original.exe"
        candidate_path = root / "candidate.exe"
        original_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x2000, callee_rva=0x1030,
        ))
        candidate_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x3000, callee_rva=0x1030,
        ))
        original = _parse_stage_a_pe(original_path)
        candidate = _parse_stage_a_pe(candidate_path)
        targets = [
            {
                "id": 0, "region_index": 0,
                "original_rva": 0x1000, "candidate_rva": 0x1000,
                "original_aliases": [], "candidate_aliases": [],
            },
            {
                "id": 1, "region_index": 1,
                "original_rva": 0x101D, "candidate_rva": 0x101D,
                "original_aliases": [], "candidate_aliases": [],
            },
            {
                "id": 2, "region_index": 2,
                "original_rva": 0x1030, "candidate_rva": 0x1030,
                "original_aliases": [], "candidate_aliases": [],
            },
        ]
        contract = {
            "code_targets": targets,
            "value_targets": [{
                "id": 0,
                "original_value": original.image_base + 0x2000,
                "candidate_value": candidate.image_base + 0x3000,
                "original_relocation_rva": 0x2000,
                "candidate_relocation_rva": 0x3000,
                "mapped_size": 4,
                "relocation_offsets": [0],
            }],
            "regions": [
                {
                    "id": "table-call", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                    "bounds": [{
                        "original": "eax", "candidate": "eax", "unsigned_lt": 1,
                    }],
                    "input_relations": [{
                        "original": "eax", "candidate": "eax", "relation": "exact",
                    }],
                    "code_targets": [targets[2]],
                },
                {
                    "id": "continuation", "numeric_id": 1,
                    "original": {"rva_start": 0x101D},
                    "candidate": {"rva_start": 0x101D},
                    "bounds": [], "code_targets": [],
                },
                {
                    "id": "callee", "numeric_id": 2,
                    "original": {"rva_start": 0x1030},
                    "candidate": {"rva_start": 0x1030},
                    "bounds": [], "code_targets": [],
                },
            ],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 1,
                    "target": cls._target(original.image_base + 0x2000),
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 1,
                    "target": cls._target(candidate.image_base + 0x3000),
                }},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
        ]
        return original, candidate, contract, behaviors

    @staticmethod
    def _inputs(
        original: StageABinary,
        candidate: StageABinary,
        contract: dict[str, Any],
        behaviors: list[dict[str, Any]],
        proposals: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return _bounded_immutable_code_pointer_table_call_inputs(
            contract,
            behaviors,
            proposals,
            original_bin=original,
            candidate_bin=candidate,
            original_image_base=original.image_base,
            candidate_image_base=candidate.image_base,
        )

    def test_direct_bounded_table_call_generates_finite_graph_and_lean_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, behaviors = self._fixture(root)
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )
            analysis = self._inputs(
                original, candidate, contract, behaviors, proposals
            )
            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_call_candidates=analysis["candidates"],
            )
            lean_dir = root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)
            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0, 1, 2]]
            )
            decoded_source = (
                lean_dir / "StageA" / "RelationalProductDecodedControlChunk0.lean"
            ).read_text()

        self.assertEqual(analysis["status"], "candidate_requires_lean_replay")
        self.assertFalse(analysis["acceptance_authority"])
        self.assertEqual(analysis["incomplete"], [])
        accepted = analysis["candidates"][0]
        self.assertEqual(accepted["entry_target_ids"], [2])
        self.assertEqual(accepted["target_ids"], [2])
        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
        self.assertEqual(graph["edges"][0]["kind"], "call")
        self.assertEqual(graph["edges"][0]["target_node_id"], 2)
        self.assertEqual(graph["edges"][0]["original_guard"], {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 0},
        })
        self.assertEqual(graph["edges"][0]["candidate_guard"], {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 0},
        })
        self.assertEqual(
            graph["evidence"][
                "bounded_immutable_code_pointer_table_call_edge_groups"
            ],
            [{"source_node_id": 0, "candidate_index": 0, "edge_ids": [0]}],
        )
        self.assertIn(0, graph["evidence"]["decoded_control_complete_node_ids"])
        self.assertEqual(
            graph["evidence"]["runtime_call_continuations"],
            [{"source_node_id": 0, "continuation_node_ids": [1]}],
        )
        self.assertEqual(
            graph["evidence"]["reachable_decoded_control_frontier_node_ids"], []
        )
        self.assertIn("ImmutableCodePointerTableRow", decoded_source)
        self.assertIn("import StageA.RelationalStaticContext\n", decoded_source)
        self.assertIn("BoundedImmutableCodePointerTableCallClaim", decoded_source)
        self.assertIn("BoundedImmutableCodePointerTableCallTargetsClosed", decoded_source)
        self.assertIn(
            "NodeBoundedImmutableCodePointerTableCallEdgesComplete", decoded_source
        )
        self.assertIn("valueTargetId := 0", decoded_source)
        self.assertIn("tableOffset := 0", decoded_source)
        self.assertIn("originalIndexRegister := .eax", decoded_source)
        self.assertIn("{ index := 0, targetId := 2 }", decoded_source)
        self.assertIn("continuationTargetId := 1", decoded_source)
        serialized = _lean_bounded_immutable_code_pointer_table_call_claim(accepted)
        self.assertIn("layout := .zeroBasedBounded", serialized)
        self.assertIn("upperExclusive := 1", serialized)
        self.assertIn("rows := [{ index := 0, targetId := 2 }]", serialized)

    def test_reverse_sentinel_nonempty_table_canonicalizes_callable_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                Path(temporary)
            )
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )

            self.assertEqual(len(proposals), 1)
            proposal = proposals[0]
            self.assertEqual(
                proposal["index_evidence"]["kind"],
                "paired_sentinel_terminated_reverse_count",
            )
            self.assertEqual(
                {
                    key: proposal["index_evidence"][key]
                    for key in (
                        "header_producer_region_index",
                        "nonzero_predecessor_region_index",
                        "decrement_region_index",
                        "scanner_initializer_region_index",
                        "scanner_region_index",
                        "scanner_loop_region_index",
                    )
                },
                {
                    "header_producer_region_index": 3,
                    "nonzero_predecessor_region_index": 5,
                    "decrement_region_index": 4,
                    "scanner_initializer_region_index": 3,
                    "scanner_region_index": 6,
                    "scanner_loop_region_index": 6,
                },
            )
            self.assertEqual(
                [row["kind"] for row in proposal["rows"]],
                ["code_pointer", "null"],
            )
            self.assertEqual(
                [row["original_index"] for row in proposal["rows"]],
                [0, 1],
            )

            analysis = self._inputs(
                original, candidate, contract, behaviors, proposals
            )
            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_call_candidates=analysis["candidates"],
            )

        self.assertEqual(analysis["status"], "candidate_requires_lean_replay")
        self.assertEqual(analysis["incomplete"], [])
        self.assertEqual(len(analysis["candidates"]), 1)
        accepted = analysis["candidates"][0]
        self.assertEqual(accepted["index_evidence"], proposal["index_evidence"])
        self.assertEqual(accepted["layout"], "sentinelTerminatedReverseCount")
        self.assertEqual(accepted["upper_exclusive"], 2)
        self.assertEqual(accepted["value_target_id"], 0)
        self.assertEqual(accepted["table_offset"], 0)
        self.assertEqual(
            [(row["original_index"], row["target_id"]) for row in accepted["rows"]],
            [(1, 2)],
        )
        self.assertEqual(accepted["entry_target_ids"], [2])
        self.assertEqual(accepted["target_ids"], [2])
        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
        self.assertEqual(graph["edges"][0]["kind"], "call")
        self.assertEqual(graph["edges"][0]["target_node_id"], 2)
        self.assertEqual(graph["edges"][0]["original_guard"], {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 1},
        })

    def test_reverse_sentinel_empty_table_generates_impossible_call_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                Path(temporary), empty=True,
            )
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )

            self.assertEqual(len(proposals), 1)
            self.assertEqual(proposals[0]["target_ids"], [])
            self.assertEqual(
                [row["kind"] for row in proposals[0]["rows"]], ["null"]
            )
            analysis = self._inputs(
                original, candidate, contract, behaviors, proposals
            )
            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_call_candidates=analysis["candidates"],
            )

        self.assertEqual(analysis["status"], "candidate_requires_lean_replay")
        self.assertEqual(len(analysis["candidates"]), 1)
        self.assertEqual(
            analysis["candidates"][0]["layout"],
            "sentinelTerminatedReverseCount",
        )
        self.assertEqual(analysis["candidates"][0]["rows"], [])
        self.assertEqual(analysis["incomplete"], [])
        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [])
        self.assertEqual(
            graph["evidence"][
                "bounded_immutable_code_pointer_table_call_edge_groups"
            ],
            [{"source_node_id": 0, "candidate_index": 0, "edge_ids": []}],
        )

    def test_reverse_sentinel_empty_source_is_uninhabited_before_register_synthesis(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                Path(temporary), empty=True,
            )
            contract["regions"][0]["bounds"] = []
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )
            refined = _attach_reverse_sentinel_table_source_invariants(
                contract, proposals
            )
            analysis = self._inputs(
                original, candidate, refined, behaviors, proposals
            )

        self.assertEqual(contract["regions"][0]["bounds"], [])
        self.assertEqual(refined["regions"][0]["bounds"], [])
        self.assertEqual(refined["regions"][0]["state_predicates"], [{
            "original": {"op": "bool_constant", "value": False},
            "candidate": {"op": "bool_constant", "value": False},
            "source": "generated_uninhabited_control_state",
        }])
        self.assertEqual(analysis["status"], "candidate_requires_lean_replay")
        self.assertEqual(analysis["incomplete"], [])

    def test_reverse_sentinel_static_data_target_is_derived_from_exact_pes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                Path(temporary), empty=True,
            )
            contract["value_targets"] = []
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )
            refined = _attach_reverse_sentinel_table_value_targets(
                original, candidate, contract, proposals
            )
            analysis = self._inputs(
                original, candidate, refined, behaviors, proposals
            )

        self.assertEqual(contract["value_targets"], [])
        self.assertEqual(len(refined["value_targets"]), 1)
        target = refined["value_targets"][0]
        self.assertEqual(target["id"], 0)
        self.assertEqual(target["original_value"], original.image_base + 0x2000)
        self.assertEqual(target["candidate_value"], candidate.image_base + 0x3000)
        self.assertEqual(target["mapped_size"], 8)
        self.assertEqual(target["relocation_offsets"], [])
        self.assertEqual(refined["regions"][0]["value_target_ids"], [0])
        self.assertEqual(refined["regions"][0]["values"], [target])
        self.assertEqual(analysis["status"], "candidate_requires_lean_replay")
        self.assertEqual(analysis["incomplete"], [])

    def test_reverse_sentinel_existing_static_data_target_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                Path(temporary)
            )
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )
            first = _attach_reverse_sentinel_table_value_targets(
                original, candidate, contract, proposals
            )
            second = _attach_reverse_sentinel_table_value_targets(
                original, candidate, first, list(reversed(proposals))
            )

        self.assertEqual(len(first["value_targets"]), 1)
        self.assertEqual(second, first)
        self.assertEqual(first["regions"][0]["value_target_ids"], [0])
        self.assertEqual(first["regions"][0]["values"], first["value_targets"])
        self.assertEqual(first["regions"][0]["target_ids"], [0, 2])
        self.assertEqual(first["regions"][6]["value_target_ids"], [0])
        self.assertEqual(first["regions"][6]["target_ids"], [2, 6])

    @staticmethod
    def _rewrite_pe_u32(
        binary: StageABinary, path: Path, rva: int, value: int,
    ) -> StageABinary:
        data = bytearray(binary.path.read_bytes())
        offset = int(binary.pe.get_offset_from_rva(rva))
        struct.pack_into("<I", data, offset, value)
        path.write_bytes(data)
        return _parse_stage_a_pe(path)

    @staticmethod
    def _remove_highlow_relocation(
        binary: StageABinary, path: Path, target_rva: int,
    ) -> StageABinary:
        data = bytearray(binary.path.read_bytes())
        directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        cursor = int(directory.VirtualAddress)
        stop = cursor + int(directory.Size)
        changed = False
        while cursor < stop:
            block = binary.pe.get_data(cursor, 8)
            page_rva = int.from_bytes(block[0:4], "little")
            block_size = int.from_bytes(block[4:8], "little")
            for entry_offset in range(8, block_size, 2):
                entry_rva = cursor + entry_offset
                encoded = int.from_bytes(binary.pe.get_data(entry_rva, 2), "little")
                if encoded >> 12 == 3 and page_rva + (encoded & 0xFFF) == target_rva:
                    file_offset = int(binary.pe.get_offset_from_rva(entry_rva))
                    struct.pack_into("<H", data, file_offset, encoded & 0xFFF)
                    changed = True
            cursor += block_size
        if not changed:
            raise AssertionError(f"missing HIGHLOW relocation at RVA {target_rva:#x}")
        path.write_bytes(data)
        return _parse_stage_a_pe(path)

    def test_reverse_sentinel_static_data_derivation_fails_closed_on_pe_tampering(
        self,
    ) -> None:
        mutations = ("header", "terminator", "relocation")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                    root
                )
                contract["value_targets"] = []
                if mutation == "header":
                    candidate = self._rewrite_pe_u32(
                        candidate, root / "candidate-header.exe", 0x3000, 0,
                    )
                elif mutation == "terminator":
                    candidate = self._rewrite_pe_u32(
                        candidate, root / "candidate-terminator.exe", 0x3008, 1,
                    )
                else:
                    candidate = self._remove_highlow_relocation(
                        candidate, root / "candidate-relocation.exe", 0x3004,
                    )
                proposals = _immutable_code_pointer_table_call_candidates(
                    original, candidate, contract, behaviors
                )
                refined = _attach_reverse_sentinel_table_value_targets(
                    original, candidate, contract, proposals
                )

                self.assertEqual(refined["value_targets"], [])
                self.assertEqual(
                    refined["regions"][0].get("value_target_ids", []), []
                )

    def test_reverse_sentinel_nonempty_table_still_requires_exact_indices(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._reverse_sentinel_fixture(
                Path(temporary)
            )
            contract["regions"][0]["input_relations"] = []
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )
            analysis = self._inputs(
                original, candidate, contract, behaviors, proposals
            )

        self.assertEqual(analysis["status"], "incomplete")
        self.assertEqual(analysis["candidates"], [])
        self.assertEqual(
            analysis["incomplete"][0]["reason"],
            "unique_exact_index_register_relation_required",
        )

    def test_reverse_sentinel_tampering_fails_closed(self) -> None:
        mutations: list[tuple[str, Any]] = [
            (
                "header-producer",
                lambda proposal: proposal["index_evidence"].update({
                    "header_producer_region_index": 4,
                }),
            ),
            (
                "scanner-loop",
                lambda proposal: proposal["index_evidence"].update({
                    "scanner_loop_region_index": 5,
                }),
            ),
            (
                "range-start",
                lambda proposal: proposal["ranges"][0].update({
                    "original_start": proposal["original_base"],
                }),
            ),
            (
                "missing-terminator",
                lambda proposal: proposal.update({
                    "rows": proposal["rows"][:-1],
                }),
            ),
            (
                "callable-slot",
                lambda proposal: proposal["rows"][0].update({
                    "original_slot": proposal["rows"][0]["original_slot"] + 4,
                }),
            ),
            (
                "target-inventory",
                lambda proposal: proposal.update({"target_ids": []}),
            ),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                original, candidate, contract, behaviors = (
                    self._reverse_sentinel_fixture(Path(temporary))
                )
                proposal = _immutable_code_pointer_table_call_candidates(
                    original, candidate, contract, behaviors
                )[0]
                mutate(proposal)

                analysis = self._inputs(
                    original, candidate, contract, behaviors, [proposal]
                )

                self.assertEqual(analysis["status"], "incomplete")
                self.assertEqual(analysis["candidates"], [])
                self.assertEqual(len(analysis["incomplete"]), 1)
                self.assertTrue(analysis["incomplete"][0]["reason"])

    def test_proposal_status_has_no_acceptance_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))
            proposal = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )[0]
            proposal["status"] = "pass"
            proposal["acceptance_authority"] = True

            analysis = self._inputs(
                original, candidate, contract, behaviors, [proposal]
            )

        self.assertEqual(len(analysis["candidates"]), 1)
        self.assertEqual(
            analysis["candidates"][0]["status"], "candidate_requires_lean_replay"
        )
        self.assertFalse(analysis["candidates"][0]["acceptance_authority"])

    def test_unsupported_or_ambiguous_inputs_remain_explicit_incomplete(self) -> None:
        mutations: list[tuple[str, Any, str]] = [
            (
                "cursor",
                lambda proposal, contract, behaviors: proposal.update(
                    {"shape": "cursor_loaded_table_word"}
                ),
                "cursor_loaded_or_non_direct_table_not_supported",
            ),
            (
                "sentinel",
                lambda proposal, contract, behaviors: proposal["index_evidence"].update(
                    {"kind": "reverse_sentinel_table_index"}
                ),
                "unique_checked_unsigned_bound_required",
            ),
            (
                "null",
                lambda proposal, contract, behaviors: proposal["rows"][0].update({
                    "kind": "null", "relocation_backed": False,
                    "original_word": 0, "candidate_word": 0,
                }),
                "null_sentinel_or_non_relocation_row_not_supported",
            ),
            (
                "missing-row",
                lambda proposal, contract, behaviors: proposal.update({"rows": []}),
                "table_rows_do_not_cover_bound",
            ),
            (
                "bad-target",
                lambda proposal, contract, behaviors: (
                    proposal["rows"][0].update({"target_id": 99}),
                    proposal.update({"target_ids": [99]}),
                ),
                "table_row_target_id_is_not_unique",
            ),
            (
                "bad-continuation",
                lambda proposal, contract, behaviors: proposal.update(
                    {"continuation_target_id": 2}
                ),
                "proposal_continuation_is_not_exact",
            ),
            (
                "missing-bound",
                lambda proposal, contract, behaviors: contract["regions"][0].update(
                    {"bounds": []}
                ),
                "unique_checked_unsigned_bound_required",
            ),
            (
                "missing-value-target",
                lambda proposal, contract, behaviors: contract.update(
                    {"value_targets": []}
                ),
                "unique_relocation_backed_value_target_required",
            ),
            (
                "missing-exact-index-relation",
                lambda proposal, contract, behaviors: contract["regions"][0].update(
                    {"input_relations": []}
                ),
                "unique_exact_index_register_relation_required",
            ),
        ]
        for name, mutate, expected_reason in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                original, candidate, contract, behaviors = self._fixture(Path(temporary))
                proposal = _immutable_code_pointer_table_call_candidates(
                    original, candidate, contract, behaviors
                )[0]
                mutate(proposal, contract, behaviors)

                analysis = self._inputs(
                    original, candidate, contract, behaviors, [proposal]
                )
                graph = _relational_product_graph(
                    contract,
                    behaviors,
                    {"edges": []},
                    [],
                    original_image_base=original.image_base,
                    candidate_image_base=candidate.image_base,
                    bounded_table_call_candidates=analysis["candidates"],
                )

                self.assertEqual(analysis["status"], "incomplete")
                self.assertEqual(analysis["candidates"], [])
                self.assertEqual(analysis["incomplete"][0]["reason"], expected_reason)
                self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [])
                self.assertIn(
                    0,
                    graph["evidence"][
                        "reachable_decoded_control_frontier_node_ids"
                    ],
                )

    def test_duplicate_proposals_and_raw_proposals_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))
            proposal = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )[0]
            duplicate_analysis = self._inputs(
                original,
                candidate,
                contract,
                behaviors,
                [proposal, copy.deepcopy(proposal)],
            )

            self.assertEqual(duplicate_analysis["candidates"], [])
            self.assertEqual(
                [row["reason"] for row in duplicate_analysis["incomplete"]],
                ["ambiguous_source_proposals", "ambiguous_source_proposals"],
            )
            with self.assertRaisesRegex(
                StageAInputError, "non-canonical bounded immutable"
            ):
                _relational_product_graph(
                    contract,
                    behaviors,
                    {"edges": []},
                    [],
                    original_image_base=original.image_base,
                    candidate_image_base=candidate.image_base,
                    bounded_table_call_candidates=[proposal],
                )


if __name__ == "__main__":
    unittest.main()
