import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.relational.analyses.registers import (
    _attach_assembled_immutable_read_address_separations,
    _fixed_immutable_expr_value,
    _infer_register_output_relation,
    _immutable_image_word_read,
    _paired_constant_relation,
    _register_relation_implies,
    _register_relation_join,
    _register_transfer_region_context_sha256,
    _synthesize_register_relations,
)
from spaghetti_extractor.relational.analyses.register_lattice import (
    _register_code_pointer_producer_relation,
)
from spaghetti_extractor.relational.analyses.dataflow import stable_dataflow_graph
from spaghetti_extractor.relational.register_dataflow_aggregate import (
    aggregate_register_dataflow_pack_results,
)
from spaghetti_extractor.relational.register_dataflow_compile import (
    compile_register_dataflow_problem,
)
from spaghetti_extractor.relational.register_dataflow_packs import (
    project_register_dataflow_packs,
)
from spaghetti_extractor.relational.register_dataflow_problem import (
    parse_register_dataflow_problem,
)
from spaghetti_extractor.relational.register_dataflow_solver import (
    solve_register_dataflow_pack,
)
from spaghetti_extractor.relational.register_dataflow_summary import (
    summarize_register_dataflow_pack_result,
)
from spaghetti_extractor.relational.register_transfer_core import canonical_sha256
from spaghetti_extractor.relational.lean.expressions import (
    _lean_register_output_claim,
)
from spaghetti_extractor.relational.analyses.segments import (
    _static_word_relation_supports_register_output,
)
from spaghetti_extractor.relational.pipeline import (
    _stabilize_fixed_code_pointer_register_calls,
)
from spaghetti_extractor.stage_binary import StageAInputError


REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def _input(register: str) -> dict[str, object]:
    return {"op": "input_reg", "reg": register}


def _read(address: int) -> dict[str, object]:
    return {"op": "read32", "address": {"op": "constant", "value": address}}


def _assembled_read(
    address: int,
    *,
    register: str = "esp",
    offset: int = 0xFFFFFFFC,
) -> dict[str, object]:
    def byte(index: int) -> dict[str, object]:
        byte_address = {"op": "constant", "value": address + index}
        return {
            "op": "read8_after_write",
            "address": byte_address,
            "write_address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": register},
                "right": {"op": "constant", "value": offset},
            },
            "write_value": {"op": "constant", "value": 0x401234},
            "prior": {"op": "read8", "address": byte_address},
        }

    bytes_ = [byte(index) for index in range(4)]
    return {
        "op": "bit_or",
        "left": bytes_[0],
        "right": {
            "op": "bit_or",
            "left": {"op": "shift_left", "value": bytes_[1], "amount": 8},
            "right": {
                "op": "bit_or",
                "left": {
                    "op": "shift_left", "value": bytes_[2], "amount": 16,
                },
                "right": {
                    "op": "shift_left", "value": bytes_[3], "amount": 24,
                },
            },
        },
    }


def _pairs() -> list[dict[str, str]]:
    return [
        {
            "original": register,
            "candidate": (
                "edi" if register == "esi"
                else "esi" if register == "edi"
                else register
            ),
        }
        for register in REGISTERS
    ]


def _registers(*, candidate: bool = False) -> dict[str, dict[str, object]]:
    pairs = _pairs()
    if candidate:
        return {
            pair["candidate"]: _input(pair["candidate"])
            for pair in pairs
        }
    return {register: _input(register) for register in REGISTERS}


def _region(index: int, *, root: bool = False) -> dict[str, object]:
    return {
        "id": f"region-{index}",
        "numeric_id": index,
        "root": root,
        "inputs": _pairs(),
        "outputs": _pairs(),
        "values": [],
        "code_targets": [],
    }


def _behavior(
    outcome: dict[str, object],
    *,
    candidate: bool = False,
    fixed_slot: int | None = None,
    clobber_fixed_register: bool = False,
) -> dict[str, object]:
    registers = _registers(candidate=candidate)
    fixed_register = "edi" if candidate else "esi"
    if fixed_slot is not None:
        registers[fixed_register] = _read(fixed_slot)
    if clobber_fixed_register:
        registers[fixed_register] = {"op": "constant", "value": 0}
    return {
        "format": "stage-a-normalized-behavior-v1",
        "registers": registers,
        "x87": {},
        "writes": [],
        "flags": {},
        "outcome": outcome,
    }


class StageARegisterAnalysisTests(unittest.TestCase):
    def test_precomputed_program_solution_replaces_iterative_solver(self) -> None:
        regions = [_region(0, root=True), _region(1)]
        behaviors = [
            {
                "original_ir": _behavior({"op": "jump", "target": 1}),
                "candidate_ir": _behavior(
                    {"op": "jump", "target": 1}, candidate=True,
                ),
            },
            {
                "original_ir": _behavior(
                    {"op": "returned", "target": _input("eax")},
                ),
                "candidate_ir": _behavior(
                    {"op": "returned", "target": _input("eax")},
                    candidate=True,
                ),
            },
        ]
        contract = {
            "code_targets": [
                {
                    "id": index,
                    "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(2)
            ],
            "value_targets": [],
            "static_word_relation_slots": [],
            "regions": regions,
        }

        def binary(sha256: str):
            return SimpleNamespace(
                image_base=0x400000,
                sha256=sha256,
                size_of_headers=4,
                sections=[],
                imports=[],
                pe=SimpleNamespace(
                    get_data=lambda _rva, size: b"\0" * size,
                ),
            )

        original_bin = binary("a" * 64)
        candidate_bin = binary("b" * 64)
        problem = compile_register_dataflow_problem(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
        )
        parse_register_dataflow_problem(
            problem,
            expected_original_sha256=problem["original_sha256"],
            expected_candidate_sha256=problem["candidate_sha256"],
            expected_contract_sha256=problem["contract_sha256"],
            expected_behaviors_sha256=problem["behaviors_sha256"],
        )
        extra_field = copy.deepcopy(problem)
        extra_field["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "fields do not match"):
            parse_register_dataflow_problem(
                extra_field,
                expected_original_sha256=problem["original_sha256"],
                expected_candidate_sha256=problem["candidate_sha256"],
                expected_contract_sha256=problem["contract_sha256"],
                expected_behaviors_sha256=problem["behaviors_sha256"],
            )

        mismatched_graph = copy.deepcopy(problem)
        mismatched_graph["graph"] = stable_dataflow_graph(
            [[1], []],
            region_ids=["region-0", "region-1"],
            transfer_semantics_sha256=["c" * 64, "d" * 64],
        ).to_payload()
        mismatched_graph["problem_sha256"] = canonical_sha256({
            key: value for key, value in mismatched_graph.items()
            if key != "problem_sha256"
        })
        with self.assertRaisesRegex(StageAInputError, "graph_sha256"):
            parse_register_dataflow_problem(
                mismatched_graph,
                expected_original_sha256=problem["original_sha256"],
                expected_candidate_sha256=problem["candidate_sha256"],
                expected_contract_sha256=problem["contract_sha256"],
                expected_behaviors_sha256=problem["behaviors_sha256"],
            )
        projection = project_register_dataflow_packs(
            graph_payload=problem["graph"],
            transfer_table_payload=None,
            transfer_programs_payload=problem["transfer_programs"],
            expected_original_sha256=original_bin.sha256,
            expected_candidate_sha256=candidate_bin.sha256,
        )
        results = {}
        for pack_id in projection.manifest["topological_pack_ids"]:
            pack = projection.inputs[pack_id]
            results[pack_id] = solve_register_dataflow_pack(
                pack_payload=pack,
                predecessor_payloads=[
                    summarize_register_dataflow_pack_result(
                        results[predecessor]
                    )
                    for predecessor in pack["predecessor_ids"]
                ],
                transfer_context_payload=projection.transfer_context,
            )
        aggregate = aggregate_register_dataflow_pack_results(
            manifest_payload=projection.manifest,
            result_payloads=list(results.values()),
        )

        programs: dict[str, object] = {}
        first_metrics: dict[str, int] = {}
        first_contract, first_analysis = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            _solver_metrics=first_metrics,
            _transfer_programs_out=programs,
        )
        reused_programs: dict[str, object] = {}
        reused_metrics: dict[str, int] = {}
        reused_contract, reused_analysis = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            _solver_metrics=reused_metrics,
            _transfer_programs_out=reused_programs,
            _dataflow_aggregate=aggregate,
        )
        self.assertEqual(reused_contract, first_contract)
        self.assertEqual(reused_analysis, first_analysis)
        self.assertEqual(reused_programs, programs)
        self.assertGreater(first_metrics["transfer_evaluations"], 0)
        self.assertEqual(reused_metrics["transfer_evaluations"], 0)

    def test_transfer_context_ignores_unrelated_binary_and_target_identity(self) -> None:
        behavior = {
            "original_ir": _behavior({"op": "returned", "target": _input("eax")}),
            "candidate_ir": _behavior(
                {"op": "returned", "target": _input("eax")},
                candidate=True,
            ),
        }
        common = {
            "behavior_pair": behavior,
            "input_pairs": {register: register for register in REGISTERS},
            "output_pairs": {register: register for register in REGISTERS},
            "original_image_base": 0x400000,
            "candidate_image_base": 0x500000,
            "register_order": REGISTERS,
        }
        baseline = _register_transfer_region_context_sha256(
            contract={
                "value_targets": [],
                "code_targets": [],
                "static_word_relation_slots": [],
            },
            original_bin=SimpleNamespace(sha256="a" * 64),
            candidate_bin=SimpleNamespace(sha256="b" * 64),
            **common,
        )
        unrelated = _register_transfer_region_context_sha256(
            contract={
                "value_targets": [],
                "code_targets": [{
                    "id": 0,
                    "original_rva": 0x1234,
                    "candidate_rva": 0x5678,
                }],
                "static_word_relation_slots": [],
            },
            original_bin=SimpleNamespace(sha256="c" * 64),
            candidate_bin=SimpleNamespace(sha256="d" * 64),
            **common,
        )

        self.assertEqual(baseline, unrelated)

    @patch(
        "spaghetti_extractor.relational.analyses.register_static._immutable_image_u32",
        return_value=7,
    )
    def test_assembled_immutable_word_retains_writes_for_lean(
        self, _immutable_image_u32,
    ) -> None:
        expression = _assembled_read(0x40FF34)
        recovered = _immutable_image_word_read(expression, object())
        self.assertEqual(recovered, (
            0x40FF34,
            [{
                "register": "esp",
                "offset": 0xFFFFFFFC,
                "value": {"op": "constant", "value": 0x401234},
            }],
            True,
            7,
        ))
        self.assertEqual(
            _infer_register_output_relation(
                expression, expression, {}, {}, 0x400000, 0x400000, True,
                original_bin=object(), candidate_bin=object(),
            ),
            ({"relation": "fixed_word", "value": 7},
             "assembled_immutable_image_word"),
        )

    @patch(
        "spaghetti_extractor.relational.analyses.register_static._immutable_image_u32",
        return_value=7,
    )
    def test_assembled_immutable_word_emits_checked_separation_inventory(
        self, _immutable_image_u32,
    ) -> None:
        expression = _assembled_read(0x40FF34)
        contract = {
            "regions": [{
                "outputs": [{"original": "ebx", "candidate": "ebx"}],
                "address_separations": [],
            }],
        }
        behaviors = [{
            "original_ir": {"registers": {"ebx": expression}},
            "candidate_ir": {"registers": {"ebx": expression}},
        }]
        binary = SimpleNamespace(image_base=0x400000)
        refined = _attach_assembled_immutable_read_address_separations(
            contract, behaviors, binary, binary,
        )
        rows = refined["regions"][0]["address_separations"]
        self.assertEqual(len(rows), 16)
        self.assertEqual({row["source"] for row in rows}, {
            "assembled_immutable_word_write_separation",
        })
        self.assertEqual(
            {(row["original_offset"], row["original_address"]) for row in rows},
            {
                ((0xFFFFFFFC + write_byte) & 0xFFFFFFFF, 0x40FF34 + word_byte)
                for write_byte in range(4)
                for word_byte in range(4)
            },
        )
        self.assertEqual(contract["regions"][0]["address_separations"], [])

    @patch(
        "spaghetti_extractor.relational.analyses.register_static._immutable_image_u32",
        return_value=7,
    )
    def test_assembled_indirect_target_emits_checked_separation_inventory(
        self, _immutable_image_u32,
    ) -> None:
        expression = _assembled_read(0x40FF34)
        contract = {
            "regions": [{"outputs": [], "address_separations": []}],
        }
        behaviors = [{
            "original_ir": {
                "registers": {},
                "outcome": {"op": "indirect_call", "target": expression},
            },
            "candidate_ir": {
                "registers": {},
                "outcome": {"op": "indirect_call", "target": expression},
            },
        }]
        binary = SimpleNamespace(image_base=0x400000)

        refined = _attach_assembled_immutable_read_address_separations(
            contract, behaviors, binary, binary,
        )

        rows = refined["regions"][0]["address_separations"]
        self.assertEqual(len(rows), 16)
        self.assertEqual({row["source"] for row in rows}, {
            "assembled_immutable_word_write_separation",
        })

    def test_assembled_immutable_word_serializer_preserves_proof_witness(self) -> None:
        source = _lean_register_output_claim({
            "kind": "immutable_image_word",
            "output": {
                "original": "ebx", "candidate": "ebx", "relation": "exact",
            },
            "original_address": 0x40FF34,
            "candidate_address": 0x40FF34,
            "original_value": 7,
            "candidate_value": 7,
            "original_assembled_read": True,
            "candidate_assembled_read": True,
            "original_writes": [{
                "register": "esp", "offset": 0xFFFFFFFC,
                "value": {"op": "constant", "value": 0x401234},
            }],
            "candidate_writes": [{
                "register": "esp", "offset": 0xFFFFFFFC,
                "value": {"op": "constant", "value": 0x401234},
            }],
        })
        self.assertIn("originalAssembledRead := true", source)
        self.assertIn("candidateAssembledRead := true", source)
        self.assertEqual(source.count("{ register := .esp"), 2)

    def test_fixed_call_proposals_require_a_stable_replayed_fixed_point(self) -> None:
        proposal = {
            "profile": "inductive_fixed_code_pointer_register_call_v1",
            "source_region_index": 1,
            "target_region_index": 3,
            "continuation_region_index": 2,
            "continuation_target_id": 2,
            "target_id": 3,
            "original_register": "esi",
            "candidate_register": "edi",
        }
        contract = {"regions": [{}, {}, {}, {}]}
        analysis = {"indirect_fixed_code_pointer_calls": [proposal]}
        with patch(
            "spaghetti_extractor.relational.pipeline._synthesize_register_relations",
            return_value=(contract, analysis),
        ) as synthesize:
            _normalized, result, combined, fixed_point = (
                _stabilize_fixed_code_pointer_register_calls(
                    contract,
                    [],
                    original_image_base=0x400000,
                    candidate_image_base=0x400000,
                    indirect_call_candidates=[],
                    import_call_candidates=[],
                    original_bin=None,  # type: ignore[arg-type]
                    candidate_bin=None,  # type: ignore[arg-type]
                )
            )
        self.assertEqual(synthesize.call_count, 2)
        self.assertEqual(combined, [proposal])
        self.assertEqual(fixed_point["converged"], True)
        self.assertEqual(result["fixed_code_pointer_call_fixed_point"], fixed_point)

    def test_fixed_call_source_overlap_fails_closed(self) -> None:
        base = {"source_region_index": 1}
        proposal = {
            "profile": "inductive_fixed_code_pointer_register_call_v1",
            "source_region_index": 1,
        }
        contract = {"regions": [{}, {}]}
        analysis = {"indirect_fixed_code_pointer_calls": [proposal]}
        with patch(
            "spaghetti_extractor.relational.pipeline._synthesize_register_relations",
            return_value=(contract, analysis),
        ):
            _normalized, _result, combined, fixed_point = (
                _stabilize_fixed_code_pointer_register_calls(
                    contract,
                    [],
                    original_image_base=0x400000,
                    candidate_image_base=0x400000,
                    indirect_call_candidates=[base],
                    import_call_candidates=[],
                    original_bin=None,  # type: ignore[arg-type]
                    candidate_bin=None,  # type: ignore[arg-type]
                )
            )
        self.assertEqual(combined, [base])
        self.assertEqual(fixed_point["converged"], False)
        self.assertEqual(fixed_point["candidate_count"], 0)

    def test_paired_code_constants_retain_unique_canonical_target(self) -> None:
        contract = {"code_targets": [{
            "id": 0,
            "original_rva": 0x1100,
            "candidate_rva": 0x1200,
            "original_aliases": [0x1110],
            "candidate_aliases": [0x1210],
        }]}
        self.assertEqual(_paired_constant_relation(
            {"op": "constant", "value": 0x401110},
            {"op": "constant", "value": 0x401210},
            contract, 0x400000, 0x400000,
        ), {"relation": "fixed_code_pointer", "target_id": 0})
        ambiguous = {
            "code_targets": [
                {**contract["code_targets"][0], "id": target_id}
                for target_id in range(2)
            ],
        }
        self.assertEqual(_paired_constant_relation(
            {"op": "constant", "value": 0x401110},
            {"op": "constant", "value": 0x401210},
            ambiguous, 0x400000, 0x400000,
        ), "code_pointer")

    def test_equal_constants_retain_checked_fixed_word(self) -> None:
        self.assertEqual(
            _paired_constant_relation(
                {"op": "constant", "value": 0x12345678},
                {"op": "constant", "value": 0x12345678},
                {}, 0x400000, 0x500000,
            ),
            {"relation": "fixed_word", "value": 0x12345678},
        )

    def test_fixed_word_lattice_is_directional(self) -> None:
        word_7 = {"relation": "fixed_word", "value": 7}
        word_8 = {"relation": "fixed_word", "value": 8}

        self.assertEqual(_register_relation_join([word_7, dict(word_7)]), word_7)
        self.assertEqual(_register_relation_join([word_7, word_8]), "exact")
        self.assertEqual(_register_relation_join([word_7, "exact"]), "exact")
        self.assertTrue(_register_relation_implies(word_7, "exact"))
        self.assertFalse(_register_relation_implies("exact", word_7))
        self.assertFalse(_register_relation_implies(word_8, word_7))

    def test_fixed_word_input_supports_equal_pure_expression(self) -> None:
        expression = {
            "op": "add",
            "left": _input("edx"),
            "right": {"op": "constant", "value": 4},
        }
        self.assertEqual(
            _infer_register_output_relation(
                expression, expression,
                {"edx": {"relation": "fixed_word", "value": 0x80}},
                {}, 0x400000, 0x400000, True,
            ),
            ("exact", "lean_exact_memory_free_expression"),
        )

    @patch(
        "spaghetti_extractor.relational.analyses.register_static._immutable_image_u32",
        return_value=0x12345678,
    )
    def test_fixed_word_input_drives_checked_immutable_expression(
        self, _immutable_image_u32,
    ) -> None:
        original_expression = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x400000},
                "right": _input("edx"),
            },
        }
        candidate_expression = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x500000},
                "right": _input("ecx"),
            },
        }
        fixed = {"edx": {"relation": "fixed_word", "value": 0x80}}
        original_bin = SimpleNamespace(image_base=0x400000)
        candidate_bin = SimpleNamespace(image_base=0x500000)

        self.assertEqual(
            _infer_register_output_relation(
                original_expression,
                candidate_expression,
                fixed,
                {},
                0x400000,
                0x500000,
                True,
                original_bin=original_bin,
                candidate_bin=candidate_bin,
                candidate_input_registers={"edx": "ecx"},
            ),
            (
                {"relation": "fixed_word", "value": 0x12345678},
                "fixed_immutable_expression",
            ),
        )
        self.assertEqual(
            _fixed_immutable_expr_value(
                original_expression, original_bin, {"edx": 0x80},
            ),
            0x12345678,
        )
        self.assertEqual(
            _immutable_image_u32.call_args_list[0].args[1], 0x400080,
        )

    @patch(
        "spaghetti_extractor.relational.analyses.register_static._immutable_image_u32",
        return_value=None,
    )
    def test_fixed_immutable_expression_fails_closed(
        self, _immutable_image_u32,
    ) -> None:
        original_expression = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x400000},
                "right": _input("edx"),
            },
        }
        candidate_expression = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x500000},
                "right": _input("ecx"),
            },
        }
        binaries = (
            SimpleNamespace(image_base=0x400000),
            SimpleNamespace(image_base=0x500000),
        )
        relation, reason = _infer_register_output_relation(
            original_expression,
            candidate_expression,
            {"edx": {"relation": "fixed_word", "value": 0x80}},
            {},
            0x400000,
            0x500000,
            True,
            original_bin=binaries[0],
            candidate_bin=binaries[1],
            candidate_input_registers={"edx": "ecx"},
        )
        self.assertEqual((relation, reason), (
            "related_word", "unsupported_or_mixed_relation",
        ))

        relation, reason = _infer_register_output_relation(
            original_expression,
            candidate_expression,
            {"edx": "exact"},
            {},
            0x400000,
            0x500000,
            True,
            original_bin=binaries[0],
            candidate_bin=binaries[1],
            candidate_input_registers={"edx": "ecx"},
        )
        self.assertEqual((relation, reason), (
            "related_word", "unsupported_or_mixed_relation",
        ))

    def test_fixed_immutable_expression_serializer_emits_state_rel_claim(self) -> None:
        source = _lean_register_output_claim({
            "kind": "fixed_immutable_expression",
            "output": {
                "original": "ebx",
                "candidate": "esi",
                "relation": "fixed_word",
                "value": 0x12345678,
            },
            "original_value": 0x12345678,
            "candidate_value": 0x12345678,
        })
        self.assertIn("RegisterOutputClaim.fixedImmutableExpression", source)
        self.assertIn("originalValue := 305419896", source)
        self.assertIn("candidateValue := 305419896", source)

    @patch(
        "spaghetti_extractor.relational.analyses.register_static._immutable_image_u32",
        return_value=0x12345678,
    )
    def test_fixed_immutable_expression_propagates_across_blocks(
        self, _immutable_image_u32,
    ) -> None:
        regions = [_region(0, root=True), _region(1)]
        first_original = _behavior({"op": "jump", "target": 1})
        first_candidate = _behavior(
            {"op": "jump", "target": 1}, candidate=True,
        )
        first_original["registers"]["edx"] = {
            "op": "constant", "value": 0x80,
        }
        first_candidate["registers"]["edx"] = {
            "op": "constant", "value": 0x80,
        }
        read = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x400000},
                "right": _input("edx"),
            },
        }
        returned = {"op": "returned", "target": _input("eax")}
        second_original = _behavior(returned)
        second_candidate = _behavior(returned, candidate=True)
        second_original["registers"]["ebx"] = read
        second_candidate["registers"]["ebx"] = read
        binary = SimpleNamespace(image_base=0x400000)
        contract = {
            "code_targets": [
                {
                    "id": index,
                    "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(2)
            ],
            "value_targets": [],
            "static_word_relation_slots": [],
            "regions": regions,
        }
        behaviors = [
            {"original_ir": first_original, "candidate_ir": first_candidate},
            {"original_ir": second_original, "candidate_ir": second_candidate},
        ]

        solver_metrics: dict[str, int] = {}
        transfer_cache = {}
        analyzed_contract, analysis = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
            original_bin=binary,
            candidate_bin=binary,
            _solver_metrics=solver_metrics,
            _transfer_cache=transfer_cache,
        )

        second_inputs = {
            row["original"]: row for row in analysis["regions"][1]["inputs"]
        }
        self.assertEqual(second_inputs["edx"], {
            "original": "edx",
            "candidate": "edx",
            "relation": "fixed_word",
            "value": 0x80,
        })
        second_claims = analysis["regions"][1]["output_claims"]
        self.assertIn({
            "kind": "fixed_immutable_expression",
            "output": {
                "original": "ebx",
                "candidate": "ebx",
                "relation": "fixed_word",
                "value": 0x12345678,
            },
            "original_value": 0x12345678,
            "candidate_value": 0x12345678,
        }, second_claims)
        self.assertEqual(solver_metrics["iterations"], 2)
        self.assertEqual(solver_metrics["transfer_evaluations"], 2)
        self.assertLess(
            solver_metrics["transfer_evaluations"],
            solver_metrics["iterations"] * analysis["counts"]["regions"],
        )
        cached_metrics: dict[str, int] = {}
        cached_contract, cached_analysis = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
            original_bin=binary,
            candidate_bin=binary,
            _solver_metrics=cached_metrics,
            _transfer_cache=transfer_cache,
        )
        self.assertEqual(cached_contract, analyzed_contract)
        self.assertEqual(cached_analysis, analysis)
        self.assertEqual(
            cached_metrics["transfer_cache_hits"],
            cached_metrics["transfer_evaluations"],
        )
        self.assertEqual(cached_metrics["transfer_cache_misses"], 0)

    def test_rooted_loop_retains_fixed_code_pointer_relation(self) -> None:
        regions = [_region(0, root=True), _region(1)]
        first_original = _behavior({"op": "jump", "target": 1})
        first_candidate = _behavior(
            {"op": "jump", "target": 1}, candidate=True,
        )
        original_target_address = 0x401020
        candidate_target_address = 0x501020
        first_original["registers"]["eax"] = {
            "op": "constant", "value": original_target_address,
        }
        first_candidate["registers"]["eax"] = {
            "op": "constant", "value": candidate_target_address,
        }
        loop_original = _behavior({"op": "jump", "target": 1})
        loop_candidate = _behavior(
            {"op": "jump", "target": 1}, candidate=True,
        )
        contract = {
            "code_targets": [
                {
                    "id": 0,
                    "region_index": 0,
                    "original_rva": 0x1000,
                    "candidate_rva": 0x1000,
                },
                {
                    "id": 1,
                    "region_index": 1,
                    "original_rva": 0x1020,
                    "candidate_rva": 0x1020,
                },
            ],
            "value_targets": [],
            "static_word_relation_slots": [],
            "regions": regions,
        }

        _refined, analysis = _synthesize_register_relations(
            contract,
            [
                {
                    "original_ir": first_original,
                    "candidate_ir": first_candidate,
                },
                {
                    "original_ir": loop_original,
                    "candidate_ir": loop_candidate,
                },
            ],
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )

        loop_inputs = {
            relation["original"]: relation
            for relation in analysis["regions"][1]["inputs"]
        }
        loop_outputs = {
            relation["original"]: relation
            for relation in analysis["regions"][1]["outputs"]
        }
        expected = {
            "original": "eax",
            "candidate": "eax",
            "relation": "fixed_code_pointer",
            "target_id": 1,
        }
        self.assertEqual(loop_inputs["eax"], expected)
        self.assertEqual(loop_outputs["eax"], expected)

    def test_protocol_callback_target_is_a_related_root(self) -> None:
        regions = [_region(0, root=True), _region(1)]
        returned = {"op": "returned", "target": _input("eax")}
        callback_original = _behavior(returned)
        callback_candidate = _behavior(returned, candidate=True)
        callback_original["registers"]["eax"] = {
            "op": "constant", "value": 0,
        }
        callback_candidate["registers"]["eax"] = {
            "op": "constant", "value": 0,
        }
        contract = {
            "code_targets": [
                {
                    "id": index,
                    "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(2)
            ],
            "value_targets": [],
            "static_word_relation_slots": [],
            "protocol_callback_control": {
                "format": "stage-a-protocol-callback-control-v1",
                "states": [{
                    "target_id": 1,
                    "active_frame_offset": {
                        "original_register": "esp",
                        "original": 0,
                        "candidate_register": "esp",
                        "candidate": 0,
                    },
                    "return_invariant": {"kind": "terminal"},
                }],
            },
            "regions": regions,
        }

        _refined, analysis = _synthesize_register_relations(
            contract,
            [
                {
                    "original_ir": _behavior(returned),
                    "candidate_ir": _behavior(returned, candidate=True),
                },
                {
                    "original_ir": callback_original,
                    "candidate_ir": callback_candidate,
                },
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        callback = analysis["regions"][1]
        self.assertEqual(
            analysis["status"], "proposal_requires_generated_lean_replay"
        )
        self.assertTrue(analysis["dataflow_complete"])
        self.assertTrue(callback["analysis_reachable"])
        self.assertTrue(callback["register_graph_rooted_reachable"])
        callback_inputs = {
            relation["original"]: relation for relation in callback["inputs"]
        }
        callback_outputs = {
            relation["original"]: relation for relation in callback["outputs"]
        }
        self.assertEqual(
            callback_inputs["ebx"]["relation"], "related_word",
        )
        self.assertEqual(callback_outputs["eax"], {
            "original": "eax",
            "candidate": "eax",
            "relation": "fixed_word",
            "value": 0,
        })

    def test_disconnected_source_scc_gets_conservative_entry(self) -> None:
        returned = {"op": "returned", "target": _input("eax")}
        loop = {"op": "jump", "target": 1}
        contract = {
            "code_targets": [
                {
                    "id": index,
                    "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(2)
            ],
            "value_targets": [],
            "static_word_relation_slots": [],
            "regions": [_region(0, root=True), _region(1)],
        }

        _refined, analysis = _synthesize_register_relations(
            contract,
            [
                {
                    "original_ir": _behavior(returned),
                    "candidate_ir": _behavior(returned, candidate=True),
                },
                {
                    "original_ir": _behavior(loop),
                    "candidate_ir": _behavior(loop, candidate=True),
                },
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        disconnected = analysis["regions"][1]
        self.assertEqual(
            analysis["status"], "proposal_requires_generated_lean_replay"
        )
        self.assertTrue(analysis["dataflow_complete"])
        self.assertTrue(disconnected["analysis_reachable"])
        self.assertFalse(disconnected["register_graph_rooted_reachable"])
        self.assertEqual(analysis["counts"]["analyzed_regions"], 2)
        self.assertEqual(analysis["counts"]["conservative_entry_regions"], 1)
        self.assertTrue(all(
            relation["relation"] == "related_word"
            for relation in disconnected["inputs"]
        ))

    def test_fixed_static_slot_output_requires_same_target_id(self) -> None:
        slot = {"relation": "fixed_code_pointer", "target_id": 7}
        self.assertTrue(_static_word_relation_supports_register_output(
            slot, {"relation": "fixed_code_pointer", "target_id": 7},
        ))
        self.assertFalse(_static_word_relation_supports_register_output(
            slot, {"relation": "fixed_code_pointer", "target_id": 8},
        ))
        self.assertFalse(_static_word_relation_supports_register_output(
            slot, {"relation": "code_pointer"},
        ))

    def test_fixed_static_slot_seed_retains_canonical_target(self) -> None:
        contract = {
            "code_targets": [{
                "id": 0, "original_rva": 0x1100, "candidate_rva": 0x1200,
            }],
            "static_word_relation_slots": [{
                "id": 0,
                "original_address": 0x402000,
                "candidate_address": 0x403000,
                "relation": "fixed_code_pointer",
                "target_id": 0,
            }],
        }

        self.assertEqual(
            _infer_register_output_relation(
                _read(0x402000),
                _read(0x403000),
                {},
                contract,
                0x400000,
                0x400000,
                True,
            ),
            ({"relation": "fixed_code_pointer", "target_id": 0},
             "static_word_slot"),
        )

        malformed = {**contract, "code_targets": []}
        relation, reason = _infer_register_output_relation(
            _read(0x402000),
            _read(0x403000),
            {},
            malformed,
            0x400000,
            0x400000,
            True,
        )
        self.assertEqual((relation, reason), (
            "related_word", "unsupported_or_mixed_relation",
        ))

        noncanonical = {
            **contract,
            "code_targets": [{
                "id": 7, "original_rva": 0x1100, "candidate_rva": 0x1200,
            }],
            "static_word_relation_slots": [{
                **contract["static_word_relation_slots"][0],
                "target_id": 7,
            }],
        }
        self.assertEqual(
            _infer_register_output_relation(
                _read(0x402000),
                _read(0x403000),
                {},
                noncanonical,
                0x400000,
                0x400000,
                True,
            )[0],
            "related_word",
        )

    def test_paired_input_register_rename_transfers_target_identity(self) -> None:
        fixed = {"relation": "fixed_code_pointer", "target_id": 7}

        self.assertEqual(
            _infer_register_output_relation(
                _input("esi"),
                _input("edi"),
                {"esi": fixed},
                {},
                0x400000,
                0x400000,
                True,
                candidate_input_registers={"esi": "edi"},
            ),
            (fixed, "identity_transfer"),
        )
        self.assertEqual(
            _infer_register_output_relation(
                _input("esi"),
                _input("ebx"),
                {"esi": fixed},
                {},
                0x400000,
                0x400000,
                True,
                candidate_input_registers={"esi": "edi"},
            )[0],
            "related_word",
        )

    def test_join_retains_only_identical_canonical_target_ids(self) -> None:
        target_7 = {"relation": "fixed_code_pointer", "target_id": 7}
        target_8 = {"relation": "fixed_code_pointer", "target_id": 8}

        self.assertEqual(
            _register_relation_join([target_7, dict(target_7)]), target_7,
        )
        self.assertEqual(
            _register_relation_join([target_7, target_8]), "related_word",
        )
        self.assertEqual(
            _register_relation_join([target_7, "code_pointer"]),
            "related_word",
        )

    def test_witnessed_fixed_target_join_is_budgeted(self) -> None:
        target_7 = _register_code_pointer_producer_relation(
            target_id=7,
            region_id="producer-7",
            region_index=1,
            claim_kind="paired_constant",
            original_register="eax",
            candidate_register="eax",
        )
        target_8 = _register_code_pointer_producer_relation(
            target_id=8,
            region_id="producer-8",
            region_index=2,
            claim_kind="static_word_slot",
            original_register="eax",
            candidate_register="eax",
        )

        joined = _register_relation_join(
            [target_8, target_7], finite_code_pointer_budget=2,
        )
        self.assertEqual([
            alternative["target_id"]
            for alternative in joined["target_alternatives"]
        ], [7, 8])
        self.assertTrue(all(
            alternative["producer_witnesses"]
            for alternative in joined["target_alternatives"]
        ))
        self.assertEqual(
            _register_relation_join(
                [target_7, target_8], finite_code_pointer_budget=1,
            ),
            "related_word",
        )

    def test_finite_code_pointer_provenance_covers_call_join(self) -> None:
        regions = [_region(index, root=index == 0) for index in range(7)]
        code_targets = [
            {
                "id": index,
                "region_index": index,
                "original_rva": 0x1000 + index * 0x10,
                "candidate_rva": 0x1000 + index * 0x10,
            }
            for index in range(7)
        ]
        branch = {
            "op": "branch",
            "condition": {"op": "input_flag", "index": 0},
            "taken": 1,
            "fallthrough": 2,
        }

        def producer(target_id: int, *, candidate: bool) -> dict[str, object]:
            behavior = _behavior(
                {"op": "jump", "target": 3}, candidate=candidate,
            )
            image_base = 0x500000 if candidate else 0x400000
            behavior["registers"]["eax"] = {
                "op": "constant",
                "value": image_base + int(code_targets[target_id][
                    "original_rva" if not candidate else "candidate_rva"
                ]),
            }
            return behavior

        returned = {"op": "returned", "target": _input("eax")}
        behaviors = [
            {
                "original_ir": _behavior(branch),
                "candidate_ir": _behavior(branch, candidate=True),
            },
            {
                "original_ir": producer(4, candidate=False),
                "candidate_ir": producer(4, candidate=True),
            },
            {
                "original_ir": producer(5, candidate=False),
                "candidate_ir": producer(5, candidate=True),
            },
            {
                "original_ir": _behavior({
                    "op": "indirect_call",
                    "target": _input("eax"),
                    "continuation": 6,
                }),
                "candidate_ir": _behavior({
                    "op": "indirect_call",
                    "target": _input("eax"),
                    "continuation": 6,
                }, candidate=True),
            },
            *[
                {
                    "original_ir": _behavior(returned),
                    "candidate_ir": _behavior(returned, candidate=True),
                }
                for _ in range(3)
            ],
        ]
        analysis = _synthesize_register_relations(
            {
                "code_targets": code_targets,
                "value_targets": [],
                "static_word_relation_slots": [],
                "regions": regions,
            },
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )[1]

        semantic_input = next(
            relation for relation in analysis["regions"][3]["inputs"]
            if relation["original"] == "eax"
        )
        self.assertEqual(semantic_input["relation"], "related_word")
        provenance = analysis["register_code_pointer_provenance"]
        self.assertEqual(provenance["finite_disjunction_budget"], 8)
        self.assertEqual(provenance["counts"]["multi_target_indirect_controls"], 1)
        self.assertEqual(len(provenance["controls"]), 1)
        control = provenance["controls"][0]
        self.assertEqual(control["operation"], "indirect_call")
        self.assertEqual([
            alternative["target_id"]
            for alternative in control["target_alternatives"]
        ], [4, 5])
        self.assertEqual([
            alternative["producer_witnesses"][0]["region_index"]
            for alternative in control["target_alternatives"]
        ], [1, 2])

    def test_finite_code_pointer_provenance_fails_closed(self) -> None:
        def synthesize(*, unknown_path: bool, clobber_path: bool, budget: int):
            regions = [_region(index, root=index == 0) for index in range(7)]
            code_targets = [
                {
                    "id": index,
                    "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(7)
            ]
            branch = {
                "op": "branch",
                "condition": {"op": "input_flag", "index": 0},
                "taken": 1,
                "fallthrough": 2,
            }

            def path(
                target_id: int, *, candidate: bool,
            ) -> dict[str, object]:
                behavior = _behavior(
                    {"op": "jump", "target": 3}, candidate=candidate,
                )
                if clobber_path and target_id == 5:
                    behavior["registers"]["eax"] = {
                        "op": "constant", "value": 0,
                    }
                elif not (unknown_path and target_id == 5):
                    image_base = 0x500000 if candidate else 0x400000
                    behavior["registers"]["eax"] = {
                        "op": "constant",
                        "value": image_base + 0x1000 + target_id * 0x10,
                    }
                return behavior

            returned = {"op": "returned", "target": _input("eax")}
            behaviors = [
                {
                    "original_ir": _behavior(branch),
                    "candidate_ir": _behavior(branch, candidate=True),
                },
                {
                    "original_ir": path(4, candidate=False),
                    "candidate_ir": path(4, candidate=True),
                },
                {
                    "original_ir": path(5, candidate=False),
                    "candidate_ir": path(5, candidate=True),
                },
                {
                    "original_ir": _behavior({
                        "op": "indirect_jump", "target": _input("eax"),
                    }),
                    "candidate_ir": _behavior({
                        "op": "indirect_jump", "target": _input("eax"),
                    }, candidate=True),
                },
                *[
                    {
                        "original_ir": _behavior(returned),
                        "candidate_ir": _behavior(returned, candidate=True),
                    }
                    for _ in range(3)
                ],
            ]
            return _synthesize_register_relations(
                {
                    "code_targets": code_targets,
                    "value_targets": [],
                    "static_word_relation_slots": [],
                    "regions": regions,
                },
                behaviors,
                original_image_base=0x400000,
                candidate_image_base=0x500000,
                code_pointer_disjunction_budget=budget,
            )[1]["register_code_pointer_provenance"]

        unknown = synthesize(
            unknown_path=True, clobber_path=False, budget=8,
        )
        self.assertEqual(unknown["controls"], [])
        self.assertEqual(
            unknown["incomplete_controls"][0]["blocker"],
            "unknown_or_clobbered_provenance",
        )

        clobbered = synthesize(
            unknown_path=False, clobber_path=True, budget=8,
        )
        self.assertEqual(clobbered["controls"], [])
        self.assertEqual(
            clobbered["incomplete_controls"][0]["blocker"],
            "unknown_or_clobbered_provenance",
        )

        overflow = synthesize(
            unknown_path=False, clobber_path=False, budget=1,
        )
        self.assertEqual(overflow["controls"], [])
        self.assertEqual(
            overflow["incomplete_controls"][0]["blocker"],
            "finite_disjunction_budget_overflow",
        )
        self.assertGreater(overflow["counts"]["overflow_locations"], 0)

    def test_finite_code_pointer_provenance_follows_register_move(self) -> None:
        regions = [_region(index, root=index == 0) for index in range(5)]
        code_targets = [
            {
                "id": index,
                "region_index": index,
                "original_rva": 0x1000 + index * 0x10,
                "candidate_rva": 0x1000 + index * 0x10,
            }
            for index in range(5)
        ]
        original_producer = _behavior({"op": "jump", "target": 1})
        candidate_producer = _behavior(
            {"op": "jump", "target": 1}, candidate=True,
        )
        original_producer["registers"]["eax"] = {
            "op": "constant", "value": 0x401040,
        }
        candidate_producer["registers"]["eax"] = {
            "op": "constant", "value": 0x501040,
        }
        original_move = _behavior({"op": "jump", "target": 2})
        candidate_move = _behavior(
            {"op": "jump", "target": 2}, candidate=True,
        )
        original_move["registers"]["ebx"] = _input("eax")
        candidate_move["registers"]["ebx"] = _input("eax")
        returned = {"op": "returned", "target": _input("eax")}
        behaviors = [
            {"original_ir": original_producer,
             "candidate_ir": candidate_producer},
            {"original_ir": original_move, "candidate_ir": candidate_move},
            {
                "original_ir": _behavior({
                    "op": "indirect_jump", "target": _input("ebx"),
                }),
                "candidate_ir": _behavior({
                    "op": "indirect_jump", "target": _input("ebx"),
                }, candidate=True),
            },
            *[
                {
                    "original_ir": _behavior(returned),
                    "candidate_ir": _behavior(returned, candidate=True),
                }
                for _ in range(2)
            ],
        ]
        provenance = _synthesize_register_relations(
            {
                "code_targets": code_targets,
                "value_targets": [],
                "static_word_relation_slots": [],
                "regions": regions,
            },
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )[1]["register_code_pointer_provenance"]

        self.assertEqual(len(provenance["controls"]), 1)
        control = provenance["controls"][0]
        self.assertEqual(control["operation"], "indirect_jump")
        self.assertEqual(control["original_register"], "ebx")
        self.assertEqual(control["target_alternatives"][0]["target_id"], 4)
        self.assertEqual(
            control["target_alternatives"][0]["producer_witnesses"][0]
            ["region_index"],
            0,
        )

    def test_fixed_word_code_address_gets_unique_producer_witness(self) -> None:
        regions = [_region(index, root=index == 0) for index in range(3)]
        producer = _behavior({"op": "jump", "target": 1})
        producer["registers"]["eax"] = {
            "op": "constant", "value": 0x401020,
        }
        behaviors = [
            {"original_ir": producer,
             "candidate_ir": copy.deepcopy(producer)},
            {
                "original_ir": _behavior({
                    "op": "indirect_jump", "target": _input("eax"),
                }),
                "candidate_ir": _behavior({
                    "op": "indirect_jump", "target": _input("eax"),
                }, candidate=True),
            },
            {
                "original_ir": _behavior({
                    "op": "returned", "target": _input("eax"),
                }),
                "candidate_ir": _behavior({
                    "op": "returned", "target": _input("eax"),
                }, candidate=True),
            },
        ]
        analysis = _synthesize_register_relations(
            {
                "code_targets": [{
                    "id": 0,
                    "region_index": 2,
                    "original_rva": 0x1020,
                    "candidate_rva": 0x1020,
                }],
                "value_targets": [],
                "static_word_relation_slots": [],
                "regions": regions,
            },
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )[1]

        output = next(
            relation for relation in analysis["regions"][0]["outputs"]
            if relation["original"] == "eax"
        )
        self.assertEqual(output, {
            "original": "eax", "candidate": "eax",
            "relation": "fixed_word", "value": 0x401020,
        })
        controls = analysis["register_code_pointer_provenance"]["controls"]
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["target_alternatives"][0]["target_id"], 0)
        self.assertEqual(
            controls[0]["target_alternatives"][0]["producer_witnesses"][0]
            ["claim_kind"],
            "paired_constant",
        )

    def test_callsite_carries_fixed_target_only_when_every_return_path_preserves_it(
        self,
    ) -> None:
        def synthesize(*, clobber_second_return: bool):
            regions = [_region(index, root=index == 0) for index in range(5)]
            regions[0]["code_targets"] = [
                {
                    "id": 1, "region_index": 1,
                    "original_rva": 0x1010, "candidate_rva": 0x1010,
                },
                {
                    "id": 4, "region_index": 4,
                    "original_rva": 0x1040, "candidate_rva": 0x1040,
                },
            ]
            call_outcome = {"op": "call", "target": 1, "continuation": 4}
            original_call = _behavior(
                call_outcome, fixed_slot=0x402000,
            )
            candidate_call = _behavior(
                call_outcome, candidate=True, fixed_slot=0x403000,
            )
            for behavior in (original_call, candidate_call):
                stack_register = "esp"
                stack_after_push = {
                    "op": "subtract",
                    "left": _input(stack_register),
                    "right": {"op": "constant", "value": 4},
                }
                behavior["registers"][stack_register] = stack_after_push
                behavior["writes"] = [{
                    "address": stack_after_push,
                    "value": {"op": "constant", "value": 0x401040},
                    "bytes": 4,
                }]
            branch = {
                "op": "branch",
                "condition": {"op": "input_flag", "index": 0},
                "taken": 2,
                "fallthrough": 3,
            }
            returned = {"op": "returned", "target": _input("eax")}
            behaviors = [{"original_ir": original, "candidate_ir": candidate}
                         for original, candidate in (
                (original_call, candidate_call),
                (_behavior(branch), _behavior(branch, candidate=True)),
                (_behavior(returned), _behavior(returned, candidate=True)),
                (
                    _behavior(
                        returned,
                        clobber_fixed_register=clobber_second_return,
                    ),
                    _behavior(
                        returned,
                        candidate=True,
                        clobber_fixed_register=clobber_second_return,
                    ),
                ),
                (_behavior(returned), _behavior(returned, candidate=True)),
            )]
            contract = {
                "code_targets": [{
                "id": 0,
                    "original_rva": 0x1100,
                    "candidate_rva": 0x1200,
                }],
                "value_targets": [],
                "static_word_relation_slots": [{
                    "id": 0,
                    "original_address": 0x402000,
                    "candidate_address": 0x403000,
                    "relation": "fixed_code_pointer",
                    "target_id": 0,
                }],
                "regions": regions,
            }
            return _synthesize_register_relations(
                contract,
                behaviors,
                original_image_base=0x400000,
                candidate_image_base=0x400000,
            )[1]

        preserved = synthesize(clobber_second_return=False)
        continuation = next(
            relation
            for relation in preserved["regions"][4]["inputs"]
            if relation["original"] == "esi"
        )
        self.assertEqual(continuation, {
            "original": "esi",
            "candidate": "edi",
            "relation": "fixed_code_pointer",
            "target_id": 0,
        })

        clobbered = synthesize(clobber_second_return=True)
        continuation = next(
            relation
            for relation in clobbered["regions"][4]["inputs"]
            if relation["original"] == "esi"
        )
        self.assertEqual(continuation["relation"], "related_word")
        self.assertNotIn("target_id", continuation)

    def test_contracted_import_thunk_preserves_caller_specific_fixed_target(
        self,
    ) -> None:
        def synthesize(*, include_contract: bool):
            regions = [_region(index, root=index == 0) for index in range(5)]
            regions[0]["code_targets"] = [
                {
                    "id": 1, "region_index": 1,
                    "original_rva": 0x1010, "candidate_rva": 0x1010,
                },
                {
                    "id": 4, "region_index": 4,
                    "original_rva": 0x1040, "candidate_rva": 0x1040,
                },
            ]
            regions[1]["code_targets"] = [
                {
                    "id": 2, "region_index": 2,
                    "original_rva": 0x1020, "candidate_rva": 0x1020,
                },
                {
                    "id": 3, "region_index": 3,
                    "original_rva": 0x1030, "candidate_rva": 0x1030,
                },
            ]

            def call_behavior(
                target: int, continuation: int, return_address: int,
                *, candidate: bool = False, fixed_slot: int | None = None,
            ) -> dict[str, object]:
                behavior = _behavior(
                    {"op": "call", "target": target,
                     "continuation": continuation},
                    candidate=candidate,
                    fixed_slot=fixed_slot,
                )
                stack_after_push = {
                    "op": "subtract",
                    "left": _input("esp"),
                    "right": {"op": "constant", "value": 4},
                }
                behavior["registers"]["esp"] = stack_after_push
                behavior["writes"] = [{
                    "address": stack_after_push,
                    "value": {"op": "constant", "value": return_address},
                    "bytes": 4,
                }]
                return behavior

            imported = {
                "dll": "msvcrt.dll",
                "name": {"op": "symbol", "bytes": list(b"__p__iob")},
            }
            returned = {"op": "returned", "target": _input("eax")}
            behaviors = [
                {
                    "original_ir": call_behavior(
                        1, 4, 0x401040, fixed_slot=0x402000,
                    ),
                    "candidate_ir": call_behavior(
                        1, 4, 0x401040, candidate=True,
                        fixed_slot=0x403000,
                    ),
                },
                {
                    "original_ir": call_behavior(2, 3, 0x401030),
                    "candidate_ir": call_behavior(
                        2, 3, 0x401030, candidate=True,
                    ),
                },
                {
                    "original_ir": _behavior({
                        "op": "external_jump", "import": imported,
                    }),
                    "candidate_ir": _behavior({
                        "op": "external_jump", "import": imported,
                    }, candidate=True),
                },
                {
                    "original_ir": _behavior(returned),
                    "candidate_ir": _behavior(returned, candidate=True),
                },
                {
                    "original_ir": _behavior(returned),
                    "candidate_ir": _behavior(returned, candidate=True),
                },
            ]
            machine_contracts = [] if not include_contract else [{
                "id": 0,
                "import": {"dll": "msvcrt.dll", "symbol": "__p__iob"},
                "disposition": "returns",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "stack_result_delta": 4,
                "result_register_relations": [{
                    "register": "eax", "relation": "related_word",
                }],
            }]
            contract = {
                "code_targets": [{
                    "id": 0,
                    "original_rva": 0x1100,
                    "candidate_rva": 0x1200,
                }],
                "value_targets": [],
                "static_word_relation_slots": [{
                    "id": 0,
                    "original_address": 0x402000,
                    "candidate_address": 0x403000,
                    "relation": "fixed_code_pointer",
                    "target_id": 0,
                }],
                "machine_import_call_contracts": machine_contracts,
                "regions": regions,
            }
            return _synthesize_register_relations(
                contract,
                behaviors,
                original_image_base=0x400000,
                candidate_image_base=0x400000,
            )[1]

        contracted = synthesize(include_contract=True)
        continuation = next(
            relation
            for relation in contracted["regions"][4]["inputs"]
            if relation["original"] == "esi"
        )
        self.assertEqual(continuation, {
            "original": "esi",
            "candidate": "edi",
            "relation": "fixed_code_pointer",
            "target_id": 0,
        })
        summaries = contracted["return_slot_analysis"][
            "call_summary_analysis"
        ]["summaries"]
        self.assertEqual([
            summary["callsite_region_index"] for summary in summaries
        ], [0])
        self.assertTrue(summaries[0]["closed"])

        uncontracted = synthesize(include_contract=False)
        continuation = next(
            relation
            for relation in uncontracted["regions"][4]["inputs"]
            if relation["original"] == "esi"
        )
        self.assertEqual(continuation["relation"], "related_word")
        self.assertFalse(
            uncontracted["return_slot_analysis"]["call_summary_analysis"]
            ["summaries"][0]["closed"]
        )

    def test_indirect_call_inventory_requires_exact_fixed_register_relation(
        self,
    ) -> None:
        def synthesize(*, include_fixed_slot: bool):
            regions = [_region(index, root=index == 0) for index in range(4)]
            behaviors = [
                {
                    "original_ir": _behavior(
                        {"op": "jump", "target": 1},
                        fixed_slot=0x402000,
                    ),
                    "candidate_ir": _behavior(
                        {"op": "jump", "target": 1},
                        candidate=True,
                        fixed_slot=0x403000,
                    ),
                },
                {
                    "original_ir": _behavior({
                        "op": "indirect_call",
                        "target": _input("esi"),
                        "continuation": 2,
                    }),
                    "candidate_ir": _behavior({
                        "op": "indirect_call",
                        "target": _input("edi"),
                        "continuation": 2,
                    }, candidate=True),
                },
                {
                    "original_ir": _behavior({
                        "op": "returned", "target": _input("eax"),
                    }),
                    "candidate_ir": _behavior({
                        "op": "returned", "target": _input("eax"),
                    }, candidate=True),
                },
                {
                    "original_ir": _behavior({
                        "op": "returned", "target": _input("eax"),
                    }),
                    "candidate_ir": _behavior({
                        "op": "returned", "target": _input("eax"),
                    }, candidate=True),
                },
            ]
            code_targets = [
                {
                    "id": index,
                    "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(4)
            ]
            return _synthesize_register_relations(
                {
                    "code_targets": code_targets,
                    "value_targets": [],
                    "static_word_relation_slots": ([{
                        "id": 0,
                        "original_address": 0x402000,
                        "candidate_address": 0x403000,
                        "relation": "fixed_code_pointer",
                        "target_id": 3,
                    }] if include_fixed_slot else []),
                    "regions": regions,
                },
                behaviors,
                original_image_base=0x400000,
                candidate_image_base=0x400000,
            )[1]

        matching = synthesize(include_fixed_slot=True)
        self.assertEqual(matching["indirect_fixed_code_pointer_calls"], [{
            "profile": "inductive_fixed_code_pointer_register_call_v1",
            "source_region_index": 1,
            "target_region_index": 3,
            "continuation_region_index": 2,
            "continuation_target_id": 2,
            "target_id": 3,
            "original_register": "esi",
            "candidate_register": "edi",
        }])
        self.assertEqual(
            matching["counts"]["indirect_fixed_code_pointer_calls"], 1,
        )
        self.assertFalse(any(
            edge["source_region_index"] == 1
            for edge in matching["edges"]
        ))

        unsupported = synthesize(include_fixed_slot=False)
        self.assertEqual(
            unsupported["indirect_fixed_code_pointer_calls"], [],
        )
        self.assertEqual(
            unsupported["counts"]["indirect_fixed_code_pointer_calls"], 0,
        )


if __name__ == "__main__":
    unittest.main()
