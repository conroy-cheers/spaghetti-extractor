import unittest
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.relational.analyses.registers import (
    _attach_assembled_immutable_read_address_separations,
    _infer_register_output_relation,
    _immutable_image_word_read,
    _paired_constant_relation,
    _register_relation_join,
    _synthesize_register_relations,
)
from spaghetti_extractor.relational.lean.expressions import (
    _lean_register_output_claim,
)
from spaghetti_extractor.relational.analyses.segments import (
    _static_word_relation_supports_register_output,
)
from spaghetti_extractor.relational.pipeline import (
    _stabilize_fixed_code_pointer_register_calls,
)


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
    @patch(
        "spaghetti_extractor.relational.analyses.registers._immutable_image_u32",
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
            ("exact", "assembled_immutable_image_word"),
        )

    @patch(
        "spaghetti_extractor.relational.analyses.registers._immutable_image_u32",
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
