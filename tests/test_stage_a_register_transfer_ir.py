import copy
import hashlib
import json
import unittest
from types import SimpleNamespace

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.register_transfer_ir import (
    RegisterTransferIncomplete,
    compile_register_transfer_program,
    evaluate_register_transfer_program,
    parse_register_transfer_program,
    parse_register_transfer_programs,
    register_transfer_programs_payload,
)
from spaghetti_extractor.relational.register_transfer_core import (
    REGISTER_TRANSFER_CONTEXT_FORMAT,
    canonical_sha256,
)


REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _input(register: str) -> dict[str, object]:
    return {"op": "input_reg", "reg": register}


def _behavior() -> dict[str, object]:
    registers = {register: _input(register) for register in REGISTERS}
    return {
        "original_ir": {"registers": copy.deepcopy(registers)},
        "candidate_ir": {"registers": copy.deepcopy(registers)},
    }


def _context(
    *, value_targets: list[dict[str, int]] | None = None,
) -> dict[str, object]:
    original = bytearray(0x200)
    candidate = bytearray(0x200)
    original[0x9C:0xA0] = (0x12345678).to_bytes(4, "little")
    candidate[0x9C:0xA0] = (0x12345678).to_bytes(4, "little")
    body = {
        "format": REGISTER_TRANSFER_CONTEXT_FORMAT,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original": {
            "sha256": "a" * 64,
            "image_base": 0x400000,
            "immutable_ranges": [{
                "start": 0x400000, "bytes_hex": original.hex(),
            }],
            "forbidden_ranges": [],
        },
        "candidate": {
            "sha256": "b" * 64,
            "image_base": 0x500000,
            "immutable_ranges": [{
                "start": 0x500000, "bytes_hex": candidate.hex(),
            }],
            "forbidden_ranges": [],
        },
        "value_targets": value_targets or [],
        "code_targets": [],
    }
    return {**body, "context_sha256": canonical_sha256(body)}


def _compile(
    behavior: dict[str, object] | None = None,
    *,
    contract: dict[str, object] | None = None,
    original: object | None = None,
    candidate: object | None = None,
    context: dict[str, object] | None = None,
) -> dict[str, object]:
    return compile_register_transfer_program(
        region_id="region-0",
        behavior_pair=behavior or _behavior(),
        input_pairs={register: register for register in REGISTERS},
        output_pairs={register: register for register in REGISTERS},
        contract=contract or {},
        original_image_base=0x400000,
        candidate_image_base=0x500000,
        original_bin=original,  # type: ignore[arg-type]
        candidate_bin=candidate,  # type: ignore[arg-type]
        context_sha256=(
            str(context["context_sha256"]) if context is not None else None
        ),
    )


class StageARegisterTransferIRTests(unittest.TestCase):
    def test_identity_program_accepts_unseen_input_relation(self) -> None:
        program = _compile()
        parsed = parse_register_transfer_program(program)
        fixed = {"relation": "fixed_code_pointer", "target_id": 17}
        inputs = {register: "related_word" for register in REGISTERS}
        inputs["esi"] = fixed

        result = evaluate_register_transfer_program(
            parsed,
            inputs,
            context_payload=_context(),
        )

        self.assertEqual(result.relations["esi"], fixed)
        self.assertEqual(result.reasons["esi"], "identity_transfer")

    def test_unknown_rule_is_rejected_even_with_recomputed_digest(self) -> None:
        program = _compile()
        program["outputs"][0]["rules"].insert(0, {
            "op": "trust_solver_status", "reason": "unchecked",
        })
        body = {
            key: value for key, value in program.items()
            if key != "program_sha256"
        }
        program["program_sha256"] = _digest(body)

        with self.assertRaisesRegex(StageAInputError, "unsupported"):
            parse_register_transfer_program(program)

    def test_fixed_immutable_program_handles_unseen_fixed_input(
        self,
    ) -> None:
        behavior = _behavior()
        behavior["original_ir"]["registers"]["eax"] = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x400000},
                "right": _input("edx"),
            },
        }
        behavior["candidate_ir"]["registers"]["eax"] = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "constant", "value": 0x500000},
                "right": _input("edx"),
            },
        }
        original = SimpleNamespace(sha256="a" * 64)
        candidate = SimpleNamespace(sha256="b" * 64)
        context = _context()
        program = _compile(
            behavior, original=original, candidate=candidate, context=context,
        )
        inputs = {register: "related_word" for register in REGISTERS}
        inputs["edx"] = {"relation": "fixed_word", "value": 0x9C}

        result = evaluate_register_transfer_program(
            program,
            inputs,
            context_payload=context,
        )

        self.assertEqual(result.relations["eax"], {
            "relation": "fixed_word", "value": 0x12345678,
        })
        self.assertEqual(result.reasons["eax"], "fixed_immutable_expression")

    def test_dynamic_program_requires_exact_immutable_images(self) -> None:
        behavior = _behavior()
        behavior["original_ir"]["registers"]["eax"] = {
            "op": "add", "left": _input("edx"),
            "right": {"op": "constant", "value": 1},
        }
        behavior["candidate_ir"]["registers"]["eax"] = {
            "op": "add", "left": _input("ecx"),
            "right": {"op": "constant", "value": 1},
        }
        original = SimpleNamespace(sha256="a" * 64)
        candidate = SimpleNamespace(sha256="b" * 64)
        context = _context()
        program = _compile(
            behavior, original=original, candidate=candidate, context=context,
        )
        inputs = {register: "related_word" for register in REGISTERS}

        with self.assertRaisesRegex(
            RegisterTransferIncomplete, "transfer_context_missing",
        ):
            evaluate_register_transfer_program(
                program,
                inputs,
                context_payload=None,
            )

        with self.assertRaisesRegex(
            RegisterTransferIncomplete, "transfer_context_identity_mismatch",
        ):
            evaluate_register_transfer_program(
                program,
                inputs,
                context_payload=_context(value_targets=[{
                    "original_value": 1, "candidate_value": 2,
                }]),
            )

    def test_relation_context_change_fails_closed(self) -> None:
        behavior = _behavior()
        behavior["original_ir"]["registers"]["eax"] = {
            "op": "add", "left": _input("edx"),
            "right": {"op": "constant", "value": 1},
        }
        behavior["candidate_ir"]["registers"]["eax"] = {
            "op": "add", "left": _input("ecx"),
            "right": {"op": "constant", "value": 1},
        }
        original = SimpleNamespace(sha256="a" * 64)
        candidate = SimpleNamespace(sha256="b" * 64)
        context = _context()
        program = _compile(
            behavior, original=original, candidate=candidate, context=context,
        )

        with self.assertRaisesRegex(
            RegisterTransferIncomplete, "transfer_context_identity_mismatch",
        ):
            evaluate_register_transfer_program(
                program,
                {register: "related_word" for register in REGISTERS},
                context_payload=_context(value_targets=[{
                    "original_value": 1, "candidate_value": 2,
                }]),
            )

    def test_program_collection_binds_binary_and_graph_identities(self) -> None:
        program = _compile()
        payload = register_transfer_programs_payload(
            original_sha256="a" * 64,
            candidate_sha256="b" * 64,
            graph_sha256="c" * 64,
            context=_context(),
            programs=[program],
            propagation={
                "regions": [{
                    "id": "region-0",
                    "seed_relation": "exact",
                    "stack_window_registers": [],
                }],
                "edges": [],
            },
        )
        parsed = parse_register_transfer_programs(
            payload,
            expected_original_sha256="a" * 64,
            expected_candidate_sha256="b" * 64,
            expected_graph_sha256="c" * 64,
        )
        self.assertEqual(parsed["programs"][0]["region_id"], "region-0")

        tampered = copy.deepcopy(payload)
        tampered["programs"][0]["region_id"] = "other"
        with self.assertRaisesRegex(StageAInputError, "digest"):
            parse_register_transfer_programs(
                tampered,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
                expected_graph_sha256="c" * 64,
            )


if __name__ == "__main__":
    unittest.main()
