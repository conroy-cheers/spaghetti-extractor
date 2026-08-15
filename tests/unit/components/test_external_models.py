from __future__ import annotations

import unittest
from collections.abc import Mapping
from dataclasses import replace

from spaghetti_extractor.components.evidence_effects import (
    call_register_key,
    execute_ordered_effects,
    expression_is_defined,
)
from spaghetti_extractor.components.external_models import (
    ExternalEvidenceModelError,
    evaluate_checked_external_call,
)
from spaghetti_extractor.external.contracts import (
    CheckedExternalSiteContract,
    CheckedStackArgument,
    ExternalSiteIdentity,
)


def _contract() -> CheckedExternalSiteContract:
    arguments = (
        {"op": "reg", "name": "eax", "width": 32},
        {"op": "reg", "name": "edx", "width": 32},
        {"op": "reg", "name": "ecx", "width": 32},
    )
    return CheckedExternalSiteContract(
        identity=ExternalSiteIdentity(
            kind="import", dll="msvcrt.dll", symbol="memcmp"
        ),
        transfer_kind="call",
        disposition="returns_here",
        profile_disposition="returns",
        abi_template="pe32-cdecl-v1",
        argument_words=3,
        argument_base_offset=0,
        arguments=arguments,
        stack_arguments=tuple(
            CheckedStackArgument(index, index * 4, 4, argument)
            for index, argument in enumerate(arguments)
        ),
        contract_id="external-contract-v3:test",
        profile_binding={"profile_id": "test", "profile_sha256": "0" * 64},
        result_register_relations=({"register": "eax", "relation": "exact"},),
        memory_effect="readOnly",
        memory_footprints=(
            {
                "access": "read",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "argument", "argument": 2, "scale": 1},
                "nullable": False,
            },
            {
                "access": "read",
                "base_argument": 1,
                "offset": 0,
                "size": {"kind": "argument", "argument": 2, "scale": 1},
                "nullable": False,
            },
        ),
        world_effect="none",
        callback_effect="none",
        callback_adapter=None,
    )


class ExternalEvidenceModelTests(unittest.TestCase):
    def test_memcmp_evaluates_equal_and_distinct_ranges(self) -> None:
        memory = {
            0x1000: 1,
            0x1001: 2,
            0x1002: 3,
            0x2000: 1,
            0x2001: 2,
            0x2002: 3,
            0x3000: 1,
            0x3001: 7,
            0x3002: 3,
        }

        def read(address: int, width: int) -> int:
            self.assertEqual(width, 1)
            return memory[address]

        state = {name: index for index, name in enumerate(
            ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )}
        equal = evaluate_checked_external_call(
            _contract(), [0x1000, 0x2000, 3], state, read
        )
        distinct = evaluate_checked_external_call(
            _contract(), [0x1000, 0x3000, 3], state, read
        )

        self.assertEqual(equal.register_values["eax"], 0)
        self.assertEqual(distinct.register_values["eax"], (2 - 7) & 0xFFFFFFFF)
        self.assertIn("ebx", equal.defined_registers)
        self.assertNotIn("ecx", equal.defined_registers)
        self.assertEqual(equal.defined_flags, frozenset())

    def test_memcmp_rejects_a_contract_with_a_weaker_footprint(self) -> None:
        contract = replace(_contract(), memory_footprints=())
        with self.assertRaisesRegex(
            ExternalEvidenceModelError, "ABI/effect contract"
        ):
            evaluate_checked_external_call(contract, [0, 0, 0], {}, lambda _a, _w: 0)

    def test_definedness_tracks_call_results_and_rejects_clobbers(self) -> None:
        defined = frozenset({"@call:0:register:eax"})
        self.assertTrue(
            expression_is_defined(
                {"op": "call_response", "call_index": 0, "register": "eax"},
                defined,
            )
        )
        self.assertFalse(
            expression_is_defined(
                {"op": "call_response", "call_index": 0, "register": "ecx"},
                defined,
            )
        )

    def test_ordered_effects_returns_the_checked_external_evaluation(self) -> None:
        class Memory:
            values = {
                0x1000: 1,
                0x1001: 2,
                0x2000: 1,
                0x2001: 2,
            }

            def read(self, address: int, width: int) -> int:
                return sum(
                    self.values[address + offset] << (offset * 8)
                    for offset in range(width)
                )

            def write(self, address: int, width: int, value: int) -> None:
                raise AssertionError((address, width, value))

        state = {"eax": 0x1000, "edx": 0x2000, "ecx": 2, "esp": 0x8000}
        defined = set(state)

        def evaluate(expression: object, values: Mapping[str, int], _memory: object) -> int:
            assert isinstance(expression, Mapping)
            return int(values[str(expression["name"])])

        calls = execute_ordered_effects(
            unit_id="unit:call",
            semantics={
                "ordered_events": [{"family": "external"}],
                "external_events": [{}],
            },
            state=state,
            defined_fields=defined,
            memory=Memory(),
            external_contracts={("unit:call", 0): _contract()},
            evaluate_expression=evaluate,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].unit_id, "unit:call")
        self.assertEqual(calls[0].evaluation.register_values["eax"], 0)
        self.assertEqual(state[call_register_key(0, "eax")], 0)
        self.assertIn(call_register_key(0, "eax"), defined)


if __name__ == "__main__":
    unittest.main()
