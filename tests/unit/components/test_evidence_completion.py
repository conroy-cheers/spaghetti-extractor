from __future__ import annotations

import unittest
from collections.abc import Mapping

from spaghetti_extractor.components.evidence_completion import (
    EvidenceCompletionError,
    evaluate_adapter_completion,
)


class _Memory:
    def __init__(self) -> None:
        self.values: dict[int, int] = {}

    def clone(self) -> "_Memory":
        result = _Memory()
        result.values = dict(self.values)
        return result

    def write(self, address: int, width: int, value: int) -> None:
        self.values[address] = value & ((1 << (width * 8)) - 1)


class EvidenceCompletionTests(unittest.TestCase):
    def test_exact_external_result_can_complete_machine_state(self) -> None:
        key = ("unit:call", 0, "eax")
        result = evaluate_adapter_completion(
            _adapter(),
            state_fields=("eax", "ebx"),
            entry_state={"eax": 7, "ebx": 11},
            entry_memory=_Memory(),
            logical_result=1,
            result_id="result",
            external_result_values={key: 0xAABBCCDD},
            external_result_defined=frozenset({key}),
            evaluate_expression=_evaluate,
        )

        self.assertEqual(result["state"], {"eax": 0xAABBCCDD, "ebx": 11})
        self.assertEqual(result["return_target"], 11)

    def test_undefined_external_result_fails_closed(self) -> None:
        key = ("unit:call", 0, "eax")
        with self.assertRaisesRegex(
            EvidenceCompletionError, "unavailable external result"
        ):
            evaluate_adapter_completion(
                _adapter(),
                state_fields=("eax", "ebx"),
                entry_state={"eax": 7, "ebx": 11},
                entry_memory=_Memory(),
                logical_result=1,
                result_id="result",
                external_result_values={key: 0xAABBCCDD},
                external_result_defined=frozenset(),
                evaluate_expression=_evaluate,
            )


def _adapter() -> dict[str, object]:
    return {
        "lowering": {
            "kind": "checked-object-view-v1",
            "completion": {
                "kind": "explicit-machine-state-v1",
                "state": {
                    "eax": {
                        "op": "external_result",
                        "unit_id": "unit:call",
                        "event_index": 0,
                        "register": "eax",
                    },
                    "ebx": {"op": "entry", "name": "ebx"},
                },
                "memory_writes": [],
                "return_target": {"op": "entry", "name": "ebx"},
            },
        }
    }


def _evaluate(
    expression: object, _state: Mapping[str, int], _memory: _Memory
) -> int:
    assert isinstance(expression, Mapping)
    if expression.get("op") != "const":
        raise AssertionError(expression)
    return int(expression["value"])


if __name__ == "__main__":
    unittest.main()
