from __future__ import annotations

import unittest

from spaghetti_extractor.call_arguments import (
    CALL_ARGUMENT_RECOVERY_FORMAT,
    recover_pe32_local_stack_argument_prefix,
    recover_pe32_stack_call_arguments,
)


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


class CallArgumentRecoveryTests(unittest.TestCase):
    def test_recovers_push_order_relative_to_call_esp(self) -> None:
        esp_minus_4 = sub(reg("esp"), const(4))
        esp_minus_8 = sub(esp_minus_4, const(4))
        esp_minus_12 = sub(esp_minus_8, const(4))
        call = {
            "kind": "external_call",
            "dll": "ddraw.dll",
            "symbol": "DirectDrawCreate",
            "ordinal": None,
            "return_rva": 0x1010,
            "register_inputs": {"esp": esp_minus_12},
        }
        unit = {
            "semantics": {
                "external_events": [call],
                "ordered_events": [
                    {"kind": "write", "width": 4, "address": esp_minus_4, "value": const(0)},
                    {"kind": "write", "width": 4, "address": esp_minus_8, "value": const(0x430000)},
                    {"kind": "write", "width": 4, "address": esp_minus_12, "value": const(0)},
                    {**call, "family": "external", "instruction_rva": 0x100B},
                ],
            }
        }

        recovered = recover_pe32_stack_call_arguments(
            unit, event_index=0, argument_words=3
        )

        self.assertEqual(recovered.status, "complete")
        self.assertEqual(recovered.as_json()["format"], CALL_ARGUMENT_RECOVERY_FORMAT)
        self.assertEqual(
            [argument["value"] for argument in recovered.arguments],
            [0, 0x430000, 0],
        )
        self.assertEqual(
            [row["stack_offset_from_unit_input"] for row in recovered.evidence],
            [-12, -8, -4],
        )

    def test_argument_prepared_outside_unit_fails_closed(self) -> None:
        call = {
            "kind": "external_call",
            "dll": "kernel32.dll",
            "symbol": "WriteFile",
            "ordinal": None,
            "return_rva": 0x1010,
            "register_inputs": {"esp": reg("esp")},
        }
        recovered = recover_pe32_stack_call_arguments(
            {
                "semantics": {
                    "external_events": [call],
                    "ordered_events": [call],
                }
            },
            event_index=0,
            argument_words=1,
        )

        self.assertEqual(recovered.status, "incomplete")
        self.assertEqual(recovered.failure_code, "argument_write_missing")

    def test_infers_contiguous_local_argument_prefix_without_abi(self) -> None:
        esp_minus_4 = sub(reg("esp"), const(4))
        esp_minus_8 = sub(esp_minus_4, const(4))
        call = {
            "kind": "internal_call",
            "target_rva": 0x1800,
            "return_rva": 0x1010,
            "register_inputs": {"esp": esp_minus_8},
        }
        unit = {
            "semantics": {
                "external_events": [call],
                "ordered_events": [
                    {
                        "kind": "write",
                        "width": 4,
                        "address": esp_minus_4,
                        "value": const(0x416038),
                    },
                    {
                        "kind": "write",
                        "width": 4,
                        "address": esp_minus_8,
                        "value": const(0x41602C),
                    },
                    call,
                ],
            }
        }

        recovered = recover_pe32_local_stack_argument_prefix(unit, event_index=0)

        self.assertEqual(recovered.status, "complete")
        self.assertEqual(
            [argument["value"] for argument in recovered.arguments],
            [0x41602C, 0x416038],
        )
        self.assertEqual(
            [row["argument_index"] for row in recovered.evidence],
            [0, 1],
        )

    def test_unknown_memory_write_before_call_fails_closed(self) -> None:
        call = {
            "kind": "indirect_call",
            "return_rva": 0x1010,
            "register_inputs": {"esp": reg("esp")},
        }
        recovered = recover_pe32_stack_call_arguments(
            {
                "semantics": {
                    "external_events": [call],
                    "ordered_events": [
                        {
                            "kind": "write",
                            "width": 4,
                            "address": reg("eax"),
                            "value": const(1),
                        },
                        call,
                    ],
                }
            },
            event_index=0,
            argument_words=0,
        )

        self.assertEqual(recovered.status, "incomplete")
        self.assertEqual(recovered.failure_code, "non_affine_pre_call_memory_write")


if __name__ == "__main__":
    unittest.main()
