from __future__ import annotations

import unittest

from spaghetti_extractor.abi.compatibility import compare_physical_abis
from spaghetti_extractor.abi.model import AbiValueV1, StackCleanupV1
from tests.unit.abi._support import (
    physical_profile,
    register_location,
    scalar_value,
    stack_location,
)


class PhysicalAbiCompatibilityTests(unittest.TestCase):
    def test_identical_profiles_are_exact_matches(self) -> None:
        observed = physical_profile()
        expected = physical_profile()

        match = compare_physical_abis(observed, expected)

        self.assertEqual(match.status, "complete")
        self.assertEqual(match.kind, "exact")
        self.assertEqual(match.issues, ())
        self.assertEqual(
            match.compatibility_id,
            compare_physical_abis(observed, expected).compatibility_id,
        )

    def test_location_changes_require_an_adapter(self) -> None:
        expected = physical_profile()
        observed = physical_profile(
            arguments=(scalar_value("arg0", register_location("ecx")),)
        )

        direct = compare_physical_abis(observed, expected)
        adapted = compare_physical_abis(observed, expected, allow_adapter=True)

        self.assertEqual(direct.kind, "violated")
        self.assertEqual(
            [(issue.code, issue.field) for issue in direct.issues],
            [("physical_value_location_mismatch", "arguments[0].fragments")],
        )
        self.assertEqual(adapted.status, "complete")
        self.assertEqual(adapted.kind, "adapter_compatible")
        self.assertEqual(adapted.issues, ())

    def test_split_and_contiguous_values_are_adapter_compatible(self) -> None:
        expected_result = AbiValueV1(
            "result0",
            64,
            "ordinary",
            (
                register_location("eax", value_bit_offset=0),
                register_location("edx", value_bit_offset=32),
            ),
        )
        observed_result = AbiValueV1(
            "result0",
            64,
            "ordinary",
            (
                stack_location(4, width_bits=64),
            ),
        )
        expected = physical_profile(results=(expected_result,))
        observed = physical_profile(results=(observed_result,))

        self.assertEqual(
            compare_physical_abis(
                observed, expected, allow_adapter=True
            ).kind,
            "adapter_compatible",
        )

    def test_cdecl_and_stdcall_cleanup_are_incompatible_even_with_adapter(self) -> None:
        cdecl = physical_profile()
        stdcall = physical_profile(
            calling_convention="stdcall",
            stack_cleanup=StackCleanupV1("callee", 4),
        )

        match = compare_physical_abis(cdecl, stdcall, allow_adapter=True)

        self.assertEqual(match.status, "violated")
        self.assertEqual(match.kind, "violated")
        self.assertEqual(
            [(issue.code, issue.field) for issue in match.issues],
            [("physical_abi_field_mismatch", "stack_cleanup")],
        )

    def test_callback_contract_mismatch_cannot_be_adapted(self) -> None:
        expected = physical_profile(
            arguments=(
                scalar_value(
                    "arg0",
                    stack_location(4),
                    role="callback",
                    callback_abi_id="callback-profile-v1",
                ),
            )
        )
        observed = physical_profile(
            arguments=(
                scalar_value(
                    "arg0",
                    register_location("ecx"),
                    role="callback",
                    callback_abi_id="callback-profile-v2",
                ),
            )
        )

        match = compare_physical_abis(observed, expected, allow_adapter=True)

        self.assertEqual(match.kind, "violated")
        self.assertEqual(
            [(issue.code, issue.field) for issue in match.issues],
            [("physical_value_shape_mismatch", "arguments[0]")],
        )

    def test_missing_preservation_guarantees_are_incompatible(self) -> None:
        expected = physical_profile()
        observed = physical_profile(preserved_state=("ebp", "ebx", "esi"))

        match = compare_physical_abis(observed, expected, allow_adapter=True)

        self.assertEqual(match.kind, "violated")
        self.assertEqual(match.issues[0].code, "preservation_guarantee_missing")
        self.assertEqual(match.issues[0].field, "preserved_state")


if __name__ == "__main__":
    unittest.main()
