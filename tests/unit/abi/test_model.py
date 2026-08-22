from __future__ import annotations

import unittest

from spaghetti_extractor.abi.model import (
    AbiEvidenceV1,
    AbiFactV1,
    AbiLocationV1,
    AbiModelError,
    AbiValueV1,
    PhysicalAbiProfileV1,
    ReviewedAbiAssumptionV1,
    stable_id,
)
from tests.unit.abi._support import (
    physical_profile,
    register_location,
    scalar_value,
)


class CanonicalAbiModelTests(unittest.TestCase):
    def test_content_ids_are_stable_for_canonical_equivalents(self) -> None:
        self.assertEqual(
            stable_id("fixture", {"second": [2, 1], "first": {"value": 3}}),
            stable_id("fixture", {"first": {"value": 3}, "second": [2, 1]}),
        )

        first = AbiEvidenceV1.create(
            kind="disassembly",
            producer="fixture-v1",
            subject_kind="function",
            subject_id="function.main",
            dependencies=("dependency.z", "dependency.a", "dependency.z"),
            payload={"register": "eax", "width_bits": 32},
        )
        second = AbiEvidenceV1.create(
            kind="disassembly",
            producer="fixture-v1",
            subject_kind="function",
            subject_id="function.main",
            dependencies=("dependency.a", "dependency.z"),
            payload={"width_bits": 32, "register": "eax"},
        )
        self.assertEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(first.dependencies, ("dependency.a", "dependency.z"))

        first_profile = physical_profile(
            preserved_state=("esi", "ebx", "esi", "ebp", "edi")
        )
        second_profile = physical_profile()
        self.assertEqual(first_profile.profile_id, second_profile.profile_id)

    def test_split_locations_round_trip_without_losing_value_offsets(self) -> None:
        split_result = AbiValueV1(
            value_id="result0",
            width_bits=64,
            role="ordinary",
            fragments=(
                register_location("eax", value_bit_offset=0),
                register_location("edx", value_bit_offset=32),
            ),
        )
        profile = physical_profile(results=(split_result,))

        decoded = PhysicalAbiProfileV1.parse(profile.to_payload())

        self.assertEqual(decoded, profile)
        self.assertEqual(
            tuple(fragment.register for fragment in decoded.results[0].fragments),
            ("eax", "edx"),
        )
        self.assertEqual(
            tuple(
                fragment.value_bit_offset
                for fragment in decoded.results[0].fragments
            ),
            (0, 32),
        )

    def test_overlapping_split_locations_are_rejected(self) -> None:
        with self.assertRaisesRegex(AbiModelError, "fragments overlap"):
            AbiValueV1(
                value_id="arg0",
                width_bits=64,
                role="ordinary",
                fragments=(
                    register_location("eax", width_bits=32, value_bit_offset=0),
                    register_location("edx", width_bits=32, value_bit_offset=16),
                ),
            )

    def test_callback_values_require_an_explicit_physical_abi(self) -> None:
        location = register_location("eax")
        with self.assertRaisesRegex(AbiModelError, "lacks a callback ABI"):
            scalar_value("arg0", location, role="callback")
        with self.assertRaisesRegex(AbiModelError, "non-callback ABI value"):
            scalar_value(
                "arg0",
                location,
                callback_abi_id="callback-profile-v1",
            )

        callback = scalar_value(
            "arg0",
            location,
            role="callback",
            callback_abi_id="callback-profile-v1",
        )
        self.assertEqual(callback.callback_abi_id, "callback-profile-v1")

    def test_missing_fields_and_stale_content_ids_are_rejected(self) -> None:
        profile = physical_profile()
        missing = profile.to_payload()
        del missing["stack_cleanup"]
        with self.assertRaisesRegex(
            AbiModelError, r"missing=\['stack_cleanup'\]"
        ):
            PhysicalAbiProfileV1.parse(missing)

        stale = profile.to_payload()
        stale["arguments"][0]["fragments"][0]["stack_offset"] = 8
        with self.assertRaisesRegex(AbiModelError, "does not bind its contents"):
            PhysicalAbiProfileV1.parse(stale)

    def test_reviewed_assumptions_are_content_bound_and_round_trip(self) -> None:
        fact = AbiFactV1.create(
            subject_id="function.main",
            field="calling_convention",
            status="exact",
            values=("cdecl",),
            evidence_ids=("review.evidence",),
        )
        assumption = ReviewedAbiAssumptionV1.create(
            subject_kind="function",
            subject_id="function.main",
            facts=(fact,),
            rationale="The decorated import and caller cleanup agree.",
            reviewer="reviewer.fixture",
            binary_sha256="a" * 64,
        )

        self.assertEqual(
            ReviewedAbiAssumptionV1.parse(assumption.to_payload()), assumption
        )

        stale = assumption.to_payload()
        stale["rationale"] = "A different rationale."
        with self.assertRaisesRegex(AbiModelError, "does not bind its contents"):
            ReviewedAbiAssumptionV1.parse(stale)

        missing = assumption.to_payload()
        del missing["reviewer"]
        with self.assertRaisesRegex(AbiModelError, r"missing=\['reviewer'\]"):
            ReviewedAbiAssumptionV1.parse(missing)

    def test_fragment_coordinates_are_kind_specific(self) -> None:
        with self.assertRaisesRegex(AbiModelError, "unrelated coordinates"):
            AbiLocationV1(
                "register",
                32,
                register="eax",
                stack_offset=4,
            )


if __name__ == "__main__":
    unittest.main()
