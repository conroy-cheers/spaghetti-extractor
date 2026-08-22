from __future__ import annotations

import unittest

from spaghetti_extractor.components.capabilities import (
    CapabilityLifecycle,
    CapabilityStatus,
    CheckedCapabilityState,
    CheckedReference,
    ReferencePermission,
    spx_reference_runtime_header,
    spx_reference_runtime_source,
)


class CheckedCapabilityTests(unittest.TestCase):
    def test_type_and_generation_checks_fail_closed(self) -> None:
        capability = CheckedCapabilityState(7, 2, 19, 3)
        checked, status = capability.begin_action(expected_type_tag=8)
        self.assertEqual(status, CapabilityStatus.TYPE_MISMATCH)
        self.assertEqual(checked.action_count, 0)
        checked, status = capability.begin_action(
            expected_type_tag=7, generation=2
        )
        self.assertEqual(status, CapabilityStatus.EXPIRED)
        self.assertEqual(checked.action_count, 0)

    def test_expiration_preserves_identity_and_rejects_actions(self) -> None:
        capability = CheckedCapabilityState(7, 2, 19, 3).expire()
        self.assertEqual(capability.lifecycle, CapabilityLifecycle.EXPIRED)
        checked, status = capability.begin_action(
            expected_type_tag=7, generation=3
        )
        self.assertEqual(status, CapabilityStatus.EXPIRED)
        self.assertEqual(checked.instance_id, 19)

    def test_reference_derivation_preserves_origin_and_generation(self) -> None:
        reference = CheckedReference(
            domain=3,
            object_id=7,
            generation=2,
            offset=4,
            extent=12,
            permissions=int(ReferencePermission.READ),
        )
        derived = reference.derive(3)
        self.assertEqual(derived.offset, 7)
        self.assertEqual(derived.difference(reference), 3)
        self.assertEqual(
            derived.validate(
                domain=3,
                object_id=7,
                generation=2,
                extent=12,
                required_permissions=int(ReferencePermission.READ),
            ),
            CapabilityStatus.OK,
        )

    def test_reference_generation_origin_and_bounds_fail_closed(self) -> None:
        reference = CheckedReference(3, 7, 2, 4, 12, 1)
        self.assertEqual(
            reference.validate(
                domain=3,
                object_id=7,
                generation=1,
                extent=12,
                required_permissions=1,
            ),
            CapabilityStatus.EXPIRED,
        )
        with self.assertRaisesRegex(ValueError, "outside its origin"):
            reference.derive(8)
        with self.assertRaisesRegex(ValueError, "one live origin"):
            reference.difference(CheckedReference(3, 8, 2, 4, 12, 1))

    def test_reference_runtime_exposes_no_raw_pointer(self) -> None:
        header = spx_reference_runtime_header()
        source = spx_reference_runtime_source()
        self.assertIn("spx_ref_validate", header)
        self.assertIn("spx_view_reference_at", header)
        self.assertIn("spx_view_read_u8", source)
        self.assertIn("spx_ref_derive", source)
        self.assertNotIn("void *address", header)


if __name__ == "__main__":
    unittest.main()
