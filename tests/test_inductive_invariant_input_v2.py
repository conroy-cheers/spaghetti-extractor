from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.inductive_invariant_input_v2 import (
    InductiveInvariantInputV2,
)
from spaghetti_extractor.invariant_certificate_v2 import (
    CutpointInvariantV2,
    ExportRequirementV2,
    InvariantCertificateV2Error,
    InvariantFactV2,
)


class InductiveInvariantInputV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.binary = BinaryBinding("a" * 64, "b" * 64)
        self.profile = "c" * 64
        self.fact = InvariantFactV2.finite("register:eax", (1, 2))
        self.value = InductiveInvariantInputV2.create(
            binary=self.binary,
            profile_sha256=self.profile,
            cutpoint_invariants=(
                CutpointInvariantV2(
                    "unit:loop",
                    (self.fact,),
                ),
            ),
            required_exports=(
                ExportRequirementV2.create("unit:loop", self.fact),
            ),
        )

    def test_round_trip_is_non_authorizing_and_exactly_bound(self) -> None:
        parsed = InductiveInvariantInputV2.parse(
            self.value.to_payload(),
            binary=self.binary,
            profile_sha256=self.profile,
            known_cutpoints=("unit:loop",),
        )
        self.assertEqual(parsed, self.value)
        self.assertFalse(parsed.to_payload()["authorizing"])
        self.assertEqual(set(parsed.cutpoint_facts), {"unit:loop"})
        self.assertEqual(len(parsed.required_exports), 1)

    def test_stale_or_authorizing_proposal_is_rejected(self) -> None:
        stale = copy.deepcopy(self.value.to_payload())
        stale["profile_sha256"] = "d" * 64
        with self.assertRaises(InvariantCertificateV2Error):
            InductiveInvariantInputV2.parse(
                stale,
                binary=self.binary,
                profile_sha256=self.profile,
                known_cutpoints=("unit:loop",),
            )

        claimed = copy.deepcopy(self.value.to_payload())
        claimed["authorizing"] = True
        with self.assertRaises(InvariantCertificateV2Error):
            InductiveInvariantInputV2.parse(
                claimed,
                binary=self.binary,
                profile_sha256=self.profile,
                known_cutpoints=("unit:loop",),
            )

        with self.assertRaisesRegex(
            InvariantCertificateV2Error, "unknown cutpoints"
        ):
            InductiveInvariantInputV2.parse(
                self.value.to_payload(),
                binary=self.binary,
                profile_sha256=self.profile,
                known_cutpoints=("unit:other",),
            )


if __name__ == "__main__":
    unittest.main()
