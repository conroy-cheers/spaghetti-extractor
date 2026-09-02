from __future__ import annotations

import unittest

from spaghetti_extractor.artifacts.build_formats import (
    FORMAT_SPECS as BUILD_FORMATS,
)
from spaghetti_extractor.artifacts.format_spec import FormatSpecV1
from spaghetti_extractor.candidate.formats import FORMAT_SPECS as CANDIDATE_FORMATS
from spaghetti_extractor.components.formats import FORMAT_SPECS as COMPONENT_FORMATS
from spaghetti_extractor.external.formats import (
    FORMAT_SPECS as EXTERNAL_FORMATS,
)
from spaghetti_extractor.operator.formats import FORMAT_SPECS as OPERATOR_FORMATS
from spaghetti_extractor.pe32.formats import FORMAT_SPECS as PE32_FORMATS
from spaghetti_extractor.qualified_platform.formats import (
    FORMAT_SPECS as QUALIFIED_PLATFORM_FORMATS,
)
from spaghetti_extractor.semantic_objects.formats import (
    FORMAT_SPECS as SEMANTIC_OBJECT_FORMATS,
)
from spaghetti_extractor.semantic_link.formats import (
    FORMAT_SPECS as SEMANTIC_LINK_FORMATS,
)
from spaghetti_extractor.transfer.formats import FORMAT_SPECS as TRANSFER_FORMATS


class FormatSpecTests(unittest.TestCase):
    def test_domain_specs_are_unique_and_round_trip(self) -> None:
        specs = (
            *BUILD_FORMATS,
            *CANDIDATE_FORMATS,
            *COMPONENT_FORMATS,
            *EXTERNAL_FORMATS,
            *OPERATOR_FORMATS,
            *PE32_FORMATS,
            *QUALIFIED_PLATFORM_FORMATS,
            *SEMANTIC_OBJECT_FORMATS,
            *SEMANTIC_LINK_FORMATS,
            *TRANSFER_FORMATS,
        )
        self.assertGreater(len(specs), 0)
        self.assertEqual(len({spec.literal for spec in specs}), len(specs))
        self.assertEqual(len({spec.symbol for spec in specs}), len(specs))
        for spec in specs:
            self.assertEqual(FormatSpecV1.parse(spec.to_payload()), spec)

    def test_literal_version_disagreement_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "version disagree"):
            FormatSpecV1(
                literal="spaghetti-extractor-fixture-v2",
                version=1,
                owner="spaghetti_extractor.candidate.formats",
                codec="spaghetti_extractor.candidate.formats",
                role="fixture",
                state="active",
                symbol="FIXTURE_FORMAT",
            )

    def test_unknown_state_fails_closed(self) -> None:
        payload = CANDIDATE_FORMATS[0].to_payload()
        payload["state"] = "legacy"
        with self.assertRaisesRegex(ValueError, "active or retired"):
            FormatSpecV1.parse(payload)


if __name__ == "__main__":
    unittest.main()
