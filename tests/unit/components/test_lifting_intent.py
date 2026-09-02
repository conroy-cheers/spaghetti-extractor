from __future__ import annotations

import unittest

from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.lifting_intent import ComponentLiftingIntentV1


def _intent() -> ComponentLiftingIntentV1:
    return ComponentLiftingIntentV1.create(
        program_id="fixture-program",
        components=[{
            "id": "lower",
            "label": "ASCII lower",
            "source": {
                "files": ["components/lower.c"],
                "shared_inputs": [],
                "operation_symbols": {"convert": "fixture_lower"},
            },
        }],
        groups=[{"id": "all", "label": "All", "members": ["lower"]}],
        configurations=[{
            "id": "portable",
            "label": "Portable",
            "selections": [
                {"kind": "component", "id": "lower", "activation": "enabled"}
            ],
        }],
    )


class ComponentLiftingIntentTests(unittest.TestCase):
    def test_round_trip_is_content_bound(self) -> None:
        intent = _intent()
        self.assertEqual(ComponentLiftingIntentV1.parse(intent.to_payload()), intent)
        stale = intent.to_payload()
        stale["components"][0]["label"] = "Changed"
        with self.assertRaisesRegex(BoundaryModelError, "digest is stale"):
            ComponentLiftingIntentV1.parse(stale)

    def test_rejects_parallel_machine_authority_fields(self) -> None:
        payload = _intent().to_payload()
        payload["components"][0]["selector"] = {"entry_rva": 1}
        with self.assertRaisesRegex(BoundaryModelError, "fields are not canonical"):
            ComponentLiftingIntentV1.parse(payload)

    def test_representation_proof_classification_is_explicit_intent(self) -> None:
        payload = _intent().to_payload()
        payload["components"][0]["proof_classification"] = "encapsulated_owned"
        payload.pop("intent_sha256")
        classified = ComponentLiftingIntentV1.create(
            program_id=payload["program_id"],
            components=payload["components"],
            groups=payload["groups"],
            configurations=payload["configurations"],
        )
        self.assertEqual(
            classified.components[0]["proof_classification"],
            "encapsulated_owned",
        )


if __name__ == "__main__":
    unittest.main()
