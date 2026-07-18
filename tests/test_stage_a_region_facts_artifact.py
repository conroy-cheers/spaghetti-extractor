from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from types import MappingProxyType

from spaghetti_extractor.relational.region_facts_artifact import (
    REGION_FACTS_ARTIFACT_FORMAT,
    REGION_FACTS_ARTIFACT_STATUS,
    RegionFactsArtifact,
    region_facts_artifact_sha256,
    region_facts_payload,
)
from spaghetti_extractor.relational.schema import (
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageARegionFactsArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hashes = {
            "original_sha256": "a" * 64,
            "candidate_sha256": "b" * 64,
            "input_relation_contract_sha256": "c" * 64,
            "normalized_behaviors_sha256": "d" * 64,
            "region_facts_semantics_sha256": "e" * 64,
        }
        self.fields = {
            "region_count": 2,
            "contract": {
                "format": "stage-a-relation-contract-v1",
                "regions": [
                    {"id": "entry", "facts": {"successors": [1]}},
                    {"id": "return", "facts": {"successors": []}},
                ],
            },
            "initial_static_code_pointer_analysis": {
                "accepted": [{"target_id": 1, "uses": ["entry"]}],
            },
            "indirect_call_candidates": [
                {"region_id": "entry", "targets": ["return"]},
            ],
            "table_call_proposals": [
                {"region_id": "entry", "table": {"entries": [1]}},
            ],
            "dynamic_call_candidates": [
                {"region_id": "entry", "range": [0, 4]},
            ],
            "import_register_seeds": [
                {"region_id": "entry", "registers": ["eax"]},
            ],
            "machine_call_analysis": {
                "calls": [{"region_id": "entry", "arguments": [0]}],
            },
        }

    def _payload(self) -> dict[str, object]:
        return region_facts_payload(**self.hashes, **self.fields)

    def _parse(self, payload: object) -> RegionFactsArtifact:
        return RegionFactsArtifact.parse(
            payload,
            **{
                f"expected_{field_name}": value
                for field_name, value in self.hashes.items()
            },
        )

    def test_canonical_roundtrip_binds_envelope_and_hash(self) -> None:
        payload = self._payload()
        artifact = self._parse(json.loads(json.dumps(payload)))

        self.assertEqual(payload["format"], REGION_FACTS_ARTIFACT_FORMAT)
        self.assertEqual(payload["profile"], STAGE_A_RELATIONAL_PROFILE_ID)
        self.assertEqual(payload["model"], STAGE_A_RELATIONAL_MODEL_ID)
        self.assertEqual(payload["status"], REGION_FACTS_ARTIFACT_STATUS)
        self.assertEqual(artifact.to_payload(), payload)
        self.assertEqual(
            region_facts_artifact_sha256(artifact),
            region_facts_artifact_sha256(payload),
        )

    def test_parse_recursively_freezes_nested_payload(self) -> None:
        artifact = self._parse(self._payload())

        self.assertIsInstance(artifact.contract, MappingProxyType)
        self.assertIsInstance(artifact.contract["regions"], tuple)
        self.assertIsInstance(
            artifact.contract["regions"][0], MappingProxyType
        )
        self.assertIsInstance(artifact.indirect_call_candidates, tuple)
        self.assertIsInstance(
            artifact.indirect_call_candidates[0], MappingProxyType
        )
        with self.assertRaises(TypeError):
            artifact.contract["regions"][0]["id"] = "tampered"
        with self.assertRaises(AttributeError):
            artifact.indirect_call_candidates.append({})
        with self.assertRaises(FrozenInstanceError):
            artifact.region_count = 3

    def test_mutable_payload_is_deeply_independent(self) -> None:
        artifact = self._parse(self._payload())
        first = artifact.mutable_payload()
        second = artifact.mutable_payload()

        self.assertEqual(set(first), set(self.fields) - {"region_count"})
        first["contract"]["regions"][0]["facts"]["successors"].append(9)
        first["indirect_call_candidates"][0]["targets"].append("tampered")
        self.assertEqual(
            second["contract"]["regions"][0]["facts"]["successors"], [1]
        )
        self.assertEqual(
            artifact.contract["regions"][0]["facts"]["successors"], (1,)
        )
        self.assertEqual(
            artifact.indirect_call_candidates[0]["targets"], ("return",)
        )

    def test_expected_identity_tampering_is_rejected(self) -> None:
        payload = self._payload()
        for field_name in self.hashes:
            with self.subTest(field=field_name):
                tampered = copy.deepcopy(payload)
                tampered[field_name] = "f" * 64
                with self.assertRaisesRegex(
                    StageAInputError, f"{field_name} mismatch"
                ):
                    self._parse(tampered)

        unbound = copy.deepcopy(payload)
        unbound["original_sha256"] = "f" * 64
        self.assertEqual(
            RegionFactsArtifact.parse(unbound).original_sha256, "f" * 64
        )

    def test_constant_identity_and_status_tampering_is_rejected(self) -> None:
        for field_name, replacement in (
            ("format", "stage-a-relational-region-facts-v2"),
            ("profile", "wrong-profile"),
            ("model", "wrong-model"),
            ("status", "analyzed"),
        ):
            with self.subTest(field=field_name):
                payload = self._payload()
                payload[field_name] = replacement
                with self.assertRaisesRegex(
                    StageAInputError, f"{field_name} mismatch"
                ):
                    self._parse(payload)

    def test_hashes_must_be_lowercase_sha256_values(self) -> None:
        for malformed in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(value=malformed):
                payload = self._payload()
                payload["original_sha256"] = malformed
                with self.assertRaisesRegex(
                    StageAInputError, "64 lowercase hex characters"
                ):
                    RegionFactsArtifact.parse(payload)

    def test_unknown_and_missing_top_level_fields_are_rejected(self) -> None:
        unknown = self._payload()
        unknown["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            self._parse(unknown)

        missing = self._payload()
        del missing["machine_call_analysis"]
        with self.assertRaisesRegex(StageAInputError, "missing fields"):
            self._parse(missing)

    def test_duplicate_contract_region_id_is_rejected(self) -> None:
        payload = self._payload()
        payload["contract"]["regions"][1]["id"] = "entry"
        with self.assertRaisesRegex(StageAInputError, "ids must be unique"):
            self._parse(payload)

    def test_contract_region_count_mismatch_is_rejected(self) -> None:
        payload = self._payload()
        payload["region_count"] = 3
        with self.assertRaisesRegex(
            StageAInputError, "region_count does not match"
        ):
            self._parse(payload)

    def test_malformed_candidate_rows_are_rejected(self) -> None:
        for field_name in (
            "indirect_call_candidates",
            "table_call_proposals",
            "dynamic_call_candidates",
            "import_register_seeds",
        ):
            with self.subTest(field=field_name):
                payload = self._payload()
                payload[field_name] = ["not-an-object"]
                with self.assertRaisesRegex(StageAInputError, "must be an object"):
                    self._parse(payload)

    def test_malformed_payload_field_types_are_rejected(self) -> None:
        for field_name, malformed in (
            ("contract", []),
            ("initial_static_code_pointer_analysis", []),
            ("indirect_call_candidates", {}),
            ("machine_call_analysis", []),
        ):
            with self.subTest(field=field_name):
                payload = self._payload()
                payload[field_name] = malformed
                with self.assertRaises(StageAInputError):
                    self._parse(payload)


if __name__ == "__main__":
    unittest.main()
