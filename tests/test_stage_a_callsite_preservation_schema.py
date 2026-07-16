import copy
import unittest
from dataclasses import FrozenInstanceError, replace

from spaghetti_extractor.relational.analyses.registers import (
    _propose_internal_callsite_preservation_summaries,
)
from spaghetti_extractor.relational.callsite_preservation import (
    ArtifactStatus,
    callsite_preservation_artifact_hash,
    parse_callsite_preservation_artifact,
    serialize_callsite_preservation_artifact,
    validate_callsite_preservation_artifact,
)
from spaghetti_extractor.relational.schema import SchemaError


REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
IMPORT = {
    "dll": "kernel32.dll",
    "symbol": "WideCharToMultiByte",
}


def _behavior(outcome):
    return {
        "format": "stage-a-normalized-behavior-v1",
        "registers": {
            register: {"op": "input_reg", "reg": register}
            for register in REGISTERS
        },
        "x87": {},
        "writes": [],
        "flags": None,
        "outcome": outcome,
    }


def _pair(outcome):
    behavior = _behavior(outcome)
    return {
        "original_ir": behavior,
        "candidate_ir": copy.deepcopy(behavior),
    }


def _valid_artifact():
    contract = {
        "regions": [
            {"numeric_id": 100},
            {"numeric_id": 200},
            {"numeric_id": 300},
            {"numeric_id": 400},
        ],
    }
    behaviors = [
        _pair({"op": "call", "target": 300, "continuation": 200}),
        _pair({
            "op": "returned",
            "target": {"op": "input_reg", "reg": "eax"},
        }),
        _pair({"op": "jump", "target": 400}),
        _pair({
            "op": "returned",
            "target": {"op": "input_reg", "reg": "eax"},
        }),
    ]
    import_analysis = {
        "relations": [{
            "region_index": 0,
            "original_register": "esi",
            "candidate_register": "esi",
            "import": IMPORT,
        }],
    }
    register_relations = {
        "return_slot_analysis": {
            "call_summary_analysis": {
                "summaries": [{
                    "callsite_region_index": 0,
                    "callee_region_index": 2,
                    "continuation_region_index": 1,
                    "return_region_indices": [3],
                    "closed": True,
                }],
            },
        },
    }
    return _propose_internal_callsite_preservation_summaries(
        contract,
        behaviors,
        import_analysis,
        register_relations,
    )


class StageACallsitePreservationSchemaTests(unittest.TestCase):
    def setUp(self):
        self.payload = _valid_artifact()

    def assertRejected(self, payload, *, region_count=4):
        with self.assertRaises(SchemaError):
            parse_callsite_preservation_artifact(
                payload,
                region_count=region_count,
            )

    def test_round_trip_is_deterministic_and_model_is_immutable(self):
        parsed = parse_callsite_preservation_artifact(
            self.payload,
            region_count=4,
        )

        self.assertEqual(parsed.status, ArtifactStatus.PROPOSAL_REQUIRES_REPLAY)
        self.assertEqual(
            serialize_callsite_preservation_artifact(parsed),
            self.payload,
        )
        self.assertEqual(
            parse_callsite_preservation_artifact(
                serialize_callsite_preservation_artifact(parsed),
                region_count=4,
            ),
            parsed,
        )
        self.assertEqual(
            validate_callsite_preservation_artifact(parsed, region_count=4),
            parsed,
        )
        with self.assertRaises(FrozenInstanceError):
            parsed.status = ArtifactStatus.FIXED_POINT_BUDGET_EXHAUSTED

    def test_artifact_hash_is_stable_across_round_trip_and_key_order(self):
        parsed = parse_callsite_preservation_artifact(
            self.payload,
            region_count=4,
        )
        reordered = dict(reversed(list(self.payload.items())))
        expected = callsite_preservation_artifact_hash(
            self.payload,
            region_count=4,
        )

        self.assertEqual(callsite_preservation_artifact_hash(parsed), expected)
        self.assertEqual(
            callsite_preservation_artifact_hash(reordered, region_count=4),
            expected,
        )
        self.assertEqual(
            [row["certificate_hash"] for row in self.payload["certificates"]],
            [
                row["certificate_hash"]
                for row in serialize_callsite_preservation_artifact(parsed)[
                    "certificates"
                ]
            ],
        )

    def test_serializer_revalidates_typed_instances_and_supports_fail_status(self):
        parsed = parse_callsite_preservation_artifact(
            self.payload,
            region_count=4,
        )
        exhausted = replace(
            parsed,
            status=ArtifactStatus.FIXED_POINT_BUDGET_EXHAUSTED,
        )
        self.assertEqual(
            serialize_callsite_preservation_artifact(exhausted)["status"],
            "incomplete_fixed_point_budget_exhausted",
        )

        inconsistent = replace(
            parsed,
            counts=replace(parsed.counts, certificates=0),
        )
        with self.assertRaises(SchemaError):
            serialize_callsite_preservation_artifact(inconsistent)

    def test_unknown_missing_and_unsupported_version_fields_are_rejected(self):
        unknown_top = copy.deepcopy(self.payload)
        unknown_top["consumer_hint"] = "ignore-me"
        missing_trust_field = copy.deepcopy(self.payload)
        del missing_trust_field["trust"]["acceptance_authority"]
        unknown_summary = copy.deepcopy(self.payload)
        unknown_summary["summaries"][0]["trusted"] = True
        unsupported_version = copy.deepcopy(self.payload)
        unsupported_version["format"] = (
            "stage-a-relational-callsite-preservation-v2"
        )

        for malformed in (
            unknown_top,
            missing_trust_field,
            unknown_summary,
            unsupported_version,
        ):
            with self.subTest(malformed=malformed):
                self.assertRejected(malformed)

    def test_duplicate_ids_hashes_and_edges_are_rejected(self):
        duplicate_certificate = copy.deepcopy(self.payload)
        duplicate_certificate["certificates"].append(copy.deepcopy(
            duplicate_certificate["certificates"][0]
        ))
        duplicate_proposal = copy.deepcopy(self.payload)
        duplicate_proposal["proposal_edges"].append(copy.deepcopy(
            duplicate_proposal["proposal_edges"][0]
        ))
        duplicate_reachable = copy.deepcopy(self.payload)
        certificate = duplicate_reachable["certificates"][0]
        certificate["reachable_edges"].append(copy.deepcopy(
            certificate["reachable_edges"][0]
        ))

        for malformed in (
            duplicate_certificate,
            duplicate_proposal,
            duplicate_reachable,
        ):
            with self.subTest(malformed=malformed):
                self.assertRejected(malformed)

    def test_noncanonical_and_duplicate_relations_are_rejected(self):
        noncanonical = copy.deepcopy(self.payload)
        noncanonical["summaries"][0]["requested_relations"].append({
            "original": "ebx",
            "candidate": "ebx",
            "import": IMPORT,
        })
        duplicate = copy.deepcopy(self.payload)
        duplicate["summaries"][0]["requested_relations"].append(copy.deepcopy(
            duplicate["summaries"][0]["requested_relations"][0]
        ))

        self.assertRejected(noncanonical)
        self.assertRejected(duplicate)

    def test_invalid_region_indices_and_return_inventories_are_rejected(self):
        out_of_range = copy.deepcopy(self.payload)
        out_of_range["proposal_edges"][0]["target_region_index"] = 4
        negative = copy.deepcopy(self.payload)
        negative["summaries"][0]["callsite_region_index"] = -1
        malformed_summary_returns = copy.deepcopy(self.payload)
        malformed_summary_returns["summaries"][0]["return_region_indices"] = []
        malformed_certificate_returns = copy.deepcopy(self.payload)
        malformed_certificate_returns["certificates"][0]["return_inventory"] = []

        for malformed in (
            out_of_range,
            negative,
            malformed_summary_returns,
            malformed_certificate_returns,
        ):
            with self.subTest(malformed=malformed):
                self.assertRejected(malformed)

    def test_inconsistent_counts_status_and_trust_are_rejected(self):
        wrong_counts = copy.deepcopy(self.payload)
        wrong_counts["counts"]["certificates"] = 0
        wrong_status = copy.deepcopy(self.payload)
        wrong_status["summaries"][0]["status"] = "incomplete"
        acceptance_authority = copy.deepcopy(self.payload)
        acceptance_authority["trust"]["acceptance_authority"] = True
        accepted_edge = copy.deepcopy(self.payload)
        accepted_edge["proposal_edges"][0]["proposal_only"] = False

        for malformed in (
            wrong_counts,
            wrong_status,
            acceptance_authority,
            accepted_edge,
        ):
            with self.subTest(malformed=malformed):
                self.assertRejected(malformed)

    def test_certificate_payload_tampering_invalidates_hash(self):
        malformed = copy.deepcopy(self.payload)
        malformed["certificates"][0]["behavior_hashes"][0]["original"] = (
            "0" * 64
        )

        self.assertRejected(malformed)


if __name__ == "__main__":
    unittest.main()
