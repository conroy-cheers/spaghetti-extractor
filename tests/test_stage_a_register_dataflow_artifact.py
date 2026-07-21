import copy
import unittest

from spaghetti_extractor.relational.register_dataflow_artifact import (
    REGISTER_ORDER,
    parse_register_transfer_table,
    register_transfer_observation_sha256,
    register_transfer_semantics_sha256,
    register_transfer_table_payload,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _relations(relation: str = "exact") -> list[dict[str, object]]:
    return [
        {"register": register, "relation": relation}
        for register in REGISTER_ORDER
    ]


class StageARegisterDataflowArtifactTests(unittest.TestCase):
    def _payload(self) -> dict[str, object]:
        inputs = _relations()
        probe = []
        observation_sha256 = register_transfer_observation_sha256(
            input_relations=inputs,
            fixed_immutable_probe=probe,
        )
        context_sha256 = "d" * 64
        return register_transfer_table_payload(
            original_sha256="a" * 64,
            candidate_sha256="b" * 64,
            graph_sha256="c" * 64,
            regions=[{
                "id": "entry",
                "context_sha256": context_sha256,
                "transfer_semantics_sha256": (
                    register_transfer_semantics_sha256(
                        context_sha256=context_sha256,
                        observation_sha256=[observation_sha256],
                    )
                ),
                "observations": [{
                    "sha256": observation_sha256,
                    "input_relations": inputs,
                    "fixed_immutable_probe": probe,
                    "output_relations": _relations(),
                    "reasons": {
                        register: "identity_transfer"
                        for register in REGISTER_ORDER
                    },
                }],
            }],
            propagation={
                "regions": [{
                    "id": "entry",
                    "seed_relation": "exact",
                    "stack_window_registers": [],
                }],
                "edges": [],
            },
        )

    def _parse(self, payload: object):
        return parse_register_transfer_table(
            payload,
            expected_original_sha256="a" * 64,
            expected_candidate_sha256="b" * 64,
            expected_graph_sha256="c" * 64,
        )

    def test_roundtrip_is_strict_and_canonical(self) -> None:
        payload = self._payload()
        table = self._parse(payload)
        self.assertEqual([region["id"] for region in table.regions], ["entry"])
        self.assertEqual(table.propagation_edges, ())

    def test_tampered_input_or_semantics_digest_is_rejected(self) -> None:
        tampered = copy.deepcopy(self._payload())
        tampered["regions"][0]["observations"][0]["input_relations"][0][
            "relation"
        ] = "related_word"
        with self.assertRaisesRegex(StageAInputError, "digest"):
            self._parse(tampered)

        tampered = copy.deepcopy(self._payload())
        tampered["regions"][0]["transfer_semantics_sha256"] = "e" * 64
        with self.assertRaisesRegex(StageAInputError, "semantics digest"):
            self._parse(tampered)

    def test_duplicate_regions_observations_and_unknown_fields_fail_closed(self):
        duplicate_region = copy.deepcopy(self._payload())
        duplicate_region["regions"].append(
            copy.deepcopy(duplicate_region["regions"][0])
        )
        duplicate_region["region_count"] = 2
        with self.assertRaisesRegex(StageAInputError, "IDs must be unique"):
            self._parse(duplicate_region)

        duplicate_observation = copy.deepcopy(self._payload())
        duplicate_observation["regions"][0]["observations"].append(
            copy.deepcopy(
                duplicate_observation["regions"][0]["observations"][0]
            )
        )
        with self.assertRaisesRegex(StageAInputError, "duplicate"):
            self._parse(duplicate_observation)

        unknown = copy.deepcopy(self._payload())
        unknown["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "unexpected"):
            self._parse(unknown)


if __name__ == "__main__":
    unittest.main()
