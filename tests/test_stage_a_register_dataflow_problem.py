import copy
import unittest

from spaghetti_extractor.relational.register_dataflow_seed import (
    parse_register_dataflow_problem_seed,
    register_dataflow_problem_seed_payload,
)
from spaghetti_extractor.relational.register_transfer_core import canonical_sha256
from spaghetti_extractor.stage_binary import StageAInputError


class StageARegisterDataflowProblemTests(unittest.TestCase):
    def _seed(self) -> dict[str, object]:
        return register_dataflow_problem_seed_payload(
            original_sha256="a" * 64,
            candidate_sha256="b" * 64,
            contract_sha256="c" * 64,
            behaviors_sha256="d" * 64,
            indirect_call_candidates=[{"id": "a"}, {"id": "b"}],
            import_call_candidates=[],
            callsite_summary_predecessors=[],
        )

    @staticmethod
    def _redigest(seed: dict[str, object]) -> None:
        seed["seed_sha256"] = canonical_sha256({
            key: value for key, value in seed.items()
            if key != "seed_sha256"
        })

    def test_seed_rejects_unknown_fields_and_binary_identity_mismatch(self) -> None:
        seed = self._seed()
        unknown = copy.deepcopy(seed)
        unknown["unchecked"] = True
        with self.assertRaisesRegex(StageAInputError, "fields do not match"):
            parse_register_dataflow_problem_seed(
                unknown,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
                expected_contract_sha256="c" * 64,
                expected_behaviors_sha256="d" * 64,
            )

        with self.assertRaisesRegex(StageAInputError, "original_sha256"):
            parse_register_dataflow_problem_seed(
                seed,
                expected_original_sha256="c" * 64,
                expected_candidate_sha256="b" * 64,
                expected_contract_sha256="c" * 64,
                expected_behaviors_sha256="d" * 64,
            )

    def test_seed_rejects_noncanonical_and_duplicate_proposals(self) -> None:
        seed = self._seed()
        noncanonical = copy.deepcopy(seed)
        noncanonical["indirect_call_candidates"].reverse()
        self._redigest(noncanonical)
        with self.assertRaisesRegex(StageAInputError, "not canonical"):
            parse_register_dataflow_problem_seed(
                noncanonical,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
                expected_contract_sha256="c" * 64,
                expected_behaviors_sha256="d" * 64,
            )

        duplicated = copy.deepcopy(seed)
        duplicated["indirect_call_candidates"].append({"id": "b"})
        duplicated["indirect_call_candidates"].sort(key=lambda row: row["id"])
        self._redigest(duplicated)
        with self.assertRaisesRegex(StageAInputError, "duplicated"):
            parse_register_dataflow_problem_seed(
                duplicated,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
                expected_contract_sha256="c" * 64,
                expected_behaviors_sha256="d" * 64,
            )

    def test_seed_rejects_contract_behavior_identity_drift(self) -> None:
        seed = self._seed()
        with self.assertRaisesRegex(StageAInputError, "behaviors_sha256"):
            parse_register_dataflow_problem_seed(
                seed,
                expected_original_sha256="a" * 64,
                expected_candidate_sha256="b" * 64,
                expected_contract_sha256="c" * 64,
                expected_behaviors_sha256="e" * 64,
            )


if __name__ == "__main__":
    unittest.main()
