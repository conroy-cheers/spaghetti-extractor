from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.isa_conformance import (
    ISAConformanceCorpus,
    ISAConformanceError,
    serialize_isa_conformance_report,
)
from spaghetti_extractor.isa_conformance_shards import (
    lean_semantic_forms_payload,
    merge_isa_conformance_shards,
    merge_lean_semantic_form_shards,
    partition_isa_conformance_corpus,
)
from spaghetti_extractor.isa_conformance_unicorn import run_unicorn_corpus
from tests.test_stage_a_isa_conformance_unicorn import _case, _corpus


class ISAConformanceShardTests(unittest.TestCase):
    def _fixture(self) -> ISAConformanceCorpus:
        return _corpus(
            *(
                _case(case_id=f"case-{index:02d}")
                for index in range(24)
            )
        )

    def test_stable_shards_merge_to_exact_full_report(self):
        corpus = self._fixture()
        shards = [
            partition_isa_conformance_corpus(
                corpus, shard_index=index, shard_count=4
            )
            for index in range(4)
        ]
        reports = [
            serialize_isa_conformance_report(
                run_unicorn_corpus(shard), corpus=shard
            )
            for shard in shards
        ]

        merged = merge_isa_conformance_shards(
            corpus, shard_corpora=shards, shard_reports=reports
        )
        direct = run_unicorn_corpus(corpus)

        self.assertEqual(merged, direct)
        self.assertEqual(
            [row.case_id for row in merged.observations],
            [case.id for case in corpus.cases],
        )

    def test_merge_rejects_missing_and_overlapping_shards(self):
        corpus = self._fixture()
        shards = [
            partition_isa_conformance_corpus(
                corpus, shard_index=index, shard_count=4
            )
            for index in range(4)
        ]
        reports = [
            serialize_isa_conformance_report(
                run_unicorn_corpus(shard), corpus=shard
            )
            for shard in shards
        ]

        with self.assertRaisesRegex(ISAConformanceError, "full corpus"):
            merge_isa_conformance_shards(
                corpus,
                shard_corpora=shards[:-1],
                shard_reports=reports[:-1],
            )
        with self.assertRaisesRegex(ISAConformanceError, "overlap"):
            merge_isa_conformance_shards(
                corpus,
                shard_corpora=[*shards, shards[0]],
                shard_reports=[*reports, reports[0]],
            )

    def test_semantic_form_shards_are_classifier_and_corpus_bound(self):
        corpus = self._fixture()
        shards = [
            partition_isa_conformance_corpus(
                corpus, shard_index=index, shard_count=4
            )
            for index in range(4)
        ]
        payloads = [
            lean_semantic_forms_payload(
                shard,
                {case.id: f"fixture.form.{case.id}" for case in shard.cases},
            )
            for shard in shards
        ]

        merged = merge_lean_semantic_form_shards(
            corpus, shard_corpora=shards, shard_payloads=payloads
        )

        self.assertEqual(merged["corpus_id"], corpus.id)
        self.assertEqual(len(merged["cases"]), len(corpus.cases))
        corrupted = copy.deepcopy(payloads)
        corrupted[0]["classifier_sha256"] = "0" * 64
        with self.assertRaisesRegex(ISAConformanceError, "classifier"):
            merge_lean_semantic_form_shards(
                corpus, shard_corpora=shards, shard_payloads=corrupted
            )


if __name__ == "__main__":
    unittest.main()
