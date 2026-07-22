from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.roundtrip_fuzz.generator import generate_spike_corpus
from spaghetti_extractor.roundtrip_fuzz.model import (
    ExpectedDisposition,
    canonical_payload_sha256,
    load_case_manifest,
    load_corpus_manifest,
)
from spaghetti_extractor.roundtrip_fuzz.reducer import reduce_case_manifest
from spaghetti_extractor.util import sha256_file


def _artifact_set_sha256(case_manifest: Path) -> str:
    manifest = load_case_manifest(case_manifest)
    artifacts = manifest.verify_artifacts(case_manifest.parent)
    return canonical_payload_sha256({
        role: sha256_file(path) for role, path in sorted(artifacts.items())
    })


def _tree_sha256(root: Path) -> str:
    return canonical_payload_sha256({
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    })


class _CheckedMismatchRunner:
    """Cheap stand-in for an already-qualified checked-witness replay.

    This test qualifies reducer orchestration, not the Lean witness checker. It
    verifies every real PE/map/contract artifact set before returning the same
    checked mismatch family that a proof-core run would expose.
    """

    def __init__(self, *, artifact_bound_violation_id: bool = False) -> None:
        self.artifact_sets: list[str] = []
        self.artifact_bound_violation_id = artifact_bound_violation_id

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        corpus_path = Path(kwargs["corpus"])
        corpus = load_corpus_manifest(corpus_path)
        selected_id = kwargs["case_ids"][0]
        reference = next(item for item in corpus.cases if item.id == selected_id)
        case_path = corpus_path.parent / reference.path
        manifest = load_case_manifest(case_path)
        artifacts = manifest.verify_artifacts(case_path.parent)
        self.artifact_sets.append(_artifact_set_sha256(case_path))

        proposal = json.loads(
            artifacts["relation_proposal"].read_text(encoding="utf-8")
        )
        self.assert_equal(
            proposal["original"]["sha256"], sha256_file(artifacts["original_pe"])
        )
        self.assert_equal(
            proposal["candidate"]["sha256"], sha256_file(artifacts["candidate_pe"])
        )

        expected = manifest.expectation.disposition.value
        is_negative = manifest.mutation is not None
        actual = "violated" if is_negative else "pass"
        violation = None
        if is_negative:
            violation_id = "stable-register-result-mismatch"
            if self.artifact_bound_violation_id:
                violation_id = "register-result-mismatch-" + sha256_file(
                    artifacts["candidate_pe"]
                )[:16]
            violation = {
                "status": "violated",
                "violation_id": violation_id,
                "family": manifest.expectation.witness_family,
                "checks": {
                    "binary_binding": True,
                    "decoded_semantics": True,
                    "lean_replay": True,
                },
                "first_proved_mismatch": {
                    "relation_atom": "register-eax",
                },
            }
        return {
            "format": "stage-a-roundtrip-run-result-v1",
            "status": actual,
            "cases": [{
                "format": "stage-a-roundtrip-case-result-v1",
                "case_id": manifest.id,
                "mode": kwargs["mode"],
                "expected_disposition": expected,
                "actual_disposition": actual,
                "expectation_matched": expected == actual,
                "phases": [],
                "acceptance": {"theorem": None, "authority": None},
                "frontiers": [],
                "violation": violation,
                "error": None,
            }],
        }

    @staticmethod
    def assert_equal(left: object, right: object) -> None:
        if left != right:
            raise AssertionError(f"artifact binding mismatch: {left!r} != {right!r}")


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"),
    "MinGW compiler is required for reducer qualification",
)
class StageARoundTripReducerQualificationTests(unittest.TestCase):
    def test_real_pe_reduction_is_deterministic_and_replays_preserved_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_root = root / "corpus"
            generate_spike_corpus(out=corpus_root, seed=7, count=3, toolchain="gnu")
            source = (
                corpus_root
                / "cases"
                / "spike-002-negative-bounded-loop"
                / "case.json"
            )

            results: list[dict[str, Any]] = []
            output_hashes: list[str] = []
            for name in ("first", "second"):
                runner = _CheckedMismatchRunner()
                output = root / name
                report = reduce_case_manifest(
                    case=source,
                    predicate="mismatch-family=register-eax",
                    out=output,
                    max_accepted_steps=2,
                    _run=runner,
                )
                results.append(report)
                output_hashes.append(_tree_sha256(output))

                materializations = report["materializations"]
                self.assertEqual(len(runner.artifact_sets), len(materializations))
                self.assertEqual(
                    runner.artifact_sets,
                    [item["artifact_set_sha256"] for item in materializations],
                )
                self.assertTrue(all(
                    item["predicate_replayed"] is True
                    and item["predicate_observation"]["satisfied"] is True
                    and item["predicate_observation"]["identity"] == "register-eax"
                    and item["predicate_observation"]["family"]
                    == "checked-mismatch-family"
                    for item in materializations
                    if item["candidate_sha256"] in {
                        step["after_sha256"]
                        for step in report["reduction"]["lineage"]["steps"]
                    }
                ))
                self.assertGreater(report["reduction"]["accepted_steps"], 0)
                self.assertEqual(
                    report["predicate"]["required_identity"], "register-eax"
                )
                self.assertEqual(
                    report["predicate"]["required_family"],
                    "checked-mismatch-family",
                )
                self.assertTrue(
                    report["trust"][
                        "predicate_replayed_after_every_accepted_reduction"
                    ]
                )
                persisted = load_case_manifest(output / "case" / "case.json")
                persisted.verify_artifacts(output / "case")
                self.assertEqual(
                    persisted.expectation.disposition,
                    ExpectedDisposition.VIOLATED,
                )

            self.assertEqual(output_hashes[0], output_hashes[1])
            self.assertEqual(
                results[0]["reduction"]["candidate_sha256"],
                results[1]["reduction"]["candidate_sha256"],
            )
            self.assertEqual(
                results[0]["reduction"]["lineage"],
                results[1]["reduction"]["lineage"],
            )

            drifting_runner = _CheckedMismatchRunner(
                artifact_bound_violation_id=True
            )
            drift_report = reduce_case_manifest(
                case=source,
                predicate="violation-family=relational-behavior-mismatch-v1",
                out=root / "identity-drift",
                max_accepted_steps=1,
                _run=drifting_runner,
            )
            self.assertEqual(drift_report["reduction"]["accepted_steps"], 0)
            self.assertGreater(drift_report["reduction"]["attempts"], 0)
            replayed = [
                item["predicate_observation"]
                for item in drift_report["materializations"]
                if item["predicate_replayed"] is True
            ]
            self.assertTrue(replayed[0]["satisfied"])
            self.assertTrue(all(
                observation["satisfied"] is False
                and observation["details"]["checked_violation_preservation"][
                    "preserved"
                ]
                is False
                for observation in replayed[1:]
            ))


if __name__ == "__main__":
    unittest.main()
