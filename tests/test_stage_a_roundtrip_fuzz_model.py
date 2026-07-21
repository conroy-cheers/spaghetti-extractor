from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.roundtrip_fuzz.model import (
    ROUNDTRIP_CASE_FORMAT,
    ROUNDTRIP_CORPUS_FORMAT,
    ArtifactRef,
    CaseManifest,
    CorpusManifest,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


class RoundTripFuzzModelTests(unittest.TestCase):
    def test_case_manifest_is_strict_and_verifies_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in {
                "semantic.json": b"{}\n",
                "original.exe": b"original",
                "candidate.exe": b"candidate",
                "relation.json": b"{}\n",
            }.items():
                (root / name).write_bytes(content)
            payload = self._case_payload(root)
            manifest = CaseManifest.parse(payload)

            self.assertEqual(manifest.id, "phase0-representative")
            self.assertEqual(
                set(manifest.verify_artifacts(root)),
                {"semantic_program", "original_pe", "candidate_pe", "relation_contract"},
            )

            unexpected = dict(payload)
            unexpected["fixture_name"] = "forbidden"
            with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
                CaseManifest.parse(unexpected)

            (root / "candidate.exe").write_bytes(b"changed")
            with self.assertRaisesRegex(StageAInputError, "binding"):
                manifest.verify_artifacts(root)

    def test_supported_negative_requires_violation_witness_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("semantic.json", "original.exe", "candidate.exe", "relation.json"):
                (root / name).write_bytes(name.encode("ascii"))
            payload = self._case_payload(root)
            payload["expectation"] = {
                "disposition": "violated",
                "witness_family": None,
                "reason_family": None,
            }
            payload["mutation"] = {
                "id": "wrong-addend",
                "semantic_delta": "candidate adds two instead of one",
                "location_id": "entry-add",
            }
            with self.assertRaisesRegex(StageAInputError, "requires only witness_family"):
                CaseManifest.parse(payload)

            payload["expectation"]["witness_family"] = "register-relation-v1"
            parsed = CaseManifest.parse(payload)
            self.assertEqual(parsed.expectation.disposition.value, "violated")

    def test_incomplete_is_reserved_for_named_capability_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("semantic.json", "original.exe", "candidate.exe", "relation.json"):
                (root / name).write_bytes(name.encode("ascii"))
            payload = self._case_payload(root)
            payload["expectation"] = {
                "disposition": "incomplete",
                "witness_family": None,
                "reason_family": None,
            }
            payload["mutation"] = {
                "id": "unsupported-opcode",
                "semantic_delta": "candidate uses an unqualified instruction",
                "location_id": "entry-op",
            }
            with self.assertRaisesRegex(StageAInputError, "requires only reason_family"):
                CaseManifest.parse(payload)

            payload["expectation"]["reason_family"] = "unsupported-instruction"
            self.assertEqual(
                CaseManifest.parse(payload).expectation.disposition.value,
                "incomplete",
            )

    def test_violation_witness_is_only_allowed_for_violated_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "semantic.json", "original.exe", "candidate.exe", "relation.json",
                "witness.json",
            ):
                (root / name).write_bytes(name.encode("ascii"))
            payload = self._case_payload(root)
            witness = ArtifactRef.from_path(
                role="violation_witness", root=root, path=root / "witness.json"
            ).to_payload()
            payload["artifacts"].append(witness)
            with self.assertRaisesRegex(StageAInputError, "expected-violated"):
                CaseManifest.parse(payload)

            payload["expectation"] = {
                "disposition": "violated",
                "witness_family": "register-relation-v1",
                "reason_family": None,
            }
            payload["mutation"] = {
                "id": "wrong-addend",
                "semantic_delta": "candidate adds two instead of one",
                "location_id": "entry-add",
            }
            self.assertEqual(
                CaseManifest.parse(payload).expectation.disposition.value,
                "violated",
            )

    def test_corpus_binds_case_manifests_and_expected_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "cases" / "phase0-representative"
            case_root.mkdir(parents=True)
            for name in ("semantic.json", "original.exe", "candidate.exe", "relation.json"):
                (case_root / name).write_bytes(name.encode("ascii"))
            case_payload = self._case_payload(case_root)
            case_path = case_root / "case.json"
            write_json(case_path, case_payload)
            corpus_payload = {
                "format": ROUNDTRIP_CORPUS_FORMAT,
                "generator_version": "phase0-hand-authored-v1",
                "root_seed": 0,
                "capability_profile": "x86-pe32-relational-v3",
                "toolchain": {
                    "id": "pinned-mingw32-v1",
                    "target": "i686-w64-mingw32",
                    "compiler": "gcc",
                    "compiler_version": "15.2.0",
                    "linker": "gnu-ld",
                    "linker_version": "2.45",
                },
                "cases": [{
                    "id": "phase0-representative",
                    "path": "cases/phase0-representative/case.json",
                    "sha256": sha256_file(case_path),
                    "shard": 0,
                }],
                "expected_counts": {"pass": 1, "violated": 0, "incomplete": 0},
                "shard_count": 1,
            }
            corpus = CorpusManifest.parse(corpus_payload)
            loaded = corpus.load_cases(root)

            self.assertEqual(loaded[0][0].id, "phase0-representative")

            corpus_payload["expected_counts"]["pass"] = 0
            mismatch = CorpusManifest.parse(corpus_payload)
            with self.assertRaisesRegex(StageAInputError, "expected counts"):
                mismatch.load_cases(root)

    def test_artifact_paths_cannot_escape_case_root(self) -> None:
        payload = {
            "role": "original_pe",
            "path": "../original.exe",
            "sha256": "0" * 64,
            "bytes": 0,
        }
        with self.assertRaisesRegex(StageAInputError, "contained path"):
            ArtifactRef.parse(payload, context="artifact")

    @staticmethod
    def _case_payload(root: Path) -> dict[str, object]:
        artifacts = [
            ArtifactRef.from_path(role=role, root=root, path=root / name).to_payload()
            for role, name in (
                ("semantic_program", "semantic.json"),
                ("original_pe", "original.exe"),
                ("candidate_pe", "candidate.exe"),
                ("relation_contract", "relation.json"),
            )
        ]
        semantic_sha256 = next(
            artifact["sha256"]
            for artifact in artifacts
            if artifact["role"] == "semantic_program"
        )
        return {
            "format": ROUNDTRIP_CASE_FORMAT,
            "id": "phase0-representative",
            "semantic_program_sha256": semantic_sha256,
            "parent_seed": 0,
            "template": "representative-control",
            "transformations": ["reachable-nop"],
            "expectation": {
                "disposition": "pass",
                "witness_family": None,
                "reason_family": None,
            },
            "mutation": None,
            "capability_profile": "x86-pe32-relational-v3",
            "capabilities": ["direct-call", "external-call", "stack-memory"],
            "proof_families": ["whole-program-acceptance"],
            "artifacts": artifacts,
            "replay": ["spaghetti-extractor", "stage-a-fuzz-run"],
            "shard": 0,
        }


if __name__ == "__main__":
    unittest.main()
