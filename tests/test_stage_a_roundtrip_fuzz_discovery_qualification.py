from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.roundtrip_fuzz.discovery import (
    DISCOVERY_QUALIFICATION_FORMAT,
    INITIAL_DISCOVERY_TEMPLATES,
    DiscoveryArtifact,
    DiscoveryCaseResult,
    DiscoveryCaseStatus,
    DiscoveryPhaseResult,
    qualify_discovery_templates,
)
from spaghetti_extractor.roundtrip_fuzz.generator import generate_spike_corpus
from spaghetti_extractor.roundtrip_fuzz.model import CaseManifest, load_corpus_manifest
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import json_dumps, sha256_file, write_json


def _case(root: Path, *, case_id: str, template: str) -> CaseManifest:
    root.mkdir(parents=True)
    files = {
        "semantic_program": "semantic.json",
        "original_pe": "original.exe",
        "candidate_pe": "candidate.exe",
        "relation_contract": "relation.json",
    }
    artifacts = []
    for role, name in files.items():
        path = root / name
        path.write_bytes(f"{case_id}:{role}\n".encode("ascii"))
        artifacts.append({
            "role": role,
            "path": name,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    return CaseManifest.parse({
        "format": "stage-a-roundtrip-case-v1",
        "id": case_id,
        "semantic_program_sha256": artifacts[0]["sha256"],
        "parent_seed": 0,
        "template": template,
        "transformations": ["qualification-shape"],
        "expectation": {
            "disposition": "pass",
            "witness_family": None,
            "reason_family": None,
        },
        "mutation": None,
        "capability_profile": "x86-pe32-relational-v3",
        "capabilities": ["integer-control"],
        "proof_families": ["whole-program-acceptance"],
        "artifacts": artifacts,
        "replay": ["spaghetti-extractor", "stage-a-fuzz-run"],
        "shard": 0,
    })


def _recovered_result(*, case: CaseManifest, out: Path) -> DiscoveryCaseResult:
    proposal = out / "proposal"
    proposal.mkdir(parents=True, exist_ok=True)
    result_path = proposal / "discovery-result.json"
    relation_path = proposal / "recovered-relation-contract.json"
    write_json(result_path, {"format": "stage-a-roundtrip-discovery-v1"})
    write_json(relation_path, {"format": "stage-a-relational-contract-v3"})
    return DiscoveryCaseResult(
        case_id=case.id,
        status=DiscoveryCaseStatus.DIFFERENT,
        phases=(
            DiscoveryPhaseResult(
                id="mapping-discovery",
                status="recovered",
                cache_key=f"mapping-{case.id}",
                cache_hit=False,
                duration_seconds=99.0,
                artifact="proposal/discovery-result.json",
                artifact_sha256=sha256_file(result_path),
                reason_code=None,
            ),
            DiscoveryPhaseResult(
                id="semantic-comparison",
                status="different",
                cache_key=f"comparison-{case.id}",
                cache_hit=True,
                duration_seconds=0.001,
                artifact=None,
                artifact_sha256=None,
                reason_code="recovered_relation_semantically_different",
            ),
        ),
        artifacts=(
            DiscoveryArtifact(
                role="discovery_result",
                path="proposal/discovery-result.json",
                sha256=sha256_file(result_path),
            ),
            DiscoveryArtifact(
                role="recovered_relation_contract",
                path="proposal/recovered-relation-contract.json",
                sha256=sha256_file(relation_path),
            ),
        ),
        frontiers=({
            "phase": "comparison",
            "reason_code": "recovered_relation_semantically_different",
        },),
        comparison={
            "status": "different",
            "counts": {"missing": 1, "extra": 1},
            "trust": {"proof_authority": False},
        },
    )


class StageARoundTripDiscoveryQualificationTests(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc"),
        "MinGW compiler is required for real discovery qualification",
    )
    def test_real_pe_qualification_recovers_one_case_per_template(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_root = root / "corpus"
            generate_spike_corpus(
                out=corpus_root, seed=1000, count=7, toolchain="gnu"
            )
            manifest = load_corpus_manifest(corpus_root / "corpus.json")

            first = qualify_discovery_templates(
                cases=manifest.load_cases(corpus_root),
                out=root / "discovery-a",
            )
            second = qualify_discovery_templates(
                cases=tuple(reversed(manifest.load_cases(corpus_root))),
                out=root / "discovery-b",
            )

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "qualified_for_proof_handoff")
        self.assertEqual(first["counts"], {
            "required_templates": 4,
            "ready_for_proof": 4,
            "proposal_frontier": 0,
        })
        self.assertTrue(all(row["proposal_ready"] for row in first["templates"]))

    def test_one_positive_per_initial_template_is_selected_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = []
            for index, template in enumerate(reversed(INITIAL_DISCOVERY_TEMPLATES)):
                case_root = root / f"input-{index}"
                cases.append((_case(
                    case_root,
                    case_id=f"z-{template}",
                    template=template,
                ), case_root))
            preferred_root = root / "preferred"
            cases.append((_case(
                preferred_root,
                case_id="a-straight-line-arithmetic",
                template="straight-line-arithmetic",
            ), preferred_root))
            calls: list[str] = []

            def execute(**kwargs):
                case = kwargs["case"]
                calls.append(case.id)
                return _recovered_result(case=case, out=kwargs["out"])

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.execute_case_discovery",
                side_effect=execute,
            ):
                first = qualify_discovery_templates(
                    cases=tuple(reversed(cases)), out=root / "qualification-a"
                )
                first_calls = tuple(calls)
                calls.clear()
                second = qualify_discovery_templates(
                    cases=cases, out=root / "qualification-b"
                )

            expected_ids = (
                "a-straight-line-arithmetic",
                "z-guarded-branch",
                "z-bounded-loop",
                "z-internal-call-stack",
            )
            self.assertEqual(first_calls, expected_ids)
            self.assertEqual(tuple(calls), expected_ids)
            self.assertEqual(first, second)
            self.assertEqual(first["format"], DISCOVERY_QUALIFICATION_FORMAT)
            self.assertEqual(first["status"], "qualified_for_proof_handoff")
            self.assertEqual(first["counts"], {
                "required_templates": 4,
                "ready_for_proof": 4,
                "proposal_frontier": 0,
            })
            self.assertEqual(
                [row["template"] for row in first["templates"]],
                list(INITIAL_DISCOVERY_TEMPLATES),
            )
            self.assertTrue(all(
                row["status"] == "ready_for_proof"
                and row["comparison_status"] == "different"
                and not row["trust"]["proof_authority"]
                and row["trust"]["ordinary_stage_a_proof_required"]
                for row in first["templates"]
            ))
            self.assertTrue(all(
                row["proposal_frontier_reason_codes"] == []
                and row["comparison_diagnostic_reason_codes"]
                == ["recovered_relation_semantically_different"]
                for row in first["templates"]
            ))
            canonical = json_dumps(first)
            self.assertNotIn("duration_seconds", canonical)
            self.assertNotIn("cache_hit", canonical)
            self.assertFalse(first["trust"]["proof_authority"])
            self.assertTrue(first["trust"]["ordinary_stage_a_proof_required"])

    def test_missing_template_fails_closed_before_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "case"
            cases = ((_case(
                case_root,
                case_id="only-straight-line",
                template="straight-line-arithmetic",
            ), case_root),)
            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.execute_case_discovery"
            ) as execute, self.assertRaisesRegex(
                StageAInputError, "no positive case for template 'guarded-branch'"
            ):
                qualify_discovery_templates(cases=cases, out=root / "qualification")
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
