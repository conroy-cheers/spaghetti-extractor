from __future__ import annotations

import json
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.roundtrip_fuzz.discovery import (
    DISCOVERY_CASE_RESULT_FORMAT,
    DiscoveryCaseResult,
    DiscoveryCaseStatus,
    compare_discovery_proposals,
    discover_binary_pair,
    discover_linker_map_pair,
    execute_case_discovery,
)
from spaghetti_extractor.roundtrip_fuzz.model import CaseManifest
from spaghetti_extractor.util import sha256_file, write_json


def _proposal(*, block_id: str = "diagnostic-name", candidate_rva: int = 0x1000) -> dict:
    return {
        "format": "stage-a-block-map-v1",
        "status": "pass",
        "original": {"path": "/private/original", "sha256": "a" * 64},
        "candidate": {"path": "/private/candidate", "sha256": "b" * 64},
        "linker_maps": {"original": "/private/original.map", "candidate": "/private/candidate.map"},
        "blocks": [{
            "id": block_id,
            "kind": "code",
            "reachable": True,
            "original": {"rva": 0x1000, "size": 4},
            "candidate": {"rva": candidate_rva, "size": 4},
            "root": {"kind": "linker_map_function", "checked": True, "symbol": block_id},
            "source": {"function": block_id},
        }],
        "waivers": [],
        "issues": [],
    }


def _case_manifest(
    root: Path,
    *,
    linker_maps: str = "both",
    ground_truth_candidate_rva: int = 0x1000,
) -> CaseManifest:
    files = {
        "semantic_program": ("semantic.json", b"{}\n"),
        "original_pe": ("original.exe", b"original-pe"),
        "candidate_pe": ("candidate.exe", b"candidate-pe"),
        "relation_contract": ("relation-contract.json", b"{}\n"),
    }
    if linker_maps in {"both", "original"}:
        files["original_linker_map"] = ("original.map", b"original-map")
    if linker_maps in {"both", "candidate"}:
        files["candidate_linker_map"] = ("candidate.map", b"candidate-map")
    for _role, (name, content) in files.items():
        (root / name).write_bytes(content)
    ground_truth = root / "relation-proposal.json"
    write_json(
        ground_truth,
        _proposal(
            block_id="generator-ground-truth",
            candidate_rva=ground_truth_candidate_rva,
        ),
    )
    files["relation_proposal"] = (ground_truth.name, ground_truth.read_bytes())
    artifacts = []
    for role, (name, _content) in files.items():
        path = root / name
        artifacts.append({
            "role": role,
            "path": name,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    return CaseManifest.parse({
        "format": "stage-a-roundtrip-case-v1",
        "id": "discovery-case",
        "semantic_program_sha256": sha256_file(root / "semantic.json"),
        "parent_seed": 7,
        "template": "opaque-template-label",
        "transformations": ["opaque-transformation-label"],
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


class StageARoundTripDiscoveryTests(unittest.TestCase):
    def _inputs(self, root: Path) -> tuple[Path, Path, Path, Path]:
        paths = tuple(root / name for name in (
            "original.exe", "candidate.exe", "original.map", "candidate.map"
        ))
        for index, path in enumerate(paths):
            path.write_bytes(f"input-{index}".encode())
        return paths  # type: ignore[return-value]

    def test_discovery_uses_only_binary_and_linker_map_inputs_and_caches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, original_map, candidate_map = self._inputs(root)
            out = root / "discovery"
            calls: list[tuple[str, tuple[str, ...]]] = []

            def generate_map(**kwargs):
                calls.append(("map", tuple(sorted(kwargs))))
                write_json(kwargs["out"], _proposal())
                write_json(kwargs["layout_contract_out"], {"format": "layout-v1"})
                return {"status": "pass", "issues": []}

            def generate_contract(**kwargs):
                calls.append(("contract", tuple(sorted(kwargs))))
                write_json(kwargs["out"], {
                    "format": "stage-a-relational-contract-v3",
                    "provenance": {"mapping_sha256": "diagnostic-only"},
                })
                return {"status": "generated", "issues": []}

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_map",
                side_effect=generate_map,
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_relation_contract",
                side_effect=generate_contract,
            ):
                first = discover_linker_map_pair(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    out=out,
                )
                second = discover_linker_map_pair(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    out=out,
                )

            self.assertEqual(first["status"], "recovered")
            self.assertFalse(first["cache"]["hit"])
            self.assertTrue(second["cache"]["hit"])
            self.assertEqual([name for name, _keys in calls], ["map", "contract"])
            self.assertNotIn("mapping", calls[0][1])
            self.assertNotIn("ground_truth", calls[0][1])
            report = json.loads((out / "discovery-result.json").read_text())
            self.assertFalse(report["trust"]["proof_authority"])
            self.assertIn("relation_proposal", report["trust"]["withheld_roles"])
            recovered = json.loads((out / "recovered-proposal.json").read_text())
            self.assertEqual(recovered["original"]["path"], "original.exe")
            self.assertEqual(recovered["linker_maps"]["candidate"], "candidate.map")

    def test_binary_discovery_derives_anonymous_entry_hints_from_pe_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original-pe")
            candidate.write_bytes(b"candidate-pe")
            observed_hints: list[tuple[str, str]] = []

            def generate_map(**kwargs):
                observed_hints.extend((
                    (
                        Path(kwargs["linker_map_original"]).name,
                        Path(kwargs["linker_map_original"]).read_text(),
                    ),
                    (
                        Path(kwargs["linker_map_candidate"]).name,
                        Path(kwargs["linker_map_candidate"]).read_text(),
                    ),
                ))
                write_json(kwargs["out"], _proposal())
                write_json(kwargs["layout_contract_out"], {"format": "layout-v1"})
                return {"status": "pass", "issues": []}

            def generate_contract(**kwargs):
                write_json(kwargs["out"], {
                    "format": "stage-a-relational-contract-v3",
                    "provenance": {"mapping_sha256": "untrusted-proposal"},
                })
                return {"status": "generated", "issues": []}

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery._parse_stage_a_pe",
                side_effect=(
                    SimpleNamespace(image_base=0x400000, entrypoint_rva=0x1000),
                    SimpleNamespace(image_base=0x500000, entrypoint_rva=0x2000),
                ),
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_map",
                side_effect=generate_map,
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_relation_contract",
                side_effect=generate_contract,
            ):
                result = discover_binary_pair(
                    original=original,
                    candidate=candidate,
                    out=root / "discovery",
                )

            self.assertEqual(result["status"], "recovered")
            self.assertEqual(observed_hints, [
                ("anonymous-original-entry.map", "0x00401000 discovered_entry\n"),
                ("anonymous-candidate-entry.map", "0x00502000 discovered_entry\n"),
            ])
            report = json.loads(
                (root / "discovery" / "discovery-result.json").read_text()
            )
            self.assertEqual(
                [item["role"] for item in report["inputs"]],
                ["original_pe", "candidate_pe"],
            )
            self.assertEqual(
                report["trust"]["consumed_roles"],
                ["original_pe", "candidate_pe"],
            )
            self.assertIn(
                "original_linker_map", report["trust"]["withheld_roles"]
            )
            self.assertIn(
                "relation_proposal", report["trust"]["withheld_roles"]
            )
            recovered = json.loads(
                (root / "discovery" / "recovered-proposal.json").read_text()
            )
            self.assertEqual(
                recovered["linker_maps"],
                {
                    "original": "anonymous-original-entry.map",
                    "candidate": "anonymous-candidate-entry.map",
                },
            )

    def test_ambiguous_mapping_emits_precise_frontier_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, original_map, candidate_map = self._inputs(root)

            def generate_map(**kwargs):
                payload = _proposal()
                payload["status"] = "incomplete"
                write_json(kwargs["out"], payload)
                write_json(kwargs["layout_contract_out"], {"format": "layout-v1"})
                return {
                    "status": "incomplete",
                    "issues": [{
                        "category": "ambiguous_function_key",
                        "obligation_id": "map:function:entry",
                        "blocker": "two candidate functions have the same key",
                        "next_action": "supply an explicit untrusted function pairing",
                        "details": {"function": "entry", "matches": 2},
                    }],
                }

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_map",
                side_effect=generate_map,
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_relation_contract"
            ) as relation:
                result = discover_linker_map_pair(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    out=root / "discovery",
                )

            self.assertEqual(result["status"], "incomplete")
            relation.assert_not_called()
            frontier = json.loads(
                (root / "discovery" / "discovery-frontier.json").read_text()
            )
            self.assertEqual(frontier["status"], "incomplete")
            self.assertEqual(frontier["items"][0]["category"], "ambiguous_function_key")
            self.assertEqual(
                frontier["items"][0]["location"],
                {"kind": "function", "value": "entry"},
            )
            self.assertIn("explicit untrusted function pairing", frontier["items"][0]["next_action"])

    def test_semantic_comparison_ignores_names_but_not_spans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recovered = root / "recovered.json"
            expected = root / "expected.json"
            write_json(recovered, _proposal(block_id="recovered-label"))
            write_json(expected, _proposal(block_id="generator-label"))
            equivalent = compare_discovery_proposals(
                recovered=recovered, ground_truth=expected
            )
            self.assertEqual(equivalent["status"], "equivalent")

            write_json(expected, _proposal(block_id="generator-label", candidate_rva=0x1010))
            different = compare_discovery_proposals(
                recovered=recovered, ground_truth=expected
            )
            self.assertEqual(different["status"], "different")
            self.assertEqual(different["counts"]["missing"], 1)
            self.assertEqual(different["counts"]["extra"], 1)
            self.assertFalse(different["trust"]["proof_authority"])

    def test_case_execution_withholds_ground_truth_and_caches_phases_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "case"
            case_root.mkdir()
            case = _case_manifest(case_root)
            out = root / "result"
            calls: list[tuple[str, dict]] = []

            def generate_map(**kwargs):
                calls.append(("map", dict(kwargs)))
                write_json(kwargs["out"], _proposal(block_id="recovered-label"))
                write_json(kwargs["layout_contract_out"], {"format": "layout-v1"})
                return {"status": "pass", "issues": []}

            def generate_contract(**kwargs):
                calls.append(("contract", dict(kwargs)))
                write_json(kwargs["out"], {
                    "format": "stage-a-relational-contract-v3",
                    "provenance": {"mapping_sha256": "untrusted-proposal"},
                })
                return {"status": "generated", "issues": []}

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery._parse_stage_a_pe",
                return_value=SimpleNamespace(
                    image_base=0x400000, entrypoint_rva=0x1000,
                ),
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_map",
                side_effect=generate_map,
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_relation_contract",
                side_effect=generate_contract,
            ):
                first = execute_case_discovery(
                    case=case, case_root=case_root, out=out
                )
                second = execute_case_discovery(
                    case=case, case_root=case_root, out=out
                )

                write_json(
                    case_root / "relation-proposal.json",
                    _proposal(
                        block_id="changed-ground-truth", candidate_rva=0x1010
                    ),
                )
                changed_case = _case_manifest(
                    case_root, ground_truth_candidate_rva=0x1010
                )
                third = execute_case_discovery(
                    case=changed_case, case_root=case_root, out=out
                )

            self.assertIsInstance(first, DiscoveryCaseResult)
            self.assertIs(first.status, DiscoveryCaseStatus.RECOVERED)
            self.assertEqual(
                [phase.cache_hit for phase in first.phases], [False, False]
            )
            self.assertEqual(
                [phase.cache_hit for phase in second.phases], [True, True]
            )
            self.assertIs(third.status, DiscoveryCaseStatus.DIFFERENT)
            self.assertEqual(
                [phase.cache_hit for phase in third.phases], [True, False]
            )
            self.assertEqual([name for name, _kwargs in calls], ["map", "contract"])

            discovery_kwargs = calls[0][1]
            self.assertEqual(
                set(discovery_kwargs),
                {
                    "original",
                    "candidate",
                    "linker_map_original",
                    "linker_map_candidate",
                    "out",
                    "layout_contract_out",
                    "original_flags",
                    "candidate_flags",
                },
            )
            for forbidden in (
                "ground_truth",
                "relation_proposal",
                "relation_contract",
                "semantic_program",
                "template",
                "transformation",
                "seed",
            ):
                self.assertNotIn(forbidden, discovery_kwargs)
            self.assertEqual(
                Path(discovery_kwargs["linker_map_original"]).name,
                "anonymous-original-entry.map",
            )
            self.assertEqual(
                Path(discovery_kwargs["linker_map_candidate"]).name,
                "anonymous-candidate-entry.map",
            )

            payload = first.to_payload()
            self.assertEqual(payload["format"], DISCOVERY_CASE_RESULT_FORMAT)
            self.assertEqual(
                set(payload["phases"][0]),
                {
                    "id",
                    "status",
                    "cache_key",
                    "cache_hit",
                    "duration_seconds",
                    "artifact",
                    "artifact_sha256",
                    "reason_code",
                },
            )
            self.assertFalse(payload["trust"]["proof_authority"])
            self.assertFalse(
                payload["trust"]["ground_truth_influences_discovery"]
            )
            self.assertTrue(payload["trust"]["corpus_mapping_hints_withheld"])
            self.assertTrue((out / "discovery-timings.json").is_file())
            self.assertTrue((out / "discovery-frontiers.json").is_file())
            persisted = json.loads(
                (out / "discovery-case-result.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["status"], "different")
            self.assertEqual(
                persisted["frontiers"][0]["reason_code"],
                "recovered_relation_semantically_different",
            )

    def test_case_execution_without_linker_maps_uses_binary_only_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_root = root / "case"
            case_root.mkdir()
            case = _case_manifest(case_root, linker_maps="none")
            out = root / "result"
            calls: list[dict] = []

            def generate_map(**kwargs):
                calls.append(dict(kwargs))
                write_json(kwargs["out"], _proposal())
                write_json(kwargs["layout_contract_out"], {"format": "layout-v1"})
                return {"status": "pass", "issues": []}

            def generate_contract(**kwargs):
                write_json(kwargs["out"], {
                    "format": "stage-a-relational-contract-v3",
                })
                return {"status": "generated", "issues": []}

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery._parse_stage_a_pe",
                return_value=SimpleNamespace(
                    image_base=0x400000, entrypoint_rva=0x1000,
                ),
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_map",
                side_effect=generate_map,
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_relation_contract",
                side_effect=generate_contract,
            ):
                first = execute_case_discovery(
                    case=case, case_root=case_root, out=out
                )
                second = execute_case_discovery(
                    case=case, case_root=case_root, out=out
                )

            self.assertIs(first.status, DiscoveryCaseStatus.RECOVERED)
            self.assertFalse(first.phases[0].cache_hit)
            self.assertTrue(second.phases[0].cache_hit)
            self.assertEqual(len(calls), 1)
            self.assertEqual(
                Path(calls[0]["linker_map_original"]).name,
                "anonymous-original-entry.map",
            )
            self.assertEqual(first.frontiers, ())
            self.assertEqual(first.comparison["status"], "equivalent")

    def test_case_execution_ignores_one_sided_or_stale_corpus_linker_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            one_sided_root = root / "one-sided"
            one_sided_root.mkdir()
            one_sided = _case_manifest(one_sided_root, linker_maps="original")
            stale_root = root / "stale"
            stale_root.mkdir()
            stale = _case_manifest(stale_root)
            (stale_root / "candidate.map").write_bytes(b"tampered")
            calls: list[dict] = []

            def generate_map(**kwargs):
                calls.append(dict(kwargs))
                write_json(kwargs["out"], _proposal())
                write_json(kwargs["layout_contract_out"], {"format": "layout-v1"})
                return {"status": "pass", "issues": []}

            def generate_contract(**kwargs):
                write_json(kwargs["out"], {
                    "format": "stage-a-relational-contract-v3",
                })
                return {"status": "generated", "issues": []}

            with patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery._parse_stage_a_pe",
                return_value=SimpleNamespace(
                    image_base=0x400000, entrypoint_rva=0x1000,
                ),
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_map",
                side_effect=generate_map,
            ), patch(
                "spaghetti_extractor.roundtrip_fuzz.discovery.stage_a_generate_relation_contract",
                side_effect=generate_contract,
            ):
                first = execute_case_discovery(
                    case=one_sided,
                    case_root=one_sided_root,
                    out=root / "one-sided-result",
                )
                second = execute_case_discovery(
                    case=stale,
                    case_root=stale_root,
                    out=root / "stale-result",
                )

            self.assertIs(first.status, DiscoveryCaseStatus.RECOVERED)
            self.assertIs(second.status, DiscoveryCaseStatus.RECOVERED)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(
                "anonymous-" in Path(call["linker_map_original"]).name
                for call in calls
            ))

    def test_case_execution_has_no_template_or_fixture_dispatch(self) -> None:
        source = inspect.getsource(execute_case_discovery)
        self.assertNotIn("case.template", source)
        self.assertNotIn("case.transformations", source)
        self.assertNotIn("case.parent_seed", source)


if __name__ == "__main__":
    unittest.main()
