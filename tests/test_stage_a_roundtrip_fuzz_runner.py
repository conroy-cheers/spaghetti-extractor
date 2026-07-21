from __future__ import annotations

import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.relational.interfaces import stage_a_interface_manifest
from spaghetti_extractor.roundtrip_fuzz.model import (
    ROUNDTRIP_CASE_FORMAT,
    ROUNDTRIP_CORPUS_FORMAT,
    ArtifactRef,
)
from spaghetti_extractor.roundtrip_fuzz.phase0 import generate_phase0_corpus
from spaghetti_extractor.roundtrip_fuzz.runner import (
    _acceptance_frontiers,
    run_roundtrip_corpus,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


class RoundTripFuzzRunnerTests(unittest.TestCase):
    def test_ready_acceptance_does_not_report_auxiliary_affine_analysis_as_frontier(self) -> None:
        result = {
            "acceptance": {"status": "ready"},
            "composition_progress": {"frontiers": {
                "affine_linked_control": {
                    "status": "proofs_not_connected_to_acceptance",
                    "acceptance_authority": False,
                },
                "segment_edge_ids": [],
            }},
        }

        self.assertEqual(_acceptance_frontiers(result), [])
        result["acceptance"]["status"] = "incomplete"
        self.assertEqual(
            _acceptance_frontiers(result)[0]["category"],
            "affine_linked_control",
        )

    def test_proof_core_uses_final_theorem_and_reuses_warm_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_path = self._write_corpus(root)
            calls = {"prepare": 0, "build": 0}

            def prepare(**kwargs):
                calls["prepare"] += 1
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                payload = {
                    "format": "stage-a-prepared-relational-v1",
                    "status": "prepared",
                    "original_sha256": sha256_file(Path(kwargs["original"])),
                    "candidate_sha256": sha256_file(Path(kwargs["candidate"])),
                    "relation_contract_sha256": "f" * 64,
                    "acceptance": {"status": "ready", "blockers": []},
                    "composition_progress": {"frontiers": {}},
                }
                write_json(out / "prepared-proof.json", payload)
                write_json(out / "stage-a-interface-manifest.json", stage_a_interface_manifest())
                write_json(out / "module-graph.json", {"format": "test"})
                return payload

            def build(**kwargs):
                calls["build"] += 1
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                case_root = root / "cases" / "case-pass"
                payload = {
                    "format": "stage-a-relational-nix-build-v1",
                    "status": "pass",
                    "expected_final_theorem": (
                        "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
                    ),
                    "original": {"sha256": sha256_file(case_root / "original.exe")},
                    "candidate": {"sha256": sha256_file(case_root / "candidate.exe")},
                    "relation_contract_sha256": "e" * 64,
                    "checks": {
                        "lean_trust_zero": True,
                        "final_theorem_matches": True,
                    },
                }
                write_json(out / "verdict.json", payload)
                return payload

            out = root / "run"
            first = run_roundtrip_corpus(
                corpus=corpus_path,
                mode="proof-core",
                out=out,
                _prepare=prepare,
                _build=build,
            )
            second = run_roundtrip_corpus(
                corpus=corpus_path,
                mode="proof-core",
                out=out,
                _prepare=lambda **_kwargs: self.fail("warm run prepared again"),
                _build=lambda **_kwargs: self.fail("warm run rebuilt again"),
            )

            self.assertEqual(first["status"], "pass", first)
            self.assertEqual(first["cases"][0]["actual_disposition"], "pass")
            self.assertEqual(
                first["cases"][0]["acceptance"]["authority"],
                "whole_program_lean",
            )
            self.assertEqual(calls, {"prepare": 1, "build": 1})
            self.assertTrue(all(
                phase["cache_hit"] for phase in second["cases"][0]["phases"]
            ))

    def test_negative_final_pass_is_always_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_path = self._write_corpus(root, negative=True)

            def prepare(**kwargs):
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                payload = {
                    "format": "stage-a-prepared-relational-v1",
                    "status": "prepared",
                    "original_sha256": sha256_file(Path(kwargs["original"])),
                    "candidate_sha256": sha256_file(Path(kwargs["candidate"])),
                    "relation_contract_sha256": "f" * 64,
                    "acceptance": {"status": "ready", "blockers": []},
                    "composition_progress": {"frontiers": {}},
                }
                write_json(out / "prepared-proof.json", payload)
                write_json(out / "stage-a-interface-manifest.json", stage_a_interface_manifest())
                write_json(out / "module-graph.json", {"format": "test"})
                return payload

            def build(**kwargs):
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                case_root = root / "cases" / "case-pass"
                payload = {
                    "format": "stage-a-relational-nix-build-v1",
                    "status": "pass",
                    "expected_final_theorem": (
                        "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
                    ),
                    "original": {"sha256": sha256_file(case_root / "original.exe")},
                    "candidate": {"sha256": sha256_file(case_root / "candidate.exe")},
                    "checks": {
                        "lean_trust_zero": True,
                        "final_theorem_matches": True,
                    },
                }
                write_json(out / "verdict.json", payload)
                return payload

            result = run_roundtrip_corpus(
                corpus=corpus_path,
                mode="proof-core",
                out=root / "run",
                _prepare=prepare,
                _build=build,
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["unexpected_pass_case_ids"], ["case-pass"])

    def test_warm_cache_rejects_stale_preparation_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_path = self._write_corpus(root)
            calls = {"prepare": 0, "build": 0}

            def prepare(**kwargs):
                calls["prepare"] += 1
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                payload = {
                    "format": "stage-a-prepared-relational-v1",
                    "status": "prepared",
                    "original_sha256": sha256_file(Path(kwargs["original"])),
                    "candidate_sha256": sha256_file(Path(kwargs["candidate"])),
                    "acceptance": {"status": "ready", "blockers": []},
                    "composition_progress": {"frontiers": {}},
                }
                write_json(out / "prepared-proof.json", payload)
                write_json(
                    out / "stage-a-interface-manifest.json",
                    stage_a_interface_manifest(),
                )
                write_json(out / "module-graph.json", {"format": "test"})
                return payload

            def build(**kwargs):
                calls["build"] += 1
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                case_root = root / "cases" / "case-pass"
                payload = {
                    "format": "stage-a-relational-nix-build-v1",
                    "status": "pass",
                    "expected_final_theorem": (
                        "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
                    ),
                    "original": {"sha256": sha256_file(case_root / "original.exe")},
                    "candidate": {"sha256": sha256_file(case_root / "candidate.exe")},
                    "checks": {
                        "lean_trust_zero": True,
                        "final_theorem_matches": True,
                    },
                }
                write_json(out / "verdict.json", payload)
                return payload

            out = root / "run"
            run_roundtrip_corpus(
                corpus=corpus_path,
                mode="proof-core",
                out=out,
                _prepare=prepare,
                _build=build,
            )
            binding_path = (
                out / "cases" / "case-pass" / "prepared"
                / "roundtrip-input-binding.json"
            )
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding["preparation_implementation_sha256"] = "0" * 64
            write_json(binding_path, binding)
            run_roundtrip_corpus(
                corpus=corpus_path,
                mode="proof-core",
                out=out,
                _prepare=prepare,
                _build=build,
            )

            self.assertEqual(calls, {"prepare": 2, "build": 1})

    def test_static_preflight_stop_is_public_and_skips_proof_work(self) -> None:
        from spaghetti_extractor.cli import _build_parser

        args = _build_parser(prog="spaghetti-extractor").parse_args([
            "stage-a-fuzz-run",
            "--corpus", "corpus.json",
            "--out", "run",
            "--stop-after-static-preflight",
        ])
        self.assertTrue(args.stop_after_static_preflight)
        with mock.patch(
            "spaghetti_extractor.cli.run_roundtrip_corpus",
            return_value={"status": "pass"},
        ) as run:
            args.func(args)
        self.assertTrue(run.call_args.kwargs["stop_after_static_preflight"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_path = self._write_corpus(root)

            def prepare(**kwargs):
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                payload = {
                    "format": "stage-a-prepared-relational-v1",
                    "status": "prepared",
                    "original_sha256": sha256_file(Path(kwargs["original"])),
                    "candidate_sha256": sha256_file(Path(kwargs["candidate"])),
                    "acceptance": {"status": "ready", "blockers": []},
                    "composition_progress": {"frontiers": {}},
                }
                write_json(out / "prepared-proof.json", payload)
                write_json(
                    out / "stage-a-interface-manifest.json",
                    stage_a_interface_manifest(),
                )
                write_json(out / "module-graph.json", {"format": "test"})
                return payload

            result = run_roundtrip_corpus(
                corpus=corpus_path,
                mode="proof-core",
                out=root / "run",
                stop_after_static_preflight=True,
                _prepare=prepare,
                _build=lambda **_kwargs: self.fail("static preflight ran proof work"),
            )

            self.assertEqual(result["status"], "pass", result)
            self.assertEqual(result["stopped_after"], "static-preflight")
            self.assertFalse(result["expectations_evaluated"])
            self.assertEqual(result["expectation_mismatch_case_ids"], [])
            case = result["cases"][0]
            self.assertEqual(case["actual_disposition"], "incomplete")
            self.assertIsNone(case["expectation_matched"])
            self.assertEqual(
                [phase["id"] for phase in case["phases"]],
                ["proof-preparation"],
            )

    def test_checked_violation_replay_reports_timing_and_content_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_path = self._write_corpus(
                root,
                negative=True,
                with_violation_witness=True,
            )
            production_calls = 0

            def prepare(**kwargs):
                out = Path(kwargs["out"])
                out.mkdir(parents=True)
                payload = {
                    "format": "stage-a-prepared-relational-v1",
                    "status": "prepared",
                    "original_sha256": sha256_file(Path(kwargs["original"])),
                    "candidate_sha256": sha256_file(Path(kwargs["candidate"])),
                    "acceptance": {"status": "ready", "blockers": []},
                    "composition_progress": {"frontiers": {}},
                }
                write_json(out / "prepared-proof.json", payload)
                write_json(
                    out / "stage-a-interface-manifest.json",
                    stage_a_interface_manifest(),
                )
                write_json(out / "module-graph.json", {"format": "test"})
                write_json(out / "relation-contract.json", {"version": 1})
                write_json(
                    out / "relational-decoded-behaviors.json",
                    {"version": 1},
                )
                lean = out / "lean" / "StageA"
                lean.mkdir(parents=True)
                (lean / "Relational.lean").write_text("def prepared := 1\n")
                return payload

            def produce(**kwargs):
                nonlocal production_calls
                production_calls += 1
                time.sleep(0.01)
                out = Path(kwargs["out"])
                source = out / "lean" / "StageA" / "RelationalCounterexample.lean"
                source.parent.mkdir(parents=True)
                source.write_text("theorem replay : True := by trivial\n")
                audit = out / "audit.json"
                write_json(audit, {
                    "format": "stage-a-violation-check-v1",
                    "status": "checked",
                })
                return {"audit": str(audit), "source": str(source)}

            def validate(**_kwargs):
                return {
                    "status": "violated",
                    "family": "register-relation-v1",
                }

            def no_proof(**_kwargs):
                raise StageAInputError("proof intentionally unavailable")

            out = root / "run"
            with (
                mock.patch(
                    "spaghetti_extractor.roundtrip_fuzz.runner.produce_checked_violation",
                    side_effect=produce,
                ),
                mock.patch(
                    "spaghetti_extractor.roundtrip_fuzz.runner.validate_checked_violation",
                    side_effect=validate,
                ),
            ):
                first = run_roundtrip_corpus(
                    corpus=corpus_path,
                    mode="proof-core",
                    out=out,
                    _prepare=prepare,
                    _build=no_proof,
                )
                second = run_roundtrip_corpus(
                    corpus=corpus_path,
                    mode="proof-core",
                    out=out,
                    _prepare=prepare,
                    _build=no_proof,
                )
                audit = out / "cases" / "case-pass" / "violation" / "audit.json"
                write_json(audit, {
                    "format": "stage-a-violation-check-v1",
                    "status": "checked",
                    "tampered": True,
                })
                third = run_roundtrip_corpus(
                    corpus=corpus_path,
                    mode="proof-core",
                    out=out,
                    _prepare=prepare,
                    _build=no_proof,
                )
                decoded = (
                    out / "cases" / "case-pass" / "prepared"
                    / "relational-decoded-behaviors.json"
                )
                write_json(decoded, {"version": 2})
                fourth = run_roundtrip_corpus(
                    corpus=corpus_path,
                    mode="proof-core",
                    out=out,
                    _prepare=prepare,
                    _build=no_proof,
                )

            first_phase = first["cases"][0]["phases"][-1]
            second_phase = second["cases"][0]["phases"][-1]
            third_phase = third["cases"][0]["phases"][-1]
            fourth_phase = fourth["cases"][0]["phases"][-1]
            self.assertFalse(first_phase["cache_hit"])
            self.assertGreater(first_phase["duration_seconds"], 0.0)
            self.assertTrue(second_phase["cache_hit"])
            self.assertEqual(first_phase["cache_key"], second_phase["cache_key"])
            self.assertFalse(third_phase["cache_hit"])
            self.assertEqual(second_phase["cache_key"], third_phase["cache_key"])
            self.assertFalse(fourth_phase["cache_hit"])
            self.assertNotEqual(third_phase["cache_key"], fourth_phase["cache_key"])
            self.assertEqual(production_calls, 3)

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc"),
        "MinGW compiler is required for deterministic PE generation",
    )
    def test_phase0_generation_is_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = Path("profiles/pe32-kernel32-console-lockstep-v1.json")
            first = generate_phase0_corpus(out=root / "first", external_profile=profile)
            second = generate_phase0_corpus(out=root / "second", external_profile=profile)

            self.assertEqual(first["corpus_sha256"], second["corpus_sha256"])
            first_root = root / "first" / "cases" / "phase0-winapi-lockstep"
            first_case = json.loads(
                (first_root / "case.json").read_text(encoding="utf-8")
            )
            second_case = json.loads(
                (root / "second" / "cases" / "phase0-winapi-lockstep" / "case.json")
                .read_text(encoding="utf-8")
            )
            self.assertEqual(first_case["artifacts"], second_case["artifacts"])
            original_source = (first_root / "original.S").read_text(encoding="utf-8")
            candidate_source = (first_root / "candidate.S").read_text(encoding="utf-8")
            self.assertIn("call _rt_branch_check", original_source)
            self.assertIn("ret", original_source)
            self.assertIn("je _rt_return_helper", original_source)
            self.assertIn("je _rt_return_helper", candidate_source)
            self.assertIn(".Lrt_exit_unexpected_return:", original_source)
            self.assertIn(
                "jmp .Lrt_exit_unexpected_return", original_source,
            )

    @staticmethod
    def _write_corpus(
        root: Path,
        *,
        negative: bool = False,
        with_violation_witness: bool = False,
    ) -> Path:
        case_root = root / "cases" / "case-pass"
        case_root.mkdir(parents=True)
        for name, data in (
            ("semantic.json", b"{}\n"),
            ("original.exe", b"original"),
            ("candidate.exe", b"candidate"),
            ("relation.json", b"{}\n"),
        ):
            (case_root / name).write_bytes(data)
        if with_violation_witness:
            (case_root / "witness.json").write_text("{}\n", encoding="utf-8")
        artifact_names = [
            ("semantic_program", "semantic.json"),
            ("original_pe", "original.exe"),
            ("candidate_pe", "candidate.exe"),
            ("relation_contract", "relation.json"),
        ]
        if with_violation_witness:
            artifact_names.append(("violation_witness", "witness.json"))
        artifacts = [
            ArtifactRef.from_path(role=role, root=case_root, path=case_root / name)
            .to_payload()
            for role, name in artifact_names
        ]
        semantic_sha256 = next(
            row["sha256"] for row in artifacts if row["role"] == "semantic_program"
        )
        case = {
            "format": ROUNDTRIP_CASE_FORMAT,
            "id": "case-pass",
            "semantic_program_sha256": semantic_sha256,
            "parent_seed": 0,
            "template": "straight-line",
            "transformations": ["register-reassignment"],
            "expectation": {
                "disposition": "violated" if negative else "pass",
                "witness_family": "register-relation-v1" if negative else None,
                "reason_family": None,
            },
            "mutation": ({
                "id": "wrong-addend",
                "semantic_delta": "candidate adds two",
                "location_id": "entry-add",
            } if negative else None),
            "capability_profile": "x86-pe32-relational-v3",
            "capabilities": ["direct-jump"],
            "proof_families": ["whole-program-acceptance"],
            "artifacts": artifacts,
            "replay": ["spaghetti-extractor", "stage-a-fuzz-run"],
            "shard": 0,
        }
        case_path = case_root / "case.json"
        write_json(case_path, case)
        corpus = {
            "format": ROUNDTRIP_CORPUS_FORMAT,
            "generator_version": "test-v1",
            "root_seed": 0,
            "capability_profile": "x86-pe32-relational-v3",
            "toolchain": {
                "id": "test-toolchain-v1",
                "target": "i686-w64-mingw32",
                "compiler": "test",
                "compiler_version": "1",
                "linker": "test",
                "linker_version": "1",
            },
            "cases": [{
                "id": "case-pass",
                "path": "cases/case-pass/case.json",
                "sha256": sha256_file(case_path),
                "shard": 0,
            }],
            "expected_counts": {
                "pass": 0 if negative else 1,
                "violated": 1 if negative else 0,
                "incomplete": 0,
            },
            "shard_count": 1,
        }
        corpus_path = root / "corpus.json"
        write_json(corpus_path, corpus)
        return corpus_path


if __name__ == "__main__":
    unittest.main()
