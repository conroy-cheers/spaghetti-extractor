from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.authority_v2_cli import (
    AuthorityV2CommandError,
    build_static_hybrid_authority_v2_from_paths,
    derive_callback_entry_contracts_v2_from_paths,
)
from spaghetti_extractor.cli import main


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


class AuthorityV2CommandSurfaceTests(unittest.TestCase):
    def test_static_build_exposes_all_generic_evidence_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exception = root / "exception.json"
            entry_range = root / "entry-range.json"
            world_ranges = root / "world-ranges.json"
            _write(exception, {"format": "checked-exception"})
            _write(entry_range, {"id": "entry-stack"})
            _write(world_ranges, {"facts": [{"id": "heap"}]})
            out = root / "pipeline"
            result = {
                "format": "spaghetti-extractor-static-hybrid-pipeline-v2",
                "status": "complete",
                "authorizes_candidate_generation": True,
            }

            with patch(
                "spaghetti_extractor.cli.build_static_hybrid_authority_v2_from_paths",
                return_value=result,
            ) as build, contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "stage-a-build-static-hybrid-authority-v2",
                    "--machine-ir", str(root / "machine-ir.jsonl"),
                    "--machine-ir-manifest", str(root / "manifest.json"),
                    "--original", str(root / "original.exe"),
                    "--behavioral-roots", str(root / "roots.json"),
                    "--legacy-v1-diagnostic", str(root / "legacy.json"),
                    "--isa-requirements", str(root / "isa-requirements.json"),
                    "--isa-selection-authority", str(root / "isa.json"),
                    "--launch-profile", str(root / "launch.json"),
                    "--checked-exception-report", str(exception),
                    "--entry-range-fact", str(entry_range),
                    "--world-range-fact", str(world_ranges),
                    "--out", str(out),
                ])

        self.assertEqual(status, 0)
        arguments = build.call_args.kwargs
        self.assertEqual(arguments["checked_exception_reports"], [exception])
        self.assertEqual(arguments["entry_range_facts"], [entry_range])
        self.assertEqual(arguments["world_range_facts"], [world_ranges])
        self.assertEqual(arguments["launch_profile"], root / "launch.json")
        self.assertEqual(
            arguments["isa_requirements"], root / "isa-requirements.json"
        )
        self.assertEqual(arguments["out"], out)

    def test_two_phase_callback_launch_commands_have_stable_path_adapters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_payload = {
                "format": "spaghetti-extractor-pe32-launch-profile-v2",
                "status": "incomplete",
                "content_sha256": "a" * 64,
            }
            callback_payload = {
                "format": "spaghetti-extractor-callback-entry-state-analysis-v2",
                "status": "complete",
                "analysis_sha256": "b" * 64,
            }
            final_payload = {
                "format": "spaghetti-extractor-pe32-launch-profile-v2",
                "status": "complete",
                "content_sha256": "c" * 64,
            }
            with patch(
                "spaghetti_extractor.cli.build_base_launch_profile_v2_from_paths",
                return_value=base_payload,
            ) as build_base, contextlib.redirect_stdout(io.StringIO()):
                base_status = main([
                    "stage-a-build-base-launch-profile-v2",
                    "--original", str(root / "original.exe"),
                    "--behavioral-roots", str(root / "roots.json"),
                    "--assumptions", str(root / "assumptions.json"),
                    "--feature-inventory", str(root / "features.json"),
                    "--out", str(root / "base.json"),
                ])
            with patch(
                "spaghetti_extractor.cli.derive_callback_entry_contracts_v2_from_paths",
                return_value=callback_payload,
            ) as derive, contextlib.redirect_stdout(io.StringIO()):
                callback_status = main([
                    "stage-a-derive-callback-entry-contracts-v2",
                    "--original", str(root / "original.exe"),
                    "--machine-ir", str(root / "machine-ir.jsonl"),
                    "--interface-provenance", str(root / "provenance.json"),
                    "--global-slot-invariants", str(root / "globals.json"),
                    "--out", str(root / "callbacks.json"),
                ])
            with patch(
                "spaghetti_extractor.cli.finalize_launch_profile_v2_from_paths",
                return_value=final_payload,
            ) as finalize, contextlib.redirect_stdout(io.StringIO()):
                final_status = main([
                    "stage-a-finalize-launch-profile-v2",
                    "--base-launch-profile", str(root / "base.json"),
                    "--behavioral-roots", str(root / "roots.json"),
                    "--callback-entry-contracts", str(root / "callbacks.json"),
                    "--out", str(root / "launch.json"),
                ])

        self.assertEqual((base_status, callback_status, final_status), (0, 0, 0))
        self.assertEqual(build_base.call_args.kwargs["out"], root / "base.json")
        self.assertEqual(
            derive.call_args.kwargs["global_slot_invariants"],
            root / "globals.json",
        )
        self.assertEqual(
            finalize.call_args.kwargs["callback_entry_contracts"],
            root / "callbacks.json",
        )

    def test_static_validation_exposes_cold_replay_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = {
                "format": "spaghetti-extractor-static-hybrid-pipeline-v2",
                "status": "incomplete",
                "authorizes_candidate_generation": False,
            }
            with patch(
                "spaghetti_extractor.cli.validate_static_hybrid_authority_v2_from_paths",
                return_value=result,
            ) as validate, contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "stage-a-validate-static-hybrid-authority-v2",
                    "--pipeline", str(root / "pipeline"),
                    "--machine-ir", str(root / "machine-ir.jsonl"),
                    "--machine-ir-manifest", str(root / "manifest.json"),
                    "--original", str(root / "original.exe"),
                    "--behavioral-roots", str(root / "roots.json"),
                    "--isa-requirements", str(root / "isa-requirements.json"),
                    "--isa-selection-authority", str(root / "isa.json"),
                ])

        self.assertEqual(status, 1)
        self.assertEqual(validate.call_args.kwargs["pipeline"], root / "pipeline")

    def test_candidate_build_and_validation_have_authority_aware_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = [
                "--final-static-hybrid-audit", str(root / "audit.json"),
                "--authority-bundle", str(root / "bundle.json"),
                "--machine-ir", str(root / "machine-ir.jsonl"),
                "--machine-ir-manifest", str(root / "manifest.json"),
                "--fallback-coverage-receipt", str(root / "fallback.json"),
                "--legacy-v1-diagnostic", str(root / "legacy.json"),
            ]
            with patch(
                "spaghetti_extractor.cli.build_candidate_authority_v2_from_paths",
                return_value={"status": "authorized", "authorizes": True},
            ) as build, contextlib.redirect_stdout(io.StringIO()):
                built = main([
                    "stage-b-build-candidate-authority-v2",
                    *common,
                    "--out", str(root / "receipt.json"),
                ])
            with patch(
                "spaghetti_extractor.cli.validate_candidate_authority_v2_from_paths",
                return_value={"status": "violated", "authorizes": False},
            ), contextlib.redirect_stdout(io.StringIO()):
                rejected = main([
                    "stage-b-validate-candidate-authority-v2",
                    "--receipt", str(root / "receipt.json"),
                    *common,
                ])

        self.assertEqual(built, 0)
        self.assertEqual(rejected, 1)
        self.assertEqual(
            build.call_args.kwargs["legacy_v1_diagnostics"],
            [root / "legacy.json"],
        )

    def test_legacy_checked_sites_are_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = root / "legacy.json"
            _write(legacy, {
                "format": "stage-b-static-hybrid-completeness-v1",
                "status": "complete",
                "checked_external_sites": [{"status": "complete"}],
            })
            with patch(
                "spaghetti_extractor.authority_v2_cli.run_static_hybrid_pipeline_v2",
                return_value={"status": "incomplete"},
            ) as pipeline:
                build_static_hybrid_authority_v2_from_paths(
                    machine_ir=root / "machine-ir.jsonl",
                    machine_ir_manifest=root / "manifest.json",
                    original=root / "original.exe",
                    behavioral_roots=root / "roots.json",
                    legacy_v1_diagnostic=legacy,
                    isa_requirements=root / "isa-requirements.json",
                    isa_selection_authority=root / "isa.json",
                    launch_profile=None,
                    out=root / "out",
                )
            pipeline.assert_called_once()
            self.assertIsNone(pipeline.call_args.kwargs["checked_external_sites"])
            self.assertEqual(
                pipeline.call_args.kwargs["legacy_completeness"], legacy
            )

    def test_static_adapter_rejects_conflicting_deprecated_launch_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(AuthorityV2CommandError):
                build_static_hybrid_authority_v2_from_paths(
                    machine_ir=root / "machine-ir.jsonl",
                    machine_ir_manifest=root / "manifest.json",
                    original=root / "original.exe",
                    behavioral_roots=root / "roots.json",
                    legacy_v1_diagnostic=None,
                    isa_requirements=root / "isa-requirements.json",
                    isa_selection_authority=root / "isa.json",
                    launch_profile=root / "launch.json",
                    launch_invariants=root / "deprecated.json",
                    out=root / "out",
                )

    def test_callback_adapter_reads_exact_machine_ir_and_strict_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text('{"id":"unit:callback"}\n', encoding="ascii")
            provenance = root / "provenance.json"
            _write(provenance, {"callback_registrations": []})
            globals_path = root / "globals.json"
            invariant = {
                "format": "spaghetti-extractor-global-slot-invariant-v2",
                "content_id": "hybrid-authority-v2:global_slot_invariant:" + "d" * 64,
                "slot_rva": 0x2000,
            }
            _write(globals_path, {"global_slot_invariants": [invariant]})
            out = root / "callbacks.json"
            expected = {"status": "complete", "analysis_sha256": "e" * 64}
            binary = SimpleNamespace(
                sha256="a" * 64,
                image_base=0x400000,
                size_of_image=0x9000,
            )
            with patch(
                "spaghetti_extractor.authority_v2_cli._parse_stage_a_pe",
                return_value=binary,
            ), patch(
                "spaghetti_extractor.authority_v2_cli.derive_callback_entry_state_contracts_v2",
                return_value=expected,
            ) as derive:
                result = derive_callback_entry_contracts_v2_from_paths(
                    original=root / "original.exe",
                    machine_ir=machine_ir,
                    interface_provenance=provenance,
                    global_slot_invariants=globals_path,
                    out=out,
                )
                written = json.loads(out.read_text(encoding="ascii"))

        self.assertEqual(result, expected)
        self.assertEqual(derive.call_args.kwargs["units"], [{"id": "unit:callback"}])
        self.assertEqual(
            derive.call_args.kwargs["global_slot_invariants"], [invariant]
        )
        self.assertEqual(written, expected)


if __name__ == "__main__":
    unittest.main()
