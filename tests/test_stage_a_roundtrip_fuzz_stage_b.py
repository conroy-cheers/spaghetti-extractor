from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pefile

from spaghetti_extractor.contract_tools import (
    stage_a_export_reference_contract,
    stage_a_generate_map,
)
from spaghetti_extractor.roundtrip_fuzz.lowering import build_gnu_pe32
from spaghetti_extractor.roundtrip_fuzz.provenance import (
    build_opaque_stage_b_input_bundle,
    validate_opaque_stage_b_input_bundle,
)
from spaghetti_extractor.roundtrip_fuzz.stage_b_roundtrip import (
    CANDIDATE_SOURCE_MANIFEST_FORMAT,
    OPAQUE_STAGE_B_ROUNDTRIP_FORMAT,
    RELATIONAL_PROOF_HANDOFF_FORMAT,
    StageAProofRequest,
    StageAProofResult,
    StageBToolchainRequest,
    StageBToolchainResult,
    _generate_native_entry_source_from_state_machine,
    make_mingw_stage_b_toolchain_callback,
    run_opaque_stage_b_relational_roundtrip,
    run_opaque_stage_b_roundtrip,
    stage_a_proof_result_from_relational_report,
)
from spaghetti_extractor.relational.contract import stage_a_generate_relation_contract
from spaghetti_extractor.stage_b_state_machine import (
    write_stage_b_state_machine_from_stage_a_export,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json


def _raw_transfer() -> dict:
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": "semantic-transfer:opaque-entry",
        "function": "mainCRTStartup",
        "block_id": "opaque-entry",
        "unit_kind": "block",
        "status": "reimplementable",
        "reachable": True,
        "expression_model": "stage-a-semantic-ir-v1",
        "original": {"rva_start": 0x1000, "rva_end": 0x1005},
        "instructions": [{"rva": 0x1000, "bytes": "b807000000"}],
        "instruction_bytes_sha256": sha256_bytes(bytes.fromhex("b807000000")),
        "pre_state": {
            "registers": {}, "flags": {},
            "memory": {"op": "memory", "name": "mem0", "address_width": 32, "value_width": 8},
        },
        "register_writes": [
            {"register": "eax", "value": {"op": "const", "value": 7, "width": 32}},
        ],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "fpu_state": None,
        "outcome": {"kind": "return"},
        "stack_delta": 0,
        "counts": {},
        "acceptance": "guidance contract only; final acceptance requires Stage A binary proof",
        "blocker_category": None,
        "blocker": None,
        "next_action": "compile and prove",
    }


def _minimal_pe(root: Path) -> Path:
    source = root / "original.S"
    source.write_text(
        ".text\n.globl _mainCRTStartup\n_mainCRTStartup:\n  movl $7, %eax\n  ret\n",
        encoding="utf-8",
    )
    binary = root / "original.exe"
    subprocess.run(
        [
            "i686-w64-mingw32-gcc", "-nostdlib", "-Wl,--entry,_mainCRTStartup",
            "-Wl,--subsystem,console", "-Wl,--no-insert-timestamp",
            f"-Wl,-Map,{root / 'original.map'}", "-o", str(binary),
            str(source),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    return binary


def _bundle(root: Path, *, annotations: tuple[tuple[str, Path], ...] = ()) -> Path:
    inputs = root / "source-inputs"
    inputs.mkdir()
    contract = inputs / "reference-contract.json"
    original = _minimal_pe(inputs)
    original_sha256 = sha256_file(original)
    contract_payload = {
        "format": "stage-a-reference-contract-v1",
        "generator": "stage-a-export-reference-contract",
        "generated_at": "1970-01-01T00:00:01+00:00",
        "model": "x86-pe32-relational-v3",
        "status": "incomplete",
        "tool_versions": {},
        "inputs": {
            "original": {"path": str(original), "sha256": original_sha256, "exists": True},
            "candidate": None,
            "mapping": None,
            "validation_report": None,
            "layout_contract": None,
        },
        "original": {"sha256": original_sha256, "machine": "i386", "bitness": 32},
        "candidate": None,
        "constraints": {},
        "families": [],
        "coverage": {},
        "assumptions": {"unchecked": []},
        "issues": [],
        "counts": {},
        "sidecars": {
            "unit_contracts": {
                "directory": ".",
                "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
            },
        },
    }
    write_json(contract, contract_payload)
    semantic_transfers = inputs / "semantic-transfer-contracts.jsonl"
    transfer = _raw_transfer()
    transfer["reference_contract"] = {
        "path": str(contract),
        "sha256": sha256_file(contract),
        "format": "stage-a-reference-contract-v1",
    }
    semantic_transfers.write_text(
        json.dumps(transfer, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    state_machine = inputs / "state-machine.jsonl"
    write_stage_b_state_machine_from_stage_a_export(
        reference_contract=contract,
        semantic_transfer_contracts=semantic_transfers,
        original_pe=original,
        out=state_machine,
    )
    bundle = root / "opaque-bundle"
    build_opaque_stage_b_input_bundle(
        out=bundle,
        original_pe=original,
        reference_contract=contract,
        semantic_transfer_contracts=semantic_transfers,
        state_machine=state_machine,
        manual_annotations=annotations,
    )
    return bundle / "manifest.json"


def _public_export_bundle(
    root: Path, *, annotations: tuple[tuple[str, Path], ...] = ()
) -> dict[str, Path]:
    source = root / "public-original.S"
    source.write_text(
        ".text\n.globl _mainCRTStartup\n_mainCRTStartup:\n"
        "  movl $7, %eax\n  ret\n",
        encoding="ascii",
    )
    linked = build_gnu_pe32(
        source=source,
        binary=root / "public-original.exe",
        linker_map=root / "public-original.map",
    )
    self_map = root / "public-self-map.json"
    stage_a_generate_map(
        original=linked.binary,
        candidate=linked.binary,
        linker_map_original=linked.linker_map,
        linker_map_candidate=linked.linker_map,
        out=self_map,
        original_flags="opaque-stage-b-original",
        candidate_flags="opaque-stage-b-static-export",
    )
    export_dir = root / "public-stage-a-export"
    export_dir.mkdir()
    reference = export_dir / "reference-contract.json"
    stage_a_export_reference_contract(
        original=linked.binary,
        out=reference,
        mapping=self_map,
        sidecar_dir=export_dir,
        unit_contract_dir=export_dir,
    )
    semantic = export_dir / "semantic-transfer-contracts.jsonl"
    state_machine = export_dir / "state-machine.jsonl"
    write_stage_b_state_machine_from_stage_a_export(
        reference_contract=reference,
        semantic_transfer_contracts=semantic,
        original_pe=linked.binary,
        out=state_machine,
    )
    bundle = root / ("public-opaque-bundle" if not annotations else "public-opaque-bundle-annotated")
    build_opaque_stage_b_input_bundle(
        out=bundle,
        original_pe=linked.binary,
        reference_contract=reference,
        semantic_transfer_contracts=semantic,
        state_machine=state_machine,
        manual_annotations=annotations,
    )
    return {
        "manifest": bundle / "manifest.json",
        "original": linked.binary,
        "original_map": linked.linker_map,
        "reference": reference,
        "semantic": semantic,
        "state_machine": state_machine,
    }


def _passing_toolchain(
    captured: list[StageBToolchainRequest] | None = None,
):
    def callback(request: StageBToolchainRequest) -> StageBToolchainResult:
        if captured is not None:
            captured.append(request)
        candidate = request.out_dir / "candidate.exe"
        linker_map = request.out_dir / "candidate.map"
        candidate.write_bytes(b"MZopaque-candidate")
        linker_map.write_text("candidate map\n", encoding="utf-8")
        consumed = (
            request.source_manifest,
            request.implementation_manifest,
            request.generated_sources[0],
        ) + tuple(item.path for item in request.manual_annotations)
        return StageBToolchainResult(
            status="pass",
            candidate_pe=candidate,
            linker_map=linker_map,
            consumed_inputs=consumed,
            provenance={
                "format": "test-toolchain-provenance-v1",
                "compiler": "injected-test-compiler",
            },
        )

    return callback


def _passing_proof(captured: list[StageAProofRequest] | None = None):
    def callback(request: StageAProofRequest) -> StageAProofResult:
        if captured is not None:
            captured.append(request)
        report = request.out_dir / "stage-a-proof.json"
        write_json(report, {
            "format": "stage-a-relational-verdict-v1",
            "verdict": "pass",
            "acceptance_authority": "whole_program_lean",
            "profile": "x86-pe32-lean-relational-v3",
            "claim_scope": {
                "whole_program_observational_equivalence": True,
                "acceptance_eligible": True,
            },
            "original": {"sha256": request.original_pe_sha256},
            "candidate": {"sha256": sha256_file(request.candidate_pe)},
            "proof": {
                "theorem": "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
                "lean": {"status": "checked"},
            },
        })
        return StageAProofResult(
            status="pass",
            report=report,
            consumed_inputs=tuple(
                path
                for path in (
                    request.reference_contract,
                    request.original_pe,
                    request.relation_contract,
                    request.candidate_pe,
                )
                if path is not None
            ),
            provenance={
                "format": "test-stage-a-proof-provenance-v1",
                "lean": "pinned-test-lean",
            },
            final_theorem="StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
            lean_kernel_checked=True,
        )

    return callback


class OpaqueStageBRoundTripTests(unittest.TestCase):
    def test_native_entry_lowering_fails_closed_on_register_dependent_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _raw_transfer()
            row["register_writes"][0]["value"] = {
                "op": "reg",
                "name": "ecx",
                "width": 32,
            }
            state_machine = root / "state-machine.jsonl"
            state_machine.write_text(json.dumps(row) + "\n", encoding="utf-8")

            source, symbol, manifest = _generate_native_entry_source_from_state_machine(
                state_machine=state_machine,
                out_dir=root,
            )

            self.assertIsNone(source)
            self.assertIsNone(symbol)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "incomplete")
            self.assertIn(
                "native_entry_return_expression_unsupported", payload["blockers"]
            )
            self.assertFalse((root / "state-machine-native-entry.c").exists())

    def test_public_static_export_generates_a_real_no_crt_native_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exported = _public_export_bundle(root)

            result = run_opaque_stage_b_relational_roundtrip(
                opaque_bundle_manifest=exported["manifest"],
                original_pe=exported["original"],
                out=root / "native-roundtrip",
                execute_proof=False,
            )

            self.assertEqual(result["status"], "incomplete", result)
            self.assertEqual(result["compilation"]["status"], "pass", result)
            self.assertEqual(result["generation"]["status"], "complete", result)
            native = result["generation"]["native_entry"]
            self.assertEqual(native["status"], "ready", native)
            self.assertEqual(native["return_profile"], "x86-stack-return")
            self.assertEqual(
                result["compilation"]["provenance"]["mode"],
                "no-crt-native-entry",
            )
            candidate_path = (
                root
                / "native-roundtrip"
                / result["compilation"]["candidate_pe"]["path"]
            )
            candidate = pefile.PE(data=candidate_path.read_bytes(), fast_load=True)
            self.assertEqual(int(candidate.FILE_HEADER.Machine), 0x14C)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.Magic), 0x10B)
            self.assertEqual(int(candidate.FILE_HEADER.Characteristics) & 0x2000, 0)
            compile_roles = {
                item["role"]
                for item in result["provenance_audit"]["phase_boundaries"][
                    "candidate_compilation"
                ]
            }
            self.assertNotIn("original-pe", compile_roles)
            self.assertNotIn("manual-relational-proof-contract", compile_roles)
            self.assertEqual(
                result["provenance_audit"]["original_runtime_inputs_exposed"], []
            )

    @unittest.skipUnless(
        os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for the remote Lean proof",
    )
    def test_real_opaque_state_machine_c_pe_roundtrip_reaches_final_theorem(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exported = _public_export_bundle(root)
            first_out = root / "first-roundtrip"
            first = run_opaque_stage_b_relational_roundtrip(
                opaque_bundle_manifest=exported["manifest"],
                original_pe=exported["original"],
                out=first_out,
                execute_proof=False,
            )
            self.assertEqual(first["compilation"]["status"], "pass", first)
            first_candidate = first_out / first["compilation"]["candidate_pe"]["path"]
            first_candidate_map = first_out / first["compilation"]["linker_map"]["path"]

            proposal = root / "recorded-relation-proposal.json"
            proposal_result = stage_a_generate_map(
                original=exported["original"],
                candidate=first_candidate,
                linker_map_original=exported["original_map"],
                linker_map_candidate=first_candidate_map,
                out=proposal,
                original_flags="opaque-static-reference",
                candidate_flags="stage-b-generated-native-c",
            )
            self.assertEqual(proposal_result["status"], "pass", proposal_result)
            relation = root / "recorded-relation-contract.json"
            relation_result = stage_a_generate_relation_contract(
                original=exported["original"],
                candidate=first_candidate,
                mapping=proposal,
                out=relation,
            )
            self.assertEqual(relation_result["status"], "generated", relation_result)

            annotated_bundle = root / "public-opaque-bundle-annotated"
            build_opaque_stage_b_input_bundle(
                out=annotated_bundle,
                original_pe=exported["original"],
                reference_contract=exported["reference"],
                semantic_transfer_contracts=exported["semantic"],
                state_machine=exported["state_machine"],
                manual_annotations=(("relational-proof-contract", relation),),
            )
            final_out = root / "final-roundtrip"
            repository = Path(__file__).resolve().parents[1]
            result = run_opaque_stage_b_relational_roundtrip(
                opaque_bundle_manifest=annotated_bundle / "manifest.json",
                original_pe=exported["original"],
                out=final_out,
                flake=repository,
                builders_file=repository / "nix" / "stage-a-builders",
                execute_proof=True,
            )

            flags = result["compilation"]["provenance"]["flags"]
            self.assertIn("-O0", flags)
            self.assertIn("-fomit-frame-pointer", flags)
            self.assertEqual(result["status"], "pass", result)
            self.assertTrue(result["proof"]["lean_kernel_checked"], result)
            self.assertIn(
                result["proof"]["final_theorem"],
                {
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
                    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked",
                },
            )
            final_candidate = final_out / result["compilation"]["candidate_pe"]["path"]
            self.assertEqual(sha256_file(first_candidate), sha256_file(final_candidate))
            compile_roles = {
                item["role"]
                for item in result["provenance_audit"]["phase_boundaries"][
                    "candidate_compilation"
                ]
            }
            proof_roles = {
                item["role"]
                for item in result["provenance_audit"]["phase_boundaries"]["stage_a_proof"]
            }
            self.assertNotIn("manual-relational-proof-contract", compile_roles)
            self.assertIn("manual-relational-proof-contract", proof_roles)

    def test_proof_relation_annotation_is_never_exposed_to_candidate_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relation = root / "relation.json"
            write_json(relation, {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": "x86-pe32-env-v1"},
            })
            compile_requests: list[StageBToolchainRequest] = []
            proof_requests: list[StageAProofRequest] = []
            manifest = _bundle(
                root,
                annotations=(("relational-proof-contract", relation),),
            )

            result = run_opaque_stage_b_roundtrip(
                opaque_bundle_manifest=manifest,
                out=root / "roundtrip",
                toolchain_callback=_passing_toolchain(compile_requests),
                stage_a_proof_callback=_passing_proof(proof_requests),
            )

            self.assertEqual(result["status"], "pass", result)
            bundled_relation = proof_requests[0].relation_contract
            self.assertIsNotNone(bundled_relation)
            self.assertNotIn(bundled_relation, compile_requests[0].allowed_semantic_inputs)
            self.assertNotIn(
                "manual-relational-proof-contract",
                [item.role for item in compile_requests[0].manual_annotations],
            )
            proof_phase = result["provenance_audit"]["phase_boundaries"]["stage_a_proof"]
            compile_phase = result["provenance_audit"]["phase_boundaries"]["candidate_compilation"]
            self.assertIn("manual-relational-proof-contract", [item["role"] for item in proof_phase])
            self.assertNotIn("manual-relational-proof-contract", [item["role"] for item in compile_phase])

    def test_public_high_level_mode_compiles_then_reports_missing_relation_frontier(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = _bundle(root)
            original = root / "source-inputs" / "original.exe"

            result = run_opaque_stage_b_relational_roundtrip(
                opaque_bundle_manifest=manifest,
                original_pe=original,
                out=root / "roundtrip",
                execute_proof=False,
            )

            self.assertEqual(result["status"], "incomplete", result)
            self.assertEqual(result["compilation"]["status"], "pass", result)
            handoff = result["proof"]["handoff"]
            self.assertEqual(handoff["format"], RELATIONAL_PROOF_HANDOFF_FORMAT)
            self.assertEqual(handoff["phase"], "relation_contract")
            self.assertEqual(
                handoff["frontier"][0]["category"],
                "recorded_relational_proof_contract_missing",
            )
            original_audit = result["provenance_audit"]["original_static_proof_input"]
            self.assertFalse(original_audit["exposed_to_stage_b"])
            compile_roles = {
                item["role"]
                for item in result["provenance_audit"]["phase_boundaries"]["candidate_compilation"]
            }
            self.assertNotIn("original-pe", compile_roles)
            proof_original = next(
                item
                for item in result["proof"]["consumed_inputs"]
                if item["role"] == "original-pe"
            )
            self.assertEqual(proof_original["scope"], "stage_a_proof_only")

    def test_public_high_level_mode_runs_normal_prepare_and_reports_contract_frontier(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relation = root / "relation.json"
            write_json(relation, {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": "x86-pe32-env-v1"},
            })
            manifest = _bundle(
                root,
                annotations=(("relational-proof-contract", relation),),
            )

            result = run_opaque_stage_b_relational_roundtrip(
                opaque_bundle_manifest=manifest,
                original_pe=root / "source-inputs" / "original.exe",
                out=root / "roundtrip",
                execute_proof=False,
            )

            self.assertEqual(result["status"], "incomplete", result)
            self.assertEqual(result["reason_codes"], ["stage_a_final_proof_incomplete"])
            handoff = result["proof"]["handoff"]
            self.assertEqual(handoff["phase"], "prepared")
            self.assertEqual(
                handoff["frontier"][0]["category"],
                "relational_proof_preparation_incomplete",
            )
            self.assertIn("relational contract", handoff["frontier"][0]["message"])
            self.assertIn("verdict.json", handoff["prepared_proof"]["artifacts"])
            proof_roles = {
                item["role"] for item in result["proof"]["consumed_inputs"]
            }
            self.assertIn("manual-relational-proof-contract", proof_roles)

    def test_public_high_level_mode_rejects_original_hash_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = _bundle(root)
            substituted = root / "substituted.exe"
            substituted.write_bytes(
                (root / "source-inputs" / "original.exe").read_bytes() + b"substitution"
            )

            with self.assertRaisesRegex(
                StageAInputError, "not the image bound by the opaque exports"
            ):
                run_opaque_stage_b_relational_roundtrip(
                    opaque_bundle_manifest=manifest,
                    original_pe=substituted,
                    out=root / "roundtrip",
                    execute_proof=False,
                )

    def test_nix_relational_report_adapter_requires_all_checked_build_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "verdict.json"
            theorem = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
            payload = {
                "format": "stage-a-relational-nix-build-v1",
                "status": "pass",
                "verdict": "pass",
                "profile": "x86-pe32-lean-relational-v3",
                "claim_scope": {
                    "whole_program_observational_equivalence": True,
                    "acceptance_eligible": True,
                },
                "expected_final_theorem": theorem,
                "original": {"sha256": "a" * 64},
                "candidate": {"sha256": "b" * 64},
                "checks": {"graph": True, "proof": True},
                "lean_audit": {
                    "status": "checked",
                    "lean_trust": 0,
                    "theorem": theorem,
                },
            }
            write_json(report, payload)

            with patch(
                "spaghetti_extractor.relational.pipeline.stage_a_check_relational_proof",
                return_value={"status": "pass"},
            ):
                checked = stage_a_proof_result_from_relational_report(
                    report=report,
                    consumed_inputs=(),
                    provenance={"format": "test"},
                )
            self.assertEqual(checked.status, "pass")
            self.assertTrue(checked.lean_kernel_checked)
            self.assertEqual(checked.final_theorem, theorem)

            payload["checks"]["proof"] = False
            write_json(report, payload)
            unchecked = stage_a_proof_result_from_relational_report(
                report=report,
                consumed_inputs=(),
                provenance={"format": "test"},
            )
            self.assertEqual(unchecked.status, "incomplete")
            self.assertFalse(unchecked.lean_kernel_checked)
            self.assertIsNone(unchecked.final_theorem)

    def test_orchestrates_opaque_state_machine_through_c_compile_and_final_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            annotation = root / "repair-note.json"
            annotation.write_text(
                json.dumps({
                    "format": "stage-b-manual-annotation-v1",
                    "note": "Use the generated return transition as emitted.",
                }),
                encoding="utf-8",
            )
            manifest = _bundle(root, annotations=(("repair-note", annotation),))
            compile_requests: list[StageBToolchainRequest] = []
            proof_requests: list[StageAProofRequest] = []

            result = run_opaque_stage_b_roundtrip(
                opaque_bundle_manifest=manifest,
                out=root / "roundtrip",
                toolchain_callback=_passing_toolchain(compile_requests),
                stage_a_proof_callback=_passing_proof(proof_requests),
            )

            self.assertEqual(result["format"], OPAQUE_STAGE_B_ROUNDTRIP_FORMAT)
            self.assertEqual(result["status"], "pass", result)
            self.assertTrue(result["proof"]["lean_kernel_checked"])
            self.assertEqual(result["provenance_audit"]["generator_inputs_exposed"], [])
            self.assertEqual(result["provenance_audit"]["ground_truth_inputs_exposed"], [])
            self.assertEqual(result["provenance_audit"]["manual_annotations"], ["manual-repair-note"])
            self.assertTrue(result["compilation"]["consumed_inputs"])
            self.assertEqual(result["proof"]["consumed_inputs"][0]["scope"], "opaque_bundle")
            source_manifest = json.loads(
                (root / "roundtrip" / result["generation"]["source_manifest"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(source_manifest["format"], CANDIDATE_SOURCE_MANIFEST_FORMAT)
            self.assertTrue(source_manifest["generated_sources"])
            self.assertEqual(source_manifest["manual_annotations"][0]["role"], "manual-repair-note")
            self.assertEqual(len(compile_requests), 1)
            self.assertEqual(len(proof_requests), 1)
            self.assertFalse(hasattr(compile_requests[0], "reference_contract"))
            self.assertFalse(hasattr(compile_requests[0], "original_pe"))
            self.assertFalse(hasattr(proof_requests[0], "generator_semantic_program"))
            self.assertTrue((root / "roundtrip" / "result.json").is_file())

    def test_incomplete_compilation_stops_before_stage_a(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proof_called = False

            def toolchain(_request: StageBToolchainRequest) -> StageBToolchainResult:
                return StageBToolchainResult(
                    status="incomplete",
                    candidate_pe=None,
                    provenance={},
                    diagnostics=({"category": "link_failed"},),
                )

            def proof(_request: StageAProofRequest) -> StageAProofResult:
                nonlocal proof_called
                proof_called = True
                raise AssertionError("proof callback must not run")

            result = run_opaque_stage_b_roundtrip(
                opaque_bundle_manifest=_bundle(root),
                out=root / "roundtrip",
                toolchain_callback=toolchain,
                stage_a_proof_callback=proof,
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["reason_codes"], ["candidate_compilation_incomplete"])
            self.assertIsNone(result["proof"])
            self.assertFalse(proof_called)

    def test_rejects_ground_truth_disguised_as_manual_annotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            annotation = root / "annotation.json"
            annotation.write_text(json.dumps({"ground_truth_map": {"entry": 0x1000}}), encoding="utf-8")

            with self.assertRaisesRegex(StageAInputError, "prohibited provenance field"):
                run_opaque_stage_b_roundtrip(
                    opaque_bundle_manifest=_bundle(root, annotations=(("note", annotation),)),
                    out=root / "roundtrip",
                    toolchain_callback=_passing_toolchain(),
                    stage_a_proof_callback=_passing_proof(),
                )

    def test_rejects_noncanonical_state_machine_side_channels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = _bundle(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            state_row = next(item for item in payload["inputs"] if item["role"] == "state_machine")
            state_machine = manifest.parent / state_row["path"]
            row = json.loads(state_machine.read_text(encoding="utf-8"))
            row["generator_seed"] = 42
            state_machine.write_text(json.dumps(row) + "\n", encoding="utf-8")
            state_row["bytes"] = state_machine.stat().st_size
            from spaghetti_extractor.util import sha256_file

            state_row["sha256"] = sha256_file(state_machine)
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                StageAInputError,
                "not canonical|canonical derivative|undeclared fields|prohibited provenance field",
            ):
                run_opaque_stage_b_roundtrip(
                    opaque_bundle_manifest=manifest,
                    out=root / "roundtrip",
                    toolchain_callback=_passing_toolchain(),
                    stage_a_proof_callback=_passing_proof(),
                )

    def test_rejects_undeclared_compiler_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "secret.c"
            secret.write_text("int secret;\n", encoding="utf-8")

            def toolchain(request: StageBToolchainRequest) -> StageBToolchainResult:
                candidate = request.out_dir / "candidate.exe"
                candidate.write_bytes(b"MZcandidate")
                return StageBToolchainResult(
                    status="pass",
                    candidate_pe=candidate,
                    consumed_inputs=(
                        request.source_manifest,
                        request.implementation_manifest,
                        request.generated_sources[0],
                        secret,
                    ),
                    provenance={"format": "test-toolchain-v1"},
                )

            with self.assertRaisesRegex(StageAInputError, "undeclared semantic inputs"):
                run_opaque_stage_b_roundtrip(
                    opaque_bundle_manifest=_bundle(root),
                    out=root / "roundtrip",
                    toolchain_callback=toolchain,
                    stage_a_proof_callback=_passing_proof(),
                )

    def test_raw_stage_a_pass_without_kernel_theorem_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def proof(request: StageAProofRequest) -> StageAProofResult:
                report = request.out_dir / "stage-a-proof.json"
                write_json(report, {
                    "format": "stage-a-relational-verdict-v1",
                    "verdict": "pass",
                    "acceptance_authority": "whole_program_lean",
                    "profile": "x86-pe32-lean-relational-v3",
                    "claim_scope": {
                        "whole_program_observational_equivalence": False,
                        "acceptance_eligible": False,
                    },
                    "original": {"sha256": request.original_pe_sha256},
                    "candidate": {"sha256": sha256_file(request.candidate_pe)},
                    "proof": {"theorem": "", "lean": {"status": "incomplete"}},
                })
                return StageAProofResult(
                    status="pass",
                    report=report,
                    consumed_inputs=(request.reference_contract, request.candidate_pe),
                    provenance={"format": "test-stage-a-proof-v1"},
                    final_theorem=None,
                    lean_kernel_checked=False,
                )

            result = run_opaque_stage_b_roundtrip(
                opaque_bundle_manifest=_bundle(root),
                out=root / "roundtrip",
                toolchain_callback=_passing_toolchain(),
                stage_a_proof_callback=proof,
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(
                {
                    "stage_a_pass_without_lean_kernel_check",
                    "stage_a_pass_without_whole_program_theorem",
                }.issubset(result["reason_codes"]),
                result,
            )

    def test_unchecked_stage_a_violation_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def proof(request: StageAProofRequest) -> StageAProofResult:
                report = request.out_dir / "stage-a-proof.json"
                write_json(report, {
                    "format": "stage-a-relational-verdict-v1",
                    "verdict": "fail",
                    "acceptance_authority": "whole_program_lean",
                    "profile": "x86-pe32-lean-relational-v3",
                    "claim_scope": {
                        "whole_program_observational_equivalence": False,
                        "acceptance_eligible": False,
                    },
                    "original": {"sha256": request.original_pe_sha256},
                    "candidate": {"sha256": sha256_file(request.candidate_pe)},
                    "proof": {"theorem": "", "lean": {"status": "incomplete"}},
                })
                return StageAProofResult(
                    status="violated",
                    report=report,
                    consumed_inputs=(request.reference_contract, request.candidate_pe),
                    provenance={"format": "test-stage-a-proof-v1"},
                )

            result = run_opaque_stage_b_roundtrip(
                opaque_bundle_manifest=_bundle(root),
                out=root / "roundtrip",
                toolchain_callback=_passing_toolchain(),
                stage_a_proof_callback=proof,
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(
                result["reason_codes"],
                ["stage_a_violation_without_lean_kernel_check"],
            )

    def test_detects_callback_mutation_of_generated_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def toolchain(request: StageBToolchainRequest) -> StageBToolchainResult:
                request.generated_sources[0].write_text("mutated\n", encoding="utf-8")
                return StageBToolchainResult(
                    status="incomplete",
                    candidate_pe=None,
                    provenance={},
                )

            with self.assertRaisesRegex(StageAInputError, "mutated input"):
                run_opaque_stage_b_roundtrip(
                    opaque_bundle_manifest=_bundle(root),
                    out=root / "roundtrip",
                    toolchain_callback=toolchain,
                    stage_a_proof_callback=_passing_proof(),
                )

    def test_rejects_file_merely_labelled_as_stage_a_reference_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = _minimal_pe(root)
            fake = root / "reference.json"
            write_json(fake, {
                "format": "stage-a-reference-contract-v1",
                "generator": "not-the-public-exporter",
            })
            semantic = root / "semantic.jsonl"
            semantic.write_text("{}\n", encoding="utf-8")
            state_machine = root / "state.jsonl"
            state_machine.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(StageAInputError, "public export"):
                build_opaque_stage_b_input_bundle(
                    out=root / "bundle",
                    original_pe=original,
                    reference_contract=fake,
                    semantic_transfer_contracts=semantic,
                    state_machine=state_machine,
                )

    def test_bundle_validation_rejects_undeclared_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = _bundle(root)
            (manifest.parent / "inputs" / "undeclared.json").write_text(
                "{}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(StageAInputError, "undeclared files"):
                validate_opaque_stage_b_input_bundle(manifest)

    def test_public_export_to_real_mingw_candidate_remains_incomplete_without_final_theorem(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "original.S"
            source.write_text(
                ".text\n.globl _mainCRTStartup\n_mainCRTStartup:\n  movl $7, %eax\n  ret\n",
                encoding="utf-8",
            )
            linked = build_gnu_pe32(
                source=source,
                binary=root / "original.exe",
                linker_map=root / "original.map",
            )
            mapping = root / "self-map.json"
            stage_a_generate_map(
                original=linked.binary,
                candidate=linked.binary,
                linker_map_original=linked.linker_map,
                linker_map_candidate=linked.linker_map,
                out=mapping,
                original_flags="opaque-stage-b-original",
                candidate_flags="opaque-stage-b-self-export",
            )
            export_dir = root / "stage-a-export"
            export_dir.mkdir()
            reference = export_dir / "reference-contract.json"
            stage_a_export_reference_contract(
                original=linked.binary,
                out=reference,
                mapping=mapping,
                sidecar_dir=export_dir,
                unit_contract_dir=export_dir,
            )
            semantic = export_dir / "semantic-transfer-contracts.jsonl"
            state_machine = export_dir / "state-machine.jsonl"
            write_stage_b_state_machine_from_stage_a_export(
                reference_contract=reference,
                semantic_transfer_contracts=semantic,
                original_pe=linked.binary,
                out=state_machine,
            )
            bundle = root / "opaque-bundle"
            build_opaque_stage_b_input_bundle(
                out=bundle,
                original_pe=linked.binary,
                reference_contract=reference,
                semantic_transfer_contracts=semantic,
                state_machine=state_machine,
            )

            def proof(request: StageAProofRequest) -> StageAProofResult:
                report = request.out_dir / "verdict.json"
                write_json(report, {
                    "format": "stage-a-relational-verdict-v1",
                    "verdict": "incomplete",
                    "acceptance_authority": "whole_program_lean",
                    "profile": "x86-pe32-lean-relational-v3",
                    "claim_scope": {
                        "whole_program_observational_equivalence": False,
                        "acceptance_eligible": False,
                    },
                    "original": {"sha256": request.original_pe_sha256},
                    "candidate": {"sha256": sha256_file(request.candidate_pe)},
                    "proof": {"theorem": "", "lean": {"status": "incomplete"}},
                })
                return stage_a_proof_result_from_relational_report(
                    report=report,
                    consumed_inputs=(request.reference_contract, request.candidate_pe),
                    provenance={
                        "format": "integration-stage-a-proof-provenance-v1",
                        "authority": "real relational-v3 verdict adapter",
                    },
                )

            result = run_opaque_stage_b_roundtrip(
                opaque_bundle_manifest=bundle / "manifest.json",
                out=root / "roundtrip",
                toolchain_callback=make_mingw_stage_b_toolchain_callback(),
                stage_a_proof_callback=proof,
            )

            self.assertEqual(result["status"], "incomplete", result)
            self.assertEqual(result["compilation"]["status"], "pass", result)
            candidate = root / "roundtrip" / result["compilation"]["candidate_pe"]["path"]
            parsed_candidate = pefile.PE(data=candidate.read_bytes(), fast_load=True)
            self.assertEqual(int(parsed_candidate.FILE_HEADER.Machine), 0x14C)
            self.assertEqual(int(parsed_candidate.OPTIONAL_HEADER.Magic), 0x10B)
            self.assertFalse(result["proof"]["lean_kernel_checked"])
            self.assertEqual(
                result["provenance_audit"]["provenance_chain"]["original_pe_sha256"],
                sha256_file(linked.binary),
            )


if __name__ == "__main__":
    unittest.main()
