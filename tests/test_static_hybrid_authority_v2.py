from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.exception_invariants_v2 import (
    EXCEPTION_INVARIANT_CHECK_V2_FORMAT,
    canonical_sha256 as exception_sha256,
)
from spaghetti_extractor.analysis_schema_v2 import (
    interprocedural_authority_signature_v2,
)
from spaghetti_extractor.hybrid_authority_builder_v2 import (
    build_machine_ir_authority_bindings,
    machine_ir_sha256,
    recompute_unit_binding,
)
from spaghetti_extractor.external_profile_authority_v2 import (
    ExternalProfileAuthorityV2,
    build_external_profile_authority_v2,
)
from spaghetti_extractor.hybrid_authority_v2 import (
    AuthorityBundle,
    BinaryBinding,
    CallFrameSummary,
    EntryStateContract,
    EventBinding,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    IndirectExitCertificate,
    canonical_json_bytes,
)
from spaghetti_extractor.hybrid_diagnostics_v2 import build_hybrid_diagnostics_v2
from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
    build_machine_ir_isa_extraction_request_v2,
    build_machine_ir_isa_requirements_v2,
)
from spaghetti_extractor.machine_ir_isa_selection_v2 import (
    build_machine_ir_isa_selection_certificate_v2,
)
from spaghetti_extractor.static_hybrid_authority_v2 import (
    STATIC_HYBRID_AUTHORITY_V2_FORMAT,
    StaticHybridAuthorityV2Error,
    _bundle_blockers,
    build_static_hybrid_authority_v2,
    validate_static_hybrid_authority_v2,
)

from tests.test_isa_kernel_selection import (
    BINARY_SHA,
    CLASSIFIER_SHA,
    SEMANTIC_FORM,
    _authority,
)


INSTRUCTION_SHA = "5" * 64
PROFILE_SHA = "6" * 64
CERTIFICATE_SHA = "7" * 64


def _row(
    *,
    external_events: list[dict] | None = None,
    faults: list[dict] | None = None,
    outcome: dict | None = None,
) -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:entry",
        "reachable": True,
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "instruction_bytes_sha256": INSTRUCTION_SHA,
        },
        "instructions": [{
            "rva_start": 0x1000,
            "rva_end": 0x1001,
            "size": 1,
            "instruction_sha256": INSTRUCTION_SHA,
            "mnemonic": "ret",
            "operands": [],
            "groups": ["ret"],
            "registers_read": ["esp"],
            "registers_written": ["esp"],
        }],
        "semantics": {
            "external_events": external_events or [],
            "faults": faults or [],
            "outcome": outcome or {"kind": "return"},
        },
    }


def _manifest(rows: list[dict]) -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "inputs": {"original_pe": {"sha256": BINARY_SHA}},
        "binary": {"sha256": BINARY_SHA},
        "artifacts": {"machine_ir": {"sha256": machine_ir_sha256(rows)}},
        "authority_bindings": build_machine_ir_authority_bindings(
            rows, pe_sha256=BINARY_SHA
        ),
    }


def _exact_unit_preparation(rows: list[dict]) -> dict:
    bindings = build_machine_ir_authority_bindings(
        rows, pe_sha256=BINARY_SHA
    )
    return {
        "format": "spaghetti-extractor-exact-unit-preparation-v2",
        "status": "complete",
        "binary": {"sha256": BINARY_SHA},
        "machine_ir": {
            "sha256": machine_ir_sha256(rows),
            "units": len(rows),
        },
        "authority_bindings": bindings,
        "issues": [],
    }


def _entry_record(rows: list[dict]) -> EntryStateContract:
    binary = BinaryBinding(BINARY_SHA, machine_ir_sha256(rows))
    return EntryStateContract(
        entry=recompute_unit_binding(rows[0], binary=binary),
        entry_kind="pe_entry",
        alternatives=FiniteAlternatives.of(
            [{"launch": "pe32-console-launch-v1"}], maximum=1
        ),
    )


def _entry_analysis(rows: list[dict]) -> dict:
    body = {
        "format": "stage-a-entry-state-analysis-v2",
        "status": "complete",
        "authority": "checked_static_replay_v2",
        "proof_authority": False,
        "authority_records": [_entry_record(rows).to_payload()],
        "issues": [],
    }
    return {**body, "analysis_sha256": _sha256(body)}


def _interprocedural(
    *, call_site_effects: list[dict] | None = None
) -> dict:
    signature = "8" * 64
    call_summaries = {"summaries": []}
    recovered_targets: list[dict] = []
    dependencies: list[dict] = []
    effects = [] if call_site_effects is None else call_site_effects
    root_unit_ids = ["unit:entry"]
    return {
        "call_summaries": call_summaries,
        "recovered_targets": recovered_targets,
        "operation_provenance": {"call_site_effects": effects},
        "fixed_point": {
            "format": "stage-a-interprocedural-analysis-v2",
            "status": "complete",
            "cold_replay_validated": True,
            "authority_replay_validated": True,
            "cold_initial_recoveries_empty": True,
            "static_recovery_authority_seeded": False,
            "global_slot_promotion": False,
            "discovery_signature": signature,
            "cold_replay_signature": signature,
            "authority_artifact_sha256": interprocedural_authority_signature_v2(
                root_unit_ids=root_unit_ids,
                dependency_inventory=dependencies,
                call_summaries=call_summaries,
                recovered_targets=recovered_targets,
                call_site_effects=effects,
            ),
            "root_unit_ids": root_unit_ids,
            "dependencies": dependencies,
            "failure_reasons": [],
            "recursive_summary_roots": [],
        },
    }


def _call_effect() -> dict:
    return {
        "format": "stage-a-call-site-effect-v2",
        "unit_id": "unit:entry",
        "event_index": 0,
        "transfer_kind": "external_call",
        "status": "complete",
        "register_frame": {
            "status": "complete",
            "preserved_registers": [],
        },
        "stack_frame": {
            "status": "complete",
            "stack_cleanup_bytes": 0,
        },
        "result_frame": {"status": "complete", "outputs": []},
        "memory_frame": {
            "status": "complete",
            "preserved": True,
            "writes": [],
        },
        "abi": None,
        "argument_words": None,
        "dependencies": [],
        "failure_codes": [],
    }


def _isa_requirements(rows: list[dict]) -> dict:
    request = build_machine_ir_isa_extraction_request_v2(
        units=rows,
        binary_sha256=BINARY_SHA,
    )
    lean_rows = {}
    for region in request["regions"]:
        span = region["span"]
        lean_rows[("original", region["index"])] = ({
            "rva": span["rva_start"],
            "size": span["size"],
            "bytes": "c3" * span["size"],
            "form": SEMANTIC_FORM,
        },)
    return build_machine_ir_isa_requirements_v2(
        request=request,
        machine_ir_sha256=machine_ir_sha256(rows),
        lean_rows=lean_rows,
        lean_evidence={
            "status": "lean_extracted_untrusted",
            "classifier_sha256": CLASSIFIER_SHA,
            "extractor_sha256": "a" * 64,
            "source_sha256": "b" * 64,
        },
    )


def _external_event() -> dict:
    return {
        "kind": "external_call",
        "instruction_rva": 0x1000,
        "dll": "fixture.dll",
        "symbol": "Exact",
        "ordinal": None,
    }


def _checked_external_site(*, profile_sha256: str = PROFILE_SHA) -> dict:
    site = {
        "unit_id": "unit:entry",
        "event_index": 0,
        "contract": {
            "format": "stage-b-checked-external-site-contract-v1",
            "identity": {
                "kind": "import",
                "dll": "fixture.dll",
                "symbol": "Exact",
                "ordinal": None,
                "protocol": None,
                "profile_id": None,
                "profile_sha256": None,
                "operation": None,
            },
            "transfer_kind": "call",
            "disposition": "returns_here",
            "profile_disposition": "returns",
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 0},
            "argument_base_offset": 0,
            "arguments": [],
            "stack_arguments": [],
            "contract_id": "fixture.dll!Exact",
            "profile_binding": {
                "profile_id": "fixture-profile",
                "profile_sha256": profile_sha256,
                "entry_key": "machine_import_signatures",
                "entry_index": 0,
            },
            "result_register_relations": [],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
            "callback_effect": "none",
            "callback_adapter": None,
            "out_pointer_relations": [],
            "out_interface_relations": [],
        },
    }
    site["target_alternative_index"] = 0
    site["target_alternative_sha256"] = hashlib.sha256(
        canonical_json_bytes(site["contract"]["identity"])
    ).hexdigest()
    return site


def _complete_report(
    rows: list[dict],
    *,
    checked_external_sites: list[dict] | None = None,
    exception_reports: list[dict] | None = None,
    isa=None,
    entry_analysis: dict | None = None,
    interprocedural: dict | None = None,
    external_profile_authority: ExternalProfileAuthorityV2 | None = None,
    isa_requirements: dict | None = None,
    exact_unit_preparation: dict | None = None,
    v1_diagnostics=None,
) -> dict:
    if isa is None:
        _qualification, _selection, isa = _authority()
    return build_static_hybrid_authority_v2(
        machine_ir_rows=rows,
        machine_ir_manifest=_manifest(rows),
        exact_unit_preparation=exact_unit_preparation,
        pe_sha256=BINARY_SHA,
        behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
        entry_state_analysis=(
            _entry_analysis(rows) if entry_analysis is None else entry_analysis
        ),
        interprocedural_result=(
            _interprocedural() if interprocedural is None else interprocedural
        ),
        checked_external_sites=checked_external_sites or [],
        external_profile_authority=external_profile_authority,
        checked_exception_reports=exception_reports or [],
        isa_selection_authority=isa,
        isa_requirements=(
            _isa_requirements(rows)
            if isa_requirements is None
            else isa_requirements
        ),
        v1_diagnostics=v1_diagnostics,
    )


def _sha256(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _write_external_profile(path: Path) -> str:
    payload = {
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "fixture-profile",
        "machine_import_signatures": [{
            "id": "fixture.dll!Exact",
            "import": {"dll": "fixture.dll", "symbol": "Exact"},
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 0},
            "disposition": "returns",
            "result_register_relations": [],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
            "callback_effect": "none",
            "out_pointer_relations": [],
            "out_interface_relations": [],
        }],
    }
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StaticHybridAuthorityV2Tests(unittest.TestCase):
    def test_checked_exact_unit_preparation_reuses_unit_identity(self) -> None:
        rows = [_row()]
        report = _complete_report(
            rows,
            exact_unit_preparation=_exact_unit_preparation(rows),
        )

        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["authorizes_candidate_generation"])

    def test_corrupt_exact_unit_preparation_is_violated(self) -> None:
        rows = [_row()]
        prepared = _exact_unit_preparation(rows)
        prepared["authority_bindings"]["units"][0]["unit_sha256"] = "9" * 64

        report = _complete_report(
            rows,
            exact_unit_preparation=prepared,
        )

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "exact_unit_preparation_corrupt",
            {
                row["details"]["code"]
                for row in report["diagnostics"]["blockers"]
            },
        )

    def test_compact_isa_certificate_authorizes_without_oracle_corpus(self) -> None:
        rows = [_row()]
        requirements = _isa_requirements(rows)
        _qualification, _selection, authority = _authority()
        certificate = build_machine_ir_isa_selection_certificate_v2(
            requirements=requirements,
            authority=authority,
        )

        report = _complete_report(
            rows,
            isa=certificate,
            isa_requirements=requirements,
        )

        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["authorizes_candidate_generation"])
        self.assertNotIn("evidence", certificate)

    def test_call_summary_scc_is_blocked_by_its_exact_indirect_exit(self) -> None:
        rows = [_row()]
        entry = _entry_record(rows)
        unit = entry.entry
        indirect = IndirectExitCertificate(
            exit_site=EventBinding(
                unit=unit,
                event_index=1,
                event_kind="indirect_call",
                instruction_rva=0x1000,
                event_sha256="a" * 64,
            ),
            analysis_fact_id="indirect-exit:fixture",
            target_expression_sha256="b" * 64,
            alternatives=None,
            issues=(EvidenceIssue(
                EvidenceIssueKind.MISSING,
                "indirect_targets_missing",
                "the finite target set is unresolved",
            ),),
        )
        frame = CallFrameSummary(
            call_site=EventBinding(
                unit=unit,
                event_index=0,
                event_kind="internal_call",
                instruction_rva=0x1000,
                event_sha256="c" * 64,
            ),
            analysis_fact_id="call-frame:fixture",
            callee=unit,
            abi="x86-pe32-v2",
            alternatives=FiniteAlternatives.of([{
                "format": "spaghetti-extractor-call-frame-families-v2",
                "status": "incomplete",
                "callee": unit.to_payload(),
                "return_behavior": {"status": "incomplete"},
                "stack_cleanup": {"status": "incomplete"},
                "register_preservation": {"status": "incomplete"},
                "result_origins": {"status": "incomplete"},
                "memory_effects": {"status": "incomplete"},
                "callback_effects": {"status": "not_applicable"},
                "world_effects": {"status": "not_applicable"},
                "target_dependencies": ["indirect-exit:fixture"],
                "blocker_codes": ["indirect_call_target_unresolved"],
            }], maximum=1),
            issues=(EvidenceIssue(
                EvidenceIssueKind.MISSING,
                "call_summary_missing",
                "the callee summary is incomplete",
            ),),
        )
        bundle = AuthorityBundle.of(
            binary=unit.binary,
            records=[entry, frame, indirect],
            required_content_ids=[
                entry.content_id,
                frame.content_id,
                indirect.content_id,
            ],
        )

        diagnostics = build_hybrid_diagnostics_v2(_bundle_blockers(bundle))
        by_code = {
            row["details"]["code"]: row
            for row in diagnostics["blockers"]
            if row["details"]["code"] in {
                "indirect_targets_missing",
                "call_summary_scc_incomplete",
                "call_summary_missing",
            }
        }

        self.assertIn(
            by_code["indirect_targets_missing"]["id"],
            by_code["call_summary_scc_incomplete"]["blocked_by"],
        )
        self.assertIn(
            by_code["call_summary_scc_incomplete"]["id"],
            by_code["call_summary_missing"]["blocked_by"],
        )
        self.assertEqual(diagnostics["counts"]["primary_blockers"], 1)

    def test_complete_exact_v2_evidence_is_the_only_authority(self) -> None:
        rows = [_row()]

        report = _complete_report(rows)

        self.assertEqual(report["format"], STATIC_HYBRID_AUTHORITY_V2_FORMAT)
        self.assertEqual(report["status"], "complete", report["diagnostics"])
        self.assertTrue(report["authorizes_candidate_generation"])
        self.assertFalse(report["v1_authorizes"])
        self.assertEqual(report["primary_blocker_ids"], [])
        self.assertTrue(report["replay"]["deterministic"])
        self.assertEqual(report, validate_static_hybrid_authority_v2(report))
        self.assertEqual(report, _complete_report(rows))

    def test_isa_request_binding_is_replayed_from_exact_machine_ir(self) -> None:
        rows = [_row()]
        requirements = _isa_requirements(rows)
        requirements["binding"]["request_sha256"] = "f" * 64
        body = dict(requirements)
        body.pop("requirements_sha256")
        requirements["requirements_sha256"] = _sha256(body)

        report = _complete_report(rows, isa_requirements=requirements)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "isa_exact_requirements_binding_mismatch",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_missing_entry_evidence_is_incomplete_with_primary_blocker(self) -> None:
        rows = [_row()]

        report = _complete_report(rows, entry_analysis={})

        self.assertEqual(report["status"], "violated")
        self.assertFalse(report["authorizes_candidate_generation"])
        primary = {
            row["details"]["code"]
            for row in report["diagnostics"]["blockers"]
            if row["id"] in report["primary_blocker_ids"]
        }
        self.assertIn("entry_state_analysis_format_mismatch", primary)

        missing = build_static_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
            entry_state_analysis=None,
            interprocedural_result=_interprocedural(),
            isa_selection_authority=_authority()[2],
        )
        self.assertEqual(missing["status"], "incomplete")
        self.assertIn(
            "entry_state_analysis_missing",
            {
                row["details"]["code"]
                for row in missing["diagnostics"]["blockers"]
                if row["id"] in missing["primary_blocker_ids"]
            },
        )

    def test_stale_entry_analysis_hash_is_violated(self) -> None:
        rows = [_row()]
        analysis = _entry_analysis(rows)
        analysis["analysis_sha256"] = "0" * 64

        report = _complete_report(rows, entry_analysis=analysis)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "entry_state_analysis_hash_mismatch",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_noncanonical_evidence_is_reported_as_violated_not_raised(self) -> None:
        rows = [_row()]
        manifest = _manifest(rows)
        manifest["invalid_float"] = 1.5

        report = build_static_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=manifest,
            pe_sha256=BINARY_SHA,
            behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
            entry_state_analysis=_entry_analysis(rows),
            interprocedural_result=_interprocedural(),
            isa_selection_authority=_authority()[2],
        )

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "machine_ir_manifest_corrupt",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_v1_pass_is_diagnostic_only_and_cannot_fill_missing_v2_evidence(self) -> None:
        rows = [_row()]
        report = build_static_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
            entry_state_analysis=None,
            interprocedural_result=_interprocedural(),
            isa_selection_authority=None,
            v1_diagnostics={"status": "pass", "authorizes": True},
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["authorizes_candidate_generation"])
        self.assertEqual(
            report["legacy_v1_diagnostics"],
            {"status": "pass", "authorizes": True},
        )
        self.assertFalse(report["v1_authorizes"])

    def test_empty_behavioral_root_inventory_cannot_be_masked_by_entry_record(self) -> None:
        rows = [_row()]
        report = build_static_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            behavioral_roots=[],
            entry_state_analysis=_entry_analysis(rows),
            interprocedural_result=_interprocedural(),
            isa_selection_authority=_authority()[2],
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["authorizes_candidate_generation"])
        self.assertIn(
            "behavioral_root_inventory_missing",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_canonical_external_site_is_converted_and_replayed(self) -> None:
        rows = [_row(external_events=[_external_event()])]

        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            profile_sha256 = _write_external_profile(profile)
            profile_authority = build_external_profile_authority_v2([profile])
            report = _complete_report(
                rows,
                checked_external_sites=[_checked_external_site(
                    profile_sha256=profile_sha256
                )],
                external_profile_authority=profile_authority,
            )

        self.assertEqual(report["status"], "complete", report["diagnostics"])
        records = report["authority_bundle"]["records"]
        external = [
            row for row in records
            if row["format"] == "spaghetti-extractor-checked-external-site-v2"
        ]
        self.assertEqual(len(external), 1)
        self.assertEqual(
            external[0]["binding"]["profile"]["profile_sha256"],
            profile_sha256,
        )
        self.assertEqual(
            external[0]["binding"]["profile"]["entry_id"],
            profile_authority.entries[0].entry_id,
        )

    def test_fake_profile_hash_is_violated_at_exact_site(self) -> None:
        rows = [_row(external_events=[_external_event()])]
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_external_profile(profile)
            report = _complete_report(
                rows,
                checked_external_sites=[_checked_external_site(
                    profile_sha256="a" * 64
                )],
                external_profile_authority=(
                    build_external_profile_authority_v2([profile])
                ),
            )

        self.assertEqual(report["status"], "violated")
        blocker = next(
            item for item in report["diagnostics"]["blockers"]
            if item["details"]["code"] == "external_profile_hash_mismatch"
        )
        self.assertEqual(blocker["details"]["unit_id"], "unit:entry")
        self.assertEqual(blocker["details"]["event_index"], 0)
        self.assertEqual(blocker["details"]["instruction_rva"], 0x1000)

    def test_missing_external_profile_artifact_is_incomplete(self) -> None:
        rows = [_row(external_events=[_external_event()])]

        report = _complete_report(
            rows, checked_external_sites=[_checked_external_site()]
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertIn(
            "external_profile_evidence_missing",
            {item["details"]["code"] for item in report["diagnostics"]["blockers"]},
        )

    def test_missing_external_site_abi_is_incomplete(self) -> None:
        rows = [_row(external_events=[_external_event()])]
        site = _checked_external_site()
        site["contract"]["abi_template"] = None

        report = _complete_report(rows, checked_external_sites=[site])

        self.assertEqual(report["status"], "incomplete")
        blocker = next(
            item for item in report["diagnostics"]["blockers"]
            if item["details"]["code"] == "external_site_abi_missing"
        )
        self.assertEqual(blocker["details"]["unit_id"], "unit:entry")
        self.assertEqual(blocker["details"]["event_index"], 0)

    def test_corrupt_external_site_is_a_violation_at_its_exact_location(self) -> None:
        rows = [_row(external_events=[_external_event()])]
        site = _checked_external_site()
        site["contract"]["arity"]["words"] = 1

        report = _complete_report(rows, checked_external_sites=[site])

        self.assertEqual(report["status"], "violated")
        blocker = next(
            row for row in report["diagnostics"]["blockers"]
            if row["details"]["code"] == "external_site_contract_corrupt"
        )
        self.assertIn("site_index", blocker["details"])
        self.assertIn("environment:unit:entry:0", {
            item["id"] for item in blocker["frontiers"]["environment"]
        })

    def test_checked_exception_report_binds_exact_fault(self) -> None:
        fault = {
            "kind": "divide_error",
            "instruction_rva": 0x1000,
            "condition": {"op": "false"},
        }
        rows = [_row(faults=[fault])]
        exception_report = {
            "format": EXCEPTION_INVARIANT_CHECK_V2_FORMAT,
            "status": "complete",
            "certificate_sha256": CERTIFICATE_SHA,
            "uses_bounded_paths": False,
            "scc_inventory": {"members": ["unit:entry"]},
            "obligations": [],
            "faults": [{
                "source_unit_id": "unit:entry",
                "fault_index": 0,
                "fault_sha256": exception_sha256(fault),
                "status": "complete",
                "outcome": "checked_infeasible",
                "reason_code": None,
            }],
            "issues": [],
        }

        report = _complete_report(rows, exception_reports=[exception_report])

        self.assertEqual(report["status"], "complete", report["diagnostics"])
        exceptional = [
            row for row in report["authority_bundle"]["records"]
            if row.get("location") == "exceptional_control"
        ]
        self.assertEqual(len(exceptional), 1)
        self.assertEqual(
            exceptional[0]["binding"]["event_sha256"],
            hashlib.sha256(canonical_json_bytes(fault)).hexdigest(),
        )

    def test_cold_replay_contradiction_is_violated(self) -> None:
        rows = [_row()]
        interprocedural = _interprocedural()
        interprocedural["fixed_point"]["cold_replay_signature"] = "9" * 64

        report = _complete_report(rows, interprocedural=interprocedural)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "interprocedural_completion_contradiction",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_unreproduced_call_frame_hypothesis_cannot_authorize_replay(self) -> None:
        rows = [_row()]
        interprocedural = _interprocedural()
        identity = 'call-frame-hypothesis:["unit:entry",0,"edi"]'
        interprocedural["fixed_point"]["inductive_replay"] = {
            "executed": True,
            "converged": True,
            "proof_authority": True,
            "accepted_nodes": [identity],
            "reproduced_ids": [],
        }

        report = _complete_report(rows, interprocedural=interprocedural)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "interprocedural_completion_contradiction",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_interprocedural_output_mutation_is_violated(self) -> None:
        rows = [_row()]
        interprocedural = _interprocedural()
        interprocedural["call_summaries"]["status"] = "complete"

        report = _complete_report(rows, interprocedural=interprocedural)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "interprocedural_completion_contradiction",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_call_site_effect_mutation_invalidates_authority_digest(self) -> None:
        rows = [_row(external_events=[_external_event()])]
        interprocedural = _interprocedural(call_site_effects=[_call_effect()])
        interprocedural["operation_provenance"]["call_site_effects"][0][
            "register_frame"
        ]["preserved_registers"] = ["ebx"]

        report = _complete_report(rows, interprocedural=interprocedural)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "interprocedural_authority_hash_mismatch",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_call_site_effect_requires_exact_machine_event(self) -> None:
        rows = [_row()]
        interprocedural = _interprocedural(call_site_effects=[_call_effect()])

        report = _complete_report(rows, interprocedural=interprocedural)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "interprocedural_call_site_effect_invalid",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_invalid_replay_blocks_call_summary_as_a_dependency(self) -> None:
        event = {
            "kind": "internal_call",
            "instruction_rva": 0x1000,
            "target_rva": 0x1000,
        }
        rows = [_row(external_events=[event])]
        interprocedural = _interprocedural()
        interprocedural["fixed_point"].update({
            "status": "incomplete",
            "cold_replay_validated": False,
            "cold_replay_signature": "9" * 64,
            "failure_reasons": ["summary_dependency_incomplete"],
        })

        report = _complete_report(rows, interprocedural=interprocedural)

        phase = next(
            row for row in report["diagnostics"]["blockers"]
            if row["details"]["code"] == "interprocedural_replay_incomplete"
        )
        consequences = [
            row for row in report["diagnostics"]["blockers"]
            if row["details"]["code"] == "interprocedural_replay_invalid"
        ]
        self.assertTrue(consequences)
        self.assertIn(phase["id"], report["primary_blocker_ids"])
        self.assertTrue(all(
            phase["id"] in row["blocked_by"] for row in consequences
        ))
        self.assertTrue(all(
            row["id"] not in report["primary_blocker_ids"]
            for row in consequences
        ))

    def test_oracle_dispute_is_violated_not_downgraded_to_missing(self) -> None:
        rows = [_row()]
        _qualification, _selection, disputed = _authority(mode="disputed")

        report = _complete_report(rows, isa=disputed)

        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "isa_selection_not_qualified",
            {row["details"]["code"] for row in report["diagnostics"]["blockers"]},
        )

    def test_every_reachable_instruction_requires_an_isa_location_binding(self) -> None:
        row = _row()
        row["instructions"].append({
            "rva_start": 0x1001,
            "rva_end": 0x1002,
            "size": 1,
            "instruction_sha256": "a" * 64,
            "mnemonic": "nop",
            "operands": [],
            "groups": [],
            "registers_read": [],
            "registers_written": [],
        })
        row["source"]["original"]["rva_end"] = 0x1002
        rows = [row]

        report = _complete_report(rows)

        self.assertEqual(report["status"], "violated")
        blocker = next(
            item for item in report["diagnostics"]["blockers"]
            if item["details"]["code"] == "isa_reachable_location_missing"
        )
        self.assertEqual(
            blocker["details"]["locations"],
            [{"rva": 0x1001, "byte_length": 1}],
        )

    def test_content_hash_and_derived_fields_reject_tampering(self) -> None:
        rows = [_row()]
        report = _complete_report(rows)
        corrupted = copy.deepcopy(report)
        corrupted["authorizes_candidate_generation"] = False

        with self.assertRaisesRegex(
            StaticHybridAuthorityV2Error, "content hash"
        ):
            validate_static_hybrid_authority_v2(corrupted)

        rehashed = copy.deepcopy(corrupted)
        body = dict(rehashed)
        body.pop("content_sha256")
        rehashed["content_sha256"] = _sha256(body)
        with self.assertRaisesRegex(
            StaticHybridAuthorityV2Error, "authorization claim"
        ):
            validate_static_hybrid_authority_v2(rehashed)

    def test_candidate_blocker_is_a_dependency_not_a_primary_task(self) -> None:
        rows = [_row()]
        report = build_static_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            behavioral_roots=[{"kind": "pe_entry", "rva": 0x1000}],
            entry_state_analysis=_entry_analysis(rows),
            interprocedural_result=_interprocedural(),
            isa_selection_authority=None,
        )

        candidate = next(
            row for row in report["diagnostics"]["blockers"]
            if row["details"]["code"] == "v2_static_authority_not_closed"
        )
        self.assertNotIn(candidate["id"], report["primary_blocker_ids"])
        self.assertTrue(candidate["blocked_by"])
        self.assertGreater(
            report["diagnostics"]["counts"]["dependent_consequences"], 0
        )


if __name__ == "__main__":
    unittest.main()
