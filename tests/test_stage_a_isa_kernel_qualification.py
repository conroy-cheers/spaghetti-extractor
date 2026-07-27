from __future__ import annotations

import copy
from dataclasses import replace
import unittest

from spaghetti_extractor.isa_conformance import (
    ISA_CONFORMANCE_REPORT_FORMAT,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa_kernel_qualification import (
    BackendBinding,
    BackendRole,
    BinaryFormRequirement,
    BinaryQualificationRequirements,
    CorpusBinding,
    GeneratorBinding,
    ISA_FORM_QUALIFICATION_FORMAT,
    ISA_KERNEL_QUALIFICATION_FORMAT,
    ISA_KERNEL_SELECTION_FORMAT,
    ISA_ORACLE_CONSENSUS_FORMAT,
    ISA_ORACLE_OBSERVATION_FORMAT,
    ISAKernelQualificationError,
    ISAProfileBinding,
    ObservationAvailability,
    OracleSuiteBinding,
    QualificationStatus,
    SemanticKernelBinding,
    SourceLocation,
    artifact_sha256,
    build_form_qualification,
    build_isa_kernel_qualification,
    build_isa_kernel_qualification_from_reports,
    build_oracle_consensus,
    build_oracle_observation,
    canonical_json,
    consensuses_from_conformance_reports,
    observations_from_conformance_report,
    parse_form_qualification,
    parse_kernel_qualification,
    parse_kernel_selection,
    parse_oracle_consensus,
    parse_oracle_observation,
    select_isa_kernel_qualification,
    select_isa_kernel_qualification_from_requirements,
)


SHA0 = "0" * 64
SHA1 = "1" * 64
SHA2 = "2" * 64
SHA3 = "3" * 64
FORM_ID = "lean-x86-form-test"
SEMANTIC_FORM = "formal-default-v1.inc-reg"


def _profile() -> ISAProfileBinding:
    return ISAProfileBinding(
        id="pe32-i686-v1",
        architecture="x86",
        cpu="i686",
        execution_mode="protected-32",
        environment="pe32",
        features=("x87",),
    )


def _kernel() -> SemanticKernelBinding:
    return SemanticKernelBinding(
        id="stage-a-lean-machine-semantics:test",
        decoder_sha256=SHA0,
        semantics_sha256=SHA1,
        lean_version="4.19.0",
    )


def _generator() -> GeneratorBinding:
    return GeneratorBinding(id="generic-operand-corpus", version="1")


def _suite() -> OracleSuiteBinding:
    return OracleSuiteBinding(
        (
            BackendBinding(
                BackendRole.BOCHS,
                "bochs-x86-32-batch-v1",
                "3.0",
            ),
            BackendBinding(
                BackendRole.UNICORN,
                "unicorn-x86-32-batch-v2",
                "2.2.0-i686",
            ),
            BackendBinding(
                BackendRole.LEAN,
                "stage-a-lean-machine-semantics",
                "formal-default-v1",
            ),
        )
    )


def _corpus_binding() -> CorpusBinding:
    return CorpusBinding("corpus:add-eax", SHA2)


def _observation(
    role: BackendRole,
    result: dict | None = None,
    *,
    availability: ObservationAvailability = ObservationAvailability.COMPLETE,
):
    backend = next(row for row in _suite().backends if row.role is role)
    actual_result = (
        None
        if availability is not ObservationAvailability.COMPLETE
        else {"state": {"eax": 2, "eflags": 0x202}}
        if result is None
        else result
    )
    return build_oracle_observation(
        form_id=FORM_ID,
        case_id="case:add-eax",
        profile=_profile(),
        semantic_kernel=_kernel(),
        corpus=_corpus_binding(),
        generator=_generator(),
        backend=backend,
        availability=availability,
        result=actual_result,
        detail=(
            ""
            if availability is ObservationAvailability.COMPLETE
            else "unsupported"
        ),
    )


def _consensus(
    *,
    bochs: dict | None = None,
    unicorn: dict | None = None,
    lean: dict | None = None,
    omit: BackendRole | None = None,
):
    results = {
        BackendRole.BOCHS: bochs,
        BackendRole.UNICORN: unicorn,
        BackendRole.LEAN: lean,
    }
    observations = [
        _observation(role, result)
        for role, result in results.items()
        if role is not omit
    ]
    return build_oracle_consensus(
        form_id=FORM_ID,
        case_id="case:add-eax",
        profile=_profile(),
        semantic_kernel=_kernel(),
        corpus=_corpus_binding(),
        generator=_generator(),
        oracle_suite=_suite(),
        observations=reversed(observations),
    )


def _form(consensuses):
    return build_form_qualification(
        form_id=FORM_ID,
        semantic_form=SEMANTIC_FORM,
        profile=_profile(),
        semantic_kernel=_kernel(),
        generator=_generator(),
        oracle_suite=_suite(),
        corpora=(_corpus_binding(),),
        consensuses=consensuses,
    )


def _qualification(forms):
    return build_isa_kernel_qualification(
        profile=_profile(),
        semantic_kernel=_kernel(),
        generator=_generator(),
        oracle_suite=_suite(),
        corpora=(_corpus_binding(),),
        required_form_ids=tuple(row.form_id for row in forms),
        forms=forms,
    )


def _location(rva: int = 0x1000) -> SourceLocation:
    return SourceLocation(
        image_id="hello.exe",
        image_sha256=SHA3,
        rva=rva,
        byte_length=1,
    )


def _x87(*, mask: bool = False):
    fill = 0xFF if mask else 0
    return {
        "control_word": 0xFFFF if mask else 0x037F,
        "status_word": 0xFFFF if mask else 0,
        "tag_word": 0xFFFF if mask else 0,
        "last_opcode": 0x7FF if mask else 0,
        "instruction_pointer": 0xFFFFFFFF if mask else 0,
        "data_pointer": 0xFFFFFFFF if mask else 0,
        "registers": [[fill] * 10 for _ in range(8)],
    }


def _machine_state(*, eax: int = 2, ecx: int = 3):
    return {
        "gprs": {
            "eax": eax,
            "ebx": 2,
            "ecx": ecx,
            "edx": 4,
            "esi": 5,
            "edi": 6,
            "ebp": 0x70001000,
            "esp": 0x70000FF0,
        },
        "eip": 0x00401001,
        "eflags": 0x202,
        "fs": {"selector": 0x3B, "base": 0x7FFDF000},
        "x87": _x87(),
    }


def _legacy_corpus():
    state = _machine_state(eax=1)
    expected = _machine_state()
    return {
        "format": "stage-a-isa-conformance-corpus-v1",
        "id": "corpus:add-eax",
        "cases": [
            {
                "id": "case:add-eax",
                "instruction_bytes": [0x40],
                "profile": {
                    "architecture": "x86",
                    "cpu": "i686",
                    "execution_mode": "protected-32",
                    "environment": "pe32",
                    "features": ["x87"],
                },
                "image_base": 0x00400000,
                "initial_state": state,
                "memory": [
                    {
                        "address": 0x1000,
                        "bytes": [0x10],
                        "permissions": "rw",
                    }
                ],
                "defined_outputs": {
                    "gprs": {
                        "eax": 0xFFFFFFFF,
                        "ebx": 0xFFFFFFFF,
                        "ecx": 0,
                        "edx": 0xFFFFFFFF,
                        "esi": 0xFFFFFFFF,
                        "edi": 0xFFFFFFFF,
                        "ebp": 0xFFFFFFFF,
                        "esp": 0xFFFFFFFF,
                    },
                    "eip": 0xFFFFFFFF,
                    "eflags": 0x8D5,
                    "fs": {"selector": 0xFFFF, "base": 0xFFFFFFFF},
                    "x87": _x87(mask=True),
                    "memory": [{"address": 0x1000, "mask": [0xFF]}],
                },
                "expected": {
                    "final_state": expected,
                    "memory": [{"address": 0x1000, "bytes": [0x10]}],
                    "control": "fallthrough",
                    "fault": "none",
                },
            }
        ],
    }


def _legacy_report(backend, *, eax: int = 2, ecx: int = 3):
    corpus = parse_isa_conformance_corpus(_legacy_corpus())
    status = "match" if eax == 2 else "mismatch"
    return {
        "format": ISA_CONFORMANCE_REPORT_FORMAT,
        "corpus_id": corpus.id,
        "input_sha256": isa_conformance_corpus_sha256(corpus),
        "backend": backend,
        "qualification": "qualified" if status == "match" else "vetoed",
        "observations": [
            {
                "case_id": "case:add-eax",
                "status": status,
                "final_state": _machine_state(eax=eax, ecx=ecx),
                "memory": [{"address": 0x1000, "bytes": [0x10]}],
                "actual": {"control": "fallthrough", "fault": "none"},
                "detail": "",
            }
        ],
        "counts": {
            "cases": 1,
            "matched": int(status == "match"),
            "mismatched": int(status == "mismatch"),
            "unsupported": 0,
            "errors": 0,
        },
        "trust": {
            "role": "isa_conformance_evidence_only",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }


class StageAISAKernelQualificationTests(unittest.TestCase):
    def test_all_agreement_qualifies_and_round_trips_deterministically(self):
        consensus = _consensus()

        self.assertEqual(consensus.status, QualificationStatus.QUALIFIED)
        self.assertEqual(
            tuple(row.backend.role for row in consensus.observations),
            tuple(BackendRole),
        )
        payload = consensus.to_payload()
        self.assertEqual(payload["format"], ISA_ORACLE_CONSENSUS_FORMAT)
        self.assertEqual(parse_oracle_consensus(payload), consensus)
        self.assertEqual(artifact_sha256(payload), consensus.sha256())
        self.assertEqual(
            canonical_json(payload),
            canonical_json(copy.deepcopy(payload)),
        )
        for observation in consensus.observations:
            self.assertEqual(
                observation.to_payload()["format"],
                ISA_ORACLE_OBSERVATION_FORMAT,
            )
            self.assertEqual(
                parse_oracle_observation(observation.to_payload()),
                observation,
            )
            self.assertFalse(observation.trust.proof_authority)
            self.assertFalse(observation.trust.closes_stage_a_proof)

    def test_agreeing_external_oracles_and_lean_mismatch_veto(self):
        consensus = _consensus(lean={"state": {"eax": 3, "eflags": 0x202}})

        self.assertEqual(consensus.status, QualificationStatus.VETOED)
        self.assertEqual(len(consensus.diagnostics), 1)
        diagnostic = consensus.diagnostics[0]
        self.assertEqual(diagnostic.code, "lean_semantics_mismatch")
        self.assertEqual(diagnostic.json_path, "$.state.eax")
        self.assertEqual(diagnostic.expected, 2)
        self.assertEqual(diagnostic.observed, 3)
        self.assertIn("Lean semantics", diagnostic.message)

    def test_external_disagreement_is_disputed_not_vetoed(self):
        consensus = _consensus(
            unicorn={"state": {"eax": 7, "eflags": 0x202}}
        )

        self.assertEqual(consensus.status, QualificationStatus.DISPUTED)
        self.assertEqual(
            {row.code for row in consensus.diagnostics},
            {"external_oracle_disagreement"},
        )
        self.assertEqual(consensus.diagnostics[0].json_path, "$.state.eax")

    def test_missing_and_unsupported_backends_are_incomplete(self):
        missing = _consensus(omit=BackendRole.LEAN)
        unsupported_rows = [
            _observation(BackendRole.BOCHS),
            _observation(BackendRole.UNICORN),
            _observation(
                BackendRole.LEAN,
                result=None,
                availability=ObservationAvailability.UNSUPPORTED,
            ),
        ]
        unsupported = build_oracle_consensus(
            form_id=FORM_ID,
            case_id="case:add-eax",
            profile=_profile(),
            semantic_kernel=_kernel(),
            corpus=_corpus_binding(),
            generator=_generator(),
            oracle_suite=_suite(),
            observations=unsupported_rows,
        )

        self.assertEqual(missing.status, QualificationStatus.INCOMPLETE)
        self.assertEqual(missing.diagnostics[0].code, "missing_backend")
        self.assertEqual(unsupported.status, QualificationStatus.INCOMPLETE)
        self.assertEqual(unsupported.diagnostics[0].code, "backend_unsupported")

    def test_form_and_kernel_statuses_preserve_strongest_failure(self):
        qualified = _form((_consensus(),))
        disputed_consensus = _consensus(
            unicorn={"state": {"eax": 7, "eflags": 0x202}}
        )
        disputed = _form((disputed_consensus,))

        self.assertEqual(qualified.status, QualificationStatus.QUALIFIED)
        self.assertEqual(disputed.status, QualificationStatus.DISPUTED)
        self.assertEqual(
            parse_form_qualification(disputed.to_payload()), disputed
        )
        self.assertEqual(
            disputed.to_payload()["format"], ISA_FORM_QUALIFICATION_FORMAT
        )

        second = build_form_qualification(
            form_id="lean-x86-form-second",
            semantic_form="formal-default-v1.second",
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
            corpora=(_corpus_binding(),),
            consensuses=(),
        )
        qualification = build_isa_kernel_qualification(
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
            corpora=(_corpus_binding(),),
            required_form_ids=tuple(sorted((FORM_ID, second.form_id))),
            forms=(disputed, second),
        )
        self.assertEqual(qualification.status, QualificationStatus.DISPUTED)
        self.assertEqual(
            qualification.to_payload()["format"],
            ISA_KERNEL_QUALIFICATION_FORMAT,
        )
        self.assertEqual(
            parse_kernel_qualification(qualification.to_payload()),
            qualification,
        )

    def test_selection_is_fail_closed_and_localizes_diagnostics(self):
        vetoed = _form(
            (_consensus(lean={"state": {"eax": 3, "eflags": 0x202}}),)
        )
        qualification = _qualification((vetoed,))
        location = _location()
        selected = select_isa_kernel_qualification(
            binary_id="hello.exe",
            binary_sha256=SHA3,
            requirements=(
                BinaryFormRequirement(FORM_ID, SEMANTIC_FORM, (location,)),
                BinaryFormRequirement(
                    "lean-x86-form-missing",
                    "formal-default-v1.missing",
                    (_location(0x1010),),
                ),
            ),
            qualification=qualification,
        )

        self.assertEqual(selected.status, QualificationStatus.VETOED)
        self.assertEqual(
            selected.to_payload()["format"], ISA_KERNEL_SELECTION_FORMAT
        )
        statuses = {
            row.form_id: row.status for row in selected.selected_forms
        }
        self.assertEqual(statuses[FORM_ID], QualificationStatus.VETOED)
        self.assertEqual(
            statuses["lean-x86-form-missing"],
            QualificationStatus.INCOMPLETE,
        )
        for diagnostic in selected.diagnostics:
            self.assertTrue(diagnostic.source_locations)
        self.assertEqual(
            parse_kernel_selection(selected.to_payload()), selected
        )

    def test_trust_hash_status_and_backend_tampering_fail_closed(self):
        observation = _observation(BackendRole.BOCHS)
        bad_trust = observation.to_payload()
        bad_trust["trust"]["proof_authority"] = True
        bad_hash = observation.to_payload()
        bad_hash["result_sha256"] = SHA0
        consensus = _consensus()
        wrong_status = consensus.to_payload()
        wrong_status["status"] = "vetoed"
        wrong_backend = consensus.to_payload()
        wrong_backend["observations"][0]["backend"]["id"] = "not-bochs"

        for payload, parser in (
            (bad_trust, parse_oracle_observation),
            (bad_hash, parse_oracle_observation),
            (wrong_backend, parse_oracle_consensus),
            (wrong_status, parse_oracle_consensus),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ISAKernelQualificationError):
                    parser(payload)

    def test_report_adapter_ignores_undefined_outputs_in_consensus(self):
        corpus = parse_isa_conformance_corpus(_legacy_corpus())
        reports = (
            _legacy_report(
                {
                    "id": "bochs-x86-32-batch-v1",
                    "kind": "emulator",
                    "version": "3.0",
                },
                ecx=0x11111111,
            ),
            _legacy_report(
                {
                    "id": "unicorn-x86-32-batch-v2",
                    "kind": "emulator",
                    "version": "2.2.0-i686",
                },
                ecx=0x22222222,
            ),
            _legacy_report(
                {
                    "id": "stage-a-lean-machine-semantics",
                    "kind": "semantic_model",
                    "version": "formal-default-v1",
                },
                ecx=0x33333333,
            ),
        )
        observations = observations_from_conformance_report(
            corpus=corpus,
            report=reports[0],
            form_ids_by_case={"case:add-eax": FORM_ID},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
        )
        self.assertEqual(
            observations[0].result["final_state"]["gprs"]["ecx"], 0
        )

        consensuses = consensuses_from_conformance_reports(
            corpus=corpus,
            reports=reports,
            form_ids_by_case={"case:add-eax": FORM_ID},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
        )
        self.assertEqual(
            consensuses[0].status, QualificationStatus.QUALIFIED
        )

    def test_report_triplet_qualifies_matching_raw_mismatch_observations(self):
        corpus = parse_isa_conformance_corpus(_legacy_corpus())
        reports = (
            _legacy_report(
                {
                    "id": "bochs-x86-32-batch-v1",
                    "kind": "emulator",
                    "version": "3.0",
                },
                eax=9,
            ),
            _legacy_report(
                {
                    "id": "unicorn-x86-32-batch-v2",
                    "kind": "emulator",
                    "version": "2.2.0-i686",
                },
                eax=9,
            ),
            _legacy_report(
                {
                    "id": "stage-a-lean-machine-semantics",
                    "kind": "semantic_model",
                    "version": "formal-default-v1",
                },
                eax=9,
            ),
        )

        qualification = build_isa_kernel_qualification_from_reports(
            corpus=corpus,
            reports=reports,
            form_ids_by_case={"case:add-eax": FORM_ID},
            semantic_forms_by_id={FORM_ID: SEMANTIC_FORM},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
        )

        self.assertEqual(
            qualification.status, QualificationStatus.QUALIFIED
        )
        self.assertEqual(
            qualification.forms[0].consensuses[0].observations[0]
            .availability,
            ObservationAvailability.COMPLETE,
        )

    def test_backend_identity_is_independent_of_exact_cpu_profile(self):
        corpus = parse_isa_conformance_corpus(_legacy_corpus())
        generic_suite = OracleSuiteBinding(
            (
                _suite().backends[0],
                BackendBinding(
                    BackendRole.UNICORN,
                    "unicorn-x86-32-batch-v3",
                    "3.0.0-i686",
                ),
                _suite().backends[2],
            )
        )
        reports = (
            _legacy_report(
                {
                    "id": "bochs-x86-32-batch-v1",
                    "kind": "emulator",
                    "version": "3.0",
                }
            ),
            _legacy_report(
                {
                    "id": "unicorn-x86-32-batch-v3",
                    "kind": "emulator",
                    "version": "3.0.0-i686",
                }
            ),
            _legacy_report(
                {
                    "id": "stage-a-lean-machine-semantics",
                    "kind": "semantic_model",
                    "version": "formal-default-v1",
                }
            ),
        )

        qualification = build_isa_kernel_qualification_from_reports(
            corpus=corpus,
            reports=reports,
            form_ids_by_case={"case:add-eax": FORM_ID},
            semantic_forms_by_id={FORM_ID: SEMANTIC_FORM},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=generic_suite,
        )
        self.assertEqual(
            qualification.status, QualificationStatus.QUALIFIED
        )

        with self.assertRaisesRegex(
            ISAKernelQualificationError, "profile does not match"
        ):
            observations_from_conformance_report(
                corpus=corpus,
                report=reports[0],
                form_ids_by_case={"case:add-eax": FORM_ID},
                profile=replace(_profile(), cpu="pentium-ii"),
                semantic_kernel=_kernel(),
                generator=_generator(),
                oracle_suite=generic_suite,
            )

    def test_missing_actual_state_from_report_is_incomplete(self):
        corpus_payload = _legacy_corpus()
        case = corpus_payload["cases"][0]
        case["instruction_bytes"] = [0xCC]
        case["defined_outputs"] = {
            "gprs": {register: 0 for register in _machine_state()["gprs"]},
            "eip": 0,
            "eflags": 0,
            "fs": {"selector": 0, "base": 0},
            "x87": {
                "control_word": 0,
                "status_word": 0,
                "tag_word": 0,
                "last_opcode": 0,
                "instruction_pointer": 0,
                "data_pointer": 0,
                "registers": [[0] * 10 for _ in range(8)],
            },
            "memory": [],
        }
        case["expected"] = {
            "final_state": None,
            "memory": None,
            "control": "fault",
            "fault": "breakpoint",
        }
        corpus = parse_isa_conformance_corpus(corpus_payload)
        report = {
            "format": ISA_CONFORMANCE_REPORT_FORMAT,
            "corpus_id": corpus.id,
            "input_sha256": isa_conformance_corpus_sha256(corpus),
            "backend": {
                "id": "bochs-x86-32-batch-v1",
                "kind": "emulator",
                "version": "3.0",
            },
            "qualification": "qualified",
            "observations": [
                {
                    "case_id": "case:add-eax",
                    "status": "match",
                    "final_state": None,
                    "memory": None,
                    "actual": {"control": "fault", "fault": "breakpoint"},
                    "detail": "",
                }
            ],
            "counts": {
                "cases": 1,
                "matched": 1,
                "mismatched": 0,
                "unsupported": 0,
                "errors": 0,
            },
            "trust": {
                "role": "isa_conformance_evidence_only",
                "proof_authority": False,
                "closes_stage_a_proof": False,
            },
        }

        observations = observations_from_conformance_report(
            corpus=corpus,
            report=report,
            form_ids_by_case={"case:add-eax": FORM_ID},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
        )
        self.assertEqual(
            observations[0].availability,
            ObservationAvailability.INCOMPLETE,
        )
        self.assertIsNone(observations[0].result)

    def test_versioned_requirements_adapter_selects_qualification(self):
        qualification = _qualification((_form((_consensus(),)),))
        requirements = BinaryQualificationRequirements(
            binary_id="hello.exe",
            binary_sha256=SHA3,
            profile_id=_profile().id,
            semantic_kernel_id=_kernel().id,
            forms=(
                BinaryFormRequirement(
                    FORM_ID, SEMANTIC_FORM, (_location(),)
                ),
            ),
        )

        selection = select_isa_kernel_qualification_from_requirements(
            requirements=requirements.to_payload(),
            qualification=qualification.to_payload(),
        )

        self.assertEqual(selection.status, QualificationStatus.QUALIFIED)
        self.assertEqual(selection.required_form_ids, (FORM_ID,))
        self.assertEqual(
            selection.kernel_qualification_sha256,
            qualification.sha256(),
        )


if __name__ == "__main__":
    unittest.main()
