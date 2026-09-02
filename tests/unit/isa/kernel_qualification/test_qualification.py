from __future__ import annotations

from tests.unit.isa.kernel_qualification._support import *


class ISAKernelQualificationTests(unittest.TestCase):
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

    def test_unicorn_x87_exception_flags_use_pairwise_capability(self):
        def result(status_word: int):
            return {
                "control": "fallthrough",
                "fault": "none",
                "final_state": {"x87": {"status_word": status_word}},
                "memory": [],
            }

        consensus = _consensus(
            bochs=result(0x0001),
            unicorn=result(0x0000),
            lean=result(0x0001),
        )
        self.assertEqual(consensus.status, QualificationStatus.QUALIFIED)

        lean_mismatch = _consensus(
            bochs=result(0x0001),
            unicorn=result(0x0000),
            lean=result(0x0002),
        )
        self.assertEqual(lean_mismatch.status, QualificationStatus.VETOED)
        self.assertEqual(
            lean_mismatch.diagnostics[0].json_path,
            "$.final_state.x87.status_word",
        )

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

    def test_unsupported_oracle_preserves_complete_structural_coverage(self):
        observations = [
            _observation(BackendRole.BOCHS),
            _observation(BackendRole.UNICORN),
            _observation(
                BackendRole.LEAN,
                result=None,
                availability=ObservationAvailability.UNSUPPORTED,
            ),
        ]
        form = _form(
            (
                build_oracle_consensus(
                    form_id=FORM_ID,
                    case_id="case:add-eax",
                    profile=_profile(),
                    semantic_kernel=_kernel(),
                    corpus=_corpus_binding(),
                    generator=_generator(),
                    oracle_suite=_suite(),
                    observations=observations,
                ),
            )
        )
        qualification = _qualification((form,))
        payload = qualification.to_payload()
        selection = select_isa_kernel_qualification(
            binary_id="hello.exe",
            binary_sha256=SHA3,
            requirements=(
                BinaryFormRequirement(
                    FORM_ID, SEMANTIC_FORM, (_location(),)
                ),
            ),
            qualification=qualification,
        )
        selection_payload = selection.to_payload()

        self.assertEqual(
            form.structural_status, StructuralCoverageStatus.COMPLETE
        )
        self.assertEqual(
            form.concrete_oracle_status, QualificationStatus.INCOMPLETE
        )
        self.assertEqual(
            qualification.structural_status,
            StructuralCoverageStatus.COMPLETE,
        )
        self.assertEqual(
            qualification.concrete_oracle_status,
            QualificationStatus.INCOMPLETE,
        )
        self.assertEqual(qualification.status, QualificationStatus.INCOMPLETE)
        self.assertEqual(
            payload["qualification_layers"]["structural"],
            {
                "status": "complete",
                "counts": {
                    "required_forms": 1,
                    "complete": 1,
                    "incomplete": 0,
                },
                "diagnostics": [],
            },
        )
        oracle_layer = payload["qualification_layers"]["concrete_oracle"]
        self.assertEqual(oracle_layer["status"], "incomplete")
        self.assertEqual(oracle_layer["counts"]["incomplete"], 1)
        self.assertEqual(
            {row["code"] for row in oracle_layer["diagnostics"]},
            {"backend_unsupported"},
        )
        self.assertEqual(
            selection_payload["qualification_layers"]["structural"]["status"],
            "complete",
        )
        selection_oracle = selection_payload["qualification_layers"][
            "concrete_oracle"
        ]
        self.assertEqual(selection_oracle["status"], "incomplete")
        self.assertEqual(
            selection_oracle["diagnostics"][0]["source_locations"][0]["rva"],
            0x1000,
        )

    def test_oracle_mismatch_still_vetoes_a_structurally_complete_form(self):
        form = _form(
            (_consensus(lean={"state": {"eax": 3, "eflags": 0x202}}),)
        )
        qualification = _qualification((form,))

        self.assertEqual(
            qualification.structural_status,
            StructuralCoverageStatus.COMPLETE,
        )
        self.assertEqual(
            qualification.concrete_oracle_status,
            QualificationStatus.VETOED,
        )
        self.assertEqual(qualification.status, QualificationStatus.VETOED)
        self.assertEqual(
            qualification.to_payload()["qualification_layers"]
            ["concrete_oracle"]["diagnostics"][0]["code"],
            "lean_semantics_mismatch",
        )

    def test_layer_metadata_tampering_fails_closed(self):
        payload = _qualification((_form((_consensus(),)),)).to_payload()
        payload["qualification_layers"]["structural"]["status"] = "incomplete"

        with self.assertRaisesRegex(
            ISAKernelQualificationError, "qualification_layers"
        ):
            parse_kernel_qualification(payload)

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
                    "id": "spaghetti-extractor-lean-machine-semantics",
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

    def test_report_adapter_applies_lean_x87_definedness_to_every_oracle(self):
        corpus = parse_isa_conformance_corpus(_legacy_corpus())
        reports = (
            _legacy_report(
                {
                    "id": "bochs-x86-32-batch-v1",
                    "kind": "emulator",
                    "version": "3.0",
                },
                x87_status_word=0x4000,
            ),
            _legacy_report(
                {
                    "id": "unicorn-x86-32-batch-v2",
                    "kind": "emulator",
                    "version": "2.2.0-i686",
                },
                x87_status_word=0x0000,
            ),
            _legacy_report(
                {
                    "id": "spaghetti-extractor-lean-machine-semantics",
                    "kind": "semantic_model",
                    "version": "formal-default-v1",
                },
                x87_status_word=0x0000,
            ),
        )
        undefined_status = X87Mask(
            control_word=0xFFFF,
            status_word=0,
            tag_word=0xFFFF,
            last_opcode=0x7FF,
            instruction_pointer=0xFFFFFFFF,
            data_pointer=0xFFFFFFFF,
            registers=tuple(bytes([0xFF] * 10) for _ in range(8)),
        )
        defined_status = replace(undefined_status, status_word=0xFFFF)

        ignored = consensuses_from_conformance_reports(
            corpus=corpus,
            reports=reports,
            form_ids_by_case={"case:add-eax": FORM_ID},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
            x87_definedness_by_case={
                "case:add-eax": undefined_status,
            },
        )
        compared = consensuses_from_conformance_reports(
            corpus=corpus,
            reports=reports,
            form_ids_by_case={"case:add-eax": FORM_ID},
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
            x87_definedness_by_case={
                "case:add-eax": defined_status,
            },
        )

        self.assertEqual(ignored[0].status, QualificationStatus.QUALIFIED)
        self.assertEqual(compared[0].status, QualificationStatus.DISPUTED)
        self.assertEqual(
            compared[0].diagnostics[0].json_path,
            "$.final_state.x87.status_word",
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
                    "id": "spaghetti-extractor-lean-machine-semantics",
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
                    "id": "spaghetti-extractor-lean-machine-semantics",
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

    def test_div_and_idiv_faults_without_machine_state_qualify(self):
        for mnemonic, instruction_bytes in (
            ("div", [0xF7, 0xF1]),
            ("idiv", [0xF7, 0xF9]),
        ):
            with self.subTest(mnemonic=mnemonic):
                corpus = _fault_corpus(instruction_bytes)
                qualification = build_isa_kernel_qualification_from_reports(
                    corpus=corpus,
                    reports=tuple(
                        _fault_report(corpus, role) for role in BackendRole
                    ),
                    form_ids_by_case={"case:add-eax": FORM_ID},
                    semantic_forms_by_id={FORM_ID: SEMANTIC_FORM},
                    profile=_profile(),
                    semantic_kernel=_kernel(),
                    generator=_generator(),
                    oracle_suite=_suite(),
                )
                consensus = qualification.forms[0].consensuses[0]

                self.assertEqual(
                    qualification.status, QualificationStatus.QUALIFIED
                )
                self.assertEqual(
                    qualification.structural_status,
                    StructuralCoverageStatus.COMPLETE,
                )
                self.assertEqual(
                    qualification.concrete_oracle_status,
                    QualificationStatus.QUALIFIED,
                )
                for observation in consensus.observations:
                    self.assertEqual(
                        observation.availability,
                        ObservationAvailability.COMPLETE,
                    )
                    self.assertEqual(
                        observation.result,
                        {
                            "control": "fault",
                            "fault": "divide_error",
                            "final_state": None,
                            "memory": None,
                        },
                    )

    def test_undefined_fault_state_capture_does_not_create_a_dispute(self):
        corpus = _fault_corpus([0xF7, 0xF1])
        reports = tuple(
            _fault_report(
                corpus,
                role,
                capture_state=role is BackendRole.BOCHS,
            )
            for role in BackendRole
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
        consensus = qualification.forms[0].consensuses[0]

        self.assertEqual(qualification.status, QualificationStatus.QUALIFIED)
        self.assertTrue(
            all(
                row.result
                == {
                    "control": "fault",
                    "fault": "divide_error",
                    "final_state": None,
                    "memory": None,
                }
                for row in consensus.observations
            )
        )

    def test_divide_fault_disagreement_remains_a_veto(self):
        corpus = _fault_corpus([0xF7, 0xF9])
        reports = (
            _fault_report(corpus, BackendRole.BOCHS),
            _fault_report(corpus, BackendRole.UNICORN),
            _fault_report(corpus, BackendRole.LEAN, fault="breakpoint"),
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
        consensus = qualification.forms[0].consensuses[0]

        self.assertEqual(qualification.status, QualificationStatus.VETOED)
        self.assertEqual(
            qualification.structural_status,
            StructuralCoverageStatus.COMPLETE,
        )
        self.assertEqual(
            qualification.concrete_oracle_status,
            QualificationStatus.VETOED,
        )
        self.assertTrue(
            all(
                row.availability is ObservationAvailability.COMPLETE
                for row in consensus.observations
            )
        )
        self.assertEqual(consensus.diagnostics[0].code, "lean_semantics_mismatch")
        self.assertEqual(consensus.diagnostics[0].json_path, "$.fault")

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
