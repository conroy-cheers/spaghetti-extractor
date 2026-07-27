from __future__ import annotations

import copy
from dataclasses import replace
import json
import unittest

from spaghetti_extractor.isa_campaign import (
    CampaignNextAction,
    CampaignPriority,
    CampaignQualificationStatus,
    CampaignReasonCode,
    ISAQualificationCampaignError,
    build_isa_qualification_campaign,
    parse_isa_qualification_campaign,
)
from spaghetti_extractor.isa_catalog import (
    DispositionReason,
    ProfileDisposition,
    parse_xed_instruction_catalog,
)
from spaghetti_extractor.isa_conformance_unicorn import UNICORN_BACKEND_ID
from spaghetti_extractor.isa_kernel_qualification import (
    BackendBinding,
    BackendRole,
    BinaryFormRequirement,
    CorpusBinding,
    GeneratorBinding,
    ISAProfileBinding,
    ObservationAvailability,
    OracleSuiteBinding,
    SemanticKernelBinding,
    SourceLocation,
    build_form_qualification,
    build_isa_kernel_qualification,
    build_oracle_consensus,
    build_oracle_observation,
    select_isa_kernel_qualification,
)


SHA0 = "0" * 64
SHA1 = "1" * 64
SHA2 = "2" * 64
SHA3 = "3" * 64


def _operand(**changes) -> dict:
    result = {
        "name": "REG0",
        "visibility": "EXPLICIT",
        "action": "RW",
        "width": "D",
        "xtype": "INT",
        "type": "NT_LOOKUP_FN",
        "nonterminal": "GPRV_R",
        "register": "",
        "immediate": None,
    }
    result.update(changes)
    return result


def _template(table_index: int, **changes) -> dict:
    result = {
        "table_index": table_index,
        "iform": f"OPAQUE_FORM_{table_index}",
        "iclass": f"OPAQUE_CLASS_{table_index}",
        "category": "BINARY",
        "extension": "BASE",
        "isa_set": "I86",
        "cpl": 3,
        "exception": "INVALID",
        "flag_info_index": table_index,
        "flag_complex": False,
        "attributes": [],
        "operands": [_operand()],
    }
    result.update(changes)
    return result


def _catalog():
    payload = {
        "format": "spaghetti-extractor-xed-inst-catalog-v1",
        "generator": {
            "name": "xed-isa-catalog",
            "xed_version": "2025.06.08",
        },
        "profile": {
            "id": "pe32-i686-v1",
            "chip": "PENTIUMPRO",
            "machine_mode": "LEGACY_32",
            "stack_address_width": 32,
            "privilege": "ring3",
        },
        "templates": [
            _template(1, category="BINARY"),
            _template(2, category="LOGICAL"),
            _template(3, category="DATAXFER"),
            _template(
                4,
                category="X87_ALU",
                isa_set="X87",
                operands=[_operand(xtype="X87")],
            ),
            _template(5, category="SYSCALL"),
            _template(6, category="SYSTEM"),
        ],
    }
    return parse_xed_instruction_catalog(payload)


def _by_table_index(catalog) -> dict[int, object]:
    return {row.table_index: row for row in catalog.templates}


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
                UNICORN_BACKEND_ID,
                "2.1.4",
            ),
            BackendBinding(
                BackendRole.LEAN,
                "stage-a-lean-machine-semantics",
                "formal-default-v1",
            ),
        )
    )


def _corpus() -> CorpusBinding:
    return CorpusBinding("campaign-corpus", SHA2)


def _qualified_consensus(form_id: str):
    observations = []
    for backend in _suite().backends:
        observations.append(
            build_oracle_observation(
                form_id=form_id,
                case_id=f"case:{form_id}",
                profile=_profile(),
                semantic_kernel=_kernel(),
                corpus=_corpus(),
                generator=_generator(),
                backend=backend,
                availability=ObservationAvailability.COMPLETE,
                result={"state": {"value": 1}},
                detail="",
            )
        )
    return build_oracle_consensus(
        form_id=form_id,
        case_id=f"case:{form_id}",
        profile=_profile(),
        semantic_kernel=_kernel(),
        corpus=_corpus(),
        generator=_generator(),
        oracle_suite=_suite(),
        observations=reversed(observations),
    )


def _form(form_id: str, semantic_form: str, *, qualified: bool):
    return build_form_qualification(
        form_id=form_id,
        semantic_form=semantic_form,
        profile=_profile(),
        semantic_kernel=_kernel(),
        generator=_generator(),
        oracle_suite=_suite(),
        corpora=(_corpus(),),
        consensuses=(
            (_qualified_consensus(form_id),) if qualified else ()
        ),
    )


def _qualification_and_selection(catalog):
    forms = _by_table_index(catalog)
    selected_form = _form(
        forms[1].form_id,
        "formal-default-v1.required-exact",
        qualified=False,
    )
    qualified_core = _form(
        forms[3].form_id,
        "formal-default-v1.qualified-core",
        qualified=True,
    )
    qualified_external = _form(
        forms[5].form_id,
        "formal-default-v1.external-event",
        qualified=True,
    )
    form_rows = tuple(
        sorted(
            (selected_form, qualified_core, qualified_external),
            key=lambda row: row.form_id,
        )
    )
    qualification = build_isa_kernel_qualification(
        profile=_profile(),
        semantic_kernel=_kernel(),
        generator=_generator(),
        oracle_suite=_suite(),
        corpora=(_corpus(),),
        required_form_ids=tuple(row.form_id for row in form_rows),
        forms=form_rows,
    )
    location = SourceLocation(
        image_id="selected.exe",
        image_sha256=SHA3,
        rva=0x1000,
        byte_length=1,
    )
    selection = select_isa_kernel_qualification(
        binary_id="selected.exe",
        binary_sha256=SHA3,
        requirements=(
            BinaryFormRequirement(
                selected_form.form_id,
                selected_form.semantic_form,
                (location,),
            ),
        ),
        qualification=qualification,
    )
    return qualification, selection


class StageAISAQualificationCampaignTests(unittest.TestCase):
    def test_ambiguous_special_state_reason_round_trips(self):
        catalog = parse_xed_instruction_catalog({
            "format": "spaghetti-extractor-xed-inst-catalog-v1",
            "generator": {
                "name": "xed-isa-catalog",
                "xed_version": "2025.06.08",
            },
            "profile": {
                "id": "pe32-i686-v1",
                "chip": "PENTIUMPRO",
                "machine_mode": "LEGACY_32",
                "stack_address_width": 32,
                "privilege": "ring3",
            },
            "templates": [_template(7, category="MISC")],
        })
        campaign = build_isa_qualification_campaign(catalog=catalog)
        reparsed = parse_isa_qualification_campaign(campaign.to_payload())

        self.assertEqual(reparsed, campaign)
        self.assertEqual(
            campaign.coverage[0].disposition_reasons,
            (DispositionReason.AMBIGUOUS_SPECIAL_STATE_CATEGORY,),
        )

    def test_campaign_counts_every_catalog_form_and_ranks_next_work(self):
        catalog = _catalog()
        forms = _by_table_index(catalog)
        qualification, selection = _qualification_and_selection(catalog)

        campaign = build_isa_qualification_campaign(
            catalog=catalog,
            qualification=qualification,
            selection=selection,
        )
        by_form = {row.form_id: row for row in campaign.coverage}

        self.assertEqual(
            [row.rank for row in campaign.ranked_next_work],
            [1, 2, 3],
        )
        self.assertEqual(
            [row.priority for row in campaign.ranked_next_work],
            [
                CampaignPriority.REQUIRED_EXACT_SEMANTIC_FORM,
                CampaignPriority.CORE_FORM,
                CampaignPriority.SEPARATELY_QUALIFIED_FORM,
            ],
        )
        required = campaign.ranked_next_work[0]
        self.assertEqual(required.form_id, forms[1].form_id)
        self.assertEqual(
            required.semantic_form, "formal-default-v1.required-exact"
        )
        self.assertEqual(
            required.next_action,
            CampaignNextAction.QUALIFY_EXACT_LEAN_SEMANTIC_FORM,
        )
        self.assertIn(
            CampaignReasonCode.REQUIRED_EXACT_SEMANTIC_FORM,
            required.reason_codes,
        )

        self.assertEqual(campaign.counts["forms"], 6)
        self.assertEqual(campaign.counts["qualified"], 1)
        self.assertEqual(campaign.counts["frontier"], 5)
        self.assertEqual(campaign.counts["ranked_next_work"], 3)
        self.assertEqual(campaign.counts["visibility_only"], 2)
        self.assertEqual(
            campaign.counts["by_profile_disposition"]["core"],
            {"forms": 3, "qualified": 1, "frontier": 2},
        )
        self.assertEqual(
            campaign.counts["by_category"]["SYSCALL"],
            {"forms": 1, "qualified": 0, "frontier": 1},
        )
        self.assertEqual(
            campaign.counts["by_isa_set"]["X87"],
            {"forms": 1, "qualified": 0, "frontier": 1},
        )
        self.assertEqual(
            campaign.counts["by_qualification_status"],
            {
                "qualified": 1,
                "unqualified": 2,
                "incomplete": 1,
                "disputed": 0,
                "vetoed": 0,
                "not_applicable": 2,
            },
        )

        external = by_form[forms[5].form_id]
        self.assertEqual(
            external.evidence_status.value,
            "qualified",
        )
        self.assertEqual(
            external.qualification_status,
            CampaignQualificationStatus.NOT_APPLICABLE,
        )
        self.assertFalse(external.counts_as_qualified)
        self.assertEqual(
            by_form[forms[6].form_id].disposition,
            ProfileDisposition.EXCLUDED_UNSUPPORTED,
        )
        self.assertEqual(
            {row.priority for row in campaign.visibility_only},
            {CampaignPriority.VISIBILITY_ONLY},
        )

    def test_plan_round_trips_hashes_and_accepts_serialized_evidence(self):
        catalog = _catalog()
        qualification, selection = _qualification_and_selection(catalog)
        first = build_isa_qualification_campaign(
            catalog=catalog,
            qualification=qualification,
            selection=selection,
        )
        second = build_isa_qualification_campaign(
            catalog=catalog,
            qualification=qualification.to_payload(),
            selection=selection.to_payload(),
        )

        self.assertEqual(first, second)
        self.assertEqual(first.to_payload(), second.to_payload())
        self.assertEqual(
            parse_isa_qualification_campaign(first.to_payload()), first
        )
        self.assertEqual(first.sha256(), second.sha256())
        self.assertFalse(first.trust.proof_authority)
        self.assertFalse(first.trust.closes_stage_a_proof)

    def test_no_evidence_is_visible_as_unqualified_or_not_applicable(self):
        campaign = build_isa_qualification_campaign(catalog=_catalog())

        self.assertEqual(campaign.counts["qualified"], 0)
        self.assertEqual(campaign.counts["ranked_next_work"], 4)
        self.assertEqual(campaign.counts["visibility_only"], 2)
        self.assertTrue(
            all(
                row.qualification_status
                is CampaignQualificationStatus.UNQUALIFIED
                for row in campaign.coverage
                if row.disposition
                in {
                    ProfileDisposition.CORE,
                    ProfileDisposition.SEPARATELY_QUALIFIED,
                }
            )
        )
        self.assertIsNone(campaign.evidence.kernel_qualification_sha256)
        self.assertIsNone(campaign.evidence.semantic_kernel)

    def test_checked_crosswalk_relates_xed_and_lean_form_id_domains(self):
        catalog = _catalog()
        xed_form = _by_table_index(catalog)[1]
        lean_form = _form(
            "lean-x86-form-fixture",
            "formal-default-v1.movRegImm",
            qualified=True,
        )
        qualification = build_isa_kernel_qualification(
            profile=_profile(),
            semantic_kernel=_kernel(),
            generator=_generator(),
            oracle_suite=_suite(),
            corpora=(_corpus(),),
            required_form_ids=(lean_form.form_id,),
            forms=(lean_form,),
        )

        campaign = build_isa_qualification_campaign(
            catalog=catalog,
            qualification=qualification,
            catalog_form_to_qualification_form={
                xed_form.form_id: lean_form.form_id
            },
        )

        coverage = {
            row.form_id: row for row in campaign.coverage
        }[xed_form.form_id]
        self.assertTrue(coverage.counts_as_qualified)
        self.assertEqual(
            coverage.semantic_form,
            "formal-default-v1.movRegImm",
        )

    def test_tampering_and_incompatible_artifact_joins_fail_closed(self):
        catalog = _catalog()
        qualification, selection = _qualification_and_selection(catalog)
        campaign = build_isa_qualification_campaign(
            catalog=catalog,
            qualification=qualification,
            selection=selection,
        )

        authority = copy.deepcopy(campaign.to_payload())
        authority["trust"]["proof_authority"] = True
        counts = copy.deepcopy(campaign.to_payload())
        counts["counts"]["qualified"] += 1
        rank = copy.deepcopy(campaign.to_payload())
        rank["frontier"][0]["rank"] = 2
        external = copy.deepcopy(campaign.to_payload())
        external_row = next(
            row
            for row in external["coverage"]
            if row["profile_disposition"] == "external_platform"
        )
        external_row["qualification_status"] = "qualified"
        external_row["counts_as_qualified"] = True
        stray_evidence = copy.deepcopy(campaign.to_payload())
        unqualified_row = next(
            row
            for row in stray_evidence["coverage"]
            if row["qualification_status"] == "unqualified"
        )
        unqualified_row["evidence_qualification_sha256"] = "a" * 64

        for payload in (authority, counts, rank, external, stray_evidence):
            with self.subTest(payload=payload):
                with self.assertRaises(ISAQualificationCampaignError):
                    parse_isa_qualification_campaign(payload)

        wrong_selection = replace(
            selection,
            kernel_qualification_sha256="f" * 64,
        )
        with self.assertRaisesRegex(
            ISAQualificationCampaignError,
            "does not bind",
        ):
            build_isa_qualification_campaign(
                catalog=catalog,
                qualification=qualification,
                selection=wrong_selection,
            )

    def test_output_and_dispatch_are_semantic_name_agnostic(self):
        catalog = _catalog()
        campaign = build_isa_qualification_campaign(catalog=catalog)
        encoded = json.dumps(campaign.to_payload(), sort_keys=True)

        self.assertNotIn("OPAQUE_FORM", encoded)
        self.assertNotIn("OPAQUE_CLASS", encoded)
        self.assertNotIn("iform", encoded)
        self.assertNotIn("iclass", encoded)
        core = [
            row
            for row in campaign.ranked_next_work
            if row.priority is CampaignPriority.CORE_FORM
        ]
        self.assertEqual(len(core), 3)
        self.assertTrue(
            all(
                row.next_action
                is CampaignNextAction.IMPLEMENT_AND_QUALIFY_CORE_FORM
                for row in core
            )
        )


if __name__ == "__main__":
    unittest.main()
