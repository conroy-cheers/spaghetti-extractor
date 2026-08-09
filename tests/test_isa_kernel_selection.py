from __future__ import annotations

import copy
import unittest

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
from spaghetti_extractor.isa_kernel_selection import (
    ISA_KERNEL_SELECTION_AUTHORITY_FORMAT,
    ISAKernelSelectionAuthorityError,
    SelectionAuthorityStatus,
    build_isa_kernel_selection_authority,
    parse_isa_kernel_selection_authority,
    validate_isa_kernel_selection_authority,
)
from spaghetti_extractor.isa_semantic_forms import lean_semantic_form_id
from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
    MACHINE_IR_FALLBACK_CAPABILITY_V2,
)
from spaghetti_extractor.machine_ir_isa_selection_v2 import (
    MachineIRISASelectionV2Error,
    build_machine_ir_isa_selection_certificate_v2,
    build_machine_ir_isa_selection_authority_v2,
    parse_machine_ir_isa_selection_certificate_v2,
)


SHA0 = "0" * 64
SHA1 = "1" * 64
SHA2 = "2" * 64
BINARY_SHA = "3" * 64
OTHER_BINARY_SHA = "4" * 64
SEMANTIC_FORM = "formal-default-v1.inc-reg"
CLASSIFIER_SHA = "9" * 64
FORM_ID = lean_semantic_form_id(
    SEMANTIC_FORM, classifier_sha256=CLASSIFIER_SHA
)
FALLBACK_ID = MACHINE_IR_FALLBACK_CAPABILITY_V2


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
    return OracleSuiteBinding((
        BackendBinding(BackendRole.BOCHS, "bochs-v1", "3.0"),
        BackendBinding(BackendRole.UNICORN, "unicorn-v1", "2.2.0"),
        BackendBinding(BackendRole.LEAN, "lean-v1", "4.19.0"),
    ))


def _corpus() -> CorpusBinding:
    return CorpusBinding(id="corpus:inc-eax", sha256=SHA2)


def _result(eax: int = 2) -> dict:
    return {"state": {"eax": eax, "eflags": 0x202}}


def _qualification(
    *,
    mode: str = "qualified",
    form_id: str = FORM_ID,
    semantic_form: str = SEMANTIC_FORM,
):
    observations = []
    for backend in _suite().backends:
        availability = ObservationAvailability.COMPLETE
        result = _result()
        detail = ""
        if mode == "unsupported" and backend.role is BackendRole.UNICORN:
            availability = ObservationAvailability.UNSUPPORTED
            result = None
            detail = "instruction is unsupported"
        elif mode == "disputed" and backend.role is BackendRole.UNICORN:
            result = _result(7)
        observations.append(build_oracle_observation(
            form_id=form_id,
            case_id="case:inc-eax",
            profile=_profile(),
            semantic_kernel=_kernel(),
            corpus=_corpus(),
            generator=_generator(),
            backend=backend,
            availability=availability,
            result=result,
            detail=detail,
        ))
    consensus = build_oracle_consensus(
        form_id=form_id,
        case_id="case:inc-eax",
        profile=_profile(),
        semantic_kernel=_kernel(),
        corpus=_corpus(),
        generator=_generator(),
        oracle_suite=_suite(),
        observations=observations,
    )
    form = build_form_qualification(
        form_id=form_id,
        semantic_form=semantic_form,
        profile=_profile(),
        semantic_kernel=_kernel(),
        generator=_generator(),
        oracle_suite=_suite(),
        corpora=(_corpus(),),
        consensuses=(consensus,),
    )
    return build_isa_kernel_qualification(
        profile=_profile(),
        semantic_kernel=_kernel(),
        generator=_generator(),
        oracle_suite=_suite(),
        corpora=(_corpus(),),
        required_form_ids=(form_id,),
        forms=(form,),
    )


def _requirement(
    *, binary_sha256: str = BINARY_SHA, rva: int = 0x1000
) -> BinaryFormRequirement:
    return BinaryFormRequirement(
        form_id=FORM_ID,
        semantic_form=SEMANTIC_FORM,
        source_locations=(SourceLocation(
            image_id="original",
            image_sha256=binary_sha256,
            rva=rva,
            byte_length=1,
        ),),
    )


def _selection(
    qualification,
    *,
    binary_sha256: str = BINARY_SHA,
    rva: int = 0x1000,
):
    return select_isa_kernel_qualification(
        binary_id="game.exe",
        binary_sha256=binary_sha256,
        requirements=(_requirement(binary_sha256=binary_sha256, rva=rva),),
        qualification=qualification,
    )


def _authority(*, mode: str = "qualified"):
    qualification = _qualification(mode=mode)
    selection = _selection(qualification)
    authority = build_isa_kernel_selection_authority(
        binary_id="game.exe",
        binary_sha256=BINARY_SHA,
        reachable_forms=(_requirement(),),
        qualification=qualification,
        selection=selection,
        fallback_capability_ids={FORM_ID: FALLBACK_ID},
    )
    return qualification, selection, authority


class ISAKernelSelectionAuthorityTests(unittest.TestCase):
    def test_machine_ir_bridge_localizes_generic_qualification(self) -> None:
        from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
            build_machine_ir_isa_extraction_request_v2,
            build_machine_ir_isa_requirements_v2,
        )
        from spaghetti_extractor.isa_semantic_forms import (
            lean_semantic_form_classifier_sha256,
        )

        classifier = lean_semantic_form_classifier_sha256()
        semantic_form = SEMANTIC_FORM
        form_id = lean_semantic_form_id(
            semantic_form, classifier_sha256=classifier
        )
        qualification = _qualification(
            form_id=form_id,
            semantic_form=semantic_form,
        )
        unit = {
            "id": "unit-1000",
            "reachable": True,
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1001}},
            "instructions": [{"rva_start": 0x1000, "rva_end": 0x1001}],
        }
        request = build_machine_ir_isa_extraction_request_v2(
            units=[unit], binary_sha256=BINARY_SHA
        )
        requirements = build_machine_ir_isa_requirements_v2(
            request=request,
            machine_ir_sha256=SHA2,
            lean_rows={
                ("original", 0): ({
                    "rva": 0x1000,
                    "size": 1,
                    "bytes": "40",
                    "form": semantic_form,
                },),
            },
            lean_evidence={
                "status": "lean_extracted_untrusted",
                "classifier_sha256": classifier,
                "extractor_sha256": SHA0,
                "source_sha256": SHA1,
            },
        )

        authority = build_machine_ir_isa_selection_authority_v2(
            requirements=requirements,
            qualification=qualification.to_payload(),
            binary_id="game.exe",
        )

        self.assertEqual(authority["status"], "qualified")
        self.assertEqual(authority["requirements"]["binary"]["sha256"], BINARY_SHA)
        self.assertEqual(
            authority["fallback_capability_ids"],
            [{"form_id": form_id, "capability_id": FALLBACK_ID}],
        )

        certificate = build_machine_ir_isa_selection_certificate_v2(
            requirements=requirements,
            authority=authority,
        )
        parsed = parse_machine_ir_isa_selection_certificate_v2(certificate)
        self.assertEqual(parsed.status, "qualified")
        self.assertEqual(parsed.binary_sha256, BINARY_SHA)
        self.assertEqual(len(parsed.forms), 1)
        self.assertEqual(parsed.forms[0]["form_id"], form_id)
        self.assertNotIn("evidence", certificate)

        corrupted = copy.deepcopy(certificate)
        corrupted["forms"][0]["semantic_form"] = "formal-default-v1.dec-reg"
        with self.assertRaisesRegex(
            MachineIRISASelectionV2Error, "self-hash is stale"
        ):
            parse_machine_ir_isa_selection_certificate_v2(corrupted)

    def test_qualified_artifact_binds_exact_binary_forms_evidence_and_fallback(self):
        qualification, selection, authority = _authority()
        payload = authority.to_payload()

        self.assertEqual(authority.status, SelectionAuthorityStatus.QUALIFIED)
        self.assertEqual(payload["format"], ISA_KERNEL_SELECTION_AUTHORITY_FORMAT)
        self.assertEqual(
            payload["requirements"]["binary"]["sha256"], BINARY_SHA
        )
        self.assertEqual(
            payload["requirements"]["forms"][0]["source_locations"][0],
            {
                "image_id": "original",
                "image_sha256": BINARY_SHA,
                "rva": 0x1000,
                "byte_length": 1,
            },
        )
        self.assertEqual(payload["kernel"]["decoder_sha256"], SHA0)
        self.assertEqual(payload["kernel"]["semantics_sha256"], SHA1)
        self.assertEqual(
            payload["evidence"]["kernel_qualification"]["sha256"],
            qualification.sha256(),
        )
        self.assertEqual(
            payload["evidence"]["binary_kernel_selection"]["sha256"],
            selection.sha256(),
        )
        self.assertEqual(payload["fallback_capability_ids"], [{
            "form_id": FORM_ID,
            "capability_id": FALLBACK_ID,
        }])
        self.assertTrue(payload["policy"]["oracle_disputes_veto_selection"])
        self.assertFalse(payload["policy"]["static_completeness_authority"])
        self.assertEqual(
            parse_isa_kernel_selection_authority(payload), authority
        )

    def test_missing_selection_is_incomplete(self):
        qualification = _qualification()
        authority = build_isa_kernel_selection_authority(
            binary_id="game.exe",
            binary_sha256=BINARY_SHA,
            reachable_forms=(_requirement(),),
            qualification=qualification,
            selection=None,
            fallback_capability_ids={FORM_ID: FALLBACK_ID},
        )

        self.assertEqual(authority.status, SelectionAuthorityStatus.INCOMPLETE)
        self.assertEqual(
            {issue.code for issue in authority.issues},
            {"kernel_selection_missing"},
        )
        self.assertIsNone(
            authority.to_payload()["evidence"]["binary_kernel_selection"]
        )
        missing = validate_isa_kernel_selection_authority(
            None,
            binary_id="game.exe",
            binary_sha256=BINARY_SHA,
            reachable_forms=(_requirement(),),
            qualification=qualification,
            selection=None,
            fallback_capability_ids={FORM_ID: FALLBACK_ID},
        )
        self.assertEqual(missing.status, SelectionAuthorityStatus.INCOMPLETE)
        self.assertEqual(missing.issues[0].code, "selection_authority_missing")

    def test_wrong_binary_hash_is_a_violation(self):
        qualification = _qualification()
        stale_selection = _selection(
            qualification, binary_sha256=OTHER_BINARY_SHA
        )
        authority = build_isa_kernel_selection_authority(
            binary_id="game.exe",
            binary_sha256=BINARY_SHA,
            reachable_forms=(_requirement(),),
            qualification=qualification,
            selection=stale_selection,
            fallback_capability_ids={FORM_ID: FALLBACK_ID},
        )

        self.assertEqual(authority.status, SelectionAuthorityStatus.VIOLATED)
        self.assertIn(
            "binary_sha256_mismatch",
            {issue.code for issue in authority.issues},
        )

    def test_unsupported_evidence_is_incomplete(self):
        _, _, authority = _authority(mode="unsupported")

        self.assertEqual(authority.status, SelectionAuthorityStatus.INCOMPLETE)
        issue = next(
            issue
            for issue in authority.issues
            if issue.code == "qualification_evidence_incomplete"
        )
        self.assertEqual(issue.form_id, FORM_ID)
        self.assertIn("backend_unsupported", issue.observed["diagnostic_codes"])

    def test_oracle_dispute_vetoes_selection(self):
        _, _, authority = _authority(mode="disputed")

        self.assertEqual(authority.status, SelectionAuthorityStatus.VIOLATED)
        issue = next(
            issue
            for issue in authority.issues
            if issue.code == "oracle_dispute_veto"
        )
        self.assertEqual(issue.form_id, FORM_ID)
        self.assertEqual(issue.observed["status"], "disputed")

    def test_fallback_capability_drift_is_a_violation(self):
        qualification, selection, authority = _authority()
        checked = validate_isa_kernel_selection_authority(
            authority,
            binary_id="game.exe",
            binary_sha256=BINARY_SHA,
            reachable_forms=(_requirement(),),
            qualification=qualification,
            selection=selection,
            fallback_capability_ids={FORM_ID: "native-fallback-v2"},
        )

        self.assertEqual(checked.status, SelectionAuthorityStatus.VIOLATED)
        self.assertFalse(checked.usable)
        self.assertEqual(checked.issues[0].code, "fallback_capability_mismatch")

    def test_corruption_is_violated_while_missing_support_is_incomplete(self):
        qualification, selection, authority = _authority()
        corrupted = copy.deepcopy(authority.to_payload())
        corrupted["status"] = "incomplete"

        with self.assertRaisesRegex(
            ISAKernelSelectionAuthorityError, "status"
        ):
            parse_isa_kernel_selection_authority(corrupted)

        checked = validate_isa_kernel_selection_authority(
            corrupted,
            binary_id="game.exe",
            binary_sha256=BINARY_SHA,
            reachable_forms=(_requirement(),),
            qualification=qualification,
            selection=selection,
            fallback_capability_ids={FORM_ID: FALLBACK_ID},
        )
        self.assertEqual(checked.status, SelectionAuthorityStatus.VIOLATED)
        self.assertEqual(checked.issues[0].code, "selection_authority_corrupted")

        incomplete = build_isa_kernel_selection_authority(
            binary_id="game.exe",
            binary_sha256=BINARY_SHA,
            reachable_forms=(_requirement(),),
            qualification=qualification,
            selection=selection,
            fallback_capability_ids={},
        )
        self.assertEqual(incomplete.status, SelectionAuthorityStatus.INCOMPLETE)
        self.assertEqual(
            {issue.code for issue in incomplete.issues},
            {"fallback_capability_missing"},
        )


if __name__ == "__main__":
    unittest.main()
