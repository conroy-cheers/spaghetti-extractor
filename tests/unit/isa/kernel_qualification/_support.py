from __future__ import annotations

import copy
from dataclasses import replace
import unittest

from spaghetti_extractor.isa.conformance import (
    ISA_CONFORMANCE_REPORT_FORMAT,
    X87Mask,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa.kernel_qualification import (
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
    StructuralCoverageStatus,
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


def _machine_state(
    *, eax: int = 2, ecx: int = 3, x87_status_word: int = 0
):
    x87 = _x87()
    x87["status_word"] = x87_status_word
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
        "x87": x87,
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


def _legacy_report(
    backend,
    *,
    eax: int = 2,
    ecx: int = 3,
    x87_status_word: int = 0,
):
    corpus = parse_isa_conformance_corpus(_legacy_corpus())
    status = (
        "match"
        if eax == 2 and x87_status_word == 0
        else "mismatch"
    )
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
                "final_state": _machine_state(
                    eax=eax,
                    ecx=ecx,
                    x87_status_word=x87_status_word,
                ),
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


def _fault_corpus(instruction_bytes: list[int]):
    payload = _legacy_corpus()
    case = payload["cases"][0]
    case["instruction_bytes"] = instruction_bytes
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
        "fault": "divide_error",
    }
    return parse_isa_conformance_corpus(payload)


def _report_backend(role: BackendRole) -> dict[str, str]:
    backend = next(row for row in _suite().backends if row.role is role)
    return {
        "id": backend.id,
        "kind": (
            "semantic_model"
            if role is BackendRole.LEAN
            else "emulator"
        ),
        "version": backend.version,
    }


def _fault_report(
    corpus,
    role: BackendRole,
    *,
    fault: str = "divide_error",
    capture_state: bool = False,
):
    status = (
        "match"
        if fault == "divide_error" and not capture_state
        else "mismatch"
    )
    return {
        "format": ISA_CONFORMANCE_REPORT_FORMAT,
        "corpus_id": corpus.id,
        "input_sha256": isa_conformance_corpus_sha256(corpus),
        "backend": _report_backend(role),
        "qualification": "qualified" if status == "match" else "vetoed",
        "observations": [
            {
                "case_id": "case:add-eax",
                "status": status,
                "final_state": _machine_state() if capture_state else None,
                "memory": [] if capture_state else None,
                "actual": {"control": "fault", "fault": fault},
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


__all__ = tuple(name for name in globals() if not name.startswith("__"))
