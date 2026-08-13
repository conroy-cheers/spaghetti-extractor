"""Deterministic, evidence-only qualification for the Stage A ISA kernel.

The artifacts in this module deliberately sit outside candidate qualification
boundary.  Structural coverage records that a declared semantic form has an
exact generated corpus case; concrete-oracle qualification records whether
Bochs, Unicorn, and Lean could execute and agree on those cases.  Unsupported
oracle execution therefore leaves structural coverage intact but makes oracle
qualification incomplete.  Concrete disagreement blocks qualification, and
agreement remains evidence rather than proof authority.  No artifact emitted
here can qualify a reconstructed candidate.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
from typing import Any

from .isa_conformance import (
    BackendKind,
    GPR_NAMES,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    InstructionTestCase,
    X87Mask,
    ObservationStatus,
    BackendObservation,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
    parse_isa_conformance_report,
)
ISA_ORACLE_OBSERVATION_FORMAT = "stage-a-isa-oracle-observation-v1"
ISA_ORACLE_CONSENSUS_FORMAT = "stage-a-isa-oracle-consensus-v1"
ISA_FORM_QUALIFICATION_FORMAT_V1 = "stage-a-isa-form-qualification-v1"
ISA_FORM_QUALIFICATION_FORMAT = "stage-a-isa-form-qualification-v2"
ISA_KERNEL_QUALIFICATION_FORMAT_V1 = "stage-a-isa-kernel-qualification-v1"
ISA_KERNEL_QUALIFICATION_FORMAT = "stage-a-isa-kernel-qualification-v2"
ISA_KERNEL_SELECTION_FORMAT_V1 = "stage-a-isa-kernel-selection-v1"
ISA_KERNEL_SELECTION_FORMAT = "stage-a-isa-kernel-selection-v2"
ISA_KERNEL_SELECTION_REQUIREMENTS_FORMAT = (
    "stage-a-isa-kernel-selection-requirements-v1"
)
ISA_KERNEL_QUALIFICATION_TRUST_ROLE = "isa_kernel_qualification_evidence_only"

_SHA256_LENGTH = 64
_MAX_INSTRUCTION_BYTES = 15
_MISSING_JSON_VALUE = {"missing": True}


class ISAKernelQualificationError(ValueError):
    """Raised when qualification evidence is malformed or self-inconsistent."""


class QualificationStatus(str, Enum):
    QUALIFIED = "qualified"
    INCOMPLETE = "incomplete"
    DISPUTED = "disputed"
    VETOED = "vetoed"


class StructuralCoverageStatus(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class BackendRole(str, Enum):
    BOCHS = "bochs"
    UNICORN = "unicorn"
    LEAN = "lean"


class ObservationAvailability(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


_ROLE_ORDER = {
    BackendRole.BOCHS: 0,
    BackendRole.UNICORN: 1,
    BackendRole.LEAN: 2,
}
_STATUS_PRECEDENCE = {
    QualificationStatus.QUALIFIED: 0,
    QualificationStatus.INCOMPLETE: 1,
    QualificationStatus.DISPUTED: 2,
    QualificationStatus.VETOED: 3,
}


@dataclass(frozen=True)
class EvidenceTrust:
    role: str = ISA_KERNEL_QUALIFICATION_TRUST_ROLE
    proof_authority: bool = False
    closes_stage_a_proof: bool = False


@dataclass(frozen=True)
class ISAProfileBinding:
    id: str
    architecture: str
    cpu: str
    execution_mode: str
    environment: str
    features: tuple[str, ...]


@dataclass(frozen=True)
class SemanticKernelBinding:
    id: str
    decoder_sha256: str
    semantics_sha256: str
    lean_version: str


@dataclass(frozen=True)
class GeneratorBinding:
    id: str
    version: str


@dataclass(frozen=True)
class BackendBinding:
    role: BackendRole
    id: str
    version: str


@dataclass(frozen=True)
class OracleSuiteBinding:
    backends: tuple[BackendBinding, ...]


@dataclass(frozen=True)
class CorpusBinding:
    id: str
    sha256: str


@dataclass(frozen=True)
class SourceLocation:
    image_id: str
    image_sha256: str
    rva: int
    byte_length: int


@dataclass(frozen=True)
class MismatchDiagnostic:
    code: str
    form_id: str
    case_id: str | None
    json_path: str
    reference_backend_id: str | None
    observed_backend_id: str | None
    reference_result_sha256: str | None
    observed_result_sha256: str | None
    expected: Any
    observed: Any
    source_locations: tuple[SourceLocation, ...]
    message: str


@dataclass(frozen=True)
class ISAOracleObservation:
    form_id: str
    case_id: str
    profile: ISAProfileBinding
    semantic_kernel: SemanticKernelBinding
    corpus: CorpusBinding
    generator: GeneratorBinding
    backend: BackendBinding
    availability: ObservationAvailability
    result: Mapping[str, Any] | None
    result_sha256: str | None
    detail: str
    trust: EvidenceTrust = EvidenceTrust()
    format: str = ISA_ORACLE_OBSERVATION_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAOracleObservation":
        return parse_oracle_observation(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_oracle_observation(self)

    def sha256(self) -> str:
        return artifact_sha256(self)


@dataclass(frozen=True)
class ISAOracleConsensus:
    form_id: str
    case_id: str
    profile: ISAProfileBinding
    semantic_kernel: SemanticKernelBinding
    corpus: CorpusBinding
    generator: GeneratorBinding
    oracle_suite: OracleSuiteBinding
    observations: tuple[ISAOracleObservation, ...]
    status: QualificationStatus
    diagnostics: tuple[MismatchDiagnostic, ...]
    trust: EvidenceTrust = EvidenceTrust()
    format: str = ISA_ORACLE_CONSENSUS_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAOracleConsensus":
        return parse_oracle_consensus(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_oracle_consensus(self)

    def sha256(self) -> str:
        return artifact_sha256(self)


@dataclass(frozen=True)
class ISAFormQualification:
    form_id: str
    semantic_form: str
    profile: ISAProfileBinding
    semantic_kernel: SemanticKernelBinding
    generator: GeneratorBinding
    oracle_suite: OracleSuiteBinding
    corpora: tuple[CorpusBinding, ...]
    consensuses: tuple[ISAOracleConsensus, ...]
    status: QualificationStatus
    diagnostics: tuple[MismatchDiagnostic, ...]
    counts: Mapping[str, int]
    trust: EvidenceTrust = EvidenceTrust()
    format: str = ISA_FORM_QUALIFICATION_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAFormQualification":
        return parse_form_qualification(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_form_qualification(self)

    def sha256(self) -> str:
        return artifact_sha256(self)

    @property
    def structural_status(self) -> StructuralCoverageStatus:
        return (
            StructuralCoverageStatus.COMPLETE
            if self.consensuses
            else StructuralCoverageStatus.INCOMPLETE
        )

    @property
    def concrete_oracle_status(self) -> QualificationStatus:
        return self.status

    @property
    def structural_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return () if self.consensuses else self.diagnostics

    @property
    def concrete_oracle_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return self.diagnostics


@dataclass(frozen=True)
class ISAKernelQualification:
    profile: ISAProfileBinding
    semantic_kernel: SemanticKernelBinding
    generator: GeneratorBinding
    oracle_suite: OracleSuiteBinding
    corpora: tuple[CorpusBinding, ...]
    required_form_ids: tuple[str, ...]
    forms: tuple[ISAFormQualification, ...]
    status: QualificationStatus
    diagnostics: tuple[MismatchDiagnostic, ...]
    counts: Mapping[str, int]
    trust: EvidenceTrust = EvidenceTrust()
    format: str = ISA_KERNEL_QUALIFICATION_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAKernelQualification":
        return parse_kernel_qualification(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_kernel_qualification(self)

    def sha256(self) -> str:
        return artifact_sha256(self)

    @property
    def structural_status(self) -> StructuralCoverageStatus:
        return _structural_status(row.structural_status for row in self.forms)

    @property
    def concrete_oracle_status(self) -> QualificationStatus:
        return _status(row.concrete_oracle_status for row in self.forms)

    @property
    def structural_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return tuple(
            sorted(
                (
                    diagnostic
                    for row in self.forms
                    for diagnostic in row.structural_diagnostics
                ),
                key=_diagnostic_key,
            )
        )

    @property
    def concrete_oracle_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return tuple(
            sorted(
                (
                    diagnostic
                    for row in self.forms
                    for diagnostic in row.concrete_oracle_diagnostics
                ),
                key=_diagnostic_key,
            )
        )


@dataclass(frozen=True)
class BinaryFormRequirement:
    form_id: str
    semantic_form: str
    source_locations: tuple[SourceLocation, ...]


@dataclass(frozen=True)
class BinaryQualificationRequirements:
    binary_id: str
    binary_sha256: str
    profile_id: str
    semantic_kernel_id: str
    forms: tuple[BinaryFormRequirement, ...]
    trust: EvidenceTrust = EvidenceTrust()
    format: str = ISA_KERNEL_SELECTION_REQUIREMENTS_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "BinaryQualificationRequirements":
        return parse_binary_qualification_requirements(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_binary_qualification_requirements(self)

    def sha256(self) -> str:
        return artifact_sha256(self)


@dataclass(frozen=True)
class SelectedFormQualification:
    form_id: str
    semantic_form: str
    source_locations: tuple[SourceLocation, ...]
    qualification_sha256: str | None
    status: QualificationStatus
    diagnostics: tuple[MismatchDiagnostic, ...]

    @property
    def structural_status(self) -> StructuralCoverageStatus:
        structural_blockers = {
            "missing_required_form",
            "semantic_form_binding_mismatch",
            "no_conformance_cases",
        }
        return (
            StructuralCoverageStatus.INCOMPLETE
            if self.qualification_sha256 is None
            or any(row.code in structural_blockers for row in self.diagnostics)
            else StructuralCoverageStatus.COMPLETE
        )

    @property
    def concrete_oracle_status(self) -> QualificationStatus:
        return self.status

    @property
    def structural_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        if self.structural_status is StructuralCoverageStatus.COMPLETE:
            return ()
        return self.diagnostics

    @property
    def concrete_oracle_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return self.diagnostics


@dataclass(frozen=True)
class ISAKernelSelection:
    binary_id: str
    binary_sha256: str
    profile: ISAProfileBinding
    semantic_kernel: SemanticKernelBinding
    kernel_qualification_sha256: str
    required_form_ids: tuple[str, ...]
    selected_forms: tuple[SelectedFormQualification, ...]
    status: QualificationStatus
    diagnostics: tuple[MismatchDiagnostic, ...]
    counts: Mapping[str, int]
    trust: EvidenceTrust = EvidenceTrust()
    format: str = ISA_KERNEL_SELECTION_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAKernelSelection":
        return parse_kernel_selection(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_kernel_selection(self)

    def sha256(self) -> str:
        return artifact_sha256(self)

    @property
    def structural_status(self) -> StructuralCoverageStatus:
        return _structural_status(
            row.structural_status for row in self.selected_forms
        )

    @property
    def concrete_oracle_status(self) -> QualificationStatus:
        return _status(
            row.concrete_oracle_status for row in self.selected_forms
        )

    @property
    def structural_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return tuple(
            sorted(
                (
                    diagnostic
                    for row in self.selected_forms
                    for diagnostic in row.structural_diagnostics
                ),
                key=_diagnostic_key,
            )
        )

    @property
    def concrete_oracle_diagnostics(self) -> tuple[MismatchDiagnostic, ...]:
        return tuple(
            sorted(
                (
                    diagnostic
                    for row in self.selected_forms
                    for diagnostic in row.concrete_oracle_diagnostics
                ),
                key=_diagnostic_key,
            )
        )


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAKernelQualificationError(f"{context} must be an object")
    return value


def _objects(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise ISAKernelQualificationError(f"{context} must be a list of objects")
    return list(value)


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append(f"missing fields {sorted(missing)!r}")
    if unknown:
        details.append(f"unknown fields {sorted(unknown)!r}")
    raise ISAKernelQualificationError(f"{context} has " + " and ".join(details))


def _string(
    value: Any,
    context: str,
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ISAKernelQualificationError(f"{context} must be a string")
    if not allow_empty and (not value or value.strip() != value):
        raise ISAKernelQualificationError(
            f"{context} must be a non-empty string without surrounding whitespace"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if len(digest) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ISAKernelQualificationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return digest


def _optional_sha256(value: Any, context: str) -> str | None:
    return None if value is None else _sha256(value, context)


def _enum(enum_type: type[Enum], value: Any, context: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ISAKernelQualificationError(f"{context} is unsupported") from exc


def _uint32(value: Any, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**32
    ):
        raise ISAKernelQualificationError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return value


def _positive_count(value: Any, context: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ISAKernelQualificationError(f"{context} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ISAKernelQualificationError(
            f"{context} must be no greater than {maximum}"
        )
    return value


def _count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ISAKernelQualificationError(
            f"{context} must be a non-negative integer"
        )
    return value


def _normalize_json(value: Any, context: str = "JSON value") -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise ISAKernelQualificationError(f"{context} must not contain floats")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ISAKernelQualificationError(
                f"{context} object keys must be strings"
            )
        return {
            key: _normalize_json(value[key], f"{context}.{key}")
            for key in sorted(value)
        }
    if isinstance(value, (list, tuple)):
        return [
            _normalize_json(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    raise ISAKernelQualificationError(
        f"{context} contains unsupported value {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one canonical byte representation used by every artifact."""
    to_payload = getattr(value, "to_payload", None)
    if callable(to_payload):
        value = to_payload()
    normalized = _normalize_json(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("ascii")


def _payload(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    to_payload = getattr(value, "to_payload", None)
    if callable(to_payload):
        result = to_payload()
        return _object(result, "artifact payload")
    raise ISAKernelQualificationError(
        "artifact must be a typed qualification artifact or mapping"
    )


def artifact_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(_payload(value))).hexdigest()


def _parse_trust(value: Any, context: str) -> EvidenceTrust:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"role", "proof_authority", "closes_stage_a_proof"},
        context,
    )
    if payload.get("role") != ISA_KERNEL_QUALIFICATION_TRUST_ROLE:
        raise ISAKernelQualificationError(f"{context}.role is unsupported")
    if payload.get("proof_authority") is not False:
        raise ISAKernelQualificationError(
            f"{context}.proof_authority must be false"
        )
    if payload.get("closes_stage_a_proof") is not False:
        raise ISAKernelQualificationError(
            f"{context}.closes_stage_a_proof must be false"
        )
    return EvidenceTrust()


def _trust_payload(trust: EvidenceTrust) -> dict[str, Any]:
    if trust != EvidenceTrust():
        raise ISAKernelQualificationError(
            "ISA kernel qualification evidence cannot claim proof authority"
        )
    return {
        "role": trust.role,
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def _parse_profile(value: Any, context: str) -> ISAProfileBinding:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "id",
            "architecture",
            "cpu",
            "execution_mode",
            "environment",
            "features",
        },
        context,
    )
    raw_features = payload.get("features")
    if not isinstance(raw_features, list):
        raise ISAKernelQualificationError(f"{context}.features must be a list")
    features = tuple(
        _string(feature, f"{context}.features[{index}]")
        for index, feature in enumerate(raw_features)
    )
    if features != tuple(sorted(set(features))):
        raise ISAKernelQualificationError(
            f"{context}.features must be unique and ordered"
        )
    return ISAProfileBinding(
        id=_string(payload.get("id"), f"{context}.id"),
        architecture=_string(
            payload.get("architecture"), f"{context}.architecture"
        ),
        cpu=_string(payload.get("cpu"), f"{context}.cpu"),
        execution_mode=_string(
            payload.get("execution_mode"), f"{context}.execution_mode"
        ),
        environment=_string(
            payload.get("environment"), f"{context}.environment"
        ),
        features=features,
    )


def _profile_payload(value: ISAProfileBinding) -> dict[str, Any]:
    parsed = _parse_profile(
        {
            "id": value.id,
            "architecture": value.architecture,
            "cpu": value.cpu,
            "execution_mode": value.execution_mode,
            "environment": value.environment,
            "features": list(value.features),
        },
        "ISA profile",
    )
    if parsed != value:
        raise ISAKernelQualificationError("ISA profile is not canonical")
    return {
        "id": value.id,
        "architecture": value.architecture,
        "cpu": value.cpu,
        "execution_mode": value.execution_mode,
        "environment": value.environment,
        "features": list(value.features),
    }


def _parse_kernel(value: Any, context: str) -> SemanticKernelBinding:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"id", "decoder_sha256", "semantics_sha256", "lean_version"},
        context,
    )
    return SemanticKernelBinding(
        id=_string(payload.get("id"), f"{context}.id"),
        decoder_sha256=_sha256(
            payload.get("decoder_sha256"), f"{context}.decoder_sha256"
        ),
        semantics_sha256=_sha256(
            payload.get("semantics_sha256"), f"{context}.semantics_sha256"
        ),
        lean_version=_string(
            payload.get("lean_version"), f"{context}.lean_version"
        ),
    )


def _kernel_payload(value: SemanticKernelBinding) -> dict[str, Any]:
    return {
        "id": value.id,
        "decoder_sha256": value.decoder_sha256,
        "semantics_sha256": value.semantics_sha256,
        "lean_version": value.lean_version,
    }


def _parse_generator(value: Any, context: str) -> GeneratorBinding:
    payload = _object(value, context)
    _exact_fields(payload, {"id", "version"}, context)
    return GeneratorBinding(
        id=_string(payload.get("id"), f"{context}.id"),
        version=_string(payload.get("version"), f"{context}.version"),
    )


def _generator_payload(value: GeneratorBinding) -> dict[str, Any]:
    return {"id": value.id, "version": value.version}


def _parse_backend(value: Any, context: str) -> BackendBinding:
    payload = _object(value, context)
    _exact_fields(payload, {"role", "id", "version"}, context)
    role = _enum(BackendRole, payload.get("role"), f"{context}.role")
    backend = BackendBinding(
        role=role,
        id=_string(payload.get("id"), f"{context}.id"),
        version=_string(payload.get("version"), f"{context}.version"),
    )
    return backend


def _backend_payload(value: BackendBinding) -> dict[str, Any]:
    parsed = _parse_backend(
        {"role": value.role.value, "id": value.id, "version": value.version},
        "backend",
    )
    if parsed != value:
        raise ISAKernelQualificationError("backend binding is not canonical")
    return {"role": value.role.value, "id": value.id, "version": value.version}


def _parse_suite(value: Any, context: str) -> OracleSuiteBinding:
    payload = _object(value, context)
    _exact_fields(payload, {"backends"}, context)
    backends = tuple(
        _parse_backend(row, f"{context}.backends[{index}]")
        for index, row in enumerate(
            _objects(payload.get("backends"), f"{context}.backends")
        )
    )
    expected_roles = tuple(BackendRole)
    actual_roles = tuple(backend.role for backend in backends)
    if actual_roles != expected_roles:
        raise ISAKernelQualificationError(
            f"{context}.backends must contain Bochs, Unicorn, and Lean in order"
        )
    if len({backend.id for backend in backends}) != len(backends):
        raise ISAKernelQualificationError(
            f"{context}.backends must use distinct backend IDs"
        )
    return OracleSuiteBinding(backends)


def _suite_payload(value: OracleSuiteBinding) -> dict[str, Any]:
    payload = {"backends": [_backend_payload(backend) for backend in value.backends]}
    if _parse_suite(payload, "oracle suite") != value:
        raise ISAKernelQualificationError("oracle suite is not canonical")
    return payload


def _parse_corpus(value: Any, context: str) -> CorpusBinding:
    payload = _object(value, context)
    _exact_fields(payload, {"id", "sha256"}, context)
    return CorpusBinding(
        id=_string(payload.get("id"), f"{context}.id"),
        sha256=_sha256(payload.get("sha256"), f"{context}.sha256"),
    )


def _corpus_payload(value: CorpusBinding) -> dict[str, Any]:
    return {"id": value.id, "sha256": value.sha256}


def _parse_location(value: Any, context: str) -> SourceLocation:
    payload = _object(value, context)
    _exact_fields(
        payload, {"image_id", "image_sha256", "rva", "byte_length"}, context
    )
    return SourceLocation(
        image_id=_string(payload.get("image_id"), f"{context}.image_id"),
        image_sha256=_sha256(
            payload.get("image_sha256"), f"{context}.image_sha256"
        ),
        rva=_uint32(payload.get("rva"), f"{context}.rva"),
        byte_length=_positive_count(
            payload.get("byte_length"),
            f"{context}.byte_length",
            maximum=_MAX_INSTRUCTION_BYTES,
        ),
    )


def _location_payload(value: SourceLocation) -> dict[str, Any]:
    return {
        "image_id": value.image_id,
        "image_sha256": value.image_sha256,
        "rva": value.rva,
        "byte_length": value.byte_length,
    }


def _location_key(value: SourceLocation) -> tuple[str, str, int, int]:
    return (
        value.image_id,
        value.image_sha256,
        value.rva,
        value.byte_length,
    )


def _ordered_locations(
    values: Iterable[SourceLocation], context: str, *, allow_empty: bool
) -> tuple[SourceLocation, ...]:
    result = tuple(values)
    if not allow_empty and not result:
        raise ISAKernelQualificationError(f"{context} must not be empty")
    if tuple(sorted(set(result), key=_location_key)) != result:
        raise ISAKernelQualificationError(
            f"{context} must be unique and deterministically ordered"
        )
    return result


def _status(values: Iterable[QualificationStatus]) -> QualificationStatus:
    statuses = tuple(values)
    if not statuses:
        return QualificationStatus.INCOMPLETE
    return max(statuses, key=_STATUS_PRECEDENCE.__getitem__)


def _status_counts(
    values: Iterable[QualificationStatus], *, total_name: str
) -> dict[str, int]:
    statuses = tuple(values)
    return {
        total_name: len(statuses),
        "qualified": statuses.count(QualificationStatus.QUALIFIED),
        "incomplete": statuses.count(QualificationStatus.INCOMPLETE),
        "disputed": statuses.count(QualificationStatus.DISPUTED),
        "vetoed": statuses.count(QualificationStatus.VETOED),
    }


def _structural_status(
    values: Iterable[StructuralCoverageStatus],
) -> StructuralCoverageStatus:
    statuses = tuple(values)
    if not statuses or StructuralCoverageStatus.INCOMPLETE in statuses:
        return StructuralCoverageStatus.INCOMPLETE
    return StructuralCoverageStatus.COMPLETE


def _structural_counts(
    values: Iterable[StructuralCoverageStatus], *, total_name: str
) -> dict[str, int]:
    statuses = tuple(values)
    return {
        total_name: len(statuses),
        "complete": statuses.count(StructuralCoverageStatus.COMPLETE),
        "incomplete": statuses.count(StructuralCoverageStatus.INCOMPLETE),
    }


def _parse_counts(
    value: Any, context: str, *, total_name: str
) -> dict[str, int]:
    payload = _object(value, context)
    fields = {total_name, "qualified", "incomplete", "disputed", "vetoed"}
    _exact_fields(payload, fields, context)
    counts = {
        field: _count(payload.get(field), f"{context}.{field}")
        for field in fields
    }
    if counts[total_name] != sum(
        counts[name] for name in ("qualified", "incomplete", "disputed", "vetoed")
    ):
        raise ISAKernelQualificationError(
            f"{context} status counts do not sum to {total_name}"
        )
    return counts


def _parse_structural_counts(
    value: Any, context: str, *, total_name: str
) -> dict[str, int]:
    payload = _object(value, context)
    fields = {total_name, "complete", "incomplete"}
    _exact_fields(payload, fields, context)
    counts = {
        field: _count(payload.get(field), f"{context}.{field}")
        for field in fields
    }
    if counts[total_name] != counts["complete"] + counts["incomplete"]:
        raise ISAKernelQualificationError(
            f"{context} status counts do not sum to {total_name}"
        )
    return counts


def _require_shared(
    actual: Any, expected: Any, context: str
) -> None:
    if actual != expected:
        raise ISAKernelQualificationError(
            f"{context} does not match the enclosing artifact"
        )


def _validate_common_bindings(
    *,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding | None = None,
) -> None:
    if not isinstance(profile, ISAProfileBinding):
        raise ISAKernelQualificationError(
            "profile must be an ISAProfileBinding"
        )
    if not isinstance(semantic_kernel, SemanticKernelBinding):
        raise ISAKernelQualificationError(
            "semantic kernel must be a SemanticKernelBinding"
        )
    if not isinstance(generator, GeneratorBinding):
        raise ISAKernelQualificationError(
            "generator must be a GeneratorBinding"
        )
    _profile_payload(profile)
    _parse_kernel(_kernel_payload(semantic_kernel), "semantic kernel")
    _parse_generator(_generator_payload(generator), "generator")
    if oracle_suite is not None:
        if not isinstance(oracle_suite, OracleSuiteBinding):
            raise ISAKernelQualificationError(
                "oracle suite must be an OracleSuiteBinding"
            )
        _suite_payload(oracle_suite)


def _parse_optional_string(value: Any, context: str) -> str | None:
    return None if value is None else _string(value, context)


def _parse_diagnostic(value: Any, context: str) -> MismatchDiagnostic:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "code",
            "form_id",
            "case_id",
            "json_path",
            "reference_backend_id",
            "observed_backend_id",
            "reference_result_sha256",
            "observed_result_sha256",
            "expected",
            "observed",
            "source_locations",
            "message",
        },
        context,
    )
    locations = tuple(
        _parse_location(row, f"{context}.source_locations[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("source_locations"), f"{context}.source_locations"
            )
        )
    )
    _ordered_locations(
        locations, f"{context}.source_locations", allow_empty=True
    )
    json_path = _string(payload.get("json_path"), f"{context}.json_path")
    if not json_path.startswith("$"):
        raise ISAKernelQualificationError(
            f"{context}.json_path must begin with '$'"
        )
    return MismatchDiagnostic(
        code=_string(payload.get("code"), f"{context}.code"),
        form_id=_string(payload.get("form_id"), f"{context}.form_id"),
        case_id=_parse_optional_string(payload.get("case_id"), f"{context}.case_id"),
        json_path=json_path,
        reference_backend_id=_parse_optional_string(
            payload.get("reference_backend_id"),
            f"{context}.reference_backend_id",
        ),
        observed_backend_id=_parse_optional_string(
            payload.get("observed_backend_id"),
            f"{context}.observed_backend_id",
        ),
        reference_result_sha256=_optional_sha256(
            payload.get("reference_result_sha256"),
            f"{context}.reference_result_sha256",
        ),
        observed_result_sha256=_optional_sha256(
            payload.get("observed_result_sha256"),
            f"{context}.observed_result_sha256",
        ),
        expected=_normalize_json(payload.get("expected"), f"{context}.expected"),
        observed=_normalize_json(payload.get("observed"), f"{context}.observed"),
        source_locations=locations,
        message=_string(payload.get("message"), f"{context}.message"),
    )


def _diagnostic_payload(value: MismatchDiagnostic) -> dict[str, Any]:
    return {
        "code": value.code,
        "form_id": value.form_id,
        "case_id": value.case_id,
        "json_path": value.json_path,
        "reference_backend_id": value.reference_backend_id,
        "observed_backend_id": value.observed_backend_id,
        "reference_result_sha256": value.reference_result_sha256,
        "observed_result_sha256": value.observed_result_sha256,
        "expected": _normalize_json(value.expected, "diagnostic.expected"),
        "observed": _normalize_json(value.observed, "diagnostic.observed"),
        "source_locations": [
            _location_payload(location) for location in value.source_locations
        ],
        "message": value.message,
    }


def _diagnostic_key(value: MismatchDiagnostic) -> tuple[Any, ...]:
    return (
        value.form_id,
        value.case_id or "",
        value.code,
        value.json_path,
        value.reference_backend_id or "",
        value.observed_backend_id or "",
        canonical_json(value.expected),
        canonical_json(value.observed),
    )


def _ordered_diagnostics(
    values: Iterable[MismatchDiagnostic], context: str
) -> tuple[MismatchDiagnostic, ...]:
    result = tuple(values)
    if tuple(sorted(result, key=_diagnostic_key)) != result:
        raise ISAKernelQualificationError(
            f"{context} must be deterministically ordered"
        )
    return result


def _qualification_layers_payload(
    *,
    structural_status: StructuralCoverageStatus,
    structural_statuses: Iterable[StructuralCoverageStatus],
    structural_diagnostics: Iterable[MismatchDiagnostic],
    structural_total_name: str,
    concrete_oracle_status: QualificationStatus,
    concrete_oracle_counts: Mapping[str, int],
    concrete_oracle_diagnostics: Iterable[MismatchDiagnostic],
) -> dict[str, Any]:
    return {
        "structural": {
            "status": structural_status.value,
            "counts": _structural_counts(
                structural_statuses, total_name=structural_total_name
            ),
            "diagnostics": [
                _diagnostic_payload(row) for row in structural_diagnostics
            ],
        },
        "concrete_oracle": {
            "status": concrete_oracle_status.value,
            "counts": dict(concrete_oracle_counts),
            "diagnostics": [
                _diagnostic_payload(row)
                for row in concrete_oracle_diagnostics
            ],
        },
    }


def _validate_qualification_layers(
    value: Any,
    *,
    expected: Mapping[str, Any],
    context: str,
    structural_total_name: str,
    concrete_oracle_total_name: str,
) -> None:
    payload = _object(value, context)
    _exact_fields(payload, {"structural", "concrete_oracle"}, context)
    structural = _object(payload.get("structural"), f"{context}.structural")
    concrete_oracle = _object(
        payload.get("concrete_oracle"), f"{context}.concrete_oracle"
    )
    for name, layer in (
        ("structural", structural),
        ("concrete_oracle", concrete_oracle),
    ):
        _exact_fields(
            layer,
            {"status", "counts", "diagnostics"},
            f"{context}.{name}",
        )
    _enum(
        StructuralCoverageStatus,
        structural.get("status"),
        f"{context}.structural.status",
    )
    _parse_structural_counts(
        structural.get("counts"),
        f"{context}.structural.counts",
        total_name=structural_total_name,
    )
    _enum(
        QualificationStatus,
        concrete_oracle.get("status"),
        f"{context}.concrete_oracle.status",
    )
    _parse_counts(
        concrete_oracle.get("counts"),
        f"{context}.concrete_oracle.counts",
        total_name=concrete_oracle_total_name,
    )
    for name, layer in (
        ("structural", structural),
        ("concrete_oracle", concrete_oracle),
    ):
        diagnostics = tuple(
            _parse_diagnostic(
                row, f"{context}.{name}.diagnostics[{index}]"
            )
            for index, row in enumerate(
                _objects(
                    layer.get("diagnostics"),
                    f"{context}.{name}.diagnostics",
                )
            )
        )
        _ordered_diagnostics(diagnostics, f"{context}.{name}.diagnostics")
    if payload != expected:
        raise ISAKernelQualificationError(
            f"{context} is inconsistent with the qualification evidence"
        )


def _json_differences(
    expected: Any, observed: Any, path: str = "$"
) -> list[tuple[str, Any, Any]]:
    if type(expected) is not type(observed):
        return [(path, expected, observed)]
    if isinstance(expected, Mapping):
        differences: list[tuple[str, Any, Any]] = []
        for key in sorted(set(expected) | set(observed)):
            child_path = f"{path}.{key}"
            if key not in expected:
                differences.append(
                    (child_path, _MISSING_JSON_VALUE, observed[key])
                )
            elif key not in observed:
                differences.append(
                    (child_path, expected[key], _MISSING_JSON_VALUE)
                )
            else:
                differences.extend(
                    _json_differences(expected[key], observed[key], child_path)
                )
        return differences
    if isinstance(expected, list):
        differences = []
        for index in range(max(len(expected), len(observed))):
            child_path = f"{path}[{index}]"
            if index >= len(expected):
                differences.append(
                    (child_path, _MISSING_JSON_VALUE, observed[index])
                )
            elif index >= len(observed):
                differences.append(
                    (child_path, expected[index], _MISSING_JSON_VALUE)
                )
            else:
                differences.extend(
                    _json_differences(
                        expected[index], observed[index], child_path
                    )
                )
        return differences
    return [] if expected == observed else [(path, expected, observed)]


def _comparison_diagnostics(
    *,
    code: str,
    form_id: str,
    case_id: str,
    reference: ISAOracleObservation,
    observed: ISAOracleObservation,
    message: str,
) -> tuple[MismatchDiagnostic, ...]:
    assert reference.result is not None
    assert observed.result is not None
    return tuple(
        MismatchDiagnostic(
            code=code,
            form_id=form_id,
            case_id=case_id,
            json_path=path,
            reference_backend_id=reference.backend.id,
            observed_backend_id=observed.backend.id,
            reference_result_sha256=reference.result_sha256,
            observed_result_sha256=observed.result_sha256,
            expected=expected,
            observed=actual,
            source_locations=(),
            message=message,
        )
        for path, expected, actual in _json_differences(
            reference.result, observed.result
        )
    )


def _missing_backend_diagnostic(
    *,
    form_id: str,
    case_id: str,
    backend: BackendBinding,
) -> MismatchDiagnostic:
    return MismatchDiagnostic(
        code="missing_backend",
        form_id=form_id,
        case_id=case_id,
        json_path="$",
        reference_backend_id=backend.id,
        observed_backend_id=None,
        reference_result_sha256=None,
        observed_result_sha256=None,
        expected={"backend_role": backend.role.value, "version": backend.version},
        observed=None,
        source_locations=(),
        message=f"required {backend.role.value} observation is missing",
    )


def _incomplete_backend_diagnostic(
    observation: ISAOracleObservation,
) -> MismatchDiagnostic:
    code = {
        ObservationAvailability.INCOMPLETE: "backend_observation_incomplete",
        ObservationAvailability.UNSUPPORTED: "backend_unsupported",
        ObservationAvailability.ERROR: "backend_error",
    }.get(observation.availability)
    if code is None:
        raise ISAKernelQualificationError(
            "complete backend observation cannot produce an incomplete diagnostic"
        )
    return MismatchDiagnostic(
        code=code,
        form_id=observation.form_id,
        case_id=observation.case_id,
        json_path="$",
        reference_backend_id=observation.backend.id,
        observed_backend_id=observation.backend.id,
        reference_result_sha256=None,
        observed_result_sha256=None,
        expected={"availability": ObservationAvailability.COMPLETE.value},
        observed={
            "availability": observation.availability.value,
            "detail": observation.detail,
        },
        source_locations=(),
        message=(
            f"{observation.backend.role.value} did not produce a complete "
            "architectural observation"
        ),
    )


def build_oracle_observation(
    *,
    form_id: str,
    case_id: str,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    corpus: CorpusBinding,
    generator: GeneratorBinding,
    backend: BackendBinding,
    availability: ObservationAvailability,
    result: Mapping[str, Any] | None,
    detail: str = "",
) -> ISAOracleObservation:
    """Build one canonical backend observation bound to all cache identities."""
    form_id = _string(form_id, "oracle observation.form_id")
    case_id = _string(case_id, "oracle observation.case_id")
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
    )
    if not isinstance(corpus, CorpusBinding):
        raise ISAKernelQualificationError(
            "corpus must be a CorpusBinding"
        )
    _corpus_payload(_parse_corpus(_corpus_payload(corpus), "corpus"))
    if not isinstance(backend, BackendBinding):
        raise ISAKernelQualificationError(
            "backend must be a BackendBinding"
        )
    _backend_payload(backend)
    if not isinstance(availability, ObservationAvailability):
        raise ISAKernelQualificationError(
            "oracle observation availability is unsupported"
        )
    detail = _string(
        detail, "oracle observation.detail", allow_empty=True
    )
    if availability is ObservationAvailability.COMPLETE:
        if result is None:
            raise ISAKernelQualificationError(
                "complete oracle observation requires a result"
            )
        normalized = _object(
            _normalize_json(result, "oracle observation.result"),
            "oracle observation.result",
        )
        result_value: Mapping[str, Any] | None = dict(normalized)
        result_sha256 = hashlib.sha256(
            canonical_json_bytes(result_value)
        ).hexdigest()
    else:
        if result is not None:
            raise ISAKernelQualificationError(
                "incomplete oracle observation must not carry a result"
            )
        if not detail:
            raise ISAKernelQualificationError(
                "incomplete oracle observation requires detail"
            )
        result_value = None
        result_sha256 = None
    return ISAOracleObservation(
        form_id=form_id,
        case_id=case_id,
        profile=profile,
        semantic_kernel=semantic_kernel,
        corpus=corpus,
        generator=generator,
        backend=backend,
        availability=availability,
        result=result_value,
        result_sha256=result_sha256,
        detail=detail,
    )


def parse_oracle_observation(value: Any) -> ISAOracleObservation:
    payload = _object(value, "ISA oracle observation")
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "case_id",
            "profile",
            "semantic_kernel",
            "corpus",
            "generator",
            "backend",
            "availability",
            "result",
            "result_sha256",
            "detail",
            "trust",
        },
        "ISA oracle observation",
    )
    if payload.get("format") != ISA_ORACLE_OBSERVATION_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA oracle observation format"
        )
    observation = build_oracle_observation(
        form_id=payload.get("form_id"),
        case_id=payload.get("case_id"),
        profile=_parse_profile(
            payload.get("profile"), "ISA oracle observation.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA oracle observation.semantic_kernel",
        ),
        corpus=_parse_corpus(
            payload.get("corpus"), "ISA oracle observation.corpus"
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA oracle observation.generator"
        ),
        backend=_parse_backend(
            payload.get("backend"), "ISA oracle observation.backend"
        ),
        availability=_enum(
            ObservationAvailability,
            payload.get("availability"),
            "ISA oracle observation.availability",
        ),
        result=payload.get("result"),
        detail=_string(
            payload.get("detail"),
            "ISA oracle observation.detail",
            allow_empty=True,
        ),
    )
    declared_digest = payload.get("result_sha256")
    if observation.result_sha256 != declared_digest:
        raise ISAKernelQualificationError(
            "ISA oracle observation result SHA-256 is inconsistent"
        )
    _parse_trust(payload.get("trust"), "ISA oracle observation.trust")
    return observation


def serialize_oracle_observation(
    value: ISAOracleObservation,
) -> dict[str, Any]:
    if not isinstance(value, ISAOracleObservation):
        raise ISAKernelQualificationError(
            "oracle observation must be an ISAOracleObservation"
        )
    payload = {
        "format": value.format,
        "form_id": value.form_id,
        "case_id": value.case_id,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "corpus": _corpus_payload(value.corpus),
        "generator": _generator_payload(value.generator),
        "backend": _backend_payload(value.backend),
        "availability": value.availability.value,
        "result": (
            _normalize_json(value.result, "oracle observation.result")
            if value.result is not None
            else None
        ),
        "result_sha256": value.result_sha256,
        "detail": value.detail,
        "trust": _trust_payload(value.trust),
    }
    if parse_oracle_observation(payload) != value:
        raise ISAKernelQualificationError(
            "oracle observation is not a valid typed instance"
        )
    return payload


def build_oracle_consensus(
    *,
    form_id: str,
    case_id: str,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    corpus: CorpusBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    observations: Iterable[ISAOracleObservation],
) -> ISAOracleConsensus:
    """Classify one case using the strict Bochs/Unicorn/Lean consensus rule."""
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    if not isinstance(corpus, CorpusBinding):
        raise ISAKernelQualificationError(
            "corpus must be a CorpusBinding"
        )
    _parse_corpus(_corpus_payload(corpus), "corpus")
    form_id = _string(form_id, "oracle consensus.form_id")
    case_id = _string(case_id, "oracle consensus.case_id")
    raw_rows = tuple(observations)
    if any(not isinstance(row, ISAOracleObservation) for row in raw_rows):
        raise ISAKernelQualificationError(
            "oracle consensus observations must be ISAOracleObservation values"
        )
    rows = tuple(
        sorted(raw_rows, key=lambda row: _ROLE_ORDER[row.backend.role])
    )
    if len({row.backend.role for row in rows}) != len(rows):
        raise ISAKernelQualificationError(
            "oracle consensus contains duplicate backend roles"
        )
    suite_by_role = {backend.role: backend for backend in oracle_suite.backends}
    for row in rows:
        _require_shared(row.form_id, form_id, "observation form ID")
        _require_shared(row.case_id, case_id, "observation case ID")
        _require_shared(row.profile, profile, "observation profile")
        _require_shared(
            row.semantic_kernel, semantic_kernel, "observation semantic kernel"
        )
        _require_shared(row.corpus, corpus, "observation corpus")
        _require_shared(row.generator, generator, "observation generator")
        _require_shared(
            row.backend,
            suite_by_role[row.backend.role],
            "observation backend",
        )
    by_role = {row.backend.role: row for row in rows}
    diagnostics: list[MismatchDiagnostic] = []
    missing = [
        backend
        for backend in oracle_suite.backends
        if backend.role not in by_role
    ]
    if missing:
        status = QualificationStatus.INCOMPLETE
        diagnostics.extend(
            _missing_backend_diagnostic(
                form_id=form_id, case_id=case_id, backend=backend
            )
            for backend in missing
        )
    elif any(
        row.availability is not ObservationAvailability.COMPLETE for row in rows
    ):
        status = QualificationStatus.INCOMPLETE
        diagnostics.extend(
            _incomplete_backend_diagnostic(row)
            for row in rows
            if row.availability is not ObservationAvailability.COMPLETE
        )
    else:
        bochs = by_role[BackendRole.BOCHS]
        unicorn = by_role[BackendRole.UNICORN]
        lean = by_role[BackendRole.LEAN]
        if bochs.result_sha256 != unicorn.result_sha256:
            status = QualificationStatus.DISPUTED
            diagnostics.extend(
                _comparison_diagnostics(
                    code="external_oracle_disagreement",
                    form_id=form_id,
                    case_id=case_id,
                    reference=bochs,
                    observed=unicorn,
                    message=(
                        "Bochs and Unicorn disagree on an architecturally "
                        "defined output"
                    ),
                )
            )
        elif bochs.result_sha256 != lean.result_sha256:
            status = QualificationStatus.VETOED
            diagnostics.extend(
                _comparison_diagnostics(
                    code="lean_semantics_mismatch",
                    form_id=form_id,
                    case_id=case_id,
                    reference=bochs,
                    observed=lean,
                    message=(
                        "Lean semantics differ from the agreeing external "
                        "Bochs and Unicorn observations"
                    ),
                )
            )
        else:
            status = QualificationStatus.QUALIFIED
    ordered_diagnostics = tuple(sorted(diagnostics, key=_diagnostic_key))
    return ISAOracleConsensus(
        form_id=form_id,
        case_id=case_id,
        profile=profile,
        semantic_kernel=semantic_kernel,
        corpus=corpus,
        generator=generator,
        oracle_suite=oracle_suite,
        observations=rows,
        status=status,
        diagnostics=ordered_diagnostics,
    )


def parse_oracle_consensus(value: Any) -> ISAOracleConsensus:
    payload = _object(value, "ISA oracle consensus")
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "case_id",
            "profile",
            "semantic_kernel",
            "corpus",
            "generator",
            "oracle_suite",
            "observations",
            "status",
            "diagnostics",
            "trust",
        },
        "ISA oracle consensus",
    )
    if payload.get("format") != ISA_ORACLE_CONSENSUS_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA oracle consensus format"
        )
    consensus = build_oracle_consensus(
        form_id=payload.get("form_id"),
        case_id=payload.get("case_id"),
        profile=_parse_profile(
            payload.get("profile"), "ISA oracle consensus.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA oracle consensus.semantic_kernel",
        ),
        corpus=_parse_corpus(
            payload.get("corpus"), "ISA oracle consensus.corpus"
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA oracle consensus.generator"
        ),
        oracle_suite=_parse_suite(
            payload.get("oracle_suite"), "ISA oracle consensus.oracle_suite"
        ),
        observations=tuple(
            parse_oracle_observation(row)
            for row in _objects(
                payload.get("observations"),
                "ISA oracle consensus.observations",
            )
        ),
    )
    declared_status = _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA oracle consensus.status",
    )
    if consensus.status is not declared_status:
        raise ISAKernelQualificationError(
            "ISA oracle consensus status is inconsistent"
        )
    declared_diagnostics = tuple(
        _parse_diagnostic(row, f"ISA oracle consensus.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA oracle consensus.diagnostics",
            )
        )
    )
    _ordered_diagnostics(
        declared_diagnostics, "ISA oracle consensus.diagnostics"
    )
    if consensus.diagnostics != declared_diagnostics:
        raise ISAKernelQualificationError(
            "ISA oracle consensus diagnostics are inconsistent"
        )
    _parse_trust(payload.get("trust"), "ISA oracle consensus.trust")
    return consensus


def serialize_oracle_consensus(
    value: ISAOracleConsensus,
) -> dict[str, Any]:
    if not isinstance(value, ISAOracleConsensus):
        raise ISAKernelQualificationError(
            "oracle consensus must be an ISAOracleConsensus"
        )
    payload = {
        "format": value.format,
        "form_id": value.form_id,
        "case_id": value.case_id,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "corpus": _corpus_payload(value.corpus),
        "generator": _generator_payload(value.generator),
        "oracle_suite": _suite_payload(value.oracle_suite),
        "observations": [
            serialize_oracle_observation(row) for row in value.observations
        ],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "trust": _trust_payload(value.trust),
    }
    if parse_oracle_consensus(payload) != value:
        raise ISAKernelQualificationError(
            "oracle consensus is not a valid typed instance"
        )
    return payload


def build_form_qualification(
    *,
    form_id: str,
    semantic_form: str,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    corpora: Iterable[CorpusBinding],
    consensuses: Iterable[ISAOracleConsensus],
) -> ISAFormQualification:
    form_id = _string(form_id, "form qualification.form_id")
    semantic_form = _string(
        semantic_form, "form qualification.semantic_form"
    )
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    raw_corpora = tuple(corpora)
    if any(not isinstance(row, CorpusBinding) for row in raw_corpora):
        raise ISAKernelQualificationError(
            "form qualification corpora must be CorpusBinding values"
        )
    corpus_rows = tuple(
        sorted(set(raw_corpora), key=lambda row: (row.id, row.sha256))
    )
    if not corpus_rows:
        raise ISAKernelQualificationError(
            "form qualification corpora must not be empty"
        )
    corpus_ids = [row.id for row in corpus_rows]
    if len(corpus_ids) != len(set(corpus_ids)):
        raise ISAKernelQualificationError(
            "form qualification corpus IDs must be unique"
        )
    raw_rows = tuple(consensuses)
    if any(not isinstance(row, ISAOracleConsensus) for row in raw_rows):
        raise ISAKernelQualificationError(
            "form qualification consensuses must be ISAOracleConsensus values"
        )
    rows = tuple(
        sorted(
            raw_rows,
            key=lambda row: (row.corpus.id, row.case_id, row.sha256()),
        )
    )
    identities = [(row.corpus.id, row.case_id) for row in rows]
    if len(identities) != len(set(identities)):
        raise ISAKernelQualificationError(
            "form qualification contains duplicate corpus case identities"
        )
    corpus_set = set(corpus_rows)
    for row in rows:
        _require_shared(row.form_id, form_id, "consensus form ID")
        _require_shared(row.profile, profile, "consensus profile")
        _require_shared(
            row.semantic_kernel, semantic_kernel, "consensus semantic kernel"
        )
        _require_shared(row.generator, generator, "consensus generator")
        _require_shared(row.oracle_suite, oracle_suite, "consensus oracle suite")
        if row.corpus not in corpus_set:
            raise ISAKernelQualificationError(
                "consensus corpus is absent from the form corpus inventory"
            )
    if rows:
        status = _status(row.status for row in rows)
        diagnostics = tuple(
            sorted(
                (
                    diagnostic
                    for row in rows
                    for diagnostic in row.diagnostics
                ),
                key=_diagnostic_key,
            )
        )
    else:
        status = QualificationStatus.INCOMPLETE
        diagnostics = (
            MismatchDiagnostic(
                code="no_conformance_cases",
                form_id=form_id,
                case_id=None,
                json_path="$",
                reference_backend_id=None,
                observed_backend_id=None,
                reference_result_sha256=None,
                observed_result_sha256=None,
                expected={"minimum_consensus_cases": 1},
                observed={"consensus_cases": 0},
                source_locations=(),
                message="semantic form has no multi-oracle conformance cases",
            ),
        )
    counts = _status_counts(
        (row.status for row in rows), total_name="consensus_cases"
    )
    return ISAFormQualification(
        form_id=form_id,
        semantic_form=semantic_form,
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=corpus_rows,
        consensuses=rows,
        status=status,
        diagnostics=diagnostics,
        counts=counts,
    )


def parse_form_qualification(value: Any) -> ISAFormQualification:
    payload = _object(value, "ISA form qualification")
    artifact_format = payload.get("format")
    legacy = artifact_format == ISA_FORM_QUALIFICATION_FORMAT_V1
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "semantic_form",
            "profile",
            "semantic_kernel",
            "generator",
            "oracle_suite",
            "corpora",
            "consensuses",
            "consensus_sha256s",
            "status",
            "diagnostics",
            "counts",
            "trust",
        }
        | (set() if legacy else {"qualification_layers"}),
        "ISA form qualification",
    )
    if artifact_format not in {
        ISA_FORM_QUALIFICATION_FORMAT_V1,
        ISA_FORM_QUALIFICATION_FORMAT,
    }:
        raise ISAKernelQualificationError(
            "unsupported ISA form qualification format"
        )
    result = build_form_qualification(
        form_id=payload.get("form_id"),
        semantic_form=payload.get("semantic_form"),
        profile=_parse_profile(
            payload.get("profile"), "ISA form qualification.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA form qualification.semantic_kernel",
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA form qualification.generator"
        ),
        oracle_suite=_parse_suite(
            payload.get("oracle_suite"),
            "ISA form qualification.oracle_suite",
        ),
        corpora=tuple(
            _parse_corpus(row, f"ISA form qualification.corpora[{index}]")
            for index, row in enumerate(
                _objects(
                    payload.get("corpora"), "ISA form qualification.corpora"
                )
            )
        ),
        consensuses=tuple(
            parse_oracle_consensus(row)
            for row in _objects(
                payload.get("consensuses"),
                "ISA form qualification.consensuses",
            )
        ),
    )
    declared_hashes = payload.get("consensus_sha256s")
    if not isinstance(declared_hashes, list):
        raise ISAKernelQualificationError(
            "ISA form qualification.consensus_sha256s must be a list"
        )
    hashes = tuple(
        _sha256(row, f"ISA form qualification.consensus_sha256s[{index}]")
        for index, row in enumerate(declared_hashes)
    )
    if hashes != tuple(row.sha256() for row in result.consensuses):
        raise ISAKernelQualificationError(
            "ISA form qualification consensus hashes are inconsistent"
        )
    if result.status is not _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA form qualification.status",
    ):
        raise ISAKernelQualificationError(
            "ISA form qualification status is inconsistent"
        )
    diagnostics = tuple(
        _parse_diagnostic(row, f"ISA form qualification.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA form qualification.diagnostics",
            )
        )
    )
    _ordered_diagnostics(diagnostics, "ISA form qualification.diagnostics")
    if diagnostics != result.diagnostics:
        raise ISAKernelQualificationError(
            "ISA form qualification diagnostics are inconsistent"
        )
    counts = _parse_counts(
        payload.get("counts"),
        "ISA form qualification.counts",
        total_name="consensus_cases",
    )
    if counts != result.counts:
        raise ISAKernelQualificationError(
            "ISA form qualification counts are inconsistent"
        )
    if not legacy:
        expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(result.structural_status,),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=result.counts,
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
        _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context="ISA form qualification.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="consensus_cases",
        )
    _parse_trust(payload.get("trust"), "ISA form qualification.trust")
    return replace(result, format=artifact_format)


def serialize_form_qualification(
    value: ISAFormQualification,
) -> dict[str, Any]:
    if not isinstance(value, ISAFormQualification):
        raise ISAKernelQualificationError(
            "form qualification must be an ISAFormQualification"
        )
    payload = {
        "format": value.format,
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "generator": _generator_payload(value.generator),
        "oracle_suite": _suite_payload(value.oracle_suite),
        "corpora": [_corpus_payload(row) for row in value.corpora],
        "consensuses": [
            serialize_oracle_consensus(row) for row in value.consensuses
        ],
        "consensus_sha256s": [row.sha256() for row in value.consensuses],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }
    if value.format == ISA_FORM_QUALIFICATION_FORMAT:
        payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(value.structural_status,),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=value.counts,
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    elif value.format != ISA_FORM_QUALIFICATION_FORMAT_V1:
        raise ISAKernelQualificationError(
            "form qualification has an unsupported format"
        )
    if parse_form_qualification(payload) != value:
        raise ISAKernelQualificationError(
            "form qualification is not a valid typed instance"
        )
    return payload


def build_kernel_qualification(
    *,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    corpora: Iterable[CorpusBinding],
    required_form_ids: Iterable[str],
    forms: Iterable[ISAFormQualification],
) -> ISAKernelQualification:
    """Build a complete form inventory for one semantic-kernel revision."""
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    raw_corpora = tuple(corpora)
    if any(not isinstance(row, CorpusBinding) for row in raw_corpora):
        raise ISAKernelQualificationError(
            "kernel qualification corpora must be CorpusBinding values"
        )
    corpus_rows = tuple(
        sorted(set(raw_corpora), key=lambda row: (row.id, row.sha256))
    )
    if not corpus_rows:
        raise ISAKernelQualificationError(
            "kernel qualification corpora must not be empty"
        )
    if len({row.id for row in corpus_rows}) != len(corpus_rows):
        raise ISAKernelQualificationError(
            "kernel qualification corpus IDs must be unique"
        )
    form_ids = tuple(
        _string(form_id, "kernel qualification required form ID")
        for form_id in required_form_ids
    )
    if not form_ids or form_ids != tuple(sorted(set(form_ids))):
        raise ISAKernelQualificationError(
            "kernel qualification required form IDs must be non-empty, unique, "
            "and ordered"
        )
    raw_forms = tuple(forms)
    if any(not isinstance(row, ISAFormQualification) for row in raw_forms):
        raise ISAKernelQualificationError(
            "kernel qualification forms must be ISAFormQualification values"
        )
    form_rows = tuple(sorted(raw_forms, key=lambda row: row.form_id))
    if tuple(row.form_id for row in form_rows) != form_ids:
        raise ISAKernelQualificationError(
            "kernel qualification must contain exactly every required form"
        )
    corpus_set = set(corpus_rows)
    for row in form_rows:
        _require_shared(row.profile, profile, "form profile")
        _require_shared(
            row.semantic_kernel, semantic_kernel, "form semantic kernel"
        )
        _require_shared(row.generator, generator, "form generator")
        _require_shared(row.oracle_suite, oracle_suite, "form oracle suite")
        if not set(row.corpora).issubset(corpus_set):
            raise ISAKernelQualificationError(
                "form qualification uses an undeclared corpus"
            )
    status = _status(row.status for row in form_rows)
    diagnostics = tuple(
        sorted(
            (
                diagnostic
                for row in form_rows
                for diagnostic in row.diagnostics
            ),
            key=_diagnostic_key,
        )
    )
    counts = _status_counts(
        (row.status for row in form_rows), total_name="required_forms"
    )
    return ISAKernelQualification(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=corpus_rows,
        required_form_ids=form_ids,
        forms=form_rows,
        status=status,
        diagnostics=diagnostics,
        counts=counts,
    )


def build_isa_kernel_qualification(
    *,
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    corpora: Iterable[CorpusBinding],
    required_form_ids: Iterable[str],
    forms: Iterable[ISAFormQualification],
) -> ISAKernelQualification:
    """Public builder used by ``stage-a-build-isa-kernel-qualification``."""
    return build_kernel_qualification(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=corpora,
        required_form_ids=required_form_ids,
        forms=forms,
    )


def parse_kernel_qualification(value: Any) -> ISAKernelQualification:
    payload = _object(value, "ISA kernel qualification")
    artifact_format = payload.get("format")
    legacy = artifact_format == ISA_KERNEL_QUALIFICATION_FORMAT_V1
    _exact_fields(
        payload,
        {
            "format",
            "profile",
            "semantic_kernel",
            "generator",
            "oracle_suite",
            "corpora",
            "required_form_ids",
            "forms",
            "form_sha256s",
            "status",
            "diagnostics",
            "counts",
            "trust",
        }
        | (set() if legacy else {"qualification_layers"}),
        "ISA kernel qualification",
    )
    if artifact_format not in {
        ISA_KERNEL_QUALIFICATION_FORMAT_V1,
        ISA_KERNEL_QUALIFICATION_FORMAT,
    }:
        raise ISAKernelQualificationError(
            "unsupported ISA kernel qualification format"
        )
    required_value = payload.get("required_form_ids")
    if not isinstance(required_value, list):
        raise ISAKernelQualificationError(
            "ISA kernel qualification.required_form_ids must be a list"
        )
    result = build_kernel_qualification(
        profile=_parse_profile(
            payload.get("profile"), "ISA kernel qualification.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA kernel qualification.semantic_kernel",
        ),
        generator=_parse_generator(
            payload.get("generator"), "ISA kernel qualification.generator"
        ),
        oracle_suite=_parse_suite(
            payload.get("oracle_suite"),
            "ISA kernel qualification.oracle_suite",
        ),
        corpora=tuple(
            _parse_corpus(row, f"ISA kernel qualification.corpora[{index}]")
            for index, row in enumerate(
                _objects(
                    payload.get("corpora"),
                    "ISA kernel qualification.corpora",
                )
            )
        ),
        required_form_ids=required_value,
        forms=tuple(
            parse_form_qualification(row)
            for row in _objects(
                payload.get("forms"), "ISA kernel qualification.forms"
            )
        ),
    )
    hashes_value = payload.get("form_sha256s")
    if not isinstance(hashes_value, list):
        raise ISAKernelQualificationError(
            "ISA kernel qualification.form_sha256s must be a list"
        )
    hashes = tuple(
        _sha256(row, f"ISA kernel qualification.form_sha256s[{index}]")
        for index, row in enumerate(hashes_value)
    )
    if hashes != tuple(row.sha256() for row in result.forms):
        raise ISAKernelQualificationError(
            "ISA kernel qualification form hashes are inconsistent"
        )
    if result.status is not _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA kernel qualification.status",
    ):
        raise ISAKernelQualificationError(
            "ISA kernel qualification status is inconsistent"
        )
    diagnostics = tuple(
        _parse_diagnostic(
            row, f"ISA kernel qualification.diagnostics[{index}]"
        )
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA kernel qualification.diagnostics",
            )
        )
    )
    _ordered_diagnostics(diagnostics, "ISA kernel qualification.diagnostics")
    if diagnostics != result.diagnostics:
        raise ISAKernelQualificationError(
            "ISA kernel qualification diagnostics are inconsistent"
        )
    counts = _parse_counts(
        payload.get("counts"),
        "ISA kernel qualification.counts",
        total_name="required_forms",
    )
    if counts != result.counts:
        raise ISAKernelQualificationError(
            "ISA kernel qualification counts are inconsistent"
        )
    if not legacy:
        expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(
                row.structural_status for row in result.forms
            ),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (row.concrete_oracle_status for row in result.forms),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
        _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context="ISA kernel qualification.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="required_forms",
        )
    _parse_trust(payload.get("trust"), "ISA kernel qualification.trust")
    return replace(result, format=artifact_format)


def serialize_kernel_qualification(
    value: ISAKernelQualification,
) -> dict[str, Any]:
    if not isinstance(value, ISAKernelQualification):
        raise ISAKernelQualificationError(
            "kernel qualification must be an ISAKernelQualification"
        )
    payload = {
        "format": value.format,
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "generator": _generator_payload(value.generator),
        "oracle_suite": _suite_payload(value.oracle_suite),
        "corpora": [_corpus_payload(row) for row in value.corpora],
        "required_form_ids": list(value.required_form_ids),
        "forms": [serialize_form_qualification(row) for row in value.forms],
        "form_sha256s": [row.sha256() for row in value.forms],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }
    if value.format == ISA_KERNEL_QUALIFICATION_FORMAT:
        payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(
                row.structural_status for row in value.forms
            ),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (row.concrete_oracle_status for row in value.forms),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    elif value.format != ISA_KERNEL_QUALIFICATION_FORMAT_V1:
        raise ISAKernelQualificationError(
            "kernel qualification has an unsupported format"
        )
    if parse_kernel_qualification(payload) != value:
        raise ISAKernelQualificationError(
            "kernel qualification is not a valid typed instance"
        )
    return payload


def _parse_requirement(value: Any, context: str) -> BinaryFormRequirement:
    payload = _object(value, context)
    _exact_fields(
        payload, {"form_id", "semantic_form", "source_locations"}, context
    )
    locations = tuple(
        _parse_location(row, f"{context}.source_locations[{index}]")
        for index, row in enumerate(
            _objects(payload.get("source_locations"), f"{context}.source_locations")
        )
    )
    _ordered_locations(
        locations, f"{context}.source_locations", allow_empty=False
    )
    image_hashes: dict[str, str] = {}
    for location in locations:
        previous = image_hashes.setdefault(
            location.image_id, location.image_sha256
        )
        if previous != location.image_sha256:
            raise ISAKernelQualificationError(
                f"{context} uses multiple hashes for image {location.image_id!r}"
            )
    return BinaryFormRequirement(
        form_id=_string(payload.get("form_id"), f"{context}.form_id"),
        semantic_form=_string(
            payload.get("semantic_form"), f"{context}.semantic_form"
        ),
        source_locations=locations,
    )


def _requirement_payload(value: BinaryFormRequirement) -> dict[str, Any]:
    return {
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "source_locations": [
            _location_payload(location) for location in value.source_locations
        ],
    }


def _parse_selected_form(
    value: Any, context: str, *, layered: bool
) -> SelectedFormQualification:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "form_id",
            "semantic_form",
            "source_locations",
            "qualification_sha256",
            "status",
            "diagnostics",
        }
        | ({"qualification_layers"} if layered else set()),
        context,
    )
    locations = tuple(
        _parse_location(row, f"{context}.source_locations[{index}]")
        for index, row in enumerate(
            _objects(payload.get("source_locations"), f"{context}.source_locations")
        )
    )
    _ordered_locations(
        locations, f"{context}.source_locations", allow_empty=False
    )
    diagnostics = tuple(
        _parse_diagnostic(row, f"{context}.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(payload.get("diagnostics"), f"{context}.diagnostics")
        )
    )
    _ordered_diagnostics(diagnostics, f"{context}.diagnostics")
    form_id = _string(payload.get("form_id"), f"{context}.form_id")
    if any(
        diagnostic.form_id != form_id
        or diagnostic.source_locations != locations
        for diagnostic in diagnostics
    ):
        raise ISAKernelQualificationError(
            f"{context} diagnostics are not localized to the selected form"
        )
    result = SelectedFormQualification(
        form_id=form_id,
        semantic_form=_string(
            payload.get("semantic_form"), f"{context}.semantic_form"
        ),
        source_locations=locations,
        qualification_sha256=_optional_sha256(
            payload.get("qualification_sha256"),
            f"{context}.qualification_sha256",
        ),
        status=_enum(
            QualificationStatus, payload.get("status"), f"{context}.status"
        ),
        diagnostics=diagnostics,
    )
    if layered:
        expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(result.structural_status,),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (result.concrete_oracle_status,),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
        _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context=f"{context}.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="required_forms",
        )
    return result


def _selected_form_payload(
    value: SelectedFormQualification, *, layered: bool
) -> dict[str, Any]:
    payload = {
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "source_locations": [
            _location_payload(location) for location in value.source_locations
        ],
        "qualification_sha256": value.qualification_sha256,
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(diagnostic)
            for diagnostic in value.diagnostics
        ],
    }
    if layered:
        payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(value.structural_status,),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (value.concrete_oracle_status,),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    return payload


def _localized(
    diagnostic: MismatchDiagnostic,
    locations: tuple[SourceLocation, ...],
) -> MismatchDiagnostic:
    return replace(diagnostic, source_locations=locations)


def _missing_form_diagnostic(
    requirement: BinaryFormRequirement,
) -> MismatchDiagnostic:
    return MismatchDiagnostic(
        code="missing_required_form",
        form_id=requirement.form_id,
        case_id=None,
        json_path="$",
        reference_backend_id=None,
        observed_backend_id=None,
        reference_result_sha256=None,
        observed_result_sha256=None,
        expected={
            "form_id": requirement.form_id,
            "semantic_form": requirement.semantic_form,
        },
        observed=None,
        source_locations=requirement.source_locations,
        message="required binary form is absent from kernel qualification",
    )


def _semantic_form_diagnostic(
    requirement: BinaryFormRequirement,
    observed: ISAFormQualification,
) -> MismatchDiagnostic:
    return MismatchDiagnostic(
        code="semantic_form_binding_mismatch",
        form_id=requirement.form_id,
        case_id=None,
        json_path="$.semantic_form",
        reference_backend_id=None,
        observed_backend_id=None,
        reference_result_sha256=None,
        observed_result_sha256=None,
        expected=requirement.semantic_form,
        observed=observed.semantic_form,
        source_locations=requirement.source_locations,
        message="required form ID resolves to a different semantic form",
    )


def build_kernel_selection(
    *,
    binary_id: str,
    binary_sha256: str,
    requirements: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification,
) -> ISAKernelSelection:
    """Select and localize qualification evidence for one exact binary."""
    binary_id = _string(binary_id, "kernel selection.binary_id")
    binary_sha256 = _sha256(
        binary_sha256, "kernel selection.binary_sha256"
    )
    if not isinstance(qualification, ISAKernelQualification):
        raise ISAKernelQualificationError(
            "qualification must be an ISAKernelQualification"
        )
    raw_requirements = tuple(requirements)
    if any(not isinstance(row, BinaryFormRequirement) for row in raw_requirements):
        raise ISAKernelQualificationError(
            "requirements must be BinaryFormRequirement values"
        )
    requirement_rows = tuple(
        sorted(raw_requirements, key=lambda row: row.form_id)
    )
    if not requirement_rows:
        raise ISAKernelQualificationError(
            "kernel selection requirements must not be empty"
        )
    if tuple(row.form_id for row in requirement_rows) != tuple(
        sorted({row.form_id for row in requirement_rows})
    ):
        raise ISAKernelQualificationError(
            "kernel selection requirement form IDs must be unique"
        )
    for row in requirement_rows:
        _parse_requirement(
            _requirement_payload(row),
            f"kernel selection requirement {row.form_id}",
        )
        if any(
            location.image_sha256 != binary_sha256
            for location in row.source_locations
        ):
            raise ISAKernelQualificationError(
                "kernel selection source location does not bind the selected binary"
            )
    forms_by_id = {row.form_id: row for row in qualification.forms}
    selected: list[SelectedFormQualification] = []
    for requirement in requirement_rows:
        form = forms_by_id.get(requirement.form_id)
        if form is None:
            diagnostics = (_missing_form_diagnostic(requirement),)
            selected.append(
                SelectedFormQualification(
                    form_id=requirement.form_id,
                    semantic_form=requirement.semantic_form,
                    source_locations=requirement.source_locations,
                    qualification_sha256=None,
                    status=QualificationStatus.INCOMPLETE,
                    diagnostics=diagnostics,
                )
            )
            continue
        if form.semantic_form != requirement.semantic_form:
            diagnostics = (_semantic_form_diagnostic(requirement, form),)
            selected.append(
                SelectedFormQualification(
                    form_id=requirement.form_id,
                    semantic_form=requirement.semantic_form,
                    source_locations=requirement.source_locations,
                    qualification_sha256=form.sha256(),
                    status=QualificationStatus.INCOMPLETE,
                    diagnostics=diagnostics,
                )
            )
            continue
        diagnostics = tuple(
            sorted(
                (
                    _localized(diagnostic, requirement.source_locations)
                    for diagnostic in form.diagnostics
                ),
                key=_diagnostic_key,
            )
        )
        selected.append(
            SelectedFormQualification(
                form_id=requirement.form_id,
                semantic_form=requirement.semantic_form,
                source_locations=requirement.source_locations,
                qualification_sha256=form.sha256(),
                status=form.status,
                diagnostics=diagnostics,
            )
        )
    selected_rows = tuple(selected)
    status = _status(row.status for row in selected_rows)
    diagnostics = tuple(
        sorted(
            (
                diagnostic
                for row in selected_rows
                for diagnostic in row.diagnostics
            ),
            key=_diagnostic_key,
        )
    )
    return ISAKernelSelection(
        binary_id=binary_id,
        binary_sha256=binary_sha256,
        profile=qualification.profile,
        semantic_kernel=qualification.semantic_kernel,
        kernel_qualification_sha256=qualification.sha256(),
        required_form_ids=tuple(row.form_id for row in requirement_rows),
        selected_forms=selected_rows,
        status=status,
        diagnostics=diagnostics,
        counts=_status_counts(
            (row.status for row in selected_rows), total_name="required_forms"
        ),
    )


def select_isa_kernel_qualification(
    *,
    binary_id: str,
    binary_sha256: str,
    requirements: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification,
) -> ISAKernelSelection:
    """Public builder used by ``stage-a-select-isa-kernel-qualification``."""
    return build_kernel_selection(
        binary_id=binary_id,
        binary_sha256=binary_sha256,
        requirements=requirements,
        qualification=qualification,
    )


def parse_kernel_selection(value: Any) -> ISAKernelSelection:
    payload = _object(value, "ISA kernel selection")
    artifact_format = payload.get("format")
    legacy = artifact_format == ISA_KERNEL_SELECTION_FORMAT_V1
    _exact_fields(
        payload,
        {
            "format",
            "binary",
            "profile",
            "semantic_kernel",
            "kernel_qualification_sha256",
            "required_form_ids",
            "selected_forms",
            "status",
            "diagnostics",
            "counts",
            "trust",
        }
        | (set() if legacy else {"qualification_layers"}),
        "ISA kernel selection",
    )
    if artifact_format not in {
        ISA_KERNEL_SELECTION_FORMAT_V1,
        ISA_KERNEL_SELECTION_FORMAT,
    }:
        raise ISAKernelQualificationError(
            "unsupported ISA kernel selection format"
        )
    binary = _object(payload.get("binary"), "ISA kernel selection.binary")
    _exact_fields(binary, {"id", "sha256"}, "ISA kernel selection.binary")
    required_value = payload.get("required_form_ids")
    if not isinstance(required_value, list):
        raise ISAKernelQualificationError(
            "ISA kernel selection.required_form_ids must be a list"
        )
    required_form_ids = tuple(
        _string(row, f"ISA kernel selection.required_form_ids[{index}]")
        for index, row in enumerate(required_value)
    )
    if (
        not required_form_ids
        or required_form_ids != tuple(sorted(set(required_form_ids)))
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection required form IDs must be non-empty, unique, "
            "and ordered"
        )
    selected = tuple(
        _parse_selected_form(
            row,
            f"ISA kernel selection.selected_forms[{index}]",
            layered=not legacy,
        )
        for index, row in enumerate(
            _objects(
                payload.get("selected_forms"),
                "ISA kernel selection.selected_forms",
            )
        )
    )
    if tuple(row.form_id for row in selected) != required_form_ids:
        raise ISAKernelQualificationError(
            "ISA kernel selection must contain exactly every required form"
        )
    expected_status = _status(row.status for row in selected)
    status = _enum(
        QualificationStatus,
        payload.get("status"),
        "ISA kernel selection.status",
    )
    if status is not expected_status:
        raise ISAKernelQualificationError(
            "ISA kernel selection status is inconsistent"
        )
    diagnostics = tuple(
        _parse_diagnostic(row, f"ISA kernel selection.diagnostics[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("diagnostics"),
                "ISA kernel selection.diagnostics",
            )
        )
    )
    _ordered_diagnostics(diagnostics, "ISA kernel selection.diagnostics")
    expected_diagnostics = tuple(
        sorted(
            (
                diagnostic
                for row in selected
                for diagnostic in row.diagnostics
            ),
            key=_diagnostic_key,
        )
    )
    if diagnostics != expected_diagnostics:
        raise ISAKernelQualificationError(
            "ISA kernel selection diagnostics are inconsistent"
        )
    counts = _parse_counts(
        payload.get("counts"),
        "ISA kernel selection.counts",
        total_name="required_forms",
    )
    if counts != _status_counts(
        (row.status for row in selected), total_name="required_forms"
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection counts are inconsistent"
        )
    _parse_trust(payload.get("trust"), "ISA kernel selection.trust")
    binary_sha256 = _sha256(
        binary.get("sha256"), "ISA kernel selection.binary.sha256"
    )
    if any(
        location.image_sha256 != binary_sha256
        for row in selected
        for location in row.source_locations
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection source location does not bind its binary"
        )
    result = ISAKernelSelection(
        binary_id=_string(binary.get("id"), "ISA kernel selection.binary.id"),
        binary_sha256=binary_sha256,
        profile=_parse_profile(
            payload.get("profile"), "ISA kernel selection.profile"
        ),
        semantic_kernel=_parse_kernel(
            payload.get("semantic_kernel"),
            "ISA kernel selection.semantic_kernel",
        ),
        kernel_qualification_sha256=_sha256(
            payload.get("kernel_qualification_sha256"),
            "ISA kernel selection.kernel_qualification_sha256",
        ),
        required_form_ids=required_form_ids,
        selected_forms=selected,
        status=status,
        diagnostics=diagnostics,
        counts=counts,
        format=artifact_format,
    )
    if not legacy:
        expected_layers = _qualification_layers_payload(
            structural_status=result.structural_status,
            structural_statuses=(
                row.structural_status for row in result.selected_forms
            ),
            structural_diagnostics=result.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=result.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (
                    row.concrete_oracle_status
                    for row in result.selected_forms
                ),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=result.concrete_oracle_diagnostics,
        )
        _validate_qualification_layers(
            payload.get("qualification_layers"),
            expected=expected_layers,
            context="ISA kernel selection.qualification_layers",
            structural_total_name="required_forms",
            concrete_oracle_total_name="required_forms",
        )
    return result


def serialize_kernel_selection(
    value: ISAKernelSelection,
) -> dict[str, Any]:
    if not isinstance(value, ISAKernelSelection):
        raise ISAKernelQualificationError(
            "kernel selection must be an ISAKernelSelection"
        )
    payload = {
        "format": value.format,
        "binary": {"id": value.binary_id, "sha256": value.binary_sha256},
        "profile": _profile_payload(value.profile),
        "semantic_kernel": _kernel_payload(value.semantic_kernel),
        "kernel_qualification_sha256": value.kernel_qualification_sha256,
        "required_form_ids": list(value.required_form_ids),
        "selected_forms": [
            _selected_form_payload(
                row, layered=value.format == ISA_KERNEL_SELECTION_FORMAT
            )
            for row in value.selected_forms
        ],
        "status": value.status.value,
        "diagnostics": [
            _diagnostic_payload(row) for row in value.diagnostics
        ],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }
    if value.format == ISA_KERNEL_SELECTION_FORMAT:
        payload["qualification_layers"] = _qualification_layers_payload(
            structural_status=value.structural_status,
            structural_statuses=(
                row.structural_status for row in value.selected_forms
            ),
            structural_diagnostics=value.structural_diagnostics,
            structural_total_name="required_forms",
            concrete_oracle_status=value.concrete_oracle_status,
            concrete_oracle_counts=_status_counts(
                (
                    row.concrete_oracle_status
                    for row in value.selected_forms
                ),
                total_name="required_forms",
            ),
            concrete_oracle_diagnostics=value.concrete_oracle_diagnostics,
        )
    elif value.format != ISA_KERNEL_SELECTION_FORMAT_V1:
        raise ISAKernelQualificationError(
            "kernel selection has an unsupported format"
        )
    if parse_kernel_selection(payload) != value:
        raise ISAKernelQualificationError(
            "kernel selection is not a valid typed instance"
        )
    return payload


def _backend_binding(
    backend_id: str, oracle_suite: OracleSuiteBinding
) -> BackendBinding:
    for backend in oracle_suite.backends:
        if backend_id == backend.id:
            return backend
    raise ISAKernelQualificationError(
        f"backend {backend_id!r} is absent from the declared oracle suite"
    )


def _profile_matches_case(
    profile: ISAProfileBinding, case: InstructionTestCase
) -> bool:
    return (
        profile.architecture == case.profile.architecture
        and profile.cpu == case.profile.cpu
        and profile.execution_mode == case.profile.execution_mode
        and profile.environment == case.profile.environment
        and profile.features == case.profile.features
    )


def _masked_bytes(value: bytes, mask: bytes) -> list[int]:
    if len(value) != len(mask):
        raise ISAKernelQualificationError(
            "observation and defined-output mask lengths disagree"
        )
    return [
        observed_byte & mask_byte
        for observed_byte, mask_byte in zip(value, mask, strict=True)
    ]


def _effective_x87_mask(
    requested: X87Mask,
    architectural: X87Mask | None,
) -> X87Mask:
    if architectural is None:
        return requested
    return X87Mask(
        control_word=requested.control_word & architectural.control_word,
        status_word=requested.status_word & architectural.status_word,
        tag_word=requested.tag_word & architectural.tag_word,
        last_opcode=requested.last_opcode & architectural.last_opcode,
        instruction_pointer=(
            requested.instruction_pointer & architectural.instruction_pointer
        ),
        data_pointer=requested.data_pointer & architectural.data_pointer,
        registers=tuple(
            bytes(left & right for left, right in zip(a, b, strict=True))
            for a, b in zip(
                requested.registers, architectural.registers, strict=True
            )
        ),
    )


def _has_defined_machine_output(
    case: InstructionTestCase,
    *,
    x87_mask: X87Mask | None = None,
) -> bool:
    masks = case.defined_outputs
    effective_x87 = masks.x87 if x87_mask is None else x87_mask
    return any(
        (
            *(getattr(masks.gprs, register) for register in GPR_NAMES),
            masks.eip,
            masks.eflags,
            masks.fs.selector,
            masks.fs.base,
            effective_x87.control_word,
            effective_x87.status_word,
            effective_x87.tag_word,
            effective_x87.last_opcode,
            effective_x87.instruction_pointer,
            effective_x87.data_pointer,
            *(byte for register in effective_x87.registers for byte in register),
            *(byte for region in masks.memory for byte in region.mask),
        )
    )


def _normalized_complete_result(
    case: InstructionTestCase,
    observation: BackendObservation,
    *,
    x87_definedness: X87Mask | None = None,
) -> dict[str, Any]:
    if observation.actual is None:
        raise ISAKernelQualificationError(
            "complete conformance observation has no control outcome"
        )
    result: dict[str, Any] = {
        "control": observation.actual.control.value,
        "fault": observation.actual.fault.value,
        "final_state": None,
        "memory": None,
    }
    effective_x87 = _effective_x87_mask(
        case.defined_outputs.x87, x87_definedness
    )
    if not _has_defined_machine_output(case, x87_mask=effective_x87):
        return result
    if observation.final_state is None:
        if observation.memory is not None:
            raise ISAKernelQualificationError(
                "conformance observation has memory without final state"
            )
        return result
    if observation.memory is None:
        raise ISAKernelQualificationError(
            "conformance observation has final state without memory"
        )
    state = observation.final_state
    masks = case.defined_outputs
    result["final_state"] = {
        "gprs": {
            register: (
                getattr(state.gprs, register)
                & getattr(masks.gprs, register)
            )
            for register in GPR_NAMES
        },
        "eip": state.eip & masks.eip,
        "eflags": state.eflags & masks.eflags,
        "fs": {
            "selector": state.fs.selector & masks.fs.selector,
            "base": state.fs.base & masks.fs.base,
        },
        "x87": {
            "control_word": state.x87.control_word & effective_x87.control_word,
            "status_word": state.x87.status_word & effective_x87.status_word,
            "tag_word": state.x87.tag_word & effective_x87.tag_word,
            "last_opcode": state.x87.last_opcode & effective_x87.last_opcode,
            "instruction_pointer": (
                state.x87.instruction_pointer
                & effective_x87.instruction_pointer
            ),
            "data_pointer": state.x87.data_pointer & effective_x87.data_pointer,
            "registers": [
                _masked_bytes(register, mask)
                for register, mask in zip(
                    state.x87.registers,
                    effective_x87.registers,
                    strict=True,
                )
            ],
        },
    }
    observed_memory = {row.address: row.data for row in observation.memory}
    normalized_memory: list[dict[str, Any]] = []
    for mask in masks.memory:
        observed = observed_memory.get(mask.address)
        if observed is None:
            normalized_memory.append(
                {
                    "address": mask.address,
                    "mask_length": len(mask.mask),
                    "observed_length": None,
                    "bytes": None,
                }
            )
            continue
        normalized_memory.append(
            {
                "address": mask.address,
                "mask_length": len(mask.mask),
                "observed_length": len(observed),
                "bytes": [
                    observed[index] & mask.mask[index]
                    for index in range(min(len(observed), len(mask.mask)))
                ],
            }
        )
    result["memory"] = normalized_memory
    return result


def observations_from_conformance_report(
    *,
    corpus: ISAConformanceCorpus | Mapping[str, Any],
    report: ISAConformanceReport | Mapping[str, Any],
    form_ids_by_case: Mapping[str, str],
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    x87_definedness_by_case: Mapping[str, X87Mask] | None = None,
) -> tuple[ISAOracleObservation, ...]:
    """Normalize an existing report into strict consensus observations.

    Complete report observations are compared by their actual masked machine
    output.  Their legacy ``match``/``mismatch`` status against the corpus
    expectation does not alter the direct multi-oracle comparison.
    """
    try:
        typed_corpus = (
            corpus
            if isinstance(corpus, ISAConformanceCorpus)
            else parse_isa_conformance_corpus(corpus)
        )
        typed_report = (
            parse_isa_conformance_report(
                report.to_payload(corpus=typed_corpus), corpus=typed_corpus
            )
            if isinstance(report, ISAConformanceReport)
            else parse_isa_conformance_report(report, corpus=typed_corpus)
        )
    except ISAConformanceError as exc:
        raise ISAKernelQualificationError(
            f"invalid ISA conformance input: {exc}"
        ) from exc
    case_ids = tuple(case.id for case in typed_corpus.cases)
    definedness = (
        {} if x87_definedness_by_case is None else x87_definedness_by_case
    )
    if not set(definedness).issubset(set(case_ids)):
        raise ISAKernelQualificationError(
            "x87 definedness names a case outside the qualification corpus"
        )
    if set(form_ids_by_case) != set(case_ids):
        raise ISAKernelQualificationError(
            "semantic-form mapping must contain exactly every corpus case"
        )
    if any(
        not isinstance(case_id, str)
        or not isinstance(form_id, str)
        or not form_id
        for case_id, form_id in form_ids_by_case.items()
    ):
        raise ISAKernelQualificationError(
            "semantic-form mapping must contain non-empty string IDs"
        )
    if any(
        not _profile_matches_case(profile, case) for case in typed_corpus.cases
    ):
        raise ISAKernelQualificationError(
            "qualification profile does not match every corpus case"
        )
    _validate_common_bindings(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
    )
    declared_backend = _backend_binding(
        typed_report.backend.id, oracle_suite
    )
    if typed_report.backend.version != declared_backend.version:
        raise ISAKernelQualificationError(
            "conformance report backend version differs from the oracle suite"
        )
    expected_kind = (
        BackendKind.SEMANTIC_MODEL
        if declared_backend.role is BackendRole.LEAN
        else BackendKind.EMULATOR
    )
    if typed_report.backend.kind is not expected_kind:
        raise ISAKernelQualificationError(
            "conformance report backend kind differs from its oracle-suite role"
        )
    corpus_binding = CorpusBinding(
        id=typed_corpus.id, sha256=typed_report.input_sha256
    )
    cases_by_id = {case.id: case for case in typed_corpus.cases}
    rows: list[ISAOracleObservation] = []
    for observation in typed_report.observations:
        if observation.status in {
            ObservationStatus.MATCH,
            ObservationStatus.MISMATCH,
        }:
            availability = ObservationAvailability.COMPLETE
            result = _normalized_complete_result(
                cases_by_id[observation.case_id],
                observation,
                x87_definedness=definedness.get(observation.case_id),
            )
            detail = observation.detail
        elif observation.status is ObservationStatus.UNSUPPORTED:
            availability = ObservationAvailability.UNSUPPORTED
            result = None
            detail = observation.detail
        else:
            availability = ObservationAvailability.ERROR
            result = None
            detail = observation.detail
        rows.append(
            build_oracle_observation(
                form_id=form_ids_by_case[observation.case_id],
                case_id=observation.case_id,
                profile=profile,
                semantic_kernel=semantic_kernel,
                corpus=corpus_binding,
                generator=generator,
                backend=declared_backend,
                availability=availability,
                result=result,
                detail=detail,
            )
        )
    return tuple(rows)


def consensuses_from_conformance_reports(
    *,
    corpus: ISAConformanceCorpus | Mapping[str, Any],
    reports: Iterable[ISAConformanceReport | Mapping[str, Any]],
    form_ids_by_case: Mapping[str, str],
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    x87_definedness_by_case: Mapping[str, X87Mask] | None = None,
) -> tuple[ISAOracleConsensus, ...]:
    """Join up to three backend reports into one consensus per corpus case."""
    typed_corpus = (
        corpus
        if isinstance(corpus, ISAConformanceCorpus)
        else parse_isa_conformance_corpus(corpus)
    )
    observations: list[ISAOracleObservation] = []
    for report in reports:
        observations.extend(
            observations_from_conformance_report(
                corpus=typed_corpus,
                report=report,
                form_ids_by_case=form_ids_by_case,
                profile=profile,
                semantic_kernel=semantic_kernel,
                generator=generator,
                oracle_suite=oracle_suite,
                x87_definedness_by_case=x87_definedness_by_case,
            )
        )
    by_case: dict[str, list[ISAOracleObservation]] = {
        case.id: [] for case in typed_corpus.cases
    }
    for observation in observations:
        by_case[observation.case_id].append(observation)
    corpus_binding = CorpusBinding(
        id=typed_corpus.id,
        sha256=(
            observations[0].corpus.sha256
            if observations
            else isa_conformance_corpus_sha256(typed_corpus)
        ),
    )
    return tuple(
        build_oracle_consensus(
            form_id=form_ids_by_case[case.id],
            case_id=case.id,
            profile=profile,
            semantic_kernel=semantic_kernel,
            corpus=corpus_binding,
            generator=generator,
            oracle_suite=oracle_suite,
            observations=by_case[case.id],
        )
        for case in typed_corpus.cases
    )


def build_isa_kernel_qualification_from_reports(
    *,
    corpus: ISAConformanceCorpus | Mapping[str, Any],
    reports: Iterable[ISAConformanceReport | Mapping[str, Any]],
    form_ids_by_case: Mapping[str, str],
    semantic_forms_by_id: Mapping[str, str],
    profile: ISAProfileBinding,
    semantic_kernel: SemanticKernelBinding,
    generator: GeneratorBinding,
    oracle_suite: OracleSuiteBinding,
    required_form_ids: Iterable[str] | None = None,
    x87_definedness_by_case: Mapping[str, X87Mask] | None = None,
) -> ISAKernelQualification:
    """Build kernel qualification directly from a backend report triplet.

    ``reports`` may omit a backend; the resulting form is then incomplete.
    Duplicate backend reports are rejected by consensus construction.
    """
    typed_corpus = (
        corpus
        if isinstance(corpus, ISAConformanceCorpus)
        else parse_isa_conformance_corpus(corpus)
    )
    consensuses = consensuses_from_conformance_reports(
        corpus=typed_corpus,
        reports=reports,
        form_ids_by_case=form_ids_by_case,
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        x87_definedness_by_case=x87_definedness_by_case,
    )
    required = tuple(
        sorted(
            set(form_ids_by_case.values())
            if required_form_ids is None
            else {
                _string(form_id, "required form ID")
                for form_id in required_form_ids
            }
        )
    )
    if not required:
        raise ISAKernelQualificationError(
            "kernel report qualification requires at least one form"
        )
    if set(semantic_forms_by_id) != set(required):
        raise ISAKernelQualificationError(
            "semantic-form catalog must contain exactly every required form"
        )
    if any(
        not isinstance(form_id, str)
        or not isinstance(semantic_form, str)
        or not semantic_form
        for form_id, semantic_form in semantic_forms_by_id.items()
    ):
        raise ISAKernelQualificationError(
            "semantic-form catalog must contain non-empty string bindings"
        )
    corpus_binding = CorpusBinding(
        typed_corpus.id, isa_conformance_corpus_sha256(typed_corpus)
    )
    by_form: dict[str, list[ISAOracleConsensus]] = {
        form_id: [] for form_id in required
    }
    for consensus in consensuses:
        if consensus.form_id in by_form:
            by_form[consensus.form_id].append(consensus)
    forms = tuple(
        build_form_qualification(
            form_id=form_id,
            semantic_form=semantic_forms_by_id[form_id],
            profile=profile,
            semantic_kernel=semantic_kernel,
            generator=generator,
            oracle_suite=oracle_suite,
            corpora=(corpus_binding,),
            consensuses=by_form[form_id],
        )
        for form_id in required
    )
    return build_isa_kernel_qualification(
        profile=profile,
        semantic_kernel=semantic_kernel,
        generator=generator,
        oracle_suite=oracle_suite,
        corpora=(corpus_binding,),
        required_form_ids=required,
        forms=forms,
    )


def parse_binary_qualification_requirements(
    value: Any,
) -> BinaryQualificationRequirements:
    payload = _object(value, "ISA kernel selection requirements")
    _exact_fields(
        payload,
        {
            "format",
            "binary",
            "profile_id",
            "semantic_kernel_id",
            "forms",
            "trust",
        },
        "ISA kernel selection requirements",
    )
    if payload.get("format") != ISA_KERNEL_SELECTION_REQUIREMENTS_FORMAT:
        raise ISAKernelQualificationError(
            "unsupported ISA kernel selection requirements format"
        )
    binary = _object(
        payload.get("binary"), "ISA kernel selection requirements.binary"
    )
    _exact_fields(
        binary, {"id", "sha256"}, "ISA kernel selection requirements.binary"
    )
    forms = tuple(
        _parse_requirement(
            row, f"ISA kernel selection requirements.forms[{index}]"
        )
        for index, row in enumerate(
            _objects(
                payload.get("forms"),
                "ISA kernel selection requirements.forms",
            )
        )
    )
    if not forms or tuple(row.form_id for row in forms) != tuple(
        sorted({row.form_id for row in forms})
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection requirement forms must be non-empty, unique, "
            "and ordered"
        )
    binary_sha256 = _sha256(
        binary.get("sha256"),
        "ISA kernel selection requirements.binary.sha256",
    )
    if any(
        location.image_sha256 != binary_sha256
        for form in forms
        for location in form.source_locations
    ):
        raise ISAKernelQualificationError(
            "ISA kernel selection requirements contain a foreign image location"
        )
    _parse_trust(
        payload.get("trust"), "ISA kernel selection requirements.trust"
    )
    return BinaryQualificationRequirements(
        binary_id=_string(
            binary.get("id"), "ISA kernel selection requirements.binary.id"
        ),
        binary_sha256=binary_sha256,
        profile_id=_string(
            payload.get("profile_id"),
            "ISA kernel selection requirements.profile_id",
        ),
        semantic_kernel_id=_string(
            payload.get("semantic_kernel_id"),
            "ISA kernel selection requirements.semantic_kernel_id",
        ),
        forms=forms,
    )


def serialize_binary_qualification_requirements(
    value: BinaryQualificationRequirements,
) -> dict[str, Any]:
    if not isinstance(value, BinaryQualificationRequirements):
        raise ISAKernelQualificationError(
            "requirements must be BinaryQualificationRequirements"
        )
    payload = {
        "format": value.format,
        "binary": {"id": value.binary_id, "sha256": value.binary_sha256},
        "profile_id": value.profile_id,
        "semantic_kernel_id": value.semantic_kernel_id,
        "forms": [_requirement_payload(row) for row in value.forms],
        "trust": _trust_payload(value.trust),
    }
    if parse_binary_qualification_requirements(payload) != value:
        raise ISAKernelQualificationError(
            "kernel selection requirements are not a valid typed instance"
        )
    return payload


def select_isa_kernel_qualification_from_requirements(
    *,
    requirements: BinaryQualificationRequirements | Mapping[str, Any],
    qualification: ISAKernelQualification | Mapping[str, Any],
) -> ISAKernelSelection:
    """Fail-closed adapter used by the qualification-selection CLI."""
    typed_requirements = (
        requirements
        if isinstance(requirements, BinaryQualificationRequirements)
        else parse_binary_qualification_requirements(requirements)
    )
    typed_qualification = (
        qualification
        if isinstance(qualification, ISAKernelQualification)
        else parse_kernel_qualification(qualification)
    )
    if typed_requirements.profile_id != typed_qualification.profile.id:
        raise ISAKernelQualificationError(
            "selection requirements profile does not match qualification"
        )
    if (
        typed_requirements.semantic_kernel_id
        != typed_qualification.semantic_kernel.id
    ):
        raise ISAKernelQualificationError(
            "selection requirements semantic kernel does not match qualification"
        )
    return select_isa_kernel_qualification(
        binary_id=typed_requirements.binary_id,
        binary_sha256=typed_requirements.binary_sha256,
        requirements=typed_requirements.forms,
        qualification=typed_qualification,
    )


# Explicit artifact-qualified aliases for callers outside this module.
parse_isa_oracle_observation = parse_oracle_observation
serialize_isa_oracle_observation = serialize_oracle_observation
parse_isa_oracle_consensus = parse_oracle_consensus
serialize_isa_oracle_consensus = serialize_oracle_consensus
parse_isa_form_qualification = parse_form_qualification
serialize_isa_form_qualification = serialize_form_qualification
parse_isa_kernel_qualification = parse_kernel_qualification
serialize_isa_kernel_qualification = serialize_kernel_qualification
parse_isa_kernel_selection = parse_kernel_selection
serialize_isa_kernel_selection = serialize_kernel_selection


__all__ = [
    "BackendBinding",
    "BackendRole",
    "BinaryFormRequirement",
    "BinaryQualificationRequirements",
    "CorpusBinding",
    "EvidenceTrust",
    "GeneratorBinding",
    "ISA_FORM_QUALIFICATION_FORMAT",
    "ISA_FORM_QUALIFICATION_FORMAT_V1",
    "ISA_KERNEL_QUALIFICATION_FORMAT",
    "ISA_KERNEL_QUALIFICATION_FORMAT_V1",
    "ISA_KERNEL_QUALIFICATION_TRUST_ROLE",
    "ISA_KERNEL_SELECTION_FORMAT",
    "ISA_KERNEL_SELECTION_FORMAT_V1",
    "ISA_KERNEL_SELECTION_REQUIREMENTS_FORMAT",
    "ISA_ORACLE_CONSENSUS_FORMAT",
    "ISA_ORACLE_OBSERVATION_FORMAT",
    "ISAFormQualification",
    "ISAKernelQualification",
    "ISAKernelQualificationError",
    "ISAKernelSelection",
    "ISAOracleConsensus",
    "ISAOracleObservation",
    "ISAProfileBinding",
    "MismatchDiagnostic",
    "ObservationAvailability",
    "OracleSuiteBinding",
    "QualificationStatus",
    "SelectedFormQualification",
    "SemanticKernelBinding",
    "SourceLocation",
    "StructuralCoverageStatus",
    "artifact_sha256",
    "build_form_qualification",
    "build_isa_kernel_qualification",
    "build_isa_kernel_qualification_from_reports",
    "build_kernel_qualification",
    "build_kernel_selection",
    "build_oracle_consensus",
    "build_oracle_observation",
    "canonical_json",
    "canonical_json_bytes",
    "consensuses_from_conformance_reports",
    "observations_from_conformance_report",
    "parse_form_qualification",
    "parse_binary_qualification_requirements",
    "parse_isa_form_qualification",
    "parse_isa_kernel_qualification",
    "parse_isa_kernel_selection",
    "parse_isa_oracle_consensus",
    "parse_isa_oracle_observation",
    "parse_kernel_qualification",
    "parse_kernel_selection",
    "parse_oracle_consensus",
    "parse_oracle_observation",
    "select_isa_kernel_qualification",
    "select_isa_kernel_qualification_from_requirements",
    "serialize_binary_qualification_requirements",
    "serialize_form_qualification",
    "serialize_isa_form_qualification",
    "serialize_isa_kernel_qualification",
    "serialize_isa_kernel_selection",
    "serialize_isa_oracle_consensus",
    "serialize_isa_oracle_observation",
    "serialize_kernel_qualification",
    "serialize_kernel_selection",
    "serialize_oracle_consensus",
    "serialize_oracle_observation",
]
