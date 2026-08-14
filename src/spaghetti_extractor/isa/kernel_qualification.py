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

from .conformance import (
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
ISA_FORM_QUALIFICATION_FORMAT = "stage-a-isa-form-qualification-v2"
ISA_KERNEL_QUALIFICATION_FORMAT = "stage-a-isa-kernel-qualification-v2"
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

from .kernel_qualification_oracles import (
    build_form_qualification,
    build_oracle_consensus,
    build_oracle_observation,
    parse_form_qualification,
    parse_oracle_consensus,
    parse_oracle_observation,
    serialize_form_qualification,
    serialize_oracle_consensus,
    serialize_oracle_observation,
)
from .kernel_qualification_artifacts import (
    build_isa_kernel_qualification,
    build_kernel_qualification,
    build_kernel_selection,
    parse_kernel_qualification,
    parse_kernel_selection,
    select_isa_kernel_qualification,
    serialize_kernel_qualification,
    serialize_kernel_selection,
)
from .kernel_qualification_reports import (
    build_isa_kernel_qualification_from_reports,
    consensuses_from_conformance_reports,
    observations_from_conformance_report,
    parse_binary_qualification_requirements,
    select_isa_kernel_qualification_from_requirements,
    serialize_binary_qualification_requirements,
)


# Explicit artifact-qualified aliases for callers outside this module.
__all__ = [
    "BackendBinding",
    "BackendRole",
    "BinaryFormRequirement",
    "BinaryQualificationRequirements",
    "CorpusBinding",
    "EvidenceTrust",
    "GeneratorBinding",
    "ISA_FORM_QUALIFICATION_FORMAT",
    "ISA_KERNEL_QUALIFICATION_FORMAT",
    "ISA_KERNEL_QUALIFICATION_TRUST_ROLE",
    "ISA_KERNEL_SELECTION_FORMAT",
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
    "parse_kernel_qualification",
    "parse_kernel_selection",
    "parse_oracle_consensus",
    "parse_oracle_observation",
    "select_isa_kernel_qualification",
    "select_isa_kernel_qualification_from_requirements",
    "serialize_binary_qualification_requirements",
    "serialize_form_qualification",
    "serialize_kernel_qualification",
    "serialize_kernel_selection",
    "serialize_oracle_consensus",
    "serialize_oracle_observation",
]
