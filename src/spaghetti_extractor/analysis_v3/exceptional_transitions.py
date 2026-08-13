"""Root-independent checked exceptional transitions for exact structural units."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
    digest,
    fail,
    mapping,
    optional_text,
    require_record_ids,
    require_stable_id,
    sequence,
    sorted_records,
    stable_id,
    strict_object,
    text,
    uint,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    blocker_payload_v3,
    canonical_dependencies_v3,
    decode_dependencies_v3,
    encode_dependencies_v3,
    manifest_blocker_v3,
    validate_authority_decision_v3,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    FaultOccurrenceV3,
    SemanticIndexRecordV3,
)


EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-exception-evidence-record-v3"
)
EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3 = "exception-evidence-v3"
EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-exceptional-transition-record-v3"
)
EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3 = "exceptional-transitions-v3"
EXCEPTION_CLOSURE_CERTIFICATE_V3 = (
    "spaghetti-extractor-exception-closure-certificate-v3"
)
LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1 = (
    "spaghetti-extractor-pe32-launch-assumption-template-v1"
)
TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1 = (
    "pe32-win32-console-unhandled-synchronous-fault-v1"
)

_TERMINAL_SYNCHRONOUS_FAULT_KINDS = frozenset({"divide_error"})
_EMPTY_UNSUPPORTED_FEATURES = {
    "direct_syscalls": [],
    "executable_writes": [],
    "threads": [],
    "unknown_async_callbacks": [],
    "unmodelled_seh": [],
}


def exceptional_transition_id_v3(
    unit_id: str, fault_index: int, fault_sha256: str
) -> str:
    return stable_id(
        "exceptional-transition-v3",
        {
            "unit_id": unit_id,
            "fault_index": fault_index,
            "fault_sha256": fault_sha256,
        },
    )


def _static_bv_v3(value: Any) -> tuple[int, int] | None:
    """Evaluate only a small, total, constant bit-vector expression fragment."""

    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op == "const":
        raw = value.get("value")
        width = value.get("width")
        if (
            not isinstance(raw, int)
            or isinstance(raw, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or not 1 <= width <= 64
        ):
            return None
        return raw & ((1 << width) - 1), width
    args = value.get("args")
    if not isinstance(args, list):
        return None
    if op == "ite" and len(args) == 3:
        condition = checked_static_boolean_v3(args[0])
        return None if condition is None else _static_bv_v3(args[1 if condition else 2])
    unary_width = {
        "not32": 32,
    }.get(str(op))
    if unary_width is not None and len(args) == 1:
        operand = _static_bv_v3(args[0])
        if operand is None or operand[1] != unary_width:
            return None
        return (~operand[0]) & ((1 << unary_width) - 1), unary_width
    binary_width = {
        "add32": 32,
        "and32": 32,
        "or32": 32,
        "sub32": 32,
        "xor32": 32,
    }.get(str(op))
    if binary_width is not None and len(args) == 2:
        left = _static_bv_v3(args[0])
        right = _static_bv_v3(args[1])
        if left is None or right is None or left[1] != binary_width or right[1] != binary_width:
            return None
        mask = (1 << binary_width) - 1
        operation = {
            "add32": lambda: left[0] + right[0],
            "and32": lambda: left[0] & right[0],
            "or32": lambda: left[0] | right[0],
            "sub32": lambda: left[0] - right[0],
            "xor32": lambda: left[0] ^ right[0],
        }[str(op)]
        return operation() & mask, binary_width
    if op in {"udiv_quot32", "udiv_rem32"} and len(args) == 3:
        operands = tuple(_static_bv_v3(item) for item in args)
        if any(item is None or item[1] != 32 for item in operands):
            return None
        high, low, divisor = (item[0] for item in operands if item is not None)
        if divisor == 0 or high >= divisor:
            return None
        dividend = (high << 32) | low
        result = dividend // divisor if op == "udiv_quot32" else dividend % divisor
        return result, 32
    return None


def checked_static_boolean_v3(value: Any) -> bool | None:
    """Replay a deliberately small exact Boolean/bit-vector fragment.

    Returning ``None`` is not an approximation: callers must remain incomplete.
    The checker never reasons about registers, memory, undefined values, or an
    operator not listed here.
    """

    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op == "true":
        return True
    if op == "false":
        return False
    args = value.get("args")
    if not isinstance(args, list):
        return None
    if op == "not" and len(args) == 1:
        operand = checked_static_boolean_v3(args[0])
        return None if operand is None else not operand
    if op in {"and_bool", "or_bool", "xor_bool"} and len(args) == 2:
        left = checked_static_boolean_v3(args[0])
        right = checked_static_boolean_v3(args[1])
        if left is None or right is None:
            return None
        if op == "and_bool":
            return left and right
        if op == "or_bool":
            return left or right
        return left != right
    if op in {"eq", "eq_bool"} and len(args) == 2:
        left_bv = _static_bv_v3(args[0])
        right_bv = _static_bv_v3(args[1])
        if left_bv is not None and right_bv is not None:
            return left_bv == right_bv
        left_bool = checked_static_boolean_v3(args[0])
        right_bool = checked_static_boolean_v3(args[1])
        return (
            None
            if left_bool is None or right_bool is None
            else left_bool == right_bool
        )
    if op in {"ult32", "ule32"} and len(args) == 2:
        left = _static_bv_v3(args[0])
        right = _static_bv_v3(args[1])
        if left is None or right is None or left[1] != 32 or right[1] != 32:
            return None
        return left[0] < right[0] if op == "ult32" else left[0] <= right[0]
    if op == "msb" and len(args) == 2:
        width = args[0]
        operand = _static_bv_v3(args[1])
        if (
            not isinstance(width, int)
            or isinstance(width, bool)
            or operand is None
            or operand[1] != width
        ):
            return None
        return bool(operand[0] & (1 << (width - 1)))
    if op == "udiv_valid32" and len(args) == 3:
        operands = tuple(_static_bv_v3(item) for item in args)
        if any(item is None or item[1] != 32 for item in operands):
            return None
        high, _low, divisor = (item[0] for item in operands if item is not None)
        return divisor != 0 and high < divisor
    return None


def _validate_complete_exception_evidence_v3(
    evidence: "ExceptionEvidenceV3",
) -> None:
    assert evidence.fault is not None
    assert evidence.guard is not None
    assert evidence.certificate is not None
    fault = mapping(evidence.fault.to_value(), "exception evidence exact fault")
    if canonical_sha256_v3(fault) != evidence.fault_sha256:
        fail(
            "exception_fault_binding_contradiction",
            "exception evidence fault payload does not match its exact fault digest",
            "copy the complete exact semantic fault without rewriting it",
        )
    if not {"condition", "instruction_rva", "kind"}.issubset(fault):
        fail(
            "exception_fault_schema_unsupported",
            "exception evidence fault lacks condition, instruction RVA, or kind",
            "emit the exact normalized semantic fault object",
        )
    condition = mapping(fault["condition"], "exception fault condition")
    uint(fault["instruction_rva"], "exception fault instruction RVA")
    fault_kind = text(fault["kind"], "exception fault kind")
    if evidence.guard != CanonicalValueV3.of(condition):
        fail(
            "exception_guard_binding_contradiction",
            "exception evidence guard is not the exact semantic fault condition",
            "bind the unmodified condition from the exact fault payload",
        )
    certificate = strict_object(
        evidence.certificate.to_value(),
        (
            {
                "condition_sha256",
                "fault_sha256",
                "format",
                "method",
                "result",
            }
            if evidence.disposition == "infeasible"
            else {
                "environment_model",
                "fault_kind",
                "fault_sha256",
                "feature_inventory",
                "format",
                "launch_profile_format",
                "launch_profile_sha256",
                "method",
            }
            if evidence.disposition == "terminates"
            else {
                "fault_sha256",
                "format",
                "handler_unit_id",
                "handler_unit_sha256",
                "method",
            }
        ),
        "exception closure certificate",
    )
    if (
        certificate["format"] != EXCEPTION_CLOSURE_CERTIFICATE_V3
        or certificate["fault_sha256"] != evidence.fault_sha256
    ):
        fail(
            "exception_certificate_binding_contradiction",
            "exception certificate format or fault digest is stale",
            "regenerate the certificate from the exact semantic fault",
        )
    if evidence.disposition == "infeasible":
        if (
            certificate["method"] != "static-condition-replay-v1"
            or certificate["result"] is not False
            or certificate["condition_sha256"]
            != canonical_sha256_v3(condition)
            or checked_static_boolean_v3(condition) is not False
        ):
            fail(
                "exception_infeasibility_certificate_invalid",
                "static replay does not prove the exact fault condition false",
                "remain incomplete or provide a checked inductive invariant",
            )
    elif evidence.disposition == "terminates":
        feature_inventory = strict_object(
            certificate["feature_inventory"],
            set(_EMPTY_UNSUPPORTED_FEATURES),
            "terminal exception feature inventory",
        )
        if (
            certificate["method"]
            != "conditional-unhandled-synchronous-fault-v1"
            or certificate["environment_model"]
            != TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1
            or certificate["launch_profile_format"]
            != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1
            or certificate["fault_kind"] != fault_kind
            or fault_kind not in _TERMINAL_SYNCHRONOUS_FAULT_KINDS
            or dict(feature_inventory) != _EMPTY_UNSUPPORTED_FEATURES
        ):
            fail(
                "exception_terminal_certificate_invalid",
                "terminal exception certificate does not establish the bounded launch profile",
                "remain incomplete unless the fault escapes all supported handlers",
            )
        digest(
            certificate["launch_profile_sha256"],
            "terminal exception launch-profile SHA-256",
        )
    else:
        if (
            certificate["method"] != "checked-handler-binding-v1"
            or certificate["handler_unit_id"] != evidence.handler_unit_id
            or certificate["handler_unit_sha256"] != evidence.handler_unit_sha256
        ):
            fail(
                "exception_handler_certificate_invalid",
                "handled exception certificate does not bind the exact handler",
                "bind the checked handler unit and its exact digest",
            )


def exception_terminal_profile_sha256_v3(
    evidence: "ExceptionEvidenceV3",
) -> str | None:
    if evidence.status != "complete" or evidence.disposition != "terminates":
        return None
    assert evidence.certificate is not None
    certificate = mapping(
        evidence.certificate.to_value(), "terminal exception certificate"
    )
    return digest(
        certificate.get("launch_profile_sha256"),
        "terminal exception launch-profile SHA-256",
    )


@dataclass(frozen=True)
class ExceptionEvidenceV3:
    record_id: str
    unit_id: str
    unit_sha256: str
    fault_index: int
    fault_sha256: str
    status: str
    disposition: str | None
    handler_unit_id: str | None
    handler_unit_sha256: str | None
    fault: CanonicalValueV3 | None
    guard: CanonicalValueV3 | None
    certificate: CanonicalValueV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        text(self.unit_id, "exception evidence unit ID")
        digest(self.unit_sha256, "exception evidence unit SHA-256")
        uint(self.fault_index, "exception evidence fault index")
        digest(self.fault_sha256, "exception evidence fault SHA-256")
        require_stable_id(
            self.record_id,
            "exceptional-transition-v3",
            {
                "unit_id": self.unit_id,
                "fault_index": self.fault_index,
                "fault_sha256": self.fault_sha256,
            },
            "exception evidence",
        )
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"exception evidence status is {self.status!r}",
                "use complete, incomplete, or violated",
            )
        if self.status == "complete":
            if (
                self.disposition not in {"handled", "infeasible", "terminates"}
                or self.fault is None
                or self.guard is None
                or self.certificate is None
                or self.primary_blocker is not None
            ):
                fail(
                    "fail_open_exception_evidence",
                    "complete exception evidence lacks exact checked closure data or has a blocker",
                    "bind the exact fault, guard, closure certificate, and disposition",
                )
            _validate_complete_exception_evidence_v3(self)
            if self.disposition == "handled":
                if self.handler_unit_id is None or self.handler_unit_sha256 is None:
                    fail(
                        "exception_handler_binding_missing",
                        "handled exception has no exact handler unit binding",
                        "bind the handler unit ID and content SHA-256",
                    )
            elif self.handler_unit_id is not None or self.handler_unit_sha256 is not None:
                fail(
                    "exception_handler_binding_contradiction",
                    "terminating exception names a handler unit",
                    "clear handler fields for a terminating transition",
                )
        elif any(
            value is not None
            for value in (
                self.disposition,
                self.handler_unit_id,
                self.handler_unit_sha256,
                self.fault,
                self.guard,
                self.certificate,
            )
        ) or self.primary_blocker is None:
            fail(
                "fail_open_exception_evidence",
                "non-complete exception evidence retains transition authority or lacks a blocker",
                "clear transition fields and provide the matching blocker",
            )
        if self.handler_unit_sha256 is not None:
            digest(self.handler_unit_sha256, "exception handler unit SHA-256")
        if self.primary_blocker is not None and self.primary_blocker.status != self.status:
            fail(
                "fail_open_exception_evidence",
                "exception evidence blocker disagrees with its status",
                "use one matching fail-closed status",
            )


def _encode_exception_evidence(value: ExceptionEvidenceV3) -> dict[str, Any]:
    return {
        "schema": EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_id": value.unit_id,
        "unit_sha256": value.unit_sha256,
        "fault_index": value.fault_index,
        "fault_sha256": value.fault_sha256,
        "status": value.status,
        "disposition": value.disposition,
        "handler_unit_id": value.handler_unit_id,
        "handler_unit_sha256": value.handler_unit_sha256,
        "fault": None if value.fault is None else value.fault.to_value(),
        "guard": None if value.guard is None else value.guard.to_value(),
        "certificate": (
            None if value.certificate is None else value.certificate.to_value()
        ),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _decode_exception_evidence(value: Any) -> ExceptionEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_id",
            "unit_sha256",
            "fault_index",
            "fault_sha256",
            "status",
            "disposition",
            "handler_unit_id",
            "handler_unit_sha256",
            "fault",
            "guard",
            "certificate",
            "primary_blocker",
        },
        "exception evidence",
    )
    if row["schema"] != EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not exception-evidence-record-v3",
            "use EXCEPTION_EVIDENCE_CODEC_V3 with exception-evidence-v3",
        )
    return ExceptionEvidenceV3(
        record_id=text(row["id"], "exception evidence ID"),
        unit_id=text(row["unit_id"], "exception evidence unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "exception evidence unit SHA-256"
        ),
        fault_index=uint(row["fault_index"], "exception evidence fault index"),
        fault_sha256=digest(
            row["fault_sha256"], "exception evidence fault SHA-256"
        ),
        status=text(row["status"], "exception evidence status"),
        disposition=optional_text(
            row["disposition"], "exception evidence disposition"
        ),
        handler_unit_id=optional_text(
            row["handler_unit_id"], "exception handler unit ID"
        ),
        handler_unit_sha256=(
            None
            if row["handler_unit_sha256"] is None
            else digest(
                row["handler_unit_sha256"], "exception handler unit SHA-256"
            )
        ),
        fault=(
            None if row["fault"] is None else CanonicalValueV3.of(row["fault"])
        ),
        guard=(
            None if row["guard"] is None else CanonicalValueV3.of(row["guard"])
        ),
        certificate=(
            None
            if row["certificate"] is None
            else CanonicalValueV3.of(row["certificate"])
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


EXCEPTION_EVIDENCE_CODEC_V3 = RecordCodecV3[ExceptionEvidenceV3](
    decode=_decode_exception_evidence,
    encode=_encode_exception_evidence,
)


@dataclass(frozen=True)
class ExceptionalTransitionV3:
    transition_id: str
    unit_id: str
    fault_index: int
    fault_sha256: str
    status: str
    authorizing: bool
    disposition: str | None
    handler_unit_id: str | None
    guard: CanonicalValueV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        require_stable_id(
            self.transition_id,
            "exceptional-transition-v3",
            {
                "unit_id": self.unit_id,
                "fault_index": self.fault_index,
                "fault_sha256": self.fault_sha256,
            },
            "exceptional transition",
        )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=(
                ()
                if self.primary_blocker is None
                or self.primary_blocker.dependency is None
                else (self.primary_blocker.dependency,)
            ),
            context=f"exceptional transition {self.transition_id!r}",
        )
        if self.status == "complete":
            if (
                self.disposition not in {"handled", "infeasible", "terminates"}
                or self.guard is None
            ):
                fail(
                    "fail_open_exception_transition",
                    "complete exceptional transition lacks checked semantics",
                    "bind a disposition and guard",
                )
            if (self.disposition == "handled") != (self.handler_unit_id is not None):
                fail(
                    "exception_handler_binding_contradiction",
                    "exception disposition disagrees with handler binding",
                    "bind a handler only for handled transitions",
                )
        elif any(
            value is not None
            for value in (self.disposition, self.handler_unit_id, self.guard)
        ):
            fail(
                "fail_open_exception_transition",
                "non-complete exceptional transition retains authority",
                "clear disposition, handler, and guard",
            )


@dataclass(frozen=True)
class ExceptionalTransitionRecordV3:
    record_id: str
    unit_sha256: str
    status: str
    authorizing: bool
    transitions: tuple[ExceptionalTransitionV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "exceptional-transition source unit ID")
        digest(self.unit_sha256, "exceptional-transition source unit SHA-256")
        if self.transitions != tuple(
            sorted(set(self.transitions), key=lambda row: row.transition_id)
        ):
            fail(
                "noncanonical_record_order",
                "exceptional transitions are duplicated or unsorted",
                "sort and deduplicate transitions by stable ID",
            )
        if any(row.unit_id != self.record_id for row in self.transitions):
            fail(
                "exception_unit_contradiction",
                "exceptional-transition inventory mixes source units",
                "place each transition under its exact source unit record",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context=f"exceptional-transition inventory {self.record_id!r}",
        )


def _transition_payload(value: ExceptionalTransitionV3) -> dict[str, Any]:
    return {
        "id": value.transition_id,
        "unit_id": value.unit_id,
        "fault_index": value.fault_index,
        "fault_sha256": value.fault_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "disposition": value.disposition,
        "handler_unit_id": value.handler_unit_id,
        "guard": None if value.guard is None else value.guard.to_value(),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _parse_transition(value: Any) -> ExceptionalTransitionV3:
    row = strict_object(
        value,
        {
            "id",
            "unit_id",
            "fault_index",
            "fault_sha256",
            "status",
            "authorizing",
            "disposition",
            "handler_unit_id",
            "guard",
            "primary_blocker",
        },
        "exceptional transition",
    )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "exceptional transition authorizing field is not Boolean",
            "emit true or false",
        )
    return ExceptionalTransitionV3(
        transition_id=text(row["id"], "exceptional-transition ID"),
        unit_id=text(row["unit_id"], "exceptional-transition unit ID"),
        fault_index=uint(row["fault_index"], "exceptional-transition fault index"),
        fault_sha256=digest(
            row["fault_sha256"], "exceptional-transition fault SHA-256"
        ),
        status=text(row["status"], "exceptional-transition status"),
        authorizing=authorizing,
        disposition=optional_text(
            row["disposition"], "exceptional-transition disposition"
        ),
        handler_unit_id=optional_text(
            row["handler_unit_id"], "exception handler unit ID"
        ),
        guard=(
            None if row["guard"] is None else CanonicalValueV3.of(row["guard"])
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


def _encode_exception_record(value: ExceptionalTransitionRecordV3) -> dict[str, Any]:
    return {
        "schema": EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "transitions": [_transition_payload(row) for row in value.transitions],
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_exception_record(value: Any) -> ExceptionalTransitionRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "status",
            "authorizing",
            "transitions",
            "primary_blocker",
            "dependencies",
        },
        "exceptional-transition record",
    )
    if row["schema"] != EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not exceptional-transition-record-v3",
            "use EXCEPTIONAL_TRANSITION_CODEC_V3 with matching artifacts",
        )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "exceptional-transition authorizing field is malformed",
            "emit an exact authorizing Boolean",
        )
    return ExceptionalTransitionRecordV3(
        record_id=text(row["id"], "exceptional-transition source unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "exceptional-transition source unit SHA-256"
        ),
        status=text(row["status"], "exceptional-transition inventory status"),
        authorizing=authorizing,
        transitions=tuple(
            _parse_transition(item)
            for item in sequence(row["transitions"], "exceptional transitions")
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


EXCEPTIONAL_TRANSITION_CODEC_V3 = RecordCodecV3[ExceptionalTransitionRecordV3](
    decode=_decode_exception_record,
    encode=_encode_exception_record,
)


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record(input_name, record_id)


def _checked_transition(
    context: PhaseContextV3,
    *,
    semantic_index: SemanticIndexRecordV3,
    fault: FaultOccurrenceV3,
) -> tuple[ExceptionalTransitionV3, tuple[RecordDependencyV3, ...]]:
    fault_index = fault.index
    fault_sha256 = fault.fault_sha256
    transition_id = exceptional_transition_id_v3(
        semantic_index.record_id, fault_index, fault_sha256
    )
    evidence_dependency = RecordDependencyV3("exception_evidence", transition_id)
    dependencies: list[RecordDependencyV3] = [evidence_dependency]
    evidence_source = _record_or_none(
        context, evidence_dependency.input_name, evidence_dependency.record_id
    )
    if evidence_source is None:
        blocker: PrimaryBlockerV3 | None = PrimaryBlockerV3(
            "incomplete",
            "exception_evidence_missing",
            evidence_dependency.input_name,
            evidence_dependency.record_id,
        )
    elif (
        manifest_blocker := manifest_blocker_v3(
            context,
            evidence_dependency.input_name,
            "exception_evidence_artifact_not_complete",
            evidence_dependency,
        )
    ) is not None:
        blocker = manifest_blocker
    else:
        evidence = EXCEPTION_EVIDENCE_CODEC_V3.read(evidence_source).value
        if (
            evidence.record_id != transition_id
            or evidence.unit_id != semantic_index.record_id
            or evidence.unit_sha256 != semantic_index.unit_sha256
            or evidence.fault_index != fault_index
            or evidence.fault_sha256 != fault_sha256
        ):
            blocker = PrimaryBlockerV3(
                "violated",
                "exception_evidence_binding_contradiction",
                evidence_dependency.input_name,
                evidence_dependency.record_id,
            )
        elif evidence.status != "complete":
            blocker = PrimaryBlockerV3(
                "violated" if evidence.status == "violated" else "incomplete",
                (
                    evidence.primary_blocker.code
                    if evidence.primary_blocker is not None
                    else "exception_evidence_incomplete"
                ),
                evidence_dependency.input_name,
                evidence_dependency.record_id,
            )
        elif evidence.disposition == "terminates":
            profile_sha256 = exception_terminal_profile_sha256_v3(evidence)
            profile_bindings = tuple(
                binding
                for binding in context.manifest("exception_evidence").bindings
                if binding.name == "launch-profile-source"
                and binding.kind == "launch-assumption-template"
                and binding.identity == LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1
            )
            blocker = (
                None
                if len(profile_bindings) == 1
                and profile_bindings[0].sha256 == profile_sha256
                else PrimaryBlockerV3(
                    "violated",
                    "exception_terminal_profile_binding_contradiction",
                    evidence_dependency.input_name,
                    evidence_dependency.record_id,
                )
            )
        elif evidence.disposition == "handled":
            assert evidence.handler_unit_id is not None
            handler_dependency = RecordDependencyV3(
                "semantic_index", evidence.handler_unit_id
            )
            dependencies.append(handler_dependency)
            handler_source = _record_or_none(
                context, handler_dependency.input_name, handler_dependency.record_id
            )
            if handler_source is None:
                blocker = PrimaryBlockerV3(
                    "violated",
                    "exception_handler_unit_missing",
                    handler_dependency.input_name,
                    handler_dependency.record_id,
                )
            else:
                handler = SEMANTIC_INDEX_CODEC_V3.read(handler_source).value
                blocker = (
                    None
                    if handler.unit_sha256 == evidence.handler_unit_sha256
                    else PrimaryBlockerV3(
                        "violated",
                        "exception_handler_binding_contradiction",
                        handler_dependency.input_name,
                        handler_dependency.record_id,
                    )
                )
        else:
            blocker = None
    complete = blocker is None
    disposition = None
    handler_unit_id = None
    guard = None
    if complete:
        assert evidence_source is not None
        evidence = EXCEPTION_EVIDENCE_CODEC_V3.read(evidence_source).value
        disposition = evidence.disposition
        handler_unit_id = evidence.handler_unit_id
        guard = evidence.guard
    return (
        ExceptionalTransitionV3(
            transition_id=transition_id,
            unit_id=semantic_index.record_id,
            fault_index=fault_index,
            fault_sha256=fault_sha256,
            status="complete" if complete else blocker.status,
            authorizing=complete,
            disposition=disposition,
            handler_unit_id=handler_unit_id,
            guard=guard,
            primary_blocker=blocker,
        ),
        canonical_dependencies_v3(dependencies),
    )


def _derive_exception_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ExceptionalTransitionRecordV3:
    semantic_index = context.typed_record(
        "semantic_index", source.record_id, SEMANTIC_INDEX_CODEC_V3
    ).value
    dependencies = [RecordDependencyV3("semantic_index", semantic_index.record_id)]
    blockers: list[PrimaryBlockerV3] = []
    for input_name, dependency, code in (
        (
            "semantic_index",
            dependencies[0],
            "semantic_index_artifact_not_complete",
        ),
    ):
        manifest_blocker = manifest_blocker_v3(
            context, input_name, code, dependency
        )
        if manifest_blocker is not None:
            blockers.append(manifest_blocker)
    transitions: list[ExceptionalTransitionV3] = []
    for fault in semantic_index.faults:
        transition, exact_dependencies = _checked_transition(
            context,
            semantic_index=semantic_index,
            fault=fault,
        )
        transitions.append(transition)
        dependencies.extend(exact_dependencies)
        if transition.primary_blocker is not None:
            blockers.append(transition.primary_blocker)
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return ExceptionalTransitionRecordV3(
        record_id=semantic_index.record_id,
        unit_sha256=semantic_index.unit_sha256,
        status=status,
        authorizing=status == "complete",
        transitions=tuple(sorted(transitions, key=lambda row: row.transition_id)),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_exceptional_transitions(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_exception_record(context, source)
    return EXCEPTIONAL_TRANSITION_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def _all_exact_fault_ids(
    context: PhaseContextV3,
    semantic_records: tuple[ArtifactRecordV3, ...],
) -> set[str]:
    result: set[str] = set()
    for source in semantic_records:
        semantic_index = context.typed_record(
            "semantic_index", source.record_id, SEMANTIC_INDEX_CODEC_V3
        ).value
        for fault in semantic_index.faults:
            result.add(
                exceptional_transition_id_v3(
                    semantic_index.record_id, fault.index, fault.fault_sha256
                )
            )
    return result


def check_exceptional_transitions_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    semantic_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in semantic_records),
        "exceptional-transition inventories",
    )
    for source, output in zip(semantic_records, outputs, strict=True):
        expected = _derive_exception_record(context, source)
        submitted = EXCEPTIONAL_TRANSITION_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "exceptional_transition_contradiction",
                f"exceptional transitions for {output.record_id!r} are stale",
                "rerun exceptional-transition analysis from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"exceptional transitions for {output.record_id!r} have stale dependencies",
                "let EXCEPTIONAL_TRANSITIONS_PHASE_V3 attach exact dependencies",
            )
    if context.manifest("exception_evidence").record_count == 0:
        return
    evidence_records = sorted_records(context.records("exception_evidence"))
    known_ids = _all_exact_fault_ids(context, semantic_records)
    unknown = sorted({row.record_id for row in evidence_records} - known_ids)
    if unknown:
        fail(
            "unknown_exception_evidence",
            f"exception evidence names absent exact fault sites {unknown!r}",
            "remove stale evidence or regenerate it from exact fault records",
        )


EXCEPTIONAL_TRANSITIONS_PHASE_V3 = map_units(
    name="exceptional-transitions-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "exception_evidence": EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
    transform=_transform_exceptional_transitions,
    completeness=check_exceptional_transitions_completeness_v3,
)


__all__ = [
    "EXCEPTIONAL_TRANSITION_CODEC_V3",
    "EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA",
    "EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3",
    "EXCEPTIONAL_TRANSITIONS_PHASE_V3",
    "EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3",
    "EXCEPTION_EVIDENCE_CODEC_V3",
    "EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA",
    "EXCEPTION_CLOSURE_CERTIFICATE_V3",
    "LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1",
    "TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1",
    "ExceptionEvidenceV3",
    "ExceptionalTransitionRecordV3",
    "ExceptionalTransitionV3",
    "check_exceptional_transitions_completeness_v3",
    "checked_static_boolean_v3",
    "exception_terminal_profile_sha256_v3",
    "exceptional_transition_id_v3",
]
