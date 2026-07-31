"""Fail-closed semantic coverage over exact relational side ISA inventories."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any
import json
import re

from ..stage_binary import StageAInputError
from ..util import sha256_bytes
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID
from .semantic_coverage_registry import (
    CPUProfile,
    DEFAULT_CPU_PROFILE,
    DEFAULT_SEMANTIC_COVERAGE_REGISTRY,
    EXACT_FORM_QUALIFIABLE_CONSTRUCTORS,
    ExactFormShape,
    RUNTIME_HANDLER_PRECEDENCE,
    RuntimeHandler,
    SemanticCoverageRegistry,
    SemanticDimensionStatus,
    SemanticQualification,
)
from .side_isa_artifact import parse_side_isa_unbound


SEMANTIC_COVERAGE_FORMAT = (
    "stage-a-relational-side-semantic-coverage-v1"
)
SEMANTIC_COVERAGE_STATUS_QUALIFIED = "qualified"
SEMANTIC_COVERAGE_STATUS_BLOCKED = "blocked"

_SIDES = ("original", "candidate")
_SIDE_RANK = {side: index for index, side in enumerate(_SIDES)}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_HEX_RE = re.compile(r"[0-9a-f]+")
_FORM_PREFIX = "StageA.Formal.InstructionSemanticForm."
_FORM_CONSTRUCTOR_RE = re.compile(
    re.escape(_FORM_PREFIX) + r"([A-Za-z][A-Za-z0-9]*)(?=$|[ \n])"
)

_TOP_FIELDS = {
    "format",
    "profile",
    "model",
    "status",
    "cpu_profile",
    "registry",
    "registry_sha256",
    "runtime_handler_precedence",
    "inputs",
    "access_domain_receipts",
    "occurrences",
    "counts",
    "trust",
    "coverage_sha256",
}
_INPUT_FIELDS = {
    "side",
    "binary_sha256",
    "side_isa_sha256",
    "request_sha256",
    "classifier_sha256",
    "extractor_sha256",
    "source_sha256",
}
_OCCURRENCE_FIELDS = {
    "id",
    "side",
    "rva",
    "size",
    "bytes",
    "form",
    "occurrence_refs",
    "runtime_handler",
    "runtime_handler_rule_id",
    "registry_entry_id",
    "qualification",
    "qualification_id",
    "required_features",
    "missing_features",
    "exact_form_shape",
    "state_transition_support",
    "access_fault_domain",
    "relational_discharge",
    "qualification_rationale",
}
_REFERENCE_FIELDS = {
    "region_index",
    "region_id",
    "numeric_id",
    "occurrence_index",
}
_COUNT_FIELDS = {
    "raw_occurrences",
    "deduplicated_occurrences",
    "occurrence_refs",
    "by_side",
    "by_runtime_handler",
    "by_qualification",
    "by_state_transition_support",
    "by_access_fault_domain",
    "by_relational_discharge",
}
_SIDE_COUNT_FIELDS = {"raw_occurrences", "deduplicated_occurrences"}
_TRUST = {
    "role": "untrusted_exact_side_semantic_coverage_classification",
    "proof_authority": False,
    "closes_stage_a_proof": False,
    "fail_closed": True,
    "acceptance_rule": "every deduplicated occurrence must be qualified",
}
_ABSENT_ACCESS_DOMAIN_RECEIPTS = {
    "format": "stage-a-access-domain-receipt-resolution-v1",
    "dimension": "access_fault_domain",
    "input_sha256": None,
    "status": "absent",
    "accepted_receipts": [],
    "diagnostics": [],
    "counts": {
        "provided": 0,
        "accepted": 0,
        "rejected": 0,
        "by_code": {},
    },
    "trust": {
        "role": "derived_access_domain_receipt_application",
        "proof_authority": False,
        "fail_closed": True,
        "affects_dimensions": ["access_fault_domain"],
    },
}

_ROUTE_FRAME_ID = "semcov-route-x87-frame-exact-v1"
_ROUTE_COMMAND_ID = "semcov-route-x87-command-exact-v1"
_ROUTE_ORDINARY_ID = "semcov-route-ordinary-fallback-v1"
_ROUTE_UNREGISTERED_ID = "semcov-route-unregistered-v1"
_Q_UNREGISTERED_ID = "semcov-q-unsupported-unregistered-v1"
_Q_ROUTE_MISMATCH_ID = "semcov-q-unsupported-route-mismatch-v1"
_Q_PROFILE_AMBIGUOUS_ID = "semcov-q-profile-ambiguous-v1"
_Q_EXACT_MEMORY_ID = "semcov-q-state-partial-exact-memory-v1"
_Q_EXACT_STRING_ID = "semcov-q-state-partial-exact-string-memory-v1"
_Q_EXACT_CONTROL_ID = "semcov-q-relational-parametric-exact-control-v1"

_OPERAND32_MEMORY = "StageA.Formal.Operand32SemanticForm.memory"
_OPERAND32_REGISTER = "StageA.Formal.Operand32SemanticForm.register"
_OPERAND8_MEMORY = "StageA.Formal.Operand8SemanticForm.memory"
_OPERAND8_REGISTER = "StageA.Formal.Operand8SemanticForm.register"

_STRING_MEMORY_CONSTRUCTORS = {"moveDwords", "storeDwords"}
_CONTROL_CONSTRUCTORS = {
    "branchCondition",
    "branchEqual",
    "callImport",
    "callIndirect",
    "callRel32",
    "jumpImport",
    "jumpIndirect",
    "jumpRel8",
    "jumpRel32",
    "ret",
    "retPop",
}
_IMPLICIT_MEMORY_CONSTRUCTORS = {
    "atomicCompareExchange",
    "leave",
    "load32",
    "movFs32",
    "popAll",
    "popFlags",
    "popReg",
    "pushAll",
    "pushFlags",
    "pushOperand",
    "pushReg",
    "store32",
}
_STACK_CONTROL_CONSTRUCTORS = {
    "callImport",
    "callIndirect",
    "callRel32",
    "ret",
    "retPop",
}
_PURE_STATE_CONSTRUCTORS = {
    "addZero",
    "bitTestRegister",
    "clearDirection",
    "cmpImm",
    "convertDwordToQuad",
    "convertWordToDword",
    "lea",
    "leaAddress",
    "movRegImm",
    "movRegReg",
    "nop",
    "subZero",
    "zeroReg",
}
_SUPPORTED_STATE_PARTIAL_CONSTRUCTORS = {
    "storeDwords",
    "x87RestoreState",
    "x87SaveState",
}


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    if set(value) != expected:
        raise StageAInputError(f"{context} fields are malformed")


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise StageAInputError(f"{context} must be a nonempty printable string")
    return value


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(
            f"{context} must be 64 lowercase hex characters"
        )
    return value


def _integer(
    value: Any, context: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        suffix = (
            f" and <= {maximum}" if maximum is not None else ""
        )
        raise StageAInputError(
            f"{context} must be an integer >= {minimum}{suffix}"
        )
    return value


def _ordered_strings(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = tuple(
        _string(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    )
    if result != tuple(sorted(set(result))):
        raise StageAInputError(
            f"{context} must be unique and canonically ordered"
        )
    return result


def _canonical_json(value: Any, context: str) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise StageAInputError(f"{context} is not canonical JSON: {exc}") from exc


def _canonical_sha256(value: Any, context: str) -> str:
    return sha256_bytes(_canonical_json(value, context))


def _access_domain_occurrence_key(
    value: Mapping[str, Any],
) -> tuple[str, str, int, int, str, str]:
    return (
        str(value["side"]),
        str(value["binary_sha256"]),
        int(value["rva"]),
        int(value["size"]),
        str(value["bytes"]),
        str(value["semantic_form"]),
    )


def _parse_access_domain_receipt_resolution(value: Any) -> dict[str, Any]:
    if value == _ABSENT_ACCESS_DOMAIN_RECEIPTS:
        return json.loads(json.dumps(_ABSENT_ACCESS_DOMAIN_RECEIPTS))
    from .access_domain_receipts import (
        parse_access_domain_receipt_resolution,
    )

    return parse_access_domain_receipt_resolution(value)


def _form_string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > 65536
        or "\r" in value
        or "\t" in value
        or any(
            ord(character) < 0x20 and character != "\n"
            for character in value
        )
    ):
        raise StageAInputError(f"{context} is not a canonical semantic form")
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for character in value:
        if character in "([{":
            stack.append(character)
        elif character in pairs:
            if not stack or stack.pop() != pairs[character]:
                raise StageAInputError(
                    f"{context} has unbalanced delimiters"
                )
    if stack:
        raise StageAInputError(f"{context} has unbalanced delimiters")
    return value


def semantic_form_constructor(form: str) -> str | None:
    """Return the exact Lean semantic constructor, or ``None`` if unreviewed."""

    checked = _form_string(form, "semantic form")
    matched = _FORM_CONSTRUCTOR_RE.match(checked)
    return matched.group(1) if matched is not None else None


def _form_has_memory_operand(form: str) -> bool:
    return any(
        marker in form
        for marker in (_OPERAND32_MEMORY, _OPERAND8_MEMORY)
    )


def _exact_form_shape(
    constructor: str | None,
    form: str,
    handler: RuntimeHandler,
) -> ExactFormShape:
    if constructor is None:
        return ExactFormShape.UNKNOWN
    if handler is RuntimeHandler.X87_FRAME:
        return ExactFormShape.X87_FRAME
    if handler is RuntimeHandler.X87_COMMAND:
        return ExactFormShape.X87_COMMAND
    if constructor in _STRING_MEMORY_CONSTRUCTORS:
        return ExactFormShape.STRING_MEMORY
    if constructor in _CONTROL_CONSTRUCTORS:
        return ExactFormShape.CONTROL
    if (
        _form_has_memory_operand(form)
        or constructor in _IMPLICIT_MEMORY_CONSTRUCTORS
    ):
        return ExactFormShape.MEMORY
    if _OPERAND32_REGISTER in form or _OPERAND8_REGISTER in form:
        return ExactFormShape.PURE_REGISTER
    if constructor in _PURE_STATE_CONSTRUCTORS:
        return ExactFormShape.PURE_STATE
    return ExactFormShape.UNKNOWN


def _dimension_failure(
    qualification: SemanticQualification,
) -> SemanticDimensionStatus:
    return {
        SemanticQualification.KNOWN_INCORRECT:
            SemanticDimensionStatus.KNOWN_INCORRECT,
        SemanticQualification.PROFILE_AMBIGUOUS:
            SemanticDimensionStatus.PROFILE_AMBIGUOUS,
        SemanticQualification.UNSUPPORTED:
            SemanticDimensionStatus.UNSUPPORTED,
    }[qualification]


def _exact_form_dimensions(
    *,
    constructor: str,
    form: str,
    shape: ExactFormShape,
    handler: RuntimeHandler,
    registry_qualification: SemanticQualification,
) -> tuple[
    SemanticDimensionStatus,
    SemanticDimensionStatus,
    SemanticDimensionStatus,
]:
    if registry_qualification in {
        SemanticQualification.KNOWN_INCORRECT,
        SemanticQualification.PROFILE_AMBIGUOUS,
        SemanticQualification.UNSUPPORTED,
    }:
        failure = _dimension_failure(registry_qualification)
        return failure, failure, failure

    if (
        registry_qualification is SemanticQualification.QUALIFIED
        or constructor in EXACT_FORM_QUALIFIABLE_CONSTRUCTORS
        or constructor in _SUPPORTED_STATE_PARTIAL_CONSTRUCTORS
        or shape is ExactFormShape.CONTROL
    ):
        state_transition = SemanticDimensionStatus.SUPPORTED
    elif handler is RuntimeHandler.X87_COMMAND:
        state_transition = SemanticDimensionStatus.PARAMETRIC
    else:
        state_transition = SemanticDimensionStatus.PARTIAL

    memory_bearing = (
        shape
        in {
            ExactFormShape.MEMORY,
            ExactFormShape.STRING_MEMORY,
            ExactFormShape.X87_FRAME,
        }
        or _form_has_memory_operand(form)
        or constructor in _STACK_CONTROL_CONSTRUCTORS
    )
    access_fault = (
        SemanticDimensionStatus.REQUIRES_PROOF
        if memory_bearing
        else SemanticDimensionStatus.NOT_APPLICABLE
    )

    if handler is RuntimeHandler.X87_COMMAND:
        relational = SemanticDimensionStatus.PARAMETRIC
    elif shape in {
        ExactFormShape.MEMORY,
        ExactFormShape.STRING_MEMORY,
        ExactFormShape.CONTROL,
        ExactFormShape.X87_FRAME,
    }:
        relational = SemanticDimensionStatus.REQUIRES_PROOF
    elif (
        shape is ExactFormShape.PURE_REGISTER
        and constructor in EXACT_FORM_QUALIFIABLE_CONSTRUCTORS
    ):
        relational = SemanticDimensionStatus.COMPLETE
    elif registry_qualification is SemanticQualification.QUALIFIED:
        relational = SemanticDimensionStatus.COMPLETE
    elif (
        registry_qualification
        is SemanticQualification.RELATIONAL_PARAMETRIC
    ):
        relational = SemanticDimensionStatus.PARAMETRIC
    else:
        relational = SemanticDimensionStatus.REQUIRES_PROOF
    return state_transition, access_fault, relational


def _aggregate_exact_qualification(
    *,
    shape: ExactFormShape,
    state_transition: SemanticDimensionStatus,
    access_fault: SemanticDimensionStatus,
    relational: SemanticDimensionStatus,
    entry_qualification: SemanticQualification,
    entry_qualification_id: str,
    entry_rationale: str,
) -> tuple[SemanticQualification, str, str]:
    failures = {state_transition, access_fault, relational}
    if SemanticDimensionStatus.UNSUPPORTED in failures:
        return (
            SemanticQualification.UNSUPPORTED,
            _Q_UNREGISTERED_ID,
            "at least one exact-form semantic dimension is unsupported",
        )
    if SemanticDimensionStatus.PROFILE_AMBIGUOUS in failures:
        return (
            SemanticQualification.PROFILE_AMBIGUOUS,
            _Q_PROFILE_AMBIGUOUS_ID,
            "CPU profile or required feature set is outside the reviewed entry",
        )
    if SemanticDimensionStatus.KNOWN_INCORRECT in failures:
        return (
            SemanticQualification.KNOWN_INCORRECT,
            entry_qualification_id,
            entry_rationale,
        )
    if (
        state_transition is SemanticDimensionStatus.PARTIAL
        or access_fault is SemanticDimensionStatus.REQUIRES_PROOF
    ):
        if shape is ExactFormShape.STRING_MEMORY:
            qualification_id = _Q_EXACT_STRING_ID
        elif shape in {
            ExactFormShape.MEMORY,
            ExactFormShape.X87_FRAME,
            ExactFormShape.X87_COMMAND,
        }:
            qualification_id = _Q_EXACT_MEMORY_ID
        else:
            qualification_id = entry_qualification_id
        return (
            SemanticQualification.STATE_PARTIAL,
            qualification_id,
            "exact form has a checked state transition but still requires "
            "access/fault-domain or state-domain proof",
        )
    if relational in {
        SemanticDimensionStatus.PARAMETRIC,
        SemanticDimensionStatus.REQUIRES_PROOF,
    }:
        return (
            SemanticQualification.RELATIONAL_PARAMETRIC,
            (
                _Q_EXACT_CONTROL_ID
                if shape is ExactFormShape.CONTROL
                else entry_qualification_id
            ),
            "exact form requires a separate relational target, environment, "
            "or shared-semantics discharge",
        )
    if (
        state_transition is SemanticDimensionStatus.SUPPORTED
        and access_fault
        in {
            SemanticDimensionStatus.COMPLETE,
            SemanticDimensionStatus.NOT_APPLICABLE,
        }
        and relational is SemanticDimensionStatus.COMPLETE
    ):
        return (
            SemanticQualification.QUALIFIED,
            entry_qualification_id,
            entry_rationale,
        )
    return (
        entry_qualification,
        entry_qualification_id,
        entry_rationale,
    )


def _x87_frame_operation(encoded: bytes) -> str | None:
    """Mirror ``decodeKernelX87FrameExact`` for a complete occurrence."""

    if len(encoded) < 2 or encoded[0] != 0xDD:
        return None
    modrm = encoded[1]
    mode = modrm >> 6
    group = (modrm >> 3) & 7
    rm = modrm & 7
    if mode == 3 or group not in {4, 6}:
        return None
    cursor = 2
    sib_base: int | None = None
    if rm == 4:
        if cursor >= len(encoded):
            return None
        sib_base = encoded[cursor] & 7
        cursor += 1
    if mode == 0:
        displacement = 4 if rm == 5 or (rm == 4 and sib_base == 5) else 0
    elif mode == 1:
        displacement = 1
    else:
        displacement = 4
    if len(encoded) != cursor + displacement:
        return None
    return "x87SaveState" if group == 6 else "x87RestoreState"


def _has_x87_command_opcode(encoded: bytes) -> bool:
    return encoded == b"\x9b" or (
        len(encoded) >= 2 and 0xD8 <= encoded[0] <= 0xDF
    )


def _runtime_handler(
    constructor: str | None,
    encoded: bytes,
    registry: SemanticCoverageRegistry,
) -> tuple[RuntimeHandler, str]:
    if _x87_frame_operation(encoded) is not None:
        return RuntimeHandler.X87_FRAME, _ROUTE_FRAME_ID
    entry = registry.entry_for(constructor) if constructor is not None else None
    if entry is None:
        return RuntimeHandler.UNSUPPORTED, _ROUTE_UNREGISTERED_ID
    if (
        entry.runtime_handler is RuntimeHandler.X87_COMMAND
        and _has_x87_command_opcode(encoded)
    ):
        return RuntimeHandler.X87_COMMAND, _ROUTE_COMMAND_ID
    return RuntimeHandler.ORDINARY, _ROUTE_ORDINARY_ID


def _classification(
    form: str,
    encoded_hex: str,
    cpu_profile: CPUProfile,
    registry: SemanticCoverageRegistry,
    *,
    access_fault_complete: bool = False,
) -> dict[str, Any]:
    constructor = semantic_form_constructor(form)
    encoded = bytes.fromhex(encoded_hex)
    handler, handler_rule_id = _runtime_handler(
        constructor, encoded, registry
    )
    entry = registry.entry_for(constructor) if constructor is not None else None
    reviewed_profile = registry.cpu_profile_for(cpu_profile.id)
    required_features = entry.required_features if entry is not None else ()
    missing_features = tuple(
        sorted(set(required_features) - set(cpu_profile.features))
    )
    if entry is None:
        base_qualification = SemanticQualification.UNSUPPORTED
        base_qualification_id = _Q_UNREGISTERED_ID
        base_rationale = "semantic form is absent from the reviewed registry"
    elif handler is not entry.runtime_handler:
        base_qualification = SemanticQualification.UNSUPPORTED
        base_qualification_id = _Q_ROUTE_MISMATCH_ID
        base_rationale = (
            "exact bytes take a different runtime route than the registry entry"
        )
    elif (
        cpu_profile.id not in entry.cpu_profile_ids
        or reviewed_profile != cpu_profile
        or missing_features
    ):
        base_qualification = SemanticQualification.PROFILE_AMBIGUOUS
        base_qualification_id = _Q_PROFILE_AMBIGUOUS_ID
        base_rationale = (
            "CPU profile or required feature set is outside the reviewed entry"
        )
    else:
        base_qualification = entry.qualification
        base_qualification_id = entry.qualification_id
        base_rationale = entry.rationale

    shape = _exact_form_shape(constructor, form, handler)
    state_transition, access_fault, relational = _exact_form_dimensions(
        constructor=constructor or "",
        form=form,
        shape=shape,
        handler=handler,
        registry_qualification=base_qualification,
    )
    if (
        access_fault_complete
        and access_fault is SemanticDimensionStatus.REQUIRES_PROOF
    ):
        access_fault = SemanticDimensionStatus.COMPLETE
    if base_qualification in {
        SemanticQualification.KNOWN_INCORRECT,
        SemanticQualification.PROFILE_AMBIGUOUS,
        SemanticQualification.UNSUPPORTED,
    }:
        qualification = base_qualification
        qualification_id = base_qualification_id
        rationale = base_rationale
    else:
        exact_qualification_id = base_qualification_id
        exact_rationale = base_rationale
        if (
            constructor in EXACT_FORM_QUALIFIABLE_CONSTRUCTORS
            and shape is ExactFormShape.PURE_REGISTER
        ):
            slug = re.sub(
                r"([a-z0-9])([A-Z])", r"\1-\2", constructor
            ).lower()
            exact_qualification_id = (
                f"semcov-q-qualified-exact-pure-register-{slug}-v1"
            )
            exact_rationale = (
                "reviewed exact pure-register transition with no memory or "
                "control-flow discharge"
            )
        qualification, qualification_id, rationale = (
            _aggregate_exact_qualification(
                shape=shape,
                state_transition=state_transition,
                access_fault=access_fault,
                relational=relational,
                entry_qualification=base_qualification,
                entry_qualification_id=exact_qualification_id,
                entry_rationale=exact_rationale,
            )
        )
    return {
        "runtime_handler": handler.value,
        "runtime_handler_rule_id": handler_rule_id,
        "registry_entry_id": entry.id if entry is not None else None,
        "qualification": qualification.value,
        "qualification_id": qualification_id,
        "required_features": list(required_features),
        "missing_features": list(missing_features),
        "exact_form_shape": shape.value,
        "state_transition_support": state_transition.value,
        "access_fault_domain": access_fault.value,
        "relational_discharge": relational.value,
        "qualification_rationale": rationale,
    }


def _parse_source_side(
    payload: Any, expected_side: str
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:
    source = _object(payload, f"{expected_side} side ISA artifact")
    binary_sha256 = _sha256(
        source.get("binary_sha256"),
        f"{expected_side} side ISA binary SHA-256",
    )
    classifier_sha256 = _sha256(
        source.get("classifier_sha256"),
        f"{expected_side} side ISA classifier SHA-256",
    )
    extractor_sha256 = _sha256(
        source.get("extractor_sha256"),
        f"{expected_side} side ISA extractor SHA-256",
    )
    source_sha256 = _sha256(
        source.get("source_sha256"),
        f"{expected_side} side ISA source SHA-256",
    )
    request, rows = parse_side_isa_unbound(
        source,
        expected_side=expected_side,
        expected_binary_sha256=binary_sha256,
        classifier_sha256=classifier_sha256,
        extractor_sha256=extractor_sha256,
        source_sha256=source_sha256,
    )
    descriptor = {
        "side": expected_side,
        "binary_sha256": binary_sha256,
        "side_isa_sha256": _canonical_sha256(
            source, f"{expected_side} side ISA artifact"
        ),
        "request_sha256": _sha256(
            source.get("request_sha256"),
            f"{expected_side} side ISA request SHA-256",
        ),
        "classifier_sha256": classifier_sha256,
        "extractor_sha256": extractor_sha256,
        "source_sha256": source_sha256,
    }
    flattened: list[dict[str, Any]] = []
    for region, occurrences in zip(request.regions, rows, strict=True):
        for occurrence_index, occurrence in enumerate(occurrences):
            flattened.append(
                {
                    "side": expected_side,
                    "rva": occurrence["rva"],
                    "size": occurrence["size"],
                    "bytes": occurrence["bytes"],
                    "form": occurrence["form"],
                    "ref": {
                        "region_index": region.index,
                        "region_id": region.id,
                        "numeric_id": region.numeric_id,
                        "occurrence_index": occurrence_index,
                    },
                }
            )
    return descriptor, flattened


def _occurrence_id(side: str, rva: int, encoded: str) -> str:
    digest = _canonical_sha256(
        {"side": side, "rva": rva, "bytes": encoded},
        "semantic coverage occurrence identity",
    )
    return "semantic-coverage-occurrence-" + digest[:24]


def _deduplicate_occurrences(
    rows: list[dict[str, Any]],
    *,
    cpu_profile: CPUProfile,
    registry: SemanticCoverageRegistry,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["side"], row["rva"], row["bytes"])
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = {
                "id": _occurrence_id(*key),
                "side": row["side"],
                "rva": row["rva"],
                "size": row["size"],
                "bytes": row["bytes"],
                "form": row["form"],
                "occurrence_refs": [row["ref"]],
            }
        else:
            if (
                existing["size"] != row["size"]
                or existing["form"] != row["form"]
            ):
                raise StageAInputError(
                    "duplicate semantic coverage occurrence disagrees on "
                    "size or semantic form"
                )
            if row["ref"] in existing["occurrence_refs"]:
                raise StageAInputError(
                    "semantic coverage occurrence reference is duplicated"
                )
            existing["occurrence_refs"].append(row["ref"])
    result: list[dict[str, Any]] = []
    for key in sorted(
        grouped,
        key=lambda item: (_SIDE_RANK[item[0]], item[1], item[2]),
    ):
        row = grouped[key]
        row["occurrence_refs"].sort(
            key=lambda ref: (
                ref["region_index"],
                ref["occurrence_index"],
                ref["region_id"],
                ref["numeric_id"],
            )
        )
        result.append(
            {
                **row,
                **_classification(
                    row["form"], row["bytes"], cpu_profile, registry
                ),
            }
        )
    return result


def _count_payload(
    occurrences: list[dict[str, Any]]
) -> dict[str, Any]:
    handler_counts = Counter(
        row["runtime_handler"] for row in occurrences
    )
    qualification_counts = Counter(
        row["qualification"] for row in occurrences
    )
    state_transition_counts = Counter(
        row["state_transition_support"] for row in occurrences
    )
    access_fault_counts = Counter(
        row["access_fault_domain"] for row in occurrences
    )
    relational_counts = Counter(
        row["relational_discharge"] for row in occurrences
    )
    by_side = {}
    for side in _SIDES:
        side_rows = [row for row in occurrences if row["side"] == side]
        by_side[side] = {
            "raw_occurrences": sum(
                len(row["occurrence_refs"]) for row in side_rows
            ),
            "deduplicated_occurrences": len(side_rows),
        }
    return {
        "raw_occurrences": sum(
            len(row["occurrence_refs"]) for row in occurrences
        ),
        "deduplicated_occurrences": len(occurrences),
        "occurrence_refs": sum(
            len(row["occurrence_refs"]) for row in occurrences
        ),
        "by_side": by_side,
        "by_runtime_handler": {
            handler.value: handler_counts[handler.value]
            for handler in RuntimeHandler
        },
        "by_qualification": {
            qualification.value: qualification_counts[qualification.value]
            for qualification in SemanticQualification
        },
        "by_state_transition_support": {
            status.value: state_transition_counts[status.value]
            for status in SemanticDimensionStatus
        },
        "by_access_fault_domain": {
            status.value: access_fault_counts[status.value]
            for status in SemanticDimensionStatus
        },
        "by_relational_discharge": {
            status.value: relational_counts[status.value]
            for status in SemanticDimensionStatus
        },
    }


def build_semantic_coverage(
    original_side_isa: Any,
    candidate_side_isa: Any,
    *,
    access_domain_receipts: Any | None = None,
    cpu_profile: CPUProfile = DEFAULT_CPU_PROFILE,
    registry: SemanticCoverageRegistry = DEFAULT_SEMANTIC_COVERAGE_REGISTRY,
) -> dict[str, Any]:
    """Classify both exact side inventories and return a canonical artifact."""

    cpu_profile = CPUProfile.parse(cpu_profile.to_payload())
    registry = SemanticCoverageRegistry.parse(registry.to_payload())
    descriptors: list[dict[str, Any]] = []
    source_rows: list[dict[str, Any]] = []
    for side, source in zip(
        _SIDES, (original_side_isa, candidate_side_isa), strict=True
    ):
        descriptor, rows = _parse_source_side(source, side)
        descriptors.append(descriptor)
        source_rows.extend(rows)
    semantic_bindings = {
        (
            descriptor["classifier_sha256"],
            descriptor["extractor_sha256"],
            descriptor["source_sha256"],
        )
        for descriptor in descriptors
    }
    if len(semantic_bindings) != 1:
        raise StageAInputError(
            "side ISA inventories use different semantic classifiers"
        )
    occurrences = _deduplicate_occurrences(
        source_rows, cpu_profile=cpu_profile, registry=registry
    )
    binary_sha256_by_side = {
        descriptor["side"]: descriptor["binary_sha256"]
        for descriptor in descriptors
    }
    if access_domain_receipts is None:
        receipt_resolution = json.loads(
            json.dumps(_ABSENT_ACCESS_DOMAIN_RECEIPTS)
        )
    else:
        from .access_domain_receipts import (
            resolve_access_domain_receipts,
        )

        receipt_resolution = resolve_access_domain_receipts(
            access_domain_receipts,
            occurrences=occurrences,
            binary_sha256_by_side=binary_sha256_by_side,
        )
    accepted_receipt_keys = {
        _access_domain_occurrence_key(receipt)
        for receipt in receipt_resolution["accepted_receipts"]
    }
    occurrences = [
        {
            **{
                field: value
                for field, value in occurrence.items()
                if field
                not in {
                    "runtime_handler",
                    "runtime_handler_rule_id",
                    "registry_entry_id",
                    "qualification",
                    "qualification_id",
                    "required_features",
                    "missing_features",
                    "exact_form_shape",
                    "state_transition_support",
                    "access_fault_domain",
                    "relational_discharge",
                    "qualification_rationale",
                }
            },
            **_classification(
                occurrence["form"],
                occurrence["bytes"],
                cpu_profile,
                registry,
                access_fault_complete=(
                    (
                        occurrence["side"],
                        binary_sha256_by_side[occurrence["side"]],
                        occurrence["rva"],
                        occurrence["size"],
                        occurrence["bytes"],
                        occurrence["form"],
                    )
                    in accepted_receipt_keys
                ),
            ),
        }
        for occurrence in occurrences
    ]
    status = (
        SEMANTIC_COVERAGE_STATUS_QUALIFIED
        if occurrences
        and all(
            row["qualification"] == SemanticQualification.QUALIFIED.value
            for row in occurrences
        )
        else SEMANTIC_COVERAGE_STATUS_BLOCKED
    )
    registry_payload = registry.to_payload()
    body = {
        "format": SEMANTIC_COVERAGE_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": status,
        "cpu_profile": cpu_profile.to_payload(),
        "registry": registry_payload,
        "registry_sha256": _canonical_sha256(
            registry_payload, "semantic coverage registry"
        ),
        "runtime_handler_precedence": list(RUNTIME_HANDLER_PRECEDENCE),
        "inputs": descriptors,
        "access_domain_receipts": receipt_resolution,
        "occurrences": occurrences,
        "counts": _count_payload(occurrences),
        "trust": dict(_TRUST),
    }
    payload = {
        **body,
        "coverage_sha256": _canonical_sha256(
            body, "semantic coverage artifact"
        ),
    }
    parse_semantic_coverage(payload)
    return payload


def _parse_input(value: Any, index: int) -> dict[str, Any]:
    context = f"semantic coverage input {index}"
    payload = _object(value, context)
    _exact_fields(payload, _INPUT_FIELDS, context)
    side = payload["side"]
    if side != _SIDES[index]:
        raise StageAInputError(
            "semantic coverage inputs must be original then candidate"
        )
    return {
        "side": side,
        **{
            field: _sha256(payload[field], f"{context}.{field}")
            for field in _INPUT_FIELDS - {"side"}
        },
    }


def _parse_reference(value: Any, context: str) -> dict[str, Any]:
    payload = _object(value, context)
    _exact_fields(payload, _REFERENCE_FIELDS, context)
    return {
        "region_index": _integer(
            payload["region_index"], f"{context}.region_index"
        ),
        "region_id": _string(payload["region_id"], f"{context}.region_id"),
        "numeric_id": _integer(
            payload["numeric_id"], f"{context}.numeric_id"
        ),
        "occurrence_index": _integer(
            payload["occurrence_index"], f"{context}.occurrence_index"
        ),
    }


def _parse_occurrence(
    value: Any,
    index: int,
    *,
    binary_sha256: str,
    accepted_receipt_keys: set[tuple[str, str, int, int, str, str]],
    cpu_profile: CPUProfile,
    registry: SemanticCoverageRegistry,
) -> dict[str, Any]:
    context = f"semantic coverage occurrence {index}"
    payload = _object(value, context)
    _exact_fields(payload, _OCCURRENCE_FIELDS, context)
    side = payload["side"]
    if side not in _SIDES:
        raise StageAInputError(f"{context}.side is invalid")
    rva = _integer(payload["rva"], f"{context}.rva", maximum=2**32 - 1)
    size = _integer(payload["size"], f"{context}.size", minimum=1, maximum=15)
    encoded = payload["bytes"]
    if (
        not isinstance(encoded, str)
        or len(encoded) != size * 2
        or _HEX_RE.fullmatch(encoded) is None
    ):
        raise StageAInputError(f"{context}.bytes is invalid")
    form = _form_string(payload["form"], f"{context}.form")
    raw_refs = payload["occurrence_refs"]
    if not isinstance(raw_refs, list) or not raw_refs:
        raise StageAInputError(
            f"{context}.occurrence_refs must be a nonempty list"
        )
    refs = [
        _parse_reference(ref, f"{context}.occurrence_refs[{ref_index}]")
        for ref_index, ref in enumerate(raw_refs)
    ]
    reference_keys = [
        (
            ref["region_index"],
            ref["occurrence_index"],
            ref["region_id"],
            ref["numeric_id"],
        )
        for ref in refs
    ]
    if reference_keys != sorted(set(reference_keys)):
        raise StageAInputError(
            f"{context}.occurrence_refs must be unique and ordered"
        )
    receipt_key = (
        side,
        binary_sha256,
        rva,
        size,
        encoded,
        form,
    )
    base_classification = _classification(
        form, encoded, cpu_profile, registry
    )
    if (
        receipt_key in accepted_receipt_keys
        and base_classification["access_fault_domain"] != "requires-proof"
    ):
        raise StageAInputError(
            f"{context} has an access-domain receipt for a dimension "
            "that does not require proof"
        )
    expected_classification = _classification(
        form,
        encoded,
        cpu_profile,
        registry,
        access_fault_complete=receipt_key in accepted_receipt_keys,
    )
    actual_classification = {
        field: payload[field]
        for field in _OCCURRENCE_FIELDS
        - {
            "id",
            "side",
            "rva",
            "size",
            "bytes",
            "form",
            "occurrence_refs",
        }
    }
    if actual_classification != expected_classification:
        raise StageAInputError(
            f"{context} classification does not match reviewed policy"
        )
    expected_id = _occurrence_id(side, rva, encoded)
    if payload["id"] != expected_id:
        raise StageAInputError(f"{context}.id does not match its identity")
    return {
        "id": expected_id,
        "side": side,
        "rva": rva,
        "size": size,
        "bytes": encoded,
        "form": form,
        "occurrence_refs": refs,
        **expected_classification,
    }


def _parse_counts(value: Any, occurrences: list[dict[str, Any]]) -> dict[str, Any]:
    payload = _object(value, "semantic coverage counts")
    _exact_fields(payload, _COUNT_FIELDS, "semantic coverage counts")
    expected = _count_payload(occurrences)
    if payload != expected:
        raise StageAInputError(
            "semantic coverage counts do not match occurrences"
        )
    by_side = _object(
        payload["by_side"], "semantic coverage counts.by_side"
    )
    if set(by_side) != set(_SIDES):
        raise StageAInputError(
            "semantic coverage counts.by_side fields are malformed"
        )
    for side in _SIDES:
        side_counts = _object(
            by_side[side],
            f"semantic coverage counts.by_side.{side}",
        )
        _exact_fields(
            side_counts,
            _SIDE_COUNT_FIELDS,
            f"semantic coverage counts.by_side.{side}",
        )
    return expected


def parse_semantic_coverage(payload: Any) -> dict[str, Any]:
    """Strictly validate a self-contained semantic coverage artifact."""

    artifact = _object(payload, "semantic coverage artifact")
    _exact_fields(artifact, _TOP_FIELDS, "semantic coverage artifact")
    expected_identity = {
        "format": SEMANTIC_COVERAGE_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "runtime_handler_precedence": list(RUNTIME_HANDLER_PRECEDENCE),
        "trust": _TRUST,
    }
    for field, expected in expected_identity.items():
        if artifact[field] != expected:
            raise StageAInputError(
                f"semantic coverage artifact {field} mismatch"
            )
    cpu_profile = CPUProfile.parse(artifact["cpu_profile"])
    registry = SemanticCoverageRegistry.parse(artifact["registry"])
    expected_registry_sha256 = _canonical_sha256(
        registry.to_payload(), "semantic coverage registry"
    )
    if artifact["registry_sha256"] != expected_registry_sha256:
        raise StageAInputError("semantic coverage registry SHA-256 mismatch")
    raw_inputs = artifact["inputs"]
    if not isinstance(raw_inputs, list) or len(raw_inputs) != len(_SIDES):
        raise StageAInputError(
            "semantic coverage inputs must contain exactly two sides"
        )
    inputs = [
        _parse_input(value, index)
        for index, value in enumerate(raw_inputs)
    ]
    binary_sha256_by_side = {
        descriptor["side"]: descriptor["binary_sha256"]
        for descriptor in inputs
    }
    semantic_bindings = {
        (
            descriptor["classifier_sha256"],
            descriptor["extractor_sha256"],
            descriptor["source_sha256"],
        )
        for descriptor in inputs
    }
    if len(semantic_bindings) != 1:
        raise StageAInputError(
            "semantic coverage inputs use different semantic classifiers"
        )
    receipt_resolution = _parse_access_domain_receipt_resolution(
        artifact["access_domain_receipts"]
    )
    accepted_receipt_keys = {
        _access_domain_occurrence_key(receipt)
        for receipt in receipt_resolution["accepted_receipts"]
    }
    raw_occurrences = artifact["occurrences"]
    if not isinstance(raw_occurrences, list) or not raw_occurrences:
        raise StageAInputError(
            "semantic coverage occurrences must be a nonempty list"
        )
    occurrences = [
        _parse_occurrence(
            value,
            index,
            binary_sha256=binary_sha256_by_side.get(
                value.get("side"), ""
            ),
            accepted_receipt_keys=accepted_receipt_keys,
            cpu_profile=cpu_profile,
            registry=registry,
        )
        for index, value in enumerate(raw_occurrences)
    ]
    occurrence_keys = [
        (
            _SIDE_RANK[row["side"]],
            row["rva"],
            row["bytes"],
        )
        for row in occurrences
    ]
    if occurrence_keys != sorted(set(occurrence_keys)):
        raise StageAInputError(
            "semantic coverage occurrences must be deduplicated and ordered"
        )
    parsed_receipt_keys = {
        (
            row["side"],
            binary_sha256_by_side[row["side"]],
            row["rva"],
            row["size"],
            row["bytes"],
            row["form"],
        )
        for row in occurrences
        if (
            row["side"],
            binary_sha256_by_side[row["side"]],
            row["rva"],
            row["size"],
            row["bytes"],
            row["form"],
        )
        in accepted_receipt_keys
    }
    if parsed_receipt_keys != accepted_receipt_keys:
        raise StageAInputError(
            "accepted access-domain receipt does not bind an exact occurrence"
        )
    counts = _parse_counts(artifact["counts"], occurrences)
    expected_status = (
        SEMANTIC_COVERAGE_STATUS_QUALIFIED
        if all(
            row["qualification"] == SemanticQualification.QUALIFIED.value
            for row in occurrences
        )
        else SEMANTIC_COVERAGE_STATUS_BLOCKED
    )
    if artifact["status"] != expected_status:
        raise StageAInputError(
            "semantic coverage status does not match qualifications"
        )
    body = {
        field: artifact[field]
        for field in _TOP_FIELDS - {"coverage_sha256"}
    }
    expected_coverage_sha256 = _canonical_sha256(
        body, "semantic coverage artifact"
    )
    if artifact["coverage_sha256"] != expected_coverage_sha256:
        raise StageAInputError("semantic coverage artifact SHA-256 mismatch")
    return {
        **body,
        "counts": counts,
        "coverage_sha256": expected_coverage_sha256,
    }


def validate_semantic_coverage(
    payload: Any,
    *,
    original_side_isa: Any,
    candidate_side_isa: Any,
    access_domain_receipts: Any | None = None,
    expected_cpu_profile: CPUProfile = DEFAULT_CPU_PROFILE,
    registry: SemanticCoverageRegistry = DEFAULT_SEMANTIC_COVERAGE_REGISTRY,
) -> dict[str, Any]:
    """Rebuild an artifact from its exact source inventories and compare it."""

    parsed = parse_semantic_coverage(payload)
    expected_cpu_profile = CPUProfile.parse(expected_cpu_profile.to_payload())
    registry = SemanticCoverageRegistry.parse(registry.to_payload())
    if parsed["cpu_profile"] != expected_cpu_profile.to_payload():
        raise StageAInputError("semantic coverage CPU profile mismatch")
    if parsed["registry"] != registry.to_payload():
        raise StageAInputError("semantic coverage reviewed registry mismatch")
    expected = build_semantic_coverage(
        original_side_isa,
        candidate_side_isa,
        access_domain_receipts=access_domain_receipts,
        cpu_profile=expected_cpu_profile,
        registry=registry,
    )
    if parsed != expected:
        raise StageAInputError(
            "semantic coverage artifact does not reproduce exact side inventories"
        )
    return parsed


semantic_coverage_payload = build_semantic_coverage
side_semantic_coverage_payload = build_semantic_coverage
parse_side_semantic_coverage = parse_semantic_coverage
validate_side_semantic_coverage = validate_semantic_coverage


__all__ = [
    "SEMANTIC_COVERAGE_FORMAT",
    "SEMANTIC_COVERAGE_STATUS_BLOCKED",
    "SEMANTIC_COVERAGE_STATUS_QUALIFIED",
    "build_semantic_coverage",
    "parse_semantic_coverage",
    "parse_side_semantic_coverage",
    "semantic_coverage_payload",
    "semantic_form_constructor",
    "side_semantic_coverage_payload",
    "validate_semantic_coverage",
    "validate_side_semantic_coverage",
]
