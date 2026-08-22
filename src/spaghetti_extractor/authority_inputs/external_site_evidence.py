"""Generate fail-closed external-site evidence from native v3 authority inputs.

The generator is intentionally conservative.  It selects exactly one checked
profile for the canonical call identity, preserves that profile's complete
machine-effect contract, and requires exact event-side argument expressions.
Control-only disposition bindings are treated as extraction provenance rather
than confused with the semantic environment profile.  The canonical
external-site phase remains the authority checker and replays every binding in
the emitted record.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..authority._schema import AnalysisV3Error, mapping
from ..authority.authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
)
from ..authority.external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_PROFILE_ISSUE_CODEC_V3,
    EXTERNAL_PROFILE_ISSUE_RECORD_V3_SCHEMA,
    EXTERNAL_PROFILE_RECORD_V3_SCHEMA,
    EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
    EXTERNAL_SITE_EVIDENCE_CODEC_V3,
    CallbackRequirementV3,
    CallbackSourceDecisionV3,
    ExternalCallArityV3,
    ExternalCallbackSourceV3,
    ExternalContractV3,
    ExternalProfileIssueV3,
    ExternalProfileV3,
    ExternalSiteEvidenceV3,
    callback_requirement_order_key_v3,
    external_site_id_v3,
)
from ..authority.external_abi import (
    ExternalArgumentRecoveryV3Error,
    recover_external_arguments_v3,
)
from ..authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
)
from ..authority.static_value_records import (
    PE32_STATIC_IMAGE_CODEC_V3,
    PE32_STATIC_IMAGE_RECORD_V3_SCHEMA,
    STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
    PE32StaticImageV3,
)
from ..authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
)
from ..authority.transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)
from ..artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetManifestV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..artifacts.io import (
    ArtifactInputReaderV3,
    open_artifact_reader_v3,
)
from ..external.callback_protocols import (
    callback_lifetime_identity,
    callback_protocol_from_machine_contract,
)
from ..authority_inputs.control_disposition import CONTROL_DISPOSITION_PROFILE_ID


_EFFECT_INVENTORIES = (
    "memory_footprints",
    "out_interface_relations",
    "out_pointer_relations",
    "result_register_relations",
)
_CALLBACK_SOURCE_VALUE_LIMIT = 32


class StandardExternalSiteEvidenceV3Error(ValueError):
    """The exact inputs cannot be reconciled into one evidence artifact."""


@dataclass(frozen=True)
class ExternalCallbackDerivationContextV3:
    """Late, exact inputs available to callback-requirement derivation."""

    source_unit_id: str
    source_event_index: int
    ordered_events: tuple[CanonicalValueV3, ...]
    image_base: int
    size_of_image: int
    semantic_units_by_rva: tuple[tuple[int, int, str], ...]
    incoming_call_frames: tuple["ExternalCallbackCallFrameV3", ...] = ()


@dataclass(frozen=True)
class ExternalCallbackCallFrameV3:
    """Exact caller state at one internal call into an external thunk."""

    source_unit_id: str
    source_event_index: int
    event: CanonicalValueV3
    ordered_events: tuple[CanonicalValueV3, ...]


@dataclass(frozen=True)
class _CallbackSourceValues:
    status: str
    values: tuple[int, ...] = ()


@dataclass(frozen=True)
class _ProfileIndex:
    exact: Mapping[tuple[str, str, bytes], ExternalProfileV3]
    by_identity: Mapping[bytes, tuple[ExternalProfileV3, ...]]
    issues_exact: Mapping[tuple[str, str, bytes], ExternalProfileIssueV3]
    issues_by_identity: Mapping[bytes, tuple[ExternalProfileIssueV3, ...]]


def _require_kind(reader: ArtifactInputReaderV3, expected: str, label: str) -> None:
    actual = reader.manifest.artifact_kind
    if actual != expected:
        raise StandardExternalSiteEvidenceV3Error(
            f"{label} has artifact kind {actual!r}, expected {expected!r}"
        )


def _binary_binding(reader: ArtifactInputReaderV3, label: str) -> ArtifactBindingV3:
    bindings = tuple(
        row
        for row in reader.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(bindings) != 1:
        raise StandardExternalSiteEvidenceV3Error(
            f"{label} must contain exactly one binary/pe32 binding"
        )
    return bindings[0]


def _dependency(name: str, reader: ArtifactInputReaderV3) -> ArtifactDependencyV3:
    return ArtifactDependencyV3(
        name=name,
        artifact_kind=reader.manifest.artifact_kind,
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
    )


def _input_status_blocker(
    reader: ArtifactInputReaderV3, *, code: str
) -> PrimaryBlockerV3 | None:
    if reader.manifest.status == "complete":
        return None
    return PrimaryBlockerV3(
        "violated" if reader.manifest.status == "violated" else "incomplete",
        code,
    )


def _identity(target: Mapping[str, Any]) -> Mapping[str, Any] | None:
    imported = target.get("import")
    candidate = imported if isinstance(imported, Mapping) else target
    dll = candidate.get("dll")
    symbol = candidate.get("symbol")
    ordinal = candidate.get("ordinal")
    if isinstance(dll, str) and dll:
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
        if has_symbol != has_ordinal:
            return {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if has_symbol else None,
                "ordinal": ordinal if has_ordinal else None,
            }
    protocol = target.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return {"kind": "protocol", "protocol": dict(protocol)}
    return None


def _profile_binding_candidates(
    event: Mapping[str, Any], target: Mapping[str, Any]
) -> tuple[Any, ...]:
    result: list[Any] = []
    abi = event.get("abi_contract")
    if isinstance(abi, Mapping) and "profile_binding" in abi:
        result.append(abi["profile_binding"])
    if "profile_binding" in target:
        result.append(target["profile_binding"])
    protocol = target.get("external_protocol")
    if isinstance(protocol, Mapping) and "profile_binding" in protocol:
        result.append(protocol["profile_binding"])
    return tuple(result)


def _parse_profile_binding(
    event: Mapping[str, Any], target: Mapping[str, Any]
) -> tuple[tuple[str, str] | None, PrimaryBlockerV3 | None]:
    candidates = _profile_binding_candidates(event, target)
    if not candidates:
        return None, None
    normalized: list[tuple[str, str]] = []
    for raw in candidates:
        if not isinstance(raw, Mapping):
            return None, PrimaryBlockerV3(
                "violated", "external_profile_binding_malformed"
            )
        profile_id = raw.get("profile_id")
        profile_sha256 = raw.get("profile_sha256")
        if not isinstance(profile_id, str) or not profile_id:
            return None, PrimaryBlockerV3(
                "incomplete", "external_profile_id_missing"
            )
        if (
            not isinstance(profile_sha256, str)
            or len(profile_sha256) != 64
            or any(character not in "0123456789abcdef" for character in profile_sha256)
        ):
            return None, PrimaryBlockerV3(
                "incomplete", "external_profile_sha256_missing"
            )
        normalized.append((profile_id, profile_sha256))
    if len(set(normalized)) != 1:
        return None, PrimaryBlockerV3(
            "violated", "external_profile_binding_contradiction"
        )
    return normalized[0], None


def _required_list(
    value: Mapping[str, Any], field: str, *, prefix: str
) -> tuple[list[Any] | None, PrimaryBlockerV3 | None]:
    if field not in value:
        return None, PrimaryBlockerV3("incomplete", f"{prefix}_{field}_missing")
    raw = value[field]
    if not isinstance(raw, list):
        return None, PrimaryBlockerV3("violated", f"{prefix}_{field}_malformed")
    return raw, None


def _required_text(
    value: Mapping[str, Any], field: str, *, prefix: str
) -> tuple[str | None, PrimaryBlockerV3 | None]:
    if field not in value:
        return None, PrimaryBlockerV3("incomplete", f"{prefix}_{field}_missing")
    raw = value[field]
    if not isinstance(raw, str) or not raw:
        return None, PrimaryBlockerV3("violated", f"{prefix}_{field}_malformed")
    return raw, None


def _abi_template(
    abi: Mapping[str, Any]
) -> tuple[str | None, PrimaryBlockerV3 | None]:
    values = [abi[field] for field in ("template", "abi_template") if field in abi]
    if not values:
        return None, PrimaryBlockerV3("incomplete", "external_abi_template_missing")
    if any(not isinstance(value, str) or not value for value in values):
        return None, PrimaryBlockerV3("violated", "external_abi_template_malformed")
    if len(set(values)) != 1:
        return None, PrimaryBlockerV3(
            "violated", "external_abi_template_contradiction"
        )
    return str(values[0]), None


def derive_exact_callback_requirement_rows_v3(
    event: Mapping[str, Any],
    *,
    context: ExternalCallbackDerivationContextV3,
    callback_values: Sequence[int] = (),
    callback_abi: Mapping[str, Any] | None = None,
    callback_lifetime: str | None = None,
) -> list[Any] | None:
    """Return explicit requirements or derive them from exact callback VAs."""

    raw = event.get("callback_requirements")
    if raw is not None:
        return raw if isinstance(raw, list) else None
    if (
        not callback_values
        or not isinstance(callback_abi, Mapping)
        or not isinstance(callback_lifetime, str)
        or not callback_lifetime
    ):
        return None
    abi_sha256 = canonical_sha256_v3(callback_abi)
    result: list[dict[str, Any]] = []
    for value in sorted(set(callback_values)):
        if not context.image_base <= value < context.image_base + context.size_of_image:
            return None
        target_rva = value - context.image_base
        matches = tuple(
            unit_id
            for rva_start, _rva_end, unit_id in context.semantic_units_by_rva
            if rva_start == target_rva
        )
        if len(matches) != 1:
            return None
        result.append(
            {
                "target_unit_id": matches[0],
                "target_rva": target_rva,
                "abi_sha256": abi_sha256,
                "lifetime": callback_lifetime,
            }
        )
    return result


def _callbacks(
    event: Mapping[str, Any],
    *,
    site_id: str,
    callback_effect: str,
    derivation_context: ExternalCallbackDerivationContextV3,
    callback_values: Sequence[int] = (),
    profile_machine: Mapping[str, Any] | None = None,
) -> tuple[tuple[CallbackRequirementV3, ...], PrimaryBlockerV3 | None]:
    machine = {} if profile_machine is None else profile_machine
    protocol = callback_protocol_from_machine_contract(
        machine, context="external callback machine contract"
    )
    protocol_abi = None if protocol is None else protocol.signature.to_payload()
    protocol_lifetime = (
        None if protocol is None else callback_lifetime_identity(protocol)
    )
    raw = derive_exact_callback_requirement_rows_v3(
        event,
        context=derivation_context,
        callback_values=callback_values,
        callback_abi=(
            protocol_abi
            if protocol_abi is not None
            else machine.get("callback_abi")
            if isinstance(machine.get("callback_abi"), Mapping)
            else None
        ),
        callback_lifetime=(
            protocol_lifetime
            if protocol_lifetime is not None
            else machine.get("callback_lifetime")
            if isinstance(machine.get("callback_lifetime"), str)
            else None
        ),
    )
    if raw is None:
        return (), PrimaryBlockerV3(
            "incomplete", "external_callback_requirements_missing"
        )
    callbacks: list[CallbackRequirementV3] = []
    try:
        for ordinal, value in enumerate(raw):
            if not isinstance(value, Mapping):
                return (), PrimaryBlockerV3(
                    "violated", "external_callback_requirement_malformed"
                )
            required = {
                "target_unit_id",
                "target_rva",
                "abi_sha256",
                "lifetime",
            }
            if set(value) != required:
                missing = required - set(value)
                return (), PrimaryBlockerV3(
                    "incomplete" if missing else "violated",
                    (
                        "external_callback_requirement_missing"
                        if missing
                        else "external_callback_requirement_malformed"
                    ),
                )
            callbacks.append(
                CallbackRequirementV3.create(
                    site_id=site_id,
                    ordinal=ordinal,
                    target_unit_id=value["target_unit_id"],
                    target_rva=value["target_rva"],
                    abi_sha256=value["abi_sha256"],
                    lifetime=value["lifetime"],
                )
            )
    except (AnalysisV3Error, TypeError, ValueError):
        return (), PrimaryBlockerV3(
            "violated", "external_callback_requirement_malformed"
        )
    result = tuple(
        sorted(set(callbacks), key=callback_requirement_order_key_v3)
    )
    callback_abi = protocol_abi or machine.get("callback_abi")
    callback_lifetime = protocol_lifetime or machine.get("callback_lifetime")
    if result and isinstance(callback_abi, Mapping):
        expected_abi_sha256 = canonical_sha256_v3(callback_abi)
        if any(row.abi_sha256 != expected_abi_sha256 for row in result):
            return (), PrimaryBlockerV3(
                "violated", "external_callback_requirement_contradiction"
            )
    if result and isinstance(callback_lifetime, str) and any(
        row.lifetime != callback_lifetime for row in result
    ):
        return (), PrimaryBlockerV3(
            "violated", "external_callback_requirement_contradiction"
        )
    if callback_values and {
        derivation_context.image_base + row.target_rva for row in result
    } != set(callback_values):
        return (), PrimaryBlockerV3(
            "violated", "external_callback_source_contradiction"
        )
    if callback_effect == "none" and result:
        return (), PrimaryBlockerV3(
            "violated", "external_callback_effect_contradiction"
        )
    if callback_effect == "registers" and not result:
        return (), PrimaryBlockerV3(
            "incomplete", "external_callback_requirement_missing"
        )
    return result, None


def _callback_values(
    status: str, values: Sequence[int] = ()
) -> _CallbackSourceValues:
    normalized = tuple(sorted(set(values)))
    if len(normalized) > _CALLBACK_SOURCE_VALUE_LIMIT:
        return _CallbackSourceValues("incomplete")
    return _CallbackSourceValues(status, normalized if status == "complete" else ())


def _expression_arguments(expression: Mapping[str, Any]) -> tuple[Any, ...] | None:
    arguments = expression.get("args")
    if isinstance(arguments, Sequence) and not isinstance(arguments, (str, bytes)):
        return tuple(arguments)
    if "left" in expression and "right" in expression:
        return (expression["left"], expression["right"])
    return None


def _submask_values(mask: int) -> _CallbackSourceValues:
    bits = tuple(index for index in range(32) if mask & (1 << index))
    if 1 << len(bits) > _CALLBACK_SOURCE_VALUE_LIMIT:
        return _CallbackSourceValues("incomplete")
    return _callback_values(
        "complete",
        (
            sum(
                1 << bit
                for ordinal, bit in enumerate(bits)
                if subset & (1 << ordinal)
            )
            for subset in range(1 << len(bits))
        ),
    )


def _apply_binary_callback_operation(
    operation: str,
    left: _CallbackSourceValues,
    right: _CallbackSourceValues,
) -> _CallbackSourceValues:
    if "violated" in {left.status, right.status}:
        return _CallbackSourceValues("violated")
    if operation == "and" and left.status != right.status:
        finite = right if right.status == "complete" else left
        unknown = left if left.status != "complete" else right
        if unknown.status == "incomplete" and finite.status == "complete":
            result: set[int] = set()
            for mask in finite.values:
                values = _submask_values(mask)
                if values.status != "complete":
                    return values
                result.update(values.values)
                if len(result) > _CALLBACK_SOURCE_VALUE_LIMIT:
                    return _CallbackSourceValues("incomplete")
            return _callback_values("complete", result)
    if left.status != "complete" or right.status != "complete":
        return _CallbackSourceValues("incomplete")
    if len(left.values) * len(right.values) > _CALLBACK_SOURCE_VALUE_LIMIT**2:
        return _CallbackSourceValues("incomplete")
    operations = {
        "and": lambda first, second: first & second,
        "or": lambda first, second: first | second,
        "xor": lambda first, second: first ^ second,
        "add": lambda first, second: first + second,
        "sub": lambda first, second: first - second,
        "mul": lambda first, second: first * second,
        "lshr": lambda first, second: first >> (second & 31),
        "shl": lambda first, second: first << (second & 31),
        "eq": lambda first, second: int(first == second),
        "ult": lambda first, second: int(first < second),
        "ule": lambda first, second: int(first <= second),
    }
    function = operations[operation]
    return _callback_values(
        "complete",
        (
            function(first, second) & 0xFFFF_FFFF
            for first in left.values
            for second in right.values
        ),
    )


def _callback_expression_values(
    expression: Any,
    *,
    event: Mapping[str, Any],
    resolving_registers: frozenset[str] = frozenset(),
) -> _CallbackSourceValues:
    if not isinstance(expression, Mapping):
        return _CallbackSourceValues("violated")
    raw_operation = expression.get("op")
    if not isinstance(raw_operation, str) or not raw_operation:
        return _CallbackSourceValues("violated")
    operation = raw_operation.lower()
    if operation in {"const", "constant"}:
        value = expression.get("value")
        width = expression.get("width", 32)
        if (
            width != 32
            or not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0xFFFF_FFFF
        ):
            return _CallbackSourceValues("violated")
        return _callback_values("complete", (value,))
    if operation in {"reg", "register", "input_reg"}:
        name = expression.get("name", expression.get("reg"))
        if (
            expression.get("width", 32) != 32
            or not isinstance(name, str)
            or not name
        ):
            return _CallbackSourceValues("violated")
        normalized_name = name.lower()
        register_inputs = event.get("register_inputs")
        if register_inputs is None:
            return _CallbackSourceValues("incomplete")
        if not isinstance(register_inputs, Mapping):
            return _CallbackSourceValues("violated")
        if normalized_name not in register_inputs:
            return _CallbackSourceValues("incomplete")
        origin = register_inputs[normalized_name]
        if not isinstance(origin, Mapping):
            return _CallbackSourceValues("violated")
        if normalized_name in resolving_registers:
            return _CallbackSourceValues("incomplete")
        return _callback_expression_values(
            origin,
            event=event,
            resolving_registers=resolving_registers | {normalized_name},
        )
    if operation in {"true", "false"}:
        return _callback_values("complete", (int(operation == "true"),))

    arguments = _expression_arguments(expression)
    if operation == "ite":
        if arguments is None or len(arguments) != 3:
            return _CallbackSourceValues("violated")
        condition = _callback_expression_values(
            arguments[0],
            event=event,
            resolving_registers=resolving_registers,
        )
        if condition.status == "violated":
            return condition
        selected = (
            (arguments[2],)
            if condition.status == "complete" and not any(condition.values)
            else (
                (arguments[1],)
                if condition.status == "complete" and all(condition.values)
                else arguments[1:]
            )
        )
        alternatives = tuple(
            _callback_expression_values(
                value,
                event=event,
                resolving_registers=resolving_registers,
            )
            for value in selected
        )
        if any(value.status == "violated" for value in alternatives):
            return _CallbackSourceValues("violated")
        if any(value.status != "complete" for value in alternatives):
            return _CallbackSourceValues("incomplete")
        return _callback_values(
            "complete", (item for value in alternatives for item in value.values)
        )

    unary = {
        "neg": lambda value: -value,
        "neg32": lambda value: -value,
        "not32": lambda value: ~value,
        "bit_not": lambda value: ~value,
    }
    if operation in unary:
        if arguments is None or len(arguments) != 1:
            return _CallbackSourceValues("violated")
        values = _callback_expression_values(
            arguments[0],
            event=event,
            resolving_registers=resolving_registers,
        )
        if values.status != "complete":
            return values
        return _callback_values(
            "complete", (unary[operation](value) & 0xFFFF_FFFF for value in values.values)
        )
    if operation in {"zero_extend", "zext", "truncate"}:
        if arguments is None or len(arguments) != 1:
            return _CallbackSourceValues("violated")
        width = expression.get("width", expression.get("width_bits", 32))
        if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 32:
            return _CallbackSourceValues("violated")
        values = _callback_expression_values(
            arguments[0],
            event=event,
            resolving_registers=resolving_registers,
        )
        if values.status != "complete":
            return values
        mask = (1 << width) - 1 if width < 32 else 0xFFFF_FFFF
        return _callback_values("complete", (value & mask for value in values.values))

    binary_aliases = {
        "and": "and", "and32": "and", "bit_and": "and",
        "or": "or", "or32": "or", "bit_or": "or",
        "xor": "xor", "xor32": "xor", "bit_xor": "xor",
        "add": "add", "add32": "add",
        "sub": "sub", "sub32": "sub",
        "mul": "mul", "mul32": "mul", "multiply": "mul",
        "lshr": "lshr", "lshr32": "lshr",
        "shl": "shl", "shl32": "shl",
        "eq": "eq", "eq32": "eq", "equal": "eq",
        "ult": "ult", "ult32": "ult", "unsigned_less": "ult",
        "unsigned_lt": "ult",
        "ule": "ule", "ule32": "ule", "unsigned_less_equal": "ule",
        "unsigned_le": "ule",
    }
    canonical = binary_aliases.get(operation)
    if canonical is None:
        return _CallbackSourceValues("incomplete")
    if arguments is None or len(arguments) < 2:
        return _CallbackSourceValues("violated")
    if canonical in {"sub", "lshr", "shl", "eq", "ult", "ule"} and len(arguments) != 2:
        return _CallbackSourceValues("violated")
    result = _callback_expression_values(
        arguments[0],
        event=event,
        resolving_registers=resolving_registers,
    )
    for argument in arguments[1:]:
        result = _apply_binary_callback_operation(
            canonical,
            result,
            _callback_expression_values(
                argument,
                event=event,
                resolving_registers=resolving_registers,
            ),
        )
        if result.status == "violated":
            break
    return result


def _stack_callback_source_values(
    event: Mapping[str, Any],
    argument_index: int,
    ordered_events: Sequence[Mapping[str, Any]] = (),
) -> _CallbackSourceValues | None:
    stack_inputs = event.get("stack_inputs")
    if stack_inputs is not None and not isinstance(stack_inputs, list):
        return _CallbackSourceValues("violated")
    abi = event.get("abi_contract")
    base_offset: Any = None
    if isinstance(abi, Mapping):
        base_offset = abi.get("argument_base_offset")
    if base_offset is None:
        base_offset = 4 if event.get("kind") in {"external_jump", "indirect_jump"} else 0
    if (
        not isinstance(base_offset, int)
        or isinstance(base_offset, bool)
        or not 0 <= base_offset <= 0xFFFF_FFFF
    ):
        return _CallbackSourceValues("violated")
    expected_offset = base_offset + argument_index * 4
    matches: list[Mapping[str, Any]] = []
    for raw in stack_inputs or ():
        if not isinstance(raw, Mapping):
            return _CallbackSourceValues("violated")
        offset = raw.get("offset")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            return _CallbackSourceValues("violated")
        if offset == expected_offset:
            matches.append(raw)
    ordered = _ordered_stack_callback_source_values(
        event,
        expected_offset=expected_offset,
        ordered_events=ordered_events,
    )
    if ordered is not None:
        if ordered.status != "complete":
            return ordered
        matches.append(
            {
                "offset": expected_offset,
                "width": 4,
                "value": {
                    "op": "finite_callback_values",
                    "values": list(ordered.values),
                },
            }
        )
    if not matches:
        return None
    combined: set[int] | None = None
    for row in matches:
        if row.get("width") != 4 or not isinstance(row.get("value"), Mapping):
            return _CallbackSourceValues("violated")
        raw_value = row["value"]
        if raw_value.get("op") == "finite_callback_values":
            values = raw_value.get("values")
            resolved = (
                _CallbackSourceValues("violated")
                if not isinstance(values, list)
                else _callback_values("complete", values)
            )
        else:
            resolved = _callback_expression_values(raw_value, event=event)
        if resolved.status == "violated":
            return resolved
        if resolved.status != "complete":
            continue
        combined = (
            set(resolved.values)
            if combined is None
            else combined & set(resolved.values)
        )
        if not combined:
            return _CallbackSourceValues("violated")
    return None if combined is None else _callback_values("complete", combined)


def _esp_relative_offset(expression: Any) -> int | None:
    if not isinstance(expression, Mapping):
        return None
    if expression.get("op") in {"reg", "register"} and expression.get("name") == "esp":
        return 0
    operation = expression.get("op")
    if operation not in {"add", "add32", "sub", "sub32"}:
        return None
    arguments = _expression_arguments(expression)
    if arguments is None or len(arguments) != 2:
        return None
    candidates = (
        (arguments, tuple(reversed(arguments)))
        if operation in {"add", "add32"}
        else (arguments,)
    )
    for register, constant in candidates:
        if (
            isinstance(register, Mapping)
            and register.get("op") in {"reg", "register"}
            and register.get("name") == "esp"
            and isinstance(constant, Mapping)
            and constant.get("op") in {"const", "constant"}
        ):
            value = constant.get("value")
            if isinstance(value, int) and not isinstance(value, bool):
                signed = value - (1 << 32) if value & (1 << 31) else value
                return -signed if operation in {"sub", "sub32"} else signed
    return None


def _ordered_stack_callback_source_values(
    event: Mapping[str, Any],
    *,
    expected_offset: int,
    ordered_events: Sequence[Mapping[str, Any]],
) -> _CallbackSourceValues | None:
    register_inputs = event.get("register_inputs")
    event_esp = (
        None
        if not isinstance(register_inputs, Mapping)
        else _esp_relative_offset(register_inputs.get("esp"))
    )
    if event_esp is None:
        return None
    desired_start = event_esp + expected_offset
    desired_end = desired_start + 4
    candidate: _CallbackSourceValues | None = None
    for row in ordered_events:
        if row.get("family") == "external":
            if row.get("instruction_rva") == event.get("instruction_rva"):
                break
            continue
        if row.get("family") != "memory" or row.get("kind") != "write":
            continue
        width = row.get("width")
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            return _CallbackSourceValues("violated")
        address = row.get("address")
        offset = _esp_relative_offset(address)
        if offset is None:
            candidate = _CallbackSourceValues("incomplete")
            continue
        if offset >= desired_end or offset + width <= desired_start:
            continue
        if offset != desired_start or width != 4:
            candidate = _CallbackSourceValues("incomplete")
            continue
        value = row.get("value")
        candidate = _callback_expression_values(value, event=event)
    return candidate


def _resolve_callback_source_values(
    event: Mapping[str, Any],
    *,
    argument_index: int,
    expression: Mapping[str, Any],
    ordered_events: Sequence[Mapping[str, Any]] = (),
    incoming_call_frames: Sequence[ExternalCallbackCallFrameV3] = (),
) -> _CallbackSourceValues:
    candidates = [_callback_expression_values(expression, event=event)]
    stack = _stack_callback_source_values(
        event, argument_index, ordered_events
    )
    if stack is not None:
        candidates.append(stack)
    if any(candidate.status == "violated" for candidate in candidates):
        return _CallbackSourceValues("violated")
    exact = [candidate for candidate in candidates if candidate.status == "complete"]
    incoming_values: set[int] = set()
    if incoming_call_frames:
        for frame in incoming_call_frames:
            caller_event = mapping(
                frame.event.to_value(), "incoming callback call-frame event"
            )
            resolved = _stack_callback_source_values(
                caller_event,
                argument_index,
                tuple(
                    mapping(row.to_value(), "incoming callback ordered event")
                    for row in frame.ordered_events
                ),
            )
            if resolved is None or resolved.status != "complete":
                return (
                    resolved
                    if resolved is not None
                    else _CallbackSourceValues("incomplete")
                )
            incoming_values.update(resolved.values)
            if len(incoming_values) > _CALLBACK_SOURCE_VALUE_LIMIT:
                return _CallbackSourceValues("incomplete")
        exact.append(_callback_values("complete", incoming_values))
    if not exact:
        return _CallbackSourceValues("incomplete")
    values = set(exact[0].values)
    for candidate in exact[1:]:
        values.intersection_update(candidate.values)
        if not values:
            return _CallbackSourceValues("violated")
    return _callback_values("complete", values)


def _is_parametric_entry_stack_word(
    event: Mapping[str, Any], expression: Mapping[str, Any]
) -> bool:
    """Recognize an exact ABI word whose value is supplied by the caller."""

    explicit = event.get("arguments")
    if explicit not in (None, []):
        return False
    return expression.get("op") == "load" and expression.get("width") == 4


def _callback_source_evidence(
    event: Mapping[str, Any],
    *,
    site_id: str,
    callback_effect: str,
    profile_machine: Mapping[str, Any],
    arguments: tuple[dict[str, Any], ...],
    arity: ExternalCallArityV3,
    derivation_context: ExternalCallbackDerivationContextV3,
) -> tuple[
    tuple[CallbackRequirementV3, ...],
    CallbackSourceDecisionV3 | None,
    PrimaryBlockerV3 | None,
]:
    if callback_effect == "none":
        if event.get("callback_requirements") not in (None, []):
            return (), None, PrimaryBlockerV3(
                "violated", "external_callback_effect_contradiction"
            )
        return (), None, None

    protocol = callback_protocol_from_machine_contract(
        profile_machine, context="external callback machine contract"
    )
    if "callback_source" not in profile_machine and (
        protocol is None or protocol.source is None
    ):
        callbacks, blocker = _callbacks(
            event,
            site_id=site_id,
            callback_effect=callback_effect,
            derivation_context=derivation_context,
            profile_machine=profile_machine,
        )
        return callbacks, None, blocker

    try:
        source = ExternalCallbackSourceV3.parse(
            profile_machine,
            argument_words=arity.minimum_words,
        )
    except AnalysisV3Error:
        return (), None, PrimaryBlockerV3(
            "violated", "external_profile_callback_source_malformed"
        )
    if source.kind != "argument_word":
        return (), None, PrimaryBlockerV3(
            "incomplete", "external_callback_source_provenance_missing"
        )
    expression = arguments[source.argument_index]
    source_values = _resolve_callback_source_values(
        event,
        argument_index=source.argument_index,
        expression=expression,
        ordered_events=tuple(
            mapping(row.to_value(), "ordered callback event")
            for row in derivation_context.ordered_events
        ),
        incoming_call_frames=derivation_context.incoming_call_frames,
    )
    if source_values.status == "violated":
        return (), None, PrimaryBlockerV3(
            "violated", "external_callback_source_contradiction"
        )
    if source_values.status != "complete":
        if _is_parametric_entry_stack_word(event, expression):
            return (
                (),
                CallbackSourceDecisionV3.create(
                    kind="parametric_entry_word",
                    argument_index=source.argument_index,
                    source_expression=expression,
                ),
                None,
            )
        return (), None, PrimaryBlockerV3(
            "incomplete", "external_callback_source_provenance_missing"
        )
    sentinel_values = tuple(
        value
        for value in source_values.values
        if value in source.non_callback_sentinel_words
    )
    callback_values = tuple(
        value
        for value in source_values.values
        if value not in source.non_callback_sentinel_words
    )
    if callback_values and sentinel_values or len(sentinel_values) > 1:
        return (), None, PrimaryBlockerV3(
            "incomplete", "external_callback_source_provenance_missing"
        )

    if sentinel_values:
        source_word = sentinel_values[0]
        raw_requirements = event.get("callback_requirements")
        if raw_requirements is not None and not isinstance(raw_requirements, list):
            return (), None, PrimaryBlockerV3(
                "violated", "external_callback_requirement_malformed"
            )
        if raw_requirements:
            return (), None, PrimaryBlockerV3(
                "violated", "external_callback_source_contradiction"
            )
        return (
            (),
            CallbackSourceDecisionV3.create(
                kind="non_callback_sentinel",
                argument_index=source.argument_index,
                source_expression=expression,
                sentinel_word=source_word,
            ),
            None,
        )

    callbacks, blocker = _callbacks(
        event,
        site_id=site_id,
        callback_effect=callback_effect,
        derivation_context=derivation_context,
        callback_values=callback_values,
        profile_machine=profile_machine,
    )
    if blocker is not None:
        return (), None, blocker
    return (
        callbacks,
        CallbackSourceDecisionV3.create(
            kind="callback_target",
            argument_index=source.argument_index,
            source_expression=expression,
        ),
        None,
    )


def _load_profiles(
    reader: ArtifactInputReaderV3,
) -> _ProfileIndex:
    result: dict[tuple[str, str, bytes], ExternalProfileV3] = {}
    by_identity: dict[bytes, list[ExternalProfileV3]] = {}
    issues: dict[tuple[str, str, bytes], ExternalProfileIssueV3] = {}
    issues_by_identity: dict[bytes, list[ExternalProfileIssueV3]] = {}
    for source in reader.iter_records():
        value = source.value.to_value()
        schema = value.get("schema") if isinstance(value, Mapping) else None
        if schema == EXTERNAL_PROFILE_RECORD_V3_SCHEMA:
            profile = EXTERNAL_PROFILE_CODEC_V3.read(source).value
            key = (
                profile.profile_id,
                profile.profile_sha256,
                profile.identity.data,
            )
            if key in result or key in issues:
                raise StandardExternalSiteEvidenceV3Error(
                    "external profile artifact repeats an exact profile binding"
                )
            result[key] = profile
            by_identity.setdefault(profile.identity.data, []).append(profile)
        elif schema == EXTERNAL_PROFILE_ISSUE_RECORD_V3_SCHEMA:
            issue = EXTERNAL_PROFILE_ISSUE_CODEC_V3.read(source).value
            key = (
                issue.profile_id,
                issue.profile_sha256,
                issue.identity.data,
            )
            if key in result or key in issues:
                raise StandardExternalSiteEvidenceV3Error(
                    "external profile artifact repeats an exact profile binding"
                )
            issues[key] = issue
            issues_by_identity.setdefault(issue.identity.data, []).append(issue)
        else:
            raise StandardExternalSiteEvidenceV3Error(
                f"external profile artifact contains unsupported schema {schema!r}"
            )
    return _ProfileIndex(
        exact=result,
        by_identity={
            key: tuple(
                sorted(
                    values,
                    key=lambda row: (
                        row.profile_id,
                        row.profile_sha256,
                        row.record_id,
                    ),
                )
            )
            for key, values in by_identity.items()
        },
        issues_exact=issues,
        issues_by_identity={
            key: tuple(
                sorted(
                    values,
                    key=lambda row: (
                        row.profile_id,
                        row.profile_sha256,
                        row.record_id,
                    ),
                )
            )
            for key, values in issues_by_identity.items()
        },
    )


def _load_static_image(reader: ArtifactInputReaderV3) -> PE32StaticImageV3:
    images: list[PE32StaticImageV3] = []
    for source in reader.iter_records():
        value = source.value.to_value()
        if (
            isinstance(value, Mapping)
            and value.get("schema") == PE32_STATIC_IMAGE_RECORD_V3_SCHEMA
        ):
            images.append(PE32_STATIC_IMAGE_CODEC_V3.read(source).value)
    if len(images) != 1:
        raise StandardExternalSiteEvidenceV3Error(
            "static-value origins must contain exactly one PE32 image context"
        )
    return images[0]


def _select_profile(
    *,
    identity: CanonicalValueV3,
    binding: tuple[str, str] | None,
    profiles: _ProfileIndex,
) -> tuple[
    ExternalProfileV3 | None,
    PrimaryBlockerV3 | None,
    RecordDependencyV3 | None,
]:
    candidates = profiles.by_identity.get(identity.data, ())
    issue_candidates = profiles.issues_by_identity.get(identity.data, ())
    if binding is not None and binding[0] != CONTROL_DISPOSITION_PROFILE_ID:
        key = (binding[0], binding[1], identity.data)
        exact = profiles.exact.get(key)
        issue = profiles.issues_exact.get(key)
        if issue is not None:
            dependency = RecordDependencyV3("external_profiles", issue.record_id)
            return (
                None,
                PrimaryBlockerV3(
                    issue.status,
                    issue.code,
                    dependency.input_name,
                    dependency.record_id,
                ),
                dependency,
            )
        if exact is None:
            return (
                None,
                PrimaryBlockerV3(
                    "violated", "external_profile_binding_contradiction"
                ),
                None,
            )
        dependency = RecordDependencyV3("external_profiles", exact.record_id)
        return exact, None, dependency
    combined_count = len(candidates) + len(issue_candidates)
    if combined_count == 0:
        return (
            None,
            PrimaryBlockerV3("incomplete", "external_profile_missing"),
            None,
        )
    if combined_count != 1:
        return (
            None,
            PrimaryBlockerV3(
                "incomplete", "external_profile_identity_ambiguous"
            ),
            None,
        )
    if issue_candidates:
        issue = issue_candidates[0]
        dependency = RecordDependencyV3("external_profiles", issue.record_id)
        return (
            None,
            PrimaryBlockerV3(
                issue.status,
                issue.code,
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    profile = candidates[0]
    dependency = RecordDependencyV3("external_profiles", profile.record_id)
    return profile, None, dependency


def _site_arity(
    profile: ExternalProfileV3,
    abi: Mapping[str, Any],
) -> tuple[ExternalCallArityV3 | None, tuple[PrimaryBlockerV3, ...]]:
    if profile.arity.kind == "fixed":
        words_raw = (
            profile.arity.words
            if "argument_words" not in abi
            else abi.get("argument_words")
        )
        if (
            not isinstance(words_raw, int)
            or isinstance(words_raw, bool)
            or not 0 <= words_raw <= 256
        ):
            return None, (
                PrimaryBlockerV3("violated", "external_argument_words_malformed"),
            )
        arity = ExternalCallArityV3.fixed(words_raw)
        if arity != profile.arity:
            return None, (
                PrimaryBlockerV3(
                    "violated", "external_profile_contract_contradiction"
                ),
            )
        return arity, ()

    if "argument_words" in abi:
        return None, (
            PrimaryBlockerV3(
                "violated", "external_variadic_exact_arity_contradiction"
            ),
        )
    raw_forwarding = abi.get("raw_caller_stack_suffix_forwarding")
    if raw_forwarding is None:
        return profile.arity, ()
    if not isinstance(raw_forwarding, Mapping):
        return None, (
            PrimaryBlockerV3(
                "violated", "external_variadic_forwarding_malformed"
            ),
        )
    try:
        arity = ExternalCallArityV3.parse(
            {
                "kind": "variadic",
                "minimum_words": profile.minimum_argument_words,
                "raw_caller_stack_suffix_forwarding": dict(raw_forwarding),
            },
            label="external site arity",
        )
    except AnalysisV3Error:
        return None, (
            PrimaryBlockerV3(
                "violated", "external_variadic_forwarding_contradiction"
            ),
        )
    if arity != profile.arity:
        return None, (
            PrimaryBlockerV3(
                "violated", "external_profile_contract_contradiction"
            ),
        )
    return arity, ()


def _recover_arguments_for_arity(
    event: Mapping[str, Any],
    *,
    transfer_kind: str,
    abi_template: str,
    arity: ExternalCallArityV3,
) -> tuple[dict[str, Any], ...]:
    if arity.kind == "fixed":
        return recover_external_arguments_v3(
            event,
            transfer_kind=transfer_kind,
            abi_template=abi_template,
            argument_words=arity.words,
        )
    explicit = event.get("arguments")
    if explicit:
        if not isinstance(explicit, list) or any(
            not isinstance(value, Mapping) for value in explicit
        ):
            raise ExternalArgumentRecoveryV3Error(
                "violated",
                "external_arguments_malformed",
                "explicit variadic prefix arguments are malformed",
            )
        if len(explicit) < arity.minimum_words:
            raise ExternalArgumentRecoveryV3Error(
                "violated",
                "external_argument_inventory_contradiction",
                "explicit variadic arguments omit a required prefix word",
            )
        prefix_event = dict(event)
        prefix_event["arguments"] = list(explicit[: arity.minimum_words])
        event = prefix_event
    return recover_external_arguments_v3(
        event,
        transfer_kind=transfer_kind,
        abi_template=abi_template,
        argument_words=arity.minimum_words,
    )


def _contract(
    *,
    event: Mapping[str, Any],
    target: Mapping[str, Any],
    site_id: str,
    identity: CanonicalValueV3,
    transfer_kind: str,
    profiles: _ProfileIndex,
    profile_reader: ArtifactInputReaderV3,
    callback_derivation_context: ExternalCallbackDerivationContextV3,
) -> tuple[
    ExternalContractV3 | None,
    PrimaryBlockerV3 | None,
    RecordDependencyV3 | None,
]:
    blockers: list[PrimaryBlockerV3] = []
    if profile_reader.manifest.status != "complete":
        return (
            None,
            PrimaryBlockerV3(
                (
                    "violated"
                    if profile_reader.manifest.status == "violated"
                    else "incomplete"
                ),
                "external_profile_artifact_not_complete",
            ),
            None,
        )
    abi_raw = event.get("abi_contract", {})
    if not isinstance(abi_raw, Mapping):
        return None, PrimaryBlockerV3("violated", "external_abi_contract_malformed"), None
    abi = abi_raw

    binding, blocker = _parse_profile_binding(event, target)
    if blocker is not None:
        blockers.append(blocker)

    profile, profile_blocker, profile_dependency = _select_profile(
        identity=identity,
        binding=binding,
        profiles=profiles,
    )
    if profile_blocker is not None:
        return None, profile_blocker, profile_dependency
    assert profile is not None
    assert profile_dependency is not None

    profile_machine = mapping(
        profile.machine_contract.to_value(), "external profile machine contract"
    )

    supplied_template: str | None = None
    if "template" in abi or "abi_template" in abi:
        supplied_template, blocker = _abi_template(abi)
        if blocker is not None:
            blockers.append(blocker)
    profile_template = profile_machine.get("abi_template")
    if not isinstance(profile_template, str) or not profile_template:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_profile_abi_template_missing")
        )
    elif supplied_template is not None and supplied_template != profile_template:
        blockers.append(
            PrimaryBlockerV3("violated", "external_profile_contract_contradiction")
        )

    arity, arity_blockers = _site_arity(profile, abi)
    blockers.extend(arity_blockers)

    arguments: tuple[dict[str, Any], ...] | None = None
    if arity is not None and isinstance(profile_template, str):
        try:
            arguments = _recover_arguments_for_arity(
                event,
                transfer_kind=transfer_kind,
                abi_template=profile_template,
                arity=arity,
            )
        except ExternalArgumentRecoveryV3Error as exc:
            blockers.append(PrimaryBlockerV3(exc.status, exc.code))

    disposition_raw = (
        profile_machine.get("disposition")
        if "disposition" not in abi
        else abi.get("disposition")
    )
    if not isinstance(disposition_raw, str) or not disposition_raw:
        disposition = None
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_disposition_missing")
        )
    else:
        disposition = disposition_raw
    if disposition == "terminates":
        disposition = "noreturn"
    elif disposition is not None and disposition not in {
        "returns",
        "tail_jump",
        "noreturn",
    }:
        blockers.append(
            PrimaryBlockerV3("violated", "external_disposition_unsupported")
        )

    memory_effect = (
        profile.memory_effect
        if "memory_effect" not in abi and profile is not None
        else abi.get("memory_effect")
    )
    world_effect = (
        profile.world_effect
        if "world_effect" not in abi and profile is not None
        else abi.get("world_effect")
    )
    callback_raw = (
        profile.callback_effect
        if "callback_effect" not in abi and profile is not None
        else abi.get("callback_effect")
    )
    if not isinstance(memory_effect, str) or not memory_effect:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_memory_effect_missing")
        )
        memory_effect = None
    if not isinstance(world_effect, str) or not world_effect:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_world_effect_missing")
        )
        world_effect = None
    if not isinstance(callback_raw, str) or not callback_raw:
        blockers.append(
            PrimaryBlockerV3("incomplete", "external_callback_effect_missing")
        )
        callback_raw = None
    callback_effect = (
        None
        if callback_raw is None
        else {
            "explicit": "registers",
            "registers": "registers",
            "none": "none",
        }.get(callback_raw)
    )
    if callback_raw is not None and callback_effect is None:
        blockers.append(
            PrimaryBlockerV3("violated", "external_callback_effect_unsupported")
        )
    if profile is not None:
        for field in _EFFECT_INVENTORIES:
            if field not in abi:
                continue
            inventory = abi[field]
            if not isinstance(inventory, list):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", f"external_{field}_malformed"
                    )
                )
            elif inventory != profile_machine.get(field, []):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "external_profile_contract_contradiction"
                    )
                )

    callbacks: tuple[CallbackRequirementV3, ...] = ()
    callback_source_decision: CallbackSourceDecisionV3 | None = None
    if (
        callback_effect is not None
        and arguments is not None
        and arity is not None
    ):
        callbacks, callback_source_decision, blocker = _callback_source_evidence(
            event,
            site_id=site_id,
            callback_effect=callback_effect,
            profile_machine=profile_machine,
            arguments=arguments,
            arity=arity,
            derivation_context=callback_derivation_context,
        )
        if blocker is not None:
            blockers.append(blocker)

    if profile is not None:
        contradictions = (
            transfer_kind not in profile.allowed_transfers
            or (
                disposition is not None
                and disposition not in profile.allowed_dispositions
            )
            or (arity is not None and arity != profile.arity)
            or (
                memory_effect is not None
                and memory_effect != profile.memory_effect
            )
            or (
                world_effect is not None
                and world_effect != profile.world_effect
            )
            or (
                callback_effect is not None
                and callback_effect != profile.callback_effect
            )
        )
        if contradictions:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "external_profile_contract_contradiction",
                    "external_profiles",
                    profile.record_id,
                )
            )

    primary = aggregate_blockers_v3(blockers)
    if primary is not None:
        return None, primary, profile_dependency
    assert profile is not None
    assert arity is not None
    assert arguments is not None
    assert disposition is not None
    assert memory_effect is not None
    assert world_effect is not None
    assert callback_effect is not None
    return (
        ExternalContractV3.create(
            identity=mapping(identity.to_value(), "external identity"),
            transfer_kind=transfer_kind,
            disposition=disposition,
            profile_id=profile.profile_id,
            profile_sha256=profile.profile_sha256,
            argument_words=arity.exact_words,
            arguments=arguments,
            memory_effect=memory_effect,
            world_effect=world_effect,
            callback_effect=callback_effect,
            machine_contract=mapping(
                profile.machine_contract.to_value(),
                "external profile machine contract",
            ),
            callbacks=callbacks,
            arity=arity,
            callback_source_decision=callback_source_decision,
        ),
        None,
        profile_dependency,
    )


def _site_record(
    *,
    exact: SemanticIndexRecordV3,
    event: Mapping[str, Any],
    event_index: int,
    alternative_index: int,
    target: Mapping[str, Any],
    transfer_kind: str,
    profiles: _ProfileIndex,
    profile_reader: ArtifactInputReaderV3,
    dependencies: Sequence[RecordDependencyV3],
    inherited_blockers: Sequence[PrimaryBlockerV3],
    callback_derivation_context: ExternalCallbackDerivationContextV3,
) -> ArtifactRecordV3:
    event_sha256 = canonical_sha256_v3(event)
    target_sha256 = canonical_sha256_v3(target)
    site_id = external_site_id_v3(
        exact.record_id, event_index, alternative_index, target
    )
    raw_identity = _identity(target)
    if raw_identity is None:
        identity = CanonicalValueV3.of(
            {"kind": "invalid", "target_sha256": target_sha256}
        )
        blockers = [
            *inherited_blockers,
            PrimaryBlockerV3("violated", "external_identity_missing"),
        ]
        contract = None
        profile_dependency = None
    else:
        identity = CanonicalValueV3.of(raw_identity)
        contract, contract_blocker, profile_dependency = _contract(
            event=event,
            target=target,
            site_id=site_id,
            identity=identity,
            transfer_kind=transfer_kind,
            profiles=profiles,
            profile_reader=profile_reader,
            callback_derivation_context=callback_derivation_context,
        )
        blockers = list(inherited_blockers)
        if contract_blocker is not None:
            blockers.append(contract_blocker)
    exact_dependencies = list(dependencies)
    if profile_dependency is not None:
        exact_dependencies.append(profile_dependency)
    primary = aggregate_blockers_v3(blockers)
    if primary is not None:
        contract = None
    evidence = ExternalSiteEvidenceV3(
        record_id=site_id,
        unit_id=exact.record_id,
        unit_sha256=exact.unit_sha256,
        event_index=event_index,
        event_sha256=event_sha256,
        alternative_index=alternative_index,
        target_sha256=target_sha256,
        identity=identity,
        status="complete" if primary is None else primary.status,
        contract=contract,
        primary_blocker=primary,
    )
    return EXTERNAL_SITE_EVIDENCE_CODEC_V3.write(
        evidence.record_id,
        evidence,
        dependencies=tuple(sorted(set(exact_dependencies))),
    )


def _external_events(
    summary: TransitionSummaryRecordV3,
) -> tuple[Mapping[str, Any], ...]:
    result: list[Mapping[str, Any]] = []
    for row in summary.exits:
        if row.source_kind != "external_event":
            continue
        value = row.exact_record.to_value()
        if not isinstance(value, Mapping):
            raise StandardExternalSiteEvidenceV3Error(
                f"transition summary {summary.record_id!r} has a malformed external event"
            )
        result.append(value)
    return tuple(result)


def _indirect_certificate(
    *,
    exact: SemanticIndexRecordV3,
    event_index: int,
    kind: str,
    target_reader: ArtifactInputReaderV3,
) -> IndirectTargetCertificateV3 | None:
    if target_reader.manifest.status == "violated":
        return None
    occurrence: IndirectExitOccurrenceV3 | None = next(
        (
            row
            for row in exact.indirect_exits
            if row.event_index == event_index and row.transfer_kind == kind
        ),
        None,
    )
    if occurrence is None:
        raise StandardExternalSiteEvidenceV3Error(
            f"unit {exact.record_id!r} has no exact indirect occurrence for event {event_index}"
        )
    source = target_reader.find_record(exact.record_id)
    if source is None:
        return None
    unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(source).value
    certificate = next(
        (row for row in unit.certificates if row.exit_id == occurrence.exit_id),
        None,
    )
    if certificate is None or certificate.status != "complete" or not certificate.authorizing:
        return None
    if (
        certificate.source_unit_id != exact.record_id
        or certificate.source_unit_sha256 != exact.unit_sha256
        or certificate.source_rva != exact.rva_start
        or certificate.source_event_index != event_index
        or certificate.transfer_kind != kind
        or certificate.target_expression != occurrence.target_expression
    ):
        raise StandardExternalSiteEvidenceV3Error(
            f"target certificate for {occurrence.exit_id!r} contradicts the semantic index"
        )
    return certificate


def generate_standard_external_site_evidence_v3(
    *,
    semantic_index_path: Path,
    transition_summaries_path: Path,
    target_certificates_path: Path,
    external_profiles_path: Path,
    static_value_origins_path: Path,
    output_directory: Path,
) -> ArtifactSetManifestV3:
    """Emit exact, fail-closed ``external-site-evidence-v3`` records."""

    semantic = open_artifact_reader_v3(semantic_index_path)
    transitions = open_artifact_reader_v3(transition_summaries_path)
    targets = open_artifact_reader_v3(target_certificates_path)
    profiles_reader = open_artifact_reader_v3(external_profiles_path)
    static_values = open_artifact_reader_v3(static_value_origins_path)
    for reader, expected, label in (
        (semantic, SEMANTIC_INDEX_ARTIFACT_KIND_V3, "semantic index"),
        (transitions, TRANSITION_SUMMARIES_ARTIFACT_KIND_V3, "transition summaries"),
        (
            targets,
            INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
            "target certificates",
        ),
        (profiles_reader, EXTERNAL_PROFILE_ARTIFACT_KIND_V3, "external profiles"),
        (
            static_values,
            STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
            "static-value origins",
        ),
    ):
        _require_kind(reader, expected, label)
    bindings = tuple(
        _binary_binding(reader, label)
        for reader, label in (
            (semantic, "semantic index"),
            (transitions, "transition summaries"),
            (targets, "target certificates"),
            (profiles_reader, "external profiles"),
            (static_values, "static-value origins"),
        )
    )
    if len(set(bindings)) != 1:
        raise StandardExternalSiteEvidenceV3Error(
            "external-site evidence inputs bind different PE32 binaries"
        )
    binary_binding = bindings[0]
    profiles = _load_profiles(profiles_reader)
    static_image = _load_static_image(static_values)

    records: list[ArtifactRecordV3] = []
    seen_sites: set[str] = set()
    semantic_status = _input_status_blocker(
        semantic, code="semantic_index_artifact_not_complete"
    )
    transition_status = _input_status_blocker(
        transitions, code="transition_summary_artifact_not_complete"
    )
    semantic_sources = tuple(
        sorted(semantic.iter_records(), key=lambda row: row.record_id)
    )
    semantic_records = tuple(
        SEMANTIC_INDEX_CODEC_V3.read(source).value
        for source in semantic_sources
    )
    semantic_units_by_rva = tuple(
        sorted(
            (row.rva_start, row.rva_end, row.record_id)
            for row in semantic_records
        )
    )
    unit_id_by_rva = {
        row.rva_start: row.record_id for row in semantic_records
    }
    transition_by_unit: dict[str, TransitionSummaryRecordV3] = {}
    incoming_call_frames: dict[str, list[ExternalCallbackCallFrameV3]] = {}
    for exact in semantic_records:
        summary_source = transitions.find_record(exact.record_id)
        if summary_source is None:
            raise StandardExternalSiteEvidenceV3Error(
                f"transition summaries omit semantic unit {exact.record_id!r}"
            )
        summary = TRANSITION_SUMMARY_CODEC_V3.read(summary_source).value
        transition_by_unit[exact.record_id] = summary
        ordered_events = tuple(row.exact_record for row in summary.ordered_events)
        for exit_row in summary.exits:
            if (
                exit_row.source_kind != "external_event"
                or exit_row.source_index is None
                or exit_row.transfer_kind != "internal_call"
            ):
                continue
            event = mapping(
                exit_row.exact_record.to_value(), "exact internal-call event"
            )
            target_rva = event.get("target_rva")
            target_unit_id = (
                unit_id_by_rva.get(target_rva)
                if isinstance(target_rva, int)
                and not isinstance(target_rva, bool)
                else None
            )
            if target_unit_id is None:
                continue
            incoming_call_frames.setdefault(target_unit_id, []).append(
                ExternalCallbackCallFrameV3(
                    source_unit_id=exact.record_id,
                    source_event_index=exit_row.source_index,
                    event=exit_row.exact_record,
                    ordered_events=ordered_events,
                )
            )
    static_image_dependency = RecordDependencyV3(
        "static_value_origins", static_image.record_id
    )
    for exact in semantic_records:
        summary = transition_by_unit[exact.record_id]
        unit_blockers = [
            blocker
            for blocker in (semantic_status, transition_status)
            if blocker is not None
        ]
        if (
            summary.record_id != exact.record_id
            or summary.unit_sha256 != exact.unit_sha256
            or summary.pe_sha256 != exact.pe_sha256
            or summary.unit_ir_sha256 != exact.unit_ir_sha256
        ):
            unit_blockers.append(
                PrimaryBlockerV3(
                    "violated", "transition_summary_unit_contradiction"
                )
            )
        elif summary.status != "complete":
            unit_blockers.append(
                PrimaryBlockerV3("incomplete", "transition_summary_incomplete")
            )
        if exact.unit_status != "qualified":
            unit_blockers.append(
                PrimaryBlockerV3("incomplete", "semantic_unit_not_qualified")
            )
        base_dependencies = (
            RecordDependencyV3("semantic_index", exact.record_id),
            RecordDependencyV3("transition_summaries", exact.record_id),
        )
        for event_index, event in enumerate(_external_events(summary)):
            callback_derivation_context = ExternalCallbackDerivationContextV3(
                source_unit_id=exact.record_id,
                source_event_index=event_index,
                ordered_events=tuple(
                    row.exact_record for row in summary.ordered_events
                ),
                image_base=static_image.image_base,
                size_of_image=static_image.size_of_image,
                semantic_units_by_rva=semantic_units_by_rva,
                incoming_call_frames=tuple(
                    sorted(
                        incoming_call_frames.get(exact.record_id, ()),
                        key=lambda row: (
                            row.source_unit_id,
                            row.source_event_index,
                        ),
                    )
                ),
            )
            kind = event.get("kind")
            alternatives: tuple[tuple[int, Mapping[str, Any]], ...]
            call_frame_dependencies = tuple(
                dependency
                for frame in callback_derivation_context.incoming_call_frames
                for dependency in (
                    RecordDependencyV3("semantic_index", frame.source_unit_id),
                    RecordDependencyV3(
                        "transition_summaries", frame.source_unit_id
                    ),
                )
            )
            dependencies = (
                *base_dependencies,
                static_image_dependency,
                *call_frame_dependencies,
            )
            if kind in {"external_call", "external_jump"}:
                alternatives = ((0, event),)
                transfer_kind = "jump" if kind == "external_jump" else "call"
            elif kind in {"indirect_call", "indirect_jump"}:
                certificate = _indirect_certificate(
                    exact=exact,
                    event_index=event_index,
                    kind=str(kind),
                    target_reader=targets,
                )
                if certificate is None:
                    continue
                alternatives = tuple(
                    (index, mapping(value.to_value(), "external target"))
                    for index, value in enumerate(certificate.external_targets)
                )
                dependencies = (
                    *base_dependencies,
                    static_image_dependency,
                    RecordDependencyV3("target_certificates", exact.record_id),
                )
                transfer_kind = "jump" if kind == "indirect_jump" else "call"
            else:
                continue
            for alternative_index, target in alternatives:
                record = _site_record(
                    exact=exact,
                    event=event,
                    event_index=event_index,
                    alternative_index=alternative_index,
                    target=target,
                    transfer_kind=transfer_kind,
                    profiles=profiles,
                    profile_reader=profiles_reader,
                    dependencies=dependencies,
                    inherited_blockers=unit_blockers,
                    callback_derivation_context=callback_derivation_context,
                )
                if record.record_id in seen_sites:
                    raise StandardExternalSiteEvidenceV3Error(
                        f"external-site identity {record.record_id!r} is duplicated"
                    )
                seen_sites.add(record.record_id)
                records.append(record)

    return ArtifactSetWriterV3(
        artifact_kind=EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(binary_binding,),
        dependencies=(
            _dependency("external_profiles", profiles_reader),
            _dependency("semantic_index", semantic),
            _dependency("static_value_origins", static_values),
            _dependency("target_certificates", targets),
            _dependency("transition_summaries", transitions),
        ),
        # The producer completed even when individual evidence is incomplete.
        # Keeping the artifact complete preserves per-site diagnostics.
        status="complete",
    ).write(output_directory, sorted(records, key=lambda row: row.record_id))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate fail-closed standard external-site evidence for analysis v3"
    )
    parser.add_argument("--semantic-index", type=Path, required=True)
    parser.add_argument("--transition-summaries", type=Path, required=True)
    parser.add_argument("--target-certificates", type=Path, required=True)
    parser.add_argument("--external-profiles", type=Path, required=True)
    parser.add_argument("--static-value-origins", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    generate_standard_external_site_evidence_v3(
        semantic_index_path=arguments.semantic_index,
        transition_summaries_path=arguments.transition_summaries,
        target_certificates_path=arguments.target_certificates,
        external_profiles_path=arguments.external_profiles,
        static_value_origins_path=arguments.static_value_origins,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ExternalCallbackDerivationContextV3",
    "StandardExternalSiteEvidenceV3Error",
    "derive_exact_callback_requirement_rows_v3",
    "generate_standard_external_site_evidence_v3",
    "main",
]
