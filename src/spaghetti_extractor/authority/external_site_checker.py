"""Reconstruct and check canonical external-site authority."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactV3Error,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..artifacts.callback_protocols import (
    callback_lifetime_identity,
    callback_protocol_from_machine_contract,
)
from ..artifacts.io import ArtifactSetReaderV3
from ..artifacts.phases import PhaseContextV3, map_units
from ._schema import (
    digest,
    fail,
    mapping,
    require_record_ids,
    sorted_records,
    stable_id,
    strict_object,
    text,
    uint,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    canonical_dependencies_v3,
    manifest_blocker_v3,
)
from .external_abi import (
    CONTROL_DISPOSITION_PROFILE_ID,
    ExternalArgumentRecoveryV3Error,
    recover_external_arguments_v3,
)
from .external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
    EXTERNAL_SITE_EVIDENCE_CODEC_V3,
    CallbackRequirementV3,
    CallbackSourceDecisionV3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
    ExternalCallArityV3,
    ExternalCallbackSourceV3,
    ExternalContractV3,
    ExternalProfileV3,
    _site_identity_payload,
)
from .identities import indirect_exit_id_v3
from .incoming_call_frames import (
    INCOMING_CALL_FRAME_CODEC_V3,
    INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
)
from .semantic_index import SEMANTIC_INDEX_CODEC_V3, SemanticIndexRecordV3
from .static_value_records import (
    PE32_STATIC_IMAGE_CODEC_V3,
    PE32_STATIC_IMAGE_RECORD_V3_SCHEMA,
    STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
    PE32StaticImageV3,
)
from .target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
)
from .transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


_CALLBACK_SOURCE_VALUE_LIMIT = 32


@dataclass(frozen=True)
class _ExpectedSite:
    site_id: str
    unit_id: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    identity: CanonicalValueV3
    transfer_kind: str
    event: Mapping[str, Any]
    ordered_events: tuple[Mapping[str, Any], ...]
    callbacks: tuple[CallbackRequirementV3, ...] | None
    forced_blocker: PrimaryBlockerV3 | None = None


@dataclass(frozen=True)
class _CallbackSourceValues:
    status: str
    values: tuple[int, ...] = ()


@dataclass(frozen=True)
class _CallbackReplayContext:
    static_image: PE32StaticImageV3
    dependencies: tuple[RecordDependencyV3, ...]
    incoming_call_frames: tuple["_CallbackCallFrame", ...] = ()


@dataclass(frozen=True)
class _CallbackCallFrame:
    source_unit_id: str
    source_event_index: int
    source_status: str
    event: CanonicalValueV3
    ordered_events: tuple[CanonicalValueV3, ...]


def _identity(value: Mapping[str, Any]) -> Mapping[str, Any]:
    imported = value.get("import")
    candidate = imported if isinstance(imported, Mapping) else value
    dll = candidate.get("dll")
    symbol = candidate.get("symbol")
    ordinal = candidate.get("ordinal")
    if isinstance(dll, str) and bool(dll):
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
        if has_symbol != has_ordinal:
            return {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if has_symbol else None,
                "ordinal": ordinal if has_ordinal else None,
            }
    protocol = value.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return {"kind": "protocol", "protocol": dict(protocol)}
    fail(
        "external_identity_missing",
        "external event or target has no canonical import/protocol identity",
        "bind exactly one import symbol/ordinal or an external_protocol object",
    )


def _expected_callbacks(
    event: Mapping[str, Any], *, site_id: str
) -> tuple[CallbackRequirementV3, ...] | None:
    raw = event.get("callback_requirements")
    if raw is None:
        return None
    if not isinstance(raw, list):
        fail(
            "record_schema_mismatch",
            "external event callback requirements are not an array",
            "emit exact callback requirement objects",
        )
    result: list[CallbackRequirementV3] = []
    for ordinal, item in enumerate(raw):
        row = strict_object(
            item,
            {"target_unit_id", "target_rva", "abi_sha256", "lifetime"},
            "machine callback requirement",
        )
        result.append(
            CallbackRequirementV3.create(
                site_id=site_id,
                ordinal=ordinal,
                target_unit_id=text(row["target_unit_id"], "callback target unit ID"),
                target_rva=uint(row["target_rva"], "callback target RVA"),
                abi_sha256=digest(row["abi_sha256"], "callback ABI SHA-256"),
                lifetime=text(row["lifetime"], "callback lifetime"),
            )
        )
    return tuple(result)


def _expected_site(
    *,
    exact: SemanticIndexRecordV3,
    event: Mapping[str, Any],
    event_index: int,
    alternative_index: int,
    target: Mapping[str, Any],
    transfer_kind: str,
    ordered_events: tuple[Mapping[str, Any], ...],
) -> _ExpectedSite:
    event_sha256 = canonical_sha256_v3(event)
    target_sha256 = canonical_sha256_v3(target)
    site_id = stable_id(
        "external-site-v3",
        _site_identity_payload(
            exact.record_id, event_index, alternative_index, target_sha256
        ),
    )
    try:
        identity = CanonicalValueV3.of(_identity(target))
        callbacks = _expected_callbacks(event, site_id=site_id)
        blocker = None
    except ArtifactV3Error as exc:
        identity = CanonicalValueV3.of({"kind": "invalid", "target_sha256": target_sha256})
        callbacks = ()
        blocker = PrimaryBlockerV3("violated", exc.code)
    return _ExpectedSite(
        site_id,
        exact.record_id,
        event_index,
        alternative_index,
        event_sha256,
        target_sha256,
        identity,
        transfer_kind,
        event,
        ordered_events,
        callbacks,
        blocker,
    )


def _indirect_exit_id(
    exact: SemanticIndexRecordV3, event: Mapping[str, Any], index: int
) -> str:
    return indirect_exit_id_v3(
        {
            "source_unit_id": exact.record_id,
            "source_rva": exact.rva_start,
            "source_event_index": index,
            "kind": event.get("kind"),
            "target_expression": event.get("target"),
        }
    )


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    try:
        return context.record(input_name, record_id)
    except ArtifactV3Error as exc:
        if exc.code == "missing_record":
            return None
        raise


def _expected_sites(
    context: PhaseContextV3,
    exact: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
) -> tuple[
    tuple[_ExpectedSite, ...],
    tuple[PrimaryBlockerV3, ...],
    tuple[RecordDependencyV3, ...],
]:
    events = tuple(
        row.exact_record.to_value()
        for row in summary.exits
        if row.source_kind == "external_event"
    )
    expected: list[_ExpectedSite] = []
    blockers: list[PrimaryBlockerV3] = []
    dependencies: list[RecordDependencyV3] = []
    ordered_events = tuple(
        mapping(row.exact_record.to_value(), "ordered transition event")
        for row in summary.ordered_events
    )
    for event_index, raw in enumerate(events):
        if not isinstance(raw, Mapping):
            blockers.append(
                PrimaryBlockerV3("violated", "external_event_malformed")
            )
            continue
        event = raw
        kind = event.get("kind")
        if kind in {"external_call", "external_jump"}:
            expected.append(
                _expected_site(
                    exact=exact,
                    event=event,
                    event_index=event_index,
                    alternative_index=0,
                    target=event,
                    transfer_kind="jump" if kind == "external_jump" else "call",
                    ordered_events=ordered_events,
                )
            )
        elif kind in {"indirect_call", "indirect_jump"}:
            exit_id = _indirect_exit_id(exact, event, event_index)
            dependency = RecordDependencyV3("target_certificates", exact.record_id)
            dependencies.append(dependency)
            if context.manifest(dependency.input_name).status == "violated":
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "indirect_target_certificate_artifact_not_complete",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            source = _record_or_none(
                context, "target_certificates", exact.record_id
            )
            if source is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "indirect_target_certificate_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            target_set = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(source).value
            target = next(
                (
                    certificate
                    for certificate in target_set.certificates
                    if certificate.exit_id == exit_id
                ),
                None,
            )
            if target is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "indirect_target_certificate_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if (
                target.source_unit_id != exact.record_id
                or target.source_unit_sha256 != exact.unit_sha256
                or target.source_rva != exact.rva_start
                or target.source_event_index != event_index
                or target.transfer_kind != kind
                or target.target_expression
                != next(
                    row.target_expression
                    for row in exact.indirect_exits
                    if row.exit_id == exit_id
                )
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "indirect_target_certificate_binding_contradiction",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if target.status != "complete" or not target.authorizing:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated" if target.status == "violated" else "incomplete",
                        (
                            target.primary_blocker.code
                            if target.primary_blocker is not None
                            else "indirect_target_certificate_not_complete"
                        ),
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            for alternative_index, external in enumerate(target.external_targets):
                target_row = mapping(
                    external.to_value(), "recovered external target"
                )
                expected.append(
                    _expected_site(
                        exact=exact,
                        event=event,
                        event_index=event_index,
                        alternative_index=alternative_index,
                        target=target_row,
                        transfer_kind="jump" if kind == "indirect_jump" else "call",
                        ordered_events=ordered_events,
                    )
                )
    return (
        tuple(sorted(expected, key=lambda row: row.site_id)),
        tuple(blockers),
        canonical_dependencies_v3(dependencies),
    )


def _contract_blocker(
    expected: _ExpectedSite, contract: ExternalContractV3
) -> PrimaryBlockerV3 | None:
    if contract.identity != expected.identity or contract.transfer_kind != expected.transfer_kind:
        return PrimaryBlockerV3("violated", "external_contract_identity_contradiction")
    abi = expected.event.get("abi_contract")
    if isinstance(abi, Mapping):
        if contract.arity.kind == "fixed":
            words = abi.get("argument_words")
            if isinstance(words, int) and not isinstance(words, bool):
                if contract.argument_words != words:
                    return PrimaryBlockerV3(
                        "violated", "external_contract_abi_contradiction"
                    )
        else:
            if "argument_words" in abi:
                return PrimaryBlockerV3("violated", "external_contract_abi_contradiction")
            forwarding = abi.get("raw_caller_stack_suffix_forwarding")
            if forwarding is not None:
                if not isinstance(forwarding, Mapping):
                    return PrimaryBlockerV3(
                        "violated", "external_contract_abi_contradiction"
                    )
                try:
                    expected_arity = ExternalCallArityV3.parse(
                        {
                            "kind": "variadic",
                            "minimum_words": contract.minimum_argument_words,
                            "raw_caller_stack_suffix_forwarding": dict(forwarding),
                        },
                        label="checked external site arity",
                    )
                except ArtifactV3Error:
                    return PrimaryBlockerV3(
                        "violated", "external_contract_abi_contradiction"
                    )
                if expected_arity != contract.arity:
                    return PrimaryBlockerV3(
                        "violated", "external_contract_abi_contradiction"
                    )
        binding = abi.get("profile_binding")
        if (
            isinstance(binding, Mapping)
            and binding.get("profile_id") != CONTROL_DISPOSITION_PROFILE_ID
            and (
                contract.profile_id != binding.get("profile_id")
                or contract.profile_sha256 != binding.get("profile_sha256")
            )
        ):
            return PrimaryBlockerV3(
                "violated", "external_contract_profile_contradiction"
            )
        callback_effect = abi.get("callback_effect")
        if callback_effect is None and abi.get("world_effect") == "callbackRegistration":
            callback_effect = "registers"
        if callback_effect == "explicit":
            callback_effect = "registers"
        if callback_effect is not None and contract.callback_effect != callback_effect:
            return PrimaryBlockerV3(
                "violated", "external_contract_callback_contradiction"
            )
    machine_contract = mapping(
        contract.machine_contract.to_value(), "external machine contract"
    )
    abi_template = machine_contract.get("abi_template")
    if not isinstance(abi_template, str):
        return PrimaryBlockerV3(
            "violated", "external_contract_abi_contradiction"
        )
    try:
        argument_event = expected.event
        explicit = expected.event.get("arguments")
        if contract.arity.kind == "variadic" and explicit:
            if not isinstance(explicit, list) or any(
                not isinstance(row, Mapping) for row in explicit
            ):
                return PrimaryBlockerV3(
                    "violated", "external_contract_argument_contradiction"
                )
            if len(explicit) < contract.minimum_argument_words:
                return PrimaryBlockerV3(
                    "violated", "external_contract_argument_contradiction"
                )
            argument_event = dict(expected.event)
            argument_event["arguments"] = list(
                explicit[: contract.minimum_argument_words]
            )
        expected_arguments = tuple(
            CanonicalValueV3.of(row)
            for row in recover_external_arguments_v3(
                argument_event,
                transfer_kind=expected.transfer_kind,
                abi_template=abi_template,
                argument_words=contract.minimum_argument_words,
            )
        )
    except ExternalArgumentRecoveryV3Error as exc:
        return PrimaryBlockerV3(exc.status, exc.code)
    if contract.arguments != expected_arguments:
        return PrimaryBlockerV3(
            "violated", "external_contract_argument_contradiction"
        )
    if expected.callbacks is not None and contract.callbacks != expected.callbacks:
        return PrimaryBlockerV3(
            "violated", "external_contract_callback_requirement_contradiction"
        )
    return None


def _profile_dependency(contract: ExternalContractV3) -> RecordDependencyV3:
    return RecordDependencyV3(
        "external_profiles",
        stable_id(
            "external-profile-v3",
            {
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "identity": contract.identity.to_value(),
            },
        ),
    )


def _profile_blocker(
    contract: ExternalContractV3, profile: ExternalProfileV3
) -> PrimaryBlockerV3 | None:
    if (
        profile.profile_id != contract.profile_id
        or profile.profile_sha256 != contract.profile_sha256
        or profile.identity != contract.identity
        or contract.transfer_kind not in profile.allowed_transfers
        or contract.disposition not in profile.allowed_dispositions
        or profile.arity != contract.arity
        or profile.memory_effect != contract.memory_effect
        or profile.world_effect != contract.world_effect
        or profile.callback_effect != contract.callback_effect
        or profile.machine_contract != contract.machine_contract
    ):
        return PrimaryBlockerV3(
            "violated", "external_profile_contract_contradiction"
        )
    return None


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
        candidate = _callback_expression_values(row.get("value"), event=event)
    return candidate


def _resolve_callback_source_values(
    event: Mapping[str, Any],
    *,
    argument_index: int,
    expression: Mapping[str, Any],
    ordered_events: Sequence[Mapping[str, Any]] = (),
    incoming_call_frames: Sequence[_CallbackCallFrame] = (),
) -> _CallbackSourceValues:
    candidates = [_callback_expression_values(expression, event=event)]
    stack = _stack_callback_source_values(event, argument_index, ordered_events)
    if stack is not None:
        candidates.append(stack)
    if any(candidate.status == "violated" for candidate in candidates):
        return _CallbackSourceValues("violated")
    exact = [candidate for candidate in candidates if candidate.status == "complete"]
    incoming_values: set[int] = set()
    if incoming_call_frames:
        for frame in incoming_call_frames:
            if frame.source_status != "complete":
                return _CallbackSourceValues("incomplete")
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
    explicit = event.get("arguments")
    if explicit not in (None, []):
        return False
    return expression.get("op") == "load" and expression.get("width") == 4


def _derived_callback_requirements(
    *,
    site_id: str,
    event: Mapping[str, Any],
    profile: ExternalProfileV3,
    callback_values: Sequence[int],
    replay_context: _CallbackReplayContext,
    submitted: tuple[CallbackRequirementV3, ...],
) -> tuple[CallbackRequirementV3, ...] | None:
    protocol = callback_protocol_from_machine_contract(
        mapping(profile.machine_contract.to_value(), "external profile machine contract"),
        context="external profile callback protocol",
    )
    explicit = _expected_callbacks(event, site_id=site_id)
    if explicit is not None:
        machine_contract = mapping(
            profile.machine_contract.to_value(),
            "external profile machine contract",
        )
        callback_abi = (
            protocol.signature.to_payload()
            if protocol is not None
            else machine_contract.get("callback_abi")
        )
        lifetime = (
            callback_lifetime_identity(protocol)
            if protocol is not None
            else machine_contract.get("callback_lifetime")
        )
        if isinstance(callback_abi, Mapping):
            abi_sha256 = canonical_sha256_v3(callback_abi)
            if any(row.abi_sha256 != abi_sha256 for row in explicit):
                return None
        if isinstance(lifetime, str) and any(
            row.lifetime != lifetime for row in explicit
        ):
            return None
        expected_values = {
            replay_context.static_image.image_base + row.target_rva
            for row in explicit
        }
        return explicit if expected_values == set(callback_values) else None
    machine_contract = mapping(
        profile.machine_contract.to_value(),
        "external profile machine contract",
    )
    callback_abi = (
        protocol.signature.to_payload()
        if protocol is not None
        else machine_contract.get("callback_abi")
    )
    lifetime = (
        callback_lifetime_identity(protocol)
        if protocol is not None
        else machine_contract.get("callback_lifetime")
    )
    if (
        not callback_values
        or not isinstance(callback_abi, Mapping)
        or not isinstance(lifetime, str)
        or not lifetime
    ):
        return None
    abi_sha256 = canonical_sha256_v3(callback_abi)
    image = replay_context.static_image
    values = tuple(sorted(set(callback_values)))
    if len(submitted) != len(values):
        return None
    for ordinal, (value, callback) in enumerate(zip(values, submitted, strict=True)):
        if not image.image_base <= value < image.image_base + image.size_of_image:
            return None
        target_rva = value - image.image_base
        expected = CallbackRequirementV3.create(
            site_id=site_id,
            ordinal=ordinal,
            target_unit_id=callback.target_unit_id,
            target_rva=target_rva,
            abi_sha256=abi_sha256,
            lifetime=lifetime,
        )
        if callback != expected:
            return None
    return submitted


def _callback_replay_context(
    context: PhaseContextV3,
    *,
    exact: SemanticIndexRecordV3,
    evidence_source: ArtifactRecordV3,
) -> _CallbackReplayContext:
    static_dependencies = tuple(
        row
        for row in evidence_source.dependencies
        if row.input_name == "static_value_origins"
    )
    if len(static_dependencies) != 1:
        fail(
            "static_image_context_missing",
            "external-site evidence does not bind exactly one static image",
            "regenerate evidence with its exact static-image dependency",
        )
    static_dependency = static_dependencies[0]
    static_source = context.record(
        static_dependency.input_name, static_dependency.record_id
    )
    static_value = static_source.value.to_value()
    if (
        not isinstance(static_value, Mapping)
        or static_value.get("schema") != PE32_STATIC_IMAGE_RECORD_V3_SCHEMA
    ):
        fail(
            "static_image_context_missing",
            "external-site evidence binds a non-image static-value record",
            "bind the exact PE32 static-image record",
        )
    image = PE32_STATIC_IMAGE_CODEC_V3.read(static_source).value
    frame_dependency = RecordDependencyV3(
        "incoming_call_frames", exact.record_id
    )
    frame_source = context.record(
        frame_dependency.input_name, frame_dependency.record_id
    )
    frame_record = INCOMING_CALL_FRAME_CODEC_V3.read(frame_source).value
    if (
        frame_record.record_id != exact.record_id
        or frame_record.unit_sha256 != exact.unit_sha256
        or frame_record.rva_start != exact.rva_start
    ):
        fail(
            "incoming_call_frame_binding_contradiction",
            "incoming-call frame index contradicts the external-site unit",
            "regenerate the checked incoming-call frame index",
        )
    return _CallbackReplayContext(
        image,
        canonical_dependencies_v3((static_dependency, frame_dependency)),
        tuple(
            _CallbackCallFrame(
                source_unit_id=row.source_unit_id,
                source_event_index=row.source_event_index,
                source_status=row.source_status,
                event=row.event,
                ordered_events=row.ordered_events,
            )
            for row in frame_record.frames
        ),
    )


def _callback_source_replay_blocker(
    contract: ExternalContractV3,
    profile: ExternalProfileV3,
    event: Mapping[str, Any] | None = None,
    ordered_events: Sequence[Mapping[str, Any]] = (),
    *,
    site_id: str | None = None,
    replay_context: _CallbackReplayContext | None = None,
) -> PrimaryBlockerV3 | None:
    machine_contract = mapping(
        profile.machine_contract.to_value(),
        "external profile machine contract",
    )
    protocol = callback_protocol_from_machine_contract(
        machine_contract, context="external callback protocol"
    )
    if "callback_source" not in machine_contract and protocol is None:
        if contract.callback_source_decision is not None:
            return PrimaryBlockerV3(
                "violated", "external_callback_source_contradiction"
            )
        if event is not None and site_id is not None:
            explicit = _expected_callbacks(event, site_id=site_id)
            if explicit is not None and contract.callbacks != explicit:
                return PrimaryBlockerV3(
                    "violated", "external_callback_requirement_contradiction"
                )
        return None
    try:
        source = ExternalCallbackSourceV3.parse(
            machine_contract,
            argument_words=profile.minimum_argument_words,
        )
    except ArtifactV3Error:
        return PrimaryBlockerV3(
            "violated", "external_profile_callback_source_malformed"
        )
    if source.kind != "argument_word":
        return PrimaryBlockerV3(
            "incomplete", "external_callback_source_provenance_missing"
        )
    expression = contract.arguments[source.argument_index].to_value()
    source_values = _resolve_callback_source_values(
        {} if event is None else event,
        argument_index=source.argument_index,
        expression=mapping(expression, "callback-source expression"),
        ordered_events=ordered_events,
        incoming_call_frames=(
            () if replay_context is None else replay_context.incoming_call_frames
        ),
    )
    if source_values.status == "violated":
        return PrimaryBlockerV3(
            "violated", "external_callback_source_contradiction"
        )
    if source_values.status != "complete":
        if _is_parametric_entry_stack_word(
            {} if event is None else event,
            mapping(expression, "callback-source expression"),
        ):
            expected = CallbackSourceDecisionV3.create(
                kind="parametric_entry_word",
                argument_index=source.argument_index,
                source_expression=mapping(
                    expression, "callback-source expression"
                ),
            )
            if contract.callback_source_decision != expected:
                return PrimaryBlockerV3(
                    "violated", "external_callback_source_contradiction"
                )
            if contract.callbacks:
                return PrimaryBlockerV3(
                    "violated", "external_callback_source_contradiction"
                )
            return None
        return PrimaryBlockerV3(
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
        return PrimaryBlockerV3(
            "incomplete", "external_callback_source_provenance_missing"
        )
    sentinel = bool(sentinel_values)
    source_word = sentinel_values[0] if sentinel else None
    expected = CallbackSourceDecisionV3.create(
        kind=("non_callback_sentinel" if sentinel else "callback_target"),
        argument_index=source.argument_index,
        source_expression=mapping(expression, "callback-source expression"),
        sentinel_word=source_word,
    )
    if contract.callback_source_decision is None:
        return PrimaryBlockerV3(
            "incomplete", "external_callback_source_decision_missing"
        )
    if contract.callback_source_decision != expected:
        return PrimaryBlockerV3(
            "violated", "external_callback_source_contradiction"
        )
    if sentinel and contract.callbacks:
        return PrimaryBlockerV3(
            "violated", "external_callback_source_contradiction"
        )
    if not sentinel and not contract.callbacks:
        return PrimaryBlockerV3(
            "incomplete", "external_callback_requirement_missing"
        )
    if not sentinel:
        if site_id is None or replay_context is None:
            if event is not None and isinstance(
                event.get("callback_requirements"), list
            ):
                return None
            return PrimaryBlockerV3(
                "incomplete", "external_callback_requirement_missing"
            )
        expected_callbacks = _derived_callback_requirements(
            site_id=site_id,
            event={} if event is None else event,
            profile=profile,
            callback_values=callback_values,
            replay_context=replay_context,
            submitted=contract.callbacks,
        )
        if expected_callbacks is None:
            return PrimaryBlockerV3(
                "incomplete", "external_callback_requirement_missing"
            )
        if contract.callbacks != expected_callbacks:
            return PrimaryBlockerV3(
                "violated", "external_callback_requirement_contradiction"
            )
    return None


def _checked_site(
    context: PhaseContextV3,
    exact: SemanticIndexRecordV3,
    expected: _ExpectedSite,
) -> tuple[CanonicalExternalSiteV3, tuple[RecordDependencyV3, ...]]:
    dependency = RecordDependencyV3("external_site_evidence", expected.site_id)
    callback_replay_context: _CallbackReplayContext | None = None
    if expected.forced_blocker is not None:
        blocker = PrimaryBlockerV3(
            expected.forced_blocker.status,
            expected.forced_blocker.code,
            dependency.input_name,
            dependency.record_id,
        )
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                blocker.status,
                False,
                None,
                blocker,
            ),
            (dependency,),
        )
    source = _record_or_none(context, dependency.input_name, dependency.record_id)
    if source is None:
        blocker = PrimaryBlockerV3(
            "incomplete",
            "external_site_evidence_missing",
            dependency.input_name,
            dependency.record_id,
        )
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                "incomplete",
                False,
                None,
                blocker,
            ),
            (dependency,),
        )
    manifest_blocker = manifest_blocker_v3(
        context,
        dependency.input_name,
        "external_site_evidence_artifact_not_complete",
        dependency,
    )
    if manifest_blocker is not None:
        return (
            CanonicalExternalSiteV3(
                expected.site_id,
                expected.unit_id,
                expected.event_index,
                expected.alternative_index,
                expected.event_sha256,
                expected.target_sha256,
                expected.identity,
                manifest_blocker.status,
                False,
                None,
                manifest_blocker,
            ),
            (dependency,),
        )
    evidence = EXTERNAL_SITE_EVIDENCE_CODEC_V3.read(source).value
    forwarded_dependency: RecordDependencyV3 | None = None
    binding_matches = (
        evidence.record_id == expected.site_id
        and evidence.unit_id == expected.unit_id
        and evidence.unit_sha256 == exact.unit_sha256
        and evidence.event_index == expected.event_index
        and evidence.event_sha256 == expected.event_sha256
        and evidence.alternative_index == expected.alternative_index
        and evidence.target_sha256 == expected.target_sha256
        and evidence.identity == expected.identity
    )
    if not binding_matches:
        blocker = PrimaryBlockerV3(
            "violated",
            "external_site_evidence_binding_contradiction",
            dependency.input_name,
            dependency.record_id,
        )
    elif evidence.status != "complete":
        evidence_blocker = evidence.primary_blocker
        claimed_dependency = (
            None if evidence_blocker is None else evidence_blocker.dependency
        )
        if claimed_dependency is not None and claimed_dependency not in source.dependencies:
            blocker = PrimaryBlockerV3(
                "violated",
                "external_site_evidence_dependency_contradiction",
                dependency.input_name,
                dependency.record_id,
            )
        else:
            forwarded_dependency = claimed_dependency
            blocker = PrimaryBlockerV3(
                "violated" if evidence.status == "violated" else "incomplete",
                (
                    evidence_blocker.code
                    if evidence_blocker is not None
                    else "external_site_evidence_incomplete"
                ),
                (
                    forwarded_dependency.input_name
                    if forwarded_dependency is not None
                    else dependency.input_name
                ),
                (
                    forwarded_dependency.record_id
                    if forwarded_dependency is not None
                    else dependency.record_id
                ),
            )
    else:
        assert evidence.contract is not None
        proposed = _contract_blocker(expected, evidence.contract)
        if proposed is not None:
            blocker = PrimaryBlockerV3(
                proposed.status,
                proposed.code,
                dependency.input_name,
                dependency.record_id,
            )
        else:
            profile_dependency = _profile_dependency(evidence.contract)
            profile_source = _record_or_none(
                context,
                profile_dependency.input_name,
                profile_dependency.record_id,
            )
            if profile_source is None:
                blocker = PrimaryBlockerV3(
                    "incomplete",
                    "external_profile_missing",
                    profile_dependency.input_name,
                    profile_dependency.record_id,
                )
            elif (
                manifest_blocker := manifest_blocker_v3(
                    context,
                    profile_dependency.input_name,
                    "external_profile_artifact_not_complete",
                    profile_dependency,
                )
            ) is not None:
                blocker = manifest_blocker
            else:
                profile = EXTERNAL_PROFILE_CODEC_V3.read(profile_source).value
                proposed = _profile_blocker(evidence.contract, profile)
                if proposed is None:
                    profile_machine = mapping(
                        profile.machine_contract.to_value(),
                        "external profile machine contract",
                    )
                    callback_protocol = callback_protocol_from_machine_contract(
                        profile_machine,
                        context="external profile callback protocol",
                    )
                    if "callback_source" in profile_machine or (
                        callback_protocol is not None
                        and callback_protocol.source is not None
                    ):
                        callback_replay_context = _callback_replay_context(
                            context,
                            exact=exact,
                            evidence_source=source,
                        )
                    proposed = _callback_source_replay_blocker(
                        evidence.contract,
                        profile,
                        expected.event,
                        expected.ordered_events,
                        site_id=expected.site_id,
                        replay_context=callback_replay_context,
                    )
                blocker = (
                    None
                    if proposed is None
                    else PrimaryBlockerV3(
                        proposed.status,
                        proposed.code,
                        profile_dependency.input_name,
                        profile_dependency.record_id,
                    )
                )
    complete = blocker is None
    exact_dependencies = [dependency]
    if forwarded_dependency is not None:
        exact_dependencies.append(forwarded_dependency)
    if evidence.contract is not None and binding_matches and evidence.status == "complete":
        exact_dependencies.append(_profile_dependency(evidence.contract))
        if callback_replay_context is not None:
            exact_dependencies.extend(callback_replay_context.dependencies)
    return (
        CanonicalExternalSiteV3(
            expected.site_id,
            expected.unit_id,
            expected.event_index,
            expected.alternative_index,
            expected.event_sha256,
            expected.target_sha256,
            expected.identity,
            "complete" if complete else blocker.status,
            complete,
            evidence.contract if complete else None,
            blocker,
        ),
        canonical_dependencies_v3(exact_dependencies),
    )


def _derive_external_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> CanonicalExternalSiteRecordV3:
    exact = SEMANTIC_INDEX_CODEC_V3.read(source).value
    summary_source = context.record("transition_summaries", exact.record_id)
    summary = TRANSITION_SUMMARY_CODEC_V3.read(summary_source).value
    dependencies = [
        RecordDependencyV3("semantic_index", exact.record_id),
        RecordDependencyV3("transition_summaries", summary.record_id),
    ]
    blockers: list[PrimaryBlockerV3] = []
    for input_name, dependency, code in (
        (
            "semantic_index",
            dependencies[0],
            "semantic_index_artifact_not_complete",
        ),
        (
            "transition_summaries",
            dependencies[1],
            "transition_summary_artifact_not_complete",
        ),
    ):
        manifest_blocker = manifest_blocker_v3(
            context, input_name, code, dependency
        )
        if manifest_blocker is not None:
            blockers.append(manifest_blocker)
    if summary.unit_sha256 != exact.unit_sha256:
        blockers.append(
            PrimaryBlockerV3(
                "violated",
                "transition_summary_unit_contradiction",
                "transition_summaries",
                summary.record_id,
            )
        )
    elif summary.status != "complete":
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "transition_summary_incomplete",
                "transition_summaries",
                summary.record_id,
            )
        )
    expected, structural_blockers, structural_dependencies = _expected_sites(
        context, exact, summary
    )
    blockers.extend(structural_blockers)
    dependencies.extend(structural_dependencies)
    sites: list[CanonicalExternalSiteV3] = []
    for row in expected:
        site, site_dependencies = _checked_site(context, exact, row)
        sites.append(site)
        dependencies.extend(site_dependencies)
        if site.primary_blocker is not None:
            blockers.append(site.primary_blocker)
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return CanonicalExternalSiteRecordV3(
        record_id=exact.record_id,
        unit_sha256=exact.unit_sha256,
        status=status,
        authorizing=status == "complete",
        sites=tuple(sorted(sites, key=lambda row: row.site_id)),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_external_sites(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_external_record(context, source)
    return CANONICAL_EXTERNAL_SITE_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def check_canonical_external_sites_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    exact_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in exact_records),
        "canonical external-site inventories",
    )
    expected_evidence_ids: set[str] = set()
    for source, output in zip(exact_records, outputs, strict=True):
        expected = _derive_external_record(context, source)
        submitted = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "canonical_external_site_contradiction",
                f"external-site inventory {output.record_id!r} is stale",
                "rerun canonical external-site analysis from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"external-site inventory {output.record_id!r} has stale dependencies",
                "let CANONICAL_EXTERNAL_SITES_PHASE_V3 attach exact dependencies",
            )
        expected_evidence_ids.update(site.site_id for site in expected.sites)
    evidence_records = sorted_records(context.records("external_site_evidence"))
    unknown = sorted({row.record_id for row in evidence_records} - expected_evidence_ids)
    if unknown:
        fail(
            "unknown_external_site_evidence",
            f"external-site evidence names absent exact sites {unknown!r}",
            "remove stale evidence or regenerate it from exact external events",
        )


CANONICAL_EXTERNAL_SITES_PHASE_V3 = map_units(
    name="canonical-external-sites-v3",
    version="4",
    source_input="semantic_index",
    input_artifact_kinds={
        "external_profiles": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
        "external_site_evidence": EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
        "incoming_call_frames": INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
        "semantic_index": "semantic-index-v3",
        "static_value_origins": STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
        "target_certificates": INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
        "transition_summaries": "transition-summaries-v3",
    },
    output_artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    transform=_transform_external_sites,
    completeness=check_canonical_external_sites_completeness_v3,
    unit_aligned_inputs=("target_certificates", "transition_summaries"),
)


__all__ = [
    "CANONICAL_EXTERNAL_SITES_PHASE_V3",
    "check_canonical_external_sites_completeness_v3",
]
