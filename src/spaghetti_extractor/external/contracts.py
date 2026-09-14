"""Canonical, fail-closed machine contracts for native external call sites.

The state-machine exporter, native bridge planner, and native runtime used to
interpret overlapping subsets of external-call metadata independently.  This
module provides the one normalized boundary object shared by the latter two
consumers.  It has no proof authority; it makes omissions and disagreement
explicit so the static completeness gate can reject them.
"""

from __future__ import annotations

from .range_ownership import RangeOwnershipError, validate_range_ownership_relations
from .range_allocation import RangeAllocationError, validate_range_allocation_relations

import copy
import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..external.callbacks import (
    parse_callback_abi,
    parse_callback_source,
    parse_nested_native_callback_behavior,
)
from ..external.callback_protocols import callback_protocol_from_machine_contract
from ..external.service_protocols import (
    CheckedExternalServiceProtocolError,
    parse_checked_external_service_protocol_v1,
)
from .range_release import RangeRelease, RangeReleaseError, machine_range_release
from .argument_domains import checked_argument_domain
from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError


CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT = (
    "spaghetti-extractor-candidate-external-site-contract-v3"
)
_PE32_ABIS = frozenset({"pe32-cdecl-v1", "pe32-stdcall-v1"})
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})
_VARIADIC_FORWARDING_KIND = "exact_raw_caller_stack_suffix_v1"
class CheckedExternalSiteContractError(ToolkitInputError):
    """An external site is missing an exact, executable machine contract."""


def require_machine_import_effects(
    value: Mapping[str, Any], *, context: str,
) -> tuple[str, str]:
    """Keep physical ABI declarations separate from semantic effect contracts.

    This checks presence, not the adequacy of a declared effect model. Its
    consumer must still check footprints, callbacks, outcomes and realization.
    In particular, absence must never be converted to the semantic claim none.
    """
    effects = []
    for field in ("memory_effect", "world_effect"):
        effect = value.get(field)
        if not isinstance(effect, str) or not effect.strip():
            raise CheckedExternalSiteContractError(
                f"{context} lacks an explicit {field}; an ABI-only declaration "
                "does not supply a semantic effect contract"
            )
        effects.append(effect)
    return effects[0], effects[1]


def _uint(value: Any, context: str, *, maximum: int = 0xFFFFFFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise CheckedExternalSiteContractError(f"{context} must be an unsigned integer")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CheckedExternalSiteContractError(f"{context} must be a nonempty string")
    return value


def _json(value: Any, context: str) -> Any:
    """Copy one deterministic JSON value and reject Python-only objects."""

    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise CheckedExternalSiteContractError(f"{context} is not canonical JSON") from exc


def _metadata(value: Any) -> Any:
    """Match the state-machine metadata projection used for profile fields."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = "byte_count" if raw_key == "bytes" else str(raw_key)
            if key in result:
                raise CheckedExternalSiteContractError(
                    f"external contract metadata collides at {key!r}"
                )
            result[key] = _metadata(item)
        return result
    if isinstance(value, list):
        return [_metadata(item) for item in value]
    return _json(value, "external contract metadata")


def _canonical_variadic_forwarding(minimum_words: int) -> dict[str, Any]:
    return {
        "kind": _VARIADIC_FORWARDING_KIND,
        "minimum_argument_words": minimum_words,
        "source": "caller_argument_stack",
        "destination": "same_library_machine_ir_callthrough",
        "extent": "all_words_after_minimum_prefix",
        "word_relation": "exact_u32",
        "order_relation": "preserved",
    }


def _parse_checked_arity(
    value: Any, *, context: str
) -> tuple[str, int, Any | None]:
    if not isinstance(value, Mapping):
        raise CheckedExternalSiteContractError(f"{context} arity is missing")
    kind = value.get("kind")
    if kind == "fixed":
        if set(value) != {"kind", "words"}:
            raise CheckedExternalSiteContractError(
                f"{context} fixed arity has noncanonical fields"
            )
        return (
            "fixed",
            _uint(value.get("words"), f"{context} argument words", maximum=256),
            None,
        )
    if kind != "variadic":
        raise CheckedExternalSiteContractError(f"{context} arity kind is unsupported")
    if set(value) != {
        "kind",
        "minimum_words",
        "raw_caller_stack_suffix_forwarding",
    }:
        raise CheckedExternalSiteContractError(
            f"{context} variadic arity has noncanonical fields"
        )
    minimum_words = _uint(
        value.get("minimum_words"),
        f"{context} minimum argument words",
        maximum=256,
    )
    forwarding = _json(
        value.get("raw_caller_stack_suffix_forwarding"),
        f"{context} variadic forwarding",
    )
    if forwarding != _canonical_variadic_forwarding(minimum_words):
        raise CheckedExternalSiteContractError(
            f"{context} variadic forwarding is not the canonical exact raw "
            "caller-stack suffix contract"
        )
    return "variadic", minimum_words, forwarding


@dataclass(frozen=True, order=True)
class ExternalSiteIdentity:
    kind: str
    dll: str | None = None
    symbol: str | None = None
    ordinal: int | None = None
    protocol: str | None = None
    profile_id: str | None = None
    profile_sha256: str | None = None
    operation: str | None = None

    @classmethod
    def imported(cls, value: Mapping[str, Any], *, context: str) -> "ExternalSiteIdentity":
        dll = _string(value.get("dll"), f"{context} DLL").lower()
        symbol = value.get("symbol")
        ordinal = value.get("ordinal")
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
        if has_symbol == has_ordinal:
            raise CheckedExternalSiteContractError(
                f"{context} must name exactly one symbol or ordinal"
            )
        return cls(
            kind="import",
            dll=dll,
            symbol=str(symbol) if has_symbol else None,
            ordinal=_uint(ordinal, f"{context} ordinal") if has_ordinal else None,
        )

    @classmethod
    def interface(cls, protocol: Mapping[str, Any], *, context: str) -> "ExternalSiteIdentity":
        kind = protocol.get("kind")
        if kind == "pe32-interface-method":
            operation = (
                f"{_string(protocol.get('interface_id'), f'{context} interface')}::"
                f"{_string(protocol.get('method'), f'{context} method')}"
            )
        elif kind == "pe32-previous-callback":
            operation = str(protocol.get("contract_id"))
            if not operation or operation == "None":
                raise CheckedExternalSiteContractError(
                    f"{context} previous callback has no contract id"
                )
        elif kind == "pe32-resolved-export":
            target = protocol.get("target")
            if not isinstance(target, Mapping):
                raise CheckedExternalSiteContractError(
                    f"{context} resolved export has no exact target identity"
                )
            imported = cls.imported(target, context=f"{context} resolved target")
            return cls(
                kind="resolved_export",
                dll=imported.dll,
                symbol=imported.symbol,
                ordinal=imported.ordinal,
                protocol=str(kind),
                profile_id=(
                    str(protocol["profile_id"])
                    if isinstance(protocol.get("profile_id"), str)
                    else None
                ),
                profile_sha256=(
                    str(protocol["profile_sha256"])
                    if isinstance(protocol.get("profile_sha256"), str)
                    else None
                ),
            )
        else:
            raise CheckedExternalSiteContractError(
                f"{context} has unsupported external protocol {kind!r}"
            )
        binding = protocol.get("profile_binding")
        profile_id_value = protocol.get("profile_id")
        profile_sha256_value = protocol.get("profile_sha256")
        if isinstance(binding, Mapping):
            profile_id_value = binding.get("profile_id", binding.get("id"))
            profile_sha256_value = binding.get(
                "profile_sha256", binding.get("sha256")
            )
        profile_id = _string(profile_id_value, f"{context} profile id")
        profile_sha256 = _string(
            profile_sha256_value, f"{context} profile SHA-256"
        )
        if len(profile_sha256) != 64 or any(c not in "0123456789abcdef" for c in profile_sha256):
            raise CheckedExternalSiteContractError(
                f"{context} profile SHA-256 must be lowercase hexadecimal"
            )
        return cls(
            kind="interface" if kind == "pe32-interface-method" else "callback",
            protocol=str(kind),
            profile_id=profile_id,
            profile_sha256=profile_sha256,
            operation=operation,
        )

    def payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "protocol": self.protocol,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "operation": self.operation,
        }


@dataclass(frozen=True)
class CheckedStackArgument:
    index: int
    offset: int
    width: int
    value: Any

    def payload(self, *, copy_json: bool = True) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "width": self.width,
            "value": (
                _json(self.value, "stack argument value")
                if copy_json else self.value
            ),
        }


@dataclass(frozen=True)
class CheckedCallbackAdapter:
    source: Any
    abi: Any
    lifetime: Any
    behavior: Any
    activation: Any | None
    resource_binding: Any | None
    instance_binding: Any | None
    target_rvas: tuple[int, ...]
    invocation: str

    def payload(self, *, copy_json: bool = True) -> dict[str, Any]:
        def value(item: Any, context: str) -> Any:
            return _json(item, context) if copy_json else item

        return {
            "source": value(self.source, "callback source"),
            "abi": value(self.abi, "callback ABI"),
            "lifetime": value(self.lifetime, "callback lifetime"),
            "behavior": value(self.behavior, "callback behavior"),
            "activation": value(self.activation, "callback activation"),
            "resource_binding": value(
                self.resource_binding, "callback resource binding"
            ),
            "instance_binding": value(
                self.instance_binding, "callback instance binding"
            ),
            "target_rvas": list(self.target_rvas),
            "invocation": self.invocation,
        }


@dataclass(frozen=True, kw_only=True)
class CheckedExternalContractBehavior:
    """The common profile behavior carried by each exact external site."""

    identity: ExternalSiteIdentity
    profile_disposition: str
    abi_template: str
    arity_kind: str
    argument_words: int
    raw_caller_stack_suffix_forwarding: Any | None
    contract_id: str
    profile_binding: Any
    result_register_relations: tuple[Any, ...]
    memory_effect: str
    memory_footprints: tuple[Any, ...]
    world_effect: str
    world_effect_argument: int | None
    callback_effect: str
    argument_domain: tuple[Any, ...] = ()
    out_pointer_relations: tuple[Any, ...] = ()
    out_interface_relations: tuple[Any, ...] = ()
    external_service_protocol: Any | None = None
    world_effect_release: RangeRelease | None = None

    @property
    def minimum_argument_words(self) -> int:
        """Words whose expressions are statically described at every site."""

        return self.argument_words

    def arity_payload(self) -> dict[str, Any]:
        if self.arity_kind == "fixed":
            return {"kind": "fixed", "words": self.argument_words}
        return {
            "kind": "variadic",
            "minimum_words": self.argument_words,
            "raw_caller_stack_suffix_forwarding": _json(
                self.raw_caller_stack_suffix_forwarding,
                "checked variadic forwarding",
            ),
        }

    def profile_effect_payload(self) -> dict[str, Any]:
        """Return the normalized profile fields consumed by runtime effect rules."""

        return {
            "id": self.contract_id,
            "arity": self.arity_payload(),
            "argument_words": self.argument_words,
            **({"argument_domain": list(self.argument_domain)} if self.argument_domain else {}),
            "result_register_relations": list(self.result_register_relations),
            "memory_effect": self.memory_effect,
            "memory_footprints": list(self.memory_footprints),
            "world_effect": self.world_effect,
            **(
                {"world_effect_argument": self.world_effect_argument}
                if self.world_effect_argument is not None
                else {}
            ),
            **({"world_effect_release": self.world_effect_release.payload()}
               if self.world_effect_release is not None else {}),
            "callback_effect": self.callback_effect,
            "out_pointer_relations": list(self.out_pointer_relations),
            "out_interface_relations": list(self.out_interface_relations),
            "external_service_protocol": _json(
                self.external_service_protocol, "external service protocol"
            ),
        }

    def identity_sha256(self) -> str:
        """Bind profile behavior without conflating independent physical sites.

        This is the native range-rule identity, not a proof of call effects or
        callback provenance. Site arguments and callback domains remain bound
        by the containing checked site and its execution closure.
        """
        return canonical_sha256_v3({
            "identity": self.identity.payload(),
            "profile_binding": self.profile_binding,
            "abi_template": self.abi_template,
            "arity": self.arity_payload(),
            "profile_disposition": self.profile_disposition,
            "effect_contract": self.profile_effect_payload(),
        })


@dataclass(frozen=True)
class CheckedExternalSiteContract(CheckedExternalContractBehavior):
    transfer_kind: str
    disposition: str
    argument_base_offset: int
    arguments: tuple[Any, ...]
    stack_arguments: tuple[CheckedStackArgument, ...]
    callback_adapter: CheckedCallbackAdapter | None

    def payload(self, *, copy_json: bool = True) -> dict[str, Any]:
        def value(item: Any, context: str) -> Any:
            return _json(item, context) if copy_json else item

        return {
            "format": CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT,
            "identity": self.identity.payload(),
            "transfer_kind": self.transfer_kind,
            "disposition": self.disposition,
            "profile_disposition": self.profile_disposition,
            "abi_template": self.abi_template,
            "arity": self.arity_payload(),
            "argument_base_offset": self.argument_base_offset,
            **({"argument_domain": [value(item, "argument domain") for item in self.argument_domain]}
               if self.argument_domain else {}),
            "arguments": [value(item, "argument") for item in self.arguments],
            "stack_arguments": [
                item.payload(copy_json=copy_json)
                for item in self.stack_arguments
            ],
            "contract_id": self.contract_id,
            "profile_binding": value(self.profile_binding, "profile binding"),
            "result_register_relations": [
                value(item, "result relation")
                for item in self.result_register_relations
            ],
            "memory_effect": self.memory_effect,
            "memory_footprints": [
                value(item, "memory footprint")
                for item in self.memory_footprints
            ],
            "world_effect": self.world_effect,
            **(
                {"world_effect_argument": self.world_effect_argument}
                if self.world_effect_argument is not None
                else {}
            ),
            **({"world_effect_release": self.world_effect_release.payload()}
               if self.world_effect_release is not None else {}),
            "callback_effect": self.callback_effect,
            "callback_adapter": (
                None
                if self.callback_adapter is None
                else self.callback_adapter.payload(copy_json=copy_json)
            ),
            "out_pointer_relations": [
                value(item, "out-pointer relation")
                for item in self.out_pointer_relations
            ],
            "out_interface_relations": [
                value(item, "out-interface relation")
                for item in self.out_interface_relations
            ],
            "external_service_protocol": value(
                self.external_service_protocol, "external service protocol"
            ),
        }


def _parse_callback_adapter(value: Any, *, context: str) -> CheckedCallbackAdapter:
    if not isinstance(value, Mapping):
        raise CheckedExternalSiteContractError(
            f"{context} requires explicit callback adapter metadata"
        )
    source = value.get("source")
    abi = value.get("abi")
    lifetime = value.get("lifetime")
    behavior = value.get("behavior")
    activation = value.get("activation")
    resource_binding = value.get("resource_binding")
    instance_binding = value.get("instance_binding")
    targets = value.get("target_rvas")
    invocation = value.get("invocation")
    if not isinstance(source, Mapping) or not isinstance(abi, Mapping):
        raise CheckedExternalSiteContractError(f"{context} callback source or ABI is malformed")
    if not isinstance(lifetime, (str, Mapping)) or not lifetime:
        raise CheckedExternalSiteContractError(f"{context} callback lifetime is missing")
    if behavior == "registration":
        if any(
            item is not None
            for item in (activation, resource_binding, instance_binding)
        ):
            raise CheckedExternalSiteContractError(
                f"{context} simple callback registration has nested protocol metadata"
            )
    elif isinstance(behavior, Mapping):
        if behavior.get("kind") != "nested_native_callback_v1":
            raise CheckedExternalSiteContractError(
                f"{context} callback behavior is unsupported"
            )
        behavior_activation = behavior.get("activation")
        if (
            not isinstance(activation, Mapping)
            or activation.get("status") != "complete"
            or not isinstance(behavior_activation, Mapping)
            or activation.get("kind") != behavior_activation.get("kind")
            or activation.get("argument_index")
            != behavior_activation.get("argument")
            or activation.get("mask") != behavior_activation.get("mask")
            or activation.get("expected_value") != behavior_activation.get("value")
            or activation.get("masked_value") != behavior_activation.get("value")
            or activation.get("failure") is not None
        ):
            raise CheckedExternalSiteContractError(
                f"{context} callback activation evidence is incomplete or inconsistent"
            )
        instance = behavior.get("instance_binding")
        if (
            not isinstance(resource_binding, Mapping)
            or resource_binding.get("kind") != "provider_callback_resource_v1"
            or resource_binding.get("provider_relation")
            != behavior.get("provider_relation")
            or resource_binding.get("callback_argument")
            != behavior.get("resource_argument")
        ):
            raise CheckedExternalSiteContractError(
                f"{context} callback resource binding is incomplete or inconsistent"
            )
        if (
            not isinstance(instance, Mapping)
            or not isinstance(instance_binding, Mapping)
            or instance_binding.get("kind")
            != "registered_instance_callback_argument_v1"
            or instance_binding.get("callback_argument")
            != instance.get("callback_argument")
            or instance_binding.get("registration_argument")
            != instance.get("registration_argument")
            or not isinstance(instance_binding.get("registration_origins"), list)
            or not instance_binding["registration_origins"]
        ):
            raise CheckedExternalSiteContractError(
                f"{context} callback instance binding is incomplete or inconsistent"
            )
    else:
        raise CheckedExternalSiteContractError(
            f"{context} callback behavior is missing"
        )
    if not isinstance(targets, list) or not targets:
        raise CheckedExternalSiteContractError(
            f"{context} callback adapter requires a nonempty finite target set"
        )
    normalized_targets = tuple(sorted({_uint(item, f"{context} callback target") for item in targets}))
    if len(normalized_targets) != len(targets):
        raise CheckedExternalSiteContractError(f"{context} callback targets are duplicated")
    if invocation != "nested-machine-ir-callback-adapter-v1":
        raise CheckedExternalSiteContractError(
            f"{context} callback adapter has unsupported invocation metadata"
        )
    return CheckedCallbackAdapter(
        source=_json(source, f"{context} callback source"),
        abi=_json(abi, f"{context} callback ABI"),
        lifetime=_json(lifetime, f"{context} callback lifetime"),
        behavior=_json(behavior, f"{context} callback behavior"),
        activation=_json(activation, f"{context} callback activation"),
        resource_binding=_json(
            resource_binding, f"{context} callback resource binding"
        ),
        instance_binding=_json(
            instance_binding, f"{context} callback instance binding"
        ),
        target_rvas=normalized_targets,
        invocation=str(invocation),
    )


def parse_checked_external_site_contract(
    value: Mapping[str, Any], *, context: str = "external site contract"
) -> CheckedExternalSiteContract:
    if value.get("format") != CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT:
        raise CheckedExternalSiteContractError(f"{context} has unsupported format")
    raw_identity = value.get("identity")
    if not isinstance(raw_identity, Mapping):
        raise CheckedExternalSiteContractError(f"{context} has no identity")
    identity_kind = raw_identity.get("kind")
    if identity_kind == "import":
        identity = ExternalSiteIdentity.imported(raw_identity, context=f"{context} identity")
    else:
        # Serialized protocol identities are already normalized; parse every field
        # strictly instead of trying to reconstruct the originating profile object.
        identity = ExternalSiteIdentity(
            kind=_string(identity_kind, f"{context} identity kind"),
            dll=raw_identity.get("dll"),
            symbol=raw_identity.get("symbol"),
            ordinal=raw_identity.get("ordinal"),
            protocol=raw_identity.get("protocol"),
            profile_id=raw_identity.get("profile_id"),
            profile_sha256=raw_identity.get("profile_sha256"),
            operation=raw_identity.get("operation"),
        )
        if identity.kind not in {"interface", "callback", "resolved_export"}:
            raise CheckedExternalSiteContractError(f"{context} identity kind is unsupported")
        if identity.kind == "resolved_export":
            ExternalSiteIdentity.imported(raw_identity, context=f"{context} identity")
        elif not all((identity.protocol, identity.profile_id, identity.profile_sha256, identity.operation)):
            raise CheckedExternalSiteContractError(f"{context} protocol identity is incomplete")

    transfer_kind = value.get("transfer_kind")
    if transfer_kind not in {"call", "jump"}:
        raise CheckedExternalSiteContractError(f"{context} transfer kind is unsupported")
    disposition = value.get("disposition")
    if disposition not in {"returns_here", "tail_jump"}:
        raise CheckedExternalSiteContractError(f"{context} disposition is unsupported")
    if (transfer_kind == "call") != (disposition == "returns_here"):
        raise CheckedExternalSiteContractError(f"{context} transfer and disposition disagree")
    profile_disposition = value.get("profile_disposition")
    if profile_disposition not in {"returns", "terminates", "nonlocal"}:
        raise CheckedExternalSiteContractError(
            f"{context} profile disposition is unsupported"
        )
    abi_template = value.get("abi_template")
    if abi_template not in _PE32_ABIS:
        raise CheckedExternalSiteContractError(f"{context} ABI template is unsupported")
    arity_kind, argument_words, raw_suffix_forwarding = _parse_checked_arity(
        value.get("arity"), context=context
    )
    argument_base_offset = _uint(
        value.get("argument_base_offset"), f"{context} argument base", maximum=0x10000
    )
    arguments = value.get("arguments")
    stack_arguments = value.get("stack_arguments")
    if not isinstance(arguments, list) or len(arguments) != argument_words:
        raise CheckedExternalSiteContractError(f"{context} argument inventory is not exact")
    if not isinstance(stack_arguments, list) or len(stack_arguments) != argument_words:
        raise CheckedExternalSiteContractError(f"{context} stack inventory is not exact")
    normalized_arguments = tuple(_json(item, f"{context} argument") for item in arguments)
    normalized_stack: list[CheckedStackArgument] = []
    for index, raw in enumerate(stack_arguments):
        if not isinstance(raw, Mapping):
            raise CheckedExternalSiteContractError(f"{context} stack argument {index} is malformed")
        item_index = _uint(raw.get("index"), f"{context} stack argument index", maximum=256)
        offset = _uint(raw.get("offset"), f"{context} stack argument offset")
        width = _uint(raw.get("width"), f"{context} stack argument width", maximum=4)
        item_value = _json(raw.get("value"), f"{context} stack argument value")
        if (
            item_index != index
            or width != 4
            or offset != argument_base_offset + index * 4
            or item_value != normalized_arguments[index]
        ):
            raise CheckedExternalSiteContractError(
                f"{context} stack argument {index} disagrees with the ABI inventory"
            )
        normalized_stack.append(CheckedStackArgument(index, offset, width, item_value))

    contract_id = str(value.get("contract_id"))
    if not contract_id or contract_id == "None":
        raise CheckedExternalSiteContractError(f"{context} has no contract id")
    profile_binding = value.get("profile_binding")
    if not isinstance(profile_binding, Mapping):
        raise CheckedExternalSiteContractError(f"{context} has no exact profile binding")
    result_relations = value.get("result_register_relations")
    memory_footprints = value.get("memory_footprints")
    out_pointers = value.get("out_pointer_relations", [])
    out_interfaces = value.get("out_interface_relations", [])
    if not all(isinstance(item, list) for item in (
        result_relations, memory_footprints, out_pointers, out_interfaces
    )):
        raise CheckedExternalSiteContractError(f"{context} effect inventories must be lists")
    for raw in result_relations:
        if not isinstance(raw, Mapping):
            raise CheckedExternalSiteContractError(f"{context} result relation is malformed")
        register = raw.get("register")
        if register is not None and str(register).lower() not in _REGISTERS:
            raise CheckedExternalSiteContractError(f"{context} result register is unsupported")
    memory_effect = _string(value.get("memory_effect"), f"{context} memory effect")
    world_effect = _string(value.get("world_effect"), f"{context} world effect")
    from .terminated_reads import checked_terminated_read, checked_terminated_write
    try:
        checked_terminated_read(value, argument_words=argument_words)
        checked_terminated_write(value, argument_words=argument_words)
    except ValueError as exc:
        raise CheckedExternalSiteContractError(f"{context}: {exc}") from exc
    try:
        release = machine_range_release(value, argument_words=argument_words, context=context)
    except RangeReleaseError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    try:
        validate_range_ownership_relations(value, argument_words=argument_words, context=context)
    except RangeOwnershipError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    try:
        validate_range_allocation_relations(value, argument_words=argument_words, context=context)
    except RangeAllocationError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    raw_world_effect_argument = value.get("world_effect_argument")
    if world_effect == "dynamicRangeRelease":
        world_effect_argument = _uint(
            raw_world_effect_argument,
            f"{context} dynamic-range release argument",
            maximum=255,
        )
        if world_effect_argument >= argument_words:
            raise CheckedExternalSiteContractError(
                f"{context} dynamic-range release argument is out of bounds"
            )
    else:
        if raw_world_effect_argument is not None:
            raise CheckedExternalSiteContractError(
                f"{context} has a release argument without a release effect"
            )
        world_effect_argument = None
    callback_effect = value.get("callback_effect")
    if callback_effect not in {"none", "explicit"}:
        raise CheckedExternalSiteContractError(
            f"{context} callback effect must be exactly none or explicit"
        )
    callback_adapter = value.get("callback_adapter")
    if callback_effect == "none":
        if callback_adapter is not None:
            raise CheckedExternalSiteContractError(
                f"{context} ordinary callthrough attaches callback metadata"
            )
        parsed_callback = None
    else:
        parsed_callback = _parse_callback_adapter(callback_adapter, context=context)
    try:
        external_service_protocol = parse_checked_external_service_protocol_v1(
            value.get("external_service_protocol"),
            argument_words=argument_words,
            context=f"{context} external service protocol",
        )
    except CheckedExternalServiceProtocolError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    if (profile_disposition == "nonlocal") != (
        isinstance(external_service_protocol, Mapping)
        and external_service_protocol.get("kind") == "nonlocal_unwind"
    ):
        raise CheckedExternalSiteContractError(
            f"{context} nonlocal disposition and service protocol disagree"
        )
    return CheckedExternalSiteContract(
        identity=identity,
        transfer_kind=str(transfer_kind),
        disposition=str(disposition),
        profile_disposition=str(profile_disposition),
        abi_template=str(abi_template),
        arity_kind=arity_kind,
        argument_words=argument_words,
        raw_caller_stack_suffix_forwarding=raw_suffix_forwarding,
        argument_domain=checked_argument_domain(value.get("argument_domain", []),
                                                argument_words=argument_words, context=context),
        argument_base_offset=argument_base_offset,
        arguments=normalized_arguments,
        stack_arguments=tuple(normalized_stack),
        contract_id=contract_id,
        profile_binding=_json(profile_binding, f"{context} profile binding"),
        result_register_relations=tuple(
            _metadata(item) for item in result_relations
        ),
        memory_effect=memory_effect,
        memory_footprints=tuple(_metadata(item) for item in memory_footprints),
        world_effect=world_effect,
        world_effect_argument=world_effect_argument,
        world_effect_release=release,
        callback_effect=str(callback_effect),
        callback_adapter=parsed_callback,
        out_pointer_relations=tuple(_metadata(item) for item in out_pointers),
        out_interface_relations=tuple(_metadata(item) for item in out_interfaces),
        external_service_protocol=external_service_protocol,
    )


def checked_external_site_contract_from_authority(
    contract: object, *, context: str = "canonical external-site contract"
) -> CheckedExternalSiteContract:
    """Project one checked v3 authority contract into the runtime ABI model."""

    raw = _json(contract, context)
    common_fields = {
            "id",
            "identity",
            "transfer_kind",
            "disposition",
            "profile_id",
            "profile_sha256",
            "arguments",
            "memory_effect",
            "world_effect",
            "callback_effect",
            "machine_contract",
            "callbacks",
    }
    expected_fields = (
        common_fields | {"argument_words"}
        if "argument_words" in raw
        else common_fields | {"arity"}
    )
    if "callback_source_decision" in raw:
        expected_fields.add("callback_source_decision")
    if set(raw) != expected_fields:
        raise CheckedExternalSiteContractError(
            f"{context} has noncanonical authority fields"
        )
    machine = raw["machine_contract"]
    identity = raw["identity"]
    transfer_kind = raw["transfer_kind"]
    disposition = raw["disposition"]
    profile_id = raw["profile_id"]
    profile_sha256 = raw["profile_sha256"]
    authority_arity = (
        {"kind": "fixed", "words": raw["argument_words"]}
        if "argument_words" in raw
        else raw["arity"]
    )
    arity_kind, argument_words, _raw_suffix_forwarding = _parse_checked_arity(
        authority_arity, context=context
    )
    arguments = raw["arguments"]
    authority_callback_effect = raw["callback_effect"]
    callbacks = raw["callbacks"]
    callback_source_decision = raw.get("callback_source_decision")
    contract_id = raw["id"]
    memory_effect = raw["memory_effect"]
    world_effect = raw["world_effect"]
    if not isinstance(machine, Mapping) or not isinstance(identity, Mapping):
        raise CheckedExternalSiteContractError(
            f"{context} has malformed identity or machine contract"
        )
    normalized_identity = dict(identity)
    if identity.get("kind") == "protocol":
        protocol_identity = identity.get("protocol")
        if not isinstance(protocol_identity, Mapping):
            raise CheckedExternalSiteContractError(
                f"{context} protocol identity is malformed"
            )
        normalized_identity = ExternalSiteIdentity.interface(
            protocol_identity,
            context=f"{context} protocol identity",
        ).payload()
    abi_template = machine.get("abi_template")
    if not isinstance(abi_template, str):
        raise CheckedExternalSiteContractError(f"{context} ABI template is missing")
    if not isinstance(arguments, list) or not isinstance(callbacks, list):
        raise CheckedExternalSiteContractError(
            f"{context} has malformed argument or callback inventories"
        )
    if len(arguments) != argument_words:
        raise CheckedExternalSiteContractError(
            f"{context} argument inventory does not cover its exact prefix"
        )
    if arity_kind == "fixed":
        machine_arity = {"kind": "fixed", "words": machine.get("argument_words")}
        if machine_arity != authority_arity:
            raise CheckedExternalSiteContractError(
                f"{context} authority and machine arities disagree"
            )
    else:
        machine_profile_arity = machine.get("arity")
        if (
            machine.get("arity_contract") != authority_arity
            or machine.get("minimum_argument_words") != argument_words
            or machine.get("raw_caller_stack_suffix_forwarding")
            != authority_arity["raw_caller_stack_suffix_forwarding"]
            or not isinstance(machine_profile_arity, Mapping)
            or machine_profile_arity.get("kind") != "variadic"
            or machine_profile_arity.get("minimum_words") != argument_words
        ):
            raise CheckedExternalSiteContractError(
                f"{context} authority and machine variadic arities disagree"
            )
    if arity_kind == "variadic" and authority_callback_effect != "none":
        raise CheckedExternalSiteContractError(
            f"{context} variadic callback registration is unsupported"
        )
    _validate_authority_callback_source_decision(
        callback_source_decision,
        arguments=arguments,
        callbacks=callbacks,
        callback_effect=authority_callback_effect,
        context=context,
    )
    argument_base = 0 if transfer_kind == "call" else 4
    callback_effect = "none"
    callback_adapter = None
    callback_source_kind = (
        callback_source_decision.get("kind")
        if isinstance(callback_source_decision, Mapping)
        else None
    )
    if (
        authority_callback_effect == "registers"
        and callback_source_kind == "callback_target"
    ):
        callback_effect = "explicit"
        protocol = callback_protocol_from_machine_contract(
            machine, context=f"{context} callback protocol"
        )
        if protocol is not None:
            callback_source = None
            if protocol.source is not None:
                callback_source = {
                    "kind": protocol.source.kind,
                    "argument": protocol.source.argument,
                    **(
                        {"offset": protocol.source.offset}
                        if protocol.source.kind == "argument_pointee"
                        else {}
                    ),
                }
            callback_abi = {
                "kind": "generic_callback",
                "argument_words": protocol.signature.argument_words,
                "stack_cleanup_bytes": protocol.signature.stack_cleanup_bytes,
                "nullable": any(
                    row.kind == "null"
                    for row in (() if protocol.source is None else protocol.source.sentinels)
                ),
            }
            callback_lifetime = protocol.lifetime.to_payload()
            nested = parse_nested_native_callback_behavior(
                machine,
                registration_argument_words=argument_words,
                context=f"{context} callback protocol",
            )
            callback_behavior = (
                "registration" if nested is None else nested.as_json()
            )
            _validate_callback_previous_result_relation(
                protocol=protocol,
                machine=machine,
                context=context,
            )
        else:
            callback_source = machine.get("callback_source")
            callback_abi = machine.get("callback_abi")
            callback_lifetime = machine.get("callback_lifetime")
            callback_behavior = machine.get("callback_behavior", "registration")
        if not isinstance(callback_source, Mapping) or not isinstance(
            callback_abi, Mapping
        ) or not isinstance(callback_lifetime, (str, Mapping)):
            raise CheckedExternalSiteContractError(
                f"{context} callback adapter metadata is incomplete"
            )
        callback_adapter = {
            "source": dict(callback_source),
            "abi": dict(callback_abi),
            "lifetime": copy.deepcopy(callback_lifetime),
            "behavior": copy.deepcopy(callback_behavior),
            "activation": copy.deepcopy(machine.get("callback_activation")),
            "resource_binding": copy.deepcopy(machine.get("resource_binding")),
            "instance_binding": copy.deepcopy(machine.get("instance_binding")),
            "target_rvas": [
                _uint(
                    row.get("target_rva") if isinstance(row, Mapping) else None,
                    f"{context} callback target",
                )
                for row in callbacks
            ],
            "invocation": "nested-machine-ir-callback-adapter-v1",
        }
    return parse_checked_external_site_contract(
        {
            "format": CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT,
            "identity": normalized_identity,
            "transfer_kind": transfer_kind,
            "disposition": (
                "tail_jump"
                if disposition == "tail_jump"
                else "returns_here"
            ),
            "profile_disposition": (
                "terminates" if disposition == "noreturn" else "returns"
            ),
            "abi_template": abi_template,
            "arity": copy.deepcopy(authority_arity),
            "argument_base_offset": argument_base,
            "arguments": arguments,
            "stack_arguments": [
                {
                    "index": index,
                    "offset": argument_base + index * 4,
                    "width": 4,
                    "value": value,
                }
                for index, value in enumerate(arguments)
            ],
            "contract_id": contract_id,
            "profile_binding": {
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
            },
            "result_register_relations": copy.deepcopy(
                machine.get("result_register_relations", [])
            ),
            "memory_effect": memory_effect,
            "memory_footprints": copy.deepcopy(
                machine.get("memory_footprints", [])
            ),
            "argument_domain": copy.deepcopy(machine.get("argument_domain", [])),
            "world_effect": world_effect,
            "world_effect_argument": machine.get("world_effect_argument"),
            "world_effect_release": machine.get("world_effect_release"),
            "callback_effect": callback_effect,
            "callback_adapter": callback_adapter,
            "out_pointer_relations": copy.deepcopy(
                machine.get("out_pointer_relations", [])
            ),
            "out_interface_relations": copy.deepcopy(
                machine.get("out_interface_relations", [])
            ),
            "external_service_protocol": None,
        },
        context=context,
    )


def _validate_authority_callback_source_decision(
    value: object,
    *,
    arguments: list[object],
    callbacks: list[object],
    callback_effect: object,
    context: str,
) -> None:
    """Validate proof-only callback classification before runtime projection."""

    if value is None:
        return
    if callback_effect != "registers" or not isinstance(value, Mapping):
        raise CheckedExternalSiteContractError(
            f"{context} has a callback-source decision outside callback registration"
        )
    kind = value.get("kind")
    fields = {"kind", "argument_index", "source_expression"}
    if kind == "non_callback_sentinel":
        fields.add("sentinel_word")
    if set(value) != fields or kind not in {
        "callback_target",
        "non_callback_sentinel",
        "parametric_entry_word",
    }:
        raise CheckedExternalSiteContractError(
            f"{context} has a malformed callback-source decision"
        )
    argument_index = _uint(
        value.get("argument_index"),
        f"{context} callback-source argument index",
        maximum=max(0, len(arguments) - 1),
    )
    if not arguments or value.get("source_expression") != arguments[argument_index]:
        raise CheckedExternalSiteContractError(
            f"{context} callback-source decision disagrees with its argument"
        )
    if kind == "callback_target":
        if not callbacks:
            raise CheckedExternalSiteContractError(
                f"{context} callback-target decision has no target inventory"
            )
    elif callbacks:
        raise CheckedExternalSiteContractError(
            f"{context} non-target callback-source decision carries targets"
        )
    if kind == "non_callback_sentinel":
        _uint(
            value.get("sentinel_word"),
            f"{context} callback-source sentinel word",
        )


def _validate_callback_previous_result_relation(
    *, protocol: object, machine: Mapping[str, object], context: str
) -> None:
    previous = getattr(protocol, "previous_result")
    relations = machine.get("result_register_relations", [])
    if not isinstance(relations, list):
        raise CheckedExternalSiteContractError(
            f"{context} callback result relations are malformed"
        )
    related = [
        row
        for row in relations
        if isinstance(row, Mapping) and row.get("relation") == "related_word"
    ]
    if previous is None:
        if related:
            raise CheckedExternalSiteContractError(
                f"{context} callback has an undeclared previous result"
            )
        return
    if len(related) != 1 or related[0].get("register") != previous.register:
        raise CheckedExternalSiteContractError(
            f"{context} callback previous result is not bound to its machine register"
        )


def checked_external_site_contract_from_event(
    *,
    event: Mapping[str, Any],
    identity: ExternalSiteIdentity,
    transfer_kind: str,
    disposition: str,
    protocol_target: Mapping[str, Any] | None = None,
    callback_evidence: Mapping[str, Any] | None = None,
    resolved_machine_contract: Mapping[str, Any] | None = None,
    context: str,
) -> CheckedExternalSiteContract:
    """Normalize one machine-IR event plus its hash-bound profile resolution."""

    raw_contract = event.get("abi_contract")
    if not isinstance(raw_contract, Mapping):
        raw_contract = _resolved_event_machine_contract(
            event,
            resolved_machine_contract,
            transfer_kind=transfer_kind,
            context=context,
        )
    arity = raw_contract.get("arity")
    if isinstance(arity, Mapping) and arity.get("kind") == "variadic":
        raise CheckedExternalSiteContractError(
            f"{context} is variadic; native external sites require exact fixed arguments"
        )
    argument_words = _uint(
        raw_contract.get("argument_words"), f"{context} argument words", maximum=256
    )
    arguments = event.get("arguments")
    if (
        resolved_machine_contract is not None
        and (
            arguments is None
            or (argument_words > 0 and arguments == [])
        )
    ):
        arguments = _resolved_stack_arguments(
            event,
            argument_words=argument_words,
            argument_base_offset=_uint(
                raw_contract.get("argument_base_offset"),
                f"{context} argument base",
                maximum=0x10000,
            ),
            context=context,
        )
    if not isinstance(arguments, list) or len(arguments) != argument_words:
        raise CheckedExternalSiteContractError(f"{context} argument inventory is not exact")
    argument_base = _uint(
        raw_contract.get("argument_base_offset"), f"{context} argument base", maximum=0x10000
    )
    # Machine-IR ``stack_inputs`` is the transfer's complete stack-memory read
    # footprint, not an ordered call-argument list.  The exact ABI inventory is
    # already carried by ``arguments``; project that list into logical stack
    # slots without conflating unrelated spills or caller-frame reads.
    normalized_stack = [
        {
            "index": index,
            "offset": argument_base + index * 4,
            "width": 4,
            "value": value,
        }
        for index, value in enumerate(arguments)
    ]

    target = protocol_target or {}
    target_abi = target.get("abi") if isinstance(target, Mapping) else None
    abi_template = raw_contract.get("template")
    if isinstance(target_abi, Mapping):
        target_template = target_abi.get("template")
        if abi_template is None:
            abi_template = target_template
        elif abi_template != target_template:
            raise CheckedExternalSiteContractError(
                f"{context} event and protocol ABI templates disagree"
            )
    target_argument_words = target.get("argument_words") if isinstance(target, Mapping) else None
    if target_argument_words is not None and target_argument_words != argument_words:
        raise CheckedExternalSiteContractError(
            f"{context} event and protocol arities disagree"
        )

    callback_effect = raw_contract.get("callback_effect")
    if callback_effect is None and raw_contract.get("world_effect") == "callbackRegistration":
        callback_effect = "explicit"
    target_callback_effect = target.get("callback_effect") if isinstance(target, Mapping) else None
    if target_callback_effect is not None:
        target_callback_status = target.get("callback_contract_status")
        target_callback_blockers = target.get("callback_contract_blockers")
        if target_callback_effect == "explicit" and (
            target_callback_status != "complete"
            or target_callback_blockers != []
        ):
            raise CheckedExternalSiteContractError(
                f"{context} callback-bearing interface contract is incomplete"
            )
        if callback_effect is None:
            callback_effect = target_callback_effect
        elif callback_effect != target_callback_effect:
            raise CheckedExternalSiteContractError(
                f"{context} event and protocol callback effects disagree"
            )
    if callback_effect is None:
        raise CheckedExternalSiteContractError(
            f"{context} has no explicit callback-effect category"
        )

    def choose(field: str, default: Any = None) -> Any:
        event_value = raw_contract.get(field, default)
        target_value = target.get(field, default) if isinstance(target, Mapping) else default
        if event_value != default and target_value != default and _metadata(event_value) != _metadata(target_value):
            raise CheckedExternalSiteContractError(
                f"{context} event and protocol {field} disagree"
            )
        return event_value if event_value != default else target_value

    profile_binding = raw_contract.get("profile_binding")
    protocol = target.get("external_protocol") if isinstance(target, Mapping) else None
    if profile_binding is None and isinstance(protocol, Mapping):
        profile_binding = {
            "profile_id": protocol.get("profile_id"),
            "profile_sha256": protocol.get("profile_sha256"),
        }
    callback_adapter = None
    if callback_effect == "explicit":
        if (
            not isinstance(callback_evidence, Mapping)
            or callback_evidence.get("status") != "complete"
            or callback_evidence.get("failure") is not None
        ):
            raise CheckedExternalSiteContractError(
                f"{context} requires complete callback provenance evidence"
            )
        source = choose("callback_source")
        abi = choose("callback_abi")
        lifetime = choose("callback_lifetime")
        behavior = choose("callback_behavior", "registration")
        evidence_behavior = callback_evidence.get("callback_behavior")
        if evidence_behavior is None:
            evidence_behavior = "registration"
        if any((source is None, abi is None, lifetime is None)) or any(
            _metadata(expected) != _metadata(observed)
            for expected, observed in (
                (source, callback_evidence.get("callback_source")),
                (abi, callback_evidence.get("callback_abi")),
                (lifetime, callback_evidence.get("callback_lifetime")),
                (behavior, evidence_behavior),
            )
        ):
            raise CheckedExternalSiteContractError(
                f"{context} callback provenance disagrees with its machine contract"
            )
        target_rvas = callback_evidence.get("target_rvas")
        if not isinstance(target_rvas, list):
            raise CheckedExternalSiteContractError(
                f"{context} callback provenance has no finite target inventory"
            )
        activation = callback_evidence.get("callback_activation")
        resource_binding = None
        instance_binding = None
        if isinstance(behavior, Mapping):
            raw_instance = behavior.get("instance_binding")
            if not isinstance(raw_instance, Mapping):
                raise CheckedExternalSiteContractError(
                    f"{context} nested callback has no instance binding"
                )
            instance_evidence = callback_evidence.get("callback_instance")
            if not isinstance(instance_evidence, Mapping):
                raise CheckedExternalSiteContractError(
                    f"{context} nested callback has no checked instance evidence"
                )
            resource_binding = {
                "kind": "provider_callback_resource_v1",
                "provider_relation": behavior.get("provider_relation"),
                "callback_argument": behavior.get("resource_argument"),
            }
            instance_binding = {
                "kind": "registered_instance_callback_argument_v1",
                "callback_argument": raw_instance.get("callback_argument"),
                "registration_argument": raw_instance.get("registration_argument"),
                "registration_origins": instance_evidence.get("origins"),
            }
        callback_adapter = {
            "source": source,
            "abi": abi,
            "lifetime": lifetime,
            "behavior": behavior,
            "activation": activation,
            "resource_binding": resource_binding,
            "instance_binding": instance_binding,
            "target_rvas": target_rvas,
            "invocation": "nested-machine-ir-callback-adapter-v1",
        }
    payload = {
        "format": CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT,
        "identity": identity.payload(),
        "transfer_kind": transfer_kind,
        "disposition": disposition,
        "profile_disposition": raw_contract.get("disposition", "returns"),
        "abi_template": abi_template,
        "arity": {"kind": "fixed", "words": argument_words},
        "argument_base_offset": argument_base,
        "arguments": arguments,
        "stack_arguments": normalized_stack,
        "contract_id": choose("contract_id", target.get("id") if isinstance(target, Mapping) else None),
        "profile_binding": profile_binding,
        "result_register_relations": _metadata(choose("result_register_relations", [])),
        "memory_effect": choose("memory_effect"),
        "memory_footprints": _metadata(choose("memory_footprints", [])),
        "argument_domain": _metadata(choose("argument_domain", [])),
        "world_effect": choose("world_effect"),
        "world_effect_argument": choose("world_effect_argument"),
        "world_effect_release": choose("world_effect_release"),
        "callback_effect": callback_effect,
        "callback_adapter": callback_adapter,
        "out_pointer_relations": _metadata(choose("out_pointer_relations", [])),
        "out_interface_relations": _metadata(
            choose("out_interface_relations", target.get("out_interfaces", []) if isinstance(target, Mapping) else [])
        ),
        "external_service_protocol": _metadata(
            choose("external_service_protocol")
        ),
    }
    return parse_checked_external_site_contract(payload, context=context)


def _resolved_event_machine_contract(
    event: Mapping[str, Any],
    contract: Mapping[str, Any] | None,
    *,
    transfer_kind: str,
    context: str,
) -> dict[str, Any]:
    """Project a checked target contract onto an exact unresolved call event."""

    if not isinstance(contract, Mapping):
        raise CheckedExternalSiteContractError(
            f"{context} has no machine ABI contract"
        )
    arity = contract.get("arity")
    if not isinstance(arity, Mapping) or arity.get("kind") != "fixed":
        raise CheckedExternalSiteContractError(
            f"{context} resolved machine contract has no fixed arity"
        )
    argument_words = _uint(
        arity.get("words"), f"{context} resolved argument words", maximum=256
    )
    template = contract.get("abi_template")
    if template not in _PE32_ABIS:
        raise CheckedExternalSiteContractError(
            f"{context} resolved machine contract has no supported ABI"
        )
    profile_binding = contract.get("profile_binding")
    if not isinstance(profile_binding, Mapping):
        raise CheckedExternalSiteContractError(
            f"{context} resolved machine contract has no exact profile binding"
        )
    result = {
        "template": template,
        "argument_words": argument_words,
        "argument_base_offset": 0 if transfer_kind == "call" else 4,
        "contract_id": contract.get("id"),
        "profile_binding": copy.deepcopy(dict(profile_binding)),
        "disposition": contract.get("disposition"),
        "result_register_relations": copy.deepcopy(
            contract.get("result_register_relations", [])
        ),
        "memory_effect": contract.get("memory_effect"),
        "memory_footprints": copy.deepcopy(contract.get("memory_footprints", [])),
        "argument_domain": copy.deepcopy(contract.get("argument_domain", [])),
        "world_effect": contract.get("world_effect"),
        "world_effect_argument": contract.get("world_effect_argument"),
        "world_effect_release": copy.deepcopy(contract.get("world_effect_release")),
        "callback_effect": contract.get("callback_effect"),
        "out_pointer_relations": copy.deepcopy(
            contract.get("out_pointer_relations", [])
        ),
        "out_interface_relations": copy.deepcopy(
            contract.get("out_interface_relations", [])
        ),
        "external_service_protocol": copy.deepcopy(
            contract.get("external_service_protocol")
        ),
    }
    for field in (
        "callback_source",
        "callback_abi",
        "callback_behavior",
        "callback_lifetime",
    ):
        if field in contract:
            result[field] = copy.deepcopy(contract[field])
    return result


def _resolved_stack_arguments(
    event: Mapping[str, Any],
    *,
    argument_words: int,
    argument_base_offset: int,
    context: str,
) -> list[dict[str, Any]]:
    register_inputs = event.get("register_inputs")
    esp = register_inputs.get("esp") if isinstance(register_inputs, Mapping) else None
    if not isinstance(esp, Mapping):
        raise CheckedExternalSiteContractError(
            f"{context} has no exact call-site ESP expression"
        )
    result: list[dict[str, Any]] = []
    for index in range(argument_words):
        offset = argument_base_offset + index * 4
        address: Any = copy.deepcopy(dict(esp))
        if offset:
            address = {
                "op": "add32",
                "args": [
                    address,
                    {"op": "const", "value": offset, "width": 32},
                ],
            }
        result.append({"op": "load", "width": 4, "address": address})
    return result


def require_profile_match(
    contract: CheckedExternalSiteContract,
    *,
    profile_contract: Mapping[str, Any],
    profile_id: str,
    profile_sha256: str,
    entry_key: str,
    entry_index: int,
    context: str,
) -> None:
    """Require one selected machine-import profile to exactly match the site."""

    imported = profile_contract.get("import")
    if not isinstance(imported, Mapping):
        raise CheckedExternalSiteContractError(f"{context} profile has no import identity")
    if contract.identity != ExternalSiteIdentity.imported(imported, context=f"{context} profile"):
        raise CheckedExternalSiteContractError(f"{context} import identity differs from its profile")
    arity = profile_contract.get("arity")
    if isinstance(arity, Mapping):
        if arity.get("kind") != "fixed":
            raise CheckedExternalSiteContractError(f"{context} variadic sites are unsupported")
        profile_words = arity.get("words")
    else:
        profile_words = profile_contract.get("argument_words")
    try:
        profile_release = machine_range_release(profile_contract, argument_words=profile_words,
                                                context=context)
    except RangeReleaseError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    expected_binding = {
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "entry_key": entry_key,
        "entry_index": entry_index,
    }
    expected = {
        "contract_id": str(profile_contract.get("id")),
        "abi_template": profile_contract.get("abi_template"),
        "argument_words": profile_words,
        "disposition": profile_contract.get("disposition", "returns"),
        "result_register_relations": _metadata(profile_contract.get("result_register_relations", [])),
        "memory_effect": profile_contract.get("memory_effect"),
        "memory_footprints": _metadata(profile_contract.get("memory_footprints", [])),
        "argument_domain": _metadata(profile_contract.get("argument_domain", [])),
        "world_effect": profile_contract.get("world_effect"),
        "world_effect_argument": profile_contract.get("world_effect_argument"),
        "world_effect_release": profile_release.payload() if profile_release is not None else None,
        "callback_effect": (
            profile_contract.get("callback_effect")
            if profile_contract.get("callback_effect") is not None
            else "explicit"
            if (profile_contract.get("world_effect") == "callbackRegistration" or
                profile_contract.get("callback_protocol") is not None)
            else "none"
        ),
        "out_pointer_relations": _metadata(profile_contract.get("out_pointer_relations", [])),
        "out_interface_relations": _metadata(profile_contract.get("out_interface_relations", [])),
        "external_service_protocol": _metadata(
            profile_contract.get("external_service_protocol")
        ),
        "profile_binding": expected_binding,
    }
    observed = {
        "contract_id": contract.contract_id,
        "abi_template": contract.abi_template,
        "argument_words": contract.argument_words,
        "disposition": contract.profile_disposition,
        "result_register_relations": list(contract.result_register_relations),
        "memory_effect": contract.memory_effect,
        "memory_footprints": list(contract.memory_footprints),
        "argument_domain": list(contract.argument_domain),
        "world_effect": contract.world_effect,
        "world_effect_argument": contract.world_effect_argument,
        "world_effect_release": (contract.world_effect_release.payload()
                                 if contract.world_effect_release is not None else None),
        "callback_effect": contract.callback_effect,
        "out_pointer_relations": list(contract.out_pointer_relations),
        "out_interface_relations": list(contract.out_interface_relations),
        "external_service_protocol": _metadata(
            contract.external_service_protocol
        ),
        "profile_binding": contract.profile_binding,
    }
    if expected["callback_effect"] == "explicit":
        try:
            profile_source = parse_callback_source(
                profile_contract,
                argument_words=int(profile_words),
                context=f"{context} profile",
            ).as_json()
            profile_abi = parse_callback_abi(
                profile_contract, context=f"{context} profile"
            ).as_json()
            profile_behavior_value = parse_nested_native_callback_behavior(
                profile_contract,
                registration_argument_words=int(profile_words),
                context=f"{context} profile",
            )
        except ToolkitInputError as exc:
            raise CheckedExternalSiteContractError(str(exc)) from exc
        profile_behavior = (
            "registration"
            if profile_behavior_value is None
            else profile_behavior_value.as_json()
        )
        if contract.callback_adapter is None:
            raise CheckedExternalSiteContractError(
                f"{context} has no checked callback adapter"
            )
        expected["callback_contract"] = {
            "source": profile_source,
            "abi": profile_abi,
            "lifetime": _metadata(profile_contract.get("callback_lifetime")),
            "behavior": _metadata(profile_behavior),
        }
        observed["callback_contract"] = {
            "source": contract.callback_adapter.source,
            "abi": contract.callback_adapter.abi,
            "lifetime": contract.callback_adapter.lifetime,
            "behavior": contract.callback_adapter.behavior,
        }
    if observed != expected:
        differing = sorted(key for key in expected if expected[key] != observed[key])
        raise CheckedExternalSiteContractError(
            f"{context} differs from its selected profile in: {', '.join(differing)}"
        )
