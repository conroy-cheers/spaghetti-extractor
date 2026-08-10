"""Canonical, fail-closed machine contracts for native external call sites.

The state-machine exporter, native bridge planner, and native runtime used to
interpret overlapping subsets of external-call metadata independently.  This
module provides the one normalized boundary object shared by the latter two
consumers.  It has no proof authority; it makes omissions and disagreement
explicit so the static completeness gate can reject them.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .callback_contracts import (
    parse_callback_abi,
    parse_callback_source,
    parse_nested_native_callback_behavior,
)
from .stage_binary import StageAInputError


CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT = "stage-b-checked-external-site-contract-v1"
_PE32_ABIS = frozenset({"pe32-cdecl-v1", "pe32-stdcall-v1"})
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})
class CheckedExternalSiteContractError(StageAInputError):
    """An external site is missing an exact, executable machine contract."""


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

    def payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "width": self.width,
            "value": _json(self.value, "stack argument value"),
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

    def payload(self) -> dict[str, Any]:
        return {
            "source": _json(self.source, "callback source"),
            "abi": _json(self.abi, "callback ABI"),
            "lifetime": _json(self.lifetime, "callback lifetime"),
            "behavior": _json(self.behavior, "callback behavior"),
            "activation": _json(self.activation, "callback activation"),
            "resource_binding": _json(
                self.resource_binding, "callback resource binding"
            ),
            "instance_binding": _json(
                self.instance_binding, "callback instance binding"
            ),
            "target_rvas": list(self.target_rvas),
            "invocation": self.invocation,
        }


@dataclass(frozen=True)
class CheckedExternalSiteContract:
    identity: ExternalSiteIdentity
    transfer_kind: str
    disposition: str
    profile_disposition: str
    abi_template: str
    argument_words: int
    argument_base_offset: int
    arguments: tuple[Any, ...]
    stack_arguments: tuple[CheckedStackArgument, ...]
    contract_id: str
    profile_binding: Any
    result_register_relations: tuple[Any, ...]
    memory_effect: str
    memory_footprints: tuple[Any, ...]
    world_effect: str
    callback_effect: str
    callback_adapter: CheckedCallbackAdapter | None
    out_pointer_relations: tuple[Any, ...] = ()
    out_interface_relations: tuple[Any, ...] = ()

    def payload(self) -> dict[str, Any]:
        return {
            "format": CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT,
            "identity": self.identity.payload(),
            "transfer_kind": self.transfer_kind,
            "disposition": self.disposition,
            "profile_disposition": self.profile_disposition,
            "abi_template": self.abi_template,
            "arity": {"kind": "fixed", "words": self.argument_words},
            "argument_base_offset": self.argument_base_offset,
            "arguments": [_json(value, "argument") for value in self.arguments],
            "stack_arguments": [value.payload() for value in self.stack_arguments],
            "contract_id": self.contract_id,
            "profile_binding": _json(self.profile_binding, "profile binding"),
            "result_register_relations": [
                _json(value, "result relation") for value in self.result_register_relations
            ],
            "memory_effect": self.memory_effect,
            "memory_footprints": [
                _json(value, "memory footprint") for value in self.memory_footprints
            ],
            "world_effect": self.world_effect,
            "callback_effect": self.callback_effect,
            "callback_adapter": (
                None if self.callback_adapter is None else self.callback_adapter.payload()
            ),
            "out_pointer_relations": [
                _json(value, "out-pointer relation") for value in self.out_pointer_relations
            ],
            "out_interface_relations": [
                _json(value, "out-interface relation")
                for value in self.out_interface_relations
            ],
        }

    def profile_effect_payload(self) -> dict[str, Any]:
        """Return the normalized profile fields consumed by runtime effect rules."""

        return {
            "id": self.contract_id,
            "argument_words": self.argument_words,
            "result_register_relations": list(self.result_register_relations),
            "memory_effect": self.memory_effect,
            "memory_footprints": list(self.memory_footprints),
            "world_effect": self.world_effect,
            "callback_effect": self.callback_effect,
            "out_pointer_relations": list(self.out_pointer_relations),
            "out_interface_relations": list(self.out_interface_relations),
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
    if profile_disposition not in {"returns", "terminates"}:
        raise CheckedExternalSiteContractError(
            f"{context} profile disposition is unsupported"
        )
    abi_template = value.get("abi_template")
    if abi_template not in _PE32_ABIS:
        raise CheckedExternalSiteContractError(f"{context} ABI template is unsupported")
    arity = value.get("arity")
    if not isinstance(arity, Mapping) or arity.get("kind") != "fixed":
        raise CheckedExternalSiteContractError(
            f"{context} variadic or missing arity is unsupported"
        )
    argument_words = _uint(arity.get("words"), f"{context} argument words", maximum=256)
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
    return CheckedExternalSiteContract(
        identity=identity,
        transfer_kind=str(transfer_kind),
        disposition=str(disposition),
        profile_disposition=str(profile_disposition),
        abi_template=str(abi_template),
        argument_words=argument_words,
        argument_base_offset=argument_base_offset,
        arguments=normalized_arguments,
        stack_arguments=tuple(normalized_stack),
        contract_id=contract_id,
        profile_binding=_json(profile_binding, f"{context} profile binding"),
        result_register_relations=tuple(_json(item, f"{context} result relation") for item in result_relations),
        memory_effect=memory_effect,
        memory_footprints=tuple(_json(item, f"{context} footprint") for item in memory_footprints),
        world_effect=world_effect,
        callback_effect=str(callback_effect),
        callback_adapter=parsed_callback,
        out_pointer_relations=tuple(_json(item, f"{context} out pointer") for item in out_pointers),
        out_interface_relations=tuple(_json(item, f"{context} out interface") for item in out_interfaces),
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
    if arguments is None and resolved_machine_contract is not None:
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
        "world_effect": choose("world_effect"),
        "callback_effect": callback_effect,
        "callback_adapter": callback_adapter,
        "out_pointer_relations": _metadata(choose("out_pointer_relations", [])),
        "out_interface_relations": _metadata(
            choose("out_interface_relations", target.get("out_interfaces", []) if isinstance(target, Mapping) else [])
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
        "world_effect": contract.get("world_effect"),
        "callback_effect": contract.get("callback_effect"),
        "out_pointer_relations": copy.deepcopy(
            contract.get("out_pointer_relations", [])
        ),
        "out_interface_relations": copy.deepcopy(
            contract.get("out_interface_relations", [])
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
        "world_effect": profile_contract.get("world_effect"),
        "callback_effect": (
            profile_contract.get("callback_effect")
            if profile_contract.get("callback_effect") is not None
            else "explicit"
            if profile_contract.get("world_effect") == "callbackRegistration"
            else None
        ),
        "out_pointer_relations": _metadata(profile_contract.get("out_pointer_relations", [])),
        "out_interface_relations": _metadata(profile_contract.get("out_interface_relations", [])),
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
        "world_effect": contract.world_effect,
        "callback_effect": contract.callback_effect,
        "out_pointer_relations": list(contract.out_pointer_relations),
        "out_interface_relations": list(contract.out_interface_relations),
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
        except StageAInputError as exc:
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
