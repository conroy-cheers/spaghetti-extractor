"""Canonical runtime identities, callback capabilities, and guest dispatch."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.contracts import (
    CheckedCallbackAdapter,
    CheckedExternalSiteContract,
    CheckedStackArgument,
    ExternalSiteIdentity,
)
from ..transfer.model import _Call, _Transfer
from .module_runtime_plan import (
    NativeGuestDispatchDomain,
    NativeGuestDispatchSite,
)
from .native_ingress_runtime_model import (
    CompactCallbackRuntimeV1,
    compact_callback_runtime_v1,
)
from .runtime_canonical_errors import CanonicalRuntimeError

def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalRuntimeError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CanonicalRuntimeError(f"{label} must be an object")
    return value


def _closed_content_id(
    payload: Mapping[str, Any], *, field: str, label: str
) -> str:
    observed = payload.get(field)
    core = {key: value for key, value in payload.items() if key != field}
    if not isinstance(observed, str) or observed != canonical_sha256_v3(core):
        raise CanonicalRuntimeError(f"{label} is stale")
    return observed


def _profile_metadata(value: Any) -> Any:
    """Normalize profile spelling once, matching the checked-contract codec."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = "byte_count" if raw_key == "bytes" else str(raw_key)
            if key in result:
                raise CanonicalRuntimeError(
                    f"external profile metadata collides at {key!r}"
                )
            result[key] = _profile_metadata(item)
        return result
    if isinstance(value, list):
        return [_profile_metadata(item) for item in value]
    return value


def _identity_key(value: Mapping[str, Any]) -> tuple[str, str, str | int]:
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    if not isinstance(dll, str) or not dll:
        raise CanonicalRuntimeError("resolved import identity has no DLL")
    if isinstance(symbol, str) and symbol and ordinal is None:
        return (dll.lower(), "symbol", symbol)
    if (
        isinstance(ordinal, int) and not isinstance(ordinal, bool)
        and 0 <= ordinal <= 0xFFFF and symbol is None
    ):
        return (dll.lower(), "ordinal", ordinal)
    raise CanonicalRuntimeError(
        "resolved import identity must name exactly one symbol or ordinal"
    )


def _call_key(call: _Call) -> tuple[str, str, str | int]:
    if call.dll is None:
        raise CanonicalRuntimeError("external transfer call has no resolved DLL")
    if call.symbol is not None and call.ordinal is None:
        return (call.dll.lower(), "symbol", call.symbol)
    if call.ordinal is not None and call.symbol is None:
        return (call.dll.lower(), "ordinal", call.ordinal)
    raise CanonicalRuntimeError(
        "external transfer call must name exactly one symbol or ordinal"
    )


def _environment_import_index(
    environment: Mapping[str, Any],
) -> dict[tuple[str, str, str | int], dict[str, Any]]:
    rows = environment.get("original_semantic_imports")
    if not isinstance(rows, list):
        raise CanonicalRuntimeError(
            "resolved external environment semantic imports are malformed"
        )
    combined_rows = list(rows)
    loader_rows = environment.get("loader_service_contracts")
    if not isinstance(loader_rows, list):
        raise CanonicalRuntimeError(
            "resolved external environment loader services are malformed"
        )
    for raw_loader in loader_rows:
        if not isinstance(raw_loader, Mapping):
            raise CanonicalRuntimeError("resolved loader service is malformed")
        catalog = raw_loader.get("resolution_catalog", [])
        if not isinstance(catalog, list):
            raise CanonicalRuntimeError(
                "resolved loader-service resolution catalog is malformed"
            )
        for raw_target in catalog:
            if (
                not isinstance(raw_target, Mapping)
                or raw_target.get("dynamic_export_kind") != "code"
            ):
                continue
            combined_rows.append(raw_target)
    result: dict[tuple[str, str, str | int], dict[str, Any]] = {}
    for index, raw in enumerate(combined_rows):
        if not isinstance(raw, Mapping):
            raise CanonicalRuntimeError(
                f"resolved semantic import {index} is malformed"
            )
        identity = raw.get("identity")
        contract = raw.get("contract")
        boundary = raw.get("boundary")
        if not all(isinstance(item, Mapping) for item in (
            identity, contract, boundary,
        )):
            raise CanonicalRuntimeError(
                f"resolved semantic import {index} is incomplete"
            )
        key = _identity_key(identity)
        prior = result.get(key)
        row = dict(raw)
        if prior is not None and prior != row:
            raise CanonicalRuntimeError(
                f"resolved semantic import identity {key!r} is ambiguous"
            )
        result[key] = row
    return result


def _loader_service_index(
    environment: Mapping[str, Any],
) -> dict[tuple[str, str, str | int], dict[str, Any]]:
    """Index checked loader services by their existing import identity.

    Loader services publish capabilities into the callable domain; they do not
    introduce a second catalog of admissible code targets.
    """

    rows = environment.get("loader_service_contracts")
    if not isinstance(rows, list):
        raise CanonicalRuntimeError(
            "resolved external environment loader services are malformed"
        )
    result: dict[tuple[str, str, str | int], dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise CanonicalRuntimeError(
                f"resolved loader service {index} is malformed"
            )
        identity = raw.get("identity")
        contract = raw.get("contract")
        payload = contract.get("payload") if isinstance(contract, Mapping) else None
        service = payload.get("loader_service") if isinstance(payload, Mapping) else None
        if not isinstance(identity, Mapping) or not isinstance(service, Mapping):
            raise CanonicalRuntimeError(
                f"resolved loader service {index} is incomplete"
            )
        key = _identity_key(identity)
        kind = service.get("kind")
        if kind == "module_handle":
            argument = service.get("module_name_argument")
            nullable = service.get("nullable_module_name")
            if (
                key[0] != "kernel32.dll"
                or key[1] != "symbol"
                or key[2] not in {"GetModuleHandleA", "GetModuleHandleW"}
                or not isinstance(argument, int)
                or isinstance(argument, bool)
                or argument < 0
                or not isinstance(nullable, bool)
            ):
                raise CanonicalRuntimeError(
                    f"resolved loader service {index} has an invalid module-handle contract"
                )
            normalized = {
                "kind": "module_handle",
                "module_name_argument": argument,
                "nullable_module_name": nullable,
                "wide_name": key[2] == "GetModuleHandleW",
                "contract_sha256": canonical_sha256_v3(dict(raw)),
            }
        elif kind == "dynamic_export_resolution":
            module_argument = service.get("module_handle_argument")
            export_argument = service.get("export_name_argument")
            if (
                key != ("kernel32.dll", "symbol", "GetProcAddress")
                or not isinstance(module_argument, int)
                or isinstance(module_argument, bool)
                or module_argument < 0
                or not isinstance(export_argument, int)
                or isinstance(export_argument, bool)
                or export_argument < 0
            ):
                raise CanonicalRuntimeError(
                    f"resolved loader service {index} has an invalid export-resolution contract"
                )
            normalized = {
                "kind": "dynamic_export_resolution",
                "module_handle_argument": module_argument,
                "export_name_argument": export_argument,
                "contract_sha256": canonical_sha256_v3(dict(raw)),
            }
        else:
            raise CanonicalRuntimeError(
                f"resolved loader service {index} has unsupported kind {kind!r}"
            )
        prior = result.get(key)
        if prior is not None and prior != normalized:
            raise CanonicalRuntimeError(
                f"resolved loader service identity {key!r} is ambiguous"
            )
        result[key] = normalized
    return result


def _callback_escape_index(
    closure: Mapping[str, Any],
) -> dict[tuple[int, str], dict[str, Any]]:
    result: dict[tuple[int, str], dict[str, Any]] = {}
    for raw in closure["callback_escapes"]:
        escape = dict(raw)
        key = (int(escape["instruction_rva"]), str(escape["protocol_id"]))
        if key in result:
            # Multiple rows at a site are meaningful only when their exact
            # protocol facts agree; combine finite targets deterministically.
            prior = result[key]
            comparable = {
                name: value for name, value in escape.items() if name != "targets"
            }
            prior_comparable = {
                name: value for name, value in prior.items() if name != "targets"
            }
            if comparable != prior_comparable:
                raise CanonicalRuntimeError(
                    "execution closure callback escapes are ambiguous"
                )
            targets = sorted(set(prior["targets"] or ()) | set(escape["targets"] or ()))
            prior["targets"] = targets
        else:
            result[key] = escape
    return result


@dataclass(frozen=True)
class _CallbackCapabilityAuthority:
    eager: Mapping[tuple[int, str, int], str]
    compact: Mapping[tuple[int, str], Mapping[str, Any]]
    interface_compact: Mapping[str, Mapping[str, Any]]
    compact_runtime: CompactCallbackRuntimeV1


def _callback_capability_index(
    *, closure: Mapping[str, Any], ingress: Mapping[str, Any], image_id: str,
) -> _CallbackCapabilityAuthority:
    """Join each callback escape target to its exact native capability.

    A target RVA is not a capability identity: the same function may escape at
    several registration sites under different lifetime rules.  Preserve the
    closure escape identity so those authorities can share a bridge address
    without sharing activation or generation state.
    """

    callback_rows: dict[tuple[str, int], Mapping[str, Any]] = {}
    for index, raw in enumerate(ingress.get("ingresses", [])):
        if not isinstance(raw, Mapping) or raw.get("role") != "callback":
            continue
        roots = raw.get("root_ids")
        target = raw.get("target_rva")
        capability_id = raw.get("capability_id")
        if (
            not isinstance(roots, list) or len(roots) != 1
            or not isinstance(roots[0], str) or not roots[0]
            or not isinstance(target, int) or isinstance(target, bool)
            or not isinstance(capability_id, str) or not capability_id
        ):
            raise CanonicalRuntimeError(
                f"native callback ingress {index} has malformed capability authority"
            )
        key = (roots[0], target)
        if key in callback_rows:
            raise CanonicalRuntimeError(
                "native ingress repeats one closure callback capability"
            )
        callback_rows[key] = raw

    result: dict[tuple[int, str, int], str] = {}
    compact_runtime = compact_callback_runtime_v1(ingress)
    compact_domains = {
        domain.identity: domain for domain in compact_runtime.domains
    }
    compact_publications = {
        str(row["escape_id"]): row
        for row in compact_runtime.publications
        if row.get("source_kind") != "interface_method"
    }
    interface_publications = {
        str(row["source_id"]): row
        for row in compact_runtime.publications
        if row.get("source_kind") == "interface_method"
        and isinstance(row.get("source_id"), str)
    }
    if len(compact_publications) != len(compact_runtime.publications):
        if len(compact_publications) + len(interface_publications) != len(
            compact_runtime.publications
        ):
            raise CanonicalRuntimeError(
                "native ingress repeats or malforms a compact callback publication"
            )
    for method_sha256, publication in interface_publications.items():
        if (
            publication.get("escape_id")
            != "interface-method-callback-v1:" + method_sha256
            or publication.get("instruction_rva") != 0
            or publication.get("identity") != method_sha256
        ):
            raise CanonicalRuntimeError(
                "native ingress interface callback publication is stale"
            )
    compact_result: dict[tuple[int, str], Mapping[str, Any]] = {}
    consumed: set[tuple[str, int]] = set()
    consumed_compact: set[str] = set()
    for index, raw in enumerate(closure.get("callback_escapes", [])):
        if not isinstance(raw, Mapping):
            raise CanonicalRuntimeError(
                f"execution closure callback escape {index} is malformed"
            )
        escape = dict(raw)
        instruction_rva = escape.get("instruction_rva")
        protocol_id = escape.get("protocol_id")
        targets = escape.get("targets")
        if targets is None:
            continue
        if (
            not isinstance(instruction_rva, int)
            or isinstance(instruction_rva, bool)
            or not isinstance(protocol_id, str) or not protocol_id
            or not isinstance(targets, list)
        ):
            raise CanonicalRuntimeError(
                f"execution closure callback escape {index} is malformed"
            )
        root_id = "callback-escape-v1:" + canonical_sha256_v3(escape)
        compact_publication = compact_publications.get(root_id)
        if compact_publication is not None:
            domain = compact_domains[str(compact_publication["domain_id"])]
            if (
                domain.protocol_id != protocol_id
                or tuple(targets) != tuple(
                    target.target_rva for target in domain.targets
                )
                or compact_publication.get("instruction_rva") != instruction_rva
                or compact_publication.get("lifetime") != escape.get("lifetime")
            ):
                raise CanonicalRuntimeError(
                    "native ingress compact callback authority is stale"
                )
            authority_key = (instruction_rva, protocol_id)
            if authority_key in compact_result:
                raise CanonicalRuntimeError(
                    "compact callback registration authority is ambiguous"
                )
            compact_result[authority_key] = compact_publication
            consumed_compact.add(root_id)
            continue
        for target in targets:
            if not isinstance(target, int) or isinstance(target, bool):
                raise CanonicalRuntimeError(
                    f"execution closure callback escape {index} target is malformed"
                )
            ingress_key = (root_id, target)
            row = callback_rows.get(ingress_key)
            if row is None:
                raise CanonicalRuntimeError(
                    "native ingress omits an exact closure callback capability"
                )
            expected_id = "code-capability-v1:" + canonical_sha256_v3({
                "module": image_id,
                "escape": escape,
                "target_rva": target,
            })
            if (
                row.get("capability_id") != expected_id
                or row.get("capability_lifetime") != escape.get("lifetime")
            ):
                raise CanonicalRuntimeError(
                    "native ingress callback capability is stale or changes lifetime"
                )
            authority_key = (instruction_rva, protocol_id, target)
            if authority_key in result:
                raise CanonicalRuntimeError(
                    "callback target has ambiguous registration authority"
                )
            result[authority_key] = expected_id
            consumed.add(ingress_key)
    if consumed != set(callback_rows):
        raise CanonicalRuntimeError(
            "native ingress contains callback capability outside the execution closure"
        )
    if consumed_compact != set(compact_publications):
        raise CanonicalRuntimeError(
            "native ingress contains compact callback publication outside the execution closure"
        )
    return _CallbackCapabilityAuthority(
        eager=result,
        compact=compact_result,
        interface_compact=interface_publications,
        compact_runtime=compact_runtime,
    )


def _callback_adapter(
    *,
    protocol: Mapping[str, Any],
    escape: Mapping[str, Any],
) -> CheckedCallbackAdapter:
    source = protocol.get("source")
    signature = protocol.get("signature")
    lifetime = protocol.get("lifetime")
    if not all(isinstance(item, Mapping) for item in (
        source, signature, lifetime,
    )):
        raise CanonicalRuntimeError("resolved callback protocol is incomplete")
    source_kind = source.get("kind")
    argument = source.get("argument")
    if (
        source_kind not in {"argument_word", "argument_pointee"}
        or not isinstance(argument, int) or isinstance(argument, bool)
        or argument < 0
    ):
        raise CanonicalRuntimeError("resolved callback source is unsupported")
    sentinel_words = []
    for sentinel in source.get("sentinels", []):
        word = sentinel.get("word") if isinstance(sentinel, Mapping) else None
        if (
            not isinstance(sentinel, Mapping)
            or sentinel.get("kind") not in {"null", "default", "ignore"}
            or not isinstance(word, int) or isinstance(word, bool)
            or not 0 <= word <= 0xFFFFFFFF
        ):
            raise CanonicalRuntimeError(
                "resolved callback source uses an unsupported sentinel"
            )
        sentinel_words.append(word)
    canonical_source: dict[str, Any] = {
        "kind": source_kind,
        "argument": argument,
    }
    if source_kind == "argument_word":
        canonical_source["non_callback_sentinel_words"] = sorted(
            set(sentinel_words)
        )
    else:
        canonical_source["offset"] = int(source.get("offset", 0))
    argument_words = signature.get("argument_words")
    cleanup = signature.get("stack_cleanup_bytes")
    result = signature.get("result")
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in (argument_words, cleanup)
    ) or not isinstance(result, Mapping):
        raise CanonicalRuntimeError("resolved callback ABI is malformed")
    targets = escape.get("targets")
    if not isinstance(targets, list) or not targets:
        raise CanonicalRuntimeError(
            "complete execution closure callback escape has no finite target"
        )
    return CheckedCallbackAdapter(
        source=canonical_source,
        abi={
            "kind": "generic_callback",
            "argument_words": argument_words,
            "stack_cleanup_bytes": cleanup,
            "nullable": 0 in sentinel_words,
            "result": dict(result),
        },
        lifetime=dict(lifetime),
        behavior="registration",
        activation=None,
        resource_binding=None,
        instance_binding=None,
        target_rvas=tuple(targets),
        invocation="nested-machine-ir-callback-adapter-v1",
    )


def _checked_contract(
    *,
    row: Mapping[str, Any],
    call: _Call,
    escape_index: Mapping[tuple[int, str], Mapping[str, Any]],
    tail_jump: bool = False,
) -> CheckedExternalSiteContract:
    identity = row["identity"]
    contract_binding = row["contract"]
    payload = contract_binding.get("payload")
    boundary = row["boundary"]
    if not isinstance(payload, Mapping):
        raise CanonicalRuntimeError("resolved import contract payload is malformed")
    profile = _profile_metadata(payload)
    argument_words = profile.get("argument_words")
    if not isinstance(argument_words, int) or isinstance(argument_words, bool):
        arity = profile.get("arity")
        if isinstance(arity, Mapping) and arity.get("kind") == "fixed":
            argument_words = arity.get("words")
        elif isinstance(arity, Mapping) and arity.get("kind") == "variadic":
            # The fixed prefix is the portion imported into typed runtime
            # arguments.  The checked forwarding rule transports the raw
            # caller suffix without guessing a total variadic argument count.
            argument_words = arity.get(
                "minimum_words", profile.get("minimum_argument_words")
            )
        else:
            argument_words = None
    if not isinstance(argument_words, int) or not 0 <= argument_words <= 256:
        raise CanonicalRuntimeError("resolved import argument count is malformed")
    arity = profile.get("arity")
    if not isinstance(arity, Mapping):
        arity = {"kind": "fixed", "words": argument_words}
    arity_kind = arity.get("kind")
    if arity_kind == "fixed":
        forwarding = None
    elif arity_kind == "variadic":
        forwarding = arity.get(
            "raw_caller_stack_suffix_forwarding",
            profile.get("raw_caller_stack_suffix_forwarding"),
        )
    else:
        raise CanonicalRuntimeError("resolved import arity is unsupported")
    argument_nodes = list(call.argument_nodes)
    argument_base_offset = 4 if tail_jump else 0
    arguments = tuple(
        {
            "kind": "transfer_expression_node",
            "node": argument_nodes[index],
        }
        if index < len(argument_nodes)
        else {
            "kind": "captured_stack_word",
            "offset": argument_base_offset + 4 * index,
        }
        for index in range(argument_words)
    )
    stack_arguments = tuple(
        CheckedStackArgument(
            index,
            argument_base_offset + 4 * index,
            4,
            arguments[index],
        )
        for index in range(argument_words)
    )
    callback_protocol = boundary.get("callback_protocol")
    adapter = None
    if callback_protocol is not None:
        if not isinstance(callback_protocol, Mapping):
            raise CanonicalRuntimeError("resolved callback protocol is malformed")
        protocol_id = callback_protocol.get("id")
        if not isinstance(protocol_id, str) or not protocol_id:
            raise CanonicalRuntimeError("resolved callback protocol has no identity")
        escape = escape_index.get((call.instruction_rva, protocol_id))
        if escape is None:
            raise CanonicalRuntimeError(
                "complete execution closure omits a resolved callback escape"
            )
        adapter = _callback_adapter(protocol=callback_protocol, escape=escape)
    profile_disposition = profile.get("disposition", "returns")
    if profile_disposition not in {"returns", "terminates", "nonlocal"}:
        raise CanonicalRuntimeError("resolved import disposition is unsupported")
    symbol = identity.get("symbol")
    ordinal = identity.get("ordinal")
    external_identity = ExternalSiteIdentity(
        kind="import",
        dll=str(identity["dll"]).lower(),
        symbol=str(symbol) if isinstance(symbol, str) else None,
        ordinal=int(ordinal) if isinstance(ordinal, int) else None,
    )
    out_pointers = boundary.get("out_pointer_relations", [])
    out_interfaces = profile.get("out_interface_relations", [])
    if not isinstance(out_pointers, list) or not isinstance(out_interfaces, list):
        raise CanonicalRuntimeError("resolved import relation inventory is malformed")
    return CheckedExternalSiteContract(
        identity=external_identity,
        # Machine transfer and callee outcome are independent facts.  A
        # returning callee reached by JMP still returns to the saved caller
        # continuation, while a no-return callee can be reached by CALL.
        transfer_kind="jump" if tail_jump else "call",
        disposition="tail_jump" if tail_jump else "returns_here",
        profile_disposition=str(profile_disposition),
        abi_template=str(profile.get("abi_template")),
        arity_kind=str(arity_kind),
        argument_words=argument_words,
        raw_caller_stack_suffix_forwarding=forwarding,
        argument_base_offset=argument_base_offset,
        arguments=arguments,
        stack_arguments=stack_arguments,
        contract_id=str(profile.get("id")),
        profile_binding={
            key: contract_binding.get(key)
            for key in (
                "profile_id", "profile_sha256", "entry_key", "entry_index"
            )
        },
        result_register_relations=tuple(
            profile.get("result_register_relations", [])
        ),
        memory_effect=str(profile.get("memory_effect", "none")),
        memory_footprints=tuple(profile.get("memory_footprints", [])),
        world_effect=str(profile.get("world_effect", "none")),
        world_effect_argument=profile.get("world_effect_argument"),
        callback_effect="explicit" if adapter is not None else "none",
        callback_adapter=adapter,
        out_pointer_relations=tuple(out_pointers),
        out_interface_relations=tuple(out_interfaces),
        external_service_protocol=profile.get(
            "external_service_protocol"
        ),
    )


def _checked_interface_method_contract(
    *,
    target: Mapping[str, Any],
    call: _Call,
    tail_jump: bool,
    callback_protocol: Mapping[str, Any] | None = None,
    callback_target_rvas: tuple[int, ...] = (),
) -> CheckedExternalSiteContract:
    """Bind one admitted interface method to the exact physical call site."""

    method = target.get("method")
    if not isinstance(method, Mapping):
        raise CanonicalRuntimeError("interface target has no method contract")
    protocol = method.get("external_protocol")
    abi = method.get("abi")
    profile_binding = method.get("profile_binding")
    receiver = method.get("receiver_resource")
    argument_words = method.get("argument_words")
    if (
        not isinstance(protocol, Mapping)
        or not isinstance(abi, Mapping)
        or not isinstance(profile_binding, Mapping)
        or not isinstance(receiver, Mapping)
        or not isinstance(argument_words, int)
        or isinstance(argument_words, bool)
        or not 1 <= argument_words <= 256
        or protocol.get("kind") != "pe32-interface-method"
        or protocol.get("profile_sha256") != target.get("profile_sha256")
        or protocol.get("interface_id") != target.get("interface_id")
        or receiver != profile_binding.get("receiver_resource")
    ):
        raise CanonicalRuntimeError("interface method contract is incomplete")
    callback_effect = method.get("callback_effect")
    adapter = None
    if callback_effect == "explicit":
        if callback_protocol is None or not callback_target_rvas:
            raise CanonicalRuntimeError(
                "interface method callback has no checked native capability domain"
            )
        callback_core = {
            "abi": dict(method.get("callback_abi", {})),
            "arguments": list(method.get("callback_arguments", [])),
            "lifetime": method.get("callback_lifetime"),
            "source": dict(method.get("callback_source", {})),
        }
        expected_protocol_id = (
            "interface-callback-v1:" + canonical_sha256_v3(callback_core)
        )
        if callback_protocol.get("id") != expected_protocol_id:
            raise CanonicalRuntimeError(
                "interface method callback protocol differs from its method contract"
            )
        adapter = _callback_adapter(
            protocol=callback_protocol,
            escape={"targets": list(callback_target_rvas)},
        )
    elif callback_effect != "none":
        raise CanonicalRuntimeError(
            "interface method callback authority is malformed"
        )
    argument_base_offset = 4 if tail_jump else 0
    argument_nodes = list(call.argument_nodes)
    arguments = tuple(
        {
            "kind": "transfer_expression_node",
            "node": argument_nodes[index],
        }
        if index < len(argument_nodes)
        else {
            "kind": "captured_stack_word",
            "offset": argument_base_offset + 4 * index,
        }
        for index in range(argument_words)
    )
    stack_arguments = tuple(
        CheckedStackArgument(
            index,
            argument_base_offset + 4 * index,
            4,
            arguments[index],
        )
        for index in range(argument_words)
    )
    out_interfaces = method.get("out_interfaces", [])
    footprints = method.get("memory_footprints", [])
    if not isinstance(out_interfaces, list) or not isinstance(footprints, list):
        raise CanonicalRuntimeError("interface method effects are malformed")
    operation = f"{protocol.get('interface_id')}::{protocol.get('method')}"
    return CheckedExternalSiteContract(
        identity=ExternalSiteIdentity.interface(
            protocol, context="admitted interface method"
        ),
        transfer_kind="jump" if tail_jump else "call",
        disposition="tail_jump" if tail_jump else "returns_here",
        profile_disposition="returns",
        abi_template=str(abi.get("template")),
        arity_kind="fixed",
        argument_words=argument_words,
        raw_caller_stack_suffix_forwarding=None,
        argument_base_offset=argument_base_offset,
        arguments=arguments,
        stack_arguments=stack_arguments,
        contract_id=(
            f"interface-method:{target.get('profile_sha256')}:{operation}"
        ),
        profile_binding=dict(profile_binding),
        result_register_relations=({
            "register": "eax", "relation": "exact",
        },),
        memory_effect=str(method.get("memory_effect")),
        memory_footprints=tuple(footprints),
        world_effect=str(method.get("world_effect")),
        world_effect_argument=None,
        callback_effect=str(callback_effect),
        callback_adapter=adapter,
        out_pointer_relations=(),
        out_interface_relations=tuple(out_interfaces),
        external_service_protocol=None,
    )


def _indirect_external_index(
    closure: Mapping[str, Any],
) -> dict[str, tuple[tuple[str, str, str | int], ...]]:
    result: dict[str, tuple[tuple[str, str, str | int], ...]] = {}
    for raw in closure["indirect_targets"]:
        external = raw.get("external_targets")
        if external is None:
            continue
        if not isinstance(external, list):
            raise CanonicalRuntimeError("closure external target set is malformed")
        identities = []
        for target in external:
            if not isinstance(target, Mapping):
                raise CanonicalRuntimeError("closure external target is malformed")
            identity = target.get("identity")
            dll = target.get("dll")
            if not isinstance(dll, str) or not isinstance(identity, (str, int)):
                raise CanonicalRuntimeError("closure external target identity is malformed")
            identities.append((
                dll.lower(), "symbol" if isinstance(identity, str) else "ordinal",
                identity,
            ))
        result[str(raw["site"])] = tuple(sorted(set(identities)))
    return result


def _guest_dispatch_sites(
    *,
    transfers: Iterable[_Transfer],
    closure: Mapping[str, Any],
) -> tuple[
    tuple[NativeGuestDispatchDomain, ...],
    tuple[NativeGuestDispatchSite, ...],
]:
    """Project exact computed guest edges from the checked closure.

    This is deliberately site-scoped.  Membership in the module-wide transfer
    inventory is necessary for a target, but never sufficient to authorize a
    computed call or jump to it.
    """

    by_rva = {transfer.rva_start: transfer for transfer in transfers}
    reachable = {
        int(row["rva"]) for row in closure["reachable_units"]
    }
    rows: list[NativeGuestDispatchSite] = []
    domains: dict[str, NativeGuestDispatchDomain] = {}
    seen: set[tuple[str, int]] = set()
    for raw in closure["indirect_targets"]:
        source_rva = raw.get("source_rva")
        site = raw.get("site")
        targets = raw.get("targets")
        if (
            not isinstance(source_rva, int)
            or isinstance(source_rva, bool)
            or not isinstance(site, str)
            or not isinstance(targets, list)
            or any(
                not isinstance(target, int) or isinstance(target, bool)
                for target in targets
            )
        ):
            raise CanonicalRuntimeError(
                "complete closure guest indirect target set is malformed"
            )
        if targets != sorted(set(targets)):
            raise CanonicalRuntimeError(
                "closure guest indirect targets are not sorted and unique"
            )
        transfer = by_rva.get(source_rva)
        if transfer is None or source_rva not in reachable:
            raise CanonicalRuntimeError(
                "closure guest indirect source is absent from its reachable transfer inventory"
            )
        if any(target not in reachable or target not in by_rva for target in targets):
            raise CanonicalRuntimeError(
                "closure guest indirect target is absent from its reachable transfer inventory"
            )
        key = (site, source_rva)
        if key in seen:
            raise CanonicalRuntimeError("closure guest indirect site is duplicated")
        seen.add(key)
        if site == "terminator":
            if (
                not transfer.actions
                or transfer.actions[-1].op != "outcome_indirect"
            ):
                raise CanonicalRuntimeError(
                    "closure terminator site does not bind an indirect transfer outcome"
                )
            kind = "indirect_jump"
            instruction_rva = source_rva
            event_index = None
        elif site.startswith("call:"):
            parts = site.split(":")
            if len(parts) != 3:
                raise CanonicalRuntimeError("closure indirect call site is malformed")
            try:
                instruction_rva = int(parts[1], 16)
                event_index = int(parts[2], 10)
            except ValueError as exc:
                raise CanonicalRuntimeError(
                    "closure indirect call site is malformed"
                ) from exc
            calls = [
                call for call in transfer.calls
                if call.kind == "indirect_call"
                and call.instruction_rva == instruction_rva
                and call.call_index == event_index
            ]
            if (
                len(calls) != 1
                or site != f"call:{instruction_rva:08x}:{event_index}"
            ):
                raise CanonicalRuntimeError(
                    "closure indirect call site does not bind one canonical call event"
                )
            kind = "indirect_call"
        else:
            raise CanonicalRuntimeError("closure indirect site kind is unsupported")
        domain_core = {
            "kind": "exact_guest_transfer_rvas_v1",
            "targets": list(targets),
        }
        domain_sha256 = canonical_sha256_v3(domain_core)
        domain = NativeGuestDispatchDomain(
            domain_sha256=domain_sha256,
            contract=domain_core,
            authority="checked_module_execution_closure",
        )
        previous_domain = domains.setdefault(domain_sha256, domain)
        if previous_domain != domain:
            raise CanonicalRuntimeError(
                "guest dispatch domain identity is ambiguous"
            )
        rows.append(NativeGuestDispatchSite(
            site=site,
            kind=kind,
            source_rva=source_rva,
            instruction_rva=instruction_rva,
            event_index=event_index,
            domain_sha256=domain_sha256,
        ))
    return (
        tuple(domains[key] for key in sorted(domains)),
        tuple(sorted(
            rows,
            key=lambda row: (
                row.source_rva,
                row.kind_code,
                row.instruction_rva or 0,
                row.event_index or 0,
            ),
        )),
    )


def guest_dispatch_from_linked_module_v2(
    *, transfers: Iterable[_Transfer], linked_module: Mapping[str, Any],
) -> tuple[
    tuple[NativeGuestDispatchDomain, ...],
    tuple[NativeGuestDispatchSite, ...],
]:
    """Bind V2 indirect effects to their shared admitted-domain contracts."""

    by_identity = {transfer.identity: transfer for transfer in transfers}
    transfer_rvas = {transfer.rva_start for transfer in by_identity.values()}
    domains_by_id: dict[str, Mapping[str, Any]] = {}
    for raw in linked_module.get("admitted_domains", []):
        if not isinstance(raw, Mapping):
            raise CanonicalRuntimeError(
                "linked semantic admitted domain is malformed"
            )
        domain = dict(raw)
        domain_sha256 = domain.pop("domain_sha256", None)
        if (
            not isinstance(domain_sha256, str)
            or domain_sha256 != canonical_sha256_v3(domain)
            or domain_sha256 in domains_by_id
        ):
            raise CanonicalRuntimeError(
                "linked semantic admitted domain is stale or duplicated"
            )
        domains_by_id[domain_sha256] = dict(raw)

    effects = linked_module.get("effects")
    indirect = effects.get("indirect_targets") if isinstance(
        effects, Mapping
    ) else None
    if not isinstance(indirect, list):
        raise CanonicalRuntimeError(
            "linked semantic module has no indirect-target effect catalog"
        )
    external_effects = effects.get("external_contracts")
    active_symbols = linked_module.get("active_symbols")
    requirements = linked_module.get("definition_requirements")

    def checked_external_members(
        domain_sha256: str, domain: Mapping[str, Any]
    ) -> None:
        if domain.get("kind") != "checked_indirect_callable_targets_v3":
            return
        targets = domain.get("external_loader_targets")
        if (
            not isinstance(targets, list)
            or targets != sorted(targets, key=canonical_sha256_v3)
            or not isinstance(domain.get("external_interface_targets"), list)
            or not isinstance(external_effects, list)
            or not isinstance(active_symbols, list)
            or not isinstance(requirements, list)
        ):
            raise CanonicalRuntimeError(
                "linked semantic callable domain has no total external catalog"
            )
        effects_by_contract: dict[str, Mapping[str, Any]] = {}
        for raw_effect in external_effects:
            if not isinstance(raw_effect, Mapping) or raw_effect.get(
                "semantic_role"
            ) != "external_function":
                continue
            contract_sha256 = raw_effect.get("contract_sha256")
            if (
                not isinstance(contract_sha256, str)
                or contract_sha256 in effects_by_contract
            ):
                raise CanonicalRuntimeError(
                    "linked semantic external effects are ambiguous"
                )
            effects_by_contract[contract_sha256] = raw_effect
        symbols_by_id = {
            str(row.get("symbol_id")): row for row in active_symbols
            if isinstance(row, Mapping)
        }
        requirements_by_symbol = {
            str(row.get("symbol_id")): row for row in requirements
            if isinstance(row, Mapping)
        }
        seen_contracts: set[str] = set()
        for raw_target in targets:
            if not isinstance(raw_target, Mapping):
                raise CanonicalRuntimeError(
                    "linked semantic callable external target is malformed"
                )
            target = dict(raw_target)
            contract_sha256 = target.get("contract_sha256")
            effect = effects_by_contract.get(str(contract_sha256))
            symbol_id = effect.get("symbol_id") if effect is not None else None
            symbol = symbols_by_id.get(str(symbol_id))
            requirement = requirements_by_symbol.get(str(symbol_id))
            resolution = (
                symbol.get("resolution") if isinstance(symbol, Mapping)
                else None
            )
            if (
                not isinstance(contract_sha256, str)
                or contract_sha256 in seen_contracts
                or effect is None
                or effect.get("identity") != target.get("identity")
                or effect.get("physical_frame_id")
                != target.get("physical_frame_id")
                or effect.get("physical_frame_sha256")
                != target.get("physical_frame_sha256")
                or domain_sha256 not in effect.get("domain_ids", ())
                or not isinstance(symbol, Mapping)
                or symbol.get("kind") != "external_function"
                or not isinstance(resolution, Mapping)
                or resolution.get("kind") != "checked_external_contract"
                or resolution.get("contract_sha256") != contract_sha256
                or domain_sha256 not in symbol.get("domain_ids", ())
                or not isinstance(requirement, Mapping)
                or requirement.get("definition_id")
                != symbol.get("definition_id")
                or requirement.get("allowed_provider_kinds")
                != ["external_environment"]
            ):
                raise CanonicalRuntimeError(
                    "linked semantic callable external member is disconnected"
                )
            seen_contracts.add(contract_sha256)

    runtime_domains: dict[str, NativeGuestDispatchDomain] = {}
    sites: list[NativeGuestDispatchSite] = []
    seen_sites: set[tuple[str, int]] = set()
    for index, raw in enumerate(indirect):
        if not isinstance(raw, Mapping):
            raise CanonicalRuntimeError(
                f"linked semantic indirect effect {index} is malformed"
            )
        effect = dict(raw)
        source_transfer_id = effect.get("source_transfer_id")
        transfer = by_identity.get(str(source_transfer_id))
        reference = effect.get("admitted_domain")
        domain_sha256 = (
            reference.get("domain_sha256")
            if isinstance(reference, Mapping) else None
        )
        raw_domain = domains_by_id.get(str(domain_sha256))
        if transfer is None or raw_domain is None:
            raise CanonicalRuntimeError(
                "linked semantic indirect effect has no transfer or domain"
            )
        checked_external_members(str(domain_sha256), raw_domain)
        contract = {
            key: value for key, value in raw_domain.items()
            if key != "domain_sha256"
        }
        domain = NativeGuestDispatchDomain(
            domain_sha256=str(domain_sha256),
            contract=contract,
            authority="linked_semantic_module_v2",
        )
        targets = domain.target_rvas
        if targets != tuple(sorted(set(targets))) or any(
            target not in transfer_rvas for target in targets
        ):
            raise CanonicalRuntimeError(
                "linked semantic guest domain is not an executable subset"
            )
        runtime_domains[domain.domain_sha256] = domain
        site_kind = effect.get("site_kind")
        if site_kind == "terminator":
            instruction_rva = effect.get("instruction_rva")
            if (
                effect.get("kind")
                != "logical_machine_state_indirect_dispatch_v2"
                or not transfer.actions
                or transfer.actions[-1].op != "outcome_indirect"
                or not isinstance(instruction_rva, int)
                or isinstance(instruction_rva, bool)
                or instruction_rva != transfer.rva_start
            ):
                raise CanonicalRuntimeError(
                    "linked semantic terminator dispatch is inconsistent"
                )
            site = "terminator"
            kind = "indirect_jump"
            event_index = None
        elif site_kind == "call":
            contract_call = effect.get("semantic_contract")
            call = (
                contract_call.get("call")
                if isinstance(contract_call, Mapping) else None
            )
            instruction_rva = effect.get("instruction_rva")
            event_index = (
                call.get("event_index") if isinstance(call, Mapping) else None
            )
            matches = [
                item for item in transfer.calls
                if item.kind == "indirect_call"
                and item.instruction_rva == instruction_rva
                and item.call_index == event_index
            ]
            if (
                effect.get("kind")
                != "checked_indirect_callable_dispatch_v2"
                or len(matches) != 1
                or not isinstance(instruction_rva, int)
                or isinstance(instruction_rva, bool)
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
            ):
                raise CanonicalRuntimeError(
                    "linked semantic indirect call is inconsistent"
                )
            site = f"call:{instruction_rva:08x}:{event_index}"
            kind = "indirect_call"
        else:
            raise CanonicalRuntimeError(
                "linked semantic indirect effect has unsupported site kind"
            )
        site_identity = (site, transfer.rva_start)
        if site_identity in seen_sites:
            raise CanonicalRuntimeError(
                "linked semantic indirect dispatch site is duplicated"
            )
        seen_sites.add(site_identity)
        sites.append(NativeGuestDispatchSite(
            site=site,
            kind=kind,
            source_rva=transfer.rva_start,
            instruction_rva=instruction_rva,
            event_index=event_index,
            domain_sha256=domain.domain_sha256,
        ))
    return (
        tuple(runtime_domains[key] for key in sorted(runtime_domains)),
        tuple(sorted(
            sites,
            key=lambda row: (
                row.source_rva, row.kind_code, row.instruction_rva or 0,
                row.event_index or 0,
            ),
        )),
    )
