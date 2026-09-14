"""Shared normalization of resolved import behavior for native and proof adapters.

The resolved environment binds the selected profile. This projection identifies
its behavior; it does not qualify physical calls, callbacks or ownership.
"""

from typing import Any, Mapping

from .contracts import (
    CheckedExternalContractBehavior, CheckedExternalSiteContractError,
    ExternalSiteIdentity, _metadata, require_machine_import_effects,
)
from .range_allocation import RangeAllocationError, validate_range_allocation_relations
from .range_ownership import RangeOwnershipError, validate_range_ownership_relations
from .range_release import RangeReleaseError, machine_range_release
from .argument_domains import checked_argument_domain


def resolved_import_contract_behavior(row: Mapping[str, Any]) -> CheckedExternalContractBehavior:
    identity = row.get("identity")
    contract_binding = row.get("contract")
    boundary = row.get("boundary")
    if not all(isinstance(item, Mapping) for item in (identity, contract_binding, boundary)):
        raise CheckedExternalSiteContractError("resolved import binding is incomplete")
    payload = contract_binding.get("payload")
    if not isinstance(payload, Mapping):
        raise CheckedExternalSiteContractError("resolved import contract payload is malformed")
    profile = _metadata(payload)
    memory_effect, world_effect = require_machine_import_effects(
        profile, context=f"resolved import {identity!r}",
    )
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
    if not isinstance(argument_words, int) or isinstance(argument_words, bool) or not 0 <= argument_words <= 256:
        raise CheckedExternalSiteContractError("resolved import argument count is malformed")
    try:
        release = machine_range_release(profile, argument_words=argument_words,
                                        context=f"resolved import {identity!r}")
    except RangeReleaseError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    try:
        validate_range_ownership_relations(profile, argument_words=argument_words,
                                          context=f"resolved import {identity!r}")
    except RangeOwnershipError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
    try:
        validate_range_allocation_relations(profile, argument_words=argument_words,
                                          context=f"resolved import {identity!r}")
    except RangeAllocationError as exc:
        raise CheckedExternalSiteContractError(str(exc)) from exc
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
        raise CheckedExternalSiteContractError("resolved import arity is unsupported")
    profile_disposition = profile.get("disposition", "returns")
    if profile_disposition not in {"returns", "terminates", "nonlocal"}:
        raise CheckedExternalSiteContractError("resolved import disposition is unsupported")
    external_identity = ExternalSiteIdentity.imported(identity, context="resolved import")
    out_pointers = boundary.get("out_pointer_relations", [])
    out_interfaces = profile.get("out_interface_relations", [])
    if not isinstance(out_pointers, list) or not isinstance(out_interfaces, list):
        raise CheckedExternalSiteContractError("resolved import relation inventory is malformed")
    return CheckedExternalContractBehavior(
        identity=external_identity,
        profile_disposition=str(profile_disposition),
        abi_template=str(profile.get("abi_template")),
        arity_kind=str(arity_kind),
        argument_words=argument_words,
        argument_domain=checked_argument_domain(profile.get("argument_domain", []), argument_words=argument_words),
        raw_caller_stack_suffix_forwarding=forwarding,
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
        memory_effect=memory_effect,
        memory_footprints=tuple(profile.get("memory_footprints", [])),
        world_effect=world_effect,
        world_effect_argument=profile.get("world_effect_argument"),
        world_effect_release=release,
        callback_effect="explicit" if boundary.get("callback_protocol") is not None else "none",
        out_pointer_relations=tuple(out_pointers),
        out_interface_relations=tuple(out_interfaces),
        external_service_protocol=profile.get(
            "external_service_protocol"
        ),
    )
