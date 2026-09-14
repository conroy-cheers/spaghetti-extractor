"""Admission of the selected external effect contract into the proof world.

Normal admission still requires caller ownership and canonical native inputs.
The paired oracle checks transitions with local classes or supplied native
inventories; its explicit internal admission does not authorize a provider. Keeping the complete
selected payload prevents a lifetime contract from becoming a scalar-only call.
"""

from typing import Mapping

from ..external.contracts import CheckedExternalSiteContractError, require_machine_import_effects
from ..external.argument_domains import ArgumentDomainError, checked_argument_domain
from ..external.terminated_reads import checked_terminated_read, checked_terminated_write
from .bisimulation_support import BisimulationRefinementError


def require_typed_external_target_support(binding):
    from .bisimulation_service_targets import checked_typed_external_target
    checked_typed_external_target(binding)


def checked_proof_external_effect_contract(binding, *, allow_lifetime_effects=False):
    if binding.get("provider_kind") != "external_call":
        return None
    service = str(binding.get("service_id", ""))
    payload = binding.get("external_effect_contract")
    if not isinstance(payload, Mapping):
        raise BisimulationRefinementError(
            f"proof service {service!r} lacks its selected external effect contract"
        )
    try:
        _, world = require_machine_import_effects(payload, context=f"proof service {service!r}")
        checked_argument_domain(payload.get("argument_domain", []),
                                argument_words=len(binding.get("argument_offsets", [])))
    except (CheckedExternalSiteContractError, ArgumentDomainError) as exc:
        raise BisimulationRefinementError(str(exc)) from exc
    relations = payload.get("result_register_relations", [])
    if not isinstance(relations, list) or any(not isinstance(row, Mapping) for row in relations):
        raise BisimulationRefinementError(f"proof service {service!r} has malformed result relations")
    try:
        checked_terminated_read(payload, argument_words=len(binding.get("argument_offsets", [])))
        checked_terminated_write(payload, argument_words=len(binding.get("argument_offsets", [])))
    except ValueError as exc:
        raise BisimulationRefinementError(str(exc)) from exc
    lifetime_results = any(row.get("relation") == "dynamic_range_base" or
                           row.get("ownership") is not None for row in relations)
    out_pointers = payload.get("out_pointer_relations", [])
    if not isinstance(out_pointers, list):
        raise BisimulationRefinementError(f"proof service {service!r} has malformed out-pointer relations")
    if (world in {"dynamicRanges", "dynamicRangeRelease"} or lifetime_results or
            out_pointers or
            payload.get("world_effect_release") is not None or
            payload.get("world_effect_argument") is not None):
        if allow_lifetime_effects:
            from .bisimulation_call_allocation import checked_lifetime_effect
            checked_lifetime_effect(payload, argument_words=len(binding.get("argument_offsets", [])))
            return dict(payload)
        raise BisimulationRefinementError(
            f"proof_service_lifetime_effect_unsupported: service {service!r} requires "
            "checked proof-world allocation/release transitions and caller ownership; "
            "native range bookkeeping does not discharge this obligation"
        )
    return dict(payload)


def checked_proof_external_contract_identity(binding):
    """Retain the selected native behavior identity in paired call transcripts.

    The canonical overlay reconstructs this identity from its resolved profile;
    the receipt binds that overlay and this lowering implementation. A digest
    supplied independently is not evidence of producer or caller qualification.
    """
    if binding.get("provider_kind") != "external_call":
        return None
    identity = binding.get("external_contract_identity_sha256")
    if (not isinstance(identity, str) or len(identity) != 64 or
            any(character not in "0123456789abcdef" for character in identity)):
        raise BisimulationRefinementError(
            "proof service lacks its canonical external contract identity"
        )
    return identity
