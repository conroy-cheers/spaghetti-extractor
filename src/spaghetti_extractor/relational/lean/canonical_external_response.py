"""Generic planning for checked canonical external responses.

The planner is deliberately untrusted.  It converts a normalized
``MachineImportCallContract`` JSON row into the runtime witnesses that the Lean
response synthesizer must receive.  Lean checks the concrete event, successor
world, ABI state, memory effect, and result relation before the plan can be
used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class CanonicalExternalResponsePlanError(ValueError):
    """A normalized machine contract cannot use the returning-response path."""


@dataclass(frozen=True)
class ResultRegisterRecipe:
    register: str
    strategy: str
    nullable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "register": self.register,
            "strategy": self.strategy,
            "nullable": self.nullable,
        }


@dataclass(frozen=True)
class CanonicalExternalResponseRecipe:
    contract_id: int
    memory_strategy: str
    world_strategy: str
    world_argument_index: int | None
    result_registers: tuple[ResultRegisterRecipe, ...]
    runtime_requirements: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "spaghetti-extractor-canonical-external-response-recipe-v1",
            "contract_id": self.contract_id,
            "memory_strategy": self.memory_strategy,
            "world_strategy": self.world_strategy,
            "world_argument_index": self.world_argument_index,
            "result_registers": [item.to_dict() for item in self.result_registers],
            "runtime_requirements": list(self.runtime_requirements),
            "proof_authority": False,
        }


_MEMORY_STRATEGIES = {
    "none": "preserve_memory",
    "readOnly": "preserve_memory_after_checked_footprints",
    "argumentRanges": "preserve_memory_after_checked_footprints",
    "newDynamicRanges": "preserve_memory_outside_fresh_ranges",
    "relationalState": "preserve_memory",
}

_WORLD_STRATEGIES = {
    "none": "preserve_world",
    "opaqueResources": "extend_or_preserve_opaque_resources",
    "dynamicRanges": "extend_or_preserve_dynamic_ranges",
    "dynamicRangeRelease": "release_paired_dynamic_range",
    "callbackRegistration": "register_paired_callback",
    "tlsState": "replace_or_preserve_tls_state",
}


def _required_int(contract: Mapping[str, Any], key: str) -> int:
    value = contract.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CanonicalExternalResponsePlanError(f"invalid {key}")
    return value


def plan_canonical_external_response(
    contract: Mapping[str, Any],
) -> CanonicalExternalResponseRecipe:
    """Return the generic response recipe for one normalized contract.

    This function does not choose concrete pointer values.  Requirements such
    as a fresh allocation pair or a checked callback are state indexed and are
    therefore left as explicit Lean-checked runtime witnesses.
    """

    contract_id = _required_int(contract, "id")
    if contract.get("disposition", "returns") != "returns":
        raise CanonicalExternalResponsePlanError(
            "canonical response synthesis only handles returning contracts"
        )

    memory_effect = contract.get("memory_effect")
    world_effect = contract.get("world_effect")
    if memory_effect not in _MEMORY_STRATEGIES:
        raise CanonicalExternalResponsePlanError("unsupported memory_effect")
    if world_effect not in _WORLD_STRATEGIES:
        raise CanonicalExternalResponsePlanError("unsupported world_effect")

    argument_index: int | None = None
    if world_effect in {"dynamicRangeRelease", "callbackRegistration"}:
        argument_index = _required_int(contract, "world_effect_argument")
    elif contract.get("world_effect_argument") is not None:
        raise CanonicalExternalResponsePlanError(
            "world_effect_argument is only valid for release or registration"
        )

    raw_relations = contract.get("result_register_relations", [])
    if not isinstance(raw_relations, list):
        raise CanonicalExternalResponsePlanError(
            "result_register_relations must be a list"
        )

    relations: list[ResultRegisterRecipe] = []
    requirements: list[str] = []
    if memory_effect in {"readOnly", "argumentRanges"}:
        requirements.append("both_runtime_memory_footprint_inventories_valid")

    if world_effect == "dynamicRangeRelease":
        requirements.extend(
            (
                "nonzero_arguments_identify_one_existing_paired_dynamic_range",
                "released_successor_world_is_valid",
            )
        )
    elif world_effect == "callbackRegistration":
        requirements.extend(
            (
                "arguments_identify_one_valid_paired_callback",
                "callback_successor_world_is_valid",
            )
        )
    elif world_effect == "opaqueResources":
        requirements.append("opaque_successor_world_is_valid")
    elif world_effect == "tlsState":
        requirements.append("tls_successor_world_is_valid")

    for raw in raw_relations:
        if not isinstance(raw, Mapping):
            raise CanonicalExternalResponsePlanError(
                "result register relation must be an object"
            )
        register = raw.get("register")
        relation = raw.get("relation")
        if not isinstance(register, str):
            raise CanonicalExternalResponsePlanError("invalid result register")
        if relation == "exact":
            relations.append(ResultRegisterRecipe(register, "shared_zero"))
        elif relation == "related_word":
            relations.append(ResultRegisterRecipe(register, "shared_zero"))
        elif relation == "dynamic_range_base":
            nullable = raw.get("nullable", False)
            if not isinstance(nullable, bool):
                raise CanonicalExternalResponsePlanError(
                    "dynamic range nullable flag must be Boolean"
                )
            strategy = "null_or_fresh_paired_range" if nullable else "fresh_paired_range"
            relations.append(ResultRegisterRecipe(register, strategy, nullable))
            if not nullable:
                requirements.extend(
                    (
                        f"positive_runtime_allocation_size:{register}",
                        f"fresh_disjoint_paired_dynamic_range:{register}",
                    )
                )
        else:
            raise CanonicalExternalResponsePlanError(
                f"unsupported result relation: {relation!r}"
            )

    if memory_effect == "newDynamicRanges" and not any(
        item.strategy in {"fresh_paired_range", "null_or_fresh_paired_range"}
        for item in relations
    ):
        raise CanonicalExternalResponsePlanError(
            "newDynamicRanges requires a dynamic-range result relation"
        )

    # Preserve deterministic order while removing duplicate requirements.
    requirements = list(dict.fromkeys(requirements))
    return CanonicalExternalResponseRecipe(
        contract_id=contract_id,
        memory_strategy=_MEMORY_STRATEGIES[str(memory_effect)],
        world_strategy=_WORLD_STRATEGIES[str(world_effect)],
        world_argument_index=argument_index,
        result_registers=tuple(relations),
        runtime_requirements=tuple(requirements),
    )


__all__ = [
    "CanonicalExternalResponsePlanError",
    "CanonicalExternalResponseRecipe",
    "ResultRegisterRecipe",
    "plan_canonical_external_response",
]
