"""Ergonomic authored input for canonical physical ABI declarations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import PHYSICAL_ABI_DECLARATION_SPEC_FORMAT
from .declarations import PhysicalAbiDeclarationSetV1, PhysicalAbiDeclarationV1
from .model import (
    AbiModelError,
    AbiTargetV1,
    AbiValueV1,
    BoundaryEffectsV1,
    PhysicalAbiProfileV1,
    PortablePrototypeV1,
    StackCleanupV1,
    VariadicPolicyV1,
    canonical_sha256,
)


def _object(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AbiModelError(f"{label} fields are malformed")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise AbiModelError(f"{label} must be an array of nonempty strings")
    return tuple(value)


def _profile(value: object) -> PhysicalAbiProfileV1:
    row = _object(
        value,
        {
            "target",
            "calling_convention",
            "stack_coordinate",
            "stack_alignment_bytes",
            "arguments",
            "results",
            "stack_cleanup",
            "variadic",
            "preserved_state",
        },
        "ABI declaration-spec profile",
    )
    arguments = row["arguments"]
    results = row["results"]
    if not isinstance(arguments, list) or not isinstance(results, list):
        raise AbiModelError("ABI declaration-spec values must be arrays")
    if row["stack_coordinate"] != "callee_entry_esp_v1":
        raise AbiModelError("ABI declaration-spec stack coordinate is unsupported")
    return PhysicalAbiProfileV1.create(
        target=AbiTargetV1.parse(row["target"]),
        calling_convention=str(row["calling_convention"]),
        stack_alignment_bytes=row["stack_alignment_bytes"],
        arguments=tuple(AbiValueV1.parse(item) for item in arguments),
        results=tuple(AbiValueV1.parse(item) for item in results),
        stack_cleanup=StackCleanupV1.parse(row["stack_cleanup"]),
        variadic=VariadicPolicyV1.parse(row["variadic"]),
        preserved_state=_strings(row["preserved_state"], "preserved state"),
    )


def _prototype(
    value: object,
    *,
    subject_id: str,
    profile_id: str,
    dependency_ids: tuple[str, ...],
) -> PortablePrototypeV1 | None:
    if value is None:
        return None
    row = _object(
        value,
        {
            "symbol",
            "return_type",
            "parameter_types",
            "parameter_names",
            "variadic",
        },
        "ABI declaration-spec prototype",
    )
    if not isinstance(row["variadic"], bool):
        raise AbiModelError("ABI prototype variadic flag must be Boolean")
    return PortablePrototypeV1.create(
        subject_id=subject_id,
        physical_profile_id=profile_id,
        symbol=str(row["symbol"]),
        return_type=str(row["return_type"]),
        parameter_types=_strings(row["parameter_types"], "parameter types"),
        parameter_names=_strings(row["parameter_names"], "parameter names"),
        variadic=row["variadic"],
        dependency_ids=dependency_ids,
    )


def _effects(
    value: object,
    *,
    subject_id: str,
    dependency_ids: tuple[str, ...],
) -> BoundaryEffectsV1 | None:
    if value is None:
        return None
    row = _object(
        value,
        {"reads", "writes", "resource_actions", "callback_actions"},
        "ABI declaration-spec effects",
    )
    return BoundaryEffectsV1.create(
        subject_id=subject_id,
        reads=_strings(row["reads"], "effect reads"),
        writes=_strings(row["writes"], "effect writes"),
        resource_actions=_strings(
            row["resource_actions"], "effect resource actions"
        ),
        callback_actions=_strings(
            row["callback_actions"], "effect callback actions"
        ),
        dependency_ids=dependency_ids,
    )


def build_declaration_set_from_spec(
    *, spec: Path | str, out: Path | str
) -> PhysicalAbiDeclarationSetV1:
    payload = json.loads(Path(spec).read_text(encoding="utf-8"))
    row = _object(
        payload,
        {
            "format",
            "snapshot_id",
            "source_kind",
            "source_sha256",
            "producer",
            "declarations",
        },
        "physical ABI declaration spec",
    )
    if row["format"] != PHYSICAL_ABI_DECLARATION_SPEC_FORMAT:
        raise AbiModelError("physical ABI declaration-spec format is unsupported")
    declarations = row["declarations"]
    if not isinstance(declarations, list):
        raise AbiModelError("physical ABI declaration spec must contain an array")
    source_sha256 = row["source_sha256"]
    if (
        not isinstance(source_sha256, str)
        or len(source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_sha256)
    ):
        raise AbiModelError("ABI declaration-spec source SHA-256 is malformed")
    spec_sha256 = canonical_sha256(row)
    result_rows = []
    for index, raw in enumerate(declarations):
        declaration = _object(
            raw,
            {
                "symbols",
                "profile",
                "prototype",
                "effects",
                "dependency_ids",
            },
            f"physical ABI declaration spec entry {index}",
        )
        symbols = _strings(declaration["symbols"], "ABI declaration symbols")
        dependency_ids = tuple(
            sorted(
                {
                    spec_sha256,
                    *_strings(
                        declaration["dependency_ids"],
                        "ABI declaration dependencies",
                    ),
                }
            )
        )
        profile = _profile(declaration["profile"])
        subject_id = f"declared-abi:{canonical_sha256(list(symbols))}"
        result_rows.append(
            PhysicalAbiDeclarationV1.create(
                symbols=symbols,
                source_kind=str(row["source_kind"]),
                source_sha256=source_sha256,
                producer=str(row["producer"]),
                profile=profile,
                prototype=_prototype(
                    declaration["prototype"],
                    subject_id=subject_id,
                    profile_id=profile.profile_id,
                    dependency_ids=dependency_ids,
                ),
                effects=_effects(
                    declaration["effects"],
                    subject_id=subject_id,
                    dependency_ids=dependency_ids,
                ),
                dependency_ids=dependency_ids,
            )
        )
    result = PhysicalAbiDeclarationSetV1.create(
        snapshot_id=str(row["snapshot_id"]), declarations=result_rows
    )
    result.write(out)
    return result


__all__ = ["build_declaration_set_from_spec"]
