"""Lossless migration adapters from existing ABI records."""

from __future__ import annotations

from typing import Iterable

from ..libraries.abi_records import (
    CallbackSlotV3,
    LibraryAbiProfileV3,
    StackCleanupV3,
    ValueLocationV3,
    VariadicPolicyV3,
)
from .model import (
    PE32_TARGET_V1,
    AbiLocationV1,
    AbiValueV1,
    PhysicalAbiProfileV1,
    StackCleanupV1,
    VariadicPolicyV1,
)


def _location(value: ValueLocationV3, value_bit_offset: int = 0) -> AbiLocationV1:
    return AbiLocationV1(
        kind=value.kind,
        width_bits=value.width_bits,
        value_bit_offset=value_bit_offset,
        register=value.register,
        stack_offset=value.stack_offset,
        memory_id=value.memory_id,
    )


def _values(
    values: Iterable[ValueLocationV3],
    *,
    prefix: str,
    hidden_sret: bool,
) -> tuple[AbiValueV1, ...]:
    result = []
    for index, value in enumerate(values):
        role = "hidden_sret" if hidden_sret and index == 0 else "ordinary"
        result.append(
            AbiValueV1(
                value_id=f"{prefix}{index}",
                width_bits=value.width_bits,
                role=role,
                fragments=(_location(value),),
            )
        )
    return tuple(result)


def physical_profile_from_library_v3(
    profile: LibraryAbiProfileV3,
) -> PhysicalAbiProfileV1:
    """Convert the physical subset of a V3 library profile.

    Structure names and boundary effects intentionally do not enter the new
    profile. Callback slots are retained by changing the corresponding argument
    role and binding it to the referenced physical profile ID.
    """

    arguments = list(
        _values(profile.arguments, prefix="arg", hidden_sret=profile.hidden_sret)
    )
    for slot in profile.callback_slots:
        if slot.argument_index >= len(arguments):
            raise ValueError("legacy callback slot exceeds the ABI argument inventory")
        old = arguments[slot.argument_index]
        arguments[slot.argument_index] = AbiValueV1(
            value_id=old.value_id,
            width_bits=old.width_bits,
            role="callback",
            fragments=old.fragments,
            callback_abi_id=slot.abi_profile_id,
        )
    results = _values(profile.returns, prefix="result", hidden_sret=False)
    control_id = (
        None
        if profile.variadic.control_argument is None
        else f"arg{profile.variadic.control_argument}"
    )
    return PhysicalAbiProfileV1.create(
        target=PE32_TARGET_V1,
        calling_convention=profile.calling_convention,
        arguments=arguments,
        results=results,
        stack_cleanup=StackCleanupV1(
            profile.stack_cleanup.kind, profile.stack_cleanup.bytes
        ),
        variadic=VariadicPolicyV1(
            profile.variadic.kind,
            profile.variadic.fixed_arguments,
            control_id,
        ),
        preserved_state=profile.preserved_registers,
    )


def library_profile_v3_from_physical(
    profile: PhysicalAbiProfileV1,
) -> LibraryAbiProfileV3:
    """Project a complete physical profile into the legacy component adapter.

    The adapter can represent one location per logical value. Split-value ABIs
    remain explicit unsupported frontiers instead of being truncated.
    """

    def location(value: AbiValueV1) -> ValueLocationV3:
        if len(value.fragments) != 1 or value.fragments[0].value_bit_offset != 0:
            raise ValueError("legacy component adapter cannot represent split ABI values")
        fragment = value.fragments[0]
        if fragment.width_bits != value.width_bits:
            raise ValueError("legacy component adapter cannot represent partial ABI values")
        return ValueLocationV3(
            fragment.kind,
            fragment.width_bits,
            fragment.register,
            fragment.stack_offset,
            fragment.memory_id,
        )

    callback_slots = tuple(
        CallbackSlotV3(index, value.callback_abi_id or "", False)
        for index, value in enumerate(profile.arguments)
        if value.role == "callback"
    )
    control = profile.variadic.control_argument_id
    control_index = (
        None
        if control is None
        else next(
            (
                index
                for index, value in enumerate(profile.arguments)
                if value.value_id == control
            ),
            None,
        )
    )
    if control is not None and control_index is None:
        raise ValueError("physical variadic control argument is absent")
    return LibraryAbiProfileV3(
        profile_id=profile.profile_id,
        architecture=profile.target.architecture,
        object_format=profile.target.object_format,
        calling_convention=profile.calling_convention,
        stack_cleanup=StackCleanupV3(
            profile.stack_cleanup.kind, profile.stack_cleanup.bytes
        ),
        arguments=tuple(location(value) for value in profile.arguments),
        returns=tuple(location(value) for value in profile.results),
        hidden_sret=any(value.role == "hidden_sret" for value in profile.arguments),
        variadic=VariadicPolicyV3(
            profile.variadic.kind,
            profile.variadic.fixed_argument_count,
            control_index,
        ),
        preserved_registers=profile.preserved_state,
        callback_slots=callback_slots,
        structure_layout_ids=(),
        boundary_effects=(),
    )


__all__ = [
    "library_profile_v3_from_physical",
    "physical_profile_from_library_v3",
]
