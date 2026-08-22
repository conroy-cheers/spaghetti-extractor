from __future__ import annotations

from spaghetti_extractor.abi.model import (
    PE32_TARGET_V1,
    AbiLocationV1,
    AbiValueV1,
    PhysicalAbiProfileV1,
    StackCleanupV1,
    VariadicPolicyV1,
)


def register_location(
    register: str,
    *,
    width_bits: int = 32,
    value_bit_offset: int = 0,
) -> AbiLocationV1:
    return AbiLocationV1(
        "register",
        width_bits,
        value_bit_offset=value_bit_offset,
        register=register,
    )


def stack_location(
    stack_offset: int,
    *,
    width_bits: int = 32,
    value_bit_offset: int = 0,
) -> AbiLocationV1:
    return AbiLocationV1(
        "stack",
        width_bits,
        value_bit_offset=value_bit_offset,
        stack_offset=stack_offset,
    )


def scalar_value(
    value_id: str,
    location: AbiLocationV1,
    *,
    role: str = "ordinary",
    callback_abi_id: str | None = None,
) -> AbiValueV1:
    return AbiValueV1(
        value_id=value_id,
        width_bits=location.width_bits,
        role=role,
        fragments=(location,),
        callback_abi_id=callback_abi_id,
    )


def physical_profile(
    *,
    calling_convention: str = "cdecl",
    arguments: tuple[AbiValueV1, ...] | None = None,
    results: tuple[AbiValueV1, ...] | None = None,
    stack_cleanup: StackCleanupV1 | None = None,
    preserved_state: tuple[str, ...] = ("ebp", "ebx", "edi", "esi"),
    stack_alignment_bytes: int = 4,
) -> PhysicalAbiProfileV1:
    selected_arguments = (
        (scalar_value("arg0", stack_location(4)),)
        if arguments is None
        else arguments
    )
    selected_results = (
        (scalar_value("result0", register_location("eax")),)
        if results is None
        else results
    )
    return PhysicalAbiProfileV1.create(
        target=PE32_TARGET_V1,
        calling_convention=calling_convention,
        arguments=selected_arguments,
        results=selected_results,
        stack_cleanup=stack_cleanup or StackCleanupV1("caller", 0),
        variadic=VariadicPolicyV1("none", len(selected_arguments)),
        preserved_state=preserved_state,
        stack_alignment_bytes=stack_alignment_bytes,
    )
