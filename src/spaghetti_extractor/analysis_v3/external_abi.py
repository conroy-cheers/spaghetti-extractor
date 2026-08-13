"""Deterministic PE32 external-call argument recovery for v3 authority."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal


CONTROL_DISPOSITION_PROFILE_ID = "pe32-control-dispositions-v1"
SUPPORTED_STACK_ABIS_V3 = frozenset({"pe32-cdecl-v1", "pe32-stdcall-v1"})


class ExternalArgumentRecoveryV3Error(ValueError):
    """The exact call boundary cannot support the selected ABI contract."""

    def __init__(
        self,
        status: Literal["incomplete", "violated"],
        code: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.status: Literal["incomplete", "violated"] = status
        self.code = code


def recover_external_arguments_v3(
    event: Mapping[str, Any],
    *,
    transfer_kind: str,
    abi_template: str,
    argument_words: int,
) -> tuple[dict[str, Any], ...]:
    """Return exact event-time argument expressions for a fixed stack ABI.

    Explicit arguments remain authoritative when extraction already emitted
    them.  Otherwise the checked call-boundary ESP identifies the words read
    from event-time memory.  Calls have not pushed their return address yet;
    tail jumps retain the caller's return address at offset zero.
    """

    if transfer_kind not in {"call", "jump"}:
        raise ExternalArgumentRecoveryV3Error(
            "violated",
            "external_transfer_kind_unsupported",
            "unsupported external transfer kind",
        )
    if abi_template not in SUPPORTED_STACK_ABIS_V3:
        raise ExternalArgumentRecoveryV3Error(
            "incomplete",
            "external_abi_template_unsupported",
            "unsupported external ABI template",
        )
    if (
        not isinstance(argument_words, int)
        or isinstance(argument_words, bool)
        or not 0 <= argument_words <= 256
    ):
        raise ExternalArgumentRecoveryV3Error(
            "violated",
            "external_argument_words_malformed",
            "invalid external argument count",
        )

    explicit = event.get("arguments")
    if explicit is not None:
        if not isinstance(explicit, list) or any(
            not isinstance(value, Mapping) for value in explicit
        ):
            raise ExternalArgumentRecoveryV3Error(
                "violated",
                "external_arguments_malformed",
                "explicit external arguments are malformed",
            )
        if explicit:
            if len(explicit) != argument_words:
                raise ExternalArgumentRecoveryV3Error(
                    "violated",
                    "external_argument_inventory_contradiction",
                    "explicit external argument count contradicts ABI",
                )
            return tuple(dict(value) for value in explicit)

    if argument_words == 0:
        return ()
    register_inputs = event.get("register_inputs")
    esp = register_inputs.get("esp") if isinstance(register_inputs, Mapping) else None
    if not isinstance(esp, Mapping):
        raise ExternalArgumentRecoveryV3Error(
            "incomplete",
            "external_call_boundary_esp_missing",
            "external event has no exact call-boundary ESP",
        )
    base_offset = 0 if transfer_kind == "call" else 4
    result: list[dict[str, Any]] = []
    for index in range(argument_words):
        offset = base_offset + index * 4
        address: dict[str, Any] = dict(esp)
        if offset:
            address = {
                "op": "add32",
                "args": [
                    address,
                    {"op": "const", "value": offset, "width": 32},
                ],
            }
        result.append({"op": "load", "width": 4, "address": address})
    return tuple(result)


__all__ = [
    "ExternalArgumentRecoveryV3Error",
    "SUPPORTED_STACK_ABIS_V3",
    "recover_external_arguments_v3",
]
