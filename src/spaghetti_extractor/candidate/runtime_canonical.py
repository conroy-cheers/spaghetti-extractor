"""Compile native runtime tables from the canonical execution artifacts.

Executable-transfer-plan-v2 is the only semantic program input. Provider
qualification, closure, environment, and ingress artifacts add checked native
materialization facts without reconstructing instruction semantics.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..pe32.recovered_executable_data import (
    RecoveredExecutableDataRange,
    load_recovered_executable_data_contract,
)
from .module_runtime_plan import ModuleRuntimePlan
from .runtime_canonical_common import (
    _callback_adapter as _callback_adapter,
    _callback_capability_index as _callback_capability_index,
    _checked_contract as _checked_contract,
    _checked_interface_method_contract as _checked_interface_method_contract,
    _closed_content_id as _closed_content_id,
    _guest_dispatch_sites as _guest_dispatch_sites,
    _loader_service_index as _loader_service_index,
    _object as _object,
    guest_dispatch_from_linked_module_v2,
)
from .runtime_canonical_errors import CanonicalRuntimeError
from .runtime_canonical_external import (
    _external_sites as _external_sites,
    _termination_import as _termination_import,
)


_TRANSFER_PLAN_INPUT_MODE = "executable_transfer_plan_v2"


def _recovered_ranges(
    *, path: Path | None, transfer_payload: Mapping[str, Any], image_base: int,
) -> tuple[RecoveredExecutableDataRange, ...]:
    if path is None:
        return ()
    contract = load_recovered_executable_data_contract(path)
    bindings = transfer_payload.get("bindings")
    if (
        not isinstance(bindings, Mapping)
        or contract.machine_ir_sha256 != bindings.get("machine_ir_sha256")
        or contract.original_pe_sha256 != bindings.get("pe_sha256")
        or contract.image_base != image_base
    ):
        raise CanonicalRuntimeError(
            "recovered executable data does not bind the canonical transfer image"
        )
    return contract.ranges


def plan_module_runtime_from_canonical(
    *,
    transfer_plan: Path,
    execution_closure: Path | Mapping[str, Any],
    resolved_external_environment: Path,
    native_ingress_plan: Path,
    recovered_executable_data: Path | None = None,
) -> ModuleRuntimePlan:
    """Compile the bridge model once from the canonical semantic universe."""

    from .runtime_canonical_build import plan_module_runtime_from_canonical as build

    return build(
        transfer_plan=transfer_plan,
        execution_closure=execution_closure,
        resolved_external_environment=resolved_external_environment,
        native_ingress_plan=native_ingress_plan,
        recovered_executable_data=recovered_executable_data,
    )


__all__ = [
    "CanonicalRuntimeError",
    "guest_dispatch_from_linked_module_v2",
    "plan_module_runtime_from_canonical",
]
