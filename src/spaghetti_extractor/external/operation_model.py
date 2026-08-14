"""Typed profiles for bounded machine-level external operations.

The schema deliberately separates three concerns:

* selectors identify where an operation can be invoked;
* operations define the machine ABI, arity, and typed outputs; and
* environment contracts bound caller-memory and relational-world effects.

Loading is fail closed.  Unknown fields, unsupported variants, duplicate
selectors, and dangling or inconsistent references are rejected before a
profile can be used as proposal input.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, TypeAlias

from ..artifacts.formats import (
    EXTERNAL_OPERATION_CONTRACT_FORMAT,
    EXTERNAL_OPERATION_PROFILE_FORMAT,
)
from .interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    RECEIVER_RESOURCE_LIFECYCLE_EFFECTS,
    RECEIVER_RESOURCE_REQUIRED_STATE,
    ExternalInterfaceProfile,
    ReceiverResourceContract,
    default_receiver_lifecycle_effect,
)
from .machine_abi import (
    MACHINE_CALL_ABI_REGISTERS,
    MachineCallABI,
    resolve_machine_call_abi,
)
from .machine_import_profiles import MachineImportIdentity
from ..pe32.stage_binary import StageAInputError

MAX_ARGUMENT_WORDS = 64
MAX_TABLE_SLOT = 0xFFFF
MAX_FOOTPRINT_BYTES = 16 * 1024 * 1024
_U32_MAX = 0xFFFFFFFF


def _import_json(identity: MachineImportIdentity) -> dict[str, Any]:
    return {"dll": identity.dll, identity.kind: identity.value}


class ExternalOperationProfileError(StageAInputError):
    """An external-operation profile or contract is malformed or ambiguous."""


@dataclass(frozen=True, order=True)
class ExternalOperationView:
    view_id: str
    table: str
    access: str = "object_table"

    def as_json(self) -> dict[str, Any]:
        return {"id": self.view_id, "table": self.table, "access": self.access}


@dataclass(frozen=True, order=True)
class FixedOutputView:
    view_id: str

    def as_json(self) -> dict[str, Any]:
        return {"kind": "fixed", "view_id": self.view_id}


@dataclass(frozen=True, order=True)
class DiscriminatorCase:
    value: int | None
    view_id: str
    bytes_sha256: str | None = None

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {"view_id": self.view_id}
        if self.value is not None:
            result["value"] = self.value
        if self.bytes_sha256 is not None:
            result["bytes_sha256"] = self.bytes_sha256
        return result


@dataclass(frozen=True, order=True)
class DiscriminatorOutputView:
    argument_index: int
    cases: tuple[DiscriminatorCase, ...]
    read_bytes: int | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "discriminator",
            "argument_index": self.argument_index,
            **(
                {"read_bytes": self.read_bytes}
                if self.read_bytes is not None
                else {}
            ),
            "cases": [case.as_json() for case in self.cases],
        }


OutputView: TypeAlias = FixedOutputView | DiscriminatorOutputView


@dataclass(frozen=True, order=True)
class SuccessGuard:
    kind: str
    register: str
    value: int | None = None
    mask: int | None = None

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind, "register": self.register}
        if self.value is not None:
            result["value"] = self.value
        if self.mask is not None:
            result["mask"] = self.mask
        return result


@dataclass(frozen=True, order=True)
class ReturnRegisterOutput:
    register: str
    view: OutputView
    success_guard: SuccessGuard | None = None

    def as_json(self) -> dict[str, Any]:
        result = {
            "kind": "return_register",
            "register": self.register,
            "view": self.view.as_json(),
        }
        if self.success_guard is not None:
            result["success_guard"] = self.success_guard.as_json()
        return result


@dataclass(frozen=True, order=True)
class OutArgumentOutput:
    argument_index: int
    write_width: int
    view: OutputView
    success_guard: SuccessGuard | None = None

    def as_json(self) -> dict[str, Any]:
        result = {
            "kind": "out_argument",
            "argument_index": self.argument_index,
            "write_width": self.write_width,
            "view": self.view.as_json(),
        }
        if self.success_guard is not None:
            result["success_guard"] = self.success_guard.as_json()
        return result


@dataclass(frozen=True, order=True)
class ReturnRegisterOperationOutput:
    register: str
    result_id: str
    success_guard: SuccessGuard | None = None

    def as_json(self) -> dict[str, Any]:
        result = {
            "kind": "return_operation",
            "register": self.register,
            "result_id": self.result_id,
        }
        if self.success_guard is not None:
            result["success_guard"] = self.success_guard.as_json()
        return result


@dataclass(frozen=True, order=True)
class OutArgumentOperationOutput:
    argument_index: int
    write_width: int
    result_id: str
    success_guard: SuccessGuard | None = None

    def as_json(self) -> dict[str, Any]:
        result = {
            "kind": "out_argument_operation",
            "argument_index": self.argument_index,
            "write_width": self.write_width,
            "result_id": self.result_id,
        }
        if self.success_guard is not None:
            result["success_guard"] = self.success_guard.as_json()
        return result


OutputRule: TypeAlias = (
    ReturnRegisterOutput
    | OutArgumentOutput
    | ReturnRegisterOperationOutput
    | OutArgumentOperationOutput
)


@dataclass(frozen=True, order=True)
class DirectImportSelector:
    operation_id: str
    identity: MachineImportIdentity

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "direct_import",
            "operation_id": self.operation_id,
            "import": _import_json(self.identity),
        }

    def semantic_key(self) -> tuple[Any, ...]:
        return ("direct_import", *self.identity.state_machine_key())


@dataclass(frozen=True, order=True)
class TableSlotSelector:
    operation_id: str
    view_id: str
    slot: int

    @property
    def offset(self) -> int:
        return self.slot * 4

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "table_slot",
            "operation_id": self.operation_id,
            "view_id": self.view_id,
            "slot": self.slot,
        }

    def semantic_key(self) -> tuple[Any, ...]:
        return ("table_slot", self.view_id, self.slot)


@dataclass(frozen=True, order=True)
class ResolverResultSelector:
    operation_id: str
    resolver_operation_id: str
    result_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "resolver_result",
            "operation_id": self.operation_id,
            "resolver_operation_id": self.resolver_operation_id,
            "result_id": self.result_id,
        }

    def semantic_key(self) -> tuple[Any, ...]:
        return ("resolver_result", self.resolver_operation_id, self.result_id)


@dataclass(frozen=True, order=True)
class CallbackSelector:
    operation_id: str
    callback_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "callback",
            "operation_id": self.operation_id,
            "callback_id": self.callback_id,
        }

    def semantic_key(self) -> tuple[Any, ...]:
        return ("callback", self.callback_id)


OperationSelector: TypeAlias = (
    DirectImportSelector
    | TableSlotSelector
    | ResolverResultSelector
    | CallbackSelector
)


@dataclass(frozen=True, order=True)
class FixedFootprintSize:
    bytes: int

    def as_json(self) -> dict[str, Any]:
        return {"kind": "fixed", "bytes": self.bytes}


@dataclass(frozen=True, order=True)
class ArgumentFootprintSize:
    argument_index: int
    scale: int
    maximum_bytes: int

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "argument",
            "argument_index": self.argument_index,
            "scale": self.scale,
            "maximum_bytes": self.maximum_bytes,
        }


FootprintSize: TypeAlias = FixedFootprintSize | ArgumentFootprintSize


@dataclass(frozen=True, order=True)
class MemoryFootprint:
    access: str
    base_argument: int
    offset: int
    size: FootprintSize
    nullable: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "access": self.access,
            "base_argument": self.base_argument,
            "offset": self.offset,
            "size": self.size.as_json(),
            "nullable": self.nullable,
        }


@dataclass(frozen=True, order=True)
class WorldEffect:
    kind: str
    argument_index: int | None = None
    callback_id: str | None = None

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind}
        if self.argument_index is not None:
            result["argument_index"] = self.argument_index
        if self.callback_id is not None:
            result["callback_id"] = self.callback_id
        return result


@dataclass(frozen=True)
class ExternalOperationContract:
    contract_id: str
    status: str
    memory_footprints: tuple[MemoryFootprint, ...]
    world_effects: tuple[WorldEffect, ...]
    blockers: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
            "id": self.contract_id,
            "status": self.status,
            "memory_footprints": [
                footprint.as_json() for footprint in self.memory_footprints
            ],
            "world_effects": [effect.as_json() for effect in self.world_effects],
        }
        if self.blockers:
            result["blockers"] = list(self.blockers)
        return result


@dataclass(frozen=True)
class ExternalOperation:
    operation_id: str
    abi: MachineCallABI
    argument_words: int
    environment_contract_id: str
    output_rules: tuple[OutputRule, ...]
    receiver_resource: ReceiverResourceContract | None = None

    def as_json(self) -> dict[str, Any]:
        result = {
            "id": self.operation_id,
            "abi_template": self.abi.template,
            "argument_words": self.argument_words,
            "environment_contract_id": self.environment_contract_id,
            "output_rules": [output.as_json() for output in self.output_rules],
        }
        if self.receiver_resource is not None:
            result["receiver_resource"] = self.receiver_resource.as_json()
        return result


@dataclass(frozen=True)
class ExternalOperationProfile:
    path: Path | None
    profile_id: str
    sha256: str
    model: str
    provenance: Mapping[str, Any]
    table_views: tuple[ExternalOperationView, ...]
    operations: tuple[ExternalOperation, ...]
    selectors: tuple[OperationSelector, ...]
    environment_contracts: tuple[ExternalOperationContract, ...]

    def operations_by_id(self) -> dict[str, ExternalOperation]:
        return {operation.operation_id: operation for operation in self.operations}

    def views_by_id(self) -> dict[str, ExternalOperationView]:
        return {view.view_id: view for view in self.table_views}

    def contracts_by_id(self) -> dict[str, ExternalOperationContract]:
        return {
            contract.contract_id: contract
            for contract in self.environment_contracts
        }

    def selectors_by_operation_id(self) -> dict[str, tuple[OperationSelector, ...]]:
        result: dict[str, list[OperationSelector]] = {}
        for selector in self.selectors:
            result.setdefault(selector.operation_id, []).append(selector)
        return {key: tuple(value) for key, value in result.items()}

    def operation_for_selector(
        self, selector: OperationSelector
    ) -> ExternalOperation | None:
        selected = {
            item.semantic_key(): item.operation_id for item in self.selectors
        }.get(selector.semantic_key())
        return self.operations_by_id().get(selected) if selected is not None else None

    def operation_for_import(
        self, identity: MachineImportIdentity
    ) -> ExternalOperation | None:
        return self.operation_for_selector(DirectImportSelector("", identity))

    def operation_for_table_slot(
        self, view_id: str, slot: int
    ) -> ExternalOperation | None:
        return self.operation_for_selector(TableSlotSelector("", view_id, slot))

    def operation_for_resolver_result(
        self, resolver_operation_id: str, result_id: str
    ) -> ExternalOperation | None:
        return self.operation_for_selector(
            ResolverResultSelector("", resolver_operation_id, result_id)
        )

    def operation_for_callback(
        self, callback_id: str
    ) -> ExternalOperation | None:
        return self.operation_for_selector(CallbackSelector("", callback_id))

    def as_json(self) -> dict[str, Any]:
        return {
            "format": EXTERNAL_OPERATION_PROFILE_FORMAT,
            "id": self.profile_id,
            "model": self.model,
            "status": "complete",
            "provenance": copy.deepcopy(dict(self.provenance)),
            "table_views": [view.as_json() for view in self.table_views],
            "operations": [operation.as_json() for operation in self.operations],
            "selectors": [selector.as_json() for selector in self.selectors],
            "environment_contracts": [
                contract.as_json() for contract in self.environment_contracts
            ],
        }
