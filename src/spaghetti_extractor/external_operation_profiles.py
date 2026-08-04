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
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, TypeAlias

from .artifact_formats import (
    EXTERNAL_OPERATION_CONTRACT_FORMAT,
    EXTERNAL_OPERATION_PROFILE_FORMAT,
)
from .external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    ExternalInterfaceProfile,
)
from .machine_abi import (
    MACHINE_CALL_ABI_REGISTERS,
    MachineCallABI,
    resolve_machine_call_abi,
)
from .machine_import_profiles import MachineImportIdentity
from .stage_binary import StageAInputError

MAX_ARGUMENT_WORDS = 64
MAX_TABLE_SLOT = 0xFFFF
MAX_FOOTPRINT_BYTES = 16 * 1024 * 1024
_U32_MAX = 0xFFFFFFFF


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

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.operation_id,
            "abi_template": self.abi.template,
            "argument_words": self.argument_words,
            "environment_contract_id": self.environment_contract_id,
            "output_rules": [output.as_json() for output in self.output_rules],
        }


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


def load_external_operation_profile(
    path: Path | str,
) -> ExternalOperationProfile:
    profile_path = Path(path).resolve()
    payload = _read_json(profile_path, "external-operation profile")
    return parse_external_operation_profile(
        payload,
        path=profile_path,
    )


def parse_external_operation_profile(
    payload: Mapping[str, Any],
    *,
    path: Path | None = None,
    payload_sha256: str | None = None,
) -> ExternalOperationProfile:
    row = _object(payload, "external-operation profile")
    _exact_keys(
        row,
        {
            "format", "id", "model", "status", "provenance", "table_views",
            "operations", "selectors", "environment_contracts",
        },
        set(),
        "external-operation profile",
    )
    if row.get("format") != EXTERNAL_OPERATION_PROFILE_FORMAT:
        raise ExternalOperationProfileError(
            "unsupported external-operation profile format"
        )
    if row.get("status") != "complete":
        raise ExternalOperationProfileError(
            "external-operation profile is not complete"
        )
    profile_id = _nonempty(row.get("id"), "external-operation profile ID")
    model = _nonempty(row.get("model"), "external-operation machine model")
    if model != "x86-pe32":
        raise ExternalOperationProfileError(
            f"unsupported external-operation machine model {model!r}"
        )
    provenance = copy.deepcopy(
        dict(_object(row.get("provenance"), "profile provenance"))
    )

    views = tuple(
        _view(value, index)
        for index, value in enumerate(
            _array(row.get("table_views"), "profile table views")
        )
    )
    _unique((view.view_id for view in views), "external-operation view ID")
    _unique((view.table for view in views), "external-operation table")

    contracts = tuple(
        _contract(value, f"environment contract {index}")
        for index, value in enumerate(
            _array(row.get("environment_contracts"), "environment contracts")
        )
    )
    _unique(
        (contract.contract_id for contract in contracts),
        "external-operation environment contract ID",
    )
    contract_ids = {contract.contract_id for contract in contracts}

    operations = tuple(
        _operation(value, index)
        for index, value in enumerate(
            _array(row.get("operations"), "profile operations")
        )
    )
    if not operations:
        raise ExternalOperationProfileError(
            "external-operation profile has no operations"
        )
    _unique(
        (operation.operation_id for operation in operations),
        "external-operation ID",
    )
    operation_ids = {operation.operation_id for operation in operations}
    views_by_id = {view.view_id: view for view in views}
    contracts_by_id = {
        contract.contract_id: contract for contract in contracts
    }

    selectors = tuple(
        _selector(value, index)
        for index, value in enumerate(
            _array(row.get("selectors"), "profile selectors")
        )
    )
    if not selectors:
        raise ExternalOperationProfileError(
            "external-operation profile has no selectors"
        )
    _unique(
        (selector.semantic_key() for selector in selectors),
        "external-operation selector",
    )

    selected_operation_ids: set[str] = set()
    for selector in selectors:
        if selector.operation_id not in operation_ids:
            raise ExternalOperationProfileError(
                f"selector references unknown operation {selector.operation_id!r}"
            )
        selected_operation_ids.add(selector.operation_id)
        if isinstance(selector, TableSlotSelector) and selector.view_id not in views_by_id:
            raise ExternalOperationProfileError(
                f"table-slot selector references unknown view {selector.view_id!r}"
            )
        if isinstance(selector, ResolverResultSelector):
            if selector.resolver_operation_id not in operation_ids:
                raise ExternalOperationProfileError(
                    "resolver-result selector references an unknown resolver operation"
                )
            if selector.resolver_operation_id == selector.operation_id:
                raise ExternalOperationProfileError(
                    "resolver-result selector cannot resolve itself"
                )
    unselected = operation_ids - selected_operation_ids
    if unselected:
        raise ExternalOperationProfileError(
            "operations have no selectors: " + ", ".join(sorted(unselected))
        )
    _reject_resolver_cycles(selectors)

    referenced_contracts: set[str] = set()
    resolver_results = {
        (selector.resolver_operation_id, selector.result_id)
        for selector in selectors
        if isinstance(selector, ResolverResultSelector)
    }
    callback_ids = {
        selector.callback_id
        for selector in selectors
        if isinstance(selector, CallbackSelector)
    }
    for operation in operations:
        contract = contracts_by_id.get(operation.environment_contract_id)
        if contract is None:
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} references unknown "
                f"environment contract {operation.environment_contract_id!r}"
            )
        referenced_contracts.add(contract.contract_id)
        _validate_operation(
            operation,
            contract,
            views_by_id,
            resolver_results=resolver_results,
            callback_ids=callback_ids,
        )
    unused_contracts = contract_ids - referenced_contracts
    if unused_contracts:
        raise ExternalOperationProfileError(
            "environment contracts are unused: "
            + ", ".join(sorted(unused_contracts))
        )

    normalized_payload = {
        "format": EXTERNAL_OPERATION_PROFILE_FORMAT,
        "id": profile_id,
        "model": model,
        "status": "complete",
        "provenance": provenance,
        "table_views": [view.as_json() for view in views],
        "operations": [operation.as_json() for operation in operations],
        "selectors": [selector.as_json() for selector in selectors],
        "environment_contracts": [contract.as_json() for contract in contracts],
    }
    canonical_payload = _canonical_json(normalized_payload)
    digest = (
        _sha256_digest(payload_sha256, "external-operation profile SHA-256")
        if payload_sha256 is not None
        else sha256(canonical_payload).hexdigest()
    )
    return ExternalOperationProfile(
        path=path,
        profile_id=profile_id,
        sha256=digest,
        model=model,
        provenance=provenance,
        table_views=views,
        operations=operations,
        selectors=selectors,
        environment_contracts=contracts,
    )


def load_external_operation_contract(
    path: Path | str,
) -> ExternalOperationContract:
    return parse_external_operation_contract(
        _read_json(Path(path).resolve(), "external-operation contract")
    )


def parse_external_operation_contract(
    payload: Mapping[str, Any],
) -> ExternalOperationContract:
    return _contract(payload, "external-operation contract")


def convert_external_interface_profile(
    profile: ExternalInterfaceProfile,
) -> ExternalOperationProfile:
    """Purely convert one loaded v1 interface profile into the v2 typed model."""

    if not isinstance(profile, ExternalInterfaceProfile):
        raise TypeError("profile must be an ExternalInterfaceProfile")

    table_views = [
        {
            "id": interface.interface_id,
            "table": interface.vtable,
            "access": "object_table",
        }
        for interface in profile.interfaces
    ]
    operations: list[dict[str, Any]] = []
    selectors: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []

    def append_operation(
        *,
        operation_id: str,
        abi: MachineCallABI,
        argument_words: int,
        outputs: list[dict[str, Any]],
        selector: dict[str, Any],
    ) -> None:
        contract_id = f"{operation_id}:environment"
        operations.append({
            "id": operation_id,
            "abi_template": abi.template,
            "argument_words": argument_words,
            "environment_contract_id": contract_id,
            "output_rules": outputs,
        })
        selectors.append({**selector, "operation_id": operation_id})
        output_widths = {
            int(output["argument_index"]): int(output["write_width"])
            for output in outputs
            if output["kind"] == "out_argument"
        }
        contracts.append({
            "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
            "id": contract_id,
            "status": "incomplete",
            "blockers": [
                "legacy_interface_profile_has_no_complete_external_effect_contract"
            ],
            "memory_footprints": [
                {
                    "access": "write",
                    "base_argument": argument_index,
                    "offset": 0,
                    "size": {"kind": "fixed", "bytes": width},
                    "nullable": False,
                }
                for argument_index, width in sorted(output_widths.items())
            ],
            "world_effects": [],
        })

    for factory in profile.factories:
        identity = factory.identity
        operation_id = (
            f"import:{identity.dll}!"
            + (str(identity.value) if identity.kind == "symbol" else f"#{identity.value}")
        )
        append_operation(
            operation_id=operation_id,
            abi=factory.abi,
            argument_words=factory.argument_words,
            outputs=[
                {
                    "kind": "out_argument",
                    "argument_index": output.argument_index,
                    "write_width": 4,
                    "view": {"kind": "fixed", "view_id": output.interface_id},
                }
                for output in factory.outputs
            ],
            selector={"kind": "direct_import", "import": _import_json(identity)},
        )

    for interface in profile.interfaces:
        for method in interface.methods:
            operation_id = (
                f"table:{interface.interface_id}[{method.slot}]:{method.name}"
            )
            append_operation(
                operation_id=operation_id,
                abi=method.abi,
                argument_words=method.argument_words,
                outputs=[
                    {
                        "kind": "out_argument",
                        "argument_index": output.argument_index,
                        "write_width": 4,
                        "view": {
                            "kind": "fixed", "view_id": output.interface_id,
                        },
                    }
                    for output in method.outputs
                ],
                selector={
                    "kind": "table_slot",
                    "view_id": interface.interface_id,
                    "slot": method.slot,
                },
            )

    converted = {
        "format": EXTERNAL_OPERATION_PROFILE_FORMAT,
        "id": profile.profile_id,
        "model": profile.model,
        "status": "complete",
        "provenance": {
            **copy.deepcopy(dict(profile.provenance)),
            "compatibility": {
                "source_format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
                "source_sha256": profile.sha256,
            },
        },
        "table_views": table_views,
        "operations": operations,
        "selectors": selectors,
        "environment_contracts": contracts,
    }
    return parse_external_operation_profile(converted, path=profile.path)


# Explicit aliases keep the conversion discoverable from either schema direction.
convert_external_interface_profile_v1 = convert_external_interface_profile
external_operation_profile_from_interface_profile = convert_external_interface_profile


def _view(value: Any, index: int) -> ExternalOperationView:
    context = f"table view {index}"
    row = _object(value, context)
    _exact_keys(row, {"id", "table"}, {"access"}, context)
    access = row.get("access", "object_table")
    if access not in {"object_table", "direct_table"}:
        raise ExternalOperationProfileError(
            f"{context} access must be object_table or direct_table"
        )
    return ExternalOperationView(
        view_id=_nonempty(row.get("id"), f"{context} ID"),
        table=_nonempty(row.get("table"), f"{context} table"),
        access=str(access),
    )


def _operation(value: Any, index: int) -> ExternalOperation:
    context = f"operation {index}"
    row = _object(value, context)
    _exact_keys(
        row,
        {
            "id", "abi_template", "argument_words", "environment_contract_id",
            "output_rules",
        },
        set(),
        context,
    )
    abi = resolve_machine_call_abi(row.get("abi_template"))
    if abi is None:
        raise ExternalOperationProfileError(f"{context} has an unsupported ABI")
    argument_words = _bounded_index(
        row.get("argument_words"),
        f"{context} argument words",
        maximum=MAX_ARGUMENT_WORDS,
        inclusive=True,
    )
    outputs = tuple(
        _output_rule(item, f"{context} output rule {position}")
        for position, item in enumerate(
            _array(row.get("output_rules"), f"{context} output rules")
        )
    )
    return ExternalOperation(
        operation_id=_nonempty(row.get("id"), f"{context} ID"),
        abi=abi,
        argument_words=argument_words,
        environment_contract_id=_nonempty(
            row.get("environment_contract_id"),
            f"{context} environment contract ID",
        ),
        output_rules=outputs,
    )


def _selector(value: Any, index: int) -> OperationSelector:
    context = f"selector {index}"
    row = _object(value, context)
    kind = row.get("kind")
    operation_id = _nonempty(row.get("operation_id"), f"{context} operation ID")
    if kind == "direct_import":
        _exact_keys(row, {"kind", "operation_id", "import"}, set(), context)
        imported = _object(row.get("import"), f"{context} import")
        _exact_keys(
            imported,
            {"dll"},
            {"symbol", "ordinal"},
            f"{context} import",
        )
        try:
            identity = MachineImportIdentity.from_mapping(imported, context=context)
        except StageAInputError as exc:
            raise ExternalOperationProfileError(str(exc)) from exc
        return DirectImportSelector(operation_id, identity)
    if kind == "table_slot":
        _exact_keys(
            row, {"kind", "operation_id", "view_id", "slot"}, set(), context
        )
        return TableSlotSelector(
            operation_id,
            _nonempty(row.get("view_id"), f"{context} view ID"),
            _bounded_index(
                row.get("slot"), f"{context} slot", maximum=MAX_TABLE_SLOT,
            ),
        )
    if kind == "resolver_result":
        _exact_keys(
            row,
            {
                "kind", "operation_id", "resolver_operation_id", "result_id",
            },
            set(),
            context,
        )
        return ResolverResultSelector(
            operation_id,
            _nonempty(
                row.get("resolver_operation_id"),
                f"{context} resolver operation ID",
            ),
            _nonempty(row.get("result_id"), f"{context} result ID"),
        )
    if kind == "callback":
        _exact_keys(
            row, {"kind", "operation_id", "callback_id"}, set(), context
        )
        return CallbackSelector(
            operation_id,
            _nonempty(row.get("callback_id"), f"{context} callback ID"),
        )
    raise ExternalOperationProfileError(
        f"{context} has unsupported kind {kind!r}"
    )


def _output_rule(value: Any, context: str) -> OutputRule:
    row = _object(value, context)
    kind = row.get("kind")
    if kind == "return_register":
        _exact_keys(
            row,
            {"kind", "register", "view"},
            {"success_guard"},
            context,
        )
        return ReturnRegisterOutput(
            register=_register(row.get("register"), f"{context} register"),
            view=_output_view(row.get("view"), f"{context} view"),
            success_guard=_optional_guard(row, context),
        )
    if kind == "out_argument":
        _exact_keys(
            row,
            {"kind", "argument_index", "write_width", "view"},
            {"success_guard"},
            context,
        )
        return OutArgumentOutput(
            argument_index=_bounded_index(
                row.get("argument_index"),
                f"{context} argument index",
                maximum=MAX_ARGUMENT_WORDS - 1,
            ),
            write_width=_write_width(
                row.get("write_width"), f"{context} write width"
            ),
            view=_output_view(row.get("view"), f"{context} view"),
            success_guard=_optional_guard(row, context),
        )
    if kind == "return_operation":
        _exact_keys(
            row,
            {"kind", "register", "result_id"},
            {"success_guard"},
            context,
        )
        return ReturnRegisterOperationOutput(
            register=_register(row.get("register"), f"{context} register"),
            result_id=_nonempty(row.get("result_id"), f"{context} result ID"),
            success_guard=_optional_guard(row, context),
        )
    if kind == "out_argument_operation":
        _exact_keys(
            row,
            {"kind", "argument_index", "write_width", "result_id"},
            {"success_guard"},
            context,
        )
        return OutArgumentOperationOutput(
            argument_index=_bounded_index(
                row.get("argument_index"),
                f"{context} argument index",
                maximum=MAX_ARGUMENT_WORDS - 1,
            ),
            write_width=_write_width(
                row.get("write_width"), f"{context} write width"
            ),
            result_id=_nonempty(row.get("result_id"), f"{context} result ID"),
            success_guard=_optional_guard(row, context),
        )
    raise ExternalOperationProfileError(
        f"{context} has unsupported kind {kind!r}"
    )


def _output_view(value: Any, context: str) -> OutputView:
    row = _object(value, context)
    kind = row.get("kind")
    if kind == "fixed":
        _exact_keys(row, {"kind", "view_id"}, set(), context)
        return FixedOutputView(_nonempty(row.get("view_id"), f"{context} ID"))
    if kind == "discriminator":
        _exact_keys(
            row,
            {"kind", "argument_index", "cases"},
            {"read_bytes"},
            context,
        )
        cases = tuple(
            _discriminator_case(item, f"{context} case {index}")
            for index, item in enumerate(
                _array(row.get("cases"), f"{context} cases")
            )
        )
        if not cases:
            raise ExternalOperationProfileError(
                f"{context} must have at least one case"
            )
        read_bytes = row.get("read_bytes")
        if read_bytes is not None:
            read_bytes = _bounded_index(
                read_bytes,
                f"{context} read bytes",
                maximum=64,
                inclusive=True,
            )
            if read_bytes == 0 or any(case.bytes_sha256 is None for case in cases):
                raise ExternalOperationProfileError(
                    f"{context} pointed-byte cases require hashes and nonzero width"
                )
            _unique(
                (case.bytes_sha256 for case in cases),
                f"{context} discriminator bytes hash",
            )
        else:
            if any(case.value is None for case in cases):
                raise ExternalOperationProfileError(
                    f"{context} scalar cases require integer values"
                )
            _unique((case.value for case in cases), f"{context} discriminator value")
        return DiscriminatorOutputView(
            argument_index=_bounded_index(
                row.get("argument_index"),
                f"{context} argument index",
                maximum=MAX_ARGUMENT_WORDS - 1,
            ),
            cases=tuple(sorted(cases)),
            read_bytes=read_bytes,
        )
    raise ExternalOperationProfileError(
        f"{context} has unsupported kind {kind!r}"
    )


def _discriminator_case(value: Any, context: str) -> DiscriminatorCase:
    row = _object(value, context)
    _exact_keys(row, {"view_id"}, {"value", "bytes_sha256"}, context)
    has_value = "value" in row
    has_hash = "bytes_sha256" in row
    if has_value == has_hash:
        raise ExternalOperationProfileError(
            f"{context} requires exactly one scalar value or bytes hash"
        )
    digest = row.get("bytes_sha256")
    if has_hash and (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ExternalOperationProfileError(
            f"{context} bytes hash must be lowercase SHA-256"
        )
    return DiscriminatorCase(
        value=(
            _u32(row.get("value"), f"{context} value")
            if has_value
            else None
        ),
        view_id=_nonempty(row.get("view_id"), f"{context} view ID"),
        bytes_sha256=str(digest) if has_hash else None,
    )


def _optional_guard(row: Mapping[str, Any], context: str) -> SuccessGuard | None:
    if "success_guard" not in row:
        return None
    guard = _object(row.get("success_guard"), f"{context} success guard")
    kind = guard.get("kind")
    if kind == "equals":
        _exact_keys(
            guard, {"kind", "register", "value"}, set(), f"{context} success guard"
        )
        return SuccessGuard(
            kind, _register(guard.get("register"), f"{context} guard register"),
            value=_u32(guard.get("value"), f"{context} guard value"),
        )
    if kind == "masked_equals":
        _exact_keys(
            guard,
            {"kind", "register", "mask", "value"},
            set(),
            f"{context} success guard",
        )
        mask = _u32(guard.get("mask"), f"{context} guard mask")
        selected = _u32(guard.get("value"), f"{context} guard value")
        if mask == 0 or selected & ~mask:
            raise ExternalOperationProfileError(
                f"{context} success guard value must fit its nonzero mask"
            )
        return SuccessGuard(
            kind,
            _register(guard.get("register"), f"{context} guard register"),
            value=selected,
            mask=mask,
        )
    if kind == "nonzero":
        _exact_keys(
            guard, {"kind", "register"}, set(), f"{context} success guard"
        )
        return SuccessGuard(
            kind, _register(guard.get("register"), f"{context} guard register")
        )
    raise ExternalOperationProfileError(
        f"{context} has unsupported success guard {kind!r}"
    )


def _contract(value: Any, context: str) -> ExternalOperationContract:
    row = _object(value, context)
    _exact_keys(
        row,
        {"format", "id", "status", "memory_footprints", "world_effects"},
        {"blockers"},
        context,
    )
    if row.get("format") != EXTERNAL_OPERATION_CONTRACT_FORMAT:
        raise ExternalOperationProfileError(
            f"{context} has an unsupported format"
        )
    status = row.get("status")
    if status not in {"complete", "incomplete"}:
        raise ExternalOperationProfileError(
            f"{context} has unsupported status {status!r}"
        )
    blockers = tuple(
        _nonempty(blocker, f"{context} blocker {index}")
        for index, blocker in enumerate(
            _array(row.get("blockers", []), f"{context} blockers")
        )
    )
    if len(set(blockers)) != len(blockers):
        raise ExternalOperationProfileError(f"{context} has duplicate blockers")
    if status == "complete" and blockers:
        raise ExternalOperationProfileError(
            f"{context} complete status cannot have blockers"
        )
    if status == "incomplete" and not blockers:
        raise ExternalOperationProfileError(
            f"{context} incomplete status requires blockers"
        )
    footprints = tuple(
        _memory_footprint(item, f"{context} memory footprint {index}")
        for index, item in enumerate(
            _array(row.get("memory_footprints"), f"{context} memory footprints")
        )
    )
    if len(set(footprints)) != len(footprints):
        raise ExternalOperationProfileError(
            f"{context} has duplicate memory footprints"
        )
    effects = tuple(
        _world_effect(item, f"{context} world effect {index}")
        for index, item in enumerate(
            _array(row.get("world_effects"), f"{context} world effects")
        )
    )
    if len(set(effects)) != len(effects):
        raise ExternalOperationProfileError(
            f"{context} has duplicate world effects"
        )
    return ExternalOperationContract(
        contract_id=_nonempty(row.get("id"), f"{context} ID"),
        status=str(status),
        memory_footprints=footprints,
        world_effects=effects,
        blockers=blockers,
    )


def _memory_footprint(value: Any, context: str) -> MemoryFootprint:
    row = _object(value, context)
    _exact_keys(
        row,
        {"access", "base_argument", "offset", "size", "nullable"},
        set(),
        context,
    )
    access = row.get("access")
    if access not in {"read", "write", "read_write"}:
        raise ExternalOperationProfileError(
            f"{context} has unsupported access {access!r}"
        )
    nullable = row.get("nullable")
    if not isinstance(nullable, bool):
        raise ExternalOperationProfileError(
            f"{context} nullable must be a boolean"
        )
    offset = row.get("offset")
    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or not -(2**31) <= offset < 2**31
    ):
        raise ExternalOperationProfileError(
            f"{context} offset must be a signed 32-bit integer"
        )
    return MemoryFootprint(
        access=str(access),
        base_argument=_bounded_index(
            row.get("base_argument"),
            f"{context} base argument",
            maximum=MAX_ARGUMENT_WORDS - 1,
        ),
        offset=offset,
        size=_footprint_size(row.get("size"), f"{context} size"),
        nullable=nullable,
    )


def _footprint_size(value: Any, context: str) -> FootprintSize:
    row = _object(value, context)
    kind = row.get("kind")
    if kind == "fixed":
        _exact_keys(row, {"kind", "bytes"}, set(), context)
        return FixedFootprintSize(_footprint_bytes(row.get("bytes"), context))
    if kind == "argument":
        _exact_keys(
            row,
            {"kind", "argument_index", "scale", "maximum_bytes"},
            set(),
            context,
        )
        scale = _positive_bounded(
            row.get("scale"), f"{context} scale", MAX_FOOTPRINT_BYTES
        )
        maximum_bytes = _positive_bounded(
            row.get("maximum_bytes"),
            f"{context} maximum bytes",
            MAX_FOOTPRINT_BYTES,
        )
        if scale > maximum_bytes:
            raise ExternalOperationProfileError(
                f"{context} scale exceeds its maximum byte bound"
            )
        return ArgumentFootprintSize(
            argument_index=_bounded_index(
                row.get("argument_index"),
                f"{context} argument index",
                maximum=MAX_ARGUMENT_WORDS - 1,
            ),
            scale=scale,
            maximum_bytes=maximum_bytes,
        )
    raise ExternalOperationProfileError(
        f"{context} has unsupported kind {kind!r}"
    )


def _world_effect(value: Any, context: str) -> WorldEffect:
    row = _object(value, context)
    kind = row.get("kind")
    if kind in {"opaqueResources", "dynamicRanges", "tlsState"}:
        _exact_keys(row, {"kind"}, set(), context)
        return WorldEffect(str(kind))
    if kind == "dynamicRangeRelease":
        _exact_keys(row, {"kind", "argument_index"}, set(), context)
        return WorldEffect(
            str(kind),
            _bounded_index(
                row.get("argument_index"),
                f"{context} argument index",
                maximum=MAX_ARGUMENT_WORDS - 1,
            ),
        )
    if kind == "callbackRegistration":
        _exact_keys(
            row,
            {"kind", "argument_index", "callback_id"},
            set(),
            context,
        )
        return WorldEffect(
            str(kind),
            _bounded_index(
                row.get("argument_index"),
                f"{context} argument index",
                maximum=MAX_ARGUMENT_WORDS - 1,
            ),
            _nonempty(row.get("callback_id"), f"{context} callback ID"),
        )
    raise ExternalOperationProfileError(
        f"{context} has unsupported kind {kind!r}"
    )


def _validate_operation(
    operation: ExternalOperation,
    contract: ExternalOperationContract,
    views_by_id: Mapping[str, ExternalOperationView],
    *,
    resolver_results: set[tuple[str, str]],
    callback_ids: set[str],
) -> None:
    locations: set[tuple[str, int | str]] = set()
    for output in operation.output_rules:
        location = (
            ("register", output.register)
            if isinstance(
                output, (ReturnRegisterOutput, ReturnRegisterOperationOutput)
            )
            else ("argument", output.argument_index)
        )
        if location in locations:
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} has duplicate output location"
            )
        locations.add(location)
        if isinstance(
            output, (ReturnRegisterOutput, ReturnRegisterOperationOutput)
        ):
            if output.register not in operation.abi.clobbered_registers:
                raise ExternalOperationProfileError(
                    f"operation {operation.operation_id!r} returns through a preserved register"
                )
        else:
            if output.argument_index >= operation.argument_words:
                raise ExternalOperationProfileError(
                    f"operation {operation.operation_id!r} output argument is out of range"
                )
            if not any(
                footprint.base_argument == output.argument_index
                and footprint.offset == 0
                and footprint.access in {"write", "read_write"}
                and isinstance(footprint.size, FixedFootprintSize)
                and footprint.size.bytes >= output.write_width
                for footprint in contract.memory_footprints
            ):
                raise ExternalOperationProfileError(
                    f"operation {operation.operation_id!r} out argument lacks a bounded write footprint"
                )
        if isinstance(output, (ReturnRegisterOutput, OutArgumentOutput)):
            _validate_output_view(operation, output.view, views_by_id)
        elif (
            operation.operation_id,
            output.result_id,
        ) not in resolver_results:
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} output result "
                f"{output.result_id!r} has no resolver-result selector"
            )
        if output.success_guard is not None and (
            output.success_guard.register not in operation.abi.clobbered_registers
        ):
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} success guard reads a preserved register"
            )

    for footprint in contract.memory_footprints:
        if footprint.base_argument >= operation.argument_words:
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} footprint base argument is out of range"
            )
        if (
            isinstance(footprint.size, ArgumentFootprintSize)
            and footprint.size.argument_index >= operation.argument_words
        ):
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} footprint size argument is out of range"
            )
    for effect in contract.world_effects:
        if (
            effect.argument_index is not None
            and effect.argument_index >= operation.argument_words
        ):
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} world-effect argument is out of range"
            )
        if (
            effect.kind == "callbackRegistration"
            and effect.callback_id not in callback_ids
        ):
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} registers unknown callback "
                f"{effect.callback_id!r}"
            )


def _validate_output_view(
    operation: ExternalOperation,
    view: OutputView,
    views_by_id: Mapping[str, ExternalOperationView],
) -> None:
    if isinstance(view, FixedOutputView):
        view_ids = (view.view_id,)
    else:
        if view.argument_index >= operation.argument_words:
            raise ExternalOperationProfileError(
                f"operation {operation.operation_id!r} discriminator argument is out of range"
            )
        view_ids = tuple(case.view_id for case in view.cases)
    unknown = set(view_ids) - set(views_by_id)
    if unknown:
        raise ExternalOperationProfileError(
            f"operation {operation.operation_id!r} references unknown output views: "
            + ", ".join(sorted(unknown))
        )


def _reject_resolver_cycles(selectors: tuple[OperationSelector, ...]) -> None:
    edges: dict[str, set[str]] = {}
    for selector in selectors:
        if isinstance(selector, ResolverResultSelector):
            edges.setdefault(selector.operation_id, set()).add(
                selector.resolver_operation_id
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(operation_id: str) -> None:
        if operation_id in visiting:
            raise ExternalOperationProfileError(
                "resolver-result selectors form a cycle"
            )
        if operation_id in visited:
            return
        visiting.add(operation_id)
        for dependency in edges.get(operation_id, set()):
            visit(dependency)
        visiting.remove(operation_id)
        visited.add(operation_id)

    for operation_id in sorted(edges):
        visit(operation_id)


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalOperationProfileError(f"cannot read {context} {path}: {exc}") from exc


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ExternalOperationProfileError(
            f"external-operation profile is not finite JSON: {exc}"
        ) from exc


def _import_json(identity: MachineImportIdentity) -> dict[str, Any]:
    return {
        "dll": identity.dll,
        identity.kind: identity.value,
    }


def _exact_keys(
    value: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    context: str,
) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        raise ExternalOperationProfileError(
            f"{context} has invalid fields ({'; '.join(details)})"
        )


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise ExternalOperationProfileError(f"{context} must be a JSON object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ExternalOperationProfileError(f"{context} must be a JSON array")
    return value


def _nonempty(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalOperationProfileError(f"{context} must be a nonempty string")
    return value


def _register(value: Any, context: str) -> str:
    if value not in MACHINE_CALL_ABI_REGISTERS:
        raise ExternalOperationProfileError(f"{context} is not a machine ABI register")
    return str(value)


def _bounded_index(
    value: Any,
    context: str,
    *,
    maximum: int,
    inclusive: bool = False,
) -> int:
    upper = maximum + 1
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < upper
    ):
        relation = "at most" if inclusive else "between 0 and"
        raise ExternalOperationProfileError(f"{context} must be {relation} {maximum}")
    return value


def _u32(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= _U32_MAX
    ):
        raise ExternalOperationProfileError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return value


def _sha256_digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ExternalOperationProfileError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _write_width(value: Any, context: str) -> int:
    if value not in {1, 2, 4, 8} or isinstance(value, bool):
        raise ExternalOperationProfileError(f"{context} must be 1, 2, 4, or 8")
    return int(value)


def _footprint_bytes(value: Any, context: str) -> int:
    return _positive_bounded(value, f"{context} bytes", MAX_FOOTPRINT_BYTES)


def _positive_bounded(value: Any, context: str, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= maximum
    ):
        raise ExternalOperationProfileError(
            f"{context} must be between 1 and {maximum}"
        )
    return value


def _unique(values: Any, context: str) -> None:
    seen: set[Any] = set()
    for value in values:
        if value in seen:
            raise ExternalOperationProfileError(f"duplicate {context}: {value!r}")
        seen.add(value)


__all__ = [
    "ArgumentFootprintSize",
    "CallbackSelector",
    "DirectImportSelector",
    "DiscriminatorCase",
    "DiscriminatorOutputView",
    "EXTERNAL_OPERATION_CONTRACT_FORMAT",
    "EXTERNAL_OPERATION_PROFILE_FORMAT",
    "ExternalOperation",
    "ExternalOperationContract",
    "ExternalOperationProfile",
    "ExternalOperationProfileError",
    "ExternalOperationView",
    "FixedFootprintSize",
    "FixedOutputView",
    "FootprintSize",
    "MAX_ARGUMENT_WORDS",
    "MAX_FOOTPRINT_BYTES",
    "MAX_TABLE_SLOT",
    "MemoryFootprint",
    "OperationSelector",
    "OutArgumentOperationOutput",
    "OutArgumentOutput",
    "OutputRule",
    "OutputView",
    "ResolverResultSelector",
    "ReturnRegisterOperationOutput",
    "ReturnRegisterOutput",
    "SuccessGuard",
    "TableSlotSelector",
    "WorldEffect",
    "convert_external_interface_profile",
    "convert_external_interface_profile_v1",
    "external_operation_profile_from_interface_profile",
    "load_external_operation_contract",
    "load_external_operation_profile",
    "parse_external_operation_contract",
    "parse_external_operation_profile",
]
