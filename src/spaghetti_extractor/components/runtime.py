"""Generate the executable component runtime package from checked v3 inputs."""

from __future__ import annotations

import copy
import json
import re
import shutil
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.formats import GENERATED_LIBRARY_COMPONENT_V1_FORMAT, MACHINE_IR_FORMAT
from ..external.contracts import (
    CheckedExternalSiteContractError,
    parse_checked_external_site_contract,
)
from .region_replacement import REGION_OVERRIDE_TABLE_FORMAT
from ..util import sha256_file, write_json
from .formats import (
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
    COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
    COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
    PORTABLE_SELECTION_V3_FORMAT,
    COMPONENT_SOURCE_PACKAGE_V3_FORMAT,
)
from .activation_receipt import ActivationReceiptV1
from .boundary_plan import (
    BoundaryOperationPlanV2,
    ComponentBoundaryPlanReceiptV2,
    ComponentBoundaryPlanV2,
)
from .atomics import interface_uses_atomics, spx_atomics_header
from .implementation import ComponentImplementationV3
from .interface_ir import PortableComponentInterfaceV2
from .machine_binding import ComponentMachineBindingV1
from .runtime_paths import render_finite_path_operation
from .semantic_contract import ComponentSemanticContractV1
from .universal_binding import read_component_machine_binding_v3
from .universal_contract import read_component_contract_v3
from .semantic_paths import SemanticPathError, build_operation_path_model
from .runtime_expressions import (
    CExpression as _CExpression,
    CompletionExpression as _CompletionExpression,
    STATE_FIELDS as _STATE_FIELDS,
    json_pointer as _json_pointer,
    machine_source_expression as _machine_source_expression,
    render_external_call as _render_external_call,
    result_register as _result_register,
)
from .adapter import load_component_adapter_plan
from .intent import ComponentIntentError
from .logical_abi import (
    LOGICAL_OBJECT_C_V1,
    NUL_TERMINATED_BYTES_V1,
    READ_ONLY_BYTES_V1,
    logical_c_type,
    parameter_shape_error,
)
from .source import load_component_source_package


def build_component_runtime_package(
    *,
    machine_ir: Path | str,
    activation_plan: Path | str,
    contracts: Mapping[str, Path | str],
    portable_interfaces: Mapping[str, Path | str] | None = None,
    semantic_contracts: Mapping[str, Path | str] | None = None,
    implementations: Mapping[str, Path | str],
    qualifications: Mapping[str, Path | str],
    adapter_plans: Mapping[str, Path | str],
    activation_receipts: Mapping[str, Path | str] | None = None,
    machine_bindings: Mapping[str, Path | str] | None = None,
    boundary_plans: Mapping[str, Path | str] | None = None,
    library_components: Mapping[str, Path | str] | None = None,
    interpreter_package: Path | str,
    out_dir: Path | str,
) -> dict[str, object]:
    """Create one hash-bound package consumed by every candidate phase.

    Enabled components are all-or-nothing. Their boundary entries receive
    strong native overrides; internal member units are marked as subsumed and
    are forbidden from silently falling back at runtime.
    """

    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    activation = _read_object(Path(activation_plan), "component activation plan")
    _check_self_hash(
        activation,
        COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
        "activation_plan_sha256",
        "component activation plan",
    )
    if activation.get("status") != "checked":
        raise ComponentIntentError("component activation plan is not checked")
    activation_counts = _object(
        activation.get("counts"), "component activation counts"
    )
    activation_entries = [
        _object(row, "component activation entry")
        for row in _array(activation.get("entries"), "component activation entries")
    ]
    ownership_states = (
        "portable_replacement",
        "machine_ir_fallback",
        "blocked",
    )
    observed_counts = {
        state: sum(row.get("implementation_kind") == state for row in activation_entries)
        for state in ownership_states
    }
    if any(
        row.get("implementation_kind") not in ownership_states
        for row in activation_entries
    ):
        raise ComponentIntentError("component activation plan has an invalid ownership state")
    if any(activation_counts.get(state) != count for state, count in observed_counts.items()):
        raise ComponentIntentError("component activation ownership counts are stale")
    if observed_counts["blocked"] != 0:
        raise ComponentIntentError("component activation plan contains blocked units")
    machine_path, machine_manifest_path, machine_rows = _load_machine_ir(Path(machine_ir))
    activation_bindings = _object(
        activation.get("bindings"), "component activation bindings"
    )
    if (
        activation_bindings.get("machine_ir_sha256") != sha256_file(machine_path)
        or activation_bindings.get("machine_ir_manifest_sha256")
        != sha256_file(machine_manifest_path)
    ):
        raise ComponentIntentError("component activation plan has stale machine-IR bindings")
    activation_by_id = {
        _string(row.get("unit_id"), "component activation unit id"): row
        for row in activation_entries
    }
    if len(activation_by_id) != len(activation_entries) or set(activation_by_id) != set(
        machine_rows
    ):
        raise ComponentIntentError(
            "component activation plan does not exactly cover the machine-IR units"
        )
    for unit_id, row in activation_by_id.items():
        if row.get("rva") != _unit_rva(machine_rows[unit_id]):
            raise ComponentIntentError(
                f"component activation plan has a stale RVA for {unit_id}"
            )
    interpreter_manifest, baseline_program_sha256 = _interpreter_binding(
        Path(interpreter_package)
    )
    portable_selections = [
        _object(row, "component selection")
        for row in _array(activation.get("selections"), "component selections")
        if isinstance(row, Mapping)
        and row.get("ownership_state") == "portable_replacement"
    ]
    library_selections = {
        _string(row.get("id"), "library component selection id"): row
        for row in portable_selections
        if row.get("kind") == "library_component"
    }
    authored_portable_selections = [
        row for row in portable_selections if row.get("kind") != "library_component"
    ]
    component_rows: list[dict[str, object]] = []
    selection_rows: list[dict[str, object]] = []
    override_entries: list[dict[str, object]] = []
    activation_receipt_inputs = activation_receipts or {}
    machine_binding_inputs = machine_bindings or {}
    boundary_plan_inputs = boundary_plans or {}
    portable_interface_inputs = portable_interfaces or {}
    semantic_contract_inputs = semantic_contracts or {}
    library_component_inputs = library_components or {}

    for selection in authored_portable_selections:
        identity = _string(selection.get("id"), "portable component id")
        implementation_root = _required_mapping_path(
            implementations, identity, "source package"
        )
        source = load_component_source_package(implementation_root)
        if source.get("format") == COMPONENT_SOURCE_PACKAGE_V3_FORMAT:
            portable_interface_path = _required_mapping_path(
                portable_interface_inputs, identity, "portable interface"
            )
            receipt_path = _required_mapping_path(
                activation_receipt_inputs, identity, "activation receipt"
            )
            binding_path = _required_mapping_path(
                machine_binding_inputs, identity, "machine binding"
            )
            interface_file = (
                portable_interface_path / "portable-interface.json"
                if portable_interface_path.is_dir()
                else portable_interface_path
            )
            interface = PortableComponentInterfaceV2.parse(
                _read_object(interface_file, "portable component interface")
            )
            binding_file = (
                binding_path / "machine-binding.json"
                if binding_path.is_dir()
                else binding_path
            )
            binding = ComponentMachineBindingV1.parse(
                _read_object(binding_file, "component machine binding")
            )
            plan_root = _required_mapping_path(
                boundary_plan_inputs, identity, "checked boundary plan"
            )
            plan_file = (
                plan_root / "boundary-plan.json" if plan_root.is_dir() else plan_root
            )
            plan_receipt_file = (
                plan_root / "boundary-plan-receipt.json"
                if plan_root.is_dir()
                else plan_root.with_name("boundary-plan-receipt.json")
            )
            boundary_plan = ComponentBoundaryPlanV2.parse(
                _read_object(plan_file, "component boundary plan")
            )
            boundary_plan_receipt = ComponentBoundaryPlanReceiptV2.parse(
                _read_object(plan_receipt_file, "component boundary plan receipt")
            )
            semantic_contract_path = _required_mapping_path(
                semantic_contract_inputs, identity, "semantic contract"
            )
            semantic_contract_file = (
                semantic_contract_path / "semantic-contract.json"
                if semantic_contract_path.is_dir()
                else semantic_contract_path
            )
            semantic_contract = ComponentSemanticContractV1.parse(
                _read_object(semantic_contract_file, "component semantic contract")
            )
            component_row, component_selections, component_overrides = (
                _build_v2_scalar_component(
                    identity=identity,
                    interface=interface,
                    implementation_root=implementation_root,
                    source=source,
                    activation_receipt_path=receipt_path,
                    binding=binding,
                    boundary_plan=boundary_plan,
                    boundary_plan_receipt=boundary_plan_receipt,
                    semantic_contract=semantic_contract,
                    members={
                        unit_id: machine_rows[unit_id]
                        for unit_id in binding.unit_ids
                    },
                    output=output,
                )
            )
            component_rows.append(component_row)
            selection_rows.extend(component_selections)
            override_entries.extend(component_overrides)
            continue
        contract_root = _required_mapping_path(contracts, identity, "contract")
        contract = _read_object(contract_root / "contract.json", "component contract")
        _check_self_hash(
            contract,
            COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
            "contract_sha256",
            "component contract",
        )
        qualification_path = _required_mapping_path(
            qualifications, identity, "qualification"
        )
        adapter_plan_root = _required_mapping_path(
            adapter_plans, identity, "adapter plan"
        )
        qualification = _read_object(
            qualification_path / "qualification.json"
            if qualification_path.is_dir()
            else qualification_path,
            "component qualification",
        )
        _check_self_hash(
            qualification,
            COMPONENT_QUALIFICATION_V3_FORMAT,
            "qualification_sha256",
            "component qualification",
        )
        adapter_plan = load_component_adapter_plan(adapter_plan_root)
        _validate_component_bindings(
            identity, contract, source, qualification, adapter_plan
        )
        interface = _read_object(
            contract_root / "reviewed-interface.json", "reviewed component interface"
        )
        catalog = _read_object(
            contract_root / "semantic-component-catalog.json", "component catalog"
        )
        machine_boundary = _component_machine_boundary(catalog, identity)
        member_ids = tuple(
            _string(value, "component member unit")
            for value in _array(
                _object(contract.get("lift_unit"), "contract lift unit").get("unit_ids"),
                "component member units",
            )
        )
        members = {unit_id: machine_rows[unit_id] for unit_id in member_ids}
        entries = [
            _object(row, "component machine entry")
            for row in _array(machine_boundary.get("entries"), "component machine entries")
        ]
        if len(entries) != 1:
            raise ComponentIntentError(
                f"component {identity} executable lowering currently requires one "
                f"checked machine entry, observed {len(entries)}"
            )

        copied_sources = _copy_component_sources(
            implementation_root, source, output, identity
        )
        shutil.copyfile(
            (adapter_plan_root if adapter_plan_root.is_dir() else adapter_plan_root.parent)
            / "spaghetti-component-abi.h",
            output / "components" / identity / "spaghetti-component-abi.h",
        )
        adapter_relative = Path("components") / identity / "generated-adapter.c"
        adapter_path = output / adapter_relative
        adapter_symbols: list[tuple[int, str, str]] = []
        adapter_text = _render_component_adapter(
            identity=identity,
            interface=interface,
            source=source,
            adapter_plan=adapter_plan,
            members=members,
            entry_ids=tuple(
                _string(entry.get("unit_id"), "component entry unit")
                for entry in entries
            ),
            symbols=adapter_symbols,
        )
        adapter_path.parent.mkdir(parents=True, exist_ok=True)
        adapter_path.write_text(adapter_text, encoding="ascii")

        component_core: dict[str, object] = {
            "id": identity,
            "contract_sha256": contract["contract_sha256"],
            "implementation_sha256": source["implementation_sha256"],
            "qualification_sha256": qualification["qualification_sha256"],
            "adapter_plan_sha256": adapter_plan["adapter_plan_sha256"],
            "source_entry": copy.deepcopy(source["entry"]),
            "unit_ids": sorted(member_ids),
            "entries": [
                {"unit_id": unit_id, "rva": rva, "symbol": symbol}
                for rva, unit_id, symbol in adapter_symbols
            ],
            "adapter_sha256": sha256_file(adapter_path),
        }
        component_manifest_sha256 = _canonical_sha256(component_core)
        component_row = {
            **component_core,
            "component_manifest_sha256": component_manifest_sha256,
        }
        component_rows.append(component_row)
        entry_by_id = {
            unit_id: (rva, symbol) for rva, unit_id, symbol in adapter_symbols
        }
        primary_entry_rva = min(rva for rva, _unit, _symbol in adapter_symbols)
        for unit_id in member_ids:
            rva = _unit_rva(members[unit_id])
            is_entry = unit_id in entry_by_id
            replacement_id = f"{identity}:{unit_id}" if is_entry else identity
            selection_rows.append(
                {
                    "unit_id": unit_id,
                    "rva": rva,
                    "replacement_id": replacement_id,
                    "cluster_id": identity,
                    "component_manifest_sha256": component_manifest_sha256,
                    "fallback_on_unimplemented": False,
                    "dispatch_role": "entry" if is_entry else "subsumed_member",
                    "entry_rva": entry_by_id[unit_id][0] if is_entry else primary_entry_rva,
                }
            )
        for rva, unit_id, symbol in adapter_symbols:
            replacement_id = f"{identity}:{unit_id}"
            override_entries.append(
                {
                    "replacement_id": replacement_id,
                    "manifest_sha256": component_manifest_sha256,
                    "cluster_id": identity,
                    "entry_unit_id": unit_id,
                    "entry_rva": rva,
                    "fallback_on_unimplemented": False,
                    "unit_ids": sorted(member_ids),
                    "rva_spans": _member_spans(members),
                    "symbol": symbol,
                    "source": _artifact(adapter_path, output, symbol=symbol),
                    "support_sources": copied_sources,
                }
            )

    for selection_id, raw_root in sorted(library_component_inputs.items()):
        component_root = Path(raw_root)
        manifest = _read_object(
            component_root / "library-component.json",
            "generated library component",
        )
        _check_self_hash(
            manifest,
            GENERATED_LIBRARY_COMPONENT_V1_FORMAT,
            "package_sha256",
            "generated library component",
        )
        if manifest.get("status") != "complete":
            raise ComponentIntentError(
                f"library adoption {selection_id!r} is not a complete generated component"
            )
        identity = _string(manifest.get("component_id"), "library component id")
        activation_selection = library_selections.get(identity)
        if activation_selection is None:
            raise ComponentIntentError(
                f"library adoption {selection_id!r} is absent from the activation plan"
            )
        source_root = component_root / "source-package"
        source = load_component_source_package(source_root)
        interface = PortableComponentInterfaceV2.parse(
            _read_object(
                component_root / "portable-interface.json",
                "library portable interface",
            )
        )
        binding = ComponentMachineBindingV1.parse(
            _read_object(
                component_root / "machine-binding.json",
                "library machine binding",
            )
        )
        universal_contract = read_component_contract_v3(
            component_root / "component-contract-v3.json"
        )
        universal_binding = read_component_machine_binding_v3(
            component_root / "machine-binding-v3.json"
        )
        universal_implementation = ComponentImplementationV3.parse(
            _read_object(
                component_root / "implementation-v3.json",
                "library universal implementation",
            )
        )
        selected_units = {
            _string(value, "library activation unit")
            for value in _array(
                activation_selection.get("unit_ids"), "library activation units"
            )
        }
        if (
            activation_selection.get("selection_id") != selection_id
            or selected_units != set(universal_binding.unit_ids)
            or activation_selection.get("machine_binding_sha256")
            != universal_binding.binding_sha256
            or activation_selection.get("activation_receipt_sha256")
            != universal_implementation.authority_sha256
            or activation_selection.get("contract_sha256")
            != universal_contract.contract_sha256
            or universal_binding.contract_sha256
            != universal_contract.contract_sha256
            or universal_implementation.contract_sha256
            != universal_contract.contract_sha256
        ):
            raise ComponentIntentError(
                f"library adoption {selection_id!r} has stale activation authority"
            )
        semantic_contract = ComponentSemanticContractV1.parse(
            _read_object(
                component_root / "semantic-contract.json",
                "library semantic contract",
            )
        )
        component_row, component_selections, component_overrides = (
            _build_v2_scalar_component(
                identity=identity,
                interface=interface,
                implementation_root=source_root,
                source=source,
                activation_receipt_path=component_root / "implementation-v3.json",
                binding=binding,
                semantic_contract=semantic_contract,
                members={
                    unit_id: machine_rows[unit_id]
                    for unit_id in binding.unit_ids
                },
                output=output,
                library_component_manifest=manifest,
            )
        )
        component_rows.append(component_row)
        selection_rows.extend(component_selections)
        override_entries.extend(component_overrides)

    if set(library_selections) != {
        _string(
            _read_object(Path(root) / "library-component.json", "generated library component").get("component_id"),
            "library component id",
        )
        for root in library_component_inputs.values()
    }:
        raise ComponentIntentError(
            "activation plan and generated library implementation inventory differ"
        )

    selected_unit_ids = [str(row["unit_id"]) for row in selection_rows]
    if len(selected_unit_ids) != len(set(selected_unit_ids)):
        raise ComponentIntentError(
            "portable components claim overlapping machine-IR units"
        )

    selection_core = {
        "format": PORTABLE_SELECTION_V3_FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "machine_ir_sha256": sha256_file(machine_path),
        "activation_plan_sha256": activation["activation_plan_sha256"],
        "entries": sorted(selection_rows, key=lambda row: (int(row["rva"]), str(row["unit_id"]))),
    }
    selection_payload = {
        **selection_core,
        "selection_sha256": _canonical_sha256(selection_core),
    }
    selection_path = output / "portable-component-selection.json"
    write_json(selection_path, selection_payload)

    override_manifest_path: Path | None = None
    if override_entries:
        override_manifest_path = _write_override_package(
            output=output,
            entries=override_entries,
            machine_ir_sha256=sha256_file(machine_path),
            baseline_program_sha256=baseline_program_sha256,
        )
    core: dict[str, object] = {
        "format": COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "bindings": {
            "activation_plan_sha256": activation["activation_plan_sha256"],
            "machine_ir_sha256": sha256_file(machine_path),
            "machine_ir_manifest_sha256": sha256_file(machine_manifest_path),
            "interpreter_manifest_sha256": sha256_file(interpreter_manifest),
            "baseline_program_sha256": baseline_program_sha256,
            "portable_selection_sha256": selection_payload["selection_sha256"],
        },
        "policy": {
            "runtime_package_is_sole_candidate_authority": True,
            "enabled_components_must_have_checked_activation_authority": True,
            "subsumed_members_may_not_fallback": True,
            "fallback_on_unimplemented": False,
            "original_execution_forbidden": True,
        },
        "components": sorted(component_rows, key=lambda row: str(row["id"])),
        "counts": {
            "portable_components": len(component_rows),
            "portable_units": len(selection_rows),
            "override_entries": len(override_entries),
        },
        "artifacts": {
            "portable_selection": _artifact(selection_path, output),
            "region_overrides": (
                None
                if override_manifest_path is None
                else _artifact(override_manifest_path, output)
            ),
        },
    }
    result = {**core, "runtime_package_sha256": _canonical_sha256(core)}
    manifest_path = output / "component-runtime-package.json"
    write_json(manifest_path, result)
    completion_core = {
        "format": COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
        "status": "complete",
        "runtime_package_sha256": result["runtime_package_sha256"],
        "activation_plan_sha256": activation["activation_plan_sha256"],
        "structural_units": len(machine_rows),
        "portable_units": len(selection_rows),
        "fallback_units": len(machine_rows) - len(selection_rows),
        "ownership_complete": True,
        "ownership_exclusive": True,
        "executes_original_binary": False,
    }
    completion = {
        **completion_core,
        "completion_sha256": _canonical_sha256(completion_core),
    }
    write_json(output / "component-runtime-completion.json", completion)
    return result


def _render_component_adapter(
    *,
    identity: str,
    interface: Mapping[str, object],
    source: Mapping[str, object],
    adapter_plan: Mapping[str, object],
    members: Mapping[str, Mapping[str, object]],
    entry_ids: tuple[str, ...],
    symbols: list[tuple[int, str, str]],
) -> str:
    parameters = [
        _object(row, "logical parameter")
        for row in _array(interface.get("parameters"), "logical parameters")
    ]
    value_results = [
        _object(row, "logical result")
        for row in _array(interface.get("results"), "logical results")
        if isinstance(row, Mapping) and row.get("kind") in {"return", "value"}
    ]
    if len(value_results) != 1:
        raise ComponentIntentError(
            f"component {identity} requires exactly one logical value result"
        )
    result = value_results[0]
    abi = _object(source.get("entry"), "component source entry").get("abi")
    for parameter in parameters:
        shape_error = parameter_shape_error(parameter, parameters, source_abi=abi)
        if shape_error is not None:
            raise ComponentIntentError(
                f"component {identity} logical parameter is unsupported: {shape_error}"
            )
    entry = _object(source.get("entry"), "component source entry")
    function_symbol = _string(entry.get("symbol"), "logical source symbol")
    prototype = "{result} {symbol}({parameters});".format(
        result=_c_type(result.get("type"), source_abi=abi),
        symbol=function_symbol,
        parameters=", ".join(
            f"{_c_type(row.get('type'), source_abi=abi)} "
            f"{_c_identifier(str(row.get('id')))}"
            for row in parameters
        )
        or "void",
    )
    functions: list[str] = []
    lowering = _object(adapter_plan.get("lowering"), "component adapter lowering")
    for entry_id in entry_ids:
        if entry_id not in members:
            raise ComponentIntentError(f"component {identity} entry is not a member")
        symbol = "spx_component_{identity}_{rva:08x}".format(
            identity=_c_identifier(identity), rva=_unit_rva(members[entry_id])
        )
        symbols.append((_unit_rva(members[entry_id]), entry_id, symbol))
        if lowering.get("kind") == "scalar-machine-projection-v1":
            result_register = _result_register(result, members)
            path = [
                members[_string(unit_id, "scalar adapter path unit")]
                for unit_id in _array(
                    lowering.get("path_unit_ids"), "scalar adapter path"
                )
            ]
            function = _render_scalar_entry_adapter(
                symbol=symbol,
                logical_symbol=function_symbol,
                parameters=parameters,
                result=result,
                result_register=result_register,
                path=path,
            )
        elif lowering.get("kind") == "scalar-control-projection-v1":
            path = [
                members[_string(unit_id, "scalar control adapter path unit")]
                for unit_id in _array(
                    lowering.get("path_unit_ids"), "scalar control adapter path"
                )
            ]
            function = _render_scalar_entry_adapter(
                symbol=symbol,
                logical_symbol=function_symbol,
                parameters=parameters,
                result=result,
                result_register=None,
                path=path,
            )
        elif lowering.get("kind") == "checked-object-view-v1":
            function = _render_object_entry_adapter(
                symbol=symbol,
                logical_symbol=function_symbol,
                parameters=parameters,
                result=result,
                completion=_object(
                    lowering.get("completion"), "component adapter completion"
                ),
                external_replay=(
                    None
                    if lowering.get("external_replay") is None
                    else _object(
                        lowering.get("external_replay"),
                        "component external replay plan",
                    )
                ),
                external_calls=_array(
                    lowering.get("external_calls", []),
                    "component external calls",
                ),
                members=members,
            )
        else:
            raise ComponentIntentError(
                f"component {identity} has no checked runtime lowering"
            )
        functions.append(function)
    return "\n".join(
        [
            '#include "state-machine-runtime.h"',
            '#include "spaghetti-component-abi.h"',
            "#include <stdint.h>",
            "",
            prototype,
            "",
            "static uint32_t component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {",
            "  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }",
            "  return rt->read(rt->context, address, width, fault);",
            "}",
            "static void component_write(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {",
            "  if (rt == 0 || rt->write == 0) { *fault = 1U; return; }",
            "  rt->write(rt->context, address, width, value, fault);",
            "}",
            "static uint32_t component_parity(uint32_t value) {",
            "  value &= 0xffU; value ^= value >> 4U; value &= 0xfU;",
            "  return (0x9669U >> value) & 1U;",
            "}",
            "static uint32_t component_sub_overflow(uint32_t left, uint32_t right, uint32_t result) {",
            "  return (((left ^ right) & (left ^ result)) >> 31U) & 1U;",
            "}",
            "static uint32_t component_add_overflow(uint32_t left, uint32_t right, uint32_t result) {",
            "  return (((~(left ^ right)) & (left ^ result)) >> 31U) & 1U;",
            "}",
            "typedef struct component_ro_bytes_context {",
            "  spx_runtime *runtime; uint32_t base; uint32_t extent; uint32_t bounded; uint32_t fault;",
            "} component_ro_bytes_context;",
            "static uint32_t component_read_u8(void *opaque, uint32_t index, uint8_t *out) {",
            "  component_ro_bytes_context *view = (component_ro_bytes_context *)opaque;",
            "  uint32_t fault = 0U, value;",
            "  if (view == 0 || out == 0 || view->runtime == 0 || view->runtime->read == 0 || (view->bounded != 0U && index >= view->extent) || view->base > UINT32_MAX - index) {",
            "    if (view != 0) { view->fault = 1U; }",
            "    return 1U;",
            "  }",
            "  value = view->runtime->read(view->runtime->context, view->base + index, 1U, &fault);",
            "  if (fault != 0U) { view->fault = 1U; return 1U; }",
            "  *out = (uint8_t)value; return 0U;",
            "}",
            "",
            *functions,
            "",
        ]
    )


def _build_v2_scalar_component(
    *,
    identity: str,
    interface: PortableComponentInterfaceV2,
    implementation_root: Path,
    source: Mapping[str, object],
    activation_receipt_path: Path,
    binding: ComponentMachineBindingV1,
    boundary_plan: ComponentBoundaryPlanV2,
    boundary_plan_receipt: ComponentBoundaryPlanReceiptV2,
    semantic_contract: ComponentSemanticContractV1,
    members: Mapping[str, Mapping[str, object]],
    output: Path,
    library_component_manifest: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    receipt_file = (
        activation_receipt_path / "activation-receipt.json"
        if activation_receipt_path.is_dir()
        else activation_receipt_path
    )
    raw_authority = _read_object(receipt_file, "component activation authority")
    if library_component_manifest is None:
        receipt = ActivationReceiptV1.parse(raw_authority)
        authority_valid = (
            receipt.status == "checked"
            and receipt.activation_authorized
            and receipt.component_id == identity
            and receipt.bindings.get("implementation_sha256")
            == source.get("implementation_sha256")
            and receipt.bindings.get("interface_sha256") == interface.sha256
            and receipt.bindings.get("component_machine_binding_sha256")
            == binding.binding_sha256
        )
        activation_authority_binding = {
            "activation_receipt_sha256": receipt.receipt_sha256,
        }
    else:
        implementation = ComponentImplementationV3.parse(raw_authority)
        manifest_bindings = _object(
            library_component_manifest.get("bindings"),
            "generated library component bindings",
        )
        authority_valid = (
            implementation.authorizing
            and implementation.kind == "portable_c"
            and implementation.component_id == identity
            and implementation.artifact_sha256
            == source.get("implementation_sha256")
            and implementation.implementation_sha256
            == manifest_bindings.get("universal_implementation_sha256")
            and manifest_bindings.get("source_package_sha256")
            == source.get("implementation_sha256")
            and manifest_bindings.get("interface_sha256") == interface.sha256
        )
        activation_authority_binding = {
            "universal_implementation_sha256": (
                implementation.implementation_sha256
            ),
        }
    if (
        not authority_valid
        or binding.identity != identity
        or not boundary_plan_receipt.authorizing
        or boundary_plan_receipt.component_id != identity
        or boundary_plan_receipt.plan_sha256 != boundary_plan.plan_sha256
        or boundary_plan.component_id != identity
        or boundary_plan.bindings.get("interface_sha256") != interface.sha256
        or boundary_plan.bindings.get("machine_binding_sha256")
        != binding.binding_sha256
        or binding.interface_sha256 != interface.sha256
        or set(binding.unit_ids) != set(members)
        or semantic_contract.status != "satisfied"
        or semantic_contract.payload.get("component_id") != identity
        or _object(
            semantic_contract.payload.get("bindings"),
            "semantic contract bindings",
        ).get("machine_binding_sha256") != binding.binding_sha256
    ):
        raise ComponentIntentError(
            f"component {identity} portable V2 activation bindings are stale"
        )

    symbols = _object(source.get("operation_symbols"), "component operation symbols")
    interface.validate_operation_symbols(symbols)
    component_dir = output / "components" / identity
    copied_sources = _copy_component_sources(
        implementation_root, source, output, identity
    )
    public_header = component_dir / "portable-component.h"
    implementation_header = component_dir / "portable-component-implementation.h"
    public_header.write_text(interface.render_public_header(), encoding="ascii")
    implementation_header.write_text(
        interface.render_implementation_header(symbols), encoding="ascii"
    )
    atomic_public_header: Path | None = None
    if interface_uses_atomics(interface.types):
        atomic_public_header = component_dir / "spx-atomics.h"
        atomic_public_header.write_text(spx_atomics_header(), encoding="ascii")
    support_sources = copied_sources + [
        _artifact(public_header, output),
        _artifact(implementation_header, output),
        *(
            [_artifact(atomic_public_header, output)]
            if atomic_public_header is not None
            else []
        ),
    ]
    adapter_path = component_dir / "generated-adapter.c"
    adapter_symbols: list[tuple[int, str, str]] = []
    adapter_path.write_text(
        _render_v2_scalar_adapter(
            identity=identity,
            interface=interface,
            binding=binding,
            boundary_plan=boundary_plan,
            semantic_contract=semantic_contract,
            source_symbols=symbols,
            members=members,
            symbols=adapter_symbols,
        ),
        encoding="ascii",
    )
    component_core: dict[str, object] = {
        "id": identity,
        "interface_format": interface.format_version,
        "interface_sha256": interface.sha256,
        "implementation_sha256": source["implementation_sha256"],
        **activation_authority_binding,
        "machine_binding_sha256": binding.binding_sha256,
        "boundary_plan_sha256": boundary_plan.plan_sha256,
        "boundary_plan_receipt_sha256": boundary_plan_receipt.receipt_sha256,
        "operation_symbols": dict(symbols),
        "unit_ids": sorted(members),
        "entries": [
            {"unit_id": unit_id, "rva": rva, "symbol": symbol}
            for rva, unit_id, symbol in adapter_symbols
        ],
        "adapter_sha256": sha256_file(adapter_path),
    }
    manifest_sha256 = _canonical_sha256(component_core)
    row = {**component_core, "component_manifest_sha256": manifest_sha256}
    entry_by_id = {unit_id: (rva, symbol) for rva, unit_id, symbol in adapter_symbols}
    primary_entry_rva = min(rva for rva, _symbol in entry_by_id.values())
    selections = [
        {
            "unit_id": unit_id,
            "rva": _unit_rva(members[unit_id]),
            "replacement_id": f"{identity}:{unit_id}" if unit_id in entry_by_id else identity,
            "cluster_id": identity,
            "component_manifest_sha256": manifest_sha256,
            "fallback_on_unimplemented": False,
            "dispatch_role": "entry" if unit_id in entry_by_id else "subsumed_member",
            "entry_rva": entry_by_id.get(unit_id, (primary_entry_rva, ""))[0],
        }
        for unit_id in sorted(members, key=lambda item: (_unit_rva(members[item]), item))
    ]
    overrides = [
        {
            "replacement_id": f"{identity}:{unit_id}",
            "manifest_sha256": manifest_sha256,
            "cluster_id": identity,
            "entry_unit_id": unit_id,
            "entry_rva": rva,
            "fallback_on_unimplemented": False,
            "unit_ids": sorted(members),
            "rva_spans": _member_spans(members),
            "symbol": symbol,
            "source": _artifact(adapter_path, output, symbol=symbol),
            "support_sources": support_sources,
        }
        for rva, unit_id, symbol in adapter_symbols
    ]
    return row, selections, overrides


def _render_v2_scalar_adapter(
    *,
    identity: str,
    interface: PortableComponentInterfaceV2,
    binding: ComponentMachineBindingV1,
    boundary_plan: ComponentBoundaryPlanV2,
    semantic_contract: ComponentSemanticContractV1,
    source_symbols: Mapping[str, object],
    members: Mapping[str, Mapping[str, object]],
    symbols: list[tuple[int, str, str]],
) -> str:
    interface_id = interface.identity
    operation_index = {row.identity: row for row in interface.operations}
    contract_operations = {
        _string(row.get("operation_id"), "semantic operation id"): row
        for row in _array(
            semantic_contract.payload.get("operations"),
            "semantic contract operations",
        )
        if isinstance(row, Mapping)
    }
    plan_operations = {
        row.operation_id: row for row in boundary_plan.operations
    }
    if set(plan_operations) != set(operation_index):
        raise ComponentIntentError(
            f"component {identity} boundary plan operation inventory differs"
        )
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "portable-component-implementation.h"',
        *(
            ['#include "spx-atomics-backend.h"']
            if interface_uses_atomics(interface.types)
            else []
        ),
        *(
            ['#include "spx-capability-backend.h"']
            if any(logical_type.kind == "callback" for logical_type in interface.types)
            else []
        ),
        "#include <stdint.h>",
        "",
        "static uint32_t component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {",
        "  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }",
        "  return rt->read(rt->context, address, width, fault);",
        "}",
        "static void component_write(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {",
        "  if (rt == 0 || rt->write == 0) { *fault = 1U; return; }",
        "  rt->write(rt->context, address, width, value, fault);",
        "}",
        "static uint32_t component_parity(uint32_t value) {",
        "  value &= 0xffU; value ^= value >> 4U; value &= 0xfU;",
        "  return (0x9669U >> value) & 1U;",
        "}",
        "static uint32_t component_sub_overflow(uint32_t left, uint32_t right, uint32_t result) {",
        "  return (((left ^ right) & (left ^ result)) >> 31U) & 1U;",
        "}",
        "static uint32_t component_add_overflow(uint32_t left, uint32_t right, uint32_t result) {",
        "  return (((~(left ^ right)) & (left ^ result)) >> 31U) & 1U;",
        "}",
        f"static const spx_{interface_id}_services_v2 component_services = {{ 0 }};",
        f"static spx_{interface_id}_context_v2 component_context = {{",
        "  .services = &component_services,",
        "  .state = { 0 },",
        f"  .protocol_state = SPX_{interface_id.upper()}_PROTOCOL_{interface.initial_protocol_state.upper()},",
        "};",
        "",
    ]
    for bound in binding.operations:
        operation = operation_index[bound.operation_id]
        entry_id = bound.entry_unit_ids[0]
        rva = _unit_rva(members[entry_id])
        adapter_symbol = f"spx_component_{_c_identifier(identity)}_{rva:08x}"
        symbols.append((rva, entry_id, adapter_symbol))
        try:
            path_model = build_operation_path_model(
                contract_operations[bound.operation_id],
                interface,
                semantic_contract.payload.get("services"),
            )
            lines.append(
                render_finite_path_operation(
                    interface=interface,
                    operation=operation,
                    binding=bound,
                    service_bindings=semantic_contract.payload.get("services", []),
                    source_symbol=_string(
                        source_symbols[bound.operation_id],
                        "portable source symbol",
                    ),
                    adapter_symbol=adapter_symbol,
                    model=path_model,
                    boundary_plan=plan_operations[bound.operation_id],
                )
            )
        except (KeyError, SemanticPathError) as exc:
            raise ComponentIntentError(
                f"portable V2 finite-path runtime lowering failed for "
                f"{bound.operation_id}: {exc}"
            ) from exc
    return "\n".join(lines)


def _render_scalar_entry_adapter(
    *,
    symbol: str,
    logical_symbol: str,
    parameters: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
    result_register: str | None,
    path: Sequence[Mapping[str, object]],
) -> str:
    lines = [
        f"spx_step_result {symbol}(spx_runtime *rt, spx_machine_state *state) {{",
        "  (void)rt;",
        "  uint32_t memory_fault = 0U;",
    ]
    input_names = {name: f"entry_{name}" for name in _STATE_FIELDS}
    lines.extend(
        f"  uint32_t entry_{name} = state->{name};" for name in _STATE_FIELDS
    )
    lines.extend(f"  (void)entry_{name};" for name in _STATE_FIELDS)
    renderer = _CExpression(input_names, memory_fault="memory_fault")
    argument_names: list[str] = []
    for index, parameter in enumerate(parameters):
        name = f"argument_{index}"
        source = _object(parameter.get("machine_source"), "logical parameter source")
        expression = source.get("expression")
        if source.get("kind") == "register":
            expression = {
                "op": "reg",
                "name": source.get("name"),
                "width": source.get("width", 32),
            }
        elif source.get("kind") == "expression":
            expression = source.get("expression")
        if expression is None:
            evidence = _object(source.get("evidence"), "logical parameter evidence")
            unit = next(
                row for row in path if row.get("id") == evidence.get("unit_id")
            )
            expression = _json_pointer(
                unit, _string(evidence.get("json_pointer"), "parameter evidence pointer")
            )
        lines.append(
            f"  {_c_type(parameter.get('type'), source_abi='logical-c-v1')} {name} = "
            f"({_c_type(parameter.get('type'), source_abi='logical-c-v1')})"
            f"({renderer.render(expression)});"
        )
        argument_names.append(name)
    lines.append("  if (memory_fault != 0U) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };")
    lines.append(
        f"  {_c_type(result.get('type'), source_abi='logical-c-v1')} "
        f"logical_result = {logical_symbol}({', '.join(argument_names)});"
    )

    terminal_kind: str | None = None
    terminal_target = "0U"
    terminal_value = "0U"
    for block_index, unit in enumerate(path):
        semantics = _object(unit.get("semantics"), "machine semantics")
        prefix = f"block_{block_index}"
        lines.extend(
            f"  uint32_t {prefix}_{name} = state->{name};"
            for name in _STATE_FIELDS
        )
        lines.extend(f"  (void){prefix}_{name};" for name in _STATE_FIELDS)
        names = {name: f"{prefix}_{name}" for name in _STATE_FIELDS}
        block_renderer = _CExpression(names, memory_fault="memory_fault")
        assignments: list[tuple[str, str]] = []
        for write_index, raw in enumerate(
            _array(semantics.get("register_writes", []), "register writes")
        ):
            write = _object(raw, "register write")
            register = _string(write.get("register"), "register write name")
            temporary = f"{prefix}_register_{write_index}"
            lines.append(
                f"  uint32_t {temporary} = {block_renderer.render(write.get('value'))};"
            )
            assignments.append((register, temporary))
        for write_index, raw in enumerate(
            _array(semantics.get("flag_writes", []), "flag writes")
        ):
            write = _object(raw, "flag write")
            flag = _string(write.get("flag"), "flag write name")
            temporary = f"{prefix}_flag_{write_index}"
            lines.append(
                f"  uint32_t {temporary} = {block_renderer.render(write.get('value'))};"
            )
            assignments.append((flag, temporary))
        outcome = _object(semantics.get("outcome"), "machine outcome")
        kind = _string(outcome.get("kind"), "machine outcome kind")
        if kind == "return":
            terminal_kind = "SPX_RETURN"
            terminal_value = f"{prefix}_return_value"
            lines.append(
                f"  uint32_t {terminal_value} = "
                f"{block_renderer.render(outcome.get('value'))};"
            )
        elif kind == "branch":
            terminal_kind = "SPX_BRANCH"
            terminal_target = (
                "((uint32_t)logical_result != 0U) ? "
                f"{int(outcome.get('true_target_rva') or 0)}U : "
                f"{int(outcome.get('false_target_rva') or 0)}U"
            )
        lines.append(
            "  if (memory_fault != 0U) return (spx_step_result)"
            "{ SPX_MEMORY_FAULT, 0U, 0U };"
        )
        lines.extend(f"  state->{name} = {value};" for name, value in assignments)
    if terminal_kind is None:
        raise ComponentIntentError("logical-c-v1 adapter path has no terminal outcome")
    if result_register is not None:
        lines.append(f"  state->{result_register} = (uint32_t)logical_result;")
    lines.append(
        f"  return (spx_step_result){{ {terminal_kind}, {terminal_target}, {terminal_value} }};"
    )
    lines.append("}")
    return "\n".join(lines)


def _render_object_entry_adapter(
    *,
    symbol: str,
    logical_symbol: str,
    parameters: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
    completion: Mapping[str, object],
    external_replay: Mapping[str, object] | None,
    external_calls: Sequence[object],
    members: Mapping[str, Mapping[str, object]],
) -> str:
    lines = [
        f"spx_step_result {symbol}(spx_runtime *rt, "
        "spx_machine_state *state) {",
        "  uint32_t memory_fault = 0U;",
    ]
    lines.extend(f"  uint32_t entry_{name} = state->{name};" for name in _STATE_FIELDS)
    lines.extend(f"  (void)entry_{name};" for name in _STATE_FIELDS)
    renderer = _CExpression(
        {name: f"entry_{name}" for name in _STATE_FIELDS},
        memory_fault="memory_fault",
    )
    raw_names: dict[str, str] = {}
    for index, parameter in enumerate(parameters):
        identity = _string(parameter.get("id"), "logical parameter id")
        source_expression = _machine_source_expression(parameter, members)
        raw_name = f"argument_{index}_machine"
        lines.append(
            f"  uint32_t {raw_name} = {renderer.render(source_expression)};"
        )
        raw_names[identity] = raw_name
    lines.append(
        "  if (memory_fault != 0U) return (spx_step_result)"
        "{ SPX_MEMORY_FAULT, 0U, 0U };"
    )
    external_result_names: dict[tuple[str, int, str], str] = {}
    if external_replay is not None:
        replay_lines, external_result_names = _render_linear_external_replay(
            external_replay,
            external_calls,
            members,
        )
        lines.extend(replay_lines)
    call_arguments: list[str] = []
    view_contexts: list[str] = []
    for index, parameter in enumerate(parameters):
        identity = _string(parameter.get("id"), "logical parameter id")
        if parameter.get("type") in {
            READ_ONLY_BYTES_V1,
            NUL_TERMINATED_BYTES_V1,
        }:
            view = _object(parameter.get("memory_view"), "logical memory view")
            context = f"argument_{index}_context"
            logical_view = f"argument_{index}"
            if parameter.get("type") == READ_ONLY_BYTES_V1:
                extent_id = _string(
                    view.get("extent_parameter_id"), "logical memory-view extent"
                )
                lines.append(
                    f"  component_ro_bytes_context {context} = "
                    f"{{ rt, {raw_names[identity]}, {raw_names[extent_id]}, 1U, 0U }};"
                )
                lines.append(
                    f"  spx_ro_bytes_v1 {logical_view} = "
                    f"{{ &{context}, {raw_names[extent_id]}, component_read_u8 }};"
                )
            else:
                lines.append(
                    f"  component_ro_bytes_context {context} = "
                    f"{{ rt, {raw_names[identity]}, 0U, 0U, 0U }};"
                )
                lines.append(
                    f"  spx_c_string_v1 {logical_view} = "
                    f"{{ &{context}, component_read_u8 }};"
                )
            call_arguments.append(f"&{logical_view}")
            view_contexts.append(context)
        else:
            call_arguments.append(
                f"({_c_type(parameter.get('type'), source_abi=LOGICAL_OBJECT_C_V1)})"
                f"{raw_names[identity]}"
            )
    lines.append(
        f"  {_c_type(result.get('type'), source_abi=LOGICAL_OBJECT_C_V1)} "
        f"logical_result = {logical_symbol}({', '.join(call_arguments)});"
    )
    if view_contexts:
        lines.append(
            "  if ("
            + " || ".join(f"{name}.fault != 0U" for name in view_contexts)
            + ") return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"
        )
    state_completion = _object(completion.get("state"), "adapter completion state")
    completion_renderer = _CompletionExpression(
        {name: f"entry_{name}" for name in _STATE_FIELDS},
        memory_fault="memory_fault",
        external_results=external_result_names,
    )
    for name in _STATE_FIELDS:
        lines.append(
            f"  uint32_t completed_{name} = "
            f"{completion_renderer.render(state_completion.get(name))};"
        )
    lines.append(
        "  uint32_t completed_return_target = "
        f"{completion_renderer.render(completion.get('return_target'))};"
    )
    memory_writes = [
        _object(row, "adapter completion memory write")
        for row in _array(
            completion.get("memory_writes"), "adapter completion memory writes"
        )
    ]
    for index, write in enumerate(memory_writes):
        lines.append(
            f"  uint32_t completed_write_{index}_address = "
            f"{completion_renderer.render(write.get('address'))};"
        )
        lines.append(
            f"  uint32_t completed_write_{index}_value = "
            f"{completion_renderer.render(write.get('value'))};"
        )
    lines.append(
        "  if (memory_fault != 0U) return (spx_step_result)"
        "{ SPX_MEMORY_FAULT, 0U, 0U };"
    )
    for index, write in enumerate(memory_writes):
        lines.append(
            "  component_write(rt, completed_write_{index}_address, {width}U, "
            "completed_write_{index}_value, &memory_fault);".format(
                index=index, width=int(write.get("width", 0))
            )
        )
    if memory_writes:
        lines.append(
            "  if (memory_fault != 0U) return (spx_step_result)"
            "{ SPX_MEMORY_FAULT, 0U, 0U };"
        )
    lines.extend(f"  state->{name} = completed_{name};" for name in _STATE_FIELDS)
    lines.append(
        "  return (spx_step_result){ SPX_RETURN, 0U, "
        "completed_return_target };"
    )
    lines.append("}")
    return "\n".join(lines)


def _render_linear_external_replay(
    plan: Mapping[str, object],
    raw_calls: Sequence[object],
    members: Mapping[str, Mapping[str, object]],
) -> tuple[list[str], dict[tuple[str, int, str], str]]:
    if plan.get("kind") != "linear-read-only-call-v1":
        raise ComponentIntentError("component external replay kind is unsupported")
    call_ref = _object(plan.get("call"), "component external replay call")
    unit_id = _string(call_ref.get("unit_id"), "component external replay unit")
    event_index = call_ref.get("event_index")
    if not isinstance(event_index, int) or isinstance(event_index, bool) or event_index < 0:
        raise ComponentIntentError("component external replay event index is invalid")
    matching = [
        _object(row, "component external call")
        for row in raw_calls
        if isinstance(row, Mapping)
        and row.get("unit_id") == unit_id
        and row.get("event_index") == event_index
    ]
    if len(matching) != 1:
        raise ComponentIntentError("component external replay call binding is stale")
    try:
        contract = parse_checked_external_site_contract(
            _object(matching[0].get("contract"), "component external contract"),
            context=f"component runtime external call {unit_id}:{event_index}",
        )
    except CheckedExternalSiteContractError as exc:
        raise ComponentIntentError(str(exc)) from exc
    if call_ref.get("contract_id") != contract.contract_id:
        raise ComponentIntentError("component external replay contract binding is stale")

    prefix_ids = [
        _string(value, "component external replay prefix unit")
        for value in _array(
            plan.get("prefix_unit_ids"), "component external replay prefix"
        )
    ]
    if not prefix_ids or prefix_ids[-1] != unit_id or any(
        value not in members for value in prefix_ids
    ):
        raise ComponentIntentError("component external replay prefix is stale")

    lines = ["  spx_machine_state external_replay_state = *state;"]
    read_index = 0
    for block_index, prefix_id in enumerate(prefix_ids):
        unit = members[prefix_id]
        semantics = _object(unit.get("semantics"), "machine semantics")
        prefix = f"external_block_{block_index}"
        renderer = _CExpression(
            {name: f"external_replay_state.{name}" for name in _STATE_FIELDS},
            memory_fault="memory_fault",
        )
        ordered = _array(semantics.get("ordered_events", []), "ordered events")
        if not ordered:
            ordered = [
                {"family": "memory", **dict(_object(row, "memory event"))}
                for row in _array(
                    semantics.get("memory_events", []), "memory events"
                )
            ] + [
                {"family": "external", **dict(_object(row, "external event"))}
                for row in _array(
                    semantics.get("external_events", []), "external events"
                )
            ]
        for raw_event in ordered:
            event = _object(raw_event, "ordered machine event")
            family = event.get("family")
            if family == "memory":
                address = renderer.render(event.get("address"))
                width = int(event.get("width", 4))
                if event.get("kind") == "read":
                    lines.extend(
                        [
                            f"  uint32_t external_read_{read_index} = component_read(rt, {address}, {width}U, &memory_fault);",
                            f"  (void)external_read_{read_index};",
                        ]
                    )
                    read_index += 1
                elif event.get("kind") == "write":
                    value = renderer.render(event.get("value"))
                    lines.append(
                        f"  component_write(rt, {address}, {width}U, {value}, &memory_fault);"
                    )
                else:
                    raise ComponentIntentError(
                        "component external replay memory event is unsupported"
                    )
                lines.append(
                    "  if (memory_fault != 0U) return (spx_step_result)"
                    "{ SPX_MEMORY_FAULT, 0U, 0U };"
                )
                continue
            if family != "external":
                raise ComponentIntentError(
                    "component external replay event family is unsupported"
                )
            if prefix_id != unit_id or event_index != 0:
                raise ComponentIntentError(
                    "component external replay encountered an unplanned event"
                )
            result_names = _render_external_call(
                lines=lines,
                contract=contract,
                event=event,
                renderer=renderer,
                unit_id=unit_id,
                event_index=event_index,
            )
            return lines, result_names

        if prefix_id == unit_id:
            raise ComponentIntentError("component external replay call was not found")
        assignments: list[tuple[str, str]] = []
        for index, raw in enumerate(
            _array(semantics.get("register_writes", []), "register writes")
        ):
            write = _object(raw, "register write")
            register = _string(write.get("register"), "register write name")
            temporary = f"{prefix}_register_{index}"
            lines.append(
                f"  uint32_t {temporary} = {renderer.render(write.get('value'))};"
            )
            assignments.append((register, temporary))
        for index, raw in enumerate(
            _array(semantics.get("flag_writes", []), "flag writes")
        ):
            write = _object(raw, "flag write")
            flag = _string(write.get("flag"), "flag write name")
            temporary = f"{prefix}_flag_{index}"
            lines.append(
                f"  uint32_t {temporary} = {renderer.render(write.get('value'))};"
            )
            assignments.append((flag, temporary))
        lines.extend(
            f"  external_replay_state.{name} = {value};"
            for name, value in assignments
        )
    raise ComponentIntentError("component external replay prefix has no call")


def _write_override_package(
    *,
    output: Path,
    entries: list[dict[str, object]],
    machine_ir_sha256: str,
    baseline_program_sha256: str,
) -> Path:
    entries.sort(key=lambda row: (int(row["entry_rva"]), str(row["replacement_id"])))
    header = output / "region-overrides.h"
    source = output / "region-overrides.c"
    prototypes = "\n".join(
        f"spx_step_result {row['symbol']}(spx_runtime *, spx_machine_state *);"
        for row in entries
    )
    header.write_text(
        """#ifndef SPX_REGION_OVERRIDES_H
#define SPX_REGION_OVERRIDES_H
#include <stdint.h>
#include "state-machine-runtime.h"
typedef spx_step_result (*spx_region_override_fn)(spx_runtime *, spx_machine_state *);
typedef struct spx_region_override {
  uint32_t entry_rva;
  spx_region_override_fn function;
  uint32_t fallback_on_unimplemented;
  const char *replacement_id;
  const char *cluster_id;
} spx_region_override;
"""
        + prototypes
        + "\nextern const spx_region_override spx_region_overrides[];\n"
        + "extern const uint32_t spx_region_override_count;\n"
        + "const spx_region_override *spx_region_override_lookup(uint32_t entry_rva);\n"
        + "#endif\n",
        encoding="ascii",
    )
    table = "\n".join(
        "  { UINT32_C(%d), %s, UINT32_C(0), %s, %s },"
        % (
            int(row["entry_rva"]),
            row["symbol"],
            json.dumps(row["replacement_id"]),
            json.dumps(row["cluster_id"]),
        )
        for row in entries
    )
    source.write_text(
        '#include "region-overrides.h"\n'
        "const spx_region_override spx_region_overrides[] = {\n"
        + table
        + "\n};\n"
        + "const uint32_t spx_region_override_count = "
        + "(uint32_t)(sizeof(spx_region_overrides) / sizeof(spx_region_overrides[0]));\n"
        + "const spx_region_override *spx_region_override_lookup(uint32_t entry_rva) {\n"
        + "  uint32_t low = 0U, high = spx_region_override_count;\n"
        + "  while (low < high) { uint32_t middle = low + (high - low) / 2U;\n"
        + "    uint32_t observed = spx_region_overrides[middle].entry_rva;\n"
        + "    if (observed < entry_rva) low = middle + 1U;\n"
        + "    else if (observed > entry_rva) high = middle;\n"
        + "    else return &spx_region_overrides[middle]; }\n"
        + "  return (const spx_region_override *)0;\n}\n",
        encoding="ascii",
    )
    core = {
        "machine_ir_sha256": machine_ir_sha256,
        "baseline_program_sha256": baseline_program_sha256,
        "entries": entries,
    }
    payload = {
        "format": REGION_OVERRIDE_TABLE_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "table_sha256": _canonical_sha256(core),
        **core,
        "artifacts": {
            "header": _artifact(header, output),
            "source": _artifact(source, output),
        },
        "checks": {
            "activation_plan": "verified",
            "component_contracts": "verified",
            "component_qualifications": "verified",
            "source_hashes": "verified",
            "unique_entries": "verified",
            "exclusive_ownership": "verified",
        },
    }
    path = output / "region-overrides-manifest.json"
    write_json(path, payload)
    return path


def _copy_component_sources(
    package: Path,
    source: Mapping[str, object],
    output: Path,
    identity: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    source_root = package / "sources"
    for field in ("files", "shared_inputs"):
        for raw in _array(source.get(field), f"component source {field}"):
            row = _object(raw, "component source file")
            relative = Path(_string(row.get("path"), "component source path"))
            destination_relative = Path("components") / identity / "source" / relative
            destination = output / destination_relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_root / relative, destination)
            rows.append(_artifact(destination, output))
    return rows


def _component_machine_boundary(
    catalog: Mapping[str, object], identity: str
) -> Mapping[str, object]:
    matches = [
        _object(row, "component catalog row")
        for row in _array(catalog.get("components"), "component catalog")
        if isinstance(row, Mapping) and row.get("id") == identity
    ]
    if len(matches) != 1:
        raise ComponentIntentError(f"component catalog does not contain {identity}")
    return _object(matches[0].get("machine_boundary"), "component machine boundary")


def _validate_component_bindings(
    identity: str,
    contract: Mapping[str, object],
    source: Mapping[str, object],
    qualification: Mapping[str, object],
    adapter_plan: Mapping[str, object],
) -> None:
    if (
        contract.get("status") != "checked"
        or qualification.get("status") != "qualified"
        or adapter_plan.get("status") != "checked"
    ):
        raise ComponentIntentError(f"component {identity} is not checked and qualified")
    if (
        source.get("lift_unit_id") != identity
        or qualification.get("lift_unit_id") != identity
        or adapter_plan.get("lift_unit_id") != identity
    ):
        raise ComponentIntentError(f"component {identity} identity binding is stale")
    bindings = _object(qualification.get("bindings"), "component qualification bindings")
    adapter_bindings = _object(
        adapter_plan.get("bindings"), "component adapter-plan bindings"
    )
    if (
        bindings.get("contract_sha256") != contract.get("contract_sha256")
        or bindings.get("implementation_sha256") != source.get("implementation_sha256")
        or bindings.get("source_entry") != source.get("entry")
        or bindings.get("adapter_plan_sha256")
        != adapter_plan.get("adapter_plan_sha256")
        or adapter_bindings.get("contract_sha256") != contract.get("contract_sha256")
        or adapter_bindings.get("implementation_sha256")
        != source.get("implementation_sha256")
        or adapter_bindings.get("source_entry") != source.get("entry")
        or _object(qualification.get("activation"), "qualification activation").get("authorized")
        is not True
    ):
        raise ComponentIntentError(f"component {identity} qualification binding is stale")


def _load_machine_ir(
    path: Path,
) -> tuple[Path, Path, dict[str, Mapping[str, object]]]:
    machine_path = path / "machine-ir.jsonl" if path.is_dir() else path
    manifest_path = path / "machine-ir-manifest.json" if path.is_dir() else path.parent / "machine-ir-manifest.json"
    manifest = _read_object(manifest_path, "machine-IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise ComponentIntentError("unsupported machine-IR manifest format")
    artifact = _object(_object(manifest.get("artifacts"), "machine-IR artifacts").get("machine_ir"), "machine-IR artifact")
    if artifact.get("sha256") != sha256_file(machine_path):
        raise ComponentIntentError("machine-IR artifact binding is stale")
    rows: dict[str, Mapping[str, object]] = {}
    for number, line in enumerate(machine_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = _object(json.loads(line), f"machine IR line {number}")
        identity = _string(row.get("id"), f"machine IR line {number} id")
        if identity in rows:
            raise ComponentIntentError(f"duplicate machine unit {identity}")
        rows[identity] = row
    return machine_path, manifest_path, rows


def _interpreter_binding(path: Path) -> tuple[Path, str]:
    manifest = path / "state-machine-interpreter-package.json" if path.is_dir() else path
    payload = _read_object(manifest, "interpreter package")
    program = _object(payload.get("program"), "interpreter program binding")
    relative = _string(program.get("path"), "interpreter program path")
    program_path = manifest.parent / relative
    digest = sha256_file(program_path)
    if program.get("sha256") != digest:
        raise ComponentIntentError("interpreter baseline program binding is stale")
    return manifest, digest


from .runtime_support import (
    _array,
    _artifact,
    _c_identifier,
    _c_type,
    _canonical_sha256,
    _check_self_hash,
    _member_spans,
    _object,
    _read_object,
    _required_mapping_path,
    _string,
    _unit_rva,
)


__all__ = [
    "build_component_runtime_package",
]
