"""Generate the executable component runtime package from checked v3 inputs."""

from __future__ import annotations

import copy
import json
import re
import shutil
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifact_formats import MACHINE_IR_FORMAT
from ..region_replacement import REGION_OVERRIDE_TABLE_FORMAT
from ..util import sha256_file, write_json
from .formats import (
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
    COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
    COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
)
from .intent import ComponentIntentError
from .source import load_component_source_package_v2


PORTABLE_COMPONENT_SELECTION_V2_FORMAT = (
    "spaghetti-extractor-portable-component-selection-v2"
)


def build_component_runtime_package_v3(
    *,
    machine_ir: Path | str,
    activation_plan: Path | str,
    contracts: Mapping[str, Path | str],
    implementations: Mapping[str, Path | str],
    qualifications: Mapping[str, Path | str],
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
    machine_path, machine_manifest_path, machine_rows = _load_machine_ir(Path(machine_ir))
    interpreter_manifest, baseline_program_sha256 = _interpreter_binding(
        Path(interpreter_package)
    )
    portable_selections = [
        _object(row, "component selection")
        for row in _array(activation.get("selections"), "component selections")
        if isinstance(row, Mapping)
        and row.get("effective_implementation") == "portable_replacement"
    ]
    component_rows: list[dict[str, object]] = []
    selection_rows: list[dict[str, object]] = []
    override_entries: list[dict[str, object]] = []

    for selection in portable_selections:
        identity = _string(selection.get("id"), "portable component id")
        contract_root = _required_mapping_path(contracts, identity, "contract")
        implementation_root = _required_mapping_path(
            implementations, identity, "source package"
        )
        qualification_path = _required_mapping_path(
            qualifications, identity, "qualification"
        )
        contract = _read_object(contract_root / "contract.json", "component contract")
        _check_self_hash(
            contract,
            COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
            "contract_sha256",
            "component contract",
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
        source = load_component_source_package_v2(implementation_root)
        _validate_component_bindings(identity, contract, source, qualification)
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
        adapter_relative = Path("components") / identity / "generated-adapter.c"
        adapter_path = output / adapter_relative
        adapter_symbols: list[tuple[int, str, str]] = []
        adapter_text = _render_component_adapter(
            identity=identity,
            interface=interface,
            source=source,
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

    selection_core = {
        "format": PORTABLE_COMPONENT_SELECTION_V2_FORMAT,
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
            "enabled_components_must_be_qualified": True,
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
    result_register = _result_register(result, members)
    entry = _object(source.get("entry"), "component source entry")
    function_symbol = _string(entry.get("symbol"), "logical source symbol")
    prototype = "{result} {symbol}({parameters});".format(
        result=_c_type(result.get("type")),
        symbol=function_symbol,
        parameters=", ".join(
            f"{_c_type(row.get('type'))} {_c_identifier(str(row.get('id')))}"
            for row in parameters
        )
        or "void",
    )
    functions: list[str] = []
    for entry_id in entry_ids:
        if entry_id not in members:
            raise ComponentIntentError(f"component {identity} entry is not a member")
        path = _straight_line_path(members, entry_id)
        symbol = "stage_b_component_{identity}_{rva:08x}".format(
            identity=_c_identifier(identity), rva=_unit_rva(members[entry_id])
        )
        symbols.append((_unit_rva(members[entry_id]), entry_id, symbol))
        functions.append(
            _render_entry_adapter(
                symbol=symbol,
                logical_symbol=function_symbol,
                parameters=parameters,
                result=result,
                result_register=result_register,
                path=path,
            )
        )
    return "\n".join(
        [
            '#include "state-machine-runtime.h"',
            "#include <stdint.h>",
            "",
            prototype,
            "",
            "static uint32_t component_read(stage_b_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {",
            "  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }",
            "  return rt->read(rt->context, address, width, fault);",
            "}",
            "static uint32_t component_parity(uint32_t value) {",
            "  value &= 0xffU; value ^= value >> 4U; value &= 0xfU;",
            "  return (0x9669U >> value) & 1U;",
            "}",
            "static uint32_t component_sub_overflow(uint32_t left, uint32_t right, uint32_t result) {",
            "  return (((left ^ right) & (left ^ result)) >> 31U) & 1U;",
            "}",
            "",
            *functions,
            "",
        ]
    )


def _render_entry_adapter(
    *,
    symbol: str,
    logical_symbol: str,
    parameters: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
    result_register: str,
    path: Sequence[Mapping[str, object]],
) -> str:
    lines = [
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
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
            f"  {_c_type(parameter.get('type'))} {name} = "
            f"({_c_type(parameter.get('type'))})({renderer.render(expression)});"
        )
        argument_names.append(name)
    lines.append("  if (memory_fault != 0U) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };")
    lines.append(
        f"  {_c_type(result.get('type'))} logical_result = {logical_symbol}({', '.join(argument_names)});"
    )

    terminal_kind: str | None = None
    terminal_value = "0U"
    for block_index, unit in enumerate(path):
        semantics = _object(unit.get("semantics"), "machine semantics")
        if _array(semantics.get("external_events", []), "external events"):
            raise ComponentIntentError("logical-c-v1 adapter does not support external events")
        if _array(semantics.get("faults", []), "fault inventory"):
            raise ComponentIntentError("logical-c-v1 adapter does not support faulting paths")
        for event in _array(semantics.get("memory_events", []), "memory events"):
            if _object(event, "memory event").get("kind") != "read":
                raise ComponentIntentError("logical-c-v1 adapter does not support memory writes")
        prefix = f"block_{block_index}"
        lines.extend(f"  uint32_t {prefix}_{name} = state->{name};" for name in _STATE_FIELDS)
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
            terminal_kind = "STAGE_B_RETURN"
            terminal_value = f"{prefix}_return_value"
            lines.append(
                f"  uint32_t {terminal_value} = {block_renderer.render(outcome.get('value'))};"
            )
        elif kind not in {"fallthrough", "jump"}:
            raise ComponentIntentError(
                f"logical-c-v1 adapter does not support {kind} paths yet"
            )
        lines.append("  if (memory_fault != 0U) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };")
        lines.extend(f"  state->{name} = {value};" for name, value in assignments)
    if terminal_kind is None:
        raise ComponentIntentError("logical-c-v1 adapter path has no terminal outcome")
    lines.append(f"  state->{result_register} = (uint32_t)logical_result;")
    lines.append(
        f"  return (stage_b_step_result){{ {terminal_kind}, 0U, {terminal_value} }};"
    )
    lines.append("}")
    return "\n".join(lines)


class _CExpression:
    def __init__(self, names: Mapping[str, str], *, memory_fault: str) -> None:
        self.names = names
        self.memory_fault = memory_fault

    def render(self, value: object) -> str:
        expression = _object(value, "machine expression")
        op = expression.get("op")
        if op == "const":
            return f"UINT32_C({int(expression.get('value', 0)) & 0xFFFFFFFF})"
        if op in {"reg", "flag"}:
            name = _string(expression.get("name"), "machine state name")
            if name not in self.names:
                raise ComponentIntentError(f"adapter expression uses unsupported state {name}")
            return self.names[name]
        if op == "false":
            return "0U"
        if op == "true":
            return "1U"
        if op == "load":
            return "component_read(rt, {address}, {width}U, &{fault})".format(
                address=self.render(expression.get("address")),
                width=int(expression.get("width", 4)),
                fault=self.memory_fault,
            )
        raw_args = _array(expression.get("args", []), f"{op} arguments")
        args = [self.render(arg) if isinstance(arg, Mapping) else str(int(arg)) for arg in raw_args]
        if op == "add32":
            return "(" + " + ".join(args) + ")"
        if op == "sub32":
            return f"({args[0]} - {args[1]})"
        if op == "and32":
            return f"({args[0]} & {args[1]})"
        if op == "or32":
            return f"({args[0]} | {args[1]})"
        if op == "xor32":
            return f"({args[0]} ^ {args[1]})"
        if op == "eq":
            return f"(({args[0]}) == ({args[1]}))"
        if op == "ult32":
            return f"((uint32_t)({args[0]}) < (uint32_t)({args[1]}))"
        if op == "ite":
            return f"(({args[0]}) ? ({args[1]}) : ({args[2]}))"
        if op == "msb":
            return f"((({args[-1]}) >> ({args[0]} - 1U)) & 1U)"
        if op == "parity":
            return f"component_parity({args[-1]})"
        if op == "sub_overflow":
            return f"component_sub_overflow({args[1]}, {args[2]}, {args[3]})"
        raise ComponentIntentError(f"adapter expression operation is unsupported: {op}")


def _straight_line_path(
    members: Mapping[str, Mapping[str, object]], entry_id: str
) -> list[Mapping[str, object]]:
    by_rva = {_unit_rva(row): row for row in members.values()}
    path: list[Mapping[str, object]] = []
    seen: set[str] = set()
    current = members[entry_id]
    while True:
        identity = _string(current.get("id"), "machine unit id")
        if identity in seen:
            raise ComponentIntentError("logical-c-v1 adapter path contains a cycle")
        seen.add(identity)
        path.append(current)
        outcome = _object(
            _object(current.get("semantics"), "machine semantics").get("outcome"),
            "machine outcome",
        )
        kind = outcome.get("kind")
        if kind == "return":
            return path
        if kind not in {"fallthrough", "jump"}:
            raise ComponentIntentError(
                f"logical-c-v1 adapter requires a straight-line path, observed {kind}"
            )
        target = outcome.get("target_rva")
        if not isinstance(target, int) or target not in by_rva:
            raise ComponentIntentError("component path exits before a supported terminal")
        current = by_rva[target]


def _result_register(
    result: Mapping[str, object], members: Mapping[str, Mapping[str, object]]
) -> str:
    refs = _array(result.get("effect_refs", []), "logical result effect references")
    if len(refs) != 1:
        raise ComponentIntentError("logical result must own one register-write effect")
    ref = _object(refs[0], "logical result effect reference")
    if ref.get("family") != "register_write":
        raise ComponentIntentError("logical result effect is not a register write")
    unit = members.get(_string(ref.get("unit_id"), "logical result effect unit"))
    index = ref.get("index")
    if unit is None or not isinstance(index, int):
        raise ComponentIntentError("logical result effect reference is stale")
    writes = _array(
        _object(unit.get("semantics"), "machine semantics").get("register_writes", []),
        "register writes",
    )
    if index < 0 or index >= len(writes):
        raise ComponentIntentError("logical result effect index is stale")
    return _string(_object(writes[index], "register write").get("register"), "result register")


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
        f"stage_b_step_result {row['symbol']}(stage_b_runtime *, stage_b_machine_state *);"
        for row in entries
    )
    header.write_text(
        """#ifndef STAGE_B_REGION_OVERRIDES_H
#define STAGE_B_REGION_OVERRIDES_H
#include <stdint.h>
#include "state-machine-runtime.h"
typedef stage_b_step_result (*stage_b_region_override_fn)(stage_b_runtime *, stage_b_machine_state *);
typedef struct stage_b_region_override {
  uint32_t entry_rva;
  stage_b_region_override_fn function;
  uint32_t fallback_on_unimplemented;
  const char *replacement_id;
  const char *cluster_id;
} stage_b_region_override;
"""
        + prototypes
        + "\nextern const stage_b_region_override stage_b_region_overrides[];\n"
        + "extern const uint32_t stage_b_region_override_count;\n"
        + "const stage_b_region_override *stage_b_region_override_lookup(uint32_t entry_rva);\n"
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
        "const stage_b_region_override stage_b_region_overrides[] = {\n"
        + table
        + "\n};\n"
        + "const uint32_t stage_b_region_override_count = "
        + "(uint32_t)(sizeof(stage_b_region_overrides) / sizeof(stage_b_region_overrides[0]));\n"
        + "const stage_b_region_override *stage_b_region_override_lookup(uint32_t entry_rva) {\n"
        + "  uint32_t low = 0U, high = stage_b_region_override_count;\n"
        + "  while (low < high) { uint32_t middle = low + (high - low) / 2U;\n"
        + "    uint32_t observed = stage_b_region_overrides[middle].entry_rva;\n"
        + "    if (observed < entry_rva) low = middle + 1U;\n"
        + "    else if (observed > entry_rva) high = middle;\n"
        + "    else return &stage_b_region_overrides[middle]; }\n"
        + "  return (const stage_b_region_override *)0;\n}\n",
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
) -> None:
    if contract.get("status") != "checked" or qualification.get("status") != "qualified":
        raise ComponentIntentError(f"component {identity} is not checked and qualified")
    if source.get("lift_unit_id") != identity or qualification.get("lift_unit_id") != identity:
        raise ComponentIntentError(f"component {identity} identity binding is stale")
    bindings = _object(qualification.get("bindings"), "component qualification bindings")
    if (
        bindings.get("contract_sha256") != contract.get("contract_sha256")
        or bindings.get("implementation_sha256") != source.get("implementation_sha256")
        or bindings.get("source_entry") != source.get("entry")
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


def _member_spans(members: Mapping[str, Mapping[str, object]]) -> list[dict[str, int]]:
    return [
        {
            "start": int(_object(_object(row.get("source"), "unit source").get("original"), "unit original")["rva_start"]),
            "end": int(_object(_object(row.get("source"), "unit source").get("original"), "unit original")["rva_end"]),
        }
        for row in sorted(members.values(), key=_unit_rva)
    ]


def _artifact(path: Path, root: Path, *, symbol: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
    }
    if symbol is not None:
        row["symbol"] = symbol
    return row


def _required_mapping_path(
    values: Mapping[str, Path | str], identity: str, description: str
) -> Path:
    value = values.get(identity)
    if value is None:
        raise ComponentIntentError(f"component {identity} has no {description}")
    return Path(value)


def _unit_rva(row: Mapping[str, object]) -> int:
    return int(_object(_object(row.get("source"), "unit source").get("original"), "unit original")["rva_start"])


def _json_pointer(value: object, pointer: str) -> object:
    current = value
    if not pointer.startswith("/"):
        raise ComponentIntentError("machine evidence pointer is malformed")
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise ComponentIntentError("machine evidence pointer traverses a scalar")
    return current


_STATE_FIELDS = (
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "cf",
    "zf",
    "sf",
    "of",
    "pf",
    "df",
)
_C_TYPES = frozenset(
    {"uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t"}
)


def _c_type(value: object) -> str:
    result = _string(value, "logical C type")
    if result not in _C_TYPES:
        raise ComponentIntentError(f"unsupported logical C type: {result}")
    return result


def _c_identifier(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not result or result[0].isdigit():
        result = "component_" + result
    return result


def _check_self_hash(
    payload: Mapping[str, object], format_name: str, field: str, description: str
) -> None:
    if payload.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    core = copy.deepcopy(dict(payload))
    expected = core.pop(field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")


def _read_object(path: Path, description: str) -> dict[str, object]:
    try:
        return dict(_object(json.loads(path.read_text(encoding="utf-8")), description))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc


def _object(value: object, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return sha256(encoded).hexdigest()


__all__ = [
    "PORTABLE_COMPONENT_SELECTION_V2_FORMAT",
    "build_component_runtime_package_v3",
]
