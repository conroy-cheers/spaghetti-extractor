"""Derive finite acyclic scalar component contracts from canonical machine IR.

This module is deliberately generic.  It accepts a closed, acyclic component
with one 32-bit stack argument, one return, no externally visible effects, and
optionally checked finite internal indirect control.  It symbolically composes
the block summaries and proves that the submitted component covers every
input.  Specialized profiles may additionally bind pointer results to exact PE
bytes.

The solver is an automation aid rather than a proof authority.  The resulting
artifact records all paths, hashes, and solver checks so a stronger checker can
replay the same compact contract later without changing the Stage B interface.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile
import z3

from .artifact_formats import FINITE_COMPONENT_CONTRACT_FORMAT
from .reconstruction_validation import _Z3ExpressionCompiler
from .stage_binary import StageAInputError
from .util import sha256_file


_WORD_MASK = 0xFFFFFFFF
_MAX_PATHS = 4096
_MAX_NONZERO_INPUTS = 1024
_MAX_C_STRING_BYTES = 4096


@dataclass(frozen=True)
class _PathResult:
    guards: tuple[Mapping[str, Any], ...]
    output: Mapping[str, Any]
    unit_ids: tuple[str, ...]
    registers: Mapping[str, Mapping[str, Any]]
    flags: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class _FiniteDerivation:
    paths: tuple[_PathResult, ...]
    compiled_paths: tuple[tuple[Any, Any, _PathResult], ...]
    compiler: _Z3ExpressionCompiler
    input_word: Any
    output: Any
    control_tables: tuple[Mapping[str, Any], ...]


def derive_finite_static_string_contract(
    *,
    component: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    machine_ir_manifest: Mapping[str, Any],
    machine_ir_sha256: str,
    static_image: Path,
) -> dict[str, Any]:
    """Derive a total ``int32_t -> nullable immutable C string`` contract."""

    image_path = Path(static_image)
    binary = _object(machine_ir_manifest.get("binary"), "machine IR binary")
    expected_image_hash = str(binary.get("sha256") or "")
    if not expected_image_hash or sha256_file(image_path) != expected_image_hash:
        raise StageAInputError("finite component static image does not match machine IR")
    if binary.get("bitness") != 32 or binary.get("machine") != "i386":
        raise StageAInputError("finite scalar components currently require an i386 PE32 image")
    image_base = int(binary["image_base"])
    image_size = int(binary["size_of_image"])
    if image_size <= 0 or image_base + image_size > 1 << 32:
        raise StageAInputError("finite component PE32 image address space is invalid")

    derivation = _derive_finite_path_semantics(
        component=component,
        units=units,
        static_image=image_path,
        image_base=image_base,
    )
    paths = derivation.paths
    compiler = derivation.compiler
    compiled_paths = derivation.compiled_paths
    input_word = derivation.input_word
    output = derivation.output
    control_tables = derivation.control_tables
    mapping_solver = z3.Solver()
    mapping_solver.set("random_seed", 0)
    mapping_solver.add(*compiler.constraints, output != _word(0))
    mappings: dict[int, int] = {}
    while True:
        check = mapping_solver.check()
        if check == z3.unsat:
            break
        if check != z3.sat:
            raise StageAInputError("finite component mapping solver returned unknown")
        model = mapping_solver.model()
        input_value = model.eval(input_word, model_completion=True).as_long() & _WORD_MASK
        output_value = model.eval(output, model_completion=True).as_long() & _WORD_MASK
        mappings[input_value] = output_value
        if len(mappings) > _MAX_NONZERO_INPUTS:
            raise StageAInputError("finite component non-zero domain is not suitably finite")
        mapping_solver.add(input_word != _word(input_value))

    pe = pefile.PE(data=image_path.read_bytes(), fast_load=True)
    values: dict[int, dict[str, Any]] = {}
    for guest_value in sorted(set(mappings.values())):
        values[guest_value] = _immutable_c_string(
            pe=pe,
            image_path=image_path,
            guest_value=guest_value,
        )
    cases = [
        {
            "input_bits": input_bits,
            "input_signed": _signed32(input_bits),
            "guest_value": guest_value,
            "value_id": values[guest_value]["id"],
        }
        for input_bits, guest_value in sorted(mappings.items())
    ]
    path_rows = [
        {
            "unit_ids": list(path.unit_ids),
            "guard_sha256": _canonical_sha256(list(path.guards)),
            "output_sha256": _canonical_sha256(path.output),
        }
        for path in paths
    ]
    core = {
        "format": FINITE_COMPONENT_CONTRACT_FORMAT,
        "status": "derived",
        "executes_original_binary": False,
        "component_id": component["id"],
        "bindings": {
            "component_sha256": component["component_sha256"],
            "machine_ir_sha256": machine_ir_sha256,
            "original_binary_sha256": expected_image_hash,
        },
        "profile": "finite_acyclic_static_string_lookup_v1",
        "address_space": {
            "kind": "pe32_image_rva_v1",
            "image_base": image_base,
            "size_of_image": image_size,
        },
        "input": {
            "type": "int32_t",
            "abi": "cdecl_stack_argument_0",
            "domain": "all_32_bit_patterns",
        },
        "result": {
            "type": "nullable_const_char_pointer",
            "default_guest_value": 0,
            "values": [values[address] for address in sorted(values)],
            "cases": cases,
        },
        "control_tables": list(control_tables),
        "symbolic_checks": {
            "engine": "z3_qf_bv",
            "paths_exhaustive": True,
            "overlapping_paths_consistent": True,
            "nonzero_domain_exhausted": True,
            "path_count": len(paths),
            "nonzero_input_count": len(cases),
            "distinct_nonzero_values": len(values),
        },
        "paths": path_rows,
        "trust": {
            "machine_ir_role": "canonical_static_semantics_input",
            "solver_role": "untrusted_derivation_automation",
            "static_image_role": "exact_byte_binding_only",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def derive_finite_scalar_contract(
    *,
    component: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    machine_ir_sha256: str,
) -> dict[str, Any]:
    """Derive a total pure ``uint32_t -> uint32_t`` path contract."""

    derivation = _derive_finite_path_semantics(component=component, units=units)
    initial_registers = _initial_registers()
    initial_flags = _initial_flags()
    modified_registers = sorted(
        name
        for name in initial_registers
        if name != "esp"
        and any(path.registers[name] != initial_registers[name] for path in derivation.paths)
    )
    modified_flags = sorted(
        name
        for name in initial_flags
        if any(path.flags[name] != initial_flags[name] for path in derivation.paths)
    )
    for path in derivation.paths:
        for name in modified_registers:
            derivation.compiler.compile(path.registers[name])
        for name in modified_flags:
            derivation.compiler.compile(path.flags[name])
    unsupported_inputs = sorted(
        set(derivation.compiler.variables) - {"component_input"}
    )
    if unsupported_inputs:
        raise StageAInputError(
            "finite scalar machine outputs depend on non-interface inputs: "
            + ", ".join(unsupported_inputs)
        )
    path_rows = [
        {
            "unit_ids": list(path.unit_ids),
            "guards": copy.deepcopy(list(path.guards)),
            "output": copy.deepcopy(dict(path.output)),
            "machine_outputs": {
                "registers": {
                    name: copy.deepcopy(dict(path.registers[name]))
                    for name in modified_registers
                },
                "flags": {
                    name: copy.deepcopy(dict(path.flags[name]))
                    for name in modified_flags
                },
            },
            "path_sha256": _canonical_sha256(
                {
                    "guards": list(path.guards),
                    "output": path.output,
                    "registers": {
                        name: path.registers[name] for name in modified_registers
                    },
                    "flags": {name: path.flags[name] for name in modified_flags},
                }
            ),
        }
        for path in derivation.paths
    ]
    core = {
        "format": FINITE_COMPONENT_CONTRACT_FORMAT,
        "status": "derived",
        "executes_original_binary": False,
        "component_id": component["id"],
        "bindings": {
            "component_sha256": component["component_sha256"],
            "machine_ir_sha256": machine_ir_sha256,
        },
        "profile": "finite_acyclic_scalar_v1",
        "input": {
            "type": "uint32_t",
            "abi": "cdecl_stack_argument_0",
            "domain": "all_32_bit_patterns",
        },
        "result": {"type": "uint32_t", "machine_result": "eax"},
        "machine_projection": {
            "registers_written": modified_registers,
            "flags_written": modified_flags,
            "stack_effect": "cdecl_return",
        },
        "control_tables": list(derivation.control_tables),
        "symbolic_checks": {
            "engine": "z3_qf_bv",
            "paths_exhaustive": True,
            "overlapping_paths_consistent": True,
            "path_count": len(derivation.paths),
        },
        "paths": path_rows,
        "trust": {
            "machine_ir_role": "canonical_static_semantics_input",
            "solver_role": "untrusted_derivation_automation",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _derive_finite_path_semantics(
    *,
    component: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    static_image: Path | None = None,
    image_base: int | None = None,
) -> _FiniteDerivation:
    member_ids = [str(value) for value in component["membership"]["resolved_unit_ids"]]
    by_id = {str(unit.get("id")): unit for unit in units}
    if set(by_id) != set(member_ids) or len(by_id) != len(units):
        raise StageAInputError("finite component units do not match exact membership")
    by_rva = {_unit_rva(unit): unit for unit in units}
    if len(by_rva) != len(units):
        raise StageAInputError("finite component unit entry RVAs are not unique")

    boundary = _object(component.get("machine_boundary"), "component boundary")
    _validate_boundary(boundary)
    entries = [
        row
        for row in _array(boundary.get("entries"), "component entries")
        if row.get("kind") != "internal_call"
    ]
    entry_id = str(entries[0]["unit_id"])
    indirect = {
        str(row["source_unit_id"]): row
        for row in _array(
            boundary.get("internal_indirect_controls", []),
            "internal indirect controls",
        )
    }
    if indirect and (static_image is None or image_base is None):
        raise StageAInputError(
            "finite scalar indirect control requires an exact static PE image"
        )
    control_tables = (
        _validate_indirect_tables(indirect, Path(static_image), int(image_base))
        if indirect
        else []
    )
    initial_registers = _initial_registers()
    initial_flags = _initial_flags()
    paths: list[_PathResult] = []

    def visit(
        unit_id: str,
        registers: Mapping[str, Mapping[str, Any]],
        flags: Mapping[str, Mapping[str, Any]],
        guards: tuple[Mapping[str, Any], ...],
        visited: tuple[str, ...],
    ) -> None:
        if len(paths) >= _MAX_PATHS:
            raise StageAInputError("finite component exceeds the symbolic path budget")
        if unit_id in visited:
            raise StageAInputError("finite component contains a cycle")
        unit = by_id.get(unit_id)
        if unit is None:
            raise StageAInputError(f"finite component reaches an external unit: {unit_id}")
        semantics = _object(unit.get("semantics"), f"semantics for {unit_id}")
        next_registers = dict(registers)
        next_flags = dict(flags)
        for write in _array(semantics.get("register_writes"), "register writes"):
            register = str(write.get("register") or "").lower()
            if register not in next_registers:
                raise StageAInputError(
                    f"finite component writes unsupported register {register}"
                )
            next_registers[register] = _substitute(
                write.get("value"), registers=registers, flags=flags
            )
        for write in _array(semantics.get("flag_writes"), "flag writes"):
            flag = str(write.get("flag") or "").lower()
            if flag not in next_flags:
                raise StageAInputError(f"finite component writes unsupported flag {flag}")
            next_flags[flag] = _substitute(
                write.get("value"), registers=registers, flags=flags
            )

        outcome = _object(semantics.get("outcome"), f"outcome for {unit_id}")
        kind = str(outcome.get("kind") or "")
        next_visited = (*visited, unit_id)
        if kind == "return":
            paths.append(
                _PathResult(
                    guards=guards,
                    output=next_registers["eax"],
                    unit_ids=next_visited,
                    registers=copy.deepcopy(next_registers),
                    flags=copy.deepcopy(next_flags),
                )
            )
            return
        if kind in {"jump", "fallthrough"}:
            target = outcome.get("target_rva")
            if not isinstance(target, int):
                raise StageAInputError(f"finite component {kind} has no direct target")
            visit(
                _target_unit_id(by_rva, target),
                next_registers,
                next_flags,
                guards,
                next_visited,
            )
            return
        if kind == "branch":
            edges = _array(semantics.get("edge_conditions"), "branch edges")
            if len(edges) != 2:
                raise StageAInputError(
                    "finite component branch must have two explicit edges"
                )
            for edge in edges:
                target = edge.get("target_rva")
                condition = edge.get("condition")
                if not isinstance(target, int) or not isinstance(condition, Mapping):
                    raise StageAInputError("finite component branch edge is malformed")
                visit(
                    _target_unit_id(by_rva, target),
                    next_registers,
                    next_flags,
                    (*guards, _substitute(condition, registers=registers, flags=flags)),
                    next_visited,
                )
            return
        if kind == "indirect_jump":
            certificate = indirect.get(unit_id)
            if certificate is None:
                raise StageAInputError(
                    "finite component indirect jump has no checked certificate"
                )
            inventory = _object(certificate.get("target_inventory"), "target inventory")
            index = _object(inventory.get("index"), "indirect index")
            index_expression = _substitute(
                index.get("expression"), registers=next_registers, flags=next_flags
            )
            rows = _array(inventory.get("entries"), "indirect table entries")
            for row in rows:
                table_index = row.get("index")
                target = row.get("target_rva")
                if not isinstance(table_index, int) or not isinstance(target, int):
                    raise StageAInputError(
                        "finite component indirect table entry is malformed"
                    )
                visit(
                    _target_unit_id(by_rva, target),
                    next_registers,
                    next_flags,
                    (
                        *guards,
                        {
                            "op": "eq",
                            "args": [
                                index_expression,
                                {"op": "const", "value": table_index, "width": 32},
                            ],
                        },
                    ),
                    next_visited,
                )
            return
        raise StageAInputError(f"finite component has unsupported outcome {kind!r}")

    visit(entry_id, initial_registers, initial_flags, (), ())
    if not paths:
        raise StageAInputError("finite component has no return paths")
    compiler = _Z3ExpressionCompiler({"component_input": 32})
    compiled_paths: list[tuple[Any, Any, _PathResult]] = []
    for path in paths:
        guard_terms = [compiler.compile(guard) != _word(0) for guard in path.guards]
        guard = z3.And(*guard_terms) if guard_terms else z3.BoolVal(True)
        compiled_paths.append((guard, compiler.compile(path.output), path))
    unsupported_inputs = sorted(set(compiler.variables) - {"component_input"})
    if unsupported_inputs:
        raise StageAInputError(
            "finite component result depends on non-interface inputs: "
            + ", ".join(unsupported_inputs)
        )
    input_word = compiler.variables.get("component_input")
    if input_word is None:
        raise StageAInputError("finite component does not consume its scalar argument")

    coverage_solver = z3.Solver()
    coverage_solver.set("random_seed", 0)
    coverage_solver.add(*compiler.constraints)
    coverage_solver.add(
        z3.Not(z3.Or(*(guard for guard, _output, _path in compiled_paths)))
    )
    if coverage_solver.check() != z3.unsat:
        raise StageAInputError("finite component symbolic paths do not cover every input")
    overlap_solver = z3.Solver()
    overlap_solver.set("random_seed", 0)
    overlap_solver.add(*compiler.constraints)
    for index, (left_guard, left_output, _left_path) in enumerate(compiled_paths):
        for right_guard, right_output, _right_path in compiled_paths[index + 1 :]:
            overlap_solver.push()
            overlap_solver.add(left_guard, right_guard, left_output != right_output)
            inconsistent = overlap_solver.check() == z3.sat
            overlap_solver.pop()
            if inconsistent:
                raise StageAInputError(
                    "finite component paths assign inconsistent outputs"
                )
    output = _word(0)
    for guard, value, _path in reversed(compiled_paths):
        output = z3.If(guard, value, output)
    return _FiniteDerivation(
        paths=tuple(paths),
        compiled_paths=tuple(compiled_paths),
        compiler=compiler,
        input_word=input_word,
        output=output,
        control_tables=tuple(control_tables),
    )


def _initial_registers() -> dict[str, dict[str, Any]]:
    return {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")
    }


def _initial_flags() -> dict[str, dict[str, Any]]:
    return {
        name: {"op": "flag", "name": name}
        for name in ("cf", "df", "of", "pf", "sf", "zf")
    }


def _validate_boundary(boundary: Mapping[str, Any]) -> None:
    counts = _object(boundary.get("counts"), "component boundary counts")
    if (
        counts.get("entries") != 1
        or counts.get("exits") != 1
        or counts.get("external_events") != 0
        or counts.get("faults") != 0
        or counts.get("memory_writes", 0) != 0
    ):
        raise StageAInputError(
            "finite scalar profile requires one entry/return and no external effects"
        )
    exits = _array(boundary.get("exits"), "component exits")
    if exits[0].get("kind") != "return":
        raise StageAInputError("finite scalar profile requires one return exit")
    if boundary.get("call_closure", {}).get("status") != "complete":
        raise StageAInputError("finite scalar profile requires complete call closure")
    memory_events = _array(
        boundary.get("effects", {}).get("memory_events", []),
        "component memory events",
    )
    if any(
        not isinstance(row.get("event"), Mapping)
        or row["event"].get("kind") != "read"
        for row in memory_events
    ):
        raise StageAInputError("finite scalar profile does not permit guest memory writes")


def _validate_indirect_tables(
    indirect: Mapping[str, Mapping[str, Any]], image_path: Path, image_base: int
) -> list[dict[str, Any]]:
    pe = pefile.PE(data=image_path.read_bytes(), fast_load=True)
    checked: list[dict[str, Any]] = []
    for row in indirect.values():
        inventory = _object(row.get("target_inventory"), "target inventory")
        if inventory.get("status") != "recovered" or inventory.get("closure") != "checked_finite_target_inventory":
            raise StageAInputError("finite component indirect target inventory is not checked")
        table = _object(inventory.get("table"), "indirect target table")
        count = int(table.get("entry_count", -1))
        width = int(table.get("entry_width", -1))
        address = table.get("address")
        if not isinstance(address, int) or count <= 0 or width != 4:
            raise StageAInputError("finite component indirect target table is malformed")
        raw = pe.get_data(address - image_base, count * width)
        if len(raw) != count * width or sha256(raw).hexdigest() != table.get("bytes_sha256"):
            raise StageAInputError("finite component indirect table bytes do not match the PE")
        entries = _array(inventory.get("entries"), "indirect entries")
        if len(entries) != count:
            raise StageAInputError("finite component indirect inventory is incomplete")
        for entry in entries:
            index = int(entry["index"])
            observed = int.from_bytes(raw[index * 4 : index * 4 + 4], "little")
            if observed != entry.get("target_address"):
                raise StageAInputError("finite component indirect target disagrees with PE bytes")
        checked.append(
            {
                "source_unit_id": row["source_unit_id"],
                "guest_address": address,
                "rva": address - image_base,
                "entry_count": count,
                "entry_width": width,
                "bytes_hex": raw.hex(),
                "bytes_sha256": sha256(raw).hexdigest(),
            }
        )
    return checked


def _substitute(
    value: Any,
    *,
    registers: Mapping[str, Mapping[str, Any]],
    flags: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"finite component expression is malformed: {value!r}")
    op = value.get("op")
    if op == "reg":
        name = str(value.get("name") or "").lower()
        if name not in registers:
            raise StageAInputError(f"finite component references unsupported register {name}")
        return copy.deepcopy(dict(registers[name]))
    if op == "flag":
        name = str(value.get("name") or "").lower()
        if name not in flags:
            raise StageAInputError(f"finite component references unsupported flag {name}")
        return copy.deepcopy(dict(flags[name]))
    if op == "load":
        if value.get("width") != 4:
            raise StageAInputError("finite scalar profile only supports 32-bit stack loads")
        address = _substitute(
            value.get("address"), registers=registers, flags=flags
        )
        if _register_offset(address, "esp") == 4:
            return {"op": "reg", "name": "component_input", "width": 32}
        raise StageAInputError("finite scalar result depends on unsupported memory")
    result: dict[str, Any] = {}
    for key, child in value.items():
        if key == "args" and isinstance(child, list):
            result[key] = [
                _substitute(item, registers=registers, flags=flags)
                if isinstance(item, Mapping)
                else copy.deepcopy(item)
                for item in child
            ]
        elif isinstance(child, Mapping):
            result[key] = _substitute(child, registers=registers, flags=flags)
        else:
            result[key] = copy.deepcopy(child)
    return result


def _register_offset(value: Mapping[str, Any], register: str) -> int | None:
    if value.get("op") == "reg" and value.get("name") == register:
        return 0
    args = value.get("args")
    if value.get("op") == "add32" and isinstance(args, list) and len(args) == 2:
        for base, constant in ((args[0], args[1]), (args[1], args[0])):
            if (
                isinstance(base, Mapping)
                and isinstance(constant, Mapping)
                and constant.get("op") == "const"
                and isinstance(constant.get("value"), int)
            ):
                offset = _register_offset(base, register)
                if offset is not None:
                    return (offset + int(constant["value"])) & _WORD_MASK
    return None


def _immutable_c_string(
    *, pe: pefile.PE, image_path: Path, guest_value: int
) -> dict[str, Any]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    if not image_base <= guest_value < image_base + int(pe.OPTIONAL_HEADER.SizeOfImage):
        raise StageAInputError(f"finite component result 0x{guest_value:08x} is not in the PE")
    rva = guest_value - image_base
    section = next(
        (
            row
            for row in pe.sections
            if int(row.VirtualAddress)
            <= rva
            < int(row.VirtualAddress) + max(int(row.Misc_VirtualSize), int(row.SizeOfRawData))
        ),
        None,
    )
    if section is None:
        raise StageAInputError("finite component string result is outside PE sections")
    characteristics = int(section.Characteristics)
    if not characteristics & 0x40000000 or characteristics & (0x80000000 | 0x20000000):
        raise StageAInputError("finite component string result is not immutable readable data")
    available = min(
        _MAX_C_STRING_BYTES,
        int(section.VirtualAddress) + int(section.SizeOfRawData) - rva,
    )
    raw = pe.get_data(rva, available)
    terminator = raw.find(b"\x00")
    if terminator < 0:
        raise StageAInputError("finite component string result is not NUL terminated")
    data = raw[: terminator + 1]
    try:
        text = data[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise StageAInputError("finite component string result is not portable ASCII") from error
    section_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
    return {
        "id": f"static-string-{guest_value:08x}",
        "guest_value": guest_value,
        "rva": rva,
        "section": section_name,
        "text": text,
        "bytes_hex": data.hex(),
        "bytes_sha256": sha256(data).hexdigest(),
        "length_with_nul": len(data),
        "source_image_sha256": sha256_file(image_path),
    }


def _target_unit_id(by_rva: Mapping[int, Mapping[str, Any]], rva: int) -> str:
    unit = by_rva.get(rva)
    if unit is None:
        raise StageAInputError(f"finite component target 0x{rva:08x} is outside membership")
    return str(unit["id"])


def _unit_rva(unit: Mapping[str, Any]) -> int:
    source = _object(unit.get("source"), "machine unit source")
    original = _object(source.get("original"), "machine unit original span")
    value = original.get("rva_start")
    if not isinstance(value, int):
        raise StageAInputError("machine unit has no entry RVA")
    return value


def _signed32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def _word(value: int) -> Any:
    return z3.BitVecVal(value & _WORD_MASK, 32)


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, Mapping) for row in value):
        raise StageAInputError(f"{label} must be an array of objects")
    return list(value)


def _canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
