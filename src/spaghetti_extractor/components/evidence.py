"""Candidate-only evidence producers for portable component implementations."""

from __future__ import annotations

import copy
import ctypes
import itertools
import json
import subprocess
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..util import sha256_file, write_json
from .formats import (
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_EVIDENCE_V3_FORMAT,
)
from .intent import ComponentIntentError
from .source import load_component_source_package_v2


_TOOL_ID = "spaghetti-extractor-component-exhaustive-evaluator"
_TOOL_VERSION = 1
_CTYPE_BY_NAME = {
    "uint8_t": ctypes.c_uint8,
    "uint16_t": ctypes.c_uint16,
    "uint32_t": ctypes.c_uint32,
    "uint64_t": ctypes.c_uint64,
    "int8_t": ctypes.c_int8,
    "int16_t": ctypes.c_int16,
    "int32_t": ctypes.c_int32,
    "int64_t": ctypes.c_int64,
}


class _UnsupportedSemantics(ValueError):
    pass


def produce_component_evidence_v3(
    *,
    contract: Path | str,
    implementation: Path | str,
    machine_ir: Path | str,
    verification: Mapping[str, object],
    compiler: Path | str,
    out: Path | str,
) -> dict[str, object]:
    """Compile portable C and compare it exhaustively with exact machine IR.

    The original binary is never executed. Unsupported source ABIs, semantics,
    or domains are reported as ``incomplete``; a concrete mismatch is
    ``violated`` and carries the first source-level counterexample.
    """

    contract_dir = Path(contract)
    contract_payload = _read_object(contract_dir / "contract.json", "component contract")
    _check_self_hash(
        contract_payload,
        COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
        "contract_sha256",
        "component contract",
    )
    source = load_component_source_package_v2(implementation)
    lift_unit = _object(contract_payload.get("lift_unit"), "contract lift unit")
    lift_unit_id = _string(lift_unit.get("id"), "contract lift-unit id")
    interface = _read_object(
        contract_dir / "reviewed-interface.json", "reviewed logical interface"
    )
    verification_payload = copy.deepcopy(dict(verification))
    domain_sha256 = _canonical_sha256(verification_payload)
    issues: list[dict[str, object]] = []
    cases = 0
    counterexamples: list[dict[str, object]] = []

    if contract_payload.get("status") != "checked":
        issues.append(_issue("incomplete", "component_contract_not_checked"))
    if source.get("lift_unit_id") != lift_unit_id:
        issues.append(_issue("violated", "component_source_identity_mismatch"))
    producer = verification_payload.get("producer")
    if producer != "exhaustive-finite-domain-v1":
        issues.append(
            _issue(
                "incomplete",
                "component_evidence_producer_not_implemented",
                observed=producer,
            )
        )

    try:
        parameters, result = _logical_signature(interface)
        domains = _parameter_domains(verification_payload, parameters)
        case_count = 1
        for domain in domains:
            case_count *= len(domain)
        if case_count > 1_000_000:
            raise _UnsupportedSemantics(
                f"declared finite domain contains {case_count} cases"
            )
        if issues:
            raise _UnsupportedSemantics("prerequisite contract or producer is not usable")
        library_path = Path(out).with_suffix(".component.so")
        _compile_source_package(
            package=Path(implementation),
            source=source,
            compiler=Path(compiler),
            output=library_path,
        )
        function = _load_logical_function(library_path, source, parameters, result)
        machine = _MachineProgram(Path(machine_ir), tuple(lift_unit["unit_ids"]))
        for values in itertools.product(*domains):
            arguments = dict(zip((row["id"] for row in parameters), values, strict=True))
            expected = machine.evaluate(interface, arguments)
            observed = int(function(*values))
            width = _ctype_width(_string(result.get("type"), "logical result type"))
            mask = (1 << width) - 1
            observed &= mask
            expected &= mask
            cases += 1
            if observed != expected:
                counterexamples.append(
                    {
                        "case_index": cases - 1,
                        "arguments": arguments,
                        "expected": expected,
                        "observed": observed,
                    }
                )
                break
    except _UnsupportedSemantics as exc:
        if not issues:
            issues.append(
                _issue(
                    "incomplete",
                    "component_evidence_semantics_unsupported",
                    detail=str(exc),
                )
            )
    except (OSError, subprocess.SubprocessError) as exc:
        issues.append(
            _issue(
                "incomplete",
                "component_source_compilation_failed",
                detail=str(exc),
            )
        )

    if counterexamples:
        issues.append(
            _issue(
                "violated",
                "component_behavior_counterexample",
                counterexample=counterexamples[0],
            )
        )
    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "satisfied"
    )
    core: dict[str, object] = {
        "format": COMPONENT_EVIDENCE_V3_FORMAT,
        "status": status,
        "lift_unit_id": lift_unit_id,
        "evidence_profile": lift_unit.get("evidence_profile"),
        "executes_original_binary": False,
        "bindings": {
            "contract_sha256": contract_payload["contract_sha256"],
            "implementation_sha256": source["implementation_sha256"],
            "machine_ir_sha256": sha256_file(_machine_ir_path(Path(machine_ir))),
            "domain_sha256": domain_sha256,
            "tool_id": _TOOL_ID,
            "tool_version": _TOOL_VERSION,
        },
        "method": {
            "kind": "exhaustive_finite_domain_v1",
            "complete_for_declared_domain": status != "incomplete",
            "candidate_only": True,
        },
        "coverage": {
            "cases": cases,
            "counterexamples": len(counterexamples),
            "first_counterexample": counterexamples[0] if counterexamples else None,
        },
        "issues": sorted(
            issues, key=lambda row: (str(row["status"]), str(row["code"]))
        ),
    }
    result_payload = {**core, "evidence_sha256": _canonical_sha256(core)}
    write_json(Path(out), result_payload)
    return result_payload


def _compile_source_package(
    *, package: Path, source: Mapping[str, object], compiler: Path, output: Path
) -> None:
    source_root = package / "sources"
    translation_units = [
        source_root / str(row["path"])
        for row in source["files"]  # type: ignore[index]
        if isinstance(row, Mapping) and str(row.get("path", "")).endswith(".c")
    ]
    if not translation_units:
        raise _UnsupportedSemantics("source package has no C translation unit")
    command = [
        str(compiler),
        "-shared",
        "-fPIC",
        "-O1",
        "-fno-inline",
        "-std=c11",
        "-Wall",
        "-Werror",
        "-I",
        str(source_root),
        "-o",
        str(output),
        *(str(path) for path in translation_units),
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise OSError(f"portable component compiler failed: {detail[:2000]}")


def _load_logical_function(
    library_path: Path,
    source: Mapping[str, object],
    parameters: Sequence[Mapping[str, object]],
    result: Mapping[str, object],
) -> Any:
    entry = _object(source.get("entry"), "component source entry")
    if entry.get("abi") != "logical-c-v1":
        raise _UnsupportedSemantics("source entry does not use logical-c-v1")
    try:
        function = getattr(ctypes.CDLL(str(library_path)), _string(entry.get("symbol"), "entry symbol"))
    except AttributeError as exc:
        raise _UnsupportedSemantics("source entry symbol is not exported") from exc
    function.argtypes = [_ctype(str(row.get("type"))) for row in parameters]
    function.restype = _ctype(str(result.get("type")))
    return function


def _logical_signature(
    interface: Mapping[str, object],
) -> tuple[list[Mapping[str, object]], Mapping[str, object]]:
    parameters = [
        _object(row, "logical parameter")
        for row in _array(interface.get("parameters"), "logical parameters")
    ]
    results = [
        _object(row, "logical result")
        for row in _array(interface.get("results"), "logical results")
        if isinstance(row, Mapping) and row.get("kind") in {"value", "return"}
    ]
    if len(results) != 1:
        raise _UnsupportedSemantics(
            "exhaustive logical-c-v1 evidence requires exactly one value result"
        )
    for row in (*parameters, results[0]):
        _ctype(_string(row.get("type"), "logical C type"))
    return parameters, results[0]


def _parameter_domains(
    verification: Mapping[str, object], parameters: Sequence[Mapping[str, object]]
) -> list[range]:
    rows = {
        str(row.get("parameter_id")): row
        for row in _array(
            verification.get("parameter_domains"), "verification parameter domains"
        )
        if isinstance(row, Mapping)
    }
    expected = [str(row.get("id")) for row in parameters]
    if set(rows) != set(expected):
        raise _UnsupportedSemantics(
            "verification domains do not exactly cover logical parameters"
        )
    result = []
    for identity in expected:
        row = rows[identity]
        if row.get("kind") != "integer-range":
            raise _UnsupportedSemantics(f"parameter {identity} has unsupported domain")
        minimum = row.get("minimum")
        maximum = row.get("maximum")
        if not isinstance(minimum, int) or not isinstance(maximum, int) or minimum > maximum:
            raise _UnsupportedSemantics(f"parameter {identity} range is malformed")
        result.append(range(minimum, maximum + 1))
    return result


class _MachineProgram:
    def __init__(self, machine_ir: Path, member_ids: tuple[str, ...]) -> None:
        rows = _load_machine_rows(machine_ir)
        self.units = {identity: rows[identity] for identity in member_ids}
        self.by_rva = {_unit_rva(row): row for row in self.units.values()}
        if len(self.by_rva) != len(self.units):
            raise _UnsupportedSemantics("component machine units have duplicate RVAs")

    def evaluate(
        self, interface: Mapping[str, object], arguments: Mapping[str, int]
    ) -> int:
        entries = _component_entries(self.units)
        if len(entries) != 1:
            raise _UnsupportedSemantics(
                "exhaustive evaluator currently requires one checked component entry"
            )
        state = _initial_state()
        memory: dict[int, int] = {}
        _write_memory(memory, state["esp"], 4, 0xDEADBEEF)
        for raw in _array(interface.get("parameters"), "logical parameters"):
            parameter = _object(raw, "logical parameter")
            identity = _string(parameter.get("id"), "logical parameter id")
            _bind_machine_input(
                _object(parameter.get("machine_source"), "parameter machine source"),
                int(arguments[identity]),
                state,
                memory,
                self.units,
            )
        value_results = [
            _object(row, "logical result")
            for row in _array(interface.get("results"), "logical results")
            if isinstance(row, Mapping) and row.get("kind") in {"value", "return"}
        ]
        result = value_results[0]
        result_source = _object(result.get("machine_source"), "logical result source")
        evidence = _object(result_source.get("evidence"), "logical result evidence")
        result_unit_id = _string(evidence.get("unit_id"), "logical result unit")
        result_pointer = _string(evidence.get("json_pointer"), "logical result pointer")
        current = entries[0]
        observed_result: int | None = None
        for _step in range(10000):
            identity = _string(current.get("id"), "machine unit id")
            semantics = _object(current.get("semantics"), "machine semantics")
            before = dict(state)
            if identity == result_unit_id:
                expression = _json_pointer(current, result_pointer)
                observed_result = _eval_expr(expression, before, memory)
            register_values = [
                (
                    _string(_object(row, "register write").get("register"), "register write name"),
                    _eval_expr(_object(row, "register write").get("value"), before, memory),
                )
                for row in _array(semantics.get("register_writes", []), "register writes")
            ]
            flag_values = [
                (
                    _string(_object(row, "flag write").get("flag"), "flag write name"),
                    _eval_expr(_object(row, "flag write").get("value"), before, memory),
                )
                for row in _array(semantics.get("flag_writes", []), "flag writes")
            ]
            for event in _array(semantics.get("memory_events", []), "memory events"):
                event = _object(event, "memory event")
                if event.get("kind") != "read":
                    raise _UnsupportedSemantics("memory-writing component evidence is not implemented")
            if _array(semantics.get("external_events", []), "external events"):
                raise _UnsupportedSemantics("external component evidence is not implemented")
            if _array(semantics.get("faults", []), "fault inventory"):
                raise _UnsupportedSemantics("faulting component evidence is not implemented")
            state.update(register_values)
            state.update(flag_values)
            outcome = _object(semantics.get("outcome"), "machine outcome")
            kind = outcome.get("kind")
            if kind == "return":
                if observed_result is None:
                    raise _UnsupportedSemantics("logical result expression was not executed")
                return observed_result
            if kind in {"fallthrough", "jump"}:
                target = outcome.get("target_rva")
            elif kind == "branch":
                condition = _eval_expr(outcome.get("condition"), before, memory)
                target = outcome.get("true_target_rva" if condition else "false_target_rva")
            else:
                raise _UnsupportedSemantics(f"unsupported component outcome {kind!r}")
            if not isinstance(target, int) or target not in self.by_rva:
                raise _UnsupportedSemantics("component path exits without a logical result")
            current = self.by_rva[target]
        raise _UnsupportedSemantics("component execution exceeded the finite step budget")


def _component_entries(units: Mapping[str, Mapping[str, object]]) -> list[Mapping[str, object]]:
    member_rvas = {_unit_rva(row) for row in units.values()}
    incoming: set[int] = set()
    for row in units.values():
        outcome = _object(_object(row.get("semantics"), "machine semantics").get("outcome"), "outcome")
        for key in ("target_rva", "true_target_rva", "false_target_rva"):
            value = outcome.get(key)
            if isinstance(value, int) and value in member_rvas:
                incoming.add(value)
    return sorted(
        (row for row in units.values() if _unit_rva(row) not in incoming),
        key=_unit_rva,
    )


def _bind_machine_input(
    source: Mapping[str, object],
    value: int,
    state: dict[str, int],
    memory: dict[int, int],
    units: Mapping[str, Mapping[str, object]],
) -> None:
    evidence = _object(source.get("evidence"), "parameter evidence")
    unit = units.get(_string(evidence.get("unit_id"), "parameter evidence unit"))
    if unit is None:
        raise _UnsupportedSemantics("parameter evidence is outside the component")
    expression = _json_pointer(
        unit, _string(evidence.get("json_pointer"), "parameter evidence pointer")
    )
    kind = source.get("kind")
    if kind == "register" and isinstance(expression, Mapping):
        state[_string(expression.get("name"), "parameter register")] = value & 0xFFFFFFFF
        return
    if kind == "expression" and isinstance(expression, Mapping) and expression.get("op") == "load":
        address = _eval_expr(expression.get("address"), state, memory)
        _write_memory(memory, address, int(expression.get("width", 4)), value)
        return
    raise _UnsupportedSemantics("logical parameter source cannot be initialized")


def _eval_expr(value: object, state: Mapping[str, int], memory: Mapping[int, int]) -> int:
    expression = _object(value, "machine expression")
    op = expression.get("op")
    args = expression.get("args", [])
    if op == "const":
        return int(expression.get("value", 0)) & _mask(int(expression.get("width", 32)))
    if op == "reg" or op == "flag":
        return int(state.get(_string(expression.get("name"), "machine state name"), 0))
    if op == "false":
        return 0
    if op == "true":
        return 1
    if op == "load":
        address = _eval_expr(expression.get("address"), state, memory)
        return _read_memory(memory, address, int(expression.get("width", 4)))
    values = [_eval_expr(arg, state, memory) if isinstance(arg, Mapping) else int(arg) for arg in _array(args, f"{op} arguments")]
    if op == "add32":
        return sum(values) & 0xFFFFFFFF
    if op == "sub32":
        return (values[0] - values[1]) & 0xFFFFFFFF
    if op == "and32":
        return values[0] & values[1]
    if op == "or32":
        return values[0] | values[1]
    if op == "xor32":
        return values[0] ^ values[1]
    if op == "eq":
        return int(values[0] == values[1])
    if op == "ult32":
        return int((values[0] & 0xFFFFFFFF) < (values[1] & 0xFFFFFFFF))
    if op == "ite":
        return values[1] if values[0] else values[2]
    if op == "msb":
        width, item = values
        return (item >> (width - 1)) & 1
    if op == "parity":
        item = values[-1] & 0xFF
        return int(item.bit_count() % 2 == 0)
    if op == "sub_overflow":
        width, left, right, result = values
        sign = 1 << (width - 1)
        return int(((left ^ right) & (left ^ result) & sign) != 0)
    raise _UnsupportedSemantics(f"unsupported machine expression operation {op!r}")


def _initial_state() -> dict[str, int]:
    state = {name: 0 for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")}
    state.update({name: 0 for name in ("cf", "zf", "sf", "of", "pf", "df")})
    state["esp"] = 0x00100000
    return state


def _read_memory(memory: Mapping[int, int], address: int, width: int) -> int:
    return sum((memory.get((address + index) & 0xFFFFFFFF, 0) & 0xFF) << (8 * index) for index in range(width))


def _write_memory(memory: dict[int, int], address: int, width: int, value: int) -> None:
    for index in range(width):
        memory[(address + index) & 0xFFFFFFFF] = (value >> (8 * index)) & 0xFF


def _load_machine_rows(path: Path) -> dict[str, Mapping[str, object]]:
    source = _machine_ir_path(path)
    rows: dict[str, Mapping[str, object]] = {}
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        raw = json.loads(line)
        row = _object(raw, f"machine IR line {number}")
        identity = _string(row.get("id"), f"machine IR line {number} id")
        rows[identity] = row
    return rows


def _machine_ir_path(path: Path) -> Path:
    return path / "machine-ir.jsonl" if path.is_dir() else path


def _unit_rva(row: Mapping[str, object]) -> int:
    return int(_object(_object(row.get("source"), "machine source").get("original"), "original span")["rva_start"])


def _json_pointer(value: object, pointer: str) -> object:
    current = value
    if pointer == "":
        return current
    if not pointer.startswith("/"):
        raise _UnsupportedSemantics("machine evidence pointer is malformed")
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise _UnsupportedSemantics("machine evidence pointer traverses a scalar")
    return current


def _ctype(name: str) -> Any:
    try:
        return _CTYPE_BY_NAME[name]
    except KeyError as exc:
        raise _UnsupportedSemantics(f"unsupported logical C type {name!r}") from exc


def _ctype_width(name: str) -> int:
    return ctypes.sizeof(_ctype(name)) * 8


def _mask(width: int) -> int:
    return (1 << width) - 1


def _check_self_hash(
    payload: Mapping[str, object], format_name: str, field: str, description: str
) -> None:
    if payload.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    core = copy.deepcopy(dict(payload))
    expected = core.pop(field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")


def _issue(status: str, code: str, **details: object) -> dict[str, object]:
    return {"status": status, "code": code, **details}


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


__all__ = ["produce_component_evidence_v3"]
