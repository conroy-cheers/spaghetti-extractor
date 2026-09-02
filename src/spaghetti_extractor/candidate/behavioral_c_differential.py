"""Veto-only execution comparison for generated C backends.

The runner compiles developer-side shared objects from already generated source
packages.  It does not build a PE, qualify runtime behavior, or grant authority.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.evaluator import (
    evaluate_transfer_plan_case,
    generated_differential_cases,
)
from ..util import sha256_file, write_json
from .formats import (
    BEHAVIORAL_C_DIFFERENTIAL_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
)


class BehavioralCDifferentialError(ValueError):
    """A generated-C differential input or execution failed closed."""


class _X87Value(ctypes.Structure):
    _fields_ = [
        ("value_bytes", ctypes.c_uint8 * 10),
        ("empty", ctypes.c_uint32),
        ("tag", ctypes.c_uint8),
    ]


class _MachineState(ctypes.Structure):
    _fields_ = [
        *((name, ctypes.c_uint32) for name in (
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "cf", "zf", "sf", "of", "pf", "df",
        )),
        ("x87_stack", _X87Value * 8),
        ("x87_control", ctypes.c_uint16),
        ("x87_status", ctypes.c_uint16),
        ("x87_pending_exception", ctypes.c_uint8),
        ("x87_last_opcode", ctypes.c_uint16),
        ("x87_instruction_pointer", ctypes.c_uint32),
        ("x87_code_selector", ctypes.c_uint16),
        ("x87_data_pointer", ctypes.c_uint32),
        ("x87_data_selector", ctypes.c_uint16),
        ("eflags", ctypes.c_uint32),
        ("fs_base", ctypes.c_uint32),
        ("original_rva", ctypes.c_uint32),
    ]


class _Runtime(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("image_base", ctypes.c_uint32),
    ] + [
        (name, ctypes.c_void_p) for name in (
            "read", "write", "atomic_compare_exchange", "atomic_exchange",
            "resolve_reference", "realize_reference", "undefined_value",
            "external_call_fallback", "resolve_code_target", "route_nonlocal",
            "invoke_callable_external_jump", "record_access_violation",
        )
    ]


_READ = ctypes.CFUNCTYPE(
    ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
)
_WRITE = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
)
_UNDEFINED = ctypes.CFUNCTYPE(
    ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
    ctypes.POINTER(_MachineState), ctypes.c_uint32,
)
_ATOMIC_CAS = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
)
_ATOMIC_EXCHANGE = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
)

_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")


def run_behavioral_c_differential(
    *,
    transfer_plan: Path,
    behavioral_c_package: Path,
    compiler: Path | str,
    out: Path,
    cases: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare generated behavioral C with the neutral transfer evaluator."""

    plan_path = Path(transfer_plan)
    behavioral_path, behavioral = _package(
        behavioral_c_package, "behavioral-c-package.json",
        BEHAVIORAL_C_PACKAGE_FORMAT, "behavioral C",
    )
    if behavioral.get("status") != "ready":
        raise BehavioralCDifferentialError("behavioral-C package is incomplete")
    if behavioral.get("executable_transfer_plan", {}).get("sha256") != sha256_file(plan_path):
        raise BehavioralCDifferentialError("behavioral C binds another transfer plan")
    backends = [("behavioral_c", behavioral_path, behavioral, "spx_behavioral_run")]
    selected_cases = [dict(row) for row in (cases or generated_differential_cases(plan_path))]
    if not selected_cases:
        raise BehavioralCDifferentialError("differential suite has no cases")
    expected = [evaluate_transfer_plan_case(plan_path, row) for row in selected_cases]
    observations: dict[str, list[dict[str, Any]]] = {}
    bindings: dict[str, Any] = {}
    with TemporaryDirectory(prefix="spx-behavioral-differential-") as temporary:
        temporary_root = Path(temporary)
        for backend_id, manifest_path, package, symbol in backends:
            library = temporary_root / f"{backend_id}.so"
            _compile_backend(
                compiler=Path(compiler), root=manifest_path.parent,
                package=package, output=library,
            )
            observations[backend_id] = [
                _execute_case(library, symbol, case) for case in selected_cases
            ]
            bindings[backend_id] = {
                "package_sha256": sha256_file(manifest_path),
                "source_count": len(_source_files(manifest_path.parent, package)),
                "shared_object_sha256": sha256_file(library),
            }
    mismatches: list[dict[str, Any]] = []
    normalized_expected = [_normalize_evaluator(row) for row in expected]
    for backend_id, rows in observations.items():
        for index, (wanted, observed) in enumerate(zip(normalized_expected, rows, strict=True)):
            differing = [
                field for field in ("status", "state", "memory")
                if wanted[field] != observed[field]
            ]
            if differing:
                mismatches.append({
                    "backend": backend_id,
                    "case_id": str(selected_cases[index].get("id", index)),
                    "fields": differing,
                    "expected": wanted,
                    "observed": observed,
                })
    core = {
        "format": BEHAVIORAL_C_DIFFERENTIAL_FORMAT,
        "status": "match" if not mismatches else "mismatch",
        "authority": "none; generated differential cases are veto-only",
        "transfer_plan_sha256": sha256_file(plan_path),
        "backends": bindings,
        "case_ids": [str(row.get("id", index)) for index, row in enumerate(selected_cases)],
        "mismatches": mismatches,
    }
    payload = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "behavioral-c-differential.json", payload)
    return payload


def _package(
    value: Path, filename: str, expected_format: str, label: str,
) -> tuple[Path, dict[str, Any]]:
    path = Path(value)
    path = path / filename if path.is_dir() else path
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BehavioralCDifferentialError(f"cannot read {label}: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("format") != expected_format
        or payload.get("status") != "ready"
    ):
        raise BehavioralCDifferentialError(f"{label} package is not ready")
    _source_files(path.parent, payload)
    return path, payload


def _source_files(root: Path, package: Mapping[str, Any]) -> list[Path]:
    rows = package.get("sources")
    if not isinstance(rows, list):
        raise BehavioralCDifferentialError("generated source inventory is malformed")
    result = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("path"), str):
            raise BehavioralCDifferentialError("generated source binding is malformed")
        path = root / str(row["path"])
        if not path.is_file() or row.get("sha256") != sha256_file(path):
            raise BehavioralCDifferentialError("generated source binding is stale")
        if path.suffix.lower() == ".c":
            result.append(path)
    if not result:
        raise BehavioralCDifferentialError("generated package has no C sources")
    return result


def _compile_backend(
    *, compiler: Path, root: Path, package: Mapping[str, Any], output: Path,
) -> None:
    stub = output.with_suffix(".c")
    stub_source = (
        '#include "state-machine-runtime.h"\n'
        "spx_call_status spx_dispatch_external_call(spx_runtime *r, const spx_call_event *e, "
        "const spx_machine_state *i, spx_machine_state *o) { "
        "(void)r; (void)e; if (i && o) *o = *i; return SPX_CALL_UNIMPLEMENTED; }\n"
        "void spx_runtime_atomic_compare_exchange(spx_runtime *r, uint32_t a, "
        "uint32_t w, uint32_t e, uint32_t d, uint32_t *o, uint32_t *x, "
        "uint32_t *f) { if (!r || !r->atomic_compare_exchange) { *f = 1U; "
        "return; } r->atomic_compare_exchange(r->context, a, w, e, d, o, x, f); }\n"
        "void spx_runtime_atomic_exchange(spx_runtime *r, uint32_t a, "
        "uint32_t w, uint32_t d, uint32_t *o, uint32_t *f) { "
        "if (!r || !r->atomic_exchange) { *f = 1U; return; } "
        "r->atomic_exchange(r->context, a, w, d, o, f); }\n"
    )
    stub.write_text(stub_source, encoding="ascii")
    command = [
        str(compiler), "-std=c11", "-O0", "-fPIC", "-shared",
        "-Wl,--no-undefined", "-I", str(root),
        *(str(path) for path in _source_files(root, package)),
        str(stub), "-o", str(output),
    ]
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "SOURCE_DATE_EPOCH": "1"})
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, env=environment)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        raise BehavioralCDifferentialError(
            f"generated backend did not compile: {detail}"
        ) from exc


def _execute_case(library: Path, symbol: str, case: Mapping[str, Any]) -> dict[str, Any]:
    memory = _case_memory(case.get("memory"))
    undefined = {
        int(key): int(value) & 0xFFFFFFFF
        for key, value in dict(case.get("undefined_values", {})).items()
    }

    def read(_context: int, address: int, width: int, fault: Any) -> int:
        addresses = [(address + offset) & 0xFFFFFFFF for offset in range(width)]
        if width not in {1, 2, 4} or any(item not in memory for item in addresses):
            fault[0] = 1
            return 0
        fault[0] = 0
        return sum(memory[item] << (8 * offset) for offset, item in enumerate(addresses))

    def write(_context: int, address: int, width: int, value: int, fault: Any) -> None:
        addresses = [(address + offset) & 0xFFFFFFFF for offset in range(width)]
        if width not in {1, 2, 4} or any(item not in memory for item in addresses):
            fault[0] = 1
            return
        fault[0] = 0
        for offset, item in enumerate(addresses):
            memory[item] = (value >> (8 * offset)) & 0xFF

    def undefined_value(
        _context: int, slot: int, _state: Any, defined: int,
    ) -> int:
        return undefined.get(slot, slot if defined == 0 else defined)

    def atomic_compare_exchange(
        context: int, address: int, width: int, expected: int, desired: int,
        observed: Any, exchanged: Any, fault: Any,
    ) -> None:
        value = read(context, address, width, fault)
        observed[0] = value
        exchanged[0] = 0
        if not fault[0] and value == expected:
            write(context, address, width, desired, fault)
            if not fault[0]:
                exchanged[0] = 1

    def atomic_exchange(
        context: int, address: int, width: int, desired: int,
        observed: Any, fault: Any,
    ) -> None:
        observed[0] = read(context, address, width, fault)
        if not fault[0]:
            write(context, address, width, desired, fault)

    callbacks = (
        _READ(read), _WRITE(write), _ATOMIC_CAS(atomic_compare_exchange),
        _ATOMIC_EXCHANGE(atomic_exchange), _UNDEFINED(undefined_value),
    )
    runtime = _Runtime()
    for field, callback in zip(
        ("read", "write", "atomic_compare_exchange", "atomic_exchange", "undefined_value"),
        callbacks, strict=True,
    ):
        setattr(runtime, field, ctypes.cast(callback, ctypes.c_void_p).value)
    input_state = _state_from_case(case.get("state"))
    output_state = _MachineState()
    loaded = ctypes.CDLL(str(library))
    function = getattr(loaded, symbol)
    function.argtypes = [
        ctypes.POINTER(_Runtime), ctypes.c_uint32,
        ctypes.POINTER(_MachineState), ctypes.POINTER(_MachineState),
    ]
    function.restype = ctypes.c_int
    status = int(function(
        ctypes.byref(runtime), int(case["entry_rva"]),
        ctypes.byref(input_state), ctypes.byref(output_state),
    ))
    return {
        "status": status,
        "state": _state_payload(output_state),
        "memory": dict(sorted(memory.items())),
    }


def _case_memory(raw: object) -> dict[int, int]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise BehavioralCDifferentialError("differential memory is malformed")
    result: dict[int, int] = {}
    for row in raw:
        if not isinstance(row, Mapping):
            raise BehavioralCDifferentialError("differential memory segment is malformed")
        address = int(row["address"])
        data = bytes.fromhex(str(row["bytes_hex"]))
        for offset, value in enumerate(data):
            key = (address + offset) & 0xFFFFFFFF
            if key in result:
                raise BehavioralCDifferentialError("differential memory overlaps")
            result[key] = value
    return result


def _state_from_case(raw: object) -> _MachineState:
    payload = dict(raw) if isinstance(raw, Mapping) else {}
    state = _MachineState()
    registers = payload.get("registers", {})
    flags = payload.get("flags", {})
    for name in _REGISTERS:
        setattr(state, name, int(registers.get(name, 0)) & 0xFFFFFFFF)
    for name in _FLAGS:
        setattr(state, name, int(flags.get(name, 0)) & 1)
    state.eflags = int(payload.get("eflags", 0)) & 0xFFFFFFFF
    state.fs_base = int(payload.get("fs_base", 0)) & 0xFFFFFFFF
    state.original_rva = int(payload.get("original_rva", 0)) & 0xFFFFFFFF
    return state


def _state_payload(state: _MachineState) -> dict[str, Any]:
    return {
        "registers": {name: int(getattr(state, name)) for name in _REGISTERS},
        "flags": {name: int(getattr(state, name)) for name in _FLAGS},
        "eflags": int(state.eflags),
        "fs_base": int(state.fs_base),
        "original_rva": int(state.original_rva),
    }


def _normalize_evaluator(observation: Mapping[str, Any]) -> dict[str, Any]:
    result = observation["result"]
    status = {
        "return": 0,
        "external_jump": 0,
        "divide_error": 2,
        "memory_fault": 3,
        "external_fault": 4,
    }.get(str(result["kind"]), 1)
    return {
        "status": status,
        "state": dict(observation["state"]),
        "memory": {
            int(row["address"]): int(row["value"])
            for row in observation["memory"]
        },
    }


__all__ = [
    "BehavioralCDifferentialError",
    "run_behavioral_c_differential",
]
