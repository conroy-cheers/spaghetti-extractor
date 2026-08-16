"""Candidate-only evidence producers for portable component implementations."""

from __future__ import annotations

import copy
import ctypes
import itertools
import json
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..external.contracts import (
    CheckedExternalSiteContract,
)
from ..util import sha256_file, write_json
from .adapter import load_component_adapter_plan
from .compiler import ComponentCompileError, compile_component_library
from .formats import (
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_EVIDENCE_V3_FORMAT,
)
from .evidence_runner import CandidateEvidenceRunner, CandidateRunError
from .evidence_effects import (
    EvidenceEffectError,
    call_flag_key,
    call_register_key,
    execute_ordered_effects,
    expression_is_defined,
    parse_adapter_external_contracts,
)
from .evidence_completion import (
    EvidenceCompletionError,
    evaluate_adapter_completion,
)
from .intent import ComponentIntentError
from .logical_abi import (
    LOGICAL_OBJECT_C_V1,
    OFFSET_INTO_VIEW_V1,
    logical_type_kind,
    parameter_shape_error,
    result_shape_error,
    source_abi_error,
)
from .source import load_component_source_package


_TOOL_ID = "spaghetti-extractor-component-evidence-evaluator"
_TOOL_VERSION = 3
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


@dataclass(frozen=True)
class _MachineEvaluation:
    logical_result: int
    parameter_machine_values: Mapping[str, int]
    entry_state: Mapping[str, int]
    entry_memory: "_MachineMemory"
    boundary_state: Mapping[str, int]
    boundary_memory: "_MachineMemory"
    boundary_defined_fields: frozenset[str]
    external_result_values: Mapping[tuple[str, int, str], int]
    external_result_defined: frozenset[tuple[str, int, str]]
    return_target: int


class _MachineMemory:
    """Concrete byte memory that rejects reads outside declared case inputs."""

    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.next_object_address = 0x00200000

    def allocate(self, values: Sequence[int]) -> int:
        address = self.next_object_address
        size = max(1, len(values))
        self.next_object_address = (address + size + 15) & ~15
        for offset, value in enumerate(values):
            self.bytes[(address + offset) & 0xFFFFFFFF] = int(value) & 0xFF
        return address

    def read(self, address: int, width: int) -> int:
        locations = [((address + index) & 0xFFFFFFFF) for index in range(width)]
        missing = [location for location in locations if location not in self.bytes]
        if missing:
            raise _UnsupportedSemantics(
                "machine semantics read outside declared case memory at "
                f"0x{missing[0]:08x}"
            )
        return sum(
            self.bytes[location] << (8 * index)
            for index, location in enumerate(locations)
        )

    def write(self, address: int, width: int, value: int) -> None:
        for index in range(width):
            self.bytes[(address + index) & 0xFFFFFFFF] = (
                value >> (8 * index)
            ) & 0xFF

    def clone(self) -> "_MachineMemory":
        result = _MachineMemory()
        result.bytes = dict(self.bytes)
        result.next_object_address = self.next_object_address
        return result


def produce_component_evidence(
    *,
    contract: Path | str,
    implementation: Path | str,
    adapter_plan: Path | str,
    machine_ir: Path | str,
    verification: Mapping[str, object],
    compiler: Path | str,
    out: Path | str,
) -> dict[str, object]:
    """Compile portable C and evaluate the declared candidate-only evidence.

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
    source = load_component_source_package(implementation)
    adapter = load_component_adapter_plan(adapter_plan)
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
    candidate: CandidateEvidenceRunner | None = None
    active_case: dict[str, object] | None = None

    if contract_payload.get("status") != "checked":
        issues.append(_issue("incomplete", "component_contract_not_checked"))
    if source.get("lift_unit_id") != lift_unit_id:
        issues.append(_issue("violated", "component_source_identity_mismatch"))
    if adapter.get("status") != "checked":
        issues.append(_issue("incomplete", "component_adapter_plan_not_checked"))
    if adapter.get("lift_unit_id") != lift_unit_id:
        issues.append(_issue("violated", "component_adapter_plan_identity_mismatch"))
    adapter_bindings = _object(
        adapter.get("bindings"), "component adapter-plan bindings"
    )
    for field, expected in {
        "contract_sha256": contract_payload.get("contract_sha256"),
        "implementation_sha256": source.get("implementation_sha256"),
        "machine_ir_sha256": sha256_file(_machine_ir_path(Path(machine_ir))),
        "source_entry": source.get("entry"),
    }.items():
        if adapter_bindings.get(field) != expected:
            issues.append(
                _issue(
                    "violated",
                    "component_adapter_plan_binding_stale",
                    field=field,
                    expected=expected,
                    observed=adapter_bindings.get(field),
                )
            )
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
        entry = _object(source.get("entry"), "component source entry")
        source_abi = _string(entry.get("abi"), "component source ABI")
        source_symbol = _string(entry.get("symbol"), "component source symbol")
        parameters, result = _logical_signature(interface, source_abi)
        if issues:
            raise _UnsupportedSemantics("prerequisite contract or producer is not usable")
        library_path = Path(out).with_suffix(".component.so")
        adapter_header = _adapter_header_path(Path(adapter_plan), adapter)
        compile_component_library(
            package=Path(implementation),
            source=source,
            compiler=Path(compiler),
            output=library_path,
            forced_header=adapter_header,
        )
        width = _ctype_width(_string(result.get("type"), "logical result type"))
        mask = (1 << width) - 1
        domains = _parameter_domains(
            verification_payload, parameters, source_abi=source_abi
        )
        case_count = 1
        for domain in domains:
            case_count *= len(domain)
        if case_count > 1_000_000:
            raise _UnsupportedSemantics(
                f"declared finite domain contains {case_count} cases"
            )
        vectors = (
            (
                f"domain-{index}",
                dict(zip((row["id"] for row in parameters), values, strict=True)),
                None,
            )
            for index, values in enumerate(itertools.product(*domains))
        )
        machine = _MachineProgram(
            Path(machine_ir),
            tuple(lift_unit["unit_ids"]),
            entry_ids=(
                _adapter_entry_ids(adapter)
                if source_abi == LOGICAL_OBJECT_C_V1
                else ()
            ),
            external_contracts=parse_adapter_external_contracts(adapter),
        )
        for case_id, arguments, _declared_expected in vectors:
            active_case = {"case_index": cases, "case_id": case_id}
            _validate_memory_views(parameters, arguments, source_abi=source_abi)
            machine_evaluation = machine.evaluate(
                interface, arguments, source_abi=source_abi
            )
            expected = _normalize_machine_result(
                result,
                parameters,
                arguments,
                machine_evaluation,
            )
            if candidate is None:
                candidate = CandidateEvidenceRunner(
                    library=library_path,
                    abi=source_abi,
                    symbol=source_symbol,
                    parameters=_candidate_parameters(
                        parameters, source_abi=source_abi
                    ),
                    result_type=_string(result.get("type"), "logical result type"),
                )
            response = candidate.run(arguments)
            observed = response.get("observed")
            violations = response.get("violations")
            if not isinstance(observed, int) or isinstance(observed, bool):
                raise CandidateRunError(
                    "component_candidate_runner_infrastructure_failed",
                    "candidate runner returned a malformed observed value",
                )
            if not isinstance(violations, list) or any(
                not isinstance(violation, Mapping) for violation in violations
            ):
                raise CandidateRunError(
                    "component_candidate_runner_infrastructure_failed",
                    "candidate runner returned malformed protocol violations",
                )
            observed &= mask
            expected &= mask
            cases += 1
            if violations:
                issues.append(
                    _issue(
                        "violated",
                        "component_checked_view_protocol_violation",
                        case_location=active_case,
                        violation=dict(violations[0]),
                    )
                )
                break
            if observed != expected:
                counterexamples.append(
                    {
                        "case_index": cases - 1,
                        "case_id": case_id,
                        "arguments": arguments,
                        "expected": expected,
                        "observed": observed,
                    }
                )
                break
            if (
                producer == "exhaustive-finite-domain-v1"
                and source_abi == LOGICAL_OBJECT_C_V1
            ):
                observed_boundary = evaluate_adapter_completion(
                    adapter,
                    state_fields=_STATE_FIELDS,
                    entry_state=machine_evaluation.entry_state,
                    entry_memory=machine_evaluation.entry_memory,
                    logical_result=observed,
                    result_id=_string(result.get("id"), "logical result id"),
                    external_result_values=(
                        machine_evaluation.external_result_values
                    ),
                    external_result_defined=(
                        machine_evaluation.external_result_defined
                    ),
                    evaluate_expression=_eval_expr,
                )
                boundary_mismatches = _boundary_mismatches(
                    machine_evaluation, observed_boundary
                )
                if boundary_mismatches:
                    counterexamples.append(
                        {
                            "case_index": cases - 1,
                            "case_id": case_id,
                            "arguments": arguments,
                            "expected": expected,
                            "observed": observed,
                            "kind": "adapter_completion_mismatch",
                            "boundary_mismatches": boundary_mismatches,
                        }
                    )
                    break
    except CandidateRunError as exc:
        issues.append(
            _issue(
                "incomplete",
                exc.code,
                detail=exc.detail,
                **({"case_location": active_case} if active_case is not None else {}),
            )
        )
    except (_UnsupportedSemantics, EvidenceCompletionError) as exc:
        if not issues:
            issues.append(
                _issue(
                    "incomplete",
                    "component_evidence_semantics_unsupported",
                    detail=str(exc),
                )
            )
    except (OSError, subprocess.SubprocessError, ComponentCompileError) as exc:
        issues.append(
            _issue(
                "incomplete",
                "component_source_compilation_failed",
                detail=str(exc),
            )
        )
    finally:
        if candidate is not None:
            candidate.close()

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
            "adapter_plan_sha256": adapter["adapter_plan_sha256"],
            "machine_ir_sha256": sha256_file(_machine_ir_path(Path(machine_ir))),
            "domain_sha256": domain_sha256,
            "tool_id": _TOOL_ID,
            "tool_version": _TOOL_VERSION,
        },
        "method": _method(producer, status),
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


def _logical_signature(
    interface: Mapping[str, object],
    source_abi: str,
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
            "logical-c-v1 evidence requires exactly one value result"
        )
    for parameter in parameters:
        error = parameter_shape_error(
            parameter, parameters, source_abi=source_abi
        )
        if error is not None:
            raise _UnsupportedSemantics(error)
    abi_error = source_abi_error(source_abi, parameters)
    if abi_error is not None:
        raise _UnsupportedSemantics(abi_error)
    result_error = result_shape_error(
        results[0], parameters, source_abi=source_abi
    )
    if result_error is not None:
        raise _UnsupportedSemantics(result_error)
    result_type = _string(results[0].get("type"), "logical C type")
    _ctype(result_type)
    return parameters, results[0]


def _candidate_parameters(
    parameters: Sequence[Mapping[str, object]],
    *,
    source_abi: str,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for parameter in parameters:
        row: dict[str, object] = {
            "id": _string(parameter.get("id"), "logical parameter id"),
            "type": _string(parameter.get("type"), "logical parameter type"),
        }
        kind = logical_type_kind(parameter.get("type"), source_abi=source_abi)
        if kind in {"read_only_bytes", "nul_terminated_bytes"}:
            view = _object(
                parameter.get("memory_view"), "logical parameter memory view"
            )
            row["memory_view"] = {"kind": view.get("kind")}
            if kind == "read_only_bytes":
                row["memory_view"]["extent_parameter_id"] = _string(
                    view.get("extent_parameter_id"),
                    "logical parameter extent parameter id",
                )
        result.append(row)
    return result


def _parameter_domains(
    verification: Mapping[str, object],
    parameters: Sequence[Mapping[str, object]],
    *,
    source_abi: str,
) -> list[Sequence[object]]:
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
    result: list[Sequence[object]] = []
    parameters_by_id = {str(row.get("id")): row for row in parameters}
    for identity in expected:
        row = rows[identity]
        type_kind = logical_type_kind(
            parameters_by_id[identity].get("type"), source_abi=source_abi
        )
        if type_kind == "scalar":
            if row.get("kind") != "integer-range":
                raise _UnsupportedSemantics(
                    f"scalar parameter {identity} requires an integer-range domain"
                )
            minimum = row.get("minimum")
            maximum = row.get("maximum")
            if (
                not isinstance(minimum, int)
                or isinstance(minimum, bool)
                or not isinstance(maximum, int)
                or isinstance(maximum, bool)
                or minimum > maximum
            ):
                raise _UnsupportedSemantics(f"parameter {identity} range is malformed")
            result.append(range(minimum, maximum + 1))
            continue
        if type_kind in {"read_only_bytes", "nul_terminated_bytes"}:
            expected_domain = (
                "byte-buffer-set"
                if type_kind == "read_only_bytes"
                else "nul-terminated-byte-buffer-set"
            )
            if row.get("kind") != expected_domain:
                raise _UnsupportedSemantics(
                    f"byte-pointer parameter {identity} requires a "
                    f"{expected_domain} domain"
                )
            values = row.get("values")
            if not isinstance(values, list) or not values:
                raise _UnsupportedSemantics(
                    f"parameter {identity} byte-buffer-set is empty or malformed"
                )
            normalized: list[list[int]] = []
            for index, value in enumerate(values):
                if (
                    not isinstance(value, list)
                    or len(value) > 65536
                    or any(
                        not isinstance(byte, int)
                        or isinstance(byte, bool)
                        or byte < 0
                        or byte > 255
                        for byte in value
                    )
                ):
                    raise _UnsupportedSemantics(
                        f"parameter {identity} byte buffer {index} is malformed"
                    )
                bytes_value = [int(byte) for byte in value]
                if type_kind == "nul_terminated_bytes" and 0 not in bytes_value:
                    raise _UnsupportedSemantics(
                        f"parameter {identity} byte buffer {index} has no NUL terminator"
                    )
                normalized.append(bytes_value)
            result.append(normalized)
            continue
        raise _UnsupportedSemantics(f"parameter {identity} has unsupported domain")
    return result


def _normalize_argument(
    parameter: Mapping[str, object],
    value: object,
    description: str,
    *,
    source_abi: str,
) -> object:
    kind = logical_type_kind(parameter.get("type"), source_abi=source_abi)
    if kind == "scalar":
        if not isinstance(value, int) or isinstance(value, bool):
            raise _UnsupportedSemantics(f"{description} must be an integer")
        return int(value)
    if kind in {"read_only_bytes", "nul_terminated_bytes"}:
        if (
            not isinstance(value, list)
            or len(value) > 65536
            or any(
                not isinstance(byte, int)
                or isinstance(byte, bool)
                or byte < 0
                or byte > 255
                for byte in value
            )
        ):
            raise _UnsupportedSemantics(f"{description} must be a byte array")
        normalized = [int(byte) for byte in value]
        if kind == "nul_terminated_bytes" and 0 not in normalized:
            raise _UnsupportedSemantics(
                f"{description} must contain a NUL terminator"
            )
        return normalized
    raise _UnsupportedSemantics(f"{description} has an unsupported logical type")


def _normalize_machine_result(
    result: Mapping[str, object],
    parameters: Sequence[Mapping[str, object]],
    arguments: Mapping[str, object],
    machine: _MachineEvaluation,
) -> int:
    """Project a concrete machine result into the reviewed logical value domain."""

    relation = result.get("value_relation")
    if relation is None:
        return machine.logical_result
    relation = _object(relation, "logical result value relation")
    if relation.get("kind") != OFFSET_INTO_VIEW_V1:
        raise _UnsupportedSemantics("logical result value relation is unsupported")
    parameter_id = _string(
        relation.get("parameter_id"), "logical result view parameter id"
    )
    parameter = next(
        (row for row in parameters if row.get("id") == parameter_id), None
    )
    if parameter is None or parameter_id not in machine.parameter_machine_values:
        raise _UnsupportedSemantics(
            "logical result value relation references an unavailable parameter"
        )
    buffer = arguments.get(parameter_id)
    if not isinstance(buffer, list):
        raise _UnsupportedSemantics(
            "logical result value relation requires a byte-view argument"
        )
    offset = (
        machine.logical_result - machine.parameter_machine_values[parameter_id]
    ) & 0xFFFFFFFF
    kind = logical_type_kind(
        parameter.get("type"), source_abi=LOGICAL_OBJECT_C_V1
    )
    if kind == "nul_terminated_bytes":
        terminator = buffer.index(0)
        limit = terminator
    elif kind == "read_only_bytes":
        view = _object(parameter.get("memory_view"), "logical result byte view")
        extent_id = _string(
            view.get("extent_parameter_id"), "logical result byte-view extent"
        )
        extent = arguments.get(extent_id)
        if not isinstance(extent, int) or isinstance(extent, bool):
            raise _UnsupportedSemantics(
                "logical result byte-view extent is unavailable"
            )
        limit = extent
    else:
        raise _UnsupportedSemantics(
            "logical result value relation does not reference a byte view"
        )
    if offset > limit:
        raise _UnsupportedSemantics(
            f"machine result offset {offset} lies outside view {parameter_id} "
            f"limit {limit}"
        )
    return offset

def _method(producer: object, status: str) -> dict[str, object]:
    if producer == "exhaustive-finite-domain-v1":
        return {
            "kind": "exhaustive_finite_domain_v1",
            "complete_for_declared_domain": status != "incomplete",
            "candidate_only": True,
            "semantic_reference": "canonical-machine-ir-v2",
            "reference_backend": "bounded-python-machine-ir-evaluator-v3",
            "candidate_backend": "compiled-portable-c",
            "independent_isa_qualification": "required-at-candidate-gate-v3",
            "universal_equivalence_claimed": False,
        }
    return {
        "kind": "unsupported",
        "candidate_only": True,
        "semantic_reference": "none",
        "reference_backend": "none",
        "candidate_backend": "compiled-portable-c",
        "independent_isa_qualification": "required-at-candidate-gate-v3",
        "universal_equivalence_claimed": False,
    }


def _boundary_mismatches(
    expected: _MachineEvaluation, observed: Mapping[str, object]
) -> list[dict[str, object]]:
    observed_state = _object(observed.get("state"), "completed boundary state")
    result: list[dict[str, object]] = []
    for name in _STATE_FIELDS:
        if name not in expected.boundary_defined_fields:
            continue
        expected_value = int(expected.boundary_state[name]) & 0xFFFFFFFF
        observed_value = observed_state.get(name)
        if observed_value != expected_value:
            result.append(
                {
                    "location": f"state.{name}",
                    "expected": expected_value,
                    "observed": observed_value,
                }
            )
    expected_target = expected.return_target & 0xFFFFFFFF
    observed_target = observed.get("return_target")
    if observed_target != expected_target:
        result.append(
            {
                "location": "return_target",
                "expected": expected_target,
                "observed": observed_target,
            }
        )
    observed_memory = observed.get("memory")
    if not isinstance(observed_memory, _MachineMemory):
        raise _UnsupportedSemantics("completed boundary memory is malformed")
    for address in sorted(
        set(expected.boundary_memory.bytes) | set(observed_memory.bytes)
    ):
        expected_byte = expected.boundary_memory.bytes.get(address)
        observed_byte = observed_memory.bytes.get(address)
        if expected_byte != observed_byte:
            result.append(
                {
                    "location": f"memory[0x{address:08x}]",
                    "expected": expected_byte,
                    "observed": observed_byte,
                }
            )
    return result


class _MachineProgram:
    def __init__(
        self,
        machine_ir: Path,
        member_ids: tuple[str, ...],
        *,
        entry_ids: tuple[str, ...] = (),
        external_contracts: Mapping[
            tuple[str, int], CheckedExternalSiteContract
        ] | None = None,
    ) -> None:
        rows = _load_machine_rows(machine_ir)
        self.units = {identity: rows[identity] for identity in member_ids}
        self.by_rva = {_unit_rva(row): row for row in self.units.values()}
        self.entry_ids = entry_ids
        self.external_contracts = dict(external_contracts or {})
        if len(self.by_rva) != len(self.units):
            raise _UnsupportedSemantics("component machine units have duplicate RVAs")

    def evaluate(
        self,
        interface: Mapping[str, object],
        arguments: Mapping[str, object],
        *,
        source_abi: str,
    ) -> _MachineEvaluation:
        entries = (
            [self.units[identity] for identity in self.entry_ids if identity in self.units]
            if self.entry_ids
            else _component_entries(self.units)
        )
        if len(entries) != 1:
            raise _UnsupportedSemantics(
                "exhaustive evaluator currently requires one checked component entry"
            )
        state = _initial_state()
        defined_fields = set(_STATE_FIELDS)
        memory = _MachineMemory()
        _write_memory(memory, state["esp"], 4, 0xDEADBEEF)
        parameters = [
            _object(raw, "logical parameter")
            for raw in _array(interface.get("parameters"), "logical parameters")
        ]
        _validate_memory_views(parameters, arguments, source_abi=source_abi)
        parameter_machine_values: dict[str, int] = {}
        for parameter in parameters:
            identity = _string(parameter.get("id"), "logical parameter id")
            parameter_machine_values[identity] = _bind_machine_input(
                parameter,
                arguments[identity],
                state,
                memory,
                self.units,
                source_abi=source_abi,
            )
        entry_state = dict(state)
        entry_memory = memory.clone()
        external_result_values: dict[tuple[str, int, str], int] = {}
        external_result_defined: set[tuple[str, int, str]] = set()
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
            before_defined = frozenset(defined_fields)
            if identity == result_unit_id:
                expression = _json_pointer(current, result_pointer)
                if not expression_is_defined(expression, before_defined):
                    raise _UnsupportedSemantics(
                        "logical result depends on undefined machine state"
                    )
                observed_result = _eval_expr(expression, before, memory)
            evaluation_state = dict(before)
            evaluation_defined = set(before_defined)
            try:
                executed_calls = execute_ordered_effects(
                    unit_id=identity,
                    semantics=semantics,
                    state=evaluation_state,
                    defined_fields=evaluation_defined,
                    memory=memory,
                    external_contracts=self.external_contracts,
                    evaluate_expression=_eval_expr,
                )
            except EvidenceEffectError as exc:
                raise _UnsupportedSemantics(str(exc)) from exc
            for executed_call in executed_calls:
                contract = self.external_contracts[
                    (executed_call.unit_id, executed_call.event_index)
                ]
                exact_registers = {
                    relation.get("register")
                    for relation in contract.result_register_relations
                    if isinstance(relation, Mapping)
                    and relation.get("relation") == "exact"
                    and isinstance(relation.get("register"), str)
                }
                for register in exact_registers:
                    key = (executed_call.unit_id, executed_call.event_index, register)
                    if key in external_result_values:
                        raise _UnsupportedSemantics(
                            "component external-call site executed more than once"
                        )
                    evaluation = executed_call.evaluation
                    if register not in evaluation.register_values:
                        raise _UnsupportedSemantics(
                            "external evidence omitted an exact result register"
                        )
                    external_result_values[key] = (
                        int(evaluation.register_values[register]) & 0xFFFFFFFF
                    )
                    if register in evaluation.defined_registers:
                        external_result_defined.add(key)
            register_values = [
                (
                    _string(_object(row, "register write").get("register"), "register write name"),
                    _eval_expr(
                        _object(row, "register write").get("value"),
                        evaluation_state,
                        memory,
                    ),
                    expression_is_defined(
                        _object(row, "register write").get("value"),
                        frozenset(evaluation_defined),
                    ),
                )
                for row in _array(semantics.get("register_writes", []), "register writes")
            ]
            flag_values = [
                (
                    _string(_object(row, "flag write").get("flag"), "flag write name"),
                    _eval_expr(
                        _object(row, "flag write").get("value"),
                        evaluation_state,
                        memory,
                    ),
                    expression_is_defined(
                        _object(row, "flag write").get("value"),
                        frozenset(evaluation_defined),
                    ),
                )
                for row in _array(semantics.get("flag_writes", []), "flag writes")
            ]
            if _array(semantics.get("faults", []), "fault inventory"):
                raise _UnsupportedSemantics("faulting component evidence is not implemented")
            for name, value, is_defined in register_values:
                state[name] = value
                if is_defined:
                    defined_fields.add(name)
                else:
                    defined_fields.discard(name)
            for name, value, is_defined in flag_values:
                state[name] = value
                if is_defined:
                    defined_fields.add(name)
                else:
                    defined_fields.discard(name)
            outcome = _object(semantics.get("outcome"), "machine outcome")
            kind = outcome.get("kind")
            if kind == "return":
                if observed_result is None:
                    raise _UnsupportedSemantics("logical result expression was not executed")
                if not expression_is_defined(
                    outcome.get("value"), frozenset(evaluation_defined)
                ):
                    raise _UnsupportedSemantics(
                        "component return target depends on undefined machine state"
                    )
                return _MachineEvaluation(
                    logical_result=observed_result,
                    parameter_machine_values=parameter_machine_values,
                    entry_state=entry_state,
                    entry_memory=entry_memory,
                    boundary_state={
                        name: int(state[name]) & 0xFFFFFFFF for name in _STATE_FIELDS
                    },
                    boundary_memory=memory.clone(),
                    boundary_defined_fields=frozenset(defined_fields),
                    external_result_values=dict(external_result_values),
                    external_result_defined=frozenset(external_result_defined),
                    return_target=_eval_expr(
                        outcome.get("value"), evaluation_state, memory
                    )
                    & 0xFFFFFFFF,
                )
            if kind in {"fallthrough", "jump"}:
                target = outcome.get("target_rva")
            elif kind == "branch":
                if not expression_is_defined(
                    outcome.get("condition"), frozenset(evaluation_defined)
                ):
                    raise _UnsupportedSemantics(
                        "component branch depends on undefined machine state"
                    )
                condition = _eval_expr(
                    outcome.get("condition"), evaluation_state, memory
                )
                target = outcome.get(
                    "true_target_rva" if condition else "false_target_rva"
                )
            else:
                raise _UnsupportedSemantics(f"unsupported component outcome {kind!r}")
            if not isinstance(target, int):
                raise _UnsupportedSemantics("component path has a malformed exit target")
            if target not in self.by_rva:
                if kind != "branch" or observed_result is None:
                    raise _UnsupportedSemantics(
                        "component path exits without a logical result"
                    )
                return _MachineEvaluation(
                    logical_result=observed_result,
                    parameter_machine_values=parameter_machine_values,
                    entry_state=entry_state,
                    entry_memory=entry_memory,
                    boundary_state={
                        name: int(state[name]) & 0xFFFFFFFF
                        for name in _STATE_FIELDS
                    },
                    boundary_memory=memory.clone(),
                    boundary_defined_fields=frozenset(defined_fields),
                    external_result_values=dict(external_result_values),
                    external_result_defined=frozenset(external_result_defined),
                    return_target=target & 0xFFFFFFFF,
                )
            current = self.by_rva[target]
        raise _UnsupportedSemantics("component execution exceeded the finite step budget")

def _component_entries(
    units: Mapping[str, Mapping[str, object]],
) -> list[Mapping[str, object]]:
    member_rvas = {_unit_rva(row) for row in units.values()}
    incoming: set[int] = set()
    for row in units.values():
        outcome = _object(
            _object(row.get("semantics"), "machine semantics").get("outcome"),
            "outcome",
        )
        for key in ("target_rva", "true_target_rva", "false_target_rva"):
            value = outcome.get(key)
            if isinstance(value, int) and value in member_rvas:
                incoming.add(value)
    return sorted(
        (row for row in units.values() if _unit_rva(row) not in incoming),
        key=_unit_rva,
    )


def _bind_machine_input(
    parameter: Mapping[str, object],
    value: object,
    state: dict[str, int],
    memory: _MachineMemory,
    units: Mapping[str, Mapping[str, object]],
    *,
    source_abi: str,
) -> int:
    source = _object(parameter.get("machine_source"), "parameter machine source")
    if (
        logical_type_kind(parameter.get("type"), source_abi=source_abi)
        in {"read_only_bytes", "nul_terminated_bytes"}
    ):
        byte_values = _normalize_argument(
            parameter,
            value,
            "machine read-only bytes input",
            source_abi=source_abi,
        )
        machine_value = memory.allocate(byte_values)  # type: ignore[arg-type]
    else:
        machine_value = int(
            _normalize_argument(
                parameter, value, "machine scalar input", source_abi=source_abi
            )
        )
    evidence = _object(source.get("evidence"), "parameter evidence")
    unit = units.get(_string(evidence.get("unit_id"), "parameter evidence unit"))
    if unit is None:
        raise _UnsupportedSemantics("parameter evidence is outside the component")
    _json_pointer(
        unit, _string(evidence.get("json_pointer"), "parameter evidence pointer")
    )
    kind = source.get("kind")
    if kind == "register":
        state[_string(source.get("name"), "parameter register")] = (
            machine_value & 0xFFFFFFFF
        )
        return machine_value & 0xFFFFFFFF
    expression = source.get("expression")
    if (
        kind == "expression"
        and isinstance(expression, Mapping)
        and expression.get("op") == "load"
    ):
        address = _eval_expr(expression.get("address"), state, memory)
        _write_memory(
            memory,
            address,
            int(expression.get("width", 4)),
            machine_value,
        )
        return machine_value & 0xFFFFFFFF
    raise _UnsupportedSemantics("logical parameter source cannot be initialized")


def _validate_memory_views(
    parameters: Sequence[Mapping[str, object]],
    arguments: Mapping[str, object],
    *,
    source_abi: str,
) -> None:
    for parameter in parameters:
        kind = logical_type_kind(parameter.get("type"), source_abi=source_abi)
        if kind not in {"read_only_bytes", "nul_terminated_bytes"}:
            continue
        identity = _string(parameter.get("id"), "byte-pointer parameter id")
        buffer = arguments.get(identity)
        if not isinstance(buffer, list):
            raise _UnsupportedSemantics(
                f"byte-pointer parameter {identity} has no declared byte buffer"
            )
        if kind == "nul_terminated_bytes":
            if 0 not in buffer:
                raise _UnsupportedSemantics(
                    f"byte-pointer parameter {identity} has no NUL terminator"
                )
            continue
        view = _object(parameter.get("memory_view"), "byte-pointer memory view")
        extent_id = _string(
            view.get("extent_parameter_id"), "byte-pointer extent parameter id"
        )
        extent = arguments.get(extent_id)
        if (
            not isinstance(extent, int)
            or isinstance(extent, bool)
            or extent < 0
            or extent > 0xFFFFFFFF
        ):
            raise _UnsupportedSemantics(
                f"byte-pointer parameter {identity} has an invalid extent"
            )
        if extent > len(buffer):
            declared_bytes = len(buffer)
            raise _UnsupportedSemantics(
                f"byte-pointer parameter {identity} has {declared_bytes} "
                f"declared bytes but extent {extent}"
            )


def _eval_expr(value: object, state: Mapping[str, int], memory: _MachineMemory) -> int:
    expression = _object(value, "machine expression")
    op = expression.get("op")
    args = expression.get("args", [])
    if op == "const":
        return int(expression.get("value", 0)) & _mask(
            int(expression.get("width", 32))
        )
    if op == "reg" or op == "flag":
        return int(state.get(_string(expression.get("name"), "machine state name"), 0))
    if op == "call_response":
        return int(
            state.get(
                call_register_key(
                    int(expression.get("call_index", -1)),
                    _string(expression.get("register"), "call response register"),
                ),
                0,
            )
        )
    if op == "call_flag":
        return int(
            state.get(
                call_flag_key(
                    int(expression.get("call_index", -1)),
                    _string(expression.get("flag"), "call response flag"),
                ),
                0,
            )
        )
    if op == "false":
        return 0
    if op == "true":
        return 1
    if op == "load":
        address = _eval_expr(expression.get("address"), state, memory)
        return _read_memory(memory, address, int(expression.get("width", 4)))
    raw_args = _array(args, f"{op} arguments")
    if op == "ite":
        if len(raw_args) != 3:
            raise _UnsupportedSemantics(
                "machine ite expression must have three arguments"
            )
        condition = (
            _eval_expr(raw_args[0], state, memory)
            if isinstance(raw_args[0], Mapping)
            else int(raw_args[0])
        )
        selected = raw_args[1] if condition else raw_args[2]
        return (
            _eval_expr(selected, state, memory)
            if isinstance(selected, Mapping)
            else int(selected)
        )
    values = [
        _eval_expr(arg, state, memory) if isinstance(arg, Mapping) else int(arg)
        for arg in raw_args
    ]
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
    if op == "mul32":
        return (values[0] * values[1]) & 0xFFFFFFFF
    if op == "not32":
        return (~values[0]) & 0xFFFFFFFF
    if op == "sign_extend":
        if len(values) != 2:
            raise _UnsupportedSemantics(
                "machine sign_extend expression must have two arguments"
            )
        width, item = values
        if width < 1 or width > 32:
            raise _UnsupportedSemantics(
                "machine sign_extend source width must be between 1 and 32 bits"
            )
        sign = 1 << (width - 1)
        narrowed = item & _mask(width)
        return ((narrowed ^ sign) - sign) & 0xFFFFFFFF
    if op == "eq":
        return int(values[0] == values[1])
    if op == "ult32":
        return int((values[0] & 0xFFFFFFFF) < (values[1] & 0xFFFFFFFF))
    if op == "not":
        return int(not values[0])
    if op == "and_bool":
        return int(all(values))
    if op == "or_bool":
        return int(any(values))
    if op == "xor_bool":
        return int(bool(values[0]) != bool(values[1]))
    if op == "eq_bool":
        return int(bool(values[0]) == bool(values[1]))
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
    if op == "add_overflow":
        width, left, right, result = values
        sign = 1 << (width - 1)
        return int(((~(left ^ right)) & (left ^ result) & sign) != 0)
    raise _UnsupportedSemantics(f"unsupported machine expression operation {op!r}")


def _initial_state() -> dict[str, int]:
    state = {name: 0 for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")}
    state.update({name: 0 for name in ("cf", "zf", "sf", "of", "pf", "df")})
    state["esp"] = 0x00100000
    return state


def _read_memory(memory: _MachineMemory, address: int, width: int) -> int:
    return memory.read(address, width)


def _write_memory(memory: _MachineMemory, address: int, width: int, value: int) -> None:
    memory.write(address, width, value)


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


def _adapter_header_path(
    adapter_plan: Path, payload: Mapping[str, object]
) -> Path:
    manifest = (
        adapter_plan / "adapter-plan.json" if adapter_plan.is_dir() else adapter_plan
    )
    artifact = _object(
        _object(payload.get("artifacts"), "component adapter artifacts").get(
            "logical_abi_header"
        ),
        "logical ABI header artifact",
    )
    return manifest.parent / _string(
        artifact.get("path"), "logical ABI header artifact path"
    )


def _adapter_entry_ids(adapter: Mapping[str, object]) -> tuple[str, ...]:
    values = adapter.get("entry_unit_ids")
    if (
        not isinstance(values, list)
        or len(values) != 1
        or not isinstance(values[0], str)
        or not values[0]
    ):
        raise _UnsupportedSemantics(
            "logical-object-c-v1 evidence requires one checked adapter entry"
        )
    return (values[0],)


def _unit_rva(row: Mapping[str, object]) -> int:
    source = _object(row.get("source"), "machine source")
    original = _object(source.get("original"), "original span")
    return int(original["rva_start"])


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
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


__all__ = ["produce_component_evidence"]
