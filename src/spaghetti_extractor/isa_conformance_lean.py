"""Concrete evaluator for the authoritative Lean IA-32 semantics.

This module generates Lean source and executes the same decoder and machine
semantics used by Stage A. Its reports are assurance evidence only and never
participate in the whole-program acceptance theorem.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from .isa_conformance import (
    BackendDescriptor,
    BackendKind,
    BackendObservation,
    ControlClass,
    ExpectedOutcome,
    FaultClass,
    FSState,
    GPRState,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    MachineState,
    ObservationStatus,
    ObservedMemoryRegion,
    ReportCounts,
    ReportQualification,
    ReportTrust,
    X87State,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_report,
    serialize_isa_conformance_report,
)
from .relational.lean.compiler import _run_lean_relational
from .isa_semantic_forms import lean_semantic_form_classifier_sha256


LEAN_ISA_BACKEND_ID = "stage-a-lean-machine-semantics"
LEAN_ISA_BACKEND_VERSION = "formal-default-v1"
_ABSENT_LEAN_X87_FIELDS = (
    "tag_word",
    "last_opcode",
    "instruction_pointer",
    "data_pointer",
)
_PREFIXES = {
    0x26,
    0x2E,
    0x36,
    0x3E,
    0x64,
    0x65,
    0x66,
    0x67,
    0xF0,
    0xF2,
    0xF3,
}


def _lean_nat(value: int) -> str:
    return f"0x{value:x}"


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _lean_list(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"


def _instruction_opcode(instruction: bytes) -> int:
    index = 0
    while index < len(instruction) and instruction[index] in _PREFIXES:
        index += 1
    return instruction[index] if index < len(instruction) else -1


def _unsupported_reason(case: Any) -> str | None:
    if case.profile.cpu not in {"i386", "i486", "i686", "haswell"}:
        return f"unsupported Lean CPU profile {case.profile.cpu!r}"
    if case.defined_outputs.fs.selector != 0:
        return "Lean MachineState does not represent the FS selector"
    opcode = _instruction_opcode(case.instruction_bytes)
    if opcode == 0x9B or 0xD8 <= opcode <= 0xDF:
        return (
            "x87 execution is relationally parametric and is not yet "
            "concretely hardware-qualified"
        )
    for field in _ABSENT_LEAN_X87_FIELDS:
        if getattr(case.defined_outputs.x87, field) != 0:
            return f"Lean MachineState does not represent x87 {field}"
    if case.expected.fault not in {FaultClass.NONE, FaultClass.DIVIDE_ERROR}:
        return f"Lean semantics do not model fault {case.expected.fault.value!r}"
    return None


def _flatten_memory(case: Any) -> list[tuple[int, int]]:
    return [
        (region.address + offset, byte)
        for region in case.memory
        for offset, byte in enumerate(region.data)
    ]


def _observed_addresses(case: Any) -> list[int]:
    return [
        mask.address + offset
        for mask in case.defined_outputs.memory
        for offset in range(len(mask.mask))
    ]


def _x87_word(value: bytes) -> int:
    return int.from_bytes(value, "little")


def _lean_instruction_bytes(case: Any) -> str:
    return _lean_list([_lean_nat(value) for value in case.instruction_bytes])


def _lean_cpu_profile(cpu: str) -> str:
    if cpu == "haswell":
        return ".haswell"
    if cpu in {"i386", "i486", "i686"}:
        return ".i686"
    raise ISAConformanceError(f"unsupported Lean CPU profile {cpu!r}")


def _lean_input(case: Any) -> str:
    registers = case.initial_state.gprs
    memory = _lean_list(
        [
            "{ address := "
            + _lean_nat(address)
            + ", value := "
            + _lean_nat(value)
            + " }"
            for address, value in _flatten_memory(case)
        ]
    )
    observed = _lean_list(
        [_lean_nat(address) for address in _observed_addresses(case)]
    )
    x87_stack = _lean_list(
        [_lean_nat(_x87_word(value)) for value in case.initial_state.x87.registers]
    )
    return """{
  bytes := %s
  pc := %s
  imageBase := %s
  cpuProfile := %s
  registers := {
    eax := %s
    ebx := %s
    ecx := %s
    edx := %s
    esi := %s
    edi := %s
    ebp := %s
    esp := %s
  }
  eflags := %s
  fsBase := %s
  memory := %s
  undefinedStartSlot := 0
  undefinedValues := []
  undefinedDefault := 0
  x87Stack := %s
  x87Control := %s
  x87Status := %s
  x87Profile := .formalDefaultV1
  observeMemory := %s
}""" % (
        _lean_instruction_bytes(case),
        _lean_nat(case.initial_state.eip - case.image_base),
        _lean_nat(case.image_base),
        _lean_cpu_profile(case.profile.cpu),
        _lean_nat(registers.eax),
        _lean_nat(registers.ebx),
        _lean_nat(registers.ecx),
        _lean_nat(registers.edx),
        _lean_nat(registers.esi),
        _lean_nat(registers.edi),
        _lean_nat(registers.ebp),
        _lean_nat(registers.esp),
        _lean_nat(case.initial_state.eflags),
        _lean_nat(case.initial_state.fs.base),
        memory,
        x87_stack,
        _lean_nat(case.initial_state.x87.control_word),
        _lean_nat(case.initial_state.x87.status_word),
        observed,
    )


def _generated_module(
    cases: list[Any], *, executable_case_ids: set[str]
) -> str:
    definitions: list[str] = [
        "import StageA.ISAConformanceRunner",
        "",
        "open StageA.Formal",
        "open Lean",
        "",
        "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0",
        "",
        "def emitISAConformanceClassification (caseId : String)",
        "    (profile : X86CPUProfile) (bytes : Bytes) : IO Unit :=",
        "  IO.println <| Json.compress <| Json.mkObj [",
        '    ("case_id", toJson caseId),',
        '    ("authority", toJson "veto_only"),',
        '    ("semantic_form", match decodeInstructionExactForProfile profile bytes with',
        "      | some decoded => toJson (reprStr decoded.instruction.semanticForm)",
        "      | none => Json.null),",
        '    ("result", Json.mkObj [("status", toJson "classification_only")])',
        "  ]",
        "",
    ]
    for index, case in enumerate(cases):
        if case.id not in executable_case_ids:
            continue
        definitions.extend(
            [
                f"def conformanceInput{index} : ISAConformanceInput := "
                + _lean_input(case),
                "",
            ]
        )
    definitions.append("def main : IO Unit := do")
    for index, case in enumerate(cases):
        if case.id in executable_case_ids:
            definitions.append(
                "  emitISAConformanceCase "
                + _lean_string(case.id)
                + f" conformanceInput{index}"
            )
        else:
            definitions.append(
                "  emitISAConformanceClassification "
                + _lean_string(case.id)
                + " "
                + _lean_cpu_profile(case.profile.cpu)
                + " "
                + _lean_instruction_bytes(case)
            )
    definitions.append("")
    return "\n".join(definitions)


def _copy_lean_sources(destination: Path) -> None:
    source = Path(__file__).parent / "lean" / "StageA"
    stage_a = destination / "StageA"
    stage_a.mkdir(parents=True)
    for module in (
        "X87",
        "Formal",
        "ISAQualification",
        "ISAConformance",
        "ISAConformanceRunner",
    ):
        shutil.copyfile(source / f"{module}.lean", stage_a / f"{module}.lean")


def _generated_runner_module() -> str:
    return "import StageA.GeneratedISAConformance\n"


def _control_outcome(control: dict[str, Any], image_base: int) -> tuple[ControlClass, int]:
    def absolute_rva(field: str) -> int:
        return (image_base + int(control[field])) & 0xFFFFFFFF

    kind = control.get("kind")
    if kind == "next":
        return ControlClass.FALLTHROUGH, absolute_rva("rva")
    if kind == "returned":
        return ControlClass.RETURN, int(control["target"])
    if kind == "jump":
        return ControlClass.DIRECT_BRANCH, absolute_rva("target_rva")
    if kind == "branch":
        target = "true_target_rva" if control.get("condition") else "false_target_rva"
        return ControlClass.DIRECT_BRANCH, absolute_rva(target)
    if kind == "call":
        return ControlClass.DIRECT_CALL, absolute_rva("target_rva")
    if kind == "indirect_call":
        return ControlClass.INDIRECT_CALL, int(control["target"])
    if kind == "indirect_jump":
        return ControlClass.INDIRECT_BRANCH, int(control["target"])
    if kind == "external_call":
        return ControlClass.INDIRECT_CALL, absolute_rva("return_rva")
    if kind == "external_jump":
        return ControlClass.INDIRECT_BRANCH, 0
    if kind in {
        "bulk_copy",
        "bulk_fill",
        "bulk_scan",
        "checked_continue",
        "atomic_compare_exchange",
    }:
        return ControlClass.FALLTHROUGH, absolute_rva("continuation_rva")
    raise ISAConformanceError(f"unsupported Lean control observation {kind!r}")


def _memory_regions(case: Any, values: list[dict[str, Any]]) -> tuple[ObservedMemoryRegion, ...]:
    by_address = {int(row["address"]): int(row["value"]) for row in values}
    regions: list[ObservedMemoryRegion] = []
    for mask in case.defined_outputs.memory:
        try:
            data = bytes(by_address[mask.address + offset] for offset in range(len(mask.mask)))
        except KeyError as exc:
            raise ISAConformanceError(
                f"Lean omitted observed memory address 0x{int(exc.args[0]):08x}"
            ) from exc
        regions.append(ObservedMemoryRegion(mask.address, data))
    return tuple(regions)


def _machine_state(case: Any, observed: dict[str, Any], eip: int) -> MachineState:
    registers = observed["registers"]
    initial_x87 = case.initial_state.x87
    return MachineState(
        gprs=GPRState(**{name: int(registers[name]) for name in GPRState.__annotations__}),
        eip=eip,
        eflags=int(observed["eflags"]),
        fs=FSState(
            selector=case.initial_state.fs.selector,
            base=int(observed["fs_base"]),
        ),
        x87=X87State(
            control_word=int(observed["x87_control"]),
            status_word=int(observed["x87_status"]),
            tag_word=initial_x87.tag_word,
            last_opcode=initial_x87.last_opcode,
            instruction_pointer=initial_x87.instruction_pointer,
            data_pointer=initial_x87.data_pointer,
            registers=tuple(
                int(value).to_bytes(10, "little")
                for value in observed["x87_stack"]
            ),
        ),
    )


def _complete_observation(case: Any, result: dict[str, Any]) -> BackendObservation:
    status = result.get("status")
    if status == "modeled_fault":
        fault = FaultClass(result["fault"])
        observation = BackendObservation(
            case_id=case.id,
            status=ObservationStatus.MISMATCH,
            final_state=None,
            memory=None,
            actual=ExpectedOutcome(ControlClass.FAULT, fault),
            detail="",
        )
    elif status == "observed":
        observed = result["observation"]
        if observed.get("proof_authority") is not False:
            raise ISAConformanceError("Lean observation claimed proof authority")
        control, eip = _control_outcome(observed["control"], case.image_base)
        observation = BackendObservation(
            case_id=case.id,
            status=ObservationStatus.MISMATCH,
            final_state=_machine_state(case, observed, eip),
            memory=_memory_regions(case, observed["memory"]),
            actual=ExpectedOutcome(control, FaultClass(observed["fault"])),
            detail="",
        )
    else:
        raise ISAConformanceError(f"unexpected complete Lean result {status!r}")
    return replace(
        observation,
        status=(
            ObservationStatus.MATCH if case.matches(observation)
            else ObservationStatus.MISMATCH
        ),
    )


def _report(
    corpus: ISAConformanceCorpus,
    observations: list[BackendObservation],
    *,
    input_sha256: str,
) -> ISAConformanceReport:
    counts = ReportCounts(
        cases=len(observations),
        matched=sum(row.status is ObservationStatus.MATCH for row in observations),
        mismatched=sum(row.status is ObservationStatus.MISMATCH for row in observations),
        unsupported=sum(
            row.status is ObservationStatus.UNSUPPORTED for row in observations
        ),
        errors=sum(row.status is ObservationStatus.ERROR for row in observations),
    )
    if counts.mismatched:
        qualification = ReportQualification.VETOED
    elif counts.unsupported or counts.errors:
        qualification = ReportQualification.UNQUALIFIED
    else:
        qualification = ReportQualification.QUALIFIED
    report = ISAConformanceReport(
        corpus_id=corpus.id,
        input_sha256=input_sha256,
        backend=BackendDescriptor(
            LEAN_ISA_BACKEND_ID,
            BackendKind.SEMANTIC_MODEL,
            LEAN_ISA_BACKEND_VERSION,
        ),
        qualification=qualification,
        observations=tuple(observations),
        counts=counts,
        trust=ReportTrust(),
    )
    payload = serialize_isa_conformance_report(report, corpus=corpus)
    return parse_isa_conformance_report(payload, corpus=corpus)


def _run_lean_isa_conformance(
    corpus: ISAConformanceCorpus,
    *,
    timeout_seconds: int = 300,
) -> tuple[ISAConformanceReport, dict[str, str]]:
    """Evaluate supported cases using the authoritative Lean semantics."""
    if not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")
    input_sha256 = isa_conformance_corpus_sha256(corpus)
    observations_by_id: dict[str, BackendObservation] = {}
    semantic_forms_by_id: dict[str, str] = {}
    runnable: list[Any] = []
    for case in corpus.cases:
        reason = _unsupported_reason(case)
        if reason is None:
            runnable.append(case)
        else:
            observations_by_id[case.id] = BackendObservation(
                case_id=case.id,
                status=ObservationStatus.UNSUPPORTED,
                final_state=None,
                memory=None,
                actual=None,
                detail=reason,
            )
    executable_case_ids = {case.id for case in runnable}
    if corpus.cases:
        if shutil.which("lean") is None:
            for case in runnable:
                observations_by_id[case.id] = BackendObservation(
                    case_id=case.id,
                    status=ObservationStatus.UNSUPPORTED,
                    final_state=None,
                    memory=None,
                    actual=None,
                    detail="Lean executable is unavailable",
                )
        else:
            with tempfile.TemporaryDirectory(prefix="isa-conformance-lean-") as temporary:
                lean_dir = Path(temporary)
                _copy_lean_sources(lean_dir)
                generated = lean_dir / "StageA" / "GeneratedISAConformance.lean"
                generated.write_text(
                    _generated_module(
                        list(corpus.cases),
                        executable_case_ids=executable_case_ids,
                    ),
                    encoding="utf-8",
                )
                compiled = _run_lean_relational(
                    lean_dir,
                    bundle="GeneratedISAConformance",
                    command_timeout_seconds=900,
                )
                if compiled.get("status") != "checked":
                    detail = str(compiled.get("stderr") or compiled.get("stdout"))
                    for case in runnable:
                        observations_by_id[case.id] = BackendObservation(
                            case_id=case.id,
                            status=ObservationStatus.ERROR,
                            final_state=None,
                            memory=None,
                            actual=None,
                            detail="Lean conformance compilation failed: " + detail,
                        )
                else:
                    lean = shutil.which("lean")
                    assert lean is not None
                    runner = lean_dir / "RunGeneratedISAConformance.lean"
                    runner.write_text(
                        _generated_runner_module(),
                        encoding="utf-8",
                    )
                    completed = subprocess.run(
                        [lean, "--trust=0", "--run", runner.name],
                        cwd=lean_dir,
                        env={**os.environ, "LEAN_PATH": "."},
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=timeout_seconds,
                        check=False,
                    )
                    if completed.returncode != 0:
                        detail = completed.stderr or completed.stdout
                        for case in runnable:
                            observations_by_id[case.id] = BackendObservation(
                                case_id=case.id,
                                status=ObservationStatus.ERROR,
                                final_state=None,
                                memory=None,
                                actual=None,
                                detail="Lean conformance execution failed: " + detail,
                            )
                    else:
                        rows = [
                            json.loads(line)
                            for line in completed.stdout.splitlines()
                            if line.strip()
                        ]
                        if len(rows) != len(corpus.cases):
                            raise ISAConformanceError(
                                "Lean conformance runner returned the wrong row count"
                            )
                        cases_by_id = {case.id: case for case in corpus.cases}
                        seen_case_ids: set[str] = set()
                        for row in rows:
                            case_id = row.get("case_id")
                            if row.get("authority") != "veto_only":
                                raise ISAConformanceError(
                                    "Lean conformance row has invalid authority"
                                )
                            if case_id not in cases_by_id or case_id in seen_case_ids:
                                raise ISAConformanceError(
                                    "Lean conformance runner returned an unknown or duplicate case"
                                )
                            seen_case_ids.add(case_id)
                            semantic_form = row.get("semantic_form")
                            if not isinstance(semantic_form, str) or not semantic_form:
                                raise ISAConformanceError(
                                    "Lean conformance row omitted its semantic form"
                                )
                            semantic_forms_by_id[case_id] = semantic_form
                            result = row.get("result")
                            if not isinstance(result, dict):
                                raise ISAConformanceError(
                                    "Lean conformance result must be an object"
                                )
                            if case_id not in executable_case_ids:
                                if result != {"status": "classification_only"}:
                                    raise ISAConformanceError(
                                        "unsupported Lean conformance case was concretely executed"
                                    )
                                continue
                            if result.get("status") in {"observed", "modeled_fault"}:
                                observation = _complete_observation(
                                    cases_by_id[case_id], result
                                )
                            elif result.get("status") == "unsupported":
                                observation = BackendObservation(
                                    case_id=case_id,
                                    status=ObservationStatus.UNSUPPORTED,
                                    final_state=None,
                                    memory=None,
                                    actual=None,
                                    detail=(
                                        f"{result.get('phase', 'unknown')}: "
                                        f"{result.get('detail', '')}"
                                    ),
                                )
                            else:
                                observation = BackendObservation(
                                    case_id=case_id,
                                    status=ObservationStatus.ERROR,
                                    final_state=None,
                                    memory=None,
                                    actual=None,
                                    detail=str(result.get("detail") or "internal Lean error"),
                                )
                            observations_by_id[case_id] = observation
    ordered = [observations_by_id[case.id] for case in corpus.cases]
    return (
        _report(corpus, ordered, input_sha256=input_sha256),
        semantic_forms_by_id,
    )


def run_lean_isa_conformance(
    corpus: ISAConformanceCorpus,
    *,
    timeout_seconds: int = 300,
) -> ISAConformanceReport:
    """Evaluate supported cases using the authoritative Lean semantics."""
    report, _ = _run_lean_isa_conformance(
        corpus, timeout_seconds=timeout_seconds
    )
    return report


def run_lean_isa_conformance_with_forms(
    corpus: ISAConformanceCorpus,
    *,
    timeout_seconds: int = 300,
) -> tuple[ISAConformanceReport, dict[str, str]]:
    """Return concrete observations plus Lean-owned semantic-form identities."""
    return _run_lean_isa_conformance(corpus, timeout_seconds=timeout_seconds)


__all__ = [
    "LEAN_ISA_BACKEND_ID",
    "LEAN_ISA_BACKEND_VERSION",
    "lean_semantic_form_classifier_sha256",
    "run_lean_isa_conformance",
    "run_lean_isa_conformance_with_forms",
]
