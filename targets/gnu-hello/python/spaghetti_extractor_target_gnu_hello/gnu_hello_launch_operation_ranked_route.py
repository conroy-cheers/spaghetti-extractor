"""Generate the exact GNU hello callback-to-interpreter route interface.

The generator binds static route anchors to the candidate PE and to the
existing checked launch/operation inventories.  It deliberately does not
claim that the candidate traverses the validation loop: that universal fact
must be supplied as an ``ExactNativeSilentRankedRoute`` proved from exact
block replays and a decreasing machine-state invariant.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import capstone
from capstone import x86_const

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_bytes, write_json


GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MODULE = (
    "GeneratedRelationalInterpreterGnuHelloLaunchOperationRankedRoute"
)
GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MANIFEST = (
    "gnu-hello-launch-operation-ranked-route.json"
)
GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_FORMAT = (
    "stage-a-gnu-hello-launch-operation-ranked-route-v1"
)

GNU_HELLO_CALLBACK_BOUNDARY_RVA = 278423
GNU_HELLO_INTERPRETER_STEP_RVA = 285378
GNU_HELLO_TRANSFER_COUNT = 5697

_U32_LIMIT = 1 << 32
_LOCAL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_NAMESPACE = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)


class GnuHelloLaunchOperationRankedRouteError(StageAInputError):
    """The concrete candidate route artifacts are stale or malformed."""


@dataclass(frozen=True)
class ExactDirectCallAnchor:
    instruction_rva: int
    instruction_bytes: bytes
    target_rva: int
    continuation_rva: int
    role: str

    def payload(self) -> dict[str, object]:
        return {
            "role": self.role,
            "instruction_rva": self.instruction_rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "target_rva": self.target_rva,
            "continuation_rva": self.continuation_rva,
        }


@dataclass(frozen=True)
class ExactLoopAnchor:
    instruction_rva: int
    instruction_bytes: bytes
    mnemonic: str
    role: str
    successors: tuple[int, ...]
    target_rva: int | None = None

    def payload(self) -> dict[str, object]:
        return {
            "role": self.role,
            "instruction_rva": self.instruction_rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "mnemonic": self.mnemonic,
            "successors": list(self.successors),
            "target_rva": self.target_rva,
        }


@dataclass(frozen=True)
class GnuHelloLaunchOperationRankedRouteSpec:
    module_name: str = GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MODULE
    namespace: str = (
        "StageA.GeneratedRelational."
        "InterpreterGnuHelloLaunchOperationRankedRoute"
    )
    launch_graph_module: str = (
        "GeneratedRelationalInterpreterNativeLaunchGraph"
    )
    launch_graph_namespace: str = (
        "StageA.GeneratedRelational.InterpreterNativeLaunchGraph"
    )
    operation_module: str = (
        "GeneratedRelationalInterpreterKernelOperationInstantiation"
    )
    operation_namespace: str = (
        "StageA.GeneratedRelational.InterpreterKernelOperationInstantiation"
    )
    boundary_rva: int = GNU_HELLO_CALLBACK_BOUNDARY_RVA
    operation_entry_rva: int = GNU_HELLO_INTERPRETER_STEP_RVA


@dataclass(frozen=True)
class GnuHelloLaunchOperationRankedRoutePlan:
    spec: GnuHelloLaunchOperationRankedRouteSpec
    candidate_sha256: str
    candidate_size: int
    direct_calls: tuple[ExactDirectCallAnchor, ...]
    loop_anchors: tuple[ExactLoopAnchor, ...]

    @property
    def complete(self) -> bool:
        return False

    def payload(self) -> dict[str, object]:
        return {
            "format": GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_FORMAT,
            "acceptance_authority": False,
            "proof_authority": False,
            "complete": self.complete,
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "boundary_rva": self.spec.boundary_rva,
            "operation_entry_rva": self.spec.operation_entry_rva,
            "transfer_validation_loop": {
                "record_count": GNU_HELLO_TRANSFER_COUNT,
                "body_rva": 289802,
                "rank_check_rva": 289875,
                "back_edge_rva": 289883,
                "program_lookup_call_rva": 289855,
                "final_program_lookup_call_rva": 289892,
                "required_rank": (
                    "5697 - i at the outer loop header, composed with the "
                    "checked rank of stage_b_program_lookup"
                ),
            },
            "exact_direct_call_anchors": [
                anchor.payload() for anchor in self.direct_calls
            ],
            "exact_loop_anchors": [
                anchor.payload() for anchor in self.loop_anchors
            ],
            "lean": {
                "module": self.spec.module_name,
                "namespace": self.spec.namespace,
                "certificate": (
                    "GeneratedGnuHelloLaunchOperationRankedRouteCertificate"
                ),
                "ranked_route": (
                    "GeneratedGnuHelloLaunchOperationRankedRoute"
                ),
            },
            "remaining_proof_obligations": [
                {
                    "id": "launch-operation:callback-frame",
                    "rva": self.spec.boundary_rva,
                    "reason": (
                        "derive ExactNativeCallbackWrapperBoundaryFrame from "
                        "the exact launch replay and callback stack words"
                    ),
                },
                {
                    "id": "launch-operation:callback-success-invariant",
                    "rva": self.spec.boundary_rva,
                    "reason": (
                        "strengthen the callback boundary with the exact "
                        "candidate context, header, buffer, helper-result, "
                        "and stack-bound facts needed to rule out every "
                        "fail-fast return before runtime validation"
                    ),
                },
                {
                    "id": "launch-operation:replay-gap",
                    "rva": self.spec.boundary_rva,
                    "reason": (
                        "generate checked candidate block replay for the "
                        "callback and runtime span from RVA 278423 through "
                        "runFunction RVA 288298; the native launch graph ends "
                        "at the former and the operation graph begins at the "
                        "latter"
                    ),
                },
                {
                    "id": "launch-operation:validation-invariant",
                    "rva": 289875,
                    "reason": (
                        "prove the candidate runtime validation state, PE "
                        "context, TEB stack bounds, sorted 5697-entry transfer "
                        "table, and nested programLookup loop are preserved "
                        "while a well-founded rank decreases"
                    ),
                },
                {
                    "id": "launch-operation:checked-progress",
                    "rva": self.spec.boundary_rva,
                    "reason": (
                        "instantiate every ranked progress chunk from exact "
                        "candidate block/graph replay through interpreterStep"
                    ),
                },
            ],
        }


_DIRECT_CALL_SPECS = (
    (278627, 291704, "callback-to-runtime"),
    (291943, 291532, "runtime-to-initialized-run"),
    (291664, 288298, "initialized-run-to-runFunction"),
    (288395, 285378, "runFunction-to-interpreterStep"),
)

_LOOP_SPECS = (
    (289802, "mov", "transfer-rva-load", (289805,), None),
    (289855, "call", "per-record-programLookup", (285217,), 285217),
    (289871, "add", "outer-rank-decrement", (289875,), None),
    (289875, "mov", "transfer-count-5697", (289880,), None),
    (289880, "cmp", "outer-rank-check", (289883,), None),
    (289883, "jb", "outer-back-edge", (289802, 289885), 289802),
    (289892, "call", "entry-programLookup", (285217,), 285217),
)


def build_gnu_hello_launch_operation_ranked_route_plan(
    *,
    candidate_pe: Path | str,
    native_launch_graph_plan: Path | str,
    operation_instantiation_manifest: Path | str,
    spec: GnuHelloLaunchOperationRankedRouteSpec | None = None,
) -> GnuHelloLaunchOperationRankedRoutePlan:
    selected = spec or GnuHelloLaunchOperationRankedRouteSpec()
    _validate_spec(selected)
    candidate_path = Path(candidate_pe)
    candidate_bytes = candidate_path.read_bytes()
    candidate_sha256 = sha256_bytes(candidate_bytes)
    launch = _read_object(native_launch_graph_plan, "native launch graph")
    operation = _read_object(
        operation_instantiation_manifest, "operation instantiation"
    )
    _validate_launch_artifact(launch, selected, candidate_sha256)
    _validate_operation_artifact(operation, selected, candidate_sha256)

    binary = _parse_stage_a_pe(candidate_path)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise GnuHelloLaunchOperationRankedRouteError(
                "launch-operation route requires an x86 PE32 candidate"
            )
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoder.detail = True
        direct_calls = tuple(
            _exact_direct_call(
                binary, decoder, instruction_rva, target_rva, role
            )
            for instruction_rva, target_rva, role in _DIRECT_CALL_SPECS
        )
        loop_anchors = tuple(
            _exact_loop_anchor(
                binary,
                decoder,
                instruction_rva,
                mnemonic,
                role,
                successors,
                target_rva,
            )
            for (
                instruction_rva,
                mnemonic,
                role,
                successors,
                target_rva,
            ) in _LOOP_SPECS
        )
        count = next(
            anchor
            for anchor in loop_anchors
            if anchor.role == "transfer-count-5697"
        )
        decoded = _decode_one(binary, decoder, count.instruction_rva)
        if (
            len(decoded.operands) != 2
            or decoded.operands[1].type != x86_const.X86_OP_IMM
            or (int(decoded.operands[1].imm) & (_U32_LIMIT - 1))
            != GNU_HELLO_TRANSFER_COUNT
        ):
            raise GnuHelloLaunchOperationRankedRouteError(
                "transfer-loop count instruction is not the exact 5697 "
                "record bound"
            )
    finally:
        binary.pe.close()

    return GnuHelloLaunchOperationRankedRoutePlan(
        spec=selected,
        candidate_sha256=candidate_sha256,
        candidate_size=len(candidate_bytes),
        direct_calls=direct_calls,
        loop_anchors=loop_anchors,
    )


def gnu_hello_launch_operation_ranked_route_source(
    plan: GnuHelloLaunchOperationRankedRoutePlan,
) -> str:
    spec = plan.spec
    anchors = ",\n  ".join(
        "{ instruction := "
        f"{{ rva := {anchor.instruction_rva}, "
        f"bytes := {_lean_bytes(anchor.instruction_bytes)} }}, "
        f"targetRva := {anchor.target_rva} }}"
        for anchor in plan.direct_calls
    )
    loop_anchors = ",\n  ".join(
        "{ instruction := "
        f"{{ rva := {anchor.instruction_rva}, "
        f"bytes := {_lean_bytes(anchor.instruction_bytes)} }}, "
        f"successors := {_lean_nats(anchor.successors)} }}"
        for anchor in plan.loop_anchors
    )
    return f"""import StageA.RelationalInterpreterMixedLaunchOperationRankedRoute
import StageA.{spec.launch_graph_module}
import StageA.{spec.operation_module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedLaunchOperationBridge
open StageA.Relational.InterpreterMixedLaunchOperationRankedRoute
open StageA.Relational.InterpreterNativeWorld
open {spec.launch_graph_namespace}
open {spec.operation_namespace}

def generatedGnuHelloLaunchOperationDirectCalls :
    List ExactNativeDirectCallAnchor := [
  {anchors}
]

theorem generatedGnuHelloLaunchOperationDirectCallsChecked :
    (generatedGnuHelloLaunchOperationDirectCalls.all fun anchor =>
      anchor.checked generatedNativeLaunchGraphCandidatePe
        generatedNativeLaunchGraphImports) = true := by
  decide +kernel

def generatedGnuHelloLaunchOperationLoopAnchors :
    List ExactNativeControlAnchor := [
  {loop_anchors}
]

theorem generatedGnuHelloLaunchOperationLoopAnchorsChecked :
    (generatedGnuHelloLaunchOperationLoopAnchors.all fun anchor =>
      anchor.checked generatedNativeLaunchGraphCandidatePe
        generatedNativeLaunchGraphImports) = true := by
  decide +kernel

theorem generatedGnuHelloCallbackBoundaryChecked :
    generatedNativeLaunchGraphCutpoints.contains
      {{ kind := .dispatch, rva := {spec.boundary_rva} }} = true := by
  decide +kernel

theorem generatedGnuHelloInterpreterStepEntryChecked :
    generatedNativeOperationRouteAnchors.contains
      ("step:entry", {spec.operation_entry_rva}) = true := by
  decide +kernel

abbrev GeneratedGnuHelloLaunchOperationRankedRoute
    (candidate : ExactNativeWorldProgram)
    (descriptor : NativeCallbackWrapperDescriptor)
    (boundaryBefore : NativeWorldExecution) :=
  ExactNativeLaunchOperationRankedRoute candidate descriptor boundaryBefore

/-- Exact candidate and endpoint binding around the generic ranked route.
The `ranked` field remains the universal validation-loop proof; static anchors
above cannot construct it. -/
structure GeneratedGnuHelloLaunchOperationRankedRouteCertificate
    (candidate : ExactNativeWorldProgram)
    (descriptor : NativeCallbackWrapperDescriptor)
    (boundaryBefore : NativeWorldExecution) where
  candidatePeExact :
    candidate.pe = generatedNativeLaunchGraphCandidatePe
  candidateImportsExact :
    candidate.imports = generatedNativeLaunchGraphImports
  boundaryRvaExact : descriptor.boundaryRva = {spec.boundary_rva}
  operationEntryRvaExact :
    descriptor.operationEntryRva = {spec.operation_entry_rva}
  ranked :
    GeneratedGnuHelloLaunchOperationRankedRoute candidate descriptor
      boundaryBefore

theorem GeneratedGnuHelloLaunchOperationRankedRouteCertificate.prefixExists
    (certificate :
      GeneratedGnuHelloLaunchOperationRankedRouteCertificate candidate
        descriptor boundaryBefore) :
    Nonempty (ExactNativeLaunchOperationPrefix candidate descriptor
      boundaryBefore) :=
  certificate.ranked.prefixExists

#print axioms generatedGnuHelloLaunchOperationDirectCallsChecked
#print axioms generatedGnuHelloLaunchOperationLoopAnchorsChecked
#print axioms generatedGnuHelloCallbackBoundaryChecked
#print axioms generatedGnuHelloInterpreterStepEntryChecked
#print axioms
  GeneratedGnuHelloLaunchOperationRankedRouteCertificate.prefixExists

end {spec.namespace}
"""


def write_gnu_hello_launch_operation_ranked_route(
    out: Path | str,
    *,
    candidate_pe: Path | str,
    native_launch_graph_plan: Path | str,
    operation_instantiation_manifest: Path | str,
    spec: GnuHelloLaunchOperationRankedRouteSpec | None = None,
) -> GnuHelloLaunchOperationRankedRoutePlan:
    plan = build_gnu_hello_launch_operation_ranked_route_plan(
        candidate_pe=candidate_pe,
        native_launch_graph_plan=native_launch_graph_plan,
        operation_instantiation_manifest=operation_instantiation_manifest,
        spec=spec,
    )
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{plan.spec.module_name}.lean").write_text(
        gnu_hello_launch_operation_ranked_route_source(plan),
        encoding="ascii",
    )
    write_json(
        output / GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MANIFEST,
        plan.payload(),
    )
    return plan


def _read_object(path: Path | str, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"cannot read {label}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise GnuHelloLaunchOperationRankedRouteError(
            f"{label} must be a JSON object"
        )
    return value


def _validate_launch_artifact(
    launch: Mapping[str, Any],
    spec: GnuHelloLaunchOperationRankedRouteSpec,
    candidate_sha256: str,
) -> None:
    if (
        launch.get("format")
        != "stage-a-relational-interpreter-native-launch-graph-v1"
    ):
        raise GnuHelloLaunchOperationRankedRouteError(
            "unsupported native launch graph format"
        )
    if launch.get("acceptance_authority") is not False:
        raise GnuHelloLaunchOperationRankedRouteError(
            "native launch graph must remain non-authoritative"
        )
    if launch.get("candidate_sha256") != candidate_sha256:
        raise GnuHelloLaunchOperationRankedRouteError(
            "native launch graph candidate hash mismatch"
        )
    cutpoints = launch.get("cutpoints")
    if not isinstance(cutpoints, list) or {
        "kind": "dispatch",
        "rva": spec.boundary_rva,
    } not in cutpoints:
        raise GnuHelloLaunchOperationRankedRouteError(
            "native launch graph omits the callback dispatch boundary"
        )


def _validate_operation_artifact(
    operation: Mapping[str, Any],
    spec: GnuHelloLaunchOperationRankedRouteSpec,
    candidate_sha256: str,
) -> None:
    if (
        operation.get("format")
        != "stage-a-relational-interpreter-kernel-operation-instantiation-v1"
    ):
        raise GnuHelloLaunchOperationRankedRouteError(
            "unsupported operation-instantiation format"
        )
    if (
        operation.get("acceptance_authority") is not False
        or operation.get("proof_authority") is not False
    ):
        raise GnuHelloLaunchOperationRankedRouteError(
            "operation-instantiation input must remain non-authoritative"
        )
    candidate = operation.get("candidate")
    if (
        not isinstance(candidate, Mapping)
        or candidate.get("sha256") != candidate_sha256
    ):
        raise GnuHelloLaunchOperationRankedRouteError(
            "operation-instantiation candidate hash mismatch"
        )
    routes = operation.get("checked_native_route_inventory")
    anchors = routes.get("anchors") if isinstance(routes, Mapping) else None
    if (
        not isinstance(anchors, Mapping)
        or anchors.get("step:entry") != spec.operation_entry_rva
    ):
        raise GnuHelloLaunchOperationRankedRouteError(
            "operation-instantiation input omits the exact interpreterStep "
            "entry"
        )


def _decode_one(binary: Any, decoder: capstone.Cs, rva: int) -> Any:
    if not 0 <= rva < _U32_LIMIT:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"instruction RVA {rva!r} is outside the PE32 range"
        )
    raw = bytes(binary.pe.get_data(rva, 15))
    rows = list(decoder.disasm(raw, binary.image_base + rva, count=1))
    if len(rows) != 1 or int(rows[0].address) != binary.image_base + rva:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"cannot decode exact candidate instruction at RVA {rva:#x}"
        )
    instruction = rows[0]
    data = bytes(instruction.bytes)
    if not data or bytes(binary.pe.get_data(rva, len(data))) != data:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"candidate instruction at RVA {rva:#x} is not byte exact"
        )
    return instruction


def _exact_direct_call(
    binary: Any,
    decoder: capstone.Cs,
    instruction_rva: int,
    target_rva: int,
    role: str,
) -> ExactDirectCallAnchor:
    instruction = _decode_one(binary, decoder, instruction_rva)
    if not instruction.group(capstone.CS_GRP_CALL):
        raise GnuHelloLaunchOperationRankedRouteError(
            f"{role} anchor at {instruction_rva:#x} is not a call"
        )
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != x86_const.X86_OP_IMM:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"{role} anchor at {instruction_rva:#x} is not a direct call"
        )
    absolute = int(operands[0].imm) & (_U32_LIMIT - 1)
    observed = absolute - binary.image_base
    if observed != target_rva:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"{role} anchor targets {observed:#x}, expected {target_rva:#x}"
        )
    return ExactDirectCallAnchor(
        instruction_rva=instruction_rva,
        instruction_bytes=bytes(instruction.bytes),
        target_rva=target_rva,
        continuation_rva=instruction_rva + int(instruction.size),
        role=role,
    )


def _exact_loop_anchor(
    binary: Any,
    decoder: capstone.Cs,
    instruction_rva: int,
    mnemonic: str,
    role: str,
    successors: tuple[int, ...],
    target_rva: int | None,
) -> ExactLoopAnchor:
    instruction = _decode_one(binary, decoder, instruction_rva)
    if instruction.mnemonic.lower() != mnemonic:
        raise GnuHelloLaunchOperationRankedRouteError(
            f"{role} anchor at {instruction_rva:#x} is "
            f"{instruction.mnemonic}, expected {mnemonic}"
        )
    if target_rva is not None:
        operands = instruction.operands
        if len(operands) != 1 or operands[0].type != x86_const.X86_OP_IMM:
            raise GnuHelloLaunchOperationRankedRouteError(
                f"{role} anchor at {instruction_rva:#x} has no direct target"
            )
        observed = (
            int(operands[0].imm) & (_U32_LIMIT - 1)
        ) - binary.image_base
        if observed != target_rva:
            raise GnuHelloLaunchOperationRankedRouteError(
                f"{role} anchor targets {observed:#x}, expected "
                f"{target_rva:#x}"
            )
    return ExactLoopAnchor(
        instruction_rva=instruction_rva,
        instruction_bytes=bytes(instruction.bytes),
        mnemonic=mnemonic,
        role=role,
        successors=successors,
        target_rva=target_rva,
    )


def _validate_spec(spec: GnuHelloLaunchOperationRankedRouteSpec) -> None:
    if _LOCAL_NAME.fullmatch(spec.module_name) is None:
        raise ValueError("module_name must be one local Lean identifier")
    for label, value in (
        ("namespace", spec.namespace),
        ("launch_graph_namespace", spec.launch_graph_namespace),
        ("operation_namespace", spec.operation_namespace),
    ):
        if _NAMESPACE.fullmatch(value) is None:
            raise ValueError(f"{label} is not a Lean namespace")
    for label, value in (
        ("launch_graph_module", spec.launch_graph_module),
        ("operation_module", spec.operation_module),
    ):
        if _LOCAL_NAME.fullmatch(value) is None:
            raise ValueError(f"{label} must be one local Lean identifier")
    for label, value in (
        ("boundary_rva", spec.boundary_rva),
        ("operation_entry_rva", spec.operation_entry_rva),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{label} must be an unsigned 32-bit integer")
        if not 0 <= value < _U32_LIMIT:
            raise ValueError(f"{label} lies outside the PE32 range")
    if spec.boundary_rva == spec.operation_entry_rva:
        raise ValueError("boundary and operation RVAs must differ")


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def _lean_nats(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


__all__ = [
    "GNU_HELLO_CALLBACK_BOUNDARY_RVA",
    "GNU_HELLO_INTERPRETER_STEP_RVA",
    "GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_FORMAT",
    "GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MANIFEST",
    "GNU_HELLO_LAUNCH_OPERATION_RANKED_ROUTE_MODULE",
    "GNU_HELLO_TRANSFER_COUNT",
    "GnuHelloLaunchOperationRankedRouteError",
    "GnuHelloLaunchOperationRankedRoutePlan",
    "GnuHelloLaunchOperationRankedRouteSpec",
    "build_gnu_hello_launch_operation_ranked_route_plan",
    "gnu_hello_launch_operation_ranked_route_source",
    "write_gnu_hello_launch_operation_ranked_route",
]
