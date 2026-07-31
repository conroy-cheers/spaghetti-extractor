"""Audit concrete Step/Run/Invoke operation instantiation.

This phase binds the complete checked semantic-record inventory to the exact
state-machine rows and operation plans.  It never turns an operation plan's
``remaining_proof_premises`` strings into proof authority.  Instead it reports
the exact Lean checker theorem or generated artifact field that is still
needed to construct the finite semantic call tree and native certificates.

The call-aware abstract and checked semantic relations are structurally
equivalent.  This phase therefore emits a concrete semantic closure term and
reports only native endpoint evidence that is genuinely absent.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_closed_call_tree import (
    INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME,
    ExactCheckedSemanticFunctionSpec,
    exact_checked_semantic_function_specs_from_record_packs,
    write_relational_interpreter_kernel_closed_call_tree_bundle,
)
from .interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from .interpreter_kernel_data import INTERPRETER_KERNEL_DATA_FORMAT
from .interpreter_kernel_invoke_operation import (
    INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT,
)
from .interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
)
from .interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
)


INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-operation-instantiation-v1"
)
INTERPRETER_KERNEL_OPERATION_INSTANTIATION_PLAN_FILENAME = (
    "interpreter-kernel-operation-instantiation.json"
)
INTERPRETER_KERNEL_OPERATION_INSTANTIATION_INVENTORY_FILENAME = (
    "finite-checked-semantic-function-inventory.json"
)
INTERPRETER_KERNEL_OPERATION_INSTANTIATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelOperationInstantiation.lean"
)
INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX = (
    "GeneratedRelationalInterpreterKernelOperationBlockFunction"
)
INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE = (
    "GeneratedRelationalInterpreterKernelOperationBlockBundle"
)
INTERPRETER_KERNEL_OPERATION_CANDIDATE_MODULE = (
    "GeneratedRelationalInterpreterKernelOperationCandidate"
)
INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE = (
    "GeneratedRelationalInterpreterKernelOperationCandidateCore"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DATA_INVENTORY_FORMATS = {
    f"stage-a-interpreter-kernel-data-inventory-v{version}"
    for version in range(1, 8)
} | {INTERPRETER_KERNEL_DATA_FORMAT}
_CALL_KINDS = {
    "external_call": "external",
    "internal_call": "internal",
    "indirect_call": "indirect",
}


class RelationalInterpreterKernelOperationInstantiationError(StageAInputError):
    """The supplied GNU operation-instantiation artifacts do not agree."""


@dataclass(frozen=True)
class SemanticStateMachineRow:
    ordinal: int
    source_rva: int
    calls: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class NativeOperationInstructionReplaySpec:
    """One PE-bound instruction in a checked native operation block."""

    ordinal: int
    rva: int
    bytes_hex: str
    mnemonic: str

    @property
    def size(self) -> int:
        return len(self.bytes_hex) // 2

    def payload(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "rva": self.rva,
            "size": self.size,
            "bytes": self.bytes_hex,
            "mnemonic": self.mnemonic,
        }


@dataclass(frozen=True)
class NativeOperationBlockReplaySpec:
    """One exact basic block and its submitted static successor inventory."""

    ordinal: int
    entry_rva: int
    instructions: tuple[NativeOperationInstructionReplaySpec, ...]
    successors: tuple[int, ...]
    terminal_class: str

    @property
    def terminal_rva(self) -> int:
        return self.instructions[-1].rva

    @property
    def byte_length(self) -> int:
        last = self.instructions[-1]
        return last.rva + last.size - self.entry_rva

    @property
    def lean_term(self) -> str:
        return f"block{self.ordinal:04d}"

    def payload(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "entry_rva": self.entry_rva,
            "terminal_rva": self.terminal_rva,
            "byte_length": self.byte_length,
            "terminal_class": self.terminal_class,
            "successors": list(self.successors),
            "instructions": [
                instruction.payload() for instruction in self.instructions
            ],
        }


@dataclass(frozen=True)
class NativeOperationFunctionReplaySpec:
    """One exact candidate function required by the operation closure."""

    ordinal: int
    kernel_ordinal: int
    families: tuple[str, ...]
    role: str
    entry_rva: int
    end_rva: int
    blocks: tuple[NativeOperationBlockReplaySpec, ...]

    @property
    def byte_length(self) -> int:
        return self.end_rva - self.entry_rva

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def instruction_count(self) -> int:
        return sum(len(block.instructions) for block in self.blocks)

    @property
    def lean_term(self) -> str:
        return f"generatedNativeOperationFunctionReplay{self.ordinal:04d}"

    @property
    def kernel_lean_term(self) -> str:
        return f"generatedKernelFunction{self.kernel_ordinal:04d}"

    def payload(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "kernel_ordinal": self.kernel_ordinal,
            "kernel_lean_term": self.kernel_lean_term,
            "families": list(self.families),
            "role": self.role,
            "entry_rva": self.entry_rva,
            "end_rva": self.end_rva,
            "byte_length": self.byte_length,
            "blocks": self.block_count,
            "instructions": self.instruction_count,
            "block_graph": [block.payload() for block in self.blocks],
            "lean_term": self.lean_term,
        }


@dataclass(frozen=True)
class NativeOperationRankedRouteSpec:
    """A compact rank certificate for one function's cutpoint-free regions."""

    function_ordinal: int
    entry_rva: int
    stop_rvas: tuple[int, ...]
    ranks: tuple[tuple[int, int], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "function_ordinal": self.function_ordinal,
            "entry_rva": self.entry_rva,
            "stop_rvas": list(self.stop_rvas),
            "ranks": [
                {"entry_rva": entry_rva, "rank": rank}
                for entry_rva, rank in self.ranks
            ],
        }


@dataclass(frozen=True)
class NativeOperationRankedRouteClusterSpec:
    """One acyclic route from a concrete entry to typed frontier blocks."""

    function_ordinal: int
    cluster_ordinal: int
    source_rva: int
    block_rvas: tuple[int, ...]
    stop_rvas: tuple[int, ...]
    ranks: tuple[tuple[int, int], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "function_ordinal": self.function_ordinal,
            "cluster_ordinal": self.cluster_ordinal,
            "source_rva": self.source_rva,
            "block_rvas": list(self.block_rvas),
            "stop_rvas": list(self.stop_rvas),
            "ranks": [
                {"entry_rva": entry_rva, "rank": rank}
                for entry_rva, rank in self.ranks
            ],
        }


@dataclass(frozen=True)
class OperationInstantiationEndpointGap:
    """One exact missing checker theorem or checked artifact field."""

    identifier: str
    family: str
    kind: str
    artifact: str
    field: str
    lean_type: str
    reason: str
    source_rva: int | None = None
    rva: int | None = None
    target_rvas: tuple[int, ...] = ()

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.identifier,
            "family": self.family,
            "kind": self.kind,
            "artifact": self.artifact,
            "field": self.field,
            "lean_type": self.lean_type,
            "reason": self.reason,
        }
        if self.source_rva is not None:
            result["source_rva"] = self.source_rva
        if self.rva is not None:
            result["rva"] = self.rva
        if self.target_rvas:
            result["target_rvas"] = list(self.target_rvas)
        return result


@dataclass(frozen=True)
class InterpreterKernelOperationInstantiationPlan:
    candidate_path: Path
    kernel_plan_path: Path
    kernel_plan_sha256: str
    state_machine_path: Path
    state_machine_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    step_operation_plan_path: Path
    step_operation_plan_sha256: str
    run_operation_plan_path: Path
    run_operation_plan_sha256: str
    invoke_operation_plan_path: Path
    invoke_operation_plan_sha256: str
    candidate_sha256: str
    candidate_size: int
    shard_size: int
    functions: tuple[ExactCheckedSemanticFunctionSpec, ...]
    call_counts: tuple[tuple[str, int], ...]
    native_function_replays: tuple[NativeOperationFunctionReplaySpec, ...]
    native_route_anchors: tuple[tuple[str, int], ...]
    native_boundary_targets: tuple[tuple[str, tuple[int, ...]], ...]
    native_structural_boundary_targets: tuple[int, ...]
    native_ranked_routes: tuple[NativeOperationRankedRouteSpec, ...]
    native_ranked_route_clusters: tuple[
        NativeOperationRankedRouteClusterSpec, ...
    ]
    missing_source_rva: int
    observed_legacy_premises: tuple[tuple[str, tuple[str, ...]], ...]
    endpoint_gaps: tuple[OperationInstantiationEndpointGap, ...]

    @property
    def constructed(self) -> bool:
        return not self.endpoint_gaps

    def function_inventory_payload(self) -> dict[str, Any]:
        return {
            "format": (
                "stage-a-finite-checked-semantic-function-inventory-v1"
            ),
            "state_machine_sha256": self.state_machine_sha256,
            "kernel_data_inventory_sha256": self.data_inventory_sha256,
            "shard_size": self.shard_size,
            "count": len(self.functions),
            "functions": [
                {
                    "ordinal": ordinal,
                    **function.payload(),
                }
                for ordinal, function in enumerate(self.functions)
            ],
        }

    def payload(self) -> dict[str, Any]:
        native_blocks = [
            block
            for function in self.native_function_replays
            for block in function.blocks
        ]
        terminal_classes: dict[str, int] = {}
        for block in native_blocks:
            terminal_classes[block.terminal_class] = (
                terminal_classes.get(block.terminal_class, 0) + 1
            )
        return {
            "format": INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT,
            "acceptance_authority": False,
            "proof_authority": False,
            "status": "locally_closed" if self.constructed else "incomplete",
            "failure_mode": "none" if self.constructed else "incomplete",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "candidate": {
                    "path": self.candidate_path.name,
                    "sha256": self.candidate_sha256,
                },
                "kernel_plan": {
                    "path": self.kernel_plan_path.name,
                    "sha256": self.kernel_plan_sha256,
                },
                "state_machine": {
                    "path": self.state_machine_path.name,
                    "sha256": self.state_machine_sha256,
                },
                "kernel_data_inventory": {
                    "path": self.data_inventory_path.name,
                    "sha256": self.data_inventory_sha256,
                },
                "step_operation_plan": {
                    "path": self.step_operation_plan_path.name,
                    "sha256": self.step_operation_plan_sha256,
                },
                "run_operation_plan": {
                    "path": self.run_operation_plan_path.name,
                    "sha256": self.run_operation_plan_sha256,
                },
                "invoke_operation_plan": {
                    "path": self.invoke_operation_plan_path.name,
                    "sha256": self.invoke_operation_plan_sha256,
                },
            },
            "checked_semantic_inventory": {
                "records": len(self.functions),
                "shard_size": self.shard_size,
                "missing_source_rva_witness": self.missing_source_rva,
                "call_counts": dict(self.call_counts),
                "inventory": (
                    INTERPRETER_KERNEL_OPERATION_INSTANTIATION_INVENTORY_FILENAME
                ),
            },
            "checked_native_replay_inventory": {
                "functions": len(self.native_function_replays),
                "blocks": len(native_blocks),
                "instructions": sum(
                    function.instruction_count
                    for function in self.native_function_replays
                ),
                "function_replays": [
                    function.payload()
                    for function in self.native_function_replays
                ],
                "execution_equalities_submitted": 0,
                "path_equalities_submitted": 0,
                "post_state_equalities_submitted": 0,
            },
            "checked_native_route_inventory": {
                "functions": len(self.native_function_replays),
                "blocks": len(native_blocks),
                "edges": sum(
                    len(block.successors) for block in native_blocks
                ),
                "terminal_classes": dict(sorted(terminal_classes.items())),
                "exact_block_graph_bound": True,
                "generic_trace_checker": (
                    "CheckedNativeOperationRunningTrace"
                ),
                "generic_cutpoint_checker": (
                    "CheckedNativeOperationRunningCutpoint"
                ),
                "generic_route_checker": (
                    "CheckedNativeOperationStateRoute"
                ),
                "generic_graph_checker": (
                    "CheckedNativeOperationGraphSuccessor"
                ),
                "graph_closure_theorem": (
                    "generatedNativeOperationGraphClosedWithBoundaries"
                ),
                "boundary_route_checker": (
                    "CheckedNativeOperationStateBoundaryRoute"
                ),
                "boundary_route_checker_imported": True,
                "boundary_route_checker_wired": False,
                "checked_block_certificates_constructed": True,
                "checked_block_bundle": (
                    INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE
                ),
                "candidate_program": (
                    "generatedClosedKernelOperationNativeProgram"
                ),
                "candidate_indirect_targets": (
                    "generatedNativeIndirectTargetInventory"
                ),
                "candidate_callback_binding": (
                    "generatedClosedKernelOperationCallbackBinding"
                ),
                "candidate_indirect_targets_wired": True,
                "anchors": {
                    identifier: rva
                    for identifier, rva in self.native_route_anchors
                },
                "specialized_boundary_targets": {
                    identifier: list(targets)
                    for identifier, targets in self.native_boundary_targets
                },
                "structural_boundary_targets": list(
                    self.native_structural_boundary_targets
                ),
                "ranked_route_checker": (
                    "checkedNativeOperationRankedRouteCertificate"
                ),
                "ranked_route_policies": [
                    route.payload() for route in self.native_ranked_routes
                ],
                "ranked_route_clusters": [
                    cluster.payload()
                    for cluster in self.native_ranked_route_clusters
                ],
            },
            # Broad premise labels from predecessor plans are diagnostic input
            # only.  They are deliberately not propagated as this phase's
            # proof interface.
            "observed_legacy_premises": {
                operation: list(premises)
                for operation, premises in self.observed_legacy_premises
            },
            "remaining_proof_premises": [],
            "missing_checked_endpoints": [
                gap.payload() for gap in self.endpoint_gaps
            ],
            "result": {
                "constructed": self.constructed,
                "semantic_bindings_term": (
                    "generatedFiniteCheckedSemanticFunctionBindings"
                ),
                "run_theorem": (
                    "generatedRunFunctionOperationRefinesUsingClosed"
                    if self.constructed
                    else None
                ),
                "invoke_theorem": (
                    "generatedInvokeCallOperationRefinesUsingClosed"
                    if self.constructed
                    else None
                ),
                "step_theorem": (
                    "generatedInterpreterStepOperationRefinesUsingClosed"
                    if self.constructed
                    else None
                ),
                "semantic_closure_term": (
                    "generatedSemanticCallTreeClosure"
                ),
            },
        }


def _close_native_fallthrough_blocks(
    blocks: Sequence[NativeOperationBlockReplaySpec],
) -> tuple[NativeOperationBlockReplaySpec, ...]:
    """Extend each entry through ordinary fallthrough fragments.

    The kernel extractor splits at every CFG entry, including entries reached
    only by physical fallthrough.  `CheckedNativeOperationBlock` deliberately
    ends at a stopped instruction, so generated block certificates retain the
    original entry but concatenate deterministic ordinary fallthrough suffixes
    until the first real control boundary.  Every original entry remains in
    the output and therefore remains independently targetable.

    A fallthrough into a specialized instruction (x87 frame/command) has no
    ordinary block entry and remains open for the typed mixed-instruction
    boundary checker; it is never misclassified as stopped ordinary code.
    """

    by_entry = {block.entry_rva: block for block in blocks}
    result: list[NativeOperationBlockReplaySpec] = []
    for block in blocks:
        instructions = list(block.instructions)
        terminal = block
        visited = {block.entry_rva}
        while (
            terminal.terminal_class == "fallthrough"
            and len(terminal.successors) == 1
            and terminal.successors[0] in by_entry
        ):
            next_block = by_entry[terminal.successors[0]]
            if next_block.entry_rva in visited:
                raise RelationalInterpreterKernelOperationInstantiationError(
                    "ordinary fallthrough fragments contain a cycle at "
                    f"0x{next_block.entry_rva:x}"
                )
            visited.add(next_block.entry_rva)
            instructions.extend(next_block.instructions)
            terminal = next_block
        normalized = tuple(
            NativeOperationInstructionReplaySpec(
                ordinal=index,
                rva=instruction.rva,
                bytes_hex=instruction.bytes_hex,
                mnemonic=instruction.mnemonic,
            )
            for index, instruction in enumerate(instructions)
        )
        result.append(
            NativeOperationBlockReplaySpec(
                ordinal=block.ordinal,
                entry_rva=block.entry_rva,
                instructions=normalized,
                successors=terminal.successors,
                terminal_class=terminal.terminal_class,
            )
        )
    return tuple(result)


def _split_native_bulk_boundaries(
    blocks: Sequence[NativeOperationBlockReplaySpec],
) -> tuple[NativeOperationBlockReplaySpec, ...]:
    """Split compiler CFG blocks at checked bulk-operation cutpoints.

    The reviewed instruction semantics deliberately returns ``.stop`` for
    `rep movs*`: the concrete bulk transition is discharged by a separate
    checked effect certificate.  Compiler CFG recovery does not necessarily
    make that instruction a block terminator, so operation composition must
    introduce its own continuation cutpoint.
    """

    segments: list[tuple[
        int,
        tuple[NativeOperationInstructionReplaySpec, ...],
        tuple[int, ...],
        str,
    ]] = []
    for block in blocks:
        start = 0
        for index, instruction in enumerate(block.instructions[:-1]):
            if _terminal_class(instruction.mnemonic, 1) != "bulk":
                continue
            tail_rva = block.instructions[index + 1].rva
            segments.append((
                block.instructions[start].rva,
                block.instructions[start : index + 1],
                (tail_rva,),
                "bulk",
            ))
            start = index + 1
        segments.append((
            block.instructions[start].rva,
            block.instructions[start:],
            block.successors,
            block.terminal_class,
        ))

    def normalized_instructions(
        instructions: Sequence[NativeOperationInstructionReplaySpec],
    ) -> tuple[NativeOperationInstructionReplaySpec, ...]:
        return tuple(
            NativeOperationInstructionReplaySpec(
                ordinal=index,
                rva=instruction.rva,
                bytes_hex=instruction.bytes_hex,
                mnemonic=instruction.mnemonic,
            )
            for index, instruction in enumerate(instructions)
        )

    canonical: dict[
        int,
        tuple[
            tuple[NativeOperationInstructionReplaySpec, ...],
            tuple[int, ...],
            str,
        ],
    ] = {}
    for entry_rva, instructions, successors, terminal_class in segments:
        # Overlapping fallthrough views can discover the same synthetic suffix
        # with different source-local instruction ordinals.  Intern by the
        # normalized segment semantics, not by those incidental ordinals.
        value = (
            normalized_instructions(instructions),
            successors,
            terminal_class,
        )
        prior = canonical.get(entry_rva)
        if prior is not None:
            if prior != value:
                raise RelationalInterpreterKernelOperationInstantiationError(
                    "operation cutpoint splitting produced conflicting block "
                    f"entry 0x{entry_rva:x}"
                )
            continue
        canonical[entry_rva] = value

    result: list[NativeOperationBlockReplaySpec] = []
    for ordinal, (entry_rva, value) in enumerate(canonical.items()):
        instructions, successors, terminal_class = value
        result.append(
            NativeOperationBlockReplaySpec(
                ordinal=ordinal,
                entry_rva=entry_rva,
                instructions=instructions,
                successors=successors,
                terminal_class=terminal_class,
            )
        )
    return tuple(result)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{context} must be a natural number"
        )
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{context} must be a non-empty string"
        )
    return value


def _instruction_bytes(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) % 2 != 0
        or re.fullmatch(r"[0-9a-fA-F]+", value) is None
    ):
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{context} must be a non-empty even-length hexadecimal string"
        )
    return value.lower()


def _terminal_class(mnemonic: str, successor_count: int) -> str:
    normalized = mnemonic.lower()
    if normalized.startswith("ret"):
        return "return"
    if normalized in {"call", "lcall"}:
        return "call"
    if normalized == "jmp":
        return "jump"
    if normalized.startswith("j"):
        return "branch"
    if normalized.startswith("loop"):
        return "branch"
    if normalized.startswith("rep"):
        return "bulk"
    if successor_count == 0:
        return "terminal"
    if successor_count == 1:
        return "fallthrough"
    if successor_count == 2:
        return "branch"
    return "multi-successor"


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as error:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"unable to read {context}: {path}"
        ) from error


def _read_state_machine(path: Path) -> tuple[SemanticStateMachineRow, ...]:
    rows: list[SemanticStateMachineRow] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"unable to read state machine: {path}"
        ) from error
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        try:
            payload = _object(
                json.loads(line), f"state-machine line {line_number}"
            )
        except json.JSONDecodeError as error:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"invalid state-machine JSON on line {line_number}"
            ) from error
        original = _object(
            payload.get("original"),
            f"state-machine line {line_number} original span",
        )
        source_rva = _nat(
            original.get("rva_start"),
            f"state-machine line {line_number} source RVA",
        )
        events = tuple(
            _object(event, f"state-machine line {line_number} call event")
            for event in _array(
                payload.get("external_events", []),
                f"state-machine line {line_number} external events",
            )
            if _object(
                event, f"state-machine line {line_number} call event"
            ).get("kind")
            in _CALL_KINDS
        )
        rows.append(
            SemanticStateMachineRow(
                ordinal=len(rows),
                source_rva=source_rva,
                calls=events,
            )
        )
    if not rows:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "state machine must contain at least one semantic record"
        )
    sources = [row.source_rva for row in rows]
    if len(sources) != len(set(sources)):
        raise RelationalInterpreterKernelOperationInstantiationError(
            "state-machine source RVAs must be unique"
        )
    return tuple(rows)


def _operation_plan(
    path: Path, expected_format: str, operation: str
) -> Mapping[str, Any]:
    payload = _read_json(path, f"{operation} operation plan")
    if payload.get("format") != expected_format:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"{operation} operation plan has an unsupported format"
        )
    candidate = _object(
        payload.get("candidate"), f"{operation} operation candidate"
    )
    _digest(candidate.get("sha256"), f"{operation} candidate digest")
    _nat(candidate.get("size"), f"{operation} candidate size")
    _object(payload.get("inputs"), f"{operation} operation inputs")
    _object(
        payload.get("checked_static_authority"),
        f"{operation} checked static authority",
    )
    _array(
        payload.get("remaining_proof_premises", []),
        f"{operation} legacy premises",
    )
    return payload


def _input_digest(
    plan: Mapping[str, Any], role: str, operation: str
) -> str:
    inputs = _object(plan.get("inputs"), f"{operation} operation inputs")
    entry = _object(inputs.get(role), f"{operation} input {role}")
    return _digest(entry.get("sha256"), f"{operation} input {role} digest")


def _legacy_premises(
    plan: Mapping[str, Any], operation: str
) -> tuple[str, ...]:
    result: list[str] = []
    for index, premise in enumerate(
        _array(
            plan.get("remaining_proof_premises", []),
            f"{operation} legacy premises",
        )
    ):
        if not isinstance(premise, str) or not premise:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"{operation} legacy premise {index} must be a string"
            )
        result.append(premise)
    return tuple(result)


def _native_gap(
    *,
    identifier: str,
    family: str,
    artifact: str,
    field: str,
    lean_type: str,
    reason: str,
    rva: int | None = None,
    target_rvas: Sequence[int] = (),
) -> OperationInstantiationEndpointGap:
    return OperationInstantiationEndpointGap(
        identifier=identifier,
        family=family,
        kind="missing-checked-artifact-field",
        artifact=artifact,
        field=field,
        lean_type=lean_type,
        reason=reason,
        rva=rva,
        target_rvas=tuple(target_rvas),
    )


def _semantic_gaps(
    rows: Sequence[SemanticStateMachineRow],
) -> list[OperationInstantiationEndpointGap]:
    gaps = [
        OperationInstantiationEndpointGap(
            identifier="semantic:run-domain-closure",
            family="semantic-call-tree",
            kind="missing-generic-checker-theorem",
            artifact="RelationalInterpreterKernelClosedCallTree",
            field="GeneratedFiniteCheckedSemanticFunctionBindings.runAvailable",
            lean_type=(
                "declared source-domain closure for every authoritative "
                "AbstractRunFunction"
            ),
            reason=(
                "runAvailable quantifies over every source RVA, but a finite "
                "record catalog always admits AbstractRunFunction.unavailable "
                "at an absent RVA"
            ),
        ),
        OperationInstantiationEndpointGap(
            identifier="semantic:step-call-derivation",
            family="semantic-call-tree",
            kind="missing-generic-checker-theorem",
            artifact="RelationalInterpreterKernel",
            field="AbstractRunFunction step evidence",
            lean_type=(
                "checked per-action Step derivation retaining nested Invoke "
                "and Run evidence"
            ),
            reason=(
                "AbstractRunFunction stores only abstractInterpreterStep "
                "equality, which erases the nested call derivations required "
                "by FiniteCheckedInterpreterStepEvidence"
            ),
        ),
        OperationInstantiationEndpointGap(
            identifier="semantic:invoke-environment-result",
            family="semantic-call-tree",
            kind="missing-generic-checker-theorem",
            artifact="RelationalInterpreterKernel",
            field=(
                "AbstractKernelTransition.invokeInternal/invokeIndirect "
                "environment result equation"
            ),
            lean_type=(
                "environment.invokeCall event state = nested Run result"
            ),
            reason=(
                "the authoritative internal and indirect Invoke constructors "
                "do not retain the equality required by "
                "CheckedInvokeCallDerivation"
            ),
        ),
    ]
    for row in rows:
        for call_index, call in enumerate(row.calls):
            if call.get("kind") != "indirect_call":
                continue
            gaps.append(
                OperationInstantiationEndpointGap(
                    identifier=(
                        f"semantic:indirect-targets:"
                        f"{row.source_rva:08x}:{call_index}"
                    ),
                    family="semantic-call-tree",
                    kind="missing-checked-artifact-field",
                    artifact="state-machine.jsonl",
                    field=(
                        "external_events[].finite_target_rvas and "
                        "resolver_certificate"
                    ),
                    lean_type=(
                        "finite target set plus proof that resolveCodeTarget "
                        "maps the exact target expression into that set"
                    ),
                    reason=(
                        "the checked row records only a dynamic target "
                        "expression, so the finite call tree cannot bind this "
                        "indirect call to exact semantic record entries"
                    ),
                    source_rva=row.source_rva,
                    rva=_nat(
                        call.get("return_rva"),
                        (
                            f"indirect call at source 0x{row.source_rva:x} "
                            "return RVA"
                        ),
                    ),
                )
            )
    return gaps


def _native_function_replays(
    kernel: Mapping[str, Any],
    step: Mapping[str, Any],
    run: Mapping[str, Any],
    invoke: Mapping[str, Any],
) -> tuple[NativeOperationFunctionReplaySpec, ...]:
    step_static = _object(
        step.get("checked_static_authority"), "Step static authority"
    )
    run_static = _object(
        run.get("checked_static_authority"), "Run static authority"
    )
    invoke_static = _object(
        invoke.get("checked_static_authority"), "Invoke static authority"
    )
    external_helper = _object(
        invoke_static.get("external_helper"), "Invoke external helper"
    )

    required: dict[int, set[str]] = {}

    def require(rva: int, family: str) -> None:
        required.setdefault(rva, set()).add(family)

    require(_nat(step_static.get("entry_rva"), "Step entry RVA"), "step")
    require(
        _nat(
            step_static.get("program_lookup_target_rva"),
            "Step programLookup target RVA",
        ),
        "step-program-lookup",
    )
    for target in _array(
        step_static.get("helper_target_rvas"), "Step helper targets"
    ):
        require(_nat(target, "Step helper target"), "step-helper")
    # The Step x87 callback is represented by the separately checked x87
    # replay artifact rather than the ordinary kernel-function inventory.
    require(_nat(run_static.get("entry_rva"), "Run entry RVA"), "run")
    require(_nat(invoke_static.get("entry_rva"), "Invoke entry RVA"), "invoke")
    require(
        _nat(external_helper.get("entry_rva"), "Invoke external helper entry"),
        "invoke-external-helper",
    )
    # Invoke callbacks are represented by the separately checked finite
    # callback-target inventory and nested callback frames.

    by_entry: dict[int, tuple[int, Mapping[str, Any]]] = {}
    function_ranges: list[tuple[int, int, int, Mapping[str, Any]]] = []
    for index, raw_function in enumerate(
        _array(kernel.get("kernel_functions"), "kernel functions")
    ):
        function = _object(raw_function, f"kernel function {index}")
        entry = _nat(
            function.get("rva_start"), f"kernel function {index} entry"
        )
        if entry in by_entry:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"kernel function entry 0x{entry:x} is ambiguous"
            )
        by_entry[entry] = (index, function)
        end = _nat(function.get("rva_end"), f"kernel function {index} end")
        if end <= entry:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"kernel function entry 0x{entry:x} has an empty range"
            )
        function_ranges.append((entry, end, index, function))

    required_entries: dict[int, set[str]] = {}
    for target, families in required.items():
        if target in by_entry:
            entry = target
        else:
            containing = [
                entry
                for entry, end, _index, _function in function_ranges
                if entry <= target < end
            ]
            if len(containing) != 1:
                detail = "missing" if not containing else "ambiguous"
                raise RelationalInterpreterKernelOperationInstantiationError(
                    f"required native operation target 0x{target:x} has "
                    f"{detail} containing function"
                )
            entry = containing[0]
        required_entries.setdefault(entry, set()).update(families)

    _, specialized_boundaries = _native_route_anchors(step, run, invoke)
    specialized_target_rvas = {
        target
        for _identifier, targets in specialized_boundaries
        for target in targets
    }
    native_return_bridge_rvas = {
        entry
        for entry, (_index, function) in by_entry.items()
        if function.get("lookup_hint") == "stage_b_native_bridge"
    }
    specialized_target_rvas.update(native_return_bridge_rvas)

    # Close direct native targets transitively. The specialized call/return and
    # external handlers control their own callees, so ordinary replay stops at
    # those typed boundaries. Boundary functions that are operation roots in
    # their own right remain in ``required_entries`` and close their internal
    # direct-call graph from that independent root.
    pending = list(sorted(required_entries))
    while pending:
        source_entry = pending.pop()
        _source_index, source_function = by_entry[source_entry]
        inherited = required_entries[source_entry]
        for raw_block in _array(
            source_function.get("blocks"),
            f"function 0x{source_entry:x} blocks",
        ):
            block = _object(
                raw_block, f"function 0x{source_entry:x} transitive block"
            )
            for raw_successor in _array(
                block.get("successors", []),
                f"function 0x{source_entry:x} transitive successors",
            ):
                successor = _nat(
                    raw_successor,
                    f"function 0x{source_entry:x} transitive successor",
                )
                if successor not in by_entry:
                    continue
                if successor in specialized_target_rvas:
                    continue
                propagated = set(inherited)
                propagated.add("native-call-tree")
                existing = required_entries.get(successor)
                if existing is None:
                    required_entries[successor] = propagated
                    pending.append(successor)
                elif not propagated.issubset(existing):
                    existing.update(propagated)
                    pending.append(successor)

    result: list[NativeOperationFunctionReplaySpec] = []
    for ordinal, entry in enumerate(sorted(required_entries)):
        kernel_ordinal, function = by_entry[entry]
        end = _nat(function.get("rva_end"), f"function 0x{entry:x} end")
        if end <= entry:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"native operation function 0x{entry:x} has an empty range"
            )
        blocks = _array(
            function.get("blocks"), f"function 0x{entry:x} blocks"
        )
        if not blocks:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"native operation function 0x{entry:x} has no blocks"
            )
        replay_blocks: list[NativeOperationBlockReplaySpec] = []
        for block_index, raw_block in enumerate(blocks):
            block = _object(
                raw_block, f"function 0x{entry:x} block {block_index}"
            )
            block_entry = _nat(
                block.get("entry_rva", block.get("rva_start")),
                f"function 0x{entry:x} block {block_index} entry",
            )
            instructions = _array(
                block.get("instructions"),
                f"function 0x{entry:x} block {block_index} instructions",
            )
            if not instructions:
                raise RelationalInterpreterKernelOperationInstantiationError(
                    f"function 0x{entry:x} block {block_index} is empty"
                )
            replay_instructions: list[NativeOperationInstructionReplaySpec] = []
            expected_rva = block_entry
            for instruction_index, raw_instruction in enumerate(instructions):
                instruction = _object(
                    raw_instruction,
                    (
                        f"function 0x{entry:x} block {block_index} "
                        f"instruction {instruction_index}"
                    ),
                )
                instruction_rva = _nat(
                    instruction.get("rva"),
                    (
                        f"function 0x{entry:x} block {block_index} "
                        f"instruction {instruction_index} RVA"
                    ),
                )
                bytes_hex = _instruction_bytes(
                    instruction.get("bytes"),
                    (
                        f"function 0x{entry:x} block {block_index} "
                        f"instruction {instruction_index} bytes"
                    ),
                )
                size = len(bytes_hex) // 2
                if "size" in instruction and _nat(
                    instruction.get("size"),
                    (
                        f"function 0x{entry:x} block {block_index} "
                        f"instruction {instruction_index} size"
                    ),
                ) != size:
                    raise RelationalInterpreterKernelOperationInstantiationError(
                        f"function 0x{entry:x} block {block_index} instruction "
                        f"{instruction_index} byte length does not match size"
                    )
                if instruction_rva != expected_rva:
                    raise RelationalInterpreterKernelOperationInstantiationError(
                        f"function 0x{entry:x} block {block_index} instruction "
                        f"{instruction_index} is not contiguous"
                    )
                if instruction_rva < entry or instruction_rva + size > end:
                    raise RelationalInterpreterKernelOperationInstantiationError(
                        f"function 0x{entry:x} block {block_index} instruction "
                        f"{instruction_index} lies outside the function range"
                    )
                mnemonic_value = instruction.get("mnemonic", "unknown")
                mnemonic = (
                    mnemonic_value
                    if isinstance(mnemonic_value, str) and mnemonic_value
                    else "unknown"
                )
                replay_instructions.append(
                    NativeOperationInstructionReplaySpec(
                        ordinal=instruction_index,
                        rva=instruction_rva,
                        bytes_hex=bytes_hex,
                        mnemonic=mnemonic,
                    )
                )
                expected_rva = instruction_rva + size
            successors = tuple(
                _nat(
                    successor,
                    (
                        f"function 0x{entry:x} block {block_index} "
                        "successor"
                    ),
                )
                for successor in _array(
                    block.get("successors", []),
                    f"function 0x{entry:x} block {block_index} successors",
                )
            )
            if len(successors) != len(set(successors)):
                raise RelationalInterpreterKernelOperationInstantiationError(
                    f"function 0x{entry:x} block {block_index} has duplicate "
                    "successors"
                )
            replay_blocks.append(
                NativeOperationBlockReplaySpec(
                    ordinal=block_index,
                    entry_rva=block_entry,
                    instructions=tuple(replay_instructions),
                    successors=successors,
                    terminal_class=_terminal_class(
                        replay_instructions[-1].mnemonic, len(successors)
                    ),
                )
            )
        block_entries = [block.entry_rva for block in replay_blocks]
        if len(block_entries) != len(set(block_entries)):
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"function 0x{entry:x} has duplicate block entries"
            )
        closed_replay_blocks = _close_native_fallthrough_blocks(replay_blocks)
        operation_blocks = _split_native_bulk_boundaries(
            closed_replay_blocks
        )
        result.append(
            NativeOperationFunctionReplaySpec(
                ordinal=ordinal,
                kernel_ordinal=kernel_ordinal,
                families=tuple(sorted(required_entries[entry])),
                role=_string(
                    function.get("role"), f"function 0x{entry:x} role"
                ),
                entry_rva=entry,
                end_rva=end,
                blocks=operation_blocks,
            )
        )

    expected_ranges = (
        ("Step", step_static),
        ("Run", run_static),
        ("Invoke", invoke_static),
    )
    by_replay_entry = {
        replay.entry_rva: replay for replay in result
    }
    for operation, static in expected_ranges:
        entry = _nat(static.get("entry_rva"), f"{operation} entry RVA")
        if "end_rva" in static:
            expected_end = _nat(
                static.get("end_rva"), f"{operation} end RVA"
            )
            if by_replay_entry[entry].end_rva != expected_end:
                raise RelationalInterpreterKernelOperationInstantiationError(
                    f"{operation} checked range does not match kernel plan"
                )
    return tuple(result)


def _native_route_anchors(
    step: Mapping[str, Any],
    run: Mapping[str, Any],
    invoke: Mapping[str, Any],
) -> tuple[
    tuple[tuple[str, int], ...],
    tuple[tuple[str, tuple[int, ...]], ...],
]:
    step_static = _object(
        step.get("checked_static_authority"), "Step static authority"
    )
    run_static = _object(
        run.get("checked_static_authority"), "Run static authority"
    )
    invoke_static = _object(
        invoke.get("checked_static_authority"), "Invoke static authority"
    )
    external_helper = _object(
        invoke_static.get("external_helper"), "Invoke external helper"
    )
    anchors = (
        ("step:entry", _nat(step_static.get("entry_rva"), "Step entry RVA")),
        (
            "step:program-lookup-call",
            _nat(
                step_static.get("program_lookup_call_rva"),
                "Step programLookup call RVA",
            ),
        ),
        (
            "step:invoke-call",
            _nat(step_static.get("invoke_call_rva"), "Step Invoke call RVA"),
        ),
        (
            "step:x87-callback-site",
            _nat(
                step_static.get("callback_site_rva"),
                "Step x87 callback site RVA",
            ),
        ),
        ("step:end", _nat(step_static.get("end_rva"), "Step end RVA")),
        ("run:entry", _nat(run_static.get("entry_rva"), "Run entry RVA")),
        (
            "run:loop-header",
            _nat(run_static.get("loop_header_rva"), "Run loop header RVA"),
        ),
        (
            "run:completion-dispatch",
            _nat(
                run_static.get("completion_dispatch_rva"),
                "Run completion dispatch RVA",
            ),
        ),
        (
            "run:step-call",
            _nat(run_static.get("step_call_rva"), "Run Step call RVA"),
        ),
        (
            "run:resolver-call",
            _nat(
                run_static.get("resolver_call_rva"), "Run resolver call RVA"
            ),
        ),
        (
            "run:epilogue",
            _nat(run_static.get("epilogue_rva"), "Run epilogue RVA"),
        ),
        ("run:end", _nat(run_static.get("end_rva"), "Run end RVA")),
        (
            "invoke:entry",
            _nat(invoke_static.get("entry_rva"), "Invoke entry RVA"),
        ),
        (
            "invoke:internal-call",
            _nat(
                invoke_static.get("internal_call_rva"),
                "Invoke internal call RVA",
            ),
        ),
        (
            "invoke:internal-continuation",
            _nat(
                invoke_static.get("internal_continuation_rva"),
                "Invoke internal continuation RVA",
            ),
        ),
        (
            "invoke:resolver-site",
            _nat(
                invoke_static.get("resolver_site_rva"),
                "Invoke resolver site RVA",
            ),
        ),
        (
            "invoke:resolver-continuation",
            _nat(
                invoke_static.get("resolver_continuation_rva"),
                "Invoke resolver continuation RVA",
            ),
        ),
        (
            "invoke:indirect-run-call",
            _nat(
                invoke_static.get("indirect_run_function_call_rva"),
                "Invoke indirect Run call RVA",
            ),
        ),
        (
            "invoke:indirect-continuation",
            _nat(
                invoke_static.get("indirect_continuation_rva"),
                "Invoke indirect continuation RVA",
            ),
        ),
        (
            "invoke:external-helper-call",
            _nat(
                invoke_static.get("external_helper_call_rva"),
                "Invoke external helper call RVA",
            ),
        ),
        (
            "invoke:external-continuation",
            _nat(
                invoke_static.get("external_continuation_rva"),
                "Invoke external continuation RVA",
            ),
        ),
        ("invoke:end", _nat(invoke_static.get("end_rva"), "Invoke end RVA")),
    )
    boundaries = (
        (
            "step:program-lookup",
            (
                _nat(
                    step_static.get("program_lookup_target_rva"),
                    "Step programLookup target RVA",
                ),
            ),
        ),
        (
            "step:invoke",
            (
                _nat(
                    step_static.get("invoke_target_rva"),
                    "Step Invoke target RVA",
                ),
            ),
        ),
        (
            "step:x87-callback",
            (
                _nat(
                    step_static.get("callback_target_rva"),
                    "Step x87 callback target RVA",
                ),
            ),
        ),
        (
            "run:step",
            (
                _nat(run_static.get("step_entry_rva"), "Run Step entry RVA"),
            ),
        ),
        (
            "invoke:run",
            (
                _nat(
                    invoke_static.get("run_function_rva"),
                    "Invoke Run entry RVA",
                ),
            ),
        ),
        (
            "invoke:finite-callback",
            tuple(
                _nat(target, "Invoke callback target RVA")
                for target in _array(
                    invoke_static.get("callback_target_rvas"),
                    "Invoke callback target RVAs",
                )
            ),
        ),
        (
            "invoke:external-helper",
            (
                _nat(
                    external_helper.get("entry_rva"),
                    "Invoke external helper entry RVA",
                ),
            ),
        ),
    )
    return anchors, boundaries


def _native_structural_boundary_targets(
    functions: Sequence[NativeOperationFunctionReplaySpec],
) -> tuple[int, ...]:
    """Return submitted direct targets absent from the checked block bundle.

    Semantic landmarks such as nested Run, Step, Invoke, and callback entries
    may still require a stronger operation-level certificate, but they are not
    graph frontiers when their exact native blocks are present.  Only an
    actually absent target may be admitted by the reflective graph-closure
    checker as a structural boundary.
    """

    entries = {
        block.entry_rva
        for function in functions
        for block in function.blocks
    }
    return tuple(
        sorted(
            {
                successor
                for function in functions
                for block in function.blocks
                for successor in block.successors
                if successor not in entries
            }
        )
    )


def _native_ranked_route(
    function: NativeOperationFunctionReplaySpec,
) -> NativeOperationRankedRouteSpec:
    """Break one native function into acyclic regions between typed cutpoints.

    Calls and returns are always cutpoints.  A direct-control source whose
    target is outside the function is also a cutpoint.  Remaining cyclic SCCs
    are cut deterministically by choosing one node from each discovered cycle.
    The resulting rank proposal is untrusted: Lean rechecks every exact
    outcome, target lookup, invariant link, and strict decrease.
    """

    by_entry = {block.entry_rva: block for block in function.blocks}
    if len(by_entry) != len(function.blocks):
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"native function 0x{function.entry_rva:x} has duplicate block "
            "entries"
        )
    local_classes = {"branch", "bulk", "jump"}
    stops = {
        block.entry_rva
        for block in function.blocks
        if block.terminal_class not in local_classes
        or any(target not in by_entry for target in block.successors)
    }

    def active_successors(entry_rva: int) -> tuple[int, ...]:
        if entry_rva in stops:
            return ()
        return tuple(
            target
            for target in by_entry[entry_rva].successors
            if target not in stops
        )

    def cycle() -> tuple[int, ...] | None:
        visited: set[int] = set()
        active: list[int] = []
        active_index: dict[int, int] = {}

        def visit(entry_rva: int) -> tuple[int, ...] | None:
            if entry_rva in active_index:
                return tuple(active[active_index[entry_rva] :])
            if entry_rva in visited:
                return None
            visited.add(entry_rva)
            active_index[entry_rva] = len(active)
            active.append(entry_rva)
            for target in active_successors(entry_rva):
                found = visit(target)
                if found is not None:
                    return found
            active.pop()
            del active_index[entry_rva]
            return None

        for entry_rva in sorted(by_entry):
            if entry_rva in stops:
                continue
            found = visit(entry_rva)
            if found is not None:
                return found
        return None

    while (found_cycle := cycle()) is not None:
        stops.add(min(found_cycle))

    ranks: dict[int, int] = {}

    def rank(entry_rva: int) -> int:
        if entry_rva in ranks:
            return ranks[entry_rva]
        if entry_rva in stops:
            ranks[entry_rva] = 0
            return 0
        successors = by_entry[entry_rva].successors
        if not successors:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"native non-cutpoint block 0x{entry_rva:x} has no successor"
            )
        result = 1 + max(rank(target) for target in successors)
        ranks[entry_rva] = result
        return result

    for entry_rva in sorted(by_entry):
        rank(entry_rva)
    return NativeOperationRankedRouteSpec(
        function_ordinal=function.ordinal,
        entry_rva=function.entry_rva,
        stop_rvas=tuple(sorted(stops)),
        ranks=tuple(sorted(ranks.items())),
    )


def _native_ranked_routes(
    functions: Sequence[NativeOperationFunctionReplaySpec],
) -> tuple[NativeOperationRankedRouteSpec, ...]:
    return tuple(_native_ranked_route(function) for function in functions)


def _native_ranked_route_clusters(
    functions: Sequence[NativeOperationFunctionReplaySpec],
    routes: Sequence[NativeOperationRankedRouteSpec],
) -> tuple[NativeOperationRankedRouteClusterSpec, ...]:
    """Partition functions into independently checkable acyclic route units."""

    route_by_ordinal = {
        route.function_ordinal: route for route in routes
    }
    clusters: list[NativeOperationRankedRouteClusterSpec] = []
    for function in functions:
        route = route_by_ordinal[function.ordinal]
        by_entry = {block.entry_rva: block for block in function.blocks}
        stop_set = set(route.stop_rvas)
        rank_by_entry = dict(route.ranks)
        starts = {function.entry_rva}
        for stop_rva in stop_set:
            starts.update(
                target
                for target in by_entry[stop_rva].successors
                if target in by_entry
            )
        for cluster_ordinal, source_rva in enumerate(sorted(starts)):
            reachable: set[int] = set()
            pending = [source_rva]
            while pending:
                entry_rva = pending.pop()
                if entry_rva in reachable:
                    continue
                reachable.add(entry_rva)
                if entry_rva in stop_set:
                    continue
                pending.extend(by_entry[entry_rva].successors)
            frontiers = tuple(sorted(reachable & stop_set))
            if not frontiers:
                raise RelationalInterpreterKernelOperationInstantiationError(
                    f"native route from 0x{source_rva:x} has no typed frontier"
                )
            clusters.append(
                NativeOperationRankedRouteClusterSpec(
                    function_ordinal=function.ordinal,
                    cluster_ordinal=cluster_ordinal,
                    source_rva=source_rva,
                    block_rvas=tuple(sorted(reachable)),
                    stop_rvas=frontiers,
                    ranks=tuple(
                        (entry_rva, rank_by_entry[entry_rva])
                        for entry_rva in sorted(reachable)
                    ),
                )
            )
    return tuple(clusters)


def _native_gaps(
    step: Mapping[str, Any],
    run: Mapping[str, Any],
    invoke: Mapping[str, Any],
) -> list[OperationInstantiationEndpointGap]:
    step_static = _object(
        step.get("checked_static_authority"), "Step static authority"
    )
    run_static = _object(
        run.get("checked_static_authority"), "Run static authority"
    )
    invoke_static = _object(
        invoke.get("checked_static_authority"), "Invoke static authority"
    )
    external_helper = _object(
        invoke_static.get("external_helper"), "Invoke external helper"
    )

    gaps = [
        _native_gap(
            identifier="native:run:semantics",
            family="runFunction",
            artifact="checked-run-native-evidence",
            field="GeneratedRunFunctionCheckedNativeEvidence.semantics",
            lean_type="GeneratedRunFunctionCheckedLocalSemantics environment",
            reason=(
                "the Run plan has checked static cutpoints but no invariant, "
                "request-local Step execution, or checked loop endpoint"
            ),
            rva=_nat(run_static.get("loop_header_rva"), "Run loop header"),
        ),
        _native_gap(
            identifier="native:run:entry",
            family="runFunction",
            artifact="checked-run-native-evidence",
            field="GeneratedRunFunctionCheckedNativeEvidence.entry",
            lean_type="RunFunctionNativeCheckedEntryAuthority ... semantics",
            reason=(
                "no checked path currently turns every ABI-related entry state "
                "into the Run loop invariant at the exact entry frame"
            ),
            rva=_nat(run_static.get("entry_rva"), "Run entry RVA"),
        ),
        _native_gap(
            identifier="native:run:result-indexed-suffix",
            family="runFunction",
            artifact="checked-run-native-evidence",
            field="GeneratedRunFunctionCheckedNativeEvidence.suffix",
            lean_type=(
                "RunFunctionNativeResultIndexedCDeclSuffixAuthority ..."
            ),
            reason=(
                "the exact cdecl suffix has not carried the loop-produced "
                "status and engine state into the ABI response, successor "
                "world, and scratch-footprint memory frame"
            ),
            rva=_nat(run_static.get("epilogue_rva"), "Run epilogue RVA"),
        ),
        _native_gap(
            identifier="native:invoke:external-execution",
            family="invokeCall",
            artifact="checked-invoke-native-evidence",
            field="GeneratedInvokeCallCheckedNativeEvidence.externalExecution",
            lean_type="GeneratedInvokeCallExternalHelperExecution environment world",
            reason=(
                "the helper bytes and decodes are checked, but no universal "
                "helper path reaches an exact wrapper endpoint"
            ),
            rva=_nat(external_helper.get("entry_rva"), "Invoke helper entry"),
        ),
        _native_gap(
            identifier="native:invoke:external-environment",
            family="invokeCall",
            artifact="checked-invoke-native-evidence",
            field="GeneratedInvokeCallCheckedNativeEvidence.externalEnvironment",
            lean_type=(
                "GeneratedInvokeCallExternalEnvironmentRefinement "
                "externalExecution"
            ),
            reason=(
                "no checked external-event result, ABI response, world update, "
                "and memory footprint endpoint is exported"
            ),
            rva=_nat(external_helper.get("entry_rva"), "Invoke helper entry"),
        ),
        _native_gap(
            identifier="native:invoke:internal-arm",
            family="invokeCall",
            artifact="checked-invoke-native-evidence",
            field="GeneratedInvokeCallCheckedNativeEvidence.internal",
            lean_type="GeneratedInvokeCallInternalArm environment world",
            reason=(
                "the internal wrapper has no checker-produced package tying "
                "its prepare/assemble path to the per-call ABI and nested Run "
                "certificate"
            ),
            rva=_nat(
                invoke_static.get("internal_call_rva"),
                "Invoke internal call RVA",
            ),
        ),
        _native_gap(
            identifier="native:invoke:indirect-arm",
            family="invokeCall",
            artifact="checked-invoke-native-evidence",
            field="GeneratedInvokeCallCheckedNativeEvidence.indirect",
            lean_type="GeneratedInvokeCallIndirectArm environment world",
            reason=(
                "the resolver callback, exact target, wrapper continuation, "
                "per-call ABI, nested Run certificate, and result frame have "
                "not been composed"
            ),
            rva=_nat(
                invoke_static.get("resolver_site_rva"),
                "Invoke resolver site RVA",
            ),
            target_rvas=tuple(
                _nat(target, "Invoke callback target")
                for target in _array(
                    invoke_static.get("callback_target_rvas"),
                    "Invoke callback targets",
                )
            ),
        ),
        _native_gap(
            identifier="native:step:program-lookup-call",
            family="interpreterStep",
            artifact="checked-step-native-evidence",
            field=(
                "GeneratedInterpreterStepCheckedNativeEvidence."
                "programLookupCall"
            ),
            lean_type=(
                "GeneratedInterpreterStepProgramLookupWorldCall "
                "environment world"
            ),
            reason=(
                "the closed programLookup theorem exists, but its exact nested "
                "caller frame and continuation endpoint are not exported"
            ),
            rva=_nat(
                step_static.get("program_lookup_call_rva"),
                "Step programLookup call RVA",
            ),
        ),
        _native_gap(
            identifier="native:step:invoke-sites",
            family="interpreterStep",
            artifact="checked-step-native-evidence",
            field=(
                "GeneratedInterpreterStepCheckedNativeEvidence."
                "invokeCallRefines"
            ),
            lean_type=(
                "request-local InterpreterStepNativeRequestLocalInvokeEvidence"
            ),
            reason=(
                "no checked native Invoke certificate is selected for each "
                "Invoke site retained by a checked Step derivation"
            ),
            rva=_nat(
                step_static.get("invoke_call_rva"), "Step Invoke call RVA"
            ),
        ),
        _native_gap(
            identifier="native:step:action-loops",
            family="interpreterStep",
            artifact="checked-step-native-evidence",
            field="GeneratedInterpreterStepCheckedNativeEvidence.actionLoops",
            lean_type=(
                "GeneratedInterpreterStepActionLoops environment world "
                "helpers"
            ),
            reason=(
                "the checked cutpoint inventory has no complete per-action path "
                "composition, including exact request-local helper calls, for "
                "every checked Step derivation"
            ),
            rva=_nat(step_static.get("entry_rva"), "Step entry RVA"),
            target_rvas=tuple(
                _nat(target, "Step helper target")
                for target in _array(
                    step_static.get("helper_target_rvas"),
                    "Step helper targets",
                )
            ),
        ),
        _native_gap(
            identifier="native:step:epilogue",
            family="interpreterStep",
            artifact="checked-step-native-evidence",
            field="GeneratedInterpreterStepCheckedNativeEvidence.epilogue",
            lean_type="GeneratedInterpreterStepEpilogue environment world",
            reason=(
                "the exact cdecl return, ABI response, successor world, and "
                "scratch-footprint memory frame are not exported"
            ),
            rva=_nat(step_static.get("end_rva"), "Step end RVA"),
        ),
    ]
    return gaps


def build_relational_interpreter_kernel_operation_instantiation_plan(
    *,
    candidate_pe: Path | str,
    kernel_plan: Path | str,
    state_machine: Path | str,
    data_inventory: Path | str,
    step_operation_plan: Path | str,
    run_operation_plan: Path | str,
    invoke_operation_plan: Path | str,
) -> InterpreterKernelOperationInstantiationPlan:
    """Bind exact GNU artifacts and enumerate concrete closure endpoints."""

    candidate_path = Path(candidate_pe)
    kernel_path = Path(kernel_plan)
    state_path = Path(state_machine)
    data_path = Path(data_inventory)
    step_path = Path(step_operation_plan)
    run_path = Path(run_operation_plan)
    invoke_path = Path(invoke_operation_plan)

    try:
        candidate_size = candidate_path.stat().st_size
        candidate_digest = sha256_file(candidate_path)
    except OSError as error:
        raise RelationalInterpreterKernelOperationInstantiationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from error
    kernel = _read_json(kernel_path, "kernel plan")
    if kernel.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "kernel plan has an unsupported format"
        )
    kernel_candidate = _object(
        kernel.get("candidate"), "kernel plan candidate"
    )
    if (
        _digest(
            kernel_candidate.get("pe_sha256"),
            "kernel plan candidate digest",
        )
        != candidate_digest
        or _nat(
            kernel_candidate.get("size"), "kernel plan candidate size"
        )
        != candidate_size
    ):
        raise RelationalInterpreterKernelOperationInstantiationError(
            "kernel plan is not bound to the exact candidate PE"
        )
    kernel_digest = sha256_file(kernel_path)

    rows = _read_state_machine(state_path)
    data = _read_json(data_path, "kernel data inventory")
    if data.get("format") not in _DATA_INVENTORY_FORMATS:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "kernel data inventory has an unsupported format"
        )
    state_digest = sha256_file(state_path)
    data_digest = sha256_file(data_path)
    if data.get("state_machine_sha256") != state_digest:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "kernel data inventory is not bound to the exact state machine"
        )
    counts = _object(data.get("counts"), "kernel data inventory counts")
    record_count = _nat(counts.get("records"), "semantic record count")
    transfer_count = _nat(counts.get("transfers"), "semantic transfer count")
    if record_count != len(rows) or transfer_count != len(rows):
        raise RelationalInterpreterKernelOperationInstantiationError(
            "kernel data inventory record/transfer counts do not match the "
            "state machine"
        )
    shard_size = _nat(data.get("shard_size"), "semantic record shard size")
    if shard_size == 0:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "semantic record shard size must be positive"
        )

    step = _operation_plan(
        step_path, INTERPRETER_KERNEL_STEP_OPERATION_FORMAT, "interpreterStep"
    )
    run = _operation_plan(
        run_path, INTERPRETER_KERNEL_RUN_OPERATION_FORMAT, "runFunction"
    )
    invoke = _operation_plan(
        invoke_path, INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT, "invokeCall"
    )
    candidates = [
        (
            _digest(
                _object(plan.get("candidate"), f"{operation} candidate").get(
                    "sha256"
                ),
                f"{operation} candidate digest",
            ),
            _nat(
                _object(plan.get("candidate"), f"{operation} candidate").get(
                    "size"
                ),
                f"{operation} candidate size",
            ),
        )
        for operation, plan in (
            ("interpreterStep", step),
            ("runFunction", run),
            ("invokeCall", invoke),
        )
    ]
    if len(set(candidates)) != 1:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "Step, Run, and Invoke plans refer to different candidate PEs"
        )
    if candidates[0] != (candidate_digest, candidate_size):
        raise RelationalInterpreterKernelOperationInstantiationError(
            "operation plans are not bound to the exact candidate PE"
        )
    for operation, plan in (
        ("interpreterStep", step),
        ("runFunction", run),
        ("invokeCall", invoke),
    ):
        if _input_digest(plan, "kernel_plan", operation) != kernel_digest:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"{operation} plan is not bound to the exact kernel plan"
            )
    for operation, plan, role in (
        ("interpreterStep", step, "kernel_data_inventory"),
        ("runFunction", run, "kernel_data_inventory"),
        ("invokeCall", invoke, "data_inventory"),
    ):
        if _input_digest(plan, role, operation) != data_digest:
            raise RelationalInterpreterKernelOperationInstantiationError(
                f"{operation} plan is not bound to the exact data inventory"
            )
    if _input_digest(invoke, "run_operation_plan", "invokeCall") != sha256_file(
        run_path
    ):
        raise RelationalInterpreterKernelOperationInstantiationError(
            "invokeCall plan is not bound to the exact runFunction plan"
        )

    sources = tuple(row.source_rva for row in rows)
    source_set = set(sources)
    call_counts = {kind: 0 for kind in _CALL_KINDS.values()}
    for row in rows:
        for call in row.calls:
            kind = _CALL_KINDS[str(call.get("kind"))]
            call_counts[kind] += 1
            if kind == "internal":
                target = _nat(
                    call.get("target_rva"),
                    f"internal call at source 0x{row.source_rva:x} target",
                )
                if target not in source_set:
                    raise RelationalInterpreterKernelOperationInstantiationError(
                        "internal call at source "
                        f"0x{row.source_rva:x} targets missing semantic record "
                        f"0x{target:x}"
                    )

    functions = exact_checked_semantic_function_specs_from_record_packs(
        source_rvas=sources,
        shard_size=shard_size,
    )
    missing_source = next(
        candidate for candidate in range(2**32) if candidate not in source_set
    )
    observed = (
        ("interpreterStep", _legacy_premises(step, "interpreterStep")),
        ("runFunction", _legacy_premises(run, "runFunction")),
        ("invokeCall", _legacy_premises(invoke, "invokeCall")),
    )
    native_function_replays = _native_function_replays(
        kernel, step, run, invoke
    )
    native_route_anchors, native_boundary_targets = _native_route_anchors(
        step, run, invoke
    )
    native_return_bridge_targets = tuple(
        sorted(
            _nat(function.get("rva_start"), "native return bridge RVA")
            for function in _array(kernel.get("kernel_functions"), "kernel functions")
            if _object(function, "kernel function").get("lookup_hint")
            == "stage_b_native_bridge"
        )
    )
    if native_return_bridge_targets:
        native_boundary_targets = native_boundary_targets + (
            ("native:return-bridge", native_return_bridge_targets),
        )
    native_structural_boundary_targets = _native_structural_boundary_targets(
        native_function_replays
    )
    native_ranked_routes = _native_ranked_routes(native_function_replays)
    native_ranked_route_clusters = _native_ranked_route_clusters(
        native_function_replays, native_ranked_routes
    )
    gaps = tuple(_native_gaps(step, run, invoke))
    return InterpreterKernelOperationInstantiationPlan(
        candidate_path=candidate_path,
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=kernel_digest,
        state_machine_path=state_path,
        state_machine_sha256=state_digest,
        data_inventory_path=data_path,
        data_inventory_sha256=data_digest,
        step_operation_plan_path=step_path,
        step_operation_plan_sha256=sha256_file(step_path),
        run_operation_plan_path=run_path,
        run_operation_plan_sha256=sha256_file(run_path),
        invoke_operation_plan_path=invoke_path,
        invoke_operation_plan_sha256=sha256_file(invoke_path),
        candidate_sha256=candidates[0][0],
        candidate_size=candidates[0][1],
        shard_size=shard_size,
        functions=functions,
        call_counts=tuple(sorted(call_counts.items())),
        native_function_replays=native_function_replays,
        native_route_anchors=native_route_anchors,
        native_boundary_targets=native_boundary_targets,
        native_structural_boundary_targets=native_structural_boundary_targets,
        native_ranked_routes=native_ranked_routes,
        native_ranked_route_clusters=native_ranked_route_clusters,
        missing_source_rva=missing_source,
        observed_legacy_premises=observed,
        endpoint_gaps=gaps,
    )


def _native_block_prefix(
    function: NativeOperationFunctionReplaySpec,
    block: NativeOperationBlockReplaySpec,
) -> str:
    return (
        f"generatedNativeOperationFunctionReplay{function.ordinal:04d}"
        f"Block{block.ordinal:04d}"
    )


def _native_instruction_prefix(
    function: NativeOperationFunctionReplaySpec,
    block: NativeOperationBlockReplaySpec,
    instruction: NativeOperationInstructionReplaySpec,
) -> str:
    return (
        f"{_native_block_prefix(function, block)}"
        f"Instruction{instruction.ordinal:04d}"
    )


def _lean_instruction(
    instruction: NativeOperationInstructionReplaySpec,
) -> str:
    byte_values = ", ".join(
        str(value) for value in bytes.fromhex(instruction.bytes_hex)
    )
    return (
        f"{{ rva := {instruction.rva}, bytes := [{byte_values}] }}"
    )


def _lean_operation_kernel_block(
    block: NativeOperationBlockReplaySpec,
) -> str:
    instructions = ", ".join(
        _lean_instruction(instruction) for instruction in block.instructions
    )
    successors = ", ".join(str(successor) for successor in block.successors)
    return (
        "{\n"
        f"    entryRva := {block.entry_rva}\n"
        f"    instructions := [{instructions}]\n"
        f"    successors := [{successors}]\n"
        "  }"
    )


def _native_operation_block_source_group(
    function: NativeOperationFunctionReplaySpec,
    blocks: Sequence[NativeOperationBlockReplaySpec],
    *,
    candidate_module: str,
    include_function_replay: bool,
) -> str:
    definitions: list[str] = []
    audits: list[str] = []
    if include_function_replay:
        definitions.append(
            f"""def {function.lean_term}
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationFunctionReplay
      (generatedClosedKernelOperationNativeProgram environment) :=
  .ofStaticChecked
    (generatedClosedKernelOperationNativeProgram environment)
    {function.entry_rva} {function.byte_length} (by decide)
    (by
      change canonicalNativeOperationFunctionCheckedStatic
        generatedClosedKernelOperationPe
        generatedClosedKernelOperationImports
        {function.entry_rva} {function.byte_length} = true
      decide +kernel)"""
        )
        audits.append(f"#print axioms {function.lean_term}")
    for block in blocks:
        block_prefix = _native_block_prefix(function, block)
        definitions.append(
            f"""def {block_prefix} : KernelBlock :=
  {_lean_operation_kernel_block(block)}

theorem {block_prefix}Checked
    (environment : NativeWorldEnvironment) :
    {block_prefix}.checked
      (generatedClosedKernelOperationNativeProgram environment).pe
      (generatedClosedKernelOperationNativeProgram environment).imports = true := by
  simp only [generatedClosedKernelOperationNativeProgram]
  decide +kernel"""
        )
        audits.append(f"#print axioms {block_prefix}Checked")
        running_edges: list[str] = []
        running_behaviors: list[str] = []
        for instruction in block.instructions:
            instruction_prefix = _native_instruction_prefix(
                function, block, instruction
            )
            behavior_term = f"{instruction_prefix}Behavior"
            definitions.append(
                f"""def {instruction_prefix} : KernelInstruction :=
  {_lean_instruction(instruction)}

def {behavior_term} : SymbolicBehavior :=
  canonicalNativeOperationInstructionBehaviorStatic
    generatedClosedKernelOperationPe
    generatedClosedKernelOperationImports
    {instruction_prefix} {instruction.ordinal}"""
            )
            if instruction.ordinal + 1 < len(block.instructions):
                definitions.append(
                    f"""def {instruction_prefix}Replay
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningInstruction
      (generatedClosedKernelOperationNativeProgram environment)
      {instruction_prefix} {instruction.ordinal} :=
  .ofCanonicalStaticChecked
    (generatedClosedKernelOperationNativeProgram environment)
    {instruction_prefix} {instruction.ordinal}
    (by
      change canonicalNativeOperationInstructionCheckedStatic
        generatedClosedKernelOperationPe
        generatedClosedKernelOperationImports
        {instruction_prefix} {instruction.ordinal} = true
      decide +kernel)
    (by
      change checkedNativeOperationRunningResult
        (canonicalNativeOperationInstructionResultStatic
          generatedClosedKernelOperationPe
          generatedClosedKernelOperationImports
          {instruction_prefix} {instruction.ordinal}) = true
      decide +kernel)

theorem {instruction_prefix}BehaviorExact
    (environment : NativeWorldEnvironment) :
    ({instruction_prefix}Replay environment).behavior =
      {behavior_term} := by
  simp only [{instruction_prefix}Replay, {behavior_term},
    generatedClosedKernelOperationNativeProgram,
    CheckedNativeOperationRunningInstruction.ofCanonicalStaticChecked_behavior]

def {instruction_prefix}Cutpoint
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningCutpoint
      ({instruction_prefix}Replay environment) :=
  .ofTrivial ({instruction_prefix}Replay environment)

def {instruction_prefix}Edge
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningEdge
      (generatedClosedKernelOperationNativeProgram environment) := {{
  instruction := {instruction_prefix}
  undefinedSlot := {instruction.ordinal}
  replay := {instruction_prefix}Replay environment
  cutpoint := {instruction_prefix}Cutpoint environment
}}"""
                )
                running_edges.append(f"{instruction_prefix}Edge environment")
                running_behaviors.append(behavior_term)
            else:
                definitions.append(
                    f"""def {instruction_prefix}Replay
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationStoppedInstruction
      (generatedClosedKernelOperationNativeProgram environment)
      {instruction_prefix} {instruction.ordinal} :=
  .ofCanonicalStaticChecked
    (generatedClosedKernelOperationNativeProgram environment)
    {instruction_prefix} {instruction.ordinal}
    (by
      change canonicalNativeOperationInstructionCheckedStatic
        generatedClosedKernelOperationPe
        generatedClosedKernelOperationImports
        {instruction_prefix} {instruction.ordinal} = true
      decide +kernel)
    (by
      change checkedNativeOperationStoppedResult
        (canonicalNativeOperationInstructionResultStatic
          generatedClosedKernelOperationPe
          generatedClosedKernelOperationImports
          {instruction_prefix} {instruction.ordinal}) = true
      decide +kernel)

theorem {instruction_prefix}BehaviorExact
    (environment : NativeWorldEnvironment) :
    ({instruction_prefix}Replay environment).behavior =
      {behavior_term} := by
  simp only [{instruction_prefix}Replay, {behavior_term},
    generatedClosedKernelOperationNativeProgram,
    CheckedNativeOperationStoppedInstruction.ofCanonicalStaticChecked_behavior]

def {instruction_prefix}Postcondition
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationPostcondition
      ({instruction_prefix}Replay environment).behavior :=
  .ofStoppedReplay ({instruction_prefix}Replay environment)

def {instruction_prefix}Cutpoint
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationStoppedCutpoint
      ({instruction_prefix}Replay environment) :=
  .ofTrivial ({instruction_prefix}Replay environment)
    ({instruction_prefix}Postcondition environment)

def {instruction_prefix}Edge
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationStoppedEdge
      (generatedClosedKernelOperationNativeProgram environment) := {{
  instruction := {instruction_prefix}
  undefinedSlot := {instruction.ordinal}
  replay := {instruction_prefix}Replay environment
  cutpoint := {instruction_prefix}Cutpoint environment
}}"""
                )
        terminal_prefix = _native_instruction_prefix(
            function, block, block.instructions[-1]
        )
        if running_edges:
            trace_term = f"{block_prefix}RunningTrace"
            behaviors_term = f"{block_prefix}RunningBehaviors"
            behavior_exact_terms = ", ".join(
                f"{_native_instruction_prefix(function, block, instruction)}"
                "BehaviorExact"
                for instruction in block.instructions[:-1]
            )
            edge_terms = ", ".join(
                f"{_native_instruction_prefix(function, block, instruction)}"
                "Edge"
                for instruction in block.instructions[:-1]
            )
            definitions.append(
                f"""def {trace_term}
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningTrace
      (generatedClosedKernelOperationNativeProgram environment) := {{
  first := {running_edges[0]}
  tail := [{", ".join(running_edges[1:])}]
  checked := by rfl
}}

def {behaviors_term} : List SymbolicBehavior := [
  {", ".join(running_behaviors)}
]

theorem {behaviors_term}Exact
    (environment : NativeWorldEnvironment) :
    ({trace_term} environment).edges.map
        (fun edge => edge.replay.behavior) =
      {behaviors_term} := by
  simp [{trace_term}, CheckedNativeOperationRunningTrace.edges,
    {behaviors_term}, {edge_terms}, {behavior_exact_terms}]"""
            )
            running_term = f"some ({trace_term} environment)"
        else:
            running_term = "none"
        terminal_behavior = f"{terminal_prefix}Behavior"
        terminal_outcome = f"{block_prefix}TerminalOutcome"
        definitions.append(
            f"""def {block_prefix}Proof
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedClosedKernelOperationNativeProgram environment) := {{
  running := {running_term}
  terminal := {terminal_prefix}Edge environment
  checked := by rfl
}}

def {terminal_outcome} : NativeOperationOutcomePostcondition :=
  NativeOperationOutcomePostcondition.ofExpr
    ({terminal_behavior}.outcome.getD (.jump 0))

theorem {terminal_outcome}Exact
    (environment : NativeWorldEnvironment) :
    ({block_prefix}Proof environment).terminal.cutpoint.postcondition.outcome =
      {terminal_outcome} := by
  change ({terminal_prefix}Postcondition environment).outcome =
    {terminal_outcome}
  simp [{terminal_prefix}Postcondition,
    CheckedNativeOperationPostcondition.ofStoppedReplay,
    {terminal_outcome}, {terminal_prefix}BehaviorExact]"""
        )
        audits.append(f"#print axioms {block_prefix}Proof")
    body = "\n\n".join(definitions)
    audit_body = "\n".join(audits)
    return f"""import StageA.RelationalInterpreterKernelOperationTraceChecker
import {candidate_module}

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{body}

{audit_body}

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def _native_operation_function_core_source(
    function: NativeOperationFunctionReplaySpec,
    *,
    candidate_module: str,
) -> str:
    return _native_operation_block_source_group(
        function,
        (),
        candidate_module=candidate_module,
        include_function_replay=True,
    )


def _native_operation_block_source(
    function: NativeOperationFunctionReplaySpec,
    block: NativeOperationBlockReplaySpec,
    *,
    candidate_module: str,
) -> str:
    return _native_operation_block_source_group(
        function,
        (block,),
        candidate_module=candidate_module,
        include_function_replay=False,
    )


def _native_operation_function_core_module(
    function: NativeOperationFunctionReplaySpec,
) -> str:
    return (
        f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
        f"{function.ordinal:04d}Core"
    )


def _native_operation_block_module(
    function: NativeOperationFunctionReplaySpec,
    block: NativeOperationBlockReplaySpec,
) -> str:
    return (
        f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
        f"{function.ordinal:04d}Block{block.ordinal:04d}"
    )


def _native_operation_block_function_source(
    function: NativeOperationFunctionReplaySpec,
) -> str:
    imports = "\n".join(
        f"import StageA.{module}"
        for module in (
            _native_operation_function_core_module(function),
            *(
                _native_operation_block_module(function, block)
                for block in function.blocks
            ),
        )
    )
    block_terms = ", ".join(
        f"{_native_block_prefix(function, block)}Proof environment"
        for block in function.blocks
    )
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate

def generatedNativeOperationFunctionReplay{function.ordinal:04d}BlockProofs
    (environment : NativeWorldEnvironment) :
    List (CheckedNativeOperationBlock
      (generatedClosedKernelOperationNativeProgram environment)) := [
  {block_terms}
]

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def _native_operation_candidate_core_source(
    *,
    callback_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelCallback"
    ),
    data_module: str = "StageA.GeneratedInterpreterKernelDataBase",
) -> str:
    return f"""import StageA.RelationalInterpreterNativeWorld
import {callback_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelOperationCandidate

open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelData

/-- Environment-independent static identity used by decode and semantic
certificate layers. -/
abbrev generatedClosedKernelOperationPe :=
  generatedInterpreterKernelCandidatePe

abbrev generatedClosedKernelOperationImports :=
  generatedInterpreterKernelImports

/-- The one exact candidate used by every checked operation replay.  Step,
Invoke, Run, and nested calls share this definition, including the checked
finite indirect-target inventory. -/
abbrev generatedClosedKernelOperationNativeProgram
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram :=
  {{
    pe := generatedClosedKernelOperationPe
    imports := generatedClosedKernelOperationImports
    environment := environment
    indirectTargets := generatedNativeIndirectTargetInventory
  }}

theorem generatedClosedKernelOperationIndirectTargetsValid :
    forall environment,
      (generatedClosedKernelOperationNativeProgram environment).indirectTargets.valid
        (generatedClosedKernelOperationNativeProgram environment).pe = true := by
  intro environment
  change generatedNativeIndirectTargetInventory.valid
    generatedInterpreterKernelCandidatePe = true
  decide +kernel

#print axioms generatedClosedKernelOperationIndirectTargetsValid

end StageA.GeneratedRelational.InterpreterKernelOperationCandidate
"""


def _native_operation_candidate_source(
    *,
    core_module: str = (
        f"StageA.{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}"
    ),
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelCallback"
    ),
) -> str:
    return f"""import StageA.RelationalInterpreterKernelCallbackNativeWorldBridge
import {core_module}
import {kernel_module}
import {callback_module}

namespace StageA.GeneratedRelational.InterpreterKernelOperationCandidate

open StageA.Relational.InterpreterKernelCallbackNativeWorldBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCallback

def generatedClosedKernelOperationCallbackBinding
    (environment : NativeWorldEnvironment) :
    ExactKernelCallbackNativeWorldBinding generatedKernelCallbackInventory
      generatedCompiledKernelProgram
      (generatedClosedKernelOperationNativeProgram environment) := {{
  callbackChecked := by
    simp only [generatedClosedKernelOperationNativeProgram]
    decide +kernel
  candidateTargets := rfl
  nativeTargetsValid := by
    simp only [generatedClosedKernelOperationNativeProgram]
    decide +kernel
}}

#print axioms generatedClosedKernelOperationCallbackBinding

end StageA.GeneratedRelational.InterpreterKernelOperationCandidate
"""


def _native_operation_block_bundle_source(
    plan: InterpreterKernelOperationInstantiationPlan,
) -> str:
    imports = "\n".join(
        (
            "import StageA."
            f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
            f"{function.ordinal:04d}"
        )
        for function in plan.native_function_replays
    )
    proof_lists = ",\n  ".join(
        (
            f"generatedNativeOperationFunctionReplay{function.ordinal:04d}"
            "BlockProofs environment"
        )
        for function in plan.native_function_replays
    )
    boundary_targets = ", ".join(
        str(target) for target in plan.native_structural_boundary_targets
    )
    ranked_routes: list[str] = []
    ranked_route_audits: list[str] = []
    functions_by_ordinal = {
        function.ordinal: function
        for function in plan.native_function_replays
    }
    for route in plan.native_ranked_route_clusters:
        function = functions_by_ordinal[route.function_ordinal]
        blocks_by_rva = {
            block.entry_rva: block for block in function.blocks
        }
        prefix = (
            "generatedNativeOperationFunctionReplay"
            f"{route.function_ordinal:04d}RankedRouteCluster"
            f"{route.cluster_ordinal:04d}"
        )
        block_terms = ", ".join(
            f"{_native_block_prefix(function, blocks_by_rva[entry_rva])}"
            "Proof environment"
            for entry_rva in route.block_rvas
        )
        block_term = f"{prefix}Blocks environment"
        source_term = (
            f"{_native_block_prefix(function, blocks_by_rva[route.source_rva])}"
            "Proof environment"
        )
        rank_body = "0"
        for entry_rva, rank in reversed(route.ranks):
            rank_body = (
                f"if entryRva = {entry_rva} then {rank} else\n"
                f"      {rank_body}"
            )
        ranked_routes.append(
            f"""def {prefix}Blocks
    (environment : NativeWorldEnvironment) :
    List (CheckedNativeOperationBlock
      (generatedClosedKernelOperationNativeProgram environment)) := [
  {block_terms}
]

def {prefix}Source
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedClosedKernelOperationNativeProgram environment) :=
  {source_term}

theorem {prefix}SourceMember :
    forall environment,
      List.Mem ({prefix}Source environment) ({prefix}Blocks environment) := by
  intro environment
  simp only [generatedClosedKernelOperationNativeProgram]
  decide +kernel

def {prefix}Certificate :
    CheckedNativeOperationRankedRouteCertificate := {{
  stopRvas := [{", ".join(str(rva) for rva in route.stop_rvas)}]
  rank := fun entryRva =>
      {rank_body}
}}

theorem {prefix}Checked :
    forall environment,
      checkedNativeOperationRankedRouteCertificate
        ({block_term}) {prefix}Certificate = true := by
  intro environment
  simp only [generatedClosedKernelOperationNativeProgram]
  decide +kernel

def {prefix}Policy
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRankedRoutePolicy
      (generatedClosedKernelOperationNativeProgram environment)
      ({block_term}) :=
  checkedNativeOperationRankedRouteCertificate_sound
    ({block_term}) {prefix}Certificate
    ({prefix}Checked environment)"""
        )
        ranked_route_audits.extend(
            (
                f"#print axioms {prefix}SourceMember",
                f"#print axioms {prefix}Checked",
                f"#print axioms {prefix}Policy",
            )
        )
    ranked_route_source = "\n\n".join(ranked_routes)
    ranked_route_audit_source = "\n".join(ranked_route_audits)
    return f"""{imports}
import StageA.RelationalInterpreterKernelOperationGraphChecker
import StageA.RelationalInterpreterKernelOperationRankedStateRoute

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationRankedStateRoute
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedNativeOperationCheckedBlocks
    (environment : NativeWorldEnvironment) :
    List (CheckedNativeOperationBlock
      (generatedClosedKernelOperationNativeProgram environment)) :=
  List.flatten [
  {proof_lists}
]

def generatedNativeOperationCheckedBlockEntries
    (environment : NativeWorldEnvironment) : List Nat :=
  (generatedNativeOperationCheckedBlocks environment).map
    (fun block => block.entryRva)

def generatedNativeOperationCheckedBlockCount : Nat :=
  {sum(function.block_count for function in plan.native_function_replays)}

def generatedNativeOperationBoundaryTargetRvas : List Nat := [
  {boundary_targets}
]

theorem generatedNativeOperationCheckedBlockCountExact :
    forall environment,
      (generatedNativeOperationCheckedBlocks environment).length =
        generatedNativeOperationCheckedBlockCount := by
  intro environment
  simp only [generatedClosedKernelOperationNativeProgram]
  decide +kernel

theorem generatedNativeOperationCheckedBlockEntriesNodup :
    forall environment,
      (generatedNativeOperationCheckedBlockEntries environment).Nodup := by
  intro environment
  simp only [generatedClosedKernelOperationNativeProgram]
  decide +kernel

theorem generatedNativeOperationBoundaryTargetRvasNodup :
    generatedNativeOperationBoundaryTargetRvas.Nodup := by
  decide +kernel

theorem generatedNativeOperationGraphClosedWithBoundaries :
    forall environment,
      checkedNativeOperationGraphClosedWithBoundaries
        (generatedNativeOperationCheckedBlocks environment)
        generatedNativeOperationBoundaryTargetRvas = true := by
  intro environment
  simp only [generatedClosedKernelOperationNativeProgram]
  decide +kernel

{ranked_route_source}

#print axioms generatedNativeOperationCheckedBlockCountExact
#print axioms generatedNativeOperationCheckedBlockEntriesNodup
#print axioms generatedNativeOperationBoundaryTargetRvasNodup
#print axioms generatedNativeOperationGraphClosedWithBoundaries
{ranked_route_audit_source}

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def relational_interpreter_kernel_operation_instantiation_source(
    plan: InterpreterKernelOperationInstantiationPlan,
    *,
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepNative"
    ),
) -> str:
    """Render checked inventory facts and concrete semantic closure."""

    if re.fullmatch(
        r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*",
        data_module,
    ) is None:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "data module must be a qualified StageA Lean module"
        )
    if re.fullmatch(
        r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*",
        native_module,
    ) is None:
        raise RelationalInterpreterKernelOperationInstantiationError(
            "native module must be a qualified StageA Lean module"
        )
    sources = ", ".join(str(function.source_rva) for function in plan.functions)
    gap_ids = ",\n  ".join(
        json.dumps(gap.identifier) for gap in plan.endpoint_gaps
    )
    route_anchors = ",\n  ".join(
        f"({json.dumps(identifier)}, {rva})"
        for identifier, rva in plan.native_route_anchors
    )
    boundary_targets = ",\n  ".join(
        (
            f"({json.dumps(identifier)}, "
            f"[{', '.join(str(target) for target in targets)}])"
        )
        for identifier, targets in plan.native_boundary_targets
    )
    status = "true" if plan.constructed else "false"
    return f"""import StageA.RelationalInterpreterKernelOperationInstantiation
import StageA.RelationalInterpreterKernelOperationBoundaryChecker
import StageA.RelationalInterpreterKernelOperationGraphChecker
import StageA.RelationalInterpreterKernelOperationReplay
import StageA.RelationalInterpreterKernelOperationRouteChecker
import StageA.RelationalInterpreterKernelOperationStateBoundaryChecker
import StageA.RelationalInterpreterKernelOperationStateRouteChecker
import StageA.{INTERPRETER_KERNEL_OPERATION_CANDIDATE_MODULE}
import StageA.{INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE}
import StageA.GeneratedRelationalInterpreterKernelClosedCallTree
import StageA.GeneratedRelationalInterpreterKernelProgramLookupOperation
import StageA.GeneratedRelationalInterpreterKernelRunOperation
import StageA.GeneratedRelationalInterpreterKernelInvokeOperation
import StageA.GeneratedRelationalInterpreterKernelStepOperation
import {data_module}
import {native_module}

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelOperationInstantiation
open StageA.Relational.InterpreterKernelOperationBoundaryChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationRouteChecker
open StageA.Relational.InterpreterKernelOperationStateBoundaryChecker
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelClosedCallTree
open StageA.GeneratedRelational.InterpreterKernelInvokeOperation
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate
open StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation
open StageA.GeneratedRelational.InterpreterKernelRunOperation
open StageA.GeneratedRelational.InterpreterKernelStepOperation
open StageA.GeneratedRelational.InterpreterKernelStepNative

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedCheckedSemanticFunctionSourceRvas : List Nat := [
  {sources}
]

theorem generatedCheckedSemanticFunctionCount :
    generatedCheckedSemanticFunctionSourceRvas.length = {len(plan.functions)} := by
  decide +kernel

def generatedOperationInstantiationEndpointIds : List String := [
  {gap_ids}
]

def generatedOperationInstantiationConstructed : Bool := {status}

def generatedNativeOperationRouteAnchors : List (Prod String Nat) := [
  {route_anchors}
]

def generatedNativeOperationBoundaryTargets :
    List (Prod String (List Nat)) := [
  {boundary_targets}
]

/-- Re-index the reviewed static operation templates over the one candidate
that also carries the checked callback target inventory. -/
def generatedClosedInterpreterStepOperationStatic
    (environment : NativeWorldEnvironment) :
    InterpreterStepNativeStaticBinding generatedCompiledKernelProgram
      (generatedClosedKernelOperationNativeProgram environment) := {{
  function := (generatedInterpreterStepOperationStatic environment).function
  reflected := generatedInterpreterStepOperationReflected
  entryRvaExact :=
    (generatedInterpreterStepOperationStatic environment).entryRvaExact
  templateEntryExact :=
    (generatedInterpreterStepOperationStatic environment).templateEntryExact
}}

def generatedClosedRunFunctionOperationStatic
    (environment : NativeWorldEnvironment) :
    RunFunctionNativeStaticBinding generatedCompiledKernelProgram
      (generatedClosedKernelOperationNativeProgram environment) := {{
  function := (generatedRunFunctionOperationStatic environment).function
  reflected := generatedRunFunctionOperationReflected
  entryRvaExact :=
    (generatedRunFunctionOperationStatic environment).entryRvaExact
  templateEntryExact :=
    (generatedRunFunctionOperationStatic environment).templateEntryExact
  stepEntryRva :=
    (generatedRunFunctionOperationStatic environment).stepEntryRva
  stepEntryExact :=
    (generatedRunFunctionOperationStatic environment).stepEntryExact
}}

def generatedClosedInvokeCallOperationStatic
    (environment : NativeWorldEnvironment) :
    InvokeCallNativeStaticBinding generatedCompiledKernelProgram
      (generatedClosedKernelOperationNativeProgram environment) := {{
  function := (generatedInvokeCallOperationStatic environment).function
  reflected := generatedInvokeCallOperationReflected
  entryRvaExact :=
    (generatedInvokeCallOperationStatic environment).entryRvaExact
}}

theorem generatedCheckedSemanticRecordMissing :
    lookupProgramRecord semanticInterpreterProgramRecords
      {plan.missing_source_rva} = none := by
  decide +kernel

/-- Concrete exact-record bindings for the complete generated inventory. -/
def generatedSemanticFunctionBindings :
    GeneratedFiniteCheckedSemanticFunctionBindings :=
  generatedFiniteCheckedSemanticFunctionBindings

/-- Concrete semantic closure for the exact GNU record list. -/
def generatedSemanticCallTreeClosure :
    CheckedSemanticCallTreeClosure semanticInterpreterProgramRecords :=
  generatedSemanticFunctionBindings.toClosure

#print axioms generatedCheckedSemanticFunctionCount
#print axioms generatedCheckedSemanticRecordMissing
#print axioms generatedSemanticFunctionBindings
#print axioms generatedSemanticCallTreeClosure
#print axioms generatedClosedInterpreterStepOperationStatic
#print axioms generatedClosedRunFunctionOperationStatic
#print axioms generatedClosedInvokeCallOperationStatic

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def write_relational_interpreter_kernel_operation_instantiation_bundle(
    *,
    out: Path | str,
    semantic_record_module: str = (
        "GeneratedInterpreterKernelSemanticRecordBundle"
    ),
    **kwargs: Any,
) -> InterpreterKernelOperationInstantiationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    lean_output = output / "StageA"
    lean_output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_operation_instantiation_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_OPERATION_INSTANTIATION_PLAN_FILENAME,
        plan.payload(),
    )
    write_json(
        output / INTERPRETER_KERNEL_OPERATION_INSTANTIATION_INVENTORY_FILENAME,
        plan.function_inventory_payload(),
    )
    write_relational_interpreter_kernel_closed_call_tree_bundle(
        out=output,
        source_module=semantic_record_module,
        records_term=(
            "StageA.GeneratedRelational.InterpreterKernelData."
            "semanticInterpreterProgramRecords"
        ),
        functions=plan.functions,
    )
    (
        output / INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME
    ).replace(
        lean_output / INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME
    )
    (
        lean_output
        / f"{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}.lean"
    ).write_text(
        _native_operation_candidate_core_source(),
        encoding="ascii",
    )
    (
        lean_output / f"{INTERPRETER_KERNEL_OPERATION_CANDIDATE_MODULE}.lean"
    ).write_text(
        _native_operation_candidate_source(),
        encoding="ascii",
    )
    for function in plan.native_function_replays:
        core_module = _native_operation_function_core_module(function)
        (lean_output / f"{core_module}.lean").write_text(
            _native_operation_function_core_source(
                function,
                candidate_module=(
                    "StageA."
                    f"{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}"
                ),
            ),
            encoding="ascii",
        )
        for block in function.blocks:
            block_module = _native_operation_block_module(function, block)
            (lean_output / f"{block_module}.lean").write_text(
                _native_operation_block_source(
                    function,
                    block,
                    candidate_module=(
                        "StageA."
                        f"{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}"
                    ),
                ),
                encoding="ascii",
            )
        module = (
            f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
            f"{function.ordinal:04d}"
        )
        (lean_output / f"{module}.lean").write_text(
            _native_operation_block_function_source(function),
            encoding="ascii",
        )
    (
        lean_output
        / f"{INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE}.lean"
    ).write_text(
        _native_operation_block_bundle_source(plan),
        encoding="ascii",
    )
    (
        lean_output / INTERPRETER_KERNEL_OPERATION_INSTANTIATION_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_operation_instantiation_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE",
    "INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX",
    "INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE",
    "INTERPRETER_KERNEL_OPERATION_CANDIDATE_MODULE",
    "INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT",
    "INTERPRETER_KERNEL_OPERATION_INSTANTIATION_INVENTORY_FILENAME",
    "INTERPRETER_KERNEL_OPERATION_INSTANTIATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_OPERATION_INSTANTIATION_PLAN_FILENAME",
    "InterpreterKernelOperationInstantiationPlan",
    "OperationInstantiationEndpointGap",
    "RelationalInterpreterKernelOperationInstantiationError",
    "build_relational_interpreter_kernel_operation_instantiation_plan",
    "relational_interpreter_kernel_operation_instantiation_source",
    "write_relational_interpreter_kernel_operation_instantiation_bundle",
]
