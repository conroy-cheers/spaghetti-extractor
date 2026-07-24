"""Generate fail-closed loop obligations for compiled interpreter kernels."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json


INTERPRETER_KERNEL_LOOP_PLAN_FORMAT = (
    "stage-a-relational-interpreter-kernel-loop-plan-v1"
)
INTERPRETER_KERNEL_LOOP_PLAN_FILENAME = "interpreter-kernel-loop-plan.json"
INTERPRETER_KERNEL_LOOP_LEAN_FILENAME = "GeneratedRelationalInterpreterKernelLoop.lean"
_KERNEL_PLAN_FORMATS = {
    "stage-a-relational-interpreter-kernel-plan-v2",
}
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelLoopGenerationError(StageAInputError):
    """The compiled-kernel CFG cannot support an exact loop certificate."""


@dataclass(frozen=True, order=True)
class CFGEdge:
    source: int
    target: int

    def payload(self) -> dict[str, int]:
        return {"source_rva": self.source, "target_rva": self.target}


@dataclass(frozen=True)
class LoopCertificatePlan:
    header_rva: int
    latch_rva: int
    body_entries: tuple[int, ...]
    entry_edges: tuple[CFGEdge, ...]
    internal_edges: tuple[CFGEdge, ...]
    exit_edges: tuple[CFGEdge, ...]

    @property
    def back_edge(self) -> CFGEdge:
        return CFGEdge(self.latch_rva, self.header_rva)

    def payload(self, *, loop_index: int, function_index: int) -> dict[str, Any]:
        prefix = f"kernel-loop:{function_index:04d}:{loop_index:04d}"
        frontiers = [
            {
                "id": f"{prefix}:invariant-establishment",
                "family": "kernel_loop_invariant_establishment",
                "status": "pending_lean_proof",
            },
            {
                "id": f"{prefix}:invariant-preservation",
                "family": "kernel_loop_invariant_preservation",
                "status": "pending_lean_proof",
                "edge_count": len(self.internal_edges),
            },
            {
                "id": f"{prefix}:rank-nonincreasing",
                "family": "kernel_loop_rank_nonincrease",
                "status": "pending_lean_proof",
                "edge_count": max(len(self.internal_edges) - 1, 0),
            },
            {
                "id": f"{prefix}:rank-decrease",
                "family": "kernel_loop_rank_decrease",
                "status": "pending_lean_proof",
                "edge": self.back_edge.payload(),
            },
            {
                "id": f"{prefix}:exit-postconditions",
                "family": "kernel_loop_exit_postconditions",
                "status": "pending_lean_proof",
                "edge_count": len(self.exit_edges),
            },
        ]
        return {
            "header_rva": self.header_rva,
            "latch_rva": self.latch_rva,
            "back_edge": self.back_edge.payload(),
            "body_entries": list(self.body_entries),
            "entry_edges": [edge.payload() for edge in self.entry_edges],
            "internal_edges": [edge.payload() for edge in self.internal_edges],
            "exit_edges": [edge.payload() for edge in self.exit_edges],
            "structural_status": "pending_lean_check",
            "semantic_status": "incomplete",
            "semantic_frontiers": frontiers,
        }


@dataclass(frozen=True)
class FunctionLoopPlan:
    function_index: int
    function_entry_rva: int
    function_role: str
    loops: tuple[LoopCertificatePlan, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "function_index": self.function_index,
            "function_entry_rva": self.function_entry_rva,
            "function_role": self.function_role,
            "exact_back_edge_count": len(self.loops),
            "loops": [
                loop.payload(loop_index=index, function_index=self.function_index)
                for index, loop in enumerate(self.loops)
            ],
        }


@dataclass(frozen=True)
class KernelLoopPlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    candidate_sha256: str
    function_count: int
    block_count: int
    functions: tuple[FunctionLoopPlan, ...]
    issues: tuple[dict[str, Any], ...]
    indirect_control_sites: tuple[dict[str, Any], ...] = ()

    @property
    def loop_count(self) -> int:
        return sum(len(function.loops) for function in self.functions)

    @property
    def semantic_frontiers(self) -> list[dict[str, Any]]:
        loop_frontiers = [
            frontier
            for function in self.functions
            for loop_index, loop in enumerate(function.loops)
            for frontier in loop.payload(
                loop_index=loop_index,
                function_index=function.function_index,
            )["semantic_frontiers"]
        ]
        target_frontiers = [
            {
                "id": f"kernel-indirect:{site['rva_start']:08x}:target-classifier",
                "family": "kernel_indirect_target_classification",
                "status": "pending_lean_proof",
                "location": {
                    "rva_start": site["rva_start"],
                    "rva_end": site["rva_end"],
                    "function_role": site["function_role"],
                },
                "requires": [
                    "exact_indirect_instruction",
                    "nonempty_finite_target_set",
                    "target_membership_for_all_reachable_states",
                ],
            }
            for site in self.indirect_control_sites
        ]
        return target_frontiers + loop_frontiers

    def payload(self) -> dict[str, Any]:
        core: dict[str, Any] = {
            "format": INTERPRETER_KERNEL_LOOP_PLAN_FORMAT,
            "status": "incomplete"
            if self.issues or self.semantic_frontiers
            else "ready",
            "acceptance_authority": False,
            "kernel_plan": {
                "path": self.kernel_plan_path.name,
                "sha256": self.kernel_plan_sha256,
            },
            "candidate_pe_sha256": self.candidate_sha256,
            "counts": {
                "functions": self.function_count,
                "blocks": self.block_count,
                "functions_with_back_edges": len(self.functions),
                "exact_cfg_back_edges": self.loop_count,
                "loop_shape_certificates": self.loop_count,
                "indirect_control_sites": len(self.indirect_control_sites),
                "structural_issues": len(self.issues),
                "semantic_frontiers": len(self.semantic_frontiers),
            },
            "structural_status": "incomplete" if self.issues else "pending_lean_check",
            "semantic_status": (
                "incomplete" if self.semantic_frontiers else "not_applicable"
            ),
            "functions": [function.payload() for function in self.functions],
            "indirect_control_sites": list(self.indirect_control_sites),
            "structural_issues": list(self.issues),
            "semantic_frontiers": self.semantic_frontiers,
        }
        digest = hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {**core, "artifact_sha256": digest}


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelLoopGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelLoopGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelLoopGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelLoopGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _reachable(
    entry: int,
    successors: Mapping[int, tuple[int, ...]],
    *,
    forbidden: int | None = None,
    allowed: set[int] | None = None,
) -> set[int]:
    if entry == forbidden or (allowed is not None and entry not in allowed):
        return set()
    reached: set[int] = set()
    pending = [entry]
    while pending:
        current = pending.pop()
        if current in reached or current == forbidden:
            continue
        if allowed is not None and current not in allowed:
            continue
        reached.add(current)
        pending.extend(successors.get(current, ()))
    return reached


def _function_loops(
    raw_function: Mapping[str, Any], function_index: int
) -> tuple[FunctionLoopPlan | None, list[dict[str, Any]], int]:
    context = f"kernel function {function_index}"
    entry = _nat(raw_function.get("rva_start"), f"{context}.rva_start")
    role = _string(raw_function.get("role"), f"{context}.role")
    raw_blocks = _list(raw_function.get("blocks"), f"{context}.blocks")
    if not raw_blocks:
        raise RelationalInterpreterKernelLoopGenerationError(f"{context} has no blocks")
    successors: dict[int, tuple[int, ...]] = {}
    for block_index, raw_block in enumerate(raw_blocks):
        block = _object(raw_block, f"{context}.blocks[{block_index}]")
        block_entry = _nat(
            block.get("entry_rva"), f"{context}.blocks[{block_index}].entry_rva"
        )
        if block_entry in successors:
            raise RelationalInterpreterKernelLoopGenerationError(
                f"{context} has duplicate block entry RVA 0x{block_entry:x}"
            )
        successors[block_entry] = tuple(
            _nat(value, f"{context}.blocks[{block_index}].successors")
            for value in _list(
                block.get("successors"),
                f"{context}.blocks[{block_index}].successors",
            )
        )
    if entry not in successors:
        raise RelationalInterpreterKernelLoopGenerationError(
            f"{context} entry RVA is not a block entry"
        )
    entries = set(successors)
    local_successors = {
        source: tuple(target for target in targets if target in entries)
        for source, targets in successors.items()
    }
    reachable = _reachable(entry, local_successors)
    issues: list[dict[str, Any]] = []
    if reachable != entries:
        missing = sorted(entries - reachable)
        issues.append(
            {
                "code": "kernel_loop_unreachable_cfg_nodes",
                "function_index": function_index,
                "function_role": role,
                "entries": missing,
                "message": "loop analysis requires rooted closure over every kernel block",
            }
        )

    predecessors: dict[int, set[int]] = {node: set() for node in entries}
    edges: list[CFGEdge] = []
    for source in sorted(entries):
        for target in local_successors[source]:
            edge = CFGEdge(source, target)
            if edge not in edges:
                edges.append(edge)
                if source in reachable:
                    predecessors[target].add(source)

    reachable_edges = [edge for edge in edges if edge.source in reachable]
    back_edges = sorted(
        edge
        for edge in reachable_edges
        if edge.target == entry
        or edge.source not in _reachable(entry, local_successors, forbidden=edge.target)
    )
    cyclic_edges = [
        edge
        for edge in reachable_edges
        if edge.source in _reachable(edge.target, local_successors)
    ]
    if cyclic_edges and not back_edges:
        issues.append(
            {
                "code": "irreducible_kernel_cycle",
                "function_index": function_index,
                "function_role": role,
                "edges": [edge.payload() for edge in cyclic_edges],
                "message": "cyclic CFG region has no dominator-backed natural-loop edge",
            }
        )
    loops: list[LoopCertificatePlan] = []
    for edge in back_edges:
        body = {edge.target, edge.source}
        pending = [] if edge.source == edge.target else [edge.source]
        while pending:
            current = pending.pop()
            for predecessor in predecessors[current]:
                if predecessor in body:
                    continue
                body.add(predecessor)
                if predecessor != edge.target:
                    pending.append(predecessor)
        entry_edges = tuple(
            candidate
            for candidate in edges
            if candidate.source not in body and candidate.target in body
        )
        bad_entries = [
            candidate for candidate in entry_edges if candidate.target != edge.target
        ]
        if bad_entries:
            issues.append(
                {
                    "code": "irreducible_kernel_loop_entry",
                    "function_index": function_index,
                    "function_role": role,
                    "header_rva": edge.target,
                    "latch_rva": edge.source,
                    "edges": [candidate.payload() for candidate in bad_entries],
                    "message": "natural loop has an entry that bypasses its header",
                }
            )
        body_reachable = _reachable(edge.target, local_successors, allowed=body)
        if body_reachable != body:
            issues.append(
                {
                    "code": "kernel_loop_body_not_header_reachable",
                    "function_index": function_index,
                    "function_role": role,
                    "header_rva": edge.target,
                    "latch_rva": edge.source,
                    "entries": sorted(body - body_reachable),
                    "message": "natural loop body is not closed from its header",
                }
            )
        loops.append(
            LoopCertificatePlan(
                header_rva=edge.target,
                latch_rva=edge.source,
                body_entries=tuple(sorted(body)),
                entry_edges=entry_edges,
                internal_edges=tuple(
                    candidate
                    for candidate in edges
                    if candidate.source in body and candidate.target in body
                ),
                exit_edges=tuple(
                    candidate
                    for candidate in edges
                    if candidate.source in body and candidate.target not in body
                ),
            )
        )
    covered_cyclic_edges = {
        candidate
        for loop in loops
        for candidate in cyclic_edges
        if candidate.source in loop.body_entries
        and candidate.target in loop.body_entries
    }
    if set(cyclic_edges) - covered_cyclic_edges:
        missing = sorted(set(cyclic_edges) - covered_cyclic_edges)
        issues.append(
            {
                "code": "kernel_cycle_not_covered_by_natural_loop",
                "function_index": function_index,
                "function_role": role,
                "edges": [edge.payload() for edge in missing],
                "message": "cyclic CFG edges are absent from all checked natural-loop bodies",
            }
        )
    if not loops:
        return None, issues, len(raw_blocks)
    return (
        FunctionLoopPlan(function_index, entry, role, tuple(loops)),
        issues,
        len(raw_blocks),
    )


def build_relational_interpreter_kernel_loop_plan(
    kernel_plan: Path | str,
) -> KernelLoopPlan:
    path = Path(kernel_plan)
    if not path.is_file():
        raise RelationalInterpreterKernelLoopGenerationError(
            f"interpreter kernel plan does not exist: {path}"
        )
    try:
        root = _object(json.loads(path.read_text(encoding="utf-8")), "kernel plan")
    except json.JSONDecodeError as error:
        raise RelationalInterpreterKernelLoopGenerationError(
            "interpreter kernel plan is not valid JSON"
        ) from error
    if root.get("format") not in _KERNEL_PLAN_FORMATS:
        raise RelationalInterpreterKernelLoopGenerationError(
            "unsupported interpreter kernel plan format"
        )
    candidate = _object(root.get("candidate"), "kernel plan candidate")
    candidate_sha256 = _string(
        candidate.get("pe_sha256"), "kernel plan candidate PE SHA-256"
    )
    raw_functions = _list(root.get("kernel_functions"), "kernel plan functions")
    if not raw_functions:
        raise RelationalInterpreterKernelLoopGenerationError(
            "interpreter kernel plan has no functions"
        )
    functions: list[FunctionLoopPlan] = []
    issues: list[dict[str, Any]] = []
    indirect_control_sites: list[dict[str, Any]] = []
    for issue_index, raw_issue in enumerate(
        _list(root.get("issues", []), "kernel plan issues")
    ):
        issue = _object(raw_issue, f"kernel plan issues[{issue_index}]")
        if issue.get("code") not in {
            "unsupported_indirect_kernel_call",
            "unsupported_indirect_kernel_jump",
        }:
            continue
        indirect_control_sites.append(
            {
                "kind": "call"
                if issue.get("code") == "unsupported_indirect_kernel_call"
                else "jump",
                "function_role": _string(
                    issue.get("function_role"),
                    f"kernel plan issues[{issue_index}].function_role",
                ),
                "rva_start": _nat(
                    issue.get("rva_start"),
                    f"kernel plan issues[{issue_index}].rva_start",
                ),
                "rva_end": _nat(
                    issue.get("rva_end"),
                    f"kernel plan issues[{issue_index}].rva_end",
                ),
            }
        )
    indirect_control_sites.sort(
        key=lambda item: (item["rva_start"], item["rva_end"], item["kind"])
    )
    block_count = 0
    for index, raw in enumerate(raw_functions):
        function, function_issues, blocks = _function_loops(
            _object(raw, f"kernel function {index}"), index
        )
        block_count += blocks
        issues.extend(function_issues)
        if function is not None:
            functions.append(function)
    return KernelLoopPlan(
        kernel_plan_path=path,
        kernel_plan_sha256=sha256_file(path),
        candidate_sha256=candidate_sha256,
        function_count=len(raw_functions),
        block_count=block_count,
        functions=tuple(functions),
        issues=tuple(issues),
        indirect_control_sites=tuple(indirect_control_sites),
    )


def _lean_loop(loop: LoopCertificatePlan) -> str:
    body = ", ".join(str(entry) for entry in loop.body_entries)
    return (
        "{ headerRva := "
        f"{loop.header_rva}, latchRva := {loop.latch_rva}, "
        f"bodyEntries := [{body}] }}"
    )


def _lean_function(function: FunctionLoopPlan) -> str:
    loops = ",\n      ".join(_lean_loop(loop) for loop in function.loops)
    return (
        "{\n    functionIndex := "
        f"{function.function_index}\n"
        f"    functionEntryRva := {function.function_entry_rva}\n"
        "    loops := [\n      "
        f"{loops}\n    ]\n  }}"
    )


def relational_interpreter_kernel_loop_source(
    plan: KernelLoopPlan,
    *,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
) -> str:
    if _LEAN_MODULE.fullmatch(kernel_module) is None:
        raise RelationalInterpreterKernelLoopGenerationError(
            "kernel_module must be a qualified StageA Lean module"
        )
    functions = ",\n  ".join(_lean_function(function) for function in plan.functions)
    return f"""import StageA.RelationalInterpreterKernelLoop
import {kernel_module}

namespace StageA.GeneratedRelational.InterpreterKernelLoop

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelLoop
open StageA.GeneratedRelational.InterpreterKernel

def generatedKernelLoopInventory : KernelLoopInventory := {{
  functions := [
  {functions}
  ]
}}

def GeneratedInterpreterKernelLoopStructuralGoal : Prop :=
  generatedKernelLoopInventory.checked generatedCompiledKernelProgram = true

def GeneratedInterpreterKernelLoopExactCFGGoal
    (pe : PE32) (imports : List PEImport) : Prop :=
  generatedCompiledKernelProgram.checked pe imports = true /\\
    GeneratedInterpreterKernelLoopStructuralGoal

def GeneratedInterpreterKernelTargetClassificationGoal
    (pe : PE32) (imports : List PEImport)
    (targets : KernelIndirectTargetInventory) : Prop :=
  targets.checked generatedCompiledKernelProgram pe imports = true

/-! This target is intentionally parameterized by contracts supplied by the
compiled-operation proof.  Generated statuses cannot choose invariants or
ranking functions and cannot close semantic induction. -/
def GeneratedInterpreterKernelLoopSemanticGoal
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (targets : KernelIndirectTargetInventory)
    (contracts : Nat -> Nat -> KernelLoopContract) : Prop :=
  GeneratedInterpreterKernelTargetClassificationGoal pe imports targets /\\
    generatedKernelLoopInventory.SemanticallyInductive
      generatedCompiledKernelProgram pe imports environment contracts

def GeneratedInterpreterKernelCFGExecutionGoal
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (targets : KernelIndirectTargetInventory)
    (before after : NativeExecution) : Prop :=
  ExactKernelCFGExecution generatedCompiledKernelProgram pe imports environment
    targets before after

def GeneratedInterpreterKernelOperationGoal
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (abi : KernelABIRelation) (targets : KernelIndirectTargetInventory)
    (contracts : Nat -> Nat -> KernelLoopContract)
    (operation : KernelOperation) : Prop :=
  KernelOperationCFGCertificate generatedCompiledKernelProgram pe imports
    environment abi targets generatedKernelLoopInventory contracts operation

theorem GeneratedInterpreterKernelOperationGoal.refines
    {{pe : PE32}} {{imports : List PEImport}} {{environment : NativeEnvironment}}
    {{abi : KernelABIRelation}} {{targets : KernelIndirectTargetInventory}}
    {{contracts : Nat -> Nat -> KernelLoopContract}}
    {{operation : KernelOperation}}
    (certificate : GeneratedInterpreterKernelOperationGoal pe imports environment
      abi targets contracts operation) :
    KernelOperationRefines generatedCompiledKernelProgram pe imports environment
      abi operation :=
  KernelOperationCFGCertificate.refines certificate

def GeneratedInterpreterCompiledKernelGoal
    (binding : KernelArtifactBinding)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (abi : KernelABIRelation) (targets : KernelIndirectTargetInventory)
    (contracts : Nat -> Nat -> KernelLoopContract) : Prop :=
  CompiledKernelCFGCertificate binding generatedCompiledKernelProgram pe imports
    environment abi targets generatedKernelLoopInventory contracts

theorem GeneratedInterpreterCompiledKernelGoal.refines
    {{binding : KernelArtifactBinding}}
    {{pe : PE32}} {{imports : List PEImport}} {{environment : NativeEnvironment}}
    {{abi : KernelABIRelation}} {{targets : KernelIndirectTargetInventory}}
    {{contracts : Nat -> Nat -> KernelLoopContract}}
    (certificate : GeneratedInterpreterCompiledKernelGoal binding pe imports
      environment abi targets contracts) :
    CompiledKernelRefinement binding generatedCompiledKernelProgram pe imports
      environment abi :=
  CompiledKernelCFGCertificate.refines certificate

end StageA.GeneratedRelational.InterpreterKernelLoop
"""


def write_relational_interpreter_kernel_loop_bundle(
    *,
    kernel_plan: Path | str,
    out: Path | str,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
) -> KernelLoopPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_loop_plan(kernel_plan)
    write_json(output / INTERPRETER_KERNEL_LOOP_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_LOOP_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_loop_source(plan, kernel_module=kernel_module),
        encoding="utf-8",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_LOOP_LEAN_FILENAME",
    "INTERPRETER_KERNEL_LOOP_PLAN_FILENAME",
    "INTERPRETER_KERNEL_LOOP_PLAN_FORMAT",
    "KernelLoopPlan",
    "RelationalInterpreterKernelLoopGenerationError",
    "build_relational_interpreter_kernel_loop_plan",
    "relational_interpreter_kernel_loop_source",
    "write_relational_interpreter_kernel_loop_bundle",
]
