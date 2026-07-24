"""Generate exact finite helper-path certificate surfaces.

Python proposes a finite block graph and rejects unresolved or cyclic control by
default. Lean rechecks every node against the compiled program, exact PE bytes,
decoded symbolic outcome, complete successor set, and decreasing rank. Runtime
proofs are emitted as independent per-node progress goals; Lean derives the
whole helper traversal by well-founded composition.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT
from .interpreter_kernel_block import INTERPRETER_KERNEL_BLOCK_PLAN_FORMAT


INTERPRETER_KERNEL_HELPER_PATH_FORMAT = (
    "stage-a-relational-interpreter-kernel-helper-path-v1"
)
INTERPRETER_KERNEL_HELPER_PATH_PLAN_FILENAME = "interpreter-kernel-helper-path.json"
INTERPRETER_KERNEL_HELPER_PATH_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelHelperPath.lean"
)

_LEAN_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_LEAN_AUTHORITY = re.compile(r"[A-Za-z_][A-Za-z0-9_.:'-]*\Z")


class RelationalInterpreterKernelHelperPathGenerationError(StageAInputError):
    """The proposed helper path is stale, ambiguous, or not fail-closed."""


@dataclass(frozen=True)
class HelperPathNodePlan:
    ordinal: int
    function_index: int
    block_index: int
    block_certificate_ordinal: int
    entry_rva: int
    terminal_external_rva: int | None
    rank: int
    targets: tuple[int, ...]

    @property
    def function_symbol(self) -> str:
        return f"generatedKernelFunction{self.function_index:04d}"

    @property
    def block_symbol(self) -> str:
        return (
            f"generatedKernelFunction{self.function_index:04d}"
            f"Block{self.block_index:04d}"
        )

    @property
    def block_certificate_symbol(self) -> str:
        return f"generatedKernelBlock{self.block_certificate_ordinal:04d}"

    @property
    def node_symbol(self) -> str:
        return f"generatedHelperPathNode{self.ordinal:04d}"

    def payload(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "function_index": self.function_index,
            "block_index": self.block_index,
            "block_certificate_ordinal": self.block_certificate_ordinal,
            "entry_rva": self.entry_rva,
            "terminal_external_rva": self.terminal_external_rva,
            "rank": self.rank,
            "targets": list(self.targets),
        }


@dataclass(frozen=True)
class InterpreterKernelHelperPathPlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    block_plan_path: Path
    block_plan_sha256: str
    candidate_sha256: str
    helper_entry_rva: int
    source_module: str
    block_context_module: str
    block_module_prefix: str
    block_shard_size: int
    nodes: tuple[HelperPathNodePlan, ...]
    external_call_rvas: tuple[int, ...]
    exceptional_authority: str | None
    cycle_entries: tuple[int, ...]
    exceptional_entries: tuple[int, ...]

    @property
    def strict(self) -> bool:
        return self.exceptional_authority is None

    @property
    def required_block_modules(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    f"{self.block_module_prefix}"
                    f"{node.block_certificate_ordinal // self.block_shard_size:04d}"
                    for node in self.nodes
                }
            )
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_HELPER_PATH_FORMAT,
            "acceptance_authority": False,
            "candidate_sha256": self.candidate_sha256,
            "inputs": {
                "kernel_plan": {
                    "path": self.kernel_plan_path.name,
                    "sha256": self.kernel_plan_sha256,
                },
                "block_plan": {
                    "path": self.block_plan_path.name,
                    "sha256": self.block_plan_sha256,
                },
            },
            "helper_entry_rva": self.helper_entry_rva,
            "external_call_rvas": list(self.external_call_rvas),
            "control_mode": (
                "strict-acyclic" if self.strict else "typed-invariant-ranking"
            ),
            "exceptional_authority": self.exceptional_authority,
            "cycle_entries": list(self.cycle_entries),
            "exceptional_entries": list(self.exceptional_entries),
            "nodes": [node.payload() for node in self.nodes],
            "closed_components": [
                "unique_compiled_block_identity",
                "exact_reflective_block_inventory",
                "finite_reachable_helper_graph",
                "decoded_direct_guard_coverage",
                "computed_native_state_threading",
                "exact_external_endpoint_identity",
                "well_founded_multi_block_composition",
                "derived_nonempty_helper_path",
            ],
            "remaining_proof_premises": [
                "per_block_universal_symbolic_concrete_agreement",
                "entry_invariant_establishment",
                "per_node_exact_computed_progress",
            ],
            "failure_mode": "incomplete",
        }


def _read_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"unable to read {context}: {path}"
        ) from exc
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _nat_tuple(value: object, context: str) -> tuple[int, ...]:
    values = tuple(_nat(item, context) for item in _array(value, context))
    if len(values) != len(set(values)):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"{context} must not contain duplicate targets"
        )
    return values


def _last_instruction_rva(block: Mapping[str, Any], context: str) -> int:
    instructions = _array(block.get("instructions"), f"{context} instructions")
    if not instructions:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            f"{context} has no instructions"
        )
    return _nat(
        _object(instructions[-1], f"{context} final instruction").get("rva"),
        f"{context} final instruction RVA",
    )


def _find_cycle(targets: Mapping[int, tuple[int, ...]]) -> tuple[int, ...]:
    visiting: set[int] = set()
    visited: set[int] = set()
    cycle: set[int] = set()

    def visit(entry: int) -> None:
        if entry in visited:
            return
        if entry in visiting:
            cycle.add(entry)
            return
        visiting.add(entry)
        for target in targets.get(entry, ()):
            if target in visiting:
                cycle.update((entry, target))
            else:
                visit(target)
                if target in cycle:
                    cycle.add(entry)
        visiting.remove(entry)
        visited.add(entry)

    for entry in targets:
        visit(entry)
    return tuple(sorted(cycle))


def _acyclic_ranks(
    entry: int, targets: Mapping[int, tuple[int, ...]]
) -> dict[int, int]:
    ranks: dict[int, int] = {}

    def rank(current: int) -> int:
        if current in ranks:
            return ranks[current]
        value = 0 if not targets[current] else 1 + max(
            rank(target) for target in targets[current]
        )
        ranks[current] = value
        return value

    rank(entry)
    return ranks


def build_relational_interpreter_kernel_helper_path_plan(
    *,
    kernel_plan: Path | str,
    block_plan: Path | str,
    helper_entry_rva: int,
    external_call_rvas: Sequence[int],
    exceptional_targets: Mapping[int, Sequence[int]] | None = None,
    exceptional_authority: str | None = None,
) -> InterpreterKernelHelperPathPlan:
    kernel_path = Path(kernel_plan)
    block_path = Path(block_plan)
    kernel = _read_object(kernel_path, "kernel plan")
    blocks = _read_object(block_path, "kernel block proof plan")
    if kernel.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "kernel plan format is unsupported"
        )
    if blocks.get("format") != INTERPRETER_KERNEL_BLOCK_PLAN_FORMAT:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "kernel block proof plan format is unsupported"
        )
    candidate = _object(kernel.get("candidate"), "kernel candidate")
    candidate_sha256 = candidate.get("pe_sha256")
    if not isinstance(candidate_sha256, str) or (
        blocks.get("candidate_sha256") != candidate_sha256
    ):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "kernel and block plans describe different candidate PEs"
        )
    helper_entry = _nat(helper_entry_rva, "helper entry RVA")
    terminals = tuple(_nat(value, "external call RVA") for value in external_call_rvas)
    if not terminals or len(terminals) != len(set(terminals)):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "external call RVAs must be finite, nonempty, and unique"
        )
    if exceptional_authority is not None and (
        _LEAN_AUTHORITY.fullmatch(exceptional_authority) is None
    ):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "exceptional authority identifier is invalid"
        )
    exceptional = {
        _nat(entry, "exceptional block entry"): tuple(
            _nat(target, "exceptional target") for target in targets
        )
        for entry, targets in (exceptional_targets or {}).items()
    }
    if any(len(targets) != len(set(targets)) for targets in exceptional.values()):
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "exceptional target sets must be unique"
        )
    if exceptional and exceptional_authority is None:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "exceptional targets require explicit invariant/ranking authority"
        )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    helper_matches = [
        (index, _object(function, f"kernel function {index}"))
        for index, function in enumerate(functions)
        if isinstance(function, Mapping)
        and function.get("rva_start") == helper_entry
        and function.get("role") == f"helper {helper_entry}"
    ]
    if len(helper_matches) != 1:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "helper entry is not the unique exact helper function"
        )

    block_by_entry: dict[int, tuple[int, int, Mapping[str, Any]]] = {}
    terminal_by_rva: dict[int, int] = {}
    for function_index, function_value in enumerate(functions):
        function = _object(function_value, f"kernel function {function_index}")
        for block_index, block_value in enumerate(
            _array(function.get("blocks"), f"kernel function {function_index} blocks")
        ):
            block = _object(
                block_value, f"kernel function {function_index} block {block_index}"
            )
            entry = _nat(block.get("entry_rva"), "kernel block entry RVA")
            if entry in block_by_entry:
                raise RelationalInterpreterKernelHelperPathGenerationError(
                    f"ambiguous compiled block entry RVA 0x{entry:x}"
                )
            block_by_entry[entry] = (function_index, block_index, block)
            last = _last_instruction_rva(block, f"kernel block 0x{entry:x}")
            if last in terminal_by_rva:
                raise RelationalInterpreterKernelHelperPathGenerationError(
                    f"ambiguous final instruction RVA 0x{last:x}"
                )
            terminal_by_rva[last] = entry

    missing_terminals = sorted(set(terminals) - set(terminal_by_rva))
    if missing_terminals:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "external call RVA is not the final instruction of a unique block: "
            + ", ".join(f"0x{rva:x}" for rva in missing_terminals)
        )
    if helper_entry not in block_by_entry:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "helper entry has no exact compiled block"
        )

    obligations = _array(blocks.get("proof_obligations"), "block proof obligations")
    obligation_by_entry: dict[int, Mapping[str, Any]] = {}
    for value in obligations:
        obligation = _object(value, "block proof obligation")
        entry = _nat(obligation.get("entry_rva"), "block obligation entry RVA")
        if entry in obligation_by_entry:
            raise RelationalInterpreterKernelHelperPathGenerationError(
                f"ambiguous block certificate entry RVA 0x{entry:x}"
            )
        obligation_by_entry[entry] = obligation

    terminal_entries = {terminal_by_rva[rva]: rva for rva in terminals}
    reachable: list[int] = []
    pending = [helper_entry]
    targets_by_entry: dict[int, tuple[int, ...]] = {}
    exceptional_entries: set[int] = set()
    while pending:
        entry = pending.pop()
        if entry in targets_by_entry:
            continue
        if entry not in block_by_entry:
            raise RelationalInterpreterKernelHelperPathGenerationError(
                f"unresolved helper-path target RVA 0x{entry:x}"
            )
        reachable.append(entry)
        if entry in terminal_entries:
            targets = ()
        elif entry in exceptional:
            targets = exceptional[entry]
            exceptional_entries.add(entry)
        else:
            block = block_by_entry[entry][2]
            targets = _nat_tuple(
                block.get("successors"), f"block 0x{entry:x} successors"
            )
            if not targets:
                raise RelationalInterpreterKernelHelperPathGenerationError(
                    f"unresolved helper-path exit at block 0x{entry:x}; "
                    "supply explicit targets and invariant/ranking authority"
                )
        targets_by_entry[entry] = targets
        pending.extend(reversed(targets))

    unreachable_terminals = sorted(set(terminal_entries) - set(reachable))
    if unreachable_terminals:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "submitted external call is unreachable from the helper entry"
        )
    cycle_entries = _find_cycle(targets_by_entry)
    if cycle_entries and exceptional_authority is None:
        raise RelationalInterpreterKernelHelperPathGenerationError(
            "cyclic helper path requires explicit invariant/ranking authority"
        )
    ranks = (
        {entry: 0 for entry in reachable}
        if cycle_entries
        else _acyclic_ranks(helper_entry, targets_by_entry)
    )

    node_plans: list[HelperPathNodePlan] = []
    for ordinal, entry in enumerate(reachable):
        function_index, block_index, _ = block_by_entry[entry]
        obligation = obligation_by_entry.get(entry)
        if obligation is None or (
            obligation.get("function_index"),
            obligation.get("block_index"),
        ) != (function_index, block_index):
            raise RelationalInterpreterKernelHelperPathGenerationError(
                f"block 0x{entry:x} lacks its exact reflective certificate"
            )
        node_plans.append(
            HelperPathNodePlan(
                ordinal=ordinal,
                function_index=function_index,
                block_index=block_index,
                block_certificate_ordinal=_nat(
                    obligation.get("ordinal"), "block certificate ordinal"
                ),
                entry_rva=entry,
                terminal_external_rva=terminal_entries.get(entry),
                rank=ranks[entry],
                targets=targets_by_entry[entry],
            )
        )

    source_module = blocks.get("source_module")
    context_module = blocks.get("context_module")
    module_prefix = blocks.get("module_prefix")
    shard_size = _nat(blocks.get("shard_size"), "block shard size")
    for value, context in (
        (source_module, "kernel source module"),
        (context_module, "block context module"),
        (module_prefix, "block module prefix"),
    ):
        if not isinstance(value, str) or _LEAN_LOCAL.fullmatch(value) is None:
            raise RelationalInterpreterKernelHelperPathGenerationError(
                f"{context} is invalid"
            )
    return InterpreterKernelHelperPathPlan(
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=sha256_file(kernel_path),
        block_plan_path=block_path,
        block_plan_sha256=sha256_file(block_path),
        candidate_sha256=candidate_sha256,
        helper_entry_rva=helper_entry,
        source_module=source_module,
        block_context_module=context_module,
        block_module_prefix=module_prefix,
        block_shard_size=shard_size,
        nodes=tuple(node_plans),
        external_call_rvas=terminals,
        exceptional_authority=exceptional_authority,
        cycle_entries=cycle_entries,
        exceptional_entries=tuple(sorted(exceptional_entries)),
    )


def _lean_nat_list(values: Sequence[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def relational_interpreter_kernel_helper_path_source(
    plan: InterpreterKernelHelperPathPlan,
) -> str:
    imports = "\n".join(
        f"import StageA.{module}" for module in plan.required_block_modules
    )
    node_definitions = []
    for node in plan.nodes:
        kind = "external" if node.terminal_external_rva is not None else "internal"
        node_definitions.append(
            f"""def {node.node_symbol} : HelperPathNode := {{
  function := {node.function_symbol}
  block := {node.block_symbol}
  rank := {node.rank}
  kind := .{kind}
  targets := {_lean_nat_list(node.targets)}
}}"""
        )
    node_names = ", ".join(node.node_symbol for node in plan.nodes)
    agreement_fields = "\n".join(
        f"  node{node.ordinal:04d} : "
        f"{node.block_certificate_symbol}UniversalAgreementGoal"
        for node in plan.nodes
    )
    reflected_entries = ",\n    ".join(
        f"""{{ node := {node.node_symbol}
      nodeListed := by decide +kernel
      certificate := {node.block_certificate_symbol}Certificate
        agreements.node{node.ordinal:04d} }}"""
        for node in plan.nodes
    )
    progress_fields = "\n".join(
        f"""  node{node.ordinal:04d} : forall undefinedSlot before calls
      eventIndex events world,
    invariant
      (.running {node.node_symbol}.entryRva undefinedSlot before calls
        eventIndex events world) ->
    Nonempty (ExactComputedHelperNodeProgress candidate
      generatedHelperPathGraph invariant rank {node.node_symbol} undefinedSlot
      before calls eventIndex events world)"""
        for node in plan.nodes
    )
    if len(plan.nodes) == 1:
        progress_dispatch = f"""    subst node
    exact progresses.node{plan.nodes[0].ordinal:04d} undefinedSlot before calls
      eventIndex events world holds"""
    else:
        alternatives = " | ".join(
            f"node{node.ordinal:04d}Exact" for node in plan.nodes
        )
        branches = "\n".join(
            f"""      | exact progresses.node{node.ordinal:04d} undefinedSlot
          before calls eventIndex events world holds"""
            for node in plan.nodes
        )
        progress_dispatch = (
            f"""    rcases nodeListed with {alternatives} <;> subst node
    all_goals
      first
{branches}"""
        )
    strict_theorem = ""
    control = (
        "Or.inr (Nonempty.intro (exceptionalAuthority localCertificate))"
    )
    exceptional_argument = f"""
    (exceptionalAuthority :
      forall localCertificate :
        HelperPathLocalProgressCertificate generatedCompiledKernelProgram
          candidate generatedHelperPathGraph precondition,
      HelperPathInvariantRankingAuthority generatedCompiledKernelProgram
        candidate generatedHelperPathGraph precondition localCertificate)"""
    if plan.strict:
        strict_theorem = """
theorem generatedHelperPathGraphStrictChecked :
    generatedHelperPathGraph.strictChecked generatedCompiledKernelProgram
      generatedKernelBlockCandidatePe generatedKernelBlockImports = true := by
  decide +kernel
"""
        control = (
            "Or.inl (by simpa [peExact, importsExact] using "
            "generatedHelperPathGraphStrictChecked)"
        )
        exceptional_argument = ""

    return f"""import StageA.RelationalInterpreterKernelHelperPath
import StageA.{plan.source_module}
import StageA.{plan.block_context_module}
{imports}

namespace StageA.GeneratedRelational.InterpreterKernelHelperPath

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelBlock
open StageA.Relational.InterpreterKernelHelperPath
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelBlock

{"\n\n".join(node_definitions)}

def generatedHelperPathGraph : HelperPathGraph := {{
  helperEntryRva := {plan.helper_entry_rva}
  nodes := [{node_names}]
}}

theorem generatedHelperPathGraphBaseChecked :
    generatedHelperPathGraph.baseChecked generatedCompiledKernelProgram
      generatedKernelBlockCandidatePe generatedKernelBlockImports = true := by
  decide +kernel
{strict_theorem}
structure GeneratedHelperPathBlockAgreements where
{agreement_fields}

def generatedHelperPathReflectiveInventory
    (agreements : GeneratedHelperPathBlockAgreements) :
    HelperPathReflectiveInventory generatedKernelBlockCandidatePe
      generatedKernelBlockImports generatedHelperPathGraph := {{
  certificates := [
    {reflected_entries}
  ]
  covers := by decide +kernel
}}

abbrev GeneratedHelperPathEntryInvariantGoal
    (candidate : ExactNativeWorldProgram)
    (precondition : HelperPathEntryPrecondition)
    (invariant : NativeWorldExecution -> Prop) : Prop :=
  forall before calls eventIndex events world,
    precondition before calls eventIndex events world ->
      invariant (.running generatedHelperPathGraph.helperEntryRva 0 before calls
        eventIndex events world)

structure GeneratedHelperPathNodeProgressGoals
    (candidate : ExactNativeWorldProgram)
    (invariant : NativeWorldExecution -> Prop)
    (rank : NativeWorldExecution -> Nat) where
{progress_fields}

def generatedHelperPathLocalProgressCertificate
    (candidate : ExactNativeWorldProgram)
    (precondition : HelperPathEntryPrecondition)
    (peExact : candidate.pe = generatedKernelBlockCandidatePe)
    (importsExact : candidate.imports = generatedKernelBlockImports)
    (agreements : GeneratedHelperPathBlockAgreements)
    (invariant : NativeWorldExecution -> Prop)
    (rank : NativeWorldExecution -> Nat)
    (establish :
      GeneratedHelperPathEntryInvariantGoal candidate precondition invariant)
    (progresses :
      GeneratedHelperPathNodeProgressGoals candidate invariant rank) :
    HelperPathLocalProgressCertificate generatedCompiledKernelProgram candidate
      generatedHelperPathGraph precondition := {{
  reflected := by
    simpa [peExact, importsExact] using
      generatedHelperPathReflectiveInventory agreements
  entryNode := {plan.nodes[0].node_symbol}
  entryListed := by decide +kernel
  entryExact := by decide +kernel
  entryInternal := by decide +kernel
  invariant
  rank
  establish
  progress := by
    intro node nodeListed undefinedSlot before calls eventIndex events world holds
    simp only [generatedHelperPathGraph, List.mem_cons, List.not_mem_nil,
      or_false] at nodeListed
{progress_dispatch}
}}

def generatedUniversalHelperPathExecutionCertificate
    (candidate : ExactNativeWorldProgram)
    (precondition : HelperPathEntryPrecondition)
    (peExact : candidate.pe = generatedKernelBlockCandidatePe)
    (importsExact : candidate.imports = generatedKernelBlockImports)
    (agreements : GeneratedHelperPathBlockAgreements)
    (invariant : NativeWorldExecution -> Prop)
    (rank : NativeWorldExecution -> Nat)
    (establish :
      GeneratedHelperPathEntryInvariantGoal candidate precondition invariant)
    (progresses :
      GeneratedHelperPathNodeProgressGoals candidate invariant rank)
    {exceptional_argument} :
    UniversalHelperPathExecutionCertificate generatedCompiledKernelProgram
      candidate generatedHelperPathGraph precondition := by
  let localCertificate :=
    generatedHelperPathLocalProgressCertificate candidate precondition peExact
      importsExact agreements invariant rank establish progresses
  exact {{
    localCertificate
    control := {control}
  }}

#print axioms generatedUniversalHelperPathExecutionCertificate

end StageA.GeneratedRelational.InterpreterKernelHelperPath
"""


def write_relational_interpreter_kernel_helper_path_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelHelperPathPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_helper_path_plan(**kwargs)
    write_json(output / INTERPRETER_KERNEL_HELPER_PATH_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_HELPER_PATH_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_helper_path_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_HELPER_PATH_FORMAT",
    "INTERPRETER_KERNEL_HELPER_PATH_LEAN_FILENAME",
    "INTERPRETER_KERNEL_HELPER_PATH_PLAN_FILENAME",
    "HelperPathNodePlan",
    "InterpreterKernelHelperPathPlan",
    "RelationalInterpreterKernelHelperPathGenerationError",
    "build_relational_interpreter_kernel_helper_path_plan",
    "relational_interpreter_kernel_helper_path_source",
    "write_relational_interpreter_kernel_helper_path_bundle",
]
