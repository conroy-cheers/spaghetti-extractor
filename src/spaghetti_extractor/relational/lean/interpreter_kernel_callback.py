"""Generate checked indirect-callback ABI obligations for compiled kernels.

The classifier consumes only candidate bytes, the rooted compiled-kernel plan,
and an explicit target-provenance contract.  Linker symbols and the Stage B
runtime layout are proposal inputs; exact instruction bytes, relocation-backed
pointer cells, executable target entries, and cdecl stack stores are checked
again before any Lean goal is emitted.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import capstone
from capstone import x86_const

from ...stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ...util import sha256_bytes, sha256_file, write_json


INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT = (
    "stage-a-relational-interpreter-kernel-callback-contract-v1"
)
INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT = (
    "stage-a-relational-interpreter-kernel-callback-plan-v1"
)
INTERPRETER_KERNEL_CALLBACK_PLAN_FILENAME = "interpreter-kernel-callback-plan.json"
INTERPRETER_KERNEL_CALLBACK_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelCallback.lean"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GNU_MAP_SYMBOL = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$"
)
_CDECL_PRESERVED = ("ebx", "esi", "edi", "ebp")
_RUNTIME_FIELDS = {
    4: ("runtime_read", (4,), "word_in_eax"),
    8: ("runtime_write", (5,), "void"),
    12: ("runtime_undefined_value", (2, 3, 4), "word_in_eax"),
    16: ("runtime_external_call", (4,), "word_in_eax"),
    20: ("runtime_resolve_code_target", (3,), "word_in_eax"),
    24: ("runtime_replay_checked_x87", (4,), "word_in_eax"),
}


class RelationalInterpreterKernelCallbackGenerationError(StageAInputError):
    """Callback evidence is malformed, stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class CallbackIssue:
    code: str
    message: str
    site_rva: int | None = None
    role: str | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.site_rva is not None:
            result["site_rva"] = self.site_rva
        if self.role is not None:
            result["role"] = self.role
        return result


@dataclass(frozen=True)
class CallbackTargetPlan:
    id: int
    rva: int
    entry_bytes: bytes
    pointer_cells: tuple[int, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rva": self.rva,
            "entry_bytes": self.entry_bytes.hex(),
            "entry_sha256": sha256_bytes(self.entry_bytes),
            "pointer_cells": list(self.pointer_cells),
        }


@dataclass(frozen=True)
class CallbackSitePlan:
    id: int
    role: str
    function_role: str
    rva: int
    instruction_bytes: bytes
    continuation_rva: int
    target_operand: Mapping[str, Any]
    argument_offsets: tuple[int, ...]
    return_kind: str
    target_provenance: str
    targets: tuple[CallbackTargetPlan, ...]
    dynamic_requirements: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "function_role": self.function_role,
            "rva": self.rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_sha256": sha256_bytes(self.instruction_bytes),
            "continuation_rva": self.continuation_rva,
            "target_operand": dict(self.target_operand),
            "cdecl": {
                "argument_count": len(self.argument_offsets),
                "argument_offsets": list(self.argument_offsets),
                "caller_stack_delta": 0,
                "preserved_registers": list(_CDECL_PRESERVED),
                "return_kind": self.return_kind,
            },
            "target_provenance": self.target_provenance,
            "targets": [target.payload() for target in self.targets],
            "dynamic_requirements": list(self.dynamic_requirements),
        }


@dataclass(frozen=True)
class InterpreterKernelCallbackPlan:
    candidate_sha256: str
    candidate_size: int
    sites: tuple[CallbackSitePlan, ...]
    issues: tuple[CallbackIssue, ...]

    @property
    def obligations(self) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        for site in self.sites:
            stem = f"kernel-callback:{site.rva:08x}"
            rows.extend((
                {
                    "id": f"{stem}:exact-site-and-target-bytes",
                    "family": "indirect_callback_exact_bytes",
                    "site_rva": site.rva,
                    "status": "pending_lean_check",
                },
                {
                    "id": f"{stem}:target-membership",
                    "family": "indirect_callback_target_membership",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                    "requirements": list(site.dynamic_requirements),
                },
                {
                    "id": f"{stem}:cdecl-entry",
                    "family": "indirect_callback_cdecl_entry",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
                {
                    "id": f"{stem}:return-state",
                    "family": "indirect_callback_return_state",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
                {
                    "id": f"{stem}:nested-frames",
                    "family": "indirect_callback_nested_frames",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
                {
                    "id": f"{stem}:relocation-backed-target-cells",
                    "family": "indirect_callback_target_cell_provenance",
                    "site_rva": site.rva,
                    "status": "pending_lean_check",
                },
                {
                    "id": f"{stem}:callback-aware-target-execution",
                    "family": "indirect_callback_target_execution",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
            ))
        for index, issue in enumerate(self.issues):
            rows.append({
                "id": f"kernel-callback-frontier:{index:04d}",
                "family": "indirect_callback_frontier",
                "site_rva": issue.site_rva,
                "status": "incomplete",
                "reason_code": issue.code,
                "message": issue.message,
            })
        return tuple(rows)

    def payload(self) -> dict[str, Any]:
        core: dict[str, Any] = {
            "format": INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
            "status": "incomplete",
            "acceptance_authority": False,
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "counts": {
                "indirect_sites": len(self.sites) + sum(
                    issue.code == "unknown_indirect_callback_target"
                    for issue in self.issues
                ),
                "classified_sites": len(self.sites),
                "finite_targets": sum(len(site.targets) for site in self.sites),
                "static_frontiers": len(self.issues),
                "pending_lean_obligations": len(self.sites) * 7,
            },
            "sites": [site.payload() for site in self.sites],
            "issues": [issue.payload() for issue in self.issues],
            "proof_obligations": list(self.obligations),
        }
        core["artifact_sha256"] = sha256_bytes(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        )
        return core


@dataclass(frozen=True)
class _Instruction:
    rva: int
    data: bytes


@dataclass(frozen=True)
class _IndirectSite:
    function_role: str
    instruction: _Instruction
    prefix: tuple[_Instruction, ...]
    target_operand: Mapping[str, Any]
    target_register: str | None
    target_field_offset: int | None
    argument_offsets: tuple[int, ...]


def propose_stage_b_interpreter_kernel_callback_contract(
    *,
    candidate_pe: Path | str,
    kernel_plan: Any,
    linker_map: Path | str,
    native_engine_plan: Path | str,
) -> dict[str, Any]:
    """Propose the standard generated-interpreter callback classification.

    The proposal is generic to the stable Stage B runtime layout.  The build
    function below rechecks every proposed pointer cell, relocation, target,
    instruction, and stack argument directly against the candidate.
    """

    candidate_path = _file(candidate_pe, "candidate PE")
    linker_path = _file(linker_map, "linker map")
    engine_path = _file(native_engine_plan, "native engine plan")
    binary = _parse_stage_a_pe(candidate_path)
    sites = _discover_indirect_sites(binary, kernel_plan)
    symbols = _map_symbols(linker_path, binary)
    runtime_rva = _unique_symbol(symbols, "stage_b_native_runtime_instance")
    engine = _json_object(engine_path, "native engine plan")
    external_sites = _list(engine.get("external_sites"), "external sites")
    bridge_table: tuple[tuple[int, ...], tuple[int, ...]] | None = None

    rows: list[dict[str, Any]] = []
    for site in sites:
        offset = site.target_field_offset
        if offset == 4 and not site.argument_offsets:
            if bridge_table is None:
                bridge_table = _locate_bridge_table(
                    binary, symbols, external_sites
                )
            bridge_cells, bridge_targets = bridge_table
            rows.append({
                "site_rva": site.instruction.rva,
                "role": "native_bridge_dispatch",
                "argument_count": 0,
                "return_kind": "void",
                "target_provenance": "immutable_finite_bridge_table",
                "pointer_cells": list(bridge_cells),
                "target_rvas": list(bridge_targets),
                "dynamic_requirements": [
                    "checked_bridge_table_selector_membership",
                    "callback_target_execution_refinement",
                ],
            })
            continue
        runtime = _RUNTIME_FIELDS.get(offset or -1)
        if runtime is None or len(site.argument_offsets) not in runtime[1]:
            rows.append({
                "site_rva": site.instruction.rva,
                "role": "unknown",
                "argument_count": len(site.argument_offsets),
                "return_kind": "word_in_eax",
                "target_provenance": "unknown",
                "pointer_cells": [],
                "target_rvas": [],
                "dynamic_requirements": ["finite_target_inventory_required"],
            })
            continue
        role, _argument_counts, return_kind = runtime
        argument_count = len(site.argument_offsets)
        cell = runtime_rva + int(offset)
        target_word = _read_u32(binary, cell, f"{role} target cell")
        target_rva = _pointer_to_rva(binary, target_word, f"{role} target")
        rows.append({
            "site_rva": site.instruction.rva,
            "role": role,
            "argument_count": argument_count,
            "return_kind": return_kind,
            "target_provenance": "relocation_backed_runtime_cell",
            "pointer_cells": [cell],
            "target_rvas": [target_rva],
            "dynamic_requirements": [
                "runtime_pointer_identity",
                "runtime_target_cell_preserved",
                "callback_target_execution_refinement",
            ],
        })

    return {
        "format": INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT,
        "candidate_sha256": binary.sha256,
        "sites": rows,
        "proposal_inputs": {
            "linker_map_sha256": sha256_file(linker_path),
            "native_engine_plan_sha256": sha256_file(engine_path),
        },
    }


def build_relational_interpreter_kernel_callback_plan(
    *,
    candidate_pe: Path | str,
    kernel_plan: Any,
    classification_contract: Path | str | Mapping[str, Any],
) -> InterpreterKernelCallbackPlan:
    candidate_path = _file(candidate_pe, "candidate PE")
    binary = _parse_stage_a_pe(candidate_path)
    contract = (
        _json_object(_file(classification_contract, "classification contract"),
                     "classification contract")
        if isinstance(classification_contract, (str, Path))
        else dict(classification_contract)
    )
    if contract.get("format") != INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT:
        raise RelationalInterpreterKernelCallbackGenerationError(
            "unsupported callback classification contract format"
        )
    if contract.get("candidate_sha256") != binary.sha256:
        raise RelationalInterpreterKernelCallbackGenerationError(
            "callback classification contract binds a different candidate PE"
        )

    discovered = _discover_indirect_sites(binary, kernel_plan)
    discovered_by_rva = {site.instruction.rva: site for site in discovered}
    rows = _list(contract.get("sites"), "callback classification sites")
    submitted: dict[int, Mapping[str, Any]] = {}
    for index, raw in enumerate(rows):
        row = _mapping(raw, f"callback classification site {index}")
        rva = _u32(row.get("site_rva"), f"callback classification site {index} RVA")
        if rva in submitted:
            raise RelationalInterpreterKernelCallbackGenerationError(
                f"duplicate callback classification at RVA 0x{rva:x}"
            )
        submitted[rva] = row
    extra = sorted(set(submitted) - set(discovered_by_rva))
    if extra:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"classification names non-indirect kernel site RVA 0x{extra[0]:x}"
        )

    relocations = _highlow_relocations(binary)
    issues: list[CallbackIssue] = []
    plans: list[CallbackSitePlan] = []
    for site_id, site in enumerate(discovered):
        row = submitted.get(site.instruction.rva)
        if row is None:
            issues.append(CallbackIssue(
                "unknown_indirect_callback_target",
                "indirect kernel call has no callback classification",
                site.instruction.rva,
                site.function_role,
            ))
            continue
        role = _string(row.get("role"), "callback role")
        provenance = _string(
            row.get("target_provenance"), "callback target provenance"
        )
        argument_count = _u32(row.get("argument_count"), "callback argument count")
        expected_offsets = tuple(index * 4 for index in range(argument_count))
        if site.argument_offsets != expected_offsets:
            issues.append(CallbackIssue(
                "cdecl_argument_layout_unproved",
                f"expected stack offsets {expected_offsets}, observed {site.argument_offsets}",
                site.instruction.rva,
                role,
            ))
            continue
        return_kind = _string(row.get("return_kind"), "callback return kind")
        if return_kind not in {"void", "word_in_eax"}:
            raise RelationalInterpreterKernelCallbackGenerationError(
                f"unsupported callback return kind {return_kind}"
            )
        pointer_cells = tuple(
            _u32(value, "callback target pointer cell")
            for value in _list(row.get("pointer_cells"), "callback pointer cells")
        )
        target_rvas = tuple(
            _u32(value, "callback target RVA")
            for value in _list(row.get("target_rvas"), "callback target RVAs")
        )
        if not target_rvas:
            issues.append(CallbackIssue(
                "unknown_indirect_callback_target",
                "callback classification has no finite target set",
                site.instruction.rva,
                role,
            ))
            continue
        if len(set(target_rvas)) != len(target_rvas):
            raise RelationalInterpreterKernelCallbackGenerationError(
                f"callback target set at RVA 0x{site.instruction.rva:x} is ambiguous"
            )
        if len(pointer_cells) != len(target_rvas):
            raise RelationalInterpreterKernelCallbackGenerationError(
                f"callback target cells and RVAs differ at RVA 0x{site.instruction.rva:x}"
            )
        targets: list[CallbackTargetPlan] = []
        for target_id, (cell, target_rva) in enumerate(
            zip(pointer_cells, target_rvas, strict=True)
        ):
            if cell not in relocations:
                raise RelationalInterpreterKernelCallbackGenerationError(
                    f"callback target cell RVA 0x{cell:x} lacks a PE32 HIGHLOW relocation"
                )
            pointer = _read_u32(binary, cell, "callback target pointer cell")
            if _pointer_to_rva(binary, pointer, "callback target pointer") != target_rva:
                raise RelationalInterpreterKernelCallbackGenerationError(
                    f"callback target cell RVA 0x{cell:x} does not name RVA 0x{target_rva:x}"
                )
            entry_bytes = _target_entry_bytes(binary, target_rva)
            targets.append(CallbackTargetPlan(
                id=target_id,
                rva=target_rva,
                entry_bytes=entry_bytes,
                pointer_cells=(cell,),
            ))
        requirements = tuple(
            _string(value, "callback dynamic requirement")
            for value in _list(
                row.get("dynamic_requirements"), "callback dynamic requirements"
            )
        )
        if not requirements:
            raise RelationalInterpreterKernelCallbackGenerationError(
                f"callback classification at RVA 0x{site.instruction.rva:x} hides dynamic proof requirements"
            )
        plans.append(CallbackSitePlan(
            id=site_id,
            role=role,
            function_role=site.function_role,
            rva=site.instruction.rva,
            instruction_bytes=site.instruction.data,
            continuation_rva=site.instruction.rva + len(site.instruction.data),
            target_operand=site.target_operand,
            argument_offsets=site.argument_offsets,
            return_kind=return_kind,
            target_provenance=provenance,
            targets=tuple(targets),
            dynamic_requirements=requirements,
        ))

    return InterpreterKernelCallbackPlan(
        candidate_sha256=binary.sha256,
        candidate_size=binary.size,
        sites=tuple(plans),
        issues=tuple(issues),
    )


def relational_interpreter_kernel_callback_source(
    plan: InterpreterKernelCallbackPlan,
) -> str:
    definitions: list[str] = []
    site_names: list[str] = []
    cell_inventory_names: list[str] = []
    for site_index, site in enumerate(plan.sites):
        target_names: list[str] = []
        cell_names: list[str] = []
        cell_id = 0
        for target_index, target in enumerate(site.targets):
            name = f"generatedKernelCallback{site_index:04d}Target{target_index:04d}"
            definitions.append(
                f"def {name} : CallbackTargetEntry := {{\n"
                f"  id := {target.id}\n"
                f"  entry := {{ rva := {target.rva}, bytes := {_lean_bytes(target.entry_bytes)} }}\n"
                "}"
            )
            target_names.append(name)
            for cell_rva in target.pointer_cells:
                cell_name = (
                    f"generatedKernelCallback{site_index:04d}Cell{cell_id:04d}"
                )
                definitions.append(
                    f"def {cell_name} : RelocationBackedCallbackTargetCell := {{\n"
                    f"  id := {cell_id}\n"
                    f"  cellRva := {cell_rva}\n"
                    f"  targetId := {target.id}\n"
                    "}"
                )
                cell_names.append(cell_name)
                cell_id += 1
        cell_inventory_name = (
            f"generatedKernelCallback{site_index:04d}TargetCells"
        )
        definitions.append(
            f"def {cell_inventory_name} : "
            "RelocationBackedCallbackTargetInventory := {\n"
            f"  cells := [{', '.join(cell_names)}]\n"
            "}"
        )
        cell_inventory_names.append(cell_inventory_name)
        site_name = f"generatedKernelCallbackSite{site_index:04d}"
        definitions.append(
            f"def {site_name} : KernelIndirectCallbackSite := {{\n"
            f"  id := {site.id}\n"
            f"  instruction := {{ rva := {site.rva}, bytes := {_lean_bytes(site.instruction_bytes)} }}\n"
            f"  continuationRva := {site.continuation_rva}\n"
            f"  targetOperand := {_lean_operand(site.target_operand)}\n"
            "  abi := {\n"
            f"    argumentCount := {len(site.argument_offsets)}\n"
            f"    argumentOffsets := {_lean_nat_list(site.argument_offsets)}\n"
            "    callerStackDelta := 0\n"
            "    preservedRegisters := [.ebx, .esi, .edi, .ebp]\n"
            f"    returnKind := .{'void' if site.return_kind == 'void' else 'wordInEax'}\n"
            "  }\n"
            f"  targets := {{ entries := [{', '.join(target_names)}] }}\n"
            "}"
        )
        site_names.append(site_name)
    cell_dispatch = "{ cells := [] }"
    for site_index in reversed(range(len(site_names))):
        cell_dispatch = (
            f"if site.id == {plan.sites[site_index].id} then "
            f"{cell_inventory_names[site_index]} else {cell_dispatch}"
        )
    return f"""import StageA.RelationalInterpreterKernelCallbackNativeWorldBridge

namespace StageA.GeneratedRelational.InterpreterKernelCallback

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallbackNativeWorldBridge
open StageA.Relational.InterpreterNativeWorld

{chr(10).join(definitions)}

def generatedKernelCallbackInventory : KernelCallbackInventory := {{
  sites := [{', '.join(site_names)}]
}}

def generatedNativeIndirectTargetInventory : NativeIndirectTargetInventory :=
  kernelCallbackNativeTargetInventory generatedKernelCallbackInventory

def generatedKernelCallbackTargetCells
    (site : KernelIndirectCallbackSite) :
    RelocationBackedCallbackTargetInventory :=
  {cell_dispatch}

def GeneratedKernelCallbackStaticGoal (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) : Prop :=
  And (generatedKernelCallbackInventory.checked program pe imports = true)
    (forall site, List.Mem site generatedKernelCallbackInventory.sites ->
      (generatedKernelCallbackTargetCells site).checked pe site.targets = true)

def GeneratedKernelCallbackNativeWorldGoal (program : CompiledKernelProgram)
    (candidate : ExactNativeWorldProgram) : Prop :=
  ExactKernelCallbackNativeWorldBinding generatedKernelCallbackInventory
    program candidate

def GeneratedKernelCallbackRefinementGoal (program : CompiledKernelProgram)
    (context : StaticProofContext) (pe : PE32) (imports : List PEImport)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite -> KernelCallbackRun -> Prop) : Prop :=
  CompiledKernelCallbacksRefine context generatedKernelCallbackInventory program
    pe imports sourceInvariant runs

def GeneratedKernelCallbackEntryRefinementGoal (program : CompiledKernelProgram)
    (context : StaticProofContext) (world : RelationalWorld)
    (pe : PE32) (imports : List PEImport)
    (contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite -> KernelCallbackExecutionTrace -> Prop) :
    Prop :=
  CompiledKernelCallbackEntriesRefine context world
    generatedKernelCallbackInventory program pe imports
    generatedKernelCallbackTargetCells contracts sourceInvariant runs

def GeneratedKernelCallbackAwareOperationGoal
    (program : CompiledKernelProgram) (context : StaticProofContext)
    (world : RelationalWorld) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (abi : KernelABIRelation)
    (trampolines : KernelExternalRetTrampolineInventory)
    (contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract)
    (trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite -> KernelCallbackExecutionTrace -> Prop)
    (operation : KernelOperation) : Prop :=
  KernelOperationCallbackCertificate context world
    generatedKernelCallbackInventory program pe imports environment abi
    trampolines generatedKernelCallbackTargetCells contracts
    trampolineContracts sourceInvariant runs operation

end StageA.GeneratedRelational.InterpreterKernelCallback
"""


def write_relational_interpreter_kernel_callback_bundle(
    *,
    candidate_pe: Path | str,
    kernel_plan: Any,
    classification_contract: Path | str | Mapping[str, Any],
    out_dir: Path | str,
) -> InterpreterKernelCallbackPlan:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_callback_plan(
        candidate_pe=candidate_pe,
        kernel_plan=kernel_plan,
        classification_contract=classification_contract,
    )
    write_json(output / INTERPRETER_KERNEL_CALLBACK_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_CALLBACK_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_callback_source(plan), encoding="ascii"
    )
    return plan


def _discover_indirect_sites(
    binary: StageABinary, kernel_plan: Any
) -> tuple[_IndirectSite, ...]:
    result: list[_IndirectSite] = []
    for function_role, blocks in _kernel_blocks(kernel_plan):
        for raw_block in blocks:
            instructions = tuple(_block_instructions(raw_block))
            for index, instruction in enumerate(instructions):
                decoded = _decode_one(binary, instruction)
                if not decoded.group(capstone.CS_GRP_CALL):
                    continue
                if len(decoded.operands) != 1 or decoded.operands[0].type == x86_const.X86_OP_IMM:
                    continue
                operand, register = _target_operand(decoded)
                prefix = instructions[:index]
                result.append(_IndirectSite(
                    function_role=function_role,
                    instruction=instruction,
                    prefix=prefix,
                    target_operand=operand,
                    target_register=register,
                    target_field_offset=_target_field_offset(binary, prefix, register),
                    argument_offsets=_argument_offsets(binary, prefix),
                ))
    return tuple(sorted(result, key=lambda item: item.instruction.rva))


def _kernel_blocks(kernel_plan: Any) -> Iterable[tuple[str, Sequence[Any]]]:
    if hasattr(kernel_plan, "functions"):
        for function in kernel_plan.functions:
            yield str(function.role), function.blocks
        return
    value = (
        _json_object(Path(kernel_plan), "kernel plan")
        if isinstance(kernel_plan, (str, Path))
        else _mapping(kernel_plan, "kernel plan")
    )
    functions = _list(value.get("kernel_functions"), "kernel functions")
    for index, raw in enumerate(functions):
        function = _mapping(raw, f"kernel function {index}")
        yield _string(function.get("role"), "kernel function role"), _list(
            function.get("blocks"), "kernel function blocks"
        )


def _block_instructions(block: Any) -> Iterable[_Instruction]:
    values = block.instructions if hasattr(block, "instructions") else _list(
        _mapping(block, "kernel block").get("instructions"),
        "kernel block instructions",
    )
    for raw in values:
        if hasattr(raw, "rva"):
            yield _Instruction(int(raw.rva), bytes(raw.data))
        else:
            row = _mapping(raw, "kernel instruction")
            yield _Instruction(
                _u32(row.get("rva"), "kernel instruction RVA"),
                bytes.fromhex(_string(row.get("bytes"), "kernel instruction bytes")),
            )


def _decode_one(binary: StageABinary, instruction: _Instruction) -> Any:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    rows = list(decoder.disasm(
        instruction.data, binary.image_base + instruction.rva, count=1
    ))
    if len(rows) != 1 or bytes(rows[0].bytes) != instruction.data:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"kernel instruction at RVA 0x{instruction.rva:x} does not decode exactly"
        )
    return rows[0]


def _target_operand(decoded: Any) -> tuple[dict[str, Any], str | None]:
    operand = decoded.operands[0]
    if operand.type == x86_const.X86_OP_REG:
        name = decoded.reg_name(operand.reg).lower()
        return {"kind": "register", "register": name}, name
    if operand.type == x86_const.X86_OP_MEM:
        memory = operand.mem
        base = decoded.reg_name(memory.base).lower() if memory.base else None
        index = decoded.reg_name(memory.index).lower() if memory.index else None
        scale = int(memory.scale) if memory.index else 1
        if scale not in {1, 2, 4, 8}:
            raise RelationalInterpreterKernelCallbackGenerationError(
                "indirect callback uses unsupported index scale"
            )
        return {
            "kind": "memory",
            "base": base,
            "index": index,
            "scale_shift": {1: 0, 2: 1, 4: 2, 8: 3}[scale],
            "displacement": int(memory.disp) & 0xFFFFFFFF,
        }, None
    raise RelationalInterpreterKernelCallbackGenerationError(
        "indirect callback target is neither a register nor memory"
    )


def _target_field_offset(
    binary: StageABinary, prefix: Sequence[_Instruction], target_register: str | None
) -> int | None:
    if target_register is None:
        return None
    for instruction in reversed(prefix):
        decoded = _decode_one(binary, instruction)
        if len(decoded.operands) < 2 or decoded.operands[0].type != x86_const.X86_OP_REG:
            continue
        if decoded.reg_name(decoded.operands[0].reg).lower() != target_register:
            continue
        source = decoded.operands[1]
        if source.type != x86_const.X86_OP_MEM:
            return None
        return int(source.mem.disp) & 0xFFFFFFFF
    return None


def _argument_offsets(
    binary: StageABinary, prefix: Sequence[_Instruction]
) -> tuple[int, ...]:
    offsets: set[int] = set()
    for instruction in prefix:
        decoded = _decode_one(binary, instruction)
        if decoded.mnemonic.lower() != "mov" or len(decoded.operands) < 2:
            continue
        destination = decoded.operands[0]
        if destination.type != x86_const.X86_OP_MEM:
            continue
        memory = destination.mem
        if not memory.base or decoded.reg_name(memory.base).lower() != "esp":
            continue
        if memory.index or int(memory.disp) < 0 or int(memory.disp) % 4:
            continue
        offsets.add(int(memory.disp))
    return tuple(sorted(offsets))


def _locate_bridge_table(
    binary: StageABinary,
    symbols: Mapping[str, tuple[int, ...]],
    external_sites: Sequence[Any],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if not external_sites:
        raise RelationalInterpreterKernelCallbackGenerationError(
            "native engine plan has no external bridge inventory"
        )
    rows: list[tuple[int, int]] = []
    for index, raw in enumerate(external_sites):
        row = _mapping(raw, f"external bridge {index}")
        bridge_id = _u32(row.get("id"), "external bridge id")
        instruction_rva = _u32(row.get("instruction_rva"), "external instruction RVA")
        target = _unique_symbol(symbols, f"stage_b_native_bridge_{bridge_id:04d}")
        rows.append((instruction_rva, target))
    needle = struct.pack(
        "<II", rows[0][0], binary.image_base + rows[0][1]
    )
    matches: list[int] = []
    image = binary.path.read_bytes()
    for section in binary.sections:
        if section.executable or section.writable or section.raw_size < len(needle):
            continue
        raw = image[section.raw_pointer : section.raw_pointer + section.raw_size]
        cursor = 0
        while True:
            found = raw.find(needle, cursor)
            if found < 0:
                break
            table_rva = section.rva_start + found
            if all(
                _read_u32(binary, table_rva + index * 20, "bridge instruction RVA")
                    == instruction_rva
                and _read_u32(binary, table_rva + index * 20 + 4, "bridge target")
                    == binary.image_base + target_rva
                for index, (instruction_rva, target_rva) in enumerate(rows)
            ):
                matches.append(table_rva)
            cursor = found + 1
    if len(matches) != 1:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"candidate has {len(matches)} exact native bridge tables"
        )
    start = matches[0]
    return (
        tuple(start + index * 20 + 4 for index in range(len(rows))),
        tuple(target for _, target in rows),
    )


def _target_entry_bytes(binary: StageABinary, rva: int) -> bytes:
    if not any(
        section.executable
        and section.rva_start <= rva < section.rva_start + section.raw_size
        for section in binary.sections
    ):
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"callback target RVA 0x{rva:x} is not executable"
        )
    raw = bytes(binary.pe.get_data(rva, 15))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rows = list(decoder.disasm(raw, binary.image_base + rva, count=1))
    if len(rows) != 1 or rows[0].address != binary.image_base + rva:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"callback target RVA 0x{rva:x} does not decode"
        )
    return bytes(rows[0].bytes)


def _highlow_relocations(binary: StageABinary) -> frozenset[int]:
    rows: set[int] = set()
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", ()) or ():
        for entry in block.entries:
            if int(entry.type) == 3:
                rows.add(int(entry.rva))
    return frozenset(rows)


def _read_u32(binary: StageABinary, rva: int, label: str) -> int:
    data = bytes(binary.pe.get_data(rva, 4))
    if len(data) != 4:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} at RVA 0x{rva:x} is truncated"
        )
    return struct.unpack("<I", data)[0]


def _pointer_to_rva(binary: StageABinary, value: int, label: str) -> int:
    if not binary.image_base <= value < binary.image_base + binary.size_of_image:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} is outside the candidate image"
        )
    return value - binary.image_base


def _map_symbols(path: Path, binary: StageABinary) -> dict[str, tuple[int, ...]]:
    result: dict[str, set[int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _GNU_MAP_SYMBOL.match(line)
        if match is None:
            continue
        value, name = int(match.group(1), 16), match.group(2)
        rva = value - binary.image_base if value >= binary.image_base else value
        if 0 <= rva < binary.size_of_image:
            result.setdefault(name.lstrip("_"), set()).add(rva)
    return {key: tuple(sorted(values)) for key, values in result.items()}


def _unique_symbol(
    symbols: Mapping[str, tuple[int, ...]], name: str
) -> int:
    values = symbols.get(name.lstrip("_"), ())
    if len(values) != 1:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"linker map has {len(values)} addresses for {name}"
        )
    return values[0]


def _lean_operand(value: Mapping[str, Any]) -> str:
    kind = value.get("kind")
    if kind == "register":
        return f".register .{value['register']}"
    if kind == "memory":
        base = "none" if value.get("base") is None else f"some .{value['base']}"
        index = "none" if value.get("index") is None else f"some .{value['index']}"
        return (
            ".memory { base := " + base + ", index := " + index +
            f", scaleShift := {value['scale_shift']}, displacement := {value['displacement']} }}"
        )
    raise RelationalInterpreterKernelCallbackGenerationError(
        f"cannot emit target operand kind {kind}"
    )


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def _lean_nat_list(values: Sequence[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _file(value: Path | str | Mapping[str, Any], label: str) -> Path:
    if isinstance(value, Mapping):
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} must be a file"
        )
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} is not a regular file: {path}"
        )
    return path


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"cannot read {label}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} must be an object"
        )
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} must be an object"
        )
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} must be a list"
        )
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} must be a nonempty string"
        )
    return value


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise RelationalInterpreterKernelCallbackGenerationError(
            f"{label} must be a uint32"
        )
    return value


__all__ = [
    "INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT",
    "INTERPRETER_KERNEL_CALLBACK_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CALLBACK_PLAN_FILENAME",
    "INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT",
    "CallbackIssue",
    "CallbackSitePlan",
    "CallbackTargetPlan",
    "InterpreterKernelCallbackPlan",
    "RelationalInterpreterKernelCallbackGenerationError",
    "build_relational_interpreter_kernel_callback_plan",
    "propose_stage_b_interpreter_kernel_callback_contract",
    "relational_interpreter_kernel_callback_source",
    "write_relational_interpreter_kernel_callback_bundle",
]
