"""Classify finite indirect calls in a compiled interpreter kernel.

The callback generator already recovers exact cdecl sites and finite internal
targets.  This phase adds the missing provenance distinction: a relocation in
read-only image data is stable under the image-memory invariant, whereas a
relocation in writable data only describes the initial value and therefore
requires an explicit preservation invariant.  Direct IAT calls are classified
by parsed import identity and remain external-environment obligations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ...util import sha256_bytes, write_json
from .interpreter_kernel_callback import (
    CallbackSitePlan,
    InterpreterKernelCallbackPlan,
    _discover_indirect_sites,
    _file,
    _json_object,
    _lean_bytes,
    _lean_nat_list,
    _lean_operand,
    _list,
    _mapping,
    _u32,
)


INTERPRETER_KERNEL_INDIRECT_PLAN_FORMAT = (
    "stage-a-relational-interpreter-kernel-indirect-plan-v1"
)
INTERPRETER_KERNEL_INDIRECT_PLAN_FILENAME = "interpreter-kernel-indirect-plan.json"
INTERPRETER_KERNEL_INDIRECT_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelIndirect.lean"
)


class RelationalInterpreterKernelIndirectGenerationError(StageAInputError):
    """Indirect evidence is malformed, stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class IndirectIssue:
    code: str
    message: str
    site_rva: int | None = None
    function_role: str | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.site_rva is not None:
            result["site_rva"] = self.site_rva
        if self.function_role is not None:
            result["function_role"] = self.function_role
        return result


@dataclass(frozen=True)
class RelocatedCellPlan:
    cell_rva: int
    target_id: int
    section_name: str
    writable: bool

    @property
    def provenance(self) -> str:
        return (
            "writable_relocation_cell"
            if self.writable
            else "immutable_relocation_cell"
        )

    def payload(self) -> dict[str, Any]:
        return {
            "cell_rva": self.cell_rva,
            "target_id": self.target_id,
            "section": self.section_name,
            "provenance": self.provenance,
            "requires_runtime_preservation": self.writable,
        }


@dataclass(frozen=True)
class RelocatedIndirectSitePlan:
    callback_index: int
    callback: CallbackSitePlan
    cells: tuple[RelocatedCellPlan, ...]

    @property
    def rva(self) -> int:
        return self.callback.rva

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.callback.id,
            "kind": "finite_internal_targets",
            "function_role": self.callback.function_role,
            "site_rva": self.callback.rva,
            "instruction_bytes": self.callback.instruction_bytes.hex(),
            "continuation_rva": self.callback.continuation_rva,
            "target_operand": dict(self.callback.target_operand),
            "cdecl": self.callback.payload()["cdecl"],
            "targets": [target.payload() for target in self.callback.targets],
            "cells": [cell.payload() for cell in self.cells],
            "dynamic_requirements": [
                "source_target_member_of_finite_set",
                "writable_target_cells_preserved_until_call",
                "exact_cdecl_entry_and_return",
                "nested_frames_preserved",
                "exact_target_execution",
            ],
        }


@dataclass(frozen=True)
class IATIndirectSitePlan:
    id: int
    function_role: str
    rva: int
    instruction_bytes: bytes
    continuation_rva: int
    target_operand: Mapping[str, Any]
    argument_offsets: tuple[int, ...]
    dll: bytes
    import_name: bytes | None
    ordinal: int | None
    iat_rva: int

    def payload(self) -> dict[str, Any]:
        identity: dict[str, Any] = {
            "dll_hex": self.dll.hex(),
            "iat_rva": self.iat_rva,
        }
        if self.import_name is not None:
            identity["symbol_hex"] = self.import_name.hex()
        else:
            identity["ordinal"] = self.ordinal
        return {
            "id": self.id,
            "kind": "iat_import",
            "function_role": self.function_role,
            "site_rva": self.rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "continuation_rva": self.continuation_rva,
            "target_operand": dict(self.target_operand),
            "cdecl": {
                "argument_count": len(self.argument_offsets),
                "argument_offsets": list(self.argument_offsets),
                "caller_stack_delta": 0,
                "preserved_registers": ["ebx", "esi", "edi", "ebp"],
                "return_kind": "word_in_eax",
            },
            "import": identity,
            "dynamic_requirements": [
                "loader_populated_iat_identity",
                "exact_external_environment_refinement",
                "exact_cdecl_entry_and_return",
                "nested_frames_preserved",
            ],
        }


@dataclass(frozen=True)
class InterpreterKernelIndirectPlan:
    candidate_sha256: str
    candidate_size: int
    relocated_sites: tuple[RelocatedIndirectSitePlan, ...]
    iat_sites: tuple[IATIndirectSitePlan, ...]
    resolved_frontiers: tuple[dict[str, Any], ...]
    remaining_frontiers: tuple[dict[str, Any], ...]
    issues: tuple[IndirectIssue, ...]

    @property
    def classified_rvas(self) -> tuple[int, ...]:
        return tuple(sorted(
            [site.rva for site in self.relocated_sites]
            + [site.rva for site in self.iat_sites]
        ))

    @property
    def obligations(self) -> tuple[dict[str, Any], ...]:
        result: list[dict[str, Any]] = []
        for site in self.relocated_sites:
            stem = f"kernel-indirect:{site.rva:08x}"
            result.extend((
                {
                    "id": f"{stem}:static-classifier",
                    "family": "finite_indirect_static_classifier",
                    "site_rva": site.rva,
                    "status": "pending_lean_check",
                },
                {
                    "id": f"{stem}:source-membership",
                    "family": "finite_indirect_source_membership",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
                {
                    "id": f"{stem}:mutable-cell-preservation",
                    "family": "finite_indirect_cell_preservation",
                    "site_rva": site.rva,
                    "status": (
                        "pending_lean_theorem"
                        if any(cell.writable for cell in site.cells)
                        else "not_applicable"
                    ),
                },
                {
                    "id": f"{stem}:abi-frame-continuation",
                    "family": "finite_indirect_abi_frame_continuation",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
                {
                    "id": f"{stem}:target-execution",
                    "family": "finite_indirect_target_execution",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
            ))
        for site in self.iat_sites:
            stem = f"kernel-indirect:{site.rva:08x}"
            result.extend((
                {
                    "id": f"{stem}:iat-identity",
                    "family": "finite_indirect_iat_identity",
                    "site_rva": site.rva,
                    "status": "pending_lean_check",
                },
                {
                    "id": f"{stem}:external-refinement",
                    "family": "finite_indirect_external_refinement",
                    "site_rva": site.rva,
                    "status": "pending_lean_theorem",
                },
            ))
        for index, issue in enumerate(self.issues):
            result.append({
                "id": f"kernel-indirect-frontier:{index:04d}",
                "family": "finite_indirect_frontier",
                "site_rva": issue.site_rva,
                "status": "incomplete",
                "reason_code": issue.code,
                "message": issue.message,
            })
        return tuple(result)

    def payload(self) -> dict[str, Any]:
        classified = len(self.relocated_sites) + len(self.iat_sites)
        core: dict[str, Any] = {
            "format": INTERPRETER_KERNEL_INDIRECT_PLAN_FORMAT,
            "status": "incomplete",
            "classification_status": "satisfied" if not self.issues else "incomplete",
            "acceptance_authority": False,
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "counts": {
                "discovered_sites": classified + len(self.issues),
                "classified_sites": classified,
                "relocated_sites": len(self.relocated_sites),
                "iat_sites": len(self.iat_sites),
                "writable_relocation_sites": sum(
                    any(cell.writable for cell in site.cells)
                    for site in self.relocated_sites
                ),
                "resolved_kernel_frontiers": len(self.resolved_frontiers),
                "remaining_kernel_frontiers": len(self.remaining_frontiers),
                "classification_frontiers": len(self.issues),
            },
            "sites": [site.payload() for site in self.relocated_sites]
            + [site.payload() for site in self.iat_sites],
            "resolved_kernel_frontiers": list(self.resolved_frontiers),
            "remaining_kernel_frontiers": list(self.remaining_frontiers),
            "issues": [issue.payload() for issue in self.issues],
            "proof_obligations": list(self.obligations),
        }
        core["artifact_sha256"] = sha256_bytes(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        )
        return core


def build_relational_interpreter_kernel_indirect_plan(
    *,
    candidate_pe: Path | str,
    kernel_plan: Path | str | Mapping[str, Any] | Any,
    callback_plan: InterpreterKernelCallbackPlan,
) -> InterpreterKernelIndirectPlan:
    candidate_path = _file(candidate_pe, "candidate PE")
    binary = _parse_stage_a_pe(candidate_path)
    payload = _kernel_payload(kernel_plan)
    discovered = _discover_indirect_sites(binary, kernel_plan)
    discovered_by_rva = {site.instruction.rva: site for site in discovered}
    callback_by_rva = {site.rva: (index, site) for index, site in enumerate(callback_plan.sites)}
    if callback_plan.candidate_sha256 != binary.sha256:
        raise RelationalInterpreterKernelIndirectGenerationError(
            "callback plan binds a different candidate PE"
        )

    issues: list[IndirectIssue] = []
    relocated: list[RelocatedIndirectSitePlan] = []
    iat: list[IATIndirectSitePlan] = []
    parsed_imports = tuple(binary.imports)

    for site_id, site in enumerate(discovered):
        callback_row = callback_by_rva.get(site.instruction.rva)
        if callback_row is not None:
            callback_index, callback = callback_row
            cells: list[RelocatedCellPlan] = []
            for target in callback.targets:
                for cell_rva in target.pointer_cells:
                    section = _unique_word_section(binary, cell_rva)
                    if section is None:
                        issues.append(IndirectIssue(
                            "target_cell_not_in_unique_section",
                            f"pointer cell RVA 0x{cell_rva:x} is not inside one mapped section",
                            site.instruction.rva,
                            site.function_role,
                        ))
                        cells = []
                        break
                    cells.append(RelocatedCellPlan(
                        cell_rva=cell_rva,
                        target_id=target.id,
                        section_name=section.name,
                        writable=section.writable,
                    ))
                if not cells:
                    break
            if cells:
                required = set(callback.dynamic_requirements)
                if any(cell.writable for cell in cells) and not {
                    "runtime_target_cell_preserved",
                    "runtime_pointer_identity",
                }.issubset(required):
                    issues.append(IndirectIssue(
                        "writable_target_cell_unbounded",
                        "writable relocation cell lacks explicit identity and preservation requirements",
                        site.instruction.rva,
                        site.function_role,
                    ))
                else:
                    relocated.append(RelocatedIndirectSitePlan(
                        callback_index=callback_index,
                        callback=callback,
                        cells=tuple(cells),
                    ))
            continue

        imported = _direct_iat_import(binary, site.target_operand, parsed_imports)
        if imported is not None:
            import_name = (
                imported.symbol.encode("ascii")
                if isinstance(imported.symbol, str)
                else None
            )
            ordinal = imported.ordinal
            iat.append(IATIndirectSitePlan(
                id=site_id,
                function_role=site.function_role,
                rva=site.instruction.rva,
                instruction_bytes=site.instruction.data,
                continuation_rva=site.instruction.rva + len(site.instruction.data),
                target_operand=site.target_operand,
                argument_offsets=site.argument_offsets,
                dll=imported.dll.encode("ascii"),
                import_name=import_name,
                ordinal=ordinal,
                iat_rva=imported.thunk_rva,
            ))
            continue

        issues.append(IndirectIssue(
            "unknown_or_writable_unbounded_target",
            "indirect call has neither a checked finite relocation inventory nor a direct IAT identity",
            site.instruction.rva,
            site.function_role,
        ))

    extra_callbacks = sorted(set(callback_by_rva) - set(discovered_by_rva))
    if extra_callbacks:
        raise RelationalInterpreterKernelIndirectGenerationError(
            f"callback plan names non-indirect site RVA 0x{extra_callbacks[0]:x}"
        )

    classified_rvas = {
        site.rva for site in relocated
    } | {site.rva for site in iat}
    resolved: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    for index, raw in enumerate(_list(payload.get("issues", []), "kernel issues")):
        row = _mapping(raw, f"kernel issue {index}")
        item = dict(row)
        if row.get("code") == "unsupported_indirect_kernel_call":
            site_rva = _u32(row.get("rva_start"), "indirect kernel issue RVA")
            if site_rva in classified_rvas:
                item["resolution"] = "checked_finite_target_classifier"
                resolved.append(item)
            else:
                remaining.append(item)
        else:
            remaining.append(item)

    blocked_rvas = {
        _u32(row.get("rva_start"), "remaining indirect kernel issue RVA")
        for row in map(lambda value: _mapping(value, "remaining kernel issue"), remaining)
        if row.get("code") == "unsupported_indirect_kernel_call"
    }
    for rva in sorted(classified_rvas - {
        _u32(row["rva_start"], "resolved indirect kernel issue RVA")
        for row in resolved
    }):
        issues.append(IndirectIssue(
            "classified_site_not_a_kernel_frontier",
            "classified indirect site does not correspond to a kernel frontier",
            rva,
            discovered_by_rva[rva].function_role,
        ))
    for rva in sorted(blocked_rvas):
        if not any(issue.site_rva == rva for issue in issues):
            issues.append(IndirectIssue(
                "kernel_frontier_unclassified",
                "kernel indirect-call frontier has no checked classifier",
                rva,
                discovered_by_rva.get(rva).function_role
                if rva in discovered_by_rva else None,
            ))

    return InterpreterKernelIndirectPlan(
        candidate_sha256=binary.sha256,
        candidate_size=binary.size,
        relocated_sites=tuple(relocated),
        iat_sites=tuple(iat),
        resolved_frontiers=tuple(resolved),
        remaining_frontiers=tuple(remaining),
        issues=tuple(issues),
    )


def relational_interpreter_kernel_indirect_source(
    plan: InterpreterKernelIndirectPlan,
) -> str:
    definitions: list[str] = []
    site_names: list[str] = []
    for index, site in enumerate(plan.relocated_sites):
        cell_names: list[str] = []
        for cell_index, cell in enumerate(site.cells):
            name = f"generatedKernelIndirect{index:04d}Cell{cell_index:04d}"
            definitions.append(
                f"def {name} : ClassifiedRelocationTargetCell := {{\n"
                f"  cell := generatedKernelCallback{site.callback_index:04d}Cell{cell_index:04d}\n"
                f"  sectionKind := .{'writable' if cell.writable else 'immutable'}\n"
                "}"
            )
            cell_names.append(name)
        name = f"generatedKernelIndirectSite{index:04d}"
        definitions.append(
            f"def {name} : ClassifiedFiniteIndirectSite := {{\n"
            f"  site := generatedKernelCallbackSite{site.callback_index:04d}\n"
            f"  cells := {{ cells := [{', '.join(cell_names)}] }}\n"
            "}"
        )
        site_names.append(f".relocated {name}")

    for index, site in enumerate(plan.iat_sites):
        name = f"generatedKernelIATIndirectSite{index:04d}"
        import_name = (
            f".symbol {_lean_bytes(site.import_name)}"
            if site.import_name is not None
            else f".ordinal {site.ordinal}"
        )
        definitions.append(
            f"def {name} : ClassifiedIATIndirectSite := {{\n"
            f"  id := {site.id}\n"
            f"  instruction := {{ rva := {site.rva}, bytes := {_lean_bytes(site.instruction_bytes)} }}\n"
            f"  continuationRva := {site.continuation_rva}\n"
            f"  targetOperand := {_lean_operand(site.target_operand)}\n"
            "  abi := {\n"
            f"    argumentCount := {len(site.argument_offsets)}\n"
            f"    argumentOffsets := {_lean_nat_list(site.argument_offsets)}\n"
            "    callerStackDelta := 0\n"
            "    preservedRegisters := [.ebx, .esi, .edi, .ebp]\n"
            "    returnKind := .wordInEax\n"
            "  }\n"
            f"  imported := {{ dll := {_lean_bytes(site.dll)}, name := {import_name}, iatRva := {site.iat_rva} }}\n"
            "}"
        )
        site_names.append(f".iat {name}")

    return f"""import StageA.RelationalInterpreterKernelIndirect
import StageA.GeneratedRelationalInterpreterKernelCallback

namespace StageA.GeneratedRelational.InterpreterKernelIndirect

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelIndirect
open StageA.GeneratedRelational.InterpreterKernelCallback

{chr(10).join(definitions)}

def generatedKernelIndirectInventory : ClassifiedKernelIndirectInventory := {{
  sites := [{', '.join(site_names)}]
}}

def GeneratedKernelIndirectStaticGoal (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) : Prop :=
  generatedKernelIndirectInventory.checked program pe imports = true

def GeneratedKernelIndirectSemanticGoal
    (context : StaticProofContext) (world : RelationalWorld)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment)
    (internalContract : ClassifiedFiniteIndirectSite -> KernelCallbackTargetContract)
    (internalInvariant : ClassifiedFiniteIndirectSite -> MachineState -> Prop)
    (internalRuns : ClassifiedFiniteIndirectSite -> KernelCallbackExecutionTrace -> Prop)
    (iatContract : ClassifiedIATIndirectSite -> KernelIATCallContract)
    (iatInvariant : ClassifiedIATIndirectSite -> MachineState -> Prop)
    (iatRuns : ClassifiedIATIndirectSite -> KernelCallbackExecutionTrace -> Prop) :
    Prop :=
  ClassifiedKernelIndirectCallsRefine context world generatedKernelIndirectInventory
    program pe imports environment internalContract internalInvariant internalRuns
    iatContract iatInvariant iatRuns

end StageA.GeneratedRelational.InterpreterKernelIndirect
"""


def write_relational_interpreter_kernel_indirect_bundle(
    *,
    candidate_pe: Path | str,
    kernel_plan: Path | str | Mapping[str, Any] | Any,
    callback_plan: InterpreterKernelCallbackPlan,
    out_dir: Path | str,
) -> InterpreterKernelIndirectPlan:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_indirect_plan(
        candidate_pe=candidate_pe,
        kernel_plan=kernel_plan,
        callback_plan=callback_plan,
    )
    write_json(output / INTERPRETER_KERNEL_INDIRECT_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_INDIRECT_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_indirect_source(plan), encoding="ascii"
    )
    return plan


def _kernel_payload(value: Path | str | Mapping[str, Any] | Any) -> Mapping[str, Any]:
    if isinstance(value, (str, Path)):
        return _json_object(Path(value), "kernel plan")
    if isinstance(value, Mapping):
        return value
    payload = getattr(value, "payload", None)
    if callable(payload):
        return _mapping(payload(), "kernel plan")
    raise RelationalInterpreterKernelIndirectGenerationError(
        "kernel plan has no serializable issue inventory"
    )


def _unique_word_section(binary: StageABinary, rva: int) -> Any | None:
    matches = [
        section for section in binary.sections
        if section.rva_start <= rva and rva + 4 <= section.rva_end
    ]
    return matches[0] if len(matches) == 1 else None


def _direct_iat_import(
    binary: StageABinary, operand: Mapping[str, Any], imports: Sequence[Any]
) -> Any | None:
    if operand.get("kind") != "memory" or operand.get("base") is not None or operand.get("index") is not None:
        return None
    absolute = int(operand.get("displacement", -1))
    if absolute < binary.image_base:
        return None
    rva = absolute - binary.image_base
    matches = [imported for imported in imports if imported.thunk_rva == rva]
    return matches[0] if len(matches) == 1 else None


__all__ = [
    "INTERPRETER_KERNEL_INDIRECT_LEAN_FILENAME",
    "INTERPRETER_KERNEL_INDIRECT_PLAN_FILENAME",
    "INTERPRETER_KERNEL_INDIRECT_PLAN_FORMAT",
    "IATIndirectSitePlan",
    "IndirectIssue",
    "InterpreterKernelIndirectPlan",
    "RelationalInterpreterKernelIndirectGenerationError",
    "RelocatedCellPlan",
    "RelocatedIndirectSitePlan",
    "build_relational_interpreter_kernel_indirect_plan",
    "relational_interpreter_kernel_indirect_source",
    "write_relational_interpreter_kernel_indirect_bundle",
]
