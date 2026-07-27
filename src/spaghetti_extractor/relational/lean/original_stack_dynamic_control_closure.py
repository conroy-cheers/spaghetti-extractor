"""Emit fail-closed original stack/dynamic indirect-control authorities.

The input classifier remains an untrusted proposal.  Generated Lean rechecks
the exact decoded instruction, PE bytes, relocation-backed target, immutable
table, and finite code inventory against an exact original context.  Runtime
stack carry, predecessor reachability, callback registration, and uninhabited
source facts remain explicit typed premises.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping

from ...errors import StageAInputError
from .original_indirect_control_authority import (
    DynamicCallbackControlSpec,
    OriginalIndirectControlAuthorityBinding,
    OriginalIndirectControlSiteSpec,
    RelocatedCodePointerSeedSpec,
)
from .stack_dynamic_indirect_control import (
    StackDynamicIndirectControlPlan,
    StackDynamicSiteFinding,
)


ORIGINAL_STACK_DYNAMIC_CONTROL_CLOSURE_FORMAT = (
    "stage-a-original-stack-dynamic-control-closure-v1"
)
ORIGINAL_STACK_DYNAMIC_CONTROL_CLOSURE_LEAN_FILENAME = (
    "GeneratedRelationalOriginalStackDynamicControlClosure.lean"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_U32_LIMIT = 1 << 32


class OriginalStackDynamicControlClosureError(StageAInputError):
    """An exact stack/dynamic authority proposal is malformed."""


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise OriginalStackDynamicControlClosureError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _natural(value: int, field: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OriginalStackDynamicControlClosureError(
            f"{field} must be a natural number"
        )
    if word and value >= _U32_LIMIT:
        raise OriginalStackDynamicControlClosureError(
            f"{field} must fit in an unsigned PE32 word"
        )
    return value


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise OriginalStackDynamicControlClosureError(
            f"{field} must be a Lean identifier"
        )
    return value


@dataclass(frozen=True)
class StackCarryAuthorityHint:
    stable_id: str
    seed_slot_rva: int
    seed_target_id: int

    def validate(self) -> None:
        if not self.stable_id:
            raise OriginalStackDynamicControlClosureError(
                "stack hint stable_id must be nonempty"
            )
        _natural(self.seed_slot_rva, "stack seed slot RVA", word=True)
        _natural(self.seed_target_id, "stack seed target id")


@dataclass(frozen=True)
class DynamicCallbackAuthorityHint:
    stable_id: str
    mode: Literal["finite_callbacks", "source_uninhabited"]
    allowed_target_ids: tuple[int, ...] = ()

    def validate(self) -> None:
        if not self.stable_id:
            raise OriginalStackDynamicControlClosureError(
                "dynamic hint stable_id must be nonempty"
            )
        for target_id in self.allowed_target_ids:
            _natural(target_id, "dynamic callback target id")
        if len(set(self.allowed_target_ids)) != len(self.allowed_target_ids):
            raise OriginalStackDynamicControlClosureError(
                "dynamic callback target IDs must be unique"
            )
        if self.mode == "finite_callbacks":
            if not self.allowed_target_ids:
                raise OriginalStackDynamicControlClosureError(
                    "finite callback mode requires a nonempty target inventory"
                )
        elif self.mode == "source_uninhabited":
            if self.allowed_target_ids:
                raise OriginalStackDynamicControlClosureError(
                    "uninhabited mode cannot submit callback targets"
                )
        else:
            raise OriginalStackDynamicControlClosureError(
                f"unsupported dynamic closure mode: {self.mode!r}"
            )


@dataclass(frozen=True)
class OriginalStackDynamicControlClosureSpec:
    stack_hints: tuple[StackCarryAuthorityHint, ...]
    dynamic_hints: tuple[DynamicCallbackAuthorityHint, ...]

    def validate(self) -> None:
        for hint in self.stack_hints:
            hint.validate()
        for hint in self.dynamic_hints:
            hint.validate()
        stable_ids = [
            hint.stable_id for hint in (*self.stack_hints, *self.dynamic_hints)
        ]
        if len(set(stable_ids)) != len(stable_ids):
            raise OriginalStackDynamicControlClosureError(
                "closure hints must have unique stable IDs"
            )


@dataclass(frozen=True)
class OriginalStackDynamicAuthoritySite:
    finding: StackDynamicSiteFinding
    premise_type: str
    closure_mode: Literal[
        "finite_stack_target",
        "empty_indexed_source",
        "finite_dynamic_targets",
        "uninhabited_dynamic_source",
    ]
    allowed_target_ids: tuple[int, ...]
    stack_hint: StackCarryAuthorityHint | None = None
    dynamic_hint: DynamicCallbackAuthorityHint | None = None

    def to_json(self) -> dict[str, object]:
        finding = self.finding
        return {
            "allowed_target_ids": list(self.allowed_target_ids),
            "closure_mode": self.closure_mode,
            "instruction_bytes": finding.instruction_bytes.hex(),
            "instruction_rva": finding.instruction_rva,
            "premise_status": "required",
            "premise_type": self.premise_type,
            "provenance_class": finding.provenance_class,
            "source_rva": finding.source_rva,
            "source_target_id": finding.source_target_id,
            "stable_id": finding.stable_id,
            "static_authority": "lean_checked",
        }


@dataclass(frozen=True)
class OriginalStackDynamicControlClosureAuthorityPlan:
    original_pe_sha256: str
    state_machine_sha256: str
    original_pe_bytes: bytes
    sites: tuple[OriginalStackDynamicAuthoritySite, ...]

    @property
    def runtime_complete(self) -> bool:
        # Runtime premises are Lean proof arguments, never Python statuses.
        return False

    def to_json(self) -> dict[str, object]:
        return {
            "artifact_role": {
                "acceptance_authority": False,
                "report_status_closes_obligations": False,
                "runtime_premises_embedded": False,
                "static_authority_generated": True,
            },
            "counts": {
                "runtime_premises_required": len(self.sites),
                "sites": len(self.sites),
                "static_authorities": len(self.sites),
            },
            "format": ORIGINAL_STACK_DYNAMIC_CONTROL_CLOSURE_FORMAT,
            "inputs": {
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "sites": [site.to_json() for site in self.sites],
            "status": "incomplete",
        }


def plan_original_stack_dynamic_control_closure(
    proposal: StackDynamicIndirectControlPlan,
    spec: OriginalStackDynamicControlClosureSpec,
    *,
    original_pe_sha256: str,
    state_machine_sha256: str,
) -> OriginalStackDynamicControlClosureAuthorityPlan:
    """Bind exact hashes and classify the typed premise required per site."""

    spec.validate()
    expected_pe = _sha256(original_pe_sha256, "original PE SHA-256")
    expected_state = _sha256(
        state_machine_sha256, "state-machine SHA-256"
    )
    if proposal.original_pe_sha256 != expected_pe:
        raise OriginalStackDynamicControlClosureError(
            "stack/dynamic proposal original PE SHA-256 does not match"
        )
    if proposal.state_machine_sha256 != expected_state:
        raise OriginalStackDynamicControlClosureError(
            "stack/dynamic proposal state-machine SHA-256 does not match"
        )
    stack_hints = {hint.stable_id: hint for hint in spec.stack_hints}
    dynamic_hints = {hint.stable_id: hint for hint in spec.dynamic_hints}
    sites: list[OriginalStackDynamicAuthoritySite] = []
    used_stack: set[str] = set()
    used_dynamic: set[str] = set()
    seen_sites: set[tuple[int, int]] = set()

    for finding in proposal.findings:
        key = (finding.source_rva, finding.instruction_rva)
        if key in seen_sites:
            raise OriginalStackDynamicControlClosureError(
                "stack/dynamic proposal contains a duplicate exact site"
            )
        seen_sites.add(key)
        if not finding.instruction_bytes:
            raise OriginalStackDynamicControlClosureError(
                f"site 0x{finding.instruction_rva:x} has no instruction bytes"
            )
        if finding.provenance_class == "stack_slot":
            hint = stack_hints.get(finding.stable_id)
            if hint is None:
                raise OriginalStackDynamicControlClosureError(
                    f"stack site {finding.stable_id} has no seed hint"
                )
            used_stack.add(finding.stable_id)
            sites.append(OriginalStackDynamicAuthoritySite(
                finding=finding,
                premise_type="CompleteStackCarryPremise",
                closure_mode="finite_stack_target",
                allowed_target_ids=(hint.seed_target_id,),
                stack_hint=hint,
            ))
        elif finding.provenance_class == "indexed_immutable_table":
            table = finding.indexed_empty_table
            if table is None:
                raise OriginalStackDynamicControlClosureError(
                    f"indexed site {finding.stable_id} has no checked empty-table proposal"
                )
            if table.address_scale != 4:
                raise OriginalStackDynamicControlClosureError(
                    "empty indexed-table authority requires a PE32 word scale"
                )
            sites.append(OriginalStackDynamicAuthoritySite(
                finding=finding,
                premise_type="CompleteEmptyIndexedSourcePredecessorPremise",
                closure_mode="empty_indexed_source",
                allowed_target_ids=(),
            ))
        elif finding.provenance_class == "dynamic_range_field":
            hint = dynamic_hints.get(finding.stable_id)
            if hint is None:
                raise OriginalStackDynamicControlClosureError(
                    f"dynamic site {finding.stable_id} has no runtime-mode hint"
                )
            used_dynamic.add(finding.stable_id)
            if hint.mode == "finite_callbacks":
                premise = "CompleteDynamicCallbackPremise"
                mode = "finite_dynamic_targets"
            else:
                premise = "CompleteDynamicSourceUninhabitedPremise"
                mode = "uninhabited_dynamic_source"
            sites.append(OriginalStackDynamicAuthoritySite(
                finding=finding,
                premise_type=premise,
                closure_mode=mode,
                allowed_target_ids=hint.allowed_target_ids,
                dynamic_hint=hint,
            ))
        else:
            raise OriginalStackDynamicControlClosureError(
                f"unsupported provenance class: {finding.provenance_class!r}"
            )

    unused = (set(stack_hints) - used_stack) | (set(dynamic_hints) - used_dynamic)
    if unused:
        raise OriginalStackDynamicControlClosureError(
            "closure hints do not match exact proposal sites: "
            + ", ".join(sorted(unused))
        )
    if not sites:
        raise OriginalStackDynamicControlClosureError(
            "stack/dynamic authority requires at least one exact site"
        )
    return OriginalStackDynamicControlClosureAuthorityPlan(
        expected_pe,
        expected_state,
        proposal.original_pe_bytes,
        tuple(sites),
    )


def original_stack_dynamic_control_closure_source(
    plan: OriginalStackDynamicControlClosureAuthorityPlan,
    binding: OriginalIndirectControlAuthorityBinding,
) -> str:
    """Emit static checks and theorem functions requiring runtime premises."""

    binding.validate()
    definitions: list[str] = []
    checks: list[str] = []
    for index, authority_site in enumerate(plan.sites):
        finding = authority_site.finding
        prefix = f"generatedOriginalStackDynamicClosure{index}"
        site_name = f"{prefix}Site"
        site_spec = OriginalIndirectControlSiteSpec(
            definition_name=site_name,
            source_target_id=finding.source_target_id,
            instruction_rva=finding.instruction_rva,
            instruction_bytes=finding.instruction_bytes,
            target=finding.target,
            transfer="call",
            continuation_target_id=finding.continuation_target_id,
        )
        definitions.append(site_spec.lean())
        checks.append(f"""theorem {site_name}Checked :
    {site_name}.checked {binding.context_name} = true := by
  decide +kernel

def {site_name}Evidence :
    CheckedOriginalIndirectControlSite {binding.context_name} := {{
  authority := {binding.authority_name}
  site := {site_name}
  checked := {site_name}Checked
}}

#print axioms {site_name}Checked""")

        if authority_site.closure_mode == "finite_stack_target":
            hint = authority_site.stack_hint
            if hint is None:
                raise AssertionError("stack authority lost its seed hint")
            seed_name = f"{prefix}Seed"
            claim_name = f"{prefix}StackClaim"
            static_name = f"{prefix}StackStatic"
            authority_name = f"{prefix}StackAuthority"
            definitions.append(RelocatedCodePointerSeedSpec(
                seed_name, hint.seed_slot_rva, hint.seed_target_id
            ).lean())
            definitions.append(f"""def {claim_name} : StackRelocatedCodePointerClaim := {{
  site := {site_name}
  seed := {seed_name}
}}""")
            checks.append(f"""theorem {claim_name}Checked :
    {claim_name}.checked {binding.context_name} = true := by
  decide +kernel

def {static_name} : CheckedStackRelocatedCodePointerClaim
    {binding.context_name} := {{
  authority := {binding.authority_name}
  claim := {claim_name}
  checked := {claim_name}Checked
}}

theorem {prefix}TargetInventoryChecked :
    codeTargetInventoryChecked {binding.context_name}
      [{seed_name}.targetId] = true := by
  decide +kernel

theorem {prefix}TargetAddressChecked :
    originalTargetAddressChecked {binding.context_name} {seed_name}.targetId
      ({seed_name}.word {binding.context_name}) = true := by
  decide +kernel

def {authority_name} : CheckedStackCarryAuthority
    {binding.context_name} := {{
  static := {static_name}
  allowedTargetsChecked := {prefix}TargetInventoryChecked
  targetAddressChecked := {prefix}TargetAddressChecked
}}

abbrev {prefix}RuntimePremise (reachable : ActualSourceReachability) :=
  CompleteStackCarryPremise {binding.context_name} {authority_name} reachable

theorem {prefix}Closed (reachable : ActualSourceReachability)
    (complete : {prefix}RuntimePremise reachable) :
    OriginalIndirectControlClosure {binding.context_name} {site_name} reachable :=
  stackCarryClosure_of_complete {binding.context_name} {authority_name}
    reachable complete

#print axioms {claim_name}Checked
#print axioms {prefix}TargetInventoryChecked
#print axioms {prefix}TargetAddressChecked
#print axioms {prefix}Closed""")
        elif authority_site.closure_mode == "empty_indexed_source":
            table = finding.indexed_empty_table
            if table is None:
                raise AssertionError("indexed authority lost its table")
            base_address = finding.target.base_address
            if base_address is None:
                raise AssertionError("indexed authority lost its base address")
            authority_name = f"{prefix}EmptyIndexedAuthority"
            checks.append(f"""def {authority_name} :
    CheckedEmptyIndexedSourceAuthority {binding.context_name} := {{
  decodedAuthority := {binding.authority_name}
  site := {site_name}
  siteChecked := {site_name}Checked
  indexRegister := .{table.index_register}
  baseAddress := {base_address}
  targetShape := by simp [{site_name}]
  lowerInclusive := {table.lower_inclusive}
  upperExclusive := {table.lower_inclusive}
  emptyInterval := rfl
}}

def {prefix}RuntimePremise (reachable : ActualSourceReachability) : Prop :=
  CompleteEmptyIndexedSourcePredecessorPremise {authority_name} reachable

theorem {prefix}Closed (reachable : ActualSourceReachability)
    (complete : {prefix}RuntimePremise reachable) :
    OriginalIndirectControlClosure {binding.context_name} {site_name} reachable := by
  exact emptyIndexedSourceClosure_of_complete {authority_name} reachable
    complete

#print axioms {prefix}Closed""")
        elif authority_site.closure_mode == "finite_dynamic_targets":
            hint = authority_site.dynamic_hint
            if hint is None:
                raise AssertionError("dynamic authority lost its hint")
            offset = _dynamic_offset(finding)
            claim_name = f"{prefix}DynamicClaim"
            static_name = f"{prefix}DynamicStatic"
            authority_name = f"{prefix}DynamicAuthority"
            definitions.append(DynamicCallbackControlSpec(
                claim_name, site_name, offset, hint.allowed_target_ids
            ).lean())
            checks.append(f"""theorem {claim_name}Checked :
    {claim_name}.checked {binding.context_name} = true := by
  decide +kernel

def {static_name} : CheckedDynamicCallbackControlClaim
    {binding.context_name} := {{
  authority := {binding.authority_name}
  claim := {claim_name}
  checked := {claim_name}Checked
}}

def {authority_name} : CheckedDynamicCallbackAuthority
    {binding.context_name} := {{ static := {static_name} }}

abbrev {prefix}RuntimePremise (reachable : ActualSourceReachability) :=
  CompleteDynamicCallbackPremise {binding.context_name} {authority_name}
    reachable

theorem {prefix}Closed (reachable : ActualSourceReachability)
    (complete : {prefix}RuntimePremise reachable) :
    OriginalIndirectControlClosure {binding.context_name} {site_name} reachable :=
  dynamicCallbackClosure_of_complete {binding.context_name} {authority_name}
    reachable complete

#print axioms {claim_name}Checked
#print axioms {prefix}Closed""")
        elif authority_site.closure_mode == "uninhabited_dynamic_source":
            checks.append(f"""def {prefix}RuntimePremise
    (reachable : ActualSourceReachability) : Prop :=
  CompleteDynamicSourceUninhabitedPremise reachable

theorem {prefix}Closed (reachable : ActualSourceReachability)
    (complete : {prefix}RuntimePremise reachable) :
    OriginalIndirectControlClosure {binding.context_name} {site_name} reachable :=
  dynamicSourceClosure_of_uninhabited {site_name}Evidence reachable complete

#print axioms {prefix}Closed""")
        else:
            raise AssertionError("unknown stack/dynamic closure mode")

    return f"""import StageA.RelationalOriginalStackDynamicControlClosure
import {binding.dependency_module}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.StackDynamicIndirectControl
open StageA.Relational.OriginalStackDynamicControlClosure

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedOriginalStackDynamicPeSha256 : String :=
  "{plan.original_pe_sha256}"

def generatedOriginalStackDynamicStateMachineSha256 : String :=
  "{plan.state_machine_sha256}"

{chr(10).join(definitions)}

{chr(10).join(checks)}

end {binding.namespace}
"""


def write_original_stack_dynamic_control_closure(
    output: Path | str,
    plan: OriginalStackDynamicControlClosureAuthorityPlan,
    binding: OriginalIndirectControlAuthorityBinding,
) -> tuple[Path, Path]:
    root = Path(output)
    report = root / "original-stack-dynamic-control-closure.json"
    lean = root / "StageA" / ORIGINAL_STACK_DYNAMIC_CONTROL_CLOSURE_LEAN_FILENAME
    lean.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lean.write_text(
        original_stack_dynamic_control_closure_source(plan, binding),
        encoding="utf-8",
    )
    return report, lean


def _dynamic_offset(finding: StackDynamicSiteFinding) -> int:
    offset = finding.static_facts.get("field_offset")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise OriginalStackDynamicControlClosureError(
            f"dynamic site {finding.stable_id} has no exact field offset"
        )
    return _natural(offset, "dynamic callback field offset", word=True)


__all__ = [
    "DynamicCallbackAuthorityHint",
    "ORIGINAL_STACK_DYNAMIC_CONTROL_CLOSURE_FORMAT",
    "ORIGINAL_STACK_DYNAMIC_CONTROL_CLOSURE_LEAN_FILENAME",
    "OriginalStackDynamicAuthoritySite",
    "OriginalStackDynamicControlClosureAuthorityPlan",
    "OriginalStackDynamicControlClosureError",
    "OriginalStackDynamicControlClosureSpec",
    "StackCarryAuthorityHint",
    "original_stack_dynamic_control_closure_source",
    "plan_original_stack_dynamic_control_closure",
    "write_original_stack_dynamic_control_closure",
]
