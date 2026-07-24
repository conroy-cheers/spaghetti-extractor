"""Load and consume checked writable-static-pointer authority proposals.

This module is the narrow integration API for the proof-oriented mixed-original
emitter.  It does not treat report status or counts as proof.  Instead it:

* verifies all producer hashes, including the canonical mixed plan;
* validates one exact key and one named Lean term per site;
* reconstructs the existing `OriginalStaticWordSlotBinding` proposal; and
* removes only the matching unresolved-indirect diagnostic.

The resulting plan still relies on generated Lean to check each binding and on
whole-program composition to discharge launch, internal-write, and external
frame preservation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from .interpreter_mixed_original import (
    INTERPRETER_MIXED_ORIGINAL_BASE_MODULE,
    InterpreterMixedOriginalPlan,
    OriginalAddressSeparation,
    OriginalCallableExternalRouteBinding,
    OriginalFiniteOriginStaticWordJumpBinding,
    OriginalGenerationDiagnostic,
    OriginalIndirectSite,
    OriginalRegion,
    OriginalRegisterOffsetWrite,
    OriginalStaticWordJumpSlotBinding,
    OriginalStaticWordSlotBinding,
    QualifiedLeanSymbol,
)
from .finite_static_word_provenance import StaticWordWriteOriginEvidence
from .relocated_writable_static_pointer_slot_proposal import (
    AUTHORITY_FORMAT,
    AUTHORITY_PROFILE,
    mixed_original_plan_sha256,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_U32_LIMIT = 1 << 32
_REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}


class RelocatedWritableStaticPointerSlotAuthorityError(StageAInputError):
    """A generated authority report is malformed or bound elsewhere."""


@dataclass(frozen=True, order=True)
class AuthorityKey:
    source_target_id: int
    source_rva: int
    instruction_rva: int
    transfer_kind: str
    continuation_target_id: int | None
    continuation_rva: int | None
    slot_rva: int
    slot_va: int
    target_id: int
    target_rva: int
    target_va: int


@dataclass(frozen=True)
class AuthorityReference:
    key: AuthorityKey
    site_id: int
    instruction_bytes: bytes
    instruction_form: str
    slot_bytes: bytes
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    value_relation: str
    internal_target_ids: tuple[int, ...]
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...]
    write_origin_evidence: tuple[StaticWordWriteOriginEvidence, ...]
    recovered_from_unresolved_target: bool
    term: QualifiedLeanSymbol

    @property
    def decomposed_adapter_module(self) -> str:
        return (
            f"StageA.{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
            f"WritableSlotAuthority{self.site_id:04d}"
        )

    @property
    def decomposed_adapter_namespace(self) -> str:
        return (
            "StageA.GeneratedRelational."
            f"WritableSlotAuthorityConsumption{self.site_id:04d}"
        )

    @property
    def callable_route_term(self) -> str:
        return f"{self.decomposed_adapter_namespace}.consumedRoute"

    @property
    def callable_route_authority_term(self) -> str:
        return (
            f"{self.decomposed_adapter_namespace}."
            "consumedCallableIndirectExitRouteAuthority"
        )

    @property
    def register_tail_authorities(
        self,
    ) -> tuple["RegisterTailAuthorityReference", ...]:
        return tuple(
            RegisterTailAuthorityReference(
                source_target_id=evidence.source_target_id,
                source_rva=evidence.source_rva,
                instruction_rva=evidence.tail_instruction_rva,
                register=evidence.value_register,
                internal_target_ids=evidence.internal_target_ids,
                external_routes=evidence.external_routes,
                module=self.decomposed_adapter_module,
                namespace=self.decomposed_adapter_namespace,
                index=index,
            )
            for index, evidence in enumerate(self.write_origin_evidence)
            if evidence.tail_instruction_rva is not None
            and evidence.value_register is not None
            and evidence.internal_target_ids
            and evidence.external_routes
        )

    @property
    def static_binding(
        self,
    ) -> (
        OriginalStaticWordSlotBinding
        | OriginalStaticWordJumpSlotBinding
        | OriginalFiniteOriginStaticWordJumpBinding
    ):
        separations = tuple(
            OriginalAddressSeparation(
                register=write.register,
                offset=write.offset + write_byte,
                address=self.key.slot_va + slot_byte,
            )
            for write in self.writes
            for slot_byte in range(4)
            for write_byte in range(4)
        )
        if self.value_relation == "finite_origins":
            if self.key.transfer_kind != "jump":
                raise RelocatedWritableStaticPointerSlotAuthorityError(
                    "finite-origin writable authority is not a tail jump"
                )
            return OriginalFiniteOriginStaticWordJumpBinding(
                slot_id=self.key.slot_rva,
                slot_rva=self.key.slot_rva,
                slot_va=self.key.slot_va,
                slot_bytes=tuple(self.slot_bytes),
                initial_target_id=self.key.target_id,
                initial_target_rva=self.key.target_rva,
                initial_target_va=self.key.target_va,
                internal_target_ids=self.internal_target_ids,
                external_routes=self.external_routes,
                assembled_read=self.assembled_read,
                writes=self.writes,
                address_separations=separations,
            )
        common = {
            "slot_id": self.key.slot_rva,
            "slot_rva": self.key.slot_rva,
            "slot_va": self.key.slot_va,
            "slot_bytes": tuple(self.slot_bytes),
            "target_id": self.key.target_id,
            "target_rva": self.key.target_rva,
            "target_va": self.key.target_va,
            "assembled_read": self.assembled_read,
            "writes": self.writes,
            "address_separations": separations,
        }
        if self.key.transfer_kind == "jump":
            return OriginalStaticWordJumpSlotBinding(**common)
        assert self.key.continuation_target_id is not None
        return OriginalStaticWordSlotBinding(
            continuation_target_id=self.key.continuation_target_id,
            **common,
        )


@dataclass(frozen=True)
class ConsumedAuthorityPlan:
    plan: InterpreterMixedOriginalPlan
    references: tuple[AuthorityReference, ...]
    blocker_count_before: int
    blocker_count_after: int

    @property
    def imported_modules(self) -> tuple[str, ...]:
        return tuple(sorted({reference.term.module for reference in self.references}))

    @property
    def authorizing_terms(self) -> tuple[str, ...]:
        return tuple(reference.term.qualified for reference in self.references)


@dataclass(frozen=True)
class RegisterTailAuthorityReference:
    source_target_id: int
    source_rva: int
    instruction_rva: int
    register: str
    internal_target_ids: tuple[int, ...]
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...]
    module: str
    namespace: str
    index: int

    @property
    def route_term(self) -> str:
        return f"{self.namespace}.consumedRegisterTail{self.index:04d}Route"

    @property
    def route_authority_term(self) -> str:
        return (
            f"{self.namespace}."
            f"consumedRegisterTail{self.index:04d}RouteAuthority"
        )


@dataclass(frozen=True)
class DecomposedAuthorityAdapter:
    key: AuthorityKey
    module: str
    namespace: str
    valid_term: str
    indirect_exit_term: str
    callable_route_authority_term: str | None
    path: Path


def load_relocated_writable_static_pointer_slot_authorities(
    report: Path | str,
    *,
    original_sha256: str,
    state_machine_sha256: str,
    machine_import_report_sha256: str,
    mixed_original_plan: InterpreterMixedOriginalPlan,
) -> tuple[AuthorityReference, ...]:
    """Load named authority references after checking all exact inputs."""

    expected = {
        "original_sha256": _digest(original_sha256, "original_sha256"),
        "state_machine_sha256": _digest(
            state_machine_sha256, "state_machine_sha256"
        ),
        "machine_import_report_sha256": _digest(
            machine_import_report_sha256, "machine_import_report_sha256"
        ),
        "mixed_original_plan_sha256": mixed_original_plan_sha256(
            mixed_original_plan
        ),
    }
    path = Path(report)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"cannot read writable-slot authority report: {error}"
        ) from error
    root = _mapping(value, "authority report")
    if root.get("format") != AUTHORITY_FORMAT:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            "writable-slot authority report has an unsupported format"
        )
    inputs = _mapping(root.get("inputs"), "authority report inputs")
    for field, digest in expected.items():
        if inputs.get(field) != digest:
            raise RelocatedWritableStaticPointerSlotAuthorityError(
                f"writable-slot authority report {field} does not match"
            )
    rows = root.get("sites")
    if not isinstance(rows, list):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            "writable-slot authority sites must be a list"
        )
    references = tuple(_reference(row, index) for index, row in enumerate(rows))
    keys = [reference.key for reference in references]
    terms = [reference.term.qualified for reference in references]
    site_ids = [reference.site_id for reference in references]
    if len(set(keys)) != len(keys):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            "writable-slot authority report contains duplicate site keys"
        )
    if len(set(terms)) != len(terms):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            "writable-slot authority report reuses one Lean term"
        )
    if len(set(site_ids)) != len(site_ids):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            "writable-slot authority report contains duplicate site IDs"
        )
    return tuple(sorted(references, key=lambda reference: reference.key))


def consume_relocated_writable_static_pointer_slot_authorities(
    plan: InterpreterMixedOriginalPlan,
    references: tuple[AuthorityReference, ...],
) -> ConsumedAuthorityPlan:
    """Attach exact static bindings and remove only matching plan blockers."""

    by_site = {
        (reference.key.source_rva, reference.key.instruction_rva): reference
        for reference in references
    }
    if len(by_site) != len(references):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            "authority references are not unique by source and instruction"
        )
    consumed: set[tuple[int, int]] = set()
    regions: list[OriginalRegion] = []
    for region in plan.regions:
        sites: list[OriginalIndirectSite] = []
        successors = list(region.successor_ids)
        for site in region.indirect_sites:
            key = (site.source_rva, site.instruction_rva)
            reference = by_site.get(key)
            if reference is None:
                sites.append(site)
                continue
            _validate_site_match(region, site, reference)
            if site.static_binding is not None:
                raise RelocatedWritableStaticPointerSlotAuthorityError(
                    f"site 0x{site.instruction_rva:x} already has static authority"
                )
            consumed.add(key)
            for target_id in reference.internal_target_ids:
                if target_id not in successors:
                    successors.append(target_id)
            sites.append(
                dataclasses.replace(
                    site,
                    detail=(
                        "relocation-backed writable static code-pointer slot "
                        "has a named Lean authority"
                    ),
                    resolved_target_rva=reference.key.target_rva,
                    static_binding=reference.static_binding,
                )
            )
        regions.append(
            dataclasses.replace(
                region,
                successor_ids=tuple(successors),
                indirect_sites=tuple(sites),
            )
        )
    missing = sorted(set(by_site) - consumed)
    if missing:
        rendered = ", ".join(
            f"0x{source:x}/0x{instruction:x}"
            for source, instruction in missing
        )
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"authority sites do not exist in the exact plan: {rendered}"
        )

    blockers = []
    removed: set[tuple[int, int]] = set()
    for blocker in plan.blockers:
        key = _blocker_site_key(blocker.rva, blocker.reason_code, blocker.detail)
        if key in consumed:
            removed.add(key)
        else:
            blockers.append(blocker)
    unremoved = sorted(consumed - removed)
    if unremoved:
        rendered = ", ".join(
            f"0x{source:x}/0x{instruction:x}"
            for source, instruction in unremoved
        )
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"authority sites lack matching unresolved blockers: {rendered}"
        )

    site_replacements = {
        (site.source_rva, site.instruction_rva): site
        for region in regions
        for site in region.indirect_sites
        if (site.source_rva, site.instruction_rva) in consumed
    }
    global_sites = tuple(
        site_replacements.get((site.source_rva, site.instruction_rva), site)
        for site in plan.indirect_sites
    )
    diagnostics = (
        *plan.diagnostics,
        *(
            OriginalGenerationDiagnostic(
                reason_code="writable_static_pointer_slot_authority",
                rva=reference.key.source_rva,
                detail=(
                    f"named term {reference.term.qualified} checks indirect "
                    f"{reference.key.transfer_kind} "
                    f"0x{reference.key.instruction_rva:x} through slot RVA "
                    f"0x{reference.key.slot_rva:x}"
                ),
            )
            for reference in references
        ),
    )
    transformed = dataclasses.replace(
        plan,
        regions=tuple(regions),
        indirect_sites=global_sites,
        blockers=tuple(blockers),
        diagnostics=tuple(diagnostics),
    )
    return ConsumedAuthorityPlan(
        plan=transformed,
        references=references,
        blocker_count_before=len(plan.blockers),
        blocker_count_after=len(transformed.blockers),
    )


def write_decomposed_writable_static_pointer_slot_adapters(
    out: Path | str,
    consumed: ConsumedAuthorityPlan,
) -> tuple[DecomposedAuthorityAdapter, ...]:
    """Bind named authorities to Meitner's per-site decomposed modules.

    These adapters are deliberately downstream of decomposition.  Each one
    imports exactly one static-indirect module and one authority module, checks
    that their binding terms are definitionally identical, and reconstructs
    the local `OriginalStaticWordSlotBinding.valid` theorem from the named
    authority plus the decomposed module's local invariant check.
    """

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    reference_by_site = {
        (reference.key.source_rva, reference.key.instruction_rva): reference
        for reference in consumed.references
    }
    static_sites = sorted(
        (
            site
            for region in consumed.plan.regions
            for site in region.indirect_sites
            if site.static_binding is not None
        ),
        key=lambda site: (site.source_rva, site.instruction_rva),
    )
    base_namespace = f"{consumed.plan.spec.namespace}Base"
    adapters: list[DecomposedAuthorityAdapter] = []
    seen: set[tuple[int, int]] = set()
    for static_index, site in enumerate(static_sites):
        site_key = (site.source_rva, site.instruction_rva)
        reference = reference_by_site.get(site_key)
        if reference is None:
            continue
        seen.add(site_key)
        local_module = (
            f"StageA.{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
            f"StaticIndirect{static_index:04d}"
        )
        module_name = (
            f"{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}"
            f"WritableSlotAuthority{reference.site_id:04d}"
        )
        module = reference.decomposed_adapter_module
        namespace = reference.decomposed_adapter_namespace
        prefix = f"generatedOriginalStaticIndirect{static_index}"
        region = (
            f"{base_namespace}.generatedOriginalStaticIndirectRegion"
            f"{reference.key.source_target_id}"
        )
        local_binding = f"{base_namespace}.{prefix}Binding"
        local_claim = f"{base_namespace}.{prefix}Claim"
        local_original = f"{base_namespace}.{prefix}OriginalNormalized"
        local_candidate = f"{base_namespace}.{prefix}CandidateNormalized"
        local_checked = f"{base_namespace}.{prefix}Checked"
        context = f"{base_namespace}.generatedOriginalStaticContext"
        carrier = f"{base_namespace}.generatedOriginalCarrierContext"
        path = stage_a / f"{module_name}.lean"
        valid_term = f"{namespace}.consumedBindingValidChecked"
        indirect_exit_term = f"{namespace}.consumedIndirectExitCertificate"
        callable_route_authority_term: str | None = None
        if reference.value_relation == "finite_origins":
            valid_term = f"{namespace}.consumedFiniteAuthorityChecked"
            callable_route_authority_term = (
                f"{namespace}.consumedCallableIndirectExitRouteAuthority"
            )
            route_rows = ", ".join(
                _lean_callable_external_route(route)
                for route in reference.external_routes
            )
            internal_targets = list(reference.internal_target_ids)
            register_tail_authorities = _lean_register_tail_authorities(
                reference,
                base_namespace=base_namespace,
            )
            path.write_text(
                f"""import StageA.RelationalCallableExternalIndirectExit
import StageA.RelationalRelocatedWritableStaticPointerSlot
import StageA.GeneratedCallableExternalCapability
import StageA.GeneratedCallableExternalProgram
import {local_module}
import {reference.term.module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalIndirectExit
open StageA.Relational.RelocatedWritableStaticPointerSlot
open StageA.Relational.ValueProvenance

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def consumedProgram :=
  StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgram

def consumedAuthority :
    CheckedFiniteJumpAuthority {context} {carrier} :=
  {reference.term.qualified}

theorem consumedFiniteAuthorityChecked :
    consumedAuthority.certificate.checked {context} {carrier} = true :=
  consumedAuthority.checked

def consumedRoute : CallableIndirectExitRoute := {{
  externalRoutes := [{route_rows}]
  originalTarget := .read32 (.constant {reference.key.slot_va})
  candidateTarget := .read32 (.constant {reference.key.slot_va})
  source := .staticWord {reference.key.slot_rva}
  transfer := .jump
  internalTargetIds := {internal_targets}
}}

theorem consumedRouteChecked :
    consumedRoute.checked consumedProgram = true := by
  decide +kernel

def consumedOriginBinding :
    CallableIndirectStaticWordOriginBinding consumedProgram consumedRoute := {{
  slot := consumedAuthority.certificate.slot {context}
  slotMember :=
    consumedAuthority.certificate.slotMember consumedAuthority.checked
  source := rfl
  originalTarget := rfl
  candidateTarget := rfl
  relation := rfl
}}

def consumedRuntimeResolution :
    CallableIndirectRuntimeResolution consumedProgram consumedRoute
      {region}.inputInvariant :=
  CallableIndirectRuntimeResolution.of_staticWordOrigin consumedProgram
    consumedRoute {region}.inputInvariant
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgramValid
    consumedRouteChecked consumedOriginBinding

theorem consumedOutcomeChecked :
    consumedRoute.indirectCertificate.outcomeChecked
      {local_original} {local_candidate} = true := by
  decide +kernel

def consumedCallableIndirectExitCertificate :
    CheckedCallableIndirectExitCertificate consumedProgram
      {region}.inputInvariant {local_original} {local_candidate} := {{
  route := consumedRoute
  programValid :=
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgramValid
  staticChecked := consumedRouteChecked
  outcomeChecked := consumedOutcomeChecked
  runtimeResolution := consumedRuntimeResolution
}}

def consumedCallableIndirectExitRouteAuthority :
    CheckedCallableIndirectExitRouteAuthority consumedRoute := {{
  program := consumedProgram
  sourceInvariant := {region}.inputInvariant
  originalBehavior := {local_original}
  candidateBehavior := {local_candidate}
  certificate := consumedCallableIndirectExitCertificate
  routeExact := rfl
}}

def consumedIndirectExitCertificate :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      {carrier} {region}.inputInvariant {local_original} {local_candidate} :=
  consumedCallableIndirectExitCertificate.generic

{register_tail_authorities}

#print axioms consumedFiniteAuthorityChecked
#print axioms consumedRouteChecked
#print axioms consumedOutcomeChecked
#print axioms consumedCallableIndirectExitRouteAuthority
#print axioms consumedIndirectExitCertificate

end {namespace}
""",
                encoding="utf-8",
            )
        elif reference.key.transfer_kind == "call":
            authority_type = "CheckedAuthority"
            binding_type = "OriginalStaticWordSlotBinding"
            adapter = "checkedStaticWordSlotIndirectCertificate"
        elif reference.key.transfer_kind == "jump":
            authority_type = "CheckedJumpAuthority"
            binding_type = "OriginalStaticWordJumpSlotBinding"
            adapter = "checkedStaticWordSlotJumpIndirectCertificate"
        else:
            raise AssertionError("validated transfer kind disappeared")
        if reference.value_relation != "finite_origins":
            path.write_text(
                f"""import StageA.RelationalRelocatedWritableStaticPointerSlot
import StageA.RelationalIndirectExitAdapters
import {local_module}
import {reference.term.module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.RelocatedWritableStaticPointerSlot

def consumedAuthority :
    {authority_type} {context} {carrier} :=
  {reference.term.qualified}

theorem consumedBindingMatches :
    {local_binding} =
      consumedAuthority.certificate.binding {context} := by
  decide +kernel

theorem consumedBindingExactChecked :
    {local_binding}.exactChecked {context} {carrier} = true := by
  rw [consumedBindingMatches]
  exact consumedAuthority.certificate.bindingExactChecked
    consumedAuthority.checked

theorem consumedBindingValidChecked :
    {local_binding}.valid {context} {carrier}
      {region}.inputInvariant {local_original} {local_candidate} = true := by
  simp only [{binding_type}.valid, Bool.and_eq_true]
  exact ⟨consumedBindingExactChecked, {local_checked}⟩

def consumedIndirectExitCertificate :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      {carrier} {region}.inputInvariant {local_original} {local_candidate} :=
  StageA.Relational.IndirectExitAdapters.{adapter}
      {carrier} {region}.inputInvariant {local_original} {local_candidate}
      {local_claim} {local_checked} (by decide +kernel)

#print axioms consumedBindingValidChecked
#print axioms consumedIndirectExitCertificate

end {namespace}
""",
                encoding="utf-8",
            )
        adapters.append(
            DecomposedAuthorityAdapter(
                key=reference.key,
                module=module,
                namespace=namespace,
                valid_term=valid_term,
                indirect_exit_term=indirect_exit_term,
                callable_route_authority_term=callable_route_authority_term,
                path=path,
            )
        )
    missing = sorted(set(reference_by_site) - seen)
    if missing:
        rendered = ", ".join(
            f"0x{source:x}/0x{instruction:x}"
            for source, instruction in missing
        )
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"decomposed emitter lacks authority sites: {rendered}"
        )
    return tuple(adapters)


def _lean_callable_external_route(
    route: OriginalCallableExternalRouteBinding,
) -> str:
    namespace = "StageA.GeneratedRelational.CallableExternalCapability"
    return (
        "{ resolver := "
        f"{namespace}.resolverCallContract{route.resolver_contract_id}, "
        "capability := "
        f"{namespace}.callableExternalCapability{route.capability_id}, "
        "abi := "
        f"{namespace}.resolvedExternalABIContract{route.abi_contract_id} }}"
    )


def _lean_register_tail_authorities(
    reference: AuthorityReference,
    *,
    base_namespace: str,
) -> str:
    definitions: list[str] = []
    for authority in reference.register_tail_authorities:
        prefix = f"consumedRegisterTail{authority.index:04d}"
        route_rows = ", ".join(
            _lean_callable_external_route(route)
            for route in authority.external_routes
        )
        definitions.append(
            f"""def {prefix}Region :=
  ({base_namespace}.generatedOriginalCarrierRegionIndex.get?
    {authority.source_target_id}).get (by decide +kernel)

theorem {prefix}RegionExact :
    {prefix}Region.id = {authority.source_target_id} /\\
      {prefix}Region.original.start = {authority.source_rva} := by
  decide +kernel

def {prefix}Behavior : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts
    {base_namespace}.generatedOriginalCarrierContext.originalPe
    {base_namespace}.generatedOriginalCarrierContext.originalImports
    {base_namespace}.generatedOriginalCarrierContext.machineImportCallContracts
    {prefix}Region.original).get (by decide +kernel)

def {prefix}OriginalNormalized : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false {prefix}Region.targets
    {prefix}Behavior).get (by decide +kernel)

def {prefix}CandidateNormalized : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior true {prefix}Region.targets
    {prefix}Behavior).get (by decide +kernel)

def {prefix}Route : CallableIndirectExitRoute := {{
  externalRoutes := [{route_rows}]
  originalTarget := .inputReg .{authority.register}
  candidateTarget := .inputReg .{authority.register}
  source := .register .{authority.register} .{authority.register}
  transfer := .jump
  internalTargetIds := {list(authority.internal_target_ids)}
}}

theorem {prefix}RouteChecked :
    {prefix}Route.checked consumedProgram = true := by
  decide +kernel

def {prefix}Invariant : StateInvariant :=
  ValueProvenance.StateInvariant.withAdditionalRegisterValueOriginRelations
    {prefix}Region.inputInvariant
    [{prefix}Route.registerOriginRelation .{authority.register}
      .{authority.register}]

def {prefix}OriginBinding :
    CallableIndirectRegisterOriginBinding {prefix}Route
      {prefix}Invariant := {{
  originalRegister := .{authority.register}
  candidateRegister := .{authority.register}
  originalTarget := rfl
  candidateTarget := rfl
  relationMember := by
    simp [{prefix}Invariant,
      ValueProvenance.StateInvariant.withAdditionalRegisterValueOriginRelations]
}}

def {prefix}RuntimeResolution :
    CallableIndirectRuntimeResolution consumedProgram {prefix}Route
      {prefix}Invariant :=
  CallableIndirectRuntimeResolution.of_registerOrigin consumedProgram
    {prefix}Route {prefix}Invariant
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgramValid
    {prefix}RouteChecked {prefix}OriginBinding

theorem {prefix}OutcomeChecked :
    {prefix}Route.indirectCertificate.outcomeChecked
      {prefix}OriginalNormalized {prefix}CandidateNormalized = true := by
  decide +kernel

def {prefix}Certificate :
    CheckedCallableIndirectExitCertificate consumedProgram
      {prefix}Invariant {prefix}OriginalNormalized
      {prefix}CandidateNormalized := {{
  route := {prefix}Route
  programValid :=
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgramValid
  staticChecked := {prefix}RouteChecked
  outcomeChecked := {prefix}OutcomeChecked
  runtimeResolution := {prefix}RuntimeResolution
}}

def {prefix}RouteAuthority :
    CheckedCallableIndirectExitRouteAuthority {prefix}Route := {{
  program := consumedProgram
  sourceInvariant := {prefix}Invariant
  originalBehavior := {prefix}OriginalNormalized
  candidateBehavior := {prefix}CandidateNormalized
  certificate := {prefix}Certificate
  routeExact := rfl
}}

#print axioms {prefix}RegionExact
#print axioms {prefix}RouteAuthority"""
        )
    return "\n\n".join(definitions)


def _validate_site_match(
    region: OriginalRegion,
    site: OriginalIndirectSite,
    reference: AuthorityReference,
) -> None:
    key = reference.key
    expected_expression = {
        "op": "load",
        "width": 4,
        "address": {
            "op": "const",
            "value": key.slot_va,
            "width": 32,
        },
    }
    checks = (
        (region.target_id == key.source_target_id, "source target ID"),
        (region.rva == key.source_rva, "source RVA"),
        (site.category == "static_pointer_slot", "site category"),
        (
            site.is_call == (key.transfer_kind == "call"),
            "transfer kind",
        ),
        (site.continuation_rva == key.continuation_rva, "continuation RVA"),
        (site.target_va == key.slot_va, "slot VA"),
        (site.target_expression == expected_expression, "target expression"),
        (
            site.resolved_target_rva in {None, key.target_rva},
            "resolved target RVA",
        ),
    )
    for valid, field in checks:
        if not valid:
            raise RelocatedWritableStaticPointerSlotAuthorityError(
                f"site 0x{site.instruction_rva:x} differs in {field}"
            )


def _blocker_site_key(
    rva: int | None, reason_code: str, detail: str
) -> tuple[int, int] | None:
    if (
        rva is None
        or reason_code != "unresolved_indirect_control"
        or " at 0x" not in detail
    ):
        return None
    value = detail.split(" at 0x", 1)[1].split(":", 1)[0]
    try:
        return rva, int(value, 16)
    except ValueError:
        return None


def _reference(value: Any, index: int) -> AuthorityReference:
    row = _mapping(value, f"sites[{index}]")
    if row.get("profile") != AUTHORITY_PROFILE:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] has an unsupported profile"
        )
    transfer_kind = row.get("transfer_kind", "call")
    if transfer_kind not in {"call", "jump"}:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}].transfer_kind is unsupported"
        )
    continuation_target_id = row.get("continuation_target_id")
    continuation_rva = row.get("continuation_rva")
    if transfer_kind == "call":
        continuation_target_id = _natural(
            continuation_target_id,
            f"sites[{index}].continuation_target_id",
        )
        continuation_rva = _u32(
            continuation_rva,
            f"sites[{index}].continuation_rva",
        )
    elif continuation_target_id is not None or continuation_rva is not None:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] jump must not carry a continuation"
        )
    key = AuthorityKey(
        source_target_id=_natural(
            row.get("source_target_id"), f"sites[{index}].source_target_id"
        ),
        source_rva=_u32(row.get("source_rva"), f"sites[{index}].source_rva"),
        instruction_rva=_u32(
            row.get("instruction_rva"), f"sites[{index}].instruction_rva"
        ),
        transfer_kind=transfer_kind,
        continuation_target_id=continuation_target_id,
        continuation_rva=continuation_rva,
        slot_rva=_u32(row.get("slot_rva"), f"sites[{index}].slot_rva"),
        slot_va=_u32(row.get("slot_va"), f"sites[{index}].slot_va"),
        target_id=_natural(
            row.get("target_id"), f"sites[{index}].target_id"
        ),
        target_rva=_u32(
            row.get("target_rva"), f"sites[{index}].target_rva"
        ),
        target_va=_u32(row.get("target_va"), f"sites[{index}].target_va"),
    )
    instruction_bytes = _hex_bytes(
        row.get("instruction_bytes"), f"sites[{index}].instruction_bytes"
    )
    if not instruction_bytes:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] instruction bytes are empty"
        )
    slot_bytes = _hex_bytes(
        row.get("slot_bytes"), f"sites[{index}].slot_bytes"
    )
    if len(slot_bytes) != 4 or int.from_bytes(slot_bytes, "little") != key.target_va:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] slot bytes do not encode the target VA"
        )
    instruction_form = row.get("instruction_form")
    if instruction_form not in {"memory_indirect", "register_indirect"}:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] instruction form is unsupported"
        )
    writes = tuple(
        _write(item, index, write_index)
        for write_index, item in enumerate(
            _list(row.get("writes"), f"sites[{index}].writes")
        )
    )
    value_relation = row.get("value_relation")
    if value_relation not in {"fixed_code_pointer", "finite_origins"}:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}].value_relation is unsupported"
        )
    internal_target_ids = tuple(
        _natural(value, f"sites[{index}].internal_target_ids[{target_index}]")
        for target_index, value in enumerate(
            _list(
                row.get("internal_target_ids"),
                f"sites[{index}].internal_target_ids",
            )
        )
    )
    external_routes = tuple(
        _external_route(value, index, route_index)
        for route_index, value in enumerate(
            _list(row.get("external_routes"), f"sites[{index}].external_routes")
        )
    )
    write_origin_evidence = tuple(
        _write_origin_evidence(value, index, write_index)
        for write_index, value in enumerate(
            _list(
                row.get("write_origin_evidence"),
                f"sites[{index}].write_origin_evidence",
            )
        )
    )
    if len(internal_target_ids) != len(set(internal_target_ids)):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] repeats an internal target"
        )
    if key.target_id not in internal_target_ids:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] omits its on-disk initial target"
        )
    resource_ids = [route.resource_id for route in external_routes]
    if len(resource_ids) != len(set(resource_ids)):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] repeats one callable resource route"
        )
    if value_relation == "fixed_code_pointer":
        if internal_target_ids != (key.target_id,) or external_routes:
            raise RelocatedWritableStaticPointerSlotAuthorityError(
                f"sites[{index}] fixed relation has a finite alternative inventory"
            )
    elif (
        transfer_kind != "jump"
        or not external_routes
        or not write_origin_evidence
    ):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}] finite relation lacks a checked tail-write inventory"
        )
    allowed_internal = set(internal_target_ids)
    allowed_routes = set(external_routes)
    for write in write_origin_evidence:
        if (
            not set(write.internal_target_ids) <= allowed_internal
            or not set(write.external_routes) <= allowed_routes
            or not write.internal_target_ids
            and not write.external_routes
        ):
            raise RelocatedWritableStaticPointerSlotAuthorityError(
                f"sites[{index}] write evidence escapes its finite inventory"
            )
    term_row = _mapping(
        row.get("authorizing_lean_term"),
        f"sites[{index}].authorizing_lean_term",
    )
    term = QualifiedLeanSymbol(
        module=_string(term_row.get("module"), f"sites[{index}].term.module"),
        namespace=_string(
            term_row.get("namespace"), f"sites[{index}].term.namespace"
        ),
        symbol=_string(term_row.get("symbol"), f"sites[{index}].term.symbol"),
    )
    try:
        term.validate(f"sites[{index}].authorizing_lean_term")
    except StageAInputError as error:
        raise RelocatedWritableStaticPointerSlotAuthorityError(str(error)) from error
    recovered = row.get("recovered_from_unresolved_target")
    if not isinstance(recovered, bool):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"sites[{index}].recovered_from_unresolved_target must be Boolean"
        )
    return AuthorityReference(
        key=key,
        site_id=_natural(row.get("site_id"), f"sites[{index}].site_id"),
        instruction_bytes=instruction_bytes,
        instruction_form=instruction_form,
        slot_bytes=slot_bytes,
        assembled_read=_boolean(
            row.get("assembled_read"), f"sites[{index}].assembled_read"
        ),
        writes=writes,
        value_relation=value_relation,
        internal_target_ids=internal_target_ids,
        external_routes=external_routes,
        write_origin_evidence=write_origin_evidence,
        recovered_from_unresolved_target=recovered,
        term=term,
    )


def _external_route(
    value: Any, site_index: int, route_index: int
) -> OriginalCallableExternalRouteBinding:
    field = f"sites[{site_index}].external_routes[{route_index}]"
    row = _mapping(value, field)
    return OriginalCallableExternalRouteBinding(
        resolver_contract_id=_natural(
            row.get("resolver_contract_id"), f"{field}.resolver_contract_id"
        ),
        capability_id=_natural(
            row.get("capability_id"), f"{field}.capability_id"
        ),
        abi_contract_id=_natural(
            row.get("abi_contract_id"), f"{field}.abi_contract_id"
        ),
        resource_id=_natural(row.get("resource_id"), f"{field}.resource_id"),
    )


def _write_origin_evidence(
    value: Any, site_index: int, write_index: int
) -> StaticWordWriteOriginEvidence:
    field = f"sites[{site_index}].write_origin_evidence[{write_index}]"
    row = _mapping(value, field)
    internal = tuple(
        _natural(item, f"{field}.internal_target_ids[{index}]")
        for index, item in enumerate(
            _list(row.get("internal_target_ids"), f"{field}.internal_target_ids")
        )
    )
    routes = tuple(
        _external_route(item, site_index, route_index)
        for route_index, item in enumerate(
            _list(row.get("external_routes"), f"{field}.external_routes")
        )
    )
    if len(internal) != len(set(internal)) or len(routes) != len(set(routes)):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} repeats an origin"
        )
    value_register = row.get("value_register")
    if value_register is not None and value_register not in _REGISTERS:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field}.value_register is unsupported"
        )
    tail_value = row.get("tail_instruction_rva")
    tail_instruction_rva = (
        None
        if tail_value is None
        else _u32(tail_value, f"{field}.tail_instruction_rva")
    )
    if tail_instruction_rva is not None and value_register is None:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} has a tail instruction without a value register"
        )
    return StaticWordWriteOriginEvidence(
        source_target_id=_natural(
            row.get("source_target_id"), f"{field}.source_target_id"
        ),
        source_rva=_u32(row.get("source_rva"), f"{field}.source_rva"),
        instruction_rva=_u32(
            row.get("instruction_rva"), f"{field}.instruction_rva"
        ),
        internal_target_ids=internal,
        external_routes=routes,
        value_register=value_register,
        tail_instruction_rva=tail_instruction_rva,
    )


def _write(
    value: Any, site_index: int, write_index: int
) -> OriginalRegisterOffsetWrite:
    field = f"sites[{site_index}].writes[{write_index}]"
    row = _mapping(value, field)
    register = row.get("register")
    if register not in _REGISTERS:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field}.register is unsupported"
        )
    offset = _u32(row.get("offset"), f"{field}.offset")
    expression = _mapping(row.get("value"), f"{field}.value")
    operation = expression.get("op")
    if operation == "const":
        _u32(expression.get("value"), f"{field}.value.value")
    elif operation == "reg":
        if expression.get("name") not in _REGISTERS:
            raise RelocatedWritableStaticPointerSlotAuthorityError(
                f"{field}.value register is unsupported"
            )
    else:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field}.value expression is unsupported"
        )
    return OriginalRegisterOffsetWrite(
        register=register,
        offset=offset,
        value=dict(expression),
        subtract=_boolean(row.get("subtract"), f"{field}.subtract"),
    )


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be an object"
        )
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be a list"
        )
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be a nonempty string"
        )
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be Boolean"
        )
    return value


def _natural(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be a natural number"
        )
    return value


def _u32(value: Any, field: str) -> int:
    result = _natural(value, field)
    if result >= _U32_LIMIT:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must fit an unsigned PE32 word"
        )
    return result


def _hex_bytes(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be even-length hexadecimal"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} is not hexadecimal"
        ) from error


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RelocatedWritableStaticPointerSlotAuthorityError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def sha256_file(path: Path | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


__all__ = [
    "AuthorityKey",
    "AuthorityReference",
    "ConsumedAuthorityPlan",
    "DecomposedAuthorityAdapter",
    "RegisterTailAuthorityReference",
    "RelocatedWritableStaticPointerSlotAuthorityError",
    "consume_relocated_writable_static_pointer_slot_authorities",
    "load_relocated_writable_static_pointer_slot_authorities",
    "sha256_file",
    "write_decomposed_writable_static_pointer_slot_adapters",
]
