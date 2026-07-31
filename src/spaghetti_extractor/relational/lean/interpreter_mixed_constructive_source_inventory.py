"""Generate finite constructive mixed-kernel source inventories.

The generator serializes typed Lean terms and deterministic finite mappings.
It does not prove runtime state relations or local chunk semantics.  Generated
Lean rechecks every source identity, candidate-record association, operation
entry, and exact-one classification residual.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-mixed-constructive-source-inventory-v1"
)
INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_MODULE = (
    "GeneratedRelationalInterpreterMixedConstructiveSourceInventory"
)
INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_LEAN_FILENAME = (
    f"{INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_MODULE}.lean"
)
INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_PLAN_FILENAME = (
    "interpreter-mixed-constructive-source-inventory.json"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_QUALIFIED = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)

_OPERATIONS = {
    "programLookup": ".programLookup",
    "interpreterStep": ".interpreterStep",
    "runFunction": ".runFunction",
    "invokeCall": ".invokeCall",
}
_RULE_KINDS = {
    "launch",
    "semantic_transfer",
    "external_operation",
    "external_boundary",
}


class ConstructiveSourceInventoryGenerationError(StageAInputError):
    """A constructive source inventory is incomplete or ambiguous."""


@dataclass(frozen=True)
class ConstructiveClassifierTerms:
    original_context: str
    original_authority: str
    launch_profile: str
    original_root: str
    reachability: str
    original_program: str
    candidate: str
    candidate_authority: str
    compiled_program: str
    kernel_abi: str
    kernel_dispatches: str
    relation_contract: str
    candidate_root_rva: str
    launch_root_target_id_exact: str
    candidate_root_rva_exact: str
    candidate_record_count_exact: str
    reachability_target_ids_exact: str

    def values(self) -> tuple[str, ...]:
        return tuple(self.__dict__.values())


@dataclass(frozen=True)
class ExactSemanticSourceBinding:
    name: str
    target_id: int
    source_rva: int
    record_index: int
    source_term: str
    target_id_exact: str
    source_rva_exact: str
    record_at_index_exact: str


@dataclass(frozen=True)
class CheckedKernelEntryBinding:
    name: str
    operation: str
    entry_rva: int
    function_entry_exact: str


@dataclass(frozen=True)
class ConstructiveSourceRuleBinding:
    source: str
    kind: str
    entry: str | None = None
    candidate_rva: int | None = None


@dataclass(frozen=True)
class ConstructiveSourceInventorySpec:
    binding_module: str
    parameter_name: str
    parameter_type: str
    namespace: str
    terms: ConstructiveClassifierTerms
    candidate_root_rva: int
    launch_root_target_id: int
    candidate_record_count: int
    expected_target_ids: tuple[int, ...]
    expected_operations: tuple[str, ...]
    sources: tuple[ExactSemanticSourceBinding, ...]
    entries: tuple[CheckedKernelEntryBinding, ...]
    rules: tuple[ConstructiveSourceRuleBinding, ...]
    output_module: str = INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_MODULE


@dataclass(frozen=True)
class ConstructiveSourceInventoryPlan:
    spec: ConstructiveSourceInventorySpec
    sources: tuple[ExactSemanticSourceBinding, ...]
    entries: tuple[CheckedKernelEntryBinding, ...]
    rules: tuple[ConstructiveSourceRuleBinding, ...]

    def payload(self) -> dict[str, object]:
        source_by_name = {source.name: source for source in self.sources}
        entry_by_name = {entry.name: entry for entry in self.entries}
        return {
            "format": INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_FORMAT,
            "acceptance_authority": False,
            "binding_module": self.spec.binding_module,
            "lean_module": self.spec.output_module,
            "lean_namespace": self.spec.namespace,
            "candidate_root_rva": self.spec.candidate_root_rva,
            "launch_root_target_id": self.spec.launch_root_target_id,
            "candidate_record_count": self.spec.candidate_record_count,
            "sources": [
                {
                    "name": source.name,
                    "target_id": source.target_id,
                    "source_rva": source.source_rva,
                    "record_index": source.record_index,
                    "source_term": source.source_term,
                    "target_id_exact": source.target_id_exact,
                    "source_rva_exact": source.source_rva_exact,
                    "record_at_index_exact": source.record_at_index_exact,
                }
                for source in self.sources
            ],
            "entries": [
                {
                    "name": entry.name,
                    "operation": entry.operation,
                    "entry_rva": entry.entry_rva,
                    "function_entry_exact": entry.function_entry_exact,
                }
                for entry in self.entries
            ],
            "rules": [
                {
                    "source": rule.source,
                    "source_target_id": source_by_name[rule.source].target_id,
                    "kind": rule.kind,
                    "entry": rule.entry,
                    "operation": (
                        None
                        if rule.entry is None
                        else entry_by_name[rule.entry].operation
                    ),
                    "candidate_rva": _rule_candidate_rva(
                        rule,
                        entry_by_name,
                        self.spec.candidate_root_rva,
                    ),
                }
                for rule in self.rules
            ],
            "checked_finite_facts": {
                "source_target_ids": [source.target_id for source in self.sources],
                "source_rvas": [source.source_rva for source in self.sources],
                "record_indices": [source.record_index for source in self.sources],
                "operation_entries": {
                    entry.operation: entry.entry_rva for entry in self.entries
                },
                "one_rule_per_source": True,
                "all_reachable_sources_associated": True,
                "candidate_record_associations_unique_and_in_bounds": True,
                "unused_candidate_records_allowed": True,
                "runtime_match_keys_unique": True,
            },
            "typed_residuals": [
                "ConstructiveMixedKernelStateFacts reachability.targetIds "
                "relationContract originalBefore candidateBefore",
                "ConstructiveMixedKernelPhaseStateFacts relationContract "
                "evidence",
                "constructiveMixedKernelSourceEvidence? generatedRules "
                "originalBefore candidateBefore = some evidence",
                "GeneratedConstructiveRuleSemanticResidual evidence",
            ],
            "failure_mode": "incomplete",
        }


def build_constructive_source_inventory_plan(
    spec: ConstructiveSourceInventorySpec,
) -> ConstructiveSourceInventoryPlan:
    _validate_spec(spec)
    sources = tuple(
        sorted(
            spec.sources,
            key=lambda source: (
                source.target_id,
                source.source_rva,
                source.record_index,
                source.name,
            ),
        )
    )
    entries = tuple(
        sorted(
            spec.entries,
            key=lambda entry: (
                entry.operation,
                entry.entry_rva,
                entry.name,
            ),
        )
    )
    source_by_name = {source.name: source for source in sources}
    entry_by_name = {entry.name: entry for entry in entries}
    rules = tuple(
        sorted(
            spec.rules,
            key=lambda rule: (
                source_by_name[rule.source].target_id,
                _rule_candidate_rva(rule, entry_by_name, spec.candidate_root_rva),
                rule.kind,
            ),
        )
    )
    return ConstructiveSourceInventoryPlan(spec, sources, entries, rules)


def relational_interpreter_mixed_constructive_source_inventory_source(
    plan: ConstructiveSourceInventoryPlan,
) -> str:
    spec = plan.spec
    terms = spec.terms
    parameter = spec.parameter_name
    type_arguments = _classifier_type_arguments(terms)
    source_type_arguments = _source_type_arguments(terms)
    source_definitions = "\n\n".join(
        _source_definition(source, parameter, source_type_arguments, terms)
        for source in plan.sources
    )
    entry_definitions = "\n\n".join(
        _entry_definition(entry, parameter, terms) for entry in plan.entries
    )
    source_by_name = {source.name: source for source in plan.sources}
    entry_by_name = {entry.name: entry for entry in plan.entries}
    rule_definitions = "\n\n".join(
        _rule_definition(
            rule,
            index,
            parameter,
            source_by_name,
            entry_by_name,
            terms.launch_profile,
        )
        for index, rule in enumerate(plan.rules)
    )
    rule_names = ", ".join(
        f"generatedRule{index:04d} {parameter}" for index in range(len(plan.rules))
    )
    target_ids = ", ".join(str(source.target_id) for source in plan.sources)
    source_rvas = ", ".join(str(source.source_rva) for source in plan.sources)
    record_indices = ", ".join(str(source.record_index) for source in plan.sources)
    expected_match_keys = ", ".join(
        f"({source_by_name[rule.source].target_id}, "
        f"{_rule_candidate_rva(rule, entry_by_name, spec.candidate_root_rva)})"
        for rule in plan.rules
    )
    simplifiers = ", ".join(
        [
            "generatedConstructiveSourceRules",
            "generatedRuleSourceTargetId",
            "generatedRuleCandidateRva",
            "generatedRuleMatchKey",
            *(f"generatedRule{index:04d}" for index in range(len(plan.rules))),
            *(
                f"generatedSource{_lean_name(source.name)}TargetIdExact"
                for source in plan.sources
            ),
            *(f"generatedEntry{_lean_name(entry.name)}" for entry in plan.entries),
            "generatedCandidateRootRvaExact",
            "generatedExpectedRuleSourceTargetIds",
            "generatedSourceTargetIds",
            "generatedExpectedRuleMatchKeys",
        ]
    )
    source_count = len(plan.sources)

    return f"""import StageA.RelationalInterpreterMixedConstructiveSourceClassifier
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

variable ({parameter} : {spec.parameter_type})

theorem generatedLaunchRootTargetIdExact :
    {terms.launch_profile}.rootTargetId = {spec.launch_root_target_id} := by
  exact {terms.launch_root_target_id_exact}

theorem generatedCandidateRootRvaExact :
    {terms.candidate_root_rva} = {spec.candidate_root_rva} := by
  exact {terms.candidate_root_rva_exact}

theorem generatedCandidateRecordCountExact :
    {terms.candidate_authority}.semanticRecords.length =
      {spec.candidate_record_count} := by
  exact {terms.candidate_record_count_exact}

theorem generatedCandidateRecordSourceRvasUnique :
    ({terms.candidate_authority}.semanticRecords.map
      (fun record => record.sourceRva)).Nodup :=
  {terms.candidate_authority}.table.sourceRvasUnique

{source_definitions}

def generatedSourceTargetIds : List Nat := [{target_ids}]
def generatedSourceRvas : List Nat := [{source_rvas}]
def generatedRecordIndices : List Nat := [{record_indices}]

theorem generatedSourceTargetIdsUnique :
    generatedSourceTargetIds.Nodup := by decide

theorem generatedReachabilityTargetIdsExact :
    {terms.reachability}.targetIds = generatedSourceTargetIds := by
  simpa [generatedSourceTargetIds] using
    {terms.reachability_target_ids_exact}

theorem generatedSourceRvasUnique :
    generatedSourceRvas.Nodup := by decide

theorem generatedRecordIndicesUnique :
    generatedRecordIndices.Nodup := by decide

theorem generatedRecordIndicesInBounds :
    generatedRecordIndices.all (fun index =>
      index < {spec.candidate_record_count}) = true := by decide

{entry_definitions}

abbrev GeneratedConstructiveSourceRule :=
  ConstructiveMixedKernelSourceRule {type_arguments}

abbrev GeneratedConstructiveSourceEvidence :=
  ConstructiveMixedKernelSourceEvidence {type_arguments}

{rule_definitions}

def generatedConstructiveSourceRules :
    List (GeneratedConstructiveSourceRule {parameter}) := [{rule_names}]

def generatedRuleSourceTargetId :
    GeneratedConstructiveSourceRule {parameter} -> Nat
  | .launch source _ | .semanticTransfer source _ |
      .externalOperation source _ | .externalBoundary source .. =>
      source.targetId

def generatedRuleCandidateRva :
    GeneratedConstructiveSourceRule {parameter} -> Nat
  | .launch .. => {terms.candidate_root_rva}
  | .semanticTransfer _ entry | .externalOperation _ entry => entry.entryRva
  | .externalBoundary _ _ candidateRva => candidateRva

def generatedRuleMatchKey
    (rule : GeneratedConstructiveSourceRule {parameter}) : Nat × Nat :=
  (generatedRuleSourceTargetId {parameter} rule,
    generatedRuleCandidateRva {parameter} rule)

def generatedExpectedRuleSourceTargetIds : List Nat :=
  generatedSourceTargetIds

def generatedExpectedRuleMatchKeys : List (Nat × Nat) := [
  {expected_match_keys}
]

theorem generatedConstructiveSourceRuleCountExact
    ({parameter} : {spec.parameter_type}) :
    (generatedConstructiveSourceRules {parameter}).length = {source_count} := by
  rfl

theorem generatedRuleSourceTargetIdsExact
    ({parameter} : {spec.parameter_type}) :
    (generatedConstructiveSourceRules {parameter}).map
      (generatedRuleSourceTargetId {parameter}) =
      generatedExpectedRuleSourceTargetIds := by
  simp [{simplifiers}]

theorem generatedRulesCoverReachability
    ({parameter} : {spec.parameter_type}) :
    (generatedConstructiveSourceRules {parameter}).map
      (generatedRuleSourceTargetId {parameter}) =
      {terms.reachability}.targetIds := by
  rw [generatedRuleSourceTargetIdsExact]
  exact Eq.symm (generatedReachabilityTargetIdsExact {parameter})

theorem generatedRuleMatchKeysExact
    ({parameter} : {spec.parameter_type}) :
    (generatedConstructiveSourceRules {parameter}).map
      (generatedRuleMatchKey {parameter}) =
      generatedExpectedRuleMatchKeys := by
  simp [{simplifiers}]

theorem generatedRuleMatchKeysUnique :
    generatedExpectedRuleMatchKeys.Nodup := by decide

theorem generatedRuleSourceTargetIdsUnique
    ({parameter} : {spec.parameter_type}) :
    ((generatedConstructiveSourceRules {parameter}).map
      (generatedRuleSourceTargetId {parameter})).Nodup := by
  rw [generatedRuleSourceTargetIdsExact]
  exact generatedSourceTargetIdsUnique

theorem generatedActualRuleMatchKeysUnique
    ({parameter} : {spec.parameter_type}) :
    ((generatedConstructiveSourceRules {parameter}).map
      (generatedRuleMatchKey {parameter})).Nodup := by
  rw [generatedRuleMatchKeysExact]
  exact generatedRuleMatchKeysUnique

def generatedConstructiveMixedKernelInvariant :
    MixedExecutionInvariant {terms.reachability}.targetIds
      {terms.relation_contract} :=
  constructiveMixedKernelRuntimeInvariant {type_arguments}
    {terms.relation_contract} (generatedConstructiveSourceRules {parameter})

/-- The local semantic proof is indexed by the exact classifier witness.
Executable source families cannot share an unrelated path or operation proof. -/
inductive GeneratedConstructiveRuleSemanticResidual
    ({parameter} : {spec.parameter_type}) :
    {{originalBefore : WorldExecution}} ->
    {{candidateBefore : NativeWorldExecution}} ->
    GeneratedConstructiveSourceEvidence {parameter}
      originalBefore candidateBefore -> Type where
  | semanticTransfer
      (source : ExactOriginalSemanticSource
        {_source_type_arguments(terms)})
      (entry : ExactCandidateKernelEntry {terms.compiled_program})
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entry.entryRva candidateBefore)
      (certificate : MixedKernelOperationComponentCertificate
        {terms.original_program} {terms.candidate} {terms.relation_contract}
        (generatedConstructiveMixedKernelInvariant {parameter})
        {terms.compiled_program} {terms.kernel_abi} {terms.kernel_dispatches}
        {terms.candidate_authority} source.source.target.rva
        entry.operation entry.entryRva originalBefore candidateBefore) :
      GeneratedConstructiveRuleSemanticResidual {parameter}
        (.semanticTransfer source entry originalAtSource candidateAtEntry)
  | externalOperation
      (source : ExactOriginalSemanticSource
        {_source_type_arguments(terms)})
      (entry : ExactCandidateKernelEntry {terms.compiled_program})
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entry.entryRva candidateBefore)
      (certificate : MixedKernelOperationComponentCertificate
        {terms.original_program} {terms.candidate} {terms.relation_contract}
        (generatedConstructiveMixedKernelInvariant {parameter})
        {terms.compiled_program} {terms.kernel_abi} {terms.kernel_dispatches}
        {terms.candidate_authority} source.source.target.rva
        entry.operation entry.entryRva originalBefore candidateBefore) :
      GeneratedConstructiveRuleSemanticResidual {parameter}
        (.externalOperation source entry originalAtSource candidateAtEntry)
  | externalBoundary
      (source : ExactOriginalSemanticSource
        {_source_type_arguments(terms)})
      (owner : ExactCandidateKernelEntry {terms.compiled_program})
      (candidateRva : Nat)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtSource : nativeExecutionAtRva candidateRva candidateBefore)
      (paths : MixedKernelChunkPaths {terms.original_program} {terms.candidate}
        {terms.relation_contract}
        (generatedConstructiveMixedKernelInvariant {parameter})
        originalBefore candidateBefore) :
      GeneratedConstructiveRuleSemanticResidual {parameter}
        (.externalBoundary source owner candidateRva originalAtSource
          candidateAtSource)
  | returned
      (originalState candidateState : MachineState)
      (originalWorld candidateWorld : RelationalWorld)
      (candidateEvents : List NativeExternalEvent) :
      GeneratedConstructiveRuleSemanticResidual {parameter}
        (.returned originalState candidateState originalWorld candidateWorld
          candidateEvents)
  | terminated
      (originalWorld candidateWorld : RelationalWorld)
      (candidateEvents : List NativeExternalEvent) :
      GeneratedConstructiveRuleSemanticResidual {parameter}
        (.terminated originalWorld candidateWorld candidateEvents)
  | matchingFault (cause : ModeledFault) :
      GeneratedConstructiveRuleSemanticResidual {parameter}
        (.matchingFault cause)

def generatedConstructiveMixedKernelSourceClassifier :
    MixedKernelRuntimeSourceClassifier {type_arguments}
      (generatedConstructiveMixedKernelInvariant {parameter}) :=
  constructiveMixedKernelRuntimeSourceClassifier {type_arguments}
    {terms.relation_contract} (generatedConstructiveSourceRules {parameter})

/-- State facts, exact-one classification, and the witness-indexed local
semantic proof remain explicit at each root or chunk endpoint. -/
structure GeneratedConstructiveSourceResidual
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) where
  evidence : GeneratedConstructiveSourceEvidence {parameter}
    originalBefore candidateBefore
  stateFacts :
    ConstructiveMixedKernelStateFacts {terms.reachability}.targetIds
      {terms.relation_contract} originalBefore candidateBefore
  phaseStateFacts :
    ConstructiveMixedKernelPhaseStateFacts {terms.relation_contract} evidence
  classificationExact :
    constructiveMixedKernelSourceEvidence?
      (generatedConstructiveSourceRules {parameter})
      originalBefore candidateBefore = some evidence
  runtimeEvidence : evidence.phase = .runtime
  semantic :
    GeneratedConstructiveRuleSemanticResidual {parameter} evidence

theorem GeneratedConstructiveSourceResidual.invariantHolds
    (residual : GeneratedConstructiveSourceResidual {parameter}
      originalBefore candidateBefore) :
    (generatedConstructiveMixedKernelInvariant {parameter}).holds
      originalBefore candidateBefore :=
  constructiveMixedKernelRuntimeInvariant_holds residual.stateFacts
    residual.phaseStateFacts
    residual.classificationExact residual.runtimeEvidence

#print axioms generatedCandidateRecordSourceRvasUnique
#print axioms generatedSourceTargetIdsUnique
#print axioms generatedReachabilityTargetIdsExact
#print axioms generatedSourceRvasUnique
#print axioms generatedRecordIndicesUnique
#print axioms generatedRecordIndicesInBounds
#print axioms generatedRuleSourceTargetIdsExact
#print axioms generatedRulesCoverReachability
#print axioms generatedRuleMatchKeysExact
#print axioms generatedRuleMatchKeysUnique
#print axioms generatedRuleSourceTargetIdsUnique
#print axioms generatedActualRuleMatchKeysUnique
#print axioms generatedConstructiveMixedKernelSourceClassifier
#print axioms GeneratedConstructiveSourceResidual.invariantHolds

end {spec.namespace}
"""


def write_constructive_source_inventory_bundle(
    out: Path | str,
    plan: ConstructiveSourceInventoryPlan,
) -> tuple[Path, Path]:
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    plan_path = root / INTERPRETER_MIXED_CONSTRUCTIVE_SOURCE_INVENTORY_PLAN_FILENAME
    lean_path = root / f"{plan.spec.output_module}.lean"
    plan_path.write_text(
        json.dumps(plan.payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lean_path.write_text(
        relational_interpreter_mixed_constructive_source_inventory_source(plan),
        encoding="utf-8",
    )
    return plan_path, lean_path


def _validate_spec(spec: ConstructiveSourceInventorySpec) -> None:
    if _STAGE_A_MODULE.fullmatch(spec.binding_module) is None:
        raise ConstructiveSourceInventoryGenerationError(
            "binding_module must be a canonical StageA module"
        )
    if _QUALIFIED.fullmatch(spec.parameter_type) is None:
        raise ConstructiveSourceInventoryGenerationError(
            "parameter_type must be a canonical Lean identifier"
        )
    if _IDENTIFIER.fullmatch(spec.parameter_name) is None:
        raise ConstructiveSourceInventoryGenerationError(
            "parameter_name must be a Lean identifier"
        )
    if _QUALIFIED.fullmatch(spec.namespace) is None:
        raise ConstructiveSourceInventoryGenerationError(
            "namespace must be a canonical Lean namespace"
        )
    if _IDENTIFIER.fullmatch(spec.output_module) is None:
        raise ConstructiveSourceInventoryGenerationError(
            "output_module must be a Lean module name"
        )
    for term in spec.terms.values():
        _checked_term(term, "context term")
    for value, context in (
        (spec.candidate_root_rva, "candidate_root_rva"),
        (spec.launch_root_target_id, "launch_root_target_id"),
        (spec.candidate_record_count, "candidate_record_count"),
    ):
        _natural(value, context)
    if spec.candidate_record_count == 0:
        raise ConstructiveSourceInventoryGenerationError(
            "candidate_record_count must be positive"
        )
    if len(set(spec.expected_target_ids)) != len(spec.expected_target_ids):
        raise ConstructiveSourceInventoryGenerationError(
            "expected_target_ids contains duplicates"
        )
    for target_id in spec.expected_target_ids:
        _natural(target_id, "expected target ID")
    if set(spec.expected_operations) - set(_OPERATIONS):
        raise ConstructiveSourceInventoryGenerationError(
            "expected_operations contains an unsupported operation"
        )
    if len(set(spec.expected_operations)) != len(spec.expected_operations):
        raise ConstructiveSourceInventoryGenerationError(
            "expected_operations contains duplicates"
        )
    _validate_sources(spec)
    _validate_entries(spec)
    _validate_rules(spec)


def _validate_sources(spec: ConstructiveSourceInventorySpec) -> None:
    names: set[str] = set()
    target_ids: set[int] = set()
    source_rvas: set[int] = set()
    record_indices: set[int] = set()
    source_terms: set[str] = set()
    for index, source in enumerate(spec.sources):
        if _IDENTIFIER.fullmatch(source.name) is None:
            raise ConstructiveSourceInventoryGenerationError(
                f"sources[{index}].name is malformed"
            )
        for term in (
            source.source_term,
            source.target_id_exact,
            source.source_rva_exact,
            source.record_at_index_exact,
        ):
            _checked_term(term, f"sources[{index}] proof term")
        for value, context in (
            (source.target_id, "target ID"),
            (source.source_rva, "source RVA"),
            (source.record_index, "record index"),
        ):
            _natural(value, f"sources[{index}] {context}")
        if source.record_index >= spec.candidate_record_count:
            raise ConstructiveSourceInventoryGenerationError(
                f"sources[{index}] record index is outside the candidate table"
            )
        _claim_unique(names, source.name, "duplicate exact source name")
        _claim_unique(target_ids, source.target_id, "duplicate exact source target ID")
        _claim_unique(source_rvas, source.source_rva, "duplicate exact source RVA")
        _claim_unique(
            record_indices,
            source.record_index,
            "duplicate candidate record association",
        )
        _claim_unique(source_terms, source.source_term, "duplicate exact source term")
    if target_ids != set(spec.expected_target_ids):
        missing = sorted(set(spec.expected_target_ids) - target_ids)
        extra = sorted(target_ids - set(spec.expected_target_ids))
        raise ConstructiveSourceInventoryGenerationError(
            f"exact source target coverage mismatch; missing={missing}, extra={extra}"
        )


def _validate_entries(spec: ConstructiveSourceInventorySpec) -> None:
    names: set[str] = set()
    operations: set[str] = set()
    entry_rvas: set[int] = set()
    for index, entry in enumerate(spec.entries):
        if _IDENTIFIER.fullmatch(entry.name) is None:
            raise ConstructiveSourceInventoryGenerationError(
                f"entries[{index}].name is malformed"
            )
        if entry.operation not in _OPERATIONS:
            raise ConstructiveSourceInventoryGenerationError(
                f"entries[{index}].operation is unsupported"
            )
        _natural(entry.entry_rva, f"entries[{index}] entry RVA")
        _checked_term(
            entry.function_entry_exact,
            f"entries[{index}] function-entry proof",
        )
        _claim_unique(names, entry.name, "duplicate candidate entry name")
        _claim_unique(
            operations, entry.operation, "duplicate candidate operation entry"
        )
        _claim_unique(entry_rvas, entry.entry_rva, "duplicate candidate entry RVA")
    if operations != set(spec.expected_operations):
        missing = sorted(set(spec.expected_operations) - operations)
        extra = sorted(operations - set(spec.expected_operations))
        raise ConstructiveSourceInventoryGenerationError(
            f"candidate operation entry coverage mismatch; "
            f"missing={missing}, extra={extra}"
        )


def _validate_rules(spec: ConstructiveSourceInventorySpec) -> None:
    source_by_name = {source.name: source for source in spec.sources}
    entry_by_name = {entry.name: entry for entry in spec.entries}
    seen_rows: set[ConstructiveSourceRuleBinding] = set()
    uses_by_source: dict[str, int] = {name: 0 for name in source_by_name}
    used_entries: set[str] = set()
    runtime_keys: set[tuple[int, int]] = set()
    launch_count = 0
    for index, rule in enumerate(spec.rules):
        if rule in seen_rows:
            raise ConstructiveSourceInventoryGenerationError(
                "duplicate constructive source rule"
            )
        seen_rows.add(rule)
        if rule.source not in source_by_name:
            raise ConstructiveSourceInventoryGenerationError(
                f"rules[{index}] references an unknown exact source"
            )
        if rule.kind not in _RULE_KINDS:
            raise ConstructiveSourceInventoryGenerationError(
                f"rules[{index}].kind is unsupported"
            )
        uses_by_source[rule.source] += 1
        source = source_by_name[rule.source]
        if rule.kind == "launch":
            launch_count += 1
            if rule.entry is not None or rule.candidate_rva is not None:
                raise ConstructiveSourceInventoryGenerationError(
                    "launch rule cannot carry an operation entry or candidate RVA"
                )
            if source.target_id != spec.launch_root_target_id:
                raise ConstructiveSourceInventoryGenerationError(
                    "launch rule source is not the declared launch root"
                )
        elif rule.kind in {"semantic_transfer", "external_operation"}:
            if rule.entry not in entry_by_name or rule.candidate_rva is not None:
                raise ConstructiveSourceInventoryGenerationError(
                    f"{rule.kind} rule requires exactly one checked entry"
                )
            used_entries.add(rule.entry)
        else:
            if rule.entry not in entry_by_name or rule.candidate_rva is None:
                raise ConstructiveSourceInventoryGenerationError(
                    "external_boundary rule requires an owner entry and candidate RVA"
                )
            _natural(rule.candidate_rva, "external boundary candidate RVA")
            used_entries.add(rule.entry)
        runtime_key = (
            source.target_id,
            _rule_candidate_rva(rule, entry_by_name, spec.candidate_root_rva),
        )
        if runtime_key in runtime_keys:
            raise ConstructiveSourceInventoryGenerationError(
                "ambiguous runtime source classification"
            )
        runtime_keys.add(runtime_key)
    missing = sorted(name for name, count in uses_by_source.items() if count == 0)
    ambiguous = sorted(name for name, count in uses_by_source.items() if count > 1)
    if missing or ambiguous:
        raise ConstructiveSourceInventoryGenerationError(
            f"source rule coverage is incomplete or ambiguous; "
            f"missing={missing}, ambiguous={ambiguous}"
        )
    if launch_count != 1:
        raise ConstructiveSourceInventoryGenerationError(
            "constructive source inventory requires exactly one launch rule"
        )
    unused_entries = sorted(set(entry_by_name) - used_entries)
    if unused_entries:
        raise ConstructiveSourceInventoryGenerationError(
            f"candidate operation entries are not referenced: {unused_entries}"
        )


def _source_definition(
    source: ExactSemanticSourceBinding,
    parameter: str,
    type_arguments: str,
    terms: ConstructiveClassifierTerms,
) -> str:
    local = _lean_name(source.name)
    return f"""def generatedSource{local} :
    ExactOriginalSemanticSource {type_arguments} :=
  {source.source_term}

theorem generatedSource{local}TargetIdExact :
    (generatedSource{local} {parameter}).targetId = {source.target_id} := by
  simpa [generatedSource{local}] using {source.target_id_exact}

theorem generatedSource{local}RvaExact :
    (generatedSource{local} {parameter}).source.target.rva =
      {source.source_rva} := by
  simpa [generatedSource{local}] using {source.source_rva_exact}

theorem generatedSource{local}RecordAtIndexExact :
    {terms.candidate_authority}.semanticRecords[{source.record_index}]? =
      some (generatedSource{local} {parameter}).record := by
  simpa [generatedSource{local}] using {source.record_at_index_exact}

theorem generatedSource{local}RecordSourceRvaExact :
    (generatedSource{local} {parameter}).record.sourceRva =
      {source.source_rva} := by
  calc
    (generatedSource{local} {parameter}).record.sourceRva =
        (generatedSource{local} {parameter}).source.target.rva :=
      (generatedSource{local} {parameter}).recordSourceExact
    _ = {source.source_rva} :=
      generatedSource{local}RvaExact {parameter}"""


def _entry_definition(
    entry: CheckedKernelEntryBinding,
    parameter: str,
    terms: ConstructiveClassifierTerms,
) -> str:
    local = _lean_name(entry.name)
    operation = _OPERATIONS[entry.operation]
    return f"""def generatedEntry{local} :
    ExactCandidateKernelEntry {terms.compiled_program} := {{
  operation := {operation}
  entryRva := {entry.entry_rva}
  entryExact := {entry.function_entry_exact}
}}"""


def _rule_definition(
    rule: ConstructiveSourceRuleBinding,
    index: int,
    parameter: str,
    source_by_name: dict[str, ExactSemanticSourceBinding],
    entry_by_name: dict[str, CheckedKernelEntryBinding],
    launch_profile: str,
) -> str:
    source_name = _lean_name(source_by_name[rule.source].name)
    source = f"generatedSource{source_name} {parameter}"
    if rule.kind == "launch":
        root_proof = f"generatedLaunchSourceRootExact{index:04d}"
        return f"""theorem {root_proof} :
    ({source}).targetId = {launch_profile}.rootTargetId := by
  exact (generatedSource{source_name}TargetIdExact {parameter}).trans
    (generatedLaunchRootTargetIdExact {parameter}).symm

def generatedRule{index:04d} :
    GeneratedConstructiveSourceRule {parameter} :=
  .launch ({source}) ({root_proof} {parameter})"""
    assert rule.entry is not None
    entry_name = _lean_name(entry_by_name[rule.entry].name)
    entry = f"generatedEntry{entry_name} {parameter}"
    constructor = {
        "semantic_transfer": "semanticTransfer",
        "external_operation": "externalOperation",
        "external_boundary": "externalBoundary",
    }[rule.kind]
    suffix = f" {rule.candidate_rva}" if rule.kind == "external_boundary" else ""
    return f"""def generatedRule{index:04d} :
    GeneratedConstructiveSourceRule {parameter} :=
  .{constructor} ({source}) ({entry}){suffix}"""


def _classifier_type_arguments(terms: ConstructiveClassifierTerms) -> str:
    return " ".join(
        (
            terms.original_context,
            terms.original_authority,
            terms.launch_profile,
            terms.original_root,
            terms.reachability,
            terms.candidate,
            terms.candidate_authority,
            terms.compiled_program,
            terms.candidate_root_rva,
        )
    )


def _source_type_arguments(terms: ConstructiveClassifierTerms) -> str:
    return " ".join(
        (
            terms.original_context,
            terms.original_authority,
            terms.launch_profile,
            terms.original_root,
            terms.reachability,
            terms.candidate,
            terms.candidate_authority,
        )
    )


def _rule_candidate_rva(
    rule: ConstructiveSourceRuleBinding,
    entry_by_name: dict[str, CheckedKernelEntryBinding],
    candidate_root_rva: int,
) -> int:
    if rule.kind == "launch":
        return candidate_root_rva
    if rule.kind == "external_boundary":
        assert rule.candidate_rva is not None
        return rule.candidate_rva
    assert rule.entry is not None
    return entry_by_name[rule.entry].entry_rva


def _lean_name(value: str) -> str:
    return value[0].upper() + value[1:]


def _checked_term(value: str, context: str) -> None:
    if _QUALIFIED.fullmatch(value) is None:
        raise ConstructiveSourceInventoryGenerationError(
            f"{context} must be a canonical Lean identifier"
        )


def _natural(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConstructiveSourceInventoryGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _claim_unique(values: set[object], value: object, message: str) -> None:
    if value in values:
        raise ConstructiveSourceInventoryGenerationError(message)
    values.add(value)
