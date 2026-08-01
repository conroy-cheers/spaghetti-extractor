"""Assemble GNU hello's checked one-sided source execution evidence.

This module is deliberately an assembler, not an analyser.  The three
existing original-side authority reports identify the 31 reachable indirect
control frontiers and their Lean-checked static authorities.  A separate
evidence manifest must name one combined, exact-transition invariant, its
finite-reachability projection, its full checked-launch root proof, and the
31 frontier projections.  Only then can this generator construct a
``CheckedOriginalInvariantFamilyEvidence`` and root its domain at every
``CheckedNativeSourcePE32ConsoleLaunch``.  A program-entry-only proof or 31
independently rooted invariants are not accepted as substitutes.

Report status values never authorize output.  Every proof input is a
canonical Lean declaration, and the generated module is useful only after
Lean elaboration and the detached axiom audit succeed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ...errors import StageAInputError


GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-source-execution-evidence-v2"
)
GNU_HELLO_SOURCE_EXECUTION_MODULE = "GeneratedGnuHelloSourceExecution"
GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE = (
    "GeneratedGnuHelloSourceExecutionAudit"
)

_MIXED_ORIGINAL_FORMAT = "stage-a-interpreter-mixed-original-v1"
_WRITABLE_FORMAT = (
    "stage-a-relocated-writable-static-pointer-slot-authorities-v2"
)
_REGISTER_FORMAT = "stage-a-register-indirect-control-authorities-v1"
_STACK_DYNAMIC_FORMAT = "stage-a-original-stack-dynamic-control-closure-v1"

_EXPECTED_COUNTS = {
    "writable_static_slot": 19,
    "register_target": 9,
    "stack_dynamic": 3,
}

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_NAME_PARTS = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "else",
        "end",
        "import",
        "in",
        "inductive",
        "instance",
        "let",
        "match",
        "namespace",
        "native_decide",
        "opaque",
        "partial",
        "protected",
        "sorry",
        "structure",
        "theorem",
        "then",
        "unsafe",
        "variable",
        "where",
        "with",
    }
)

FrontierCategory = Literal[
    "writable_static_slot", "register_target", "stack_dynamic"
]


class GnuHelloSourceExecutionGenerationError(StageAInputError):
    """The GNU hello one-sided evidence package is incomplete or inconsistent."""


@dataclass(frozen=True)
class LeanFactRef:
    """One exact declaration exported by one named Lean module."""

    module: str
    namespace: str
    symbol: str

    @property
    def declaration(self) -> str:
        return f"{self.namespace}.{self.symbol}"

    def validate(self, label: str) -> None:
        if _STAGE_A_MODULE.fullmatch(self.module) is None:
            raise GnuHelloSourceExecutionGenerationError(
                f"{label}.module must be a canonical StageA module"
            )
        _validate_identifier(self.namespace, f"{label}.namespace")
        _validate_local_name(self.symbol, f"{label}.symbol")
        if not self.namespace.startswith("StageA."):
            raise GnuHelloSourceExecutionGenerationError(
                f"{label}.namespace must be below StageA"
            )

    @classmethod
    def from_json(cls, value: object, label: str) -> "LeanFactRef":
        row = _object(value, label)
        if set(row) != {"module", "namespace", "symbol"}:
            raise GnuHelloSourceExecutionGenerationError(
                f"{label} must contain exactly module, namespace, and symbol"
            )
        fact = cls(
            module=_string(row["module"], f"{label}.module"),
            namespace=_string(row["namespace"], f"{label}.namespace"),
            symbol=_string(row["symbol"], f"{label}.symbol"),
        )
        fact.validate(label)
        return fact

    def to_json(self) -> dict[str, str]:
        return {
            "module": self.module,
            "namespace": self.namespace,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class FrontierExecutionFact:
    """One exact static authority and its combined-invariant projections."""

    category: FrontierCategory
    source_rva: int
    source_target_id: int
    static_authority: LeanFactRef
    target_membership: LeanFactRef
    running_target_membership: LeanFactRef
    callback_target_membership: LeanFactRef

    def validate(self, label: str) -> None:
        if self.category not in _EXPECTED_COUNTS:
            raise GnuHelloSourceExecutionGenerationError(
                f"{label}.category is unsupported"
            )
        _natural(self.source_rva, f"{label}.source_rva", word=True)
        _natural(self.source_target_id, f"{label}.source_target_id")
        for name in (
            "static_authority",
            "target_membership",
            "running_target_membership",
            "callback_target_membership",
        ):
            getattr(self, name).validate(f"{label}.{name}")


@dataclass(frozen=True)
class GnuHelloSourceExecutionSpec:
    """Exact declarations needed to assemble the GNU one-sided domain."""

    project: LeanFactRef
    combined_invariant: LeanFactRef
    target_ids: LeanFactRef
    target_ids_unique: LeanFactRef
    reachability_projection: LeanFactRef
    target_round_trips: LeanFactRef
    invariant_at_launch: LeanFactRef
    exact_binding: LeanFactRef
    instruction_semantics_adequate: LeanFactRef
    program_record_kernel_matches: LeanFactRef
    launch_realizable: LeanFactRef
    frontiers: tuple[FrontierExecutionFact, ...]
    input_hashes: tuple[tuple[str, str], ...]
    namespace: str = "StageA.GeneratedRelational.GnuHelloSourceExecution"
    output_module: str = GNU_HELLO_SOURCE_EXECUTION_MODULE
    audit_module: str = GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE

    def validate(self) -> None:
        for name in (
            "project",
            "combined_invariant",
            "target_ids",
            "target_ids_unique",
            "reachability_projection",
            "target_round_trips",
            "invariant_at_launch",
            "exact_binding",
            "instruction_semantics_adequate",
            "program_record_kernel_matches",
            "launch_realizable",
        ):
            getattr(self, name).validate(name)
        _validate_identifier(self.namespace, "namespace")
        _validate_local_name(self.output_module, "output_module")
        _validate_local_name(self.audit_module, "audit_module")
        if self.output_module == self.audit_module:
            raise GnuHelloSourceExecutionGenerationError(
                "output_module and audit_module must be distinct"
            )
        if len(self.frontiers) != 31:
            raise GnuHelloSourceExecutionGenerationError(
                f"exactly 31 frontier facts are required, got {len(self.frontiers)}"
            )
        keys = [(frontier.category, frontier.source_rva) for frontier in self.frontiers]
        if keys != sorted(keys):
            raise GnuHelloSourceExecutionGenerationError(
                "frontier facts must be in deterministic category/RVA order"
            )
        if len(set(keys)) != len(keys):
            raise GnuHelloSourceExecutionGenerationError(
                "frontier facts must not contain duplicate category/RVA keys"
            )
        counts = {
            category: sum(frontier.category == category for frontier in self.frontiers)
            for category in _EXPECTED_COUNTS
        }
        if counts != _EXPECTED_COUNTS:
            raise GnuHelloSourceExecutionGenerationError(
                f"frontier family counts must be {_EXPECTED_COUNTS}, got {counts}"
            )
        for index, frontier in enumerate(self.frontiers):
            frontier.validate(f"frontiers[{index}]")
        hash_names = [name for name, _digest in self.input_hashes]
        if hash_names != sorted(hash_names) or len(set(hash_names)) != len(hash_names):
            raise GnuHelloSourceExecutionGenerationError(
                "input_hashes must have unique names in deterministic order"
            )
        for name, digest in self.input_hashes:
            _validate_local_name(name, "input hash name")
            if _SHA256.fullmatch(digest) is None:
                raise GnuHelloSourceExecutionGenerationError(
                    f"input hash {name} is not lowercase SHA-256"
                )


@dataclass(frozen=True)
class GnuHelloSourceExecutionModules:
    proof: Path
    audit: Path
    manifest: Path


@dataclass(frozen=True)
class GnuHelloSourceExecutionAssemblyResult:
    """Result of fail-closed artifact assembly, including incomplete reports."""

    launch_family_complete: bool
    manifest: Path
    proof: Path | None = None
    audit: Path | None = None


def assemble_gnu_hello_source_execution_spec(
    mixed_original_plan: Path | str,
    writable_authority_report: Path | str,
    register_authority_report: Path | str,
    stack_dynamic_authority_report: Path | str,
    evidence_manifest: Path | str,
) -> GnuHelloSourceExecutionSpec:
    """Validate exact artifact bindings and return a complete proof spec."""

    paths = {
        "mixed_original_plan": Path(mixed_original_plan),
        "writable_authority_report": Path(writable_authority_report),
        "register_authority_report": Path(register_authority_report),
        "stack_dynamic_authority_report": Path(stack_dynamic_authority_report),
        "evidence_manifest": Path(evidence_manifest),
    }
    documents = {name: _read_json(path, name) for name, path in paths.items()}
    hashes = {name: _sha256(path) for name, path in paths.items()}

    plan = documents["mixed_original_plan"]
    writable = documents["writable_authority_report"]
    register = documents["register_authority_report"]
    stack = documents["stack_dynamic_authority_report"]
    manifest = documents["evidence_manifest"]

    _require_format(plan, _MIXED_ORIGINAL_FORMAT, "mixed original plan")
    _require_format(writable, _WRITABLE_FORMAT, "writable authority report")
    _require_format(register, _REGISTER_FORMAT, "register authority report")
    _require_format(stack, _STACK_DYNAMIC_FORMAT, "stack/dynamic authority report")
    _require_format(
        manifest,
        GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT,
        "source execution evidence manifest",
    )

    expected_frontiers = _frontiers_from_plan(plan)
    authorities = {
        **_writable_authorities(writable),
        **_register_authorities(register),
        **_stack_dynamic_authorities(stack),
    }
    if set(authorities) != expected_frontiers:
        missing = sorted(expected_frontiers - set(authorities))
        extra = sorted(set(authorities) - expected_frontiers)
        raise GnuHelloSourceExecutionGenerationError(
            "the 31-frontier static authority inventory is not exact; "
            f"missing={_render_keys(missing)}, extra={_render_keys(extra)}"
        )

    artifact_hashes = {
        name: digest for name, digest in hashes.items()
        if name != "evidence_manifest"
    }
    _check_artifact_bindings(plan, writable, register, stack, artifact_hashes)
    _check_manifest_bindings(manifest, artifact_hashes)

    top = _object(manifest.get("facts"), "evidence manifest facts")
    required_top = {
        "project",
        "combined_invariant",
        "target_ids",
        "target_ids_unique",
        "reachability_projection",
        "target_round_trips",
        "invariant_at_launch",
        "exact_binding",
        "instruction_semantics_adequate",
        "program_record_kernel_matches",
        "launch_realizable",
    }
    if set(top) != required_top:
        raise GnuHelloSourceExecutionGenerationError(
            "evidence manifest facts must contain exactly "
            + ", ".join(sorted(required_top))
        )

    evidence_rows = _list(manifest.get("frontiers"), "evidence manifest frontiers")
    evidence: dict[tuple[FrontierCategory, int], FrontierExecutionFact] = {}
    for index, value in enumerate(evidence_rows):
        row = _object(value, f"frontiers[{index}]")
        required = {
            "category",
            "source_rva",
            "source_target_id",
            "static_authority",
            "target_membership",
            "running_target_membership",
            "callback_target_membership",
        }
        if set(row) != required:
            raise GnuHelloSourceExecutionGenerationError(
                f"frontiers[{index}] must contain exactly " + ", ".join(sorted(required))
            )
        category = _category(row["category"], f"frontiers[{index}].category")
        source_rva = _natural(row["source_rva"], f"frontiers[{index}].source_rva", word=True)
        source_target_id = _natural(
            row["source_target_id"], f"frontiers[{index}].source_target_id"
        )
        key = (category, source_rva)
        if key in evidence:
            raise GnuHelloSourceExecutionGenerationError(
                f"duplicate one-sided evidence for {_render_key(key)}"
            )
        if key not in authorities:
            raise GnuHelloSourceExecutionGenerationError(
                f"one-sided evidence names unknown frontier {_render_key(key)}"
            )
        expected_target_id, expected_static = authorities[key]
        static = LeanFactRef.from_json(
            row["static_authority"], f"frontiers[{index}].static_authority"
        )
        if source_target_id != expected_target_id:
            raise GnuHelloSourceExecutionGenerationError(
                f"{_render_key(key)} source target id must be {expected_target_id}, "
                f"got {source_target_id}"
            )
        if static != expected_static:
            raise GnuHelloSourceExecutionGenerationError(
                f"{_render_key(key)} static authority must be "
                f"{expected_static.declaration} from {expected_static.module}"
            )
        fact = FrontierExecutionFact(
            category=category,
            source_rva=source_rva,
            source_target_id=source_target_id,
            static_authority=static,
            target_membership=LeanFactRef.from_json(
                row["target_membership"], f"frontiers[{index}].target_membership"
            ),
            running_target_membership=LeanFactRef.from_json(
                row["running_target_membership"],
                f"frontiers[{index}].running_target_membership",
            ),
            callback_target_membership=LeanFactRef.from_json(
                row["callback_target_membership"],
                f"frontiers[{index}].callback_target_membership",
            ),
        )
        fact.validate(f"frontiers[{index}]")
        evidence[key] = fact

    missing_evidence = sorted(expected_frontiers - set(evidence))
    if missing_evidence:
        rendered = ", ".join(_render_key(key) for key in missing_evidence)
        raise GnuHelloSourceExecutionGenerationError(
            "missing combined-invariant running/callback frontier projections "
            f"for: {rendered}"
        )
    if len(evidence) != 31:
        raise GnuHelloSourceExecutionGenerationError(
            f"expected 31 exact one-sided frontier facts, got {len(evidence)}"
        )

    spec = GnuHelloSourceExecutionSpec(
        project=LeanFactRef.from_json(top["project"], "facts.project"),
        combined_invariant=LeanFactRef.from_json(
            top["combined_invariant"], "facts.combined_invariant"
        ),
        target_ids=LeanFactRef.from_json(top["target_ids"], "facts.target_ids"),
        target_ids_unique=LeanFactRef.from_json(
            top["target_ids_unique"], "facts.target_ids_unique"
        ),
        reachability_projection=LeanFactRef.from_json(
            top["reachability_projection"], "facts.reachability_projection"
        ),
        target_round_trips=LeanFactRef.from_json(
            top["target_round_trips"], "facts.target_round_trips"
        ),
        invariant_at_launch=LeanFactRef.from_json(
            top["invariant_at_launch"], "facts.invariant_at_launch"
        ),
        exact_binding=LeanFactRef.from_json(
            top["exact_binding"], "facts.exact_binding"
        ),
        instruction_semantics_adequate=LeanFactRef.from_json(
            top["instruction_semantics_adequate"],
            "facts.instruction_semantics_adequate",
        ),
        program_record_kernel_matches=LeanFactRef.from_json(
            top["program_record_kernel_matches"],
            "facts.program_record_kernel_matches",
        ),
        launch_realizable=LeanFactRef.from_json(
            top["launch_realizable"], "facts.launch_realizable"
        ),
        frontiers=tuple(evidence[key] for key in sorted(evidence)),
        input_hashes=tuple(sorted(hashes.items())),
    )
    spec.validate()
    return spec


def gnu_hello_source_execution_source(spec: GnuHelloSourceExecutionSpec) -> str:
    """Emit exact one-sided evidence assembly and downstream projections."""

    spec.validate()
    facts = (
        spec.project,
        spec.combined_invariant,
        spec.target_ids,
        spec.target_ids_unique,
        spec.reachability_projection,
        spec.target_round_trips,
        spec.invariant_at_launch,
        spec.exact_binding,
        spec.instruction_semantics_adequate,
        spec.program_record_kernel_matches,
        spec.launch_realizable,
        *(fact for frontier in spec.frontiers for fact in (
            frontier.static_authority,
            frontier.target_membership,
            frontier.running_target_membership,
            frontier.callback_target_membership,
        )),
    )
    modules = sorted({fact.module for fact in facts})
    imports = "\n".join(
        [
            *(f"import {module}" for module in modules),
            "import StageA.RelationalNativeSource",
            "import StageA.RelationalSourceExecutionDomain",
        ]
    )
    frontier_definitions = "\n\n".join(
        _frontier_definitions(index, frontier)
        for index, frontier in enumerate(spec.frontiers)
    )
    frontier_projections = "\n\n".join(
        _frontier_projections(index, frontier)
        for index, frontier in enumerate(spec.frontiers)
    )
    hashes = "\n".join(
        f'def generatedInputSha256_{name} : String := "{digest}"'
        for name, digest in spec.input_hashes
    )
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.NativeSource

noncomputable section

{hashes}

abbrev generatedNativeSourceProject : NativeSourceProject :=
  {spec.project.declaration}

abbrev generatedOriginalProgram : DecodedWorldProgram :=
  generatedNativeSourceProject.program.worldProgram

abbrev generatedOriginalInvariant :
    OriginalWorldExecutionInvariant generatedOriginalProgram :=
  {spec.combined_invariant.declaration}

def generatedReachableTargetIds : List Nat :=
  {spec.target_ids.declaration}

def generatedOriginalInvariantFamilyEvidence :
    CheckedOriginalInvariantFamilyEvidence generatedOriginalProgram := {{
  invariant := generatedOriginalInvariant
  targetIds := generatedReachableTargetIds
  targetIdsUnique := {spec.target_ids_unique.declaration}
  reachabilityProjection := {spec.reachability_projection.declaration}
  targetRoundTrips := {spec.target_round_trips.declaration}
}}

theorem generatedOriginalInvariantAtLaunch
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    generatedOriginalInvariant.holds sourceRoot.toWorldExecution :=
  {spec.invariant_at_launch.declaration} sourceRoot launch

{frontier_definitions}

{frontier_projections}

def generatedOriginalInvariantDomainCertificateAt
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    OriginalInvariantDomainCertificate generatedOriginalProgram
      sourceRoot.toWorldExecution :=
  generatedOriginalInvariantFamilyEvidence.domainCertificateAtLaunch
    sourceRoot.toWorldExecution
    (generatedOriginalInvariantAtLaunch sourceRoot launch)

def generatedSourceExecutionDomainAt
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    CheckedExecutionDomain generatedOriginalProgram
      sourceRoot.toWorldExecution :=
  generatedOriginalInvariantFamilyEvidence.domainAtLaunch
    sourceRoot.toWorldExecution
    (generatedOriginalInvariantAtLaunch sourceRoot launch)

theorem generatedDecodedSemanticStepsAdmissibleAt
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    DecodedSemanticStepsAdmissible generatedOriginalProgram
      (generatedSourceExecutionDomainAt sourceRoot launch) :=
  (generatedOriginalInvariantDomainCertificateAt sourceRoot launch).decodedSemanticStepsAdmissible
    {spec.instruction_semantics_adequate.declaration}

theorem generatedRawEipSuccessorConcretizableAt
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    forall logical raw,
      (generatedSourceExecutionDomainAt sourceRoot launch).holds logical ->
      logical.ConcretizesToRawEip generatedOriginalProgram raw ->
      exists rawNext,
        (generatedOriginalProgram.pe32TransitionSystem.step logical).next.ConcretizesToRawEip
          generatedOriginalProgram rawNext :=
  (generatedOriginalInvariantDomainCertificateAt sourceRoot launch).rawEipSuccessorConcretizable

def generatedCheckedNativeSourceProjectAt
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    CheckedNativeSourceProject generatedNativeSourceProject
      sourceRoot.toWorldExecution
      (generatedSourceExecutionDomainAt sourceRoot launch) := {{
  exactBinding := {spec.exact_binding.declaration}
  instructionSemanticsAdequate :=
    {spec.instruction_semantics_adequate.declaration}
  decodedSemanticStepsAdmissible :=
    generatedDecodedSemanticStepsAdmissibleAt sourceRoot launch
  programRecordKernelMatchesDecodedSemantics :=
    {spec.program_record_kernel_matches.declaration}
      sourceRoot.toWorldExecution
      (generatedSourceExecutionDomainAt sourceRoot launch)
  rawEipLeftStepClosed :=
    generatedRawEipSuccessorConcretizableAt sourceRoot launch
}}

def generatedCheckedNativeSourceLaunchAt
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    CheckedNativeSourceLaunch generatedNativeSourceProject sourceRoot := {{
  domain := generatedSourceExecutionDomainAt sourceRoot launch
  checkedProject := generatedCheckedNativeSourceProjectAt sourceRoot launch
}}

def generatedCheckedNativeSourceLaunchFamily :
    CheckedNativeSourceLaunchFamily generatedNativeSourceProject := {{
  realizable := {spec.launch_realizable.declaration}
  source := fun sourceRoot sourceLaunch =>
    Nonempty.intro
      (generatedCheckedNativeSourceLaunchAt sourceRoot sourceLaunch)
}}

end
end {spec.namespace}
"""


def gnu_hello_source_execution_audit_source(
    spec: GnuHelloSourceExecutionSpec,
) -> str:
    """Emit a detached audit for all one-sided acceptance-facing outputs."""

    spec.validate()
    prefix = spec.namespace
    audits = [
        f"#print axioms {prefix}.generatedOriginalInvariantFamilyEvidence",
        f"#print axioms {prefix}.generatedOriginalInvariantAtLaunch",
        f"#print axioms {prefix}.generatedOriginalInvariantDomainCertificateAt",
        f"#print axioms {prefix}.generatedDecodedSemanticStepsAdmissibleAt",
        f"#print axioms {prefix}.generatedRawEipSuccessorConcretizableAt",
        f"#print axioms {prefix}.generatedCheckedNativeSourceLaunchFamily",
    ]
    for index in range(len(spec.frontiers)):
        audits.extend(
            [
                f"#print axioms {prefix}.generatedFrontier{index:04d}RunningTargetMembership",
                f"#print axioms {prefix}.generatedFrontier{index:04d}CallbackTargetMembership",
            ]
        )
    return f"""import StageA.{spec.output_module}

{chr(10).join(audits)}
"""


def write_gnu_hello_source_execution(
    out: Path | str, spec: GnuHelloSourceExecutionSpec
) -> GnuHelloSourceExecutionModules:
    """Write proof, audit, and provenance manifest deterministically."""

    spec.validate()
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    proof = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_module}.lean"
    manifest = root / "gnu-hello-source-execution-assembly.json"
    proof.write_text(gnu_hello_source_execution_source(spec), encoding="ascii")
    audit.write_text(
        gnu_hello_source_execution_audit_source(spec), encoding="ascii"
    )
    manifest.write_text(
        json.dumps(_assembly_manifest(spec), indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    return GnuHelloSourceExecutionModules(
        proof=proof, audit=audit, manifest=manifest
    )


def write_gnu_hello_source_execution_from_artifacts(
    out: Path | str,
    mixed_original_plan: Path | str,
    writable_authority_report: Path | str,
    register_authority_report: Path | str,
    stack_dynamic_authority_report: Path | str,
    evidence_manifest: Path | str,
) -> GnuHelloSourceExecutionAssemblyResult:
    """Assemble when complete, or emit a non-authorizing incomplete report."""

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    report = root / "gnu-hello-source-execution-assembly.json"
    try:
        spec = assemble_gnu_hello_source_execution_spec(
            mixed_original_plan,
            writable_authority_report,
            register_authority_report,
            stack_dynamic_authority_report,
            evidence_manifest,
        )
    except GnuHelloSourceExecutionGenerationError as error:
        report.write_text(
            json.dumps(
                {
                    "format": "stage-a-gnu-hello-source-execution-assembly-v2",
                    "launch_scope": "all_checked_pe32_console_launches",
                    "launch_family_complete": False,
                    "acceptance_authority": False,
                    "blockers": [
                        {
                            "reason_code": "source_launch_family_incomplete",
                            "detail": str(error),
                        }
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        return GnuHelloSourceExecutionAssemblyResult(
            launch_family_complete=False, manifest=report
        )
    modules = write_gnu_hello_source_execution(root, spec)
    return GnuHelloSourceExecutionAssemblyResult(
        launch_family_complete=True,
        manifest=modules.manifest,
        proof=modules.proof,
        audit=modules.audit,
    )


def _frontier_definitions(index: int, frontier: FrontierExecutionFact) -> str:
    prefix = f"generatedFrontier{index:04d}"
    return f"""def {prefix}SourceRva : Nat := {frontier.source_rva}

def {prefix}SourceTargetId : Nat := {frontier.source_target_id}

def {prefix}StaticAuthority :=
  {frontier.static_authority.declaration}

def {prefix}TargetMembership :
    RelationalWorld -> StageA.Formal.MachineState -> Prop :=
  {frontier.target_membership.declaration}"""


def _frontier_projections(index: int, frontier: FrontierExecutionFact) -> str:
    prefix = f"generatedFrontier{index:04d}"
    return f"""theorem {prefix}RunningTargetMembership
    {{state : StageA.Formal.MachineState}} {{calls : List Nat}}
    {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    (member : generatedOriginalInvariant.holds
      (.running {prefix}SourceTargetId state calls eventIndex world)) :
    {prefix}TargetMembership world state := by
  exact {frontier.running_target_membership.declaration} member

theorem {prefix}CallbackTargetMembership
    {{state : StageA.Formal.MachineState}} {{calls : List Nat}}
    {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    {{callbacks : List WorldExternalCallbackRuntime}}
    (member : generatedOriginalInvariant.holds
      (.callbackRunning {prefix}SourceTargetId state calls eventIndex world
        callbacks)) :
    {prefix}TargetMembership world state := by
  exact {frontier.callback_target_membership.declaration} member"""


def _frontiers_from_plan(
    plan: dict[str, Any],
) -> set[tuple[FrontierCategory, int]]:
    blockers = _list(plan.get("blockers"), "mixed original plan blockers")
    result: set[tuple[FrontierCategory, int]] = set()
    for index, value in enumerate(blockers):
        blocker = _object(value, f"blockers[{index}]")
        if blocker.get("reason_code") != "unresolved_indirect_control":
            raise GnuHelloSourceExecutionGenerationError(
                f"blockers[{index}] is not unresolved indirect control"
            )
        rva = _natural(blocker.get("rva"), f"blockers[{index}].rva", word=True)
        detail = _string(blocker.get("detail"), f"blockers[{index}].detail")
        if detail.startswith("static_pointer_slot at "):
            category: FrontierCategory = "writable_static_slot"
        elif detail.startswith(("register_function_pointer at ", "register_tail_target at ")):
            category = "register_target"
        elif detail.startswith("stack_or_dynamic_pointer at "):
            category = "stack_dynamic"
        else:
            raise GnuHelloSourceExecutionGenerationError(
                f"blockers[{index}] has an unsupported frontier category"
            )
        key = (category, rva)
        if key in result:
            raise GnuHelloSourceExecutionGenerationError(
                f"mixed original plan repeats {_render_key(key)}"
            )
        result.add(key)
    counts = {
        category: sum(key[0] == category for key in result)
        for category in _EXPECTED_COUNTS
    }
    if counts != _EXPECTED_COUNTS:
        raise GnuHelloSourceExecutionGenerationError(
            f"mixed original plan must expose {_EXPECTED_COUNTS}, got {counts}"
        )
    return result


def _writable_authorities(
    report: dict[str, Any],
) -> dict[tuple[FrontierCategory, int], tuple[int, LeanFactRef]]:
    return _reported_authorities(
        report,
        category="writable_static_slot",
        expected_count=19,
        label="writable authority report",
    )


def _register_authorities(
    report: dict[str, Any],
) -> dict[tuple[FrontierCategory, int], tuple[int, LeanFactRef]]:
    blockers = _list(report.get("blockers"), "register authority blockers")
    if blockers:
        raise GnuHelloSourceExecutionGenerationError(
            "register authority report retains unresolved register blockers"
        )
    return _reported_authorities(
        report,
        category="register_target",
        expected_count=9,
        label="register authority report",
    )


def _reported_authorities(
    report: dict[str, Any],
    *,
    category: FrontierCategory,
    expected_count: int,
    label: str,
) -> dict[tuple[FrontierCategory, int], tuple[int, LeanFactRef]]:
    rows = _list(report.get("sites"), f"{label} sites")
    if len(rows) != expected_count:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must contain {expected_count} sites, got {len(rows)}"
        )
    result: dict[tuple[FrontierCategory, int], tuple[int, LeanFactRef]] = {}
    for index, value in enumerate(rows):
        row = _object(value, f"{label} sites[{index}]")
        rva = _natural(row.get("source_rva"), f"{label} sites[{index}].source_rva", word=True)
        target_id = _natural(
            row.get("source_target_id"), f"{label} sites[{index}].source_target_id"
        )
        authority = LeanFactRef.from_json(
            row.get("authorizing_lean_term"),
            f"{label} sites[{index}].authorizing_lean_term",
        )
        key = (category, rva)
        if key in result:
            raise GnuHelloSourceExecutionGenerationError(
                f"{label} repeats {_render_key(key)}"
            )
        result[key] = (target_id, authority)
    return result


def _stack_dynamic_authorities(
    report: dict[str, Any],
) -> dict[tuple[FrontierCategory, int], tuple[int, LeanFactRef]]:
    rows = _list(report.get("sites"), "stack/dynamic authority sites")
    if len(rows) != 3:
        raise GnuHelloSourceExecutionGenerationError(
            f"stack/dynamic authority report must contain 3 sites, got {len(rows)}"
        )
    expected_modes = {
        "finite_stack_target": "generatedOriginalStackDynamicClosure0StackAuthority",
        "empty_indexed_source": "generatedOriginalStackDynamicClosure1EmptyIndexedAuthority",
        "uninhabited_dynamic_source": "generatedOriginalStackDynamicClosure2SiteEvidence",
    }
    result: dict[tuple[FrontierCategory, int], tuple[int, LeanFactRef]] = {}
    seen_modes: set[str] = set()
    for index, value in enumerate(rows):
        row = _object(value, f"stack/dynamic sites[{index}]")
        mode = _string(row.get("closure_mode"), f"stack/dynamic sites[{index}].closure_mode")
        if mode not in expected_modes or mode in seen_modes:
            raise GnuHelloSourceExecutionGenerationError(
                "stack/dynamic authority report must contain each checked closure mode once"
            )
        if row.get("static_authority") != "lean_checked":
            raise GnuHelloSourceExecutionGenerationError(
                f"stack/dynamic sites[{index}] lacks a Lean-checked static authority"
            )
        seen_modes.add(mode)
        rva = _natural(row.get("source_rva"), f"stack/dynamic sites[{index}].source_rva", word=True)
        target_id = _natural(
            row.get("source_target_id"), f"stack/dynamic sites[{index}].source_target_id"
        )
        authority = LeanFactRef(
            module="StageA.GeneratedRelationalOriginalStackDynamicControlClosure",
            namespace=(
                "StageA.GeneratedRelational.OriginalStackDynamicControlClosure"
            ),
            symbol=expected_modes[mode],
        )
        authority.validate(f"stack/dynamic sites[{index}] authority")
        result[("stack_dynamic", rva)] = (target_id, authority)
    return result


def _check_artifact_bindings(
    plan: dict[str, Any],
    writable: dict[str, Any],
    register: dict[str, Any],
    stack: dict[str, Any],
    hashes: dict[str, str],
) -> None:
    state_hash = _sha_field(plan, "state_machine_sha256", "mixed original plan")
    writable_inputs = _object(writable.get("inputs"), "writable report inputs")
    register_inputs = _object(register.get("inputs"), "register report inputs")
    stack_inputs = _object(stack.get("inputs"), "stack/dynamic report inputs")
    plan_hash = hashes["mixed_original_plan"]
    if _sha_field(
        writable_inputs, "mixed_original_plan_sha256", "writable report"
    ) != plan_hash:
        raise GnuHelloSourceExecutionGenerationError(
            "writable authority report does not bind the exact mixed-original plan"
        )
    if _sha_field(
        register_inputs, "mixed_original_plan_sha256", "register report"
    ) != plan_hash:
        raise GnuHelloSourceExecutionGenerationError(
            "register authority report does not bind the exact mixed-original plan"
        )
    for label, inputs in (
        ("writable report", writable_inputs),
        ("register report", register_inputs),
    ):
        if _sha_field(inputs, "state_machine_sha256", label) != state_hash:
            raise GnuHelloSourceExecutionGenerationError(
                f"{label} does not bind the mixed-original state machine"
            )
    if _sha_field(stack_inputs, "state_machine_sha256", "stack/dynamic report") != state_hash:
        raise GnuHelloSourceExecutionGenerationError(
            "stack/dynamic report does not bind the mixed-original state machine"
        )
    original_hashes = {
        _sha_field(writable_inputs, "original_sha256", "writable report"),
        _sha_field(register_inputs, "original_sha256", "register report"),
        _sha_field(stack_inputs, "original_pe_sha256", "stack/dynamic report"),
    }
    if len(original_hashes) != 1:
        raise GnuHelloSourceExecutionGenerationError(
            "original PE hashes disagree across the three authority reports"
        )
    if _sha_field(register_inputs, "writable_slot_report_sha256", "register report") != hashes[
        "writable_authority_report"
    ]:
        raise GnuHelloSourceExecutionGenerationError(
            "register authority report does not bind the exact writable authority report"
        )


def _check_manifest_bindings(
    manifest: dict[str, Any], hashes: dict[str, str]
) -> None:
    inputs = _object(manifest.get("inputs"), "evidence manifest inputs")
    if set(inputs) != set(hashes):
        raise GnuHelloSourceExecutionGenerationError(
            "evidence manifest inputs must bind exactly "
            + ", ".join(sorted(hashes))
        )
    for name, digest in hashes.items():
        if _sha_field(inputs, name, "evidence manifest inputs") != digest:
            raise GnuHelloSourceExecutionGenerationError(
                f"evidence manifest does not bind exact {name}"
            )


def _assembly_manifest(spec: GnuHelloSourceExecutionSpec) -> dict[str, Any]:
    return {
        "format": "stage-a-gnu-hello-source-execution-assembly-v2",
        "launch_scope": "all_checked_pe32_console_launches",
        "inputs": dict(spec.input_hashes),
        "counts": {
            "frontiers": len(spec.frontiers),
            **_EXPECTED_COUNTS,
        },
        "lean": {
            "proof_module": f"StageA.{spec.output_module}",
            "audit_module": f"StageA.{spec.audit_module}",
            "domain": f"{spec.namespace}.generatedSourceExecutionDomainAt",
            "invariant_family_evidence": (
                f"{spec.namespace}.generatedOriginalInvariantFamilyEvidence"
            ),
            "launch_family": (
                f"{spec.namespace}.generatedCheckedNativeSourceLaunchFamily"
            ),
        },
        "launch_family_complete": True,
        "acceptance_authority": False,
        "blockers": [],
        "frontiers": [
            {
                "category": frontier.category,
                "source_rva": frontier.source_rva,
                "source_target_id": frontier.source_target_id,
                "static_authority": frontier.static_authority.to_json(),
                "target_membership": frontier.target_membership.to_json(),
                "running_target_membership": (
                    frontier.running_target_membership.to_json()
                ),
                "callback_target_membership": (
                    frontier.callback_target_membership.to_json()
                ),
            }
            for frontier in spec.frontiers
        ],
    }


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloSourceExecutionGenerationError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GnuHelloSourceExecutionGenerationError(
            f"cannot hash {path}: {error}"
        ) from error


def _require_format(value: dict[str, Any], expected: str, label: str) -> None:
    if value.get("format") != expected:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} has unsupported format"
        )


def _sha_field(value: dict[str, Any], field: str, label: str) -> str:
    digest = _string(value.get(field), f"{label}.{field}")
    if _SHA256.fullmatch(digest) is None:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label}.{field} is not lowercase SHA-256"
        )
    return digest


def _validate_identifier(value: object, label: str) -> None:
    if not (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(part.casefold() not in _FORBIDDEN_NAME_PARTS for part in value.split("."))
    ):
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must be a canonical Lean identifier"
        )


def _validate_local_name(value: object, label: str) -> None:
    if not (
        isinstance(value, str)
        and _LOCAL_NAME.fullmatch(value) is not None
        and value.casefold() not in _FORBIDDEN_NAME_PARTS
    ):
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must be a canonical local Lean identifier"
        )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GnuHelloSourceExecutionGenerationError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloSourceExecutionGenerationError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must be a non-empty string"
        )
    return value


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must be a natural number"
        )
    if word and value > 0xFFFFFFFF:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must fit in a 32-bit word"
        )
    return value


def _category(value: object, label: str) -> FrontierCategory:
    if value not in _EXPECTED_COUNTS:
        raise GnuHelloSourceExecutionGenerationError(
            f"{label} must name a supported frontier family"
        )
    return value  # type: ignore[return-value]


def _render_key(key: tuple[FrontierCategory, int]) -> str:
    return f"{key[0]}@0x{key[1]:x}"


def _render_keys(keys: list[tuple[FrontierCategory, int]]) -> str:
    return "[" + ", ".join(_render_key(key) for key in keys) + "]"


__all__ = [
    "GNU_HELLO_SOURCE_EXECUTION_AUDIT_MODULE",
    "GNU_HELLO_SOURCE_EXECUTION_EVIDENCE_FORMAT",
    "GNU_HELLO_SOURCE_EXECUTION_MODULE",
    "FrontierExecutionFact",
    "GnuHelloSourceExecutionGenerationError",
    "GnuHelloSourceExecutionAssemblyResult",
    "GnuHelloSourceExecutionModules",
    "GnuHelloSourceExecutionSpec",
    "LeanFactRef",
    "assemble_gnu_hello_source_execution_spec",
    "gnu_hello_source_execution_audit_source",
    "gnu_hello_source_execution_source",
    "write_gnu_hello_source_execution",
    "write_gnu_hello_source_execution_from_artifacts",
]
