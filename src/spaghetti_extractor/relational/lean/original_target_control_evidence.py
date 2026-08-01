"""Emit artifact-bound original-target control evidence adapters.

The producer in this module is intentionally generic.  It consumes the exact
source target-effect declaration inventory, its transition index, the state
machine that classified those effects, and the combined original target
inventory.  It does not accept a list of theorem names or a report status as
preservation authority.

The generated Lean shards expose fixed-name adapters to
``RelationalOriginalTargetControlPreservation``.  Lean performs the semantic
fault/outcome split and constructs ``CheckedOriginalTargetTransition`` together
with reachability and call-frame posts.  Python only selects the applicable
static control constructor and translates RVAs through the complete target
inventory.  Indirect control without a canonical checked resolution and
external control without a machine contract remain explicit, target-local
blockers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError


ORIGINAL_TARGET_CONTROL_EVIDENCE_FORMAT = (
    "stage-a-original-target-control-evidence-v1"
)
ORIGINAL_TARGET_CONTROL_DECLARATIONS_FORMAT = (
    "stage-a-original-target-control-evidence-declarations-v1"
)
ORIGINAL_TARGET_CONTROL_BLOCKERS_FORMAT = (
    "stage-a-original-target-control-evidence-blockers-v1"
)

_EFFECTS_FORMAT = "stage-a-gnu-hello-source-transition-index-declarations-v1"
_TRANSITION_FORMAT = "stage-a-gnu-hello-source-transition-index-v1"
_COMBINED_FORMAT = (
    "stage-a-original-combined-execution-inventory-declarations-v1"
)
_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"

_MODULE_PREFIX = "GeneratedOriginalTargetControlEvidence"
_NAMESPACE = "StageA.GeneratedRelational.OriginalTargetControlEvidence"
_MANIFEST_NAME = "original-target-control-evidence.json"
_DECLARATIONS_NAME = "original-target-control-evidence-declarations.json"
_BLOCKERS_NAME = "original-target-control-evidence-blockers.json"

_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_EVENT_KINDS = frozenset(
    {"external_call", "internal_call", "indirect_call"}
)
_EXTERNAL_DISPOSITIONS = frozenset({"protocol", "returns", "terminates"})


class OriginalTargetControlEvidenceError(StageAInputError):
    """The exact control-evidence inputs are inconsistent or incomplete."""


@dataclass(frozen=True)
class LeanRef:
    module: str
    declaration: str

    @classmethod
    def from_json(cls, value: object, label: str) -> "LeanRef":
        row = _object(value, label)
        if set(row) != {"module", "declaration"}:
            raise OriginalTargetControlEvidenceError(
                f"{label} must contain exactly module and declaration"
            )
        result = cls(
            module=_string(row["module"], f"{label}.module"),
            declaration=_string(row["declaration"], f"{label}.declaration"),
        )
        result.validate(label)
        return result

    @classmethod
    def qualified(cls, module: object, declaration: object, label: str) -> "LeanRef":
        result = cls(
            module=_string(module, f"{label}.module"),
            declaration=_string(declaration, f"{label}.declaration"),
        )
        result.validate(label)
        return result

    def validate(self, label: str) -> None:
        if _MODULE.fullmatch(self.module) is None:
            raise OriginalTargetControlEvidenceError(
                f"{label}.module must be a canonical StageA module"
            )
        if _IDENTIFIER.fullmatch(self.declaration) is None:
            raise OriginalTargetControlEvidenceError(
                f"{label}.declaration must be a canonical Lean declaration"
            )


@dataclass(frozen=True)
class TargetEffect:
    target_id: int
    source_rva: int
    kind: str
    refs: tuple[LeanRef, ...]
    certificate: LeanRef

    @property
    def imports(self) -> set[str]:
        return {self.certificate.module, *(ref.module for ref in self.refs)}


@dataclass(frozen=True)
class ControlClass:
    kind: str
    targets: tuple[int, ...] = ()
    external_disposition: str | None = None
    fault_capable: bool = False

    @property
    def key(self) -> str:
        if self.external_disposition is None:
            return self.kind
        return f"{self.kind}:{self.external_disposition}"


@dataclass(frozen=True)
class ClassifiedTarget:
    effect: TargetEffect
    control: ControlClass
    blocker: dict[str, Any] | None


@dataclass(frozen=True)
class GeneratedOriginalTargetControlEvidence:
    modules: tuple[Path, ...]
    audit: Path
    declarations: Path
    blockers: Path
    manifest: Path
    target_count: int
    emitted_count: int
    blocked_count: int
    shard_count: int


def generate_original_target_control_evidence(
    out: Path | str,
    *,
    source_target_effect_declarations: Path | str,
    transition_index_manifest: Path | str,
    state_machine: Path | str,
    combined_target_inventory: Path | str,
    shard_size: int = 64,
) -> GeneratedOriginalTargetControlEvidence:
    """Generate deterministic control-evidence adapters and blockers.

    ``external_target_contracts`` is optional checked data in the combined
    inventory.  Its rows contain only ``target_id`` and ``disposition``; no
    declaration or theorem name is accepted.  The generated external adapter
    still requires Lean's ``CheckedOriginalImportEvidence``, so the data cannot
    authorize a missing site or contract lookup.
    """

    if (
        isinstance(shard_size, bool)
        or not isinstance(shard_size, int)
        or shard_size <= 0
    ):
        raise OriginalTargetControlEvidenceError(
            "shard_size must be a positive integer"
        )

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(root)
    paths = {
        "source_target_effect_declarations": Path(
            source_target_effect_declarations
        ),
        "transition_index_manifest": Path(transition_index_manifest),
        "state_machine": Path(state_machine),
        "combined_target_inventory": Path(combined_target_inventory),
    }
    hashes = {name: _sha256(path) for name, path in paths.items()}
    effects = _load_json(
        paths["source_target_effect_declarations"],
        "source target-effect declarations",
    )
    transition = _load_json(
        paths["transition_index_manifest"], "transition-index manifest"
    )
    combined = _load_json(
        paths["combined_target_inventory"], "combined target inventory"
    )
    _require_format(effects, _EFFECTS_FORMAT, "source target-effect declarations")
    _require_format(transition, _TRANSITION_FORMAT, "transition-index manifest")
    _require_format(combined, _COMBINED_FORMAT, "combined target inventory")

    rows = _state_machine_rows(paths["state_machine"])
    targets = _effect_targets(effects, transition)
    _validate_transition(transition, hashes, targets)
    combined_refs = _combined_refs(combined, targets)
    rows_by_rva = _exact_rows_by_rva(rows, targets)
    target_by_rva = {target.source_rva: target.target_id for target in targets}
    contracts = _external_contracts(combined, {target.target_id for target in targets})

    classified = tuple(
        _classify_target(
            target,
            rows_by_rva[target.source_rva],
            target_by_rva,
            contracts,
        )
        for target in targets
    )
    blockers = tuple(
        target.blocker for target in classified if target.blocker is not None
    )

    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    modules: list[Path] = []
    data_path = stage_a / f"{_MODULE_PREFIX}Data.lean"
    _write_ascii(
        data_path,
        _data_source(
            combined_refs=combined_refs,
            transition_module=_transition_aggregate_module(transition),
        ),
    )
    modules.append(data_path)

    shard_names: list[str] = []
    for shard_index, start in enumerate(range(0, len(classified), shard_size)):
        members = classified[start : start + shard_size]
        module = f"{_MODULE_PREFIX}Shard{shard_index:04d}"
        shard_names.append(module)
        path = stage_a / f"{module}.lean"
        _write_ascii(path, _shard_source(module, members))
        modules.append(path)

    aggregate_path = stage_a / f"{_MODULE_PREFIX}.lean"
    _write_ascii(aggregate_path, _aggregate_source(shard_names))
    modules.append(aggregate_path)

    audit_path = stage_a / f"{_MODULE_PREFIX}Audit.lean"
    _write_ascii(audit_path, _audit_source(classified))

    declarations_path = root / _DECLARATIONS_NAME
    declaration_rows = [
        _declaration_row(item, index // shard_size)
        for index, item in enumerate(classified)
    ]
    _write_json(
        declarations_path,
        {
            "format": ORIGINAL_TARGET_CONTROL_DECLARATIONS_FORMAT,
            "namespace": _NAMESPACE,
            "module_prefix": _MODULE_PREFIX,
            "targets": declaration_rows,
        },
    )

    blockers_path = root / _BLOCKERS_NAME
    _write_json(
        blockers_path,
        {
            "format": ORIGINAL_TARGET_CONTROL_BLOCKERS_FORMAT,
            "inputs": dict(sorted(hashes.items())),
            "blockers": list(blockers),
        },
    )

    class_counts = Counter(item.control.key for item in classified)
    manifest_path = root / _MANIFEST_NAME
    _write_json(
        manifest_path,
        {
            "format": ORIGINAL_TARGET_CONTROL_EVIDENCE_FORMAT,
            "validation_required": "lean-kernel-check-and-detached-axiom-audit",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": dict(sorted(hashes.items())),
            "counts": {
                "targets": len(classified),
                "emitted": len(classified),
                "blocked": len(blockers),
                "shards": len(shard_names),
                "classes": dict(sorted(class_counts.items())),
            },
            "modules": [f"StageA.{path.stem}" for path in modules],
            "audit_module": f"StageA.{audit_path.stem}",
            "declarations": declarations_path.name,
            "blockers": blockers_path.name,
        },
    )
    return GeneratedOriginalTargetControlEvidence(
        modules=tuple(modules),
        audit=audit_path,
        declarations=declarations_path,
        blockers=blockers_path,
        manifest=manifest_path,
        target_count=len(classified),
        emitted_count=len(classified),
        blocked_count=len(blockers),
        shard_count=len(shard_names),
    )


def _effect_targets(
    effects: Mapping[str, Any], transition: Mapping[str, Any]
) -> tuple[TargetEffect, ...]:
    namespace = _identifier(effects.get("namespace"), "effects.namespace")
    module_prefix = _local(effects.get("module_prefix"), "effects.module_prefix")
    shard_span = _positive(effects.get("shard_span"), "effects.shard_span")
    transition_modules = {
        _module_name(value, "transition modules[]")
        for value in _list(transition.get("modules"), "transition modules")
    }
    result: list[TargetEffect] = []
    for index, value in enumerate(_list(effects.get("targets"), "effect targets")):
        row = _object(value, f"effect targets[{index}]")
        target_id = _natural(row.get("target_id"), f"effect targets[{index}].target_id")
        source_rva = _word(row.get("source_rva"), f"effect targets[{index}].source_rva")
        kind = _string(row.get("kind"), f"effect targets[{index}].kind")
        evidence = _object(row.get("evidence"), f"effect targets[{index}].evidence")
        if kind == "ordinary":
            refs = (
                LeanRef.from_json(
                    evidence.get("checked_effect"),
                    f"effect targets[{index}].evidence.checked_effect",
                ),
            )
        elif kind == "x87":
            refs = (
                LeanRef.from_json(
                    evidence.get("facts"),
                    f"effect targets[{index}].evidence.facts",
                ),
                LeanRef.from_json(
                    evidence.get("successful_components"),
                    f"effect targets[{index}].evidence.successful_components",
                ),
            )
        else:
            raise OriginalTargetControlEvidenceError(
                f"effect target {target_id} has unsupported kind {kind!r}"
            )
        shard = f"StageA.{module_prefix}Shard{target_id // shard_span:06d}"
        if shard not in transition_modules:
            raise OriginalTargetControlEvidenceError(
                f"transition index omits certificate shard {shard}"
            )
        result.append(
            TargetEffect(
                target_id=target_id,
                source_rva=source_rva,
                kind=kind,
                refs=refs,
                certificate=LeanRef.qualified(
                    shard,
                    f"{namespace}.generatedActiveTargetTransitionCertificate_{target_id}",
                    f"target {target_id} transition certificate",
                ),
            )
        )
    ids = [target.target_id for target in result]
    rvas = [target.source_rva for target in result]
    if not result:
        raise OriginalTargetControlEvidenceError(
            "source target-effect declarations must not be empty"
        )
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise OriginalTargetControlEvidenceError(
            "effect targets must be sorted and unique by target identifier"
        )
    if len(set(rvas)) != len(rvas):
        raise OriginalTargetControlEvidenceError(
            "effect targets must be unique by source RVA"
        )
    return tuple(result)


def _validate_transition(
    transition: Mapping[str, Any],
    hashes: Mapping[str, str],
    targets: Sequence[TargetEffect],
) -> None:
    inputs = _object(transition.get("inputs"), "transition inputs")
    declarations = _object(
        inputs.get("declaration_inventory"),
        "transition inputs.declaration_inventory",
    )
    if _digest(declarations.get("sha256"), "transition declaration hash") != hashes[
        "source_target_effect_declarations"
    ]:
        raise OriginalTargetControlEvidenceError(
            "transition index does not bind exact source target-effect declarations"
        )
    counts = _object(transition.get("counts"), "transition counts")
    if _natural(counts.get("targets"), "transition counts.targets") != len(targets):
        raise OriginalTargetControlEvidenceError(
            "transition index target count differs from effect declarations"
        )


def _combined_refs(
    combined: Mapping[str, Any], targets: Sequence[TargetEffect]
) -> dict[str, LeanRef]:
    counts = _object(combined.get("counts"), "combined counts")
    if _natural(
        counts.get("reachable_targets"), "combined counts.reachable_targets"
    ) != len(targets):
        raise OriginalTargetControlEvidenceError(
            "combined target inventory count differs from effect declarations"
        )
    lean = _object(combined.get("lean"), "combined lean")
    module = _module_name(lean.get("module"), "combined lean.module")
    result = {
        name: LeanRef.qualified(module, lean.get(field), f"combined lean.{field}")
        for name, field in (
            ("program", "program"),
            ("original_context", "original_context"),
            ("inventory", "inventory"),
        )
    }
    reachable = lean.get("reachable_target_ids")
    if reachable is not None:
        result["reachable_target_ids"] = LeanRef.qualified(
            module, reachable, "combined lean.reachable_target_ids"
        )
    return result


def _exact_rows_by_rva(
    rows: Sequence[Mapping[str, Any]], targets: Sequence[TargetEffect]
) -> dict[int, Mapping[str, Any]]:
    result: dict[int, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        original = _object(row.get("original"), f"state row {index}.original")
        rva = _word(original.get("rva_start"), f"state row {index}.original.rva_start")
        if rva in result:
            raise OriginalTargetControlEvidenceError(
                f"state machine repeats source RVA 0x{rva:x}"
            )
        result[rva] = row
    expected = {target.source_rva for target in targets}
    actual = set(result)
    if actual != expected:
        missing = [f"0x{value:x}" for value in sorted(expected - actual)]
        extra = [f"0x{value:x}" for value in sorted(actual - expected)]
        raise OriginalTargetControlEvidenceError(
            f"state-machine/effect target inventory differs: missing={missing}, extra={extra}"
        )
    return result


def _external_contracts(
    combined: Mapping[str, Any], target_ids: set[int]
) -> dict[int, str]:
    raw = combined.get("external_target_contracts", [])
    rows = _list(raw, "combined external_target_contracts")
    result: dict[int, str] = {}
    for index, value in enumerate(rows):
        row = _object(value, f"combined external_target_contracts[{index}]")
        if set(row) != {"target_id", "disposition"}:
            raise OriginalTargetControlEvidenceError(
                "combined external_target_contracts rows must contain exactly "
                "target_id and disposition"
            )
        target_id = _natural(
            row["target_id"], f"combined external_target_contracts[{index}].target_id"
        )
        disposition = _string(
            row["disposition"],
            f"combined external_target_contracts[{index}].disposition",
        )
        if target_id not in target_ids:
            raise OriginalTargetControlEvidenceError(
                f"external contract names unknown target {target_id}"
            )
        if disposition not in _EXTERNAL_DISPOSITIONS:
            raise OriginalTargetControlEvidenceError(
                f"external target {target_id} has unsupported disposition {disposition!r}"
            )
        if target_id in result:
            raise OriginalTargetControlEvidenceError(
                f"external contracts repeat target {target_id}"
            )
        result[target_id] = disposition
    return result


def _classify_target(
    target: TargetEffect,
    row: Mapping[str, Any],
    target_by_rva: Mapping[int, int],
    contracts: Mapping[int, str],
) -> ClassifiedTarget:
    faults = _list(row.get("faults", []), f"target {target.target_id} faults")
    fault_capable = target.kind == "x87" or bool(faults)
    ordered = _list(
        row.get("ordered_events", []), f"target {target.target_id} ordered_events"
    )
    controls = [
        _object(value, f"target {target.target_id} ordered control event")
        for value in ordered
        if isinstance(value, dict) and value.get("kind") in _CONTROL_EVENT_KINDS
    ]
    if len(controls) > 1:
        return _blocked(
            target,
            ControlClass("multiple_control_events", fault_capable=fault_capable),
            "multiple_control_events",
        )
    if controls:
        event = controls[0]
        kind = _string(event.get("kind"), f"target {target.target_id} call kind")
        continuation = _target_for_rva(
            target,
            event.get("return_rva"),
            target_by_rva,
            "call continuation",
            allow_zero=kind == "external_call",
        )
        if kind == "internal_call":
            callee = _target_for_rva(
                target,
                event.get("target_rva"),
                target_by_rva,
                "direct callee",
            )
            if isinstance(callee, dict):
                return ClassifiedTarget(target, ControlClass("call"), callee)
            if isinstance(continuation, dict):
                return ClassifiedTarget(target, ControlClass("call"), continuation)
            return ClassifiedTarget(
                target,
                ControlClass("call", (callee, continuation), fault_capable=fault_capable),
                None,
            )
        if kind == "indirect_call":
            return _blocked(
                target,
                ControlClass("indirect_call", fault_capable=fault_capable),
                "unresolved_indirect_control",
            )
        return _external_classification(
            target,
            continuation,
            contracts,
            fault_capable=fault_capable,
        )

    outcome = _object(row.get("outcome"), f"target {target.target_id} outcome")
    kind = _string(outcome.get("kind"), f"target {target.target_id} outcome.kind")
    if kind in {"fallthrough", "jump"}:
        successor = _target_for_rva(
            target,
            outcome.get("target_rva"),
            target_by_rva,
            f"{kind} successor",
        )
        if isinstance(successor, dict):
            return ClassifiedTarget(target, ControlClass(kind), successor)
        return ClassifiedTarget(
            target,
            ControlClass(kind, (successor,), fault_capable=fault_capable),
            None,
        )
    if kind == "branch":
        taken = _target_for_rva(
            target,
            outcome.get("true_target_rva"),
            target_by_rva,
            "branch taken successor",
        )
        fallthrough = _target_for_rva(
            target,
            outcome.get("false_target_rva"),
            target_by_rva,
            "branch fallthrough successor",
        )
        blocker = taken if isinstance(taken, dict) else fallthrough
        if isinstance(blocker, dict):
            return ClassifiedTarget(target, ControlClass("branch"), blocker)
        return ClassifiedTarget(
            target,
            ControlClass(
                "branch", (taken, fallthrough), fault_capable=fault_capable
            ),
            None,
        )
    if kind in {"direct_call", "call"}:
        callee = _target_for_rva(
            target, outcome.get("target_rva"), target_by_rva, "direct callee"
        )
        continuation = _target_for_rva(
            target,
            outcome.get("return_rva", outcome.get("continuation_rva")),
            target_by_rva,
            "call continuation",
        )
        blocker = callee if isinstance(callee, dict) else continuation
        if isinstance(blocker, dict):
            return ClassifiedTarget(target, ControlClass("call"), blocker)
        return ClassifiedTarget(
            target,
            ControlClass("call", (callee, continuation), fault_capable=fault_capable),
            None,
        )
    if kind == "return":
        return ClassifiedTarget(
            target, ControlClass("return", fault_capable=fault_capable), None
        )
    if kind in {"indirect_jump", "indirect_jump_table"}:
        return _blocked(
            target,
            ControlClass("indirect_jump", fault_capable=fault_capable),
            "unresolved_indirect_control",
        )
    if kind == "external_jump":
        return _external_classification(
            target, None, contracts, fault_capable=fault_capable
        )
    if kind in {"fault", "termination", "terminated"}:
        normalized = "fault" if kind == "fault" else "termination"
        return ClassifiedTarget(
            target, ControlClass(normalized, fault_capable=True), None
        )
    return _blocked(
        target,
        ControlClass(kind, fault_capable=fault_capable),
        "unsupported_control_class",
    )


def _external_classification(
    target: TargetEffect,
    continuation: int | dict[str, Any] | None,
    contracts: Mapping[int, str],
    *,
    fault_capable: bool,
) -> ClassifiedTarget:
    if isinstance(continuation, dict):
        return ClassifiedTarget(target, ControlClass("external"), continuation)
    disposition = contracts.get(target.target_id)
    targets = () if continuation is None else (continuation,)
    control = ControlClass(
        "external",
        targets,
        external_disposition=disposition,
        fault_capable=fault_capable,
    )
    if disposition is None:
        return _blocked(target, control, "uncontracted_external_control")
    return ClassifiedTarget(target, control, None)


def _target_for_rva(
    source: TargetEffect,
    value: object,
    target_by_rva: Mapping[int, int],
    label: str,
    *,
    allow_zero: bool = False,
) -> int | None | dict[str, Any]:
    if allow_zero and value is None:
        return None
    rva = _word(value, f"target {source.target_id} {label}")
    if allow_zero and rva == 0:
        return None
    target = target_by_rva.get(rva)
    if target is None:
        return _blocker(source, "unmapped_direct_target", detail_rva=rva)
    return target


def _blocked(
    target: TargetEffect, control: ControlClass, reason: str
) -> ClassifiedTarget:
    return ClassifiedTarget(target, control, _blocker(target, reason))


def _blocker(
    target: TargetEffect, reason: str, *, detail_rva: int | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "reason_code": reason,
        "target_id": target.target_id,
        "source_rva": target.source_rva,
    }
    if detail_rva is not None:
        result["detail_rva"] = detail_rva
    return result


def _data_source(
    *, combined_refs: Mapping[str, LeanRef], transition_module: str
) -> str:
    imports = {
        transition_module,
        *(ref.module for ref in combined_refs.values()),
        "StageA.RelationalOriginalTargetControlPreservation",
    }
    aliases = [
        f"abbrev generatedCombined{name[:1].upper() + name[1:]} :=\n  {ref.declaration}"
        for name, ref in sorted(combined_refs.items())
    ]
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

noncomputable section

{chr(10).join(aliases)}

def generatedControlCase
    (targetId : Nat)
    {{program : Program}}
    {{originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}}
    {{checked : CheckedOriginalTargetEffect program targetId}}
    (evidence : CheckedOriginalTargetControlEvidence originalContext inventory
      checked)
    (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    CheckedOriginalTargetControlPreservationCase originalContext inventory
      checked invocation :=
  evidence.toPreservationCase invocation holds

def generatedCheckedTransition
    (targetId : Nat)
    {{program : Program}}
    {{originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}}
    {{checked : CheckedOriginalTargetEffect program targetId}}
    (evidence : CheckedOriginalTargetControlEvidence originalContext inventory
      checked)
    (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation :=
  (generatedControlCase targetId evidence invocation holds).transition

def generatedReachabilityPost
    (targetId : Nat)
    {{program : Program}}
    {{originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}}
    {{checked : CheckedOriginalTargetEffect program targetId}}
    (evidence : CheckedOriginalTargetControlEvidence originalContext inventory
      checked)
    (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    OriginalReachabilityPostEvidence inventory.reachableTargets.targetIds
      (generatedCheckedTransition targetId evidence invocation holds).successor :=
  (generatedControlCase targetId evidence invocation holds).reachability

def generatedCallFramePost
    (targetId : Nat)
    {{program : Program}}
    {{originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}}
    {{checked : CheckedOriginalTargetEffect program targetId}}
    (evidence : CheckedOriginalTargetControlEvidence originalContext inventory
      checked)
    (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    OriginalCallFramePostEvidence program.worldProgram.context
      (generatedCheckedTransition targetId evidence invocation holds).successor :=
  (generatedControlCase targetId evidence invocation holds).callFrames

def generatedRunningPost := CheckedOriginalControlPost.running
def generatedCallbackRunningPost := CheckedOriginalControlPost.callbackRunning
def generatedAwaitingExternalPost := CheckedOriginalControlPost.awaitingExternal
def generatedReturnedPost := CheckedOriginalControlPost.returned
def generatedTerminatedPost := CheckedOriginalControlPost.terminated
def generatedFaultPost := CheckedOriginalControlPost.fault

def generatedJumpControl
    (sourceTargetId target : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{state : MachineState}}
    (evidence : CheckedOriginalStaticTargetEvidence targetIds target) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.jump target) :=
  evidence.jumpControl

def generatedBranchControl
    (sourceTargetId taken fallthrough : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{state : MachineState}} {{condition : Bool}}
    (evidence : CheckedOriginalBranchTargetEvidence targetIds taken
      fallthrough) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.branch condition taken fallthrough) :=
  evidence.branchControl

def generatedCallControl
    (sourceTargetId target continuation : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{state : MachineState}}
    (evidence : CheckedOriginalDirectCallEvidence targetIds target
      continuation) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.call target continuation) :=
  evidence.callControl

def generatedReturnControl
    (sourceTargetId : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{program : DecodedWorldProgram}}
    {{state : MachineState}} {{calls : List Nat}}
    {{callbacks : List WorldExternalCallbackRuntime}} {{target : Word}}
    (evidence : CheckedOriginalReturnEvidence program state calls callbacks
      target) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.returned target) :=
  evidence.returnedControl

def generatedExternalCallControl
    (sourceTargetId continuation : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{program : DecodedWorldProgram}}
    {{state : MachineState}} {{imported : ExternalTarget}}
    (evidence : CheckedOriginalImportEvidence program sourceTargetId
      continuation imported)
    (arguments : List Word)
    (continuationReachable : List.Mem continuation targetIds) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.externalCall imported arguments continuation) :=
  evidence.externalCallControl arguments continuationReachable

def generatedExternalJumpControl
    (sourceTargetId continuation : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{program : DecodedWorldProgram}}
    {{state : MachineState}} {{imported : ExternalTarget}}
    (evidence : CheckedOriginalImportEvidence program sourceTargetId
      continuation imported) (arguments : List Word) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.externalJump imported arguments) :=
  evidence.externalJumpControl arguments

def generatedIndirectCallControl
    (sourceTargetId : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{state : MachineState}} {{target : Word}}
    (resolution : CheckedOriginalIndirectTargetResolution context targetIds
      sourceTargetId state target)
    (continuation : Nat)
    (continuationReachable : List.Mem continuation targetIds) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.indirectCall target continuation) :=
  StageA.Relational.OriginalTargetControlPreservation.CheckedOriginalIndirectTargetResolution.indirectCallControl
    resolution continuation continuationReachable

def generatedIndirectJumpControl
    (sourceTargetId : Nat)
    {{context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}}
    {{targetIds : List Nat}} {{state : MachineState}} {{target : Word}}
    (resolution : CheckedOriginalIndirectTargetResolution context targetIds
      sourceTargetId state target) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.indirectJump target) :=
  StageA.Relational.OriginalTargetControlPreservation.CheckedOriginalIndirectTargetResolution.indirectJumpControl
    resolution

end
end {_NAMESPACE}
"""


def _shard_source(module: str, members: Sequence[ClassifiedTarget]) -> str:
    imports = {f"StageA.{_MODULE_PREFIX}Data"}
    for member in members:
        imports.update(member.effect.imports)
    body = "\n\n".join(_target_source(member) for member in members)
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation

noncomputable section

{body}

end
end {_NAMESPACE}
"""


def _target_source(item: ClassifiedTarget) -> str:
    target = item.effect
    prefix = f"generatedTarget{target.target_id}"
    if target.kind == "ordinary":
        source_aliases = f"abbrev {prefix}SourceEffect := {target.refs[0].declaration}"
    else:
        source_aliases = (
            f"abbrev {prefix}SourceFacts := {target.refs[0].declaration}\n"
            f"abbrev {prefix}SourceComponents := {target.refs[1].declaration}"
        )
    declarations = [
        source_aliases,
        f"abbrev {prefix}TransitionCertificate := {target.certificate.declaration}",
        f"abbrev {prefix}ControlCase := @generatedControlCase {target.target_id}",
        f"abbrev {prefix}CheckedTransition := @generatedCheckedTransition {target.target_id}",
        f"abbrev {prefix}ReachabilityPost := @generatedReachabilityPost {target.target_id}",
        f"abbrev {prefix}CallFramePost := @generatedCallFramePost {target.target_id}",
        f"abbrev {prefix}RunningPost := @generatedRunningPost",
        f"abbrev {prefix}CallbackRunningPost := @generatedCallbackRunningPost",
        f"abbrev {prefix}FaultPost := @generatedFaultPost",
    ]
    control = item.control
    if control.kind in {"fallthrough", "jump"} and control.targets:
        declarations.append(
            f"abbrev {prefix}{_camel(control.kind)}Control := "
            f"@generatedJumpControl {target.target_id} {control.targets[0]}"
        )
    elif control.kind == "branch" and len(control.targets) == 2:
        declarations.append(
            f"abbrev {prefix}BranchControl := @generatedBranchControl "
            f"{target.target_id} {control.targets[0]} {control.targets[1]}"
        )
    elif control.kind == "call" and len(control.targets) == 2:
        declarations.append(
            f"abbrev {prefix}CallControl := @generatedCallControl "
            f"{target.target_id} {control.targets[0]} {control.targets[1]}"
        )
    elif control.kind == "return":
        declarations.extend(
            (
                f"abbrev {prefix}ReturnControl := "
                f"@generatedReturnControl {target.target_id}",
                f"abbrev {prefix}ReturnedPost := @generatedReturnedPost",
                f"abbrev {prefix}AwaitingExternalPost := @generatedAwaitingExternalPost",
            )
        )
    elif control.kind == "external":
        if control.targets:
            declarations.append(
                f"abbrev {prefix}ExternalCallControl := "
                f"@generatedExternalCallControl {target.target_id} "
                f"{control.targets[0]}"
            )
        else:
            declarations.append(
                f"abbrev {prefix}ExternalJumpControl := "
                f"@generatedExternalJumpControl {target.target_id}"
            )
        if control.external_disposition == "terminates":
            declarations.append(
                f"abbrev {prefix}TerminatedPost := @generatedTerminatedPost"
            )
        elif control.external_disposition == "protocol":
            declarations.append(
                f"abbrev {prefix}AwaitingExternalPost := "
                "@generatedAwaitingExternalPost"
            )
        elif control.external_disposition == "returns":
            declarations.extend(
                (
                    f"abbrev {prefix}ExternalRunningPost := @generatedRunningPost",
                    f"abbrev {prefix}ExternalCallbackRunningPost := "
                    "@generatedCallbackRunningPost",
                )
            )
    elif control.kind == "indirect_call":
        declarations.append(
            f"abbrev {prefix}IndirectCallControl := "
            f"@generatedIndirectCallControl {target.target_id}"
        )
    elif control.kind == "indirect_jump":
        declarations.append(
            f"abbrev {prefix}IndirectJumpControl := "
            f"@generatedIndirectJumpControl {target.target_id}"
        )
    elif control.kind == "termination":
        declarations.append(
            f"abbrev {prefix}TerminatedPost := @generatedTerminatedPost"
        )
    return "\n\n".join(declarations)


def _aggregate_source(shards: Sequence[str]) -> str:
    return "\n".join(f"import StageA.{module}" for module in shards) + "\n"


def _audit_source(targets: Sequence[ClassifiedTarget]) -> str:
    lines = [f"import StageA.{_MODULE_PREFIX}", ""]
    for item in targets:
        prefix = f"{_NAMESPACE}.generatedTarget{item.effect.target_id}"
        lines.extend(
            (
                f"#print axioms {prefix}CheckedTransition",
                f"#print axioms {prefix}ReachabilityPost",
                f"#print axioms {prefix}CallFramePost",
                f"#print axioms {prefix}CallbackRunningPost",
            )
        )
    return "\n".join(lines) + "\n"


def _declaration_row(
    item: ClassifiedTarget, shard_index: int
) -> dict[str, Any]:
    target = item.effect
    prefix = f"{_NAMESPACE}.generatedTarget{target.target_id}"
    row: dict[str, Any] = {
        "target_id": target.target_id,
        "source_rva": target.source_rva,
        "semantic_kind": target.kind,
        "control_class": item.control.key,
        "fault_capable": item.control.fault_capable,
        "module": f"StageA.{_MODULE_PREFIX}Shard{shard_index:04d}",
        "checked_transition": f"{prefix}CheckedTransition",
        "reachability_post": f"{prefix}ReachabilityPost",
        "call_frame_post": f"{prefix}CallFramePost",
        "running_post": f"{prefix}RunningPost",
        "callback_running_post": f"{prefix}CallbackRunningPost",
        "fault_post": f"{prefix}FaultPost",
    }
    if item.blocker is not None:
        row["blocker_reason"] = item.blocker["reason_code"]
    return row


def _transition_aggregate_module(transition: Mapping[str, Any]) -> str:
    modules = [
        _module_name(value, "transition modules[]")
        for value in _list(transition.get("modules"), "transition modules")
    ]
    candidates = [module for module in modules if not module.endswith("Data") and "Shard" not in module]
    if len(candidates) != 1:
        raise OriginalTargetControlEvidenceError(
            "transition index must name exactly one aggregate module"
        )
    return candidates[0]


def _state_machine_rows(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise OriginalTargetControlEvidenceError(
            f"cannot read state machine: {error}"
        ) from error
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = _object(json.loads(line), f"state-machine line {line_number}")
        except json.JSONDecodeError as error:
            raise OriginalTargetControlEvidenceError(
                f"state-machine line {line_number} is invalid JSON: {error}"
            ) from error
        row_format = row.get("stage_b_format")
        if row_format is not None and row_format != _STATE_MACHINE_FORMAT:
            raise OriginalTargetControlEvidenceError(
                f"state-machine line {line_number} has unsupported format"
            )
        rows.append(row)
    if not rows:
        raise OriginalTargetControlEvidenceError("state machine must not be empty")
    return rows


def _remove_stale_outputs(root: Path) -> None:
    for name in (_MANIFEST_NAME, _DECLARATIONS_NAME, _BLOCKERS_NAME):
        path = root / name
        if path.exists():
            path.unlink()
    stage_a = root / "StageA"
    if stage_a.is_dir():
        for path in stage_a.glob(f"{_MODULE_PREFIX}*.lean"):
            path.unlink()


def _module_name(value: object, label: str) -> str:
    result = _string(value, label)
    if not result.startswith("StageA."):
        result = f"StageA.{result}"
    if _MODULE.fullmatch(result) is None:
        raise OriginalTargetControlEvidenceError(
            f"{label} must be a canonical StageA module"
        )
    return result


def _identifier(value: object, label: str) -> str:
    result = _string(value, label)
    if _IDENTIFIER.fullmatch(result) is None:
        raise OriginalTargetControlEvidenceError(
            f"{label} must be a canonical Lean identifier"
        )
    return result


def _local(value: object, label: str) -> str:
    result = _string(value, label)
    if _LOCAL.fullmatch(result) is None:
        raise OriginalTargetControlEvidenceError(
            f"{label} must be a local Lean identifier"
        )
    return result


def _imports(modules: Sequence[str] | set[str]) -> str:
    return "\n".join(f"import {module}" for module in sorted(set(modules)))


def _camel(value: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in value.split("_"))


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OriginalTargetControlEvidenceError(
            f"cannot read {label}: {error}"
        ) from error


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise OriginalTargetControlEvidenceError(
            f"cannot hash input {path}: {error}"
        ) from error


def _write_ascii(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="ascii")


def _write_json(path: Path, value: object) -> None:
    _write_ascii(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _require_format(document: Mapping[str, Any], expected: str, label: str) -> None:
    if document.get("format") != expected:
        raise OriginalTargetControlEvidenceError(f"{label} has unsupported format")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OriginalTargetControlEvidenceError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise OriginalTargetControlEvidenceError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OriginalTargetControlEvidenceError(
            f"{label} must be a nonempty string"
        )
    return value


def _natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OriginalTargetControlEvidenceError(
            f"{label} must be a natural number"
        )
    return value


def _positive(value: object, label: str) -> int:
    result = _natural(value, label)
    if result == 0:
        raise OriginalTargetControlEvidenceError(f"{label} must be positive")
    return result


def _word(value: object, label: str) -> int:
    result = _natural(value, label)
    if result > 0xFFFFFFFF:
        raise OriginalTargetControlEvidenceError(
            f"{label} must fit in a 32-bit word"
        )
    return result


def _digest(value: object, label: str) -> str:
    result = _string(value, label)
    if _SHA256.fullmatch(result) is None:
        raise OriginalTargetControlEvidenceError(
            f"{label} must be a SHA-256 digest"
        )
    return result


__all__ = [
    "ORIGINAL_TARGET_CONTROL_BLOCKERS_FORMAT",
    "ORIGINAL_TARGET_CONTROL_DECLARATIONS_FORMAT",
    "ORIGINAL_TARGET_CONTROL_EVIDENCE_FORMAT",
    "GeneratedOriginalTargetControlEvidence",
    "OriginalTargetControlEvidenceError",
    "generate_original_target_control_evidence",
]
