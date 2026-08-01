"""Assemble checked GNU hello source-target effect certificates.

This module deliberately does not infer proof authority from JSON status fields.
It binds one canonical state-machine generation to the generated source,
normalization, semantic-refinement, x87, and original-carrier Lean sources.  A
separate declaration inventory must name every remaining universal proof fact.
Lean then checks the generated structure constructors against those facts.

The distinction is important.  Exact normalization and fused-machine
refinement are conditional theorems; alone they do not prove that the decoded
evaluator succeeds for every state/call stack.  Ordinary targets therefore
provide one ``ExactOrdinaryTargetSemanticReplay`` builder.  Lean derives the
decoded evaluator, total source step, control-kind equality, and machine-state
equality from that full-effect replay instead of coordinating separate dynamic
claims.  Exact singleton x87 schedules export their checked singleton facts
next to the exact replay witness; the generic x87 machine theorem supplies
total input validity.  Missing facts are reported as an explicit frontier and
never replaced by generated axioms, report statuses, or assumed target effects.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ...errors import StageAInputError
from .gnu_hello_source_transition_index import (
    GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT,
    LeanDeclaration,
)
from .interpreter_normalization import _ordinary_items, is_x87_row


GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT = (
    "stage-a-gnu-hello-source-target-effect-inputs-v1"
)
GNU_HELLO_SOURCE_TARGET_EFFECTS_FORMAT = (
    "stage-a-gnu-hello-source-target-effects-v1"
)
GNU_HELLO_SOURCE_TARGET_EFFECTS_FRONTIER_FORMAT = (
    "stage-a-gnu-hello-source-target-effects-frontier-v1"
)
GNU_HELLO_SOURCE_TARGET_EFFECTS_MODULE_PREFIX = (
    "GeneratedGnuHelloSourceTargetEffects"
)
GNU_HELLO_SOURCE_TARGET_EFFECTS_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloSourceTargetEffects"
)

_MIXED_FORMAT = "stage-a-interpreter-mixed-original-v1"
_PHASE_FORMAT = "stage-a-relational-phase-v1"
_NORMALIZATION_MODULE_FORMAT = "stage-a-relational-interpreter-normalization-v1"
_SEMANTIC_FORMAT = "stage-a-relational-interpreter-semantic-refinement-v2"
_X87_MODULE_FORMAT = "stage-a-relational-interpreter-x87-module-inventory-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DECLARATION = re.compile(
    r"^\s*(?:noncomputable\s+)?(?:abbrev|axiom|def|opaque|theorem)\s+"
    r"([A-Za-z_][A-Za-z0-9_']*)\b",
    re.MULTILINE,
)


class GnuHelloSourceTargetEffectsError(StageAInputError):
    """The requested target-effect authority is absent or inconsistent."""


@dataclass(frozen=True)
class ArtifactSet:
    state_machine: Path
    mixed_plan: Path
    source_program_root: Path
    source_program_manifest: Path
    normalization_root: Path
    normalization_inventory: Path
    semantic_refinement_root: Path
    semantic_refinement_inventory: Path
    x87_root: Path
    x87_inventory: Path
    exact_original_root: Path


@dataclass(frozen=True)
class GeneratedSourceTargetEffects:
    modules: tuple[Path, ...]
    declaration_inventory: Path
    manifest: Path
    frontier: Path
    target_count: int
    ordinary_count: int
    x87_count: int


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GnuHelloSourceTargetEffectsError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloSourceTargetEffectsError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloSourceTargetEffectsError(
            f"{label} must be a non-empty string"
        )
    return value


def _natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloSourceTargetEffectsError(
            f"{label} must be a non-negative integer"
        )
    return value


def _exact_keys(row: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(row)
    if actual != expected:
        raise GnuHelloSourceTargetEffectsError(
            f"{label} fields differ (missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)})"
        )


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloSourceTargetEffectsError(
            f"cannot read {label}: {error}"
        ) from error


def _read_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                rows.append(_object(json.loads(line), f"state-machine line {line_number}"))
            except json.JSONDecodeError as error:
                raise GnuHelloSourceTargetEffectsError(
                    f"state-machine line {line_number} is invalid JSON: {error}"
                ) from error
    except (OSError, UnicodeError) as error:
        raise GnuHelloSourceTargetEffectsError(
            f"cannot read state machine: {error}"
        ) from error
    if not rows:
        raise GnuHelloSourceTargetEffectsError("state machine must not be empty")
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root_module_hashes(root: Path) -> dict[str, str]:
    stage_a = root / "StageA"
    if not stage_a.is_dir():
        raise GnuHelloSourceTargetEffectsError(
            f"Lean artifact root {root} has no StageA directory"
        )
    modules: dict[str, str] = {}
    for source in sorted(stage_a.rglob("*.lean")):
        relative = source.relative_to(root).with_suffix("")
        module = ".".join(relative.parts)
        if module in modules:
            raise GnuHelloSourceTargetEffectsError(
                f"Lean artifact root {root} contains duplicate module {module}"
            )
        modules[module] = _sha256(source)
    if not modules:
        raise GnuHelloSourceTargetEffectsError(
            f"Lean artifact root {root} contains no Lean modules"
        )
    return modules


def _artifact_bindings(artifacts: ArtifactSet) -> dict[str, Any]:
    """Return the complete deterministic identity of all authority inputs."""

    file_fields = (
        "state_machine",
        "mixed_plan",
        "source_program_manifest",
        "normalization_inventory",
        "semantic_refinement_inventory",
        "x87_inventory",
    )
    root_fields = (
        "source_program_root",
        "normalization_root",
        "semantic_refinement_root",
        "x87_root",
        "exact_original_root",
    )
    return {
        "files": {
            name: _sha256(getattr(artifacts, name)) for name in file_fields
        },
        "lean_modules": {
            name: _root_module_hashes(getattr(artifacts, name))
            for name in root_fields
        },
    }


def _decl(value: object, label: str) -> LeanDeclaration:
    try:
        return LeanDeclaration.from_json(value, label)
    except StageAInputError as error:
        raise GnuHelloSourceTargetEffectsError(str(error)) from error


def _decl_json(value: LeanDeclaration) -> dict[str, str]:
    return {"module": value.module, "declaration": value.declaration}


def _phase_hash(manifest: Mapping[str, Any], label: str) -> str:
    inputs = _object(manifest.get("inputs"), f"{label}.inputs")
    machine = _object(inputs.get("state_machine"), f"{label}.inputs.state_machine")
    digest = _string(machine.get("sha256"), f"{label} state-machine hash")
    if _SHA256.fullmatch(digest) is None:
        raise GnuHelloSourceTargetEffectsError(
            f"{label} state-machine hash is not canonical SHA-256"
        )
    return digest


def _module_names(inventory: Mapping[str, Any], label: str) -> list[str]:
    modules = inventory.get("modules")
    if isinstance(modules, dict):
        names = sorted(modules)
    elif isinstance(modules, list):
        names = sorted(_string(item, f"{label}.modules[]") for item in modules)
    else:
        raise GnuHelloSourceTargetEffectsError(
            f"{label}.modules must be an object or list"
        )
    if len(set(names)) != len(names):
        raise GnuHelloSourceTargetEffectsError(f"{label} module names are duplicated")
    return names


def _module_path(root: Path, module: str) -> Path:
    if not module.startswith("StageA."):
        module = f"StageA.{module}"
    return root / (module.replace(".", "/") + ".lean")


def _validate_module_sources(
    root: Path, inventory: Mapping[str, Any], label: str
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    metadata = inventory.get("modules")
    for name in _module_names(inventory, label):
        canonical = name if name.startswith("StageA.") else f"StageA.{name}"
        source = _module_path(root, canonical)
        if not source.is_file():
            raise GnuHelloSourceTargetEffectsError(
                f"{label} is missing source for {canonical}"
            )
        raw = source.read_bytes()
        if isinstance(metadata, dict):
            row = _object(metadata[name], f"{label}.modules.{name}")
            expected = row.get("source_sha256")
            if expected is not None:
                expected = _string(expected, f"{label}.{name}.source_sha256")
                if hashlib.sha256(raw).hexdigest() != expected:
                    raise GnuHelloSourceTargetEffectsError(
                        f"{label} source hash differs for {canonical}"
                    )
        text = raw.decode("utf-8")
        result[canonical] = set(_DECLARATION.findall(text))
    return result


def _declaration_present(
    declaration: LeanDeclaration,
    declaration_sets: Iterable[Mapping[str, set[str]]],
) -> bool:
    local = declaration.declaration.rsplit(".", 1)[-1]
    return any(local in declarations.get(declaration.module, set()) for declarations in declaration_sets)


def _require_declaration(
    declaration: LeanDeclaration,
    declaration_sets: Iterable[Mapping[str, set[str]]],
    label: str,
) -> None:
    if not _declaration_present(declaration, declaration_sets):
        raise GnuHelloSourceTargetEffectsError(
            f"{label} declaration {declaration.declaration} is absent from "
            f"{declaration.module}"
        )


def _source_declaration(module: str, name: str) -> LeanDeclaration:
    return LeanDeclaration(module=module, declaration=f"{module}.{name}")


def _find_generated_declaration(
    declarations: Mapping[str, set[str]], name: str, label: str
) -> LeanDeclaration:
    modules = sorted(
        module for module, names in declarations.items() if name in names
    )
    if len(modules) != 1:
        raise GnuHelloSourceTargetEffectsError(
            f"{label} declaration {name} must occur in exactly one generated "
            f"module (found={modules})"
        )
    return _source_declaration(modules[0], name)


def _validate_artifacts(
    artifacts: ArtifactSet,
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    dict[int, tuple[str, int]],
    tuple[dict[str, set[str]], ...],
]:
    rows = _read_rows(artifacts.state_machine)
    machine_hash = _sha256(artifacts.state_machine)
    mixed = _load_json(artifacts.mixed_plan, "mixed-original plan")
    source_manifest = _load_json(
        artifacts.source_program_manifest, "source-program manifest"
    )
    normalization = _load_json(
        artifacts.normalization_inventory, "normalization module inventory"
    )
    semantic = _load_json(
        artifacts.semantic_refinement_inventory,
        "semantic-refinement inventory",
    )
    x87 = _load_json(artifacts.x87_inventory, "x87 module inventory")

    if mixed.get("format") != _MIXED_FORMAT:
        raise GnuHelloSourceTargetEffectsError(
            "mixed-original plan has unsupported format"
        )
    if source_manifest.get("format") != _PHASE_FORMAT or source_manifest.get(
        "phase"
    ) != "semantic-program-lean":
        raise GnuHelloSourceTargetEffectsError(
            "source-program manifest has unsupported format or phase"
        )
    if normalization.get("format") != _NORMALIZATION_MODULE_FORMAT:
        raise GnuHelloSourceTargetEffectsError(
            "normalization module inventory has unsupported format"
        )
    if semantic.get("format") != _SEMANTIC_FORMAT:
        raise GnuHelloSourceTargetEffectsError(
            "semantic-refinement inventory has unsupported format"
        )
    if x87.get("format") != _X87_MODULE_FORMAT:
        raise GnuHelloSourceTargetEffectsError(
            "x87 module inventory has unsupported format"
        )

    hashes = {
        machine_hash,
        _string(mixed.get("state_machine_sha256"), "mixed state-machine hash"),
        _phase_hash(source_manifest, "source-program manifest"),
    }
    for root, label, phase in (
        (artifacts.normalization_root, "normalization", "normalization-lean"),
        (
            artifacts.semantic_refinement_root,
            "semantic refinement",
            "semantic-refinement-lean",
        ),
        (artifacts.x87_root, "x87", "x87-lean"),
    ):
        phase_manifest = _load_json(root / "phase-manifest.json", f"{label} phase manifest")
        if phase_manifest.get("format") != _PHASE_FORMAT or phase_manifest.get(
            "phase"
        ) != phase:
            raise GnuHelloSourceTargetEffectsError(
                f"{label} phase manifest has unsupported format or phase"
            )
        hashes.add(_phase_hash(phase_manifest, f"{label} phase manifest"))
    if len(hashes) != 1:
        raise GnuHelloSourceTargetEffectsError(
            "source, normalization, refinement, x87, and mixed artifacts "
            "come from different state machines"
        )

    try:
        ordinary_items = _ordinary_items(rows)
    except StageAInputError as error:
        raise GnuHelloSourceTargetEffectsError(str(error)) from error
    ordinary_by_rva = {
        item["start"]: index for index, item in ordinary_items
    }
    x87_rows = sorted(
        (row for row in rows if is_x87_row(row)),
        key=lambda row: (
            _natural(_object(row.get("original"), "x87 original").get("rva_start"), "x87 rva_start"),
            _string(row.get("id"), "x87 id"),
        ),
    )
    x87_by_rva = {
        _natural(_object(row["original"], "x87 original")["rva_start"], "x87 rva_start"): index
        for index, row in enumerate(x87_rows)
    }
    if len(x87_by_rva) != len(x87_rows):
        raise GnuHelloSourceTargetEffectsError("x87 source RVAs are duplicated")

    counts = _object(source_manifest.get("counts"), "source-program counts")
    observed_counts = (
        len(rows),
        len(ordinary_items),
        len(x87_rows),
    )
    declared_counts = (
        _natural(counts.get("transfers"), "counts.transfers"),
        _natural(counts.get("ordinary_transfers"), "counts.ordinary_transfers"),
        _natural(counts.get("x87_transfers"), "counts.x87_transfers"),
    )
    if observed_counts != declared_counts:
        raise GnuHelloSourceTargetEffectsError(
            "source-program counts differ from the state-machine partition"
        )

    source_modules = _validate_module_sources(
        artifacts.source_program_root,
        {"modules": source_manifest.get("modules", [])},
        "source program",
    )
    normalization_modules = _validate_module_sources(
        artifacts.normalization_root, normalization, "normalization"
    )
    semantic_modules = _validate_module_sources(
        artifacts.semantic_refinement_root, semantic, "semantic refinement"
    )
    x87_modules = _validate_module_sources(artifacts.x87_root, x87, "x87")

    target_kinds: dict[int, tuple[str, int]] = {}
    raw_targets = _array(mixed.get("reachable_target_ids"), "reachable_target_ids")
    target_ids = tuple(_natural(value, "reachable_target_ids[]") for value in raw_targets)
    if target_ids != tuple(sorted(set(target_ids))):
        raise GnuHelloSourceTargetEffectsError(
            "reachable target identifiers must be sorted and unique"
        )
    # The target-to-RVA correspondence is supplied by exact carrier facts.  It
    # is checked against these two complete state-machine partitions after the
    # authority inventory is parsed.
    return (
        rows,
        mixed,
        target_kinds,
        (source_modules, normalization_modules, semantic_modules, x87_modules),
    )


_BASE_DECLARATION_FIELDS = (
    "world_program",
    "original_pe",
    "original_side",
    "original_pe_exact",
    "source_program_constructor",
    "instruction_semantics_adequate",
    "exact_binding_constructor",
    "target_inventory",
    "target_inventory_unique",
    "submitted_target_ids_exact",
)

_ORDINARY_STATIC_FIELDS = (
    "source_exact",
    "classification_exact",
    "record_lookup_exact",
    "region_exact",
    "path_record_exact",
    "path_source_exact",
    "region_start_exact",
    "region_stop_exact",
    "non_x87",
    "record_member",
    "not_x87",
)

_ORDINARY_DYNAMIC_FIELDS = ("semantic_replay",)

_X87_FIELDS = (
    "source_rva_exact",
    "classification_exact",
    "classified",
    "partition",
    "witness_member",
    "region",
    "region_exact",
    "region_span_exact",
    "source_continuation_exact",
    "decoded_continuation_exact",
)


def _parse_authority(
    path: Path,
    mixed: Mapping[str, Any],
    rows: list[dict[str, Any]],
    declaration_sets: tuple[dict[str, set[str]], ...],
    expected_artifact_bindings: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, set[str]]]:
    authority = _load_json(path, "source-target effect authority")
    expected = {
        "format",
        "imports",
        "namespace",
        "module_prefix",
        "shard_span",
        "artifact_bindings",
        "authority_modules",
        *_BASE_DECLARATION_FIELDS,
        "targets",
    }
    _exact_keys(authority, expected, "source-target effect authority")
    if authority.get("format") != GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT:
        raise GnuHelloSourceTargetEffectsError(
            "source-target effect authority has unsupported format"
        )
    namespace = _string(authority["namespace"], "authority.namespace")
    module_prefix = _string(authority["module_prefix"], "authority.module_prefix")
    if namespace != GNU_HELLO_SOURCE_TARGET_EFFECTS_NAMESPACE:
        raise GnuHelloSourceTargetEffectsError(
            "source-target effect authority namespace differs from the stable namespace"
        )
    if module_prefix != GNU_HELLO_SOURCE_TARGET_EFFECTS_MODULE_PREFIX:
        raise GnuHelloSourceTargetEffectsError(
            "source-target effect authority module prefix differs from the stable prefix"
        )
    if _natural(authority["shard_span"], "authority.shard_span") == 0:
        raise GnuHelloSourceTargetEffectsError("authority.shard_span must be positive")
    if authority["artifact_bindings"] != expected_artifact_bindings:
        raise GnuHelloSourceTargetEffectsError(
            "source-target effect authority artifact bindings differ from the "
            "exact generated inputs"
        )

    exact_modules = sorted(
        {
            _string(value, "authority.imports[]")
            for value in _array(authority["imports"], "authority.imports")
        }
    )
    authority_modules = _object(
        authority["authority_modules"], "authority.authority_modules"
    )
    if set(authority_modules) != set(exact_modules):
        raise GnuHelloSourceTargetEffectsError(
            "source-target authority module hashes must exactly cover imports"
        )
    for module in exact_modules:
        digest = _string(
            authority_modules[module], f"authority.authority_modules.{module}"
        )
        if _SHA256.fullmatch(digest) is None:
            raise GnuHelloSourceTargetEffectsError(
                f"authority module hash for {module} is not canonical SHA-256"
            )
        source = _module_path(path.parent, module)
        if not source.is_file() or _sha256(source) != digest:
            raise GnuHelloSourceTargetEffectsError(
                f"source-target authority module hash differs for {module}"
            )
    exact_inventory = {"modules": exact_modules}
    exact_declarations = _validate_module_sources(
        path.parent, exact_inventory, "source-target effect authority"
    )
    all_sets = (*declaration_sets, exact_declarations)
    for field in _BASE_DECLARATION_FIELDS:
        declaration = _decl(authority[field], f"authority.{field}")
        _require_declaration(declaration, all_sets, f"authority.{field}")

    try:
        ordinary = _ordinary_items(rows)
    except StageAInputError as error:
        raise GnuHelloSourceTargetEffectsError(str(error)) from error
    ordinary_by_rva = {item["start"]: index for index, item in ordinary}
    x87_sorted = sorted(
        (row for row in rows if is_x87_row(row)),
        key=lambda row: (
            int(_object(row["original"], "x87 original")["rva_start"]),
            str(row["id"]),
        ),
    )
    x87_by_rva = {
        int(_object(row["original"], "x87 original")["rva_start"]): index
        for index, row in enumerate(x87_sorted)
    }
    reachable = tuple(
        _natural(value, "reachable_target_ids[]")
        for value in _array(mixed["reachable_target_ids"], "reachable_target_ids")
    )
    parsed_targets: list[dict[str, Any]] = []
    for position, raw in enumerate(_array(authority["targets"], "authority.targets")):
        target = _object(raw, f"authority.targets[{position}]")
        _exact_keys(
            target,
            {"target_id", "source_rva", "kind", "evidence"},
            f"authority.targets[{position}]",
        )
        target_id = _natural(target["target_id"], f"targets[{position}].target_id")
        source_rva = _natural(target["source_rva"], f"targets[{position}].source_rva")
        kind = _string(target["kind"], f"targets[{position}].kind")
        evidence = _object(target["evidence"], f"targets[{position}].evidence")
        if kind == "ordinary":
            _exact_keys(
                evidence,
                {"region", "static", "dynamic"},
                f"targets[{position}].evidence",
            )
            if source_rva not in ordinary_by_rva:
                raise GnuHelloSourceTargetEffectsError(
                    f"ordinary target {target_id} RVA {source_rva} is absent from "
                    "the ordinary state-machine partition"
                )
            static = _object(evidence["static"], f"target {target_id} static evidence")
            dynamic = _object(evidence["dynamic"], f"target {target_id} dynamic evidence")
            _exact_keys(static, set(_ORDINARY_STATIC_FIELDS), f"target {target_id} static evidence")
            _exact_keys(dynamic, set(_ORDINARY_DYNAMIC_FIELDS), f"target {target_id} dynamic evidence")
            declarations = {
                "region": _decl(evidence["region"], f"target {target_id}.region"),
                **{
                    name: _decl(static[name], f"target {target_id}.static.{name}")
                    for name in _ORDINARY_STATIC_FIELDS
                },
                **{
                    name: _decl(dynamic[name], f"target {target_id}.dynamic.{name}")
                    for name in _ORDINARY_DYNAMIC_FIELDS
                },
            }
            ordinary_index = ordinary_by_rva[source_rva]
            source_modules, normalization_modules, semantic_modules, _ = declaration_sets
            generated_dependencies = (
                _find_generated_declaration(
                    source_modules,
                    f"semanticInterpreterProgramRecord{ordinary_index}",
                    f"target {target_id} source record",
                ),
                _find_generated_declaration(
                    source_modules,
                    f"semanticInterpreterTransfer{ordinary_index}",
                    f"target {target_id} source transfer",
                ),
                _find_generated_declaration(
                    normalization_modules,
                    f"exactNormalizedTransferPath{ordinary_index}",
                    f"target {target_id} normalization path",
                ),
                _find_generated_declaration(
                    normalization_modules,
                    f"exactNormalizedTransferPath{ordinary_index}Certificate",
                    f"target {target_id} normalization certificate",
                ),
            )
            for declaration in (*declarations.values(), *generated_dependencies):
                _require_declaration(declaration, all_sets, f"target {target_id}")
            parsed_targets.append(
                {
                    "target_id": target_id,
                    "source_rva": source_rva,
                    "kind": kind,
                    "ordinary_index": ordinary_index,
                    "declarations": declarations,
                    "dependencies": generated_dependencies,
                }
            )
        elif kind == "x87":
            _exact_keys(
                evidence,
                {"continuation_target_id", *_X87_FIELDS},
                f"target {target_id} x87 evidence",
            )
            if source_rva not in x87_by_rva:
                raise GnuHelloSourceTargetEffectsError(
                    f"x87 target {target_id} RVA {source_rva} is absent from "
                    "the x87 state-machine partition"
                )
            x87_index = x87_by_rva[source_rva]
            witness = _find_generated_declaration(
                declaration_sets[3],
                f"checkedInterpreterX87Schedule{x87_index:04d}Witness",
                f"target {target_id} x87 schedule witness",
            )
            schedule_facts = _find_generated_declaration(
                declaration_sets[3],
                f"checkedInterpreterX87Schedule{x87_index:04d}SingletonFacts",
                f"target {target_id} x87 singleton facts",
            )
            declarations = {
                name: _decl(evidence[name], f"target {target_id}.x87.{name}")
                for name in _X87_FIELDS
            }
            for declaration in (*declarations.values(), witness, schedule_facts):
                _require_declaration(declaration, all_sets, f"target {target_id}")
            parsed_targets.append(
                {
                    "target_id": target_id,
                    "source_rva": source_rva,
                    "kind": kind,
                    "x87_index": x87_index,
                    "continuation_target_id": _natural(
                        evidence["continuation_target_id"],
                        f"target {target_id}.continuation_target_id",
                    ),
                    "declarations": declarations,
                    "witness": witness,
                    "schedule_facts": schedule_facts,
                }
            )
        else:
            raise GnuHelloSourceTargetEffectsError(
                f"target {target_id} kind must be ordinary or x87"
            )

    target_ids = tuple(target["target_id"] for target in parsed_targets)
    if target_ids != reachable:
        missing = sorted(set(reachable) - set(target_ids))
        unexpected = sorted(set(target_ids) - set(reachable))
        raise GnuHelloSourceTargetEffectsError(
            "target-effect authority must cover every reachable target "
            f"(missing={missing}, unexpected={unexpected})"
        )
    if len({target["source_rva"] for target in parsed_targets}) != len(parsed_targets):
        raise GnuHelloSourceTargetEffectsError(
            "target-effect authority contains duplicate source RVAs"
        )
    return authority, parsed_targets, exact_declarations


def inspect_gnu_hello_source_target_effect_frontier(
    *,
    state_machine: Path | str,
    mixed_original_plan: Path | str,
    source_program_root: Path | str,
    source_program_manifest: Path | str,
    normalization_root: Path | str,
    normalization_inventory: Path | str,
    semantic_refinement_root: Path | str,
    semantic_refinement_inventory: Path | str,
    x87_root: Path | str,
    x87_inventory: Path | str,
    exact_original_root: Path | str,
) -> dict[str, Any]:
    """Report facts not exported by the current generated artifact families."""

    artifacts = ArtifactSet(
        *(Path(value) for value in (
            state_machine,
            mixed_original_plan,
            source_program_root,
            source_program_manifest,
            normalization_root,
            normalization_inventory,
            semantic_refinement_root,
            semantic_refinement_inventory,
            x87_root,
            x87_inventory,
            exact_original_root,
        ))
    )
    rows, mixed, _target_kinds, declaration_sets = _validate_artifacts(artifacts)
    reachable_count = len(_array(mixed["reachable_target_ids"], "reachable_target_ids"))
    ordinary_count = len(_ordinary_items(rows))
    x87_count = sum(is_x87_row(row) for row in rows)
    all_declarations = set().union(*(set().union(*group.values()) for group in declaration_sets))
    ordinary_missing = "ExactOrdinaryTargetSemanticReplay" not in all_declarations
    x87_declarations = set().union(*declaration_sets[3].values())
    x87_missing_count = sum(
        f"checkedInterpreterX87Schedule{index:04d}SingletonFacts"
        not in x87_declarations
        for index in range(x87_count)
    )
    blockers: list[dict[str, Any]] = []
    if ordinary_missing:
        blockers.append(
            {
                "category": "ordinary_total_effect_evidence_missing",
                "affected_state_machine_targets": ordinary_count,
                "required_types": [
                    "ExactOrdinaryTargetSemanticReplay",
                ],
                "reason": (
                    "normalization and fused-machine refinement are conditional; "
                    "the generated sources do not yet package total decoded "
                    "evaluation and exact local effects into one universal replay"
                ),
                "next_action": (
                    "emit one checked ExactOrdinaryTargetSemanticReplay builder "
                    "per exact target; Lean derives evaluator, source-step, "
                    "control-kind, and full-machine projection certificates"
                ),
            }
        )
    if x87_missing_count:
        blockers.append(
            {
                "category": "x87_singleton_schedule_facts_missing",
                "affected_state_machine_targets": x87_missing_count,
                "required_types": ["ExactX87SingletonScheduleFacts"],
                "reason": (
                    "one or more x87 sources do not export singleton "
                    "record/decoder/universal input-validity facts"
                ),
                "next_action": (
                    "extend x87 schedule generation with checked singleton schedule "
                    "facts, including inputValid for every MachineState"
                ),
            }
        )
    return {
        "format": GNU_HELLO_SOURCE_TARGET_EFFECTS_FRONTIER_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "state_machine_sha256": _sha256(artifacts.state_machine),
        "reachable_targets": reachable_count,
        "state_machine_partition": {
            "ordinary": ordinary_count,
            "x87": x87_count,
        },
        "blockers": blockers,
        "ready": not blockers,
    }


def _ordinary_source(target: Mapping[str, Any], namespace: str) -> str:
    target_id = target["target_id"]
    source_rva = target["source_rva"]
    index = target["ordinary_index"]
    declarations: Mapping[str, LeanDeclaration] = target["declarations"]
    record, transfer, path, certificate = target["dependencies"]
    prefix = f"generatedOrdinary{target_id}"
    return f"""abbrev {prefix}Record := {record.declaration}
abbrev {prefix}Transfer := {transfer.declaration}
abbrev {prefix}Path := {path.declaration}

def {prefix}Binding : ExactOrdinaryTargetBinding generatedOriginalPe
    generatedSourceProgram {target_id} {source_rva} {record.declaration}
    {path.declaration} {transfer.declaration} {declarations['region'].declaration} := {{
  originalRole := generatedOriginalSide
  originalPeExact := generatedOriginalPeExact
  sourceExact := {declarations['source_exact'].declaration}
  classificationExact := {declarations['classification_exact'].declaration}
  recordLookupExact := {declarations['record_lookup_exact'].declaration}
  regionExact := {declarations['region_exact'].declaration}
  pathRecordExact := {declarations['path_record_exact'].declaration}
  pathSourceExact := {declarations['path_source_exact'].declaration}
  regionStartExact := {declarations['region_start_exact'].declaration}
  regionStopExact := {declarations['region_stop_exact'].declaration}
  nonX87 := {declarations['non_x87'].declaration}
  normalization := {certificate.declaration}
}}

def {prefix}Replay :
    ExactOrdinaryTargetSemanticReplay {prefix}Binding :=
  {declarations['semantic_replay'].declaration} {prefix}Binding

abbrev {prefix}Decoded :
    ExactDecodedOrdinaryTargetEvaluator {prefix}Binding :=
  {prefix}Replay.decoded

def {prefix}CheckedEffect :
    CheckedOrdinaryTargetEffect {prefix}Binding {prefix}Decoded :=
  {prefix}Replay.toCheckedOrdinaryTargetEffect

theorem {prefix}RecordMember :
    List.Mem {record.declaration} generatedSourceProgram.records :=
  {declarations['record_member'].declaration}

theorem {prefix}NotX87 :
    Not (List.Mem {source_rva} generatedSourceProgram.x87SourceRvas) :=
  {declarations['not_x87'].declaration}
"""


def _x87_source(target: Mapping[str, Any], namespace: str) -> str:
    target_id = target["target_id"]
    declarations: Mapping[str, LeanDeclaration] = target["declarations"]
    witness: LeanDeclaration = target["witness"]
    schedule_facts: LeanDeclaration = target["schedule_facts"]
    prefix = f"generatedX87{target_id}"
    return f"""abbrev {prefix}Witness := {witness.declaration}

def {prefix}ScheduleFacts :
    ExactX87SingletonScheduleFacts generatedOriginalPe {witness.declaration} :=
  {schedule_facts.declaration}

def {prefix}Facts : ExactX87SingletonTargetFacts generatedOriginalPe
    generatedSourceProgram {target_id} {witness.declaration}
    {prefix}ScheduleFacts := {{
  originalSide := generatedOriginalSide
  originalPeExact := generatedOriginalPeExact
  sourceRvaExact := {declarations['source_rva_exact'].declaration}
  classificationExact := {declarations['classification_exact'].declaration}
  classified := {declarations['classified'].declaration}
  partition := {declarations['partition'].declaration}
  witnessMember := {declarations['witness_member'].declaration}
  region := {declarations['region'].declaration}
  regionExact := {declarations['region_exact'].declaration}
  regionSpanExact := {declarations['region_span_exact'].declaration}
  continuationTargetId := {target['continuation_target_id']}
  sourceContinuationExact :=
    {declarations['source_continuation_exact'].declaration}
  decodedContinuationExact :=
    {declarations['decoded_continuation_exact'].declaration}
}}

def {prefix}SuccessfulComponents :
    SuccessfulTargetEffectComponents generatedSourceProgram {target_id} :=
  {prefix}Facts.toSuccessfulTargetEffectComponents
"""


def _target_imports(target: Mapping[str, Any]) -> set[str]:
    imports = {declaration.module for declaration in target["declarations"].values()}
    if target["kind"] == "ordinary":
        imports.update(declaration.module for declaration in target["dependencies"])
    else:
        imports.add(target["witness"].module)
        imports.add(target["schedule_facts"].module)
    return imports


def generate_gnu_hello_source_target_effects(
    out: Path | str,
    *,
    state_machine: Path | str,
    mixed_original_plan: Path | str,
    source_program_root: Path | str,
    source_program_manifest: Path | str,
    normalization_root: Path | str,
    normalization_inventory: Path | str,
    semantic_refinement_root: Path | str,
    semantic_refinement_inventory: Path | str,
    x87_root: Path | str,
    x87_inventory: Path | str,
    exact_original_root: Path | str,
    authority_inventory: Path | str,
) -> GeneratedSourceTargetEffects:
    artifacts = ArtifactSet(
        *(Path(value) for value in (
            state_machine,
            mixed_original_plan,
            source_program_root,
            source_program_manifest,
            normalization_root,
            normalization_inventory,
            semantic_refinement_root,
            semantic_refinement_inventory,
            x87_root,
            x87_inventory,
            exact_original_root,
        ))
    )
    rows, mixed, _target_kinds, declaration_sets = _validate_artifacts(artifacts)
    authority, targets, exact_declarations = _parse_authority(
        Path(authority_inventory),
        mixed,
        rows,
        declaration_sets,
        _artifact_bindings(artifacts),
    )
    namespace = authority["namespace"]
    module_prefix = authority["module_prefix"]
    shard_span = authority["shard_span"]
    base = {field: _decl(authority[field], f"authority.{field}") for field in _BASE_DECLARATION_FIELDS}

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    modules: list[Path] = []
    data_module = f"{module_prefix}Data"
    base_imports = sorted({declaration.module for declaration in base.values()})
    data_source = f"""{chr(10).join(f'import {module}' for module in base_imports)}
import StageA.RelationalSourceInterpreterKernel

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel

noncomputable section

abbrev generatedWorldProgram : DecodedWorldProgram :=
  {base['world_program'].declaration}
abbrev generatedOriginalPe : PE32 := {base['original_pe'].declaration}
abbrev generatedSourceProgram : Program :=
  {base['source_program_constructor'].declaration} generatedWorldProgram
theorem generatedOriginalSide : generatedWorldProgram.candidate = false :=
  {base['original_side'].declaration}
theorem generatedOriginalPeExact :
    generatedWorldProgram.context.originalPe = generatedOriginalPe :=
  {base['original_pe_exact'].declaration}

end
end {namespace}
"""
    data_path = stage_a / f"{data_module}.lean"
    data_path.write_text(data_source, encoding="ascii")
    modules.append(data_path)

    buckets: dict[int, list[dict[str, Any]]] = {}
    for target in targets:
        buckets.setdefault(target["target_id"] // shard_span, []).append(target)
    target_modules: dict[int, str] = {}
    for bucket, members in sorted(buckets.items()):
        module = f"{module_prefix}Shard{bucket:06d}"
        imports = sorted({item for target in members for item in _target_imports(target)})
        body = "\n\n".join(
            _ordinary_source(target, namespace)
            if target["kind"] == "ordinary"
            else _x87_source(target, namespace)
            for target in members
        )
        source = f"""import StageA.{data_module}
{chr(10).join(f'import {item}' for item in imports)}
import StageA.RelationalSourceOrdinaryTargetRouting
import StageA.RelationalSourceX87TargetRouting

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

noncomputable section

{body}
end
end {namespace}
"""
        path = stage_a / f"{module}.lean"
        path.write_text(source, encoding="ascii")
        modules.append(path)
        for target in members:
            target_modules[target["target_id"]] = f"StageA.{module}"

    declarations_targets: list[dict[str, Any]] = []
    for target in targets:
        target_id = target["target_id"]
        module = target_modules[target_id]
        if target["kind"] == "ordinary":
            prefix = f"{namespace}.generatedOrdinary{target_id}"
            declarations_targets.append(
                {
                    "target_id": target_id,
                    "source_rva": target["source_rva"],
                    "kind": "ordinary",
                    "evidence": {
                        "binding": {"module": module, "declaration": f"{prefix}Binding"},
                        "checked_effect": {"module": module, "declaration": f"{prefix}CheckedEffect"},
                        "record": {"module": module, "declaration": f"{prefix}Record"},
                        "record_member": {"module": module, "declaration": f"{prefix}RecordMember"},
                        "not_x87": {"module": module, "declaration": f"{prefix}NotX87"},
                    },
                }
            )
        else:
            declarations_targets.append(
                {
                    "target_id": target_id,
                    "source_rva": target["source_rva"],
                    "kind": "x87",
                    "evidence": {
                        "facts": {
                            "module": module,
                            "declaration": f"{namespace}.generatedX87{target_id}Facts",
                        },
                        "successful_components": {
                            "module": module,
                            "declaration": (
                                f"{namespace}.generatedX87{target_id}SuccessfulComponents"
                            ),
                        },
                    },
                }
            )

    declaration_inventory = {
        "format": GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT,
        "imports": sorted(set(authority["imports"])),
        **{field: _decl_json(base[field]) for field in _BASE_DECLARATION_FIELDS},
        "targets": declarations_targets,
        "namespace": "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex",
        "module_prefix": "GeneratedGnuHelloSourceTransitionIndex",
        "shard_span": shard_span,
    }
    declaration_path = root / "source-target-effect-declarations.json"
    declaration_path.write_text(
        json.dumps(declaration_inventory, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )

    frontier_value = {
        "format": GNU_HELLO_SOURCE_TARGET_EFFECTS_FRONTIER_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "ready": True,
        "blockers": [],
        "reachable_targets": len(targets),
    }
    frontier_path = root / "source-target-effects-frontier.json"
    frontier_path.write_text(
        json.dumps(frontier_value, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    input_paths = {
        field: getattr(artifacts, field)
        for field in ArtifactSet.__dataclass_fields__
        if field not in {"source_program_root", "normalization_root", "semantic_refinement_root", "x87_root", "exact_original_root"}
    }
    input_paths["authority_inventory"] = Path(authority_inventory)
    manifest_value = {
        "format": GNU_HELLO_SOURCE_TARGET_EFFECTS_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "validation_required": "lean-kernel-check-and-axiom-audit",
        "state_machine_sha256": _sha256(artifacts.state_machine),
        "inputs": {
            name: {"path": path.name, "sha256": _sha256(path)}
            for name, path in sorted(input_paths.items())
        },
        "modules": [path.stem for path in modules],
        "declaration_inventory": declaration_path.name,
        "frontier": frontier_path.name,
        "counts": {
            "targets": len(targets),
            "ordinary": sum(target["kind"] == "ordinary" for target in targets),
            "x87": sum(target["kind"] == "x87" for target in targets),
            "shards": len(buckets),
        },
    }
    manifest_path = root / "source-target-effects.json"
    manifest_path.write_text(
        json.dumps(manifest_value, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    return GeneratedSourceTargetEffects(
        modules=tuple(modules),
        declaration_inventory=declaration_path,
        manifest=manifest_path,
        frontier=frontier_path,
        target_count=len(targets),
        ordinary_count=sum(target["kind"] == "ordinary" for target in targets),
        x87_count=sum(target["kind"] == "x87" for target in targets),
    )


__all__ = [
    "GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT",
    "GNU_HELLO_SOURCE_TARGET_EFFECTS_FORMAT",
    "GNU_HELLO_SOURCE_TARGET_EFFECTS_FRONTIER_FORMAT",
    "GNU_HELLO_SOURCE_TARGET_EFFECTS_MODULE_PREFIX",
    "GNU_HELLO_SOURCE_TARGET_EFFECTS_NAMESPACE",
    "GeneratedSourceTargetEffects",
    "GnuHelloSourceTargetEffectsError",
    "generate_gnu_hello_source_target_effects",
    "inspect_gnu_hello_source_target_effect_frontier",
]
