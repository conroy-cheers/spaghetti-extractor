from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...stage_b_interpreter_backend import (
    StageBInterpreterError,
    _TransferCompiler,
)
from ...util import sha256_bytes


RELATIONAL_INTERPRETER_NORMALIZATION_FORMAT = (
    "stage-a-relational-interpreter-normalization-v1"
)
RELATIONAL_INTERPRETER_NORMALIZATION_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-normalization-inventory-v1"
)
_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(r"StageA\.([A-Za-z_][A-Za-z0-9_']*)\Z")
_STAGE_A_IMPORT = re.compile(
    r"^import StageA\.([A-Za-z_][A-Za-z0-9_']*)$", re.MULTILINE
)
_SEMANTIC_REFINEMENT_BINDING = re.compile(
    r"semanticRefinement := ([A-Za-z_][A-Za-z0-9_']*)"
)
_WIDTH = {1: "byte", 2: "word", 4: "dword"}
_CALL_KIND = {
    "external_call": "external",
    "internal_call": "internal",
    "indirect_call": "indirect",
}


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a JSON array")
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a natural number")
    return value


def _lean_name(value: str, context: str) -> str:
    if _LEAN_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a qualified Lean identifier")
    return value


def _local_name(value: str, context: str) -> str:
    if _LOCAL_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a local Lean identifier")
    return value


def _stage_a_module(value: str, context: str) -> tuple[str, str]:
    match = _STAGE_A_MODULE.fullmatch(value)
    if match is None:
        raise StageAInputError(
            f"{context} must be a canonical StageA.<module> identifier"
        )
    return value, match.group(1)


def _read_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = dict(_object(json.loads(line), f"state-machine line {line_number}"))
            except json.JSONDecodeError as error:
                raise StageAInputError(
                    f"state-machine line {line_number} is not valid JSON"
                ) from error
            if row.get("stage_b_format") != _STATE_MACHINE_FORMAT:
                raise StageAInputError(
                    f"state-machine line {line_number} has an unsupported format"
                )
            rows.append(row)
    if not rows:
        raise StageAInputError("state machine contains no transfers")
    return rows


def _bytes_literal(value: bytes) -> str:
    return "[" + ", ".join(str(byte) for byte in value) + "]"


def _instruction(raw: object, context: str) -> tuple[int, bytes]:
    instruction = _object(raw, context)
    rva = _nat(instruction.get("rva"), f"{context} rva")
    size = _nat(instruction.get("size"), f"{context} size")
    encoded = instruction.get("bytes")
    if not isinstance(encoded, str) or len(encoded) % 2:
        raise StageAInputError(f"{context} bytes must be even-length hexadecimal")
    try:
        value = bytes.fromhex(encoded)
    except ValueError as error:
        raise StageAInputError(f"{context} bytes must be hexadecimal") from error
    if not value or len(value) != size or size > 15:
        raise StageAInputError(f"{context} size differs from its IA-32 bytes")
    return rva, value


def _validated_row(row: Mapping[str, Any]) -> dict[str, Any]:
    identity = row.get("id")
    if not isinstance(identity, str) or not identity:
        raise StageAInputError("normalization transfer id must be non-empty")
    original = _object(row.get("original"), f"{identity} original span")
    start = _nat(original.get("rva_start"), f"{identity} rva_start")
    stop = _nat(original.get("rva_end"), f"{identity} rva_end")
    size = _nat(original.get("size"), f"{identity} size")
    if start >= stop or stop - start != size:
        raise StageAInputError(f"{identity} original span is inconsistent")
    instructions = [
        _instruction(raw, f"{identity} instruction {index}")
        for index, raw in enumerate(_list(row.get("instructions"), "instructions"))
    ]
    expected = start
    for rva, encoded in instructions:
        if rva != expected:
            raise StageAInputError(f"{identity} instruction partition is not contiguous")
        expected += len(encoded)
    if expected != stop:
        raise StageAInputError(f"{identity} instruction partition does not cover its span")
    digest = row.get("instruction_bytes_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise StageAInputError(f"{identity} instruction digest is not canonical")
    encoded_span = b"".join(encoded for _, encoded in instructions)
    if sha256_bytes(encoded_span) != digest:
        raise StageAInputError(f"{identity} instruction digest differs from exact bytes")
    return {
        "id": identity,
        "start": start,
        "stop": stop,
        "instructions": instructions,
        "row": dict(row),
    }


def _is_x87_row(row: Mapping[str, Any]) -> bool:
    return (
        row.get("fpu_state") is not None
        or row.get("instruction_effect_schedule") is not None
    )


def _terminal(transfer: Any) -> str:
    outcome = transfer.actions[-1]
    args = tuple(outcome.args)
    expected_arity = {
        "outcome_fallthrough": 1,
        "outcome_jump": 1,
        "outcome_branch": 3,
        "outcome_return": 1,
        "outcome_indirect": 1,
        "outcome_external": 0,
    }.get(outcome.op)
    if expected_arity is None:
        raise StageAInputError(f"unsupported normalization terminal {outcome.op!r}")
    if len(args) != expected_arity:
        raise StageAInputError(
            f"normalization terminal {outcome.op!r} requires {expected_arity} "
            f"arguments, observed {len(args)}"
        )
    if outcome.op == "outcome_fallthrough":
        return f".fallthrough {args[0]}"
    if outcome.op == "outcome_jump":
        return f".jump {args[0]}"
    if outcome.op == "outcome_branch":
        return f".branch {args[1]} {args[2]}"
    if outcome.op == "outcome_return":
        return ".returned"
    if outcome.op == "outcome_indirect":
        return ".indirectJump"
    if outcome.op == "outcome_external":
        return ".externalJump"
    raise AssertionError("validated normalization terminal was not rendered")


def _ordinary_items(
    rows: Iterable[Mapping[str, Any]],
) -> list[tuple[int, dict[str, Any]]]:
    """Validate one canonical program inventory and select its ordinary rows.

    Program-record indices are assigned after removing x87 rows, matching
    ``relational_interpreter_program_source``.  Sorting happens only after the
    indices are fixed, so proof sharding is stable without changing those
    bindings.
    """

    validated: list[tuple[Mapping[str, Any], dict[str, Any]]] = []
    identities: set[str] = set()
    source_rvas: set[int] = set()
    for row in rows:
        item = _validated_row(row)
        if item["id"] in identities:
            raise StageAInputError(
                f"normalization transfer id {item['id']!r} is duplicated"
            )
        if item["start"] in source_rvas:
            raise StageAInputError(
                f"normalization source RVA {item['start']} is duplicated"
            )
        identities.add(item["id"])
        source_rvas.add(item["start"])
        validated.append((row, item))

    ordinary_items = [item for row, item in validated if not _is_x87_row(row)]
    ordinary: list[tuple[int, dict[str, Any]]] = []
    for ordinary_index, item in enumerate(ordinary_items):
        try:
            transfer = _TransferCompiler(item["row"]).compile()
            _terminal(transfer)
            _ordered_effects(transfer)
        except (
            StageAInputError,
            StageBInterpreterError,
            IndexError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise StageAInputError(
                f"ordinary normalization transfer {item['id']!r} is unsupported: "
                f"{error}"
            ) from error
        ordinary.append((ordinary_index, item))
    if not ordinary:
        raise StageAInputError("normalization input contains no ordinary transfers")
    ordinary.sort(key=lambda value: (value[1]["start"], value[1]["id"]))
    return ordinary


def _ordered_effects(transfer: Any) -> list[str]:
    effects: list[str] = []
    for action in transfer.actions[:-1]:
        if action.op == "eval_word":
            node = transfer.nodes[action.args[0]]
            if node.op == "load":
                effects.append(f".read .{_WIDTH[node.aux]}")
        elif action.op == "memory_write":
            effects.append(f".write .{_WIDTH[action.aux]}")
        elif action.op == "call":
            call = transfer.calls[action.args[0]]
            effects.append(f".call .{_CALL_KIND[call.kind]}")
        elif action.op == "divide_if":
            effects.append(".divideGuard")
        elif action.op == "rep_movsd":
            effects.append(".repMovsd")
        elif action.op == "rep_stosd":
            effects.append(".repStosd")
    return effects


def _path_definition(
    item: Mapping[str, Any],
    *,
    record_name: str,
    definition_name: str,
) -> str:
    transfer = _TransferCompiler(item["row"]).compile()
    instructions = ",\n".join(
        "      { rva := " + str(rva) + ", bytes := " + _bytes_literal(encoded) + " }"
        for rva, encoded in item["instructions"]
    )
    effects = ", ".join(_ordered_effects(transfer))
    call_boundaries = ",\n  ".join(
        "{ instructionRva := "
        + str(call.instruction_rva)
        + ", callIndex := "
        + str(call.call_index)
        + ", argumentOffsets := [], stackInputs := ["
        + ", ".join(
            "{ offset := " + str(offset) + ", width := ." + _WIDTH[width] + " }"
            for offset, width, _ in call.stack_inputs
        )
        + "] }"
        for call in transfer.calls
    )
    call_boundary_field = (
        f"\n  callBoundaries := [\n  {call_boundaries}\n  ]"
        if call_boundaries
        else ""
    )
    return f"""def {definition_name} : ExactNormalizedTransferPath := {{
  sourceRva := {item['start']}
  stopRva := {item['stop']}
  chunks := [{{
    span := {{ start := {item['start']}, size := {item['stop'] - item['start']} }}
    instructions := [
{instructions}
    ]
  }}]
  terminal := {_terminal(transfer)}
  orderedEffects := [{effects}]
  record := {record_name}
{call_boundary_field}
}}
"""


def relational_interpreter_normalization_source(
    row: Mapping[str, Any],
    *,
    source_module: str,
    pe_name: str,
    record_name: str,
    transfer_name: str,
    definition_name: str = "exactNormalizedTransferPath",
) -> str:
    """Emit immutable checker data, never a semantic theorem or status field."""

    source_module, _ = _stage_a_module(source_module, "source_module")
    pe_name = _lean_name(pe_name, "pe_name")
    record_name = _lean_name(record_name, "record_name")
    transfer_name = _lean_name(transfer_name, "transfer_name")
    definition_name = _local_name(definition_name, "definition_name")
    item = _validated_row(row)
    definition = _path_definition(
        item, record_name=record_name, definition_name=definition_name
    )
    return f"""import StageA.RelationalInterpreterNormalization
import {source_module}

namespace StageA.GeneratedRelational

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization

{definition}
def {definition_name}ExpectedTransfer : SemanticTransfer :=
  {transfer_name}

def {definition_name}DiagnosticShapeChecked : Bool :=
  diagnosticTransferShapeChecked {pe_name} {definition_name}
    {definition_name}ExpectedTransfer

def {definition_name}SemanticObligation : Prop :=
  SemanticTransferRefinesExactPath {pe_name} {definition_name}
    {definition_name}ExpectedTransfer

end StageA.GeneratedRelational
"""


def relational_interpreter_normalization_inventory(
    state_machine: Path,
    *,
    shard_size: int = 48,
) -> dict[str, Any]:
    """Inventory every GNU/generic transfer without granting proof authority."""

    if shard_size <= 0:
        raise StageAInputError("normalization shard_size must be positive")
    rows = _read_rows(Path(state_machine))
    ready: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    feature_counts: Counter[str] = Counter()
    status_fields_ignored = 0
    for row in rows:
        status_fields_ignored += int("status" in row)
        identity = row.get("id")
        try:
            item = _validated_row(row)
        except (StageAInputError, StageBInterpreterError) as error:
            blocked.append(
                {
                    "transfer_id": identity if isinstance(identity, str) else None,
                    "reason": "unsupported_or_malformed_transfer",
                    "detail": str(error),
                }
            )
            continue
        if _is_x87_row(row):
            blocked.append(
                {
                    "transfer_id": identity,
                    "rva_start": item["start"],
                    "reason": "x87_separate_exact_schedule",
                    "detail": "use the exact x87 schedule checker before normalization",
                }
            )
            continue
        try:
            transfer = _TransferCompiler(row).compile()
        except StageBInterpreterError as error:
            blocked.append(
                {
                    "transfer_id": identity if isinstance(identity, str) else None,
                    "rva_start": item["start"],
                    "reason": "unsupported_or_malformed_transfer",
                    "detail": str(error),
                }
            )
            continue
        effects = _ordered_effects(transfer)
        feature_counts.update(effects)
        ready.append(
            {
                "transfer_id": identity,
                "rva_start": item["start"],
                "rva_end": item["stop"],
                "instructions": len(item["instructions"]),
                "ordered_effects": len(effects),
            }
        )
    ready.sort(key=lambda entry: (entry["rva_start"], entry["transfer_id"]))
    blocked.sort(
        key=lambda entry: (
            entry.get("rva_start", 2**32),
            str(entry.get("transfer_id") or ""),
        )
    )
    shards = [
        {
            "index": index // shard_size,
            "first_rva": group[0]["rva_start"],
            "last_rva": group[-1]["rva_start"],
            "transfers": [entry["transfer_id"] for entry in group],
        }
        for index in range(0, len(ready), shard_size)
        if (group := ready[index : index + shard_size])
    ]
    return {
        "format": RELATIONAL_INTERPRETER_NORMALIZATION_INVENTORY_FORMAT,
        "status": "incomplete",
        "proof_authority": False,
        "total_transfers": len(rows),
        "ready_for_lean_check": len(ready),
        "blocked": len(blocked),
        "lean_certificates_proved": 0,
        "status_fields_ignored": status_fields_ignored,
        "feature_counts": dict(sorted(feature_counts.items())),
        "blocker_counts": dict(
            sorted(Counter(entry["reason"] for entry in blocked).items())
        ),
        "blocked_transfers": blocked,
        "shards": shards,
    }


def relational_interpreter_normalization_bundle_sources(
    rows: Iterable[Mapping[str, Any]],
    *,
    source_module: str,
    pe_name: str,
    record_prefix: str = "semanticInterpreterProgramRecord",
    transfer_prefix: str = "semanticInterpreterTransfer",
    module_prefix: str = "GeneratedInterpreterNormalization",
    shard_size: int = 48,
    semantic_refinement_module: str | None = None,
    semantic_refinement_prefix: str = "exactNormalizedTransferSemanticRefinement",
) -> dict[str, str]:
    """Emit deterministic exact-path shards and, when bound, certificates.

    The optional refinement module is a deliberate proof boundary.  It must
    provide one universal ``SemanticTransferRefinesExactPath`` theorem per
    ordinary transfer.  Lean checks every supplied theorem against the exact
    PE/path/transfer type before this generator can construct an acceptance
    inventory.  Omitting the module retains the data-only extraction mode and
    cannot create an ``ExactOriginalTransferInventory``.
    """

    source_module, _ = _stage_a_module(source_module, "source_module")
    pe_name = _lean_name(pe_name, "pe_name")
    record_prefix = _local_name(record_prefix, "record_prefix")
    transfer_prefix = _local_name(transfer_prefix, "transfer_prefix")
    module_prefix = _local_name(module_prefix, "module_prefix")
    semantic_refinement_prefix = _local_name(
        semantic_refinement_prefix, "semantic_refinement_prefix"
    )
    if semantic_refinement_module is not None:
        semantic_refinement_module, _ = _stage_a_module(
            semantic_refinement_module, "semantic_refinement_module"
        )
    if shard_size <= 0:
        raise StageAInputError("normalization shard_size must be positive")
    selected = _ordinary_items(rows)
    sources: dict[str, str] = {}
    path_shard_names: list[str] = []
    refinement_shard_names: list[str] = []
    refinement_source_shard_names: list[str] = []
    refinement_source_map_names: list[str] = []
    for shard_start in range(0, len(selected), shard_size):
        shard = selected[shard_start : shard_start + shard_size]
        shard_index = shard_start // shard_size
        module = f"{module_prefix}Shard{shard_index:04d}"
        path_definitions: list[str] = []
        certificate_definitions: list[str] = []
        shard_members: list[tuple[int, str, str]] = []
        for source_index, item in shard:
            local = f"exactNormalizedTransferPath{source_index}"
            path_definitions.append(
                _path_definition(
                    item,
                    record_name=f"{record_prefix}{source_index}",
                    definition_name=local,
                )
            )
            if semantic_refinement_module is not None:
                certificate = f"{local}Certificate"
                semantic_refinement = (
                    f"{semantic_refinement_prefix}{source_index}"
                )
                certificate_definitions.append(
                    f"""theorem {local}DiagnosticShape :
    diagnosticTransferShapeChecked {pe_name} {local}
      {transfer_prefix}{source_index} = true := by decide +kernel

def {certificate} : ExactProgramRecordNormalizationCertificate {pe_name}
    {local} {transfer_prefix}{source_index} := {{
  recordDecoded := {record_prefix}{source_index}Decoded
  transferChecked := {record_prefix}{source_index}TransferChecked
  normalization := {{
    diagnosticShape := {local}DiagnosticShape
    semanticRefinement := {semantic_refinement}
  }}
}}
"""
                )
                shard_members.append((source_index, local, certificate))
        path_body = "\n".join(path_definitions)
        path_shard = f"{module}Paths"
        path_shard_names.append(path_shard)
        shard_paths = ",\n  ".join(member for _, member, _ in shard_members)
        if semantic_refinement_module is None:
            shard_paths = ",\n  ".join(
                f"exactNormalizedTransferPath{source_index}"
                for source_index, _ in shard
            )
        path_body += f"""
def {path_shard} : List ExactNormalizedTransferPath := [
  {shard_paths}
]
"""
        if semantic_refinement_module is None:
            sources[module] = f"""import StageA.RelationalInterpreterNormalization
import {source_module}

namespace StageA.GeneratedRelational

open StageA.Relational.InterpreterNormalization

{path_body}
end StageA.GeneratedRelational
"""
        else:
            data_module = f"{module}Data"
            sources[data_module] = f"""import StageA.RelationalInterpreterNormalization
import {source_module}

namespace StageA.GeneratedRelational

open StageA.Relational.InterpreterNormalization

{path_body}
end StageA.GeneratedRelational
"""
            refinement_shard = f"{module}Refinements"
            refinement_shard_names.append(refinement_shard)
            refinement_source_shard = f"{module}SourceRvas"
            refinement_source_shard_names.append(refinement_source_shard)
            refinement_source_map = f"{module}RefinementsSourceMap"
            refinement_source_map_names.append(refinement_source_map)
            shard_refinements = ",\n    ".join(
                "{ path := "
                + member
                + ", transfer := "
                + f"{transfer_prefix}{source_index}"
                + ", certificate := "
                + certificate
                + " }"
                for source_index, member, certificate in shard_members
            )
            shard_source_rvas = ", ".join(
                str(item["start"]) for _, item in shard
            )
            shard_path_names = ", ".join(
                member for _, member, _ in shard_members
            )
            certificate_definitions.append(
                f"""def {refinement_source_shard} : List Nat :=
  [{shard_source_rvas}]

def {refinement_shard} (context : StaticProofContext) :
    List (ExactOriginalTransferRefinement
      {{ context with originalPe := {pe_name} }}) := [
    {shard_refinements}
]

theorem {refinement_source_map} (context : StaticProofContext) :
    ({refinement_shard} context).map
        (fun refinement => refinement.path.sourceRva) =
      {refinement_source_shard} := by
  simp [{refinement_shard}, {refinement_source_shard}, {shard_path_names}]
"""
            )
            certificate_body = "\n".join(certificate_definitions)
            sources[module] = f"""import StageA.{data_module}
import StageA.RelationalInterpreterAcceptance
import {semantic_refinement_module}

namespace StageA.GeneratedRelational

open StageA.Relational
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterAcceptance

{certificate_body}
end StageA.GeneratedRelational
"""
    bundle_module = f"{module_prefix}Bundle"
    imported_modules = (
        [
            module
            for module in sources
            if not module.endswith("Data")
        ]
        if semantic_refinement_module is not None
        else list(sources)
    )
    imports = "\n".join(f"import StageA.{module}" for module in imported_modules)
    members = " ++\n  ".join(path_shard_names)
    acceptance = ""
    acceptance_open = ""
    if semantic_refinement_module is not None:
        acceptance_open = "open StageA.Relational.InterpreterAcceptance\n"
        refinements = " ++\n      ".join(
            f"{name} context" for name in refinement_shard_names
        )
        source_rvas = " ++\n  ".join(refinement_source_shard_names)
        source_map_rewrites = "\n    ".join(
            f"rw [{name} context]" for name in refinement_source_map_names
        )
        acceptance = f"""
def exactNormalizedTransferSourceRvas : List Nat :=
  {source_rvas}

theorem exactNormalizedTransferSourceRvasNodup :
    exactNormalizedTransferSourceRvas.Nodup := by decide +kernel

/-- Construct the exact ordinary acceptance inventory only after every shard's
universal semantic theorem has been checked by Lean. -/
def exactNormalizedTransferOriginalInventory
    (context : StaticProofContext)
    (originalPeBound : context.originalPe = {pe_name}) :
    ExactOriginalTransferInventory context := by
  let normalized : StaticProofContext := {{
    context with originalPe := {pe_name}
  }}
  have normalizedEq : normalized = context := by
    cases context
    simp_all [normalized]
  let refinements : List (ExactOriginalTransferRefinement normalized) :=
      {refinements}
  have sourceMap :
      refinements.map (fun refinement => refinement.path.sourceRva) =
        exactNormalizedTransferSourceRvas := by
    simp only [refinements, List.map_append]
    {source_map_rewrites}
    rfl
  have inventory : ExactOriginalTransferInventory normalized := {{
    requiredSourceRvas := exactNormalizedTransferSourceRvas
    certifiedSourceRvas := exactNormalizedTransferSourceRvas
    requiredUnique := exactNormalizedTransferSourceRvasNodup
    certifiedUnique := exactNormalizedTransferSourceRvasNodup
    complete := by intro sourceRva required; exact required
    exact := by intro sourceRva certified; exact certified
    refined := by
      intro sourceRva certified
      have member : sourceRva \u2208
          refinements.map (fun refinement => refinement.path.sourceRva) := by
        rw [sourceMap]
        exact certified
      rcases List.mem_map.mp member with \u27e8refinement, present, source\u27e9
      exact \u27e8refinement, source\u27e9
  }}
  exact normalizedEq \u25b8 inventory
"""
    sources[bundle_module] = f"""{imports}

namespace StageA.GeneratedRelational

open StageA.Relational
open StageA.Relational.InterpreterNormalization
{acceptance_open}

def exactNormalizedTransferPaths : List ExactNormalizedTransferPath :=
  {members}

{acceptance}
end StageA.GeneratedRelational
"""
    return sources


def relational_interpreter_normalization_module_inventory(
    sources: Mapping[str, str], *, target: str
) -> dict[str, Any]:
    target = _local_name(target, "target")
    if target not in sources:
        raise StageAInputError("normalization target is absent from generated sources")
    modules = {
        name: {
            "imports": _STAGE_A_IMPORT.findall(source),
            "source_sha256": sha256_bytes(source.encode()),
            "source_bytes": len(source.encode()),
        }
        for name, source in sorted(sources.items())
    }
    required_external_modules = sorted(
        {
            dependency
            for metadata in modules.values()
            for dependency in metadata["imports"]
            if dependency not in modules
        }
    )
    proof_bearing = any(
        "ExactProgramRecordNormalizationCertificate" in source
        for source in sources.values()
    )
    semantic_refinement_obligations = sorted(
        {
            name
            for source in sources.values()
            for name in _SEMANTIC_REFINEMENT_BINDING.findall(source)
        }
    )
    return {
        "format": RELATIONAL_INTERPRETER_NORMALIZATION_FORMAT,
        "status": "proof_sources_ready" if proof_bearing else "data_ready",
        "proof_authority": False,
        "modules": modules,
        "required_external_modules": required_external_modules,
        "target": target,
        "targets": (
            {
                "bundle_node": target,
                "exact_original_inventory": (
                    "exactNormalizedTransferOriginalInventory"
                ),
            }
            if proof_bearing
            else {"bundle_node": target}
        ),
        "counts": {
            "modules": len(modules),
            "semantic_refinement_obligations": len(
                semantic_refinement_obligations
            ),
        },
        "semantic_refinement_obligations": semantic_refinement_obligations,
    }


__all__ = [
    "RELATIONAL_INTERPRETER_NORMALIZATION_FORMAT",
    "RELATIONAL_INTERPRETER_NORMALIZATION_INVENTORY_FORMAT",
    "relational_interpreter_normalization_bundle_sources",
    "relational_interpreter_normalization_inventory",
    "relational_interpreter_normalization_module_inventory",
    "relational_interpreter_normalization_source",
]
