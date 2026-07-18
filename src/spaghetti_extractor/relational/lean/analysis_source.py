from __future__ import annotations

from pathlib import Path
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..schema import (
    RELATIONAL_ANALYSIS_KERNEL_MODULES,
    RELATIONAL_KERNEL_MODULES,
    RegionStatePredicate,
    SchemaError,
)
from .expressions import (
    _lean_machine_import_call_contract,
    _lean_region_definition as _lean_region_definition_base,
    _lean_semantic_bool_expr,
)


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"
def _lean_region_state_predicates(region: dict[str, Any]) -> list[str] | None:
    if "state_predicates" not in region:
        return None
    raw_predicates = region["state_predicates"]
    if not isinstance(raw_predicates, list):
        raise StageAInputError("region state_predicates must be a list")

    rows: list[str] = []
    for index, raw_predicate in enumerate(raw_predicates):
        context = (
            f"region {region.get('id', region.get('numeric_id', '?'))} "
            f"state_predicates[{index}]"
        )
        try:
            if not isinstance(raw_predicate, dict):
                raise SchemaError("region state predicate row must be an object")
            predicate = RegionStatePredicate.parse(raw_predicate)
            original = _lean_semantic_bool_expr(predicate.original)
            candidate = _lean_semantic_bool_expr(predicate.candidate)
        except (
            KeyError,
            SchemaError,
            TypeError,
            ValueError,
            StageAInputError,
        ) as exc:
            raise StageAInputError(f"{context} is malformed: {exc}") from exc
        rows.append(
            "{ original := " + original + ", candidate := " + candidate + " }"
        )
    return rows


def _lean_region_definition(index: int, region: dict[str, Any]) -> str:
    definition = _lean_region_definition_base(index, region)
    predicates = _lean_region_state_predicates(region)
    if predicates is None:
        return definition
    if not definition.endswith(" }"):
        raise StageAInputError("region definition has an unsupported literal shape")
    return (
        definition[:-2]
        + ", predicates := ["
        + ", ".join(predicates)
        + "] }"
    )


def _copy_relational_kernel_sources(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for module in RELATIONAL_KERNEL_MODULES:
        _write_text_if_changed(
            destination / f"{module}.lean",
            (_LEAN_SOURCE_ROOT / f"{module}.lean").read_text(encoding="utf-8"),
        )


def _copy_relational_analysis_kernel_sources(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for module in RELATIONAL_ANALYSIS_KERNEL_MODULES:
        _write_text_if_changed(
            destination / f"{module}.lean",
            (_LEAN_SOURCE_ROOT / f"{module}.lean").read_text(encoding="utf-8"),
        )


def _lean_extraction_source(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    *,
    requests: set[tuple[str, int]],
) -> str:
    evaluations: list[str] = []
    definitions: list[str] = []
    machine_call_contracts = ", ".join(
        _lean_machine_import_call_contract(item)
        for item in contract.get("machine_import_call_contracts", [])
    )
    definitions.append(
        "def machineImportCallContracts : List MachineImportCallContract := "
        f"[{machine_call_contracts}]"
    )
    for index, region in enumerate(contract["regions"]):
        if not any((side, index) in requests for side in ("original", "candidate")):
            continue
        definitions.append(_lean_region_definition(index, region))
        for side in ("original", "candidate"):
            if (side, index) not in requests:
                continue
            span = region[side]
            span_literal = f"{{ start := {span['rva_start']}, size := {span['size']} }}"
            candidate_literal = "true" if side == "candidate" else "false"
            evaluations.extend((
                f"  let some {side}Behavior{index} := "
                f"regionBehaviorWithMachineCallContracts {side}Pe {side}Imports "
                f"machineImportCallContracts {span_literal} | "
                f'throw (IO.userError "{side} region {index} did not decode")',
                f"  let some {side}Normalized{index} := normalizeSymbolicBehavior "
                f"{candidate_literal} region{index}.targets {side}Behavior{index} | "
                f'throw (IO.userError "{side} region {index} did not normalize")',
                f'  IO.println ("STAGE_A_BEHAVIOR_BEGIN {side} {index}\\n" ++ '
                f'reprStr (some {side}Behavior{index}) ++ "\\nSTAGE_A_BEHAVIOR_IR\\n" ++ '
                f'SemanticIR.normalizedBehaviorString {side}Normalized{index} ++ '
                '"\\nSTAGE_A_BEHAVIOR_END")',
            ))
    return (
        "import StageA.Relational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + "\n\n".join(definitions)
        + "\n\n"
        "def main : IO Unit := do\n"
        "  let originalData ← IO.FS.readBinFile \"../artifacts/original.pe\"\n"
        "  let candidateData ← IO.FS.readBinFile \"../artifacts/candidate.pe\"\n"
        "  let originalBytes : Bytes := originalData.toList.map (fun byte => byte.toNat)\n"
        "  let candidateBytes : Bytes := candidateData.toList.map (fun byte => byte.toNat)\n"
        "  let some originalPe := parsePE32 originalBytes | throw (IO.userError \"original PE parse failed\")\n"
        "  let some candidatePe := parsePE32 candidateBytes | throw (IO.userError \"candidate PE parse failed\")\n"
        "  let some originalImports := parseImports originalPe | throw (IO.userError \"original imports parse failed\")\n"
        "  let some candidateImports := parseImports candidatePe | throw (IO.userError \"candidate imports parse failed\")\n"
        + "\n".join(evaluations)
        + "\n"
    )


def _lean_behavior_field(source: str, field: str, next_field: str) -> str | None:
    end_marker = f", {next_field} := "
    for start_marker in (f", {field} := ", f"{{ {field} := "):
        try:
            return source.split(start_marker, 1)[1].split(end_marker, 1)[0]
        except (AttributeError, IndexError):
            continue
    return None


def _lean_x87_state_only_pair(behaviors: dict[str, str]) -> bool:
    original = _lean_behavior_field(behaviors.get("original", ""), "x87", "writes")
    candidate = _lean_behavior_field(behaviors.get("candidate", ""), "x87", "writes")
    if original is None or original != candidate:
        return False
    external_dependencies = (
        "StageA.Formal.X87Expr.load ",
        "StageA.Formal.Expr.inputReg ",
        "StageA.Formal.Expr.inputFlagValue ",
        "StageA.Formal.Expr.inputFsBase",
        "StageA.Formal.Expr.read8 ",
        "StageA.Formal.Expr.read32 ",
        "StageA.Formal.Expr.read8AfterWrite ",
        "StageA.Formal.Expr.undefinedValue ",
    )
    return not any(marker in original for marker in external_dependencies)
