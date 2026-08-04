"""Generate checked data for one original combined execution inventory.

This module is an artifact assembler.  It binds the mixed-original frontier
plan to the three exact indirect-control authority families and to explicit
Lean declaration inventories.  It emits only finite data and declaration
aliases; whole-execution preservation remains a separate proof obligation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from spaghetti_extractor.errors import StageAInputError


ORIGINAL_COMBINED_REACHABILITY_DECLARATIONS_FORMAT = (
    "stage-a-original-combined-reachability-declarations-v1"
)
ORIGINAL_COMBINED_CALL_FRAME_DECLARATIONS_FORMAT = (
    "stage-a-original-combined-call-frame-declarations-v1"
)
ORIGINAL_COMBINED_VALUE_FLOW_DECLARATIONS_FORMAT = (
    "stage-a-original-combined-value-flow-declarations-v1"
)
ORIGINAL_COMBINED_INVENTORY_MANIFEST_FORMAT = (
    "stage-a-original-combined-execution-inventory-declarations-v1"
)

_MIXED_ORIGINAL_FORMAT = "stage-a-interpreter-mixed-original-v1"
_WRITABLE_FORMAT = (
    "stage-a-relocated-writable-static-pointer-slot-authorities-v2"
)
_REGISTER_FORMAT = "stage-a-register-indirect-control-authorities-v1"
_STACK_FORMAT = "stage-a-original-stack-dynamic-control-closure-v1"
_STACK_COMBINED_FORMAT = (
    "stage-a-gnu-hello-stack-dynamic-combined-evidence-v1"
)

_EXPECTED_SITE_COUNTS = {
    "writable_static_slot": 19,
    "register_target": 9,
    "stack_dynamic": 3,
}
_EXPECTED_STATIC_WORD_SLOTS = 3

_MODULE_PREFIX = "GeneratedRelationalOriginalCombinedInventory"
_NAMESPACE = "StageA.GeneratedRelational.OriginalCombinedInventory"
_MANIFEST_NAME = "original-combined-execution-inventory-declarations.json"

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CALL_FRAME_KINDS = frozenset(
    {
        "call_entry_certificate",
        "call_frame_transfer",
        "call_preservation",
        "frame_inventory",
    }
)


class OriginalCombinedInventoryGenerationError(StageAInputError):
    """An exact authority or declaration input is incomplete or inconsistent."""


@dataclass(frozen=True)
class LeanDeclarationRef:
    module: str
    namespace: str
    symbol: str

    @property
    def declaration(self) -> str:
        return f"{self.namespace}.{self.symbol}"

    @classmethod
    def from_json(cls, value: object, label: str) -> "LeanDeclarationRef":
        row = _object(value, label)
        if set(row) != {"module", "namespace", "symbol"}:
            raise OriginalCombinedInventoryGenerationError(
                f"{label} must contain exactly module, namespace, and symbol"
            )
        result = cls(
            module=_string(row["module"], f"{label}.module"),
            namespace=_string(row["namespace"], f"{label}.namespace"),
            symbol=_string(row["symbol"], f"{label}.symbol"),
        )
        result.validate(label)
        return result

    @classmethod
    def from_declaration(
        cls, module: str, declaration: object, label: str
    ) -> "LeanDeclarationRef":
        name = _string(declaration, label)
        if "." not in name:
            raise OriginalCombinedInventoryGenerationError(
                f"{label} must be a fully qualified Lean declaration"
            )
        namespace, symbol = name.rsplit(".", 1)
        result = cls(module=module, namespace=namespace, symbol=symbol)
        result.validate(label)
        return result

    def validate(self, label: str) -> None:
        if _STAGE_A_MODULE.fullmatch(self.module) is None:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.namespace is not a Lean identifier"
            )
        if not self.namespace.startswith("StageA."):
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.namespace must be below StageA"
            )
        if _LOCAL_IDENTIFIER.fullmatch(self.symbol) is None:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.symbol is not a local Lean identifier"
            )

    def to_json(self) -> dict[str, str]:
        return {
            "module": self.module,
            "namespace": self.namespace,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class StaticWordSlot:
    slot_rva: int
    relation: str
    transfer_kind: str
    authority: LeanDeclarationRef


@dataclass(frozen=True)
class CallFrameFact:
    name: str
    kind: str
    site_instruction_rva: int | None
    term: LeanDeclarationRef


@dataclass(frozen=True)
class ValueFlowFact:
    fact_id: int
    term: LeanDeclarationRef
    id_exact: LeanDeclarationRef


@dataclass(frozen=True)
class DeclarationInputs:
    mixed_original_plan_sha256: str
    original_sha256: str
    state_machine_sha256: str

    def to_json(self) -> dict[str, str]:
        return {
            "mixed_original_plan_sha256": self.mixed_original_plan_sha256,
            "original_sha256": self.original_sha256,
            "state_machine_sha256": self.state_machine_sha256,
        }


@dataclass(frozen=True)
class OriginalCombinedInventoryModules:
    modules: tuple[Path, ...]
    manifest: Path


def write_original_combined_inventory(
    output_root: Path,
    *,
    mixed_original_plan: Path,
    writable_authority_report: Path,
    writable_authority_manifest: Path,
    register_authority_report: Path,
    register_authority_manifest: Path,
    stack_dynamic_authority_report: Path,
    stack_dynamic_authority_manifest: Path,
    stack_combined_evidence_report: Path,
    reachability_declarations: Path,
    call_frame_declarations: Path,
    value_flow_declarations: Path,
    shard_size: int = 512,
) -> OriginalCombinedInventoryModules:
    """Validate exact inputs and write shardable Lean inventory data."""

    if isinstance(shard_size, bool) or not isinstance(shard_size, int):
        raise OriginalCombinedInventoryGenerationError(
            "shard_size must be a positive integer"
        )
    if shard_size <= 0:
        raise OriginalCombinedInventoryGenerationError(
            "shard_size must be a positive integer"
        )

    paths = {
        "mixed_original_plan": mixed_original_plan,
        "writable_authority_report": writable_authority_report,
        "writable_authority_manifest": writable_authority_manifest,
        "register_authority_report": register_authority_report,
        "register_authority_manifest": register_authority_manifest,
        "stack_dynamic_authority_report": stack_dynamic_authority_report,
        "stack_dynamic_authority_manifest": stack_dynamic_authority_manifest,
        "stack_combined_evidence_report": stack_combined_evidence_report,
        "reachability_declarations": reachability_declarations,
        "call_frame_declarations": call_frame_declarations,
        "value_flow_declarations": value_flow_declarations,
    }
    documents = {name: _load_json(path, name) for name, path in paths.items()}
    hashes = {name: _sha256_file(path) for name, path in paths.items()}

    plan = documents["mixed_original_plan"]
    _require_format(plan, _MIXED_ORIGINAL_FORMAT, "mixed original plan")
    reachable_target_ids = _natural_list(
        plan.get("reachable_target_ids"),
        "mixed original plan reachable_target_ids",
    )
    if not reachable_target_ids:
        raise OriginalCombinedInventoryGenerationError(
            "mixed original plan reachable_target_ids must be nonempty"
        )
    _require_unique(reachable_target_ids, "mixed original plan reachable_target_ids")
    plan_frontiers = _plan_frontiers(plan)

    writable = documents["writable_authority_report"]
    register = documents["register_authority_report"]
    stack = documents["stack_dynamic_authority_report"]
    stack_combined = documents["stack_combined_evidence_report"]
    _require_format(writable, _WRITABLE_FORMAT, "writable authority report")
    _require_format(register, _REGISTER_FORMAT, "register authority report")
    _require_format(stack, _STACK_FORMAT, "stack authority report")
    _require_format(
        stack_combined, _STACK_COMBINED_FORMAT, "stack combined evidence report"
    )

    expected_inputs = _authority_inputs(
        plan_hash=hashes["mixed_original_plan"],
        writable_hash=hashes["writable_authority_report"],
        writable=writable,
        register=register,
        stack=stack,
    )
    static_slots, writable_refs = _writable_sites(writable, plan_frontiers)
    register_refs = _register_sites(register, plan_frontiers)
    stack_rows = _stack_sites(stack, plan_frontiers)
    stack_refs, combined_dependencies = _combined_stack_sites(
        stack_combined, stack_rows
    )

    _validate_phase_manifest(
        documents["writable_authority_manifest"],
        label="writable authority manifest",
        phase="mixed-original-writable-slot-authority-lean",
        public_output=("authority_report", writable_authority_report.name),
        declaration_refs=writable_refs,
        expected_inputs=expected_inputs,
    )
    _validate_phase_manifest(
        documents["register_authority_manifest"],
        label="register authority manifest",
        phase="mixed-original-register-indirect-authority-lean",
        public_output=("authority_report", register_authority_report.name),
        declaration_refs=register_refs,
        expected_inputs=expected_inputs,
        exact_input_hash=(
            "writable_slot_authority_report",
            hashes["writable_authority_report"],
        ),
    )
    _validate_phase_manifest(
        documents["stack_dynamic_authority_manifest"],
        label="stack authority manifest",
        phase="mixed-original-stack-dynamic-authority-lean",
        public_output=("closure", stack_dynamic_authority_report.name),
        additional_public_output=(
            "combined_evidence",
            stack_combined_evidence_report.name,
        ),
        declaration_refs=stack_refs,
        expected_inputs=expected_inputs,
    )

    reachability = _reachability_declarations(
        documents["reachability_declarations"], expected_inputs
    )
    call_frames = _call_frame_declarations(
        documents["call_frame_declarations"],
        expected_inputs,
        combined_dependencies,
        {
            _natural(row["instruction_rva"], "stack authority instruction_rva")
            for row in stack_rows
            if row.get("closure_mode") == "finite_stack_target"
        },
    )
    value_flow = _value_flow_declarations(
        documents["value_flow_declarations"], expected_inputs
    )

    stage_a_root = output_root / "StageA"
    stage_a_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    target_shards: list[str] = []
    for index, start in enumerate(range(0, len(reachable_target_ids), shard_size)):
        module = f"{_MODULE_PREFIX}ReachableShard{index:04d}"
        path = stage_a_root / f"{module}.lean"
        chunk = reachable_target_ids[start : start + shard_size]
        _write_ascii(path, _render_target_shard(module, index, chunk))
        written.append(path)
        target_shards.append(module)

    reachability_path = stage_a_root / f"{_MODULE_PREFIX}Reachability.lean"
    _write_ascii(
        reachability_path,
        _render_reachability(reachability, target_shards),
    )
    written.append(reachability_path)

    static_path = stage_a_root / f"{_MODULE_PREFIX}StaticWords.lean"
    _write_ascii(static_path, _render_static_words(static_slots, reachability))
    written.append(static_path)

    register_path = stage_a_root / f"{_MODULE_PREFIX}RegisterTargets.lean"
    _write_ascii(register_path, _render_register_targets(register_refs, reachability))
    written.append(register_path)

    stack_path = stage_a_root / f"{_MODULE_PREFIX}StackDynamicTargets.lean"
    _write_ascii(stack_path, _render_stack_targets(stack_refs, reachability))
    written.append(stack_path)

    call_frame_path = stage_a_root / f"{_MODULE_PREFIX}CallFrames.lean"
    _write_ascii(call_frame_path, _render_call_frames(call_frames))
    written.append(call_frame_path)

    value_flow_path = stage_a_root / f"{_MODULE_PREFIX}ValueFlows.lean"
    _write_ascii(value_flow_path, _render_value_flows(value_flow, reachability))
    written.append(value_flow_path)

    inventory_path = stage_a_root / f"{_MODULE_PREFIX}.lean"
    _write_ascii(inventory_path, _render_inventory())
    written.append(inventory_path)

    manifest_path = output_root / _MANIFEST_NAME
    manifest = _canonical_manifest(
        hashes=hashes,
        reachable_target_ids=reachable_target_ids,
        target_shards=target_shards,
        static_slots=static_slots,
        register_refs=register_refs,
        stack_rows=stack_rows,
        call_frames=call_frames,
        value_flow=value_flow,
        modules=written,
    )
    _write_ascii(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return OriginalCombinedInventoryModules(tuple(written), manifest_path)


def _authority_inputs(
    *,
    plan_hash: str,
    writable_hash: str,
    writable: dict[str, Any],
    register: dict[str, Any],
    stack: dict[str, Any],
) -> DeclarationInputs:
    writable_inputs = _object(writable.get("inputs"), "writable report inputs")
    register_inputs = _object(register.get("inputs"), "register report inputs")
    stack_inputs = _object(stack.get("inputs"), "stack report inputs")

    _require_digest_value(
        writable_inputs,
        "mixed_original_plan_sha256",
        plan_hash,
        "writable report inputs",
    )
    _require_digest_value(
        register_inputs,
        "mixed_original_plan_sha256",
        plan_hash,
        "register report inputs",
    )
    _require_digest_value(
        register_inputs,
        "writable_slot_report_sha256",
        writable_hash,
        "register report inputs",
    )

    original = _common_digest(
        (
            (writable_inputs, "original_sha256", "writable report"),
            (register_inputs, "original_sha256", "register report"),
            (stack_inputs, "original_pe_sha256", "stack report"),
        )
    )
    state_machine = _common_digest(
        (
            (writable_inputs, "state_machine_sha256", "writable report"),
            (register_inputs, "state_machine_sha256", "register report"),
            (stack_inputs, "state_machine_sha256", "stack report"),
        )
    )
    return DeclarationInputs(plan_hash, original, state_machine)


def _plan_frontiers(plan: dict[str, Any]) -> dict[str, set[int]]:
    result = {category: set() for category in _EXPECTED_SITE_COUNTS}
    blockers = _list(plan.get("blockers"), "mixed original plan blockers")
    for index, value in enumerate(blockers):
        blocker = _object(value, f"mixed original plan blockers[{index}]")
        if blocker.get("reason_code") != "unresolved_indirect_control":
            raise OriginalCombinedInventoryGenerationError(
                f"mixed original plan blockers[{index}] is not unresolved indirect control"
            )
        detail = _string(
            blocker.get("detail"), f"mixed original plan blockers[{index}].detail"
        )
        if detail.startswith("static_pointer_slot at "):
            category = "writable_static_slot"
        elif detail.startswith(
            ("register_function_pointer at ", "register_tail_target at ")
        ):
            category = "register_target"
        elif detail.startswith("stack_or_dynamic_pointer at "):
            category = "stack_dynamic"
        else:
            raise OriginalCombinedInventoryGenerationError(
                f"mixed original plan blockers[{index}] has unsupported detail"
            )
        rva = _natural(
            blocker.get("rva"), f"mixed original plan blockers[{index}].rva"
        )
        if rva in result[category]:
            raise OriginalCombinedInventoryGenerationError(
                f"mixed original plan repeats {category} RVA 0x{rva:x}"
            )
        result[category].add(rva)
    counts = {category: len(rvas) for category, rvas in result.items()}
    if counts != _EXPECTED_SITE_COUNTS:
        raise OriginalCombinedInventoryGenerationError(
            f"mixed original plan frontier counts must be {_EXPECTED_SITE_COUNTS}, got {counts}"
        )
    return result


def _writable_sites(
    report: dict[str, Any], plan_frontiers: dict[str, set[int]]
) -> tuple[list[StaticWordSlot], list[LeanDeclarationRef]]:
    rows = _exact_site_rows(report, "writable authority report", 19)
    seen_rvas: set[int] = set()
    refs: list[LeanDeclarationRef] = []
    slots: dict[int, tuple[tuple[object, ...], StaticWordSlot]] = {}
    for index, row in enumerate(rows):
        label = f"writable authority report sites[{index}]"
        source_rva = _natural(row.get("source_rva"), f"{label}.source_rva")
        if source_rva in seen_rvas:
            raise OriginalCombinedInventoryGenerationError(
                f"writable authority report repeats source RVA 0x{source_rva:x}"
            )
        seen_rvas.add(source_rva)
        ref = LeanDeclarationRef.from_json(
            row.get("authorizing_lean_term"), f"{label}.authorizing_lean_term"
        )
        refs.append(ref)
        relation = _string(row.get("value_relation"), f"{label}.value_relation")
        if relation not in {"fixed_code_pointer", "finite_origins"}:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.value_relation is unsupported"
            )
        transfer = _string(row.get("transfer_kind"), f"{label}.transfer_kind")
        if transfer not in {"call", "jump"}:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.transfer_kind is unsupported"
            )
        slot_rva = _natural(row.get("slot_rva"), f"{label}.slot_rva")
        internal = tuple(
            _natural_list(row.get("internal_target_ids"), f"{label}.internal_target_ids")
        )
        external_rows = _list(row.get("external_routes"), f"{label}.external_routes")
        external = tuple(
            _natural(
                _object(route, f"{label}.external_routes[{route_index}]").get(
                    "resource_id"
                ),
                f"{label}.external_routes[{route_index}].resource_id",
            )
            for route_index, route in enumerate(external_rows)
        )
        if relation == "fixed_code_pointer":
            target_id = _natural(row.get("target_id"), f"{label}.target_id")
            if internal != (target_id,) or external:
                raise OriginalCombinedInventoryGenerationError(
                    f"{label} fixed relation has inconsistent alternatives"
                )
            signature: tuple[object, ...] = (relation, internal, external)
        else:
            if not internal and not external:
                raise OriginalCombinedInventoryGenerationError(
                    f"{label} finite relation has no alternatives"
                )
            _require_unique(list(internal), f"{label}.internal_target_ids")
            _require_unique(list(external), f"{label}.external resource ids")
            signature = (relation, internal, external)
        slot = StaticWordSlot(slot_rva, relation, transfer, ref)
        previous = slots.get(slot_rva)
        if previous is None:
            slots[slot_rva] = (signature, slot)
        elif previous[0] != signature:
            raise OriginalCombinedInventoryGenerationError(
                f"writable slot RVA 0x{slot_rva:x} has conflicting authorities"
            )
    if seen_rvas != plan_frontiers["writable_static_slot"]:
        _raise_site_difference(
            "writable authority report",
            plan_frontiers["writable_static_slot"],
            seen_rvas,
        )
    if len(slots) != _EXPECTED_STATIC_WORD_SLOTS:
        raise OriginalCombinedInventoryGenerationError(
            f"writable authorities must cover exactly {_EXPECTED_STATIC_WORD_SLOTS} "
            f"static word slots, got {len(slots)}"
        )
    _require_unique(
        [ref.declaration for ref in refs], "writable authority declarations"
    )
    return [slots[rva][1] for rva in sorted(slots)], refs


def _register_sites(
    report: dict[str, Any], plan_frontiers: dict[str, set[int]]
) -> list[LeanDeclarationRef]:
    blockers = report.get("blockers", [])
    if blockers not in (None, []):
        raise OriginalCombinedInventoryGenerationError(
            "register authority report retains unresolved blockers"
        )
    rows = _exact_site_rows(report, "register authority report", 9)
    by_rva: dict[int, LeanDeclarationRef] = {}
    for index, row in enumerate(rows):
        label = f"register authority report sites[{index}]"
        rva = _natural(row.get("source_rva"), f"{label}.source_rva")
        if rva in by_rva:
            raise OriginalCombinedInventoryGenerationError(
                f"register authority report repeats source RVA 0x{rva:x}"
            )
        by_rva[rva] = LeanDeclarationRef.from_json(
            row.get("authorizing_lean_term"), f"{label}.authorizing_lean_term"
        )
    if set(by_rva) != plan_frontiers["register_target"]:
        _raise_site_difference(
            "register authority report",
            plan_frontiers["register_target"],
            set(by_rva),
        )
    refs = [by_rva[rva] for rva in sorted(by_rva)]
    _require_unique([ref.declaration for ref in refs], "register declarations")
    return refs


def _stack_sites(
    report: dict[str, Any], plan_frontiers: dict[str, set[int]]
) -> list[dict[str, Any]]:
    rows = _exact_site_rows(report, "stack authority report", 3)
    by_rva: dict[int, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        label = f"stack authority report sites[{index}]"
        rva = _natural(row.get("source_rva"), f"{label}.source_rva")
        _natural(row.get("source_target_id"), f"{label}.source_target_id")
        _natural(row.get("instruction_rva"), f"{label}.instruction_rva")
        _natural_list(row.get("allowed_target_ids"), f"{label}.allowed_target_ids")
        if rva in by_rva:
            raise OriginalCombinedInventoryGenerationError(
                f"stack authority report repeats source RVA 0x{rva:x}"
            )
        by_rva[rva] = row
    if set(by_rva) != plan_frontiers["stack_dynamic"]:
        _raise_site_difference(
            "stack authority report", plan_frontiers["stack_dynamic"], set(by_rva)
        )
    return [by_rva[rva] for rva in sorted(by_rva)]


def _combined_stack_sites(
    report: dict[str, Any], stack_rows: list[dict[str, Any]]
) -> tuple[list[LeanDeclarationRef], dict[int, set[str]]]:
    rows = _list(report.get("sites"), "stack combined evidence report sites")
    if len(rows) != 3:
        raise OriginalCombinedInventoryGenerationError(
            f"stack combined evidence report must contain exactly 3 sites, got {len(rows)}"
        )
    kernel_check = _object(
        report.get("kernel_check"), "stack combined evidence report kernel_check"
    )
    kernel_term = LeanDeclarationRef.from_json(
        kernel_check.get("term"),
        "stack combined evidence report kernel_check.term",
    )
    by_instruction = {
        _natural(row.get("instruction_rva"), "stack authority site instruction_rva"): row
        for row in stack_rows
    }
    refs: dict[int, LeanDeclarationRef] = {}
    dependencies: dict[int, set[str]] = {}
    for index, value in enumerate(rows):
        row = _object(value, f"stack combined evidence report sites[{index}]")
        label = f"stack combined evidence report sites[{index}]"
        instruction_rva = _natural(
            row.get("instruction_rva"), f"{label}.instruction_rva"
        )
        if instruction_rva in refs:
            raise OriginalCombinedInventoryGenerationError(
                f"stack combined evidence repeats instruction RVA 0x{instruction_rva:x}"
            )
        closure = by_instruction.get(instruction_rva)
        if closure is None:
            raise OriginalCombinedInventoryGenerationError(
                f"stack combined evidence has extra instruction RVA 0x{instruction_rva:x}"
            )
        source_target_id = _natural(
            row.get("source_target_id"), f"{label}.source_target_id"
        )
        if source_target_id != closure["source_target_id"]:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.source_target_id does not match stack authority"
            )
        ref = LeanDeclarationRef.from_declaration(
            kernel_term.module,
            row.get("combined_requirement_term"),
            f"{label}.combined_requirement_term",
        )
        refs[instruction_rva] = ref
        dependency_names = _string_list(
            row.get("checked_dependencies"), f"{label}.checked_dependencies"
        )
        _require_unique(dependency_names, f"{label}.checked_dependencies")
        dependencies[instruction_rva] = set(dependency_names)
    missing = set(by_instruction) - set(refs)
    if missing:
        rendered = ", ".join(f"0x{rva:x}" for rva in sorted(missing))
        raise OriginalCombinedInventoryGenerationError(
            f"stack combined evidence is missing instruction RVAs: {rendered}"
        )
    ordered = [refs[rva] for rva in sorted(refs)]
    _require_unique([ref.declaration for ref in ordered], "stack requirement declarations")
    return ordered, dependencies


def _reachability_declarations(
    document: dict[str, Any], expected: DeclarationInputs
) -> dict[str, LeanDeclarationRef]:
    _require_format(
        document,
        ORIGINAL_COMBINED_REACHABILITY_DECLARATIONS_FORMAT,
        "reachability declarations",
    )
    _validate_declaration_inputs(document, expected, "reachability declarations")
    declarations = _object(
        document.get("declarations"), "reachability declarations.declarations"
    )
    required = {
        "program",
        "original_context",
        "target_ids",
        "target_ids_exact",
        "target_ids_unique",
        "target_round_trips",
    }
    if set(declarations) != required:
        _raise_exact_keys("reachability declarations.declarations", required, declarations)
    return {
        name: LeanDeclarationRef.from_json(
            declarations[name], f"reachability declarations.declarations.{name}"
        )
        for name in sorted(required)
    }


def _call_frame_declarations(
    document: dict[str, Any],
    expected: DeclarationInputs,
    combined_dependencies: dict[int, set[str]],
    required_stack_sites: set[int],
) -> list[CallFrameFact]:
    _require_format(
        document,
        ORIGINAL_COMBINED_CALL_FRAME_DECLARATIONS_FORMAT,
        "call-frame declarations",
    )
    _validate_declaration_inputs(document, expected, "call-frame declarations")
    declarations = _object(
        document.get("declarations"), "call-frame declarations.declarations"
    )
    if set(declarations) != {"facts"}:
        _raise_exact_keys(
            "call-frame declarations.declarations", {"facts"}, declarations
        )
    rows = _list(declarations["facts"], "call-frame declarations facts")
    if not rows:
        raise OriginalCombinedInventoryGenerationError(
            "call-frame declarations facts must be nonempty"
        )
    facts: list[CallFrameFact] = []
    for index, value in enumerate(rows):
        row = _object(value, f"call-frame declarations facts[{index}]")
        required = {"name", "kind", "site_instruction_rva", "term"}
        if set(row) != required:
            _raise_exact_keys(f"call-frame declarations facts[{index}]", required, row)
        name = _string(row["name"], f"call-frame declarations facts[{index}].name")
        if _LOCAL_IDENTIFIER.fullmatch(name) is None:
            raise OriginalCombinedInventoryGenerationError(
                f"call-frame declarations facts[{index}].name is not a Lean identifier"
            )
        kind = _string(row["kind"], f"call-frame declarations facts[{index}].kind")
        if kind not in _CALL_FRAME_KINDS:
            raise OriginalCombinedInventoryGenerationError(
                f"call-frame declarations facts[{index}].kind is unsupported"
            )
        site_value = row["site_instruction_rva"]
        site_rva = (
            None
            if site_value is None
            else _natural(
                site_value,
                f"call-frame declarations facts[{index}].site_instruction_rva",
            )
        )
        facts.append(
            CallFrameFact(
                name=name,
                kind=kind,
                site_instruction_rva=site_rva,
                term=LeanDeclarationRef.from_json(
                    row["term"], f"call-frame declarations facts[{index}].term"
                ),
            )
        )
    _require_unique([fact.name for fact in facts], "call-frame fact names")
    _require_unique(
        [fact.term.declaration for fact in facts], "call-frame fact declarations"
    )
    scoped_sites = {fact.site_instruction_rva for fact in facts if fact.site_instruction_rva is not None}
    if scoped_sites != required_stack_sites:
        missing = [f"0x{rva:x}" for rva in sorted(required_stack_sites - scoped_sites)]
        extra = [f"0x{rva:x}" for rva in sorted(scoped_sites - required_stack_sites)]
        raise OriginalCombinedInventoryGenerationError(
            "call-frame stack-site inventory has "
            f"missing={missing}, extra={extra}"
        )
    unknown_sites = scoped_sites - set(combined_dependencies)
    if unknown_sites:
        rendered = ", ".join(f"0x{rva:x}" for rva in sorted(unknown_sites))
        raise OriginalCombinedInventoryGenerationError(
            f"call-frame declarations name unknown stack sites: {rendered}"
        )
    for site_rva in sorted(scoped_sites):
        declared = {
            fact.term.declaration
            for fact in facts
            if fact.site_instruction_rva == site_rva
        }
        required = combined_dependencies[site_rva]
        if declared != required:
            missing = sorted(required - declared)
            extra = sorted(declared - required)
            raise OriginalCombinedInventoryGenerationError(
                f"call-frame declarations for stack instruction 0x{site_rva:x} "
                f"have missing={missing}, extra={extra}"
            )
    return sorted(facts, key=lambda fact: (fact.name, fact.term.declaration))


def _value_flow_declarations(
    document: dict[str, Any], expected: DeclarationInputs
) -> dict[str, object]:
    _require_format(
        document,
        ORIGINAL_COMBINED_VALUE_FLOW_DECLARATIONS_FORMAT,
        "value-flow declarations",
    )
    _validate_declaration_inputs(document, expected, "value-flow declarations")
    declarations = _object(
        document.get("declarations"), "value-flow declarations.declarations"
    )
    required = {"inventory", "facts_exact", "facts"}
    if set(declarations) != required:
        _raise_exact_keys("value-flow declarations.declarations", required, declarations)
    rows = _list(declarations["facts"], "value-flow declarations facts")
    if not rows:
        raise OriginalCombinedInventoryGenerationError(
            "value-flow declarations facts must be nonempty"
        )
    facts: list[ValueFlowFact] = []
    for index, value in enumerate(rows):
        row = _object(value, f"value-flow declarations facts[{index}]")
        required_row = {"id", "term", "id_exact"}
        if set(row) != required_row:
            _raise_exact_keys(
                f"value-flow declarations facts[{index}]", required_row, row
            )
        facts.append(
            ValueFlowFact(
                fact_id=_natural(
                    row["id"], f"value-flow declarations facts[{index}].id"
                ),
                term=LeanDeclarationRef.from_json(
                    row["term"], f"value-flow declarations facts[{index}].term"
                ),
                id_exact=LeanDeclarationRef.from_json(
                    row["id_exact"],
                    f"value-flow declarations facts[{index}].id_exact",
                ),
            )
        )
    if [fact.fact_id for fact in facts] != sorted(fact.fact_id for fact in facts):
        raise OriginalCombinedInventoryGenerationError(
            "value-flow facts must be in increasing id order"
        )
    _require_unique([fact.fact_id for fact in facts], "value-flow fact ids")
    _require_unique(
        [fact.term.declaration for fact in facts], "value-flow fact declarations"
    )
    return {
        "inventory": LeanDeclarationRef.from_json(
            declarations["inventory"], "value-flow declarations inventory"
        ),
        "facts_exact": LeanDeclarationRef.from_json(
            declarations["facts_exact"], "value-flow declarations facts_exact"
        ),
        "facts": facts,
    }


def _validate_declaration_inputs(
    document: dict[str, Any], expected: DeclarationInputs, label: str
) -> None:
    inputs = _object(document.get("inputs"), f"{label}.inputs")
    expected_json = expected.to_json()
    if set(inputs) != set(expected_json):
        _raise_exact_keys(f"{label}.inputs", set(expected_json), inputs)
    for name, digest in expected_json.items():
        _require_digest_value(inputs, name, digest, f"{label}.inputs")


def _validate_phase_manifest(
    document: dict[str, Any],
    *,
    label: str,
    phase: str,
    public_output: tuple[str, str],
    declaration_refs: list[LeanDeclarationRef],
    expected_inputs: DeclarationInputs,
    additional_public_output: tuple[str, str] | None = None,
    exact_input_hash: tuple[str, str] | None = None,
) -> None:
    if document.get("phase") != phase:
        raise OriginalCombinedInventoryGenerationError(
            f"{label}.phase must be {phase!r}"
        )
    outputs = _object(document.get("public_outputs"), f"{label}.public_outputs")
    required_outputs = [public_output]
    if additional_public_output is not None:
        required_outputs.append(additional_public_output)
    for key, filename in required_outputs:
        if outputs.get(key) != filename:
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.public_outputs.{key} must be {filename!r}"
            )
    modules = _string_list(document.get("modules"), f"{label}.modules")
    _require_unique(modules, f"{label}.modules")
    module_set = set(modules)
    for ref in declaration_refs:
        local_module = ref.module.removeprefix("StageA.")
        if local_module not in module_set:
            raise OriginalCombinedInventoryGenerationError(
                f"{label} is missing Lean module {local_module!r} for {ref.declaration}"
            )
    inputs = _object(document.get("inputs"), f"{label}.inputs")
    for key, expected in (
        ("original_pe", expected_inputs.original_sha256),
        ("state_machine", expected_inputs.state_machine_sha256),
    ):
        row = _object(inputs.get(key), f"{label}.inputs.{key}")
        _require_digest_value(row, "sha256", expected, f"{label}.inputs.{key}")
    if exact_input_hash is not None:
        key, expected = exact_input_hash
        row = _object(inputs.get(key), f"{label}.inputs.{key}")
        _require_digest_value(row, "sha256", expected, f"{label}.inputs.{key}")


def _render_target_shard(module: str, index: int, target_ids: list[int]) -> str:
    return f"""import StageA.RelationalOriginalCombinedExecutionInvariant

namespace {_NAMESPACE}

def generatedReachableTargetIdsShard{index:04d} : List Nat :=
  {_lean_nat_list(target_ids)}

end {_NAMESPACE}
"""


def _render_reachability(
    declarations: dict[str, LeanDeclarationRef], target_shards: list[str]
) -> str:
    imports = {
        "StageA.RelationalOriginalCombinedExecutionInvariant",
        *(f"StageA.{module}" for module in target_shards),
        *(ref.module for ref in declarations.values()),
    }
    shard_names = [
        f"generatedReachableTargetIdsShard{index:04d}"
        for index in range(len(target_shards))
    ]
    target_expression = " ++\n    ".join(shard_names)
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCombinedExecutionInvariant

def generatedProgram : DecodedWorldProgram :=
  {declarations['program'].declaration}

def generatedOriginalContext : OriginalDecodedStaticContext :=
  {declarations['original_context'].declaration}

def generatedReachableTargetIds : List Nat :=
  {target_expression}

theorem generatedReachableTargetIdsExact :
    {declarations['target_ids'].declaration} = generatedReachableTargetIds :=
  {declarations['target_ids_exact'].declaration}

theorem generatedReachableTargetIdsUnique :
    generatedReachableTargetIds.Nodup := by
  rw [← generatedReachableTargetIdsExact]
  exact {declarations['target_ids_unique'].declaration}

theorem generatedReachableTargetRoundTrips :
    forall targetId, targetId ∈ generatedReachableTargetIds ->
      exists eip,
        generatedProgram.canonicalRawEip? targetId = some eip /\
          generatedProgram.resolveRawEip eip = some targetId := by
  intro targetId member
  apply {declarations['target_round_trips'].declaration} targetId
  rw [generatedReachableTargetIdsExact]
  exact member

def generatedReachableTargets :
    ExactOriginalReachableTargetInventory generatedProgram := {{
  targetIds := generatedReachableTargetIds
  targetIdsUnique := generatedReachableTargetIdsUnique
  targetRoundTrips := generatedReachableTargetRoundTrips
}}

end {_NAMESPACE}
"""


def _render_static_words(
    slots: list[StaticWordSlot], declarations: dict[str, LeanDeclarationRef]
) -> str:
    imports = {
        "StageA.RelationalOriginalCombinedExecutionInvariant",
        f"StageA.{_MODULE_PREFIX}Reachability",
        *(slot.authority.module for slot in slots),
    }
    definitions: list[str] = []
    names: list[str] = []
    for index, slot in enumerate(slots):
        name = f"generatedStaticWordRequirement{index:04d}"
        names.append(name)
        authority = slot.authority.declaration
        if slot.relation == "finite_origins":
            budget = f"{authority}.certificate.origins.length"
            origins = f"{authority}.certificate.origins"
            words = "[]"
            mode = "  admissibility := .worldOrigins\n"
        else:
            budget = "1"
            origins = f"[.staticCodeTarget {authority}.certificate.targetId 0]"
            words = (
                "[BitVec.ofNat 32 (generatedOriginalContext.pe.imageBase + "
                f"{authority}.certificate.targetRva)]"
            )
            mode = ""
        definitions.append(
            f"""def {name} : OriginalStaticWordRequirement := {{
  slot := {authority}.certificate.slot generatedOriginalContext
  finiteAlternativeBudget := {budget}
  origins := {origins}
  allowedOriginalWords := {words}
{mode}}}"""
        )
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.ValueProvenance

{chr(10).join(definitions)}

def generatedStaticWordInventory : OriginalStaticWordInventory := {{
  requirements := {_lean_name_list(names)}
}}

end {_NAMESPACE}
"""


def _render_register_targets(
    refs: list[LeanDeclarationRef], declarations: dict[str, LeanDeclarationRef]
) -> str:
    imports = {
        "StageA.RelationalOriginalCombinedExecutionInvariant",
        f"StageA.{_MODULE_PREFIX}Reachability",
        *(ref.module for ref in refs),
    }
    definitions = []
    names = []
    for index, ref in enumerate(refs):
        name = f"generatedRegisterRequirement{index:04d}"
        names.append(name)
        definitions.append(
            f"""def {name} :
    OriginalRegisterTargetRequirement generatedOriginalContext := {{
  certificate := {ref.declaration}.certificate
}}"""
        )
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational.OriginalCombinedExecutionInvariant

{chr(10).join(definitions)}

def generatedRegisterRequirements :
    List (OriginalRegisterTargetRequirement generatedOriginalContext) :=
  {_lean_name_list(names)}

end {_NAMESPACE}
"""


def _render_stack_targets(
    refs: list[LeanDeclarationRef], declarations: dict[str, LeanDeclarationRef]
) -> str:
    imports = {
        "StageA.RelationalOriginalCombinedExecutionInvariant",
        f"StageA.{_MODULE_PREFIX}Reachability",
        *(ref.module for ref in refs),
    }
    definitions = []
    names = []
    for index, ref in enumerate(refs):
        name = f"generatedStackDynamicRequirement{index:04d}"
        names.append(name)
        definitions.append(
            f"""def {name} :
    OriginalStackDynamicTargetRequirement generatedOriginalContext :=
  {ref.declaration}"""
        )
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational.OriginalCombinedExecutionInvariant

{chr(10).join(definitions)}

def generatedStackDynamicRequirements :
    List (OriginalStackDynamicTargetRequirement generatedOriginalContext) :=
  {_lean_name_list(names)}

end {_NAMESPACE}
"""


def _render_call_frames(facts: list[CallFrameFact]) -> str:
    imports = {
        "StageA.RelationalOriginalCombinedExecutionInvariant",
        *(fact.term.module for fact in facts),
    }
    definitions = "\n".join(
        f"def generatedCallFrameFact{index:04d} :=\n  {fact.term.declaration}"
        for index, fact in enumerate(facts)
    )
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

{definitions}

end {_NAMESPACE}
"""


def _render_value_flows(
    declarations: dict[str, object], reachability: dict[str, LeanDeclarationRef]
) -> str:
    inventory = declarations["inventory"]
    facts_exact = declarations["facts_exact"]
    facts = declarations["facts"]
    assert isinstance(inventory, LeanDeclarationRef)
    assert isinstance(facts_exact, LeanDeclarationRef)
    assert isinstance(facts, list)
    imports = {
        "StageA.RelationalOriginalCombinedExecutionInvariant",
        f"StageA.{_MODULE_PREFIX}Reachability",
        inventory.module,
        facts_exact.module,
        *(fact.term.module for fact in facts),
        *(fact.id_exact.module for fact in facts),
    }
    names = [f"generatedValueFlowFact{index:04d}" for index in range(len(facts))]
    definitions: list[str] = []
    for index, fact in enumerate(facts):
        name = names[index]
        definitions.append(
            f"""def {name} :
    OriginalFiniteValueFlowFact generatedProgram.context :=
  {fact.term.declaration}

theorem {name}IdExact : {name}.id = {fact.fact_id} := by
  simpa [{name}] using {fact.id_exact.declaration}"""
        )
    simp_names = ", ".join(names)
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational.OriginalValueFlowExecutionInvariant

{chr(10).join(definitions)}

def generatedValueFlowInventory :
    OriginalValueFlowInventory generatedProgram.context :=
  {inventory.declaration}

theorem generatedValueFlowFactsExact :
    generatedValueFlowInventory.facts = {_lean_name_list(names)} := by
  simpa [generatedValueFlowInventory, {simp_names}] using
    {facts_exact.declaration}

end {_NAMESPACE}
"""


def _render_inventory() -> str:
    imports = {
        f"StageA.{_MODULE_PREFIX}CallFrames",
        f"StageA.{_MODULE_PREFIX}Reachability",
        f"StageA.{_MODULE_PREFIX}RegisterTargets",
        f"StageA.{_MODULE_PREFIX}StackDynamicTargets",
        f"StageA.{_MODULE_PREFIX}StaticWords",
        f"StageA.{_MODULE_PREFIX}ValueFlows",
    }
    return f"""{_imports(imports)}

namespace {_NAMESPACE}

open StageA.Relational.OriginalCombinedExecutionInvariant

def generatedInventory :
    OriginalCombinedExecutionInventory generatedProgram generatedOriginalContext := {{
  reachableTargets := generatedReachableTargets
  staticWords := generatedStaticWordInventory
  valueFlows := generatedValueFlowInventory
  registerTargets := generatedRegisterRequirements
  stackDynamicTargets := generatedStackDynamicRequirements
}}

end {_NAMESPACE}
"""


def _canonical_manifest(
    *,
    hashes: dict[str, str],
    reachable_target_ids: list[int],
    target_shards: list[str],
    static_slots: list[StaticWordSlot],
    register_refs: list[LeanDeclarationRef],
    stack_rows: list[dict[str, Any]],
    call_frames: list[CallFrameFact],
    value_flow: dict[str, object],
    modules: list[Path],
) -> dict[str, object]:
    value_facts = value_flow["facts"]
    assert isinstance(value_facts, list)
    return {
        "format": ORIGINAL_COMBINED_INVENTORY_MANIFEST_FORMAT,
        "inputs": dict(sorted(hashes.items())),
        "lean": {
            "module": f"StageA.{_MODULE_PREFIX}",
            "namespace": _NAMESPACE,
            "inventory": f"{_NAMESPACE}.generatedInventory",
            "program": f"{_NAMESPACE}.generatedProgram",
            "original_context": f"{_NAMESPACE}.generatedOriginalContext",
            "reachable_target_ids": f"{_NAMESPACE}.generatedReachableTargetIds",
            "reachable_target_round_trips": (
                f"{_NAMESPACE}.generatedReachableTargetRoundTrips"
            ),
            "static_word_inventory": f"{_NAMESPACE}.generatedStaticWordInventory",
            "value_flow_inventory": f"{_NAMESPACE}.generatedValueFlowInventory",
            "register_requirements": [
                f"{_NAMESPACE}.generatedRegisterRequirement{index:04d}"
                for index in range(len(register_refs))
            ],
            "stack_dynamic_requirements": [
                f"{_NAMESPACE}.generatedStackDynamicRequirement{index:04d}"
                for index in range(len(stack_rows))
            ],
            "call_frame_facts": [
                f"{_NAMESPACE}.generatedCallFrameFact{index:04d}"
                for index in range(len(call_frames))
            ],
            "value_flow_facts": [
                f"{_NAMESPACE}.generatedValueFlowFact{index:04d}"
                for index in range(len(value_facts))
            ],
        },
        "counts": {
            "reachable_targets": len(reachable_target_ids),
            "reachable_target_shards": len(target_shards),
            "static_word_slots": len(static_slots),
            "register_requirements": len(register_refs),
            "stack_dynamic_requirements": len(stack_rows),
            "call_frame_facts": len(call_frames),
            "value_flow_facts": len(value_facts),
        },
        "reachable_target_shards": [
            {
                "module": f"StageA.{module}",
                "declaration": (
                    f"{_NAMESPACE}.generatedReachableTargetIdsShard{index:04d}"
                ),
            }
            for index, module in enumerate(target_shards)
        ],
        "static_word_slots": [
            {
                "slot_rva": slot.slot_rva,
                "relation": slot.relation,
                "declaration": (
                    f"{_NAMESPACE}.generatedStaticWordRequirement{index:04d}"
                ),
                "source_authority": slot.authority.to_json(),
            }
            for index, slot in enumerate(static_slots)
        ],
        "stack_dynamic_sites": [
            {
                "source_rva": row["source_rva"],
                "instruction_rva": row["instruction_rva"],
                "source_target_id": row["source_target_id"],
            }
            for row in stack_rows
        ],
        "call_frame_declarations": [
            {
                "name": fact.name,
                "kind": fact.kind,
                "site_instruction_rva": fact.site_instruction_rva,
                "source": fact.term.to_json(),
            }
            for fact in call_frames
        ],
        "value_flow_declarations": [
            {
                "id": fact.fact_id,
                "source": fact.term.to_json(),
                "id_exact": fact.id_exact.to_json(),
            }
            for fact in value_facts
        ],
        "modules": [f"StageA.{path.stem}" for path in modules],
    }


def _exact_site_rows(
    report: dict[str, Any], label: str, expected_count: int
) -> list[dict[str, Any]]:
    rows = [
        _object(value, f"{label} sites[{index}]")
        for index, value in enumerate(_list(report.get("sites"), f"{label} sites"))
    ]
    if len(rows) != expected_count:
        raise OriginalCombinedInventoryGenerationError(
            f"{label} must contain exactly {expected_count} sites, got {len(rows)}"
        )
    if "site_count" in report and report["site_count"] is not None:
        count = _natural(report["site_count"], f"{label}.site_count")
        if count != len(rows):
            raise OriginalCombinedInventoryGenerationError(
                f"{label}.site_count does not match sites"
            )
    return rows


def _raise_site_difference(label: str, expected: set[int], actual: set[int]) -> None:
    missing = [f"0x{rva:x}" for rva in sorted(expected - actual)]
    extra = [f"0x{rva:x}" for rva in sorted(actual - expected)]
    raise OriginalCombinedInventoryGenerationError(
        f"{label} site inventory has missing={missing}, extra={extra}"
    )


def _common_digest(
    rows: tuple[tuple[dict[str, Any], str, str], ...]
) -> str:
    values: list[str] = []
    for document, key, label in rows:
        value = _string(document.get(key), f"{label} inputs.{key}")
        if _SHA256.fullmatch(value) is None:
            raise OriginalCombinedInventoryGenerationError(
                f"{label} inputs.{key} is not a SHA-256 digest"
            )
        values.append(value)
    if len(set(values)) != 1:
        raise OriginalCombinedInventoryGenerationError(
            f"authority reports bind different {rows[0][1]} digests"
        )
    return values[0]


def _require_digest_value(
    document: dict[str, Any], key: str, expected: str, label: str
) -> None:
    actual = _string(document.get(key), f"{label}.{key}")
    if _SHA256.fullmatch(actual) is None:
        raise OriginalCombinedInventoryGenerationError(
            f"{label}.{key} is not a SHA-256 digest"
        )
    if actual != expected:
        raise OriginalCombinedInventoryGenerationError(
            f"{label}.{key} must be {expected}, got {actual}"
        )


def _raise_exact_keys(
    label: str, expected: set[str], actual: dict[str, Any]
) -> None:
    missing = sorted(expected - set(actual))
    extra = sorted(set(actual) - expected)
    raise OriginalCombinedInventoryGenerationError(
        f"{label} has missing keys {missing} and extra keys {extra}"
    )


def _require_format(document: dict[str, Any], expected: str, label: str) -> None:
    if document.get("format") != expected:
        raise OriginalCombinedInventoryGenerationError(
            f"{label}.format must be {expected!r}"
        )


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OriginalCombinedInventoryGenerationError(
            f"cannot read {label} {path}: {error}"
        ) from error
    return _object(value, label)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise OriginalCombinedInventoryGenerationError(
            f"cannot hash {path}: {error}"
        ) from error
    return digest.hexdigest()


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OriginalCombinedInventoryGenerationError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise OriginalCombinedInventoryGenerationError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OriginalCombinedInventoryGenerationError(
            f"{label} must be a nonempty string"
        )
    return value


def _natural(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OriginalCombinedInventoryGenerationError(
            f"{label} must be a natural number"
        )
    return value


def _natural_list(value: object, label: str) -> list[int]:
    return [
        _natural(item, f"{label}[{index}]")
        for index, item in enumerate(_list(value, label))
    ]


def _string_list(value: object, label: str) -> list[str]:
    return [
        _string(item, f"{label}[{index}]")
        for index, item in enumerate(_list(value, label))
    ]


def _require_unique(values: list[object], label: str) -> None:
    try:
        unique_count = len(set(values))
    except TypeError as error:
        raise OriginalCombinedInventoryGenerationError(
            f"{label} contains an unhashable value"
        ) from error
    if unique_count != len(values):
        raise OriginalCombinedInventoryGenerationError(
            f"{label} must not contain duplicates"
        )


def _imports(modules: set[str]) -> str:
    return "\n".join(f"import {module}" for module in sorted(modules))


def _lean_nat_list(values: list[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _lean_name_list(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"


def _write_ascii(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise OriginalCombinedInventoryGenerationError(
            f"cannot write {path}: {error}"
        ) from error
