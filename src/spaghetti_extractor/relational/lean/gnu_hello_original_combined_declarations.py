"""Derive GNU hello original-combined declaration inputs fail closed.

The combined execution inventory consumes three small JSON files containing
Lean declaration references.  This adapter does not infer theorem types from
symbol names and never treats a report status as authority.  It binds existing
checked artifact identities, requires explicit typed export inventories where
the old schemas are insufficient, and emits only the exact downstream shapes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file
from .original_combined_inventory import (
    ORIGINAL_COMBINED_CALL_FRAME_DECLARATIONS_FORMAT,
    ORIGINAL_COMBINED_REACHABILITY_DECLARATIONS_FORMAT,
    ORIGINAL_COMBINED_VALUE_FLOW_DECLARATIONS_FORMAT,
    LeanDeclarationRef,
)


_MIXED_PLAN_FORMAT = "stage-a-interpreter-mixed-original-v1"
_STATIC_PLAN_FORMAT = "stage-a-interpreter-mixed-original-static-reachability-v1"
_PHASE_FORMAT = "stage-a-relational-phase-v1"
_DIRECT_CALL_FORMAT = "stage-a-mixed-original-direct-call-authority-bindings-v2"
_STACK_FORMAT = "stage-a-original-stack-dynamic-control-closure-v1"
_STACK_COMBINED_FORMAT = "stage-a-gnu-hello-stack-dynamic-combined-evidence-v1"
_VALUE_IR_FORMAT = "stage-a-runtime-value-carry-ir-v1"
_VALUE_REPORT_FORMAT = "stage-a-runtime-value-carry-lean-v1"

REACHABILITY_EXPORT_FIELD = "original_combined_reachability_declarations"
VALUE_FLOW_EXPORT_FIELD = "original_combined_value_flow_declarations"

_REACHABILITY_FILE = "original-combined-reachability-declarations.json"
_CALL_FRAME_FILE = "original-combined-call-frame-declarations.json"
_VALUE_FLOW_FILE = "original-combined-value-flow-declarations.json"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class GnuHelloOriginalCombinedDeclarationsError(StageAInputError):
    """One declaration source is absent, ambiguous, or inconsistently bound."""


@dataclass(frozen=True)
class GnuHelloOriginalCombinedDeclarationOutputs:
    reachability: Path
    call_frames: Path
    value_flows: Path


@dataclass(frozen=True)
class _Inputs:
    mixed_original_plan_sha256: str
    original_sha256: str
    state_machine_sha256: str

    def json(self) -> dict[str, str]:
        return {
            "mixed_original_plan_sha256": self.mixed_original_plan_sha256,
            "original_sha256": self.original_sha256,
            "state_machine_sha256": self.state_machine_sha256,
        }


def write_gnu_hello_original_combined_declarations(
    *,
    mixed_original_plan: Path | str,
    mixed_original_manifest: Path | str,
    static_reachability_plan: Path | str,
    static_reachability_manifest: Path | str,
    carrier_binding_manifest: Path | str,
    direct_call_authority_report: Path | str,
    stack_dynamic_authority_report: Path | str,
    stack_dynamic_authority_manifest: Path | str,
    stack_combined_evidence_report: Path | str,
    value_provenance_ir: Path | str,
    value_provenance_report: Path | str,
    out: Path | str,
) -> GnuHelloOriginalCombinedDeclarationOutputs:
    """Write the three hash-bound declaration documents consumed downstream."""

    paths = {
        "mixed plan": Path(mixed_original_plan),
        "mixed manifest": Path(mixed_original_manifest),
        "static reachability plan": Path(static_reachability_plan),
        "static reachability manifest": Path(static_reachability_manifest),
        "carrier binding manifest": Path(carrier_binding_manifest),
        "direct-call report": Path(direct_call_authority_report),
        "stack authority report": Path(stack_dynamic_authority_report),
        "stack authority manifest": Path(stack_dynamic_authority_manifest),
        "stack combined evidence": Path(stack_combined_evidence_report),
        "value-provenance IR": Path(value_provenance_ir),
        "value-provenance report": Path(value_provenance_report),
    }
    documents = {label: _load(path, label) for label, path in paths.items()}

    plan = documents["mixed plan"]
    mixed_manifest = documents["mixed manifest"]
    static_plan = documents["static reachability plan"]
    static_manifest = documents["static reachability manifest"]
    carrier = documents["carrier binding manifest"]
    direct = documents["direct-call report"]
    stack = documents["stack authority report"]
    stack_manifest = documents["stack authority manifest"]
    combined = documents["stack combined evidence"]
    value_ir = documents["value-provenance IR"]
    value_report = documents["value-provenance report"]

    _format(plan, _MIXED_PLAN_FORMAT, "mixed plan")
    target_ids = _nat_list(
        plan.get("reachable_target_ids"), "mixed plan reachable_target_ids"
    )
    if not target_ids or target_ids != sorted(set(target_ids)):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "mixed plan reachable_target_ids must be nonempty, sorted, and unique"
        )
    state_machine = _digest(
        plan.get("state_machine_sha256"), "mixed plan state_machine_sha256"
    )
    plan_hash = sha256_file(paths["mixed plan"])

    _phase(mixed_manifest, "mixed-original-final-lean", "mixed manifest")
    mixed_inputs = _object(mixed_manifest.get("inputs"), "mixed manifest inputs")
    original = _bound_file_digest(mixed_inputs, "original_pe", "mixed manifest")
    _equal_digest(
        _bound_file_digest(mixed_inputs, "state_machine", "mixed manifest"),
        state_machine,
        "mixed manifest state_machine",
    )
    counts = _object(plan.get("counts"), "mixed plan counts")
    mixed_counts = _object(mixed_manifest.get("counts"), "mixed manifest counts")
    if _nat(counts.get("regions"), "mixed plan region count") != _nat(
        mixed_counts.get("regions"), "mixed manifest region count"
    ):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "mixed manifest region count does not match mixed plan"
        )

    _format(static_plan, _STATIC_PLAN_FORMAT, "static reachability plan")
    static_inputs = _object(
        static_plan.get("inputs"), "static reachability plan inputs"
    )
    _equal_digest(
        _bound_file_digest(
            static_inputs, "mixed_original_plan", "static reachability plan"
        ),
        plan_hash,
        "static reachability plan mixed_original_plan",
    )
    _equal_digest(
        _digest(
            static_inputs.get("state_machine_sha256"),
            "static reachability state machine",
        ),
        state_machine,
        "static reachability state machine",
    )
    static_counts = _object(static_plan.get("counts"), "static reachability plan counts")
    if (
        _nat(
            static_counts.get("reachable_targets"),
            "static reachable target count",
        )
        != len(target_ids)
    ):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "static reachability target count does not match mixed plan"
        )
    static_result = _object(static_plan.get("result"), "static reachability result")
    static_theorem = _declaration_string(
        static_result.get("theorem"), "static reachability theorem"
    )

    _phase(
        static_manifest,
        "mixed-original-static-reachability",
        "static reachability manifest",
    )
    static_manifest_inputs = _object(
        static_manifest.get("inputs"), "static reachability manifest inputs"
    )
    _equal_digest(
        _bound_file_digest(
            static_manifest_inputs,
            "mixed_original_plan",
            "static reachability manifest",
        ),
        plan_hash,
        "static reachability manifest mixed_original_plan",
    )
    if static_manifest.get("theorem") != static_theorem:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "static reachability manifest theorem does not match its plan"
        )

    _phase(
        carrier,
        "mixed-original-carrier-binding-lean",
        "carrier binding manifest",
    )
    carrier_inputs = _object(carrier.get("inputs"), "carrier binding manifest inputs")
    _equal_digest(
        _bound_file_digest(
            carrier_inputs,
            "mixed_original_manifest",
            "carrier binding manifest",
        ),
        sha256_file(paths["mixed manifest"]),
        "carrier binding mixed_original_manifest",
    )
    exact_binding = _declaration_string(
        carrier.get("exact_mixed_binding"), "carrier exact_mixed_binding"
    )

    _format(direct, _DIRECT_CALL_FORMAT, "direct-call report")
    direct_inputs = _object(direct.get("inputs"), "direct-call report inputs")
    _shared_binary_inputs(direct_inputs, original, state_machine, "direct-call report")

    _format(stack, _STACK_FORMAT, "stack authority report")
    stack_inputs = _object(stack.get("inputs"), "stack authority report inputs")
    _shared_binary_inputs(
        stack_inputs,
        original,
        state_machine,
        "stack authority report",
        original_key="original_pe_sha256",
    )

    _phase(
        stack_manifest,
        "mixed-original-stack-dynamic-authority-lean",
        "stack authority manifest",
    )
    stack_manifest_inputs = _object(
        stack_manifest.get("inputs"), "stack authority manifest inputs"
    )
    _equal_digest(
        _bound_file_digest(
            stack_manifest_inputs, "original_pe", "stack authority manifest"
        ),
        original,
        "stack authority manifest original_pe",
    )
    _equal_digest(
        _bound_file_digest(
            stack_manifest_inputs, "state_machine", "stack authority manifest"
        ),
        state_machine,
        "stack authority manifest state_machine",
    )
    _equal_digest(
        _bound_file_digest(
            stack_manifest_inputs,
            "direct_call_authority",
            "stack authority manifest",
        ),
        sha256_file(paths["direct-call report"]),
        "stack authority manifest direct_call_authority",
    )
    _equal_digest(
        _bound_file_digest(
            stack_manifest_inputs,
            "runtime_value_carry",
            "stack authority manifest",
        ),
        sha256_file(paths["value-provenance IR"]),
        "stack authority manifest runtime_value_carry",
    )
    _equal_digest(
        _bound_file_digest(
            stack_manifest_inputs,
            "runtime_value_carry_lean_report",
            "stack authority manifest",
        ),
        sha256_file(paths["value-provenance report"]),
        "stack authority manifest runtime_value_carry_lean_report",
    )

    _format(combined, _STACK_COMBINED_FORMAT, "stack combined evidence")
    if combined.get("proof_authority") is not False:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "stack combined evidence must explicitly disclaim report proof authority"
        )

    _format(value_ir, _VALUE_IR_FORMAT, "value-provenance IR")
    value_inputs = _object(value_ir.get("inputs"), "value-provenance IR inputs")
    _shared_binary_inputs(
        value_inputs,
        original,
        state_machine,
        "value-provenance IR",
        original_key="original_pe_sha256",
    )
    _equal_digest(
        _digest(
            value_inputs.get("direct_call_authority_sha256"),
            "value-provenance direct-call digest",
        ),
        sha256_file(paths["direct-call report"]),
        "value-provenance direct_call_authority",
    )

    _format(value_report, _VALUE_REPORT_FORMAT, "value-provenance report")
    if value_report.get("proof_authority") is not False:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "value-provenance report must explicitly disclaim report proof authority"
        )
    _validate_value_routes(value_ir, value_report)

    inputs = _Inputs(plan_hash, original, state_machine)
    reachability = _reachability_document(
        plan=plan,
        carrier=carrier,
        mixed_manifest=mixed_manifest,
        static_manifest=static_manifest,
        static_theorem=static_theorem,
        exact_binding=exact_binding,
        inputs=inputs,
    )
    call_frames = _call_frame_document(
        direct=direct,
        stack=stack,
        stack_manifest=stack_manifest,
        combined=combined,
        value_ir=value_ir,
        inputs=inputs,
    )
    value_flows = _value_flow_document(
        value_report=value_report, value_ir=value_ir, inputs=inputs
    )

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    reachability_path = root / _REACHABILITY_FILE
    call_frames_path = root / _CALL_FRAME_FILE
    value_flows_path = root / _VALUE_FLOW_FILE
    _write_json(reachability_path, reachability)
    _write_json(call_frames_path, call_frames)
    _write_json(value_flows_path, value_flows)
    return GnuHelloOriginalCombinedDeclarationOutputs(
        reachability=reachability_path,
        call_frames=call_frames_path,
        value_flows=value_flows_path,
    )


def _reachability_document(
    *,
    plan: Mapping[str, Any],
    carrier: Mapping[str, Any],
    mixed_manifest: Mapping[str, Any],
    static_manifest: Mapping[str, Any],
    static_theorem: str,
    exact_binding: str,
    inputs: _Inputs,
) -> dict[str, Any]:
    exports_value = plan.get(REACHABILITY_EXPORT_FIELD)
    if exports_value is None:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "mixed-original plan is missing required schema field "
            f"{REACHABILITY_EXPORT_FIELD}; it must name a concrete DecodedWorldProgram, "
            "target-list equality/uniqueness, and canonical target round-trip witnesses"
        )
    declarations = _object(
        exports_value, f"mixed-original plan {REACHABILITY_EXPORT_FIELD}"
    )
    names = {
        "program",
        "original_context",
        "target_ids",
        "target_ids_exact",
        "target_ids_unique",
        "target_round_trips",
    }
    _exact_keys(declarations, names, "reachability declarations")
    refs = {
        name: _ref(declarations[name], f"reachability declarations.{name}")
        for name in names
    }
    allowed_modules = (
        _module_inventory(mixed_manifest, "mixed manifest")
    )
    _refs_in_modules(
        refs.values(),
        allowed_modules,
        "reachability",
    )
    if not static_theorem.endswith(
        ".generatedExactOriginalDecodedStaticReachability"
    ):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "static reachability theorem is not the canonical checked export"
        )
    if not exact_binding.endswith(".generatedOriginalExactMixedProgramBinding"):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "carrier exact mixed binding is not the canonical checked export"
        )
    _module_inventory(static_manifest, "static reachability manifest")
    _module_inventory(carrier, "carrier binding manifest")
    return {
        "format": ORIGINAL_COMBINED_REACHABILITY_DECLARATIONS_FORMAT,
        "inputs": inputs.json(),
        "declarations": {name: refs[name].to_json() for name in sorted(names)},
    }


def _call_frame_document(
    *,
    direct: Mapping[str, Any],
    stack: Mapping[str, Any],
    stack_manifest: Mapping[str, Any],
    combined: Mapping[str, Any],
    value_ir: Mapping[str, Any],
    inputs: _Inputs,
) -> dict[str, Any]:
    stack_sites = [
        _object(row, f"stack site {index}")
        for index, row in enumerate(_list(stack.get("sites"), "stack sites"))
    ]
    finite_sites = [
        site
        for site in stack_sites
        if site.get("closure_mode") == "finite_stack_target"
    ]
    if not finite_sites:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "stack authority report has no finite_stack_target site"
        )
    combined_rows = [
        _object(value, f"combined site {index}")
        for index, value in enumerate(
            _list(combined.get("sites"), "stack combined sites")
        )
    ]
    combined_sites = {
        _nat(row.get("instruction_rva"), f"combined site {index} instruction_rva"): row
        for index, row in enumerate(combined_rows)
    }
    if len(combined_sites) != len(combined_rows):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "stack combined evidence repeats an instruction RVA"
        )
    direct_rows = [
        _object(row, f"direct-call contract {index}")
        for index, row in enumerate(
            _list(direct.get("contracts"), "direct-call contracts")
        )
    ]
    value_routes = [
        _object(row, f"value route {index}")
        for index, row in enumerate(_list(value_ir.get("routes"), "value routes"))
    ]
    kernel_check = _object(combined.get("kernel_check"), "stack combined kernel_check")
    kernel_term = _ref(kernel_check.get("term"), "stack combined kernel_check.term")
    modules = _module_inventory(stack_manifest, "stack authority manifest")
    if kernel_term.module.removeprefix("StageA.") not in modules:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "stack authority manifest does not list the combined-evidence module"
        )

    facts: list[dict[str, Any]] = []
    ordered_sites = sorted(
        finite_sites,
        key=lambda row: _nat(
            row.get("instruction_rva"), "stack site instruction_rva"
        ),
    )
    for site_index, site in enumerate(ordered_sites):
        instruction_rva = _nat(
            site.get("instruction_rva"),
            f"finite stack site {site_index} instruction_rva",
        )
        source_rva = _nat(
            site.get("source_rva"), f"finite stack site {site_index} source_rva"
        )
        source_target_id = _nat(
            site.get("source_target_id"),
            f"finite stack site {site_index} source_target_id",
        )
        combined_site = combined_sites.get(instruction_rva)
        if combined_site is None:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"stack combined evidence is missing finite stack instruction 0x{instruction_rva:x}"
            )
        if (
            _nat(
                combined_site.get("source_target_id"),
                "combined source_target_id",
            )
            != source_target_id
        ):
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"stack combined source target disagrees at 0x{instruction_rva:x}"
            )
        dependencies = _string_list(
            combined_site.get("checked_dependencies"),
            "combined checked_dependencies",
        )
        expected_kinds = {
            "generatedStackCallEntryCertificate": "call_entry_certificate",
            "generatedStackCallFrameTransferAuthority": "call_frame_transfer",
        }
        if {name.rsplit(".", 1)[-1] for name in dependencies} != set(
            expected_kinds
        ):
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"finite stack instruction 0x{instruction_rva:x} lacks the "
                "exact call-entry and call-frame typed dependencies"
            )
        for dependency in sorted(dependencies):
            namespace, symbol = dependency.rsplit(".", 1)
            if namespace != kernel_term.namespace:
                raise GnuHelloOriginalCombinedDeclarationsError(
                    f"call-frame dependency {dependency} is outside the "
                    "checked combined-evidence namespace"
                )
            ref = LeanDeclarationRef(kernel_term.module, namespace, symbol)
            ref.validate("call-frame dependency")
            facts.append(
                {
                    "name": f"stack{instruction_rva:08x}{symbol}",
                    "kind": expected_kinds[symbol],
                    "site_instruction_rva": instruction_rva,
                    "term": ref.to_json(),
                }
            )

        matching_contracts = [
            row
            for row in direct_rows
            if row.get("source_rva") == source_rva
            and row.get("callsite_rva") == instruction_rva
            and row.get("origin") in {
                "checked_direct_call_caller_frame_word_summary",
                "checked_finite_origin_call_caller_frame_word_summary",
            }
        ]
        if len(matching_contracts) != 1:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"finite stack instruction 0x{instruction_rva:x} must have one "
                "exact caller-frame direct-call contract"
            )
        contract = matching_contracts[0]
        authority = _ref(
            contract.get("authorizing_lean_term"),
            "caller-frame direct-call authority",
        )
        dedicated = _ref(
            contract.get("caller_frame_word_authorizing_lean_term"),
            "dedicated caller-frame authority",
        )
        if authority != dedicated:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"finite stack instruction 0x{instruction_rva:x} has mismatched "
                "caller-frame authorities"
            )
        offsets = _nat_list(
            contract.get("preserved_caller_frame_word_offsets"),
            "caller-frame offsets",
        )
        if not offsets or len(set(offsets)) != len(offsets):
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"finite stack instruction 0x{instruction_rva:x} has no finite "
                "caller-frame word inventory"
            )
        continuation_target_id = _nat(
            contract.get("continuation_target_id"),
            "direct-call continuation_target_id",
        )
        matching_transfers = [
            transfer
            for route in value_routes
            for transfer_index, transfer_value in enumerate(
                _list(route.get("transfers"), "value route transfers")
            )
            for transfer in [_object(transfer_value, f"value transfer {transfer_index}")]
            if transfer.get("kind") == "call_frame_word_preserve"
            and transfer.get("source_target_id") == source_target_id
            and transfer.get("target_target_id") == continuation_target_id
        ]
        if len(matching_transfers) != 1:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"finite stack instruction 0x{instruction_rva:x} must have one "
                "exact value-provenance call-frame transfer"
            )
        transfer_authority = _ref(
            matching_transfers[0].get("authority_lean_term"),
            "value-provenance call-frame transfer authority",
        )
        if transfer_authority != authority:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"finite stack instruction 0x{instruction_rva:x} value-provenance "
                "authority disagrees with direct-call authority"
            )

    names = [row["name"] for row in facts]
    if len(set(names)) != len(names):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "derived call-frame fact names are not unique"
        )
    return {
        "format": ORIGINAL_COMBINED_CALL_FRAME_DECLARATIONS_FORMAT,
        "inputs": inputs.json(),
        "declarations": {"facts": facts},
    }


def _value_flow_document(
    *, value_report: Mapping[str, Any], value_ir: Mapping[str, Any], inputs: _Inputs
) -> dict[str, Any]:
    exports_value = value_report.get(VALUE_FLOW_EXPORT_FIELD)
    if exports_value is None:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "value-provenance report is missing required schema field "
            f"{VALUE_FLOW_EXPORT_FIELD}; aggregate_invariant_constructor is not a typed "
            "OriginalValueFlowInventory export"
        )
    exports = _object(exports_value, f"value-provenance {VALUE_FLOW_EXPORT_FIELD}")
    required = {"inventory", "facts_exact", "facts"}
    _exact_keys(exports, required, f"value-provenance {VALUE_FLOW_EXPORT_FIELD}")
    inventory = _ref(exports["inventory"], "value-flow inventory")
    facts_exact = _ref(exports["facts_exact"], "value-flow facts_exact")
    rows = [
        _object(value, f"value-flow fact {index}")
        for index, value in enumerate(_list(exports["facts"], "value-flow facts"))
    ]
    expected_facts = _expected_value_flow_facts(value_ir)
    facts: list[dict[str, Any]] = []
    observed_fact_order: list[str] = []
    seen_facts: set[str] = set()
    for index, row in enumerate(rows):
        _exact_keys(
            row,
            {
                "route_stable_id",
                "fact_stable_id",
                "location_id",
                "target_ids",
                "id",
                "term",
                "id_exact",
            },
            f"value-flow fact {index}",
        )
        route = _string(
            row["route_stable_id"],
            f"value-flow fact {index} route_stable_id",
        )
        stable_id = _string(
            row["fact_stable_id"],
            f"value-flow fact {index} fact_stable_id",
        )
        if stable_id in seen_facts:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"value-flow declarations repeat fact {stable_id!r}"
            )
        seen_facts.add(stable_id)
        observed_fact_order.append(stable_id)
        expected = expected_facts.get(stable_id)
        if expected is None:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"value-flow declaration {stable_id!r} is not present in the "
                "exact value-provenance route inventory"
            )
        location_id = _nat(
            row["location_id"], f"value-flow fact {index} location_id"
        )
        target_ids = _nat_list(
            row["target_ids"], f"value-flow fact {index} target_ids"
        )
        if (
            route != expected["route_stable_id"]
            or location_id != expected["location_id"]
            or target_ids != expected["target_ids"]
        ):
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"value-flow declaration {stable_id!r} does not match its "
                "exact route/location fact group"
            )
        facts.append(
            {
                "id": _nat(row["id"], f"value-flow fact {index} id"),
                "term": _ref(row["term"], f"value-flow fact {index} term").to_json(),
                "id_exact": _ref(
                    row["id_exact"], f"value-flow fact {index} id_exact"
                ).to_json(),
            }
        )
    if seen_facts != set(expected_facts):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "typed value-flow facts do not cover the exact value-provenance route inventory"
        )
    if observed_fact_order != list(expected_facts):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "typed value-flow facts are not in canonical route/location order"
        )
    if [row["id"] for row in facts] != list(range(len(facts))):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "typed value-flow fact IDs must be nonempty, dense, and unique"
        )
    modules = _module_inventory(value_report, "value-provenance report")
    refs = [inventory, facts_exact]
    for row in facts:
        refs.extend(
            (
                LeanDeclarationRef.from_json(row["term"], "value-flow term"),
                LeanDeclarationRef.from_json(
                    row["id_exact"], "value-flow id_exact"
                ),
            )
        )
    _refs_in_modules(refs, modules, "value-flow")
    return {
        "format": ORIGINAL_COMBINED_VALUE_FLOW_DECLARATIONS_FORMAT,
        "inputs": inputs.json(),
        "declarations": {
            "inventory": inventory.to_json(),
            "facts_exact": facts_exact.to_json(),
            "facts": facts,
        },
    }


def _expected_value_flow_facts(
    value_ir: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {}
    routes = _list(value_ir.get("routes"), "value routes")
    for route_index, route_value in enumerate(routes):
        route = _object(route_value, f"value route {route_index}")
        route_id = _string(
            route.get("stable_id"), f"value route {route_index} stable_id"
        )
        locations = [
            _object(value, f"value route {route_id} location {index}")
            for index, value in enumerate(
                _list(route.get("locations"), f"value route {route_id} locations")
            )
        ]
        location_ids = [
            _nat(location.get("location_id"), f"value route {route_id} location_id")
            for location in locations
        ]
        if location_ids != list(range(len(locations))):
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"value route {route_id!r} locations must form a dense index"
            )
        grouped: dict[int, list[int]] = {}
        seen_route_facts: set[tuple[int, int]] = set()
        for fact_index, fact_value in enumerate(
            _list(route.get("facts"), f"value route {route_id} facts")
        ):
            fact = _object(
                fact_value, f"value route {route_id} fact {fact_index}"
            )
            target_id = _nat(
                fact.get("target_id"),
                f"value route {route_id} fact target_id",
            )
            location_id = _nat(
                fact.get("location_id"),
                f"value route {route_id} fact location_id",
            )
            if location_id >= len(locations):
                raise GnuHelloOriginalCombinedDeclarationsError(
                    f"value route {route_id!r} fact references unknown location "
                    f"{location_id}"
                )
            key = (target_id, location_id)
            if key in seen_route_facts:
                raise GnuHelloOriginalCombinedDeclarationsError(
                    f"value route {route_id!r} repeats fact {key}"
                )
            seen_route_facts.add(key)
            grouped.setdefault(location_id, []).append(target_id)
        if not grouped:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"value route {route_id!r} has no finite value facts"
            )
        for location_id in sorted(grouped):
            target_ids = sorted(grouped[location_id])
            stable_id = f"{route_id}:location:{location_id}"
            if stable_id in expected:
                raise GnuHelloOriginalCombinedDeclarationsError(
                    f"value-flow fact stable ID {stable_id!r} is not unique"
                )
            expected[stable_id] = {
                "route_stable_id": route_id,
                "location_id": location_id,
                "target_ids": target_ids,
            }
    if not expected:
        raise GnuHelloOriginalCombinedDeclarationsError(
            "value-provenance IR has no typed value-flow fact groups"
        )
    return expected


def _validate_value_routes(value_ir: Mapping[str, Any], value_report: Mapping[str, Any]) -> None:
    ir_routes = {
        _string(row.get("stable_id"), f"value IR route {index} stable_id"): row
        for index, value in enumerate(_list(value_ir.get("routes"), "value IR routes"))
        for row in [_object(value, f"value IR route {index}")]
    }
    report_routes = {
        _string(row.get("stable_id"), f"value report route {index} stable_id"): row
        for index, value in enumerate(_list(value_report.get("routes"), "value report routes"))
        for row in [_object(value, f"value report route {index}")]
    }
    if set(ir_routes) != set(report_routes):
        raise GnuHelloOriginalCombinedDeclarationsError(
            "value-provenance report route inventory does not match its IR"
        )
    for stable_id in sorted(ir_routes):
        ir_transfer_ids = {
            _nat(row.get("transfer_id"), f"value IR route {stable_id} transfer_id")
            for value in _list(ir_routes[stable_id].get("transfers"), f"value IR route {stable_id} transfers")
            for row in [_object(value, f"value IR route {stable_id} transfer")]
        }
        report_transfer_ids = {
            _nat(row.get("transfer_id"), f"value report route {stable_id} transfer_id")
            for value in _list(report_routes[stable_id].get("semantic_authority"), f"value report route {stable_id} semantic_authority")
            for row in [_object(value, f"value report route {stable_id} authority")]
        }
        if ir_transfer_ids != report_transfer_ids:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"value-provenance route {stable_id!r} semantic authority inventory is incomplete"
            )


def _phase(document: Mapping[str, Any], phase: str, label: str) -> None:
    _format(document, _PHASE_FORMAT, label)
    if document.get("phase") != phase or document.get("proof_authority") is not False:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"{label} must be phase {phase!r} and explicitly disclaim report proof authority"
        )


def _module_inventory(document: Mapping[str, Any], label: str) -> set[str]:
    modules = _string_list(document.get("modules"), f"{label} modules")
    if len(set(modules)) != len(modules):
        raise GnuHelloOriginalCombinedDeclarationsError(f"{label} modules are not unique")
    return set(modules)


def _refs_in_modules(refs: Any, modules: set[str], label: str) -> None:
    for ref in refs:
        local = ref.module.removeprefix("StageA.")
        if local not in modules:
            raise GnuHelloOriginalCombinedDeclarationsError(
                f"{label} declaration {ref.declaration} names unlisted module {ref.module}"
            )


def _shared_binary_inputs(
    inputs: Mapping[str, Any],
    original: str,
    state_machine: str,
    label: str,
    *,
    original_key: str = "original_sha256",
) -> None:
    _equal_digest(_digest(inputs.get(original_key), f"{label} {original_key}"), original, f"{label} {original_key}")
    _equal_digest(
        _digest(inputs.get("state_machine_sha256"), f"{label} state_machine_sha256"),
        state_machine,
        f"{label} state_machine_sha256",
    )


def _bound_file_digest(inputs: Mapping[str, Any], key: str, label: str) -> str:
    row = _object(inputs.get(key), f"{label} inputs.{key}")
    return _digest(row.get("sha256"), f"{label} inputs.{key}.sha256")


def _equal_digest(observed: str, expected: str, label: str) -> None:
    if observed != expected:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"{label} SHA-256 does not match the shared artifact identity"
        )


def _ref(value: object, label: str) -> LeanDeclarationRef:
    try:
        return LeanDeclarationRef.from_json(value, label)
    except StageAInputError as error:
        raise GnuHelloOriginalCombinedDeclarationsError(str(error)) from error


def _declaration_string(value: object, label: str) -> str:
    text = _string(value, label)
    if "." not in text:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"{label} must be a fully qualified Lean declaration"
        )
    return text


def _format(document: Mapping[str, Any], expected: str, label: str) -> None:
    if document.get("format") != expected:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"{label}.format must be {expected!r}"
        )


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"{label} must contain exactly {', '.join(sorted(expected))}"
        )


def _load(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GnuHelloOriginalCombinedDeclarationsError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloOriginalCombinedDeclarationsError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloOriginalCombinedDeclarationsError(f"{label} must be a nonempty string")
    return value


def _string_list(value: object, label: str) -> list[str]:
    rows = _list(value, label)
    result = [_string(row, f"{label}[{index}]") for index, row in enumerate(rows)]
    if len(set(result)) != len(result):
        raise GnuHelloOriginalCombinedDeclarationsError(f"{label} must be unique")
    return result


def _nat(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloOriginalCombinedDeclarationsError(f"{label} must be a natural number")
    return value


def _nat_list(value: object, label: str) -> list[int]:
    return [_nat(row, f"{label}[{index}]") for index, row in enumerate(_list(value, label))]


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise GnuHelloOriginalCombinedDeclarationsError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


__all__ = [
    "GnuHelloOriginalCombinedDeclarationOutputs",
    "GnuHelloOriginalCombinedDeclarationsError",
    "REACHABILITY_EXPORT_FIELD",
    "VALUE_FLOW_EXPORT_FIELD",
    "write_gnu_hello_original_combined_declarations",
]
