"""Close rooted direct control with exact, overlapping instruction views."""

from __future__ import annotations

import heapq
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ._contract_tools.common import BlockMapping
from ._contract_tools.reference_contract import _semantic_transfer_contract
from .artifact_formats import MACHINE_IR_FORMAT
from .recursive_decode import (
    ROOTED_INSTRUCTION_VIEW_FORMAT,
    discover_rooted_instruction_views,
)
from .stage_b_state_machine import (
    STAGE_B_STATE_MACHINE_FORMAT,
    annotate_state_machine_import_contracts,
    load_stage_a_reference_contract_binding,
    normalize_stage_a_semantic_transfer,
    semantic_direct_targets,
    write_stage_b_state_machine,
)
from .stage_binary import BlockSide, StageAInputError, _parse_stage_a_pe
from .util import sha256_bytes, sha256_file, write_json


ROOTED_STATE_MACHINE_CLOSURE_FORMAT = "stage-b-rooted-static-control-closure-v1"


def close_state_machine_rooted_direct_control(
    *,
    state_machine: Path,
    original_pe: Path,
    reference_contract: Path,
    out: Path,
    report: Path,
    machine_import_profiles: Sequence[Path] = (),
    control_manifest: Path | None = None,
    instruction_budget: int = 65536,
    iteration_budget: int = 32,
) -> dict[str, Any]:
    """Materialize every missing direct target reachable from binary roots.

    Conservative full-section decoding may choose a false linear view over a
    real branch destination. Recursive decoding preserves both views and lets
    rooted control select the executable one. Indirect exits remain explicit
    frontiers for provenance analysis in the final machine-IR phase.
    """

    state_machine = _regular_file(state_machine, "base state machine")
    original_pe = _regular_file(original_pe, "original PE")
    reference_contract = _regular_file(
        reference_contract, "reference contract"
    )
    machine_import_profiles = tuple(
        _regular_file(path, "machine import profile")
        for path in machine_import_profiles
    )
    control_manifest = (
        _regular_file(control_manifest, "control manifest")
        if control_manifest is not None
        else None
    )
    if instruction_budget <= 0:
        raise StageAInputError("rooted decode instruction budget must be positive")
    if iteration_budget <= 0:
        raise StageAInputError("rooted decode iteration budget must be positive")

    reference = load_stage_a_reference_contract_binding(
        reference_contract, original_pe=original_pe
    )
    base_rows = _canonical_state_machine_rows(state_machine)
    annotated_rows, terminating_rvas = annotate_state_machine_import_contracts(
        base_rows, machine_import_profiles=machine_import_profiles
    )
    merged = list(annotated_rows)
    supplemental: list[dict[str, Any]] = []
    terminating = set(terminating_rvas)
    rounds: list[dict[str, Any]] = []
    discovered_views: list[dict[str, Any]] = []
    merge_destinations: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    binary = _parse_stage_a_pe(original_pe)
    try:
        binary_roots = _binary_roots(binary)
        manifest_seeds = (
            _manifest_seed_roots(
                control_manifest,
                state_machine_sha256=sha256_file(state_machine),
                original_sha256=sha256_file(original_pe),
                reference_sha256=reference.sha256,
                materialized_rvas={_transfer_start(row) for row in merged},
            )
            if control_manifest is not None
            else []
        )
        manifest_roots = [
            seed for seed in manifest_seeds if seed.get("behavioral_root") is True
        ]
        pending_decode_seeds = {
            int(seed["rva"])
            for seed in manifest_seeds
            if int(seed["rva"]) not in {_transfer_start(row) for row in merged}
        }
        roots = _merge_roots(binary_roots, manifest_roots)
        initial = _rooted_direct_reachability(merged, roots)
        final = initial
        for round_index in range(iteration_budget):
            seeds = sorted(
                set(final["missing_target_rvas"]) | pending_decode_seeds
            )
            if not seeds:
                break
            remaining_budget = instruction_budget - len(discovered_views)
            if remaining_budget <= 0:
                issues.append({
                    "code": "rooted_instruction_budget_exhausted",
                    "message": "rooted direct closure exhausted its instruction budget",
                    "pending_rvas": seeds,
                })
                break
            existing_rvas = {_transfer_start(row) for row in merged}
            discovery = discover_rooted_instruction_views(
                binary, seeds, existing_rvas, remaining_budget
            )
            round_rows = [
                _view_transfer(
                    binary=binary,
                    view=view,
                    reference_path=reference_contract,
                    reference_sha256=reference.sha256,
                )
                for view in discovery["views"]
            ]
            round_rows, round_terminating = annotate_state_machine_import_contracts(
                round_rows, machine_import_profiles=machine_import_profiles
            )
            new_rows = [
                row for row in round_rows
                if _transfer_start(row) not in existing_rvas
            ]
            discovered_views.extend(discovery["views"])
            merge_destinations.extend(discovery["merge_destinations"])
            issues.extend(discovery["issues"])
            rounds.append({
                "index": round_index,
                "seed_rvas": list(seeds),
                "decoded_instruction_count": discovery["decoded_instruction_count"],
                "new_transfers": len(new_rows),
                "merge_destinations": len(discovery["merge_destinations"]),
                "issues": len(discovery["issues"]),
            })
            if discovery["status"] != "complete" or not new_rows:
                if not discovery["issues"]:
                    issues.append({
                        "code": "rooted_decode_made_no_progress",
                        "message": "rooted direct targets remain but decoding added no transfer",
                        "pending_rvas": seeds,
                    })
                break
            merged.extend(new_rows)
            supplemental.extend(new_rows)
            pending_decode_seeds.difference_update(
                _transfer_start(row) for row in new_rows
            )
            terminating.update(round_terminating)
            final = _rooted_direct_reachability(merged, roots)
        else:
            if final["missing_target_rvas"]:
                issues.append({
                    "code": "rooted_iteration_budget_exhausted",
                    "message": "rooted direct closure exhausted its iteration budget",
                    "pending_rvas": final["missing_target_rvas"],
                })
    finally:
        binary.pe.close()

    merged.sort(key=lambda row: (_transfer_start(row), str(row.get("id"))))
    final = _rooted_direct_reachability(merged, roots)
    if final["missing_target_rvas"]:
        issues.append({
            "code": "rooted_direct_control_incomplete",
            "message": "rooted direct targets remain after recursive decode",
            "pending_rvas": final["missing_target_rvas"],
        })
    status = (
        "complete"
        if not final["missing_target_rvas"]
        and not issues
        else "incomplete"
    )

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_stage_b_state_machine(out, merged)
    payload = {
        "format": ROOTED_STATE_MACHINE_CLOSURE_FORMAT,
        "status": status,
        "inputs": {
            "state_machine_sha256": sha256_file(state_machine),
            "original_pe_sha256": sha256_file(original_pe),
            "reference_contract_sha256": reference.sha256,
            "machine_import_profile_sha256s": [
                sha256_file(path) for path in machine_import_profiles
            ],
            "control_manifest_sha256": (
                sha256_file(control_manifest)
                if control_manifest is not None
                else None
            ),
        },
        "output": {"path": out.name, "sha256": sha256_file(out)},
        "roots": roots,
        "decode_seeds": manifest_seeds,
        "initial_reachability": initial,
        "final_reachability": final,
        "discovery": {
            "format": ROOTED_INSTRUCTION_VIEW_FORMAT,
            "status": "complete" if not issues else "incomplete",
            "instruction_budget": instruction_budget,
            "iteration_budget": iteration_budget,
            "rounds": rounds,
            "views": discovered_views,
            "merge_destinations": merge_destinations,
            "issues": issues,
        },
        "issues": issues,
        "counts": {
            "base_transfers": len(base_rows),
            "supplemental_transfers": len(supplemental),
            "output_transfers": len(merged),
            "initial_reachable_transfers": initial["counts"]["reachable_transfers"],
            "final_reachable_transfers": final["counts"]["reachable_transfers"],
            "initial_missing_direct_targets": initial["counts"]["missing_direct_targets"],
            "remaining_missing_direct_targets": final["counts"]["missing_direct_targets"],
            "indirect_frontiers": final["counts"]["indirect_frontiers"],
            "closure_rounds": len(rounds),
            "terminating_transfers": len(terminating),
            "issues": len(issues),
        },
        "terminating_transfer_rvas": sorted(terminating),
        "trust": {
            "executes_original_binary": False,
            "recursive_decode_is_proposal_only": True,
            "exact_pe_binding_required_downstream": True,
            "semantic_binding_required_downstream": True,
            "indirect_control_is_not_silently_closed": True,
            "control_manifest_is_proposal_only": True,
        },
    }
    report = Path(report)
    report.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, payload)
    return payload


def _rooted_direct_reachability(
    rows: list[dict[str, Any]], roots: list[dict[str, Any]]
) -> dict[str, Any]:
    starts: dict[int, dict[str, Any]] = {}
    for row in rows:
        start = _transfer_start(row)
        if start in starts:
            raise StageAInputError(
                f"state machine has duplicate transfer start 0x{start:x}"
            )
        starts[start] = row

    pending = [int(root["rva"]) for root in roots]
    heapq.heapify(pending)
    queued = set(pending)
    visited: set[int] = set()
    missing: set[int] = set()
    indirect: list[dict[str, Any]] = []
    edges = 0
    while pending:
        rva = heapq.heappop(pending)
        queued.discard(rva)
        if rva in visited:
            continue
        visited.add(rva)
        row = starts.get(rva)
        if row is None:
            missing.add(rva)
            continue
        if row.get("control_disposition") is not None:
            continue

        successors = list(semantic_direct_targets(row))
        external_events = row.get("external_events")
        if not isinstance(external_events, list):
            raise StageAInputError("semantic transfer external_events must be a list")
        for event_index, raw_event in enumerate(external_events):
            event = _mapping(raw_event, "semantic external event")
            kind = event.get("kind")
            if kind == "internal_call":
                successors.append(
                    _u32(event.get("target_rva"), "internal call target")
                )
            elif kind in {"indirect_call", "indirect_jump"}:
                indirect.append({
                    "source_rva": rva,
                    "source_unit_id": row.get("id"),
                    "source_event_index": event_index,
                    "kind": kind,
                })
        outcome = _mapping(row.get("outcome"), "semantic transfer outcome")
        if outcome.get("kind") == "indirect":
            indirect.append({
                "source_rva": rva,
                "source_unit_id": row.get("id"),
                "source_event_index": None,
                "kind": "indirect_jump",
            })

        for target in sorted(set(successors)):
            edges += 1
            if target not in visited and target not in queued:
                heapq.heappush(pending, target)
                queued.add(target)

    reachable = sorted(rva for rva in visited if rva in starts)
    return {
        "status": "complete" if not missing else "incomplete",
        "root_rvas": sorted(int(root["rva"]) for root in roots),
        "reachable_transfer_rvas": reachable,
        "missing_target_rvas": sorted(missing),
        "indirect_frontiers": sorted(
            indirect,
            key=lambda item: (
                int(item["source_rva"]),
                str(item["kind"]),
                -1
                if item["source_event_index"] is None
                else int(item["source_event_index"]),
            ),
        ),
        "counts": {
            "roots": len(roots),
            "reachable_transfers": len(reachable),
            "missing_direct_targets": len(missing),
            "indirect_frontiers": len(indirect),
            "direct_edges": edges,
        },
    }


def _binary_roots(binary: Any) -> list[dict[str, Any]]:
    roots: dict[int, dict[str, Any]] = {
        int(binary.entrypoint_rva): {
            "kind": "pe_entrypoint",
            "rva": int(binary.entrypoint_rva),
        }
    }
    for exported in binary.exports or ():
        if exported.kind == "code":
            roots.setdefault(
                int(exported.rva),
                {"kind": "pe_export", "rva": int(exported.rva), "name": exported.name},
            )
    for rva in binary.tls_callback_rvas or ():
        roots.setdefault(int(rva), {"kind": "pe_tls_callback", "rva": int(rva)})
    return [roots[rva] for rva in sorted(roots)]


def _manifest_seed_roots(
    path: Path,
    *,
    state_machine_sha256: str,
    original_sha256: str,
    reference_sha256: str,
    materialized_rvas: set[int],
) -> list[dict[str, Any]]:
    """Read control-frontier proposals from an exactly bound machine IR.

    The manifest is not proof authority.  It only identifies additional RVAs
    that the exact recursive decoder should attempt to materialize.
    """

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"control manifest is not valid JSON: {exc}") from exc
    manifest = _mapping(payload, "control manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise StageAInputError(
            f"control manifest must have format {MACHINE_IR_FORMAT}"
        )

    inputs = _mapping(manifest.get("inputs"), "control manifest inputs")
    state_binding = _mapping(
        inputs.get("state_machine"), "control manifest state-machine binding"
    )
    original_binding = _mapping(
        inputs.get("original_pe"), "control manifest original-PE binding"
    )
    reference_binding = _mapping(
        inputs.get("reference_contract"),
        "control manifest reference-contract binding",
    )
    expected_bindings = (
        (
            state_binding.get("sha256"),
            state_machine_sha256,
            "state machine",
        ),
        (original_binding.get("sha256"), original_sha256, "original PE"),
        (
            reference_binding.get("sha256"),
            reference_sha256,
            "reference contract",
        ),
    )
    for observed, expected, label in expected_bindings:
        if observed != expected:
            raise StageAInputError(
                f"control manifest {label} binding differs from the supplied input"
            )

    binary = _mapping(manifest.get("binary"), "control manifest binary")
    if binary.get("sha256") != original_sha256:
        raise StageAInputError(
            "control manifest binary binding differs from the supplied original PE"
        )
    source_map = manifest.get("source_map")
    if not isinstance(source_map, list):
        raise StageAInputError("control manifest source_map must be a list")
    units_by_id: dict[str, int] = {}
    for index, raw_source in enumerate(source_map):
        source = _mapping(raw_source, f"control manifest source_map[{index}]")
        unit_id = source.get("unit_id")
        if not isinstance(unit_id, str) or not unit_id:
            raise StageAInputError(
                f"control manifest source_map[{index}] has no unit identity"
            )
        if unit_id in units_by_id:
            raise StageAInputError(
                f"control manifest source_map has duplicate unit {unit_id}"
            )
        units_by_id[unit_id] = _u32(
            source.get("rva_start"),
            f"control manifest source_map[{index}] rva_start",
        )

    control = _mapping(manifest.get("control"), "control manifest control")
    reachability = _mapping(
        control.get("reachability"), "control manifest reachability"
    )
    raw_reachable = reachability.get("reachable_units")
    if not isinstance(raw_reachable, list):
        raise StageAInputError(
            "control manifest reachable-unit inventory must be a list"
        )
    reachable: set[str] = set()
    for index, unit_id in enumerate(raw_reachable):
        if not isinstance(unit_id, str) or unit_id not in units_by_id:
            raise StageAInputError(
                "control manifest reachable-unit inventory contains an unknown "
                f"unit at index {index}"
            )
        reachable.add(unit_id)

    proposals: dict[int, dict[str, Any]] = {}

    raw_roots = control.get("roots")
    if not isinstance(raw_roots, list):
        raise StageAInputError("control manifest root inventory must be a list")
    for index, raw_root in enumerate(raw_roots):
        root = _mapping(raw_root, f"control manifest root[{index}]")
        rva = _u32(root.get("rva"), f"control manifest root[{index}] rva")
        if rva not in materialized_rvas:
            proposals.setdefault(
                rva,
                {
                    "kind": "provenance_recovered_behavioral_root",
                    "rva": rva,
                    "source": "control_manifest",
                    "behavioral_root": True,
                },
            )

    raw_direct = control.get("direct_targets")
    if not isinstance(raw_direct, list):
        raise StageAInputError(
            "control manifest direct-target inventory must be a list"
        )
    for index, raw_target in enumerate(raw_direct):
        target = _mapping(
            raw_target, f"control manifest direct_targets[{index}]"
        )
        source_id = target.get("source_unit_id")
        if not isinstance(source_id, str) or source_id not in units_by_id:
            raise StageAInputError(
                f"control manifest direct_targets[{index}] has an unknown source"
            )
        status = target.get("status")
        if status not in {"resolved", "incomplete"}:
            raise StageAInputError(
                f"control manifest direct_targets[{index}] has an invalid status"
            )
        rva = _u32(
            target.get("target_rva"),
            f"control manifest direct_targets[{index}] target_rva",
        )
        if (
            source_id in reachable
            and status == "incomplete"
            and rva not in materialized_rvas
        ):
            proposals.setdefault(
                rva,
                {
                    "kind": "provenance_recovered_direct_target",
                    "rva": rva,
                    "source": "control_manifest",
                    "source_unit_id": source_id,
                    "behavioral_root": False,
                },
            )

    raw_recovered = control.get("recovered_indirect_targets")
    if not isinstance(raw_recovered, list):
        raise StageAInputError(
            "control manifest recovered-target inventory must be a list"
        )
    for index, raw_recovery in enumerate(raw_recovered):
        recovery = _mapping(
            raw_recovery,
            f"control manifest recovered_indirect_targets[{index}]",
        )
        source_id = recovery.get("source_unit_id")
        if not isinstance(source_id, str) or source_id not in units_by_id:
            raise StageAInputError(
                "control manifest recovered_indirect_targets"
                f"[{index}] has an unknown source"
            )
        status = recovery.get("status")
        if status not in {"recovered", "incomplete"}:
            raise StageAInputError(
                "control manifest recovered_indirect_targets"
                f"[{index}] has an invalid status"
            )
        target_rvas = recovery.get("target_rvas")
        if not isinstance(target_rvas, list):
            raise StageAInputError(
                "control manifest recovered-target RVA inventory must be a list"
            )
        for target_index, raw_rva in enumerate(target_rvas):
            rva = _u32(
                raw_rva,
                "control manifest recovered_indirect_targets"
                f"[{index}].target_rvas[{target_index}]",
            )
            if (
                source_id in reachable
                and status == "recovered"
                and rva not in materialized_rvas
            ):
                proposals.setdefault(
                    rva,
                    {
                        "kind": "provenance_recovered_indirect_target",
                        "rva": rva,
                        "source": "control_manifest",
                        "source_unit_id": source_id,
                        "behavioral_root": False,
                    },
                )
    raw_callbacks = control.get("callback_cutpoint_proposals", [])
    if not isinstance(raw_callbacks, list):
        raise StageAInputError(
            "control manifest callback-cutpoint proposal inventory must be a list"
        )
    for index, raw_callback in enumerate(raw_callbacks):
        callback = _mapping(
            raw_callback, f"control manifest callback_cutpoint_proposals[{index}]"
        )
        source_id = callback.get("source_unit_id")
        if not isinstance(source_id, str) or source_id not in units_by_id:
            raise StageAInputError(
                "control manifest callback-cutpoint proposal has an unknown source"
            )
        rva = _u32(
            callback.get("rva"),
            f"control manifest callback_cutpoint_proposals[{index}] rva",
        )
        if rva not in materialized_rvas:
            proposals.setdefault(
                rva,
                {
                    "kind": "provenance_recovered_callback_cutpoint",
                    "rva": rva,
                    "source": "control_manifest",
                    "source_unit_id": source_id,
                    "behavioral_root": False,
                },
            )
    return [proposals[rva] for rva in sorted(proposals)]


def _merge_roots(
    binary_roots: list[dict[str, Any]],
    proposal_roots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    roots: dict[int, dict[str, Any]] = {}
    for root in (*binary_roots, *proposal_roots):
        rva = _u32(root.get("rva"), "root RVA")
        roots.setdefault(rva, dict(root))
    return [roots[rva] for rva in sorted(roots)]


def _view_transfer(
    *,
    binary: Any,
    view: Mapping[str, Any],
    reference_path: Path,
    reference_sha256: str,
) -> dict[str, Any]:
    start = _u32(view.get("rva_start"), "rooted view start")
    end = _u32(view.get("rva_end"), "rooted view end")
    if end <= start:
        raise StageAInputError("rooted view span is empty")
    encoded = view.get("bytes")
    if not isinstance(encoded, str):
        raise StageAInputError("rooted view byte proposal is malformed")
    try:
        proposed_bytes = bytes.fromhex(encoded)
    except ValueError as exc:
        raise StageAInputError("rooted view byte proposal is malformed") from exc
    image_bytes = bytes(binary.pe.get_data(start, end - start))
    if len(proposed_bytes) != end - start or proposed_bytes != image_bytes:
        raise StageAInputError(
            f"rooted view 0x{start:x}-0x{end:x} differs from the original PE"
        )
    identity = f"rooted-view-{start:08x}-{end:08x}"
    span = BlockSide(start, end)
    mapped = BlockMapping(
        id=identity,
        original=span,
        candidate=span,
        kind="code",
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "kind": "rooted_recursive_decode_view",
                "proposal_format": ROOTED_INSTRUCTION_VIEW_FORMAT,
                "control": view.get("control"),
                "provenance": view.get("provenance"),
            }
        },
    )
    raw = _semantic_transfer_contract(
        binary,
        mapped,
        identity,
        {
            "format": "stage-a-reference-contract-v1",
            "path": reference_path.name,
            "sha256": reference_sha256,
        },
        semantic_side=span,
        semantic_block_id=identity,
    )
    transfer_sha256 = sha256_bytes(_canonical_json(raw))
    return normalize_stage_a_semantic_transfer(
        raw,
        reference_contract_sha256=reference_sha256,
        semantic_transfer_sha256=transfer_sha256,
    )


def _canonical_state_machine_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"invalid state-machine JSON on line {line_number}: {exc}"
            ) from exc
        row = _mapping(value, f"state-machine line {line_number}")
        if row.get("stage_b_format") != STAGE_B_STATE_MACHINE_FORMAT:
            raise StageAInputError(
                f"state-machine line {line_number} is not canonical"
            )
        normalized = normalize_stage_a_semantic_transfer(dict(row))
        if normalized.get("contract_sha256") != row.get("contract_sha256"):
            raise StageAInputError(
                f"state-machine line {line_number} has a stale contract digest"
            )
        rows.append(dict(row))
    if not rows:
        raise StageAInputError("base state machine is empty")
    return rows


def _regular_file(path: Path, context: str) -> Path:
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"{context} must be a regular non-symlink file")
    return path


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return dict(value)


def _transfer_start(row: Mapping[str, Any]) -> int:
    original = _mapping(row.get("original"), "state-machine original span")
    return _u32(original.get("rva_start"), "state-machine transfer start")


def _u32(value: Any, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**32
    ):
        raise StageAInputError(f"{context} must be an unsigned 32-bit integer")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


__all__ = [
    "ROOTED_STATE_MACHINE_CLOSURE_FORMAT",
    "close_state_machine_rooted_direct_control",
]
