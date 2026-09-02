"""Generated Behavioral-C dispatch inventory for canonical runtimes.

Provider selection is deliberately absent here.  The shared runtime is built
before ``implementation-selection-v2`` exists; selected portable definitions
are therefore routed only by the final V2 native-link plan.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..transfer.model import _Transfer
from .module_runtime_plan import (
    NativeImplementationDispatchReceipt,
    NativeImplementationEntry,
    NativeImplementationTarget,
)


def _canonical_runtime_error() -> type[ValueError]:
    from .runtime_canonical import CanonicalRuntimeError

    return CanonicalRuntimeError


def implementation_receipt(
    *,
    transfers: tuple[_Transfer, ...],
    closure: Mapping[str, Any],
    machine_ir_sha256: str,
    closure_file_sha256: str,
) -> NativeImplementationDispatchReceipt:
    transfer_by_id = {
        transfer.identity: (transfer.rva_start, transfer.contract_sha256)
        for transfer in transfers
    }
    reachable_rows = closure["reachable_units"]
    reachable = {str(row["unit_id"]) for row in reachable_rows}
    roots_by_rva = {
        transfer.rva_start: transfer.identity for transfer in transfers
    }
    roots = tuple(sorted(roots_by_rva[int(rva)] for rva in closure["roots"]))
    entries = []
    for transfer in sorted(transfers, key=lambda item: item.rva_start):
        entries.append(NativeImplementationEntry(
            unit_id=transfer.identity,
            rva=transfer.rva_start,
            transfer_sha256=transfer.contract_sha256,
            reachability=(
                "root" if transfer.identity in roots else
                "reachable" if transfer.identity in reachable else
                "confirmed_unreachable"
            ),
            implementation_class="generated_behavioral_c",
            dispatch_lookup="spx_program_lookup",
            replacement_id=None,
            cluster_id=None,
            component_manifest_sha256=None,
            component_entry_rva=None,
        ))
    by_rva = {transfer.rva_start: transfer for transfer in transfers}
    targets = []
    supported_kinds = {
        "direct_control", "internal_call", "call_continuation",
        "indirect_internal",
    }
    seen_targets: set[tuple[str, int, int]] = set()
    for edge in closure["reachable_edges"]:
        kind = str(edge["kind"])
        if kind not in supported_kinds:
            continue
        source = by_rva.get(int(edge["source_rva"]))
        target = by_rva.get(int(edge["target_rva"]))
        if source is None or target is None:
            raise _canonical_runtime_error()("closure edge is absent from transfer inventory")
        key = (kind, source.rva_start, target.rva_start)
        if key in seen_targets:
            continue
        seen_targets.add(key)
        targets.append(NativeImplementationTarget(
            kind=kind,
            source_unit_id=source.identity,
            source_rva=source.rva_start,
            source_event_index=None,
            target_unit_id=target.identity,
            target_rva=target.rva_start,
        ))
    return NativeImplementationDispatchReceipt(
        semantic_input_sha256=machine_ir_sha256,
        machine_ir_manifest_sha256=closure_file_sha256,
        reachability_status="complete",
        roots=roots,
        reachable_unit_ids=tuple(sorted(reachable)),
        potential_unit_ids=(),
        confirmed_unreachable_unit_ids=tuple(
            sorted(set(transfer_by_id) - reachable)
        ),
        reachability_frontiers=(),
        entries=tuple(entries),
        targets=tuple(sorted(
            targets,
            key=lambda item: (
                item.source_rva, item.kind, item.target_rva,
            ),
        )),
        blockers=(),
    )
