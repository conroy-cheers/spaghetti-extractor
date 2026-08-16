"""Dispatch and callback receipt validation for native runtime planning."""

from __future__ import annotations

import json
from typing import Any, Mapping

from ..artifacts.formats import (
    CALLBACK_ADAPTER_RECEIPT_FORMAT,
    IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT,
)
from ..external.contracts import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    parse_checked_external_site_contract,
)
from ..util import sha256_bytes
from .runtime_model import (
    NativeImplementationDispatch,
    CandidateRuntimeError,
    _InterpreterTransferBinding,
    _SHA256_RE,
)
from .runtime_values import (
    _required_count,
    _required_list,
    _required_object,
    _required_portable_identity,
    _required_sha256,
    _required_string,
    _required_u32,
)


_CALLBACK_ADAPTER_RECEIPT_FORMAT = CALLBACK_ADAPTER_RECEIPT_FORMAT
_IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT = IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT


def _canonical_json_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError) as exc:
        raise CandidateRuntimeError(
            "native receipt is not canonical JSON"
        ) from exc
    return sha256_bytes(encoded)


def _validate_implementation_dispatch_receipt(
    payload: dict[str, Any],
    *,
    state_machine_sha256: str,
    transfer_bindings: tuple[_InterpreterTransferBinding, ...],
) -> tuple[dict[str, Any], tuple[NativeImplementationDispatch, ...]]:
    """Validate exact dispatch coverage independently of engine generation."""

    raw = _required_object(
        payload.get("implementation_dispatch_receipt"),
        "native-engine implementation dispatch receipt",
    )
    expected_fields = {
        "format",
        "status",
        "semantic_input_sha256",
        "machine_ir_manifest_sha256",
        "reachability",
        "policy",
        "counts",
        "entries",
        "targets",
        "blockers",
        "receipt_sha256",
    }
    if (
        set(raw) != expected_fields
        or raw.get("format") != _IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT
        or raw.get("semantic_input_sha256") != state_machine_sha256
    ):
        raise CandidateRuntimeError(
            "native-engine implementation dispatch receipt is not canonically bound"
        )
    body = {
        key: raw[key]
        for key in expected_fields
        if key not in {"format", "receipt_sha256"}
    }
    if (
        _required_sha256(
            raw.get("receipt_sha256"), "implementation dispatch receipt SHA-256"
        )
        != _canonical_json_sha256(body)
    ):
        raise CandidateRuntimeError(
            "native-engine implementation dispatch receipt hash is invalid"
        )
    if _required_list(raw.get("blockers"), "implementation dispatch blockers"):
        raise CandidateRuntimeError(
            "ready native-engine plan has incomplete implementation dispatch"
        )
    policy = _required_object(
        raw.get("policy"), "implementation dispatch policy"
    )
    expected_policy = {
        "one_implementation_class_per_transfer": True,
        "rooted_targets_require_implementation": True,
        "runtime_code_target_lookup": "exact-active-transfer-rva",
        "unresolved_dispatch": "fail-closed-as-unimplemented",
        "portable_component_fallback_on_unimplemented": False,
        "structural_execution_receipt_required_for_candidate": True,
        "acceptance_authority": False,
    }
    if policy != expected_policy:
        raise CandidateRuntimeError(
            "native-engine implementation dispatch policy is unsupported"
        )

    reachability = _required_object(
        raw.get("reachability"), "implementation dispatch reachability"
    )
    if set(reachability) != {
        "status",
        "roots",
        "reachable_unit_ids",
        "potential_unit_ids",
        "confirmed_unreachable_unit_ids",
        "frontiers",
    }:
        raise CandidateRuntimeError(
            "implementation dispatch reachability fields are not canonical"
        )
    roots = _required_list(reachability.get("roots"), "implementation roots")
    reachable = _required_list(
        reachability.get("reachable_unit_ids"), "implementation reachable units"
    )
    potential = _required_list(
        reachability.get("potential_unit_ids"), "implementation potential units"
    )
    unreachable = _required_list(
        reachability.get("confirmed_unreachable_unit_ids"),
        "implementation confirmed-unreachable units",
    )
    frontiers = _required_list(
        reachability.get("frontiers"), "implementation reachability frontiers"
    )
    inventories = roots + reachable + potential + unreachable
    if (
        any(not isinstance(value, str) or not value for value in inventories)
        or roots != sorted(set(roots))
        or reachable != sorted(set(reachable))
        or potential != sorted(set(potential))
        or unreachable != sorted(set(unreachable))
        or not set(roots) <= set(reachable)
        or set(reachable) & set(potential)
        or set(reachable) & set(unreachable)
        or set(potential) & set(unreachable)
        or any(not isinstance(frontier, Mapping) for frontier in frontiers)
    ):
        raise CandidateRuntimeError(
            "implementation dispatch rooted reachability is malformed"
        )
    reachability_status = reachability.get("status")
    receipt_status = raw.get("status")
    manifest_sha256 = raw.get("machine_ir_manifest_sha256")
    if reachability_status == "complete":
        if (
            receipt_status != "complete"
            or not roots
            or not reachable
            or potential
            or frontiers
            or _SHA256_RE.fullmatch(str(manifest_sha256 or "")) is None
        ):
            raise CandidateRuntimeError(
                "complete implementation dispatch lacks rooted manifest evidence"
            )
    else:
        raise CandidateRuntimeError(
            "ready native-engine implementation reachability is incomplete"
        )

    entries = _required_list(raw.get("entries"), "implementation dispatch entries")
    active_unit_ids = {binding.unit_id for binding in transfer_bindings}
    partition_unit_ids = set(reachable) | set(unreachable)
    if partition_unit_ids != active_unit_ids:
        raise CandidateRuntimeError(
            "implementation reachability does not partition the complete transfer inventory"
        )
    entry_fields = {
        "unit_id",
        "rva",
        "transfer_sha256",
        "reachability",
        "implementation_class",
        "dispatch_lookup",
        "replacement_id",
        "cluster_id",
        "component_manifest_sha256",
        "component_entry_rva",
        "fallback_on_unimplemented",
        "entry_sha256",
    }
    if len(entries) != len(transfer_bindings):
        raise CandidateRuntimeError(
            "implementation dispatch omits or adds interpreter transfers"
        )
    dispatches: list[NativeImplementationDispatch] = []
    entry_by_id: dict[str, NativeImplementationDispatch] = {}
    for index, (raw_entry, binding) in enumerate(
        zip(entries, transfer_bindings, strict=True)
    ):
        entry = _required_object(raw_entry, f"implementation dispatch entry {index}")
        if set(entry) != entry_fields:
            raise CandidateRuntimeError(
                "implementation dispatch entry fields are not canonical"
            )
        entry_body = {
            key: entry[key] for key in entry_fields if key != "entry_sha256"
        }
        if (
            _required_sha256(
                entry.get("entry_sha256"),
                f"implementation dispatch entry {index} SHA-256",
            )
            != _canonical_json_sha256(entry_body)
        ):
            raise CandidateRuntimeError(
                "implementation dispatch entry hash is invalid"
            )
        unit_id = _required_string(
            entry.get("unit_id"), f"implementation dispatch entry {index} unit id"
        )
        rva = _required_u32(
            entry.get("rva"), f"implementation dispatch entry {index} RVA"
        )
        _required_sha256(
            entry.get("transfer_sha256"),
            f"implementation dispatch entry {index} transfer SHA-256",
        )
        if unit_id != binding.unit_id or rva != binding.rva or unit_id in entry_by_id:
            raise CandidateRuntimeError(
                "implementation dispatch is duplicate, reordered, or mismatched"
            )
        reachability_class = entry.get("reachability")
        expected_reachability = (
            "root"
            if unit_id in roots
            else "reachable"
            if unit_id in reachable
            else "potential"
            if unit_id in potential
            else "confirmed_unreachable"
            if unit_id in unreachable
            else "unbound"
        )
        if reachability_class != expected_reachability:
            raise CandidateRuntimeError(
                "implementation dispatch reachability class is inconsistent"
            )
        implementation_class = entry.get("implementation_class")
        replacement_id = entry.get("replacement_id")
        cluster_id = entry.get("cluster_id")
        component_sha256 = entry.get("component_manifest_sha256")
        component_entry_rva = entry.get("component_entry_rva")
        if entry.get("fallback_on_unimplemented") is not False:
            raise CandidateRuntimeError(
                "implementation dispatch permits a second fallback class"
            )
        if implementation_class == "machine_ir_fallback":
            if (
                entry.get("dispatch_lookup") != "spx_program_lookup"
                or replacement_id is not None
                or cluster_id is not None
                or component_sha256 is not None
                or component_entry_rva is not None
            ):
                raise CandidateRuntimeError(
                    "machine-IR fallback dispatch carries portable metadata"
                )
        elif implementation_class == "selected_portable_component":
            if entry.get("dispatch_lookup") != "spx_region_override_lookup":
                raise CandidateRuntimeError(
                    "portable component dispatch uses the wrong lookup"
                )
            replacement_id = _required_portable_identity(
                replacement_id, "portable component replacement id"
            )
            cluster_id = _required_portable_identity(
                cluster_id, "portable component cluster id"
            )
            _required_sha256(
                component_sha256, "portable component manifest SHA-256"
            )
            if component_entry_rva != rva:
                raise CandidateRuntimeError(
                    "portable component entry does not bind its own RVA"
                )
        elif implementation_class == "selected_portable_component_member":
            if entry.get("dispatch_lookup") != "component_entry_subsumed":
                raise CandidateRuntimeError(
                    "portable component member uses the wrong dispatch class"
                )
            replacement_id = _required_portable_identity(
                replacement_id, "portable component member replacement id"
            )
            cluster_id = _required_portable_identity(
                cluster_id, "portable component member cluster id"
            )
            _required_sha256(
                component_sha256, "portable component member manifest SHA-256"
            )
            component_entry_rva = _required_u32(
                component_entry_rva, "portable component member entry RVA"
            )
            if component_entry_rva == rva:
                raise CandidateRuntimeError(
                    "portable component member aliases its boundary entry"
                )
        else:
            raise CandidateRuntimeError(
                "implementation dispatch has an unsupported implementation class"
            )
        dispatch = NativeImplementationDispatch(
            unit_id=unit_id,
            rva=rva,
            implementation_class=str(implementation_class),
            replacement_id=replacement_id,
            cluster_id=cluster_id,
            component_entry_rva=(
                component_entry_rva if isinstance(component_entry_rva, int) else None
            ),
        )
        entry_by_id[unit_id] = dispatch
        dispatches.append(dispatch)

    targets = _required_list(raw.get("targets"), "implementation dispatch targets")
    target_fields = {
        "kind",
        "source_unit_id",
        "source_rva",
        "source_event_index",
        "target_unit_id",
        "target_rva",
        "target_sha256",
    }
    seen_targets: set[tuple[str, str, int | None, str]] = set()
    for index, raw_target in enumerate(targets):
        target = _required_object(
            raw_target, f"implementation dispatch target {index}"
        )
        if set(target) != target_fields:
            raise CandidateRuntimeError(
                "implementation dispatch target fields are not canonical"
            )
        target_body = {
            key: target[key] for key in target_fields if key != "target_sha256"
        }
        if (
            _required_sha256(
                target.get("target_sha256"),
                f"implementation dispatch target {index} SHA-256",
            )
            != _canonical_json_sha256(target_body)
        ):
            raise CandidateRuntimeError(
                "implementation dispatch target hash is invalid"
            )
        kind = _required_string(
            target.get("kind"), f"implementation dispatch target {index} kind"
        )
        if kind not in {
            "direct_control",
            "internal_call",
            "call_continuation",
            "indirect_internal",
        }:
            raise CandidateRuntimeError(
                "implementation dispatch target kind is unsupported"
            )
        source_unit_id = _required_string(
            target.get("source_unit_id"), "implementation target source unit"
        )
        target_unit_id = _required_string(
            target.get("target_unit_id"), "implementation target unit"
        )
        event_index = target.get("source_event_index")
        if event_index is not None:
            event_index = _required_count(
                event_index, "implementation target source event index"
            )
        source_dispatch = entry_by_id.get(source_unit_id)
        target_dispatch = entry_by_id.get(target_unit_id)
        key = (kind, source_unit_id, event_index, target_unit_id)
        if (
            reachability_status != "complete"
            or source_dispatch is None
            or target_dispatch is None
            or source_unit_id not in reachable
            or target_unit_id not in reachable
            or _required_u32(
                target.get("source_rva"), "implementation target source RVA"
            )
            != source_dispatch.rva
            or _required_u32(
                target.get("target_rva"), "implementation target RVA"
            )
            != target_dispatch.rva
            or key in seen_targets
        ):
            raise CandidateRuntimeError(
                "implementation target has no unique rooted executable dispatch"
            )
        seen_targets.add(key)
    if reachability_status != "complete" and targets:
        raise CandidateRuntimeError(
            "non-closed implementation dispatch contains rooted target claims"
        )

    counts = _required_object(raw.get("counts"), "implementation dispatch counts")
    expected_counts = {
        "dispatch_entries": len(entries),
        "rooted_reachable_units": len(reachable),
        "rooted_targets": len(targets),
        "machine_ir_fallback": sum(
            dispatch.implementation_class == "machine_ir_fallback"
            for dispatch in dispatches
        ),
        "selected_portable_component": sum(
            dispatch.implementation_class == "selected_portable_component"
            for dispatch in dispatches
        ),
        "selected_portable_component_member": sum(
            dispatch.implementation_class
            == "selected_portable_component_member"
            for dispatch in dispatches
        ),
        "blockers": 0,
    }
    if counts != expected_counts:
        raise CandidateRuntimeError(
            "implementation dispatch counts differ from their inventories"
        )
    return dict(raw), tuple(dispatches)


def _validate_callback_adapter_receipts(
    payload: dict[str, Any],
    *,
    callback_abis: list[Any],
) -> tuple[dict[str, Any], ...]:
    """Require an exact receipt for every generated registration adapter."""

    callback_by_rva: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(callback_abis):
        callback = _required_object(raw, f"native-engine callback ABI {index}")
        rva = _required_u32(callback.get("rva"), "callback ABI RVA")
        if rva in callback_by_rva:
            raise CandidateRuntimeError(
                "native-engine callback ABI inventory contains duplicates"
            )
        callback_by_rva[rva] = callback

    adapters = _required_list(
        payload.get("callback_adapters"), "native-engine callback adapters"
    )
    normalized_adapters: list[dict[str, Any]] = []
    adapter_by_site: dict[tuple[int, int], list[dict[str, Any]]] = {}
    adapter_keys: set[tuple[int, int, int, int]] = set()
    expected_adapter_fields = {
        "id",
        "instruction_rva",
        "argument_index",
        "original_rva",
        "callback_rva",
        "symbol",
        "matching",
    }
    for index, raw in enumerate(adapters):
        adapter = _required_object(raw, f"native-engine callback adapter {index}")
        if set(adapter) != expected_adapter_fields:
            raise CandidateRuntimeError(
                "native-engine callback adapter fields are not canonical"
            )
        adapter_id = _required_count(adapter.get("id"), "callback adapter id")
        instruction_rva = _required_u32(
            adapter.get("instruction_rva"), "callback adapter instruction RVA"
        )
        argument_index = _required_count(
            adapter.get("argument_index"), "callback adapter argument index"
        )
        original_rva = _required_u32(
            adapter.get("original_rva"), "callback adapter original RVA"
        )
        callback_rva = _required_u32(
            adapter.get("callback_rva"), "callback adapter callback RVA"
        )
        key = (instruction_rva, argument_index, original_rva, callback_rva)
        if (
            adapter_id != index
            or key in adapter_keys
            or original_rva != callback_rva
            or adapter.get("matching") != "runtime-image-base-plus-rva"
            or adapter.get("symbol")
            != f"spx_payload_callback_{callback_rva:08x}"
            or callback_rva not in callback_by_rva
        ):
            raise CandidateRuntimeError(
                "native-engine callback adapter is duplicate or mismatched"
            )
        adapter_keys.add(key)
        normalized = dict(adapter)
        normalized_adapters.append(normalized)
        adapter_by_site.setdefault((instruction_rva, argument_index), []).append(
            normalized
        )

    explicit_sites: dict[
        tuple[int, str, int, int],
        tuple[dict[str, Any], CheckedExternalSiteContract],
    ] = {}
    for site_index, raw in enumerate(
        _required_list(payload.get("external_sites"), "native-engine external sites")
    ):
        site = _required_object(raw, f"native-engine external site {site_index}")
        raw_contract = site.get("checked_external_contract")
        if not isinstance(raw_contract, Mapping):
            continue
        try:
            contract = parse_checked_external_site_contract(
                raw_contract,
                context=f"native-engine external site {site_index}",
            )
        except CheckedExternalSiteContractError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        if contract.callback_effect != "explicit":
            continue
        adapter_contract = contract.callback_adapter
        if adapter_contract is None:
            raise CandidateRuntimeError(
                "explicit callback contract has no normalized adapter"
            )
        site_id = _required_count(site.get("id"), "external site id")
        transfer_id = _required_string(
            site.get("transfer_id"), "external site transfer id"
        )
        event_index = _required_count(
            site.get("event_index"), "external site event index"
        )
        instruction_rva = _required_u32(
            site.get("instruction_rva"), "external site instruction RVA"
        )
        key = (site_id, transfer_id, event_index, instruction_rva)
        if key in explicit_sites:
            raise CandidateRuntimeError(
                "native-engine explicit callback sites are duplicated"
            )
        explicit_sites[key] = (site, contract)

    receipts = _required_list(
        payload.get("callback_adapter_receipts"),
        "native-engine callback adapter receipts",
    )
    expected_receipt_fields = {
        "format",
        "site_id",
        "transfer_id",
        "event_index",
        "instruction_rva",
        "checked_external_contract_sha256",
        "source",
        "abi",
        "lifetime",
        "invocation",
        "target_rvas",
        "adapter_entries",
        "receipt_sha256",
    }
    seen_sites: set[tuple[int, str, int, int]] = set()
    consumed_adapter_ids: set[int] = set()
    normalized_receipts: list[dict[str, Any]] = []
    for index, raw in enumerate(receipts):
        receipt = _required_object(
            raw, f"native-engine callback adapter receipt {index}"
        )
        if (
            set(receipt) != expected_receipt_fields
            or receipt.get("format") != _CALLBACK_ADAPTER_RECEIPT_FORMAT
        ):
            raise CandidateRuntimeError(
                "native-engine callback adapter receipt fields are not canonical"
            )
        site_key = (
            _required_count(receipt.get("site_id"), "callback receipt site id"),
            _required_string(
                receipt.get("transfer_id"), "callback receipt transfer id"
            ),
            _required_count(
                receipt.get("event_index"), "callback receipt event index"
            ),
            _required_u32(
                receipt.get("instruction_rva"),
                "callback receipt instruction RVA",
            ),
        )
        site_binding = explicit_sites.get(site_key)
        if site_binding is None or site_key in seen_sites:
            raise CandidateRuntimeError(
                "native-engine callback adapter receipt has no unique checked site"
            )
        seen_sites.add(site_key)
        site, contract = site_binding
        adapter_contract = contract.callback_adapter
        assert adapter_contract is not None
        body = {
            key: receipt[key]
            for key in expected_receipt_fields
            if key not in {"format", "receipt_sha256"}
        }
        if (
            _required_sha256(
                receipt.get("receipt_sha256"), "callback receipt SHA-256"
            ) != _canonical_json_sha256(body)
            or receipt.get("checked_external_contract_sha256")
            != _canonical_json_sha256(contract.payload())
            or receipt.get("source") != adapter_contract.source
            or receipt.get("abi") != adapter_contract.abi
            or receipt.get("lifetime") != adapter_contract.lifetime
            or receipt.get("invocation") != adapter_contract.invocation
            or receipt.get("target_rvas") != list(adapter_contract.target_rvas)
        ):
            raise CandidateRuntimeError(
                "native-engine callback adapter receipt differs from its checked contract"
            )
        source = adapter_contract.source
        abi = adapter_contract.abi
        if not isinstance(source, Mapping) or not isinstance(abi, Mapping):
            raise CandidateRuntimeError(
                "native-engine callback receipt source or ABI is malformed"
            )
        source_kind = source.get("kind")
        argument_index = _required_count(
            source.get("argument"), "callback receipt source argument"
        )
        pointee_offset = (
            _required_count(source.get("offset"), "callback receipt pointee offset")
            if source_kind == "argument_pointee"
            else 0
        )
        registration = _required_object(
            site.get("callback_registration"),
            "native-engine callback registration",
        )
        nullable = abi.get("nullable")
        if (
            source_kind not in {"argument_word", "argument_pointee"}
            or not isinstance(nullable, bool)
            or registration
            != {
                "source_kind": source_kind,
                "argument_index": argument_index,
                "stack_offset": contract.argument_base_offset
                + argument_index * 4,
                "pointee_offset": pointee_offset,
                "nullable": nullable,
            }
        ):
            raise CandidateRuntimeError(
                "native-engine callback registration differs from its receipt"
            )
        expected_entries = adapter_by_site.get(
            (site_key[3], argument_index), []
        )
        raw_entries = _required_list(
            receipt.get("adapter_entries"), "callback receipt adapter entries"
        )
        if raw_entries != expected_entries or [
            entry.get("callback_rva") for entry in expected_entries
        ] != list(adapter_contract.target_rvas):
            raise CandidateRuntimeError(
                "native-engine callback receipt adapter inventory is incomplete or extra"
            )
        expected_kind = abi.get("kind")
        expected_cleanup = abi.get("stack_cleanup_bytes")
        for entry in expected_entries:
            callback = callback_by_rva[int(entry["callback_rva"])]
            if (
                callback.get("kind") != expected_kind
                or callback.get("stack_cleanup_bytes") != expected_cleanup
            ):
                raise CandidateRuntimeError(
                    "native-engine callback receipt ABI differs from its target"
                )
            adapter_id = int(entry["id"])
            if adapter_id in consumed_adapter_ids:
                raise CandidateRuntimeError(
                    "native-engine callback adapter is covered by multiple receipts"
                )
            consumed_adapter_ids.add(adapter_id)
        normalized_receipts.append(dict(receipt))

    if seen_sites != set(explicit_sites) or consumed_adapter_ids != {
        int(adapter["id"]) for adapter in normalized_adapters
    }:
        raise CandidateRuntimeError(
            "native-engine callback adapter receipt coverage is incomplete"
        )
    return tuple(normalized_receipts)
