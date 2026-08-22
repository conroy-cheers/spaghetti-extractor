"""Plan and emit the candidate machine engine from checked authority inputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.formats import NATIVE_ENGINE_PACKAGE_FORMAT, NATIVE_ENGINE_PLAN_FORMAT
from ..external.callbacks import CallbackABI, CallbackSource
from ..external.callback_protocols import parse_callback_protocol
from ..external.contracts import (
    CheckedExternalSiteContract,
)
from ..external.runtime_projection import load_authoritative_external_sites
from ..pe32.recovered_executable_data import (
    RecoveredExecutableDataRange,
    load_recovered_executable_data_contract,
)
from ..errors import ToolkitInputError
from ..util import sha256_bytes, sha256_file
from .engine_analysis import (
    _RegisterImportSiteAnalysis,
    _adapt_native_machine_ir_unit,
    _checked_contract_callback_registration,
    _exact_u32_expression,
    _external_runtime_semantics,
    _forward_expression_from_prior_writes,
    _machine_ir_event_evidence,
    _machine_ir_manifest_payload,
    _machine_ir_register_import_sites,
    _parse_native_termination_import,
    _stack_expression_at_offset,
    _static_iat_import_identity,
)
from .engine_components import (
    _build_callback_adapter_receipts,
    _build_implementation_dispatch_receipt,
    _callback_storage_origin_is_safe,
    _previous_callback_storage_writes,
)
from .authority.execution import load_candidate_execution_authority_v3
from .callback_authority import load_callback_protocol_authority_v1
from .engine_model import (
    NativeCallbackAdapter,
    NativeCallbackPassthrough,
    NativeCallbackTarget,
    NativeEnginePlan,
    NativeExternalSite,
    NativeImportBinding,
    NativeTerminationImport,
    NativeX87Operation,
    PE32_BASE_RELOCATION_EVIDENCE_FORMAT,
    _CALL_KINDS,
    _HEX_BYTES,
    _MACHINE_IR_INPUT_MODE,
    _SEMANTIC_RUNTIME_EVENT_KINDS,
    _X87ReplayASLRUnsafe,
    _canonical_sha256,
)
from .engine_x87 import (
    _absolute_iat_va,
    _blocker,
    _callback_spec,
    _indirect_call_encoding,
    _instruction_inventory,
    _parse_pe_base_relocation_evidence,
    _qualified_machine_ir_x87_operations,
    _qualified_x87_operations,
    _read_jsonl_objects,
    _required_sha256,
    _required_string,
    _required_u32,
)
from .x87 import (
    TYPED_NATIVE_X87_OPERATION_FORMAT,
    TypedX87Operand,
    TypedX87Operation,
    extract_typed_x87_operation,
    typed_x87_operation_from_micro_op,
)


def plan_spx_native_engine(
    *,
    machine_ir: Path,
    machine_ir_manifest: Path,
    recovered_executable_data: Path | str | None = None,
    entry_rva: int,
    tls_callback_targets: Iterable[int | Mapping[str, Any]] = (),
    import_iat_vas: Mapping[tuple[str, str | int], int] | None = None,
    termination_import: Mapping[str, Any] | None = None,
    base_relocation_evidence: Mapping[str, Any] | None = None,
    canonical_external_sites: Path | str,
    callback_authority: Path | str,
    root_closure: Path | str,
    target_certificates: Path | str,
    parametric_summaries: Path | str,
    fixed_image_base: int | None = None,
    preferred_image_base: int | None = None,
    initial_zero_ranges: Iterable[tuple[int, int]] = (),
    selected_portable_components: Iterable[Mapping[str, Any]] = (),
) -> NativeEnginePlan:
    """Plan machine-level external bridges from one strict or byte-free input."""

    input_path = Path(machine_ir)
    if fixed_image_base is not None:
        fixed_image_base = _required_u32(fixed_image_base, "fixed image base")
    if preferred_image_base is None:
        preferred_image_base = fixed_image_base
    elif preferred_image_base is not None:
        preferred_image_base = _required_u32(
            preferred_image_base, "preferred image base"
        )
    checked_zero_ranges: list[tuple[int, int]] = []
    for index, value in enumerate(initial_zero_ranges):
        if not isinstance(value, tuple) or len(value) != 2:
            raise ToolkitInputError(f"initial zero range {index} must be a pair")
        start = _required_u32(value[0], f"initial zero range {index} start")
        end = _required_u32(value[1], f"initial zero range {index} end")
        if end <= start:
            raise ToolkitInputError(f"initial zero range {index} must be nonempty")
        checked_zero_ranges.append((start, end))
    normalized_zero_ranges = tuple(sorted(checked_zero_ranges))
    raw_rows = _read_jsonl_objects(
        input_path, "machine IR"
    )
    semantic_input_sha256 = sha256_file(input_path)
    selected_portable_components = tuple(selected_portable_components)
    tls_callback_targets = tuple(tls_callback_targets)
    machine_ir_mode = True
    machine_ir_manifest_payload = _machine_ir_manifest_payload(
        machine_ir=Path(machine_ir),
        manifest=Path(machine_ir_manifest),
    )
    checked_external_contracts_required = True
    authoritative_external_index = load_authoritative_external_sites(
        canonical_external_sites
    )
    callback_authority_index = load_callback_protocol_authority_v1(
        callback_authority
    )
    callback_authority_by_site = callback_authority_index.by_external_site()
    authoritative_external_sites = authoritative_external_index.by_event()
    execution_authority = load_candidate_execution_authority_v3(
        root_closure=Path(root_closure),
        target_certificates=Path(target_certificates),
        parametric_summaries=Path(parametric_summaries),
    )
    consumed_authoritative_site_ids: set[str] = set()
    recovered_data_ranges: tuple[RecoveredExecutableDataRange, ...] = ()
    if recovered_executable_data is not None:
        recovered_data = load_recovered_executable_data_contract(
            recovered_executable_data
        )
        if recovered_data.machine_ir_sha256 != sha256_file(input_path):
            raise ToolkitInputError(
                "recovered executable-data contract binds a different machine IR"
            )
        manifest_binary = (
            machine_ir_manifest_payload.get("binary")
            if isinstance(machine_ir_manifest_payload, Mapping)
            else None
        )
        if (
            not isinstance(manifest_binary, Mapping)
            or manifest_binary.get("sha256") != recovered_data.original_pe_sha256
            or manifest_binary.get("image_base") != recovered_data.image_base
        ):
            raise ToolkitInputError(
                "recovered executable-data contract binds a different original image"
            )
        if (
            preferred_image_base is not None
            and recovered_data.image_base != preferred_image_base
        ):
            raise ToolkitInputError(
                "recovered executable-data image base differs from native inputs"
            )
        recovered_data_ranges = recovered_data.ranges
    internal_indirect_sites = execution_authority.internal_indirect_sites
    rows = [
        _adapt_native_machine_ir_unit(row, index)
        for index, row in enumerate(raw_rows)
    ]
    implementation_source_rows = raw_rows
    sites: list[NativeExternalSite] = []
    import_iat_vas = import_iat_vas or {}
    import_bindings: list[NativeImportBinding] = []
    if preferred_image_base is not None:
        for (dll, identity), raw_iat_va in sorted(
            import_iat_vas.items(), key=lambda item: (item[0][0].lower(), str(item[0][1]))
        ):
            iat_va = _required_u32(raw_iat_va, "import IAT VA")
            if iat_va < preferred_image_base:
                raise ToolkitInputError("import IAT VA precedes the preferred image base")
            if not isinstance(dll, str) or not dll:
                raise ToolkitInputError("import binding DLL must be nonempty")
            if isinstance(identity, str) and identity:
                symbol, ordinal = identity, None
            elif isinstance(identity, int) and not isinstance(identity, bool) and identity >= 0:
                symbol, ordinal = None, identity
            else:
                raise ToolkitInputError("import binding must use one symbol or ordinal")
            import_bindings.append(NativeImportBinding(
                dll=dll.lower(),
                symbol=symbol,
                ordinal=ordinal,
                iat_va=iat_va,
                iat_rva=iat_va - preferred_image_base,
            ))
    propagated_import_analysis = (
        _machine_ir_register_import_sites(
            rows,
            import_iat_vas=import_iat_vas,
            call_preserved_registers=execution_authority.call_preservation_by_site,
            allow_diagnostic_abi_hypotheses=False,
        )
        if machine_ir_mode
        else _RegisterImportSiteAnalysis({}, {})
    )
    propagated_import_sites = propagated_import_analysis.sites
    propagated_import_dependencies = (
        propagated_import_analysis.diagnostic_dependencies
    )
    blockers: list[dict[str, Any]] = []
    checked_termination_import = _parse_native_termination_import(
        termination_import, import_iat_vas
    )
    indirect_calls = 0
    seen_sites: dict[int, NativeExternalSite] = {}
    seen_returns: dict[int, NativeExternalSite] = {}
    transfer_rvas: set[int] = set()
    transfer_ids: set[str] = set()
    transfer_rows: dict[int, tuple[str, str]] = {}
    transfer_details: dict[int, tuple[Mapping[str, Any], dict[int, Mapping[str, Any]]]] = {}
    internal_call_inputs: dict[int, list[tuple[str, int, Mapping[str, Any]]]] = {}
    callback_site_transfer_rvas: dict[int, int] = {}
    callback_site_events: dict[int, Mapping[str, Any]] = {}
    callback_site_abis: dict[
        int, tuple[CallbackSource, int, CallbackABI]
    ] = {}
    callback_site_authorities: dict[int, tuple[Any, ...]] = {}
    x87_operations: list[NativeX87Operation] = []
    relocation_evidence = _parse_pe_base_relocation_evidence(
        base_relocation_evidence
    )
    for row_index, row in enumerate(rows):
        transfer_id = _required_string(row.get("id"), f"transfer {row_index} id")
        if transfer_id in transfer_ids:
            raise ToolkitInputError(f"duplicate state-machine transfer id {transfer_id}")
        transfer_ids.add(transfer_id)
        original = row.get("original")
        if not isinstance(original, dict):
            raise ToolkitInputError(f"{transfer_id} has no original span")
        transfer_rva = _required_u32(
            original.get("rva_start"), f"{transfer_id} original.rva_start"
        )
        if transfer_rva in transfer_rvas:
            raise ToolkitInputError(f"duplicate state-machine transfer RVA {transfer_rva:#x}")
        transfer_rvas.add(transfer_rva)
        transfer_rows[transfer_rva] = (
            transfer_id,
            str(row.get("_source_record_sha256") or _canonical_sha256(row)),
        )
        ordered = row.get("ordered_events")
        if not isinstance(ordered, list):
            raise ToolkitInputError(f"{transfer_id} ordered_events must be a list")
        instructions = row.get("instructions")
        if not isinstance(instructions, list):
            raise ToolkitInputError(f"{transfer_id} instructions must be a list")
        instruction_by_rva = _instruction_inventory(transfer_id, instructions)
        transfer_details[transfer_rva] = (row, instruction_by_rva)

        fpu_state = row.get("fpu_state")
        machine_ir_micro_ops = row.get("_machine_ir_x87_micro_ops")
        if fpu_state is not None or machine_ir_micro_ops:
            if relocation_evidence is not None:
                export = row.get("static_program_export")
                if not isinstance(export, Mapping):
                    raise ToolkitInputError(
                        f"transfer {row_index} lacks its static-program export binding"
                    )
                bound_contract = _required_sha256(
                    export.get("static_program_contract_sha256"),
                    f"transfer {row_index} static analysis static-program SHA-256",
                )
                if (
                    bound_contract
                    != relocation_evidence.static_program_contract_sha256
                ):
                    raise ToolkitInputError(
                        f"transfer {row_index} and PE relocation evidence bind "
                        "different static-program contracts"
                    )
            try:
                qualified = (
                    _qualified_machine_ir_x87_operations(
                        row=row,
                        transfer_id=transfer_id,
                        first_id=len(x87_operations),
                        relocation_evidence=relocation_evidence,
                        fixed_image_base=fixed_image_base,
                    )
                    if machine_ir_mode
                    else _qualified_x87_operations(
                        row=row,
                        transfer_id=transfer_id,
                        first_id=len(x87_operations),
                        relocation_evidence=relocation_evidence,
                        fixed_image_base=fixed_image_base,
                    )
                )
            except ToolkitInputError as exc:
                aslr_unsafe = isinstance(exc, _X87ReplayASLRUnsafe)
                blockers.append(_blocker(
                    (
                        "x87_replay_aslr_unsafe"
                        if aslr_unsafe
                        else "x87_physical_state_unqualified"
                    ),
                    transfer_id=transfer_id,
                    observed=str(exc),
                    next_action=(
                        "supply exact HIGHLOW relocation evidence and emit a relocated "
                        "operand, or use a stack/register-relative x87 memory form"
                        if aslr_unsafe
                        else "export a complete exact singleton x87 replay binding; mixed "
                        "ordinary/x87 effects and symbolic-only state remain unsupported"
                    ),
                ))
            else:
                x87_operations.extend(qualified)

        event_index = 0
        for event in ordered:
            if not isinstance(event, dict) or event.get("family") != "external":
                continue
            kind = str(event.get("kind") or "")
            if kind == "internal_call":
                target_rva = event.get("target_rva")
                if isinstance(target_rva, int) and not isinstance(target_rva, bool):
                    internal_call_inputs.setdefault(target_rva, []).append(
                        (transfer_id, event_index, event)
                    )
                event_index += 1
                continue
            if kind == "indirect_call" and (
                transfer_id, event_index
            ) in internal_indirect_sites:
                event_index += 1
                continue
            if kind in _SEMANTIC_RUNTIME_EVENT_KINDS:
                event_index += 1
                continue
            if kind not in _CALL_KINDS:
                blockers.append(_blocker(
                    "unsupported_external_event_kind",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    observed=kind,
                    next_action="add and qualify a machine-level bridge for this event kind",
                ))
                event_index += 1
                continue
            instruction_rva = _required_u32(
                event.get("instruction_rva"),
                f"{transfer_id} external event instruction_rva",
            )
            return_rva = _required_u32(
                event.get("return_rva"), f"{transfer_id} external event return_rva"
            )
            instruction = instruction_by_rva.get(instruction_rva)
            if instruction is None:
                blockers.append(_blocker(
                    "external_instruction_missing",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    next_action="regenerate exact instruction evidence for the external event",
                ))
                event_index += 1
                continue
            mnemonic = str(instruction.get("mnemonic") or "").lower()
            outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
            disposition = (
                "tail_jump"
                if mnemonic == "jmp" and outcome.get("kind") == "external_jump"
                else "returns_here"
            )
            raw: bytes | None = None
            raw_hex = instruction.get("bytes")
            if machine_ir_mode:
                instruction_end = _required_u32(
                    instruction.get("rva_end"),
                    f"{transfer_id} external instruction end RVA",
                )
                source_instruction_sha256 = _required_sha256(
                    instruction.get("instruction_sha256"),
                    f"{transfer_id} external instruction SHA-256",
                )
            elif isinstance(raw_hex, str) and _HEX_BYTES.fullmatch(raw_hex):
                raw = bytes.fromhex(raw_hex)
                instruction_end = instruction_rva + len(raw)
                source_instruction_sha256 = sha256_bytes(raw)
            else:
                instruction_end = instruction_rva
                source_instruction_sha256 = ""
            if (
                mnemonic not in {"call", "jmp"}
                or (mnemonic == "jmp" and disposition != "tail_jump")
                or (not machine_ir_mode and raw is None)
            ):
                blockers.append(_blocker(
                    "external_call_instruction_unsupported",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    observed={
                        "mnemonic": mnemonic,
                        "source_instruction_sha256": (
                            source_instruction_sha256 or None
                        ),
                    },
                    next_action=(
                        "supply a typed call/jump instruction bound to the machine-IR span"
                        if machine_ir_mode
                        else "supply a decoded direct or IAT call instruction with exact bytes"
                    ),
                ))
                event_index += 1
                continue
            if disposition == "returns_here" and instruction_end != return_rva:
                blockers.append(_blocker(
                    "external_return_rva_mismatch",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    expected=instruction_end,
                    observed=return_rva,
                    next_action="repair the call boundary before generating a physical bridge",
                ))
                event_index += 1
                continue
            dynamic_target = kind == "indirect_call"
            event_identity_sha256: str | None = None
            abi_metadata_sha256: str | None = None
            target_expression: Any = None
            if machine_ir_mode:
                (
                    event_identity_sha256,
                    abi_metadata_sha256,
                    target_expression,
                ) = _machine_ir_event_evidence(
                    event, transfer_id=transfer_id, event_index=event_index
                )
            callback_registration = None
            iat_va: int | None = None
            target_resolution_evidence: dict[str, Any] | None = None
            if dynamic_target:
                indirect_calls += 1
                dll = None
                symbol = None
                ordinal = None
                resolved_import = _static_iat_import_identity(
                    target_expression, import_iat_vas=import_iat_vas
                )
                if resolved_import is None:
                    resolved_import = propagated_import_sites.get(
                        (transfer_rva, instruction_rva)
                    )
                if resolved_import is not None:
                    dll, symbol, ordinal, iat_va = resolved_import
                    dependencies = propagated_import_dependencies.get(
                        (transfer_rva, instruction_rva), ()
                    )
                    if dependencies:
                        target_resolution_evidence = {
                            "kind": "runtime-guarded-import-origin-v1",
                            "proof_authority": False,
                            "import_iat_va": iat_va,
                            "runtime_guard": "indirect-target-equals-current-iat-cell",
                            "diagnostic_dependencies": [
                                dependency.payload()
                                for dependency in dependencies
                            ],
                        }
                        blockers.append(_blocker(
                            "internal_call_abi_provenance_incomplete",
                            transfer_id=transfer_id,
                            event_index=event_index,
                            instruction_rva=instruction_rva,
                            detail=(
                                "an exact IAT origin crossed an internal call whose "
                                "callee-preserved register frame is not statically closed"
                            ),
                            observed=target_resolution_evidence,
                            next_action=(
                                "prove the internal call frame before candidate generation"
                            ),
                        ))
                if not machine_ir_mode and (raw is None or not _indirect_call_encoding(raw)):
                    blockers.append(_blocker(
                        "indirect_call_encoding_unsupported",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        observed=raw.hex() if raw is not None else None,
                        next_action=(
                            "supply an exact i686 FF /2 indirect CALL instruction "
                            "whose evaluated target is present in the semantic event"
                        ),
                    ))
                    event_index += 1
                    continue
            else:
                dll = _required_string(
                    event.get("dll"), f"{transfer_id} external dll"
                )
                symbol = event.get("symbol")
                ordinal = event.get("ordinal")
                if (isinstance(symbol, str) and symbol) == (
                    isinstance(ordinal, int) and not isinstance(ordinal, bool)
                ):
                    raise ToolkitInputError(
                        f"{transfer_id} external event must name exactly one symbol or ordinal"
                    )
                identity: str | int = symbol if isinstance(symbol, str) else int(ordinal)
                supplied_iat = import_iat_vas.get((dll.lower(), identity))
                encoded_iat = (
                    None
                    if machine_ir_mode or raw is None
                    else _absolute_iat_va(raw, mnemonic)
                )
                if supplied_iat is not None:
                    supplied_iat = _required_u32(supplied_iat, "import IAT VA")
                if encoded_iat is not None and supplied_iat not in {None, encoded_iat}:
                    blockers.append(_blocker(
                        "external_import_iat_evidence_mismatch",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        expected=encoded_iat,
                        observed=supplied_iat,
                        next_action="regenerate the IAT identity map from the exact load-image contract",
                    ))
                    event_index += 1
                    continue
                iat_va = encoded_iat if encoded_iat is not None else supplied_iat
                if iat_va is None:
                    blockers.append(_blocker(
                        "external_import_iat_evidence_missing",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        observed=(
                            source_instruction_sha256
                            if machine_ir_mode
                            else raw.hex() if raw is not None else None
                        ),
                        next_action=(
                            "bind this import identity to one exact original IAT cell "
                            "from the load-image contract"
                        ),
                    ))
                    event_index += 1
                    continue
                if disposition == "tail_jump" and (
                    str(outcome.get("dll") or "").lower() != dll.lower()
                    or outcome.get("symbol") != symbol
                    or outcome.get("ordinal") != ordinal
                ):
                    blockers.append(_blocker(
                        "external_tail_jump_identity_mismatch",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        expected={
                            "dll": dll.lower(),
                            "symbol": symbol,
                            "ordinal": ordinal,
                        },
                        observed={
                            "dll": outcome.get("dll"),
                            "symbol": outcome.get("symbol"),
                            "ordinal": outcome.get("ordinal"),
                        },
                        next_action=(
                            "bind the external_jump outcome to the exact ordered "
                            "tail-import event identity"
                        ),
                    ))
                    event_index += 1
                    continue
            checked_external_contract: CheckedExternalSiteContract | None = None

            authority_sites = authoritative_external_sites.get(
                (transfer_id, event_index), ()
            )
            if authority_sites:
                event_sha256 = _canonical_sha256(event)
                if any(site.event_sha256 != event_sha256 for site in authority_sites):
                    raise ToolkitInputError(
                        f"{transfer_id} external event {event_index} disagrees "
                        "with canonical authority"
                    )
                unit_sha256 = transfer_rows[transfer_rva][1]
                if any(site.unit_sha256 != unit_sha256 for site in authority_sites):
                    raise ToolkitInputError(
                        f"{transfer_id} external event {event_index} unit bytes "
                        "disagree with canonical authority"
                    )
                contracts_by_payload = {
                    json.dumps(
                        _external_runtime_semantics(site.contract),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ): site.contract
                    for site in authority_sites
                }
                if len(contracts_by_payload) != 1:
                    blockers.append(_blocker(
                        "canonical_external_site_alternatives_ambiguous",
                        transfer_id=transfer_id,
                        event_index=event_index,
                        instruction_rva=instruction_rva,
                        observed=[site.site_id for site in authority_sites],
                        next_action=(
                            "split alternatives or emit one common checked machine contract"
                        ),
                    ))
                else:
                    consumed_authoritative_site_ids.update(
                        site.site_id for site in authority_sites
                    )
                    checked_external_contract = next(iter(contracts_by_payload.values()))
                    target_resolution_evidence = {
                        "kind": "canonical-external-sites-v3",
                        "artifact_id": authoritative_external_index.artifact_id,
                        "manifest_sha256": authoritative_external_index.manifest_sha256,
                        "site_ids": [site.site_id for site in authority_sites],
                        "target_sha256s": [site.target_sha256 for site in authority_sites],
                    }

            if checked_external_contract is not None:
                checked_registration = _checked_contract_callback_registration(
                    checked_external_contract,
                    context=f"{transfer_id} external event {event_index}",
                )
                if checked_registration is not None:
                    callback_registration = checked_registration
                    site_ids = (
                        []
                        if target_resolution_evidence is None
                        else target_resolution_evidence.get("site_ids", [])
                    )
                    authority_rows = tuple(
                        callback
                        for site_id in site_ids
                        for callback in callback_authority_by_site.get(site_id, ())
                    )
                    if not authority_rows:
                        blockers.append(_blocker(
                            "callback_protocol_authority_missing",
                            transfer_id=transfer_id,
                            event_index=event_index,
                            instruction_rva=instruction_rva,
                            observed=site_ids,
                            next_action=(
                                "derive callback-authority-v4 from the canonical "
                                "external registration site"
                            ),
                        ))
                    else:
                        callback_site_authorities[instruction_rva] = authority_rows
            elif checked_external_contracts_required:
                blockers.append(_blocker(
                    "canonical_external_site_authority_missing",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    observed=(
                        "canonical-external-sites-v3 was not supplied"
                        if authoritative_external_index is None
                        else "no complete authorizing site matched this event"
                    ),
                    next_action=(
                        "run the canonical external-site authority phase and pass "
                        "its exact artifact to static candidate generation"
                    ),
                ))
            site = NativeExternalSite(
                id=len(sites),
                transfer_id=transfer_id,
                event_index=event_index,
                instruction_rva=instruction_rva,
                return_rva=return_rva,
                instruction_bytes=raw,
                source_instruction_sha256=source_instruction_sha256,
                site_kind="dynamic_target" if dynamic_target else "direct_import",
                dll=dll.lower() if dll is not None else None,
                symbol=symbol if isinstance(symbol, str) else None,
                ordinal=int(ordinal) if isinstance(ordinal, int) else None,
                disposition=disposition,
                iat_va=iat_va,
                transfer_sha256=transfer_rows[transfer_rva][1],
                event_identity_sha256=event_identity_sha256,
                abi_metadata_sha256=abi_metadata_sha256,
                target_expression=target_expression,
                callback_source_kind=(
                    callback_registration[0].kind
                    if callback_registration is not None
                    else None
                ),
                callback_argument_index=(
                    callback_registration[0].argument_index
                    if callback_registration is not None
                    else None
                ),
                callback_argument_offset=(
                    callback_registration[1]
                    if callback_registration is not None
                    else None
                ),
                callback_pointee_offset=(
                    callback_registration[0].pointee_offset
                    if callback_registration is not None
                    else 0
                ),
                callback_nullable=(
                    callback_registration[2].nullable
                    if callback_registration is not None
                    else False
                ),
                external_protocol=None,
                interface_argument_words=None,
                out_interface_relations=(),
                checked_external_contract=checked_external_contract,
                checked_external_contract_required=(
                    checked_external_contracts_required
                ),
                target_resolution_evidence=target_resolution_evidence,
            )
            prior_site = seen_sites.get(instruction_rva)
            if prior_site is not None and prior_site != site:
                raise ToolkitInputError(
                    f"ambiguous external bridge at RVA {instruction_rva:#x}"
                )
            prior_return = seen_returns.get(return_rva)
            if (
                disposition == "returns_here"
                and prior_return is not None
                and prior_return.instruction_rva != instruction_rva
            ):
                blockers.append(_blocker(
                    "ambiguous_external_return_bridge",
                    transfer_id=transfer_id,
                    event_index=event_index,
                    return_rva=return_rva,
                    observed=[prior_return.instruction_rva, instruction_rva],
                    next_action="split the physical return continuations with checked callsite state",
                ))
                event_index += 1
                continue
            seen_sites[instruction_rva] = site
            if disposition == "returns_here":
                seen_returns[return_rva] = site
            sites.append(site)
            if callback_registration is not None:
                callback_site_transfer_rvas[instruction_rva] = transfer_rva
                callback_site_events[instruction_rva] = event
                callback_site_abis[instruction_rva] = callback_registration
            event_index += 1

    if authoritative_external_index is not None:
        submitted = {
            site.site_id for site in authoritative_external_index.sites
        }
        unused = sorted(submitted - consumed_authoritative_site_ids)
        if unused:
            blockers.append(_blocker(
                "canonical_external_site_authority_unused",
                observed=unused,
                next_action=(
                    "regenerate canonical external-site authority from the exact "
                    "machine-IR event inventory"
                ),
            ))

    callback_specs: dict[int, tuple[str, str, str, int]] = {}
    declared_callback_root_rvas = {
        value.get("rva")
        for value in tls_callback_targets
        if isinstance(value, Mapping)
        and isinstance(value.get("rva"), int)
        and not isinstance(value.get("rva"), bool)
    }
    for index, value in enumerate(tls_callback_targets):
        try:
            callback_rva, callback_kind, stack_cleanup = _callback_spec(value, index)
        except ToolkitInputError as exc:
            blockers.append(_blocker(
                "callback_abi_ambiguous",
                callback_index=index,
                observed=value,
                detail=str(exc),
                next_action=(
                    "encode callback kind and exact stack cleanup; TLS callbacks require "
                    "kind=tls_callback and stack_cleanup_bytes=12"
                ),
            ))
            continue
        binding = transfer_rows.get(callback_rva)
        if binding is None:
            blockers.append(_blocker(
                "callback_transfer_missing",
                callback_rva=callback_rva,
                next_action="export a checked semantic transfer for every callback root",
            ))
            continue
        if callback_rva in callback_specs:
            raise ToolkitInputError(f"duplicate callback target RVA {callback_rva:#x}")
        transfer_id, transfer_sha256 = binding
        callback_specs[callback_rva] = (
            transfer_id, transfer_sha256, callback_kind, stack_cleanup
        )

    callback_adapter_specs: set[tuple[int, int, int, int]] = set()
    callback_passthrough_specs: set[tuple[int, int, int, str]] = set()
    callback_storage_writes, all_static_writes = _previous_callback_storage_writes(rows)
    for site in sorted(sites, key=lambda item: item.instruction_rva):
        registration = callback_site_abis.get(site.instruction_rva)
        if registration is None:
            continue
        source_spec, argument_offset, callback_abi = registration
        argument_index = source_spec.argument_index
        callback_kind = callback_abi.kind
        stack_cleanup = callback_abi.stack_cleanup_bytes
        nullable = callback_abi.nullable
        transfer_rva = callback_site_transfer_rvas[site.instruction_rva]
        candidate_expressions: list[tuple[str, Any]] = []
        callback_adapter = (
            site.checked_external_contract.callback_adapter
            if site.checked_external_contract is not None
            else None
        )
        authority_rows = callback_site_authorities.get(site.instruction_rva, ())
        if authority_rows:
            protocols = {
                json.dumps(
                    row.protocol.to_value(),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for row in authority_rows
                if row.protocol is not None
            }
            target_rvas = tuple(sorted({row.target_rva for row in authority_rows}))
            if len(protocols) != 1:
                blockers.append(_blocker(
                    "callback_protocol_authority_ambiguous",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed=sorted(protocols),
                    next_action="split callback alternatives by exact protocol",
                ))
                continue
            protocol = parse_callback_protocol(
                json.loads(next(iter(protocols))),
                registration_argument_words=(
                    site.checked_external_contract.argument_words
                    if site.checked_external_contract is not None
                    else argument_index + 1
                ),
                context=f"{site.transfer_id} callback protocol authority",
            )
            if (
                protocol.source is None
                or protocol.source.argument != argument_index
                or protocol.source.kind != source_spec.kind
                or protocol.signature.argument_words != callback_abi.argument_words
                or protocol.signature.stack_cleanup_bytes != stack_cleanup
            ):
                blockers.append(_blocker(
                    "callback_protocol_runtime_contradiction",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    next_action="regenerate runtime bindings from callback authority",
                ))
                continue
            if callback_adapter is not None and callback_adapter.target_rvas != target_rvas:
                blockers.append(_blocker(
                    "callback_adapter_authority_contradiction",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed=list(callback_adapter.target_rvas),
                    expected=list(target_rvas),
                    next_action="regenerate the adapter from callback-authority-v4",
                ))
                continue
            callback_image_base = (
                relocation_evidence.image_base
                if relocation_evidence is not None
                else fixed_image_base
            )
            if callback_image_base is None:
                blockers.append(_blocker(
                    "callback_image_binding_missing",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    next_action=(
                        "bind callback RVAs to the exact preferred PE image base"
                    ),
                ))
                continue
            candidate_expressions.extend(
                (
                    "bounded machine-IR callback provenance",
                    {
                        "op": "const",
                        "value": (callback_image_base + int(rva)) & 0xFFFFFFFF,
                        "width": 32,
                    },
                )
                for rva in target_rvas
            )
        elif callback_adapter is not None:
            blockers.append(_blocker(
                "callback_protocol_authority_missing",
                transfer_id=site.transfer_id,
                instruction_rva=site.instruction_rva,
                next_action="supply complete callback-authority-v4",
            ))
            continue
        elif source_spec.kind == "argument_pointee":
            blockers.append(_blocker(
                "callback_target_provenance_incomplete",
                transfer_id=site.transfer_id,
                instruction_rva=site.instruction_rva,
                observed={
                    "callback_source": source_spec.as_json(),
                    "manifest_evidence": None,
                },
                next_action=(
                    "run bounded interface provenance and provide its hash-bound "
                    "callback-registration inventory"
                ),
            ))
            continue
        elif site.disposition == "tail_jump":
            incoming = internal_call_inputs.get(transfer_rva, [])
            if not incoming:
                if (
                    transfer_rva == entry_rva
                    or transfer_rva in declared_callback_root_rvas
                ):
                    blockers.append(_blocker(
                        "callback_target_provenance_incomplete",
                        transfer_id=site.transfer_id,
                        instruction_rva=site.instruction_rva,
                        observed=(
                            "callback registration root has no checked argument provenance"
                        ),
                        next_action=(
                            "supply a finite checked callback target set for every "
                            "reachable registration path"
                        ),
                    ))
                continue
            caller_offset = argument_index * 4
            candidate_expressions.extend(
                (
                    f"{caller_id} external event {caller_event_index}",
                    _stack_expression_at_offset(caller_event, caller_offset),
                )
                for caller_id, caller_event_index, caller_event in incoming
            )
        else:
            event = callback_site_events[site.instruction_rva]
            arguments = event.get("arguments")
            argument_expression = (
                arguments[argument_index]
                if isinstance(arguments, list) and argument_index < len(arguments)
                else None
            )
            stack_expression = _stack_expression_at_offset(event, argument_offset)
            exact_argument = _exact_u32_expression(argument_expression)
            exact_stack = _exact_u32_expression(stack_expression)
            if (
                exact_argument is not None
                and exact_stack is not None
                and exact_argument != exact_stack
            ):
                blockers.append(_blocker(
                    "callback_target_provenance_ambiguous",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed=[exact_argument, exact_stack],
                    next_action=(
                        "make the machine argument and checked stack witness identify "
                        "the same callback word"
                    ),
                ))
                continue
            candidate_expressions.append((
                f"{site.transfer_id} external event {site.event_index}",
                _forward_expression_from_prior_writes(
                    argument_expression
                    if exact_argument is not None
                    else stack_expression,
                    row=transfer_details[transfer_rva][0],
                    before_instruction_rva=site.instruction_rva,
                ),
            ))

        for source, expression in candidate_expressions:
            preferred_value = _exact_u32_expression(expression)
            if preferred_value is None:
                storage_va = (
                    _exact_u32_expression(expression.get("address"))
                    if isinstance(expression, Mapping)
                    and expression.get("op") == "load"
                    and expression.get("width") == 4
                    else None
                )
                storage_invariant = (
                    None
                    if storage_va is None
                    else _callback_storage_origin_is_safe(
                        rows=rows,
                        use_rva=transfer_rva,
                        storage_va=storage_va,
                        callback_writes=callback_storage_writes,
                        all_writes=all_static_writes,
                        initial_zero_ranges=normalized_zero_ranges,
                        nullable=nullable,
                    )
                )
                if storage_va is not None and storage_invariant is not None:
                    callback_passthrough_specs.add((
                        site.instruction_rva,
                        argument_index,
                        storage_va,
                        storage_invariant,
                    ))
                    continue
                blockers.append(_blocker(
                    "callback_target_provenance_incomplete",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed={"source": source, "expression": expression},
                    next_action=(
                        "reduce the callback argument to a bounded finite set of static "
                        "code targets before generating a native adapter"
                    ),
                ))
                continue
            if preferred_value == 0:
                if nullable:
                    continue
                blockers.append(_blocker(
                    "callback_target_null_forbidden",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed={"source": source, "value": 0},
                    next_action="supply a non-null callback target required by the API contract",
                ))
                continue
            callback_image_base = (
                relocation_evidence.image_base
                if relocation_evidence is not None
                else fixed_image_base
            )
            if callback_image_base is None:
                blockers.append(_blocker(
                    "callback_image_binding_missing",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed={"source": source, "preferred_value": preferred_value},
                    next_action=(
                        "bind callback constants to the exact preferred PE image base"
                    ),
                ))
                continue
            callback_rva = preferred_value - callback_image_base
            if not 0 <= callback_rva <= 0xFFFFFFFF:
                blockers.append(_blocker(
                    "callback_target_outside_static_image",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    observed={"source": source, "preferred_value": preferred_value},
                    next_action=(
                        "model dynamic or imported callback provenance explicitly; static "
                        "registration accepts only image-relative targets"
                    ),
                ))
                continue
            binding = transfer_rows.get(callback_rva)
            if binding is None:
                blockers.append(_blocker(
                    "callback_transfer_missing",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    callback_rva=callback_rva,
                    observed={"source": source, "preferred_value": preferred_value},
                    next_action=(
                        "export a checked semantic transfer for every registered callback"
                    ),
                ))
                continue
            callback_transfer_id, callback_transfer_sha256 = binding
            existing = callback_specs.get(callback_rva)
            callback_spec = (
                callback_transfer_id,
                callback_transfer_sha256,
                callback_kind,
                stack_cleanup,
            )
            if existing is not None and existing != callback_spec:
                blockers.append(_blocker(
                    "callback_abi_ambiguous",
                    transfer_id=site.transfer_id,
                    instruction_rva=site.instruction_rva,
                    callback_rva=callback_rva,
                    expected=existing[2:],
                    observed=callback_spec[2:],
                    next_action=(
                        "use one exact callback ABI for each static callback target"
                    ),
                ))
                continue
            callback_specs[callback_rva] = callback_spec
            callback_adapter_specs.add((
                site.instruction_rva,
                argument_index,
                callback_rva,
                callback_rva,
            ))
    callbacks = tuple(
        NativeCallbackTarget(
            id=index,
            rva=rva,
            transfer_id=callback_specs[rva][0],
            transfer_sha256=callback_specs[rva][1],
            kind=callback_specs[rva][2],
            stack_cleanup_bytes=callback_specs[rva][3],
        )
        for index, rva in enumerate(sorted(callback_specs))
    )
    callback_adapters = tuple(
        NativeCallbackAdapter(
            id=index,
            instruction_rva=instruction_rva,
            argument_index=argument_index,
            original_rva=original_rva,
            callback_rva=callback_rva,
        )
        for index, (
            instruction_rva, argument_index, original_rva, callback_rva
        ) in enumerate(sorted(callback_adapter_specs))
    )
    callback_adapter_receipts, receipt_blockers = (
        _build_callback_adapter_receipts(
            sites=tuple(sites),
            adapters=callback_adapters,
            targets=callbacks,
        )
    )
    blockers.extend(receipt_blockers)
    callback_passthroughs = tuple(
        NativeCallbackPassthrough(
            instruction_rva=instruction_rva,
            argument_index=argument_index,
            storage_va=storage_va,
            storage_invariant=storage_invariant,
        )
        for instruction_rva, argument_index, storage_va, storage_invariant in sorted(
            callback_passthrough_specs
        )
    )
    if entry_rva not in transfer_rvas:
        blockers.append(_blocker(
            "entry_transfer_missing",
            entry_rva=entry_rva,
            next_action="export the semantic transfer beginning at the PE entrypoint",
        ))
    implementation_dispatch_receipt, implementation_blockers = (
        _build_implementation_dispatch_receipt(
            semantic_input_sha256=semantic_input_sha256,
            execution_authority=execution_authority,
            machine_ir_manifest_sha256=(
                sha256_file(machine_ir_manifest)
            ),
            inventory_source_rows=raw_rows,
            source_rows=implementation_source_rows,
            rows=rows,
            external_sites=sites,
            selected_portable_components=selected_portable_components,
        )
    )
    blockers.extend(implementation_blockers)
    return NativeEnginePlan(
        input_mode=_MACHINE_IR_INPUT_MODE,
        entry_rva=_required_u32(entry_rva, "entry RVA"),
        transfer_count=len(rows),
        external_sites=tuple(sorted(sites, key=lambda item: item.instruction_rva)),
        import_bindings=tuple(import_bindings),
        indirect_call_count=indirect_calls,
        callback_targets=callbacks,
        callback_adapters=callback_adapters,
        callback_adapter_receipts=callback_adapter_receipts,
        implementation_dispatch_receipt=implementation_dispatch_receipt,
        callback_passthroughs=callback_passthroughs,
        x87_operations=tuple(x87_operations),
        termination_import=checked_termination_import,
        recovered_executable_data_ranges=recovered_data_ranges,
        fixed_image_base=fixed_image_base,
        blockers=tuple(blockers),
    )


from .engine_package import write_spx_native_engine_package  # noqa: E402




__all__ = [
    "NATIVE_ENGINE_PACKAGE_FORMAT",
    "NATIVE_ENGINE_PLAN_FORMAT",
    "PE32_BASE_RELOCATION_EVIDENCE_FORMAT",
    "NativeEnginePlan",
    "NativeCallbackTarget",
    "NativeExternalSite",
    "NativeTerminationImport",
    "NativeX87Operation",
    "TypedX87Operation",
    "TypedX87Operand",
    "TYPED_NATIVE_X87_OPERATION_FORMAT",
    "extract_typed_x87_operation",
    "typed_x87_operation_from_micro_op",
    "plan_spx_native_engine",
    "write_spx_native_engine_package",
]
