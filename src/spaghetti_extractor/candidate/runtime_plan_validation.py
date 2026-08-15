"""Native engine plan and external contract validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import NATIVE_ENGINE_PLAN_FORMAT
from ..external.contracts import (
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    parse_checked_external_site_contract,
)
from ..external.machine_import_profiles import (
    MachineImportIdentity,
    MachineImportProfileError,
    load_machine_import_profile_set,
)
from .runtime_model import (
    NativeExternalRangeRule,
    NativeImplementationDispatch,
    StageBNativeRuntimeError,
    _InterpreterTransferBinding,
)
from .runtime_receipts import (
    _validate_callback_adapter_receipts,
    _validate_implementation_dispatch_receipt,
)
from .runtime_values import (
    _required_count,
    _required_list,
    _required_object,
    _required_sha256,
    _required_string,
    _required_u32,
)


def _validate_native_plan(
    payload: dict[str, Any],
    *,
    state_machine_sha256: str,
    input_mode: str,
    transfer_rvas: tuple[int, ...],
    transfer_bindings: tuple[_InterpreterTransferBinding, ...],
) -> tuple[
    int,
    tuple[tuple[int, int], ...],
    tuple[dict[str, Any], ...],
    dict[str, Any],
    tuple[NativeImplementationDispatch, ...],
    tuple[tuple[int, int], ...],
]:
    if payload.get("format") != NATIVE_ENGINE_PLAN_FORMAT:
        raise StageBNativeRuntimeError("native-engine plan has an unsupported format")
    if payload.get("status") != "ready":
        raise StageBNativeRuntimeError("native-engine plan is not ready")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise StageBNativeRuntimeError(
            "interpreter and native-engine packages bind different state machines"
        )
    if payload.get("input_mode") != input_mode:
        raise StageBNativeRuntimeError(
            "native-engine plan and packages bind different semantic input modes"
        )
    if _required_list(payload.get("blockers"), "native-engine blockers"):
        raise StageBNativeRuntimeError("ready native-engine plan contains blockers")
    implementation_dispatch_receipt, implementation_dispatches = (
        _validate_implementation_dispatch_receipt(
            payload,
            state_machine_sha256=state_machine_sha256,
            transfer_bindings=transfer_bindings,
        )
    )
    callback_targets = tuple(
        _required_u32(value, "native-engine callback RVA")
        for value in _required_list(
            payload.get("callback_targets"), "native-engine callbacks"
        )
    )
    if callback_targets != tuple(sorted(set(callback_targets))):
        raise StageBNativeRuntimeError(
            "native-engine callback RVAs must be sorted and unique"
        )
    if any(target not in transfer_rvas for target in callback_targets):
        raise StageBNativeRuntimeError(
            "native-engine callback lacks a checked interpreter transfer"
        )
    recovered_data = _required_object(
        payload.get("recovered_executable_data"),
        "native-engine recovered executable data",
    )
    if recovered_data.get("dispatch_policy") != "fail_closed_as_noncode":
        raise StageBNativeRuntimeError(
            "native-engine recovered executable data is not fail-closed"
        )
    recovered_ranges: list[tuple[int, int]] = []
    for index, raw in enumerate(
        _required_list(
            recovered_data.get("ranges"),
            "native-engine recovered executable-data ranges",
        )
    ):
        row = _required_object(raw, f"recovered executable-data range {index}")
        _required_string(row.get("id"), f"recovered executable-data range {index} id")
        _required_sha256(
            row.get("bytes_sha256"),
            f"recovered executable-data range {index} SHA-256",
        )
        start = _required_u32(
            row.get("rva_start"), f"recovered executable-data range {index} start"
        )
        end = _required_u32(
            row.get("rva_end"), f"recovered executable-data range {index} end"
        )
        if end <= start:
            raise StageBNativeRuntimeError(
                "native-engine recovered executable-data range is empty"
            )
        if recovered_ranges and start < recovered_ranges[-1][1]:
            raise StageBNativeRuntimeError(
                "native-engine recovered executable-data ranges overlap or are unsorted"
            )
        recovered_ranges.append((start, end))
    entry_rva = _required_u32(payload.get("entry_rva"), "native-engine entry RVA")
    if any(
        start <= target < end
        for target in (entry_rva, *callback_targets)
        for start, end in recovered_ranges
    ):
        raise StageBNativeRuntimeError(
            "native entry or callback target overlaps recovered executable data"
        )
    callback_abis = _required_list(
        payload.get("callback_abis"), "native-engine callback ABIs"
    )
    if len(callback_abis) != len(callback_targets):
        raise StageBNativeRuntimeError(
            "native-engine callback ABI inventory differs from callback targets"
        )
    for index, (raw, target) in enumerate(
        zip(callback_abis, callback_targets, strict=True)
    ):
        callback = _required_object(raw, f"native-engine callback ABI {index}")
        if _required_u32(callback.get("rva"), "callback ABI RVA") != target:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI RVA differs from its target"
            )
        expected_symbol = f"stage_b_payload_callback_{target:08x}"
        if _required_string(callback.get("symbol"), "callback ABI symbol") != expected_symbol:
            raise StageBNativeRuntimeError(
                "native-engine callback ABI symbol is not the canonical RVA anchor"
            )
        _required_string(callback.get("transfer_id"), "callback ABI transfer id")
        _required_sha256(
            callback.get("transfer_sha256"), "callback ABI transfer SHA-256"
        )
        kind = _required_string(callback.get("kind"), "callback ABI kind")
        cleanup = _required_count(
            callback.get("stack_cleanup_bytes"), "callback ABI stack cleanup"
        )
        if kind == "tls_callback":
            if cleanup != 12:
                raise StageBNativeRuntimeError(
                    "PE32 TLS callback ABI must clean exactly 12 stack bytes"
                )
        elif kind != "generic_callback":
            raise StageBNativeRuntimeError(
                "native-engine callback ABI kind is unsupported"
            )
    callback_adapter_receipts = _validate_callback_adapter_receipts(
        payload, callback_abis=callback_abis
    )
    passthroughs = _required_list(
        payload.get("callback_passthroughs"),
        "native-engine callback passthroughs",
    )
    seen_passthroughs: set[tuple[int, int]] = set()
    for index, raw in enumerate(passthroughs):
        passthrough = _required_object(
            raw, f"native-engine callback passthrough {index}"
        )
        key = (
            _required_u32(
                passthrough.get("instruction_rva"), "callback passthrough call RVA"
            ),
            _required_count(
                passthrough.get("argument_index"), "callback passthrough argument"
            ),
        )
        _required_u32(
            passthrough.get("storage_va"), "callback passthrough storage VA"
        )
        if (
            passthrough.get("origin") != "previous_registered_callback"
            or passthrough.get("storage_invariant") not in {
                "dominating_previous_registered_callback",
                "initial_zero_or_previous_registered_callback",
            }
            or passthrough.get("runtime_action")
            != "pass_through_environment_pointer"
            or key in seen_passthroughs
        ):
            raise StageBNativeRuntimeError(
                "native-engine callback passthrough is malformed or duplicate"
            )
        seen_passthroughs.add(key)
    if entry_rva not in transfer_rvas:
        raise StageBNativeRuntimeError(
            "native-engine entry RVA is absent from the interpreter transfer table"
        )
    counts = _required_object(payload.get("counts"), "native-engine counts")
    if _required_count(counts.get("transfers"), "native-engine transfer count") != len(
        transfer_rvas
    ):
        raise StageBNativeRuntimeError(
            "native-engine and interpreter transfer counts differ"
        )
    if _required_count(
        counts.get("callback_adapters"),
        "native-engine callback adapter count",
    ) != len(_required_list(
        payload.get("callback_adapters"), "native-engine callback adapters"
    )):
        raise StageBNativeRuntimeError(
            "native-engine callback adapter count differs from its inventory"
        )
    if _required_count(
        counts.get("callback_adapter_receipts"),
        "native-engine callback adapter receipt count",
    ) != len(callback_adapter_receipts):
        raise StageBNativeRuntimeError(
            "native-engine callback adapter receipt count differs from its inventory"
        )
    if _required_count(
        counts.get("callback_passthroughs"),
        "native-engine callback passthrough count",
    ) != len(passthroughs):
        raise StageBNativeRuntimeError(
            "native-engine callback passthrough count differs from its inventory"
        )
    return entry_rva, tuple(
        (
            _required_u32(
                _required_object(raw, f"native-engine callback ABI {index}").get("rva"),
                "callback ABI RVA",
            ),
            _required_count(
                _required_object(raw, f"native-engine callback ABI {index}").get(
                    "stack_cleanup_bytes"
                ),
                "callback ABI stack cleanup",
            ),
        )
        for index, raw in enumerate(callback_abis)
    ), callback_adapter_receipts, implementation_dispatch_receipt, (
        implementation_dispatches
    ), tuple(recovered_ranges)


def _validate_native_termination(value: Any) -> bool:
    if value is None:
        return False
    payload = _required_object(value, "native-engine termination import")
    _required_string(payload.get("dll"), "termination import DLL")
    symbol = payload.get("symbol")
    ordinal = payload.get("ordinal")
    if (symbol is None) == (ordinal is None):
        raise StageBNativeRuntimeError(
            "termination import must provide exactly one symbol or ordinal"
        )
    if symbol is not None:
        _required_string(symbol, "termination import symbol")
    else:
        _required_u32(ordinal, "termination import ordinal")
    _required_u32(payload.get("iat_va"), "termination import IAT VA")
    if (
        payload.get("transfer") != "tail_jump"
        or payload.get("argument_source") != "cdecl-stack-word-0-from-eax"
        or payload.get("required_disposition") != "terminates"
    ):
        raise StageBNativeRuntimeError(
            "native-engine termination import policy is unsupported"
        )
    return True


def _external_range_rules(
    native_plan: dict[str, Any],
    profile_path: Path | None,
) -> tuple[
    tuple[NativeExternalRangeRule, ...],
    tuple[int, ...],
    tuple[dict[str, Any], ...],
]:
    external_sites = _required_list(
        native_plan.get("external_sites"), "native-engine external sites"
    )
    has_external_site = any(
        isinstance(site, Mapping)
        and (
            isinstance(site.get("import"), Mapping)
            or site.get("site_kind") in {"external_call", "external_jump"}
            or isinstance(site.get("external_protocol"), Mapping)
        )
        for site in external_sites
    )
    if not has_external_site:
        selected_contracts = {}
    elif profile_path is None:
        raise StageBNativeRuntimeError(
            "native runtime requires the canonical machine-import profile bundle"
        )
    else:
        try:
            profile_set = load_machine_import_profile_set([profile_path])
        except MachineImportProfileError as exc:
            raise StageBNativeRuntimeError(str(exc)) from exc
        selected_contracts = profile_set.by_identity()

    bindings: dict[tuple[str, str, str | int], dict[str, Any]] = {}
    for binding_index, raw_binding in enumerate(
        _required_list(native_plan.get("import_bindings", []), "native-engine import bindings")
    ):
        binding = _required_object(
            raw_binding, f"native-engine import binding {binding_index}"
        )
        dll = _required_string(binding.get("dll"), "import binding DLL").lower()
        symbol = binding.get("symbol")
        ordinal = binding.get("ordinal")
        identity = (
            dll,
            "symbol" if isinstance(symbol, str) else "ordinal",
            symbol if isinstance(symbol, str) else ordinal,
        )
        _required_u32(binding.get("iat_va"), "import binding IAT VA")
        iat_rva = _required_u32(binding.get("iat_rva"), "import binding IAT RVA")
        if iat_rva == 0 or identity in bindings:
            raise StageBNativeRuntimeError(
                "native-engine import bindings are duplicate or use RVA zero"
            )
        bindings[identity] = dict(binding)

    expanded_sites: list[
        tuple[dict[str, Any], int | None, dict[str, Any], int, str]
    ] = []
    authorized_sites: set[int] = set()
    blocked_sites: list[dict[str, Any]] = []
    dispatch_receipt = _required_object(
        native_plan.get("implementation_dispatch_receipt"),
        "native-engine implementation dispatch receipt",
    )
    dispatch_reachability = _required_object(
        dispatch_receipt.get("reachability"),
        "native-engine implementation reachability",
    )
    if dispatch_reachability.get("status") != "complete":
        raise StageBNativeRuntimeError(
            "native runtime requires complete implementation reachability"
        )

    def block_site(
        *, site_index: int, site: Mapping[str, Any], category: str, detail: str
    ) -> None:
        del site_index, site, category
        raise StageBNativeRuntimeError(detail)

    for site_index, raw_site in enumerate(external_sites):
        site = _required_object(raw_site, f"native-engine external site {site_index}")
        is_external = (
            isinstance(site.get("import"), Mapping)
            or isinstance(site.get("external_protocol"), Mapping)
        )
        if not is_external:
            block_site(
                site_index=site_index,
                site=site,
                category="uncontracted_dynamic_external_target",
                detail=(
                    f"native-engine external site {site_index} has no checked "
                    "import, interface, or callable target identity"
                ),
            )
            continue
        raw_contract = site.get("checked_external_contract")
        resolution = site.get("target_resolution_evidence")
        if not isinstance(raw_contract, Mapping):
            block_site(
                site_index=site_index,
                site=site,
                category="checked_external_contract_missing",
                detail=(
                    f"native-engine external site {site_index} has no checked "
                    "external contract"
                ),
            )
            continue
        if (
            not isinstance(resolution, Mapping)
            or resolution.get("kind") != "canonical-external-sites-v3"
        ):
            block_site(
                site_index=site_index,
                site=site,
                category="canonical_external_site_missing",
                detail=(
                    f"native-engine external site {site_index} is not bound to "
                    "canonical-external-sites-v3"
                ),
            )
            continue
        try:
            checked = parse_checked_external_site_contract(
                raw_contract,
                context=f"native-engine external site {site_index}",
            )
        except CheckedExternalSiteContractError as exc:
            raise StageBNativeRuntimeError(str(exc)) from exc

        imported_site = site.get("import")
        if isinstance(imported_site, Mapping):
            try:
                outer_identity = ExternalSiteIdentity.imported(
                    imported_site,
                    context=f"native-engine external site {site_index}",
                )
            except CheckedExternalSiteContractError as exc:
                raise StageBNativeRuntimeError(str(exc)) from exc
            if checked.identity != outer_identity:
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} identity differs from its checked contract"
                )

        target_iat_rva: int | None = None
        if checked.identity.kind == "import":
            profile_identity = MachineImportIdentity(
                dll=str(checked.identity.dll),
                kind="symbol" if checked.identity.symbol is not None else "ordinal",
                value=(
                    str(checked.identity.symbol)
                    if checked.identity.symbol is not None
                    else int(checked.identity.ordinal)
                ),
            )
            selected = selected_contracts.get(profile_identity)
            if selected is None:
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} has no selected exact profile"
                )
            if (
                checked.profile_binding.get("profile_id") != selected.profile_id
                or checked.profile_binding.get("profile_sha256")
                != selected.profile_sha256
            ):
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} binds a "
                    "different canonical profile"
                )
            binding_identity = (
                profile_identity.dll,
                profile_identity.kind,
                profile_identity.value,
            )
            binding = bindings.get(binding_identity)
            if binding is None and site.get("site_kind") == "dynamic_target":
                raise StageBNativeRuntimeError(
                    f"native-engine external site {site_index} has no exact import binding"
                )
            if site.get("site_kind") == "dynamic_target" and binding is not None:
                target_iat_rva = _required_u32(
                    binding.get("iat_rva"), "import binding IAT RVA"
                )
        expanded_sites.append((
            dict(site),
            target_iat_rva,
            checked.profile_effect_payload(),
            checked.argument_base_offset,
            checked.contract_id,
        ))
        authorized_sites.add(
            _required_u32(site.get("instruction_rva"), "external site RVA")
        )

    rules: list[NativeExternalRangeRule] = []
    for (
        site,
        target_iat_rva,
        contract,
        argument_base_offset,
        contract_id,
    ) in expanded_sites:
        instruction_rva = _required_u32(
            site.get("instruction_rva"), "external site instruction RVA"
        )
        argument_count = _required_count(
            contract.get("argument_words"),
            f"machine-call contract {contract_id} argument count",
        )
        if argument_count > 256:
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has too many arguments"
            )
        disposition = site.get("disposition")
        if disposition not in {"returns_here", "tail_jump"}:
            raise StageBNativeRuntimeError(
                f"external site {instruction_rva:#x} has an unsupported disposition"
            )
        relations = contract.get("result_register_relations", [])
        if not isinstance(relations, list):
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has invalid result relations"
            )
        for relation_index, raw_relation in enumerate(relations):
            relation = _required_object(
                raw_relation,
                f"machine-call contract {contract_id} result {relation_index}",
            )
            if relation.get("relation") != "dynamic_range_base":
                continue
            register = _required_string(
                relation.get("register"), "dynamic-range result register"
            ).lower()
            if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} uses an unsupported result register"
                )
            size = _required_object(
                relation.get("size"), "dynamic-range result size"
            )
            kind = _required_string(size.get("kind"), "dynamic-range size kind")
            size_value = 0
            size_argument: int | None = None
            size_right_argument: int | None = None
            termination_unit_bytes = 0
            termination_zero_units = 0
            termination_max_units = 0
            if kind == "fixed":
                size_value = _required_count(
                    size.get("byte_count"), "fixed dynamic-range size"
                )
            elif kind == "argument":
                size_argument = _required_count(
                    size.get("argument"), "dynamic-range size argument"
                )
                size_value = _required_count(
                    size.get("scale", 1), "dynamic-range size scale"
                )
            elif kind == "product":
                size_argument = _required_count(
                    size.get("left_argument"), "dynamic-range left size argument"
                )
                size_right_argument = _required_count(
                    size.get("right_argument"), "dynamic-range right size argument"
                )
            elif kind == "bounded_zero_run":
                termination_unit_bytes = _required_count(
                    size.get("unit_bytes"), "terminated range unit size"
                )
                termination_zero_units = _required_count(
                    size.get("zero_units"), "terminated range zero-run length"
                )
                termination_max_units = _required_count(
                    size.get("max_units"), "terminated range unit limit"
                )
                if (
                    termination_unit_bytes not in {1, 2, 4}
                    or termination_zero_units == 0
                    or termination_zero_units > 16
                    or termination_max_units < termination_zero_units
                    or termination_max_units > 1048576
                ):
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an invalid terminated range size"
                    )
            else:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has unsupported range size {kind!r}"
                )
            for size_index in (size_argument, size_right_argument):
                if size_index is not None and size_index >= argument_count:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} range size argument is out of bounds"
                    )
            minimum_size = _required_count(
                relation.get("minimum_size", 0), "dynamic-range minimum size"
            )
            nullable = relation.get("nullable")
            if not isinstance(nullable, bool):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has invalid nullability"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="add_result_range",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=register,
                    argument=None,
                    size_kind=kind,
                    size_value=size_value,
                    size_argument=size_argument,
                    size_right_argument=size_right_argument,
                    minimum_size=minimum_size,
                    nullable=nullable,
                    termination_unit_bytes=termination_unit_bytes,
                    termination_zero_units=termination_zero_units,
                    termination_max_units=termination_max_units,
                    pointee_offset=0,
                    max_elements=0,
                    element_unit_bytes=0,
                    element_max_units=0,
                    contract_id=contract_id,
                )
            )
            required_words = relation.get("required_words", [])
            if not isinstance(required_words, list):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has invalid required words"
                )
            for word_index, raw_word in enumerate(required_words):
                word = _required_object(
                    raw_word,
                    f"machine-call contract {contract_id} required word {word_index}",
                )
                shape = word.get("pointee_shape")
                if shape is None:
                    continue
                if word.get("relation") != "nullable_dynamic_pointer":
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} gives a shape to a non-pointer word"
                    )
                shape = _required_object(shape, "dynamic-pointer pointee shape")
                if shape.get("kind") != "null_terminated_pointer_vector":
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported pointee shape"
                    )
                pointee_offset = _required_count(
                    word.get("offset"), "dynamic-pointer word offset"
                )
                if pointee_offset % 4 != 0 or pointee_offset + 4 > minimum_size:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an out-of-range pointer word"
                    )
                max_elements = _required_count(
                    shape.get("max_elements"), "pointer-vector element limit"
                )
                if max_elements == 0 or max_elements > 65536:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an invalid pointer-vector limit"
                    )
                element = _required_object(
                    shape.get("element"), "pointer-vector element shape"
                )
                if element.get("kind") != "bounded_terminated":
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported vector element shape"
                    )
                element_unit_bytes = _required_count(
                    element.get("unit_bytes"), "terminated-element unit size"
                )
                if element_unit_bytes not in {1, 2, 4}:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported element unit"
                    )
                sentinel = element.get("sentinel")
                if sentinel != [0] * element_unit_bytes:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported element sentinel"
                    )
                element_max_units = _required_count(
                    element.get("max_units"), "terminated-element unit limit"
                )
                if element_max_units == 0 or element_max_units > 1048576:
                    raise StageBNativeRuntimeError(
                        f"machine-call contract {contract_id} has an invalid element unit limit"
                    )
                rules.append(
                    NativeExternalRangeRule(
                        instruction_rva=instruction_rva,
                        target_iat_rva=target_iat_rva,
                        action="add_result_pointee_ranges",
                        argument_base_offset=argument_base_offset,
                        argument_count=argument_count,
                        register=register,
                        argument=None,
                        size_kind=None,
                        size_value=0,
                        size_argument=None,
                        size_right_argument=None,
                        minimum_size=0,
                        nullable=True,
                        termination_unit_bytes=0,
                        termination_zero_units=0,
                        termination_max_units=0,
                        pointee_offset=pointee_offset,
                        max_elements=max_elements,
                        element_unit_bytes=element_unit_bytes,
                        element_max_units=element_max_units,
                        contract_id=contract_id,
                    )
                )
        out_pointer_relations = contract.get("out_pointer_relations", [])
        if not isinstance(out_pointer_relations, list):
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has invalid out-pointer relations"
            )
        for out_index, raw_out in enumerate(out_pointer_relations):
            out_relation = _required_object(
                raw_out,
                f"machine-call contract {contract_id} out pointer {out_index}",
            )
            if out_relation.get("relation") != "nullable_dynamic_pointer":
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer relation"
                )
            argument = _required_count(
                out_relation.get("argument"), "out-pointer argument"
            )
            if argument >= argument_count:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} out-pointer argument is out of bounds"
                )
            pointee_offset = _required_count(
                out_relation.get("offset", 0), "out-pointer offset"
            )
            shape = _required_object(
                out_relation.get("pointee_shape"), "out-pointer pointee shape"
            )
            if shape.get("kind") != "null_terminated_pointer_vector":
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer shape"
                )
            max_elements = _required_count(
                shape.get("max_elements"), "out-pointer vector limit"
            )
            if max_elements == 0 or max_elements > 65536:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-pointer vector limit"
                )
            element = _required_object(
                shape.get("element"), "out-pointer vector element shape"
            )
            if element.get("kind") != "bounded_terminated":
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer element shape"
                )
            element_unit_bytes = _required_count(
                element.get("unit_bytes"), "out-pointer element unit size"
            )
            sentinel = element.get("sentinel")
            if (
                element_unit_bytes not in {1, 2, 4}
                or sentinel != [0] * element_unit_bytes
            ):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer sentinel"
                )
            element_max_units = _required_count(
                element.get("max_units"), "out-pointer element unit limit"
            )
            if element_max_units == 0 or element_max_units > 1048576:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-pointer element limit"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="add_argument_pointee_ranges",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=None,
                    argument=argument,
                    size_kind=None,
                    size_value=0,
                    size_argument=None,
                    size_right_argument=None,
                    minimum_size=0,
                    nullable=True,
                    termination_unit_bytes=0,
                    termination_zero_units=0,
                    termination_max_units=0,
                    pointee_offset=pointee_offset,
                    max_elements=max_elements,
                    element_unit_bytes=element_unit_bytes,
                    element_max_units=element_max_units,
                    contract_id=contract_id,
                )
            )
        out_interface_relations = contract.get("out_interface_relations", [])
        if not isinstance(out_interface_relations, list):
            raise StageBNativeRuntimeError(
                f"machine-call contract {contract_id} has invalid out-interface relations"
            )
        for out_index, raw_out in enumerate(out_interface_relations):
            out_relation = _required_object(
                raw_out,
                f"machine-call contract {contract_id} out interface {out_index}",
            )
            argument = _required_count(
                out_relation.get("argument_index"), "out-interface argument"
            )
            if argument >= argument_count:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} out-interface argument is out of bounds"
                )
            pointee_offset = _required_count(
                out_relation.get("offset", 0), "out-interface offset"
            )
            object_size = _required_count(
                out_relation.get("object_size"), "out-interface object size"
            )
            vtable_size = _required_count(
                out_relation.get("vtable_size"), "out-interface vtable size"
            )
            nullable = out_relation.get("nullable")
            if (
                out_relation.get("write_width") != 4
                or object_size < 4
                or vtable_size < 4
                or vtable_size % 4 != 0
                or not isinstance(nullable, bool)
                or out_relation.get("success_condition")
                != "hresult_succeeded_eax"
            ):
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-interface shape"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="add_argument_interface_ranges",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=None,
                    argument=argument,
                    size_kind="fixed",
                    size_value=vtable_size,
                    size_argument=None,
                    size_right_argument=None,
                    minimum_size=object_size,
                    nullable=nullable,
                    termination_unit_bytes=0,
                    termination_zero_units=0,
                    termination_max_units=0,
                    pointee_offset=pointee_offset,
                    max_elements=0,
                    element_unit_bytes=0,
                    element_max_units=0,
                    contract_id=contract_id,
                )
            )
        if contract.get("world_effect") == "dynamicRangeRelease":
            argument = _required_count(
                contract.get("world_effect_argument"),
                "dynamic-range release argument",
            )
            if argument >= argument_count:
                raise StageBNativeRuntimeError(
                    f"machine-call contract {contract_id} release argument is out of bounds"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    action="release_argument_range",
                    argument_base_offset=argument_base_offset,
                    argument_count=argument_count,
                    register=None,
                    argument=argument,
                    size_kind=None,
                    size_value=0,
                    size_argument=None,
                    size_right_argument=None,
                    minimum_size=0,
                    nullable=True,
                    termination_unit_bytes=0,
                    termination_zero_units=0,
                    termination_max_units=0,
                    pointee_offset=0,
                    max_elements=0,
                    element_unit_bytes=0,
                    element_max_units=0,
                    contract_id=contract_id,
                )
            )
    sorted_rules = tuple(
        sorted(
            rules,
            key=lambda item: (
                item.instruction_rva,
                item.target_iat_rva or 0,
                {
                    "add_result_range": 0,
                    "add_result_pointee_ranges": 1,
                    "add_argument_pointee_ranges": 2,
                    "add_argument_interface_ranges": 3,
                    "release_argument_range": 4,
                }[item.action],
                item.contract_id,
            ),
        )
    )
    return (
        sorted_rules,
        tuple(sorted(authorized_sites)),
        tuple(sorted(
            blocked_sites,
            key=lambda item: (
                int(item["instruction_rva"]),
                str(item["category"]),
            ),
        )),
    )
