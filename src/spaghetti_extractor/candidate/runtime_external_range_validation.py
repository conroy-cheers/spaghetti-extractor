"""Checked external range validation for canonical runtime plans."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

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
    CandidateRuntimeError,
    INTERFACE_METHOD_TARGET_TAG,
    NativeExternalRangeRule,
    NativeGuestDispatchDomain,
    interface_class_catalog,
    interface_method_target_catalog,
    loader_target_catalog,
)
from .runtime_plan_validation import (
    ValidatedExternalInventoryV8,
    validated_external_inventory_v8,
)
from .runtime_values import (
    _required_count,
    _required_list,
    _required_object,
    _required_string,
    _required_u32,
)

def _external_range_rules(
    native_plan: dict[str, Any],
    profile_path: Path | None,
    *,
    resolved_environment_sha256: str | None = None,
    guest_dispatch_domains: tuple[NativeGuestDispatchDomain, ...] = (),
    external_inventory: ValidatedExternalInventoryV8 | None = None,
) -> tuple[
    tuple[NativeExternalRangeRule, ...],
    tuple[int, ...],
    tuple[dict[str, Any], ...],
]:
    inventory = (
        external_inventory
        if external_inventory is not None
        else validated_external_inventory_v8(native_plan)
    )
    has_external_site = any(
        isinstance(target, Mapping)
        and (
            isinstance(target.get("import"), Mapping)
            or isinstance(target.get("external_protocol"), Mapping)
            or isinstance(target.get("checked_external_contract"), Mapping)
        )
        for target in inventory.target_contracts.values()
    )
    if not has_external_site:
        selected_contracts = {}
    elif profile_path is None and resolved_environment_sha256 is None:
        raise CandidateRuntimeError(
            "native runtime requires one exact resolved external environment"
        )
    elif profile_path is not None:
        try:
            profile_set = load_machine_import_profile_set([profile_path])
        except MachineImportProfileError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        selected_contracts = profile_set.by_identity()
    else:
        selected_contracts = {}

    bindings: dict[tuple[str, str, str | int], dict[str, Any]] = {}
    for binding_index, raw_binding in enumerate(
        _required_list(native_plan.get("import_bindings", []), "module-runtime import bindings")
    ):
        binding = _required_object(
            raw_binding, f"module-runtime import binding {binding_index}"
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
            raise CandidateRuntimeError(
                "module-runtime import bindings are duplicate or use RVA zero"
            )
        bindings[identity] = dict(binding)

    loader_targets, loader_target_indexes = loader_target_catalog(
        guest_dispatch_domains
    )
    loader_targets_by_sha256 = {
        digest: loader_targets[index - 1]
        for digest, index in loader_target_indexes.items()
    }
    interface_targets, interface_target_indexes = interface_method_target_catalog(
        guest_dispatch_domains
    )
    if len(interface_targets) >= INTERFACE_METHOD_TARGET_TAG:
        raise CandidateRuntimeError("runtime interface-method catalog is too large")
    interface_targets_by_sha256 = {
        digest: interface_targets[index - 1]
        for digest, index in interface_target_indexes.items()
    }
    _interface_classes, interface_class_indexes = interface_class_catalog(
        guest_dispatch_domains
    )
    interface_classes_by_id: dict[str, list[int]] = {}
    for (_profile_sha256, interface_id), class_index in (
        interface_class_indexes.items()
    ):
        interface_classes_by_id.setdefault(interface_id, []).append(class_index)

    expanded_sites: list[
        tuple[
            dict[str, Any], int | None, int | None,
            dict[str, Any], int, str,
        ]
    ] = []
    authorized_sites: set[int] = set()
    blocked_sites: list[dict[str, Any]] = []
    dispatch_receipt = _required_object(
        native_plan.get("implementation_dispatch_receipt"),
        "module-runtime implementation dispatch receipt",
    )
    dispatch_reachability = _required_object(
        dispatch_receipt.get("reachability"),
        "module-runtime implementation reachability",
    )
    if dispatch_reachability.get("status") != "complete":
        raise CandidateRuntimeError(
            "native runtime requires complete implementation reachability"
        )

    def block_site(
        *, site_index: int, site: Mapping[str, Any], category: str, detail: str
    ) -> None:
        del site_index, site, category
        raise CandidateRuntimeError(detail)

    parsed_targets: dict[
        tuple[str, str],
        tuple[int | None, int | None, dict[str, Any], int, str],
    ] = {}
    for site_index, site, target_id, target_body in (
        inventory.iter_site_targets()
    ):
        site_kind = _required_string(
            site.get("site_kind"),
            f"module-runtime external site {site_index} kind",
        )
        cache_key = (target_id, site_kind)
        cached = parsed_targets.get(cache_key)
        if cached is not None:
            expanded_sites.append((dict(site), *cached))
            authorized_sites.add(_required_u32(
                site.get("instruction_rva"), "external site RVA"
            ))
            continue
        raw_contract = target_body.get("checked_external_contract")
        resolution = target_body.get("target_resolution_evidence")
        if not isinstance(raw_contract, Mapping):
            has_outer_identity = isinstance(target_body.get("import"), Mapping)
            block_site(
                site_index=site_index,
                site=site,
                category=(
                    "checked_external_contract_missing"
                    if has_outer_identity
                    else "uncontracted_dynamic_external_target"
                ),
                detail=(
                    f"module-runtime external site {site_index} has no checked "
                    + (
                        "external contract"
                        if has_outer_identity
                        else "import, interface, or callable target identity"
                    )
                ),
            )
            continue
        if not isinstance(resolution, Mapping):
            block_site(
                site_index=site_index,
                site=site,
                category="canonical_external_site_missing",
                detail=(
                    f"module-runtime external site {site_index} has no exact "
                    "target-resolution evidence"
                ),
            )
            continue
        resolution_kind = resolution.get("kind")
        if resolution_kind == "resolved-external-environment-v1":
            if (
                resolved_environment_sha256 is None
                or resolution.get("sha256") != resolved_environment_sha256
            ):
                raise CandidateRuntimeError(
                    f"module-runtime external site {site_index} binds a "
                    "different resolved external environment"
                )
        elif resolution_kind != "canonical-external-sites-v3":
            raise CandidateRuntimeError(
                f"module-runtime external site {site_index} uses an "
                "unsupported target-resolution authority"
            )
        try:
            checked = parse_checked_external_site_contract(
                raw_contract,
                context=f"module-runtime external site {site_index}",
            )
        except CheckedExternalSiteContractError as exc:
            raise CandidateRuntimeError(str(exc)) from exc

        imported_site = target_body.get("import")
        if isinstance(imported_site, Mapping):
            try:
                outer_identity = ExternalSiteIdentity.imported(
                    imported_site,
                    context=f"module-runtime external site {site_index}",
                )
            except CheckedExternalSiteContractError as exc:
                raise CandidateRuntimeError(str(exc)) from exc
            if checked.identity != outer_identity:
                raise CandidateRuntimeError(
                    f"module-runtime external site {site_index} identity differs from its checked contract"
                )

        target_iat_rva: int | None = None
        target_catalog_index: int | None = None
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
            if resolution_kind == "canonical-external-sites-v3":
                selected = selected_contracts.get(profile_identity)
                if selected is None:
                    raise CandidateRuntimeError(
                        f"module-runtime external site {site_index} has no selected exact profile"
                    )
                if (
                    checked.profile_binding.get("profile_id") != selected.profile_id
                    or checked.profile_binding.get("profile_sha256")
                    != selected.profile_sha256
                ):
                    raise CandidateRuntimeError(
                        f"module-runtime external site {site_index} binds a "
                        "different canonical profile"
                    )
            binding_identity = (
                profile_identity.dll,
                profile_identity.kind,
                profile_identity.value,
            )
            binding = bindings.get(binding_identity)
            if site_kind == "dynamic_target" and binding is not None:
                target_iat_rva = _required_u32(
                    binding.get("iat_rva"), "import binding IAT RVA"
                )
            elif site_kind == "dynamic_target":
                admitted_member_sha256 = resolution.get(
                    "admitted_member_sha256"
                )
                admitted_target = loader_targets_by_sha256.get(
                    admitted_member_sha256
                )
                target_catalog_index = loader_target_indexes.get(
                    admitted_member_sha256
                )
                identity = (
                    admitted_target.get("identity")
                    if admitted_target is not None else None
                )
                if (
                    target_catalog_index is None
                    or not isinstance(identity, Mapping)
                    or str(identity.get("dll", "")).lower()
                    != profile_identity.dll
                    or identity.get("symbol")
                    != (
                        profile_identity.value
                        if profile_identity.kind == "symbol" else None
                    )
                    or identity.get("ordinal")
                    != (
                        profile_identity.value
                        if profile_identity.kind == "ordinal" else None
                    )
                ):
                    raise CandidateRuntimeError(
                        f"module-runtime external site {site_index} has no exact "
                        "IAT or checked loader-catalog binding"
                    )
        elif checked.identity.kind == "interface":
            if site_kind != "dynamic_target":
                raise CandidateRuntimeError(
                    f"module-runtime external site {site_index} has an invalid "
                    "interface dispatch kind"
                )
            admitted_member_sha256 = resolution.get("admitted_member_sha256")
            admitted_target = interface_targets_by_sha256.get(
                admitted_member_sha256
            )
            method = (
                admitted_target.get("method")
                if admitted_target is not None else None
            )
            protocol = method.get("external_protocol") if isinstance(
                method, Mapping
            ) else None
            target_index = interface_target_indexes.get(admitted_member_sha256)
            operation = (
                f"{protocol.get('interface_id')}::{protocol.get('method')}"
                if isinstance(protocol, Mapping) else None
            )
            if (
                target_index is None
                or not isinstance(protocol, Mapping)
                or checked.identity.profile_id != admitted_target.get("profile_id")
                or checked.identity.profile_sha256
                != admitted_target.get("profile_sha256")
                or checked.identity.operation != operation
            ):
                raise CandidateRuntimeError(
                    f"module-runtime external site {site_index} has no exact "
                    "live-interface method binding"
                )
            target_catalog_index = INTERFACE_METHOD_TARGET_TAG | target_index
        else:
            raise CandidateRuntimeError(
                f"module-runtime external site {site_index} has an unsupported "
                "checked identity kind"
            )
        cached = (
            target_iat_rva,
            target_catalog_index,
            checked.profile_effect_payload(),
            checked.argument_base_offset,
            checked.contract_id,
        )
        parsed_targets[cache_key] = cached
        expanded_sites.append((dict(site), *cached))
        authorized_sites.add(
            _required_u32(site.get("instruction_rva"), "external site RVA")
        )

    rules: list[NativeExternalRangeRule] = []
    for (
        site,
        target_iat_rva,
        target_catalog_index,
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
            raise CandidateRuntimeError(
                f"machine-call contract {contract_id} has too many arguments"
            )
        disposition = site.get("disposition")
        if disposition not in {"returns_here", "tail_jump"}:
            raise CandidateRuntimeError(
                f"external site {instruction_rva:#x} has an unsupported disposition"
            )
        # Every checked route gets a zero-effect row.  Runtime capture uses it
        # to select exactly one loader-written IAT target and import the
        # route's physical argument frame even when the contract has no
        # dynamic memory-range effects.
        rules.append(NativeExternalRangeRule(
            instruction_rva=instruction_rva,
            target_iat_rva=target_iat_rva,
            target_catalog_index=target_catalog_index,
            interface_class_index=None,
            action="validate_call",
            argument_base_offset=argument_base_offset,
            argument_count=argument_count,
            register=None,
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
            pointee_offset=0,
            max_elements=0,
            element_unit_bytes=0,
            element_max_units=0,
            contract_id=contract_id,
        ))
        relations = contract.get("result_register_relations", [])
        if not isinstance(relations, list):
            raise CandidateRuntimeError(
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
                raise CandidateRuntimeError(
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
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an invalid terminated range size"
                    )
            else:
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has unsupported range size {kind!r}"
                )
            for size_index in (size_argument, size_right_argument):
                if size_index is not None and size_index >= argument_count:
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} range size argument is out of bounds"
                    )
            minimum_size = _required_count(
                relation.get("minimum_size", 0), "dynamic-range minimum size"
            )
            nullable = relation.get("nullable")
            if not isinstance(nullable, bool):
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has invalid nullability"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    target_catalog_index=target_catalog_index,
                    interface_class_index=None,
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
                raise CandidateRuntimeError(
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
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} gives a shape to a non-pointer word"
                    )
                shape = _required_object(shape, "dynamic-pointer pointee shape")
                if shape.get("kind") != "null_terminated_pointer_vector":
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported pointee shape"
                    )
                pointee_offset = _required_count(
                    word.get("offset"), "dynamic-pointer word offset"
                )
                if pointee_offset % 4 != 0 or pointee_offset + 4 > minimum_size:
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an out-of-range pointer word"
                    )
                max_elements = _required_count(
                    shape.get("max_elements"), "pointer-vector element limit"
                )
                if max_elements == 0 or max_elements > 65536:
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an invalid pointer-vector limit"
                    )
                element = _required_object(
                    shape.get("element"), "pointer-vector element shape"
                )
                if element.get("kind") != "bounded_terminated":
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported vector element shape"
                    )
                element_unit_bytes = _required_count(
                    element.get("unit_bytes"), "terminated-element unit size"
                )
                if element_unit_bytes not in {1, 2, 4}:
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported element unit"
                    )
                sentinel = element.get("sentinel")
                if sentinel != [0] * element_unit_bytes:
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an unsupported element sentinel"
                    )
                element_max_units = _required_count(
                    element.get("max_units"), "terminated-element unit limit"
                )
                if element_max_units == 0 or element_max_units > 1048576:
                    raise CandidateRuntimeError(
                        f"machine-call contract {contract_id} has an invalid element unit limit"
                    )
                rules.append(
                    NativeExternalRangeRule(
                        instruction_rva=instruction_rva,
                        target_iat_rva=target_iat_rva,
                        target_catalog_index=target_catalog_index,
                        interface_class_index=None,
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
            raise CandidateRuntimeError(
                f"machine-call contract {contract_id} has invalid out-pointer relations"
            )
        for out_index, raw_out in enumerate(out_pointer_relations):
            out_relation = _required_object(
                raw_out,
                f"machine-call contract {contract_id} out pointer {out_index}",
            )
            if out_relation.get("relation") != "nullable_dynamic_pointer":
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer relation"
                )
            argument = _required_count(
                out_relation.get("argument"), "out-pointer argument"
            )
            if argument >= argument_count:
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} out-pointer argument is out of bounds"
                )
            pointee_offset = _required_count(
                out_relation.get("offset", 0), "out-pointer offset"
            )
            shape = _required_object(
                out_relation.get("pointee_shape"), "out-pointer pointee shape"
            )
            if shape.get("kind") != "null_terminated_pointer_vector":
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer shape"
                )
            max_elements = _required_count(
                shape.get("max_elements"), "out-pointer vector limit"
            )
            if max_elements == 0 or max_elements > 65536:
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-pointer vector limit"
                )
            element = _required_object(
                shape.get("element"), "out-pointer vector element shape"
            )
            if element.get("kind") != "bounded_terminated":
                raise CandidateRuntimeError(
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
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an unsupported out-pointer sentinel"
                )
            element_max_units = _required_count(
                element.get("max_units"), "out-pointer element unit limit"
            )
            if element_max_units == 0 or element_max_units > 1048576:
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-pointer element limit"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    target_catalog_index=target_catalog_index,
                    interface_class_index=None,
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
            raise CandidateRuntimeError(
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
                raise CandidateRuntimeError(
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
            interface_id = _required_string(
                out_relation.get("interface_id"), "out-interface identity"
            )
            class_matches = interface_classes_by_id.get(interface_id, [])
            if len(class_matches) > 1:
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an ambiguous "
                    "out-interface class"
                )
            interface_class_index = (
                class_matches[0] if class_matches else None
            )
            if (
                out_relation.get("write_width") != 4
                or object_size < 4
                or vtable_size < 4
                or vtable_size % 4 != 0
                or not isinstance(nullable, bool)
                or out_relation.get("success_condition")
                != "hresult_succeeded_eax"
            ):
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} has an invalid out-interface shape"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    target_catalog_index=target_catalog_index,
                    interface_class_index=interface_class_index,
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
                raise CandidateRuntimeError(
                    f"machine-call contract {contract_id} release argument is out of bounds"
                )
            rules.append(
                NativeExternalRangeRule(
                    instruction_rva=instruction_rva,
                    target_iat_rva=target_iat_rva,
                    target_catalog_index=target_catalog_index,
                    interface_class_index=None,
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
                item.target_catalog_index or 0,
                {
                    "validate_call": -1,
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
