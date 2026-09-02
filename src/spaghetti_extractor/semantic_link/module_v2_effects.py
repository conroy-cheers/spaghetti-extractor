"""Effect derivation for linked-semantic-module-v2 construction."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.semantic_object import SemanticObjectV1
from .capabilities import semantic_export_capabilities_v1
from .import_uses import semantic_import_uses_v1
from .module_v2_core import (
    _callable_external_contracts,
    _fail,
    _import_identity_key,
    _mapping,
)

def _checked_no_return_sources(semantic: SemanticObjectV1) -> set[str]:
    environment = semantic.resolved_external_environment
    if environment is None:
        return set()
    no_return: set[tuple[str, str]] = set()
    for raw in environment.payload["machine_import_contracts"]:
        row = _mapping(raw, "machine-import contract")
        identity = _mapping(row.get("identity"), "machine-import identity")
        boundary = row.get("boundary")
        if not isinstance(boundary, Mapping):
            continue
        frame = boundary.get("physical_call_frame_v3")
        if not isinstance(frame, Mapping):
            continue
        transport = frame.get("transport")
        outcomes = (
            transport.get("outcomes") if isinstance(transport, Mapping) else None
        )
        dll = identity.get("dll")
        name = identity.get("symbol")
        if name is None and isinstance(identity.get("ordinal"), int):
            name = f"ordinal:{identity['ordinal']}"
        if (
            outcomes == ["no_return"]
            and isinstance(dll, str) and isinstance(name, str)
        ):
            no_return.add((dll.lower(), name))
    result = set()
    for transfer in semantic.transfer_plan["transfers"]:
        terminator = _mapping(transfer.get("terminator"), "transfer terminator")
        operands = terminator.get("operands")
        if (
            terminator.get("op") != "outcome_fallthrough"
            or not isinstance(operands, list) or len(operands) != 1
        ):
            continue
        calls = [
            _mapping(raw, "transfer call") for raw in transfer.get("calls", [])
        ]
        if not calls:
            continue
        maximum_event = max(
            row.get("event_index", -1)
            for row in calls if isinstance(row.get("event_index"), int)
        )
        matches = []
        for call in calls:
            name = call.get("symbol")
            if name is None and isinstance(call.get("ordinal"), int):
                name = f"ordinal:{call['ordinal']}"
            dll = call.get("dll")
            if (
                call.get("kind") == "external_call"
                and call.get("return_rva") == operands[0]
                and call.get("event_index") == maximum_event
                and isinstance(dll, str) and isinstance(name, str)
                and (dll.lower(), name) in no_return
            ):
                matches.append(call)
        if len(matches) == 1:
            result.add(f"original:function:{transfer['identity']}")
    return result


def _active_objects(
    linked_payload: Mapping[str, Any],
    may_symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    provenance = {
        str(row["symbol_id"]): row for row in may_symbols
    }
    result = []
    for raw in linked_payload["objects"]:
        row = _mapping(raw, "V1 linked object")
        symbol_id = row.get("semantic_symbol_id")
        if symbol_id not in provenance:
            continue
        result.append({
            "object_id": row["id"],
            "semantic_symbol_id": symbol_id,
            "root_ids": list(provenance[str(symbol_id)]["root_ids"]),
            "domain_ids": list(provenance[str(symbol_id)]["domain_ids"]),
        })
    result.sort(key=lambda row: row["object_id"])
    return result


def _runtime_provider_effects_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
    definitions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Bind every active runtime primitive to its qualified platform rule."""

    definition_by_symbol = {
        str(row["symbol_id"]): row for row in definitions
    }
    active_runtime = [
        row for row in active_symbols
        if _mapping(
            row.get("resolution"), "active runtime resolution"
        ).get("kind") == "qualified_platform_primitive"
        and definition_by_symbol.get(str(row["symbol_id"]), {}).get(
            "definition_kind"
        ) == "qualified_platform_primitive"
    ]
    if not active_runtime:
        return []
    platform = semantic.qualified_platform
    if platform is None:
        _fail("runtime-provider effects require a qualified platform")
    catalog: dict[str, Mapping[str, Any]] = {}
    for raw in platform.get("runtime_provider_catalog", []):
        rule = _mapping(raw, "qualified runtime-provider rule")
        provider = rule.get("provider")
        if rule.get("layer") != "transfer_plan":
            continue
        if not isinstance(provider, str) or not provider or provider in catalog:
            _fail("qualified runtime-provider identities are malformed")
        catalog[provider] = rule
    platform_sha256 = _mapping(
        semantic.payload.get("bindings"), "semantic-object bindings"
    ).get("qualified_platform_sha256")
    if not isinstance(platform_sha256, str):
        _fail("semantic object has no qualified-platform binding")
    result = []
    for active in active_runtime:
        resolution = _mapping(
            active.get("resolution"), "active runtime resolution"
        )
        provider = resolution.get("provider_id")
        symbol_id = str(active["symbol_id"])
        definition = definition_by_symbol.get(symbol_id)
        rule = catalog.get(str(provider))
        if (
            not isinstance(provider, str) or not provider
            or rule is None or definition is None
            or definition.get("definition_kind")
            != "qualified_platform_primitive"
            or active.get("definition_id") != definition.get("definition_id")
        ):
            _fail("active runtime primitive has no qualified definition")
        effect = {
            "kind": "qualified_runtime_provider_effect_v2",
            "provider_id": provider,
            "symbol_id": symbol_id,
            "definition_id": definition["definition_id"],
            "qualified_platform_sha256": platform_sha256,
            "provider_contract": dict(rule),
            "provider_contract_sha256": canonical_sha256_v3(dict(rule)),
            "root_ids": list(active["root_ids"]),
            "domain_ids": list(active["domain_ids"]),
        }
        result.append({
            "effect_id": (
                "runtime-provider-effect-v2:"
                + canonical_sha256_v3(effect)
            ),
            **effect,
        })
    return sorted(result, key=lambda row: str(row["effect_id"]))


def _exception_effects_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
    definitions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project every may-active checked exception transition exactly once."""

    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("exception effects require a resolved environment")
    checked_protocols = [
        _mapping(row, "checked exception protocol")
        for row in environment.payload["checked_exception_protocols"]
    ]
    semantic_symbols = {
        str(row["symbol_id"]): _mapping(row, "semantic symbol")
        for raw in semantic.payload["symbols"]
        for row in (_mapping(raw, "semantic symbol"),)
    }
    semantic_definitions = {
        str(row["symbol_id"]): _mapping(row, "semantic definition")
        for raw in semantic.payload["definitions"]
        for row in (_mapping(raw, "semantic definition"),)
    }
    definitions_by_symbol = {
        str(row["symbol_id"]): row for row in definitions
    }
    result = []
    for active in active_symbols:
        resolution = _mapping(
            active.get("resolution"), "active exception resolution"
        )
        if (
            active.get("kind") != "exception_transition"
            or resolution.get("kind") != "semantic_definition"
            or resolution.get("definition_kind")
            != "checked_exception_transition"
        ):
            continue
        symbol_id = str(active["symbol_id"])
        symbol = semantic_symbols.get(symbol_id)
        semantic_definition = semantic_definitions.get(symbol_id)
        definition = definitions_by_symbol.get(symbol_id)
        declaration = symbol.get("declaration") if symbol is not None else None
        logical_type = symbol.get("logical_type") if symbol is not None else None
        transition = (
            semantic_definition.get("transition")
            if semantic_definition is not None else None
        )
        if (
            symbol is None or semantic_definition is None or definition is None
            or not isinstance(declaration, Mapping)
            or not isinstance(logical_type, Mapping)
            or not isinstance(transition, Mapping)
            or semantic_definition.get("definition_kind")
            != "checked_exception_transition"
            or definition.get("definition_kind")
            != "checked_exception_transition"
            or active.get("definition_id") != definition.get("definition_id")
            or declaration.get("transition_id")
            != transition.get("transition_id")
            or declaration.get("transition_sha256")
            != transition.get("transition_sha256")
        ):
            _fail("active exception transition lacks its checked definition")
        occurrence = {
            key: declaration.get(key) for key in (
                "unit_id", "source_rva", "occurrence_kind", "effect_index",
                "call_index", "fault_index", "fault_sha256", "operation",
            )
        }
        matching_protocols = [
            protocol for protocol in checked_protocols
            if protocol.get("occurrence") == occurrence
            and protocol.get("state_projection")
            == transition.get("state_projection")
        ]
        if len(matching_protocols) > 1:
            _fail("active exception transition has ambiguous checked protocols")
        protocol = matching_protocols[0] if matching_protocols else None
        handler = None if protocol is None else protocol.get("handler")
        resumption = None if protocol is None else protocol.get("resumption")
        if handler is not None and not isinstance(handler, Mapping):
            _fail("checked exception handler is malformed")
        if resumption is not None and not isinstance(resumption, Mapping):
            _fail("checked exception resumption is malformed")
        if protocol is not None:
            expected_handler = (
                (None, None) if handler is None
                else (handler.get("unit_id"), handler.get("rva"))
            )
            expected_resumption = (
                (None, None) if resumption is None
                else (resumption.get("unit_id"), resumption.get("rva"))
            )
            if (
                (
                    declaration.get("handler_unit_id"),
                    declaration.get("handler_rva"),
                ) != expected_handler
                or (
                    declaration.get("resumption_unit_id"),
                    declaration.get("resumption_rva"),
                ) != expected_resumption
                or declaration.get("unwind_unit_ids")
                != protocol.get("unwind_unit_ids")
            ):
                _fail("checked exception protocol disagrees with transition")
            routing_authority = {
                "kind": "checked_exception_protocol_v1",
                "protocol_id": protocol["protocol_id"],
                "protocol_sha256": protocol["protocol_sha256"],
            }
        elif transition.get("disposition") == "terminates":
            if (
                declaration.get("handler_unit_id") is not None
                or declaration.get("resumption_unit_id") is not None
                or declaration.get("unwind_unit_ids") != []
                or transition.get("state_projection") is not None
            ):
                _fail("launch-policy exception termination has guest routing state")
            routing_authority = {
                "kind": "launch_policy",
                "launch_policy_payload_sha256": environment.payload[
                    "launch_policy"
                ]["payload_sha256"],
            }
        elif transition.get("disposition") == "infeasible":
            if (
                declaration.get("handler_unit_id") is not None
                or declaration.get("resumption_unit_id") is not None
                or declaration.get("unwind_unit_ids") != []
                or transition.get("state_projection") is not None
            ):
                _fail("infeasible exception transition has guest routing state")
            routing_authority = {
                "kind": "transfer_static_infeasibility",
                "transition_sha256": transition["transition_sha256"],
            }
        else:
            _fail("active exception transition has no checked routing authority")
        enriched_transition = {
            **dict(transition),
            "routing_authority": routing_authority,
            "handler_unit_id": (
                None if handler is None else handler["unit_id"]
            ),
            "handler_rva": None if handler is None else handler["rva"],
            "resumption_unit_id": (
                None if resumption is None else resumption["unit_id"]
            ),
            "resumption_rva": (
                None if resumption is None else resumption["rva"]
            ),
            "unwind_unit_ids": (
                [] if protocol is None
                else list(protocol["unwind_unit_ids"])
            ),
        }
        effect = {
            "kind": "checked_exception_transition_effect_v2",
            "symbol_id": symbol_id,
            "definition_id": definition["definition_id"],
            "occurrence": occurrence,
            "transition": enriched_transition,
            "native_exception": dict(logical_type),
            "root_ids": list(active["root_ids"]),
            "domain_ids": list(active["domain_ids"]),
        }
        result.append({
            "effect_id": (
                "exception-transition-effect-v2:"
                + canonical_sha256_v3(effect)
            ),
            **effect,
        })
    return sorted(result, key=lambda row: str(row["effect_id"]))


def _lifecycle_effects_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Inventory all may-active calls with a checked no-return outcome."""

    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("lifecycle effects require a resolved environment")
    no_return: dict[tuple[str, str], Mapping[str, Any]] = {}
    for raw in environment.payload["machine_import_contracts"]:
        contract = _mapping(raw, "machine-import contract")
        identity = _mapping(contract.get("identity"), "machine-import identity")
        key = _import_identity_key(identity)
        boundary = contract.get("boundary")
        frame = (
            boundary.get("physical_call_frame_v3")
            if isinstance(boundary, Mapping) else None
        )
        transport = frame.get("transport") if isinstance(frame, Mapping) else None
        outcomes = (
            transport.get("outcomes") if isinstance(transport, Mapping) else None
        )
        if key is None or outcomes != ["no_return"]:
            continue
        if key in no_return:
            _fail("no-return external identities are duplicated")
        no_return[key] = contract
    active_transfer = {
        str(row["symbol_id"]).removeprefix("original:function:"): row
        for row in active_symbols
        if str(row.get("symbol_id", "")).startswith("original:function:")
    }
    external_symbol_by_contract: dict[str, str] = {}
    for row in active_symbols:
        if row.get("kind") != "external_function":
            continue
        contract_sha256 = _mapping(
            row.get("resolution"), "external resolution"
        ).get("contract_sha256")
        if not isinstance(contract_sha256, str):
            continue
        if contract_sha256 in external_symbol_by_contract:
            _fail("active external contracts resolve to duplicate symbols")
        external_symbol_by_contract[contract_sha256] = str(row["symbol_id"])
    result = []
    for raw_transfer in semantic.transfer_plan["transfers"]:
        transfer = _mapping(raw_transfer, "transfer")
        transfer_id = str(transfer.get("identity"))
        active = active_transfer.get(transfer_id)
        if active is None:
            continue
        for raw_call in transfer.get("calls", []):
            call = _mapping(raw_call, "transfer call")
            if call.get("kind") != "external_call":
                continue
            identity = {
                key: call.get(key) for key in ("dll", "symbol", "ordinal")
            }
            key = _import_identity_key(identity)
            contract = no_return.get(key) if key is not None else None
            if contract is None:
                continue
            boundary = _mapping(contract.get("boundary"), "external boundary")
            frame = _mapping(
                boundary.get("physical_call_frame_v3"), "external frame"
            )
            contract_sha256 = canonical_sha256_v3(dict(contract))
            target_symbol_id = external_symbol_by_contract.get(
                contract_sha256
            )
            if target_symbol_id is None:
                _fail("no-return call has no active external definition")
            effect = {
                "kind": "checked_external_no_return_effect_v2",
                "source_symbol_id": f"original:function:{transfer_id}",
                "source_transfer_id": transfer_id,
                "target_symbol_id": target_symbol_id,
                "call_id": call.get("id"),
                "instruction_rva": call.get("instruction_rva"),
                "external_identity": identity,
                "external_contract_sha256": contract_sha256,
                "physical_frame_id": frame.get("id"),
                "physical_frame_sha256": canonical_sha256_v3(dict(frame)),
                "allowed_outcome": "no_return",
                "root_ids": list(active["root_ids"]),
                "domain_ids": list(active["domain_ids"]),
            }
            result.append({
                "effect_id": (
                    "external-no-return-effect-v2:"
                    + canonical_sha256_v3(effect)
                ),
                **effect,
            })
    return sorted(result, key=lambda row: str(row["effect_id"]))


def _nonlocal_effects_and_holes_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
]:
    """Derive checked finite nonlocal routes from transfer-v2 call structure."""

    active_by_transfer = {
        str(row["symbol_id"]).removeprefix("original:function:"): row
        for row in active_symbols
        if str(row.get("symbol_id", "")).startswith("original:function:")
    }
    transfers = {
        str(row["identity"]): _mapping(row, "transfer")
        for row in semantic.transfer_plan["transfers"]
    }
    transfer_by_rva = {
        int(_mapping(row["source"], "transfer source")["rva_start"]): row
        for row in transfers.values()
    }
    effects = []
    obligations = []
    holes = []
    for transfer_id, transfer in transfers.items():
        source_active = active_by_transfer.get(transfer_id)
        if source_active is None:
            continue
        terminator = _mapping(
            transfer.get("terminator"), "transfer terminator"
        )
        if terminator.get("op") != "outcome_nonlocal":
            continue
        operands = terminator.get("operands")
        expressions = {
            int(row["id"]): _mapping(row, "transfer expression")
            for row in transfer.get("expressions", [])
        }
        target_expression = (
            expressions.get(operands[0])
            if isinstance(operands, list) and len(operands) == 2
            and isinstance(operands[0], int)
            and not isinstance(operands[0], bool)
            else None
        )
        target_parameters = (
            target_expression.get("parameters")
            if isinstance(target_expression, Mapping) else None
        )
        target_rva = (
            target_parameters.get("immediate")
            if target_expression is not None
            and target_expression.get("op") == "const"
            and target_expression.get("width_bits") == 32
            and isinstance(target_parameters, Mapping)
            else None
        )
        source_rva = int(_mapping(
            transfer.get("source"), "transfer source"
        )["rva_start"])
        target_transfer = (
            transfer_by_rva.get(target_rva)
            if isinstance(target_rva, int) and not isinstance(target_rva, bool)
            else None
        )
        callers = []
        if target_transfer is not None:
            for caller_id, caller in transfers.items():
                if caller_id not in active_by_transfer:
                    continue
                for raw_call in caller.get("calls", []):
                    call = _mapping(raw_call, "transfer call")
                    if (
                        call.get("kind") == "internal_call"
                        and call.get("target_rva") == source_rva
                        and call.get("return_rva") == target_rva
                    ):
                        callers.append((caller_id, caller, call))
        if (
            target_transfer is None
            or str(target_transfer["identity"]) not in active_by_transfer
            or len(callers) != 1
        ):
            evidence = {
                "code": "checked_nonlocal_protocol_v2_missing",
                "transfer_id": transfer_id,
                "source_rva": source_rva,
                "terminator": dict(terminator),
                "constant_target_rva": target_rva,
                "matching_active_callers": len(callers),
            }
            evidence_sha256 = canonical_sha256_v3(evidence)
            core = {
                "code": str(evidence["code"]),
                "subject": f"nonlocal-outcome:{evidence_sha256}",
                "evidence_sha256": evidence_sha256,
            }
            holes.append({
                "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(core)}",
                **core,
            })
            continue

        caller_id, caller, call = callers[0]
        caller_rva = int(_mapping(
            caller.get("source"), "caller transfer source"
        )["rva_start"])
        target_id = str(target_transfer["identity"])
        contract = {
            "kind": "checked_nonlocal_outcome_protocol_v2",
            "source_transfer_id": transfer_id,
            "source_rva": source_rva,
            "target_transfer_id": target_id,
            "target_rva": target_rva,
            "target_function_entry_transfer_id": caller_id,
            "target_function_entry_rva": caller_rva,
            "call_id": call.get("id"),
            "value_expression_id": operands[1],
            "cleanup": {
                "kind": "expire_abandoned_ingress_and_call_frames",
                "generation": "current_thread_invocation",
            },
        }
        subject = f"{transfer_id}:nonlocal"
        admitted_domain = {
            "kind": "checked_nonlocal_ancestor_route_v2",
            "source_rva": source_rva,
            "target_rva": target_rva,
            "target_function_entry_rva": caller_rva,
        }
        obligation_core = {
            "class": "checked_exceptions_outcomes",
            "subjects": [subject],
            "semantic_contract_sha256": canonical_sha256_v3(contract),
            "admitted_domain": admitted_domain,
            "evidence_dependencies": [
                "executable-transfer-plan-v2:"
                + str(semantic.transfer_plan["plan_sha256"]),
            ],
            "allowed_provider_kinds": ["qualified_runtime"],
        }
        obligation = {
            "obligation_id": (
                "residual-obligation-v2:"
                + canonical_sha256_v3(obligation_core)
            ),
            **obligation_core,
        }
        effect = {
            **contract,
            "source_symbol_id": f"original:function:{transfer_id}",
            "target_symbol_id": f"original:function:{target_id}",
            "target_function_entry_symbol_id": (
                f"original:function:{caller_id}"
            ),
            "obligation_id": obligation["obligation_id"],
            "root_ids": list(source_active["root_ids"]),
            "domain_ids": list(source_active["domain_ids"]),
        }
        effects.append({
            "effect_id": (
                "checked-nonlocal-transition-v2:"
                + canonical_sha256_v3(effect)
            ),
            **effect,
        })
        obligations.append(obligation)
    return (
        sorted(effects, key=lambda row: str(row["effect_id"])),
        sorted(obligations, key=lambda row: str(row["obligation_id"])),
        sorted(holes, key=lambda row: str(row["hole_id"])),
    )


def _export_capability_effects_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rebind the deterministic checked-EAT projection to V2 identities."""

    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("export capabilities require a resolved environment")
    projected_symbols = [
        {**dict(row), "reachable": True} for row in active_symbols
    ]
    provisional, blockers = semantic_export_capabilities_v1(
        module_interface=semantic.module_interface,
        resolved_environment=environment.payload,
        symbols=projected_symbols,
    )
    active_by_symbol = {
        str(row["symbol_id"]): row for row in active_symbols
    }
    effects = []
    for raw in provisional:
        row = dict(_mapping(raw, "checked export capability"))
        row.pop("capability_id", None)
        target_symbol = row.pop("target_symbol", None)
        target = active_by_symbol.get(str(target_symbol))
        frame = row.pop("physical_frame", None)
        if target is None or not isinstance(frame, Mapping):
            _fail("checked export capability target is not may active")
        effect = {
            "kind": "checked_export_capability_effect_v2",
            "logical_image_id": row["logical_image_id"],
            "target_rva": row["target_rva"],
            "target_symbol_id": target_symbol,
            "exports": row["exports"],
            "boundary_subject_id": row["boundary_subject_id"],
            "checked_call_protocol_id": row["checked_call_protocol_id"],
            "physical_frame_id": row["physical_frame_id"],
            "physical_frame_sha256": canonical_sha256_v3(dict(frame)),
            "physical_frame": dict(frame),
            "root_ids": list(target["root_ids"]),
            "domain_ids": list(target["domain_ids"]),
        }
        effects.append({
            "effect_id": (
                "export-capability-effect-v2:"
                + canonical_sha256_v3(effect)
            ),
            **effect,
        })
    holes = []
    for raw in blockers:
        blocker = dict(_mapping(raw, "export capability blocker"))
        evidence_sha256 = canonical_sha256_v3(blocker)
        core = {
            "code": str(blocker.get(
                "code", "checked_export_capability_unresolved"
            )),
            "subject": f"export-capability:{evidence_sha256}",
            "evidence_sha256": evidence_sha256,
        }
        holes.append({
            "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(core)}",
            **core,
        })
    return (
        sorted(effects, key=lambda row: str(row["effect_id"])),
        sorted(holes, key=lambda row: str(row["hole_id"])),
    )


def _external_contract_effects_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Project every may-active checked external definition exactly once."""

    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("external effects require a resolved environment")
    contracts_by_sha256: dict[str, Mapping[str, Any]] = {}
    for raw in _callable_external_contracts(environment.payload):
        contract = _mapping(raw, "resolved machine-import contract")
        digest = canonical_sha256_v3(dict(contract))
        if digest in contracts_by_sha256:
            _fail("resolved external contracts duplicate content identities")
        contracts_by_sha256[digest] = contract
    semantic_symbols = {
        str(row["symbol_id"]): _mapping(row, "semantic symbol")
        for raw in semantic.payload["symbols"]
        for row in (_mapping(raw, "semantic symbol"),)
    }
    result: list[dict[str, Any]] = []
    for active in active_symbols:
        resolution = _mapping(
            active.get("resolution"), "active external resolution"
        )
        if resolution.get("kind") != "checked_external_contract":
            continue
        symbol_id = str(active["symbol_id"])
        symbol = semantic_symbols.get(symbol_id)
        declaration = (
            symbol.get("declaration") if symbol is not None else None
        )
        frame = symbol.get("physical_frame") if symbol is not None else None
        contract_sha256 = (
            declaration.get("environment_contract_sha256")
            if isinstance(declaration, Mapping) else None
        )
        contract = contracts_by_sha256.get(str(contract_sha256))
        identity = contract.get("identity") if contract is not None else None
        contract_binding = (
            contract.get("contract") if contract is not None else None
        )
        contract_payload = (
            contract_binding.get("payload")
            if isinstance(contract_binding, Mapping) else None
        )
        external_service_protocol = (
            contract_payload.get("external_service_protocol")
            if isinstance(contract_payload, Mapping) else None
        )
        semantic_role = (
            "external_function"
            if symbol is not None and symbol.get("kind") == "external_function"
            else "loader_import_slot"
            if symbol is not None
            and symbol.get("kind") == "unclassified_import"
            and symbol.get("storage_class") == "iat_slot"
            else None
        )
        if (
            symbol is None or semantic_role is None
            or not isinstance(declaration, Mapping)
            or declaration.get("declaration_role") not in {
                "machine_import", "loader_service",
            }
            or not isinstance(contract_sha256, str)
            or contract is None
            or not isinstance(identity, Mapping)
            or _import_identity_key(identity) is None
            or semantic_role == "external_function"
            and not isinstance(frame, Mapping)
            or semantic_role == "loader_import_slot" and frame is not None
            or resolution.get("contract_sha256") != contract_sha256
        ):
            _fail("active external definition lacks its checked contract")
        effect = {
            "kind": "checked_external_contract_effect_v2",
            "symbol_id": symbol_id,
            "definition_id": active.get("definition_id"),
            "semantic_role": semantic_role,
            "declaration_role": declaration.get("declaration_role"),
            "identity": dict(identity),
            "contract_sha256": contract_sha256,
            "physical_frame_id": (
                frame.get("id") if isinstance(frame, Mapping) else None
            ),
            "physical_frame_sha256": (
                canonical_sha256_v3(dict(frame))
                if isinstance(frame, Mapping) else None
            ),
            "allowed_outcomes": (
                list(frame["transport"].get("outcomes", []))
                if isinstance(frame, Mapping)
                and isinstance(frame.get("transport"), Mapping)
                else [] if isinstance(frame, Mapping) else None
            ),
            "external_service_protocol": (
                dict(external_service_protocol)
                if isinstance(external_service_protocol, Mapping) else None
            ),
            "root_ids": list(active["root_ids"]),
            "domain_ids": list(active["domain_ids"]),
        }
        result.append({
            "effect_id": (
                "external-contract-effect-v2:"
                + canonical_sha256_v3(effect)
            ),
            **effect,
        })
    return sorted(result, key=lambda row: str(row["effect_id"]))


def external_service_obligations_v2(
    *, semantic: SemanticObjectV1,
    external_contract_effects: Sequence[Mapping[str, Any]],
    import_use_effects: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Turn checked service transduction into explicit runtime obligations.

    The external-environment provider still owns the loader callable.  A
    service protocol additionally requires the shared runtime to translate
    guest control or nested exception objects.  Keeping this as a residual
    obligation prevents a checked ABI from falsely claiming native support.
    """

    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("external service obligations require a resolved environment")
    effects = {
        str(row.get("contract_sha256")): row
        for row in external_contract_effects
        if row.get("semantic_role") == "external_function"
        and isinstance(row.get("external_service_protocol"), Mapping)
    }
    grouped_sites: dict[str, list[dict[str, Any]]] = {
        digest: [] for digest in effects
    }
    for raw_use in import_use_effects:
        use = _mapping(raw_use, "external-service import use")
        digest = str(use.get("external_contract_sha256"))
        if digest not in grouped_sites or use.get("use_kind") != "code":
            continue
        for raw_site in use.get("sites", []):
            site = dict(_mapping(raw_site, "external-service call site"))
            grouped_sites[digest].append(site)
    result: list[dict[str, Any]] = []
    for digest, effect in sorted(effects.items()):
        sites = sorted(grouped_sites[digest], key=canonical_sha256_v3)
        if not sites:
            # A callable may be admitted by a dynamic domain without a direct
            # call site.  Its runtime obligation is activated when the symbol
            # is active, so do not silently omit it.
            sites = [{
                "kind": "admitted_external_callable",
                "symbol_id": effect.get("symbol_id"),
                "root_ids": list(effect.get("root_ids", [])),
                "domain_ids": list(effect.get("domain_ids", [])),
            }]
        protocol = dict(_mapping(
            effect.get("external_service_protocol"),
            "external service protocol",
        ))
        protocol_kind = str(protocol.get("kind"))
        obligation_class = {
            "nonlocal_unwind": "checked_external_nonlocal_service",
            "unhandled_exception_filter": (
                "checked_external_exception_object_service"
            ),
        }.get(protocol_kind)
        if obligation_class is None:
            _fail("checked external service kind is unsupported")
        subjects = sorted({
            "external-service-site:" + canonical_sha256_v3(site)
            for site in sites
        })
        admitted_domain = {
            "kind": "checked_external_service_protocol_v1",
            "identity": dict(_mapping(
                effect.get("identity"), "external service identity"
            )),
            "contract_sha256": digest,
            "protocol": protocol,
            "sites": sites,
        }
        core = {
            "class": obligation_class,
            "subjects": subjects,
            "semantic_contract_sha256": canonical_sha256_v3({
                "external_contract_effect": dict(effect),
                "admitted_domain": admitted_domain,
            }),
            "admitted_domain": admitted_domain,
            "evidence_dependencies": [
                "executable-transfer-plan-v2:"
                + str(semantic.transfer_plan["plan_sha256"]),
                "resolved-external-environment-v1:" + environment.identity,
            ],
            "allowed_provider_kinds": ["qualified_runtime"],
        }
        result.append({
            "obligation_id": (
                "residual-obligation-v2:" + canonical_sha256_v3(core)
            ),
            **core,
        })
    return sorted(result, key=lambda row: str(row["obligation_id"]))


def _import_use_effects_v2(
    *, semantic: SemanticObjectV1,
    active_symbols: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rebind the one exact transfer-v2 IAT projection to V2 provenance."""

    environment = semantic.resolved_external_environment
    if environment is None:
        _fail("import-use effects require a resolved environment")
    active_by_symbol = {
        str(row["symbol_id"]): row for row in active_symbols
    }
    active_transfer_by_id = {
        symbol_id.removeprefix("original:function:"): row
        for symbol_id, row in active_by_symbol.items()
        if symbol_id.startswith("original:function:")
    }
    provisional_roots = {
        transfer_id: {f"may-active:{transfer_id}"}
        for transfer_id in active_transfer_by_id
    }
    provisional, blockers = semantic_import_uses_v1(
        semantic=semantic,
        resolved_environment=environment.payload,
        roots_by_unit=provisional_roots,
    )
    semantic_symbols = {
        str(row["symbol_id"]): _mapping(row, "semantic symbol")
        for raw in semantic.payload["symbols"]
        for row in (_mapping(raw, "semantic symbol"),)
    }
    slot_by_id: dict[str, tuple[str, Mapping[str, Any]]] = {}
    callable_by_contract: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for symbol_id, active in active_by_symbol.items():
        symbol = semantic_symbols.get(symbol_id)
        declaration = symbol.get("declaration") if symbol is not None else None
        if not isinstance(declaration, Mapping):
            continue
        slot_id = declaration.get("slot_id")
        if isinstance(slot_id, str) and slot_id:
            if slot_id in slot_by_id:
                _fail("active loader import-slot identity is duplicated")
            slot_by_id[slot_id] = symbol_id, active
        contract_sha256 = declaration.get("environment_contract_sha256")
        if (
            symbol is not None and symbol.get("kind") == "external_function"
            and isinstance(contract_sha256, str)
        ):
            if contract_sha256 in callable_by_contract:
                _fail("active external callable contract is duplicated")
            callable_by_contract[contract_sha256] = symbol_id, active

    result: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []
    for raw in provisional:
        row = _mapping(raw, "provisional import-use effect")
        slot = slot_by_id.get(str(row.get("slot_id")))
        if slot is None:
            _fail("may-active import use has no loader slot definition")
        slot_symbol_id, slot_active = slot
        slot_resolution = _mapping(
            slot_active.get("resolution"), "loader slot resolution"
        )
        contract_sha256 = slot_resolution.get("contract_sha256")
        callable_entry = callable_by_contract.get(str(contract_sha256))
        use_kind = row.get("use_kind")
        callable_symbol_id = (
            callable_entry[0] if callable_entry is not None else None
        )
        callable_active = (
            callable_entry[1] if callable_entry is not None else None
        )
        sites = []
        for raw_site in row.get("sites", []):
            site = dict(_mapping(raw_site, "provisional import-use site"))
            transfer_id = str(site.get("transfer_id"))
            source = active_transfer_by_id.get(transfer_id)
            if source is None:
                _fail("import-use site source is not may active")
            site.pop("root_ids", None)
            site.update({
                "source_symbol_id": f"original:function:{transfer_id}",
                "root_ids": list(source["root_ids"]),
                "domain_ids": list(source["domain_ids"]),
            })
            sites.append(site)
        sites.sort(key=canonical_sha256_v3)
        if not sites:
            _fail("may-active import use has no sites")
        frame = row.get("importer_physical_frame")
        code_sites = [site for site in sites if site.get("kind") == "code_call"]
        if code_sites and (
            callable_entry is None or not isinstance(frame, Mapping)
        ):
            for site in code_sites:
                subject = _import_code_use_subject(
                    source_symbol_id=str(site["source_symbol_id"]),
                    call_id=int(site["call_id"]),
                    instruction_rva=int(site["instruction_rva"]),
                )
                evidence_sha256 = canonical_sha256_v3({
                    "slot_id": row.get("slot_id"),
                    "identity": row.get("identity"),
                    "site": site,
                })
                core = {
                    "code": "checked_import_code_contract_unresolved",
                    "subject": subject,
                    "evidence_sha256": evidence_sha256,
                }
                holes.append({
                    "hole_id": (
                        "semantic-hole-v2:" + canonical_sha256_v3(core)
                    ),
                    **core,
                })
            # Preserve the loader slot and every site as semantic evidence, but
            # do not emit a checked effect without a checked callable contract.
            continue
        root_ids = sorted({
            item for site in sites for item in site["root_ids"]
        })
        domain_ids = sorted({
            item for site in sites for item in site["domain_ids"]
        })
        effect = {
            "kind": "checked_import_use_effect_v2",
            "logical_image_id": row.get("logical_image_id"),
            "slot_id": row.get("slot_id"),
            "import_kind": row.get("import_kind"),
            "iat_rva": row.get("iat_rva"),
            "identity": dict(_mapping(
                row.get("identity"), "import-use identity"
            )),
            "use_kind": use_kind,
            "loader_slot_symbol_id": slot_symbol_id,
            "loader_slot_definition_id": slot_active.get("definition_id"),
            "callable_symbol_id": callable_symbol_id,
            "callable_definition_id": (
                callable_active.get("definition_id")
                if callable_active is not None else None
            ),
            "external_contract_sha256": contract_sha256,
            "importer_physical_frame_id": (
                frame.get("id") if isinstance(frame, Mapping) else None
            ),
            "importer_physical_frame_sha256": (
                canonical_sha256_v3(dict(frame))
                if isinstance(frame, Mapping) else None
            ),
            "required_permissions": row.get("required_permissions"),
            "minimum_extent": row.get("minimum_extent"),
            "sites": sites,
            "root_ids": root_ids,
            "domain_ids": domain_ids,
        }
        result.append({
            "effect_id": (
                "import-use-effect-v2:" + canonical_sha256_v3(effect)
            ),
            **effect,
        })
    for raw in blockers:
        blocker = dict(_mapping(raw, "may-active import-use blocker"))
        evidence_sha256 = canonical_sha256_v3(blocker)
        core = {
            "code": str(blocker.get("code", "import_use_unresolved")),
            "subject": f"import-use-analysis:{evidence_sha256}",
            "evidence_sha256": evidence_sha256,
        }
        holes.append({
            "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(core)}",
            **core,
        })
    return (
        sorted(result, key=lambda row: str(row["effect_id"])),
        sorted(holes, key=lambda row: str(row["hole_id"])),
    )


def _import_code_use_subject(
    *, source_symbol_id: str, call_id: int, instruction_rva: int,
) -> str:
    """Return the exact site identity shared by import holes and validation."""

    return "import-code-use:" + canonical_sha256_v3({
        "source_symbol_id": source_symbol_id,
        "call_id": call_id,
        "instruction_rva": instruction_rva,
    })
