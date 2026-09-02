"""Derivation of checked native ingress authorities from existing evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    BOUNDARY_LIFECYCLE_V1_FORMAT,
    BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
    CHECKED_CALL_PROTOCOL_V2_FORMAT,
    PHYSICAL_CALL_FRAME_V3_FORMAT,
)
from ..calls.frame import PhysicalCallFrameV2
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..transfer.closure import validate_module_execution_closure_v1
from ..transfer.model import TransferPlanError
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.operations import EFFECT_OPERATIONS_V2
from ..util import sha256_file
from .native_ingress_errors import NativeIngressError
from .native_ingress_runtime_model import (
    boundary_lifecycle_transducer_v1,
    physical_frame_transducer_v1,
)
from .outcomes import (
    CheckedBoundaryOutcomeProtocolV1,
    CheckedSEHProtocolV1,
    PinnedCodeLayoutAuthorityV2,
)


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeIngressError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise NativeIngressError(f"{label} must be an object")
    return value


def _derive_ingress_authorities(
    *,
    interface: Mapping[str, Any],
    roots: Mapping[str, Any],
    transfer_plan: Path,
    execution_closure: Path | Mapping[str, Any],
    resolved_external_environment: Path,
    pinned_layout_authorities: Sequence[PinnedCodeLayoutAuthorityV2] = (),
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, Any]],
    dict[str, list[dict[str, Any]]],
]:
    """Derive native entries from loader roots and already checked authorities.

    The two loader-owned PE32 frames are reviewed profiles.  All callable
    exports and callbacks must arrive through the ordinary call-protocol
    checker; there is deliberately no operator-authored ingress JSON escape.
    """

    try:
        transfer_payload, _transfers = load_executable_transfer_plan(
            Path(transfer_plan), require_complete=True
        )
        if isinstance(execution_closure, Mapping):
            closure = dict(execution_closure)
        else:
            closure = dict(_object(
                Path(execution_closure), "module execution closure"
            ))
            validate_module_execution_closure_v1(closure)
    except TransferPlanError as exc:
        raise NativeIngressError(
            f"cannot load canonical execution authority: {exc}"
        ) from exc

    transfer_file_sha256 = sha256_file(Path(transfer_plan))
    closure_binding = closure["bindings"].get(
        "executable_transfer_plan_sha256"
    )
    if closure_binding != transfer_file_sha256:
        raise NativeIngressError(
            "module execution closure does not bind the exact executable transfer plan"
        )
    environment_path = Path(resolved_external_environment)
    environment = _object(environment_path, "resolved external environment")
    if environment.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT:
        raise NativeIngressError(
            "resolved external environment has an unsupported format"
        )
    environment_core = {
        key: value for key, value in environment.items()
        if key != "resolved_environment_sha256"
    }
    if environment.get("resolved_environment_sha256") != canonical_sha256_v3(
        environment_core
    ):
        raise NativeIngressError("resolved external environment is stale")
    if closure["bindings"].get("resolved_external_environment_sha256") != (
        sha256_file(environment_path)
    ):
        raise NativeIngressError(
            "module execution closure does not bind the exact resolved external environment"
        )
    closure_sha256 = str(
        closure.get("source_execution_closure_sha256")
        or closure.get("closure_sha256")
        or closure.get("linked_semantic_module_sha256")
    )
    if len(closure_sha256) != 64:
        raise NativeIngressError("execution semantics identity is malformed")
    units: dict[int, str] = {
        int(row["source"]["rva_start"]): str(row["identity"])
        for row in transfer_payload["transfers"]
    }
    reachable_units: dict[int, str] = {
        int(row["rva"]): str(row["unit_id"])
        for row in closure["reachable_units"]
    }
    if any(units.get(rva) != unit_id for rva, unit_id in reachable_units.items()):
        raise NativeIngressError(
            "module execution closure unit identities contradict the transfer plan"
        )
    transfers_by_identity = {
        str(row["identity"]): row for row in transfer_payload["transfers"]
    }

    def exception_portal_rva(transition: Mapping[str, Any]) -> int:
        occurrence_kind = transition.get("occurrence_kind")
        if occurrence_kind == "effect":
            if transition.get("call_index") is not None:
                raise NativeIngressError(
                    "effect exception occurrence carries a call index"
                )
            return int(transition["source_rva"])
        if occurrence_kind != "call":
            raise NativeIngressError(
                "checked exception occurrence kind is unsupported"
            )
        call_index = transition.get("call_index")
        transfer = transfers_by_identity.get(str(transition["unit_id"]))
        calls = [] if not isinstance(transfer, Mapping) else transfer.get("calls")
        matches = (
            []
            if not isinstance(calls, list)
            else [
                row for row in calls
                if isinstance(row, Mapping)
                and row.get("event_index") == call_index
                and transition["operation"]
                in row.get("native_exception_operations", [])
            ]
        )
        if len(matches) != 1:
            raise NativeIngressError(
                "checked call exception does not identify one canonical transfer call"
            )
        return int(matches[0]["instruction_rva"])

    checked_calls: list[dict[str, Any]] = []
    catalogs = environment.get("canonical_boundaries")
    if not isinstance(catalogs, list):
        raise NativeIngressError(
            "resolved external environment canonical boundaries are malformed"
        )
    for index, raw_catalog in enumerate(catalogs):
        if not isinstance(raw_catalog, Mapping):
            raise NativeIngressError(
                f"resolved external environment boundary {index} is malformed"
            )
        if raw_catalog.get("kind") not in {
            "checked_protocol", "checked_machine_callback",
            "checked_interface_callback",
        }:
            continue
        catalog_subject = raw_catalog.get("subject")
        artifacts = raw_catalog.get("artifacts")
        if not isinstance(catalog_subject, str) or not isinstance(artifacts, Mapping):
            raise NativeIngressError(
                f"resolved external environment checked boundary {index} is malformed"
            )
        payloads: dict[str, dict[str, Any]] = {}
        for key in (
            "checked_call_protocol", "physical_call_frame_v3",
            "boundary_lifecycle",
            "boundary_lifecycle_receipt",
        ):
            artifact = artifacts.get(key)
            payload = artifact.get("payload") if isinstance(artifact, Mapping) else None
            if not isinstance(payload, Mapping):
                raise NativeIngressError(
                    f"resolved external environment checked boundary {catalog_subject!r} "
                    f"omits {key}"
                )
            payloads[key] = dict(payload)
        transport = payloads["physical_call_frame_v3"].get("transport")
        subject = transport.get("subject") if isinstance(transport, Mapping) else None
        if not isinstance(subject, Mapping):
            raise NativeIngressError(
                f"resolved external environment checked boundary {catalog_subject!r} "
                "has no physical subject"
            )
        checked_calls.append({
            "kind": raw_catalog.get("kind"),
            "identity": dict(raw_catalog.get("identity", {})),
            "catalog_subject": catalog_subject,
            "subject": dict(subject),
            "call_protocol": payloads["checked_call_protocol"],
            "physical_frame": payloads["physical_call_frame_v3"],
            "lifecycle_protocol": payloads["boundary_lifecycle"],
            "lifecycle_receipt": payloads["boundary_lifecycle_receipt"],
            "callback_arguments": list(
                raw_catalog.get("callback_arguments", [])
            ),
        })
    identities = [
        (row["subject"].get("kind"), row["subject"].get("id"))
        for row in checked_calls
    ]
    if len(identities) != len(set(identities)):
        raise NativeIngressError("checked call packages repeat a subject identity")

    blockers: list[dict[str, Any]] = [
        {
            "category": "execution_closure_blocker",
            "closure_blocker": dict(row),
        }
        for row in closure["blockers"]
    ]
    authorities: list[dict[str, Any]] = []
    outcomes: dict[str, CheckedBoundaryOutcomeProtocolV1] = {}
    seh_protocols: dict[str, CheckedSEHProtocolV1] = {}
    callback_domains: dict[str, dict[str, Any]] = {}
    callback_publications: list[dict[str, Any]] = []
    exception_rows_by_root: dict[int, list[Mapping[str, Any]]] = {}
    for row in closure["exception_continuations"]:
        for root_rva in row["root_rvas"]:
            exception_rows_by_root.setdefault(int(root_rva), []).append(row)

    def seh_for(
        transition: Mapping[str, Any], role: str
    ) -> CheckedSEHProtocolV1:
        operation = str(transition["operation"])
        specification = EFFECT_OPERATIONS_V2.get(operation)
        native_exception = (
            None if specification is None else specification.native_exception
        )
        if native_exception is None:
            raise NativeIngressError(
                f"checked exception operation {operation!r} has no canonical "
                "native exception metadata"
            )
        escape = (
            "terminate_process_root"
            if role == "process_entry"
            else "escape_callable_root"
        )
        portal_rva = exception_portal_rva(transition)
        projections = (
            transition["state_projection"]
            if transition["state_projection"] is not None
            else {
                "registers": (),
                "flags": (),
                "x87": (),
                "stack": (),
                "exception_record": (),
                "context": (),
            }
        )
        observed_address_fields: set[str] = set()
        if "exceptionaddress" in {
            str(value).lower()
            for value in projections["exception_record"]
        }:
            observed_address_fields.add("ExceptionAddress")
        if "eip" in {
            str(value).lower() for value in projections["context"]
        }:
            observed_address_fields.add("Eip")
        pinned_arguments: dict[str, Any] = {
            "observed_address_fields": tuple(sorted(observed_address_fields)),
        }
        if observed_address_fields:
            required_rvas = {int(transition["source_rva"])}
            if transition["resumption_rva"] is not None:
                required_rvas.add(int(transition["resumption_rva"]))
            matching_authorities = []
            for authority in pinned_layout_authorities:
                bindings = {
                    int(row["source_rva"]): int(row["candidate_rva"])
                    for row in authority.rva_bindings
                }
                if (
                    observed_address_fields <= set(authority.observed_fields)
                    and all(bindings.get(rva) == rva for rva in required_rvas)
                ):
                    matching_authorities.append(authority)
            if len(matching_authorities) == 1:
                pinned_arguments.update({
                    "address_policy": "pinned_original_layout",
                    "pinned_layout_authority_id": (
                        matching_authorities[0].authority_id
                    ),
                })
            elif len(matching_authorities) > 1:
                blockers.append({
                    "category": "pinned_code_layout_authority_ambiguous",
                    "transition_id": transition["transition_id"],
                    "authority_ids": sorted(
                        authority.authority_id
                        for authority in matching_authorities
                    ),
                })
        protocol = CheckedSEHProtocolV1.create(
            transition_id=str(transition["transition_id"]),
            transition_sha256=str(transition["transition_sha256"]),
            exception=native_exception.payload(),
            projections=projections,
            handler_unit_id=(
                str(transition["handler_unit_id"])
                if transition["disposition"] == "handled"
                else None
            ),
            handler_rva=(
                int(transition["handler_rva"])
                if transition["disposition"] == "handled"
                else None
            ),
            resumption_unit_id=(
                str(transition["resumption_unit_id"])
                if transition["resumption_unit_id"] is not None
                else None
            ),
            resumption_rva=(
                int(transition["resumption_rva"])
                if transition["resumption_rva"] is not None
                else None
            ),
            unwind_effect_ids=tuple(transition["unwind_unit_ids"]),
            escape_disposition=escape,
            gateway_handler_symbol="spx_native_seh_gateway",
            portals=({
                "source_rva": portal_rva,
                "candidate_symbol": (
                    "spx_exception_portal_"
                    + str(transition["transition_sha256"])[:24]
                ),
            },),
            **pinned_arguments,
        )
        seh_protocols[protocol.protocol_id] = protocol
        return protocol

    def outcome_for(
        frame: Mapping[str, Any], role: str, root_rva: int
    ) -> CheckedBoundaryOutcomeProtocolV1:
        transport = PhysicalCallFrameV2.parse(frame["transport"])
        kinds = set(transport.outcomes)
        derived_seh = tuple(sorted(
            {
                seh_for(row, role).protocol_id
                for row in exception_rows_by_root.get(root_rva, ())
                if row["disposition"] in {"handled", "terminates"}
            }
        ))
        if derived_seh:
            kinds.add("exceptional")
        unsupported = sorted(kinds & {"nonlocal"})
        if unsupported:
            blockers.append({
                "category": "ingress_outcome_authority_missing",
                "role": role,
                "outcomes": unsupported,
            })
            kinds.difference_update(unsupported)
        if not kinds:
            kinds.add("normal")
        protocol = CheckedBoundaryOutcomeProtocolV1.create(
            outcomes=tuple(sorted(kinds)),
            normal_projection_id=(
                "machine-result" if "normal" in kinds else None
            ),
            no_return_disposition=(
                "terminate_process" if "no_return" in kinds else None
            ),
            seh_protocol_ids=derived_seh,
        )
        outcomes[protocol.protocol_id] = protocol
        return protocol

    def append_authority(
        spec: Mapping[str, Any], checked: Mapping[str, Any]
    ) -> None:
        rva = int(spec["target_rva"])
        unit_id = str(spec.get("target_unit_id") or units.get(rva) or "")
        if not unit_id:
            blockers.append({
                "category": "ingress_target_unit_missing",
                "role": spec["role"],
                "target_rva": rva,
            })
            return
        if reachable_units.get(rva) != unit_id:
            blockers.append({
                "category": "ingress_target_not_reachable",
                "role": spec["role"],
                "target_rva": rva,
                "target_unit_id": unit_id,
            })
            return
        outcome = outcome_for(
            checked["physical_frame"], str(spec["role"]), rva
        )
        authorities.append({
            "role": spec["role"],
            "target_rva": rva,
            "target_unit_id": unit_id,
            "root_ids": list(spec["root_ids"]),
            "execution_closure_sha256": closure_sha256,
            "call_protocol": checked["call_protocol"],
            "physical_frame": checked["physical_frame"],
            "lifecycle_protocol": checked["lifecycle_protocol"],
            "lifecycle_receipt": checked["lifecycle_receipt"],
            "outcome_protocol_id": outcome.protocol_id,
            "capability_id": spec.get("capability_id"),
            "capability_lifetime": spec.get("capability_lifetime"),
        })

    for spec in _root_specs(interface, roots):
        role = str(spec["role"])
        if role in {"process_entry", "dll_entry", "tls_callback"}:
            append_authority(spec, _reviewed_loader_call(role, interface["image_id"]))
            continue
        aliases = {
            *(row["name"] for row in spec["exports"] if row["name"] is not None),
            *(f"ordinal:{row['ordinal']}" for row in spec["exports"]),
        }
        matches = [
            row for row in checked_calls
            if row["subject"].get("kind") == "export"
            and row["subject"].get("id") in aliases
        ]
        if len(matches) != 1:
            blockers.append({
                "category": "export_call_protocol_missing_or_ambiguous",
                "target_rva": spec["target_rva"],
                "aliases": sorted(aliases),
            })
            continue
        append_authority(spec, matches[0])

    callback_escapes = closure.get("callback_escapes")
    if not isinstance(callback_escapes, list):
        raise NativeIngressError(
            "module execution closure callback escapes are malformed"
        )
    for index, raw_escape in enumerate(callback_escapes):
        if not isinstance(raw_escape, Mapping):
            raise NativeIngressError(
                f"module execution closure callback escape {index} is malformed"
            )
        required = {
            "instruction_rva", "dll", "identity", "protocol_id", "targets",
            "action", "lifetime", "delivery",
        }
        if set(raw_escape) != required:
            raise NativeIngressError(
                f"module execution closure callback escape {index} has invalid fields"
            )
        escape = dict(raw_escape)
        targets = escape["targets"]
        if targets is None:
            continue
        if (
            not isinstance(targets, list)
            or any(
                not isinstance(target, int) or isinstance(target, bool)
                or not 0 <= target <= 0xFFFFFFFF
                for target in targets
            )
            or targets != sorted(set(targets))
        ):
            raise NativeIngressError(
                f"module execution closure callback escape {index} targets are malformed"
            )
        protocol_id = escape["protocol_id"]
        if not isinstance(protocol_id, str) or not protocol_id:
            raise NativeIngressError(
                f"module execution closure callback escape {index} protocol is malformed"
            )
        escape_identity = "callback-escape-v1:" + canonical_sha256_v3(escape)
        matches = [
            row for row in checked_calls
            if row["subject"].get("kind") == "callback"
            and row["subject"].get("id") == protocol_id
        ]
        if len(matches) != 1:
            blockers.append({
                "category": "callback_call_protocol_missing_or_ambiguous",
                "escape_id": escape_identity,
                "instruction_rva": escape["instruction_rva"],
                "protocol_id": protocol_id,
                "admitted_target_count": len(targets),
            })
            continue
        checked = matches[0]
        _physical, physical_issues = physical_frame_transducer_v1(
            checked["physical_frame"]
        )
        lifecycle = checked["lifecycle_protocol"]
        lifecycle_issues: tuple[Mapping[str, Any], ...] = ()
        if lifecycle.get("format") == BOUNDARY_LIFECYCLE_V1_FORMAT:
            _lifecycle, lifecycle_issues = (
                boundary_lifecycle_transducer_v1(
                    checked["physical_frame"], lifecycle
                )
            )
        if physical_issues or lifecycle_issues:
            blockers.append({
                "category": "callback_ingress_transducer_incomplete",
                "escape_id": escape_identity,
                "instruction_rva": escape["instruction_rva"],
                "protocol_id": protocol_id,
                "admitted_target_count": len(targets),
                "physical_issues": [
                    dict(item) for item in physical_issues
                ],
                "lifecycle_issues": [
                    dict(item) for item in lifecycle_issues
                ],
            })
            continue
        missing_targets = [
            target_rva for target_rva in targets
            if (
                units.get(target_rva) is None
                or reachable_units.get(target_rva) != units.get(target_rva)
            )
        ]
        if missing_targets:
            blockers.append({
                "category": "callback_domain_targets_not_reachable",
                "escape_id": escape_identity,
                "instruction_rva": escape["instruction_rva"],
                "protocol_id": protocol_id,
                "admitted_target_count": len(targets),
                "missing_target_count": len(missing_targets),
                "first_missing_target_rva": missing_targets[0],
            })
            continue
        # Preserve every callback may-domain as one runtime publication.  An
        # earlier size threshold eagerly assigned one bridge address per
        # target for small domains but used generation-scoped lazy assignment
        # for large domains.  Besides duplicating the realization model, that
        # made authority depend on domain cardinality: overlapping broad
        # domains below the threshold appeared to use every transfer through
        # every physical ABI before any callback was actually published.
        #
        # The compact runtime already enforces the stronger rule at the right
        # time.  A target receives an address only when selected at a checked
        # publication, and the process-generation assignment table rejects a
        # later incompatible physical-frame assignment.  Keeping domains
        # compact unconditionally therefore preserves the exact may-universe,
        # removes the static cross product, and does not relax fail-closed ABI
        # enforcement.
        outcome_targets: dict[str, list[int]] = {}
        for target_rva in targets:
            outcome = outcome_for(
                checked["physical_frame"], "callback", target_rva
            )
            outcome_targets.setdefault(outcome.protocol_id, []).append(
                target_rva
            )
        domain_core = {
            "module": interface["image_id"],
            "protocol_id": protocol_id,
            "physical_frame_id": checked["physical_frame"]["id"],
            "target_rvas": targets,
        }
        domain_id = "callback-domain-v1:" + canonical_sha256_v3(
            domain_core
        )
        domain = {
            "id": domain_id,
            "protocol_id": protocol_id,
            "target_rvas": targets,
            "call_protocol": checked["call_protocol"],
            "physical_frame": checked["physical_frame"],
            "lifecycle_protocol": checked["lifecycle_protocol"],
            "lifecycle_receipt": checked["lifecycle_receipt"],
            "outcome_groups": [
                {
                    "outcome_protocol_id": outcome_id,
                    "target_rvas": outcome_targets[outcome_id],
                }
                for outcome_id in sorted(outcome_targets)
            ],
        }
        previous_domain = callback_domains.get(domain_id)
        if previous_domain is not None and previous_domain != domain:
            raise NativeIngressError(
                "compact callback domain identity is ambiguous"
            )
        callback_domains[domain_id] = domain
        publication_core = {
            "domain_id": domain_id,
            "escape_id": escape_identity,
            "instruction_rva": escape["instruction_rva"],
            "dll": escape["dll"],
            "identity": escape["identity"],
            "action": escape["action"],
            "lifetime": escape["lifetime"],
            "delivery": escape["delivery"],
        }
        callback_publications.append({
            "id": "callback-publication-v1:" + canonical_sha256_v3(
                publication_core
            ),
            **publication_core,
        })

    # Interface callback arguments are capabilities published by a checked
    # interface method invocation, not by an import call.  Keep one domain and
    # publication per content-addressed method contract; physical call sites
    # select that publication later through their admitted method member.  In
    # particular, do not expand this into a site x method x target ingress
    # inventory.
    linked_payload = closure.get("_linked_semantic_module_v2")
    if isinstance(linked_payload, Mapping):
        interface_callback_catalogs: dict[str, Mapping[str, Any]] = {}
        for checked in checked_calls:
            if checked.get("kind") == "checked_interface_callback":
                identity = checked.get("identity")
                callback_sha256 = (
                    identity.get("callback_contract_sha256")
                    if isinstance(identity, Mapping) else None
                )
                if not isinstance(callback_sha256, str):
                    raise NativeIngressError(
                        "checked interface callback has no contract identity"
                    )
                if callback_sha256 in interface_callback_catalogs:
                    raise NativeIngressError(
                        "checked interface callback contract is ambiguous"
                    )
                interface_callback_catalogs[callback_sha256] = checked

        interface_methods: dict[str, Mapping[str, Any]] = {}
        for raw_domain in linked_payload.get("admitted_domains", []):
            if not isinstance(raw_domain, Mapping):
                raise NativeIngressError(
                    "linked semantic admitted domain is malformed"
                )
            for raw_target in raw_domain.get("external_interface_targets", []):
                if not isinstance(raw_target, Mapping):
                    raise NativeIngressError(
                        "linked semantic interface target is malformed"
                    )
                method = raw_target.get("method")
                method_sha256 = raw_target.get("method_contract_sha256")
                if not isinstance(method, Mapping):
                    raise NativeIngressError(
                        "linked semantic interface method is malformed"
                    )
                if method.get("callback_effect") == "none":
                    continue
                if (
                    method.get("callback_effect") != "explicit"
                    or not isinstance(method_sha256, str)
                ):
                    raise NativeIngressError(
                        "linked semantic interface callback is incomplete"
                    )
                previous = interface_methods.get(method_sha256)
                if previous is not None and previous != raw_target:
                    raise NativeIngressError(
                        "linked semantic interface callback method is ambiguous"
                    )
                interface_methods[method_sha256] = raw_target

        target_rvas = list(transfer_payload.get("entry_targets", []))
        if (
            any(
                not isinstance(target, int) or isinstance(target, bool)
                for target in target_rvas
            )
            or target_rvas != sorted(set(target_rvas))
        ):
            raise NativeIngressError(
                "transfer-plan callback target universe is malformed"
            )
        for method_sha256 in sorted(interface_methods):
            target = interface_methods[method_sha256]
            method = target["method"]
            callback_core = {
                "abi": dict(method["callback_abi"]),
                "arguments": list(method["callback_arguments"]),
                "lifetime": method["callback_lifetime"],
                "source": dict(method["callback_source"]),
            }
            callback_sha256 = canonical_sha256_v3(callback_core)
            checked = interface_callback_catalogs.get(callback_sha256)
            if checked is None:
                blockers.append({
                    "category": "interface_callback_boundary_missing",
                    "method_contract_sha256": method_sha256,
                    "callback_contract_sha256": callback_sha256,
                })
                continue
            physical = checked["physical_frame"]
            _physical, physical_issues = physical_frame_transducer_v1(physical)
            lifecycle = checked["lifecycle_protocol"]
            lifecycle_issues: tuple[Mapping[str, Any], ...] = ()
            if lifecycle.get("format") == BOUNDARY_LIFECYCLE_V1_FORMAT:
                _lifecycle, lifecycle_issues = boundary_lifecycle_transducer_v1(
                    physical, lifecycle
                )
            if physical_issues or lifecycle_issues:
                blockers.append({
                    "category": "interface_callback_ingress_transducer_incomplete",
                    "method_contract_sha256": method_sha256,
                    "callback_contract_sha256": callback_sha256,
                    "physical_issues": [dict(row) for row in physical_issues],
                    "lifecycle_issues": [dict(row) for row in lifecycle_issues],
                })
                continue
            missing_targets = [
                rva for rva in target_rvas
                if units.get(rva) is None or reachable_units.get(rva) != units.get(rva)
            ]
            if missing_targets:
                blockers.append({
                    "category": "interface_callback_domain_targets_not_reachable",
                    "method_contract_sha256": method_sha256,
                    "callback_contract_sha256": callback_sha256,
                    "admitted_target_count": len(target_rvas),
                    "missing_target_count": len(missing_targets),
                    "first_missing_target_rva": missing_targets[0],
                })
                continue
            protocol_id = str(checked["catalog_subject"]).removeprefix(
                "callback:"
            )
            outcome_targets: dict[str, list[int]] = {}
            for target_rva in target_rvas:
                outcome = outcome_for(physical, "callback", target_rva)
                outcome_targets.setdefault(outcome.protocol_id, []).append(target_rva)
            domain_core = {
                "module": interface["image_id"],
                "protocol_id": protocol_id,
                "physical_frame_id": physical["id"],
                "target_rvas": target_rvas,
            }
            domain_id = "callback-domain-v1:" + canonical_sha256_v3(domain_core)
            domain = {
                "id": domain_id,
                "protocol_id": protocol_id,
                "target_rvas": target_rvas,
                "call_protocol": checked["call_protocol"],
                "physical_frame": physical,
                "lifecycle_protocol": lifecycle,
                "lifecycle_receipt": checked["lifecycle_receipt"],
                "interface_callback_arguments": [
                    {
                        **dict(argument),
                        "profile_sha256": target["profile_sha256"],
                    }
                    for argument in checked.get("callback_arguments", [])
                ],
                "outcome_groups": [
                    {
                        "outcome_protocol_id": outcome_id,
                        "target_rvas": outcome_targets[outcome_id],
                    }
                    for outcome_id in sorted(outcome_targets)
                ],
            }
            previous_domain = callback_domains.get(domain_id)
            if previous_domain is not None and previous_domain != domain:
                raise NativeIngressError(
                    "interface callback domain identity is ambiguous"
                )
            callback_domains[domain_id] = domain
            publication_core = {
                "domain_id": domain_id,
                "escape_id": "interface-method-callback-v1:" + method_sha256,
                "instruction_rva": 0,
                "dll": None,
                "identity": method_sha256,
                "action": "register",
                "lifetime": method["callback_lifetime"],
                "delivery": "nested",
                "source_kind": "interface_method",
                "source_id": method_sha256,
            }
            callback_publications.append({
                "id": "callback-publication-v1:" + canonical_sha256_v3(
                    publication_core
                ),
                **publication_core,
            })

    return (
        authorities,
        [outcomes[key].to_payload() for key in sorted(outcomes)],
        [seh_protocols[key].to_payload() for key in sorted(seh_protocols)],
        blockers,
        {
            "domains": [
                callback_domains[key] for key in sorted(callback_domains)
            ],
            "publications": sorted(
                callback_publications,
                key=lambda row: (row["instruction_rva"], row["id"]),
            ),
        },
    )


def _reviewed_loader_call(role: str, image_id: str) -> dict[str, Any]:
    if role == "process_entry":
        convention, argument_count, cleanup = "custom", 0, 0
        transfer_kind, result = "direct", False
    elif role == "dll_entry":
        convention, argument_count, cleanup = "stdcall", 3, 12
        transfer_kind, result = "direct", True
    elif role == "tls_callback":
        convention, argument_count, cleanup = "stdcall", 3, 12
        transfer_kind, result = "callback", False
    else:  # pragma: no cover - private caller constrains this
        raise NativeIngressError(f"no reviewed loader frame for {role!r}")

    def slot(identity: str, *, offset: int, slot_role: str) -> dict[str, Any]:
        return {
            "id": identity,
            "role": slot_role,
            "storage_bits": 32,
            "value_bits": 32,
            "pass_mode": "direct",
            "logical_path": [],
            "fragments": [{
                "logical_offset_bits": 0,
                "width_bits": 32,
                "location_offset_bits": 0,
                "representation": "identity",
                "specified": True,
                "location": {
                    "kind": "stack",
                    "phase": "callee_entry",
                    "width_bits": 32,
                    "bank": None,
                    "name": None,
                    "stack_base": "callee-entry-esp-v1",
                    "stack_offset_bytes": offset,
                    "memory_slot": None,
                },
            }],
        }

    arguments = [
        slot(f"arg{index}", offset=4 + 4 * index, slot_role="parameter")
        for index in range(argument_count)
    ]
    results = []
    if result:
        result_slot = slot("result0", offset=0, slot_role="result")
        result_slot["fragments"][0]["location"] = {
            "kind": "register", "phase": "callee_exit", "width_bits": 32,
            "bank": "gpr", "name": "eax", "stack_base": None,
            "stack_offset_bytes": None, "memory_slot": None,
        }
        results.append(result_slot)
    transport = PhysicalCallFrameV2.create(
        subject={"kind": "function", "id": f"pe32-{role}", "image_selector": image_id},
        transfer_kind=transfer_kind,
        target="i686-pc-windows-pe32",
        abi_dialect="pe32-i386-loader-v1",
        calling_convention=convention,
        arguments=arguments,
        results=results,
        stack={
            "coordinate": "callee-entry-esp-v1", "alignment_bytes": 4,
            "cleanup": "custom" if role == "process_entry" else "callee",
            "cleanup_bytes": cleanup, "reserved_bytes": 0,
        },
        preserved_state=("ebp", "ebx", "edi", "esi", "esp"),
        clobbered_state=("eax", "ecx", "edx", "eflags", "st0", "st1"),
        outcomes=("normal",),
    )
    reviewed_profile = {
        "role": role,
        "transport": transport.to_payload(),
        "review": "pe32-loader-entry-profile-v1",
    }
    schema_sha256 = canonical_sha256_v3({"schema": reviewed_profile})
    layout_sha256 = canonical_sha256_v3({"layout": reviewed_profile})
    signature_id = f"pe32-{role}-signature-v1"
    bindings = [
        {
            "slot_id": item["id"],
            "path": {
                "root": "parameter" if item["role"] == "parameter" else "result",
                "value_id": item["id"],
                "fields": [],
            },
            "transport": "semantic",
        }
        for item in (*arguments, *results)
    ]
    frame = {
        "format": PHYSICAL_CALL_FRAME_V3_FORMAT,
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "transport": transport.to_payload(),
        "bindings": bindings,
        "dialect_rule_ids": [f"pe32.loader.{role}.v1"],
    }
    frame["id"] = f"physical-call-frame-v3:{canonical_sha256_v3(frame)}"
    lifecycle_protocol = {
        "kind": "reviewed_pe32_loader_lifecycle_v1",
        "role": role,
        "image_id": image_id,
        "event_source": (
            "none" if role == "process_entry" else "loader_reason_argument"
        ),
        "effects": (
            [] if role == "process_entry" else [{
                "attach": "activate_image_or_thread_generation",
                "detach": "expire_image_or_thread_generation",
            }]
        ),
    }
    lifecycle = {
        "format": BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
        "lifecycle_sha256": canonical_sha256_v3(lifecycle_protocol),
        "status": "complete",
        "obligations": [{
            "id": f"pe32.loader.{role}.lifecycle",
            "status": "checked",
            "code": "loader_owned_transition_checked",
        }],
    }
    lifecycle["receipt_sha256"] = canonical_sha256_v3(lifecycle)
    protocol = {
        "format": CHECKED_CALL_PROTOCOL_V2_FORMAT,
        "status": "complete",
        "schema_id": f"pe32-{role}-schema-v1",
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "physical_frame_id": frame["id"],
        "evidence_receipt_id": f"reviewed-pe32-loader-frame:{role}:v1",
        "lifecycle_sha256": lifecycle["lifecycle_sha256"],
        "lifecycle_receipt_sha256": lifecycle["receipt_sha256"],
        "projection_sha256": None,
        "projection_receipt_sha256": None,
        "issues": [],
    }
    protocol["id"] = f"checked-call-protocol-v2:{canonical_sha256_v3(protocol)}"
    return {
        "call_protocol": protocol,
        "physical_frame": frame,
        "lifecycle_protocol": lifecycle_protocol,
        "lifecycle_receipt": lifecycle,
    }


def _root_specs(interface: Mapping[str, Any], roots: Mapping[str, Any]) -> list[dict[str, Any]]:
    export_slots: dict[int, list[Mapping[str, Any]]] = {}
    for row in interface["export_directory"]["slots"]:
        if row["kind"] == "code":
            export_slots.setdefault(int(row["rva"]), []).append(row)
    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    for root in roots.get("roots", []):
        if not isinstance(root, Mapping):
            raise NativeIngressError("behavioral root is malformed")
        kind = root.get("kind")
        rva = root.get("rva")
        if not isinstance(rva, int) or isinstance(rva, bool):
            raise NativeIngressError("behavioral root RVA is invalid")
        if kind == "pe_entrypoint":
            role = "dll_entry" if interface["kind"] == "dll" else "process_entry"
            exports: list[dict[str, Any]] = []
            tls_order = None
        elif kind == "pe_export":
            role = "export"
            slots = export_slots.get(rva)
            if slots is None:
                raise NativeIngressError("behavioral export root has no code EAT slot")
            exports = sorted(
                (
                    {"name": name, "ordinal": slot["ordinal"]}
                    for slot in slots for name in slot["names"]
                ),
                key=lambda item: (item["ordinal"], item["name"]),
            )
            exports.extend(
                {"name": None, "ordinal": slot["ordinal"]}
                for slot in slots if not slot["names"]
            )
            exports.sort(key=lambda item: (item["ordinal"], item["name"] or ""))
            tls_order = None
        elif kind == "pe_tls_callback":
            role = "tls_callback"
            exports = []
            tls_order = root.get("callback_index")
        else:
            continue
        key = (role, rva)
        row = grouped.setdefault(key, {
            "role": role,
            "target_rva": rva,
            "root_ids": [],
            "exports": exports,
            "capability_id": None,
            "tls_order": tls_order,
        })
        identity = root.get("identity")
        if not isinstance(identity, str) or not identity:
            raise NativeIngressError("behavioral root identity is invalid")
        row["root_ids"].append(identity)
        if row["exports"] != exports or row["tls_order"] != tls_order:
            raise NativeIngressError("behavioral roots disagree for one native target")
    result = list(grouped.values())
    for row in result:
        row["root_ids"] = sorted(set(row["root_ids"]))
    return sorted(result, key=lambda row: (row["target_rva"], row["role"]))
