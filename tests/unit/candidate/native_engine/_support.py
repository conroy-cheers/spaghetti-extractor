from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pefile

from spaghetti_extractor.external.contracts import (
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
)
from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.artifacts.formats import MACHINE_IR_FORMAT
from spaghetti_extractor.machine_ir.memory_actions import build_memory_action_graph
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
    CallbackRequirementV3,
    CallbackSourceDecisionV3,
    ExternalContractV3,
    external_site_id_v3,
)
from spaghetti_extractor.authority.callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V4,
    CALLBACK_AUTHORITY_CODEC_V4,
    CallbackAuthorityRecordV3,
    CallbackAuthorityV4,
    derive_callback_entry_state_v3,
)
from spaghetti_extractor.external.callback_protocols import (
    callback_lifetime_identity,
    parse_callback_protocol,
)
from spaghetti_extractor.authority._schema import stable_id
from spaghetti_extractor.authority.authority_common import PrimaryBlockerV3
from spaghetti_extractor.authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    CallEffectV3,
    ParametricIndirectExitV3,
    ParametricSccSummaryV3,
    ReturnBehaviorV3,
    ValueFactV3,
    ValueOriginV3,
    parametric_scc_id_v3,
)
from spaghetti_extractor.authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
    LaunchRootClosureV3,
    RootedControlEdgeV3,
)
from spaghetti_extractor.authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateUnitV3,
    IndirectTargetCertificateV3,
)
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.candidate.engine import (
    plan_spx_native_engine,
    write_spx_native_engine_package,
)
from spaghetti_extractor.util import sha256_bytes, write_json
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.candidate.native_ingress_runtime import exact_tls_regions


def _native_ingress_plan(
    entry_rva: int,
    *,
    tls_callbacks: tuple[int, ...] = (),
    callbacks: tuple[tuple[int, int], ...] = (),
) -> dict[str, object]:
    specifications = [("process_entry", entry_rva, 0, None)]
    specifications.extend(
        ("tls_callback", rva, 12, None) for rva in tls_callbacks
    )
    specifications.extend(
        ("callback", rva, cleanup, f"fixture-capability-{rva:08x}")
        for rva, cleanup in callbacks
    )
    ingresses = []
    bridges = []
    for index, (role, rva, cleanup, capability) in enumerate(specifications):
        transport = PhysicalCallFrameV2.create(
            subject={
                "kind": "callback" if role == "callback" else "function",
                "id": f"fixture-ingress-{rva:08x}",
                "image_selector": "fixture",
            },
            transfer_kind="callback" if role == "callback" else "direct",
            target="i686-pc-windows-gnu",
            abi_dialect="pe32-i386-gnu-v1",
            calling_convention="stdcall" if cleanup else "cdecl",
            arguments=[],
            results=[],
            stack={
                "coordinate": "callee-entry-esp",
                "alignment_bytes": 4,
                "cleanup": "callee" if cleanup else "caller",
                "cleanup_bytes": cleanup,
                "reserved_bytes": 0,
            },
            preserved_state=["ebx", "ebp", "esi", "edi"],
            clobbered_state=["eax", "ecx", "edx", "eflags"],
            outcomes=["normal"],
        )
        symbol = f"spx_ingress_{index:04d}"
        ingresses.append({
            "role": role,
            "target_rva": rva,
            "target_unit_id": f"unit:{rva:08x}",
            "bridge_symbol": symbol,
            "physical_frame_id": transport.frame_id,
            "physical_frame": {"transport": transport.to_payload()},
            "outcome_protocol_id": "fixture-normal-outcome",
            "capability_id": capability,
            "lifecycle_receipt": {"status": "complete"},
        })
        bridges.append({"symbol": symbol})
    core: dict[str, object] = {
        "format": "spaghetti-extractor-native-ingress-plan-v1",
        "status": "complete",
        "ingresses": ingresses,
        "bridges": bridges,
        "outcome_protocols": [{
            "id": "fixture-normal-outcome", "outcomes": ["normal"]
        }],
        "seh_protocols": [],
        "tls_layout": {
            "runtime_offset": 0,
            "runtime_control_bytes": 0x80000,
            "private_stack_bytes": 0x100000,
            "runtime_regions": exact_tls_regions(
                control_bytes=0x80000, stack_bytes=0x100000
            ),
        },
        "runtime_requirements": {"features": [
            "code_capability_registry_v1",
            "host_thread_concurrency_v1",
            "loader_lock_safe_bootstrap_v1",
            "outgoing_bridge_pe_tls_state_v1",
            "per_thread_ingress_frame_chain_v1",
            "same_thread_reentrancy_v1",
            "tls_private_engine_stack_v1",
            "transactional_boundary_writeback_v1",
        ]},
    }
    return {**core, "plan_sha256": canonical_sha256_v3(core)}


def _write_native_ingress_plan(
    root: Path,
    entry_rva: int,
    *,
    tls_callbacks: tuple[int, ...] = (),
    callbacks: tuple[tuple[int, int], ...] = (),
) -> Path:
    path = root / "native-ingress-plan.json"
    write_json(
        path,
        _native_ingress_plan(
            entry_rva, tls_callbacks=tls_callbacks, callbacks=callbacks
        ),
    )
    return path


def _transfer(*, event: dict | None = None) -> dict:
    instructions = []
    ordered = []
    if event is not None:
        instructions = [{
            "rva": event["instruction_rva"],
            "size": 6,
            "bytes": "ff159c214300",
            "mnemonic": "call",
            "op_str": "dword ptr [0x43219c]",
        }]
        ordered = [{"family": "external", **event}]
    return {
        "id": "semantic-transfer:entry",
        "original": {"rva_start": 0x1420, "rva_end": 0x1430},
        "instructions": instructions,
        "ordered_events": ordered,
        "fpu_state": None,
    }


def _machine_ir_transfer(
    *,
    event: dict | None = None,
    rva: int = 0x142A,
    size: int = 6,
    mnemonic: str = "call",
    instruction_sha256: str | None = None,
) -> dict:
    instruction_digest = instruction_sha256 or sha256_bytes(b"typed-call")
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    ordered: list[dict] = []
    if event is not None:
        ordered = [{
            "family": "external",
            "arguments": [],
            "register_inputs": registers,
            "flag_inputs": flags,
            "stack_inputs": [],
            **event,
        }]
    end = rva + size
    unit = {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "unit",
        "id": f"semantic-transfer:typed-{rva:08x}",
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": end, "size": size},
            "contract_sha256": "a" * 64,
            "instruction_bytes_sha256": sha256_bytes(
                f"unit:{rva:08x}:{size}".encode("ascii")
            ),
            "semantic_export": None,
        },
        "instructions": [{
            "rva_start": rva,
            "rva_end": end,
            "size": size,
            "instruction_sha256": instruction_digest,
            "mnemonic": mnemonic,
            "operands": [],
            "registers_read": [],
            "registers_written": [],
            "groups": ["call"] if mnemonic == "call" else [],
        }],
        "x87_micro_ops": [],
        "control": {
            "kind": "return" if mnemonic == "ret" else "fallthrough",
            "direct_targets": [] if mnemonic == "ret" else [end],
            "has_indirect_target": False,
        },
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": ordered,
            "faults": [],
            "ordered_events": ordered,
            "edge_conditions": [],
            "outcome": {"kind": "fallthrough", "target_rva": end},
            "stack_delta": 0,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": None,
        },
    }
    unit["semantics"]["memory_actions"] = build_memory_action_graph(
        instructions=unit["instructions"], memory_events=[], ordered_events=ordered
    )
    return unit


def _implementation_manifest(
    machine_ir: Path,
) -> dict:
    return {
        "format": MACHINE_IR_FORMAT,
        "artifacts": {
            "machine_ir": {
                "format": MACHINE_IR_FORMAT,
                "sha256": sha256_bytes(machine_ir.read_bytes()),
            },
        },
    }


def _fixture_callback_protocol(contract):
    adapter = contract.callback_adapter
    if adapter is None:
        return None
    source = dict(adapter.source)
    source["sentinels"] = (
        [{"word": 0, "kind": "null"}]
        if adapter.abi.get("nullable") is True
        else []
    )
    words = int(adapter.abi["argument_words"])
    cleanup = int(adapter.abi["stack_cleanup_bytes"])
    legacy_lifetime = str(adapter.lifetime)
    lifetime = (
        {"kind": "during_call"}
        if legacy_lifetime == "during_native_call"
        else {
            "kind": "until_resource_event_or_process_exit",
            "end_event": "class_unregistered",
        }
        if legacy_lifetime == "until_class_unregistered_or_process_exit"
        else {"kind": "until_replaced_or_process_exit"}
    )
    return parse_callback_protocol(
        {
            "format": "spaghetti-extractor-callback-protocol-v1",
            "id": f"fixture-callback:{contract.contract_id}",
            "action": "register",
            "source": source,
            "signature": {
                "abi_template": (
                    "pe32-stdcall-v1" if cleanup == words * 4 else "pe32-cdecl-v1"
                ),
                "argument_words": words,
                "stack_cleanup_bytes": cleanup,
                "result": {"kind": "word", "register": "eax"},
            },
            "instance": {"kind": "singleton"},
            "previous_result": None,
            "lifetime": lifetime,
            "delivery": {
                "timing": "nested_or_deferred",
                "thread": "external_concurrent",
            },
            "cardinality": {
                "minimum": 0,
                "maximum": None,
                "scope": "registration_generation",
            },
            "provider_behavior": None,
        },
        registration_argument_words=contract.argument_words,
        context="fixture callback protocol",
    )


def _fixture_machine_contract(contract) -> dict[str, object]:
    machine_contract: dict[str, object] = {
        "abi_template": contract.abi_template,
        "argument_words": contract.argument_words,
        "result_register_relations": list(contract.result_register_relations),
        "memory_footprints": list(contract.memory_footprints),
        "out_pointer_relations": list(contract.out_pointer_relations),
        "out_interface_relations": list(contract.out_interface_relations),
    }
    protocol = _fixture_callback_protocol(contract)
    if protocol is not None:
        machine_contract.update({
            "callback_protocol": protocol.to_payload(),
            "callback_activation": contract.callback_adapter.activation,
            "resource_binding": contract.callback_adapter.resource_binding,
            "instance_binding": contract.callback_adapter.instance_binding,
        })
    return machine_contract


def _canonical_external_sites(
    root: Path,
    *,
    unit: dict,
    event_index: int,
    identity: dict,
    contract,
    callback_target_rvas: tuple[int, ...] = (),
    event: dict | None = None,
    unit_sha256: str | None = None,
) -> Path:
    event = (
        unit["semantics"]["external_events"][event_index]
        if event is None
        else event
    )
    target_sha256 = canonical_sha256_v3(identity)
    site_id = external_site_id_v3(
        unit["id"], event_index, 0, identity
    )
    machine_contract = _fixture_machine_contract(contract)
    protocol = _fixture_callback_protocol(contract)
    callbacks = tuple(
        CallbackRequirementV3.create(
            site_id=site_id,
            ordinal=ordinal,
            target_unit_id=f"semantic-transfer:typed-{rva:08x}",
            target_rva=rva,
            abi_sha256=canonical_sha256_v3(protocol.signature.to_payload()),
            lifetime=callback_lifetime_identity(protocol),
        )
        for ordinal, rva in enumerate(callback_target_rvas)
    )
    authority_contract = ExternalContractV3.create(
        identity=identity,
        transfer_kind=contract.transfer_kind,
        disposition=(
            "tail_jump"
            if contract.disposition == "tail_jump"
            else (
                "noreturn"
                if contract.profile_disposition == "terminates"
                else "returns"
            )
        ),
        profile_id=str(contract.profile_binding["profile_id"]),
        profile_sha256=str(contract.profile_binding["profile_sha256"]),
        argument_words=contract.argument_words,
        arguments=list(contract.arguments),
        memory_effect=contract.memory_effect,
        world_effect=contract.world_effect,
        callback_effect=(
            "registers" if contract.callback_effect == "explicit" else "none"
        ),
        machine_contract=machine_contract,
        callbacks=callbacks,
        callback_source_decision=(
            None
            if not callbacks or protocol is None or protocol.source is None
            else CallbackSourceDecisionV3.create(
                kind="callback_target",
                argument_index=protocol.source.argument,
                source_expression=contract.arguments[protocol.source.argument],
            )
        ),
    )
    site = CanonicalExternalSiteV3(
        site_id=site_id,
        unit_id=unit["id"],
        event_index=event_index,
        alternative_index=0,
        event_sha256=canonical_sha256_v3(event),
        target_sha256=target_sha256,
        identity=CanonicalValueV3.of(identity),
        status="complete",
        authorizing=True,
        contract=authority_contract,
        primary_blocker=None,
    )
    record = CanonicalExternalSiteRecordV3(
        record_id=unit["id"],
        unit_sha256=(canonical_sha256_v3(unit) if unit_sha256 is None else unit_sha256),
        status="complete",
        authorizing=True,
        sites=(site,),
        primary_blocker=None,
        dependencies=(),
    )
    output = root / "canonical-external-sites"
    ArtifactSetWriterV3(
        artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        bindings=(),
    ).write(
        output,
        [ArtifactRecordV3.create(
            unit["id"], CANONICAL_EXTERNAL_SITE_CODEC_V3.encode(record)
        )],
    )
    return output


def _canonical_callback_authority(
    root: Path,
    *,
    registration_unit: dict,
    event_index: int,
    identity: dict,
    contract,
    target_units: tuple[dict, ...],
) -> Path:
    site_id = external_site_id_v3(
        registration_unit["id"], event_index, 0, identity
    )
    protocol = _fixture_callback_protocol(contract)
    if protocol is None:
        raise AssertionError("callback authority fixture requires a callback protocol")
    machine_contract = CanonicalValueV3.of(_fixture_machine_contract(contract))
    callbacks = []
    for ordinal, unit in enumerate(target_units):
        target_rva = int(unit["source"]["original"]["rva_start"])
        requirement = CallbackRequirementV3.create(
            site_id=site_id,
            ordinal=ordinal,
            target_unit_id=str(unit["id"]),
            target_rva=target_rva,
            abi_sha256=canonical_sha256_v3(protocol.signature.to_payload()),
            lifetime=callback_lifetime_identity(protocol),
        )
        entry_state, blocker = derive_callback_entry_state_v3(
            external_site_id=site_id,
            requirement=requirement,
            machine_contract=machine_contract,
        )
        if blocker is not None or entry_state is None:
            raise AssertionError("fixture callback entry state is incomplete")
        callbacks.append(CallbackAuthorityV4(
            callback_id=requirement.callback_id,
            external_site_id=site_id,
            target_unit_id=requirement.target_unit_id,
            target_unit_sha256=canonical_sha256_v3(unit),
            target_rva=target_rva,
            abi_sha256=requirement.abi_sha256,
            lifetime=requirement.lifetime,
            status="complete",
            authorizing=True,
            entry_state=entry_state,
            primary_blocker=None,
            protocol=CanonicalValueV3.of(protocol.to_payload()),
        ))
    record = CallbackAuthorityRecordV3(
        record_id=str(registration_unit["id"]),
        unit_sha256=canonical_sha256_v3(registration_unit),
        status="complete",
        authorizing=True,
        callbacks=tuple(sorted(callbacks, key=lambda row: row.callback_id)),
        primary_blocker=None,
        dependencies=(),
    )
    output = root / "callback-authority"
    ArtifactSetWriterV3(
        artifact_kind=CALLBACK_AUTHORITY_ARTIFACT_KIND_V4,
        bindings=(),
    ).write(
        output,
        (CALLBACK_AUTHORITY_CODEC_V4.write(record.record_id, record),),
    )
    return output


def _candidate_execution_artifacts(
    root: Path,
    *,
    units: list[dict],
    roots: list[str] | None = None,
    reachable: list[str] | None = None,
    complete: bool = True,
) -> tuple[Path, Path, Path]:
    """Write minimal checked execution artifacts for candidate unit tests."""

    unit_ids = tuple(sorted(str(row["id"]) for row in units))
    root_ids = tuple(sorted(unit_ids[:1] if roots is None else roots))
    reachable_ids = tuple(sorted(unit_ids if reachable is None else reachable))
    def original(row: dict) -> dict:
        source = row.get("source")
        return source["original"] if isinstance(source, dict) else row["original"]

    by_rva = {
        int(original(row)["rva_start"]): str(row["id"]) for row in units
    }
    edges: set[RootedControlEdgeV3] = set()
    indirect_rows: dict[str, list[tuple[dict, tuple[str, ...], str]]] = {}
    call_rows: dict[str, list[CallEffectV3]] = {}
    for unit in units:
        source_id = str(unit["id"])
        if source_id not in reachable_ids:
            continue
        control = unit.get("control")
        for target_rva in (
            control.get("direct_targets", []) if isinstance(control, dict) else []
        ):
            target_id = by_rva.get(int(target_rva))
            if target_id in reachable_ids:
                edges.add(
                    RootedControlEdgeV3.create(
                        source_id, target_id, "direct", source_id
                    )
                )
        semantics = unit.get("semantics")
        events = (
            semantics.get("external_events", [])
            if isinstance(semantics, dict)
            else unit.get("ordered_events", [])
        )
        for event_index, event in enumerate(
            row
            for row in events
            if isinstance(row, dict) and row.get("family", "external") == "external"
        ):
            kind = event.get("kind")
            if kind == "internal_call":
                target_id = by_rva.get(int(event["target_rva"]))
                if target_id is None:
                    continue
                edges.add(
                    RootedControlEdgeV3.create(
                        source_id, target_id, "internal_call", source_id
                    )
                )
                call_rows.setdefault(source_id, []).append(
                    CallEffectV3(
                        stable_id(
                            "fixture-parametric-call",
                            {
                                "source_unit_id": source_id,
                                "event_index": event_index,
                                "target_unit_id": target_id,
                            },
                        ),
                        source_id,
                        event_index,
                        "direct_internal",
                        (target_id,),
                        None,
                        (),
                        None,
                        (),
                    )
                )
            if kind != "indirect_call" or event.get("dll"):
                continue
            return_id = by_rva.get(int(event.get("return_rva", -1)))
            target_ids = tuple(
                sorted(
                    unit_id
                    for unit_id in reachable_ids
                    if unit_id not in {source_id, return_id}
                )
            )
            if not target_ids:
                continue
            exit_id = f"fixture-indirect:{source_id}:{event_index}"
            indirect_rows.setdefault(source_id, []).append(
                (event, target_ids, exit_id)
            )
    target_records = []
    for unit in units:
        unit_id = str(unit["id"])
        certificates = []
        unit_sha256 = canonical_sha256_v3(unit)
        source_rva = int(original(unit)["rva_start"])
        for event, target_ids, exit_id in indirect_rows.get(unit_id, []):
            expression = event.get("target", {"op": "fixture-indirect"})
            expression_value = CanonicalValueV3.of(expression)
            expression_sha256 = canonical_sha256_v3(expression)
            binding = {
                "exit_id": exit_id,
                "source_unit_id": unit_id,
                "source_unit_sha256": unit_sha256,
                "source_rva": source_rva,
                "source_event_index": int(exit_id.rsplit(":", 1)[1]),
                "transfer_kind": "indirect_call",
                "target_expression": expression,
                "target_expression_sha256": expression_sha256,
            }
            certificate_id = (
                "indirect-target-certificate:"
                + canonical_sha256_v3(binding)[:24]
            )
            decision = {
                "id": certificate_id,
                **binding,
                "status": "complete",
                "authorizing": True,
                "target_unit_ids": list(target_ids),
                "external_targets": [],
                "evaluation_method": "checked_parametric_summary",
                "evidence_sha256": canonical_sha256_v3(
                    {"fixture": exit_id, "targets": list(target_ids)}
                ),
                "dependencies": [],
                "primary_blocker": None,
            }
            certificate = IndirectTargetCertificateV3(
                certificate_id=certificate_id,
                exit_id=exit_id,
                source_unit_id=unit_id,
                source_unit_sha256=unit_sha256,
                source_rva=source_rva,
                source_event_index=binding["source_event_index"],
                transfer_kind="indirect_call",
                target_expression=expression_value,
                target_expression_sha256=expression_sha256,
                status="complete",
                authorizing=True,
                target_unit_ids=target_ids,
                external_targets=(),
                evaluation_method="checked_parametric_summary",
                evidence_sha256=decision["evidence_sha256"],
                dependencies=(),
                primary_blocker=None,
                certificate_sha256=canonical_sha256_v3(decision),
            )
            certificates.append(certificate)
            for target_id in target_ids:
                edges.add(
                    RootedControlEdgeV3.create(
                        unit_id,
                        target_id,
                        "recovered_indirect",
                        certificate_id,
                    )
                )
        if certificates:
            target_unit = IndirectTargetCertificateUnitV3(
                record_id=unit_id,
                source_unit_id=unit_id,
                unit_sha256=unit_sha256,
                status="complete",
                authorizing=True,
                certificates=tuple(sorted(certificates, key=lambda row: row.exit_id)),
                dependencies=(),
                primary_blocker=None,
            )
            target_records.append(
                INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.write(
                    unit_id, target_unit
                )
            )
    target_path = root / "target-certificates"
    ArtifactSetWriterV3(
        artifact_kind=INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
        bindings=(),
    ).write(target_path, target_records)

    submitted = tuple(f"fixture-root:{unit_id}" for unit_id in root_ids)
    closure_id = stable_id(
        "launch-root-closure-v3",
        {
            "submitted_root_ids": list(submitted),
            "callback_root_ids": [],
            "dependency_records": [],
        },
    )
    closure = LaunchRootClosureV3(
        record_id=closure_id,
        status="complete" if complete else "incomplete",
        authorizing=complete,
        submitted_root_ids=submitted,
        admitted_root_ids=submitted,
        callback_root_ids=(),
        root_unit_ids=root_ids,
        reachable_unit_ids=reachable_ids,
        edges=tuple(sorted(edges)),
        frontier_ids=() if complete else ("fixture-frontier",),
        primary_blocker=(
            None
            if complete
            else PrimaryBlockerV3("incomplete", "fixture_reachability_incomplete")
        ),
        dependencies=(),
    )
    root_path = root / "root-closure"
    ArtifactSetWriterV3(
        artifact_kind=LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3, bindings=()
    ).write(root_path, (LAUNCH_ROOT_CLOSURE_CODEC_V3.write(closure_id, closure),))

    summaries = []
    for unit in units:
        unit_id = str(unit["id"])
        semantics = unit.get("semantics")
        outcome = (
            semantics.get("outcome", {})
            if isinstance(semantics, dict)
            else unit.get("outcome", {})
        )
        returns = isinstance(outcome, dict) and outcome.get("kind") == "return"
        scc_id = parametric_scc_id_v3((unit_id,), ())
        value_facts = []
        indirect_exits = []
        for event, target_ids, exit_id in indirect_rows.get(unit_id, []):
            fact_id = f"fixture-fact:{exit_id}"
            value_facts.append(
                ValueFactV3(
                    fact_id,
                    "finite",
                    tuple(
                        sorted(
                            ValueOriginV3("static_code_target", target_id, 0)
                            for target_id in target_ids
                        )
                    ),
                )
            )
            indirect_exits.append(
                ParametricIndirectExitV3(
                    exit_id,
                    unit_id,
                    canonical_sha256_v3(
                        event.get("target", {"op": "fixture-indirect"})
                    ),
                    fact_id,
                    target_ids,
                    (),
                )
            )
        summaries.append(
            PARAMETRIC_SCC_SUMMARY_CODEC_V3.write(
                scc_id,
                ParametricSccSummaryV3(
                    record_id=scc_id,
                    scc_id=scc_id,
                    status="complete",
                    authorizing=True,
                    proposal_id="fixture-proposal",
                    member_unit_ids=(unit_id,),
                    recursive=False,
                    checked_base_path_unit_ids=(),
                    value_facts=tuple(value_facts),
                    register_relations=(),
                    stack_accesses=(),
                    stack_cleanup_bytes=0 if returns else None,
                    return_address_preserved=returns,
                    memory_effects=(),
                    call_effects=tuple(call_rows.get(unit_id, ())),
                    returns=(
                        ReturnBehaviorV3(
                            unit_id,
                            returns,
                            not returns,
                            0 if returns else None,
                            returns,
                        ),
                    ),
                    indirect_exits=tuple(indirect_exits),
                    primary_blocker=None,
                    dependencies=(),
                ),
            )
        )
    summary_path = root / "parametric-summaries"
    ArtifactSetWriterV3(
        artifact_kind=PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
        bindings=(),
    ).write(summary_path, summaries)
    return root_path, target_path, summary_path


def _empty_callback_authority(root: Path) -> Path:
    output = root / "callback-authority"
    ArtifactSetWriterV3(
        artifact_kind=CALLBACK_AUTHORITY_ARTIFACT_KIND_V4,
        bindings=(),
    ).write(output, ())
    return output


def _machine_ir_x87_transfer(
    *, rva: int, mnemonic: str, encoded: bytes
) -> dict:
    unit = _machine_ir_transfer(
        rva=rva,
        size=len(encoded),
        mnemonic=mnemonic,
        instruction_sha256=sha256_bytes(encoded),
    )
    unit["instructions"][0].update({
        "operands": [{
            "kind": "register",
            "name": "st(1)",
            "width_bits": 80,
            "access": "read",
        }],
        "registers_read": ["st(0)", "st(1)"],
        "registers_written": ["eflags"],
        "groups": ["fpu"],
    })
    unit["source"]["instruction_bytes_sha256"] = sha256_bytes(encoded)
    transfer_digest = unit["source"]["instruction_bytes_sha256"]
    micro_id = f"{unit['id']}:x87:{rva:08x}"
    unit["x87_micro_ops"] = [{
        "format": "spaghetti-extractor-x87-micro-op-v1",
        "id": micro_id,
        "unit_id": unit["id"],
        "rva_start": rva,
        "rva_end": rva + len(encoded),
        "size": len(encoded),
        "instruction_sha256": sha256_bytes(encoded),
        "transfer_instruction_sha256": transfer_digest,
        "mnemonic": mnemonic,
        "operands": unit["instructions"][0]["operands"],
        "implicit_registers_read": ["st(0)", "st(1)"],
        "implicit_registers_written": ["eflags"],
        "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
        "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
        "physical_state_effect": "defined_by_checked_typed_x87_executor",
    }]
    unit["semantics"]["fpu_state"] = {
        "typed_replay": {
            "source_format": "spaghetti-extractor-native-exact-x87-command-replay-obligation-v1",
            "architecture": "x86",
            "bitness": 32,
            "image_base": 0x400000,
            "rva_start": rva,
            "rva_end": rva + len(encoded),
            "instruction_bytes_sha256": transfer_digest,
            "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
            "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
            "micro_op_ids": [micro_id],
        }
    }
    return unit


def _x87_replay_transfer() -> dict:
    encoded = bytes.fromhex("d9e8")
    digest = sha256_bytes(encoded)
    row = _transfer()
    row.update({
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": digest,
        "original": {"rva_start": 0x1420, "rva_end": 0x1422, "size": 2},
        "instructions": [{
            "rva": 0x1420,
            "size": 2,
            "bytes": encoded.hex(),
            "mnemonic": "fld1",
            "op_str": "",
        }],
        "outcome": {"kind": "fallthrough", "target_rva": 0x1422},
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "status": "required",
            "authoritative_state_type": "SpaghettiExtractor.ISA.X87.PhysicalState",
            "required_fields": [
                "stack", "tags", "control", "status", "pending_exception",
                "last_opcode", "instruction_pointer", "code_selector",
                "data_pointer", "data_selector",
            ],
            "missing_or_invalid_fields": [
                "tags", "pending_exception", "last_opcode",
                "instruction_pointer", "code_selector", "data_pointer",
                "data_selector",
            ],
            "logical_state_guidance": {},
            "replay": {
                "format": "spaghetti-extractor-native-exact-x87-command-replay-obligation-v1",
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
                "architecture": "x86",
                "bitness": 32,
                "image_base": 0x400000,
                "rva_start": 0x1420,
                "rva_end": 0x1422,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{
                    "rva": 0x1420, "size": 2, "bytes": encoded.hex()
                }],
            },
        },
    })
    return row


def _absolute_x87_replay_transfer() -> dict:
    row = _x87_replay_transfer()
    encoded = bytes.fromhex("d90534124000")
    digest = sha256_bytes(encoded)
    row["static_program_export"] = {"static_program_contract_sha256": "c" * 64}
    row["instruction_bytes_sha256"] = digest
    row["original"] = {
        "rva_start": 0x1420,
        "rva_end": 0x1420 + len(encoded),
        "size": len(encoded),
    }
    row["instructions"] = [{
        "rva": 0x1420,
        "size": len(encoded),
        "bytes": encoded.hex(),
        "mnemonic": "fld",
        "op_str": "dword ptr [0x401234]",
    }]
    row["outcome"] = {
        "kind": "fallthrough",
        "target_rva": 0x1420 + len(encoded),
    }
    replay = row["fpu_state"]["replay"]
    replay.update({
        "rva_end": 0x1420 + len(encoded),
        "bytes": encoded.hex(),
        "bytes_sha256": digest,
        "instructions": [{
            "rva": 0x1420,
            "size": len(encoded),
            "bytes": encoded.hex(),
        }],
    })
    return row


def _relocation_evidence(
    relocations: list[dict] | None = None,
    *,
    static_program_contract_sha256: str = "c" * 64,
) -> dict:
    return {
        "format": "spaghetti-extractor-pe32-base-relocation-evidence-v1",
        "complete": True,
        "pe_sha256": "d" * 64,
        "static_program_contract_sha256": static_program_contract_sha256,
        "image_base": 0x400000,
        "relocations": relocations if relocations is not None else [{
            "source_rva": 0x1422,
            "type": 3,
            "kind": "highlow",
            "width": 4,
            "preferred_value": 0x401234,
        }],
    }


_RUNTIME_HEADER = r"""#ifndef SPX_STATE_MACHINE_RUNTIME_H
#define SPX_STATE_MACHINE_RUNTIME_H
#include <stdint.h>
typedef struct spx_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} spx_x87_value;
typedef struct spx_machine_state {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  spx_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t eflags;
  uint32_t fs_base;
  uint32_t original_rva;
} spx_machine_state;
typedef struct spx_stack_input {
  uint32_t offset, width, value;
} spx_stack_input;
typedef enum spx_call_event_kind {
  SPX_CALL_EXTERNAL_IMPORT = 0,
  SPX_CALL_INTERNAL_DIRECT = 1,
  SPX_CALL_INDIRECT = 2
} spx_call_event_kind;
typedef struct spx_call_event {
  spx_call_event_kind kind;
  uint32_t instruction_rva, call_index, target_rva, return_rva;
  const char *dll, *symbol;
  uint32_t ordinal, has_ordinal;
  const uint32_t *arguments;
  uint32_t argument_count;
  const spx_stack_input *stack_inputs;
  uint32_t stack_input_count;
} spx_call_event;
#define SPX_MAX_EXTERNAL_ARGUMENTS 256U
typedef struct spx_external_call_snapshot {
  uint32_t instruction_rva;
  uint32_t target_iat_rva;
  uint32_t argument_base_offset;
  uint32_t argument_count;
  uint32_t arguments[SPX_MAX_EXTERNAL_ARGUMENTS];
} spx_external_call_snapshot;
typedef struct spx_runtime spx_runtime;
typedef enum spx_call_status {
  SPX_CALL_OK = 0,
  SPX_CALL_UNIMPLEMENTED = 1,
  SPX_CALL_DIVIDE_ERROR = 2,
  SPX_CALL_MEMORY_FAULT = 3,
  SPX_CALL_EXTERNAL_FAULT = 4
} spx_call_status;
typedef spx_call_status (*spx_external_call_handler)(
    spx_runtime *, const spx_call_event *,
    const spx_machine_state *, spx_machine_state *);
typedef uint32_t (*spx_code_target_resolver)(
    spx_runtime *, uint32_t, uint32_t *);
struct spx_runtime {
  void *context;
  uint32_t (*read)(void *, uint32_t, uint32_t, uint32_t *);
  void (*write)(void *, uint32_t, uint32_t, uint32_t, uint32_t *);
  uint32_t (*undefined_value)(
      void *, uint32_t, const spx_machine_state *, uint32_t);
  spx_external_call_handler external_call_fallback;
  spx_code_target_resolver resolve_code_target;
  void *replay_checked_x87_command;
};
#endif
"""


def _x87_runtime_header() -> str:
    header = _RUNTIME_HEADER.replace(
        "typedef struct spx_runtime spx_runtime;",
        """typedef struct spx_typed_x87_operation {
  uint32_t image_base, rva_start, rva_end, source_size;
  const char *operation_identity;
  const char *contract_sha256;
  const char *checked_decoder;
  const char *checked_executor;
} spx_typed_x87_operation;
typedef struct spx_runtime spx_runtime;""",
    )
    header = header.replace(
        "typedef uint32_t (*spx_code_target_resolver)(",
        """typedef spx_call_status (*spx_typed_x87_handler)(
    spx_runtime *, const spx_typed_x87_operation *,
    const spx_machine_state *, spx_machine_state *);
typedef uint32_t (*spx_code_target_resolver)(""",
    )
    return header.replace(
        "  void *replay_checked_x87_command;",
        "  spx_typed_x87_handler execute_typed_x87_operation;",
    )


class NativeEngineTestCase(unittest.TestCase):
    def _write(self, root: Path, rows: list[dict]) -> Path:
        path = root / "state-machine.jsonl"
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        return path

    def _strict_inputs(
        self,
        root: Path,
        units: list[dict],
        *,
        roots: list[str] | None = None,
        reachable: list[str] | None = None,
        potential: list[str] | None = None,
    ) -> tuple[Path, Path, Path, dict[str, Path]]:
        machine_ir = root / "machine-ir.jsonl"
        machine_ir.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in units),
            encoding="utf-8",
        )
        unit_ids = [str(row["id"]) for row in units]
        manifest = root / "machine-ir-manifest.json"
        manifest.write_text(
            json.dumps(
                _implementation_manifest(machine_ir),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        sites = root / "canonical-external-sites"
        ArtifactSetWriterV3(
            artifact_kind=CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
            bindings=(),
        ).write(sites, [])
        authority = _candidate_execution_artifacts(
            root,
            units=units,
            roots=roots,
            reachable=reachable,
            complete=not potential,
        )
        authority = (*authority, _empty_callback_authority(root))
        return machine_ir, manifest, sites, {
            "root_closure": authority[0],
            "target_certificates": authority[1],
            "parametric_summaries": authority[2],
            "callback_authority": authority[3],
        }


__all__ = tuple(name for name in globals() if not name.startswith("__"))
