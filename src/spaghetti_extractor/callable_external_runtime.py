"""Project checked callable-external evidence into a candidate runtime contract.

The projection has no proof authority. It gives Stage B one compact,
hash-bound description of resolver-issued callables after static analysis has
proposed corresponding resolver, value-provenance, and ABI evidence. Unknown
or ambiguous targets remain unavailable at runtime.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .checked_external_site_contract import (
    CheckedExternalSiteContract,
    parse_checked_external_site_contract,
)
from .errors import StageAInputError
from .external_capabilities import (
    CallableArgumentSourceSpec,
    CallableExternalProfile,
    MemoryFootprintSpec,
    load_callable_external_profile,
    parse_callable_external_capability_artifact,
)
from .external_site_proposals_v2 import parse_external_site_proposals_v2
from .external_sites import (
    parse_callable_external_execution_artifact,
)
from .util import sha256_bytes, sha256_file, write_json


CALLABLE_EXTERNAL_RUNTIME_FORMAT = "stage-b-callable-external-runtime-v1"
CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT = (
    "spaghetti-extractor-callable-external-runtime-v2"
)
CALLABLE_EXTERNAL_PROPOSAL_FORMAT = "stage-a-callable-external-proposal-v1"
WRITABLE_SLOT_AUTHORITY_FORMAT = (
    "stage-a-relocated-writable-static-pointer-slot-authorities-v2"
)


class CallableExternalRuntimeError(StageAInputError):
    """Callable evidence cannot be projected without ambiguity."""


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise CallableExternalRuntimeError(f"{context} must be a JSON object")
    return value


def _list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise CallableExternalRuntimeError(f"{context} must be a JSON array")
    return value


def _natural(value: object, context: str, *, u32: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CallableExternalRuntimeError(f"{context} must be a natural number")
    if u32 and value >= 2**32:
        raise CallableExternalRuntimeError(f"{context} must fit in PE32")
    return value


def _sha256(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CallableExternalRuntimeError(f"{context} must be a SHA-256 digest")
    return value


def _canonical_bytes(value: object) -> bytes:
    import json

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _read_json(path: Path | str, context: str) -> Mapping[str, Any]:
    import json

    source = Path(path)
    try:
        return _object(json.loads(source.read_text(encoding="utf-8")), context)
    except (OSError, UnicodeError, ValueError) as exc:
        raise CallableExternalRuntimeError(f"cannot read {context}: {exc}") from exc


def _argument_payload(source: CallableArgumentSourceSpec) -> dict[str, Any]:
    if source.kind == "register":
        return {"kind": "register", "register": source.register}
    if source.kind == "stack_word":
        return {"kind": "stack_word", "offset": source.offset}
    return {"kind": "constant", "value": source.value}


def _footprint_payload(footprint: MemoryFootprintSpec) -> dict[str, Any]:
    return {
        "access": footprint.access,
        "base_argument": footprint.base_argument,
        "offset": footprint.offset,
        "bytes": footprint.bytes,
        "nullable": footprint.nullable,
    }


@dataclass(frozen=True)
class CallableResolverRuntimeSite:
    id: int
    instruction_rva: int
    resolver_contract_id: int
    capability_id: int
    result_register: str
    nullable: bool
    source_unit_id: str | None = None
    source_event_index: int | None = None
    profile_sha256: str | None = None
    target_id: int | None = None

    def payload(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "instruction_rva": self.instruction_rva,
            "resolver_contract_id": self.resolver_contract_id,
            "capability_id": self.capability_id,
            "result_register": self.result_register,
            "nullable": self.nullable,
        }
        if self.source_unit_id is not None:
            payload.update({
                "source_unit_id": self.source_unit_id,
                "source_event_index": self.source_event_index,
                "profile_sha256": self.profile_sha256,
                "target_id": self.target_id,
            })
        return payload


@dataclass(frozen=True)
class CallableExternalRuntimeRoute:
    id: int
    source_rva: int
    instruction_rva: int
    slot_rva: int
    target_origin: str
    value_register: str | None
    transfer: str
    resolver_contract_id: int
    capability_id: int
    abi_contract_id: int
    resource_id: int
    stack_result_delta: int
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    argument_sources: tuple[CallableArgumentSourceSpec, ...]
    memory_effect: str
    memory_footprints: tuple[MemoryFootprintSpec, ...]
    world_effect: str = "none"
    source_unit_id: str | None = None
    source_event_index: int | None = None
    target_alternative_index: int | None = None
    target_alternative_sha256: str | None = None
    external_protocol: Mapping[str, Any] | None = None
    checked_external_contract: CheckedExternalSiteContract | None = None

    def semantic_key(self) -> tuple[object, ...]:
        return (
            self.source_rva,
            self.instruction_rva,
            self.slot_rva,
            self.target_origin,
            self.value_register,
            self.transfer,
            self.resolver_contract_id,
            self.capability_id,
            self.abi_contract_id,
            self.resource_id,
            self.stack_result_delta,
            self.preserved_registers,
            self.clobbered_registers,
            self.argument_sources,
            self.memory_effect,
            self.memory_footprints,
            self.world_effect,
            self.source_unit_id,
            self.source_event_index,
            self.target_alternative_index,
            self.target_alternative_sha256,
            (
                None
                if self.external_protocol is None
                else _canonical_bytes(self.external_protocol)
            ),
            (
                None
                if self.checked_external_contract is None
                else _canonical_bytes(self.checked_external_contract.payload())
            ),
        )

    def payload(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "source_rva": self.source_rva,
            "instruction_rva": self.instruction_rva,
            "slot_rva": self.slot_rva,
            "target_origin": self.target_origin,
            "value_register": self.value_register,
            "resolver_contract_id": self.resolver_contract_id,
            "capability_id": self.capability_id,
            "abi_contract_id": self.abi_contract_id,
            "resource_id": self.resource_id,
            "transfer": self.transfer,
            "argument_sources": [
                _argument_payload(source) for source in self.argument_sources
            ],
            "stack_result_delta": self.stack_result_delta,
            "preserved_registers": list(self.preserved_registers),
            "clobbered_registers": list(self.clobbered_registers),
            "memory_effect": self.memory_effect,
            "memory_footprints": [
                _footprint_payload(footprint)
                for footprint in self.memory_footprints
            ],
            "world_effect": self.world_effect,
        }
        if self.source_unit_id is not None:
            payload.update({
                "source_unit_id": self.source_unit_id,
                "source_event_index": self.source_event_index,
                "target_alternative_index": self.target_alternative_index,
                "target_alternative_sha256": self.target_alternative_sha256,
                "external_protocol": copy.deepcopy(dict(self.external_protocol or {})),
                "checked_external_contract": (
                    None
                    if self.checked_external_contract is None
                    else self.checked_external_contract.payload()
                ),
            })
        return payload


@dataclass(frozen=True)
class CallableExternalRuntimeContract:
    identity: str
    original_sha256: str
    state_machine_sha256: str
    proposal_sha256: str
    capability_sha256: str
    execution_sha256: str
    authority_sha256: str
    resolvers: tuple[CallableResolverRuntimeSite, ...]
    routes: tuple[CallableExternalRuntimeRoute, ...]
    format: str = CALLABLE_EXTERNAL_RUNTIME_FORMAT
    authority_class: str = "legacy-candidate-projection-v1"
    interprocedural_sha256: str | None = None
    external_site_proposals_sha256: str | None = None
    profile_authority_sha256: str | None = None

    def payload(self) -> dict[str, Any]:
        inputs = {
            "original_sha256": self.original_sha256,
            "state_machine_sha256": self.state_machine_sha256,
        }
        if self.format == CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT:
            inputs.update({
                "interprocedural_sha256": self.interprocedural_sha256,
                "external_site_proposals_sha256": (
                    self.external_site_proposals_sha256
                ),
                "profile_authority_sha256": self.profile_authority_sha256,
            })
        else:
            inputs.update({
                "proposal_sha256": self.proposal_sha256,
                "capability_sha256": self.capability_sha256,
                "execution_sha256": self.execution_sha256,
                "authority_sha256": self.authority_sha256,
            })
        return {
            "format": self.format,
            "status": "ready",
            "identity": self.identity,
            "authority_class": self.authority_class,
            "inputs": inputs,
            "resolver_sites": [site.payload() for site in self.resolvers],
            "routes": [route.payload() for route in self.routes],
            "counts": {
                "resolver_sites": len(self.resolvers),
                "routes": len(self.routes),
            },
            "trust": {
                "acceptance_authority": False,
                "candidate_generation_only": True,
                "static_contract_artifacts_required": True,
                "unknown_runtime_targets_rejected": True,
                "accepted_candidate_modes": (
                    ["structural-diagnostic"]
                    if self.authority_class == "diagnostic-proposal-v2"
                    else ["static-closed", "structural-diagnostic"]
                ),
            },
        }


def build_callable_external_runtime_contract(
    *,
    proposal: Mapping[str, Any],
    capability: Mapping[str, Any],
    execution: Mapping[str, Any],
    writable_slot_authority: Mapping[str, Any],
    proposal_sha256: str,
    capability_sha256: str,
    execution_sha256: str,
    authority_sha256: str,
) -> CallableExternalRuntimeContract:
    """Build a strict candidate-only projection from Stage A evidence."""

    if proposal.get("format") != CALLABLE_EXTERNAL_PROPOSAL_FORMAT:
        raise CallableExternalRuntimeError("unsupported callable proposal format")
    if proposal.get("status") != "ready" or _list(
        proposal.get("blockers"), "callable proposal blockers"
    ):
        raise CallableExternalRuntimeError("callable proposal is incomplete")
    proposal_inputs = _object(proposal.get("inputs"), "callable proposal inputs")
    original_sha256 = _sha256(
        proposal_inputs.get("original_sha256"), "callable proposal original SHA-256"
    )
    state_machine_sha256 = _sha256(
        proposal_inputs.get("state_machine_sha256"),
        "callable proposal state-machine SHA-256",
    )
    proposal_sites: dict[int, Mapping[str, Any]] = {}
    for index, raw in enumerate(_list(proposal.get("sites"), "proposal sites")):
        row = _object(raw, f"proposal sites[{index}]")
        site_id = _natural(row.get("boundary_id"), f"proposal sites[{index}].boundary_id")
        if site_id in proposal_sites:
            raise CallableExternalRuntimeError("callable proposal site ids are ambiguous")
        _natural(row.get("instruction_rva"), f"proposal sites[{index}].instruction_rva", u32=True)
        proposal_sites[site_id] = row

    capability_artifact = parse_callable_external_capability_artifact(capability)
    execution_artifact = parse_callable_external_execution_artifact(execution)
    resolver_by_id = {
        resolver.id: resolver for resolver in capability_artifact.resolver_contracts
    }
    capability_by_id = {
        item.id: item for item in capability_artifact.capabilities
    }
    abi_by_id = {
        item.id: item for item in capability_artifact.resolved_abi_contracts
    }

    resolvers: list[CallableResolverRuntimeSite] = []
    seen_capabilities: set[int] = set()
    for site in execution_artifact.sites:
        if site.kind != "resolver":
            continue
        proposal_site = proposal_sites.get(site.id)
        if proposal_site is None:
            raise CallableExternalRuntimeError(
                f"resolver site {site.id} has no exact proposal instruction"
            )
        assert site.resolver_contract_id is not None
        assert site.capability_id is not None
        resolver = resolver_by_id.get(site.resolver_contract_id)
        selected_capability = capability_by_id.get(site.capability_id)
        if (
            resolver is None
            or selected_capability is None
            or selected_capability.resolver_contract_id != resolver.id
            or resolver.machine_contract_id != site.machine_contract_id
            or site.capability_id in seen_capabilities
        ):
            raise CallableExternalRuntimeError(
                f"resolver site {site.id} has ambiguous capability authority"
            )
        seen_capabilities.add(site.capability_id)
        resolvers.append(CallableResolverRuntimeSite(
            id=len(resolvers),
            instruction_rva=_natural(
                proposal_site.get("instruction_rva"),
                f"resolver site {site.id} instruction_rva",
                u32=True,
            ),
            resolver_contract_id=resolver.id,
            capability_id=site.capability_id,
            result_register=resolver.result_register,
            nullable=resolver.nullable,
        ))
    if not resolvers:
        raise CallableExternalRuntimeError("callable runtime has no resolver sites")

    if writable_slot_authority.get("format") != WRITABLE_SLOT_AUTHORITY_FORMAT:
        raise CallableExternalRuntimeError("unsupported writable-slot authority format")
    authority_role = _object(
        writable_slot_authority.get("artifact_role"), "writable-slot artifact role"
    )
    if authority_role.get("acceptance_authority") is not False:
        raise CallableExternalRuntimeError(
            "candidate projection cannot treat writable-slot proposals as proof authority"
        )
    if _list(writable_slot_authority.get("blockers"), "writable-slot blockers"):
        raise CallableExternalRuntimeError("writable-slot authority is incomplete")
    authority_inputs = _object(
        writable_slot_authority.get("inputs"), "writable-slot inputs"
    )
    if (
        authority_inputs.get("original_sha256") != original_sha256
        or authority_inputs.get("state_machine_sha256") != state_machine_sha256
    ):
        raise CallableExternalRuntimeError(
            "callable and writable-slot artifacts bind different inputs"
        )

    raw_routes: list[CallableExternalRuntimeRoute] = []

    def add_route(
        *,
        raw_route: Mapping[str, Any],
        source_rva: int,
        instruction_rva: int,
        slot_rva: int,
        target_origin: str,
        value_register: str | None,
        transfer: str,
    ) -> None:
        resolver_id = _natural(raw_route.get("resolver_contract_id"), "route resolver id")
        capability_id = _natural(raw_route.get("capability_id"), "route capability id")
        abi_id = _natural(raw_route.get("abi_contract_id"), "route ABI id")
        resource_id = _natural(raw_route.get("resource_id"), "route resource id")
        selected_capability = capability_by_id.get(capability_id)
        abi = abi_by_id.get(abi_id)
        if (
            selected_capability is None
            or abi is None
            or selected_capability.resolver_contract_id != resolver_id
            or selected_capability.resource_id != resource_id
            or abi.capability_id != capability_id
            or abi.transfer != transfer
            or capability_id not in seen_capabilities
        ):
            raise CallableExternalRuntimeError(
                "callable route does not name one checked call/jump capability"
            )
        raw_routes.append(CallableExternalRuntimeRoute(
            id=0,
            source_rva=source_rva,
            instruction_rva=instruction_rva,
            slot_rva=slot_rva,
            target_origin=target_origin,
            value_register=value_register,
            transfer=transfer,
            resolver_contract_id=resolver_id,
            capability_id=capability_id,
            abi_contract_id=abi_id,
            resource_id=resource_id,
            stack_result_delta=abi.stack_result_delta,
            preserved_registers=abi.preserved_registers,
            clobbered_registers=abi.clobbered_registers,
            argument_sources=abi.argument_sources,
            memory_effect=abi.memory_effect,
            memory_footprints=abi.memory_footprints,
        ))

    for site_index, raw in enumerate(
        _list(writable_slot_authority.get("sites"), "writable-slot sites")
    ):
        site = _object(raw, f"writable-slot sites[{site_index}]")
        external_routes = _list(
            site.get("external_routes"),
            f"writable-slot sites[{site_index}].external_routes",
        )
        origins = site.get("write_origin_evidence", [])
        if not isinstance(origins, list):
            raise CallableExternalRuntimeError(
                f"writable-slot sites[{site_index}].write_origin_evidence must be an array"
            )
        if not external_routes and not origins:
            continue
        if (
            site.get("transfer_kind") not in {"call", "jump"}
            or site.get("value_relation") != "finite_origins"
        ):
            raise CallableExternalRuntimeError(
                "callable writable-slot authority is not a finite-origin call/jump"
            )
        source_rva = _natural(site.get("source_rva"), "callable source RVA", u32=True)
        transfer = str(site.get("transfer_kind"))
        instruction_rva = _natural(
            site.get("instruction_rva"), "callable instruction RVA", u32=True
        )
        slot_rva = _natural(site.get("slot_rva"), "callable slot RVA", u32=True)
        for route_index, raw_route in enumerate(external_routes):
            route = _object(
                raw_route,
                f"writable-slot sites[{site_index}].external_routes[{route_index}]",
            )
            add_route(
                raw_route=route,
                source_rva=source_rva,
                instruction_rva=instruction_rva,
                slot_rva=slot_rva,
                target_origin="writable_static_slot",
                value_register=None,
                transfer=transfer,
            )

        for origin_index, raw_origin in enumerate(origins):
            origin = _object(
                raw_origin,
                f"writable-slot sites[{site_index}].write_origin_evidence[{origin_index}]",
            )
            origin_routes = _list(
                origin.get("external_routes"),
                f"writable-slot sites[{site_index}].write_origin_evidence"
                f"[{origin_index}].external_routes",
            )
            if not origin_routes:
                continue
            tail_rva = _natural(
                origin.get("tail_instruction_rva"),
                "callable write-origin tail instruction RVA",
                u32=True,
            )
            origin_source_rva = _natural(
                origin.get("source_rva"), "callable write-origin source RVA", u32=True
            )
            value_register = origin.get("value_register")
            if value_register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}:
                raise CallableExternalRuntimeError(
                    "callable write-origin route has no supported value register"
                )
            for route_index, raw_route in enumerate(origin_routes):
                route = _object(
                    raw_route,
                    f"writable-slot sites[{site_index}].write_origin_evidence"
                    f"[{origin_index}].external_routes[{route_index}]",
                )
                add_route(
                    raw_route=route,
                    source_rva=origin_source_rva,
                    instruction_rva=tail_rva,
                    slot_rva=slot_rva,
                    target_origin="resolver_result_register",
                    value_register=value_register,
                    transfer=transfer,
                )
    if not raw_routes:
        raise CallableExternalRuntimeError("callable runtime has no finite-origin routes")
    keys = [route.semantic_key() for route in raw_routes]
    if len(set(keys)) != len(keys):
        raise CallableExternalRuntimeError("callable runtime routes are duplicated")
    routes = tuple(
        CallableExternalRuntimeRoute(
            **{**route.__dict__, "id": index}
        )
        for index, route in enumerate(
            sorted(raw_routes, key=CallableExternalRuntimeRoute.semantic_key)
        )
    )
    identity_body = {
        "format": CALLABLE_EXTERNAL_RUNTIME_FORMAT,
        "inputs": {
            "proposal_sha256": proposal_sha256,
            "capability_sha256": capability_sha256,
            "execution_sha256": execution_sha256,
            "authority_sha256": authority_sha256,
        },
        "resolver_sites": [site.payload() for site in resolvers],
        "routes": [route.payload() for route in routes],
    }
    return CallableExternalRuntimeContract(
        identity=sha256_bytes(_canonical_bytes(identity_body)),
        original_sha256=original_sha256,
        state_machine_sha256=state_machine_sha256,
        proposal_sha256=_sha256(proposal_sha256, "proposal SHA-256"),
        capability_sha256=_sha256(capability_sha256, "capability SHA-256"),
        execution_sha256=_sha256(execution_sha256, "execution SHA-256"),
        authority_sha256=_sha256(authority_sha256, "authority SHA-256"),
        resolvers=tuple(resolvers),
        routes=routes,
    )


def build_callable_external_runtime_contract_v2(
    *,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    interprocedural: Mapping[str, Any],
    external_site_proposals: Mapping[str, Any],
    callable_profiles: Sequence[CallableExternalProfile],
    original_sha256: str,
    machine_ir_sha256: str,
    interprocedural_sha256: str,
    external_site_proposals_sha256: str,
    profile_authority_sha256: str,
    authority_class: str = "diagnostic-proposal-v2",
) -> CallableExternalRuntimeContract:
    """Project v2 resolver provenance into a guarded candidate contract.

    This projection deliberately accepts a proposal-only interprocedural seed
    only for structural-diagnostic candidates.  It never upgrades that seed to
    static authority: the runtime records the exact resolver result and checks
    every later indirect call against that live value before dispatch.
    """

    original_sha256 = _sha256(original_sha256, "original SHA-256")
    machine_ir_sha256 = _sha256(machine_ir_sha256, "machine-IR SHA-256")
    interprocedural_sha256 = _sha256(
        interprocedural_sha256, "interprocedural SHA-256"
    )
    external_site_proposals_sha256 = _sha256(
        external_site_proposals_sha256, "external-site proposal SHA-256"
    )
    profile_authority_sha256 = _sha256(
        profile_authority_sha256, "profile-authority SHA-256"
    )
    if authority_class not in {
        "diagnostic-proposal-v2",
        "static-authority-v2",
    }:
        raise CallableExternalRuntimeError(
            "callable runtime authority class is unsupported"
        )
    if interprocedural.get("format") != "stage-a-interprocedural-analysis-v2":
        raise CallableExternalRuntimeError(
            "callable runtime requires v2 interprocedural evidence"
        )
    fixed_point = _object(
        interprocedural.get("fixed_point"), "interprocedural fixed point"
    )
    if authority_class == "diagnostic-proposal-v2":
        if fixed_point.get("proposal_only") is not True:
            raise CallableExternalRuntimeError(
                "diagnostic callable runtime requires a proposal-only seed"
            )
    elif (
        fixed_point.get("proposal_only") is True
        or fixed_point.get("cold_replay_validated") is not True
        or fixed_point.get("authority_replay_validated") is not True
    ):
        raise CallableExternalRuntimeError(
            "static callable runtime requires cold-replayed authority"
        )

    proposals = parse_external_site_proposals_v2(
        external_site_proposals,
        pe_sha256=original_sha256,
        machine_ir_sha256=machine_ir_sha256,
    )
    profiles_by_sha: dict[str, CallableExternalProfile] = {}
    profiles_by_id: dict[str, CallableExternalProfile] = {}
    for profile in callable_profiles:
        if (
            profile.sha256 in profiles_by_sha
            or profile.profile_id in profiles_by_id
        ):
            raise CallableExternalRuntimeError(
                "callable runtime profiles are ambiguous"
            )
        profiles_by_sha[profile.sha256] = profile
        profiles_by_id[profile.profile_id] = profile
    if not profiles_by_sha:
        raise CallableExternalRuntimeError("callable runtime has no selected profiles")

    rows_by_id: dict[str, Mapping[str, Any]] = {}
    for raw in machine_ir_rows:
        unit_id = raw.get("id")
        if not isinstance(unit_id, str) or not unit_id:
            raise CallableExternalRuntimeError("machine-IR unit has no stable id")
        if unit_id in rows_by_id:
            raise CallableExternalRuntimeError("machine-IR unit ids are ambiguous")
        rows_by_id[unit_id] = raw

    recoveries = {
        (str(raw.get("source_unit_id")), raw.get("source_event_index")): raw
        for raw in interprocedural.get("recovered_targets", ())
        if isinstance(raw, Mapping)
        and isinstance(raw.get("source_unit_id"), str)
        and isinstance(raw.get("source_event_index"), int)
    }
    route_records: list[
        tuple[
            Mapping[str, Any],
            CheckedExternalSiteContract,
            Mapping[str, Any],
            CallableExternalProfile,
            Any,
            Any,
            Mapping[str, Any],
        ]
    ] = []
    target_keys: set[tuple[str, int]] = set()
    for raw in proposals:
        unit_id = str(raw["unit_id"])
        event_index = int(raw["event_index"])
        checked = parse_checked_external_site_contract(
            _object(raw.get("contract"), "checked external contract"),
            context=f"{unit_id}:{event_index}",
        )
        if checked.identity.kind != "resolved_export":
            continue
        recovery = recoveries.get((unit_id, event_index))
        if not isinstance(recovery, Mapping) or recovery.get("status") != "recovered":
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} has no recovery"
            )
        alternatives = recovery.get("external_targets")
        if not isinstance(alternatives, list):
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} has malformed alternatives"
            )
        alternative_sha256 = str(raw["target_alternative_sha256"])
        matches = [
            target
            for target in alternatives
            if isinstance(target, Mapping)
            and sha256_bytes(_canonical_bytes(target)) == alternative_sha256
        ]
        if len(matches) != 1:
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} alternative is ambiguous"
            )
        target_json = matches[0]
        protocol = _object(
            target_json.get("external_protocol"),
            f"resolved-export site {unit_id}:{event_index} protocol",
        )
        profile_sha256 = _sha256(
            protocol.get("profile_sha256"), "resolved-export profile SHA-256"
        )
        profile = profiles_by_sha.get(profile_sha256)
        if (
            profile is None
            or protocol.get("profile_id") != profile.profile_id
        ):
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} names an unselected profile"
            )
        target_id = _natural(
            protocol.get("target_id"), "resolved-export target id"
        )
        target = profile.target_by_id(target_id)
        if target is None or checked.transfer_kind not in target.transfers:
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} target is unsupported"
            )
        resolver = profile.resolver_by_id().get(target.resolver_id)
        if resolver is None:
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} resolver is missing"
            )
        row = rows_by_id.get(unit_id)
        event = _machine_ir_event(row, event_index, unit_id)
        if event.get("instruction_rva") is None:
            raise CallableExternalRuntimeError(
                f"resolved-export site {unit_id}:{event_index} has no instruction RVA"
            )
        route_records.append((
            raw,
            checked,
            protocol,
            profile,
            target,
            resolver,
            event,
        ))
        target_keys.add((profile.sha256, target.id))
    if not route_records:
        raise CallableExternalRuntimeError(
            "callable runtime has no checked resolved-export routes"
        )
    capability_ids = {
        key: index for index, key in enumerate(sorted(target_keys))
    }

    recoveries_by_target: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    provenance = _object(
        interprocedural.get("operation_provenance"), "operation provenance"
    )
    for raw in provenance.get("call_argument_recoveries", ()):
        if not isinstance(raw, Mapping) or raw.get("status") != "complete":
            continue
        callable_resolver = raw.get("callable_resolver")
        resolved_target = raw.get("resolved_target")
        if not isinstance(callable_resolver, Mapping) or not isinstance(
            resolved_target, Mapping
        ):
            continue
        profile_sha256 = callable_resolver.get("profile_sha256")
        target_id = resolved_target.get("target_id")
        if isinstance(profile_sha256, str) and isinstance(target_id, int):
            recoveries_by_target.setdefault(
                (profile_sha256, target_id), []
            ).append(raw)

    resolver_sites: list[CallableResolverRuntimeSite] = []
    seen_resolver_sites: set[tuple[str, int, tuple[str, int]]] = set()
    for key in sorted(target_keys):
        profile = profiles_by_sha[key[0]]
        target = profile.target_by_id(key[1])
        assert target is not None
        resolver = profile.resolver_by_id()[target.resolver_id]
        recoveries_for_target = recoveries_by_target.get(key, [])
        if not recoveries_for_target:
            raise CallableExternalRuntimeError(
                f"callable target {profile.profile_id}:{target.id} has no resolver callsite"
            )
        for recovery in recoveries_for_target:
            unit_id = recovery.get("unit_id")
            event_index = recovery.get("event_index")
            if not isinstance(unit_id, str) or not isinstance(event_index, int):
                raise CallableExternalRuntimeError(
                    "callable resolver recovery has no exact unit/event identity"
                )
            event = _machine_ir_event(rows_by_id.get(unit_id), event_index, unit_id)
            if not _event_matches_import(event, resolver.identity.dll, resolver.identity.kind, resolver.identity.value):
                raise CallableExternalRuntimeError(
                    f"callable resolver recovery {unit_id}:{event_index} names a different import"
                )
            instruction_rva = _natural(
                event.get("instruction_rva"), "resolver instruction RVA", u32=True
            )
            site_key = (unit_id, event_index, key)
            if site_key in seen_resolver_sites:
                raise CallableExternalRuntimeError("callable resolver sites are duplicated")
            seen_resolver_sites.add(site_key)
            resolver_sites.append(CallableResolverRuntimeSite(
                id=0,
                instruction_rva=instruction_rva,
                resolver_contract_id=capability_ids[key],
                capability_id=capability_ids[key],
                result_register=resolver.result_register,
                nullable=resolver.nullable,
                source_unit_id=unit_id,
                source_event_index=event_index,
                profile_sha256=profile.sha256,
                target_id=target.id,
            ))
    resolver_sites = [
        CallableResolverRuntimeSite(**{**site.__dict__, "id": index})
        for index, site in enumerate(sorted(
            resolver_sites,
            key=lambda site: (
                site.instruction_rva,
                str(site.source_unit_id),
                int(site.source_event_index or 0),
                site.capability_id,
            ),
        ))
    ]

    raw_routes: list[CallableExternalRuntimeRoute] = []
    for (
        raw,
        checked,
        protocol,
        profile,
        target,
        resolver,
        event,
    ) in route_records:
        unit_id = str(raw["unit_id"])
        event_index = int(raw["event_index"])
        expression = event.get("target")
        register = (
            str(expression.get("name")).lower()
            if isinstance(expression, Mapping)
            and expression.get("op") == "reg"
            and isinstance(expression.get("name"), str)
            else None
        )
        source = _object(
            rows_by_id[unit_id].get("source"), f"{unit_id} source"
        )
        original = _object(source.get("original"), f"{unit_id} original source")
        abi = target.abi
        raw_routes.append(CallableExternalRuntimeRoute(
            id=0,
            source_rva=_natural(
                original.get("rva_start"), f"{unit_id} source RVA", u32=True
            ),
            instruction_rva=_natural(
                event.get("instruction_rva"), f"{unit_id} instruction RVA", u32=True
            ),
            slot_rva=0,
            target_origin=(
                "resolver_result_register"
                if register is not None
                else "checked_resolved_export_expression"
            ),
            value_register=register,
            transfer=checked.transfer_kind,
            resolver_contract_id=capability_ids[(profile.sha256, target.id)],
            capability_id=capability_ids[(profile.sha256, target.id)],
            abi_contract_id=capability_ids[(profile.sha256, target.id)],
            resource_id=capability_ids[(profile.sha256, target.id)],
            stack_result_delta=(
                4 + (
                    checked.argument_words * 4
                    if checked.abi_template == "pe32-stdcall-v1"
                    else 0
                )
            ),
            preserved_registers=abi.preserved_registers,
            clobbered_registers=abi.clobbered_registers,
            argument_sources=tuple(
                CallableArgumentSourceSpec(kind="stack_word", offset=item.offset)
                for item in checked.stack_arguments
            ),
            memory_effect=checked.memory_effect,
            memory_footprints=_fixed_memory_footprints(checked),
            world_effect=checked.world_effect,
            source_unit_id=unit_id,
            source_event_index=event_index,
            target_alternative_index=int(raw["target_alternative_index"]),
            target_alternative_sha256=str(raw["target_alternative_sha256"]),
            external_protocol=copy.deepcopy(dict(protocol)),
            checked_external_contract=checked,
        ))
    keys = [route.semantic_key() for route in raw_routes]
    if len(keys) != len(set(keys)):
        raise CallableExternalRuntimeError("callable runtime routes are duplicated")
    routes = tuple(
        CallableExternalRuntimeRoute(**{**route.__dict__, "id": index})
        for index, route in enumerate(
            sorted(raw_routes, key=CallableExternalRuntimeRoute.semantic_key)
        )
    )
    identity_body = {
        "format": CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT,
        "authority_class": authority_class,
        "inputs": {
            "original_sha256": original_sha256,
            "state_machine_sha256": machine_ir_sha256,
            "interprocedural_sha256": interprocedural_sha256,
            "external_site_proposals_sha256": external_site_proposals_sha256,
            "profile_authority_sha256": profile_authority_sha256,
        },
        "resolver_sites": [site.payload() for site in resolver_sites],
        "routes": [route.payload() for route in routes],
    }
    return CallableExternalRuntimeContract(
        identity=sha256_bytes(_canonical_bytes(identity_body)),
        original_sha256=original_sha256,
        state_machine_sha256=machine_ir_sha256,
        proposal_sha256=external_site_proposals_sha256,
        capability_sha256=profile_authority_sha256,
        execution_sha256=interprocedural_sha256,
        authority_sha256=interprocedural_sha256,
        resolvers=tuple(resolver_sites),
        routes=routes,
        format=CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT,
        authority_class=authority_class,
        interprocedural_sha256=interprocedural_sha256,
        external_site_proposals_sha256=external_site_proposals_sha256,
        profile_authority_sha256=profile_authority_sha256,
    )


def _machine_ir_event(
    row: Mapping[str, Any] | None,
    event_index: int,
    unit_id: str,
) -> Mapping[str, Any]:
    if row is None:
        raise CallableExternalRuntimeError(f"machine-IR unit {unit_id} is missing")
    semantics = _object(row.get("semantics"), f"{unit_id} semantics")
    events = _list(semantics.get("external_events"), f"{unit_id} events")
    if event_index < 0 or event_index >= len(events):
        raise CallableExternalRuntimeError(
            f"machine-IR unit {unit_id} event index is out of range"
        )
    return _object(events[event_index], f"{unit_id} event {event_index}")


def _event_matches_import(
    event: Mapping[str, Any], dll: str, kind: str, value: str | int
) -> bool:
    if str(event.get("dll") or "").lower() != dll.lower():
        return False
    return event.get(kind) == value


def _fixed_memory_footprints(
    checked: CheckedExternalSiteContract,
) -> tuple[MemoryFootprintSpec, ...]:
    result: list[MemoryFootprintSpec] = []
    for index, raw in enumerate(checked.memory_footprints):
        row = _object(raw, f"memory footprint {index}")
        size = row.get("byte_count", row.get("bytes"))
        if not isinstance(size, int):
            raise CallableExternalRuntimeError(
                "callable runtime currently requires fixed memory footprints"
            )
        result.append(MemoryFootprintSpec(
            access=str(row.get("access")),
            base_argument=_natural(
                row.get("base_argument"), "memory footprint base argument"
            ),
            offset=_natural(row.get("offset", 0), "memory footprint offset", u32=True),
            bytes=_natural(size, "memory footprint size", u32=True),
            nullable=bool(row.get("nullable", False)),
        ))
    return tuple(result)


def write_callable_external_runtime_contract(
    *,
    proposal: Path | str,
    capability: Path | str,
    execution: Path | str,
    writable_slot_authority: Path | str,
    out: Path | str,
) -> CallableExternalRuntimeContract:
    proposal_path = Path(proposal)
    capability_path = Path(capability)
    execution_path = Path(execution)
    authority_path = Path(writable_slot_authority)
    contract = build_callable_external_runtime_contract(
        proposal=_read_json(proposal_path, "callable proposal"),
        capability=_read_json(capability_path, "callable capability"),
        execution=_read_json(execution_path, "callable execution"),
        writable_slot_authority=_read_json(
            authority_path, "writable-slot authority"
        ),
        proposal_sha256=sha256_file(proposal_path),
        capability_sha256=sha256_file(capability_path),
        execution_sha256=sha256_file(execution_path),
        authority_sha256=sha256_file(authority_path),
    )
    write_json(Path(out), contract.payload())
    return contract


def write_callable_external_runtime_contract_v2(
    *,
    original: Path | str,
    machine_ir: Path | str,
    interprocedural: Path | str,
    external_site_proposals: Path | str,
    profile_authority: Path | str,
    callable_profiles: Sequence[Path | str],
    out: Path | str,
    authority_class: str = "diagnostic-proposal-v2",
) -> CallableExternalRuntimeContract:
    import json

    original_path = Path(original)
    machine_ir_path = Path(machine_ir)
    interprocedural_path = Path(interprocedural)
    proposals_path = Path(external_site_proposals)
    profile_authority_path = Path(profile_authority)
    try:
        rows = tuple(
            _object(json.loads(line), f"machine-IR line {line_number}")
            for line_number, line in enumerate(
                machine_ir_path.read_text(encoding="utf-8").splitlines(), 1
            )
            if line.strip()
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise CallableExternalRuntimeError(
            f"cannot read callable runtime machine IR: {exc}"
        ) from exc
    contract = build_callable_external_runtime_contract_v2(
        machine_ir_rows=rows,
        interprocedural=_read_json(interprocedural_path, "interprocedural evidence"),
        external_site_proposals=_read_json(
            proposals_path, "external-site proposals"
        ),
        callable_profiles=tuple(
            load_callable_external_profile(path) for path in callable_profiles
        ),
        original_sha256=sha256_file(original_path),
        machine_ir_sha256=sha256_file(machine_ir_path),
        interprocedural_sha256=sha256_file(interprocedural_path),
        external_site_proposals_sha256=sha256_file(proposals_path),
        profile_authority_sha256=sha256_file(profile_authority_path),
        authority_class=authority_class,
    )
    write_json(Path(out), contract.payload())
    return contract


def load_callable_external_runtime_contract(
    path: Path | str,
) -> CallableExternalRuntimeContract:
    payload = _read_json(path, "callable runtime contract")
    runtime_format = payload.get("format")
    if runtime_format not in {
        CALLABLE_EXTERNAL_RUNTIME_FORMAT,
        CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT,
    }:
        raise CallableExternalRuntimeError("unsupported callable runtime format")
    if payload.get("status") != "ready":
        raise CallableExternalRuntimeError("callable runtime contract is not ready")
    authority_class = payload.get("authority_class")
    if runtime_format == CALLABLE_EXTERNAL_RUNTIME_FORMAT:
        if authority_class not in {None, "legacy-candidate-projection-v1"}:
            raise CallableExternalRuntimeError(
                "legacy callable runtime has an invalid authority class"
            )
        authority_class = "legacy-candidate-projection-v1"
    elif authority_class not in {
        "diagnostic-proposal-v2",
        "static-authority-v2",
    }:
        raise CallableExternalRuntimeError(
            "v2 callable runtime has an invalid authority class"
        )
    inputs = _object(payload.get("inputs"), "callable runtime inputs")
    resolvers: list[CallableResolverRuntimeSite] = []
    for index, raw in enumerate(_list(payload.get("resolver_sites"), "resolver sites")):
        row = _object(raw, f"resolver sites[{index}]")
        register = row.get("result_register")
        nullable = row.get("nullable")
        if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}:
            raise CallableExternalRuntimeError("resolver result register is unsupported")
        if not isinstance(nullable, bool):
            raise CallableExternalRuntimeError("resolver nullable flag is malformed")
        resolver = CallableResolverRuntimeSite(
            id=_natural(row.get("id"), "resolver id"),
            instruction_rva=_natural(row.get("instruction_rva"), "resolver RVA", u32=True),
            resolver_contract_id=_natural(row.get("resolver_contract_id"), "resolver contract id"),
            capability_id=_natural(row.get("capability_id"), "resolver capability id"),
            result_register=register,
            nullable=nullable,
            source_unit_id=(
                str(row["source_unit_id"])
                if row.get("source_unit_id") is not None
                else None
            ),
            source_event_index=(
                _natural(row.get("source_event_index"), "resolver event index")
                if row.get("source_unit_id") is not None
                else None
            ),
            profile_sha256=(
                _sha256(row.get("profile_sha256"), "resolver profile SHA-256")
                if row.get("source_unit_id") is not None
                else None
            ),
            target_id=(
                _natural(row.get("target_id"), "resolver target id")
                if row.get("source_unit_id") is not None
                else None
            ),
        )
        if (
            resolver.id != index
            or (
                runtime_format == CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT
                and (
                    not resolver.source_unit_id
                    or resolver.source_event_index is None
                    or resolver.profile_sha256 is None
                    or resolver.target_id is None
                )
            )
        ):
            raise CallableExternalRuntimeError("resolver ids are not canonical")
        resolvers.append(resolver)
    routes: list[CallableExternalRuntimeRoute] = []
    for index, raw in enumerate(_list(payload.get("routes"), "callable routes")):
        row = _object(raw, f"callable routes[{index}]")
        transfer = row.get("transfer")
        world_effect = row.get("world_effect")
        if (
            transfer not in {"call", "jump"}
            or not isinstance(world_effect, str)
            or not world_effect
            or (
                runtime_format == CALLABLE_EXTERNAL_RUNTIME_FORMAT
                and world_effect != "none"
            )
        ):
            raise CallableExternalRuntimeError("runtime route is not a supported call/jump")
        arguments = tuple(
            CallableArgumentSourceSpec.parse(item, f"callable routes[{index}].argument_sources[{position}]")
            for position, item in enumerate(_list(row.get("argument_sources"), "route arguments"))
        )
        footprints = tuple(
            MemoryFootprintSpec(
                access=str(item.get("access")),
                base_argument=_natural(item.get("base_argument"), "footprint base"),
                offset=_natural(item.get("offset"), "footprint offset", u32=True),
                bytes=_natural(item.get("bytes"), "footprint bytes", u32=True),
                nullable=bool(item.get("nullable")),
            )
            for item in (
                _object(value, "route footprint")
                for value in _list(row.get("memory_footprints"), "route footprints")
            )
        )
        route = CallableExternalRuntimeRoute(
            id=_natural(row.get("id"), "route id"),
            source_rva=_natural(row.get("source_rva"), "route source RVA", u32=True),
            instruction_rva=_natural(row.get("instruction_rva"), "route instruction RVA", u32=True),
            slot_rva=_natural(row.get("slot_rva"), "route slot RVA", u32=True),
            target_origin=str(row.get("target_origin")),
            value_register=(
                str(row["value_register"])
                if row.get("value_register") is not None
                else None
            ),
            transfer=str(transfer),
            resolver_contract_id=_natural(row.get("resolver_contract_id"), "route resolver id"),
            capability_id=_natural(row.get("capability_id"), "route capability id"),
            abi_contract_id=_natural(row.get("abi_contract_id"), "route ABI id"),
            resource_id=_natural(row.get("resource_id"), "route resource id"),
            stack_result_delta=_natural(row.get("stack_result_delta"), "route stack delta", u32=True),
            preserved_registers=tuple(_list(row.get("preserved_registers"), "preserved registers")),
            clobbered_registers=tuple(_list(row.get("clobbered_registers"), "clobbered registers")),
            argument_sources=arguments,
            memory_effect=str(row.get("memory_effect")),
            memory_footprints=footprints,
            world_effect=str(row.get("world_effect")),
            source_unit_id=(
                str(row["source_unit_id"])
                if row.get("source_unit_id") is not None
                else None
            ),
            source_event_index=(
                _natural(row.get("source_event_index"), "route event index")
                if row.get("source_unit_id") is not None
                else None
            ),
            target_alternative_index=(
                _natural(
                    row.get("target_alternative_index"),
                    "route target alternative index",
                )
                if row.get("source_unit_id") is not None
                else None
            ),
            target_alternative_sha256=(
                _sha256(
                    row.get("target_alternative_sha256"),
                    "route target alternative SHA-256",
                )
                if row.get("source_unit_id") is not None
                else None
            ),
            external_protocol=(
                copy.deepcopy(dict(_object(
                    row.get("external_protocol"), "route external protocol"
                )))
                if row.get("source_unit_id") is not None
                else None
            ),
            checked_external_contract=(
                parse_checked_external_site_contract(
                    _object(
                        row.get("checked_external_contract"),
                        "route checked external contract",
                    ),
                    context=f"callable routes[{index}]",
                )
                if row.get("source_unit_id") is not None
                else None
            ),
        )
        if (
            route.id != index
            or route.stack_result_delta % 4
            or route.target_origin not in {
                "writable_static_slot",
                "resolver_result_register",
                "checked_resolved_export_expression",
            }
            or (
                route.target_origin == "writable_static_slot"
                and route.value_register is not None
            )
            or (
                route.target_origin == "resolver_result_register"
                and route.value_register
                not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}
            )
            or (
                route.target_origin == "checked_resolved_export_expression"
                and route.value_register is not None
            )
            or (
                runtime_format == CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT
                and (
                    not route.source_unit_id
                    or route.source_event_index is None
                    or route.target_alternative_index is None
                    or route.target_alternative_sha256 is None
                    or not route.external_protocol
                    or route.checked_external_contract is None
                    or route.checked_external_contract.transfer_kind
                    != route.transfer
                )
            )
        ):
            raise CallableExternalRuntimeError("route ids or stack delta are malformed")
        routes.append(route)
    if not resolvers or not routes:
        raise CallableExternalRuntimeError("callable runtime inventory is empty")
    counts = _object(payload.get("counts"), "callable runtime counts")
    if (
        counts.get("resolver_sites") != len(resolvers)
        or counts.get("routes") != len(routes)
    ):
        raise CallableExternalRuntimeError("callable runtime counts are stale")
    result = CallableExternalRuntimeContract(
        identity=_sha256(payload.get("identity"), "callable runtime identity"),
        original_sha256=_sha256(inputs.get("original_sha256"), "original SHA-256"),
        state_machine_sha256=_sha256(inputs.get("state_machine_sha256"), "state-machine SHA-256"),
        proposal_sha256=_sha256(
            inputs.get(
                "proposal_sha256", inputs.get("external_site_proposals_sha256")
            ),
            "proposal SHA-256",
        ),
        capability_sha256=_sha256(
            inputs.get("capability_sha256", inputs.get("profile_authority_sha256")),
            "capability SHA-256",
        ),
        execution_sha256=_sha256(
            inputs.get("execution_sha256", inputs.get("interprocedural_sha256")),
            "execution SHA-256",
        ),
        authority_sha256=_sha256(
            inputs.get("authority_sha256", inputs.get("interprocedural_sha256")),
            "authority SHA-256",
        ),
        resolvers=tuple(resolvers),
        routes=tuple(routes),
        format=str(runtime_format),
        authority_class=str(authority_class),
        interprocedural_sha256=(
            _sha256(
                inputs.get("interprocedural_sha256"),
                "interprocedural SHA-256",
            )
            if runtime_format == CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT
            else None
        ),
        external_site_proposals_sha256=(
            _sha256(
                inputs.get("external_site_proposals_sha256"),
                "external-site proposal SHA-256",
            )
            if runtime_format == CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT
            else None
        ),
        profile_authority_sha256=(
            _sha256(
                inputs.get("profile_authority_sha256"),
                "profile-authority SHA-256",
            )
            if runtime_format == CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT
            else None
        ),
    )
    identity_body = (
        {
            "format": CALLABLE_EXTERNAL_RUNTIME_FORMAT,
            "inputs": {
                "proposal_sha256": result.proposal_sha256,
                "capability_sha256": result.capability_sha256,
                "execution_sha256": result.execution_sha256,
                "authority_sha256": result.authority_sha256,
            },
            "resolver_sites": [site.payload() for site in result.resolvers],
            "routes": [route.payload() for route in result.routes],
        }
        if runtime_format == CALLABLE_EXTERNAL_RUNTIME_FORMAT
        else {
            "format": CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT,
            "authority_class": result.authority_class,
            "inputs": {
                "original_sha256": result.original_sha256,
                "state_machine_sha256": result.state_machine_sha256,
                "interprocedural_sha256": result.interprocedural_sha256,
                "external_site_proposals_sha256": (
                    result.external_site_proposals_sha256
                ),
                "profile_authority_sha256": result.profile_authority_sha256,
            },
            "resolver_sites": [site.payload() for site in result.resolvers],
            "routes": [route.payload() for route in result.routes],
        }
    )
    if sha256_bytes(_canonical_bytes(identity_body)) != result.identity:
        raise CallableExternalRuntimeError("callable runtime identity is stale")
    return result


__all__ = [
    "CALLABLE_EXTERNAL_RUNTIME_FORMAT",
    "CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT",
    "CallableExternalRuntimeContract",
    "CallableExternalRuntimeError",
    "CallableExternalRuntimeRoute",
    "CallableResolverRuntimeSite",
    "build_callable_external_runtime_contract",
    "build_callable_external_runtime_contract_v2",
    "load_callable_external_runtime_contract",
    "write_callable_external_runtime_contract",
    "write_callable_external_runtime_contract_v2",
]
