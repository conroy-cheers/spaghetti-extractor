"""Project checked callable-external evidence into a candidate runtime contract.

The projection has no proof authority. It gives Stage B one compact,
hash-bound description of resolver-issued callables after static analysis has
proposed corresponding resolver, value-provenance, and ABI evidence. Unknown
or ambiguous targets remain unavailable at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .errors import StageAInputError
from .external_capabilities import (
    CallableArgumentSourceSpec,
    MemoryFootprintSpec,
    parse_callable_external_capability_artifact,
)
from .external_sites import (
    parse_callable_external_execution_artifact,
)
from .util import sha256_bytes, sha256_file, write_json


CALLABLE_EXTERNAL_RUNTIME_FORMAT = "stage-b-callable-external-runtime-v1"
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

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "instruction_rva": self.instruction_rva,
            "resolver_contract_id": self.resolver_contract_id,
            "capability_id": self.capability_id,
            "result_register": self.result_register,
            "nullable": self.nullable,
        }


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
        )

    def payload(self) -> dict[str, Any]:
        return {
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
            "world_effect": "none",
        }


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

    def payload(self) -> dict[str, Any]:
        return {
            "format": CALLABLE_EXTERNAL_RUNTIME_FORMAT,
            "status": "ready",
            "identity": self.identity,
            "inputs": {
                "original_sha256": self.original_sha256,
                "state_machine_sha256": self.state_machine_sha256,
                "proposal_sha256": self.proposal_sha256,
                "capability_sha256": self.capability_sha256,
                "execution_sha256": self.execution_sha256,
                "authority_sha256": self.authority_sha256,
            },
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


def load_callable_external_runtime_contract(
    path: Path | str,
) -> CallableExternalRuntimeContract:
    payload = _read_json(path, "callable runtime contract")
    if payload.get("format") != CALLABLE_EXTERNAL_RUNTIME_FORMAT:
        raise CallableExternalRuntimeError("unsupported callable runtime format")
    if payload.get("status") != "ready":
        raise CallableExternalRuntimeError("callable runtime contract is not ready")
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
        )
        if resolver.id != index:
            raise CallableExternalRuntimeError("resolver ids are not canonical")
        resolvers.append(resolver)
    routes: list[CallableExternalRuntimeRoute] = []
    for index, raw in enumerate(_list(payload.get("routes"), "callable routes")):
        row = _object(raw, f"callable routes[{index}]")
        transfer = row.get("transfer")
        if transfer not in {"call", "jump"} or row.get("world_effect") != "none":
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
        )
        if (
            route.id != index
            or route.stack_result_delta % 4
            or route.target_origin not in {
                "writable_static_slot", "resolver_result_register"
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
        proposal_sha256=_sha256(inputs.get("proposal_sha256"), "proposal SHA-256"),
        capability_sha256=_sha256(inputs.get("capability_sha256"), "capability SHA-256"),
        execution_sha256=_sha256(inputs.get("execution_sha256"), "execution SHA-256"),
        authority_sha256=_sha256(inputs.get("authority_sha256"), "authority SHA-256"),
        resolvers=tuple(resolvers),
        routes=tuple(routes),
    )
    identity_body = {
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
    if sha256_bytes(_canonical_bytes(identity_body)) != result.identity:
        raise CallableExternalRuntimeError("callable runtime identity is stale")
    return result


__all__ = [
    "CALLABLE_EXTERNAL_RUNTIME_FORMAT",
    "CallableExternalRuntimeContract",
    "CallableExternalRuntimeError",
    "CallableExternalRuntimeRoute",
    "CallableResolverRuntimeSite",
    "build_callable_external_runtime_contract",
    "load_callable_external_runtime_contract",
    "write_callable_external_runtime_contract",
]
