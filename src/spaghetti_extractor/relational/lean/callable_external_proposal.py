"""Discover resolver-issued callable capabilities from exact static evidence.

Resolver and resolved-symbol semantics are declarative profile data.  This
scanner binds those declarations to an exact imported-call boundary, exact
stack argument expressions, and immutable PE bytes.  It never submits a
runtime function-pointer value: resolver refinement is the only authority for
the concrete paired capability later observed at execution time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from ...errors import StageAInputError
from .callable_external_capability import (
    CALLABLE_EXTERNAL_CAPABILITY_FORMAT,
    CallableArgumentSourceSpec,
    ResolvedExternalABIContractSpec,
)
from .interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    OriginalCallableExternalRouteBinding,
    OriginalStaticDataBinding,
)
from .static_machine_import_contracts import STATIC_MACHINE_IMPORT_FORMAT


CALLABLE_EXTERNAL_PROFILE_FORMAT = "stage-a-callable-external-profile-v1"
CALLABLE_EXTERNAL_PROPOSAL_FORMAT = "stage-a-callable-external-proposal-v1"

_PROFILE_FIELDS = frozenset({"format", "id", "resolvers", "targets"})
_RESOLVER_FIELDS = frozenset({
    "id",
    "import",
    "result_register",
    "identity_argument_indices",
    "nullable",
})
_TARGET_FIELDS = frozenset({
    "id",
    "resolver_id",
    "identity_arguments",
    "abis",
})
_IMPORT_FIELDS = frozenset({"dll", "symbol"})
_STRING_IDENTITY_FIELDS = frozenset({"kind", "index", "bytes"})
_EXACT_IDENTITY_FIELDS = frozenset({"kind", "index", "value"})
_ABI_FIELDS = frozenset({
    "transfer",
    "argument_sources",
    "stack_result_delta",
    "preserved_registers",
    "clobbered_registers",
    "memory_effect",
    "memory_footprints",
    "world_effect",
})
_FOOTPRINT_FIELDS = frozenset({
    "access",
    "base_argument",
    "offset",
    "bytes",
    "nullable",
})
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"})
_IMAGE_SCN_MEM_WRITE = 0x80000000
_IMAGE_SCN_MEM_EXECUTE = 0x20000000


class CallableExternalProposalError(StageAInputError):
    """Callable resolver profile or exact static evidence is malformed."""


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CallableExternalProposalError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise CallableExternalProposalError(f"{context} field names must be strings")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise CallableExternalProposalError(f"{context} must be an array")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise CallableExternalProposalError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise CallableExternalProposalError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _natural(value: object, context: str, *, u32: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CallableExternalProposalError(f"{context} must be a natural number")
    if u32 and value >= 2**32:
        raise CallableExternalProposalError(f"{context} must fit in PE32")
    return value


def _bytes(value: object, context: str) -> bytes:
    values = tuple(
        _natural(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context))
    )
    if any(item > 0xFF for item in values):
        raise CallableExternalProposalError(
            f"{context} contains a value outside the byte range"
        )
    result = bytes(values)
    if not result or b"\0" in result:
        raise CallableExternalProposalError(
            f"{context} must be nonempty bytes without a terminator"
        )
    return result


@dataclass(frozen=True, order=True)
class CallableImportIdentity:
    dll: str
    symbol: str

    @classmethod
    def parse(cls, value: object, context: str) -> "CallableImportIdentity":
        item = _object(value, context)
        _exact_fields(item, _IMPORT_FIELDS, context)
        dll = item["dll"]
        symbol = item["symbol"]
        if (
            not isinstance(dll, str)
            or not dll
            or not dll.isascii()
            or not isinstance(symbol, str)
            or not symbol
            or not symbol.isascii()
        ):
            raise CallableExternalProposalError(
                f"{context} requires nonempty ASCII dll and symbol"
            )
        return cls(dll=dll.lower(), symbol=symbol)


@dataclass(frozen=True)
class CallableIdentityProfile:
    kind: str
    index: int
    bytes: bytes | None = None
    value: int | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "CallableIdentityProfile":
        item = _object(value, context)
        kind = item.get("kind")
        if kind == "canonical_static_string":
            _exact_fields(item, _STRING_IDENTITY_FIELDS, context)
            return cls(
                kind=kind,
                index=_natural(item["index"], f"{context}.index"),
                bytes=_bytes(item["bytes"], f"{context}.bytes"),
            )
        if kind == "exact_word":
            _exact_fields(item, _EXACT_IDENTITY_FIELDS, context)
            return cls(
                kind=kind,
                index=_natural(item["index"], f"{context}.index"),
                value=_natural(item["value"], f"{context}.value", u32=True),
            )
        raise CallableExternalProposalError(
            f"{context}.kind must be canonical_static_string or exact_word"
        )


@dataclass(frozen=True)
class CallableResolverProfile:
    id: int
    imported: CallableImportIdentity
    result_register: str
    identity_argument_indices: tuple[int, ...]
    nullable: bool


@dataclass(frozen=True)
class CallableABIProfile:
    transfer: str
    argument_sources: tuple[CallableArgumentSourceSpec, ...]
    stack_result_delta: int
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    memory_effect: str
    memory_footprints: tuple[Mapping[str, Any], ...]

    def artifact_spec(
        self, *, artifact_id: int, capability_id: int
    ) -> ResolvedExternalABIContractSpec:
        from .callable_external_capability import MemoryFootprintSpec

        return ResolvedExternalABIContractSpec(
            id=artifact_id,
            capability_id=capability_id,
            transfer=self.transfer,
            argument_sources=self.argument_sources,
            stack_result_delta=self.stack_result_delta,
            preserved_registers=self.preserved_registers,
            clobbered_registers=self.clobbered_registers,
            memory_effect=self.memory_effect,
            memory_footprints=tuple(
                MemoryFootprintSpec(
                    access=str(item["access"]),
                    base_argument=int(item["base_argument"]),
                    offset=int(item["offset"]),
                    bytes=int(item["bytes"]),
                    nullable=bool(item["nullable"]),
                )
                for item in self.memory_footprints
            ),
        )


@dataclass(frozen=True)
class CallableTargetProfile:
    id: int
    resolver_id: int
    identities: tuple[CallableIdentityProfile, ...]
    abis: tuple[CallableABIProfile, ...]


@dataclass(frozen=True)
class CallableExternalProfile:
    id: str
    resolvers: tuple[CallableResolverProfile, ...]
    targets: tuple[CallableTargetProfile, ...]


@dataclass(frozen=True)
class CallableExternalProposalBlocker:
    category: str
    location_rva: int | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
        }


@dataclass(frozen=True)
class DiscoveredCallableResolverSite:
    boundary_id: int
    source_rva: int
    instruction_rva: int
    machine_contract_id: int
    argument_words: int
    resolver: CallableResolverProfile
    target: CallableTargetProfile
    identities: tuple[CallableIdentityProfile, ...]
    identity_values: tuple[int, ...]
    static_data: tuple[OriginalStaticDataBinding, ...]


@dataclass(frozen=True)
class CallableExternalProposal:
    profile_id: str
    original_sha256: str
    state_machine_sha256: str
    machine_import_report_sha256: str
    sites: tuple[DiscoveredCallableResolverSite, ...]
    static_data_bindings: tuple[OriginalStaticDataBinding, ...]
    blockers: tuple[CallableExternalProposalBlocker, ...]

    @property
    def complete(self) -> bool:
        return not self.blockers

    def to_json(self) -> dict[str, Any]:
        return {
            "format": CALLABLE_EXTERNAL_PROPOSAL_FORMAT,
            "profile_id": self.profile_id,
            "inputs": {
                "machine_import_report_sha256": self.machine_import_report_sha256,
                "original_sha256": self.original_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "sites": [
                {
                    "boundary_id": site.boundary_id,
                    "identity_values": list(site.identity_values),
                    "instruction_rva": site.instruction_rva,
                    "machine_contract_id": site.machine_contract_id,
                    "argument_words": site.argument_words,
                    "profile_target_id": site.target.id,
                    "resolver_profile_id": site.resolver.id,
                    "source_rva": site.source_rva,
                }
                for site in self.sites
            ],
            "static_data_bindings": [
                {
                    "bytes_sha256": binding.bytes_sha256,
                    "relocation_offsets": list(binding.relocation_offsets),
                    "rva": binding.rva,
                    "size": binding.size,
                    "va": binding.va,
                }
                for binding in self.static_data_bindings
            ],
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "counts": {
                "blockers": len(self.blockers),
                "callable_sites": len(self.sites),
                "static_data_bindings": len(self.static_data_bindings),
            },
            "status": "ready" if self.complete else "incomplete",
        }


@dataclass(frozen=True)
class CallableResolverRouteEvidence:
    """Canonical callable route issued by one exact resolver instruction."""

    instruction_rva: int
    result_register: str
    nullable: bool
    route: OriginalCallableExternalRouteBinding


def callable_resource_ids_by_instruction_rva(
    proposal: CallableExternalProposal,
) -> dict[int, int]:
    """Return the canonical capability/resource ID for each resolver call."""

    result: dict[int, int] = {}
    for capability_id, site in enumerate(proposal.sites):
        if site.instruction_rva in result:
            raise CallableExternalProposalError(
                "multiple callable resolver sites select instruction "
                f"RVA 0x{site.instruction_rva:x}"
            )
        result[site.instruction_rva] = capability_id
    return result


def callable_resolver_routes_by_instruction_rva(
    proposal: CallableExternalProposal,
    plan: InterpreterMixedOriginalPlan,
    *,
    transfer: str,
) -> dict[int, CallableResolverRouteEvidence]:
    """Return the exact generated Lean route selected by each resolver call.

    A concrete indirect exit has one ABI shape. Multiple ABI declarations for
    the same capability and transfer require call-site shape selection, which
    this evidence layer deliberately leaves incomplete instead of choosing
    one by ordering.
    """

    if transfer not in {"call", "jump"}:
        raise CallableExternalProposalError(
            f"unsupported callable transfer {transfer!r}"
        )
    capability, execution = callable_external_artifact_payload(proposal, plan)
    resolver_rows = {
        int(row["id"]): row for row in capability["resolver_contracts"]
    }
    capability_rows = {
        int(row["id"]): row for row in capability["capabilities"]
    }
    abi_rows_by_capability: dict[int, list[Mapping[str, Any]]] = {}
    for row in capability["resolved_abi_contracts"]:
        if row["transfer"] == transfer:
            abi_rows_by_capability.setdefault(
                int(row["capability_id"]), []
            ).append(row)
    execution_by_boundary = {
        int(row["id"]): row for row in execution["sites"]
    }
    result: dict[int, CallableResolverRouteEvidence] = {}
    for site in proposal.sites:
        execution_row = execution_by_boundary.get(site.boundary_id)
        if execution_row is None:
            raise CallableExternalProposalError(
                f"resolver boundary {site.boundary_id} has no execution artifact"
            )
        resolver_id = int(execution_row["resolver_contract_id"])
        capability_id = int(execution_row["capability_id"])
        resolver_row = resolver_rows.get(resolver_id)
        capability_row = capability_rows.get(capability_id)
        abi_rows = abi_rows_by_capability.get(capability_id, [])
        if resolver_row is None or capability_row is None:
            raise CallableExternalProposalError(
                f"resolver boundary {site.boundary_id} has incomplete route artifacts"
            )
        if len(abi_rows) != 1:
            raise CallableExternalProposalError(
                f"resolver boundary {site.boundary_id} has {len(abi_rows)} "
                f"{transfer} ABI routes; exact call-site selection is required"
            )
        if site.instruction_rva in result:
            raise CallableExternalProposalError(
                f"duplicate resolver instruction RVA 0x{site.instruction_rva:x}"
            )
        result[site.instruction_rva] = CallableResolverRouteEvidence(
            instruction_rva=site.instruction_rva,
            result_register=str(resolver_row["result_register"]),
            nullable=bool(resolver_row["nullable"]),
            route=OriginalCallableExternalRouteBinding(
                resolver_contract_id=resolver_id,
                capability_id=capability_id,
                abi_contract_id=int(abi_rows[0]["id"]),
                resource_id=int(capability_row["resource_id"]),
            ),
        )
    return result


def parse_callable_external_profile(payload: object) -> CallableExternalProfile:
    root = _object(payload, "callable external profile")
    _exact_fields(root, _PROFILE_FIELDS, "callable external profile")
    if root["format"] != CALLABLE_EXTERNAL_PROFILE_FORMAT:
        raise CallableExternalProposalError(
            "unsupported callable external profile format"
        )
    profile_id = root["id"]
    if not isinstance(profile_id, str) or not profile_id:
        raise CallableExternalProposalError("callable external profile id is missing")

    resolvers: list[CallableResolverProfile] = []
    for index, raw in enumerate(_array(root["resolvers"], "resolvers")):
        context = f"resolvers[{index}]"
        item = _object(raw, context)
        _exact_fields(item, _RESOLVER_FIELDS, context)
        register = item["result_register"]
        if not isinstance(register, str) or register not in _REGISTERS:
            raise CallableExternalProposalError(
                f"{context}.result_register is unsupported"
            )
        indices = tuple(
            _natural(value, f"{context}.identity_argument_indices[{position}]")
            for position, value in enumerate(
                _array(
                    item["identity_argument_indices"],
                    f"{context}.identity_argument_indices",
                )
            )
        )
        if tuple(sorted(set(indices))) != indices:
            raise CallableExternalProposalError(
                f"{context}.identity_argument_indices must be unique and ordered"
            )
        nullable = item["nullable"]
        if not isinstance(nullable, bool):
            raise CallableExternalProposalError(
                f"{context}.nullable must be a boolean"
            )
        resolvers.append(CallableResolverProfile(
            id=_natural(item["id"], f"{context}.id"),
            imported=CallableImportIdentity.parse(
                item["import"], f"{context}.import"
            ),
            result_register=register,
            identity_argument_indices=indices,
            nullable=nullable,
        ))
    if not resolvers or [item.id for item in resolvers] != list(
        range(len(resolvers))
    ):
        raise CallableExternalProposalError(
            "resolver ids must be a nonempty canonical zero-based sequence"
        )
    resolver_by_id = {item.id: item for item in resolvers}

    targets: list[CallableTargetProfile] = []
    for index, raw in enumerate(_array(root["targets"], "targets")):
        context = f"targets[{index}]"
        item = _object(raw, context)
        _exact_fields(item, _TARGET_FIELDS, context)
        resolver_id = _natural(item["resolver_id"], f"{context}.resolver_id")
        resolver = resolver_by_id.get(resolver_id)
        if resolver is None:
            raise CallableExternalProposalError(
                f"{context} names an unknown resolver"
            )
        identities = tuple(
            CallableIdentityProfile.parse(identity, f"{context}.identity_arguments[{i}]")
            for i, identity in enumerate(
                _array(item["identity_arguments"], f"{context}.identity_arguments")
            )
        )
        if tuple(identity.index for identity in identities) != (
            resolver.identity_argument_indices
        ):
            raise CallableExternalProposalError(
                f"{context}.identity_arguments must exactly cover resolver indices"
            )
        abis = tuple(
            _parse_abi(abi, f"{context}.abis[{i}]")
            for i, abi in enumerate(_array(item["abis"], f"{context}.abis"))
        )
        if not abis or len({abi.transfer for abi in abis}) != len(abis):
            raise CallableExternalProposalError(
                f"{context}.abis must contain unique call/jump routes"
            )
        targets.append(CallableTargetProfile(
            id=_natural(item["id"], f"{context}.id"),
            resolver_id=resolver_id,
            identities=identities,
            abis=abis,
        ))
    if not targets or [item.id for item in targets] != list(range(len(targets))):
        raise CallableExternalProposalError(
            "target ids must be a nonempty canonical zero-based sequence"
        )
    target_keys = [
        (
            target.resolver_id,
            tuple(
                (identity.kind, identity.index, identity.bytes, identity.value)
                for identity in target.identities
            ),
        )
        for target in targets
    ]
    if len(set(target_keys)) != len(target_keys):
        raise CallableExternalProposalError("callable target identities are ambiguous")
    return CallableExternalProfile(
        id=profile_id,
        resolvers=tuple(resolvers),
        targets=tuple(targets),
    )


def load_callable_external_profile(path: Path | str) -> CallableExternalProfile:
    return parse_callable_external_profile(
        json.loads(Path(path).read_text(encoding="utf-8"))
    )


def _parse_abi(value: object, context: str) -> CallableABIProfile:
    item = _object(value, context)
    _exact_fields(item, _ABI_FIELDS, context)
    transfer = item["transfer"]
    if transfer not in {"call", "jump"}:
        raise CallableExternalProposalError(
            f"{context}.transfer must be call or jump"
        )
    sources = tuple(
        CallableArgumentSourceSpec.parse(source, f"{context}.argument_sources[{i}]")
        for i, source in enumerate(
            _array(item["argument_sources"], f"{context}.argument_sources")
        )
    )
    stack_delta = _natural(
        item["stack_result_delta"], f"{context}.stack_result_delta", u32=True
    )
    if stack_delta % 4:
        raise CallableExternalProposalError(
            f"{context}.stack_result_delta must be word aligned"
        )

    def registers(field: str) -> tuple[str, ...]:
        result: list[str] = []
        for position, raw in enumerate(_array(item[field], f"{context}.{field}")):
            if not isinstance(raw, str) or raw not in _REGISTERS:
                raise CallableExternalProposalError(
                    f"{context}.{field}[{position}] is unsupported"
                )
            result.append(raw)
        if len(set(result)) != len(result):
            raise CallableExternalProposalError(
                f"{context}.{field} contains duplicates"
            )
        return tuple(result)

    preserved = registers("preserved_registers")
    clobbered = registers("clobbered_registers")
    if set(preserved) & set(clobbered) or set(preserved) | set(clobbered) != (
        _REGISTERS
    ):
        raise CallableExternalProposalError(
            f"{context} register sets must disjointly cover the ABI registers"
        )
    memory_effect = item["memory_effect"]
    if memory_effect not in {"none", "read_only", "argument_ranges"}:
        raise CallableExternalProposalError(
            f"{context}.memory_effect is unsupported"
        )
    if item["world_effect"] != "none":
        raise CallableExternalProposalError(
            f"{context}.world_effect must be none in this profile"
        )
    footprints: list[Mapping[str, Any]] = []
    for position, raw in enumerate(
        _array(item["memory_footprints"], f"{context}.memory_footprints")
    ):
        footprint_context = f"{context}.memory_footprints[{position}]"
        footprint = _object(raw, footprint_context)
        _exact_fields(footprint, _FOOTPRINT_FIELDS, footprint_context)
        access = footprint["access"]
        base = _natural(
            footprint["base_argument"],
            f"{footprint_context}.base_argument",
        )
        size = _natural(
            footprint["bytes"], f"{footprint_context}.bytes", u32=True
        )
        nullable = footprint["nullable"]
        if (
            access not in {"read", "write"}
            or base >= len(sources)
            or size == 0
            or not isinstance(nullable, bool)
        ):
            raise CallableExternalProposalError(
                f"{footprint_context} is malformed"
            )
        footprints.append({
            "access": access,
            "base_argument": base,
            "offset": _natural(
                footprint["offset"], f"{footprint_context}.offset", u32=True
            ),
            "bytes": size,
            "nullable": nullable,
        })
    if memory_effect == "none" and footprints:
        raise CallableExternalProposalError(
            f"{context}.memory_effect none forbids footprints"
        )
    if memory_effect == "read_only" and any(
        footprint["access"] != "read" for footprint in footprints
    ):
        raise CallableExternalProposalError(
            f"{context}.memory_effect read_only forbids writes"
        )
    if memory_effect == "argument_ranges" and not any(
        footprint["access"] == "write" for footprint in footprints
    ):
        raise CallableExternalProposalError(
            f"{context}.memory_effect argument_ranges requires a write"
        )
    return CallableABIProfile(
        transfer=transfer,
        argument_sources=sources,
        stack_result_delta=stack_delta,
        preserved_registers=preserved,
        clobbered_registers=clobbered,
        memory_effect=memory_effect,
        memory_footprints=tuple(footprints),
    )


def discover_callable_external_proposal(
    *,
    original_pe: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
    profile: Path | str | CallableExternalProfile,
) -> CallableExternalProposal:
    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    report_path = Path(machine_import_report)
    loaded_profile = (
        profile
        if isinstance(profile, CallableExternalProfile)
        else load_callable_external_profile(profile)
    )
    original_sha256 = _sha256(pe_path)
    state_sha256 = _sha256(state_path)
    report_sha256 = _sha256(report_path)
    report = _json_object(report_path, "machine import report")
    if report.get("format") != STATIC_MACHINE_IMPORT_FORMAT:
        raise CallableExternalProposalError(
            "machine import report has the wrong format"
        )
    inputs = _object(report.get("inputs"), "machine import report inputs")
    if (
        inputs.get("original_sha256") != original_sha256
        or inputs.get("state_machine_sha256") != state_sha256
    ):
        raise CallableExternalProposalError(
            "machine import report is not hash-bound to the exact inputs"
        )
    rows = _state_rows(state_path)
    signatures = {
        _natural(item.get("id"), f"signatures[{index}].id"): item
        for index, raw in enumerate(_array(report.get("signatures"), "signatures"))
        if (item := _object(raw, f"signatures[{index}]"))
    }
    resolvers_by_import = {
        (resolver.imported.dll, resolver.imported.symbol): resolver
        for resolver in loaded_profile.resolvers
    }
    targets_by_resolver: dict[int, tuple[CallableTargetProfile, ...]] = {
        resolver.id: tuple(
            target
            for target in loaded_profile.targets
            if target.resolver_id == resolver.id
        )
        for resolver in loaded_profile.resolvers
    }
    blockers: list[CallableExternalProposalBlocker] = []
    sites: list[DiscoveredCallableResolverSite] = []

    pe = pefile.PE(str(pe_path), fast_load=False)
    try:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        for boundary_index, raw in enumerate(
            _array(report.get("boundaries"), "boundaries")
        ):
            boundary = _object(raw, f"boundaries[{boundary_index}]")
            imported = _object(
                boundary.get("import"), f"boundaries[{boundary_index}].import"
            )
            dll = imported.get("dll")
            symbol = imported.get("symbol")
            if not isinstance(dll, str) or not isinstance(symbol, str):
                continue
            resolver = resolvers_by_import.get((dll.lower(), symbol))
            if resolver is None:
                continue
            location = (
                boundary.get("instruction_rva")
                if isinstance(boundary.get("instruction_rva"), int)
                else boundary.get("source_rva")
                if isinstance(boundary.get("source_rva"), int)
                else None
            )
            try:
                site = _discover_site(
                    pe=pe,
                    image_base=image_base,
                    rows=rows,
                    signatures=signatures,
                    boundary=boundary,
                    resolver=resolver,
                    targets=targets_by_resolver[resolver.id],
                )
            except CallableExternalProposalError as error:
                blockers.append(CallableExternalProposalBlocker(
                    category="callable_resolver_site_incomplete",
                    location_rva=location,
                    detail=str(error),
                ))
                continue
            if site is not None:
                sites.append(site)
    finally:
        pe.close()

    bindings: dict[tuple[int, int], OriginalStaticDataBinding] = {}
    for site in sites:
        for binding in site.static_data:
            key = (binding.rva, binding.size)
            prior = bindings.get(key)
            if prior is not None and prior != binding:
                blockers.append(CallableExternalProposalBlocker(
                    category="ambiguous_static_identity_mapping",
                    location_rva=site.instruction_rva,
                    detail=(
                        "the same immutable identity range produced conflicting "
                        "exact bindings"
                    ),
                ))
            else:
                bindings[key] = binding
    return CallableExternalProposal(
        profile_id=loaded_profile.id,
        original_sha256=original_sha256,
        state_machine_sha256=state_sha256,
        machine_import_report_sha256=report_sha256,
        sites=tuple(sorted(sites, key=lambda site: site.boundary_id)),
        static_data_bindings=tuple(bindings[key] for key in sorted(bindings)),
        blockers=tuple(blockers),
    )


def _discover_site(
    *,
    pe: pefile.PE,
    image_base: int,
    rows: Mapping[int, Mapping[str, Any]],
    signatures: Mapping[int, Mapping[str, Any]],
    boundary: Mapping[str, Any],
    resolver: CallableResolverProfile,
    targets: Sequence[CallableTargetProfile],
) -> DiscoveredCallableResolverSite | None:
    boundary_id = _natural(boundary.get("id"), "resolver boundary id")
    source_rva = _natural(
        boundary.get("source_rva"), f"resolver boundary {boundary_id} source_rva"
    )
    instruction_rva = _natural(
        boundary.get("instruction_rva"),
        f"resolver boundary {boundary_id} instruction_rva",
    )
    signature_id = _natural(
        boundary.get("signature_id"),
        f"resolver boundary {boundary_id} signature_id",
    )
    signature = signatures.get(signature_id)
    if signature is None:
        raise CallableExternalProposalError(
            f"resolver boundary {boundary_id} has no machine signature"
        )
    if signature.get("world_effect") != "opaqueResources":
        raise CallableExternalProposalError(
            f"resolver boundary {boundary_id} must use opaqueResources world effects"
        )
    arity = _object(
        signature.get("arity"), f"resolver boundary {boundary_id} arity"
    )
    argument_words = (
        _natural(arity.get("words"), f"resolver boundary {boundary_id} words")
        if arity.get("kind") == "fixed"
        else None
    )
    if argument_words is None or any(
        index >= argument_words for index in resolver.identity_argument_indices
    ):
        raise CallableExternalProposalError(
            f"resolver boundary {boundary_id} has incompatible argument arity"
        )
    row = rows.get(source_rva)
    if row is None:
        raise CallableExternalProposalError(
            f"resolver boundary {boundary_id} has no exact state-machine row"
        )
    events = _array(row.get("external_events"), f"state row 0x{source_rva:x} events")
    if len(events) != 1:
        raise CallableExternalProposalError(
            f"resolver boundary {boundary_id} must contain exactly one external event"
        )
    event = _object(events[0], f"resolver boundary {boundary_id} event")
    stack_inputs: dict[int, Mapping[str, Any]] = {}
    for index, raw in enumerate(
        _array(event.get("stack_inputs"), f"resolver boundary {boundary_id} stack")
    ):
        item = _object(raw, f"resolver boundary {boundary_id} stack[{index}]")
        offset = item.get("offset")
        if isinstance(offset, int) and offset not in stack_inputs:
            stack_inputs[offset] = item

    identities: list[CallableIdentityProfile] = []
    values: list[int] = []
    static_data: list[OriginalStaticDataBinding] = []
    observed: list[tuple[str, int, bytes | None, int | None]] = []
    for identity_index in resolver.identity_argument_indices:
        stack = stack_inputs.get(identity_index * 4)
        if stack is None:
            raise CallableExternalProposalError(
                f"resolver boundary {boundary_id} lacks identity argument "
                f"{identity_index}"
            )
        expression = _object(
            stack.get("value"),
            f"resolver boundary {boundary_id} identity {identity_index}",
        )
        value = expression.get("value")
        if expression.get("op") != "const" or not isinstance(value, int):
            raise CallableExternalProposalError(
                f"resolver boundary {boundary_id} identity argument "
                f"{identity_index} is not an exact word"
            )
        if not 0 <= value < 2**32:
            raise CallableExternalProposalError(
                f"resolver boundary {boundary_id} identity word is outside PE32"
            )
        values.append(value)
        c_string = _immutable_c_string(pe, image_base, value)
        if c_string is None:
            observed.append(("exact_word", identity_index, None, value))
        else:
            observed.append((
                "canonical_static_string",
                identity_index,
                c_string,
                None,
            ))

    matches = [
        target
        for target in targets
        if tuple(
            (identity.kind, identity.index, identity.bytes, identity.value)
            for identity in target.identities
        ) == tuple(observed)
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise CallableExternalProposalError(
            f"resolver boundary {boundary_id} matches multiple target profiles"
        )
    target = matches[0]
    identities.extend(target.identities)
    for identity, value in zip(target.identities, values, strict=True):
        if identity.kind != "canonical_static_string":
            continue
        assert identity.bytes is not None
        rva = value - image_base
        exact = pe.get_data(rva, len(identity.bytes) + 1)
        if exact != identity.bytes + b"\0":
            raise CallableExternalProposalError(
                f"resolver boundary {boundary_id} static identity bytes changed"
            )
        static_data.append(OriginalStaticDataBinding(
            rva=rva,
            va=value,
            size=len(exact),
            bytes_sha256=hashlib.sha256(exact).hexdigest(),
        ))
    return DiscoveredCallableResolverSite(
        boundary_id=boundary_id,
        source_rva=source_rva,
        instruction_rva=instruction_rva,
        machine_contract_id=boundary_id,
        argument_words=argument_words,
        resolver=resolver,
        target=target,
        identities=tuple(identities),
        identity_values=tuple(values),
        static_data=tuple(static_data),
    )


def _immutable_c_string(
    pe: pefile.PE, image_base: int, address: int, *, limit: int = 4096
) -> bytes | None:
    if address < image_base:
        return None
    rva = address - image_base
    sections = [
        section
        for section in pe.sections
        if int(section.VirtualAddress) <= rva
        and rva < int(section.VirtualAddress) + max(
            int(section.Misc_VirtualSize), int(section.SizeOfRawData)
        )
    ]
    if len(sections) != 1:
        return None
    section = sections[0]
    if int(section.Characteristics) & (
        _IMAGE_SCN_MEM_WRITE | _IMAGE_SCN_MEM_EXECUTE
    ):
        return None
    available = (
        int(section.VirtualAddress)
        + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        - rva
    )
    data = pe.get_data(rva, min(limit, available))
    terminator = data.find(b"\0")
    if terminator <= 0:
        return None
    return data[:terminator]


def callable_external_artifact_payload(
    proposal: CallableExternalProposal,
    plan: InterpreterMixedOriginalPlan,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind a complete proposal to carrier target IDs and source cutpoints."""
    if not proposal.complete:
        raise CallableExternalProposalError(
            "cannot build a callable artifact from an incomplete proposal"
        )
    data_bindings = _carrier_data_bindings(plan)
    data_target_by_key = {
        (binding.rva, binding.size, binding.bytes_sha256): target_id
        for target_id, binding in enumerate(data_bindings)
        if isinstance(binding, OriginalStaticDataBinding)
    }
    source_target_by_rva = {region.rva: region.target_id for region in plan.regions}

    resolver_ids: dict[tuple[int, int], int] = {}
    resolver_rows: list[dict[str, Any]] = []
    capability_rows: list[dict[str, Any]] = []
    abi_rows: list[dict[str, Any]] = []
    execution_rows: list[dict[str, Any]] = []
    abi_id = 0
    resource_ids = callable_resource_ids_by_instruction_rva(proposal)
    for site in proposal.sites:
        capability_id = resource_ids[site.instruction_rva]
        resolver_key = (site.resolver.id, site.machine_contract_id)
        resolver_artifact_id = resolver_ids.get(resolver_key)
        if resolver_artifact_id is None:
            resolver_artifact_id = len(resolver_rows)
            resolver_ids[resolver_key] = resolver_artifact_id
            argument_sources = [
                {"kind": "stack_word", "offset": index * 4}
                for index in range(site.argument_words)
            ]
            resolver_rows.append({
                "id": resolver_artifact_id,
                "machine_contract_id": site.machine_contract_id,
                "result_register": site.resolver.result_register,
                "result_relation": "opaque_callable_capability",
                "argument_sources": argument_sources,
                "identity_argument_indices": list(
                    site.resolver.identity_argument_indices
                ),
                "nullable": site.resolver.nullable,
            })

        identity_rows: list[dict[str, Any]] = []
        static_iter = iter(site.static_data)
        for identity, value in zip(
            site.identities, site.identity_values, strict=True
        ):
            if identity.kind == "exact_word":
                identity_rows.append({
                    "kind": "exact_word",
                    "index": identity.index,
                    "value": value,
                })
                continue
            binding = next(static_iter)
            target_id = data_target_by_key.get(
                (binding.rva, binding.size, binding.bytes_sha256)
            )
            if target_id is None:
                raise CallableExternalProposalError(
                    "carrier context omitted a callable static identity binding"
                )
            assert identity.bytes is not None
            identity_rows.append({
                "kind": "canonical_static_string",
                "argument_index": identity.index,
                "target_id": target_id,
                "offset": 0,
                "bytes": list(identity.bytes),
            })
        capability_rows.append({
            "id": capability_id,
            "resource_id": capability_id,
            "resolver_contract_id": resolver_artifact_id,
            "resolver_site_id": site.boundary_id,
            "identity_arguments": identity_rows,
        })
        source_target_id = source_target_by_rva.get(site.source_rva)
        if source_target_id is None:
            raise CallableExternalProposalError(
                f"resolver source RVA 0x{site.source_rva:x} is not a cutpoint"
            )
        resolver_sources = resolver_rows[resolver_artifact_id]["argument_sources"]
        execution_rows.append({
            "kind": "resolver",
            "id": site.boundary_id,
            "source_target_id": source_target_id,
            "machine_contract_id": site.machine_contract_id,
            "argument_sources": resolver_sources,
            "resolver_contract_id": resolver_artifact_id,
            "capability_id": capability_id,
        })
        for abi in site.target.abis:
            spec = abi.artifact_spec(
                artifact_id=abi_id, capability_id=capability_id
            )
            abi_rows.append({
                "id": spec.id,
                "capability_id": spec.capability_id,
                "transfer": spec.transfer,
                "argument_sources": [
                    _argument_source_json(source)
                    for source in spec.argument_sources
                ],
                "stack_result_delta": spec.stack_result_delta,
                "preserved_registers": list(spec.preserved_registers),
                "clobbered_registers": list(spec.clobbered_registers),
                "memory_effect": spec.memory_effect,
                "memory_footprints": [
                    {
                        "access": footprint.access,
                        "base_argument": footprint.base_argument,
                        "offset": footprint.offset,
                        "bytes": footprint.bytes,
                        "nullable": footprint.nullable,
                    }
                    for footprint in spec.memory_footprints
                ],
                "world_effect": "none",
            })
            abi_id += 1
    return (
        {
            "format": CALLABLE_EXTERNAL_CAPABILITY_FORMAT,
            "resolver_contracts": resolver_rows,
            "capabilities": capability_rows,
            "resolved_abi_contracts": abi_rows,
        },
        {
            "format": "stage-a-callable-external-execution-v1",
            "sites": sorted(execution_rows, key=lambda row: int(row["id"])),
        },
    )


def _carrier_data_bindings(
    plan: InterpreterMixedOriginalPlan,
) -> tuple[object, ...]:
    from .interpreter_mixed_original import _unique_static_data_bindings

    return _unique_static_data_bindings(plan)


def _argument_source_json(source: CallableArgumentSourceSpec) -> dict[str, Any]:
    if source.kind == "register":
        return {"kind": "register", "register": source.register}
    if source.kind == "stack_word":
        return {"kind": "stack_word", "offset": source.offset}
    return {"kind": "constant", "value": source.value}


def _state_rows(path: Path) -> dict[int, Mapping[str, Any]]:
    rows: dict[int, Mapping[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = _object(
                json.loads(line), f"state-machine line {line_number}"
            )
            original = _object(
                row.get("original"),
                f"state-machine line {line_number}.original",
            )
            rva = _natural(
                original.get("rva_start"),
                f"state-machine line {line_number}.original.rva_start",
            )
            if rva in rows:
                raise CallableExternalProposalError(
                    f"state-machine source RVA 0x{rva:x} is ambiguous"
                )
            rows[rva] = row
    return rows


def _json_object(path: Path, context: str) -> Mapping[str, Any]:
    return _object(json.loads(path.read_text(encoding="utf-8")), context)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "CALLABLE_EXTERNAL_PROFILE_FORMAT",
    "CALLABLE_EXTERNAL_PROPOSAL_FORMAT",
    "CallableExternalProfile",
    "CallableExternalProposal",
    "CallableExternalProposalError",
    "CallableResolverRouteEvidence",
    "callable_external_artifact_payload",
    "callable_resolver_routes_by_instruction_rva",
    "callable_resource_ids_by_instruction_rva",
    "discover_callable_external_proposal",
    "load_callable_external_profile",
    "parse_callable_external_profile",
]
