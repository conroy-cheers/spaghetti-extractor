"""Generate static contracts for resolver-issued callable capabilities.

The format contains no submitted execution trace. Candidate runtime adapters
consume these machine-level identities, arguments, and effect boundaries.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import StageAInputError
from .machine_abi import MachineCallABI, resolve_machine_call_abi
from .machine_import_profiles import (
    NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL,
    NATIVE_DLL_CALLTHROUGH_PREREQUISITES,
    MachineImportIdentity,
)
from .util import sha256_file


CALLABLE_EXTERNAL_CAPABILITY_FORMAT = (
    "stage-a-callable-external-capability-v3"
)
CALLABLE_EXTERNAL_PROFILE_FORMAT = "stage-a-callable-external-profile-v2"

_ROOT_FIELDS = frozenset({
    "format",
    "resolver_contracts",
    "capabilities",
    "resolved_abi_contracts",
})
_RESOLVER_FIELDS = frozenset({
    "id",
    "machine_contract_id",
    "result_register",
    "result_relation",
    "argument_sources",
    "identity_argument_indices",
    "nullable",
})
_CAPABILITY_FIELDS = frozenset({
    "id",
    "resource_id",
    "resolver_contract_id",
    "resolver_site_id",
    "identity_arguments",
})
_EXACT_IDENTITY_FIELDS = frozenset({"kind", "index", "value"})
_STRING_IDENTITY_FIELDS = frozenset({
    "kind",
    "argument_index",
    "target_id",
    "offset",
    "bytes",
})
_ABI_FIELDS = frozenset({
    "id",
    "capability_id",
    "transfer",
    "argument_sources",
    "stack_result_delta",
    "preserved_registers",
    "clobbered_registers",
    "memory_effect",
    "memory_footprints",
    "world_effect",
})
_ARGUMENT_REGISTER_FIELDS = frozenset({"kind", "register"})
_ARGUMENT_STACK_FIELDS = frozenset({"kind", "offset"})
_ARGUMENT_CONSTANT_FIELDS = frozenset({"kind", "value"})
_FOOTPRINT_FIELDS = frozenset({
    "access",
    "base_argument",
    "offset",
    "bytes",
    "nullable",
})
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"})
_ARGUMENT_REGISTERS = _REGISTERS | {"esp"}
_TRANSFERS = frozenset({"call", "jump"})
_MEMORY_EFFECTS = frozenset({"none", "read_only", "argument_ranges"})
_CALLABLE_RESULT_RELATION = "opaque_callable_capability"

_PROFILE_ROOT_FIELDS = frozenset({"format", "id", "model", "resolvers", "targets"})
_PROFILE_RESOLVER_FIELDS = frozenset({
    "id",
    "import",
    "result_register",
    "module_argument_index",
    "identity_argument_indices",
    "nullable",
})
_PROFILE_TARGET_FIELDS = frozenset({
    "id",
    "resolver_id",
    "module",
    "identity_arguments",
    "target",
    "machine_contract",
    "transfers",
})
_PROFILE_MODULE_FIELDS = frozenset({
    "loader_import",
    "loader_name_argument_index",
    "bytes",
})
_PROFILE_IDENTITY_FIELDS = frozenset({"kind", "index", "bytes"})
_PROFILE_TRANSFERS = frozenset({"call", "jump"})
_NATIVE_CONTRACT_FIELDS = frozenset({
    "id",
    "import",
    "abi_template",
    "arity",
    "disposition",
    "result_register_relations",
    "effect_model",
    "memory_effect",
    "memory_footprints",
    "world_effect",
    "callback_effect",
})


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be an array")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise StageAInputError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise StageAInputError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _natural(value: object, context: str, *, u32: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a natural number")
    if u32 and value >= 2**32:
        raise StageAInputError(f"{context} must fit in an unsigned 32-bit word")
    return value


def _byte_list(value: object, context: str) -> tuple[int, ...]:
    result = tuple(
        _natural(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context))
    )
    if any(item > 0xFF for item in result):
        raise StageAInputError(f"{context} contains a value outside the byte range")
    return result


def _register_list(value: object, context: str) -> tuple[str, ...]:
    result: list[str] = []
    for index, item in enumerate(_array(value, context)):
        if not isinstance(item, str) or item not in _REGISTERS:
            raise StageAInputError(f"{context}[{index}] is not an ABI register")
        result.append(item)
    if len(set(result)) != len(result):
        raise StageAInputError(f"{context} contains duplicate registers")
    return tuple(result)


@dataclass(frozen=True)
class CallableArgumentSourceSpec:
    kind: str
    register: str | None = None
    offset: int | None = None
    value: int | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "CallableArgumentSourceSpec":
        source = _object(value, context)
        kind = source.get("kind")
        if kind == "register":
            _exact_fields(source, _ARGUMENT_REGISTER_FIELDS, context)
            register = source["register"]
            if not isinstance(register, str) or register not in _ARGUMENT_REGISTERS:
                raise StageAInputError(f"{context}.register is unsupported")
            return cls(kind=kind, register=register)
        if kind == "stack_word":
            _exact_fields(source, _ARGUMENT_STACK_FIELDS, context)
            offset = _natural(source["offset"], f"{context}.offset", u32=True)
            if offset % 4:
                raise StageAInputError(f"{context}.offset must be word aligned")
            return cls(kind=kind, offset=offset)
        if kind == "constant":
            _exact_fields(source, _ARGUMENT_CONSTANT_FIELDS, context)
            return cls(
                kind=kind,
                value=_natural(source["value"], f"{context}.value", u32=True),
            )
        raise StageAInputError(
            f"{context}.kind must be register, stack_word, or constant"
        )

    def lean(self) -> str:
        if self.kind == "register":
            return f".register .{self.register}"
        if self.kind == "stack_word":
            return f".stackWord {self.offset}"
        return f".constant (BitVec.ofNat 32 {self.value})"


def _argument_sources(value: object, context: str) -> tuple[CallableArgumentSourceSpec, ...]:
    return tuple(
        CallableArgumentSourceSpec.parse(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context))
    )


@dataclass(frozen=True)
class CallableResolverProfileSpec:
    id: int
    identity: MachineImportIdentity
    result_register: str
    module_argument_index: int
    identity_argument_indices: tuple[int, ...]
    nullable: bool


@dataclass(frozen=True)
class CallableModuleProfileSpec:
    loader_identity: MachineImportIdentity
    loader_name_argument_index: int
    name_bytes: bytes

    @property
    def name(self) -> str:
        return self.name_bytes.decode("ascii")


@dataclass(frozen=True)
class CallableExternalTargetProfileSpec:
    id: int
    resolver_id: int
    module: CallableModuleProfileSpec
    name_argument_index: int
    name_bytes: bytes
    identity: MachineImportIdentity
    abi: MachineCallABI
    argument_words: int
    machine_contract: Mapping[str, Any]
    transfers: tuple[str, ...]

    @property
    def name(self) -> str:
        return self.name_bytes.decode("ascii")

    def target_json(
        self,
        *,
        profile_id: str,
        profile_sha256: str,
        resolver: CallableResolverProfileSpec,
        transfer: str,
    ) -> dict[str, Any]:
        if transfer not in self.transfers:
            raise StageAInputError(
                f"callable target {profile_id}:{self.id} does not allow {transfer}"
            )
        return {
            "external_protocol": {
                "kind": "pe32-resolved-export",
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
                "target_id": self.id,
                "resolver_import": _identity_json(resolver.identity),
                "loader_import": _identity_json(self.module.loader_identity),
                "module": self.module.name,
                "name": self.name,
                "target": _identity_json(self.identity),
                "transfer_kind": transfer,
                "machine_contract": copy.deepcopy(dict(self.machine_contract)),
            },
            "abi": self.abi.as_json(),
            "argument_words": self.argument_words,
            "out_interfaces": [],
        }


@dataclass(frozen=True)
class CallableExternalProfile:
    path: Path
    profile_id: str
    sha256: str
    resolvers: tuple[CallableResolverProfileSpec, ...]
    targets: tuple[CallableExternalTargetProfileSpec, ...]

    def resolver_by_id(self) -> dict[int, CallableResolverProfileSpec]:
        return {resolver.id: resolver for resolver in self.resolvers}

    def targets_by_resolver(
        self, resolver_id: int
    ) -> tuple[CallableExternalTargetProfileSpec, ...]:
        return tuple(target for target in self.targets if target.resolver_id == resolver_id)

    def target_by_id(self, target_id: int) -> CallableExternalTargetProfileSpec | None:
        return next((target for target in self.targets if target.id == target_id), None)


def _identity_json(identity: MachineImportIdentity) -> dict[str, Any]:
    return {"dll": identity.dll, identity.kind: identity.value}


def _ascii_identity_bytes(value: object, context: str) -> bytes:
    raw = bytes(_byte_list(value, context))
    if not raw or b"\0" in raw:
        raise StageAInputError(f"{context} must be a nonempty unterminated string")
    try:
        decoded = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise StageAInputError(f"{context} must contain ASCII identity bytes") from exc
    if decoded.encode("ascii") != raw:
        raise StageAInputError(f"{context} is not canonical ASCII")
    return raw


def _parse_profile_identity(value: object, context: str) -> MachineImportIdentity:
    return MachineImportIdentity.from_mapping(_object(value, context), context=context)


def _parse_native_target_contract(
    value: object,
    *,
    identity: MachineImportIdentity,
    context: str,
) -> tuple[Mapping[str, Any], MachineCallABI, int]:
    contract = _object(value, context)
    _exact_fields(contract, _NATIVE_CONTRACT_FIELDS, context)
    if _parse_profile_identity(contract["import"], f"{context}.import") != identity:
        raise StageAInputError(f"{context}.import differs from the named target")
    abi = resolve_machine_call_abi(contract.get("abi_template"))
    if abi is None:
        raise StageAInputError(f"{context}.abi_template is unsupported")
    arity = _object(contract.get("arity"), f"{context}.arity")
    if set(arity) != {"kind", "words"} or arity.get("kind") != "fixed":
        raise StageAInputError(f"{context}.arity must be an exact fixed word count")
    argument_words = _natural(arity.get("words"), f"{context}.arity.words")
    if argument_words > 256:
        raise StageAInputError(f"{context}.arity.words exceeds the PE32 bound")
    if contract.get("disposition") != "returns":
        raise StageAInputError(f"{context}.disposition must be returns")
    results = _array(
        contract.get("result_register_relations"),
        f"{context}.result_register_relations",
    )
    for index, result in enumerate(results):
        row = _object(result, f"{context}.result_register_relations[{index}]")
        if (
            set(row) != {"register", "relation"}
            or row.get("register") not in {"eax", "edx"}
            or row.get("relation") not in {"exact", "related_word"}
        ):
            raise StageAInputError(
                f"{context}.result_register_relations[{index}] is invalid"
            )
    effect = _object(contract.get("effect_model"), f"{context}.effect_model")
    prerequisites = _object(
        effect.get("prerequisites"), f"{context}.effect_model.prerequisites"
    )
    if (
        set(effect) != {"kind", "prerequisites"}
        or effect.get("kind") != NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL
        or set(prerequisites) != NATIVE_DLL_CALLTHROUGH_PREREQUISITES
        or any(prerequisites.get(key) is not True for key in prerequisites)
    ):
        raise StageAInputError(
            f"{context} must require exact same-pinned-DLL native call-through"
        )
    if (
        contract.get("memory_effect") != "nativeCallthrough"
        or contract.get("memory_footprints") != []
        or contract.get("world_effect") != "nativeCallthrough"
        or contract.get("callback_effect") != "none"
    ):
        raise StageAInputError(
            f"{context} must explicitly use non-callback native call-through effects"
        )
    return copy.deepcopy(dict(contract)), abi, argument_words


def load_callable_external_profile(path: Path | str) -> CallableExternalProfile:
    source = Path(path).resolve()
    try:
        payload = _object(json.loads(source.read_text(encoding="utf-8")), str(source))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read callable external profile {source}: {exc}") from exc
    _exact_fields(payload, _PROFILE_ROOT_FIELDS, str(source))
    if payload.get("format") != CALLABLE_EXTERNAL_PROFILE_FORMAT:
        raise StageAInputError(f"unsupported callable external profile {source}")
    if payload.get("model") != "x86-pe32":
        raise StageAInputError(f"{source} has an unsupported machine model")
    profile_id = payload.get("id")
    if not isinstance(profile_id, str) or not profile_id:
        raise StageAInputError(f"{source} has no profile id")

    resolvers: list[CallableResolverProfileSpec] = []
    for index, raw in enumerate(_array(payload.get("resolvers"), f"{source}.resolvers")):
        context = f"{source}.resolvers[{index}]"
        row = _object(raw, context)
        _exact_fields(row, _PROFILE_RESOLVER_FIELDS, context)
        register = row.get("result_register")
        if register not in _REGISTERS:
            raise StageAInputError(f"{context}.result_register is unsupported")
        module_index = _natural(
            row.get("module_argument_index"), f"{context}.module_argument_index"
        )
        identity_indices = tuple(
            _natural(value, f"{context}.identity_argument_indices[{position}]")
            for position, value in enumerate(
                _array(
                    row.get("identity_argument_indices"),
                    f"{context}.identity_argument_indices",
                )
            )
        )
        if not identity_indices or len(set(identity_indices)) != len(identity_indices):
            raise StageAInputError(
                f"{context}.identity_argument_indices must be nonempty and unique"
            )
        nullable = row.get("nullable")
        if not isinstance(nullable, bool):
            raise StageAInputError(f"{context}.nullable must be a boolean")
        resolvers.append(CallableResolverProfileSpec(
            id=_natural(row.get("id"), f"{context}.id"),
            identity=_parse_profile_identity(row.get("import"), f"{context}.import"),
            result_register=str(register),
            module_argument_index=module_index,
            identity_argument_indices=identity_indices,
            nullable=nullable,
        ))
    if not resolvers:
        raise StageAInputError(f"{source}.resolvers must not be empty")
    _unique_ids(resolvers, f"{source}.resolvers")
    if len({resolver.identity for resolver in resolvers}) != len(resolvers):
        raise StageAInputError(f"{source}.resolvers contains ambiguous import identities")
    resolver_by_id = {resolver.id: resolver for resolver in resolvers}

    targets: list[CallableExternalTargetProfileSpec] = []
    route_keys: set[tuple[int, bytes, bytes]] = set()
    for index, raw in enumerate(_array(payload.get("targets"), f"{source}.targets")):
        context = f"{source}.targets[{index}]"
        row = _object(raw, context)
        _exact_fields(row, _PROFILE_TARGET_FIELDS, context)
        resolver_id = _natural(row.get("resolver_id"), f"{context}.resolver_id")
        resolver = resolver_by_id.get(resolver_id)
        if resolver is None:
            raise StageAInputError(f"{context} names an unknown resolver")
        module_row = _object(row.get("module"), f"{context}.module")
        _exact_fields(module_row, _PROFILE_MODULE_FIELDS, f"{context}.module")
        module = CallableModuleProfileSpec(
            loader_identity=_parse_profile_identity(
                module_row.get("loader_import"), f"{context}.module.loader_import"
            ),
            loader_name_argument_index=_natural(
                module_row.get("loader_name_argument_index"),
                f"{context}.module.loader_name_argument_index",
            ),
            name_bytes=_ascii_identity_bytes(
                module_row.get("bytes"), f"{context}.module.bytes"
            ),
        )
        identities = _array(
            row.get("identity_arguments"), f"{context}.identity_arguments"
        )
        if len(identities) != 1:
            raise StageAInputError(
                f"{context}.identity_arguments must contain one static name"
            )
        identity_row = _object(identities[0], f"{context}.identity_arguments[0]")
        _exact_fields(
            identity_row, _PROFILE_IDENTITY_FIELDS, f"{context}.identity_arguments[0]"
        )
        if identity_row.get("kind") != "canonical_static_string":
            raise StageAInputError(
                f"{context}.identity_arguments[0] must be canonical_static_string"
            )
        name_index = _natural(
            identity_row.get("index"), f"{context}.identity_arguments[0].index"
        )
        if (name_index,) != resolver.identity_argument_indices:
            raise StageAInputError(
                f"{context}.identity_arguments does not exactly cover the resolver identity"
            )
        name_bytes = _ascii_identity_bytes(
            identity_row.get("bytes"), f"{context}.identity_arguments[0].bytes"
        )
        identity = _parse_profile_identity(row.get("target"), f"{context}.target")
        if (
            identity.kind != "symbol"
            or identity.dll.encode("ascii") != module.name_bytes.lower()
            or str(identity.value).encode("ascii") != name_bytes
        ):
            raise StageAInputError(
                f"{context}.target must exactly match the module and static symbol name"
            )
        contract, abi, argument_words = _parse_native_target_contract(
            row.get("machine_contract"), identity=identity, context=f"{context}.machine_contract"
        )
        transfers = tuple(
            str(value)
            for value in _array(row.get("transfers"), f"{context}.transfers")
        )
        if (
            not transfers
            or len(set(transfers)) != len(transfers)
            or any(value not in _PROFILE_TRANSFERS for value in transfers)
        ):
            raise StageAInputError(f"{context}.transfers must be unique call/jump values")
        route_key = (resolver_id, module.name_bytes.lower(), name_bytes)
        if route_key in route_keys:
            raise StageAInputError(f"{context} duplicates a resolver module/name route")
        route_keys.add(route_key)
        targets.append(CallableExternalTargetProfileSpec(
            id=_natural(row.get("id"), f"{context}.id"),
            resolver_id=resolver_id,
            module=module,
            name_argument_index=name_index,
            name_bytes=name_bytes,
            identity=identity,
            abi=abi,
            argument_words=argument_words,
            machine_contract=contract,
            transfers=transfers,
        ))
    if not targets:
        raise StageAInputError(f"{source}.targets must not be empty")
    _unique_ids(targets, f"{source}.targets")
    return CallableExternalProfile(
        path=source,
        profile_id=profile_id,
        sha256=sha256_file(source),
        resolvers=tuple(resolvers),
        targets=tuple(targets),
    )


@dataclass(frozen=True)
class ResolverCallContractSpec:
    id: int
    machine_contract_id: int
    result_register: str
    argument_sources: tuple[CallableArgumentSourceSpec, ...]
    identity_argument_indices: tuple[int, ...]
    nullable: bool

    def lean(self) -> str:
        sources = ", ".join(source.lean() for source in self.argument_sources)
        indices = ", ".join(str(index) for index in self.identity_argument_indices)
        return (
            "{ id := "
            f"{self.id}, machineContractId := {self.machine_contract_id}, "
            f"resultRegister := .{self.result_register}, "
            f"argumentSources := [{sources}], "
            f"immutableIdentityArgumentIndices := [{indices}], "
            f"nullable := {str(self.nullable).lower()} }}"
        )


@dataclass(frozen=True)
class ExactIdentitySpec:
    index: int
    value: int

    def lean(self) -> str:
        return f"{{ index := {self.index}, value := BitVec.ofNat 32 {self.value} }}"


@dataclass(frozen=True)
class StaticStringIdentitySpec:
    argument_index: int
    target_id: int
    offset: int
    bytes: tuple[int, ...]

    def lean(self) -> str:
        rendered = ", ".join(str(byte) for byte in self.bytes)
        return (
            f"{{ argumentIndex := {self.argument_index}, "
            f"targetId := {self.target_id}, offset := {self.offset}, "
            f"bytes := [{rendered}] }}"
        )


@dataclass(frozen=True)
class CallableExternalCapabilitySpec:
    id: int
    resource_id: int
    resolver_contract_id: int
    resolver_site_id: int
    exact_identities: tuple[ExactIdentitySpec, ...]
    string_identities: tuple[StaticStringIdentitySpec, ...]

    def lean_capability(self) -> str:
        exact = ", ".join(item.lean() for item in self.exact_identities)
        strings = ", ".join(item.lean() for item in self.string_identities)
        return (
            "{ id := "
            f"{self.id}, resourceId := {self.resource_id}, "
            f"resolverContractId := {self.resolver_contract_id}, "
            f"resolverSiteId := {self.resolver_site_id}, "
            f"immutableIdentityArguments := [{exact}], "
            f"immutableStringIdentityArguments := [{strings}] }}"
        )

@dataclass(frozen=True)
class MemoryFootprintSpec:
    access: str
    base_argument: int
    offset: int
    bytes: int
    nullable: bool

    def lean(self) -> str:
        return (
            f"{{ access := .{self.access}, baseArgument := {self.base_argument}, "
            f"offset := {self.offset}, size := .fixed {self.bytes}, "
            f"nullable := {str(self.nullable).lower()} }}"
        )


@dataclass(frozen=True)
class ResolvedExternalABIContractSpec:
    id: int
    capability_id: int
    transfer: str
    argument_sources: tuple[CallableArgumentSourceSpec, ...]
    stack_result_delta: int
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    memory_effect: str
    memory_footprints: tuple[MemoryFootprintSpec, ...]

    def lean(self) -> str:
        sources = ", ".join(source.lean() for source in self.argument_sources)
        preserved = ", ".join(f".{register}" for register in self.preserved_registers)
        clobbered = ", ".join(f".{register}" for register in self.clobbered_registers)
        footprints = ", ".join(item.lean() for item in self.memory_footprints)
        effect = {
            "none": "none",
            "read_only": "readOnly",
            "argument_ranges": "argumentRanges",
        }[self.memory_effect]
        return (
            "{ id := "
            f"{self.id}, capabilityId := {self.capability_id}, "
            f"transfer := .{self.transfer}, argumentSources := [{sources}], "
            f"stackResultDelta := {self.stack_result_delta}, "
            f"preservedRegisters := [{preserved}], "
            f"clobberedRegisters := [{clobbered}], memoryEffect := .{effect}, "
            f"memoryFootprints := [{footprints}], worldEffect := .none }}"
        )


@dataclass(frozen=True)
class CallableExternalCapabilityArtifact:
    resolver_contracts: tuple[ResolverCallContractSpec, ...]
    capabilities: tuple[CallableExternalCapabilitySpec, ...]
    resolved_abi_contracts: tuple[ResolvedExternalABIContractSpec, ...]


def _unique_ids(values: Sequence[object], context: str) -> None:
    ids = [getattr(value, "id") for value in values]
    if len(set(ids)) != len(ids):
        raise StageAInputError(f"{context} ids are ambiguous")
    if ids != sorted(ids):
        raise StageAInputError(f"{context} must be in canonical id order")


def _parse_resolvers(value: object) -> tuple[ResolverCallContractSpec, ...]:
    result: list[ResolverCallContractSpec] = []
    for index, raw in enumerate(_array(value, "resolver_contracts")):
        context = f"resolver_contracts[{index}]"
        item = _object(raw, context)
        _exact_fields(item, _RESOLVER_FIELDS, context)
        register = item["result_register"]
        if not isinstance(register, str) or register not in _REGISTERS:
            raise StageAInputError(f"{context}.result_register is unsupported")
        if item["result_relation"] != _CALLABLE_RESULT_RELATION:
            raise StageAInputError(
                f"{context}.result_relation must be "
                f"{_CALLABLE_RESULT_RELATION}; ordinary relatedWord is not callable"
            )
        sources = _argument_sources(
            item["argument_sources"], f"{context}.argument_sources"
        )
        if any(source.kind != "stack_word" for source in sources):
            raise StageAInputError(
                f"{context}.argument_sources must use exact stack_word sources"
            )
        indices = tuple(
            _natural(raw_index, f"{context}.identity_argument_indices[{item_index}]")
            for item_index, raw_index in enumerate(
                _array(
                    item["identity_argument_indices"],
                    f"{context}.identity_argument_indices",
                )
            )
        )
        if len(set(indices)) != len(indices):
            raise StageAInputError(
                f"{context}.identity_argument_indices contains duplicates"
            )
        if any(identity >= len(sources) for identity in indices):
            raise StageAInputError(
                f"{context}.identity_argument_indices is outside argument_sources"
            )
        nullable = item["nullable"]
        if not isinstance(nullable, bool):
            raise StageAInputError(f"{context}.nullable must be a boolean")
        result.append(ResolverCallContractSpec(
            id=_natural(item["id"], f"{context}.id"),
            machine_contract_id=_natural(
                item["machine_contract_id"], f"{context}.machine_contract_id"
            ),
            result_register=register,
            argument_sources=sources,
            identity_argument_indices=indices,
            nullable=nullable,
        ))
    if not result:
        raise StageAInputError("resolver_contracts must not be empty")
    _unique_ids(result, "resolver_contracts")
    return tuple(result)


def _parse_capabilities(
    value: object, resolvers: Mapping[int, ResolverCallContractSpec]
) -> tuple[CallableExternalCapabilitySpec, ...]:
    result: list[CallableExternalCapabilitySpec] = []
    for index, raw in enumerate(_array(value, "capabilities")):
        context = f"capabilities[{index}]"
        item = _object(raw, context)
        _exact_fields(item, _CAPABILITY_FIELDS, context)
        capability_id = _natural(item["id"], f"{context}.id")
        resource_id = _natural(item["resource_id"], f"{context}.resource_id")
        if resource_id != capability_id:
            raise StageAInputError(
                f"{context}.resource_id must equal the capability id"
            )
        resolver_id = _natural(
            item["resolver_contract_id"], f"{context}.resolver_contract_id"
        )
        resolver = resolvers.get(resolver_id)
        if resolver is None:
            raise StageAInputError(f"{context} names an unknown resolver contract")

        exact: list[ExactIdentitySpec] = []
        strings: list[StaticStringIdentitySpec] = []
        ordered_indices: list[int] = []
        seen_string = False
        for identity_index, raw_identity in enumerate(
            _array(item["identity_arguments"], f"{context}.identity_arguments")
        ):
            identity_context = f"{context}.identity_arguments[{identity_index}]"
            identity = _object(raw_identity, identity_context)
            kind = identity.get("kind")
            if kind == "exact_word":
                if seen_string:
                    raise StageAInputError(
                        f"{context}.identity_arguments must put exact words before strings"
                    )
                _exact_fields(identity, _EXACT_IDENTITY_FIELDS, identity_context)
                argument_index = _natural(
                    identity["index"], f"{identity_context}.index"
                )
                exact.append(ExactIdentitySpec(
                    index=argument_index,
                    value=_natural(
                        identity["value"], f"{identity_context}.value", u32=True
                    ),
                ))
            elif kind == "canonical_static_string":
                seen_string = True
                _exact_fields(identity, _STRING_IDENTITY_FIELDS, identity_context)
                argument_index = _natural(
                    identity["argument_index"],
                    f"{identity_context}.argument_index",
                )
                bytes_value = _byte_list(
                    identity["bytes"], f"{identity_context}.bytes"
                )
                if any(byte == 0 for byte in bytes_value):
                    raise StageAInputError(
                        f"{identity_context}.bytes must exclude embedded terminators"
                    )
                strings.append(StaticStringIdentitySpec(
                    argument_index=argument_index,
                    target_id=_natural(
                        identity["target_id"], f"{identity_context}.target_id"
                    ),
                    offset=_natural(
                        identity["offset"], f"{identity_context}.offset", u32=True
                    ),
                    bytes=bytes_value,
                ))
            else:
                raise StageAInputError(
                    f"{identity_context}.kind must be exact_word or "
                    "canonical_static_string"
                )
            ordered_indices.append(argument_index)
        if tuple(ordered_indices) != resolver.identity_argument_indices:
            raise StageAInputError(
                f"{context}.identity_arguments must exactly cover the resolver "
                "identity indices in order"
            )
        result.append(CallableExternalCapabilitySpec(
            id=capability_id,
            resource_id=resource_id,
            resolver_contract_id=resolver_id,
            resolver_site_id=_natural(
                item["resolver_site_id"], f"{context}.resolver_site_id"
            ),
            exact_identities=tuple(exact),
            string_identities=tuple(strings),
        ))
    if not result:
        raise StageAInputError("capabilities must not be empty")
    _unique_ids(result, "capabilities")
    if len({item.resource_id for item in result}) != len(result):
        raise StageAInputError("capability resource ids are ambiguous")
    return tuple(result)


def _parse_footprints(
    value: object, context: str, argument_count: int
) -> tuple[MemoryFootprintSpec, ...]:
    result: list[MemoryFootprintSpec] = []
    for index, raw in enumerate(_array(value, context)):
        item_context = f"{context}[{index}]"
        item = _object(raw, item_context)
        _exact_fields(item, _FOOTPRINT_FIELDS, item_context)
        access = item["access"]
        if access not in {"read", "write"}:
            raise StageAInputError(f"{item_context}.access must be read or write")
        base_argument = _natural(
            item["base_argument"], f"{item_context}.base_argument"
        )
        if base_argument >= argument_count:
            raise StageAInputError(
                f"{item_context}.base_argument is outside argument_sources"
            )
        nullable = item["nullable"]
        if not isinstance(nullable, bool):
            raise StageAInputError(f"{item_context}.nullable must be a boolean")
        result.append(MemoryFootprintSpec(
            access=access,
            base_argument=base_argument,
            offset=_natural(item["offset"], f"{item_context}.offset", u32=True),
            bytes=_natural(item["bytes"], f"{item_context}.bytes", u32=True),
            nullable=nullable,
        ))
        if result[-1].bytes == 0:
            raise StageAInputError(f"{item_context}.bytes must be positive")
    if len(set(result)) != len(result):
        raise StageAInputError(f"{context} contains duplicate footprints")
    return tuple(result)


def _parse_abis(
    value: object, capabilities: Mapping[int, CallableExternalCapabilitySpec]
) -> tuple[ResolvedExternalABIContractSpec, ...]:
    result: list[ResolvedExternalABIContractSpec] = []
    for index, raw in enumerate(_array(value, "resolved_abi_contracts")):
        context = f"resolved_abi_contracts[{index}]"
        item = _object(raw, context)
        _exact_fields(item, _ABI_FIELDS, context)
        capability_id = _natural(
            item["capability_id"], f"{context}.capability_id"
        )
        if capability_id not in capabilities:
            raise StageAInputError(f"{context} names an unknown capability")
        transfer = item["transfer"]
        if transfer not in _TRANSFERS:
            raise StageAInputError(f"{context}.transfer must be call or jump")
        sources = _argument_sources(
            item["argument_sources"], f"{context}.argument_sources"
        )
        delta = _natural(
            item["stack_result_delta"], f"{context}.stack_result_delta", u32=True
        )
        if delta % 4:
            raise StageAInputError(
                f"{context}.stack_result_delta must be word aligned"
            )
        preserved = _register_list(
            item["preserved_registers"], f"{context}.preserved_registers"
        )
        clobbered = _register_list(
            item["clobbered_registers"], f"{context}.clobbered_registers"
        )
        if set(preserved) & set(clobbered):
            raise StageAInputError(f"{context} ABI register sets overlap")
        if set(preserved) | set(clobbered) != _REGISTERS:
            raise StageAInputError(
                f"{context} ABI register sets must cover every non-stack register"
            )
        memory_effect = item["memory_effect"]
        if memory_effect not in _MEMORY_EFFECTS:
            raise StageAInputError(f"{context}.memory_effect is unsupported")
        if item["world_effect"] != "none":
            raise StageAInputError(
                f"{context}.world_effect must be none in the standalone wrapper"
            )
        footprints = _parse_footprints(
            item["memory_footprints"],
            f"{context}.memory_footprints",
            len(sources),
        )
        if memory_effect == "none" and footprints:
            raise StageAInputError(
                f"{context}.memory_effect none requires no footprints"
            )
        if memory_effect == "read_only" and any(
            footprint.access != "read" for footprint in footprints
        ):
            raise StageAInputError(
                f"{context}.memory_effect read_only forbids write footprints"
            )
        if memory_effect == "argument_ranges" and not any(
            footprint.access == "write" for footprint in footprints
        ):
            raise StageAInputError(
                f"{context}.memory_effect argument_ranges requires a write footprint"
            )
        result.append(ResolvedExternalABIContractSpec(
            id=_natural(item["id"], f"{context}.id"),
            capability_id=capability_id,
            transfer=transfer,
            argument_sources=sources,
            stack_result_delta=delta,
            preserved_registers=preserved,
            clobbered_registers=clobbered,
            memory_effect=memory_effect,
            memory_footprints=footprints,
        ))
    if not result:
        raise StageAInputError("resolved_abi_contracts must not be empty")
    _unique_ids(result, "resolved_abi_contracts")
    routes = [(item.capability_id, item.transfer) for item in result]
    if len(set(routes)) != len(routes):
        raise StageAInputError("resolved ABI capability/transfer routes are ambiguous")
    return tuple(result)


def parse_callable_external_capability_artifact(
    payload: object,
) -> CallableExternalCapabilityArtifact:
    root = _object(payload, "callable external capability artifact")
    _exact_fields(root, _ROOT_FIELDS, "callable external capability artifact")
    if root["format"] != CALLABLE_EXTERNAL_CAPABILITY_FORMAT:
        raise StageAInputError("unsupported callable external capability format")
    resolvers = _parse_resolvers(root["resolver_contracts"])
    resolver_by_id = {item.id: item for item in resolvers}
    capabilities = _parse_capabilities(root["capabilities"], resolver_by_id)
    capability_by_id = {item.id: item for item in capabilities}
    return CallableExternalCapabilityArtifact(
        resolver_contracts=resolvers,
        capabilities=capabilities,
        resolved_abi_contracts=_parse_abis(
            root["resolved_abi_contracts"], capability_by_id
        ),
    )


__all__ = [
    "CALLABLE_EXTERNAL_CAPABILITY_FORMAT",
    "CALLABLE_EXTERNAL_PROFILE_FORMAT",
    "CallableArgumentSourceSpec",
    "CallableExternalCapabilityArtifact",
    "CallableExternalProfile",
    "CallableExternalTargetProfileSpec",
    "CallableModuleProfileSpec",
    "CallableResolverProfileSpec",
    "load_callable_external_profile",
    "parse_callable_external_capability_artifact",
]
