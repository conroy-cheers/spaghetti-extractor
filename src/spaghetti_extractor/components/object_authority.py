"""Portable object-origin authority for machine addresses and references."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .capabilities import CapabilityStatus, CheckedReference
from .formats import MACHINE_OBJECT_AUTHORITY_V1_FORMAT
from .interface_ir import PortableComponentInterfaceV2
from .machine_binding import ComponentMachineBindingV1, MachineProjectionV1


OBJECT_AUTHORITY_V1 = MACHINE_OBJECT_AUTHORITY_V1_FORMAT
OBJECT_KINDS = frozenset(
    {"image", "static", "stack", "process", "external", "tls", "resource"}
)
LIFETIMES = frozenset(
    {"process", "image", "invocation", "thread", "allocation", "resource"}
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ORIGIN_DOMAINS = {
    "image": 1,
    "static": 1,
    "stack": 2,
    "process": 3,
    "external": 3,
    "tls": 4,
    "resource": 5,
}


class MachineObjectAuthorityError(ValueError):
    """Object authority is malformed, ambiguous, stale, or insufficient."""


@dataclass(frozen=True)
class MachineObjectRuleV1:
    identity: str
    kind: str
    domain: int
    object_id: int
    permissions: int
    lifetime: str
    evidence_sha256: str
    base: int | None = None
    extent: int | None = None

    @classmethod
    def parse(cls, value: object, context: str = "machine object rule") -> "MachineObjectRuleV1":
        if not isinstance(value, Mapping) or set(value) != {
            "id", "kind", "domain", "object", "base", "extent",
            "permissions", "lifetime", "evidence_sha256",
        }:
            raise MachineObjectAuthorityError(f"{context} has invalid fields")
        identity, kind, lifetime = value["id"], value["kind"], value["lifetime"]
        if not isinstance(identity, str) or not identity:
            raise MachineObjectAuthorityError(f"{context} id is invalid")
        if kind not in OBJECT_KINDS or lifetime not in LIFETIMES:
            raise MachineObjectAuthorityError(f"{context} policy is invalid")
        numbers: dict[str, int] = {}
        for field in ("domain", "object", "permissions"):
            item = value[field]
            if not isinstance(item, int) or isinstance(item, bool) or item <= 0 or item > 2**64 - 1:
                raise MachineObjectAuthorityError(f"{context} {field} is invalid")
            numbers[field] = item
        base, extent = value["base"], value["extent"]
        if (base is None) != (extent is None):
            raise MachineObjectAuthorityError(
                f"{context} static base and extent must be supplied together"
            )
        if base is not None and (
            not isinstance(base, int) or isinstance(base, bool) or base < 0 or base > 0xFFFFFFFF
        ):
            raise MachineObjectAuthorityError(f"{context} base is invalid")
        if extent is not None and (
            not isinstance(extent, int) or isinstance(extent, bool) or extent <= 0 or extent > 0x100000000
        ):
            raise MachineObjectAuthorityError(f"{context} extent is invalid")
        if base is not None and base + int(extent) > 0x100000000:
            raise MachineObjectAuthorityError(f"{context} range overflows x86 address space")
        evidence = value["evidence_sha256"]
        if not isinstance(evidence, str) or _DIGEST.fullmatch(evidence) is None:
            raise MachineObjectAuthorityError(f"{context} evidence is invalid")
        return cls(
            identity,
            str(kind),
            numbers["domain"],
            numbers["object"],
            numbers["permissions"],
            str(lifetime),
            evidence,
            None if base is None else int(base),
            None if extent is None else int(extent),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "kind": self.kind,
            "domain": self.domain,
            "object": self.object_id,
            "base": self.base,
            "extent": self.extent,
            "permissions": self.permissions,
            "lifetime": self.lifetime,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True)
class MachineObjectInstanceV1:
    rule_id: str
    domain: int
    object_id: int
    generation: int
    base: int
    extent: int
    permissions: int
    live: bool = True

    @property
    def end(self) -> int:
        return self.base + self.extent


@dataclass(frozen=True)
class ReferenceResolutionV1:
    status: CapabilityStatus
    reference: CheckedReference | None
    rule_id: str | None
    code: str


class MachineObjectAuthorityV1:
    def __init__(
        self,
        *,
        machine_backend: str,
        bindings: Mapping[str, str],
        rules: Sequence[MachineObjectRuleV1 | Mapping[str, object]],
    ) -> None:
        parsed = tuple(
            item if isinstance(item, MachineObjectRuleV1) else MachineObjectRuleV1.parse(item)
            for item in rules
        )
        parsed = tuple(sorted(parsed, key=lambda item: item.identity))
        identities = tuple(item.identity for item in parsed)
        origin_keys = tuple((item.domain, item.object_id) for item in parsed)
        if identities != tuple(sorted(set(identities))):
            raise MachineObjectAuthorityError("object rules must be unique and ordered")
        if len(origin_keys) != len(set(origin_keys)):
            raise MachineObjectAuthorityError("object rules reuse an origin identity")
        if not machine_backend:
            raise MachineObjectAuthorityError("object authority backend is missing")
        if not bindings or any(
            not isinstance(key, str) or not key or not isinstance(value, str) or _DIGEST.fullmatch(value) is None
            for key, value in bindings.items()
        ):
            raise MachineObjectAuthorityError("object authority bindings are invalid")
        self.machine_backend = machine_backend
        self.bindings = dict(sorted(bindings.items()))
        self.rules = parsed
        self._rules = {item.identity: item for item in parsed}

    @classmethod
    def parse(cls, value: object) -> "MachineObjectAuthorityV1":
        if not isinstance(value, Mapping) or set(value) != {
            "format", "machine_backend", "bindings", "rules", "authority_sha256"
        }:
            raise MachineObjectAuthorityError("machine object authority has invalid fields")
        if value["format"] != OBJECT_AUTHORITY_V1:
            raise MachineObjectAuthorityError("unsupported machine object authority format")
        core = {key: copy.deepcopy(item) for key, item in value.items() if key != "authority_sha256"}
        observed = value["authority_sha256"]
        if not isinstance(observed, str) or _DIGEST.fullmatch(observed) is None or canonical_sha256_v3(core) != observed:
            raise MachineObjectAuthorityError("machine object authority digest is stale")
        bindings = value["bindings"]
        rules = value["rules"]
        if not isinstance(bindings, Mapping) or not isinstance(rules, list):
            raise MachineObjectAuthorityError("machine object authority inventory is invalid")
        return cls(
            machine_backend=str(value["machine_backend"]),
            bindings=bindings,
            rules=rules,
        )

    @property
    def authority_sha256(self) -> str:
        return canonical_sha256_v3(self._core_payload())

    def _core_payload(self) -> dict[str, object]:
        return {
            "format": OBJECT_AUTHORITY_V1,
            "machine_backend": self.machine_backend,
            "bindings": dict(self.bindings),
            "rules": [item.to_payload() for item in self.rules],
        }

    def to_payload(self) -> dict[str, object]:
        core = self._core_payload()
        return {**core, "authority_sha256": canonical_sha256_v3(core)}

    def static_instances(self) -> tuple[MachineObjectInstanceV1, ...]:
        return tuple(
            MachineObjectInstanceV1(
                rule_id=item.identity,
                domain=item.domain,
                object_id=item.object_id,
                generation=1,
                base=int(item.base),
                extent=int(item.extent),
                permissions=item.permissions,
            )
            for item in self.rules
            if item.base is not None and item.extent is not None
        )

    def bind_dynamic(
        self,
        *,
        rule_id: str,
        generation: int,
        base: int,
        extent: int,
        permissions: int | None = None,
    ) -> MachineObjectInstanceV1:
        try:
            rule = self._rules[rule_id]
        except KeyError as exc:
            raise MachineObjectAuthorityError("dynamic object uses an unknown rule") from exc
        if rule.base is not None:
            raise MachineObjectAuthorityError("static object rule cannot be rebound")
        if generation <= 0 or base < 0 or extent <= 0 or base + extent > 0x100000000:
            raise MachineObjectAuthorityError("dynamic object instance is invalid")
        granted = rule.permissions if permissions is None else permissions
        if granted <= 0 or granted & rule.permissions != granted:
            raise MachineObjectAuthorityError("dynamic object permissions exceed its rule")
        return MachineObjectInstanceV1(
            rule.identity,
            rule.domain,
            rule.object_id,
            generation,
            base,
            extent,
            granted,
        )

    def resolve(
        self,
        address: int,
        *,
        requested_extent: int,
        required_permissions: int,
        instances: Sequence[MachineObjectInstanceV1] = (),
        nullable: bool = False,
        allow_one_past: bool = False,
    ) -> ReferenceResolutionV1:
        if address == 0:
            if nullable:
                return ReferenceResolutionV1(
                    CapabilityStatus.OK,
                    CheckedReference(0, 0, 0, 0, 0, 0),
                    None,
                    "null_reference",
                )
            return ReferenceResolutionV1(CapabilityStatus.FAULT, None, None, "null_forbidden")
        candidates = []
        for item in (*self.static_instances(), *instances):
            if not item.live:
                continue
            inside = item.base <= address < item.end
            one_past = allow_one_past and address == item.end
            if not inside and not one_past:
                continue
            offset = address - item.base
            if requested_extent < 0 or offset + requested_extent > item.extent:
                continue
            if item.permissions & required_permissions != required_permissions:
                continue
            candidates.append((item, offset))
        if not candidates:
            return ReferenceResolutionV1(CapabilityStatus.FAULT, None, None, "origin_missing")
        origins = {(item.domain, item.object_id, item.generation) for item, _ in candidates}
        if len(origins) != 1:
            return ReferenceResolutionV1(CapabilityStatus.TYPE_MISMATCH, None, None, "origin_ambiguous")
        item, offset = candidates[0]
        return ReferenceResolutionV1(
            CapabilityStatus.OK,
            CheckedReference(
                item.domain,
                item.object_id,
                item.generation,
                offset,
                item.extent,
                item.permissions,
            ),
            item.rule_id,
            "origin_resolved",
        )

    def realize(
        self,
        reference: CheckedReference,
        *,
        required_permissions: int,
        instances: Sequence[MachineObjectInstanceV1] = (),
        nullable: bool = False,
        allow_one_past: bool = False,
    ) -> tuple[CapabilityStatus, int | None, str]:
        if reference.is_null:
            return (
                (CapabilityStatus.OK, 0, "null_reference")
                if nullable
                else (CapabilityStatus.FAULT, None, "null_forbidden")
            )
        candidates = [
            item
            for item in (*self.static_instances(), *instances)
            if item.live
            and item.domain == reference.domain
            and item.object_id == reference.object_id
        ]
        if len(candidates) != 1:
            return CapabilityStatus.TYPE_MISMATCH, None, "origin_missing_or_ambiguous"
        item = candidates[0]
        status = reference.validate(
            domain=item.domain,
            object_id=item.object_id,
            generation=item.generation,
            extent=item.extent,
            required_permissions=required_permissions,
            allow_one_past=allow_one_past,
            nullable=nullable,
        )
        if status is not CapabilityStatus.OK:
            return status, None, "reference_invalid"
        address = item.base + reference.offset
        if address > 0xFFFFFFFF:
            return CapabilityStatus.FAULT, None, "address_overflow"
        return CapabilityStatus.OK, address, "reference_realized"


def derive_machine_object_authority(
    *,
    interface: PortableComponentInterfaceV2,
    machine_binding: ComponentMachineBindingV1,
) -> MachineObjectAuthorityV1:
    """Derive closed origin rules from checked reference/view projections."""

    if (
        machine_binding.interface_id != interface.identity
        or machine_binding.interface_sha256 != interface.sha256
    ):
        raise MachineObjectAuthorityError(
            "object authority targets a different portable interface"
        )
    types = interface.type_index()
    operations = interface.operation_index()
    policies: dict[str, dict[str, object]] = {}

    def add(projection: MachineProjectionV1, type_id: str) -> None:
        if projection.kind not in {"reference", "view"}:
            return
        logical_type = types[type_id]
        if logical_type.kind != projection.kind:
            raise MachineObjectAuthorityError(
                "origin projection kind differs from its logical type"
            )
        authority = projection.payload.get("authority")
        if not isinstance(authority, Mapping):
            raise MachineObjectAuthorityError("origin projection has no authority")
        identity = str(authority.get("id"))
        permissions = {"read": 1, "write": 2, "read_write": 3}.get(
            str(logical_type.access)
        )
        if permissions is None:
            raise MachineObjectAuthorityError("origin access policy is unsupported")
        candidate = {
            "kind": str(authority.get("kind")),
            "lifetime": str(authority.get("lifetime")),
        }
        previous = policies.get(identity)
        if previous is not None and (
            previous["kind"] != candidate["kind"]
            or previous["lifetime"] != candidate["lifetime"]
        ):
            raise MachineObjectAuthorityError(
                f"origin authority {identity!r} has inconsistent policies"
            )
        candidate["permissions"] = permissions | int(
            0 if previous is None else previous["permissions"]
        )
        policies[identity] = candidate

    state_types = {item.identity: item.type_id for item in interface.state}
    for bound in machine_binding.operations:
        operation = operations[bound.operation_id]
        parameter_types = {item.identity: item.type_id for item in operation.parameters}
        result_types = {item.identity: item.type_id for item in operation.results}
        for item in bound.parameters:
            add(item.projection, parameter_types[item.identity])
        for item in bound.results:
            add(item.projection, result_types[item.identity])
        for item in bound.state:
            add(item.entry, state_types[item.identity])
            add(item.exit, state_types[item.identity])

    rules: list[MachineObjectRuleV1] = []
    used_origins: set[tuple[int, int]] = set()
    for identity, policy in sorted(policies.items()):
        kind = str(policy["kind"])
        domain = _ORIGIN_DOMAINS[kind]
        object_id = int(
            canonical_sha256_v3(
                {"authority": identity, "kind": kind, "domain": domain}
            )[:16],
            16,
        ) or 1
        if (domain, object_id) in used_origins:
            raise MachineObjectAuthorityError("derived origin identity collision")
        used_origins.add((domain, object_id))
        rules.append(
            MachineObjectRuleV1(
                identity=identity,
                kind=kind,
                domain=domain,
                object_id=object_id,
                permissions=int(policy["permissions"]),
                lifetime=str(policy["lifetime"]),
                evidence_sha256=machine_binding.binding_sha256,
            )
        )
    return MachineObjectAuthorityV1(
        machine_backend="x86-pe32-v1",
        bindings={
            "interface_sha256": interface.sha256,
            "machine_binding_sha256": machine_binding.binding_sha256,
            "machine_ir_sha256": machine_binding.machine_ir_sha256,
        },
        rules=rules,
    )


__all__ = [
    "MachineObjectAuthorityError",
    "MachineObjectAuthorityV1",
    "MachineObjectInstanceV1",
    "MachineObjectRuleV1",
    "OBJECT_AUTHORITY_V1",
    "ReferenceResolutionV1",
    "derive_machine_object_authority",
]
