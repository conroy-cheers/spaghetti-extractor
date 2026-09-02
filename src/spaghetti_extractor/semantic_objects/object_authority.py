"""Portable object-origin authority for machine addresses and references."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .references import CapabilityStatus, CheckedReference
from .formats import MACHINE_OBJECT_AUTHORITY_V2_FORMAT


OBJECT_AUTHORITY_V2 = MACHINE_OBJECT_AUTHORITY_V2_FORMAT
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


_GENERATION_MODE_BY_LOCATOR = {
    "image_rva": "image_epoch",
    "tls_offset": "thread_epoch",
    "captured_stack": "invocation_epoch",
    "resolved_data_import": "provider_anchor_epoch",
    "external_allocation": "allocation_epoch",
    "resource": "resource_epoch",
}


@dataclass(frozen=True)
class MachineObjectInstanceV2:
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
class ReferenceResolutionV2:
    status: CapabilityStatus
    reference: CheckedReference | None
    rule_id: str | None
    code: str


_LOCATOR_FIELDS = {
    "image_rva": frozenset({"kind", "image_id", "rva"}),
    "tls_offset": frozenset({"kind", "module_id", "offset"}),
    "captured_stack": frozenset({"kind", "frame_id", "offset"}),
    "resolved_data_import": frozenset({"kind", "slot_id", "offset"}),
    "external_allocation": frozenset({"kind", "allocation_id", "offset"}),
    "resource": frozenset({"kind", "resource_id", "offset"}),
}


@dataclass(frozen=True)
class LoaderRealizedLocatorV2:
    """A stable object locator whose concrete address is supplied by the loader/runtime."""

    kind: str
    identity: str
    offset: int

    @classmethod
    def parse(
        cls, value: object, context: str = "loader-realized locator"
    ) -> "LoaderRealizedLocatorV2":
        if not isinstance(value, Mapping):
            raise MachineObjectAuthorityError(f"{context} must be an object")
        kind = value.get("kind")
        fields = _LOCATOR_FIELDS.get(str(kind))
        if fields is None or set(value) != fields:
            raise MachineObjectAuthorityError(f"{context} has invalid fields or kind")
        identity_field = {
            "image_rva": "image_id",
            "tls_offset": "module_id",
            "captured_stack": "frame_id",
            "resolved_data_import": "slot_id",
            "external_allocation": "allocation_id",
            "resource": "resource_id",
        }[str(kind)]
        identity = value[identity_field]
        offset_field = "rva" if kind == "image_rva" else "offset"
        offset = value[offset_field]
        if not isinstance(identity, str) or not identity:
            raise MachineObjectAuthorityError(f"{context} identity is invalid")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            or offset > 0xFFFFFFFF
        ):
            raise MachineObjectAuthorityError(f"{context} offset is invalid")
        return cls(str(kind), identity, int(offset))

    def to_payload(self) -> dict[str, object]:
        identity_field = {
            "image_rva": "image_id",
            "tls_offset": "module_id",
            "captured_stack": "frame_id",
            "resolved_data_import": "slot_id",
            "external_allocation": "allocation_id",
            "resource": "resource_id",
        }[self.kind]
        offset_field = "rva" if self.kind == "image_rva" else "offset"
        return {
            "kind": self.kind,
            identity_field: self.identity,
            offset_field: self.offset,
        }

    @property
    def selector(self) -> str:
        return f"{self.kind}:{self.identity}:{self.offset:08x}"


@dataclass(frozen=True)
class MachineObjectRuleV2:
    identity: str
    kind: str
    domain: int
    object_id: int
    generation: int
    extent: int
    permissions: int
    lifetime: str
    locator: LoaderRealizedLocatorV2
    interior_pointers: bool
    evidence_sha256: str

    @classmethod
    def parse(
        cls, value: object, context: str = "machine object rule V2"
    ) -> "MachineObjectRuleV2":
        fields = {
            "id", "kind", "domain", "object", "generation", "extent",
            "permissions", "lifetime", "locator", "interior_pointers",
            "evidence_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise MachineObjectAuthorityError(f"{context} has invalid fields")
        identity, kind, lifetime = value["id"], value["kind"], value["lifetime"]
        if not isinstance(identity, str) or not identity:
            raise MachineObjectAuthorityError(f"{context} id is invalid")
        if kind not in OBJECT_KINDS or lifetime not in LIFETIMES:
            raise MachineObjectAuthorityError(f"{context} policy is invalid")
        numbers: dict[str, int] = {}
        for field in ("domain", "object", "generation", "extent", "permissions"):
            item = value[field]
            maximum = 0xFFFFFFFF if field == "extent" else 2**64 - 1
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or item <= 0
                or item > maximum
            ):
                raise MachineObjectAuthorityError(f"{context} {field} is invalid")
            numbers[field] = int(item)
        interior = value["interior_pointers"]
        if not isinstance(interior, bool):
            raise MachineObjectAuthorityError(
                f"{context} interior_pointers must be Boolean"
            )
        evidence = value["evidence_sha256"]
        if not isinstance(evidence, str) or _DIGEST.fullmatch(evidence) is None:
            raise MachineObjectAuthorityError(f"{context} evidence is invalid")
        return cls(
            str(identity), str(kind), numbers["domain"], numbers["object"],
            numbers["generation"], numbers["extent"], numbers["permissions"],
            str(lifetime), LoaderRealizedLocatorV2.parse(value["locator"], context),
            interior, evidence,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "kind": self.kind,
            "domain": self.domain,
            "object": self.object_id,
            "generation": self.generation,
            "extent": self.extent,
            "permissions": self.permissions,
            "lifetime": self.lifetime,
            "locator": self.locator.to_payload(),
            "interior_pointers": self.interior_pointers,
            "evidence_sha256": self.evidence_sha256,
        }

    @property
    def generation_policy(self) -> dict[str, object]:
        """Return the sole runtime generation interpretation for this rule.

        The authority format already binds a generation seed, locator, and
        lifetime.  Projecting their meaning here avoids a second authored
        lifecycle policy while making link/runtime consumers agree explicitly
        about where the live generation comes from.
        """

        return {
            "mode": _GENERATION_MODE_BY_LOCATOR[self.locator.kind],
            "seed": self.generation,
            "expires_with": self.lifetime,
        }


@dataclass(frozen=True)
class DataExportAnchorV2:
    identity: str
    rule_id: str
    byte_offset: int
    access: str
    aliases: tuple[dict[str, object], ...]
    typed_view: Mapping[str, object] | None = None

    @classmethod
    def parse(
        cls, value: object, context: str = "data export anchor"
    ) -> "DataExportAnchorV2":
        fields = {"id", "rule_id", "byte_offset", "access", "aliases", "typed_view"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise MachineObjectAuthorityError(f"{context} has invalid fields")
        identity, rule_id, offset, access = (
            value["id"], value["rule_id"], value["byte_offset"], value["access"]
        )
        if not isinstance(identity, str) or not identity or not isinstance(rule_id, str) or not rule_id:
            raise MachineObjectAuthorityError(f"{context} identity is invalid")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise MachineObjectAuthorityError(f"{context} byte offset is invalid")
        if access not in {"read", "write", "read_write"}:
            raise MachineObjectAuthorityError(f"{context} access is invalid")
        aliases_raw = value["aliases"]
        if not isinstance(aliases_raw, list) or not aliases_raw:
            raise MachineObjectAuthorityError(f"{context} aliases must be nonempty")
        aliases: list[dict[str, object]] = []
        for index, alias in enumerate(aliases_raw):
            if not isinstance(alias, Mapping) or set(alias) != {"name", "ordinal"}:
                raise MachineObjectAuthorityError(f"{context} alias {index} is invalid")
            name, ordinal = alias["name"], alias["ordinal"]
            if name is not None and (not isinstance(name, str) or not name):
                raise MachineObjectAuthorityError(f"{context} alias name is invalid")
            if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0:
                raise MachineObjectAuthorityError(f"{context} alias ordinal is invalid")
            aliases.append({"name": name, "ordinal": int(ordinal)})
        ordered = tuple(sorted(aliases, key=lambda row: (int(row["ordinal"]), str(row["name"] or ""))))
        if tuple(aliases) != ordered or len({(row["name"], row["ordinal"]) for row in ordered}) != len(ordered):
            raise MachineObjectAuthorityError(f"{context} aliases are not canonical")
        typed_view = value["typed_view"]
        if typed_view is not None and (
            not isinstance(typed_view, Mapping)
            or set(typed_view) != {"boundary_type_id", "target_layout_sha256"}
            or not isinstance(typed_view["boundary_type_id"], str)
            or not isinstance(typed_view["target_layout_sha256"], str)
            or _DIGEST.fullmatch(str(typed_view["target_layout_sha256"])) is None
        ):
            raise MachineObjectAuthorityError(f"{context} typed view is invalid")
        return cls(str(identity), str(rule_id), int(offset), str(access), ordered, typed_view)

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "rule_id": self.rule_id,
            "byte_offset": self.byte_offset,
            "access": self.access,
            "aliases": [dict(row) for row in self.aliases],
            "typed_view": None if self.typed_view is None else dict(self.typed_view),
        }


class MachineObjectAuthorityV2:
    """Loader-relative object authority with explicit resolution selectors."""

    def __init__(
        self,
        *,
        machine_backend: str,
        bindings: Mapping[str, str],
        rules: Sequence[MachineObjectRuleV2 | Mapping[str, object]],
        data_export_anchors: Sequence[DataExportAnchorV2 | Mapping[str, object]] = (),
    ) -> None:
        if not isinstance(machine_backend, str) or not machine_backend:
            raise MachineObjectAuthorityError("object authority backend is missing")
        if not bindings or any(
            not isinstance(key, str) or not key or not isinstance(value, str)
            or _DIGEST.fullmatch(value) is None for key, value in bindings.items()
        ):
            raise MachineObjectAuthorityError("object authority bindings are invalid")
        parsed = tuple(sorted((
            item if isinstance(item, MachineObjectRuleV2) else MachineObjectRuleV2.parse(item)
            for item in rules
        ), key=lambda item: item.identity))
        if len({item.identity for item in parsed}) != len(parsed):
            raise MachineObjectAuthorityError("object rules contain duplicate IDs")
        if len({(item.domain, item.object_id) for item in parsed}) != len(parsed):
            raise MachineObjectAuthorityError("object rules reuse an origin identity")
        if len({item.locator.selector for item in parsed}) != len(parsed):
            raise MachineObjectAuthorityError("object rules have ambiguous locators")
        anchors = tuple(sorted((
            item if isinstance(item, DataExportAnchorV2) else DataExportAnchorV2.parse(item)
            for item in data_export_anchors
        ), key=lambda item: item.identity))
        if len({item.identity for item in anchors}) != len(anchors):
            raise MachineObjectAuthorityError("data anchors contain duplicate IDs")
        rule_index = {item.identity: item for item in parsed}
        for anchor in anchors:
            rule = rule_index.get(anchor.rule_id)
            if rule is None or anchor.byte_offset >= rule.extent:
                raise MachineObjectAuthorityError("data anchor is outside its object rule")
            required = {"read": 1, "write": 2, "read_write": 3}[anchor.access]
            if rule.permissions & required != required:
                raise MachineObjectAuthorityError("data anchor access contradicts its rule")
        self.machine_backend = machine_backend
        self.bindings = dict(sorted(bindings.items()))
        self.rules = parsed
        self.data_export_anchors = anchors
        self._rules = rule_index

    @classmethod
    def parse(cls, value: object) -> "MachineObjectAuthorityV2":
        fields = {"format", "machine_backend", "bindings", "rules", "data_export_anchors", "authority_sha256"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise MachineObjectAuthorityError("machine object authority V2 has invalid fields")
        if value["format"] != OBJECT_AUTHORITY_V2:
            raise MachineObjectAuthorityError("unsupported machine object authority V2 format")
        core = {key: copy.deepcopy(item) for key, item in value.items() if key != "authority_sha256"}
        if value["authority_sha256"] != canonical_sha256_v3(core):
            raise MachineObjectAuthorityError("machine object authority V2 digest is stale")
        if not isinstance(value["bindings"], Mapping) or not isinstance(value["rules"], list) or not isinstance(value["data_export_anchors"], list):
            raise MachineObjectAuthorityError("machine object authority V2 inventory is invalid")
        return cls(
            machine_backend=str(value["machine_backend"]),
            bindings=value["bindings"],
            rules=value["rules"],
            data_export_anchors=value["data_export_anchors"],
        )

    def _core_payload(self) -> dict[str, object]:
        return {
            "format": OBJECT_AUTHORITY_V2,
            "machine_backend": self.machine_backend,
            "bindings": dict(self.bindings),
            "rules": [item.to_payload() for item in self.rules],
            "data_export_anchors": [item.to_payload() for item in self.data_export_anchors],
        }

    @property
    def authority_sha256(self) -> str:
        return canonical_sha256_v3(self._core_payload())

    def to_payload(self) -> dict[str, object]:
        core = self._core_payload()
        return {**core, "authority_sha256": canonical_sha256_v3(core)}

    def realize_instances(
        self, realizations: Mapping[str, int]
    ) -> tuple[MachineObjectInstanceV2, ...]:
        expected = {item.locator.selector for item in self.rules}
        if set(realizations) != expected:
            raise MachineObjectAuthorityError(
                "object realization selector inventory is incomplete or stale"
            )
        instances: list[MachineObjectInstanceV2] = []
        for rule in self.rules:
            base = realizations[rule.locator.selector]
            if not isinstance(base, int) or isinstance(base, bool) or base < 0 or base + rule.extent > 0x100000000:
                raise MachineObjectAuthorityError("object realization is outside x86 address space")
            instances.append(MachineObjectInstanceV2(
                rule.identity, rule.domain, rule.object_id, rule.generation,
                int(base), rule.extent, rule.permissions,
            ))
        return tuple(instances)

    def resolve(
        self,
        address: int,
        *,
        requested_extent: int,
        required_permissions: int,
        instances: Sequence[MachineObjectInstanceV2],
        authority_selector: str | None = None,
        nullable: bool = False,
        allow_one_past: bool = False,
    ) -> ReferenceResolutionV2:
        selected = tuple(
            item for item in instances
            if authority_selector is None or item.rule_id == authority_selector
        )
        if authority_selector is not None and authority_selector not in self._rules:
            return ReferenceResolutionV2(CapabilityStatus.TYPE_MISMATCH, None, None, "authority_selector_unknown")
        if address == 0:
            if nullable:
                return ReferenceResolutionV2(CapabilityStatus.OK, CheckedReference(0, 0, 0, 0, 0, 0), None, "null_reference")
            return ReferenceResolutionV2(CapabilityStatus.FAULT, None, None, "null_forbidden")
        candidates: list[tuple[MachineObjectInstanceV2, int]] = []
        for item in selected:
            rule = self._rules.get(item.rule_id)
            if rule is None or not item.live:
                continue
            inside = item.base <= address < item.end
            one_past = allow_one_past and rule.interior_pointers and address == item.end
            if not inside and not one_past:
                continue
            offset = address - item.base
            if (offset and not rule.interior_pointers) or requested_extent < 0 or offset + requested_extent > item.extent:
                continue
            if item.permissions & required_permissions != required_permissions:
                continue
            candidates.append((item, offset))
        if not candidates:
            return ReferenceResolutionV2(CapabilityStatus.FAULT, None, None, "origin_missing")
        if len(candidates) != 1:
            return ReferenceResolutionV2(CapabilityStatus.TYPE_MISMATCH, None, None, "origin_ambiguous")
        item, offset = candidates[0]
        return ReferenceResolutionV2(
            CapabilityStatus.OK,
            CheckedReference(item.domain, item.object_id, item.generation, offset, item.extent, item.permissions),
            item.rule_id,
            "origin_resolved",
        )


def derive_pe32_machine_object_authority_v2(
    *,
    module_interface: Mapping[str, Any],
    module_interface_sha256: str,
    refinements: Sequence[Mapping[str, object]] = (),
) -> MachineObjectAuthorityV2:
    """Derive default section objects, checked partitions, and exact EAT data anchors."""

    if module_interface.get("format") != "spaghetti-extractor-pe32-module-interface-v2":
        raise MachineObjectAuthorityError("PE32 object authority requires module-interface-v2")
    if _DIGEST.fullmatch(module_interface_sha256) is None:
        raise MachineObjectAuthorityError("module-interface binding digest is invalid")
    image_id = module_interface.get("image_id")
    sections = module_interface.get("sections")
    export_directory = module_interface.get("export_directory")
    if not isinstance(image_id, str) or not image_id or not isinstance(sections, list) or not isinstance(export_directory, Mapping):
        raise MachineObjectAuthorityError("module interface loader surface is malformed")
    section_index: dict[int, Mapping[str, Any]] = {}
    for row in sections:
        if not isinstance(row, Mapping) or not isinstance(row.get("index"), int):
            raise MachineObjectAuthorityError("module interface section is malformed")
        section_index[int(row["index"])] = row
    by_section: dict[int, list[Mapping[str, object]]] = {}
    for index, row in enumerate(refinements):
        if not isinstance(row, Mapping) or set(row) != {
            "id", "section_index", "rva", "extent", "permissions", "lifetime", "evidence_sha256"
        }:
            raise MachineObjectAuthorityError(f"section refinement {index} is malformed")
        section_id = row["section_index"]
        if not isinstance(section_id, int) or isinstance(section_id, bool) or section_id not in section_index:
            raise MachineObjectAuthorityError(f"section refinement {index} names an unknown section")
        by_section.setdefault(int(section_id), []).append(row)
    rules: list[MachineObjectRuleV2] = []
    used_origins: set[tuple[int, int]] = set()

    def append_rule(
        *, identity: str, section: Mapping[str, Any], rva: int, extent: int,
        permissions: int, lifetime: str, evidence: str,
    ) -> None:
        object_id = int(canonical_sha256_v3({
            "image_id": image_id, "rule_id": identity, "rva": rva,
            "extent": extent,
        })[:16], 16) or 1
        while (1, object_id) in used_origins:
            object_id = object_id + 1 if object_id < 2**64 - 1 else 1
        used_origins.add((1, object_id))
        rules.append(MachineObjectRuleV2(
            identity=identity,
            kind="image",
            domain=1,
            object_id=object_id,
            generation=1,
            extent=extent,
            permissions=permissions,
            lifetime="image",
            locator=LoaderRealizedLocatorV2("image_rva", str(image_id), rva),
            interior_pointers=True,
            evidence_sha256=evidence,
        ))

    for section_id, section in sorted(section_index.items()):
        if section.get("executable") is True:
            if section_id in by_section:
                raise MachineObjectAuthorityError("executable sections cannot receive data-object refinements")
            continue
        rva = section.get("rva")
        extent = section.get("mapped_size")
        permissions_row = section.get("permissions")
        if (
            not isinstance(rva, int) or isinstance(rva, bool)
            or not isinstance(extent, int) or isinstance(extent, bool) or extent <= 0
            or not isinstance(permissions_row, Mapping)
        ):
            raise MachineObjectAuthorityError("module interface section geometry is invalid")
        section_permissions = (1 if permissions_row.get("read") is True else 0) | (2 if permissions_row.get("write") is True else 0)
        if section_permissions == 0:
            raise MachineObjectAuthorityError("non-executable image section has no data permissions")
        partitions = sorted(by_section.get(section_id, ()), key=lambda row: int(row["rva"]))
        if not partitions:
            append_rule(
                identity=f"image:{image_id}:section:{section_id}", section=section,
                rva=rva, extent=extent, permissions=section_permissions,
                lifetime="image", evidence=module_interface_sha256,
            )
            continue
        cursor = rva
        for partition in partitions:
            part_rva, part_extent = partition["rva"], partition["extent"]
            if (
                not isinstance(part_rva, int) or isinstance(part_rva, bool)
                or not isinstance(part_extent, int) or isinstance(part_extent, bool)
                or part_extent <= 0 or part_rva != cursor
            ):
                raise MachineObjectAuthorityError("section refinements do not form a non-overlapping partition")
            part_permissions = partition["permissions"]
            if not isinstance(part_permissions, int) or isinstance(part_permissions, bool) or part_permissions <= 0 or part_permissions & section_permissions != part_permissions:
                raise MachineObjectAuthorityError("section refinement permissions contradict the section")
            lifetime = partition["lifetime"]
            identity = partition["id"]
            evidence = partition["evidence_sha256"]
            if lifetime != "image" or not isinstance(identity, str) or not identity or not isinstance(evidence, str) or _DIGEST.fullmatch(evidence) is None:
                raise MachineObjectAuthorityError("section refinement authority is invalid")
            append_rule(
                identity=identity, section=section, rva=part_rva,
                extent=part_extent, permissions=part_permissions,
                lifetime="image", evidence=evidence,
            )
            cursor += part_extent
        if cursor != rva + extent:
            raise MachineObjectAuthorityError("section refinements do not cover their entire section")

    anchors: list[DataExportAnchorV2] = []
    slots = export_directory.get("slots")
    if not isinstance(slots, list):
        raise MachineObjectAuthorityError("module interface EAT geometry is malformed")
    data_by_rva: dict[int, list[Mapping[str, Any]]] = {}
    for slot in slots:
        if not isinstance(slot, Mapping) or slot.get("kind") != "data":
            continue
        target_rva = slot.get("rva")
        ordinal = slot.get("ordinal")
        names = slot.get("names")
        if not isinstance(target_rva, int) or not isinstance(ordinal, int) or not isinstance(names, list):
            raise MachineObjectAuthorityError("data export slot is malformed")
        data_by_rva.setdefault(target_rva, []).append(slot)
    for target_rva, target_slots in sorted(data_by_rva.items()):
        containing = [
            rule for rule in rules
            if rule.locator.kind == "image_rva"
            and rule.locator.offset <= target_rva < rule.locator.offset + rule.extent
        ]
        if len(containing) != 1:
            raise MachineObjectAuthorityError("data export does not resolve to exactly one image object")
        rule = containing[0]
        alias_rows: list[dict[str, object]] = []
        for target_slot in target_slots:
            ordinal = int(target_slot["ordinal"])
            names = target_slot["names"]
            alias_rows.extend(
                ({"name": name, "ordinal": ordinal} for name in names)
                if names else ({"name": None, "ordinal": ordinal},)
            )
        aliases = tuple(sorted(
            alias_rows,
            key=lambda row: (int(row["ordinal"]), str(row["name"] or "")),
        ))
        anchors.append(DataExportAnchorV2(
            identity=f"data-export:{image_id}:rva:{target_rva:08x}",
            rule_id=rule.identity,
            byte_offset=target_rva - rule.locator.offset,
            access="read_write" if rule.permissions & 2 else "read",
            aliases=aliases,
        ))
    return MachineObjectAuthorityV2(
        machine_backend="x86-pe32-loader-relative-v2",
        bindings={
            "module_interface_sha256": module_interface_sha256,
            "original_pe_sha256": str(module_interface["identity"]["pe_sha256"]),
            "load_image_contract_sha256": str(module_interface["identity"]["load_image_contract_sha256"]),
        },
        rules=rules,
        data_export_anchors=anchors,
    )


__all__ = [
    "DataExportAnchorV2",
    "LoaderRealizedLocatorV2",
    "MachineObjectAuthorityError",
    "MachineObjectAuthorityV2",
    "MachineObjectInstanceV2",
    "MachineObjectRuleV2",
    "OBJECT_AUTHORITY_V2",
    "ReferenceResolutionV2",
    "derive_pe32_machine_object_authority_v2",
]
