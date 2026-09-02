"""Architecture-neutral physical call-frame transport."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    PHYSICAL_CALL_FRAME_V2_FORMAT,
    PHYSICAL_CALL_FRAME_V3_FORMAT,
)
from ..boundary import (
    BoundarySchemaV1,
    BoundaryValuePathV1,
    TargetDataLayoutV1,
    resolve_field_path_type,
)
from ._canonical import (
    CallProtocolError,
    array,
    boolean,
    content_id,
    exact,
    identifier,
    object_,
    sint,
    text,
    uint,
)


TRANSFER_KINDS = frozenset(
    {"direct", "indirect", "import", "export", "callback", "table_slot", "tail"}
)
SLOT_ROLES = frozenset(
    {"parameter", "result", "this", "hidden_sret", "variadic_control", "variadic_argument"}
)
PASS_MODES = frozenset({"direct", "split", "extended", "coerced", "indirect", "ignored"})
LOCATION_KINDS = frozenset({"register", "stack", "memory", "none"})
REGISTER_BANKS = frozenset({"gpr", "x87", "xmm", "flags", "custom"})
PHASES = frozenset({"caller_before", "callee_entry", "callee_exit", "caller_after"})
REPRESENTATIONS = frozenset(
    {"identity", "zero_extend", "sign_extend", "truncate", "bitcast", "x87_storage", "unspecified"}
)
OUTCOMES = frozenset({"normal", "no_return", "exceptional", "nonlocal"})


def physical_frame_abi_sha256_v1(value: object) -> str:
    """Identify only the caller-visible physical ABI of a call frame.

    A frame's content identity also binds its semantic schema, subject, and
    direction.  Those facts intentionally differ at the two ends of a PE
    import edge.  Cross-module compatibility and export-alias coalescing need
    the narrower identity of the bytes, registers, and stack discipline that
    actually cross that edge.
    """

    if not isinstance(value, Mapping):
        raise CallProtocolError("physical call frame is malformed")
    transport = value.get("transport")
    if not isinstance(transport, Mapping):
        raise CallProtocolError("physical call transport is malformed")
    physical = {
        key: item
        for key, item in transport.items()
        if key not in {"format", "id", "subject", "transfer_kind"}
    }
    return canonical_sha256_v3(physical)


@dataclass(frozen=True)
class CallSubjectV1:
    kind: str
    identity: str
    image_selector: str | None

    @classmethod
    def parse(cls, value: object, context: str = "call subject") -> "CallSubjectV1":
        row = object_(value, context)
        exact(row, {"kind", "id", "image_selector"}, context)
        kind = text(row["kind"], f"{context} kind")
        if kind not in {"function", "import", "export", "callback", "callsite", "table_slot", "library_member"}:
            raise CallProtocolError(f"{context} kind is unsupported")
        return cls(
            kind,
            identifier(row["id"], f"{context} id"),
            None if row["image_selector"] is None else identifier(row["image_selector"], f"{context} image selector"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"kind": self.kind, "id": self.identity, "image_selector": self.image_selector}


@dataclass(frozen=True)
class FrameLocationV2:
    kind: str
    phase: str
    width_bits: int
    bank: str | None = None
    name: str | None = None
    stack_base: str | None = None
    stack_offset_bytes: int | None = None
    memory_slot: str | None = None

    @classmethod
    def parse(cls, value: object, context: str = "frame location") -> "FrameLocationV2":
        row = object_(value, context)
        exact(row, {"kind", "phase", "width_bits", "bank", "name", "stack_base", "stack_offset_bytes", "memory_slot"}, context)
        kind = text(row["kind"], f"{context} kind")
        if kind not in LOCATION_KINDS:
            raise CallProtocolError(f"{context} kind is unsupported")
        phase = text(row["phase"], f"{context} phase")
        if phase not in PHASES:
            raise CallProtocolError(f"{context} phase is unsupported")
        width = uint(row["width_bits"], f"{context} width", minimum=1)
        bank = None if row["bank"] is None else text(row["bank"], f"{context} bank")
        name = None if row["name"] is None else identifier(row["name"], f"{context} name")
        base = None if row["stack_base"] is None else identifier(row["stack_base"], f"{context} stack base")
        offset = None if row["stack_offset_bytes"] is None else sint(row["stack_offset_bytes"], f"{context} stack offset")
        memory = None if row["memory_slot"] is None else identifier(row["memory_slot"], f"{context} memory slot")
        if kind == "register":
            if bank not in REGISTER_BANKS or name is None or any(item is not None for item in (base, offset, memory)):
                raise CallProtocolError(f"{context} register coordinates are invalid")
        elif kind == "stack":
            if base is None or offset is None or any(item is not None for item in (bank, name, memory)):
                raise CallProtocolError(f"{context} stack coordinates are invalid")
        elif kind == "memory":
            if memory is None or any(item is not None for item in (bank, name, base, offset)):
                raise CallProtocolError(f"{context} memory coordinates are invalid")
        elif any(item is not None for item in (bank, name, base, offset, memory)):
            raise CallProtocolError(f"{context} none location has coordinates")
        return cls(kind, phase, width, bank, name, base, offset, memory)

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "phase": self.phase,
            "width_bits": self.width_bits,
            "bank": self.bank,
            "name": self.name,
            "stack_base": self.stack_base,
            "stack_offset_bytes": self.stack_offset_bytes,
            "memory_slot": self.memory_slot,
        }

    @property
    def key(self) -> tuple[object, ...]:
        return (self.kind, self.phase, self.bank, self.name, self.stack_base, self.stack_offset_bytes, self.memory_slot)


@dataclass(frozen=True)
class FrameFragmentV2:
    logical_offset_bits: int
    width_bits: int
    location_offset_bits: int
    representation: str
    specified: bool
    location: FrameLocationV2

    @classmethod
    def parse(cls, value: object, context: str) -> "FrameFragmentV2":
        row = object_(value, context)
        exact(row, {"logical_offset_bits", "width_bits", "location_offset_bits", "representation", "specified", "location"}, context)
        representation = text(row["representation"], f"{context} representation")
        if representation not in REPRESENTATIONS:
            raise CallProtocolError(f"{context} representation is unsupported")
        specified = boolean(row["specified"], f"{context} specified")
        if (representation == "unspecified") != (not specified):
            raise CallProtocolError(f"{context} unspecified representation and flag disagree")
        location = FrameLocationV2.parse(row["location"], f"{context} location")
        width = uint(row["width_bits"], f"{context} width", minimum=1)
        location_offset = uint(row["location_offset_bits"], f"{context} location offset")
        if location_offset + width > location.width_bits:
            raise CallProtocolError(f"{context} exceeds its physical location")
        return cls(uint(row["logical_offset_bits"], f"{context} logical offset"), width, location_offset, representation, specified, location)

    def to_payload(self) -> dict[str, object]:
        return {
            "logical_offset_bits": self.logical_offset_bits,
            "width_bits": self.width_bits,
            "location_offset_bits": self.location_offset_bits,
            "representation": self.representation,
            "specified": self.specified,
            "location": self.location.to_payload(),
        }


@dataclass(frozen=True)
class FrameSlotV2:
    identity: str
    role: str
    storage_bits: int
    value_bits: int
    pass_mode: str
    logical_path: tuple[str, ...]
    fragments: tuple[FrameFragmentV2, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "FrameSlotV2":
        row = object_(value, context)
        exact(row, {"id", "role", "storage_bits", "value_bits", "pass_mode", "logical_path", "fragments"}, context)
        role = text(row["role"], f"{context} role")
        mode = text(row["pass_mode"], f"{context} pass mode")
        if role not in SLOT_ROLES or mode not in PASS_MODES:
            raise CallProtocolError(f"{context} role or pass mode is unsupported")
        storage = uint(row["storage_bits"], f"{context} storage bits")
        useful = uint(row["value_bits"], f"{context} value bits")
        if useful > storage:
            raise CallProtocolError(f"{context} value bits exceed storage")
        path = tuple(identifier(item, f"{context} logical path") for item in array(row["logical_path"], f"{context} logical path"))
        fragments = tuple(FrameFragmentV2.parse(item, f"{context} fragment {index}") for index, item in enumerate(array(row["fragments"], f"{context} fragments")))
        if mode == "ignored" and fragments:
            raise CallProtocolError(f"{context} ignored slot has physical fragments")
        if mode != "ignored" and not fragments:
            raise CallProtocolError(f"{context} transported slot has no fragments")
        logical = sorted((item.logical_offset_bits, item.logical_offset_bits + item.width_bits) for item in fragments if item.specified)
        if any(right[0] < left[1] for left, right in zip(logical, logical[1:])):
            raise CallProtocolError(f"{context} specified logical fragments overlap")
        if any(end > storage for _, end in logical):
            raise CallProtocolError(f"{context} fragment exceeds logical storage")
        physical: dict[tuple[object, ...], list[tuple[int, int]]] = {}
        for fragment in fragments:
            physical.setdefault(fragment.location.key, []).append((fragment.location_offset_bits, fragment.location_offset_bits + fragment.width_bits))
        for ranges in physical.values():
            ranges.sort()
            if any(right[0] < left[1] for left, right in zip(ranges, ranges[1:])):
                raise CallProtocolError(f"{context} physical fragments overlap")
        return cls(identifier(row["id"], f"{context} id"), role, storage, useful, mode, path, fragments)

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "role": self.role,
            "storage_bits": self.storage_bits,
            "value_bits": self.value_bits,
            "pass_mode": self.pass_mode,
            "logical_path": list(self.logical_path),
            "fragments": [item.to_payload() for item in self.fragments],
        }


@dataclass(frozen=True)
class StackDisciplineV2:
    coordinate: str
    alignment_bytes: int
    cleanup: str
    cleanup_bytes: int
    reserved_bytes: int

    @classmethod
    def parse(cls, value: object, context: str = "stack discipline") -> "StackDisciplineV2":
        row = object_(value, context)
        exact(row, {"coordinate", "alignment_bytes", "cleanup", "cleanup_bytes", "reserved_bytes"}, context)
        cleanup = text(row["cleanup"], f"{context} cleanup")
        if cleanup not in {"caller", "callee", "none", "custom"}:
            raise CallProtocolError(f"{context} cleanup is unsupported")
        cleanup_bytes = uint(row["cleanup_bytes"], f"{context} cleanup bytes")
        if cleanup in {"caller", "none"} and cleanup_bytes:
            raise CallProtocolError(f"{context} caller/none cleanup cannot pop bytes")
        return cls(identifier(row["coordinate"], f"{context} coordinate"), uint(row["alignment_bytes"], f"{context} alignment", minimum=1), cleanup, cleanup_bytes, uint(row["reserved_bytes"], f"{context} reserved bytes"))

    def to_payload(self) -> dict[str, object]:
        return {"coordinate": self.coordinate, "alignment_bytes": self.alignment_bytes, "cleanup": self.cleanup, "cleanup_bytes": self.cleanup_bytes, "reserved_bytes": self.reserved_bytes}


@dataclass(frozen=True)
class PhysicalCallFrameV2:
    frame_id: str
    subject: CallSubjectV1
    transfer_kind: str
    target: str
    abi_dialect: str
    calling_convention: str
    arguments: tuple[FrameSlotV2, ...]
    results: tuple[FrameSlotV2, ...]
    stack: StackDisciplineV2
    preserved_state: tuple[str, ...]
    clobbered_state: tuple[str, ...]
    outcomes: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        subject: CallSubjectV1 | Mapping[str, object],
        transfer_kind: str,
        target: str,
        abi_dialect: str,
        calling_convention: str,
        arguments: Sequence[FrameSlotV2 | Mapping[str, object]],
        results: Sequence[FrameSlotV2 | Mapping[str, object]],
        stack: StackDisciplineV2 | Mapping[str, object],
        preserved_state: Sequence[str],
        clobbered_state: Sequence[str],
        outcomes: Sequence[str] = ("normal",),
    ) -> "PhysicalCallFrameV2":
        parsed_subject = subject if isinstance(subject, CallSubjectV1) else CallSubjectV1.parse(subject)
        if transfer_kind not in TRANSFER_KINDS:
            raise CallProtocolError("call transfer kind is unsupported")
        parsed_arguments = tuple(item if isinstance(item, FrameSlotV2) else FrameSlotV2.parse(item, f"call argument {index}") for index, item in enumerate(arguments))
        parsed_results = tuple(item if isinstance(item, FrameSlotV2) else FrameSlotV2.parse(item, f"call result {index}") for index, item in enumerate(results))
        ids = [item.identity for item in (*parsed_arguments, *parsed_results)]
        if len(ids) != len(set(ids)):
            raise CallProtocolError("call frame slot ids are duplicated")
        _reject_physical_overlap((*parsed_arguments, *parsed_results))
        parsed_stack = stack if isinstance(stack, StackDisciplineV2) else StackDisciplineV2.parse(stack)
        preserved = tuple(sorted(set(identifier(item, "preserved state") for item in preserved_state)))
        clobbered = tuple(sorted(set(identifier(item, "clobbered state") for item in clobbered_state)))
        if set(preserved) & set(clobbered):
            raise CallProtocolError("machine state cannot be both preserved and clobbered")
        outcome_values = tuple(sorted(set(text(item, "call outcome") for item in outcomes)))
        if not outcome_values or any(item not in OUTCOMES for item in outcome_values):
            raise CallProtocolError("call outcomes are empty or unsupported")
        core = {
            "format": PHYSICAL_CALL_FRAME_V2_FORMAT,
            "subject": parsed_subject.to_payload(),
            "transfer_kind": transfer_kind,
            "target": identifier(target, "call target"),
            "abi_dialect": identifier(abi_dialect, "call ABI dialect"),
            "calling_convention": identifier(calling_convention, "calling convention"),
            "arguments": [item.to_payload() for item in parsed_arguments],
            "results": [item.to_payload() for item in parsed_results],
            "stack": parsed_stack.to_payload(),
            "preserved_state": list(preserved),
            "clobbered_state": list(clobbered),
            "outcomes": list(outcome_values),
        }
        return cls(content_id("physical-call-frame-v2", core), parsed_subject, transfer_kind, str(core["target"]), str(core["abi_dialect"]), str(core["calling_convention"]), parsed_arguments, parsed_results, parsed_stack, preserved, clobbered, outcome_values)

    @classmethod
    def parse(cls, value: object) -> "PhysicalCallFrameV2":
        row = object_(value, "physical call frame")
        exact(row, {"format", "id", "subject", "transfer_kind", "target", "abi_dialect", "calling_convention", "arguments", "results", "stack", "preserved_state", "clobbered_state", "outcomes"}, "physical call frame")
        if row["format"] != PHYSICAL_CALL_FRAME_V2_FORMAT:
            raise CallProtocolError("unsupported physical call frame format")
        result = cls.create(subject=CallSubjectV1.parse(row["subject"]), transfer_kind=str(row["transfer_kind"]), target=str(row["target"]), abi_dialect=str(row["abi_dialect"]), calling_convention=str(row["calling_convention"]), arguments=[FrameSlotV2.parse(item, f"call argument {index}") for index, item in enumerate(array(row["arguments"], "call arguments"))], results=[FrameSlotV2.parse(item, f"call result {index}") for index, item in enumerate(array(row["results"], "call results"))], stack=StackDisciplineV2.parse(row["stack"]), preserved_state=[str(item) for item in array(row["preserved_state"], "preserved state")], clobbered_state=[str(item) for item in array(row["clobbered_state"], "clobbered state")], outcomes=[str(item) for item in array(row["outcomes"], "call outcomes")])
        if row["id"] != result.frame_id:
            raise CallProtocolError("physical call frame id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PHYSICAL_CALL_FRAME_V2_FORMAT,
            "id": self.frame_id,
            "subject": self.subject.to_payload(),
            "transfer_kind": self.transfer_kind,
            "target": self.target,
            "abi_dialect": self.abi_dialect,
            "calling_convention": self.calling_convention,
            "arguments": [item.to_payload() for item in self.arguments],
            "results": [item.to_payload() for item in self.results],
            "stack": self.stack.to_payload(),
            "preserved_state": list(self.preserved_state),
            "clobbered_state": list(self.clobbered_state),
            "outcomes": list(self.outcomes),
        }


@dataclass(frozen=True)
class FrameValueBindingV3:
    slot_id: str
    path: BoundaryValuePathV1
    transport: str

    @classmethod
    def parse(cls, value: object, context: str) -> "FrameValueBindingV3":
        row = object_(value, context)
        exact(row, {"slot_id", "path", "transport"}, context)
        transport = text(row["transport"], f"{context} transport")
        if transport not in {"semantic", "hidden_return_address", "variadic_metadata"}:
            raise CallProtocolError(f"{context} transport is unsupported")
        return cls(
            identifier(row["slot_id"], f"{context} slot"),
            BoundaryValuePathV1.parse(row["path"], f"{context} path"),
            transport,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "slot_id": self.slot_id,
            "path": self.path.to_payload(),
            "transport": self.transport,
        }


@dataclass(frozen=True)
class PhysicalCallFrameV3:
    """A physical frame content-bound to canonical values and target layout."""

    frame_id: str
    schema_sha256: str
    layout_sha256: str
    signature_id: str
    transport: PhysicalCallFrameV2
    bindings: tuple[FrameValueBindingV3, ...]
    dialect_rule_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        schema: BoundarySchemaV1,
        layout: TargetDataLayoutV1,
        signature_id: str,
        transport: PhysicalCallFrameV2,
        bindings: Sequence[FrameValueBindingV3 | Mapping[str, object]],
        dialect_rule_ids: Sequence[str],
    ) -> "PhysicalCallFrameV3":
        if layout.schema_sha256 != schema.schema_sha256:
            raise CallProtocolError("physical call frame layout binds another schema")
        signature = schema.signature_index.get(signature_id)
        if signature is None:
            raise CallProtocolError("physical call frame names an unknown signature")
        function = schema.type_index[signature.function_type_id]
        if (
            transport.target != layout.target
            or transport.abi_dialect != layout.abi_dialect
            or transport.calling_convention != function.body["calling_convention"]
        ):
            raise CallProtocolError(
                "physical call transport disagrees with its signature or target layout"
            )
        parsed = tuple(
            sorted(
                (
                    item
                    if isinstance(item, FrameValueBindingV3)
                    else FrameValueBindingV3.parse(item, f"frame binding {index}")
                    for index, item in enumerate(bindings)
                ),
                key=lambda item: item.slot_id,
            )
        )
        slots = {item.identity: item for item in (*transport.arguments, *transport.results)}
        if [item.slot_id for item in parsed] != sorted(slots):
            raise CallProtocolError(
                "physical call frame must bind every transport slot exactly once"
            )
        for binding in parsed:
            _validate_v3_binding(schema, layout, signature, slots[binding.slot_id], binding)
        rules = tuple(
            sorted(set(identifier(item, "call dialect rule id") for item in dialect_rule_ids))
        )
        if not rules:
            raise CallProtocolError("physical call frame lacks dialect rule provenance")
        core = {
            "format": PHYSICAL_CALL_FRAME_V3_FORMAT,
            "schema_sha256": schema.schema_sha256,
            "layout_sha256": layout.layout_sha256,
            "signature_id": signature.identity,
            "transport": transport.to_payload(),
            "bindings": [item.to_payload() for item in parsed],
            "dialect_rule_ids": list(rules),
        }
        return cls(
            content_id("physical-call-frame-v3", core),
            schema.schema_sha256,
            layout.layout_sha256,
            signature.identity,
            transport,
            parsed,
            rules,
        )

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        schema: BoundarySchemaV1,
        layout: TargetDataLayoutV1,
    ) -> "PhysicalCallFrameV3":
        row = object_(value, "physical call frame V3")
        exact(
            row,
            {
                "format", "id", "schema_sha256", "layout_sha256", "signature_id",
                "transport", "bindings", "dialect_rule_ids",
            },
            "physical call frame V3",
        )
        if row["format"] != PHYSICAL_CALL_FRAME_V3_FORMAT:
            raise CallProtocolError("unsupported physical call frame V3 format")
        result = cls.create(
            schema=schema,
            layout=layout,
            signature_id=str(row["signature_id"]),
            transport=PhysicalCallFrameV2.parse(row["transport"]),
            bindings=[
                FrameValueBindingV3.parse(item, f"frame binding {index}")
                for index, item in enumerate(array(row["bindings"], "frame bindings"))
            ],
            dialect_rule_ids=[
                str(item) for item in array(row["dialect_rule_ids"], "dialect rules")
            ],
        )
        if row["id"] != result.frame_id:
            raise CallProtocolError("physical call frame V3 id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PHYSICAL_CALL_FRAME_V3_FORMAT,
            "id": self.frame_id,
            "schema_sha256": self.schema_sha256,
            "layout_sha256": self.layout_sha256,
            "signature_id": self.signature_id,
            "transport": self.transport.to_payload(),
            "bindings": [item.to_payload() for item in self.bindings],
            "dialect_rule_ids": list(self.dialect_rule_ids),
        }


def _validate_v3_binding(
    schema: BoundarySchemaV1,
    layout: TargetDataLayoutV1,
    signature: object,
    slot: FrameSlotV2,
    binding: FrameValueBindingV3,
) -> None:
    signature_parameters = getattr(signature, "parameters")
    signature_results = getattr(signature, "results")
    values = (
        signature_parameters
        if binding.path.root == "parameter"
        else signature_results
        if binding.path.root == "result"
        else ()
    )
    value = next(
        (item for item in values if item.identity == binding.path.value_id), None
    )
    if value is None:
        raise CallProtocolError("physical call binding names an unknown signature value")
    if binding.transport == "hidden_return_address":
        if slot.role != "hidden_sret" or binding.path.root != "result":
            raise CallProtocolError("hidden return address binding is inconsistent")
        if slot.storage_bits != layout.pointer_width_bits:
            raise CallProtocolError("hidden return address has the wrong pointer width")
        return
    if binding.transport == "variadic_metadata":
        if slot.role != "variadic_control":
            raise CallProtocolError("variadic metadata binding is inconsistent")
        return
    if slot.role in {"parameter", "this"} and binding.path.root != "parameter":
        raise CallProtocolError("argument slot is not bound to a parameter")
    if slot.role == "result" and binding.path.root != "result":
        raise CallProtocolError("result slot is not bound to a result")
    type_id = resolve_field_path_type(
        schema, value.type_id, binding.path.fields,
        context="physical call binding",
    ).identity
    expected_layout = layout.index.get(type_id)
    if expected_layout is None or slot.storage_bits != expected_layout.size_bits:
        raise CallProtocolError("physical call slot storage disagrees with canonical layout")


def _reject_physical_overlap(slots: Sequence[FrameSlotV2]) -> None:
    occupied: dict[tuple[object, ...], list[tuple[int, int, str]]] = {}
    for slot in slots:
        for fragment in slot.fragments:
            location = fragment.location
            if location.kind == "register":
                key = (location.phase, "register", location.bank, location.name)
                start = fragment.location_offset_bits
            elif location.kind == "stack":
                key = (location.phase, "stack", location.stack_base)
                start = int(location.stack_offset_bytes or 0) * 8 + fragment.location_offset_bits
            elif location.kind == "memory":
                key = (location.phase, "memory", location.memory_slot)
                start = fragment.location_offset_bits
            else:
                continue
            occupied.setdefault(key, []).append((start, start + fragment.width_bits, slot.identity))
    for key, ranges in occupied.items():
        ranges.sort()
        for left, right in zip(ranges, ranges[1:]):
            if right[0] < left[1]:
                raise CallProtocolError(
                    f"call frame slots {left[2]!r} and {right[2]!r} overlap at {key!r}"
                )


__all__ = [
    "CallSubjectV1",
    "FrameFragmentV2",
    "FrameLocationV2",
    "FrameSlotV2",
    "FrameValueBindingV3",
    "PhysicalCallFrameV2",
    "PhysicalCallFrameV3",
    "StackDisciplineV2",
    "physical_frame_abi_sha256_v1",
]
