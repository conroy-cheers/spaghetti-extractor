"""Typed external-interface protocol profiles for PE32 reconstruction.

Profiles describe machine-level factory calls and vtable layouts.  They are
static proposal inputs: a profile can identify an external target, but the
final proof must still replay the call boundary and environment refinement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .machine_abi import MachineCallABI, resolve_machine_call_abi
from .machine_import_profiles import MachineImportIdentity
from .stage_binary import StageAInputError
from .util import sha256_file


EXTERNAL_INTERFACE_PROFILE_FORMAT = "stage-a-external-interface-profile-v1"
SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL = "same-library-call-through-v1"
_SAME_NATIVE_TARGET_EFFECT = "sameNativeTargetCallThrough"
_SDK_EXTRACTION_PROVENANCE_KIND = (
    "pinned_clang_ast_from_reviewed_sdk_headers"
)
_SAME_LIBRARY_CALL_THROUGH_PREREQUISITES = (
    "candidate_uses_same_runtime_native_library_binding",
    "candidate_resolves_same_native_interface_target",
    "candidate_uses_declared_machine_abi",
    "candidate_forwards_same_machine_argument_words",
    "candidate_invokes_native_target_exactly_once",
)
_CALLBACK_PREREQUISITE = "candidate_preserves_native_callback_boundary"
INTERFACE_CALLER_MEMORY_FRAME_MODEL = (
    "pe32-declared-pointer-arguments-v1"
)


class ExternalInterfaceProfileError(StageAInputError):
    """An external-interface profile is malformed or ambiguous."""


@dataclass(frozen=True)
class InterfaceEffectContract:
    model: str
    memory_effect: str
    world_effect: str
    callback_effect: str
    prerequisites: tuple[str, ...]
    callback_source: Mapping[str, Any] | None = None
    callback_abi: Mapping[str, Any] | None = None
    callback_lifetime: str | None = None
    callback_status: str | None = None
    callback_blockers: tuple[str, ...] = ()

    def as_json(self) -> dict[str, Any]:
        result = {
            "effect_model": {
                "kind": self.model,
                "library_relation": "same-runtime-native-library-binding",
                "target_relation": "same-pinned-native-interface-target",
                "invocation_relation": "one-to-one",
                "machine_argument_relation": "word-for-word",
                "machine_result_relation": "same-native-call-result",
                "pointed_to_footprints": "not-inferred-from-c-types",
                "prerequisites": list(self.prerequisites),
            },
            "memory_effect": self.memory_effect,
            "memory_footprints": [],
            "world_effect": self.world_effect,
            "callback_effect": self.callback_effect,
        }
        if self.callback_effect == "explicit":
            result.update({
                "callback_source": (
                    None if self.callback_source is None else dict(self.callback_source)
                ),
                "callback_abi": (
                    None if self.callback_abi is None else dict(self.callback_abi)
                ),
                "callback_lifetime": self.callback_lifetime,
                "callback_contract_status": self.callback_status,
                "callback_contract_blockers": list(self.callback_blockers),
            })
        return result


SAME_LIBRARY_CALL_THROUGH_EFFECTS = InterfaceEffectContract(
    model=SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    memory_effect=_SAME_NATIVE_TARGET_EFFECT,
    world_effect=_SAME_NATIVE_TARGET_EFFECT,
    callback_effect="none",
    prerequisites=_SAME_LIBRARY_CALL_THROUGH_PREREQUISITES,
)


def same_library_call_through_effect_json() -> dict[str, Any]:
    """Return the canonical conservative effect relation for native call-through."""

    return SAME_LIBRARY_CALL_THROUGH_EFFECTS.as_json()


def same_library_callback_call_through_effect_json(
    *,
    source: Mapping[str, Any] | None,
    abi: Mapping[str, Any] | None,
    lifetime: str | None,
    status: str,
    blockers: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return a callback-aware native call-through proposal.

    AST extraction can establish a callback's argument source and machine ABI,
    but lifetime is API protocol information.  Missing protocol facts remain an
    explicit incomplete method contract instead of being generalized from a C
    function-pointer type.
    """

    return InterfaceEffectContract(
        model=SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        memory_effect=_SAME_NATIVE_TARGET_EFFECT,
        world_effect=_SAME_NATIVE_TARGET_EFFECT,
        callback_effect="explicit",
        prerequisites=(
            *_SAME_LIBRARY_CALL_THROUGH_PREREQUISITES,
            _CALLBACK_PREREQUISITE,
        ),
        callback_source=source,
        callback_abi=abi,
        callback_lifetime=lifetime,
        callback_status=status,
        callback_blockers=blockers,
    ).as_json()


@dataclass(frozen=True, order=True)
class InterfaceOutput:
    argument_index: int
    interface_id: str
    object_size: int
    vtable_size: int

    def as_json(self) -> dict[str, Any]:
        return {
            "argument_index": self.argument_index,
            "interface_id": self.interface_id,
            "write_width": 4,
            "object_size": self.object_size,
            "vtable_size": self.vtable_size,
            "nullable": True,
            "success_condition": "hresult_succeeded_eax",
        }


@dataclass(frozen=True, order=True)
class InterfaceMemoryArgument:
    argument_index: int
    role: str
    access: str
    extent: str
    retention: str

    def as_json(self) -> dict[str, Any]:
        return {
            "argument_index": self.argument_index,
            "role": self.role,
            "access": self.access,
            "extent": self.extent,
            "retention": self.retention,
        }


@dataclass(frozen=True)
class InterfaceCallerMemoryFrame:
    arguments: tuple[InterfaceMemoryArgument, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "status": "complete",
            "model": INTERFACE_CALLER_MEMORY_FRAME_MODEL,
            "arguments": [argument.as_json() for argument in self.arguments],
            "assumptions": [
                "caller memory is accessed only through declared pointer arguments",
                "non-callback pointer arguments are retained only during the call",
                "opaque interface resources are disjoint from caller image and stack memory",
            ],
        }


@dataclass(frozen=True)
class InterfaceFactory:
    identity: MachineImportIdentity
    declaration: str
    abi: MachineCallABI
    argument_words: int
    outputs: tuple[InterfaceOutput, ...]
    effects: InterfaceEffectContract | None = None
    caller_memory_frame: InterfaceCallerMemoryFrame | None = None


@dataclass(frozen=True)
class InterfaceMethod:
    interface_id: str
    name: str
    slot: int
    abi: MachineCallABI
    argument_words: int
    outputs: tuple[InterfaceOutput, ...]
    effects: InterfaceEffectContract | None = None
    caller_memory_frame: InterfaceCallerMemoryFrame | None = None

    @property
    def offset(self) -> int:
        return self.slot * 4

    def target_json(
        self, *, profile_id: str, profile_sha256: str
    ) -> dict[str, Any]:
        result = {
            "external_protocol": {
                "kind": "pe32-interface-method",
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
                "interface_id": self.interface_id,
                "method": self.name,
                "slot": self.slot,
                "offset": self.offset,
            },
            "abi": self.abi.as_json(),
            "argument_words": self.argument_words,
            "out_interfaces": [output.as_json() for output in self.outputs],
        }
        if self.effects is not None:
            result.update(self.effects.as_json())
        if self.caller_memory_frame is not None:
            result["caller_memory_frame"] = self.caller_memory_frame.as_json()
        return result


@dataclass(frozen=True)
class ExternalInterface:
    interface_id: str
    vtable: str
    methods: tuple[InterfaceMethod, ...]

    def method_at_offset(self, offset: int) -> InterfaceMethod | None:
        if offset < 0 or offset % 4:
            return None
        slot = offset // 4
        if slot >= len(self.methods):
            return None
        method = self.methods[slot]
        return method if method.slot == slot else None


@dataclass(frozen=True)
class ExternalInterfaceProfile:
    path: Path
    profile_id: str
    sha256: str
    model: str
    provenance: Mapping[str, Any]
    factories: tuple[InterfaceFactory, ...]
    interfaces: tuple[ExternalInterface, ...]

    def factories_by_identity(self) -> dict[MachineImportIdentity, InterfaceFactory]:
        return {factory.identity: factory for factory in self.factories}

    def interfaces_by_id(self) -> dict[str, ExternalInterface]:
        return {interface.interface_id: interface for interface in self.interfaces}


def load_external_interface_profile(
    path: Path | str,
) -> ExternalInterfaceProfile:
    profile_path = Path(path).resolve()
    try:
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalInterfaceProfileError(
            f"cannot read external-interface profile {profile_path}: {exc}"
        ) from exc
    if (
        not isinstance(payload, Mapping)
        or payload.get("format") != EXTERNAL_INTERFACE_PROFILE_FORMAT
    ):
        raise ExternalInterfaceProfileError(
            f"unsupported external-interface profile format in {profile_path}"
        )
    if payload.get("status") != "complete":
        raise ExternalInterfaceProfileError(
            f"external-interface profile is not complete: {profile_path}"
        )
    profile_id = _nonempty(payload.get("id"), "external-interface profile ID")
    model = _nonempty(payload.get("model"), "external-interface machine model")
    if model != "x86-pe32":
        raise ExternalInterfaceProfileError(
            f"unsupported external-interface machine model {model!r}"
        )
    provenance = _object(payload.get("provenance"), "profile provenance")
    declared_effect_model = payload.get("effect_model")
    if declared_effect_model not in {
        None,
        SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    }:
        raise ExternalInterfaceProfileError(
            "external-interface profile has an unsupported effect model"
        )
    if (
        provenance.get("kind") == _SDK_EXTRACTION_PROVENANCE_KIND
        and declared_effect_model != SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL
    ):
        raise ExternalInterfaceProfileError(
            "SDK-extracted external-interface profile has no reviewed "
            "same-library call-through effect model"
        )
    require_call_through = (
        declared_effect_model == SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL
    )

    raw_interfaces = _array(payload.get("interfaces"), "profile interfaces")
    interface_ids = {
        _nonempty(_object(raw, "interface").get("id"), "interface ID")
        for raw in raw_interfaces
    }
    if len(interface_ids) != len(raw_interfaces):
        raise ExternalInterfaceProfileError("duplicate external-interface ID")
    interface_vtable_sizes = {
        _nonempty(_object(raw, "interface").get("id"), "interface ID"):
        len(_array(_object(raw, "interface").get("methods"), "interface methods")) * 4
        for raw in raw_interfaces
    }

    interfaces: list[ExternalInterface] = []
    for raw in raw_interfaces:
        row = _object(raw, "interface")
        interface_id = _nonempty(row.get("id"), "interface ID")
        vtable = _nonempty(row.get("vtable"), f"{interface_id} vtable")
        methods = tuple(
            _method(
                item,
                interface_id=interface_id,
                expected_slot=index,
                known_interfaces=interface_ids,
                interface_vtable_sizes=interface_vtable_sizes,
                require_call_through=require_call_through,
            )
            for index, item in enumerate(
                _array(row.get("methods"), f"{interface_id} methods")
            )
        )
        if not methods:
            raise ExternalInterfaceProfileError(
                f"external interface {interface_id} has no methods"
            )
        interfaces.append(ExternalInterface(interface_id, vtable, methods))
    if len({interface.vtable for interface in interfaces}) != len(interfaces):
        raise ExternalInterfaceProfileError("duplicate external-interface vtable")

    factories: list[InterfaceFactory] = []
    identities: set[MachineImportIdentity] = set()
    for index, raw in enumerate(_array(payload.get("factories"), "profile factories")):
        row = _object(raw, f"factory {index}")
        imported = _object(row.get("import"), f"factory {index} import")
        identity = MachineImportIdentity.from_mapping(
            imported, context=f"factory {index} import"
        )
        if identity in identities:
            raise ExternalInterfaceProfileError(
                f"duplicate interface factory {identity.dll}!{identity.value}"
            )
        identities.add(identity)
        argument_words = _bounded_words(
            row.get("argument_words"), f"factory {index} argument words"
        )
        abi = _entry_abi(
            row,
            context=f"factory {index}",
            require_explicit=require_call_through,
        )
        effects = _effects(
            row,
            context=f"factory {index}",
            required=require_call_through or row.get("machine_abi") is not None,
            argument_words=argument_words,
        )
        outputs = _outputs(
            row.get("out_interfaces"),
            argument_words=argument_words,
            known_interfaces=interface_ids,
            interface_vtable_sizes=interface_vtable_sizes,
            context=f"factory {index}",
        )
        if not outputs:
            raise ExternalInterfaceProfileError(
                f"interface factory {identity.dll}!{identity.value} has no output"
            )
        factories.append(InterfaceFactory(
            identity=identity,
            declaration=_nonempty(row.get("declaration"), f"factory {index} declaration"),
            abi=abi,
            argument_words=argument_words,
            outputs=outputs,
            effects=effects,
            caller_memory_frame=_caller_memory_frame(
                row.get("caller_memory_frame"),
                argument_words=argument_words,
                required=require_call_through,
                context=f"factory {index}",
            ),
        ))

    return ExternalInterfaceProfile(
        path=profile_path,
        profile_id=profile_id,
        sha256=sha256_file(profile_path),
        model=model,
        provenance=provenance,
        factories=tuple(sorted(
            factories,
            key=lambda factory: (
                factory.identity.dll,
                factory.identity.kind,
                str(factory.identity.value),
            ),
        )),
        interfaces=tuple(sorted(interfaces, key=lambda interface: interface.interface_id)),
    )


def _method(
    value: Any,
    *,
    interface_id: str,
    expected_slot: int,
    known_interfaces: set[str],
    interface_vtable_sizes: Mapping[str, int],
    require_call_through: bool,
) -> InterfaceMethod:
    row = _object(value, f"{interface_id} method {expected_slot}")
    slot = row.get("slot")
    offset = row.get("offset")
    if slot != expected_slot or offset != expected_slot * 4:
        raise ExternalInterfaceProfileError(
            f"{interface_id} method inventory is not contiguous PE32 vtable order"
        )
    argument_words = _bounded_words(
        row.get("argument_words"), f"{interface_id} method {expected_slot} arguments"
    )
    if argument_words == 0:
        raise ExternalInterfaceProfileError(
            f"{interface_id} method {expected_slot} omits its interface pointer"
        )
    abi = _entry_abi(
        row,
        context=f"{interface_id} method {expected_slot}",
        require_explicit=require_call_through,
    )
    effects = _effects(
        row,
        context=f"{interface_id} method {expected_slot}",
        required=require_call_through or row.get("machine_abi") is not None,
        argument_words=argument_words,
    )
    return InterfaceMethod(
        interface_id=interface_id,
        name=_nonempty(row.get("name"), f"{interface_id} method {expected_slot} name"),
        slot=expected_slot,
        abi=abi,
        argument_words=argument_words,
        outputs=_outputs(
            row.get("out_interfaces", []),
            argument_words=argument_words,
            known_interfaces=known_interfaces,
            interface_vtable_sizes=interface_vtable_sizes,
            context=f"{interface_id} method {expected_slot}",
        ),
        effects=effects,
        caller_memory_frame=_caller_memory_frame(
            row.get("caller_memory_frame"),
            argument_words=argument_words,
            required=require_call_through,
            context=f"{interface_id} method {expected_slot}",
        ),
    )


def _caller_memory_frame(
    value: Any,
    *,
    argument_words: int,
    required: bool,
    context: str,
) -> InterfaceCallerMemoryFrame | None:
    if value is None:
        if required:
            raise ExternalInterfaceProfileError(
                f"{context} has no complete caller-memory frame"
            )
        return None
    row = _object(value, f"{context} caller-memory frame")
    if set(row) != {"status", "model", "arguments", "assumptions"}:
        raise ExternalInterfaceProfileError(
            f"{context} caller-memory frame fields differ from the supported model"
        )
    if (
        row.get("status") != "complete"
        or row.get("model") != INTERFACE_CALLER_MEMORY_FRAME_MODEL
        or row.get("assumptions")
        != InterfaceCallerMemoryFrame(()).as_json()["assumptions"]
    ):
        raise ExternalInterfaceProfileError(
            f"{context} has an incomplete or unsupported caller-memory frame"
        )
    arguments: list[InterfaceMemoryArgument] = []
    seen: set[int] = set()
    for index, raw in enumerate(_array(
        row.get("arguments"), f"{context} caller-memory arguments"
    )):
        argument = _object(raw, f"{context} caller-memory argument {index}")
        if set(argument) != {
            "argument_index", "role", "access", "extent", "retention"
        }:
            raise ExternalInterfaceProfileError(
                f"{context} caller-memory argument {index} fields differ"
            )
        argument_index = argument.get("argument_index")
        role = argument.get("role")
        access = argument.get("access")
        extent = argument.get("extent")
        retention = argument.get("retention")
        if (
            not isinstance(argument_index, int)
            or isinstance(argument_index, bool)
            or not 0 <= argument_index < argument_words
            or argument_index in seen
            or role not in {"caller_memory", "interface_resource", "callback"}
            or access not in {"read", "read_write"}
            or extent not in {"fixed_word", "enclosing_object", "opaque_resource"}
            or retention not in {"during_call", "callback_contract"}
            or (role == "caller_memory" and extent == "opaque_resource")
            or (role != "caller_memory" and extent != "opaque_resource")
            or (role == "callback" and retention != "callback_contract")
            or (role != "callback" and retention != "during_call")
        ):
            raise ExternalInterfaceProfileError(
                f"{context} caller-memory argument {index} is invalid"
            )
        seen.add(argument_index)
        arguments.append(InterfaceMemoryArgument(
            argument_index=argument_index,
            role=str(role),
            access=str(access),
            extent=str(extent),
            retention=str(retention),
        ))
    return InterfaceCallerMemoryFrame(tuple(sorted(arguments)))


def _outputs(
    value: Any,
    *,
    argument_words: int,
    known_interfaces: set[str],
    interface_vtable_sizes: Mapping[str, int],
    context: str,
) -> tuple[InterfaceOutput, ...]:
    result: list[InterfaceOutput] = []
    seen: set[int] = set()
    for index, raw in enumerate(_array(value, f"{context} output interfaces")):
        row = _object(raw, f"{context} output {index}")
        argument_index = row.get("argument_index")
        interface_id = _nonempty(
            row.get("interface_id"), f"{context} output {index} interface"
        )
        if (
            not isinstance(argument_index, int)
            or isinstance(argument_index, bool)
            or not 0 <= argument_index < argument_words
            or argument_index in seen
        ):
            raise ExternalInterfaceProfileError(
                f"{context} has an invalid or duplicate output argument"
            )
        if row.get("write_width") != 4 or interface_id not in known_interfaces:
            raise ExternalInterfaceProfileError(
                f"{context} output {argument_index} has an invalid interface or width"
            )
        seen.add(argument_index)
        object_size = row.get("object_size", 4)
        vtable_size = row.get(
            "vtable_size", interface_vtable_sizes[interface_id]
        )
        if (
            object_size != 4
            or vtable_size != interface_vtable_sizes[interface_id]
            or row.get("nullable", True) is not True
            or row.get("success_condition", "hresult_succeeded_eax")
            != "hresult_succeeded_eax"
        ):
            raise ExternalInterfaceProfileError(
                f"{context} output {argument_index} has an invalid interface shape"
            )
        result.append(
            InterfaceOutput(argument_index, interface_id, object_size, vtable_size)
        )
    return tuple(sorted(result))


def _abi(value: Any, context: str) -> MachineCallABI:
    abi = resolve_machine_call_abi(value)
    if abi is None:
        raise ExternalInterfaceProfileError(f"{context} has an unsupported ABI")
    return abi


def _entry_abi(
    row: Mapping[str, Any],
    *,
    context: str,
    require_explicit: bool,
) -> MachineCallABI:
    abi = _abi(row.get("abi_template"), context)
    machine_abi = row.get("machine_abi")
    if machine_abi is None:
        effect_fields = same_library_call_through_effect_json()
        if require_explicit or any(key in row for key in effect_fields):
            raise ExternalInterfaceProfileError(
                f"{context} has no explicit machine ABI"
            )
        return abi
    if not isinstance(machine_abi, Mapping) or dict(machine_abi) != abi.as_json():
        raise ExternalInterfaceProfileError(
            f"{context} machine ABI differs from its template"
        )
    return abi


def _effects(
    row: Mapping[str, Any],
    *,
    context: str,
    required: bool,
    argument_words: int,
) -> InterfaceEffectContract | None:
    ordinary = same_library_call_through_effect_json()
    present = any(key in row for key in ordinary)
    if not present:
        if required:
            raise ExternalInterfaceProfileError(
                f"{context} has no same-library call-through effect contract"
            )
        return None
    callback_effect = row.get("callback_effect")
    if callback_effect == "none":
        if any(row.get(key) != value for key, value in ordinary.items()):
            raise ExternalInterfaceProfileError(
                f"{context} has an invalid same-library call-through effect contract"
            )
        return SAME_LIBRARY_CALL_THROUGH_EFFECTS
    if callback_effect != "explicit":
        raise ExternalInterfaceProfileError(
            f"{context} has an invalid same-library call-through effect contract"
        )
    expected_base = InterfaceEffectContract(
        model=SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        memory_effect=_SAME_NATIVE_TARGET_EFFECT,
        world_effect=_SAME_NATIVE_TARGET_EFFECT,
        callback_effect="explicit",
        prerequisites=(
            *_SAME_LIBRARY_CALL_THROUGH_PREREQUISITES,
            _CALLBACK_PREREQUISITE,
        ),
    ).as_json()
    for field in (
        "effect_model",
        "memory_effect",
        "memory_footprints",
        "world_effect",
        "callback_effect",
    ):
        if row.get(field) != expected_base[field]:
            raise ExternalInterfaceProfileError(
                f"{context} has an invalid callback call-through effect contract"
            )
    status = row.get("callback_contract_status")
    blockers = row.get("callback_contract_blockers")
    source = row.get("callback_source")
    callback_abi = row.get("callback_abi")
    lifetime = row.get("callback_lifetime")
    if status not in {"complete", "incomplete"} or not isinstance(blockers, list):
        raise ExternalInterfaceProfileError(
            f"{context} has an invalid callback contract status"
        )
    if any(not isinstance(blocker, str) or not blocker for blocker in blockers):
        raise ExternalInterfaceProfileError(
            f"{context} has invalid callback contract blockers"
        )
    if status == "complete" and blockers:
        raise ExternalInterfaceProfileError(
            f"{context} complete callback contract has blockers"
        )
    if status == "incomplete" and not blockers:
        raise ExternalInterfaceProfileError(
            f"{context} incomplete callback contract has no blockers"
        )
    if source is not None:
        source = _object(source, f"{context} callback source")
        index = source.get("argument")
        if (
            source.get("kind") != "argument_word"
            or not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < argument_words
        ):
            raise ExternalInterfaceProfileError(
                f"{context} has an invalid callback argument source"
            )
    if callback_abi is not None:
        callback_abi = _object(callback_abi, f"{context} callback ABI")
        callback_words = callback_abi.get("argument_words")
        cleanup = callback_abi.get("stack_cleanup_bytes")
        if (
            callback_abi.get("kind") != "generic_callback"
            or not isinstance(callback_words, int)
            or isinstance(callback_words, bool)
            or not 0 <= callback_words <= 64
            or cleanup != callback_words * 4
            or not isinstance(callback_abi.get("nullable"), bool)
        ):
            raise ExternalInterfaceProfileError(
                f"{context} has an invalid callback machine ABI"
            )
    if status == "complete" and (
        source is None
        or callback_abi is None
        or not isinstance(lifetime, str)
        or not lifetime
    ):
        raise ExternalInterfaceProfileError(
            f"{context} complete callback contract lacks source, ABI, or lifetime"
        )
    if lifetime is not None and (not isinstance(lifetime, str) or not lifetime):
        raise ExternalInterfaceProfileError(
            f"{context} has an invalid callback lifetime"
        )
    return InterfaceEffectContract(
        model=SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        memory_effect=_SAME_NATIVE_TARGET_EFFECT,
        world_effect=_SAME_NATIVE_TARGET_EFFECT,
        callback_effect="explicit",
        prerequisites=(
            *_SAME_LIBRARY_CALL_THROUGH_PREREQUISITES,
            _CALLBACK_PREREQUISITE,
        ),
        callback_source=None if source is None else dict(source),
        callback_abi=None if callback_abi is None else dict(callback_abi),
        callback_lifetime=lifetime,
        callback_status=str(status),
        callback_blockers=tuple(blockers),
    )


def _bounded_words(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 64
    ):
        raise ExternalInterfaceProfileError(f"{context} must be between 0 and 64")
    return value


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExternalInterfaceProfileError(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ExternalInterfaceProfileError(f"{context} must be a list")
    return value


def _nonempty(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalInterfaceProfileError(f"{context} must be a nonempty string")
    return value


__all__ = [
    "EXTERNAL_INTERFACE_PROFILE_FORMAT",
    "INTERFACE_CALLER_MEMORY_FRAME_MODEL",
    "SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL",
    "SAME_LIBRARY_CALL_THROUGH_EFFECTS",
    "ExternalInterface",
    "ExternalInterfaceProfile",
    "ExternalInterfaceProfileError",
    "InterfaceFactory",
    "InterfaceCallerMemoryFrame",
    "InterfaceEffectContract",
    "InterfaceMemoryArgument",
    "InterfaceMethod",
    "InterfaceOutput",
    "load_external_interface_profile",
    "same_library_callback_call_through_effect_json",
    "same_library_call_through_effect_json",
]
