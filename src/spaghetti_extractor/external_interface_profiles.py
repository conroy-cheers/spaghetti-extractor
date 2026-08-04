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


class ExternalInterfaceProfileError(StageAInputError):
    """An external-interface profile is malformed or ambiguous."""


@dataclass(frozen=True, order=True)
class InterfaceOutput:
    argument_index: int
    interface_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "argument_index": self.argument_index,
            "interface_id": self.interface_id,
            "write_width": 4,
        }


@dataclass(frozen=True)
class InterfaceFactory:
    identity: MachineImportIdentity
    declaration: str
    abi: MachineCallABI
    argument_words: int
    outputs: tuple[InterfaceOutput, ...]


@dataclass(frozen=True)
class InterfaceMethod:
    interface_id: str
    name: str
    slot: int
    abi: MachineCallABI
    argument_words: int
    outputs: tuple[InterfaceOutput, ...]

    @property
    def offset(self) -> int:
        return self.slot * 4

    def target_json(
        self, *, profile_id: str, profile_sha256: str
    ) -> dict[str, Any]:
        return {
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

    raw_interfaces = _array(payload.get("interfaces"), "profile interfaces")
    interface_ids = {
        _nonempty(_object(raw, "interface").get("id"), "interface ID")
        for raw in raw_interfaces
    }
    if len(interface_ids) != len(raw_interfaces):
        raise ExternalInterfaceProfileError("duplicate external-interface ID")

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
        outputs = _outputs(
            row.get("out_interfaces"),
            argument_words=argument_words,
            known_interfaces=interface_ids,
            context=f"factory {index}",
        )
        if not outputs:
            raise ExternalInterfaceProfileError(
                f"interface factory {identity.dll}!{identity.value} has no output"
            )
        factories.append(InterfaceFactory(
            identity=identity,
            declaration=_nonempty(row.get("declaration"), f"factory {index} declaration"),
            abi=_abi(row.get("abi_template"), f"factory {index}"),
            argument_words=argument_words,
            outputs=outputs,
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
    return InterfaceMethod(
        interface_id=interface_id,
        name=_nonempty(row.get("name"), f"{interface_id} method {expected_slot} name"),
        slot=expected_slot,
        abi=_abi(row.get("abi_template"), f"{interface_id} method {expected_slot}"),
        argument_words=argument_words,
        outputs=_outputs(
            row.get("out_interfaces", []),
            argument_words=argument_words,
            known_interfaces=known_interfaces,
            context=f"{interface_id} method {expected_slot}",
        ),
    )


def _outputs(
    value: Any,
    *,
    argument_words: int,
    known_interfaces: set[str],
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
        result.append(InterfaceOutput(argument_index, interface_id))
    return tuple(sorted(result))


def _abi(value: Any, context: str) -> MachineCallABI:
    abi = resolve_machine_call_abi(value)
    if abi is None:
        raise ExternalInterfaceProfileError(f"{context} has an unsupported ABI")
    return abi


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
    "ExternalInterface",
    "ExternalInterfaceProfile",
    "ExternalInterfaceProfileError",
    "InterfaceFactory",
    "InterfaceMethod",
    "InterfaceOutput",
    "load_external_interface_profile",
]
