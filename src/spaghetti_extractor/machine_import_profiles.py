"""Deterministic loading and selection for machine-import profile graphs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .stage_binary import StageAInputError
from .util import sha256_file


MACHINE_IMPORT_PROFILE_FORMATS = frozenset({
    "stage-a-external-environment-profile-v1",
    "stage-a-external-interface-profile-v1",
    "stage-a-static-machine-import-profile-v1",
})
NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL = "exact_native_dll_callthrough_v1"
SAME_LIBRARY_CALLTHROUGH_EFFECT_MODEL = "same-library-call-through-v1"
NATIVE_DLL_CALLTHROUGH_PREREQUISITES = frozenset({
    "same_pinned_dll_implementation",
    "exact_machine_arguments",
    "candidate_address_space_used_directly",
})
SAME_LIBRARY_CALLTHROUGH_PREREQUISITES = (
    "candidate_uses_same_runtime_native_library_binding",
    "candidate_resolves_same_native_interface_target",
    "candidate_uses_declared_machine_abi",
    "candidate_forwards_same_machine_argument_words",
    "candidate_invokes_native_target_exactly_once",
)
_CALLER_MEMORY_FRAME_MODEL = "pe32-declared-pointer-arguments-v1"
_CALLER_MEMORY_FRAME_ASSUMPTIONS = [
    "caller memory is accessed only through declared pointer arguments",
    "non-callback pointer arguments are retained only during the call",
    "opaque interface resources are disjoint from caller image and stack memory",
]

_PE32_ABI_TEMPLATES = frozenset({"pe32-cdecl-v1", "pe32-stdcall-v1"})
_NATIVE_CALLTHROUGH_CALLBACK_FIELDS = frozenset({
    "callback_abi",
    "callback_lifetime",
    "callback_source",
})
_PE32_RESULT_REGISTERS = frozenset({"eax", "edx"})


class MachineImportProfileError(StageAInputError):
    """A machine-import profile graph is malformed or ambiguous."""


@dataclass(frozen=True, order=True)
class MachineImportIdentity:
    dll: str
    kind: str
    value: str | int

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], *, context: str
    ) -> MachineImportIdentity:
        dll = value.get("dll")
        symbol = value.get("symbol")
        ordinal = value.get("ordinal")
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = (
            isinstance(ordinal, int)
            and not isinstance(ordinal, bool)
            and ordinal >= 0
        )
        if not isinstance(dll, str) or not dll or has_symbol == has_ordinal:
            raise MachineImportProfileError(
                f"{context} must name one DLL and exactly one symbol or ordinal"
            )
        return cls(
            dll=dll.lower(),
            kind="symbol" if has_symbol else "ordinal",
            value=symbol if has_symbol else ordinal,
        )

    def state_machine_key(self) -> tuple[str, str, int | None]:
        return (
            self.dll,
            str(self.value) if self.kind == "symbol" else "",
            int(self.value) if self.kind == "ordinal" else None,
        )


@dataclass(frozen=True)
class LoadedMachineImportProfile:
    path: Path
    profile_id: str
    sha256: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class SelectedMachineImportContract:
    identity: MachineImportIdentity
    profile_id: str
    profile_path: Path
    profile_sha256: str
    entry_key: str
    entry_index: int
    contract: Mapping[str, Any]
    arity_kind: str | None
    argument_words: int | None


@dataclass(frozen=True)
class MachineImportProfileSet:
    profiles: tuple[LoadedMachineImportProfile, ...]
    contracts: tuple[SelectedMachineImportContract, ...]

    def by_identity(self) -> dict[MachineImportIdentity, SelectedMachineImportContract]:
        return {contract.identity: contract for contract in self.contracts}


def load_machine_import_profile_graph(
    profile_paths: Sequence[Path | str],
) -> tuple[LoadedMachineImportProfile, ...]:
    """Load includes before includers, once per canonical path."""

    loaded: list[LoadedMachineImportProfile] = []
    visited: set[Path] = set()
    visiting: list[Path] = []

    def visit(raw_path: Path | str, *, relative_to: Path | None = None) -> None:
        path = Path(raw_path)
        if relative_to is not None and not path.is_absolute():
            path = relative_to / path
        canonical = path.resolve()
        if canonical in visited:
            return
        if canonical in visiting:
            cycle = " -> ".join(str(item) for item in (*visiting, canonical))
            raise MachineImportProfileError(
                f"machine import profile include cycle: {cycle}"
            )
        try:
            payload = json.loads(canonical.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MachineImportProfileError(
                f"cannot read machine import profile {canonical}: {exc}"
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or payload.get("format") not in MACHINE_IMPORT_PROFILE_FORMATS
        ):
            raise MachineImportProfileError(
                f"unsupported machine import profile format in {canonical}"
            )
        profile_id = payload.get("id")
        if not isinstance(profile_id, str) or not profile_id:
            raise MachineImportProfileError(
                f"machine import profile {canonical} has no id"
            )
        includes = payload.get("includes", [])
        if not isinstance(includes, list) or any(
            not isinstance(item, str) or not item for item in includes
        ):
            raise MachineImportProfileError(
                f"{canonical} includes must be a list of nonempty paths"
            )
        visiting.append(canonical)
        try:
            for include in includes:
                visit(include, relative_to=canonical.parent)
        finally:
            visiting.pop()
        visited.add(canonical)
        loaded.append(LoadedMachineImportProfile(
            path=canonical,
            profile_id=profile_id,
            sha256=sha256_file(canonical),
            payload=payload,
        ))

    for profile_path in profile_paths:
        visit(profile_path)
    return tuple(loaded)


def load_machine_import_profile_set(
    profile_paths: Sequence[Path | str],
) -> MachineImportProfileSet:
    """Select one unambiguous contract per exact import identity."""

    profiles = load_machine_import_profile_graph(profile_paths)
    selected: dict[MachineImportIdentity, SelectedMachineImportContract] = {}
    ambiguous: set[MachineImportIdentity] = set()
    for profile in profiles:
        default_callback_effect = profile.payload.get("default_callback_effect")
        if default_callback_effect not in {"none", None}:
            raise MachineImportProfileError(
                f"{profile.path} default_callback_effect must be exactly 'none'"
            )
        for entry_key in (
            "machine_import_call_contracts",
            "machine_import_signatures",
        ):
            entries = profile.payload.get(entry_key, [])
            if not isinstance(entries, list):
                raise MachineImportProfileError(
                    f"{profile.path} {entry_key} must be a list"
                )
            for entry_index, raw in enumerate(entries):
                if not isinstance(raw, Mapping):
                    raise MachineImportProfileError(
                        f"{profile.path} {entry_key}[{entry_index}] must be an object"
                    )
                imported = raw.get("import")
                if not isinstance(imported, Mapping):
                    raise MachineImportProfileError(
                        f"{profile.path} {entry_key}[{entry_index}] has no import object"
                    )
                identity = MachineImportIdentity.from_mapping(
                    imported,
                    context=f"{profile.path} {entry_key}[{entry_index}].import",
                )
                arity_kind, arity_words = _arity(raw)
                _validate_effect_model(
                    raw,
                    imported=imported,
                    arity_kind=arity_kind,
                    argument_words=arity_words,
                    context=f"{profile.path} {entry_key}[{entry_index}]",
                )
                candidate = SelectedMachineImportContract(
                    identity=identity,
                    profile_id=profile.profile_id,
                    profile_path=profile.path,
                    profile_sha256=profile.sha256,
                    entry_key=entry_key,
                    entry_index=entry_index,
                    contract=_normalize_entry(
                        raw,
                        profile_id=profile.profile_id,
                        entry_key=entry_key,
                        entry_index=entry_index,
                        default_callback_effect=default_callback_effect,
                    ),
                    arity_kind=arity_kind,
                    argument_words=(
                        arity_words if arity_kind == "fixed" else None
                    ),
                )
                prior = selected.get(identity)
                if prior is None or raw.get("override") is True:
                    selected[identity] = candidate
                    ambiguous.discard(identity)
                elif prior.contract.get("override") is not True:
                    ambiguous.add(identity)
    if ambiguous:
        rendered = ", ".join(
            f"{identity.dll}!{identity.value}" for identity in sorted(ambiguous)
        )
        raise MachineImportProfileError(
            "ambiguous machine import profile identities: " + rendered
        )
    return MachineImportProfileSet(
        profiles=profiles,
        contracts=tuple(selected[key] for key in sorted(selected)),
    )


def _arity(entry: Mapping[str, Any]) -> tuple[str | None, int | None]:
    if "arity" not in entry:
        words = entry.get("argument_words")
        if words is None:
            return None, None
        if (
            not isinstance(words, int)
            or isinstance(words, bool)
            or not 0 <= words <= 256
        ):
            raise MachineImportProfileError("argument_words must be between 0 and 256")
        return "fixed", words
    arity = entry.get("arity")
    if not isinstance(arity, Mapping):
        raise MachineImportProfileError("machine import arity must be an object")
    kind = arity.get("kind")
    key = "words" if kind == "fixed" else "minimum_words"
    words = arity.get(key)
    if kind not in {"fixed", "variadic"} or (
        not isinstance(words, int)
        or isinstance(words, bool)
        or not 0 <= words <= 256
    ):
        raise MachineImportProfileError(
            "machine import arity must be fixed or variadic with a bounded word count"
        )
    return str(kind), words


def _validate_effect_model(
    entry: Mapping[str, Any],
    *,
    imported: Mapping[str, Any],
    arity_kind: str | None,
    argument_words: int | None,
    context: str,
) -> None:
    if "effect_model" not in entry:
        return
    effect_model = entry.get("effect_model")
    if not isinstance(effect_model, Mapping):
        raise MachineImportProfileError(
            f"{context} effect_model must be an exact versioned object"
        )
    if effect_model.get("kind") == SAME_LIBRARY_CALLTHROUGH_EFFECT_MODEL:
        _validate_same_library_callthrough_effect(
            entry,
            imported=imported,
            arity_kind=arity_kind,
            argument_words=argument_words,
            context=context,
        )
        return
    if set(effect_model) != {"kind", "prerequisites"}:
        raise MachineImportProfileError(
            f"{context} effect_model must declare only kind and prerequisites"
        )
    if effect_model.get("kind") != NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL:
        raise MachineImportProfileError(
            f"{context} has unsupported or vague effect_model kind"
        )

    prerequisites = effect_model.get("prerequisites")
    if not isinstance(prerequisites, Mapping):
        raise MachineImportProfileError(
            f"{context} native callthrough prerequisites must be an object"
        )
    missing = NATIVE_DLL_CALLTHROUGH_PREREQUISITES - set(prerequisites)
    unknown = set(prerequisites) - NATIVE_DLL_CALLTHROUGH_PREREQUISITES
    false_prerequisites = {
        key for key in NATIVE_DLL_CALLTHROUGH_PREREQUISITES
        if prerequisites.get(key) is not True
    }
    if missing or unknown or false_prerequisites:
        raise MachineImportProfileError(
            f"{context} native callthrough prerequisites must explicitly require "
            "the same pinned DLL implementation, exact machine arguments, and "
            "direct use of the candidate address space"
        )

    identity_keys = {"dll", "symbol" if "symbol" in imported else "ordinal"}
    if set(imported) != identity_keys:
        raise MachineImportProfileError(
            f"{context} native callthrough requires an exact import identity"
        )
    contract_id = entry.get("id")
    if not isinstance(contract_id, (str, int)) or isinstance(contract_id, bool):
        raise MachineImportProfileError(
            f"{context} native callthrough requires an explicit contract id"
        )
    if isinstance(contract_id, str) and not contract_id:
        raise MachineImportProfileError(
            f"{context} native callthrough requires an explicit contract id"
        )
    if entry.get("abi_template") not in _PE32_ABI_TEMPLATES:
        raise MachineImportProfileError(
            f"{context} native callthrough requires an exact supported PE32 ABI"
        )
    arity = entry.get("arity")
    if (
        arity_kind != "fixed"
        or not isinstance(argument_words, int)
        or not isinstance(arity, Mapping)
        or set(arity) != {"kind", "words"}
    ):
        raise MachineImportProfileError(
            f"{context} native callthrough requires an explicit fixed arity"
        )

    disposition = entry.get("disposition")
    if disposition not in {"returns", "terminates"}:
        raise MachineImportProfileError(
            f"{context} native callthrough requires an explicit disposition"
        )
    _validate_native_callthrough_results(
        entry.get("result_register_relations"),
        disposition=str(disposition),
        context=context,
    )

    if (
        entry.get("memory_effect") != "nativeCallthrough"
        or entry.get("memory_footprints") != []
    ):
        raise MachineImportProfileError(
            f"{context} native callthrough requires a declared memory category"
        )
    if entry.get("world_effect") != "nativeCallthrough":
        raise MachineImportProfileError(
            f"{context} native callthrough requires a declared world category"
        )
    _validate_native_callthrough_callback(
        entry,
        argument_words=argument_words,
        context=context,
    )


def _validate_same_library_callthrough_effect(
    entry: Mapping[str, Any],
    *,
    imported: Mapping[str, Any],
    arity_kind: str | None,
    argument_words: int | None,
    context: str,
) -> None:
    effect_model = entry.get("effect_model")
    expected = {
        "kind": SAME_LIBRARY_CALLTHROUGH_EFFECT_MODEL,
        "library_relation": "same-runtime-native-library-binding",
        "target_relation": "same-pinned-native-interface-target",
        "invocation_relation": "one-to-one",
        "machine_argument_relation": "word-for-word",
        "machine_result_relation": "same-native-call-result",
        "pointed_to_footprints": "not-inferred-from-c-types",
        "prerequisites": list(SAME_LIBRARY_CALLTHROUGH_PREREQUISITES),
    }
    if effect_model != expected:
        raise MachineImportProfileError(
            f"{context} has an invalid same-library callthrough effect model"
        )
    identity_keys = {"dll", "symbol" if "symbol" in imported else "ordinal"}
    if set(imported) != identity_keys:
        raise MachineImportProfileError(
            f"{context} same-library callthrough requires an exact import identity"
        )
    if entry.get("abi_template") not in _PE32_ABI_TEMPLATES:
        raise MachineImportProfileError(
            f"{context} same-library callthrough requires an exact PE32 ABI"
        )
    if arity_kind != "fixed" or argument_words is None:
        raise MachineImportProfileError(
            f"{context} same-library callthrough requires a fixed arity"
        )
    if not isinstance(entry.get("machine_abi"), Mapping):
        raise MachineImportProfileError(
            f"{context} same-library callthrough has no explicit machine ABI"
        )
    if (
        entry.get("memory_effect") != "sameNativeTargetCallThrough"
        or entry.get("memory_footprints") != []
        or entry.get("world_effect") != "sameNativeTargetCallThrough"
        or entry.get("callback_effect") != "none"
    ):
        raise MachineImportProfileError(
            f"{context} same-library callthrough has incomplete effect categories"
        )
    _validate_native_callthrough_results(
        entry.get("result_register_relations"),
        disposition="returns",
        context=context,
    )
    _validate_caller_memory_frame(
        entry.get("caller_memory_frame"),
        argument_words=argument_words,
        context=context,
    )


def _validate_caller_memory_frame(
    value: Any,
    *,
    argument_words: int,
    context: str,
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "status", "model", "arguments", "assumptions"
    }:
        raise MachineImportProfileError(
            f"{context} same-library callthrough has no exact caller-memory frame"
        )
    if (
        value.get("status") != "complete"
        or value.get("model") != _CALLER_MEMORY_FRAME_MODEL
        or value.get("assumptions") != _CALLER_MEMORY_FRAME_ASSUMPTIONS
    ):
        raise MachineImportProfileError(
            f"{context} same-library callthrough caller-memory frame is unsupported"
        )
    arguments = value.get("arguments")
    if not isinstance(arguments, list):
        raise MachineImportProfileError(
            f"{context} caller-memory frame arguments must be a list"
        )
    seen: set[int] = set()
    for index, raw in enumerate(arguments):
        if not isinstance(raw, Mapping) or set(raw) != {
            "argument_index", "role", "access", "extent", "retention"
        }:
            raise MachineImportProfileError(
                f"{context} caller-memory frame argument {index} is malformed"
            )
        argument_index = raw.get("argument_index")
        role = raw.get("role")
        access = raw.get("access")
        extent = raw.get("extent")
        retention = raw.get("retention")
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
            raise MachineImportProfileError(
                f"{context} caller-memory frame argument {index} is invalid"
            )
        seen.add(argument_index)


def _validate_native_callthrough_results(
    value: Any, *, disposition: str, context: str
) -> None:
    if not isinstance(value, list):
        raise MachineImportProfileError(
            f"{context} native callthrough requires explicit return relations"
        )
    if disposition == "terminates":
        if value:
            raise MachineImportProfileError(
                f"{context} terminating native callthrough cannot return a value"
            )
        return
    if len(value) > 2:
        raise MachineImportProfileError(
            f"{context} native callthrough has too many return relations"
        )
    registers: set[str] = set()
    for index, raw in enumerate(value):
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"register", "relation"}
            or raw.get("register") not in _PE32_RESULT_REGISTERS
            or raw.get("relation") not in {"exact", "related_word"}
        ):
            raise MachineImportProfileError(
                f"{context} native callthrough return relation {index} is invalid"
            )
        register = str(raw["register"])
        if register in registers:
            raise MachineImportProfileError(
                f"{context} native callthrough repeats return register {register}"
            )
        registers.add(register)
    if registers and "eax" not in registers:
        raise MachineImportProfileError(
            f"{context} native callthrough return relations must include eax"
        )


def _validate_native_callthrough_callback(
    entry: Mapping[str, Any], *, argument_words: int, context: str
) -> None:
    category = entry.get("callback_effect")
    if category not in {"none", "explicit"}:
        raise MachineImportProfileError(
            f"{context} native callthrough requires a declared callback category"
        )
    present_fields = _NATIVE_CALLTHROUGH_CALLBACK_FIELDS & set(entry)
    if category == "none":
        if present_fields:
            raise MachineImportProfileError(
                f"{context} non-callback callthrough attaches callback metadata"
            )
        return
    if present_fields != _NATIVE_CALLTHROUGH_CALLBACK_FIELDS:
        raise MachineImportProfileError(
            f"{context} callback-bearing callthrough requires source, ABI, and lifetime"
        )

    source = entry.get("callback_source")
    if not isinstance(source, Mapping):
        raise MachineImportProfileError(
            f"{context} callback-bearing callthrough has no exact callback source"
        )
    source_kind = source.get("kind")
    expected_source_keys = (
        {"kind", "argument"}
        if source_kind == "argument_word"
        else {"kind", "argument", "offset"}
    )
    argument = source.get("argument")
    offset = source.get("offset", 0)
    if (
        source_kind not in {"argument_word", "argument_pointee"}
        or set(source) != expected_source_keys
        or not isinstance(argument, int)
        or isinstance(argument, bool)
        or not 0 <= argument < argument_words
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or not 0 <= offset <= 0xFFFF
    ):
        raise MachineImportProfileError(
            f"{context} callback-bearing callthrough has an invalid callback source"
        )

    callback_abi = entry.get("callback_abi")
    if not isinstance(callback_abi, Mapping) or set(callback_abi) != {
        "kind", "argument_words", "stack_cleanup_bytes", "nullable",
    }:
        raise MachineImportProfileError(
            f"{context} callback-bearing callthrough has no exact callback ABI"
        )
    callback_words = callback_abi.get("argument_words")
    cleanup = callback_abi.get("stack_cleanup_bytes")
    if (
        callback_abi.get("kind") != "generic_callback"
        or not isinstance(callback_words, int)
        or isinstance(callback_words, bool)
        or not 0 <= callback_words <= 64
        or not isinstance(cleanup, int)
        or isinstance(cleanup, bool)
        or not 0 <= cleanup <= 0xFFFF
        or not isinstance(callback_abi.get("nullable"), bool)
    ):
        raise MachineImportProfileError(
            f"{context} callback-bearing callthrough has an invalid callback ABI"
        )
    lifetime = entry.get("callback_lifetime")
    if not isinstance(lifetime, str) or not lifetime:
        raise MachineImportProfileError(
            f"{context} callback-bearing callthrough has no exact callback lifetime"
        )


def _normalize_entry(
    entry: Mapping[str, Any],
    *,
    profile_id: str,
    entry_key: str,
    entry_index: int,
    default_callback_effect: Any,
) -> dict[str, Any]:
    result = dict(entry)
    arity_kind, words = _arity(entry)
    if arity_kind == "fixed":
        result["argument_words"] = words
    elif arity_kind == "variadic":
        result["minimum_argument_words"] = words
    result.setdefault("id", f"{profile_id}:{entry_key}:{entry_index}")
    if "callback_effect" not in result and default_callback_effect is not None:
        result["callback_effect"] = default_callback_effect
    result["profile_id"] = profile_id
    return result
