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


def _normalize_entry(
    entry: Mapping[str, Any],
    *,
    profile_id: str,
    entry_key: str,
    entry_index: int,
) -> dict[str, Any]:
    result = dict(entry)
    arity_kind, words = _arity(entry)
    if arity_kind == "fixed":
        result["argument_words"] = words
    elif arity_kind == "variadic":
        result["minimum_argument_words"] = words
    result.setdefault("id", f"{profile_id}:{entry_key}:{entry_index}")
    result["profile_id"] = profile_id
    return result
