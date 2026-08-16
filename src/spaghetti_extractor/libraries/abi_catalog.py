"""Immutable ABI catalog records and sparse search-index construction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    LIBRARY_CATALOG_LOCK_FORMAT,
)
from ..util import sha256_file
from .abi_records import (
    ABI_CATALOG_V3_FORMAT,
    CATALOG_SEARCH_INDEX_V3_FORMAT,
    IndexEntryV3,
    LibraryAbiError,
    LibraryAbiProfileV3,
    LibraryBehaviorEntryV3,
    LibraryFunctionSignatureV3,
    LibraryIssueV3,
    StrictCodec,
    _array,
    _object,
    _sha256,
    _text,
    canonical_sha256,
    phase_status,
    stable_id,
)


def _portable_operation_id(*, family_id: str, symbol: str) -> str:
    digest = stable_id(
        "library-operation-v1",
        {"family_id": family_id, "symbol": symbol},
    ).split(":", 1)[1]
    return f"library_operation_{digest}"


@dataclass(frozen=True)
class LibraryAbiCatalogV3:
    catalog_id: str
    abi_profiles: tuple[LibraryAbiProfileV3, ...]
    functions: tuple[LibraryFunctionSignatureV3, ...]
    behaviors: tuple[LibraryBehaviorEntryV3, ...]
    catalog_sha256: str

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": ABI_CATALOG_V3_FORMAT,
            "catalog_id": self.catalog_id,
            "abi_profiles": [item.to_payload() for item in self.abi_profiles],
            "functions": [item.to_payload() for item in self.functions],
            "behaviors": [item.to_payload() for item in self.behaviors],
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "catalog_sha256": self.catalog_sha256}

    @classmethod
    def create(
        cls,
        *,
        catalog_id: str,
        abi_profiles: Iterable[LibraryAbiProfileV3],
        functions: Iterable[LibraryFunctionSignatureV3],
        behaviors: Iterable[LibraryBehaviorEntryV3],
    ) -> "LibraryAbiCatalogV3":
        profiles = tuple(sorted(abi_profiles, key=lambda item: item.profile_id))
        function_rows = tuple(sorted(functions, key=lambda item: item.function_id))
        behavior_rows = tuple(
            sorted(behaviors, key=lambda item: item.behavior_entry_id)
        )
        core = {
            "format": ABI_CATALOG_V3_FORMAT,
            "catalog_id": catalog_id,
            "abi_profiles": [item.to_payload() for item in profiles],
            "functions": [item.to_payload() for item in function_rows],
            "behaviors": [item.to_payload() for item in behavior_rows],
        }
        result = cls(
            catalog_id,
            profiles,
            function_rows,
            behavior_rows,
            canonical_sha256(core),
        )
        result.validate("ABI catalog")
        return result

    def validate(self, location: str) -> None:
        _text(self.catalog_id, f"{location}.catalog_id")
        if canonical_sha256(self.core_payload) != self.catalog_sha256:
            raise LibraryAbiError(
                "stale_catalog_hash",
                "catalog SHA-256 does not bind its contents",
                location=f"{location}.catalog_sha256",
            )
        profile_ids = tuple(item.profile_id for item in self.abi_profiles)
        function_ids = tuple(item.function_id for item in self.functions)
        behavior_ids = tuple(item.behavior_entry_id for item in self.behaviors)
        for label, values in (
            ("abi_profiles", profile_ids),
            ("functions", function_ids),
            ("behaviors", behavior_ids),
        ):
            if tuple(sorted(set(values))) != values:
                raise LibraryAbiError(
                    "catalog_identity_conflict",
                    f"{label} must have sorted unique IDs",
                    location=f"{location}.{label}",
                )
        profile_set = set(profile_ids)
        for function in self.functions:
            if function.catalog_id != self.catalog_id:
                raise LibraryAbiError(
                    "catalog_binding_mismatch",
                    "function binds another catalog",
                    location=f"{location}.functions[{function.function_id}]",
                )
            if (
                function.abi_profile_id is not None
                and function.abi_profile_id not in profile_set
            ):
                raise LibraryAbiError(
                    "unknown_abi_profile",
                    "function references an unknown ABI profile",
                    location=f"{location}.functions[{function.function_id}].abi_profile_id",
                )
        for profile in self.abi_profiles:
            for slot in profile.callback_slots:
                if slot.abi_profile_id not in profile_set:
                    raise LibraryAbiError(
                        "unknown_callback_abi",
                        "callback slot references an unknown ABI profile",
                        location=f"{location}.abi_profiles[{profile.profile_id}].callback_slots",
                    )
        for behavior in self.behaviors:
            missing = sorted(set(behavior.abi_profile_ids) - profile_set)
            if missing:
                raise LibraryAbiError(
                    "unknown_behavior_abi",
                    f"behavior references unknown ABI profiles {missing!r}",
                    location=f"{location}.behaviors[{behavior.behavior_entry_id}].abi_profile_ids",
                )

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryAbiCatalogV3":
        row = _object(
            value,
            {
                "format",
                "catalog_id",
                "abi_profiles",
                "functions",
                "behaviors",
                "catalog_sha256",
            },
            {},
            location,
        )
        if row["format"] != ABI_CATALOG_V3_FORMAT:
            raise LibraryAbiError(
                "wrong_artifact_format",
                "not a v3 ABI catalog",
                location=f"{location}.format",
            )
        result = cls(
            catalog_id=_text(row["catalog_id"], f"{location}.catalog_id"),
            abi_profiles=tuple(
                LibraryAbiProfileV3.from_payload(
                    item, f"{location}.abi_profiles[{index}]"
                )
                for index, item in enumerate(
                    _array(row["abi_profiles"], f"{location}.abi_profiles")
                )
            ),
            functions=tuple(
                LibraryFunctionSignatureV3.from_payload(
                    item, f"{location}.functions[{index}]"
                )
                for index, item in enumerate(
                    _array(row["functions"], f"{location}.functions")
                )
            ),
            behaviors=tuple(
                LibraryBehaviorEntryV3.from_payload(
                    item, f"{location}.behaviors[{index}]"
                )
                for index, item in enumerate(
                    _array(row["behaviors"], f"{location}.behaviors")
                )
            ),
            catalog_sha256=_sha256(
                row["catalog_sha256"], f"{location}.catalog_sha256"
            ),
        )
        result.validate(location)
        return result


LIBRARY_ABI_CATALOG_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), LibraryAbiCatalogV3.from_payload
)


@dataclass(frozen=True)
class CatalogSearchIndexV3:
    status: str
    catalog_bindings: tuple[tuple[str, str], ...]
    abi_profiles: tuple[LibraryAbiProfileV3, ...]
    functions: tuple[LibraryFunctionSignatureV3, ...]
    behaviors: tuple[LibraryBehaviorEntryV3, ...]
    normalized_hash_index: tuple[IndexEntryV3, ...]
    exact_hash_index: tuple[IndexEntryV3, ...]
    unit_merkle_index: tuple[IndexEntryV3, ...]
    cfg_hash_index: tuple[IndexEntryV3, ...]
    import_index: tuple[IndexEntryV3, ...]
    string_index: tuple[IndexEntryV3, ...]
    constant_index: tuple[IndexEntryV3, ...]
    issues: tuple[LibraryIssueV3, ...]
    index_sha256: str

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": CATALOG_SEARCH_INDEX_V3_FORMAT,
            "status": self.status,
            "executes_original_binary": False,
            "catalog_bindings": [
                {"catalog_id": catalog_id, "catalog_sha256": digest}
                for catalog_id, digest in self.catalog_bindings
            ],
            "abi_profiles": [item.to_payload() for item in self.abi_profiles],
            "functions": [item.to_payload() for item in self.functions],
            "behaviors": [item.to_payload() for item in self.behaviors],
            "indexes": {
                "normalized_hash": [
                    item.to_payload() for item in self.normalized_hash_index
                ],
                "exact_hash": [item.to_payload() for item in self.exact_hash_index],
                "unit_merkle": [item.to_payload() for item in self.unit_merkle_index],
                "cfg_hash": [item.to_payload() for item in self.cfg_hash_index],
                "import": [item.to_payload() for item in self.import_index],
                "string": [item.to_payload() for item in self.string_index],
                "constant": [item.to_payload() for item in self.constant_index],
            },
            "issues": [item.to_payload() for item in self.issues],
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "index_sha256": self.index_sha256}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "CatalogSearchIndexV3":
        row = _object(
            value,
            {
                "format",
                "status",
                "executes_original_binary",
                "catalog_bindings",
                "abi_profiles",
                "functions",
                "behaviors",
                "indexes",
                "issues",
                "index_sha256",
            },
            {},
            location,
        )
        if row["format"] != CATALOG_SEARCH_INDEX_V3_FORMAT:
            raise LibraryAbiError(
                "wrong_artifact_format",
                "not a v3 catalog search index",
                location=f"{location}.format",
            )
        if row["executes_original_binary"] is not False:
            raise LibraryAbiError(
                "original_execution_forbidden",
                "catalog search index claims original execution",
                location=f"{location}.executes_original_binary",
            )
        bindings = []
        for index, item in enumerate(
            _array(row["catalog_bindings"], f"{location}.catalog_bindings")
        ):
            binding = _object(
                item,
                {"catalog_id", "catalog_sha256"},
                {},
                f"{location}.catalog_bindings[{index}]",
            )
            bindings.append(
                (
                    _text(binding["catalog_id"], f"{location}.catalog_bindings[{index}].catalog_id"),
                    _sha256(binding["catalog_sha256"], f"{location}.catalog_bindings[{index}].catalog_sha256"),
                )
            )
        indexes = _object(
            row["indexes"],
            {"normalized_hash", "exact_hash", "unit_merkle", "cfg_hash", "import", "string", "constant"},
            {},
            f"{location}.indexes",
        )

        def entries(name: str) -> tuple[IndexEntryV3, ...]:
            return tuple(
                IndexEntryV3.from_payload(
                    item, f"{location}.indexes.{name}[{index}]"
                )
                for index, item in enumerate(
                    _array(indexes[name], f"{location}.indexes.{name}")
                )
            )

        result = cls(
            status=_text(row["status"], f"{location}.status"),
            catalog_bindings=tuple(bindings),
            abi_profiles=tuple(
                LibraryAbiProfileV3.from_payload(
                    item, f"{location}.abi_profiles[{index}]"
                )
                for index, item in enumerate(
                    _array(row["abi_profiles"], f"{location}.abi_profiles")
                )
            ),
            functions=tuple(
                LibraryFunctionSignatureV3.from_payload(
                    item, f"{location}.functions[{index}]"
                )
                for index, item in enumerate(
                    _array(row["functions"], f"{location}.functions")
                )
            ),
            behaviors=tuple(
                LibraryBehaviorEntryV3.from_payload(
                    item, f"{location}.behaviors[{index}]"
                )
                for index, item in enumerate(
                    _array(row["behaviors"], f"{location}.behaviors")
                )
            ),
            normalized_hash_index=entries("normalized_hash"),
            exact_hash_index=entries("exact_hash"),
            unit_merkle_index=entries("unit_merkle"),
            cfg_hash_index=entries("cfg_hash"),
            import_index=entries("import"),
            string_index=entries("string"),
            constant_index=entries("constant"),
            issues=tuple(
                LibraryIssueV3.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(
                    _array(row["issues"], f"{location}.issues")
                )
            ),
            index_sha256=_sha256(row["index_sha256"], f"{location}.index_sha256"),
        )
        if result.status != phase_status(result.issues):
            raise LibraryAbiError(
                "status_contradiction",
                "search-index status disagrees with its issues",
                location=f"{location}.status",
            )
        if canonical_sha256(result.core_payload) != result.index_sha256:
            raise LibraryAbiError(
                "stale_index_hash",
                "search-index SHA-256 does not bind its contents",
                location=f"{location}.index_sha256",
            )
        return result


CATALOG_SEARCH_INDEX_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), CatalogSearchIndexV3.from_payload
)


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise LibraryAbiError(
            "catalog_read_failed", str(error), location=str(path)
        ) from error
    if not isinstance(value, Mapping):
        raise LibraryAbiError(
            "record_type_mismatch", "expected an object", location=str(path)
        )
    return value


def _catalog_paths(source: Path | str | Sequence[Path | str]) -> tuple[Path, ...]:
    if isinstance(source, (str, Path)):
        initial = (Path(source),)
    else:
        initial = tuple(Path(item) for item in source)
    expanded: list[Path] = []
    for path in initial:
        payload = _read_json(path)
        if payload.get("format") == LIBRARY_CATALOG_LOCK_FORMAT:
            for index, raw in enumerate(payload.get("entries", [])):
                if not isinstance(raw, Mapping):
                    raise LibraryAbiError(
                        "record_type_mismatch",
                        "catalog-lock entry is not an object",
                        location=f"{path}.entries[{index}]",
                    )
                entry_path = Path(_text(raw.get("path"), f"{path}.entries[{index}].path"))
                expected = _sha256(
                    raw.get("file_sha256"), f"{path}.entries[{index}].file_sha256"
                )
                if not entry_path.is_file() or sha256_file(entry_path) != expected:
                    raise LibraryAbiError(
                        "stale_catalog_lock",
                        "locked catalog index is missing or changed",
                        location=str(entry_path),
                    )
                expanded.append(entry_path)
        else:
            expanded.append(path)
    return tuple(expanded)


def _legacy_functions(
    payload: Mapping[str, Any], path: Path
) -> tuple[tuple[LibraryFunctionSignatureV3, ...], tuple[LibraryIssueV3, ...]]:
    if payload.get("format") not in {
        LIBRARY_ARTIFACT_INDEX_FORMAT,
        LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    }:
        raise LibraryAbiError(
            "unsupported_catalog_format",
            "expected a v3 ABI catalog or legacy artifact index",
            location=f"{path}.format",
        )
    catalog_id = _text(payload.get("catalog_id"), f"{path}.catalog_id")
    snapshot = payload.get("snapshot")
    snapshot_id = (
        str(snapshot.get("id"))
        if isinstance(snapshot, Mapping) and snapshot.get("id")
        else "legacy-unspecified-release"
    )
    functions: list[LibraryFunctionSignatureV3] = []
    issues: list[LibraryIssueV3] = []
    for artifact_index, raw_artifact in enumerate(payload.get("artifacts", [])):
        if not isinstance(raw_artifact, Mapping):
            continue
        identity = raw_artifact.get("library_identity")
        family_id = (
            str(identity.get("family_id"))
            if isinstance(identity, Mapping) and identity.get("family_id")
            else catalog_id
        )
        release_id = (
            str(identity.get("release_id"))
            if isinstance(identity, Mapping) and identity.get("release_id")
            else snapshot_id
        )
        artifact_id = str(raw_artifact.get("id", f"artifact-{artifact_index}"))
        retention_model = str(raw_artifact.get("retention_model", "unknown"))

        def visit(node: object, member_path: tuple[str, ...]) -> None:
            if not isinstance(node, Mapping):
                return
            code_sections = {
                int(section["index"])
                for section in node.get("sections", [])
                if isinstance(section, Mapping)
                and isinstance(section.get("index"), int)
                and (section.get("contains_code") is True or section.get("executable") is True)
            }
            for raw_member in node.get("members", []):
                if isinstance(raw_member, Mapping):
                    name = str(raw_member.get("name", "anonymous-member"))
                    visit(raw_member.get("index"), (*member_path, name))
            for fingerprint_index, raw_fingerprint in enumerate(
                node.get("function_fingerprints", [])
            ):
                if not isinstance(raw_fingerprint, Mapping):
                    continue
                symbol = str(raw_fingerprint.get("name", "anonymous"))
                symbols = tuple(
                    sorted(
                        {
                            str(item)
                            for item in raw_fingerprint.get("aliases", [symbol])
                            if isinstance(item, str) and item
                        }
                    )
                ) or (symbol,)
                member_id = "/".join(member_path) or artifact_id
                binding = {
                    "catalog_id": catalog_id,
                    "artifact_id": artifact_id,
                    "member_id": member_id,
                    "symbol": symbol,
                    "offset": raw_fingerprint.get("offset", fingerprint_index),
                }
                function_id = stable_id("library-function-v3", binding)
                raw_holes = raw_fingerprint.get("relocation_holes", [])
                holes = tuple(
                    sorted(
                        (
                            int(hole["offset"]),
                            int(hole["width"]),
                            str(hole.get("type", "unknown")),
                            str(hole.get("target_symbol") or "unknown"),
                        )
                        for hole in raw_holes
                        if isinstance(hole, Mapping)
                        and isinstance(hole.get("offset"), int)
                        and isinstance(hole.get("width"), int)
                        and hole["width"] > 0
                    )
                ) if isinstance(raw_holes, list) else ()
                direct_callees = tuple(
                    sorted(
                        {
                            str(hole.get("target_symbol"))
                            for hole in raw_holes
                            if isinstance(hole, Mapping)
                            and hole.get("target_symbol")
                            and hole.get("target_section") in code_sections
                        }
                    )
                ) if isinstance(raw_holes, list) else ()
                imports = tuple(
                    sorted(
                        {
                            str(hole.get("target_symbol"))
                            for hole in raw_holes
                            if isinstance(hole, Mapping)
                            and hole.get("target_symbol")
                            and hole.get("target_section") == 0
                        }
                    )
                ) if isinstance(raw_holes, list) else ()
                data_refs = tuple(
                    sorted(
                        {
                            str(hole.get("target_symbol"))
                            for hole in raw_holes
                            if isinstance(hole, Mapping)
                            and hole.get("target_symbol")
                            and isinstance(hole.get("target_section"), int)
                            and hole.get("target_section") not in code_sections
                            and hole.get("target_section") != 0
                        }
                    )
                ) if isinstance(raw_holes, list) else ()
                function = LibraryFunctionSignatureV3(
                    function_id=function_id,
                    catalog_id=catalog_id,
                    family_id=family_id,
                    release_id=release_id,
                    member_id=member_id,
                    symbols=symbols,
                    normalized_bytes_sha256=(
                        str(raw_fingerprint["normalized_sha256"])
                        if raw_fingerprint.get("normalized_sha256")
                        else None
                    ),
                    exact_bytes_sha256=(
                        str(raw_fingerprint["bytes_sha256"])
                        if raw_fingerprint.get("bytes_sha256")
                        else None
                    ),
                    unit_merkle_sha256=None,
                    cfg_sha256=None,
                    direct_callees=direct_callees,
                    imports=imports,
                    constants=(),
                    strings=(),
                    data_refs=data_refs,
                    abi_profile_id=None,
                    object_size=(
                        int(raw_fingerprint["size"])
                        if isinstance(raw_fingerprint.get("size"), int)
                        and raw_fingerprint["size"] > 0
                        else None
                    ),
                    masked_bytes_hex=(
                        str(raw_fingerprint["masked_bytes"])
                        if raw_fingerprint.get("masked_bytes")
                        else None
                    ),
                    relocation_holes=holes,
                    fixed_bytes=(
                        int(raw_fingerprint["fixed_bytes"])
                        if isinstance(raw_fingerprint.get("fixed_bytes"), int)
                        else None
                    ),
                    match_strength=(
                        str(raw_fingerprint["match_strength"])
                        if raw_fingerprint.get("match_strength") in {"weak", "strong"}
                        else None
                    ),
                    retention_model=retention_model,
                    operation_id=_portable_operation_id(
                        family_id=family_id,
                        symbol=min(symbols),
                    ),
                )
                functions.append(function)
                issues.append(
                    LibraryIssueV3(
                        "incomplete",
                        "legacy_function_abi_missing",
                        "legacy catalog signature has no complete machine ABI profile",
                        f"catalog:{catalog_id}/function:{function_id}",
                    )
                )

        visit(raw_artifact.get("index"), ())
    return tuple(functions), tuple(issues)


def _entries(
    functions: Iterable[LibraryFunctionSignatureV3],
    feature: str,
) -> tuple[IndexEntryV3, ...]:
    grouped: dict[str, set[str]] = {}
    for function in functions:
        raw = getattr(function, feature)
        values: tuple[object, ...]
        if isinstance(raw, tuple):
            values = raw
        elif raw is None:
            values = ()
        else:
            values = (raw,)
        for value in values:
            grouped.setdefault(str(value), set()).add(function.function_id)
    return tuple(
        IndexEntryV3(key, tuple(sorted(function_ids)))
        for key, function_ids in sorted(grouped.items())
    )


def build_catalog_search_index(
    catalog_lock_or_indexes: Path | str | Sequence[Path | str],
    out: Path | str,
) -> CatalogSearchIndexV3:
    """Build one deterministic sparse index from immutable catalog records.

    ``catalog_lock_or_indexes`` accepts a catalog lock, v3 ABI-catalog paths,
    legacy v1/v2 artifact-index paths, or a sequence of those paths.
    """

    bindings: list[tuple[str, str]] = []
    profiles: list[LibraryAbiProfileV3] = []
    functions: list[LibraryFunctionSignatureV3] = []
    behaviors: list[LibraryBehaviorEntryV3] = []
    issues: list[LibraryIssueV3] = []
    for path in _catalog_paths(catalog_lock_or_indexes):
        payload = _read_json(path)
        if payload.get("format") == ABI_CATALOG_V3_FORMAT:
            catalog = LIBRARY_ABI_CATALOG_CODEC_V3.decode(payload, str(path))
            bindings.append((catalog.catalog_id, catalog.catalog_sha256))
            profiles.extend(catalog.abi_profiles)
            functions.extend(catalog.functions)
            behaviors.extend(catalog.behaviors)
        else:
            legacy_functions, legacy_issues = _legacy_functions(payload, path)
            catalog_id = _text(payload.get("catalog_id"), f"{path}.catalog_id")
            digest = _sha256(payload.get("index_sha256"), f"{path}.index_sha256")
            bindings.append((catalog_id, digest))
            functions.extend(legacy_functions)
            issues.extend(legacy_issues)
    bindings.sort()
    if len({item[0] for item in bindings}) != len(bindings):
        raise LibraryAbiError(
            "catalog_identity_conflict",
            "duplicate catalog identity",
            location="catalog search index",
        )

    def deduplicate(rows: Iterable[Any], identity: str, label: str) -> list[Any]:
        selected: dict[str, Any] = {}
        for row in rows:
            key = str(getattr(row, identity))
            previous = selected.get(key)
            if previous is not None and previous != row:
                raise LibraryAbiError(
                    "catalog_identity_conflict",
                    f"contradictory {label} records share ID {key!r}",
                    location="catalog search index",
                )
            selected[key] = row
        return [selected[key] for key in sorted(selected)]

    profiles = deduplicate(profiles, "profile_id", "ABI profile")
    functions = deduplicate(functions, "function_id", "function")
    behaviors = deduplicate(behaviors, "behavior_entry_id", "behavior")
    status = phase_status(issues)
    placeholder = CatalogSearchIndexV3(
        status=status,
        catalog_bindings=tuple(bindings),
        abi_profiles=tuple(profiles),
        functions=tuple(functions),
        behaviors=tuple(behaviors),
        normalized_hash_index=_entries(functions, "normalized_bytes_sha256"),
        exact_hash_index=_entries(functions, "exact_bytes_sha256"),
        unit_merkle_index=_entries(functions, "unit_merkle_sha256"),
        cfg_hash_index=_entries(functions, "cfg_sha256"),
        import_index=_entries(functions, "imports"),
        string_index=_entries(functions, "strings"),
        constant_index=_entries(functions, "constants"),
        issues=tuple(sorted(issues)),
        index_sha256="0" * 64,
    )
    result = CatalogSearchIndexV3(
        **{
            **placeholder.__dict__,
            "index_sha256": canonical_sha256(placeholder.core_payload),
        }
    )
    CATALOG_SEARCH_INDEX_CODEC_V3.write(out, result)
    return result


__all__ = [
    "CATALOG_SEARCH_INDEX_CODEC_V3",
    "LIBRARY_ABI_CATALOG_CODEC_V3",
    "CatalogSearchIndexV3",
    "LibraryAbiCatalogV3",
    "build_catalog_search_index",
]
