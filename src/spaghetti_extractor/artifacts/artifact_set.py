"""Typed, canonical, bounded artifact sets for incremental analysis phases.

The v3 format deliberately separates a small canonical manifest from bounded
NDJSON packs.  Pack identities bind their exact bytes while the artifact
identity binds every pack, static binding, and upstream dependency.  Hashes
provide cache and provenance identities; consumers must still invoke their
semantic completeness checker before treating records as authority.
"""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeAlias


ARTIFACT_SET_V3_FORMAT = "spaghetti-extractor-artifact-set-v3"
ARTIFACT_PACK_V3_FORMAT = "spaghetti-extractor-artifact-pack-v3"
ARTIFACT_BUNDLE_V3_FORMAT = "spaghetti-extractor-artifact-bundle-v3"
STRUCTURAL_SCHEDULE_V3_FORMAT = (
    "spaghetti-extractor-structural-schedule-v3"
)
DEPENDENCY_SCHEDULE_V3_FORMAT = (
    "spaghetti-extractor-dependency-schedule-v3"
)
SCHEMA_VERSION = 3
IDENTITY_BUCKETS = 64
MAX_PACK_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BUNDLE_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BUNDLE_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_READER_PACK_CACHE_BYTES = 128 * 1024 * 1024
MAX_STRUCTURAL_SCHEDULE_BYTES = 2 * 1024 * 1024
MAX_DEPENDENCY_SCHEDULE_BYTES = 4 * 1024 * 1024
DEFAULT_VALUE_CODEC = "recursive-json-v1:min-128"
DEFAULT_PACK_COMPRESSION = "gzip-v1"

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_NAME_RE = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_STATUSES = frozenset({"complete", "incomplete", "violated"})
_RESOURCE_CLASSES = frozenset({"small", "medium", "large", "oracle"})

JsonValue: TypeAlias = (
    None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]
)


class ArtifactV3Error(ValueError):
    """A v3 artifact failed closed with an actionable remediation."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        remediation: str,
        location: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.remediation = remediation
        self.location = location
        where = "" if location is None else f" at {location}"
        super().__init__(f"{code}{where}: {message}. Next action: {remediation}")


def _fail(
    code: str,
    message: str,
    remediation: str,
    *,
    location: str | None = None,
) -> None:
    raise ArtifactV3Error(
        code, message, remediation=remediation, location=location
    )


def _json_value(value: Any, *, context: str = "JSON value") -> JsonValue:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        _fail(
            "noncanonical_json",
            f"{context} contains a floating-point value",
            "encode exact numeric values as integers or bounded strings",
        )
    # Canonical artifacts use concrete JSON containers.  Avoid paying for
    # collections.abc protocol checks at every node in large semantic trees;
    # retain the generic branches below for adapter-provided mappings.
    if type(value) is dict:
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(
                    "noncanonical_json",
                    f"{context} contains a non-string key",
                    "use string keys in every artifact object",
                )
            result[key] = _json_value(item, context=f"{context}.{key}")
        return result
    if type(value) is list or type(value) is tuple:
        return [
            _json_value(item, context=f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(
                    "noncanonical_json",
                    f"{context} contains a non-string key",
                    "use string keys in every artifact object",
                )
            result[key] = _json_value(item, context=f"{context}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [
            _json_value(item, context=f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    _fail(
        "noncanonical_json",
        f"{context} contains unsupported type {type(value).__name__}",
        "convert the value to canonical JSON before emitting it",
    )


def canonical_json_bytes_v3(value: Any) -> bytes:
    return _dump_canonical_json_v3(_json_value(value))


def _dump_canonical_json_v3(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256_v3(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes_v3(value)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(
                "duplicate_json_key",
                f"canonical JSON repeats key {key!r}",
                "regenerate the artifact with the v3 canonical writer",
            )
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    _fail(
        "noncanonical_json",
        f"canonical JSON contains floating-point value {value}",
        "encode exact numeric values as integers or bounded strings",
    )


def _reject_constant(value: str) -> Any:
    _fail(
        "noncanonical_json",
        f"canonical JSON contains non-finite constant {value}",
        "remove NaN or infinity from the artifact",
    )


def parse_canonical_json_v3(data: bytes, *, location: str) -> JsonValue:
    try:
        text = data.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(
            "invalid_json",
            f"artifact data is not canonical ASCII JSON: {exc}",
            "regenerate it with ArtifactSetWriterV3",
            location=location,
        )
    normalized = _dump_canonical_json_v3(value)
    if normalized != data:
        _fail(
            "noncanonical_json",
            "artifact JSON does not use canonical key ordering and spacing",
            "regenerate it with ArtifactSetWriterV3",
            location=location,
        )
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _fail(
            "invalid_digest",
            f"{context} is not a lowercase SHA-256 digest",
            "bind the exact producer content hash",
        )
    return value


def _name(value: Any, context: str) -> str:
    if not isinstance(value, str) or _NAME_RE.fullmatch(value) is None:
        _fail(
            "invalid_name",
            f"{context} is not a stable lowercase identifier",
            "use 1-128 lowercase letters, digits, dots, underscores, or hyphens",
        )
    return value


def _text(value: Any, context: str, *, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        _fail(
            "invalid_text",
            f"{context} is not bounded printable text",
            "emit a deterministic nonempty identifier without control characters",
        )
    return value


def _strict_object(
    value: Any, fields: set[str], context: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(
            "noncanonical_fields",
            f"{context} does not have exactly {sorted(fields)!r}",
            "regenerate it with the matching v3 schema writer",
        )
    return value


def _strict_sequence(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(
            "invalid_sequence",
            f"{context} is not an array",
            "emit a canonical JSON array",
        )
    return value


def _canonical_tuple(values: Iterable[str], context: str) -> tuple[str, ...]:
    result = tuple(values)
    for value in result:
        _text(value, context)
    if result != tuple(sorted(set(result))):
        _fail(
            "noncanonical_order",
            f"{context} is duplicated or unsorted",
            "sort and deduplicate the identifiers before constructing the record",
        )
    return result


def identity_bucket_v3(identity: str) -> int:
    """Return the stable 64-way bucket for an identity."""

    _text(identity, "record identity")
    return int.from_bytes(hashlib.sha256(identity.encode("utf-8")).digest(), "big") % IDENTITY_BUCKETS


@dataclass(frozen=True, order=True)
class CanonicalValueV3:
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            _fail(
                "invalid_canonical_value",
                "CanonicalValueV3.data is not bytes",
                "construct values with CanonicalValueV3.of",
            )
        parse_canonical_json_v3(self.data, location="canonical value")

    @classmethod
    def of(cls, value: Any) -> "CanonicalValueV3":
        data = canonical_json_bytes_v3(value)
        result = object.__new__(cls)
        object.__setattr__(result, "data", data)
        return result

    def to_value(self) -> JsonValue:
        return json.loads(self.data.decode("ascii"))


@dataclass(frozen=True, order=True)
class InternedExpressionV3:
    expression_id: str
    value: CanonicalValueV3

    @classmethod
    def create(cls, value: Any) -> "InternedExpressionV3":
        canonical = CanonicalValueV3.of(value)
        digest = hashlib.sha256(canonical.data).hexdigest()
        return cls(f"expr:{digest}", canonical)

    def __post_init__(self) -> None:
        expected = "expr:" + hashlib.sha256(self.value.data).hexdigest()
        if self.expression_id != expected:
            _fail(
                "stale_expression_id",
                f"expression ID {self.expression_id!r} does not bind its value",
                "recreate it with InternedExpressionV3.create",
            )

    def reference(self) -> dict[str, str]:
        return {"$expr": self.expression_id}

    def to_payload(self) -> dict[str, JsonValue]:
        return {"id": self.expression_id, "value": self.value.to_value()}


@dataclass(frozen=True)
class EncodedValueV3:
    root: JsonValue
    nodes: tuple[tuple[str, JsonValue], ...]


class ValueCodecV3(Protocol):
    """Codec contract for deterministic pack-local value interning."""

    @property
    def identity(self) -> str: ...

    def encode(self, value: CanonicalValueV3) -> EncodedValueV3: ...

    def decode(
        self,
        root: JsonValue,
        nodes: Mapping[str, JsonValue],
        *,
        used_nodes: set[str] | None = None,
    ) -> CanonicalValueV3: ...


class RecursiveJsonCodecV3:
    """Merkle-intern repeated compound JSON values within each pack.

    Small values remain inline to avoid turning scalar-heavy records into a
    forest of tiny definitions.  Large dictionaries and arrays become nodes;
    parent nodes refer recursively to child nodes, so repeated exact records,
    expression trees, and state inventories are represented once per pack.
    """

    def __init__(self, minimum_bytes: int = 128, *, cache_nodes: int = 8192) -> None:
        if not 32 <= minimum_bytes <= 4096:
            _fail(
                "invalid_codec_threshold",
                f"recursive interning threshold {minimum_bytes} is outside 32..4096",
                "use the default 128-byte threshold unless a measured codec requires another bounded value",
            )
        self.minimum_bytes = minimum_bytes
        self._cache_nodes = cache_nodes
        self._node_cache: OrderedDict[str, JsonValue] = OrderedDict()

    @property
    def identity(self) -> str:
        return f"recursive-json-v1:min-{self.minimum_bytes}"

    def encode(self, value: CanonicalValueV3) -> EncodedValueV3:
        nodes: dict[str, JsonValue] = {}

        def cached_closure_available(node_id: str) -> bool:
            pending = [node_id]
            observed: set[str] = set()
            while pending:
                current = pending.pop()
                if current in observed:
                    continue
                if current not in self._node_cache:
                    return False
                observed.add(current)
                pending.extend(
                    _encoded_node_references(self._node_cache[current])
                )
            return True

        def add_cached_closure(node_id: str) -> None:
            pending = [node_id]
            while pending:
                current = pending.pop()
                if current in nodes:
                    continue
                encoded = self._node_cache[current]
                nodes[current] = encoded
                pending.extend(_encoded_node_references(encoded))

        def visit(item: JsonValue, *, force_inline: bool = False) -> JsonValue:
            if not isinstance(item, (dict, list)):
                return item
            canonical = canonical_json_bytes_v3(item)
            should_intern = not force_inline and len(canonical) >= self.minimum_bytes
            node_id = "value-node:" + hashlib.sha256(canonical).hexdigest()
            if (
                should_intern
                and node_id in self._node_cache
                and cached_closure_available(node_id)
            ):
                self._node_cache.move_to_end(node_id)
                add_cached_closure(node_id)
                return {"$v3_ref": node_id}
            if isinstance(item, dict):
                encoded_object = {
                    key: visit(child) for key, child in sorted(item.items())
                }
                encoded: JsonValue = (
                    {"$v3_object": [[key, value] for key, value in encoded_object.items()]}
                    if "$v3_ref" in encoded_object or "$v3_object" in encoded_object
                    else encoded_object
                )
            else:
                encoded = [visit(child) for child in item]
            if not should_intern:
                return encoded
            nodes[node_id] = encoded
            self._node_cache[node_id] = encoded
            self._node_cache.move_to_end(node_id)
            while len(self._node_cache) > self._cache_nodes:
                self._node_cache.popitem(last=False)
            return {"$v3_ref": node_id}

        root = visit(value.to_value(), force_inline=True)
        return EncodedValueV3(root, tuple(sorted(nodes.items())))

    def decode(
        self,
        root: JsonValue,
        nodes: Mapping[str, JsonValue],
        *,
        used_nodes: set[str] | None = None,
    ) -> CanonicalValueV3:
        active: set[str] = set()
        cache: dict[str, JsonValue] = {}

        def visit(encoded: JsonValue) -> JsonValue:
            if not isinstance(encoded, (Mapping, list)):
                return _json_value(encoded)
            if isinstance(encoded, list):
                return [visit(item) for item in encoded]
            if set(encoded) == {"$v3_object"}:
                items = _strict_sequence(encoded["$v3_object"], "escaped object items")
                result: JsonValue = {}
                assert isinstance(result, dict)
                previous_key: str | None = None
                for pair in items:
                    pair_items = _strict_sequence(pair, "inline object pair")
                    if len(pair_items) != 2 or not isinstance(pair_items[0], str):
                        _fail("invalid_encoded_value", "escaped object item is not [key, value]", "regenerate it with RecursiveJsonCodecV3")
                    key = pair_items[0]
                    if previous_key is not None and key <= previous_key:
                        _fail("noncanonical_encoded_value", "escaped object keys are duplicated or unsorted", "regenerate it with RecursiveJsonCodecV3")
                    result[key] = visit(pair_items[1])
                    previous_key = key
                return result
            if set(encoded) != {"$v3_ref"}:
                return {key: visit(child) for key, child in encoded.items()}
            node_id = str(encoded["$v3_ref"])
            if node_id in cache:
                if used_nodes is not None:
                    used_nodes.add(node_id)
                return cache[node_id]
            if node_id in active:
                _fail(
                    "cyclic_value_nodes",
                    f"recursive value graph contains a cycle at {node_id!r}",
                    "regenerate it from finite canonical JSON values",
                )
            if node_id not in nodes:
                _fail(
                    "undefined_value_node",
                    f"encoded value refers to absent node {node_id!r}",
                    "place every recursive value node in the same pack",
                )
            active.add(node_id)
            result = visit(nodes[node_id])
            active.remove(node_id)
            expected = "value-node:" + canonical_sha256_v3(result)
            if expected != node_id:
                _fail(
                    "stale_value_node",
                    f"recursive value node {node_id!r} does not bind its decoded value",
                    "discard and rebuild the artifact pack",
                )
            cache[node_id] = result
            if used_nodes is not None:
                used_nodes.add(node_id)
            return result

        return CanonicalValueV3.of(visit(root))


def _encoded_node_references(value: JsonValue) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        if set(value) == {"$v3_ref"} and isinstance(value["$v3_ref"], str):
            result.add(value["$v3_ref"])
        else:
            for child in value.values():
                result.update(_encoded_node_references(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_encoded_node_references(child))
    return result


def value_codec_v3(identity: str) -> ValueCodecV3:
    match = re.fullmatch(r"recursive-json-v1:min-([0-9]+)", identity)
    if match is None:
        _fail(
            "unsupported_value_codec",
            f"artifact requires unregistered value codec {identity!r}",
            "register the codec with the reader or regenerate using RecursiveJsonCodecV3",
        )
    return RecursiveJsonCodecV3(int(match.group(1)))


@dataclass(frozen=True, order=True)
class RecordDependencyV3:
    input_name: str
    record_id: str

    def __post_init__(self) -> None:
        _name(self.input_name, "dependency input name")
        _text(self.record_id, "dependency record ID")

    def to_payload(self) -> dict[str, str]:
        return {"input": self.input_name, "record_id": self.record_id}

    @classmethod
    def parse(cls, value: Any) -> "RecordDependencyV3":
        row = _strict_object(value, {"input", "record_id"}, "record dependency")
        return cls(str(row["input"]), str(row["record_id"]))


def _collect_expression_refs(value: JsonValue) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        if "$expr" in value:
            if set(value) != {"$expr"} or not isinstance(value["$expr"], str):
                _fail(
                    "invalid_expression_reference",
                    "an expression reference must be exactly {'$expr': '<id>'}",
                    "use InternedExpressionV3.reference()",
                )
            result.add(value["$expr"])
        else:
            for item in value.values():
                result.update(_collect_expression_refs(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_collect_expression_refs(item))
    return result


@dataclass(frozen=True, order=True)
class ArtifactRecordV3:
    record_id: str
    value: CanonicalValueV3
    dependencies: tuple[RecordDependencyV3, ...] = ()
    expressions: tuple[InternedExpressionV3, ...] = ()

    def __post_init__(self) -> None:
        _text(self.record_id, "record ID")
        if self.dependencies != tuple(sorted(set(self.dependencies))):
            _fail(
                "noncanonical_dependencies",
                f"record {self.record_id!r} has duplicate or unsorted dependencies",
                "sort and deduplicate record dependencies",
            )
        if self.expressions != tuple(
            sorted(set(self.expressions), key=lambda row: row.expression_id)
        ):
            _fail(
                "noncanonical_expressions",
                f"record {self.record_id!r} has duplicate or unsorted expressions",
                "construct the record with ArtifactRecordV3.create",
            )
        declared = {row.expression_id for row in self.expressions}
        referenced = _collect_expression_refs(self.value.to_value())
        if declared != referenced:
            _fail(
                "expression_inventory_mismatch",
                f"record {self.record_id!r} declares {sorted(declared)!r} but references {sorted(referenced)!r}",
                "use InternedExpressionV3.reference() and pass exactly those expressions to ArtifactRecordV3.create",
            )

    @classmethod
    def create(
        cls,
        record_id: str,
        value: Any,
        *,
        dependencies: Iterable[RecordDependencyV3] = (),
        expressions: Iterable[InternedExpressionV3] = (),
    ) -> "ArtifactRecordV3":
        return cls(
            record_id=record_id,
            value=CanonicalValueV3.of(value),
            dependencies=tuple(sorted(set(dependencies))),
            expressions=tuple(
                sorted(set(expressions), key=lambda row: row.expression_id)
            ),
        )


@dataclass(frozen=True, order=True)
class ArtifactBindingV3:
    name: str
    kind: str
    identity: str
    sha256: str

    def __post_init__(self) -> None:
        _name(self.name, "binding name")
        _name(self.kind, "binding kind")
        _text(self.identity, "binding identity")
        _digest(self.sha256, "binding SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "name": self.name,
            "kind": self.kind,
            "identity": self.identity,
            "sha256": self.sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "ArtifactBindingV3":
        row = _strict_object(
            value, {"name", "kind", "identity", "sha256"}, "artifact binding"
        )
        return cls(*(str(row[key]) for key in ("name", "kind", "identity", "sha256")))


@dataclass(frozen=True, order=True)
class ArtifactDependencyV3:
    name: str
    artifact_kind: str
    artifact_id: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        _name(self.name, "artifact dependency name")
        _name(self.artifact_kind, "artifact dependency kind")
        _text(self.artifact_id, "artifact dependency ID")
        _digest(self.manifest_sha256, "artifact dependency manifest SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "name": self.name,
            "artifact_kind": self.artifact_kind,
            "artifact_id": self.artifact_id,
            "manifest_sha256": self.manifest_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "ArtifactDependencyV3":
        row = _strict_object(
            value,
            {"name", "artifact_kind", "artifact_id", "manifest_sha256"},
            "artifact dependency",
        )
        return cls(
            name=str(row["name"]),
            artifact_kind=str(row["artifact_kind"]),
            artifact_id=str(row["artifact_id"]),
            manifest_sha256=str(row["manifest_sha256"]),
        )


@dataclass(frozen=True, order=True)
class ArtifactPackV3:
    bucket: int
    part: int
    path: str
    record_count: int
    size_bytes: int
    sha256: str
    decoded_size_bytes: int
    decoded_sha256: str
    first_record_id: str
    last_record_id: str

    def __post_init__(self) -> None:
        if not 0 <= self.bucket < IDENTITY_BUCKETS or self.part < 0:
            _fail(
                "invalid_pack_index",
                "pack bucket or part is outside its bounded range",
                "let ArtifactSetWriterV3 assign pack indexes",
            )
        expected_path = f"packs/{self.bucket:02d}-{self.part:04d}.ndjson.gz"
        if self.path != expected_path:
            _fail(
                "invalid_pack_path",
                f"pack path {self.path!r} is not {expected_path!r}",
                "let ArtifactSetWriterV3 choose deterministic pack paths",
            )
        if self.record_count <= 0 or self.size_bytes <= 0 or self.decoded_size_bytes <= 0:
            _fail(
                "empty_pack",
                "artifact packs must contain at least one record",
                "omit empty packs from the manifest",
            )
        _digest(self.sha256, "pack SHA-256")
        _digest(self.decoded_sha256, "decoded pack SHA-256")
        _text(self.first_record_id, "first record ID")
        _text(self.last_record_id, "last record ID")
        if self.first_record_id > self.last_record_id:
            _fail(
                "invalid_pack_range",
                "pack record range is reversed",
                "sort records by identity before packing",
            )

    def to_payload(self) -> dict[str, JsonValue]:
        return {
            "bucket": self.bucket,
            "part": self.part,
            "path": self.path,
            "record_count": self.record_count,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "decoded_size_bytes": self.decoded_size_bytes,
            "decoded_sha256": self.decoded_sha256,
            "first_record_id": self.first_record_id,
            "last_record_id": self.last_record_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "ArtifactPackV3":
        fields = {
            "bucket", "part", "path", "record_count", "size_bytes", "sha256",
            "decoded_size_bytes", "decoded_sha256", "first_record_id", "last_record_id",
        }
        row = _strict_object(value, fields, "artifact pack descriptor")
        try:
            return cls(
                bucket=int(row["bucket"]),
                part=int(row["part"]),
                path=str(row["path"]),
                record_count=int(row["record_count"]),
                size_bytes=int(row["size_bytes"]),
                sha256=str(row["sha256"]),
                decoded_size_bytes=int(row["decoded_size_bytes"]),
                decoded_sha256=str(row["decoded_sha256"]),
                first_record_id=str(row["first_record_id"]),
                last_record_id=str(row["last_record_id"]),
            )
        except (TypeError, ValueError) as exc:
            _fail(
                "invalid_pack_descriptor",
                f"pack descriptor fields have invalid types: {exc}",
                "regenerate the artifact manifest",
            )


@dataclass(frozen=True)
class ArtifactSetManifestV3:
    artifact_kind: str
    artifact_id: str
    status: str
    bindings: tuple[ArtifactBindingV3, ...]
    dependencies: tuple[ArtifactDependencyV3, ...]
    packs: tuple[ArtifactPackV3, ...]
    record_count: int
    value_codec: str = DEFAULT_VALUE_CODEC
    pack_compression: str = DEFAULT_PACK_COMPRESSION
    max_pack_bytes: int = MAX_PACK_BYTES
    bucket_count: int = IDENTITY_BUCKETS

    def __post_init__(self) -> None:
        _name(self.artifact_kind, "artifact kind")
        if self.status not in _STATUSES:
            _fail(
                "invalid_status",
                f"artifact status {self.status!r} is not fail-closed",
                "use complete, incomplete, or violated",
            )
        if self.bucket_count != IDENTITY_BUCKETS:
            _fail(
                "invalid_bucket_count",
                f"artifact declares {self.bucket_count} identity buckets",
                f"use the required {IDENTITY_BUCKETS}-bucket v3 assignment",
            )
        _text(self.value_codec, "value codec", maximum=128)
        value_codec_v3(self.value_codec)
        if self.pack_compression != DEFAULT_PACK_COMPRESSION:
            _fail(
                "unsupported_pack_compression",
                f"artifact declares {self.pack_compression!r}",
                f"use the deterministic {DEFAULT_PACK_COMPRESSION} codec",
            )
        if not 256 <= self.max_pack_bytes <= MAX_PACK_BYTES:
            _fail(
                "invalid_pack_limit",
                f"pack limit {self.max_pack_bytes} is outside 256..{MAX_PACK_BYTES}",
                "use the default 8 MiB limit or a smaller test limit",
            )
        if self.record_count < 0:
            _fail(
                "invalid_record_count",
                "artifact record count is negative",
                "regenerate the manifest from emitted records",
            )
        if self.bindings != tuple(sorted(set(self.bindings))):
            _fail(
                "noncanonical_bindings",
                "artifact bindings are duplicated or unsorted",
                "sort bindings by their typed fields",
            )
        if len({row.name for row in self.bindings}) != len(self.bindings):
            _fail(
                "duplicate_binding_name",
                "artifact bindings repeat a name",
                "give each semantic binding one stable name",
            )
        if self.dependencies != tuple(sorted(set(self.dependencies))):
            _fail(
                "noncanonical_artifact_dependencies",
                "artifact dependencies are duplicated or unsorted",
                "sort dependencies by their typed fields",
            )
        if len({row.name for row in self.dependencies}) != len(self.dependencies):
            _fail(
                "duplicate_dependency_name",
                "artifact dependencies repeat an input name",
                "declare each input exactly once",
            )
        if self.packs != tuple(sorted(self.packs)):
            _fail(
                "noncanonical_pack_order",
                "artifact packs are not ordered by bucket and part",
                "let ArtifactSetWriterV3 construct the manifest",
            )
        if sum(row.record_count for row in self.packs) != self.record_count:
            _fail(
                "stale_record_count",
                "manifest record count disagrees with pack descriptors",
                "regenerate the manifest from the exact packs",
            )
        previous_part: dict[int, int] = {}
        for pack in self.packs:
            expected = previous_part.get(pack.bucket, -1) + 1
            if pack.part != expected or pack.size_bytes > self.max_pack_bytes or pack.decoded_size_bytes > self.max_pack_bytes:
                _fail(
                    "invalid_pack_inventory",
                    "pack parts are non-contiguous or exceed the declared limit",
                    "repack with ArtifactSetWriterV3",
                )
            previous_part[pack.bucket] = pack.part
        expected_id = "artifact-set-v3:" + canonical_sha256_v3(
            self.identity_payload()
        )
        if self.artifact_id != expected_id:
            _fail(
                "stale_artifact_id",
                "artifact ID does not bind its manifest inventory",
                "regenerate the artifact set instead of editing its manifest",
            )

    def identity_payload(self) -> dict[str, JsonValue]:
        return {
            "format": ARTIFACT_SET_V3_FORMAT,
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": self.artifact_kind,
            "status": self.status,
            "bucket_count": self.bucket_count,
            "max_pack_bytes": self.max_pack_bytes,
            "record_count": self.record_count,
            "value_codec": self.value_codec,
            "pack_compression": self.pack_compression,
            "bindings": [row.to_payload() for row in self.bindings],
            "dependencies": [row.to_payload() for row in self.dependencies],
            "packs": [row.to_payload() for row in self.packs],
        }

    def to_payload(self) -> dict[str, JsonValue]:
        return {**self.identity_payload(), "artifact_id": self.artifact_id}

    def to_bytes(self) -> bytes:
        data = canonical_json_bytes_v3(self.to_payload())
        if len(data) > MAX_ARTIFACT_MANIFEST_BYTES:
            _fail(
                "oversized_artifact_manifest",
                f"artifact manifest is {len(data)} bytes",
                "use stable pack buckets instead of listing records in the manifest",
            )
        return data

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def create(
        cls,
        *,
        artifact_kind: str,
        status: str,
        bindings: Iterable[ArtifactBindingV3],
        dependencies: Iterable[ArtifactDependencyV3],
        packs: Iterable[ArtifactPackV3],
        record_count: int,
        max_pack_bytes: int,
        value_codec: str = DEFAULT_VALUE_CODEC,
        pack_compression: str = DEFAULT_PACK_COMPRESSION,
    ) -> "ArtifactSetManifestV3":
        fields = dict(
            artifact_kind=artifact_kind,
            status=status,
            bindings=tuple(sorted(set(bindings))),
            dependencies=tuple(sorted(set(dependencies))),
            packs=tuple(sorted(packs)),
            record_count=record_count,
            value_codec=value_codec,
            pack_compression=pack_compression,
            max_pack_bytes=max_pack_bytes,
            bucket_count=IDENTITY_BUCKETS,
        )
        identity = {
            "format": ARTIFACT_SET_V3_FORMAT,
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": artifact_kind,
            "status": status,
            "bucket_count": IDENTITY_BUCKETS,
            "max_pack_bytes": max_pack_bytes,
            "record_count": record_count,
            "value_codec": value_codec,
            "pack_compression": pack_compression,
            "bindings": [row.to_payload() for row in fields["bindings"]],
            "dependencies": [row.to_payload() for row in fields["dependencies"]],
            "packs": [row.to_payload() for row in fields["packs"]],
        }
        return cls(artifact_id="artifact-set-v3:" + canonical_sha256_v3(identity), **fields)

    @classmethod
    def parse_bytes(cls, data: bytes, *, location: str = "manifest.json") -> "ArtifactSetManifestV3":
        if len(data) > MAX_ARTIFACT_MANIFEST_BYTES:
            _fail(
                "oversized_artifact_manifest",
                f"artifact manifest is {len(data)} bytes",
                "regenerate it as a compact pack inventory",
                location=location,
            )
        value = parse_canonical_json_v3(data, location=location)
        fields = {
            "format", "schema_version", "artifact_kind", "artifact_id", "status",
            "bucket_count", "max_pack_bytes", "record_count", "bindings",
            "dependencies", "packs",
            "value_codec",
            "pack_compression",
        }
        row = _strict_object(value, fields, "artifact manifest")
        if row["format"] != ARTIFACT_SET_V3_FORMAT or row["schema_version"] != SCHEMA_VERSION:
            _fail(
                "wrong_artifact_format",
                "manifest is not an artifact-set-v3 document",
                "use the v3 reader only with v3 artifacts",
                location=location,
            )
        try:
            return cls(
                artifact_kind=str(row["artifact_kind"]),
                artifact_id=str(row["artifact_id"]),
                status=str(row["status"]),
                bucket_count=int(row["bucket_count"]),
                max_pack_bytes=int(row["max_pack_bytes"]),
                record_count=int(row["record_count"]),
                value_codec=str(row["value_codec"]),
                pack_compression=str(row["pack_compression"]),
                bindings=tuple(ArtifactBindingV3.parse(item) for item in _strict_sequence(row["bindings"], "manifest bindings")),
                dependencies=tuple(ArtifactDependencyV3.parse(item) for item in _strict_sequence(row["dependencies"], "manifest dependencies")),
                packs=tuple(ArtifactPackV3.parse(item) for item in _strict_sequence(row["packs"], "manifest packs")),
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ArtifactV3Error):
                raise
            _fail(
                "invalid_artifact_manifest",
                f"manifest fields have invalid types: {exc}",
                "regenerate the artifact set",
                location=location,
            )


def _record_value_payload(record: ArtifactRecordV3) -> dict[str, JsonValue]:
    return {
        "value": record.value.to_value(),
        "expression_ids": [row.expression_id for row in record.expressions],
        "dependencies": [row.to_payload() for row in record.dependencies],
    }


def _record_value_id(record: ArtifactRecordV3) -> str:
    return "record-value:" + canonical_sha256_v3(_record_value_payload(record))


def _pack_header(
    artifact_kind: str,
    bucket: int,
    part: int,
    record_ids: Sequence[str],
) -> bytes:
    return canonical_json_bytes_v3({
        "entry": "header",
        "format": ARTIFACT_PACK_V3_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": artifact_kind,
        "bucket": bucket,
        "part": part,
        "record_count": len(record_ids),
        "first_record_id": record_ids[0],
        "last_record_id": record_ids[-1],
    }) + b"\n"


class ArtifactSetWriterV3:
    """Stream records through a disk index into deterministic bounded packs."""

    def __init__(
        self,
        *,
        artifact_kind: str,
        bindings: Iterable[ArtifactBindingV3],
        dependencies: Iterable[ArtifactDependencyV3] = (),
        status: str = "complete",
        max_pack_bytes: int = MAX_PACK_BYTES,
        value_codec: ValueCodecV3 | None = None,
    ) -> None:
        self.artifact_kind = _name(artifact_kind, "artifact kind")
        self.bindings = tuple(sorted(set(bindings)))
        self.dependencies = tuple(sorted(set(dependencies)))
        self.status = status
        if status not in _STATUSES:
            _fail(
                "invalid_status", f"status {status!r} is invalid", "use complete, incomplete, or violated"
            )
        if not 256 <= max_pack_bytes <= MAX_PACK_BYTES:
            _fail(
                "invalid_pack_limit",
                f"pack limit {max_pack_bytes} is outside 256..{MAX_PACK_BYTES}",
                "use the default limit or a bounded smaller test value",
            )
        self.max_pack_bytes = max_pack_bytes
        self.value_codec = RecursiveJsonCodecV3() if value_codec is None else value_codec
        _text(self.value_codec.identity, "value codec identity", maximum=128)
        if len({row.name for row in self.dependencies}) != len(self.dependencies):
            _fail(
                "duplicate_dependency_name",
                "artifact dependencies repeat an input name",
                "declare each input once",
            )

    def write(
        self, output_directory: Path | str, records: Iterable[ArtifactRecordV3]
    ) -> ArtifactSetManifestV3:
        destination = Path(output_directory)
        if destination.exists():
            _fail(
                "output_exists",
                f"artifact output {destination} already exists",
                "choose a fresh output path so stale packs cannot survive",
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
        database_path = staging / ".records.sqlite"
        try:
            count = self._spool(database_path, records)
            packs = self._write_packs(staging, database_path)
            database_path.unlink()
            manifest = ArtifactSetManifestV3.create(
                artifact_kind=self.artifact_kind,
                status=self.status,
                bindings=self.bindings,
                dependencies=self.dependencies,
                packs=packs,
                record_count=count,
                max_pack_bytes=self.max_pack_bytes,
                value_codec=self.value_codec.identity,
                pack_compression=DEFAULT_PACK_COMPRESSION,
            )
            (staging / "manifest.json").write_bytes(manifest.to_bytes())
            os.replace(staging, destination)
            return manifest
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def _spool(
        self, database_path: Path, records: Iterable[ArtifactRecordV3]
    ) -> int:
        connection = sqlite3.connect(database_path)
        try:
            connection.execute(
                "CREATE TABLE records (record_id TEXT PRIMARY KEY, bucket INTEGER NOT NULL, payload BLOB NOT NULL, dependencies BLOB NOT NULL, expressions BLOB NOT NULL)"
            )
            count = 0
            for item in records:
                if not isinstance(item, ArtifactRecordV3):
                    _fail(
                        "untyped_record",
                        f"writer received {type(item).__name__} instead of ArtifactRecordV3",
                        "return ArtifactRecordV3.create(...) from the phase transform",
                    )
                undeclared = sorted({row.input_name for row in item.dependencies} - {row.name for row in self.dependencies})
                if undeclared:
                    _fail(
                        "undeclared_dependency",
                        f"record {item.record_id!r} refers to undeclared inputs {undeclared!r}",
                        "add those inputs to the phase declaration; do not read or reference them implicitly",
                    )
                try:
                    connection.execute(
                        "INSERT INTO records VALUES (?, ?, ?, ?, ?)",
                        (
                            item.record_id,
                            identity_bucket_v3(item.record_id),
                            item.value.data,
                            canonical_json_bytes_v3([row.to_payload() for row in item.dependencies]),
                            canonical_json_bytes_v3([row.to_payload() for row in item.expressions]),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    _fail(
                        "duplicate_record_id",
                        f"record ID {item.record_id!r} was emitted more than once",
                        "make the phase output identity deterministic and unique",
                    )
                count += 1
            connection.commit()
            return count
        finally:
            connection.close()

    def _write_packs(self, root: Path, database_path: Path) -> tuple[ArtifactPackV3, ...]:
        packs_directory = root / "packs"
        packs_directory.mkdir()
        result: list[ArtifactPackV3] = []
        connection = sqlite3.connect(database_path)
        try:
            for bucket in range(IDENTITY_BUCKETS):
                cursor = connection.execute(
                    "SELECT record_id, payload, dependencies, expressions FROM records WHERE bucket = ? ORDER BY record_id",
                    (bucket,),
                )
                part = 0
                state = _PackBuildState(self.artifact_kind, bucket, part, self.value_codec)
                for row in cursor:
                    record = ArtifactRecordV3(
                        record_id=str(row[0]),
                        value=CanonicalValueV3(bytes(row[1])),
                        dependencies=tuple(RecordDependencyV3.parse(item) for item in json.loads(bytes(row[2]).decode("ascii"))),
                        expressions=tuple(InternedExpressionV3(str(item["id"]), CanonicalValueV3.of(item["value"])) for item in json.loads(bytes(row[3]).decode("ascii"))),
                    )
                    if not state.can_add(record, self.max_pack_bytes):
                        if not state.record_ids:
                            _fail(
                                "oversized_record",
                                f"record {record.record_id!r} cannot fit in a {self.max_pack_bytes}-byte pack",
                                "split the semantic record into smaller independently identified records",
                            )
                        result.append(state.flush(packs_directory, self.max_pack_bytes))
                        part += 1
                        state = _PackBuildState(self.artifact_kind, bucket, part, self.value_codec)
                        if not state.can_add(record, self.max_pack_bytes):
                            _fail(
                                "oversized_record",
                                f"record {record.record_id!r} cannot fit in a {self.max_pack_bytes}-byte pack",
                                "split the semantic record into smaller independently identified records",
                            )
                    state.add(record)
                if state.record_ids:
                    result.append(state.flush(packs_directory, self.max_pack_bytes))
        finally:
            connection.close()
        return tuple(result)


class _PackBuildState:
    def __init__(self, artifact_kind: str, bucket: int, part: int, value_codec: ValueCodecV3) -> None:
        self.artifact_kind = artifact_kind
        self.bucket = bucket
        self.part = part
        self.lines: list[bytes] = []
        self.body_size = 0
        self.record_ids: list[str] = []
        self.expression_ids: set[str] = set()
        self.value_ids: set[str] = set()
        self.value_node_ids: set[str] = set()
        self.value_codec = value_codec
        self._pending: tuple[str, list[bytes], set[str]] | None = None

    def _new_lines(self, record: ArtifactRecordV3) -> tuple[list[bytes], set[str]]:
        lines: list[bytes] = []
        value_node_ids: set[str] = set()
        for expression in record.expressions:
            if expression.expression_id not in self.expression_ids:
                lines.append(canonical_json_bytes_v3({
                    "entry": "expression",
                    "id": expression.expression_id,
                    "value": expression.value.to_value(),
                }) + b"\n")
        value_id = _record_value_id(record)
        if value_id not in self.value_ids:
            encoded = self.value_codec.encode(record.value)
            for node_id, node in encoded.nodes:
                if node_id not in self.value_node_ids:
                    value_node_ids.add(node_id)
                    lines.append(canonical_json_bytes_v3({
                        "entry": "value_node",
                        "id": node_id,
                        "encoded": node,
                    }) + b"\n")
            lines.append(canonical_json_bytes_v3({
                "entry": "record_value",
                "id": value_id,
                "value": encoded.root,
                "expression_ids": [row.expression_id for row in record.expressions],
                "dependencies": [row.to_payload() for row in record.dependencies],
            }) + b"\n")
        lines.append(canonical_json_bytes_v3({
            "entry": "record",
            "id": record.record_id,
            "value_id": value_id,
        }) + b"\n")
        return lines, value_node_ids

    def can_add(self, record: ArtifactRecordV3, maximum: int) -> bool:
        additions, value_node_ids = self._new_lines(record)
        self._pending = (record.record_id, additions, value_node_ids)
        ids = [*self.record_ids, record.record_id]
        return len(_pack_header(self.artifact_kind, self.bucket, self.part, ids)) + self.body_size + sum(map(len, additions)) <= maximum

    def add(self, record: ArtifactRecordV3) -> None:
        if self._pending is not None and self._pending[0] == record.record_id:
            _, additions, value_node_ids = self._pending
        else:
            additions, value_node_ids = self._new_lines(record)
        self._pending = None
        self.lines.extend(additions)
        self.body_size += sum(map(len, additions))
        self.record_ids.append(record.record_id)
        self.expression_ids.update(row.expression_id for row in record.expressions)
        self.value_ids.add(_record_value_id(record))
        self.value_node_ids.update(value_node_ids)

    def flush(self, directory: Path, maximum: int) -> ArtifactPackV3:
        decoded = _pack_header(
            self.artifact_kind, self.bucket, self.part, self.record_ids
        ) + b"".join(self.lines)
        if len(decoded) > maximum:
            _fail(
                "oversized_pack",
                f"decoded pack {self.bucket:02d}-{self.part:04d} is {len(decoded)} bytes",
                "reduce record size or the number of records assigned to a pack",
            )
        buffer = io.BytesIO()
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=6, mtime=0, fileobj=buffer
        ) as compressed_stream:
            compressed_stream.write(decoded)
        data = buffer.getvalue()
        if len(data) > maximum:
            _fail(
                "oversized_pack",
                f"compressed pack {self.bucket:02d}-{self.part:04d} is {len(data)} bytes",
                "lower the decoded pack budget or split unusually incompressible records",
            )
        relative = f"packs/{self.bucket:02d}-{self.part:04d}.ndjson.gz"
        (directory / Path(relative).name).write_bytes(data)
        return ArtifactPackV3(
            bucket=self.bucket,
            part=self.part,
            path=relative,
            record_count=len(self.record_ids),
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            decoded_size_bytes=len(decoded),
            decoded_sha256=hashlib.sha256(decoded).hexdigest(),
            first_record_id=self.record_ids[0],
            last_record_id=self.record_ids[-1],
        )
