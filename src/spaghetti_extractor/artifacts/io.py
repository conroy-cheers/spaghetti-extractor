"""Checked artifact readers and zero-copy bundles."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import shutil
import tempfile
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias

from .artifact_set import (
    ARTIFACT_BUNDLE_V3_FORMAT,
    ARTIFACT_PACK_V3_FORMAT,
    ARTIFACT_SET_V3_FORMAT,
    MAX_ARTIFACT_BUNDLE_INVENTORY_BYTES,
    MAX_ARTIFACT_BUNDLE_MANIFEST_BYTES,
    MAX_PACK_BYTES,
    MAX_READER_PACK_CACHE_BYTES,
    SCHEMA_VERSION,
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactPackV3,
    ArtifactRecordV3,
    ArtifactSetManifestV3,
    CanonicalValueV3,
    InternedExpressionV3,
    JsonValue,
    RecordDependencyV3,
    _STATUSES,
    _canonical_tuple,
    _digest,
    _fail,
    _name,
    _record_value_id,
    _strict_object,
    _strict_sequence,
    _text,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    identity_bucket_v3,
    parse_canonical_json_v3,
    parse_canonical_json_lines_v3,
    value_codec_v3,
)


class ArtifactSetReaderV3:
    """Validate and stream a v3 artifact without materializing all payloads."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._pack_cache: OrderedDict[
            str,
            tuple[
                int,
                tuple[int, int, int, int],
                tuple[ArtifactRecordV3, ...],
                dict[str, ArtifactRecordV3],
            ],
        ] = OrderedDict()
        self._pack_cache_bytes = 0
        manifest_path = self._root / "manifest.json"
        try:
            data = manifest_path.read_bytes()
        except OSError as exc:
            _fail(
                "missing_manifest",
                f"cannot read {manifest_path}: {exc}",
                "provide an artifact-set-v3 output directory",
            )
        self.manifest = ArtifactSetManifestV3.parse_bytes(
            data, location=str(manifest_path)
        )
        self._value_codec = value_codec_v3(self.manifest.value_codec)
        self._validate_layout()

    @property
    def manifest_sha256(self) -> str:
        return self.manifest.manifest_sha256

    def dependency_binding(self, name: str) -> ArtifactDependencyV3:
        return ArtifactDependencyV3(
            name=name,
            artifact_kind=self.manifest.artifact_kind,
            artifact_id=self.manifest.artifact_id,
            manifest_sha256=self.manifest_sha256,
        )

    def _validate_layout(self) -> None:
        expected = {"manifest.json", *(row.path for row in self.manifest.packs)}
        observed = {
            path.relative_to(self._root).as_posix()
            for path in self._root.rglob("*")
            if path.is_file()
        }
        if observed != expected:
            _fail(
                "artifact_layout_mismatch",
                f"artifact files differ: missing={sorted(expected - observed)!r}, extra={sorted(observed - expected)!r}",
                "regenerate into a fresh output directory and do not add sidecar files inside the artifact set",
                location=str(self._root),
            )

    def iter_records(self) -> Iterator[ArtifactRecordV3]:
        seen: set[str] = set()
        count = 0
        for pack in self.manifest.packs:
            for record in self._iter_pack(pack):
                if record.record_id in seen:
                    _fail(
                        "duplicate_record_id",
                        f"record {record.record_id!r} appears in multiple packs",
                        "regenerate the artifact with one authoritative record per ID",
                    )
                seen.add(record.record_id)
                count += 1
                yield record
        if count != self.manifest.record_count:
            _fail(
                "record_count_mismatch",
                f"stream yielded {count} records but manifest declares {self.manifest.record_count}",
                "regenerate the manifest and packs together",
            )

    def _load_pack(
        self, descriptor: ArtifactPackV3
    ) -> tuple[tuple[ArtifactRecordV3, ...], dict[str, ArtifactRecordV3]]:
        path = self._root / descriptor.path
        fingerprint = self._pack_fingerprint(path)
        cached = self._pack_cache.get(descriptor.path)
        if cached is not None:
            if cached[1] != fingerprint:
                _fail(
                    "artifact_changed_during_read",
                    f"pack {descriptor.path!r} changed after it was checked",
                    "use immutable content-addressed phase inputs",
                    location=str(path),
                )
            self._pack_cache.move_to_end(descriptor.path)
            return cached[2], cached[3]
        records = tuple(self._decode_pack(descriptor))
        if self._pack_fingerprint(path) != fingerprint:
            _fail(
                "artifact_changed_during_read",
                f"pack {descriptor.path!r} changed while it was checked",
                "use immutable content-addressed phase inputs",
                location=str(path),
            )
        by_id = {record.record_id: record for record in records}
        if len(by_id) != len(records):
            _fail(
                "duplicate_record_id",
                f"pack {descriptor.path!r} contains duplicate record IDs",
                "discard the artifact and rebuild the producing CA derivation",
                location=str(self._root / descriptor.path),
            )
        cache_bytes = descriptor.decoded_size_bytes
        while (
            self._pack_cache
            and self._pack_cache_bytes + cache_bytes > MAX_READER_PACK_CACHE_BYTES
        ):
            _path, (evicted_bytes, _fingerprint, _records, _index) = (
                self._pack_cache.popitem(last=False)
            )
            self._pack_cache_bytes -= evicted_bytes
        if cache_bytes <= MAX_READER_PACK_CACHE_BYTES:
            self._pack_cache[descriptor.path] = (
                cache_bytes,
                fingerprint,
                records,
                by_id,
            )
            self._pack_cache_bytes += cache_bytes
        return records, by_id

    @staticmethod
    def _pack_fingerprint(path: Path) -> tuple[int, int, int, int]:
        try:
            stat = path.stat()
        except OSError as exc:
            _fail(
                "missing_pack",
                f"cannot stat checked pack: {exc}",
                "discard the artifact and rebuild the producing CA derivation",
                location=str(path),
            )
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def _iter_pack(self, descriptor: ArtifactPackV3) -> Iterator[ArtifactRecordV3]:
        records, _by_id = self._load_pack(descriptor)
        yield from records

    def _decode_pack(self, descriptor: ArtifactPackV3) -> Iterator[ArtifactRecordV3]:
        path = self._root / descriptor.path
        with path.open("rb") as source:
            compressed = source.read(self.manifest.max_pack_bytes + 1)
            trailing = source.read(1)
        size = len(compressed)
        if (
            trailing
            or size != descriptor.size_bytes
            or hashlib.sha256(compressed).hexdigest() != descriptor.sha256
        ):
            _fail(
                "corrupt_pack",
                f"pack bytes do not match descriptor size/hash",
                "discard the artifact and rebuild the producing CA derivation",
                location=str(path),
            )
        if size > self.manifest.max_pack_bytes:
            _fail(
                "oversized_pack",
                f"pack is {size} bytes, above {self.manifest.max_pack_bytes}",
                "repack it through ArtifactSetWriterV3",
                location=str(path),
            )
        decoded = bytearray()
        try:
            with gzip.GzipFile(
                fileobj=io.BytesIO(compressed), mode="rb"
            ) as decoded_source:
                while chunk := decoded_source.read(1024 * 1024):
                    decoded.extend(chunk)
                    if len(decoded) > self.manifest.max_pack_bytes:
                        _fail(
                            "oversized_decoded_pack",
                            "decoded NDJSON exceeds the bounded pack limit",
                            "discard the artifact and rebuild it with bounded v3 packs",
                            location=str(path),
                        )
        except (gzip.BadGzipFile, EOFError, OSError) as exc:
            _fail(
                "corrupt_decoded_pack",
                f"pack cannot be decompressed: {exc}",
                "discard the artifact and rebuild the producing CA derivation",
                location=str(path),
            )
        decoded_bytes = bytes(decoded)
        decoded_size = len(decoded_bytes)
        if (
            decoded_size != descriptor.decoded_size_bytes
            or hashlib.sha256(decoded_bytes).hexdigest() != descriptor.decoded_sha256
            or decoded_size > self.manifest.max_pack_bytes
        ):
            _fail(
                "corrupt_decoded_pack",
                "decoded NDJSON does not match its bounded manifest identity",
                "discard the artifact and rebuild the producing CA derivation",
                location=str(path),
            )
        expressions: dict[str, InternedExpressionV3] = {}
        value_nodes: dict[str, JsonValue] = {}
        values: dict[
            str, tuple[JsonValue, tuple[str, ...], tuple[RecordDependencyV3, ...]]
        ] = {}
        used_expressions: set[str] = set()
        used_values: set[str] = set()
        used_value_nodes: set[str] = set()
        record_ids: list[str] = []
        rows = parse_canonical_json_lines_v3(
            decoded_bytes,
            location=str(path),
            maximum_line_bytes=self.manifest.max_pack_bytes,
        )
        if not rows:
            _fail(
                "empty_pack",
                "pack has no header",
                "regenerate the pack",
                location=str(path),
            )
        header_row = _strict_object(
            rows[0],
            {
                "entry",
                "format",
                "schema_version",
                "artifact_kind",
                "bucket",
                "part",
                "record_count",
                "first_record_id",
                "last_record_id",
            },
            "pack header",
        )
        if header_row != {
            "entry": "header",
            "format": ARTIFACT_PACK_V3_FORMAT,
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": self.manifest.artifact_kind,
            "bucket": descriptor.bucket,
            "part": descriptor.part,
            "record_count": descriptor.record_count,
            "first_record_id": descriptor.first_record_id,
            "last_record_id": descriptor.last_record_id,
        }:
            _fail(
                "pack_header_mismatch",
                "pack header contradicts its manifest descriptor",
                "discard the artifact and rebuild it",
                location=f"{path}:1",
            )
        for line_number, row in enumerate(rows[1:], 2):
            if not isinstance(row, Mapping):
                _fail(
                    "invalid_pack_entry",
                    "NDJSON entry is not an object",
                    "regenerate the pack",
                    location=f"{path}:{line_number}",
                )
            entry = row.get("entry")
            if entry == "expression":
                parsed = _strict_object(
                    row, {"entry", "id", "value"}, "expression entry"
                )
                expression = InternedExpressionV3(
                    str(parsed["id"]), CanonicalValueV3.of(parsed["value"])
                )
                if expression.expression_id in expressions:
                    _fail(
                        "duplicate_expression",
                        f"expression {expression.expression_id!r} is repeated",
                        "emit each interned value once per pack",
                        location=f"{path}:{line_number}",
                    )
                expressions[expression.expression_id] = expression
            elif entry == "value_node":
                parsed = _strict_object(
                    row, {"entry", "id", "encoded"}, "recursive value node entry"
                )
                node_id = str(parsed["id"])
                if not node_id.startswith("value-node:") or node_id in value_nodes:
                    _fail(
                        "duplicate_value_node",
                        f"recursive value node {node_id!r} is invalid or repeated",
                        "emit each codec node exactly once per pack",
                        location=f"{path}:{line_number}",
                    )
                # parse_canonical_json_v3 has already established that the
                # complete line is an exact JsonValue.  Retain that checked
                # tree instead of recursively copying it once more.
                value_nodes[node_id] = parsed["encoded"]
            elif entry == "record_value":
                parsed = _strict_object(
                    row,
                    {"entry", "id", "value", "expression_ids", "dependencies"},
                    "record value entry",
                )
                expression_ids = _canonical_tuple(
                    (
                        str(item)
                        for item in _strict_sequence(
                            parsed["expression_ids"], "expression IDs"
                        )
                    ),
                    "expression IDs",
                )
                dependencies = tuple(
                    RecordDependencyV3.parse(item)
                    for item in _strict_sequence(
                        parsed["dependencies"], "record dependencies"
                    )
                )
                missing_expressions = sorted(set(expression_ids) - set(expressions))
                if missing_expressions:
                    _fail(
                        "undefined_expression",
                        "record value refers to an expression not yet defined",
                        "place intern definitions before their first use",
                        location=f"{path}:{line_number}",
                    )
                value_id = str(parsed["id"])
                if not value_id.startswith("record-value:") or value_id in values:
                    _fail(
                        "stale_record_value",
                        "record value identity is malformed or duplicated",
                        "regenerate the pack",
                        location=f"{path}:{line_number}",
                    )
                values[value_id] = (
                    parsed["value"],
                    expression_ids,
                    dependencies,
                )
            elif entry == "record":
                parsed = _strict_object(
                    row, {"entry", "id", "value_id"}, "record entry"
                )
                record_id = str(parsed["id"])
                value_id = str(parsed["value_id"])
                if value_id not in values:
                    _fail(
                        "undefined_record_value",
                        f"record {record_id!r} refers to unknown {value_id!r}",
                        "place record values before their first use",
                        location=f"{path}:{line_number}",
                    )
                if identity_bucket_v3(record_id) != descriptor.bucket:
                    _fail(
                        "wrong_record_bucket",
                        f"record {record_id!r} is in the wrong bucket",
                        "use identity_bucket_v3 through ArtifactSetWriterV3",
                        location=f"{path}:{line_number}",
                    )
                encoded_value, expression_ids, dependencies = values[value_id]
                value = self._value_codec.decode(
                    encoded_value, value_nodes, used_nodes=used_value_nodes
                )
                record = ArtifactRecordV3(
                    record_id,
                    value,
                    dependencies,
                    tuple(expressions[item] for item in expression_ids),
                )
                if _record_value_id(record) != value_id:
                    _fail(
                        "stale_record_value",
                        f"record value {value_id!r} does not bind its decoded content",
                        "discard and rebuild the artifact",
                        location=f"{path}:{line_number}",
                    )
                record_ids.append(record_id)
                used_values.add(value_id)
                used_expressions.update(expression_ids)
                yield record
            else:
                _fail(
                    "invalid_pack_entry",
                    f"unknown NDJSON entry kind {entry!r}",
                    "regenerate the pack with the v3 writer",
                    location=f"{path}:{line_number}",
                )
        if record_ids != sorted(record_ids) or len(set(record_ids)) != len(record_ids):
            _fail(
                "noncanonical_record_order",
                "pack records are duplicated or unsorted",
                "regenerate the pack with the v3 writer",
                location=str(path),
            )
        if (
            len(record_ids) != descriptor.record_count
            or record_ids[:1] != [descriptor.first_record_id]
            or record_ids[-1:] != [descriptor.last_record_id]
        ):
            _fail(
                "pack_inventory_mismatch",
                "pack records contradict its descriptor",
                "regenerate the artifact set",
                location=str(path),
            )
        if (
            used_values != set(values)
            or used_expressions != set(expressions)
            or used_value_nodes != set(value_nodes)
        ):
            _fail(
                "unused_interned_value",
                "pack contains unused interned values",
                "emit only values referenced by records in that pack",
                location=str(path),
            )

    @staticmethod
    def _read_line(source: Any, path: Path, line_number: int) -> bytes:
        raw = source.readline(MAX_PACK_BYTES + 1)
        if not raw:
            _fail(
                "empty_pack",
                "pack has no header",
                "regenerate the pack",
                location=str(path),
            )
        return ArtifactSetReaderV3._strip_newline(raw, path, line_number)

    @staticmethod
    def _strip_newline(raw: bytes, path: Path, line_number: int) -> bytes:
        if not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
            _fail(
                "noncanonical_ndjson",
                "pack line does not end in one LF",
                "write packs with ArtifactSetWriterV3",
                location=f"{path}:{line_number}",
            )
        return raw[:-1]

    def find_record(self, record_id: str) -> ArtifactRecordV3 | None:
        bucket = identity_bucket_v3(record_id)
        for pack in self.manifest.packs:
            if (
                pack.bucket != bucket
                or not pack.first_record_id <= record_id <= pack.last_record_id
            ):
                continue
            _records, by_id = self._load_pack(pack)
            record = by_id.get(record_id)
            if record is not None:
                return record
        return None

    def get_record(self, record_id: str) -> ArtifactRecordV3:
        record = self.find_record(record_id)
        if record is not None:
            return record
        _fail(
            "missing_record",
            f"artifact {self.manifest.artifact_id} has no record {record_id!r}",
            "fix the scheduling reference or regenerate the upstream artifact",
        )

    def validate_completeness(
        self,
        expected_record_ids: Iterable[str],
        *,
        dependency_record_exists: Callable[[RecordDependencyV3], bool] | None = None,
    ) -> None:
        expected = set(expected_record_ids)
        observed: set[str] = set()
        for record in self.iter_records():
            observed.add(record.record_id)
            if dependency_record_exists is not None:
                for dependency in record.dependencies:
                    if not dependency_record_exists(dependency):
                        _fail(
                            "missing_dependency_record",
                            f"record {record.record_id!r} depends on absent {dependency.input_name}#{dependency.record_id}",
                            "repair the planner or bind the exact upstream record",
                        )
        if expected != observed:
            _fail(
                "planner_omission",
                f"artifact coverage differs: missing={sorted(expected - observed)!r}, unexpected={sorted(observed - expected)!r}",
                "regenerate the scheduling plan from the independently checked structural universe",
            )


@dataclass(frozen=True, order=True)
class ArtifactBundleMemberV3:
    path: str
    artifact_kind: str
    artifact_id: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"members/[0-9]{4}", self.path) is None:
            _fail(
                "invalid_bundle_member_path",
                f"bundle member path {self.path!r} is not canonical",
                "let write_artifact_bundle_v3 assign member paths",
            )
        _name(self.artifact_kind, "bundle member artifact kind")
        _text(self.artifact_id, "bundle member artifact ID")
        _digest(self.manifest_sha256, "bundle member manifest SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "path": self.path,
            "artifact_kind": self.artifact_kind,
            "artifact_id": self.artifact_id,
            "manifest_sha256": self.manifest_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "ArtifactBundleMemberV3":
        row = _strict_object(
            value,
            {"path", "artifact_kind", "artifact_id", "manifest_sha256"},
            "artifact bundle member",
        )
        return cls(
            path=str(row["path"]),
            artifact_kind=str(row["artifact_kind"]),
            artifact_id=str(row["artifact_id"]),
            manifest_sha256=str(row["manifest_sha256"]),
        )


@dataclass(frozen=True)
class ArtifactBundleManifestV3:
    artifact_kind: str
    artifact_id: str
    status: str
    bindings: tuple[ArtifactBindingV3, ...]
    members: tuple[ArtifactBundleMemberV3, ...]
    record_count: int
    inventory_path: str
    inventory_size_bytes: int
    inventory_sha256: str
    inventory_decoded_size_bytes: int
    inventory_decoded_sha256: str

    def __post_init__(self) -> None:
        _name(self.artifact_kind, "artifact bundle kind")
        if self.status not in _STATUSES:
            _fail(
                "invalid_status",
                f"artifact bundle status {self.status!r} is not fail-closed",
                "use complete, incomplete, or violated",
            )
        if self.bindings != tuple(sorted(set(self.bindings))):
            _fail(
                "noncanonical_bindings",
                "artifact bundle bindings are duplicated or unsorted",
                "let write_artifact_bundle_v3 construct the bundle",
            )
        if not self.members or self.members != tuple(sorted(self.members)):
            _fail(
                "noncanonical_bundle_members",
                "artifact bundle members are empty, duplicated, or unsorted",
                "let write_artifact_bundle_v3 construct the bundle",
            )
        if len({row.artifact_id for row in self.members}) != len(self.members):
            _fail(
                "duplicate_bundle_member",
                "artifact bundle repeats a member artifact identity",
                "deduplicate shard descriptors before bundling",
            )
        if any(row.artifact_kind != self.artifact_kind for row in self.members):
            _fail(
                "bundle_kind_mismatch",
                "artifact bundle members have different kinds",
                "bundle only shards from one declared artifact family",
            )
        if self.record_count < 0:
            _fail(
                "invalid_record_count",
                "artifact bundle record count is negative",
                "regenerate the bundle inventory",
            )
        if self.inventory_path != "record-ids.json.gz":
            _fail(
                "invalid_bundle_inventory_path",
                f"artifact bundle inventory path is {self.inventory_path!r}",
                "use the canonical record-ids.json.gz path",
            )
        for size, label in (
            (self.inventory_size_bytes, "compressed"),
            (self.inventory_decoded_size_bytes, "decoded"),
        ):
            if not 0 < size <= MAX_ARTIFACT_BUNDLE_INVENTORY_BYTES:
                _fail(
                    "oversized_bundle_inventory",
                    f"{label} bundle inventory size is {size}",
                    "partition the scheduling bundle into smaller dependency packs",
                )
        _digest(self.inventory_sha256, "bundle inventory SHA-256")
        _digest(self.inventory_decoded_sha256, "decoded bundle inventory SHA-256")
        expected_id = "artifact-bundle-v3:" + canonical_sha256_v3(
            self.identity_payload()
        )
        if self.artifact_id != expected_id:
            _fail(
                "stale_artifact_id",
                "artifact bundle ID does not bind its member inventory",
                "regenerate the bundle instead of editing its manifest",
            )

    @property
    def dependencies(self) -> tuple[ArtifactDependencyV3, ...]:
        return ()

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def identity_payload(self) -> dict[str, JsonValue]:
        return {
            "format": ARTIFACT_BUNDLE_V3_FORMAT,
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": self.artifact_kind,
            "status": self.status,
            "bindings": [row.to_payload() for row in self.bindings],
            "members": [row.to_payload() for row in self.members],
            "record_count": self.record_count,
            "inventory_path": self.inventory_path,
            "inventory_size_bytes": self.inventory_size_bytes,
            "inventory_sha256": self.inventory_sha256,
            "inventory_decoded_size_bytes": self.inventory_decoded_size_bytes,
            "inventory_decoded_sha256": self.inventory_decoded_sha256,
        }

    def to_payload(self) -> dict[str, JsonValue]:
        return {**self.identity_payload(), "artifact_id": self.artifact_id}

    def to_bytes(self) -> bytes:
        data = canonical_json_bytes_v3(self.to_payload())
        if len(data) > MAX_ARTIFACT_BUNDLE_MANIFEST_BYTES:
            _fail(
                "oversized_bundle_manifest",
                f"artifact bundle manifest is {len(data)} bytes",
                "partition the bundle instead of embedding record data",
            )
        return data

    @classmethod
    def create(
        cls,
        *,
        artifact_kind: str,
        status: str,
        bindings: Iterable[ArtifactBindingV3],
        members: Iterable[ArtifactBundleMemberV3],
        record_count: int,
        inventory_size_bytes: int,
        inventory_sha256: str,
        inventory_decoded_size_bytes: int,
        inventory_decoded_sha256: str,
    ) -> "ArtifactBundleManifestV3":
        ordered_bindings = tuple(sorted(set(bindings)))
        ordered_members = tuple(sorted(set(members)))
        core: dict[str, JsonValue] = {
            "format": ARTIFACT_BUNDLE_V3_FORMAT,
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": artifact_kind,
            "status": status,
            "bindings": [row.to_payload() for row in ordered_bindings],
            "members": [row.to_payload() for row in ordered_members],
            "record_count": record_count,
            "inventory_path": "record-ids.json.gz",
            "inventory_size_bytes": inventory_size_bytes,
            "inventory_sha256": inventory_sha256,
            "inventory_decoded_size_bytes": inventory_decoded_size_bytes,
            "inventory_decoded_sha256": inventory_decoded_sha256,
        }
        return cls(
            artifact_kind=artifact_kind,
            artifact_id="artifact-bundle-v3:" + canonical_sha256_v3(core),
            status=status,
            bindings=ordered_bindings,
            members=ordered_members,
            record_count=record_count,
            inventory_path="record-ids.json.gz",
            inventory_size_bytes=inventory_size_bytes,
            inventory_sha256=inventory_sha256,
            inventory_decoded_size_bytes=inventory_decoded_size_bytes,
            inventory_decoded_sha256=inventory_decoded_sha256,
        )

    @classmethod
    def parse_bytes(
        cls, data: bytes, *, location: str = "manifest.json"
    ) -> "ArtifactBundleManifestV3":
        if len(data) > MAX_ARTIFACT_BUNDLE_MANIFEST_BYTES:
            _fail(
                "oversized_bundle_manifest",
                f"artifact bundle manifest is {len(data)} bytes",
                "regenerate a compact bundle manifest",
                location=location,
            )
        fields = {
            "format",
            "schema_version",
            "artifact_kind",
            "artifact_id",
            "status",
            "bindings",
            "members",
            "record_count",
            "inventory_path",
            "inventory_size_bytes",
            "inventory_sha256",
            "inventory_decoded_size_bytes",
            "inventory_decoded_sha256",
        }
        row = _strict_object(
            parse_canonical_json_v3(data, location=location),
            fields,
            "artifact bundle manifest",
        )
        if (
            row["format"] != ARTIFACT_BUNDLE_V3_FORMAT
            or row["schema_version"] != SCHEMA_VERSION
        ):
            _fail(
                "wrong_artifact_format",
                "document is not an artifact-bundle-v3 manifest",
                "provide the matching v3 bundle directory",
                location=location,
            )
        return cls(
            artifact_kind=str(row["artifact_kind"]),
            artifact_id=str(row["artifact_id"]),
            status=str(row["status"]),
            bindings=tuple(
                ArtifactBindingV3.parse(item)
                for item in _strict_sequence(row["bindings"], "bundle bindings")
            ),
            members=tuple(
                ArtifactBundleMemberV3.parse(item)
                for item in _strict_sequence(row["members"], "bundle members")
            ),
            record_count=int(row["record_count"]),
            inventory_path=str(row["inventory_path"]),
            inventory_size_bytes=int(row["inventory_size_bytes"]),
            inventory_sha256=str(row["inventory_sha256"]),
            inventory_decoded_size_bytes=int(row["inventory_decoded_size_bytes"]),
            inventory_decoded_sha256=str(row["inventory_decoded_sha256"]),
        )


class ArtifactBundleReaderV3:
    """A checked zero-copy view over selected records in artifact shards."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        manifest_path = self._root / "manifest.json"
        try:
            data = manifest_path.read_bytes()
        except OSError as exc:
            _fail(
                "missing_manifest",
                f"cannot read {manifest_path}: {exc}",
                "provide an artifact-bundle-v3 output directory",
            )
        self.manifest = ArtifactBundleManifestV3.parse_bytes(
            data, location=str(manifest_path)
        )
        self._record_ids = self._read_inventory()
        self._record_id_set = frozenset(self._record_ids)
        self._members = tuple(
            ArtifactSetReaderV3(self._root / member.path)
            for member in self.manifest.members
        )
        for descriptor, reader in zip(
            self.manifest.members, self._members, strict=True
        ):
            if (
                reader.manifest.artifact_kind != descriptor.artifact_kind
                or reader.manifest.artifact_id != descriptor.artifact_id
                or reader.manifest_sha256 != descriptor.manifest_sha256
            ):
                _fail(
                    "bundle_member_mismatch",
                    f"bundle member {descriptor.path!r} differs from its manifest binding",
                    "rebuild the bundle from the exact content-addressed member artifacts",
                )
            if reader.manifest.status != self.manifest.status:
                _fail(
                    "bundle_status_mismatch",
                    f"bundle member {descriptor.path!r} has status {reader.manifest.status!r}",
                    "bundle only shards with the same fail-closed status",
                )
            if reader.manifest.bindings != self.manifest.bindings:
                _fail(
                    "bundle_binding_mismatch",
                    f"bundle member {descriptor.path!r} has different semantic bindings",
                    "bundle only shards for the same binary and environment profile",
                )
        expected_layout = {"manifest.json", "record-ids.json.gz", "members"}
        if {path.name for path in self._root.iterdir()} != expected_layout:
            _fail(
                "artifact_layout_mismatch",
                "artifact bundle has missing or unexpected top-level entries",
                "rebuild it with write_artifact_bundle_v3",
                location=str(self._root),
            )
        member_entries = sorted((self._root / "members").iterdir())
        if [f"members/{path.name}" for path in member_entries] != [
            row.path for row in self.manifest.members
        ]:
            _fail(
                "artifact_layout_mismatch",
                "artifact bundle member paths differ from its manifest",
                "rebuild it with write_artifact_bundle_v3",
                location=str(self._root),
            )

    @property
    def manifest_sha256(self) -> str:
        return self.manifest.manifest_sha256

    def dependency_binding(self, name: str) -> ArtifactDependencyV3:
        return ArtifactDependencyV3(
            name=name,
            artifact_kind=self.manifest.artifact_kind,
            artifact_id=self.manifest.artifact_id,
            manifest_sha256=self.manifest_sha256,
        )

    def _read_inventory(self) -> tuple[str, ...]:
        path = self._root / self.manifest.inventory_path
        try:
            compressed = path.read_bytes()
        except OSError as exc:
            _fail(
                "missing_bundle_inventory",
                f"cannot read {path}: {exc}",
                "rebuild the content-addressed bundle",
            )
        if (
            len(compressed) != self.manifest.inventory_size_bytes
            or hashlib.sha256(compressed).hexdigest() != self.manifest.inventory_sha256
        ):
            _fail(
                "corrupt_bundle_inventory",
                "compressed bundle inventory does not match its manifest",
                "discard and rebuild the content-addressed bundle",
                location=str(path),
            )
        try:
            decoded = gzip.decompress(compressed)
        except gzip.BadGzipFile as exc:
            _fail(
                "corrupt_bundle_inventory",
                f"bundle inventory is not deterministic gzip: {exc}",
                "discard and rebuild the content-addressed bundle",
                location=str(path),
            )
        if (
            len(decoded) != self.manifest.inventory_decoded_size_bytes
            or hashlib.sha256(decoded).hexdigest()
            != self.manifest.inventory_decoded_sha256
        ):
            _fail(
                "corrupt_bundle_inventory",
                "decoded bundle inventory does not match its manifest",
                "discard and rebuild the content-addressed bundle",
                location=str(path),
            )
        values = parse_canonical_json_v3(decoded, location=str(path))
        record_ids = tuple(
            str(item) for item in _strict_sequence(values, "bundle record IDs")
        )
        if (
            record_ids != tuple(sorted(set(record_ids)))
            or len(record_ids) != self.manifest.record_count
        ):
            _fail(
                "noncanonical_bundle_inventory",
                "bundle record inventory is duplicated, unsorted, or has a stale count",
                "regenerate it from the exact scheduling selection",
                location=str(path),
            )
        return record_ids

    def iter_records(self) -> Iterator[ArtifactRecordV3]:
        observed: set[str] = set()
        for member in self._members:
            for record in member.iter_records():
                if record.record_id not in self._record_id_set:
                    continue
                if record.record_id in observed:
                    _fail(
                        "duplicate_bundle_record",
                        f"bundle record {record.record_id!r} occurs in multiple members",
                        "use disjoint source shards or select one authoritative producer",
                    )
                observed.add(record.record_id)
                yield record
        if observed != self._record_id_set:
            _fail(
                "planner_omission",
                f"bundle coverage differs: missing={sorted(self._record_id_set - observed)!r}",
                "repair the shard selection or regenerate the affected phase",
            )

    def find_record(self, record_id: str) -> ArtifactRecordV3 | None:
        if record_id not in self._record_id_set:
            return None
        found: ArtifactRecordV3 | None = None
        for member in self._members:
            record = member.find_record(record_id)
            if record is None:
                continue
            if found is not None:
                _fail(
                    "duplicate_bundle_record",
                    f"bundle record {record_id!r} occurs in multiple members",
                    "use disjoint source shards or select one authoritative producer",
                )
            found = record
        if found is None:
            _fail(
                "planner_omission",
                f"bundle selected absent record {record_id!r}",
                "repair the shard selection or regenerate the affected phase",
            )
        return found

    def get_record(self, record_id: str) -> ArtifactRecordV3:
        record = self.find_record(record_id)
        if record is not None:
            return record
        _fail(
            "missing_record",
            f"artifact bundle has no selected record {record_id!r}",
            "fix the scheduling reference or select the exact upstream record",
        )

    def validate_completeness(
        self,
        expected_record_ids: Iterable[str],
        *,
        dependency_record_exists: Callable[[RecordDependencyV3], bool] | None = None,
    ) -> None:
        expected = tuple(sorted(set(expected_record_ids)))
        if expected != self._record_ids:
            _fail(
                "planner_omission",
                "bundle selection differs from the independently expected inventory",
                "regenerate the affected scheduling bundle",
            )
        for record in self.iter_records():
            if dependency_record_exists is not None:
                for dependency in record.dependencies:
                    if not dependency_record_exists(dependency):
                        _fail(
                            "missing_dependency_record",
                            f"record {record.record_id!r} depends on absent {dependency.input_name}#{dependency.record_id}",
                            "repair the planner or bind the exact upstream record",
                        )


ArtifactInputManifestV3: TypeAlias = ArtifactSetManifestV3 | ArtifactBundleManifestV3
ArtifactInputReaderV3: TypeAlias = ArtifactSetReaderV3 | ArtifactBundleReaderV3


def open_artifact_reader_v3(root: Path | str) -> ArtifactInputReaderV3:
    manifest_path = Path(root) / "manifest.json"
    try:
        data = manifest_path.read_bytes()
    except OSError as exc:
        _fail(
            "missing_manifest",
            f"cannot read {manifest_path}: {exc}",
            "provide an artifact-set-v3 or artifact-bundle-v3 directory",
        )
    payload = parse_canonical_json_v3(data, location=str(manifest_path))
    if not isinstance(payload, Mapping):
        _fail(
            "invalid_artifact_manifest",
            "artifact manifest is not an object",
            "regenerate it with the v3 artifact framework",
        )
    if payload.get("format") == ARTIFACT_SET_V3_FORMAT:
        return ArtifactSetReaderV3(root)
    if payload.get("format") == ARTIFACT_BUNDLE_V3_FORMAT:
        return ArtifactBundleReaderV3(root)
    _fail(
        "wrong_artifact_format",
        f"unsupported artifact input format {payload.get('format')!r}",
        "provide an artifact-set-v3 or artifact-bundle-v3 directory",
    )


def write_artifact_bundle_v3(
    output_directory: Path | str,
    member_paths: Iterable[Path | str],
    expected_record_ids: Iterable[str],
    *,
    expected_kind: str,
) -> ArtifactBundleManifestV3:
    """Write a canonical zero-copy selection over checked artifact sets."""

    selected_ids = tuple(sorted(set(expected_record_ids)))
    raw_members: dict[tuple[str, str], tuple[Path, ArtifactSetReaderV3]] = {}
    for raw_path in member_paths:
        path = Path(raw_path)
        reader = ArtifactSetReaderV3(path)
        key = (reader.manifest.artifact_id, reader.manifest_sha256)
        raw_members.setdefault(key, (path, reader))
    if not raw_members:
        _fail(
            "empty_artifact_bundle",
            "artifact bundle has no member shards",
            "select at least one checked source shard",
        )
    ordered = tuple(raw_members[key] for key in sorted(raw_members))
    prototype = ordered[0][1].manifest
    if prototype.artifact_kind != expected_kind:
        _fail(
            "bundle_kind_mismatch",
            f"artifact bundle expected {expected_kind!r}, observed {prototype.artifact_kind!r}",
            "connect the artifact family declared by the phase graph",
        )
    for _path, reader in ordered[1:]:
        if reader.manifest.artifact_kind != prototype.artifact_kind:
            _fail(
                "bundle_kind_mismatch",
                "artifact bundle mixes artifact kinds",
                "bundle only shards from one declared artifact family",
            )
        if reader.manifest.status != prototype.status:
            _fail(
                "bundle_status_mismatch",
                "artifact bundle mixes fail-closed statuses",
                "partition complete, incomplete, and violated artifacts",
            )
        if reader.manifest.bindings != prototype.bindings:
            _fail(
                "bundle_binding_mismatch",
                "artifact bundle mixes semantic bindings",
                "bundle only shards for the same binary and environment profile",
            )

    destination = Path(output_directory)
    if destination.exists():
        _fail(
            "output_exists",
            f"artifact bundle output {destination} already exists",
            "choose a fresh output path",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    try:
        members_directory = staging / "members"
        members_directory.mkdir()
        members: list[ArtifactBundleMemberV3] = []
        for index, (path, reader) in enumerate(ordered):
            relative = f"members/{index:04d}"
            os.symlink(path.resolve(), staging / relative, target_is_directory=True)
            members.append(
                ArtifactBundleMemberV3(
                    path=relative,
                    artifact_kind=reader.manifest.artifact_kind,
                    artifact_id=reader.manifest.artifact_id,
                    manifest_sha256=reader.manifest_sha256,
                )
            )
        inventory = canonical_json_bytes_v3(list(selected_ids))
        if len(inventory) > MAX_ARTIFACT_BUNDLE_INVENTORY_BYTES:
            _fail(
                "oversized_bundle_inventory",
                f"bundle record inventory is {len(inventory)} bytes",
                "partition the scheduling bundle into smaller dependency packs",
            )
        buffer = io.BytesIO()
        with gzip.GzipFile(
            filename="", mode="wb", compresslevel=6, mtime=0, fileobj=buffer
        ) as compressed_stream:
            compressed_stream.write(inventory)
        compressed = buffer.getvalue()
        if len(compressed) > MAX_ARTIFACT_BUNDLE_INVENTORY_BYTES:
            _fail(
                "oversized_bundle_inventory",
                f"compressed bundle record inventory is {len(compressed)} bytes",
                "partition the scheduling bundle into smaller dependency packs",
            )
        (staging / "record-ids.json.gz").write_bytes(compressed)
        manifest = ArtifactBundleManifestV3.create(
            artifact_kind=prototype.artifact_kind,
            status=prototype.status,
            bindings=prototype.bindings,
            members=members,
            record_count=len(selected_ids),
            inventory_size_bytes=len(compressed),
            inventory_sha256=hashlib.sha256(compressed).hexdigest(),
            inventory_decoded_size_bytes=len(inventory),
            inventory_decoded_sha256=hashlib.sha256(inventory).hexdigest(),
        )
        (staging / "manifest.json").write_bytes(manifest.to_bytes())
        os.replace(staging, destination)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def check_artifact_set_v3(
    root: Path | str,
    *,
    expected_record_ids: Iterable[str],
    expected_bindings: Iterable[ArtifactBindingV3] | None = None,
    expected_dependencies: Iterable[ArtifactDependencyV3] | None = None,
    dependency_record_exists: Callable[[RecordDependencyV3], bool] | None = None,
) -> ArtifactSetManifestV3:
    reader = ArtifactSetReaderV3(root)
    if expected_bindings is not None and reader.manifest.bindings != tuple(
        sorted(set(expected_bindings))
    ):
        _fail(
            "binding_mismatch",
            "artifact semantic bindings differ from the authority inputs",
            "rebuild the artifact from the exact binary/profile/checker bindings",
        )
    if expected_dependencies is not None and reader.manifest.dependencies != tuple(
        sorted(set(expected_dependencies))
    ):
        _fail(
            "dependency_mismatch",
            "artifact dependency bindings differ from declared inputs",
            "rebuild the phase with its exact declared artifact inputs",
        )
    reader.validate_completeness(
        expected_record_ids, dependency_record_exists=dependency_record_exists
    )
    return reader.manifest
