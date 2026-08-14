"""Bounded preparation of dynamic machine IR for the v3 Nix authority DAG."""

from __future__ import annotations

import hashlib
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..artifact_set_v3 import (
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    identity_bucket_v3,
    parse_canonical_json_v3,
)
from ._schema import fail, mapping, sequence, text, uint
from .planning import (
    RECORD_EDGES_FORMAT_V3,
    STRUCTURAL_INVENTORY_FORMAT_V3,
    prepare_scheduling_boundaries_v3,
)


SOURCE_PLAN_FORMAT_V3 = "spaghetti-extractor-analysis-source-plan-v3"


@dataclass(frozen=True)
class PreparedUnitV3:
    unit_id: str
    unit_sha256: str
    rva_start: int
    rva_end: int
    dependencies: tuple[str, ...]
    resource_class: str
    bucket: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "unit_sha256": self.unit_sha256,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "dependencies": list(self.dependencies),
            "resource_class": self.resource_class,
            "bucket": self.bucket,
        }


@dataclass(frozen=True)
class _SourceUnitV3:
    unit_id: str
    unit_sha256: str
    rva_start: int
    rva_end: int
    direct_target_rvas: tuple[int, ...]
    resource_class: str
    bucket: int


def _resource_class(encoded_size: int) -> str:
    if encoded_size <= 128 * 1024:
        return "small"
    if encoded_size <= 512 * 1024:
        return "medium"
    return "large"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_units(
    machine_ir: Path,
    shards_directory: Path,
    *,
    shard_bucket_count: int,
) -> tuple[tuple[_SourceUnitV3, ...], dict[tuple[str, int], str]]:
    rows: list[_SourceUnitV3] = []
    seen: set[str] = set()
    divisor = 64 // shard_bucket_count
    digests: dict[tuple[str, int], Any] = {}
    with ExitStack() as files, machine_ir.open("rb") as stream:
        outputs: dict[tuple[str, int], Any] = {}
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            payload = line.rstrip(b"\r\n")
            value = parse_canonical_json_v3(
                payload, location=f"{machine_ir}:{line_number}"
            )
            row = dict(mapping(value, f"machine-IR unit {line_number}"))
            unit_id = text(row.get("id"), "machine-IR unit ID")
            if unit_id in seen:
                fail(
                    "duplicate_structural_unit",
                    f"machine IR repeats unit {unit_id!r}",
                    "emit each exact structural unit once",
                )
            seen.add(unit_id)
            encoded = canonical_json_bytes_v3(row)
            resource_class = _resource_class(len(encoded))
            identity_bucket = identity_bucket_v3(unit_id)
            key = (resource_class, identity_bucket // divisor)
            output = outputs.get(key)
            if output is None:
                filename = f"{resource_class}-{key[1]:02d}.ndjson"
                output = files.enter_context(
                    (shards_directory / filename).open("wb")
                )
                outputs[key] = output
                digests[key] = hashlib.sha256()
            record = encoded + b"\n"
            output.write(record)
            digests[key].update(record)
            start, end = _span(row)
            rows.append(
                _SourceUnitV3(
                    unit_id=unit_id,
                    unit_sha256=hashlib.sha256(encoded).hexdigest(),
                    rva_start=start,
                    rva_end=end,
                    direct_target_rvas=_direct_target_rvas(row),
                    resource_class=resource_class,
                    bucket=identity_bucket,
                )
            )
    if not rows:
        fail(
            "empty_structural_universe",
            "machine IR contains no unit records",
            "run exact static extraction before v3 preparation",
        )
    return (
        tuple(sorted(rows, key=lambda row: row.unit_id)),
        {key: digest.hexdigest() for key, digest in digests.items()},
    )


def _span(row: dict[str, Any]) -> tuple[int, int]:
    source = mapping(row.get("source"), "machine-IR source")
    original = mapping(source.get("original"), "machine-IR original span")
    start = uint(original.get("rva_start"), "machine-IR start RVA")
    end = uint(original.get("rva_end"), "machine-IR end RVA")
    if end <= start:
        fail(
            "invalid_structural_span",
            f"unit {row.get('id')!r} has an empty or reversed span",
            "repair exact machine-IR extraction",
        )
    return start, end


def _direct_target_rvas(row: dict[str, Any]) -> tuple[int, ...]:
    control = mapping(row.get("control"), "machine-IR control")
    values = sequence(control.get("direct_targets", []), "direct target RVAs")
    return tuple(sorted(set(uint(value, "direct target RVA") for value in values)))


def prepare_analysis_source_v3(
    *,
    machine_ir: Path,
    binary: Path,
    output_directory: Path,
    shard_bucket_count: int = 4,
    resource_classes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write a canonical, bounded IFD boundary for a dynamic PE analysis."""

    if shard_bucket_count not in {1, 2, 4, 8, 16, 32, 64}:
        fail(
            "invalid_shard_bucket_count",
            f"source plan requested {shard_bucket_count} shard buckets",
            "use a power-of-two divisor of 64",
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    shards_directory = output_directory / "shards"
    shards_directory.mkdir()
    rows, shard_digests = _prepare_units(
        machine_ir,
        shards_directory,
        shard_bucket_count=shard_bucket_count,
    )
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    machine_ir_sha256 = _hash_file(machine_ir)
    by_rva: dict[int, str] = {}
    for row in rows:
        start = row.rva_start
        if start in by_rva:
            fail(
                "ambiguous_structural_entry",
                f"units {by_rva[start]!r} and {row.unit_id!r} share RVA {start:#x}",
                "give overlapping decode views distinct checked entry identities",
            )
        by_rva[start] = row.unit_id

    prepared: list[PreparedUnitV3] = []
    unresolved_direct_targets: list[dict[str, Any]] = []
    for row in rows:
        unit_id = row.unit_id
        dependencies: list[str] = []
        for target_rva in row.direct_target_rvas:
            target = by_rva.get(target_rva)
            if target is None:
                unresolved_direct_targets.append(
                    {
                        "source_unit_id": unit_id,
                        "target_rva": target_rva,
                    }
                )
            else:
                dependencies.append(target)
        prepared.append(
            PreparedUnitV3(
                unit_id=unit_id,
                unit_sha256=row.unit_sha256,
                rva_start=row.rva_start,
                rva_end=row.rva_end,
                dependencies=tuple(sorted(set(dependencies))),
                resource_class=row.resource_class,
                bucket=row.bucket,
            )
        )

    universe_rows = [
        {
            "unit_id": row.unit_id,
            "unit_sha256": row.unit_sha256,
            "rva_start": row.rva_start,
            "rva_end": row.rva_end,
        }
        for row in prepared
    ]
    universe_sha256 = canonical_sha256_v3(universe_rows)
    shard_groups: dict[tuple[str, int], list[PreparedUnitV3]] = {}
    divisor = 64 // shard_bucket_count
    for row in prepared:
        shard_groups.setdefault(
            (row.resource_class, row.bucket // divisor), []
        ).append(row)
    shard_rows: list[dict[str, Any]] = []
    for (resource_class, bucket), members in sorted(shard_groups.items()):
        key = f"{resource_class}-{bucket:02d}"
        filename = f"{key}.ndjson"
        shard_rows.append(
            {
                "key": key,
                "filename": filename,
                "identity_bucket": bucket,
                "resource_class": resource_class,
                "unit_ids": [row.unit_id for row in members],
                "sha256": shard_digests[(resource_class, bucket)],
            }
        )
    structural_inventory = {
        "format": STRUCTURAL_INVENTORY_FORMAT_V3,
        "universe_sha256": universe_sha256,
        "units": [
            {
                "unit_id": row.unit_id,
                "start": row.rva_start,
                "end": row.rva_end,
                "dependencies": list(row.dependencies),
                "resource_class": row.resource_class,
            }
            for row in prepared
        ],
    }
    record_edges = {
        "format": RECORD_EDGES_FORMAT_V3,
        "nodes": [
            {
                "node_id": row.unit_id,
                "dependencies": list(row.dependencies),
                # The dependency plan owns only topology.  Consuming SCC
                # phases bind node IDs to their declared same-ID artifacts.
                "records": [],
                "resource_class": row.resource_class,
            }
            for row in prepared
        ],
    }
    unresolved_direct_targets_document = {
        "format": "spaghetti-extractor-unresolved-direct-targets-v3",
        "targets": unresolved_direct_targets,
    }
    documents = {
        "structural_inventory": (
            "structural-inventory.json",
            canonical_json_bytes_v3(structural_inventory),
        ),
        "record_edges": (
            "record-edges.json",
            canonical_json_bytes_v3(record_edges),
        ),
        "unresolved_direct_targets": (
            "unresolved-direct-targets.json",
            canonical_json_bytes_v3(unresolved_direct_targets_document),
        ),
    }
    document_bindings: dict[str, dict[str, Any]] = {}
    for key, (filename, encoded) in documents.items():
        (output_directory / filename).write_bytes(encoded)
        document_bindings[key] = {
            "filename": filename,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    document_bindings["unresolved_direct_targets"]["count"] = len(
        unresolved_direct_targets
    )

    preplanned_boundaries = prepare_scheduling_boundaries_v3(
        structural_inventory=output_directory / "structural-inventory.json",
        record_edges=output_directory / "record-edges.json",
        output_directory=output_directory / "boundaries",
        resource_classes=resource_classes,
        schedule_bucket_count=shard_bucket_count,
    )

    # Keep the IFD document small. Large checked inventories remain separate
    # store-path inputs and are never materialized as nested Nix values.
    plan_core = {
        "format": SOURCE_PLAN_FORMAT_V3,
        "binary_sha256": binary_sha256,
        "machine_ir_source_sha256": machine_ir_sha256,
        "universe_sha256": universe_sha256,
        "unit_count": len(prepared),
        "shard_bucket_count": shard_bucket_count,
        "shards": shard_rows,
        "preplanned_boundaries": preplanned_boundaries,
        **document_bindings,
    }
    plan = {**plan_core, "plan_id": "analysis-source-plan-v3:" + canonical_sha256_v3(plan_core)}
    (output_directory / "plan.json").write_bytes(canonical_json_bytes_v3(plan))
    return plan


__all__ = [
    "PreparedUnitV3",
    "RECORD_EDGES_FORMAT_V3",
    "SOURCE_PLAN_FORMAT_V3",
    "STRUCTURAL_INVENTORY_FORMAT_V3",
    "prepare_analysis_source_v3",
]
