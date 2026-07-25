from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from ..util import sha256_bytes, sha256_file, write_json
from .schema import (
    LEAN_MODULE_GRAPH_V2_FORMAT,
    RELATIONAL_KERNEL_MODULES,
    SchemaError,
)


CHECKED_ARTIFACT_MANIFEST_FORMAT = "stage-a-checked-artifact-manifest-v1"
CHECKED_ARTIFACT_ID_FORMAT = "stage-a-checked-artifact-id-v1"
CHECKED_ARTIFACT_CHECKER_VERSION = "stage-a-checked-artifact-checkers-v1"


class CheckedArtifactKind(StrEnum):
    KERNEL = "kernel"
    IMAGE_ATTESTATION = "image-attestation"
    IMAGE_PACK = "image-pack"
    REGION_DATA = "region-data"
    REGION_DECODE = "checked-region-decode"
    REGION_SEMANTICS = "checked-region-semantics"
    EFFECTS = "checked-transition-effects"
    SOLVER_EVIDENCE = "checked-solver-evidence"
    SEGMENT_REFINEMENT = "checked-segment-refinement"
    PRODUCT_GRAPH = "checked-product-graph"
    ACCEPTANCE = "whole-program-acceptance"
    AUDIT_SUPPORT = "audit-support"
    OTHER = "other"


def checked_image_identity(
    *, side: str, binary_sha256: str
) -> "CheckedArtifactIdentity":
    """Return the canonical identity shared by generation and the manifest."""
    return CheckedArtifactIdentity.create(
        kind=CheckedArtifactKind.IMAGE_ATTESTATION,
        semantic_key=f"pe32-image:{side}",
        dependency_ids=(),
        relevant_input_sha256=binary_sha256,
        normalized_data_sha256=binary_sha256,
    )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{field} must be a non-empty string")
    return value


def _sha256(value: Any, field: str) -> str:
    result = _nonempty_string(value, field)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise SchemaError(f"{field} must be a lowercase SHA-256 digest")
    return result


def _string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise SchemaError(f"{field} must be a list of non-empty strings")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise SchemaError(f"{field} must not contain duplicates")
    return result


@dataclass(frozen=True)
class CheckedArtifactIdentity:
    kind: CheckedArtifactKind
    semantic_key: str
    checker_version: str
    dependency_ids: tuple[str, ...]
    relevant_input_sha256: str
    normalized_data_sha256: str
    artifact_id: str

    @classmethod
    def create(
        cls,
        *,
        kind: CheckedArtifactKind,
        semantic_key: str,
        dependency_ids: Sequence[str],
        relevant_input_sha256: str,
        normalized_data_sha256: str,
        checker_version: str = CHECKED_ARTIFACT_CHECKER_VERSION,
    ) -> "CheckedArtifactIdentity":
        dependencies = tuple(sorted(set(dependency_ids)))
        payload = {
            "format": CHECKED_ARTIFACT_ID_FORMAT,
            "kind": kind.value,
            "semantic_key": semantic_key,
            "checker_version": checker_version,
            "dependency_ids": list(dependencies),
            "relevant_input_sha256": relevant_input_sha256,
            "normalized_data_sha256": normalized_data_sha256,
        }
        artifact_id = sha256_bytes(_canonical_json(payload))
        return cls(
            kind=kind,
            semantic_key=_nonempty_string(semantic_key, "semantic_key"),
            checker_version=_nonempty_string(checker_version, "checker_version"),
            dependency_ids=dependencies,
            relevant_input_sha256=_sha256(
                relevant_input_sha256, "relevant_input_sha256"
            ),
            normalized_data_sha256=_sha256(
                normalized_data_sha256, "normalized_data_sha256"
            ),
            artifact_id=artifact_id,
        )

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CheckedArtifactIdentity":
        try:
            kind = CheckedArtifactKind(payload.get("kind"))
        except ValueError as exc:
            raise SchemaError("checked artifact kind is unsupported") from exc
        result = cls(
            kind=kind,
            semantic_key=_nonempty_string(payload.get("semantic_key"), "semantic_key"),
            checker_version=_nonempty_string(
                payload.get("checker_version"), "checker_version"
            ),
            dependency_ids=_string_tuple(
                payload.get("dependency_ids"), "dependency_ids"
            ),
            relevant_input_sha256=_sha256(
                payload.get("relevant_input_sha256"), "relevant_input_sha256"
            ),
            normalized_data_sha256=_sha256(
                payload.get("normalized_data_sha256"), "normalized_data_sha256"
            ),
            artifact_id=_sha256(payload.get("artifact_id"), "artifact_id"),
        )
        expected = cls.create(
            kind=result.kind,
            semantic_key=result.semantic_key,
            checker_version=result.checker_version,
            dependency_ids=result.dependency_ids,
            relevant_input_sha256=result.relevant_input_sha256,
            normalized_data_sha256=result.normalized_data_sha256,
        )
        if result.artifact_id != expected.artifact_id:
            raise SchemaError("checked artifact identity digest mismatch")
        return result

    def payload(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "checker_version": self.checker_version,
            "dependency_ids": list(self.dependency_ids),
            "kind": self.kind.value,
            "normalized_data_sha256": self.normalized_data_sha256,
            "relevant_input_sha256": self.relevant_input_sha256,
            "semantic_key": self.semantic_key,
        }


@dataclass(frozen=True)
class CheckedArtifactRecord:
    identity: CheckedArtifactIdentity
    modules: tuple[str, ...]
    exported_theorems: tuple[str, ...]
    native_decision_theorems: tuple[str, ...]
    acceptance_authority: bool
    metadata: Mapping[str, Any]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CheckedArtifactRecord":
        identity_payload = payload.get("identity")
        if not isinstance(identity_payload, Mapping):
            raise SchemaError("checked artifact identity must be an object")
        metadata = payload.get("metadata")
        if not isinstance(metadata, Mapping):
            raise SchemaError("checked artifact metadata must be an object")
        authority = payload.get("acceptance_authority")
        if not isinstance(authority, bool):
            raise SchemaError("acceptance_authority must be a boolean")
        return cls(
            identity=CheckedArtifactIdentity.parse(identity_payload),
            modules=_string_tuple(payload.get("modules"), "modules"),
            exported_theorems=_string_tuple(
                payload.get("exported_theorems"), "exported_theorems"
            ),
            native_decision_theorems=_string_tuple(
                payload.get("native_decision_theorems"),
                "native_decision_theorems",
            ),
            acceptance_authority=authority,
            metadata=MappingProxyType(dict(metadata)),
        )

    def payload(self) -> dict[str, Any]:
        return {
            "acceptance_authority": self.acceptance_authority,
            "exported_theorems": list(self.exported_theorems),
            "identity": self.identity.payload(),
            "metadata": dict(self.metadata),
            "modules": list(self.modules),
            "native_decision_theorems": list(self.native_decision_theorems),
        }


@dataclass(frozen=True)
class CheckedArtifactManifest:
    model: str
    machine_semantics_version: str
    authoritative: bool
    artifacts: tuple[CheckedArtifactRecord, ...]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CheckedArtifactManifest":
        if payload.get("format") != CHECKED_ARTIFACT_MANIFEST_FORMAT:
            raise SchemaError("unsupported checked artifact manifest format")
        rows = payload.get("artifacts")
        if not isinstance(rows, list) or any(
            not isinstance(row, Mapping) for row in rows
        ):
            raise SchemaError("checked artifact manifest artifacts must be objects")
        authoritative = payload.get("authoritative")
        if not isinstance(authoritative, bool):
            raise SchemaError("checked artifact manifest authority must be boolean")
        artifacts = tuple(CheckedArtifactRecord.parse(row) for row in rows)
        artifact_ids = [artifact.identity.artifact_id for artifact in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise SchemaError("checked artifact IDs must be unique")
        semantic_keys = [
            (artifact.identity.kind, artifact.identity.semantic_key)
            for artifact in artifacts
        ]
        if len(semantic_keys) != len(set(semantic_keys)):
            raise SchemaError(
                "checked artifact kind and semantic key pairs must be unique"
            )
        declared = set(artifact_ids)
        for artifact in artifacts:
            missing = set(artifact.identity.dependency_ids) - declared
            if missing:
                raise SchemaError(
                    "checked artifact names missing dependencies: "
                    + ", ".join(sorted(missing))
                )
            if artifact.acceptance_authority and not authoritative:
                raise SchemaError(
                    "a non-authoritative manifest cannot contain acceptance authority"
                )
        return cls(
            model=_nonempty_string(payload.get("model"), "model"),
            machine_semantics_version=_nonempty_string(
                payload.get("machine_semantics_version"),
                "machine_semantics_version",
            ),
            authoritative=authoritative,
            artifacts=artifacts,
        )

    def payload(self) -> dict[str, Any]:
        return {
            "artifacts": [artifact.payload() for artifact in self.artifacts],
            "authoritative": self.authoritative,
            "format": CHECKED_ARTIFACT_MANIFEST_FORMAT,
            "machine_semantics_version": self.machine_semantics_version,
            "model": self.model,
        }


@dataclass(frozen=True)
class CheckedArtifactManifestDiff:
    reused: tuple[str, ...]
    changed: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "changed": list(self.changed),
            "counts": {
                "added": len(self.added),
                "changed": len(self.changed),
                "removed": len(self.removed),
                "reused": len(self.reused),
            },
            "removed": list(self.removed),
            "reused": list(self.reused),
        }


def _artifact_manifest_key(record: CheckedArtifactRecord) -> str:
    identity = record.identity
    return f"{identity.kind.value}:{identity.semantic_key}"


def diff_checked_artifact_manifests(
    before: CheckedArtifactManifest,
    after: CheckedArtifactManifest,
) -> CheckedArtifactManifestDiff:
    """Compare semantic artifact identities across a controlled mutation."""
    if before.model != after.model:
        raise SchemaError("cannot diff checked artifact manifests for different models")
    previous = {
        _artifact_manifest_key(record): record.identity.artifact_id
        for record in before.artifacts
    }
    current = {
        _artifact_manifest_key(record): record.identity.artifact_id
        for record in after.artifacts
    }
    previous_keys = set(previous)
    current_keys = set(current)
    shared = previous_keys & current_keys
    return CheckedArtifactManifestDiff(
        reused=tuple(sorted(key for key in shared if previous[key] == current[key])),
        changed=tuple(sorted(key for key in shared if previous[key] != current[key])),
        added=tuple(sorted(current_keys - previous_keys)),
        removed=tuple(sorted(previous_keys - current_keys)),
    )


def _source_projection_sha256(
    modules: Sequence[str], module_sources: Mapping[str, Path]
) -> str:
    projection = [
        {
            "module": module,
            "source_sha256": sha256_file(module_sources[module]),
        }
        for module in sorted(set(modules))
    ]
    return sha256_bytes(_canonical_json(projection))


def write_checked_artifact_manifest(
    *,
    destination: Path,
    model: str,
    original_sha256: str,
    candidate_sha256: str,
    root_module: str,
    expected_final_theorem: str | None,
    module_sources: Mapping[str, Path],
    authoritative: bool,
) -> CheckedArtifactManifest:
    """Bind generated checked leaves into a compact, typed proof-artifact DAG."""
    region_path = destination.parent / "checked-region-artifacts.json"
    try:
        region_payload = json.loads(region_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot read checked region artifacts: {exc}") from exc
    if (
        not isinstance(region_payload, Mapping)
        or region_payload.get("format") != "stage-a-checked-region-artifacts-v1"
        or not isinstance(region_payload.get("artifacts"), list)
    ):
        raise SchemaError("checked region artifact inventory is malformed")

    kernel_modules = sorted(
        module for module in RELATIONAL_KERNEL_MODULES
        if module in module_sources
    )
    machine_semantics_version = _source_projection_sha256(
        kernel_modules, module_sources
    )

    records: list[CheckedArtifactRecord] = []
    image_ids: list[str] = []
    for side, digest, module in (
        ("original", original_sha256, "RelationalProofOriginal"),
        ("candidate", candidate_sha256, "RelationalProofCandidate"),
    ):
        if module not in module_sources:
            raise SchemaError(f"checked image module StageA.{module} is missing")
        identity = checked_image_identity(side=side, binary_sha256=digest)
        image_ids.append(identity.artifact_id)
        records.append(CheckedArtifactRecord(
            identity=identity,
            modules=(module,),
            exported_theorems=(
                f"StageA.GeneratedRelational.{side}Parsed",
                f"StageA.GeneratedRelational.{side}ImportsChecked",
                f"StageA.GeneratedRelational.{side}RelocationsParsed",
            ),
            native_decision_theorems=(),
            acceptance_authority=False,
            metadata=MappingProxyType({"side": side}),
        ))

    region_ids: list[str] = []
    for index, raw in enumerate(region_payload["artifacts"]):
        if not isinstance(raw, Mapping):
            raise SchemaError(f"checked region artifact {index} is malformed")
        identity_payload = raw.get("identity")
        if not isinstance(identity_payload, Mapping):
            raise SchemaError(f"checked region artifact {index} lacks identity")
        identity = CheckedArtifactIdentity.parse(identity_payload)
        module = _nonempty_string(raw.get("module"), f"artifacts[{index}].module")
        if module not in module_sources:
            raise SchemaError(
                f"checked region artifact names missing module StageA.{module}"
            )
        theorem = _nonempty_string(
            raw.get("decoded_theorem"),
            f"artifacts[{index}].decoded_theorem",
        )
        definition = _nonempty_string(
            raw.get("semantic_definition"),
            f"artifacts[{index}].semantic_definition",
        )
        legacy = raw.get("legacy_full_image_replay", True)
        if not isinstance(legacy, bool):
            raise SchemaError(
                f"artifacts[{index}].legacy_full_image_replay must be a boolean"
            )
        local_exports = [f"StageA.GeneratedRelational.{definition}EffectsExact"]
        replay_theorem = raw.get("semantic_replay_theorem")
        if replay_theorem is not None:
            local_exports.insert(
                0,
                "StageA.GeneratedRelational."
                + _nonempty_string(
                    replay_theorem,
                    f"artifacts[{index}].semantic_replay_theorem",
                ),
            )
        records.append(CheckedArtifactRecord(
            identity=identity,
            modules=(module,),
            exported_theorems=tuple(local_exports),
            native_decision_theorems=(),
            acceptance_authority=False,
            metadata=MappingProxyType({
                "legacy_full_image_replay": legacy,
                "region_id": raw.get("region_id"),
                "region_index": raw.get("region_index"),
                "side": raw.get("side"),
                "span": raw.get("span"),
            }),
        ))
        binding_payload = raw.get("binding_identity")
        if binding_payload is None:
            region_ids.append(identity.artifact_id)
            continue
        if not isinstance(binding_payload, Mapping):
            raise SchemaError(
                f"artifacts[{index}].binding_identity must be an object"
            )
        binding_identity = CheckedArtifactIdentity.parse(binding_payload)
        binding_module = _nonempty_string(
            raw.get("binding_module"),
            f"artifacts[{index}].binding_module",
        )
        if binding_module not in module_sources:
            raise SchemaError(
                "checked region image binding names missing module "
                f"StageA.{binding_module}"
            )
        binding_definition = _nonempty_string(
            raw.get("image_binding_definition"),
            f"artifacts[{index}].image_binding_definition",
        )
        region_ids.append(binding_identity.artifact_id)
        records.append(CheckedArtifactRecord(
            identity=binding_identity,
            modules=(binding_module,),
            exported_theorems=(
                f"StageA.GeneratedRelational.{theorem}",
            ),
            native_decision_theorems=(),
            acceptance_authority=False,
            metadata=MappingProxyType({
                "binding_definition": binding_definition,
                "region_id": raw.get("region_id"),
                "region_index": raw.get("region_index"),
                "semantic_artifact_id": identity.artifact_id,
                "side": raw.get("side"),
                "span": raw.get("span"),
            }),
        ))

    segment_modules = sorted(
        module for module in module_sources
        if "SegmentRefinement" in module
    )
    segment_source = _source_projection_sha256(segment_modules, module_sources)
    segment_identity = CheckedArtifactIdentity.create(
        kind=CheckedArtifactKind.SEGMENT_REFINEMENT,
        semantic_key="relational-segment-refinements",
        dependency_ids=region_ids,
        relevant_input_sha256=segment_source,
        normalized_data_sha256=segment_source,
    )
    records.append(CheckedArtifactRecord(
        identity=segment_identity,
        modules=tuple(segment_modules),
        exported_theorems=(),
        native_decision_theorems=(),
        acceptance_authority=False,
        metadata=MappingProxyType({"aggregate": True}),
    ))

    graph_modules = sorted(
        module for module in module_sources
        if "ProductGraph" in module
        or "ReachableProduct" in module
        or "ProductEdge" in module
        or "ProductNode" in module
    )
    graph_source = _source_projection_sha256(graph_modules, module_sources)
    graph_identity = CheckedArtifactIdentity.create(
        kind=CheckedArtifactKind.PRODUCT_GRAPH,
        semantic_key="relational-product-graph",
        dependency_ids=(segment_identity.artifact_id,),
        relevant_input_sha256=graph_source,
        normalized_data_sha256=graph_source,
    )
    records.append(CheckedArtifactRecord(
        identity=graph_identity,
        modules=tuple(graph_modules),
        exported_theorems=(),
        native_decision_theorems=(),
        acceptance_authority=False,
        metadata=MappingProxyType({"indexed": True}),
    ))

    root_source = sha256_file(module_sources[root_module])
    acceptance_identity = CheckedArtifactIdentity.create(
        kind=CheckedArtifactKind.ACCEPTANCE,
        semantic_key="pe32-whole-program-equivalence",
        dependency_ids=(
            *image_ids,
            graph_identity.artifact_id,
        ),
        relevant_input_sha256=root_source,
        normalized_data_sha256=sha256_bytes(_canonical_json({
            "root_module": root_module,
            "expected_final_theorem": expected_final_theorem,
        })),
    )
    records.append(CheckedArtifactRecord(
        identity=acceptance_identity,
        modules=(root_module,),
        exported_theorems=(
            () if expected_final_theorem is None else (expected_final_theorem,)
        ),
        native_decision_theorems=(),
        acceptance_authority=authoritative,
        metadata=MappingProxyType({
            "parity_path": not authoritative,
            "root_module": root_module,
        }),
    ))

    manifest = CheckedArtifactManifest(
        model=model,
        machine_semantics_version=machine_semantics_version,
        authoritative=authoritative,
        artifacts=tuple(records),
    )
    CheckedArtifactManifest.parse(manifest.payload())
    write_json(destination, manifest.payload())
    return manifest
