"""Immutable public data model for test discovery and execution plans."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .diagnostics import Diagnostic, TestkitError


INDEX_FORMAT = "spaghetti-extractor-test-impact-index-v1"
PLAN_FORMAT = "spaghetti-extractor-test-suite-plan-v2"
REBUILD_EXPLANATION_FORMAT = "spaghetti-extractor-rebuild-explanation-v1"


def canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _strings(value: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TestkitError(
            Diagnostic(
                "error",
                "invalid_manifest_field",
                f"{field_name} must be a list of strings",
                remediation="Regenerate the manifest with `nix run .#dev -- index`.",
            )
        )
    return tuple(value)


@dataclass(frozen=True, slots=True)
class ModuleRecord:
    name: str
    path: str
    dependencies: tuple[str, ...]
    resources: tuple[str, ...]
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "dependencies": list(self.dependencies),
            "resources": list(self.resources),
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ModuleRecord":
        return cls(
            name=str(value["name"]),
            path=str(value["path"]),
            dependencies=_strings(value["dependencies"], field_name="dependencies"),
            resources=_strings(value["resources"], field_name="resources"),
            sha256=str(value["sha256"]),
        )


@dataclass(frozen=True, slots=True)
class TestRecord:
    id: str
    path: str
    module: str
    tier: str
    subsystem: str
    capabilities: tuple[str, ...]
    target: str | None
    dependencies: tuple[str, ...]
    dependency_paths: tuple[str, ...]
    fixtures: tuple[str, ...]
    resources: tuple[str, ...]
    sha256: str
    input_sha256: str
    shard: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "path": self.path,
            "module": self.module,
            "tier": self.tier,
            "subsystem": self.subsystem,
            "capabilities": list(self.capabilities),
            "target": self.target,
            "dependencies": list(self.dependencies),
            "dependency_paths": list(self.dependency_paths),
            "fixtures": list(self.fixtures),
            "resources": list(self.resources),
            "sha256": self.sha256,
            "input_sha256": self.input_sha256,
            "shard": self.shard,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "TestRecord":
        target = value.get("target")
        if target is not None and not isinstance(target, str):
            raise TestkitError(
                Diagnostic("error", "invalid_manifest_field", "test target must be a string or null")
            )
        return cls(
            id=str(value["id"]),
            path=str(value["path"]),
            module=str(value["module"]),
            tier=str(value["tier"]),
            subsystem=str(value["subsystem"]),
            capabilities=_strings(value["capabilities"], field_name="capabilities"),
            target=target,
            dependencies=_strings(value["dependencies"], field_name="dependencies"),
            dependency_paths=_strings(value["dependency_paths"], field_name="dependency_paths"),
            fixtures=_strings(value["fixtures"], field_name="fixtures"),
            resources=_strings(value["resources"], field_name="resources"),
            sha256=str(value["sha256"]),
            input_sha256=str(value["input_sha256"]),
            shard=str(value["shard"]),
        )


@dataclass(frozen=True, slots=True)
class ImpactIndex:
    repository: str
    modules: tuple[ModuleRecord, ...]
    tests: tuple[TestRecord, ...]
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "format": INDEX_FORMAT,
            "repository": self.repository,
            "modules": [row.as_dict() for row in self.modules],
            "tests": [row.as_dict() for row in self.tests],
            "diagnostics": [row.as_dict() for row in self.diagnostics],
        }
        payload["identity"] = canonical_sha256(payload)
        return payload

    @property
    def identity(self) -> str:
        return str(self.as_dict()["identity"])

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ImpactIndex":
        if value.get("format") != INDEX_FORMAT:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "unsupported_index_format",
                    f"expected {INDEX_FORMAT}",
                    remediation="Regenerate the impact index with the current testkit.",
                )
            )
        modules = value.get("modules")
        tests = value.get("tests")
        diagnostics = value.get("diagnostics", [])
        if not isinstance(modules, list) or not isinstance(tests, list) or not isinstance(diagnostics, list):
            raise TestkitError(Diagnostic("error", "invalid_index", "index inventories must be lists"))
        if any(not isinstance(row, Mapping) for row in (*modules, *tests, *diagnostics)):
            raise TestkitError(Diagnostic("error", "invalid_index", "index inventory rows must be objects"))
        parsed = cls(
            repository=str(value.get("repository", ".")),
            modules=tuple(ModuleRecord.from_dict(row) for row in modules if isinstance(row, Mapping)),
            tests=tuple(TestRecord.from_dict(row) for row in tests if isinstance(row, Mapping)),
            diagnostics=tuple(
                Diagnostic(
                    severity=str(row["severity"]),
                    code=str(row["code"]),
                    message=str(row["message"]),
                    location=None if row.get("location") is None else str(row["location"]),
                    remediation=None if row.get("remediation") is None else str(row["remediation"]),
                    example=None if row.get("example") is None else str(row["example"]),
                )
                for row in diagnostics
                if isinstance(row, Mapping)
            ),
        )
        if len({row.name for row in parsed.modules}) != len(parsed.modules) or len({row.path for row in parsed.modules}) != len(parsed.modules):
            raise TestkitError(Diagnostic("error", "duplicate_index_module", "module names and paths must be unique"))
        if len({row.id for row in parsed.tests}) != len(parsed.tests) or len({row.path for row in parsed.tests}) != len(parsed.tests):
            raise TestkitError(Diagnostic("error", "duplicate_index_test", "test IDs and paths must be unique"))
        supplied = value.get("identity")
        if supplied is not None and supplied != parsed.identity:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "index_identity_mismatch",
                    "impact index content does not match its identity",
                    remediation="Regenerate the impact index instead of editing it manually.",
                )
            )
        return parsed


@dataclass(frozen=True, slots=True)
class PlannedShard:
    id: str
    resource_class: str
    tests: tuple[str, ...]
    test_paths: tuple[str, ...]
    files: tuple[str, ...]
    fixtures: tuple[str, ...]
    input_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "resource_class": self.resource_class,
            "tests": list(self.tests),
            "test_paths": list(self.test_paths),
            "files": list(self.files),
            "fixtures": list(self.fixtures),
            "input_sha256": self.input_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "PlannedShard":
        return cls(
            id=str(value["id"]),
            resource_class=str(value["resource_class"]),
            tests=_strings(value["tests"], field_name="tests"),
            test_paths=_strings(value["test_paths"], field_name="test_paths"),
            files=_strings(value["files"], field_name="files"),
            fixtures=_strings(value["fixtures"], field_name="fixtures"),
            input_sha256=str(value["input_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class SuitePlan:
    mode: str
    index_identity: str
    target: str | None
    changed_paths: tuple[str, ...]
    selected_tests: tuple[str, ...]
    selection_reasons: tuple[tuple[str, tuple[str, ...]], ...]
    shards: tuple[PlannedShard, ...]
    nix_checks: tuple[str, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "format": PLAN_FORMAT,
            "mode": self.mode,
            "index_identity": self.index_identity,
            "target": self.target,
            "changed_paths": list(self.changed_paths),
            "selected_tests": list(self.selected_tests),
            "selection_reasons": {
                key: list(reasons) for key, reasons in self.selection_reasons
            },
            "shards": [row.as_dict() for row in self.shards],
            "nix_checks": list(self.nix_checks),
            "diagnostics": [row.as_dict() for row in self.diagnostics],
        }
        payload["identity"] = canonical_sha256(payload)
        return payload

    @property
    def identity(self) -> str:
        return str(self.as_dict()["identity"])

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "SuitePlan":
        if value.get("format") != PLAN_FORMAT:
            raise TestkitError(Diagnostic("error", "unsupported_plan_format", f"expected {PLAN_FORMAT}"))
        shards = value.get("shards")
        reasons = value.get("selection_reasons")
        diagnostics = value.get("diagnostics", [])
        if not isinstance(shards, list) or not isinstance(reasons, Mapping) or not isinstance(diagnostics, list):
            raise TestkitError(Diagnostic("error", "invalid_plan", "plan inventories are malformed"))
        if any(not isinstance(row, Mapping) for row in (*shards, *diagnostics)):
            raise TestkitError(Diagnostic("error", "invalid_plan", "plan inventory rows must be objects"))
        parsed = cls(
            mode=str(value["mode"]),
            index_identity=str(value["index_identity"]),
            target=None if value.get("target") is None else str(value["target"]),
            changed_paths=_strings(value.get("changed_paths", []), field_name="changed_paths"),
            selected_tests=_strings(value["selected_tests"], field_name="selected_tests"),
            selection_reasons=tuple(
                (str(key), _strings(row, field_name=f"selection_reasons.{key}"))
                for key, row in sorted(reasons.items())
            ),
            shards=tuple(PlannedShard.from_dict(row) for row in shards if isinstance(row, Mapping)),
            nix_checks=_strings(value.get("nix_checks", []), field_name="nix_checks"),
            diagnostics=tuple(
                Diagnostic(
                    str(row["severity"]),
                    str(row["code"]),
                    str(row["message"]),
                    None if row.get("location") is None else str(row["location"]),
                    None if row.get("remediation") is None else str(row["remediation"]),
                    None if row.get("example") is None else str(row["example"]),
                )
                for row in diagnostics
                if isinstance(row, Mapping)
            ),
        )
        if len({row.id for row in parsed.shards}) != len(parsed.shards):
            raise TestkitError(Diagnostic("error", "duplicate_plan_shard", "shard IDs must be unique"))
        supplied = value.get("identity")
        if supplied is not None and supplied != parsed.identity:
            raise TestkitError(Diagnostic("error", "plan_identity_mismatch", "suite plan content does not match its identity"))
        return parsed


def safe_relative_path(value: str, *, field_name: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value in {"", "."}:
        raise TestkitError(
            Diagnostic(
                "error",
                "unsafe_relative_path",
                f"{field_name} must be a repository-relative path: {value!r}",
                remediation="Use a path relative to the repository root without '..'.",
            )
        )
    return path.as_posix()


__all__ = [
    "INDEX_FORMAT",
    "PLAN_FORMAT",
    "REBUILD_EXPLANATION_FORMAT",
    "ImpactIndex",
    "ModuleRecord",
    "PlannedShard",
    "SuitePlan",
    "TestRecord",
    "canonical_json",
    "canonical_sha256",
    "safe_relative_path",
]
