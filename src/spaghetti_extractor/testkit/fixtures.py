"""Discoverable shared-fixture catalog and test lookup helper."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Mapping

from .diagnostics import Diagnostic, TestkitError


FIXTURE_MANIFEST_FORMAT = "spaghetti-extractor-test-fixtures-v1"
FIXTURE_ENV = "SPAGHETTI_TEST_FIXTURES"


@dataclass(frozen=True, slots=True)
class FixtureDefinition:
    id: str
    description: str
    capabilities: tuple[str, ...]
    nix_attribute: str

    def as_dict(self, *, path: str | None = None) -> dict[str, object]:
        return {
            "id": self.id,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "nix_attribute": self.nix_attribute,
            "available": path is not None,
            "path": path,
        }


BUILTIN_FIXTURES = (
    FixtureDefinition("bochs-conformance", "Batched pinned Bochs ISA executor", ("bochs", "isa"), "test-fixture-bochs-conformance"),
    FixtureDefinition("compiler", "Pinned PE32 cross-compiler toolchain", ("compiler",), "test-fixture-compiler"),
    FixtureDefinition("headless-wine", "Candidate-only Wine runner in an isolated headless display", ("wine",), "test-fixture-headless-wine"),
    FixtureDefinition("lean-isa-runner", "Precompiled Lean ISA conformance runner", ("isa", "lean"), "test-fixture-lean-isa-runner"),
    FixtureDefinition("nix", "Pinned Nix evaluator and build client", ("nix",), "test-fixture-nix"),
    FixtureDefinition("pe32-minimal-import-call", "Small deterministic PE32 import-call fixture", ("native",), "test-fixture-pe32-minimal-import-call"),
)


class FixtureCatalog:
    def __init__(
        self,
        definitions: tuple[FixtureDefinition, ...] = BUILTIN_FIXTURES,
        paths: Mapping[str, str] | None = None,
    ) -> None:
        self._definitions = {row.id: row for row in definitions}
        self._paths = dict(paths or {})
        unknown = sorted(set(self._paths) - set(self._definitions))
        if unknown:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "unknown_fixture_realization",
                    f"fixture manifest contains unknown IDs: {', '.join(unknown)}",
                    remediation="Register fixtures through nix/test-suite-fixtures.nix.",
                )
            )

    @staticmethod
    def _repository_definitions(repository: Path | None) -> tuple[FixtureDefinition, ...]:
        if repository is None:
            return ()
        directory = repository / "tests" / "fixtures" / "catalog"
        definitions: list[FixtureDefinition] = []
        for path in sorted(directory.glob("*.json")) if directory.is_dir() else ():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise TestkitError(Diagnostic("error", "fixture_definition_unreadable", str(exc), location=str(path), remediation="Regenerate the fixture definition with the scaffolder.")) from exc
            if not isinstance(value, Mapping) or value.get("format") != "spaghetti-extractor-test-fixture-definition-v1":
                raise TestkitError(Diagnostic("error", "unsupported_fixture_definition", "fixture definition has an unsupported format", location=str(path), remediation="Regenerate it with `nix run .#dev -- scaffold fixture <kind> <name>`."))
            capabilities = value.get("capabilities", [])
            if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
                raise TestkitError(Diagnostic("error", "invalid_fixture_definition", "fixture capabilities must be strings", location=str(path)))
            fixture_id = value.get("id")
            description = value.get("description")
            if not isinstance(fixture_id, str) or not isinstance(description, str):
                raise TestkitError(Diagnostic("error", "invalid_fixture_definition", "fixture id and description must be strings", location=str(path)))
            definitions.append(
                FixtureDefinition(
                    id=fixture_id,
                    description=description,
                    capabilities=tuple(sorted(set(capabilities))),
                    nix_attribute=str(value.get("nix_attribute", f"test-fixture-{fixture_id}")),
                )
            )
        return tuple(definitions)

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        repository: Path | None = None,
    ) -> "FixtureCatalog":
        environment = os.environ if environment is None else environment
        definitions = {row.id: row for row in BUILTIN_FIXTURES}
        definitions.update(
            (row.id, row) for row in cls._repository_definitions(repository)
        )
        manifest_value = environment.get(FIXTURE_ENV)
        if not manifest_value:
            return cls(tuple(definitions.values()))
        path = Path(manifest_value)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "fixture_manifest_unreadable",
                    str(exc),
                    location=str(path),
                    remediation="Enter the Nix test environment or unset SPAGHETTI_TEST_FIXTURES.",
                )
            ) from exc
        if not isinstance(payload, Mapping) or payload.get("format") != FIXTURE_MANIFEST_FORMAT:
            raise TestkitError(Diagnostic("error", "unsupported_fixture_manifest", f"fixture manifest must use {FIXTURE_MANIFEST_FORMAT}", location=str(path)))
        rows = payload.get("fixtures")
        if not isinstance(rows, Mapping) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in rows.items()):
            raise TestkitError(Diagnostic("error", "invalid_fixture_manifest", "fixtures must map IDs to store paths", location=str(path)))
        manifest_definitions = payload.get("definitions", {})
        if not isinstance(manifest_definitions, Mapping):
            raise TestkitError(Diagnostic("error", "invalid_fixture_manifest", "fixture definitions must be an object", location=str(path)))
        for fixture_id, row in manifest_definitions.items():
            if not isinstance(fixture_id, str) or not isinstance(row, Mapping):
                raise TestkitError(Diagnostic("error", "invalid_fixture_manifest", "fixture definition rows are malformed", location=str(path)))
            capabilities = row.get("capabilities", [])
            if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
                raise TestkitError(Diagnostic("error", "invalid_fixture_manifest", "fixture capabilities must be strings", location=str(path)))
            definitions[fixture_id] = FixtureDefinition(
                fixture_id,
                str(row.get("description", fixture_id)),
                tuple(sorted(set(capabilities))),
                str(row.get("nix_attribute", f"test-fixture-{fixture_id}")),
            )
        return cls(tuple(definitions.values()), paths=rows)

    def definitions(self) -> tuple[FixtureDefinition, ...]:
        return tuple(self._definitions[key] for key in sorted(self._definitions))

    def describe(self, fixture_id: str) -> dict[str, object]:
        definition = self._definitions.get(fixture_id)
        if definition is None:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "unknown_fixture",
                    f"unknown fixture {fixture_id!r}",
                    remediation="List available fixtures with `nix run .#dev -- fixtures`.",
                )
            )
        return definition.as_dict(path=self._paths.get(fixture_id))

    def lookup(self, fixture_id: str) -> Path:
        description = self.describe(fixture_id)
        value = description["path"]
        if value is None:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "fixture_not_realized",
                    f"fixture {fixture_id!r} is known but unavailable in this environment",
                    remediation=f"Run through Nix with `{description['nix_attribute']}` supplied to the test-suite fixture set.",
                    example=f'from spaghetti_extractor.testkit import fixture\npath = fixture("{fixture_id}")',
                )
            )
        path = Path(str(value))
        if not path.exists():
            raise TestkitError(
                Diagnostic(
                    "error",
                    "fixture_path_missing",
                    f"fixture {fixture_id!r} points to a missing path",
                    location=str(path),
                    remediation="Rebuild the Nix fixture environment instead of substituting an ad-hoc host tool.",
                )
            )
        return path


def fixture(fixture_id: str) -> Path:
    """Resolve a shared fixture from the Nix-provided environment manifest."""

    return FixtureCatalog.from_environment().lookup(fixture_id)


__all__ = [
    "BUILTIN_FIXTURES",
    "FIXTURE_ENV",
    "FIXTURE_MANIFEST_FORMAT",
    "FixtureCatalog",
    "FixtureDefinition",
    "fixture",
]
