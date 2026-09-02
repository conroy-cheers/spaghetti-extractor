"""Plan and apply convention-correct developer scaffolds."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from .diagnostics import Diagnostic, TestkitError
from .model import canonical_sha256
from .static_manifest import refresh_repository_metadata


TEST_TIERS = frozenset({"benchmark", "integration", "smoke", "unit"})
NAME = re.compile(r"^[a-z][a-z0-9_]*$")
TARGET_ID = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclass(frozen=True, slots=True)
class ScaffoldFile:
    path: str
    content: str
    purpose: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "content": self.content, "purpose": self.purpose}


@dataclass(frozen=True, slots=True)
class ScaffoldPlan:
    kind: str
    name: str
    files: tuple[ScaffoldFile, ...]
    next_commands: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "format": "spaghetti-extractor-scaffold-plan-v1",
            "kind": self.kind,
            "name": self.name,
            "files": [row.as_dict() for row in self.files],
            "next_commands": list(self.next_commands),
        }
        payload["identity"] = canonical_sha256(payload)
        return payload

    def render(self) -> str:
        lines = [f"Scaffold {self.kind} {self.name}"]
        for row in self.files:
            lines.extend(("", f"create {row.path}  # {row.purpose}", "```", row.content.rstrip(), "```"))
        lines.append("")
        lines.extend(f"then: {command}" for command in self.next_commands)
        return "\n".join(lines) + "\n"


def apply_scaffold_plan(repository: Path, plan: ScaffoldPlan) -> tuple[Path, ...]:
    """Create planned files and refresh checked metadata as one transaction."""

    root = repository.resolve()
    destinations: list[Path] = []
    for row in plan.files:
        destination = (root / row.path).resolve()
        if destination == root or root not in destination.parents:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "scaffold_path_escape",
                    f"scaffold destination escapes the repository: {row.path!r}",
                    remediation="Use a convention-derived relative destination inside the repository.",
                )
            )
        if destination.exists():
            raise TestkitError(
                Diagnostic(
                    "error",
                    "scaffold_destination_exists",
                    f"refusing to overwrite {row.path}",
                    location=row.path,
                    remediation="Choose a new name or edit the existing file explicitly.",
                )
            )
        destinations.append(destination)

    created: list[Path] = []
    created_directories: set[Path] = set()
    try:
        for destination, row in zip(destinations, plan.files, strict=True):
            parent = destination.parent
            while parent != root and not parent.exists():
                created_directories.add(parent)
                parent = parent.parent
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(row.content, encoding="ascii")
            created.append(destination)
        refresh_repository_metadata(root)
    except Exception as exc:
        for destination in reversed(created):
            destination.unlink(missing_ok=True)
        for directory in sorted(
            created_directories, key=lambda path: len(path.parts), reverse=True
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
        if isinstance(exc, TestkitError):
            raise
        raise TestkitError(
            Diagnostic(
                "error",
                "scaffold_write_failed",
                f"could not create scaffold: {exc}",
                remediation="Correct repository permissions and rerun the same scaffold command.",
            )
        ) from exc
    return tuple(created)


def _name(value: str, *, field: str) -> str:
    normalized = value.replace("-", "_")
    if not NAME.fullmatch(normalized):
        raise TestkitError(
            Diagnostic(
                "error",
                "invalid_scaffold_name",
                f"{field} must be lowercase snake_case: {value!r}",
                remediation="Use letters, digits, and underscores, beginning with a letter.",
            )
        )
    return normalized


def plan_test_scaffold(
    *,
    subsystem: str,
    name: str,
    tier: str = "unit",
    capability: str | None = None,
) -> ScaffoldPlan:
    subsystem = _name(subsystem, field="subsystem")
    name = _name(name.removeprefix("test_"), field="test name")
    if tier not in TEST_TIERS:
        raise TestkitError(Diagnostic("error", "invalid_test_tier", f"unsupported tier {tier!r}", remediation=f"Choose one of: {', '.join(sorted(TEST_TIERS))}."))
    if tier == "integration":
        capability = _name(capability or subsystem, field="integration capability")
        directory = f"tests/integration/{capability}"
    elif tier == "smoke":
        directory = "tests/smoke"
    elif tier == "benchmark":
        directory = "tests/benchmark"
    else:
        directory = f"tests/unit/{subsystem}"
    path = f"{directory}/test_{name}.py"
    class_name = "".join(part.title() for part in name.split("_")) + "Tests"
    content = (
        "from __future__ import annotations\n\n"
        "import unittest\n\n\n"
        f"class {class_name}(unittest.TestCase):\n"
        "    def test_expected_behavior(self) -> None:\n"
        "        self.assertTrue(True)\n\n\n"
        'if __name__ == "__main__":\n'
        "    unittest.main()\n"
    )
    return ScaffoldPlan(
        kind="test",
        name=name,
        files=(ScaffoldFile(path, content, "convention-classified test module"),),
        next_commands=(
            "nix run .#test -- affected --changed " + path,
            "nix run .#dev -- doctor",
        ),
    )


def plan_fixture_scaffold(*, fixture_kind: str, name: str) -> ScaffoldPlan:
    fixture_kind = _name(fixture_kind, field="fixture kind")
    name = _name(name, field="fixture name")
    identifier = name.replace("_", "-")
    manifest = json.dumps(
        {
            "format": "spaghetti-extractor-test-fixture-definition-v1",
            "id": identifier,
            "kind": fixture_kind,
            "description": f"Shared {fixture_kind} fixture for {identifier}",
            "capabilities": [fixture_kind],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    nix = (
        "{ pkgs }:\n"
        "pkgs.runCommand " + json.dumps(f"spaghetti-test-fixture-{identifier}") + " {\n"
        "  __contentAddressed = true;\n"
        "  allowSubstitutes = true;\n"
        "  preferLocalBuild = false;\n"
        "} ''\n"
        "  set -euo pipefail\n"
        "  mkdir -p \"$out\"\n"
        f"  # Build the pinned {fixture_kind} fixture here.\n"
        "''\n"
    )
    return ScaffoldPlan(
        kind="fixture",
        name=identifier,
        files=(
            ScaffoldFile(f"tests/fixtures/catalog/{identifier}.json", manifest, "fixture metadata"),
            ScaffoldFile(f"nix/test-fixture-{identifier}.nix", nix, "content-addressed fixture build"),
        ),
        next_commands=(
            f"nix build .#test-fixture-{identifier} --no-link",
            f"nix run .#dev -- fixtures {identifier}",
        ),
    )


def plan_target_scaffold(*, target_id: str) -> ScaffoldPlan:
    """Create an intentionally unregistered PE32 target skeleton."""

    if not TARGET_ID.fullmatch(target_id):
        raise TestkitError(
            Diagnostic(
                "error",
                "invalid_target_id",
                f"target id must be lowercase kebab-case: {target_id!r}",
                remediation="Use letters, digits, and hyphens, beginning with a letter.",
            )
        )
    metadata = json.dumps(
        {
            "format": "spaghetti-extractor-target-bundle-v3",
            "id": target_id,
            "display_name": target_id,
            "input": {"kind": "pe32", "expected_sha256": "0" * 64},
            "paths": {"nix": "default.nix", "components": None},
            "workflow": {"default_configuration": None},
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    module = f'''{{ pkgs, sdk }}:

let
  # Bind a reproducible PE derivation before adding this target to registry.nix.
  originalPe = throw "configure the {target_id} original PE derivation";
  runtimeProfile = "${{sdk.profiles}}/pe32-native-callthrough-runtime-v1.json";
  environment = sdk.environment.pe32 {{
    id = "{target_id}-win32";
    profilePacks = [ runtimeProfile ];
    interfacePacks = [ ];
    launchProfile =
      "${{sdk.profiles}}/pe32-win32-console-launch-assumptions-v1.json";
    boundaryIntents = {{ }};
    support.processTermination = null;
  }};
  workflow = sdk.workflow.pe32 {{
    original = originalPe;
    targetId = "{target_id}";
    binaryIdentity = "{target_id}.exe";
    externalEnvironment = environment;
    lifting = {{
      boundaries = [ ];
      components = null;
      libraries = {{ packs = [ ]; adoptionRoot = null; }};
    }};
    backend = {{ kind = "behavioral-c"; sourcePresentation = null; }};
    analysisLimits = {{ maxUnits = 512; maxCandidatesPerSeed = 12; }};
  }};
in
sdk.target.pe32Bundle {{
  targetRoot = ./.;
  inherit workflow;
  inputs = {{ }};
}}
'''
    return ScaffoldPlan(
        kind="target",
        name=target_id,
        files=(
            ScaffoldFile(
                f"targets/{target_id}/target.json",
                metadata,
                "target metadata with no component or runtime claims",
            ),
            ScaffoldFile(
                f"targets/{target_id}/default.nix",
                module,
                "public-SDK-only target module requiring an explicit PE binding",
            ),
        ),
        next_commands=(
            f"edit targets/{target_id}/default.nix and target.json to bind the exact PE",
            f"add {target_id} = ./{target_id}; to targets/registry.nix",
            "nix flake check ./targets",
        ),
    )


__all__ = [
    "TEST_TIERS",
    "ScaffoldFile",
    "ScaffoldPlan",
    "apply_scaffold_plan",
    "plan_fixture_scaffold",
    "plan_target_scaffold",
    "plan_test_scaffold",
]
