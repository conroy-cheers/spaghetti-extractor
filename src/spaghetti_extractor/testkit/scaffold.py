"""Plan and apply convention-correct developer scaffolds."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from .diagnostics import Diagnostic, TestkitError
from .model import canonical_sha256


PHASE_KINDS = frozenset({"map-units", "map-sccs", "reduce"})
TEST_TIERS = frozenset({"benchmark", "integration", "smoke", "target", "unit"})
NAME = re.compile(r"^[a-z][a-z0-9_]*$")


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
    """Create every planned file atomically with fail-closed path checks."""

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
    try:
        for destination, row in zip(destinations, plan.files, strict=True):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(row.content, encoding="ascii")
            created.append(destination)
    except OSError as exc:
        for destination in reversed(created):
            destination.unlink(missing_ok=True)
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
    target: str | None = None,
) -> ScaffoldPlan:
    subsystem = _name(subsystem, field="subsystem")
    name = _name(name.removeprefix("test_"), field="test name")
    if tier not in TEST_TIERS:
        raise TestkitError(Diagnostic("error", "invalid_test_tier", f"unsupported tier {tier!r}", remediation=f"Choose one of: {', '.join(sorted(TEST_TIERS))}."))
    if tier == "integration":
        capability = _name(capability or subsystem, field="integration capability")
        directory = f"tests/integration/{capability}"
    elif tier == "target":
        target = _name(target or subsystem, field="target")
        directory = f"tests/targets/{target}"
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


def plan_phase_scaffold(*, phase_kind: str, name: str) -> ScaffoldPlan:
    if phase_kind not in PHASE_KINDS:
        raise TestkitError(Diagnostic("error", "invalid_phase_kind", f"unsupported phase kind {phase_kind!r}", remediation=f"Choose one of: {', '.join(sorted(PHASE_KINDS))}."))
    name = _name(name, field="phase name")
    constructor = phase_kind.replace("-", "_")
    if phase_kind == "map-units":
        transform_signature = "def transform(context: PhaseContextV3, source: ArtifactRecordV3) -> ArtifactRecordV3:\n"
        transform_body = "    return ArtifactRecordV3.create(source.record_id, source.value.to_value())\n"
        constructor_arguments = (
            '    source_input="source",\n'
            '    input_artifact_kinds={"source": "source-v3"},\n'
            f'    output_artifact_kind={name!r} + "-v3",\n'
            "    transform=transform,\n"
        )
    elif phase_kind == "map-sccs":
        transform_signature = "def transform(context: PhaseContextV3, work_item: SccWorkItemV3) -> ArtifactRecordV3:\n"
        transform_body = "    return ArtifactRecordV3.create(work_item.record_id, {\"members\": list(work_item.scc.members)})\n"
        constructor_arguments = (
            '    input_artifact_kinds={"source": "source-v3"},\n'
            f'    output_artifact_kind={name!r} + "-v3",\n'
            "    transform=transform,\n"
        )
    else:
        transform_signature = "def transform(context: PhaseContextV3) -> ArtifactRecordV3:\n"
        transform_body = "    return ArtifactRecordV3.create(\"summary\", {\"status\": \"incomplete\"})\n\n\ndef check_complete(output, context: PhaseContextV3) -> None:\n    output.validate_completeness((\"summary\",))\n"
        constructor_arguments = (
            '    input_artifact_kinds={"source": "source-v3"},\n'
            f'    output_artifact_kind={name!r} + "-v3",\n'
            "    transform=transform,\n"
            "    completeness=check_complete,\n"
        )
    source = (
        f'"""{phase_kind} authority phase over typed v3 artifacts."""\n\n'
        "from __future__ import annotations\n\n"
        "from spaghetti_extractor.artifact_set_v3 import ArtifactRecordV3\n"
        "from spaghetti_extractor.phase_framework_v3 import (\n"
        "    PhaseContextV3,\n"
        "    SccWorkItemV3,\n"
        f"    {constructor},\n"
        ")\n\n\n"
        + transform_signature
        + transform_body
        + "\n\nPHASE = "
        + constructor
        + "(\n"
        + f"    name={name!r},\n"
        + '    version="1",\n'
        + constructor_arguments
        + ")\n"
    )
    test = (
        "from __future__ import annotations\n\n"
        "import unittest\n\n"
        f"from spaghetti_extractor.analysis_v3.{name} import PHASE\n\n\n"
        f"class {''.join(part.title() for part in name.split('_'))}PhaseTests(unittest.TestCase):\n"
        "    def test_declares_expected_phase_kind(self) -> None:\n"
        f"        self.assertEqual(PHASE.form, {constructor!r})\n"
    )
    nix = (
        "# Thin registration: execution, dependency tracking, and CA packing are shared.\n"
        "{ mkArtifactPhaseV3, inputs, bindings, schedule ? null }:\n"
        "mkArtifactPhaseV3 {\n"
        f"  name = {json.dumps('spaghetti-' + name + '-v3')};\n"
        f"  phaseReference = {json.dumps(f'spaghetti_extractor.analysis_v3.{name}:PHASE')};\n"
        f"  expectedKind = {json.dumps(name + '-v3')};\n"
        "  inherit inputs bindings schedule;\n"
        "}\n"
    )
    return ScaffoldPlan(
        kind="phase",
        name=name,
        files=(
            ScaffoldFile(f"src/spaghetti_extractor/analysis_v3/{name}.py", source, "typed v3 phase implementation"),
            ScaffoldFile(f"tests/unit/analysis_v3/test_{name}.py", test, "focused phase unit test"),
            ScaffoldFile(f"nix/phase-v3-{name}.nix", nix, "thin v3 phase registration"),
        ),
        next_commands=(
            f"nix run .#test -- affected --changed src/spaghetti_extractor/analysis_v3/{name}.py",
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


__all__ = [
    "PHASE_KINDS",
    "TEST_TIERS",
    "ScaffoldFile",
    "ScaffoldPlan",
    "apply_scaffold_plan",
    "plan_fixture_scaffold",
    "plan_phase_scaffold",
    "plan_test_scaffold",
]
