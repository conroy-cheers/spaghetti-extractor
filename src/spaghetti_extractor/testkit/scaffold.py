"""Render convention-correct scaffolding without hidden repository mutation."""

from __future__ import annotations

from dataclasses import dataclass
import json
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
            f"python -m unittest {path}",
            "python -m spaghetti_extractor.testkit plan affected --changed " + path,
        ),
    )


def plan_phase_scaffold(*, phase_kind: str, name: str) -> ScaffoldPlan:
    if phase_kind not in PHASE_KINDS:
        raise TestkitError(Diagnostic("error", "invalid_phase_kind", f"unsupported phase kind {phase_kind!r}", remediation=f"Choose one of: {', '.join(sorted(PHASE_KINDS))}."))
    name = _name(name, field="phase name")
    function = f"run_{name}"
    source = (
        f'"""{phase_kind} analysis phase."""\n\n'
        "from __future__ import annotations\n\n"
        "from collections.abc import Iterable\n"
        "from typing import TypeVar\n\n"
        "Input = TypeVar(\"Input\")\n"
        "Output = TypeVar(\"Output\")\n\n"
        f"PHASE_KIND = {phase_kind!r}\n\n\n"
        f"def {function}(records: Iterable[Input]) -> tuple[Output, ...]:\n"
        "    \"\"\"Transform declared inputs; artifact identity and packing are framework-owned.\"\"\"\n"
        "    raise NotImplementedError\n"
    )
    test = (
        "from __future__ import annotations\n\n"
        "import unittest\n\n"
        f"from spaghetti_extractor.analysis.{name} import PHASE_KIND\n\n\n"
        f"class {''.join(part.title() for part in name.split('_'))}PhaseTests(unittest.TestCase):\n"
        "    def test_declares_expected_phase_kind(self) -> None:\n"
        f"        self.assertEqual(PHASE_KIND, {phase_kind!r})\n"
    )
    nix = (
        "# Register this implementation through the shared phase framework.\n"
        "{ mkAnalysisPhase }:\n"
        "mkAnalysisPhase {\n"
        f"  name = {json.dumps(name)};\n"
        f"  kind = {json.dumps(phase_kind)};\n"
        f"  pythonModule = {json.dumps(f'spaghetti_extractor.analysis.{name}')};\n"
        "}\n"
    )
    return ScaffoldPlan(
        kind="phase",
        name=name,
        files=(
            ScaffoldFile(f"src/spaghetti_extractor/analysis/{name}.py", source, "typed phase implementation"),
            ScaffoldFile(f"tests/unit/analysis/test_{name}.py", test, "focused phase unit test"),
            ScaffoldFile(f"nix/phase-{name}.nix", nix, "thin phase registration"),
        ),
        next_commands=(
            f"python -m unittest tests/unit/analysis/test_{name}.py",
            f"python -m spaghetti_extractor.testkit plan affected --changed src/spaghetti_extractor/analysis/{name}.py",
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
            f"python -m spaghetti_extractor.testkit fixtures {identifier}",
        ),
    )


__all__ = [
    "PHASE_KINDS",
    "TEST_TIERS",
    "ScaffoldFile",
    "ScaffoldPlan",
    "plan_fixture_scaffold",
    "plan_phase_scaffold",
    "plan_test_scaffold",
]
