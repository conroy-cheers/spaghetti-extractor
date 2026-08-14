"""Explicit manifest for every supported public toolkit command."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


# Keep this declaration literal: python_module_index.py reads it without importing
# command implementations, making this the authority for public command roots.
SUPPORTED_COMMAND_MANIFEST: Final[tuple[dict[str, str], ...]] = (
    {
        "name": "project analyze",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "realize the target SDK analysis artifact family",
    },
    {
        "name": "project status",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "show the declared target project status",
    },
    {
        "name": "project check",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "run the target regression or acceptance gate",
    },
    {
        "name": "component build",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "build the target's default component runtime",
    },
    {
        "name": "candidate build",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "build the target's default static candidate",
    },
    {
        "name": "candidate test",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "run the target's candidate acceptance tests",
    },
    {
        "name": "expert stage-a-inventory-binary",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "classify every executable byte and recover static code regions",
    },
    {
        "name": "expert stage-a-export-behavioral-roots",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "bind PE entry, executable export, and immutable TLS callback roots",
    },
    {
        "name": "expert stage-a-export-opaque-reconstruction",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "emit the original-only reference contract and canonical state machine",
    },
    {
        "name": "expert stage-a-export-reference-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "emit reusable static constraints and source-mapped transfer contracts",
    },
    {
        "name": "expert stage-a-smoke-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "run the cheap reference-contract consistency gate",
    },
    {
        "name": "expert stage-a-explain-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "explain one static contract region, family, or issue",
    },
    {
        "name": "expert stage-a-diff-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "diff two static contract iterations",
    },
    {
        "name": "expert stage-a-expand-import-abi",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "bind reviewed ABI policy to exact PE imports",
    },
    {
        "name": "expert stage-a-inventory-isa",
        "group": "spaghetti_extractor.commands.isa",
        "help": "classify the instruction forms required by one static binary inventory",
    },
    {
        "name": "expert stage-a-check-isa-conformance",
        "group": "spaghetti_extractor.commands.isa",
        "help": "run one ISA oracle as a cached Nix derivation",
    },
    {
        "name": "expert stage-a-enrich-isa-catalog",
        "group": "spaghetti_extractor.commands.isa",
        "help": "replay static encodings and derive qualification metadata",
    },
    {
        "name": "expert stage-a-export-ghidra-proposal",
        "group": "spaghetti_extractor.commands.proposals",
        "help": "emit a binary-bound, non-authorizing Ghidra proposal",
    },
    {
        "name": "expert roundtrip-generate",
        "group": "spaghetti_extractor.commands.roundtrip",
        "help": "generate small PE32 static-analysis regression cases",
    },
    {
        "name": "expert roundtrip-run",
        "group": "spaghetti_extractor.commands.roundtrip",
        "help": "qualify generated PE32 extraction and violation localization",
    },
    {
        "name": "expert stage-a-export-machine-ir",
        "group": "spaghetti_extractor.commands.reconstruction",
        "help": "export deterministic byte-free executable machine IR",
    },
    {
        "name": "expert stage-b-build-candidate-authority",
        "group": "spaghetti_extractor.commands.authority",
        "help": "recompute the fail-closed v3 candidate-generation authority receipt",
    },
    {
        "name": "expert stage-b-validate-candidate-authority",
        "group": "spaghetti_extractor.commands.authority",
        "help": "recompute and validate a v3 candidate receipt against exact inputs",
    },
    {
        "name": "expert stage-b-generate-interpreter",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit the portable machine-IR interpreter package",
    },
    {
        "name": "expert stage-b-generate-native-engine",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit PE32 ABI bridges for the generated interpreter",
    },
    {
        "name": "expert stage-b-generate-native-runtime",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit the candidate-only external runtime package",
    },
    {
        "name": "expert stage-b-discover-components",
        "group": "spaghetti_extractor.commands.components",
        "help": "propose component coarsenings without authorizing replacement",
    },
    {
        "name": "expert stage-b-resolve-components",
        "group": "spaghetti_extractor.commands.components",
        "help": "resolve exact leaf, group, and configuration ownership from authored intent",
    },
    {
        "name": "expert stage-b-build-component-contract",
        "group": "spaghetti_extractor.commands.components",
        "help": "derive and check one independently liftable leaf or aggregate boundary",
    },
    {
        "name": "expert stage-b-package-component-source",
        "group": "spaghetti_extractor.commands.components",
        "help": "content-bind the exact portable source inputs for one lift unit",
    },
    {
        "name": "expert stage-b-produce-component-evidence",
        "group": "spaghetti_extractor.commands.components",
        "help": "produce candidate-only behavioral evidence for one portable component",
    },
    {
        "name": "expert stage-b-qualify-component",
        "group": "spaghetti_extractor.commands.components",
        "help": "bind exact evidence and source to one component contract",
    },
    {
        "name": "expert stage-b-compose-components",
        "group": "spaghetti_extractor.commands.components",
        "help": "compose one non-overlapping configuration with total machine-IR fallback",
    },
    {
        "name": "expert stage-b-build-component-runtime",
        "group": "spaghetti_extractor.commands.components",
        "help": "build the sole executable authority package for one component configuration",
    },
    {
        "name": "expert stage-b-render-source-operations",
        "group": "spaghetti_extractor.commands.source",
        "help": "render recovered external operations as non-authoritative C calls",
    },
    {
        "name": "expert stage-b-run-functional-suite",
        "group": "spaghetti_extractor.commands.validation",
        "help": "run curated candidate-only expected-output tests under headless Wine",
    },
)

# Keep this mapping literal for the module-index checker. Every exact operator
# or expert command path retains the role of the implementation root it exposes.
SUPPORTED_COMMAND_ROLES: Final[dict[str, str]] = {
    "project analyze": "operator",
    "project status": "operator",
    "project check": "operator",
    "component build": "operator",
    "candidate build": "operator",
    "candidate test": "operator",
    "expert stage-a-inventory-binary": "proposal",
    "expert stage-a-export-behavioral-roots": "proposal",
    "expert stage-a-export-opaque-reconstruction": "proposal",
    "expert stage-a-export-reference-contract": "proposal",
    "expert stage-a-smoke-contract": "diagnostic",
    "expert stage-a-explain-contract": "diagnostic",
    "expert stage-a-diff-contract": "diagnostic",
    "expert stage-a-expand-import-abi": "proposal",
    "expert stage-a-inventory-isa": "proposal",
    "expert stage-a-check-isa-conformance": "expert",
    "expert stage-a-enrich-isa-catalog": "proposal",
    "expert stage-a-export-ghidra-proposal": "proposal",
    "expert roundtrip-generate": "proposal",
    "expert roundtrip-run": "proposal",
    "expert stage-a-export-machine-ir": "proposal",
    "expert stage-b-build-candidate-authority": "expert",
    "expert stage-b-validate-candidate-authority": "expert",
    "expert stage-b-generate-interpreter": "expert",
    "expert stage-b-generate-native-engine": "expert",
    "expert stage-b-generate-native-runtime": "expert",
    "expert stage-b-discover-components": "proposal",
    "expert stage-b-resolve-components": "expert",
    "expert stage-b-build-component-contract": "expert",
    "expert stage-b-package-component-source": "expert",
    "expert stage-b-produce-component-evidence": "expert",
    "expert stage-b-qualify-component": "expert",
    "expert stage-b-compose-components": "expert",
    "expert stage-b-build-component-runtime": "expert",
    "expert stage-b-render-source-operations": "diagnostic",
    "expert stage-b-run-functional-suite": "diagnostic",
}


@dataclass(frozen=True)
class CommandSpec:
    name: str
    group: str
    help: str
    role: str

    @property
    def path(self) -> tuple[str, str]:
        namespace, command = self.name.split(" ", 1)
        return namespace, command

    @property
    def implementation_name(self) -> str:
        namespace, command = self.path
        return command if namespace == "expert" else self.name


def _load_manifest() -> tuple[CommandSpec, ...]:
    names_in_manifest = {row["name"] for row in SUPPORTED_COMMAND_MANIFEST}
    if names_in_manifest != set(SUPPORTED_COMMAND_ROLES):
        raise RuntimeError("supported command roles do not match the command manifest")
    commands = tuple(
        CommandSpec(**row, role=SUPPORTED_COMMAND_ROLES[row["name"]])
        for row in SUPPORTED_COMMAND_MANIFEST
    )
    names = [command.name for command in commands]
    if len(set(names)) != len(names):
        raise RuntimeError("supported command manifest contains duplicate names")
    if any(not command.group.startswith("spaghetti_extractor.commands.") for command in commands):
        raise RuntimeError("supported command group escapes the commands package")
    return commands


SUPPORTED_COMMANDS: Final = _load_manifest()
COMMANDS_BY_NAME: Final = MappingProxyType(
    {command.name: command for command in SUPPORTED_COMMANDS}
)


__all__ = [
    "COMMANDS_BY_NAME",
    "SUPPORTED_COMMAND_MANIFEST",
    "SUPPORTED_COMMAND_ROLES",
    "SUPPORTED_COMMANDS",
    "CommandSpec",
]
