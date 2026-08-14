"""Explicit manifest for every supported public toolkit command."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


# Keep this declaration literal: python_module_index.py reads it without importing
# command implementations, making this the authority for public command roots.
SUPPORTED_COMMAND_MANIFEST: Final[tuple[dict[str, str], ...]] = (
    {
        "name": "stage-a-inventory-binary",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "classify every executable byte and recover static code regions",
    },
    {
        "name": "stage-a-export-behavioral-roots",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "bind PE entry, executable export, and immutable TLS callback roots",
    },
    {
        "name": "stage-a-export-opaque-reconstruction",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "emit the original-only reference contract and canonical state machine",
    },
    {
        "name": "stage-a-export-reference-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "emit reusable static constraints and source-mapped transfer contracts",
    },
    {
        "name": "stage-a-smoke-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "run the cheap reference-contract consistency gate",
    },
    {
        "name": "stage-a-explain-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "explain one static contract region, family, or issue",
    },
    {
        "name": "stage-a-diff-contract",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "diff two static contract iterations",
    },
    {
        "name": "stage-a-expand-import-abi",
        "group": "spaghetti_extractor.commands.static_analysis",
        "help": "bind reviewed ABI policy to exact PE imports",
    },
    {
        "name": "stage-a-inventory-isa",
        "group": "spaghetti_extractor.commands.isa",
        "help": "classify the instruction forms required by one static binary inventory",
    },
    {
        "name": "stage-a-check-isa-conformance",
        "group": "spaghetti_extractor.commands.isa",
        "help": "run one ISA oracle as a cached Nix derivation",
    },
    {
        "name": "stage-a-check-isa-conformance-worker",
        "group": "spaghetti_extractor.commands.isa",
        "help": "internal Nix worker for one concrete ISA oracle",
    },
    {
        "name": "stage-a-enrich-isa-catalog",
        "group": "spaghetti_extractor.commands.isa",
        "help": "replay static encodings and derive qualification metadata",
    },
    {
        "name": "roundtrip-generate",
        "group": "spaghetti_extractor.commands.roundtrip",
        "help": "generate small PE32 static-analysis regression cases",
    },
    {
        "name": "roundtrip-run",
        "group": "spaghetti_extractor.commands.roundtrip",
        "help": "qualify generated PE32 extraction and violation localization",
    },
    {
        "name": "stage-a-export-machine-ir",
        "group": "spaghetti_extractor.commands.reconstruction",
        "help": "export deterministic byte-free executable machine IR",
    },
    {
        "name": "stage-b-build-candidate-authority-v3",
        "group": "spaghetti_extractor.commands.authority",
        "help": "recompute the fail-closed v3 candidate-generation authority receipt",
    },
    {
        "name": "stage-b-validate-candidate-authority-v3",
        "group": "spaghetti_extractor.commands.authority",
        "help": "recompute and validate a v3 candidate receipt against exact inputs",
    },
    {
        "name": "stage-b-generate-interpreter",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit the portable machine-IR interpreter package",
    },
    {
        "name": "stage-b-generate-native-engine",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit PE32 ABI bridges for the generated interpreter",
    },
    {
        "name": "stage-b-generate-native-runtime",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit the candidate-only external runtime package",
    },
    {
        "name": "stage-b-discover-components",
        "group": "spaghetti_extractor.commands.components",
        "help": "propose component coarsenings without authorizing replacement",
    },
    {
        "name": "stage-b-resolve-components",
        "group": "spaghetti_extractor.commands.components",
        "help": "resolve exact leaf, group, and configuration ownership from authored intent",
    },
    {
        "name": "stage-b-build-component-contract",
        "group": "spaghetti_extractor.commands.components",
        "help": "derive and check one independently liftable leaf or aggregate boundary",
    },
    {
        "name": "stage-b-package-component-source",
        "group": "spaghetti_extractor.commands.components",
        "help": "content-bind the exact portable source inputs for one lift unit",
    },
    {
        "name": "stage-b-produce-component-evidence",
        "group": "spaghetti_extractor.commands.components",
        "help": "produce candidate-only behavioral evidence for one portable component",
    },
    {
        "name": "stage-b-qualify-component",
        "group": "spaghetti_extractor.commands.components",
        "help": "bind exact evidence and source to one component contract",
    },
    {
        "name": "stage-b-compose-components",
        "group": "spaghetti_extractor.commands.components",
        "help": "compose one non-overlapping configuration with total machine-IR fallback",
    },
    {
        "name": "stage-b-build-component-runtime",
        "group": "spaghetti_extractor.commands.components",
        "help": "build the sole executable authority package for one component configuration",
    },
    {
        "name": "stage-b-render-source-operations",
        "group": "spaghetti_extractor.commands.source",
        "help": "render recovered external operations as non-authoritative C calls",
    },
    {
        "name": "stage-b-run-functional-suite",
        "group": "spaghetti_extractor.commands.validation",
        "help": "run curated candidate-only expected-output tests under headless Wine",
    },
)


@dataclass(frozen=True)
class CommandSpec:
    name: str
    group: str
    help: str


def _load_manifest() -> tuple[CommandSpec, ...]:
    commands = tuple(CommandSpec(**row) for row in SUPPORTED_COMMAND_MANIFEST)
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
    "SUPPORTED_COMMANDS",
    "CommandSpec",
]
