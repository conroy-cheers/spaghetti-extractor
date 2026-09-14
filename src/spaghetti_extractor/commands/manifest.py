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
        "help": "show ranked static-authority repair frontiers",
    },
    {
        "name": "project check",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "run the target regression or acceptance gate",
    },
    {
        "name": "component list",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "list authored component units and their available products",
    },
    {
        "name": "component status",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "show checked component refinement and activation status",
    },
    {
        "name": "component build",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "build one component unit work package",
    },
    {
        "name": "component start",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "materialize checked component scaffolding or start its source intent",
    },
    {
        "name": "component check",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "require component qualification, or check source with --source",
    },
    {
        "name": "boundary status",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "show typed call transport, lifecycle, and idiomatic-view frontiers",
    },
    {
        "name": "boundary inspect",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "inspect one checked or proposed call protocol",
    },
    {
        "name": "boundary propose",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "build compiler-assisted and machine-checked call proposals",
    },
    {
        "name": "boundary adopt",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "write stable operator intent for one call subject",
    },
    {
        "name": "boundary check",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "require complete checked call-protocol authority",
    },
    {
        "name": "library status",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "show checked library constellation matches and lifting payoff",
    },
    {
        "name": "library inspect",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "inspect one library hypothesis, family, or target RVA",
    },
    {
        "name": "library adopt",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "record a content-bound linked-library island adoption intent",
    },
    {
        "name": "library check",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "require complete identity, boundary, and implementation evidence",
    },
    {
        "name": "candidate list",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "list candidate configurations and declared test suites",
    },
    {
        "name": "candidate status",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "show provider-selection readiness for one configuration",
    },
    {
        "name": "candidate build",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "build the target's default static candidate",
    },
    {
        "name": "candidate test",
        "group": "spaghetti_extractor.commands.workflows",
        "help": "run declared candidate-only expected-output tests",
    },
    {
        "name": "expert static-inventory-binary",
        "group": "spaghetti_extractor.commands.proposal_static",
        "help": "classify every executable byte and recover static code regions",
    },
    {
        "name": "expert static-export-roots",
        "group": "spaghetti_extractor.commands.proposal_static",
        "help": "bind PE entry, executable export, and immutable TLS callback roots",
    },
    {
        "name": "expert static-program-export",
        "group": "spaghetti_extractor.commands.proposal_static",
        "help": "emit the original-only static program and canonical state machine",
    },
    {
        "name": "expert external-bind-import-abi",
        "group": "spaghetti_extractor.commands.proposal_static",
        "help": "bind reviewed ABI policy to exact PE imports",
    },
    {
        "name": "expert isa-inventory",
        "group": "spaghetti_extractor.commands.proposal_isa",
        "help": "classify the instruction forms required by one static binary inventory",
    },
    {
        "name": "expert isa-check-conformance",
        "group": "spaghetti_extractor.commands.expert_isa",
        "help": "run one ISA oracle as a cached Nix derivation",
    },
    {
        "name": "expert isa-enrich-catalog",
        "group": "spaghetti_extractor.commands.proposal_isa",
        "help": "replay static encodings and derive qualification metadata",
    },
    {
        "name": "expert static-export-ghidra-proposal",
        "group": "spaghetti_extractor.commands.proposals",
        "help": "emit a binary-bound, non-authorizing Ghidra proposal",
    },
    {
        "name": "expert semantic-diagnose",
        "group": "spaghetti_extractor.commands.semantic_diagnostics",
        "help": "inspect semantic blockers, caller sites, input dependencies, slices, or deltas",
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
        "name": "expert machine-ir-export",
        "group": "spaghetti_extractor.commands.reconstruction",
        "help": "export deterministic byte-free executable machine IR",
    },
    {
        "name": "expert candidate-transfer-plan",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "compile exact checked machine IR into the canonical executable transfer plan",
    },
    {
        "name": "expert candidate-generate-behavioral-c",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit faithful direct C plus exact coverage and runtime receipts",
    },
    {
        "name": "expert candidate-module-interface",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "emit one exact PE32 loader-visible module interface",
    },
    {
        "name": "expert candidate-object-authority",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "derive loader-relative object and data-export authority",
    },
    {
        "name": "expert candidate-project-load-plan",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "build a checked multi-image import-slot load plan",
    },
    {
        "name": "expert candidate-observed-load-graph",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "check a content-bound loader observation against a project load plan",
    },
    {
        "name": "expert candidate-project-completion",
        "group": "spaghetti_extractor.commands.runtime",
        "help": "reduce per-image and host-load evidence into project completion",
    },
    {
        "name": "expert component-discover",
        "group": "spaghetti_extractor.commands.proposal_components",
        "help": "propose component coarsenings without authorizing replacement",
    },
    {
        "name": "expert component-render-source-operations",
        "group": "spaghetti_extractor.commands.source",
        "help": "render recovered external operations as non-authoritative C calls",
    },
    {
        "name": "expert call-protocol-check",
        "group": "spaghetti_extractor.commands.call_protocols",
        "help": "check one typed call protocol against dialect and relation laws",
    },
    {
        "name": "expert boundary-check",
        "group": "spaghetti_extractor.commands.boundaries",
        "help": "validate a shared boundary schema, target layout, and ABI frames",
    },
    {
        "name": "expert candidate-test-suite-run",
        "group": "spaghetti_extractor.commands.validation",
        "help": "run a curated candidate-only test suite",
    },
)

# Keep this mapping literal for the module-index checker. Every exact operator
# or expert command path retains the role of the implementation root it exposes.
SUPPORTED_COMMAND_ROLES: Final[dict[str, str]] = {
    "project analyze": "operator",
    "project status": "operator",
    "project check": "operator",
    "component list": "operator",
    "component status": "operator",
    "component build": "operator",
    "component start": "operator",
    "component check": "operator",
    "boundary status": "operator",
    "boundary inspect": "operator",
    "boundary propose": "operator",
    "boundary adopt": "operator",
    "boundary check": "operator",
    "library status": "operator",
    "library inspect": "operator",
    "library adopt": "operator",
    "library check": "operator",
    "candidate list": "operator",
    "candidate status": "operator",
    "candidate build": "operator",
    "candidate test": "operator",
    "expert static-inventory-binary": "proposal",
    "expert static-export-roots": "proposal",
    "expert static-program-export": "proposal",
    "expert external-bind-import-abi": "proposal",
    "expert isa-inventory": "proposal",
    "expert isa-check-conformance": "expert",
    "expert isa-enrich-catalog": "proposal",
    "expert static-export-ghidra-proposal": "proposal",
    "expert semantic-diagnose": "diagnostic",
    "expert roundtrip-generate": "proposal",
    "expert roundtrip-run": "proposal",
    "expert machine-ir-export": "proposal",
    "expert candidate-generate-behavioral-c": "expert",
    "expert candidate-transfer-plan": "expert",
    "expert candidate-module-interface": "expert",
    "expert candidate-object-authority": "expert",
    "expert candidate-project-load-plan": "expert",
    "expert candidate-observed-load-graph": "expert",
    "expert candidate-project-completion": "expert",
    "expert component-discover": "proposal",
    "expert component-render-source-operations": "diagnostic",
    "expert call-protocol-check": "expert",
    "expert boundary-check": "expert",
    "expert candidate-test-suite-run": "diagnostic",
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
