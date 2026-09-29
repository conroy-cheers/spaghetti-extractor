"""CLI option definitions for the shared operator workflow handlers."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from .common import Handler
from . import workflows as handlers


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

_BOUNDARY_SUBJECT = re.compile(
    r"(?:call|callback|export|component|component-seed|component_operation|service):"
    r"[a-z0-9][a-z0-9._-]*"
)

def _identifier(value: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "identifier must contain only letters, digits, '.', '_', or '-'"
        )
    return value


def _opaque_identity(value: str) -> str:
    if not value or len(value) > 512 or any(
        character.isspace() or ord(character) < 0x20 for character in value
    ):
        raise argparse.ArgumentTypeError(
            "identity must be nonempty, bounded, and contain no whitespace"
        )
    return value


def _boundary_subject_identity(value: str) -> str:
    if _BOUNDARY_SUBJECT.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "boundary subject must be a stable kind:id identity"
        )
    return value


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", type=_identifier, help="registered target id")
    parser.add_argument(
        "--target-flake",
        default="./targets",
        metavar="REF",
        help="target corpus flake reference (default: ./targets)",
    )
    execution = parser.add_mutually_exclusive_group()
    execution.add_argument(
        "--builders-file",
        type=Path,
        metavar="FILE",
        help=(
            "Nix builders inventory; defaults to "
            "$SPAGHETTI_EXTRACTOR_BUILDERS_FILE or the nearest "
            "nix/builders.local, then XDG configuration"
        ),
    )
    execution.add_argument(
        "--local",
        action="store_true",
        help="disable remote Nix builders for this command",
    )
    parser.add_argument(
        "--trusted-public-keys-file",
        type=Path,
        metavar="FILE",
        help=(
            "trusted Nix cache keys; defaults to "
            "$SPAGHETTI_EXTRACTOR_TRUSTED_PUBLIC_KEYS_FILE, a companion "
            "nix/trusted-public-keys.local, then XDG configuration"
        ),
    )


def _parse_rva(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("RVA must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("RVA must not be negative")
    return parsed


def _add_component_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("unit", type=_identifier, help="component unit id")


def _add_progress_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--limit", type=_positive, default=20)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--family")
    parser.add_argument("--code")
    parser.add_argument("--details", action="store_true")



def configure_workflow_command(name: str, parser: argparse.ArgumentParser) -> Handler:
    _add_target_arguments(parser)
    if name == "boundary inventory":
        parser.add_argument("--partition", type=Path, required=True)
        parser.add_argument("--semantic-module", type=Path, required=True,
                            help="retained linked-semantic-module.json and its package members")
        parser.add_argument("--bindings", type=Path, help="existing V5 machine-binding index")
        parser.add_argument("--interfaces", type=Path, help="existing V5 interface index")
        parser.add_argument("--qualification", type=Path, action="append", default=[])
        parser.add_argument("--output", type=Path, required=True)
        return handlers._boundary_inventory
    if name == "project analyze":
        return handlers._project_analyze
    if name == "project status":
        _add_progress_arguments(parser)
        return handlers._project_status
    if name == "project check":
        parser.add_argument("--acceptance", action="store_true")
        return handlers._project_check
    if name == "component list":
        origin=parser.add_mutually_exclusive_group()
        origin.add_argument('--comparison-package', type=Path, metavar='DIR',
                            help='list selected components and caller requirements in a local workspace without building target products')
        origin.add_argument('--source-project', type=Path, metavar='DIR',
                            help='browse an exported component library and its reusable declarations without its comparison workspaces')
        parser.add_argument('--services', action='store_true',
                            help='with --comparison-package or --source-project, browse existing service contracts and binding information')
        parser.add_argument('--service', action='append', metavar='QUERY',
                            help='inspect services matching a component, service name, contract identity or C adapter (repeatable; implies --services)')
        parser.add_argument("--near", type=_parse_rva, metavar="RVA",
                            help="list bounded boundary alternatives at this instruction")
        parser.add_argument("--json", action="store_true")
        return handlers._component_list
    if name in {
        "component status", "component build", "component start", "component check",
    }:
        _add_component_selector(parser)
        if name != 'component build':
            parser.add_argument('--dependency-source', action='append', metavar='COMPONENT=DIR',
                                help='import only the named component C from a comparison, source project or matching interface authoring workspace, retaining consumer adapters and other selected bodies')
        if name == "component status":
            _add_progress_arguments(parser)
            comparison = parser.add_mutually_exclusive_group()
            comparison.add_argument('--comparison-package', type=Path, metavar='DIR',
                                help='show a local component overview, including selected suppliers; --details shows the full boundary without building target products')
            comparison.add_argument('--comparison-result', type=Path, metavar='DIR',
                                help='inspect retained evidence without rerunning; a selected supplier or --details shows case participation and inputs')
            parser.add_argument('--dependency-package', action='append', metavar='COMPONENT=DIR',
                                help='with --comparison-package, preview supplier packages or exported C drafts and their consumers without modifying the workspace')
            parser.add_argument('--reuse-comparison', type=Path, metavar='DIR',
                                help='with --comparison-package, preview edits, affected consumers and cache eligibility against a retained result')
            parser.add_argument('--case', metavar='NAME',
                                help='select a named case for a reuse preview, or filter retained-result inspection without changing replay selection')
            parser.add_argument(
                "--development",
                action="store_true",
                help=(
                    "show contract/source progress without requiring machine-derived "
                    "activation authority"
                ),
            )
            return handlers._component_status
        if name == "component build":
            return handlers._component_build
        if name == "component start":
            origin=parser.add_mutually_exclusive_group()
            origin.add_argument('--comparison-package', type=Path, metavar='DIR',
                                help='prepare an editable concrete comparison package with --output')
            origin.add_argument('--comparison-result', type=Path, metavar='DIR',
                                help='reopen retained comparison inputs and print the next check with that result as its reuse baseline')
            origin.add_argument('--experimental-package', type=Path, metavar='DIR',
                                help='reopen the named component or main program from a retained experiment')
            origin.add_argument('--interface-intent', type=Path, metavar='FILE',
                                help='start C authoring from a reviewed interface, before preparing executable comparison adapters')
            parser.add_argument('--service-catalog', type=Path, metavar='FILE',
                                help='with --interface-intent, retain the existing exact service contract catalog beside the C')
            parser.add_argument('--service-bridge', type=Path, metavar='FILE',
                                help='with --interface-intent, retain reviewed service binding choices and generate their C bridge')
            parser.add_argument('--state-owners', type=Path, metavar='FILE',
                                help='with --interface-intent, declare shared state owners, authored storage and runtime lifetime for practical comparisons')
            parser.add_argument('--resource-checks', type=Path, metavar='FILE',
                                help='with --interface-intent, retain reviewed resource observations and generate their runtime support')
            parser.add_argument('--adapter-file', action='append', metavar='NAME=FILE',
                                help='with --interface-intent, add or replace adapter C under adapters/ (repeatable)')
            parser.add_argument('--include-file', action='append', metavar='NAME=FILE',
                                help='with --interface-intent, add or replace adapter support files under headers/ (repeatable)')
            parser.add_argument('--assumption-file', type=Path, action='append', metavar='FILE',
                                help='with --interface-intent, retain each file as one boundary assumption (repeatable; replaces inherited assumptions)')
            parser.add_argument('--operation-symbol', action='append', metavar='OPERATION=SYMBOL',
                                help='with --interface-intent, choose a C operation name; retained entries keep their names, new entries use lifted_COMPONENT_OPERATION')
            parser.add_argument('--compiler', type=Path, metavar='FILE',
                                help='with --interface-intent, select the editor/syntax-check compiler (default: retained choice, otherwise cc)')
            parser.add_argument('--reuse-source', type=Path, metavar='DIR',
                                help='carry authored C into a new draft; comparisons/experiments accept comparison workspaces, source exports or matching interface authoring workspaces; --interface-intent reuses interface authoring workspaces')
            parser.add_argument('--reuse-cases', type=Path, action='append', metavar='DIR',
                                help='with a comparison or experiment, append case definitions from a package or result, retaining the current C and driver (repeatable)')
            parser.add_argument('--case-file', type=Path, action='append', metavar='FILE',
                                help='append a JSON list of case definitions to the current comparison setup, retaining C and the driver (repeatable)')
            parser.add_argument('--source-file', action='append', metavar='NAME=FILE',
                                help='add or replace authored C/header files in the focused component, after --reuse-source if supplied; NAME includes source/ (repeatable)')
            parser.add_argument('--remove-source', action='append', metavar='NAME',
                                help='retire an authored file from the new draft; NAME includes source/ (repeatable)')
            parser.add_argument('--private-header', action='append', metavar='NAME',
                                help='declare a new implementation-only helper header; existing header roles stay fixed (repeatable)')
            parser.add_argument('--dependency-package', action='append', metavar='COMPONENT=DIR',
                                help='with a comparison or experiment, retain a supplier package or its exported C draft under the existing contracts, without executing checks')
            parser.add_argument('--refine-requirement', action='append', metavar='REQUIREMENT=DIR',
                                help='review a supplier for CONSUMER/REQUIREMENT (or a bare root requirement) in the selected network; prepare an unverified draft')
            destination = parser.add_mutually_exclusive_group(required=True)
            destination.add_argument(
                "--output", type=Path, metavar="DIR",
                help="copy the checked package into a writable directory",
            )
            destination.add_argument(
                "--apply", action="store_true",
                help="atomically add the skeleton and its canonical source intent",
            )
            return handlers._component_start
        parser.add_argument('--comparison-package', type=Path, metavar='DIR',
                            help='compare original and authored C; a selected supplier runs the enclosing consumer cases and retains consumer evidence')
        parser.add_argument('--authoring-workspace', type=Path, metavar='DIR',
                            help='with --source, check current interface-first C on host/PE32 before a comparison exists; no target build or original execution')
        parser.add_argument('--compiler-view', action='store_true',
                            help='retain diagnostic active C and macro definitions for the selected compilation; requires an authoring workspace or comparison package')
        destinations=parser.add_mutually_exclusive_group()
        destinations.add_argument('--output', type=Path, metavar='DIR',
                                  help='retain comparison inputs/observations, or interface-workspace source feedback')
        destinations.add_argument('--history', type=Path, metavar='DIR',
                                  help='retain each check in a new directory and reuse the previous result automatically; latest points to the completed check')
        parser.add_argument('--history-baseline', type=Path, metavar='DIR',
                            help='with --history, reuse this result only until the history has its first completed check')
        parser.add_argument('--case', metavar='ID', help='with --comparison-package, run one retained case')
        parser.add_argument('--case-arguments', metavar='JSON',
                            help='with --case, try a named case using a JSON array of driver argument strings; retain it in the result without editing the workspace')
        parser.add_argument('--reuse-comparison', type=Path, metavar='DIR',
                            help='reuse matching retained concrete evidence if its consumed inputs are unchanged')
        parser.add_argument('--rerun', action='store_true',
                            help='execute cases again; with --reuse-comparison retain valid compiled objects but rerun observations')
        parser.add_argument('--dependency-package', action='append', metavar='COMPONENT=DIR',
                            help='use a supplier package or its exported C draft under the exact retained interface and assumptions')
        parser.add_argument('--comparison-timeout', type=_positive, default=60, metavar='SECONDS',
                            help='per-process concrete comparison deadline')
        parser.add_argument("--source", action="store_true",
                            help="check source compilation/profile without requiring or granting qualification")
        parser.add_argument('--compare-baseline', action='store_true',
                            help='with --source, compare a configured source edit; does not import baseline application proofs')
        parser.add_argument("--conditional", action="store_true",
                            help="check under configured runtime contracts without provider or activation authority")
        parser.add_argument('--region', action='append', metavar='OPERATION/OBLIGATION',
                            help='check selected proof regions without qualification; keep omitted coverage unresolved (repeatable)')
        parser.add_argument('--reuse-proof', type=Path, metavar='DIR',
                            help='reuse matching retained ordinary proof evidence; recheck all remaining obligations')
        parser.add_argument('--query-timeout', type=_positive, metavar='SECONDS',
                            help='with --region, --reuse-proof, --conditional or concrete --local-contracts, override the per-query timeout')
        parser.add_argument('--entry-query-timeout', type=_positive, metavar='SECONDS',
                            help='with --conditional, give independent entry queries their own timeout; defaults to --query-timeout')
        parser.add_argument("--local-contracts", action="store_true",
                            help="check configured --source contracts or optional concrete-package memory contracts without provider authority")
        parser.add_argument("--json", action="store_true", help="show structured checking feedback or provider qualification")
        return handlers._component_check
    if name == "boundary status":
        parser.add_argument("--json", action="store_true")
        return handlers._boundary_status
    if name in {
        "boundary inspect",
        "boundary propose",
        "boundary adopt",
        "boundary check",
    }:
        parser.add_argument("subject", type=_boundary_subject_identity)
        if name in {"boundary inspect", "boundary propose"}:
            parser.add_argument("--proposal", type=_opaque_identity, metavar="ID",
                                help="select an explicit component-seed alternative")
        if name == "boundary inspect":
            parser.add_argument("--json", action="store_true")
            return handlers._boundary_inspect
        if name == "boundary propose":
            parser.add_argument("--output", type=Path, metavar="DIR")
            return handlers._boundary_propose
        if name == "boundary adopt":
            parser.add_argument("--input", type=Path, metavar="DIR",
                                help="edited component or seed package with canonical inputs, or a declared caller definition")
            destination = parser.add_mutually_exclusive_group()
            destination.add_argument("--output", type=Path, metavar="PATH")
            destination.add_argument("--apply", action="store_true",
                                     help="apply reviewed configured declarations to the local target; does not install draft C")
            return handlers._boundary_adopt
        return handlers._boundary_check
    if name == "library status":
        parser.add_argument("--json", action="store_true")
        return handlers._library_status
    if name == "library inspect":
        selector = parser.add_mutually_exclusive_group(required=True)
        selector.add_argument("--rva", type=_parse_rva)
        selector.add_argument("--island", type=_opaque_identity)
        selector.add_argument("--family", type=_opaque_identity)
        parser.add_argument("--json", action="store_true")
        return handlers._library_inspect
    if name == "library adopt":
        parser.add_argument("--island", required=True, type=_opaque_identity)
        selection = parser.add_mutually_exclusive_group(required=True)
        selection.add_argument(
            "--recipe",
            type=_opaque_identity,
            help="adopt the uniquely matching reusable implementation recipe",
        )
        selection.add_argument(
            "--draft",
            type=_opaque_identity,
            metavar="RECIPE",
            help="record an implementation recipe that still needs qualification",
        )
        parser.add_argument("--replace", action="store_true")
        parser.add_argument("--dry-run", action="store_true")
        return handlers._library_adopt
    if name == "library check":
        parser.add_argument("--selection", type=_opaque_identity)
        return handlers._library_check
    if name == "candidate list":
        parser.add_argument("--json", action="store_true")
        return handlers._candidate_list
    if name == "candidate status":
        parser.add_argument("--configuration", type=_identifier)
        parser.add_argument('--reuse-proof', action='append', metavar='COMPONENT=DIR',
                            help='reuse matching proof evidence while checking current selected components (repeatable)')
        _add_progress_arguments(parser)
        return handlers._candidate_status
    if name == "candidate policy":
        parser.add_argument('--comparison', type=Path, required=True, metavar='DIR')
        parser.add_argument('--configuration', type=_identifier, required=True)
        parser.add_argument('--component-comparison', action='append', metavar='COMPONENT=DIR')
        parser.add_argument('--network-only', action='append', default=[], metavar='COMPONENT',
                            help='explicitly rely on network cases without requiring a separate component receipt (repeatable)')
        parser.add_argument('--output', type=Path, required=True, metavar='DIR')
        return handlers._candidate_policy
    if name == "candidate build":
        parser.add_argument("--configuration", type=_identifier)
        parser.add_argument('--reuse-proof', action='append', metavar='COMPONENT=DIR',
                            help='reuse matching proof evidence while building current selected components (repeatable)')
        parser.add_argument("--experimental-comparison", type=Path, metavar="DIR")
        parser.add_argument("--component-comparison", action="append", metavar="COMPONENT=DIR")
        parser.add_argument("--experimental-policy", type=Path, metavar="FILE")
        parser.add_argument('--reuse-experimental', type=Path, metavar='DIR',
                            help='reuse the previous experiment policy and unchanged component receipts; supply fresh checks for changed units')
        parser.add_argument("--output", type=Path, metavar="DIR")
        return handlers._candidate_build
    if name == "candidate apply":
        parser.add_argument('--project', type=Path, required=True, metavar='DIR')
        parser.add_argument('--comparison', type=Path, action='append', default=[], metavar='DIR',
                            help='matching retained comparisons for changed components; omit for binding-only changes')
        parser.add_argument('--component', action='append', metavar='COMPONENT')
        parser.add_argument('--remove-component', action='append', metavar='COMPONENT')
        parser.add_argument('--accept-boundary-change', action='append', default=[], metavar='COMPONENT')
        parser.add_argument('--assembly-command', required=True, metavar='COMMAND',
                            help='quoted command for the existing target assembly recipe; runs without a shell in a staged project; {project} expands to its path')
        parser.add_argument('--check-command', action='append', default=[], metavar='COMMAND',
                            help='build or workload command to pass before publication (repeatable); same expansion as --assembly-command')
        return handlers._candidate_apply
    if name == "candidate export":
        parser.add_argument('--comparison', type=Path, action='append', required=True, metavar='DIR',
                            help='matching retained comparison; include selected dependencies (repeatable)')
        parser.add_argument('--output', type=Path, required=True, metavar='DIR')
        updates=parser.add_mutually_exclusive_group()
        updates.add_argument('--update', action='store_true',
                            help='refresh an existing library with the same boundaries, preserving operator files and a backup')
        updates.add_argument('--update-components', action='store_true',
                            help='refresh only components in the supplied comparisons; retain other components from the existing library')
        parser.add_argument('--component', action='append', metavar='COMPONENT',
                            help='with --update-components, publish only this compared component (repeatable); retain neighboring C drafts')
        parser.add_argument('--remove-component', action='append', metavar='COMPONENT',
                            help='with --update-components, remove a reviewed superseded component (repeatable); update its consumers and program bindings')
        parser.add_argument('--accept-boundary-change', action='append', default=[], metavar='COMPONENT',
                            help='accept reviewed boundary/header changes or a new component with --update-components; recheck application/backend integration')
        return handlers._candidate_export
    if name == "candidate test":
        parser.add_argument("--suite", type=_identifier)
        parser.add_argument("--experimental-package", type=Path, metavar="DIR")
        parser.add_argument("--experimental-timeout", type=float, metavar="SECONDS")
        parser.add_argument("--output", type=Path, metavar="DIR")
        return handlers._candidate_test
    raise ValueError(f"unsupported operator workflow: {name}")
