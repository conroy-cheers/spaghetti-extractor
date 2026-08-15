"""Operator workflows backed exclusively by target-SDK Nix artifacts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Mapping

from ..build_support.nix_invocation import builder_arguments, nix_command
from .common import Handler


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _identifier(value: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "identifier must contain only letters, digits, '.', '_', or '-'"
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


def _flake_installable(args: argparse.Namespace, attribute: str) -> str:
    target_flake = str(args.target_flake)
    if "#" in target_flake:
        raise ValueError("--target-flake must not include an output attribute")
    return f"{target_flake}#{attribute}"


def _attr_segment(value: str) -> str:
    """Quote one operator-controlled Nix attribute path segment."""

    return json.dumps(value, ensure_ascii=True)


def _operator_attribute(args: argparse.Namespace, suffix: str) -> str:
    return (
        "legacyPackages.x86_64-linux.operatorTargets."
        f"{_attr_segment(args.target)}.{suffix}"
    )


def _run(command: Sequence[str]) -> int:
    return subprocess.run(list(command), check=False).returncode


def _capture(command: Sequence[str], *, stream_stderr: bool = False) -> str:
    process = subprocess.run(
        list(command),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=None if stream_stderr else subprocess.PIPE,
    )
    if process.returncode != 0:
        message = (
            "" if process.stderr is None else process.stderr.strip()
        ) or process.stdout.strip()
        raise ValueError(message or f"command failed with status {process.returncode}")
    return process.stdout.strip()


def _operator_index(args: argparse.Namespace) -> Mapping[str, Any]:
    output = _capture(
        nix_command(
            "eval",
            "--json",
            _flake_installable(
                args,
                "legacyPackages.x86_64-linux.operatorIndex."
                f"{_attr_segment(args.target)}",
            ),
        ),
    )
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError(f"target operator index is invalid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError("target operator index must be an object")
    return value


def _build(args: argparse.Namespace, suffix: str, *, no_link: bool = False) -> int:
    command = nix_command("build")
    if no_link:
        command.append("--no-link")
    command.extend(
        builder_arguments(
            target_flake=str(args.target_flake),
            builders_file=args.builders_file,
            trusted_public_keys_file=args.trusted_public_keys_file,
            local=args.local,
        )
    )
    command.append(_flake_installable(args, _operator_attribute(args, suffix)))
    return _run(command)


def _realize_json(args: argparse.Namespace, suffix: str, filename: str) -> dict[str, Any]:
    output = _capture(
        [
            *nix_command(
                "build",
                "--quiet",
                "--no-link",
                "--print-out-paths",
            ),
            *builder_arguments(
                target_flake=str(args.target_flake),
                builders_file=args.builders_file,
                trusted_public_keys_file=args.trusted_public_keys_file,
                local=args.local,
            ),
            _flake_installable(args, _operator_attribute(args, suffix)),
        ],
        stream_stderr=True,
    )
    paths = [Path(line) for line in output.splitlines() if line.strip()]
    if len(paths) != 1:
        raise ValueError("status realization did not produce exactly one store path")
    path = paths[0] / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read checked status artifact: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("checked status artifact must be an object")
    return payload


def _project_analyze(args: argparse.Namespace) -> int:
    return _build(args, "project.analysis")


def _project_status(args: argparse.Namespace) -> int:
    payload = _realize_json(args, "project.status", "project-status.json")
    frontiers = _filtered_frontiers(args, payload)
    if args.json:
        _print_filtered_json(payload, frontiers)
        return 0
    counts = payload.get("counts", {})
    authority = payload.get("authority", {})
    print(
        f"{args.target}: status={payload.get('status')} "
        f"authority-ready={str(payload.get('authority_ready')).lower()} "
        f"authority={authority.get('status')} "
        f"frontiers={counts.get('primary_frontiers', 0)} "
        f"dependent={counts.get('dependent_occurrences', 0)}"
    )
    _print_frontiers(payload, frontiers)
    return 0


def _filtered_frontiers(
    args: argparse.Namespace, payload: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    frontiers = list(payload.get("primary_frontiers", []))
    if args.family:
        frontiers = [row for row in frontiers if row.get("family") == args.family]
    if args.status:
        frontiers = [row for row in frontiers if row.get("status") == args.status]
    if not args.all:
        frontiers = frontiers[: args.limit]
    return frontiers


def _print_filtered_json(
    payload: Mapping[str, Any], frontiers: list[Mapping[str, Any]]
) -> None:
    print(
        json.dumps(
            {**payload, "primary_frontiers": frontiers}, indent=2, sort_keys=True
        )
    )


def _print_frontiers(
    payload: Mapping[str, Any], frontiers: list[Mapping[str, Any]]
) -> None:
    for row in frontiers:
        location = row.get("source_location") or {}
        rva = location.get("rva_start")
        where = f" rva=0x{rva:x}" if isinstance(rva, int) else ""
        print(
            f"{row.get('status')}: {row.get('family')}:"
            f"{row.get('code')} [{row.get('record_id')}]"
            f" dependents={row.get('dependent_occurrences', 0)}{where}"
        )
        print(f"  next: {row.get('next_action')}")
    if not frontiers and payload.get("next_action"):
        print(f"next: {payload.get('next_action')}")


def _project_check(args: argparse.Namespace) -> int:
    suffix = "project.acceptanceCheck" if args.acceptance else "project.regressionCheck"
    return _build(args, suffix, no_link=True)


def _component_index(args: argparse.Namespace) -> Mapping[str, Any]:
    return _components_from_index(_operator_index(args))


def _components_from_index(index: Mapping[str, Any]) -> Mapping[str, Any]:
    components = index.get("components")
    if not isinstance(components, Mapping):
        raise ValueError("target has no component index")
    return components


def _component_list(args: argparse.Namespace) -> int:
    index = _operator_index(args)
    components = _components_from_index(index)
    if index.get("hasComponents") is not True:
        proposals = _realize_json(
            args, "components.proposals", "proposal-index.json"
        )
        if args.json:
            print(json.dumps(proposals, indent=2, sort_keys=True))
            return 0
        print("component intent: not configured")
        for row in proposals.get("proposals", []):
            if not isinstance(row, Mapping):
                continue
            membership = row.get("membership", {})
            start = membership.get("rva_start") if isinstance(membership, Mapping) else None
            end = membership.get("rva_end") if isinstance(membership, Mapping) else None
            span = (
                f"0x{start:x}-0x{end:x}"
                if isinstance(start, int) and isinstance(end, int)
                else "unknown-span"
            )
            kinds = row.get("proposal_kinds", [])
            kind = ",".join(str(value) for value in kinds) if isinstance(kinds, list) else ""
            print(f"proposal      {str(row.get('id')):32} {kind:24} {span}")
        print("next: author component intent from the generated proposals")
        return 0
    if args.json:
        print(json.dumps(components, indent=2, sort_keys=True))
        return 0
    for kind, collection in (
        ("unit", components.get("units", {})),
        ("configuration", components.get("configurations", {})),
    ):
        if not isinstance(collection, Mapping):
            continue
        for identity, row in sorted(collection.items()):
            label = row.get("label", "") if isinstance(row, Mapping) else ""
            unit_kind = row.get("kind", kind) if isinstance(row, Mapping) else kind
            print(f"{kind:13} {identity:32} {unit_kind:13} {label}")
    return 0


def _component_selection(args: argparse.Namespace) -> tuple[str, str]:
    if args.configuration is not None and args.unit is not None:
        raise ValueError("choose either a component unit or --configuration, not both")
    index = _operator_index(args)
    if index.get("hasComponents") is not True:
        raise ValueError(
            "target has no authored component intent; run project analyze and "
            "component list, then configure component boundaries"
        )
    components = _components_from_index(index)
    if args.configuration is not None:
        kind = "configurations"
        identity = args.configuration
    elif args.unit is not None:
        kind = "units"
        identity = args.unit
    else:
        kind = "configurations"
        identity = str(index.get("defaultConfiguration"))
    collection = components.get(kind)
    if not isinstance(collection, Mapping) or identity not in collection:
        available = (
            ", ".join(sorted(collection))
            if isinstance(collection, Mapping)
            else "none"
        )
        raise ValueError(
            f"unknown component {kind[:-1]} {identity!r}; available: {available}"
        )
    return kind, identity


def _component_status(args: argparse.Namespace) -> int:
    kind, identity = _component_selection(args)
    payload = _realize_json(
        args,
        f"components.{kind}.{_attr_segment(identity)}.status",
        "status.json",
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{identity}: {payload.get('status')}")
        counts = payload.get("counts")
        if counts is not None:
            print(f"  counts: {json.dumps(counts, sort_keys=True)}")
        action = payload.get("next_action")
        if action:
            print(f"  next: {action.get('action')} [{action.get('code')}]")
    return 0


def _component_build(args: argparse.Namespace) -> int:
    kind, identity = _component_selection(args)
    product = "runtime" if kind == "configurations" else "workPackage"
    return _build(
        args, f"components.{kind}.{_attr_segment(identity)}.{product}"
    )


def _component_check(args: argparse.Namespace) -> int:
    kind, identity = _component_selection(args)
    return _build(
        args,
        f"components.{kind}.{_attr_segment(identity)}.check",
        no_link=True,
    )


def _candidate_build(args: argparse.Namespace) -> int:
    index = _operator_index(args)
    candidate = index.get("candidate")
    configurations = (
        candidate.get("configurations", [])
        if isinstance(candidate, Mapping)
        else []
    )
    configuration = args.configuration or index.get("defaultConfiguration")
    if not configurations:
        raise ValueError(
            "target has no candidate configurations; author component intent first"
        )
    if configuration not in configurations:
        raise ValueError(
            f"unknown candidate configuration {configuration!r}; "
            f"available: {', '.join(configurations)}"
        )
    return _build(args, f"candidate.builds.{_attr_segment(configuration)}")


def _candidate_list(args: argparse.Namespace) -> int:
    index = _operator_index(args)
    candidate = index.get("candidate")
    if not isinstance(candidate, Mapping):
        raise ValueError("target has no candidate index")
    if args.json:
        print(json.dumps(candidate, indent=2, sort_keys=True))
        return 0
    default = index.get("defaultConfiguration")
    configurations = candidate.get("configurations", [])
    suites = candidate.get("testSuites", {})
    if not isinstance(configurations, list) or not isinstance(suites, Mapping):
        raise ValueError("target candidate index is malformed")
    for configuration in configurations:
        marker = "default" if configuration == default else ""
        declared = sorted(
            identity
            for identity, row in suites.items()
            if isinstance(row, Mapping)
            and row.get("configurationId") == configuration
        )
        print(
            f"configuration {str(configuration):32} {marker:8} "
            f"tests={','.join(declared) if declared else 'none'}"
        )
    return 0


def _candidate_status(args: argparse.Namespace) -> int:
    index = _operator_index(args)
    candidate = index.get("candidate")
    configurations = (
        candidate.get("configurations", []) if isinstance(candidate, Mapping) else []
    )
    configuration = args.configuration or index.get("defaultConfiguration")
    if not configurations:
        raise ValueError(
            "target has no candidate configurations; use project status while "
            "component intent is not configured"
        )
    if configuration not in configurations:
        raise ValueError(
            f"unknown candidate configuration {configuration!r}; "
            f"available: {', '.join(configurations)}"
        )
    payload = _realize_json(
        args,
        f"candidate.statuses.{_attr_segment(configuration)}",
        "candidate-status.json",
    )
    frontiers = _filtered_frontiers(args, payload)
    if args.json:
        _print_filtered_json(payload, frontiers)
        return 0
    counts = payload.get("counts", {})
    print(
        f"{args.target}: status={payload.get('status')} "
        f"configuration={payload.get('configuration_id')} "
        f"authority-ready={str(payload.get('authority_ready')).lower()} "
        f"configuration-ready={str(payload.get('configuration_ready')).lower()} "
        f"build-ready={str(payload.get('build_ready')).lower()} "
        f"frontiers={counts.get('primary_frontiers', 0)} "
        f"dependent={counts.get('dependent_occurrences', 0)}"
    )
    _print_frontiers(payload, frontiers)
    return 0


def _candidate_test(args: argparse.Namespace) -> int:
    candidate = _operator_index(args).get("candidate")
    suites = candidate.get("testSuites", {}) if isinstance(candidate, Mapping) else {}
    if not isinstance(suites, Mapping) or not suites:
        raise ValueError("target declares no candidate-only test suites")
    if args.suite is None:
        return _build(args, "candidate.allTests", no_link=True)
    if args.suite not in suites:
        raise ValueError(
            f"unknown candidate test suite {args.suite!r}; available: {', '.join(sorted(suites))}"
        )
    return _build(
        args, f"candidate.tests.{_attr_segment(args.suite)}", no_link=True
    )


def _add_component_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("unit", nargs="?", type=_identifier, help="leaf or group id")
    parser.add_argument("--configuration", type=_identifier, metavar="ID")


def _add_progress_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--limit", type=_positive, default=20)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--family")
    parser.add_argument("--status", choices=("incomplete", "violated"))


def configure_command(name: str, parser: argparse.ArgumentParser) -> Handler:
    _add_target_arguments(parser)
    if name == "project analyze":
        return _project_analyze
    if name == "project status":
        _add_progress_arguments(parser)
        return _project_status
    if name == "project check":
        parser.add_argument("--acceptance", action="store_true")
        return _project_check
    if name == "component list":
        parser.add_argument("--json", action="store_true")
        return _component_list
    if name in {"component status", "component build", "component check"}:
        _add_component_selector(parser)
        if name == "component status":
            parser.add_argument("--json", action="store_true")
            return _component_status
        return _component_build if name == "component build" else _component_check
    if name == "candidate list":
        parser.add_argument("--json", action="store_true")
        return _candidate_list
    if name == "candidate status":
        parser.add_argument("--configuration", type=_identifier)
        _add_progress_arguments(parser)
        return _candidate_status
    if name == "candidate build":
        parser.add_argument("--configuration", type=_identifier)
        return _candidate_build
    if name == "candidate test":
        parser.add_argument("--suite", type=_identifier)
        return _candidate_test
    raise ValueError(f"unsupported operator workflow: {name}")


__all__ = ["configure_command"]
