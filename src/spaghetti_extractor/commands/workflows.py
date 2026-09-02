"""Operator workflows backed exclusively by target-SDK Nix artifacts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs

from ..boundary.work_status import parse_component_work_package_inspection_v1
from ..build_support.nix_invocation import builder_arguments, nix_command
from ..components.formats import (
    COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT,
    COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT,
)
from ..components.proposal_package import load_component_proposal_package_v2
from ..components.work_package_v6 import ComponentAdoptionIntentV1
from ..operator.formats import OPERATOR_WORK_STATUS_FORMAT
from .common import Handler


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
    root = _realize_path(args, suffix)
    path = root / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read checked status artifact: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("checked status artifact must be an object")
    return payload


def _realize_path(args: argparse.Namespace, suffix: str) -> Path:
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
    return paths[0]


def _project_analyze(args: argparse.Namespace) -> int:
    return _build(args, "project.analysis")


def _project_status(args: argparse.Namespace) -> int:
    payload = _realize_json(args, "project.status", "project-status.json")
    if payload.get("format") != OPERATOR_WORK_STATUS_FORMAT:
        raise ValueError("project status is not an operator-work-status-v1 view")
    raw_subjects = payload.get("subjects")
    if not isinstance(raw_subjects, list) or len(raw_subjects) != 1 or not isinstance(
        raw_subjects[0], Mapping
    ):
        raise ValueError("project status must contain exactly one module subject")
    subject = dict(raw_subjects[0])
    if subject.get("subject") != f"module:{args.target}":
        raise ValueError("project status binds another target module")
    raw_blockers = subject.get("blockers")
    if not isinstance(raw_blockers, list) or any(
        not isinstance(row, Mapping) for row in raw_blockers
    ):
        raise ValueError("project status blocker inventory is malformed")
    blockers = [dict(row) for row in raw_blockers]
    if args.family:
        blockers = [row for row in blockers if row.get("family") == args.family]
    if args.status and subject.get("state") != args.status:
        blockers = []
    if not args.all:
        blockers = blockers[: args.limit]
    if args.json:
        print(json.dumps({
            **payload,
            "subjects": [{**subject, "blockers": blockers}],
        }, indent=2, sort_keys=True))
        return 0
    counts = payload.get("counts", {})
    print(
        f"{args.target}: status={payload.get('status')} "
        f"semantic={subject.get('state')} "
        f"semantic-authority={str(subject.get('authority')).lower()} "
        f"blockers={counts.get('blockers', 0)}"
    )
    for blocker in blockers:
        code = blocker.get("code", "unknown_semantic_blocker")
        identity = next((
            blocker.get(field)
            for field in (
                "symbol_id", "relocation_id", "hole_id", "root_id", "unit_id"
            )
            if blocker.get(field) is not None
        ), None)
        suffix = f" [{identity}]" if identity is not None else ""
        print(f"incomplete: semantic-link:{code}{suffix}")
    if not blockers and subject.get("ranked_next_action"):
        print(f"next: {subject.get('ranked_next_action')}")
    return 0


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
    if args.development and kind != "units":
        raise ValueError(
            "--development applies only to a component leaf or operator-defined group"
        )
    product = "developmentStatus" if args.development else "status"
    payload = _realize_json(
        args,
        f"components.{kind}.{_attr_segment(identity)}.{product}",
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
    product = "runtime" if kind == "configurations" else "build"
    return _build(
        args, f"components.{kind}.{_attr_segment(identity)}.{product}"
    )


def _component_bind(args: argparse.Namespace) -> int:
    kind, identity = _component_selection(args)
    if kind != "units":
        raise ValueError("component bind requires a leaf or operator-defined group")
    components = _component_index(args)
    units = components.get("units")
    row = units.get(identity) if isinstance(units, Mapping) else None
    if not isinstance(row, Mapping) or row.get("hasMachineBinding") is not True:
        raise ValueError(
            f"component {identity!r} has no declared exact machine binding"
        )
    return _build(
        args,
        f"components.units.{_attr_segment(identity)}.machineBinding",
        no_link=True,
    )


def _component_check(args: argparse.Namespace) -> int:
    kind, identity = _component_selection(args)
    return _build(
        args,
        f"components.{kind}.{_attr_segment(identity)}.check",
        no_link=True,
    )


def _component_relation(args: argparse.Namespace) -> int:
    index = _component_index(args)
    units = index.get("units")
    row = units.get(args.unit) if isinstance(units, Mapping) else None
    if not isinstance(row, Mapping):
        available = ", ".join(sorted(units)) if isinstance(units, Mapping) else "none"
        raise ValueError(f"unknown component unit {args.unit!r}; available: {available}")
    if row.get("hasMachineBinding") is not True:
        raise ValueError(f"component {args.unit!r} has no exact machine binding")
    suffix = f"components.units.{_attr_segment(args.unit)}"
    if args.relation_action == "check":
        return _build(args, f"{suffix}.relationCheck", no_link=True)
    status = _realize_json(
        args,
        f"{suffix}.relation",
        "relation-status.json",
    )
    if args.relation_action == "status":
        if args.json:
            print(json.dumps(status, indent=2, sort_keys=True))
        else:
            print(f"{args.unit}: relation={status.get('status')} [{status.get('code')}]")
            if status.get("detail"):
                print(f"  next: {status.get('detail')}")
        return 0
    relation = _realize_json(
        args,
        f"{suffix}.relation",
        "relation-ir.json",
    )
    if args.relation_action in {"inspect", "propose"}:
        if args.json:
            print(json.dumps(relation, indent=2, sort_keys=True))
        else:
            print(
                f"{args.unit}: backend={relation.get('machine_backend')} "
                f"operations={len(relation.get('operations', []))}"
            )
            for operation in relation.get("operations", []):
                if not isinstance(operation, Mapping):
                    continue
                clauses = operation.get("clauses", [])
                print(f"  {operation.get('operation_id')}: {len(clauses)} clauses")
                for clause in clauses:
                    if isinstance(clause, Mapping):
                        path = clause.get("logical_path")
                        logical = ""
                        if isinstance(path, Mapping):
                            logical = f" -> {path.get('root')}.{path.get('id')}"
                        print(
                            f"    {clause.get('id')}: {clause.get('kind')}"
                            f" phase={clause.get('phase')}{logical}"
                        )
        return 0
    if args.output is None:
        raise ValueError("component relation adopt requires --output FILE")
    declaration = _relation_declaration(relation)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(
        json.dumps(declaration, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    print(f"adopted relation declaration: {output}")
    return 0


def _relation_declaration(relation: Mapping[str, Any]) -> dict[str, object]:
    operations = []
    for operation in relation.get("operations", []):
        if not isinstance(operation, Mapping):
            continue
        clauses = []
        for clause in operation.get("clauses", []):
            if not isinstance(clause, Mapping):
                continue
            clauses.append(
                {
                    "id": clause.get("id"),
                    "proposal_id": clause.get("id"),
                    "kind": clause.get("kind"),
                    "logical_path": clause.get("logical_path"),
                }
            )
        operations.append(
            {"operation_id": operation.get("operation_id"), "clauses": clauses}
        )
    return {
        "format": "spaghetti-extractor-component-relation-declaration-v1",
        "component_id": relation.get("component_id"),
        "machine_backend": relation.get("machine_backend"),
        "operations": operations,
    }


def _boundary_index(args: argparse.Namespace) -> Mapping[str, Any]:
    boundaries = _operator_index(args).get("boundaries")
    if not isinstance(boundaries, Mapping) or boundaries.get("configured") is not True:
        raise ValueError(
            "target has no checked boundary workflow; run project analyze after "
            "configuring boundary intents"
        )
    return boundaries


def _boundary_subject(args: argparse.Namespace) -> Mapping[str, Any]:
    boundaries = _boundary_index(args)
    subjects = boundaries.get("subjects")
    row = subjects.get(args.subject) if isinstance(subjects, Mapping) else None
    if not isinstance(row, Mapping):
        if args.subject.startswith("component-seed:"):
            return {
                "kind": "component_seed_proposal",
                "dynamic": True,
            }
        available = ", ".join(sorted(subjects)) if isinstance(subjects, Mapping) else "none"
        raise ValueError(
            f"unknown boundary subject {args.subject!r}; available: {available}"
        )
    return row


def _component_seed_rva(subject: str) -> int:
    raw = subject.removeprefix("component-seed:")
    try:
        value = int(raw, 0)
    except ValueError as exc:
        raise ValueError("component seed must contain a numeric RVA") from exc
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("component seed RVA is outside PE32")
    return value


def _component_seed_proposal(
    args: argparse.Namespace,
) -> tuple[int, dict[str, Any]]:
    rva = _component_seed_rva(args.subject)
    package = load_component_proposal_package_v2(
        _realize_path(args, "components.proposals")
    )
    candidates = []
    for raw in package.index["proposals"]:
        if not isinstance(raw, Mapping):
            continue
        membership = raw.get("membership")
        if not isinstance(membership, Mapping):
            continue
        start = membership.get("rva_start")
        end = membership.get("rva_end")
        if (
            isinstance(start, int) and isinstance(end, int)
            and start <= rva < end
        ):
            candidates.append(dict(raw))
    if not candidates:
        raise ValueError(f"component seed RVA 0x{rva:08x} has no proposal")
    candidates.sort(key=lambda row: (
        int(row.get("score", {}).get("front", 1 << 30)),
        int(row.get("score", {}).get("rank", 1 << 30)),
        int(row.get("blockers", {}).get("count", 1 << 30)),
        -int(row.get("membership", {}).get("unit_count", 0)),
        str(row.get("id")),
    ))
    return rva, package.get_proposal(str(candidates[0]["id"]))


def _component_seed_inspection(
    subject: str, rva: int, proposal: Mapping[str, Any],
) -> dict[str, Any]:
    blockers = proposal.get("blockers", [])
    return {
        "format": COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "authority": False,
        "subject": subject,
        "seed_rva": rva,
        "proposal": dict(proposal),
        "ranked_next_action": (
            "adopt the proposed component boundary and refine its interface"
            if not blockers else "repair the first proposal blocker"
        ),
    }


def _component_seed_adoption_intent(
    rva: int, proposal: Mapping[str, Any],
) -> dict[str, Any]:
    return dict(ComponentAdoptionIntentV1.for_seed(
        rva, proposal.get("proposal_kinds", [])
    ).payload)


def _write_component_seed_editable_package(
    *, output: Path, subject: str, rva: int, proposal: Mapping[str, Any],
) -> None:
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise ValueError("boundary proposal output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    (output / "include").mkdir()
    (output / "src").mkdir()
    intent = _component_seed_adoption_intent(rva, proposal)
    inspection = _component_seed_inspection(subject, rva, proposal)
    interface = proposal.get("interface_hint", {})
    parameters = interface.get("parameters", []) if isinstance(interface, Mapping) else []
    objects = interface.get("objects", []) if isinstance(interface, Mapping) else []
    services = interface.get("services", []) if isinstance(interface, Mapping) else []
    symbol = str(intent["operations"][0]["symbol"])
    parameter_names = []
    for index, parameter in enumerate(parameters):
        register = parameter.get("register") if isinstance(parameter, Mapping) else None
        suffix = str(register) if isinstance(register, str) else str(index)
        parameter_names.append(f"uint32_t machine_value_{suffix}")
    for index, _object in enumerate(objects):
        parameter_names.append(f"void *object_view_{index}")
    signature = ", ".join(parameter_names) or "void"
    header = "\n".join([
        "#ifndef SPX_COMPONENT_SEED_H",
        "#define SPX_COMPONENT_SEED_H",
        "",
        "#include <stdint.h>",
        "",
        "/* Draft only: refine these proposed machine-facing types before proof. */",
        f"uint32_t {symbol}({signature});",
        "",
        "#endif /* SPX_COMPONENT_SEED_H */",
        "",
    ])
    source = "\n".join([
        '#include "component.h"',
        "",
        '#error "refine the proposal interface, then implement this component"',
        "",
        f"/* Seed RVA: 0x{rva:08x}. */",
        f"/* Proposed services: {len(services)}; object views: {len(objects)}. */",
        f"/* Implement: uint32_t {symbol}({signature}); */",
        "",
    ])
    readme = "\n".join([
        f"# Component seed 0x{rva:08x}",
        "",
        "This is a non-authorizing, machine-derived editing package.",
        "Refine the draft types and boundary intent, keep authored C separate",
        "from faithful generated C, then run contextual refinement.",
        "",
        f"Proposal forms: {', '.join(str(item) for item in proposal.get('proposal_kinds', []))}",
        f"Candidate units: {proposal.get('membership', {}).get('unit_count')}",
        f"Expected proof cost: {proposal.get('score', {}).get('vector', {}).get('expected_proof_cost')}",
        "",
    ])
    (output / "component-adoption-intent.json").write_text(
        json.dumps(intent, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "component-proposal-inspection.json").write_text(
        json.dumps(inspection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "include/component.h").write_text(header, encoding="utf-8")
    (output / "src/component.c").write_text(source, encoding="utf-8")
    (output / "README.md").write_text(readme, encoding="utf-8")


def _boundary_status(args: argparse.Namespace) -> int:
    _boundary_index(args)
    payload = _realize_json(args, "boundaries.status", "boundary-status.json")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    counts = payload.get("counts", {})
    print(
        f"{args.target}: boundaries={counts.get('subjects', 0)} "
        f"complete={counts.get('complete', 0)} "
        f"incomplete={counts.get('incomplete', 0)} "
        f"violated={counts.get('violated', 0)}"
    )
    for row in payload.get("subjects", []):
        if not isinstance(row, Mapping):
            continue
        print(
            f"{str(row.get('state')):10} {row.get('subject')} "
            f"authority={'yes' if row.get('authority') is True else 'no'}"
        )
        for blocker in row.get("blockers", []):
            print(f"  blocker: {blocker}")
        if row.get("ranked_next_action"):
            print(f"  next: {row.get('ranked_next_action')}")
    return 0


def _boundary_inspect(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    if subject.get("dynamic") is True:
        rva, proposal = _component_seed_proposal(args)
        payload = _component_seed_inspection(args.subject, rva, proposal)
    else:
        payload = _realize_json(
            args,
            f"boundaries.subjects.{_attr_segment(args.subject)}.inspection",
            str(subject.get("inspectionArtifact", "call-inspection.json")),
        )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if payload.get("format") == COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT:
        proposal = payload.get("proposal", {})
        membership = proposal.get("membership", {})
        score = proposal.get("score", {}).get("vector", {})
        print(
            f"{args.subject}: status={payload.get('status')} authority=no "
            f"span=0x{int(membership.get('rva_start', 0)):08x}-"
            f"0x{int(membership.get('rva_end', 0)):08x} "
            f"units={membership.get('unit_count')} "
            f"proof-cost={score.get('expected_proof_cost')}"
        )
        print(
            "  forms: "
            + ", ".join(str(item) for item in proposal.get("proposal_kinds", []))
        )
        for blocker in proposal.get("blockers", []):
            print(f"  blocker: {blocker}")
        print(f"  next: {payload.get('ranked_next_action')}")
        return 0
    if payload.get("format") == COMPONENT_WORK_PACKAGE_INSPECTION_V1_FORMAT:
        payload = parse_component_work_package_inspection_v1(payload)
        print(
            f"{args.subject}: status={payload.get('status')} authority=no "
            f"component={payload.get('component_id')} "
            f"mode={payload.get('proof_classification')}"
        )
        for operation in payload.get("operations", []):
            print(
                f"  operation: {operation.get('operation_id')} "
                f"symbol={operation.get('symbol')}"
            )
        for issue in payload.get("issues", []):
            print(f"  blocker: {issue}")
        return 0
    print(
        f"{args.subject}: status={payload.get('status')} "
        f"dialect={payload.get('abi_dialect')} "
        f"convention={payload.get('calling_convention')}"
    )
    faithful = payload.get("faithful_prototype")
    if faithful:
        print(f"  faithful: {faithful}")
    idiomatic = payload.get("idiomatic_prototype")
    if idiomatic:
        print(f"  idiomatic: {idiomatic}")
    for issue in payload.get("issues", []):
        print(f"  blocker: {issue}")
    return 0


def _boundary_propose(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    if subject.get("dynamic") is True:
        rva, proposal = _component_seed_proposal(args)
        if args.output is None:
            return _build(args, "components.proposals", no_link=True)
        _write_component_seed_editable_package(
            output=args.output.resolve(), subject=args.subject,
            rva=rva, proposal=proposal,
        )
        print(f"wrote component seed work package: {args.output.resolve()}")
        return 0
    if args.output is not None:
        raise ValueError("--output is currently supported for component seeds")
    return _build(
        args,
        f"boundaries.subjects.{_attr_segment(args.subject)}.proposal",
        no_link=True,
    )


def _boundary_adopt(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    if args.output is None:
        raise ValueError("boundary adopt requires --output FILE")
    if subject.get("dynamic") is True:
        rva, proposal = _component_seed_proposal(args)
        payload = _component_seed_adoption_intent(rva, proposal)
    else:
        payload = _realize_json(
            args,
            f"boundaries.subjects.{_attr_segment(args.subject)}.intentTemplate",
            str(subject.get("intentArtifact", "call-intent.json")),
        )
    forbidden = {"status", "proposal_id", "evidence_ids"}
    forbidden.update(key for key in payload if key.endswith("_sha256"))
    if set(payload) & forbidden:
        raise ValueError(
            "generated boundary intent contains authority or digest fields"
        )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(f"adopted boundary intent: {output}")
    return 0


def _boundary_check(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    if subject.get("dynamic") is True:
        _component_seed_proposal(args)
        raise ValueError(
            "component seed is a non-authorizing proposal; adopt it, author "
            "a checked interface, and check the resulting component"
        )
    return _build(
        args,
        f"boundaries.subjects.{_attr_segment(args.subject)}.check",
        no_link=True,
    )


def _library_status_payload(args: argparse.Namespace) -> dict[str, Any]:
    return _realize_json(args, "libraries.status", "library-status.json")


def _library_status(args: argparse.Namespace) -> int:
    payload = _library_status_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    counts = payload.get("counts", {})
    print(
        f"{args.target}: adoption={payload.get('adoption_status')} "
        f"recognition={payload.get('recognition_status')} "
        f"releases={counts.get('releases', 0)} "
        f"islands={counts.get('islands', 0)} "
        f"identity={counts.get('identity_complete', 0)} "
        f"boundary={counts.get('boundary_complete', 0)} "
        f"implementation={counts.get('implementation_complete', 0)} "
        f"ready={counts.get('ready_adoptions', 0)}/"
        f"{counts.get('adoption_intents', 0)}"
    )
    for row in payload.get("selections", []):
        if not isinstance(row, Mapping):
            continue
        print(
            f"  {row.get('island_id')}: mode={row.get('mode')} "
            f"status={row.get('status')} "
            f"implementation={row.get('implementation_id') or row.get('recipe_id')}"
        )
    for blocker in payload.get("primary_blockers", [])[:10]:
        if isinstance(blocker, Mapping):
            print(
                f"blocker: {blocker.get('code')} "
                f"[{blocker.get('status')}] at {blocker.get('location')}"
            )
            if blocker.get("next_action"):
                print(f"  next: {blocker.get('next_action')}")
    return 0


def _parse_rva(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("RVA must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("RVA must not be negative")
    return parsed


def _library_inspect(args: argparse.Namespace) -> int:
    payload = _library_status_payload(args)
    rows = payload.get("islands", [])
    if not isinstance(rows, list):
        raise ValueError("library status has no island inventory")
    selected = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        matches = row.get("matches", [])
        contains_rva = args.rva is None or any(
            isinstance(match, Mapping)
            and isinstance(match.get("target_span_start"), int)
            and isinstance(match.get("target_span_end"), int)
            and match["target_span_start"] <= args.rva < match["target_span_end"]
            for match in matches
        )
        if args.island is not None and row.get("id") != args.island:
            continue
        if args.family is not None and row.get("family_id") != args.family:
            continue
        if contains_rva:
            selected.append(row)
    if not selected:
        raise ValueError("no library island matches the requested selector")
    if args.json:
        print(json.dumps(selected, indent=2, sort_keys=True))
    else:
        for row in selected:
            matches = row.get("matches", [])
            score = sum(
                int(match.get("score", 0))
                for match in matches
                if isinstance(match, Mapping)
            )
            print(
                f"{row.get('id')}: family={row.get('family_id')} "
                f"release={row.get('release_id')} status={row.get('status')} "
                f"score={score}"
            )
            for evidence in row.get("matches", []):
                if isinstance(evidence, Mapping):
                    print(
                        f"  {','.join(evidence.get('evidence', []))}: "
                        f"{evidence.get('target_function_id')} -> "
                        f"{evidence.get('catalog_function_id')}"
                    )
            for function in row.get("catalog_functions", []):
                if isinstance(function, Mapping):
                    print(
                        f"  catalog: {','.join(function.get('symbols', [])) or '<anonymous>'} "
                        f"member={function.get('member_id')} "
                        f"operation={function.get('operation_id')} "
                        f"abi={function.get('abi_profile_id')}"
                    )
            blockers = row.get("issues", [])
            for blocker in blockers if isinstance(blockers, list) else []:
                if isinstance(blocker, Mapping):
                    print(f"  {blocker.get('status')}: {blocker.get('code')}")
    return 0


def _local_target_bundle(args: argparse.Namespace) -> Path:
    reference = str(args.target_flake)
    if reference.startswith("path:"):
        location, separator, query = reference[5:].partition("?")
        root = Path(location)
        if separator:
            values = parse_qs(query, strict_parsing=True)
            directories = values.get("dir", [])
            if len(directories) > 1:
                raise ValueError("--target-flake has more than one dir parameter")
            if directories:
                root /= directories[0]
    elif ":" not in reference and "?" not in reference and "#" not in reference:
        root = Path(reference)
    else:
        raise ValueError(
            "library adoption requires a writable local --target-flake path"
        )
    bundle = (root / args.target).resolve()
    if not bundle.is_dir():
        raise ValueError(f"local target bundle does not exist: {bundle}")
    return bundle


def _library_adopt(args: argparse.Namespace) -> int:
    from ..libraries.v4_adoption_records import LibraryAdoptionIntentV1
    from ..target_bundles.metadata import TargetMetadata

    payload = _library_status_payload(args)
    islands = payload.get("islands", [])
    island = next(
        (
            row
            for row in islands
            if isinstance(row, Mapping) and row.get("id") == args.island
        ),
        None,
    )
    if island is None:
        raise ValueError(f"unknown library island {args.island!r}")
    hypotheses_sha256 = island.get("hypotheses_sha256")
    if not isinstance(hypotheses_sha256, str):
        raise ValueError("library status omitted the island hypotheses hash")

    implementation_id: str | None = None
    recipe_id: str | None = None
    mode = "draft"
    if args.recipe is not None:
        recipes = island.get("recipes", [])
        candidates = [
            row.get("implementation_id")
            for row in recipes
            if isinstance(row, Mapping) and row.get("recipe_id") == args.recipe
        ]
        candidates = [value for value in candidates if isinstance(value, str)]
        if len(candidates) != 1:
            available = sorted(
                str(row.get("recipe_id"))
                for row in recipes
                if isinstance(row, Mapping) and isinstance(row.get("recipe_id"), str)
            )
            raise ValueError(
                f"recipe {args.recipe!r} is not uniquely available for this island; "
                f"available: {', '.join(available) or 'none'}"
            )
        implementation_id = candidates[0]
        mode = "adopt"
    else:
        recipe_id = args.draft

    intent = LibraryAdoptionIntentV1.create(
        target_id=args.target,
        island_id=args.island,
        hypotheses_sha256=hypotheses_sha256,
        implementation_id=implementation_id,
        recipe_id=recipe_id,
        mode=mode,
    )
    bundle = _local_target_bundle(args)
    metadata = TargetMetadata.load(bundle / "target.json")
    library_paths = [path for name, path in metadata.paths if name == "libraries"]
    if len(library_paths) != 1:
        raise ValueError(
            "target metadata must declare paths.libraries before adopting an island"
        )
    destination = bundle / Path(library_paths[0]) / f"{args.island.split(':')[-1]}.json"
    serialized = json.dumps(intent.to_payload(), indent=2, sort_keys=True) + "\n"
    if destination.exists():
        existing = destination.read_text(encoding="utf-8")
        if existing == serialized:
            print(destination)
            return 0
        if not args.replace:
            raise ValueError(
                f"refusing to replace existing library adoption intent: {destination}"
            )
    if args.dry_run:
        print(serialized, end="")
        return 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(serialized, encoding="utf-8")
    print(destination)
    return 0


def _library_check(args: argparse.Namespace) -> int:
    if args.selection is None:
        return _build(args, "libraries.check", no_link=True)
    index = _operator_index(args)
    libraries = index.get("libraries")
    available = (
        libraries.get("selections", [])
        if isinstance(libraries, Mapping)
        else []
    )
    selection = args.selection
    if selection not in available:
        derived = selection.split(":")[-1]
        if derived in available:
            selection = derived
        else:
            raise ValueError(
                f"unknown library selection {args.selection!r}; "
                f"available: {', '.join(str(value) for value in available) or 'none'}"
            )
    suffix = f"libraries.checks.{_attr_segment(selection)}"
    return _build(args, suffix, no_link=True)


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


def _candidate_check(args: argparse.Namespace) -> int:
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
    return _build(
        args,
        (
            f"candidate.checks.{_attr_segment(configuration)}."
            f"{_attr_segment(args.mode)}"
        ),
        no_link=True,
    )


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
    configuration = args.configuration
    suffix = (
        f"candidate.statuses.{_attr_segment(configuration)}"
        if configuration is not None
        else "candidate.materializedStatus"
    )
    payload = _realize_json(
        args,
        suffix,
        "project-status.json",
    )
    if payload.get("format") != OPERATOR_WORK_STATUS_FORMAT:
        raise ValueError("candidate status is not an operator-work-status-v1 view")
    raw_subjects = payload.get("subjects")
    if not isinstance(raw_subjects, list):
        raise ValueError("candidate status subject inventory is malformed")
    candidates = [
        dict(row) for row in raw_subjects
        if isinstance(row, Mapping)
        and str(row.get("subject", "")).startswith(
            f"configuration:{args.target}:"
        )
    ]
    if len(candidates) != 1:
        raise ValueError(
            "target has no unique candidate configuration status; use project "
            "status while component intent is not configured"
        )
    subject = candidates[0]
    observed_configuration = str(subject["subject"]).rsplit(":", 1)[-1]
    if configuration is not None and observed_configuration != configuration:
        raise ValueError("candidate status binds another configuration")
    configuration = observed_configuration
    raw_blockers = subject.get("blockers")
    if not isinstance(raw_blockers, list) or any(
        not isinstance(row, Mapping) for row in raw_blockers
    ):
        raise ValueError("candidate status blocker inventory is malformed")
    blockers = [dict(row) for row in raw_blockers]
    if args.family and args.family != "provider-selection":
        blockers = []
    if args.status and args.status != subject.get("state"):
        blockers = []
    if not args.all:
        blockers = blockers[: args.limit]
    if args.json:
        print(json.dumps({
            **payload,
            "subjects": [
                {**row, "blockers": blockers}
                if row.get("subject") == subject["subject"] else row
                for row in raw_subjects
            ],
        }, indent=2, sort_keys=True))
        return 0
    raw_bindings = subject.get("bindings")
    if not isinstance(raw_bindings, list) or any(
        not isinstance(row, Mapping) for row in raw_bindings
    ):
        raise ValueError("candidate status binding inventory is malformed")
    binding = next(iter(raw_bindings), {})
    ready = binding.get("ready_for_realization") is True
    print(
        f"{args.target}: status={payload.get('status')} "
        f"configuration={configuration} "
        f"selection={subject.get('state')} "
        f"realization-ready={str(ready).lower()} "
        f"blockers={len(raw_blockers)}"
    )
    for blocker in blockers:
        code = blocker.get("code", "unknown_provider_selection_blocker")
        identity = blocker.get("symbol_id") or blocker.get("provider_id")
        suffix = f" [{identity}]" if identity is not None else ""
        print(f"incomplete: provider-selection:{code}{suffix}")
    if not blockers and subject.get("ranked_next_action"):
        print(f"next: {subject.get('ranked_next_action')}")
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
    if name in {
        "component status",
        "component build",
        "component bind",
        "component check",
    }:
        _add_component_selector(parser)
        if name == "component status":
            parser.add_argument("--json", action="store_true")
            parser.add_argument(
                "--development",
                action="store_true",
                help=(
                    "show contract/source progress without requiring machine-derived "
                    "activation authority"
                ),
            )
            return _component_status
        if name == "component build":
            return _component_build
        if name == "component bind":
            return _component_bind
        return _component_check
    if name == "component relation":
        parser.add_argument("unit", type=_identifier, help="component leaf or group id")
        parser.add_argument(
            "relation_action",
            choices=("status", "propose", "inspect", "adopt", "check"),
        )
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--output", type=Path, metavar="FILE")
        return _component_relation
    if name == "boundary status":
        parser.add_argument("--json", action="store_true")
        return _boundary_status
    if name in {
        "boundary inspect",
        "boundary propose",
        "boundary adopt",
        "boundary check",
    }:
        parser.add_argument("subject", type=_boundary_subject_identity)
        if name == "boundary inspect":
            parser.add_argument("--json", action="store_true")
            return _boundary_inspect
        if name == "boundary propose":
            parser.add_argument("--output", type=Path, metavar="DIR")
            return _boundary_propose
        if name == "boundary adopt":
            parser.add_argument("--output", type=Path, metavar="FILE")
            return _boundary_adopt
        return _boundary_check
    if name == "library status":
        parser.add_argument("--json", action="store_true")
        return _library_status
    if name == "library inspect":
        selector = parser.add_mutually_exclusive_group(required=True)
        selector.add_argument("--rva", type=_parse_rva)
        selector.add_argument("--island", type=_opaque_identity)
        selector.add_argument("--family", type=_opaque_identity)
        parser.add_argument("--json", action="store_true")
        return _library_inspect
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
        return _library_adopt
    if name == "library check":
        parser.add_argument("--selection", type=_opaque_identity)
        return _library_check
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
    if name == "candidate check":
        parser.add_argument("--configuration", type=_identifier)
        parser.add_argument(
            "--mode",
            choices=("hybrid", "portable"),
            default="hybrid",
            help="hybrid permits checked machine implementations; portable does not",
        )
        return _candidate_check
    if name == "candidate test":
        parser.add_argument("--suite", type=_identifier)
        return _candidate_test
    raise ValueError(f"unsupported operator workflow: {name}")


__all__ = ["configure_command"]
