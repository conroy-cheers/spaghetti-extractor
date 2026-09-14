"""Operator workflows backed exclusively by target-SDK Nix artifacts."""

from __future__ import annotations

import argparse
import copy
import json
import re
import shlex
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs

from ..build_support.nix_invocation import builder_arguments, nix_command
from ..components.formats import (
    COMPONENT_PROPOSAL_INSPECTION_V1_FORMAT,
    COMPONENT_WORK_PACKAGE_V6_FORMAT,
)
from ..components.proposal_package import load_component_proposal_package_v2
from ..operator.formats import OPERATOR_WORK_STATUS_FORMAT
from ..operator.index_v1 import parse_operator_index_v1
from ..operator.projections import (
    normalize_blocker,
    project_candidate_selection,
    project_component_qualification,
    project_component_work_package,
    project_missing_component,
)
from ..operator.work_status import build_operator_blocker_detail_v1
from ..util import sha256_file
from .component_start import (
    apply_component_start as _apply_component_start_transaction,
    component_start_plan as _component_start_plan,
    copy_component_start_package as _copy_component_start_package,
    safe_package_file as _safe_package_file,
)
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
    parsed = parse_operator_index_v1(value)
    if parsed["targetId"] != args.target:
        raise ValueError("target operator index binds another target")
    return parsed


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
    _, payload = _realize_artifact(args, suffix, filename)
    return payload


def _realize_artifact(
    args: argparse.Namespace, suffix: str, filename: str | None = None,
    *, apply_arguments: Mapping[str, object] | None = None,
) -> tuple[Path, dict[str, Any]]:
    root = (_realize_path(args, suffix) if apply_arguments is None else
            _realize_path(args, suffix, apply_arguments=apply_arguments))
    path = root if root.is_file() else root / str(filename)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read operator product: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("operator product must be an object")
    return path, payload


def _realize_path(args: argparse.Namespace, suffix: str, *,
                  apply_arguments: Mapping[str, object] | None = None) -> Path:
    installable = _flake_installable(args, _operator_attribute(args, suffix))
    if apply_arguments is not None:
        # Pass data through JSON, escaping Nix interpolation as well as quotes.
        # Evaluate the requested product function before building its derivation;
        # no shell evaluation or mutable temporary flake is involved.
        literal = json.dumps(json.dumps(apply_arguments, ensure_ascii=True), ensure_ascii=True).replace('${', '\\${')
        derivation = _capture(nix_command('eval', '--raw', installable, '--apply',
            f'product: (product (builtins.fromJSON {literal})).drvPath'))
        if re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\n]+\.drv', derivation) is None:
            raise ValueError('parameterized operator product did not return a store derivation')
        installable = derivation + '^out'
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
            installable,
        ],
        stream_stderr=True,
    )
    paths = [Path(line) for line in output.splitlines() if line.strip()]
    if len(paths) != 1:
        raise ValueError("operator product did not produce exactly one store path")
    return paths[0]


def _single_status_subject(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("format") != OPERATOR_WORK_STATUS_FORMAT:
        raise ValueError("operator status format is unsupported")
    subjects = payload.get("subjects")
    if (
        not isinstance(subjects, list)
        or len(subjects) != 1
        or not isinstance(subjects[0], Mapping)
    ):
        raise ValueError("operator status must contain exactly one subject")
    return dict(subjects[0])


def _render_operator_status(
    args: argparse.Namespace,
    payload: Mapping[str, Any],
    *,
    headline: str,
    raw_blockers: Sequence[Mapping[str, Any]] | None = None,
    default_family: str,
    default_code: str,
) -> int:
    subject = _single_status_subject(payload)
    family = getattr(args, "family", None)
    code = getattr(args, "code", None)
    show_all = bool(getattr(args, "all", False))
    limit = int(getattr(args, "limit", 20))
    details = bool(getattr(args, "details", False))
    if details:
        if family is None and code is None and not show_all:
            raise ValueError("--details requires --family, --code, or --all")
        if raw_blockers is None:
            raise ValueError("operator blocker details are unavailable")
        selected = []
        for raw in raw_blockers:
            normalized = normalize_blocker(
                raw, default_family=default_family, default_code=default_code
            )
            if family is not None and normalized["family"] != family:
                continue
            if code is not None and normalized["code"] != code:
                continue
            selected.append(dict(raw))
        sources = subject.get("sources")
        if not isinstance(sources, list) or not sources or not isinstance(sources[0], Mapping):
            raise ValueError("operator blocker details have no materialized source")
        source = dict(sources[0])
        detail = build_operator_blocker_detail_v1(
            target_id=args.target,
            subject=str(subject["subject"]),
            source_format=str(source["format"]),
            source_sha256=str(source["sha256"]),
            blockers=selected,
            family=family,
            code=code,
            limit=None if show_all else limit,
        )
        if args.json:
            print(json.dumps(detail, indent=2, sort_keys=True))
        else:
            print(f"{headline} details={detail['returned']}/{detail['total']}")
            for row in detail["blockers"]:
                print(f"  {json.dumps(row, sort_keys=True)}")
        return 0

    blockers = subject.get("blockers")
    groups = blockers.get("groups") if isinstance(blockers, Mapping) else None
    if not isinstance(groups, list) or any(not isinstance(row, Mapping) for row in groups):
        raise ValueError("operator status blocker groups are malformed")
    selected_groups = [
        dict(row) for row in groups
        if (family is None or row.get("family") == family)
        and (code is None or row.get("code") == code)
    ]
    if not show_all:
        selected_groups = selected_groups[:limit]
    if args.json:
        rendered = copy.deepcopy(dict(payload))
        rendered["subjects"][0]["blockers"]["groups"] = selected_groups
        print(json.dumps(rendered, indent=2, sort_keys=True))
        return 0
    print(headline)
    for row in selected_groups:
        location = row.get("example_location")
        suffix = "" if location is None else f" [{location}]"
        print(
            f"  blocker: {row.get('family')}:{row.get('code')} "
            f"count={row.get('count')}{suffix}"
        )
    if not selected_groups and subject.get("next_action"):
        print(f"  next: {subject.get('next_action')}")
    return 0


def _project_analyze(args: argparse.Namespace) -> int:
    return _build(args, "project.analysis")


def _project_status(args: argparse.Namespace) -> int:
    payload = _realize_json(args, "project.status", "project-status.json")
    subject = _single_status_subject(payload)
    if subject.get("subject") != f"module:{args.target}":
        raise ValueError("project status binds another target module")
    raw_blockers = None
    if args.details:
        from ..semantic_link.module_v2 import LinkedSemanticModuleV2

        module_path, _ = _realize_artifact(
            args, "project.semanticModule", "linked-semantic-module.json"
        )
        module = LinkedSemanticModuleV2.load(module_path)
        raw_blockers = [dict(row) for row in module.payload["semantic_holes"]]
        sources = subject.get("sources")
        source = sources[0] if isinstance(sources, list) and sources else None
        if not isinstance(source, Mapping) or source.get("sha256") != sha256_file(module_path):
            raise ValueError("project status source binding is stale")
    counts = payload.get("counts", {})
    headline = (
        f"{args.target}: status={payload.get('status')} "
        f"semantic={subject.get('state')} "
        f"authority={subject.get('authority')} "
        f"blockers={counts.get('blockers', 0)}"
    )
    return _render_operator_status(
        args,
        payload,
        headline=headline,
        raw_blockers=raw_blockers,
        default_family="semantic-link",
        default_code="unknown_semantic_blocker",
    )


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


def _component_list_near(args: argparse.Namespace) -> int:
    package = load_component_proposal_package_v2(
        _realize_path(args, "components.proposals")
    )
    candidates = package.proposals_at_rva(args.near)
    if not candidates:
        raise ValueError(f"component seed RVA 0x{args.near:08x} has no proposal")
    rows = [{
        "id": row["id"], "proposal_sha256": row["proposal_sha256"],
        "membership": row["membership"], "proposal_kinds": row["proposal_kinds"],
        "blocker_count": len(row["blockers"]),
        "exits": len(row.get("boundary", {}).get("exits", [])),
    } for row in candidates]
    if args.json:
        print(json.dumps({"authority": False, "seed_rva": args.near,
                          "alternatives": rows}, indent=2, sort_keys=True))
        return 0
    print(f"seed 0x{args.near:08x}: {len(rows)} boundary alternatives; authority=no")
    for row in rows:
        print(f"  {row['id']} units={row['membership']['unit_count']} "
              f"exits={row['exits']} blockers={row['blocker_count']} "
              f"forms={','.join(row['proposal_kinds'])}")
    print(f"next: boundary inspect {args.target} component-seed:0x{args.near:x} "
          "--proposal ID; review before boundary propose --output DIR")
    return 0


def _component_list(args: argparse.Namespace) -> int:
    if args.near is not None:
        return _component_list_near(args)
    index = _operator_index(args)
    components = _components_from_index(index)
    units = components.get("units")
    if not isinstance(units, Mapping):
        raise ValueError("target component unit index is malformed")
    if args.json:
        print(json.dumps(index, indent=2, sort_keys=True))
        return 0
    if not units:
        proposals = _realize_json(
            args, "components.proposals", "proposal-index.json"
        )
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
    for identity, raw in sorted(units.items()):
        row = dict(raw) if isinstance(raw, Mapping) else {}
        products = row.get("products", [])
        availability = ",".join(products) if isinstance(products, list) else "invalid"
        print(
            f"unit          {identity:32} {row.get('label', '')} "
            f"[{availability or 'intent-only'}]"
        )
    return 0


def _component_selection(args: argparse.Namespace) -> tuple[str, Mapping[str, Any]]:
    units = _component_index(args).get("units")
    row = units.get(args.unit) if isinstance(units, Mapping) else None
    if not isinstance(row, Mapping):
        available = (
            ", ".join(sorted(units))
            if isinstance(units, Mapping)
            else "none"
        )
        raise ValueError(
            f"unknown component unit {args.unit!r}; available: {available}"
        )
    return args.unit, row


def _component_status(args: argparse.Namespace) -> int:
    identity, row = _component_selection(args)
    products = row.get("products")
    if not isinstance(products, list):
        raise ValueError("component product inventory is malformed")
    suffix = f"components.units.{_attr_segment(identity)}"
    raw_blockers: list[dict[str, Any]] | None = None
    if not args.development and "qualification" in products:
        path, source_payload = _realize_artifact(
            args, f"{suffix}.qualification", "semantic-provider-qualification.json"
        )
        payload, raw_blockers = project_component_qualification(
            target_id=args.target,
            component_id=identity,
            path=path,
            value=source_payload,
        )
        default_family = "provider-qualification"
        default_code = "provider_qualification_blocker"
    elif "workPackage" in products:
        path, source_payload = _realize_artifact(
            args, f"{suffix}.workPackage", "component-work-package-v6.json"
        )
        payload, raw_blockers = project_component_work_package(
            target_id=args.target,
            component_id=identity,
            path=path,
            value=source_payload,
        )
        default_family = "component-development"
        default_code = "component_development_blocker"
    else:
        payload = project_missing_component(
            target_id=args.target, component_id=identity, products=products
        )
        default_family = "component-contract"
        default_code = "component_product_missing"
    subject = _single_status_subject(payload)
    headline = (
        f"{identity}: status={subject.get('state')} "
        f"scope={payload.get('scope')} authority={subject.get('authority')} "
        f"blockers={subject.get('blockers', {}).get('count', 0)}"
    )
    return _render_operator_status(
        args,
        payload,
        headline=headline,
        raw_blockers=raw_blockers,
        default_family=default_family,
        default_code=default_code,
    )


def _component_build(args: argparse.Namespace) -> int:
    identity, row = _component_selection(args)
    if "workPackage" not in row.get("products", []):
        raise ValueError(f"component {identity!r} has no V6 work package")
    return _build(
        args,
        f"components.units.{_attr_segment(identity)}.workPackage",
    )


def _component_start_work_package(
    args: argparse.Namespace, component_id: str,
) -> tuple[Path, Mapping[str, Any]]:
    from ..components.work_package_v6 import ComponentWorkPackageV6

    path, payload = _realize_artifact(
        args,
        f"components.units.{_attr_segment(component_id)}.workPackage",
        "component-work-package-v6.json",
    )
    package = ComponentWorkPackageV6.parse(payload)
    if package.payload["component_id"] != component_id:
        raise ValueError("component work package binds another component")
    root = path.parent
    for row in package.payload["generated_files"]:
        candidate = _safe_package_file(root, row["path"], "generated component")
        if sha256_file(candidate) != row["sha256"]:
            raise ValueError(f"generated component file is stale: {row['path']}")
    for row in package.payload["faithful_c_slices"]:
        candidate = _safe_package_file(root, row["source_path"], "faithful-C slice")
        if sha256_file(candidate) != row["source_sha256"]:
            raise ValueError(f"faithful-C slice is stale: {row['source_path']}")
    semantic_slice = _safe_package_file(
        root, "semantic-slice-v2.json", "semantic slice"
    )
    try:
        materialized_slice = json.loads(semantic_slice.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read materialized semantic slice: {exc}") from exc
    if materialized_slice != package.payload["semantic_slice"]:
        raise ValueError("materialized semantic slice disagrees with the work package")
    return root, package.payload


def _component_start(args: argparse.Namespace) -> int:
    component_id, row = _component_selection(args)
    if "workPackage" not in row.get("products", []):
        raise ValueError(f"component {component_id!r} has no V6 work package")
    package_root, package = _component_start_work_package(args, component_id)
    relative_source = f"components/{component_id}.c"
    plan = _component_start_plan(
        component_id=component_id,
        package=package,
        target_path=relative_source,
    )
    if args.output is not None:
        output = args.output.resolve()
        _copy_component_start_package(
            source=package_root, output=output, plan=plan
        )
        print(f"wrote writable component work package: {output}")
        return 0
    intent_path, source_path = _apply_component_start_transaction(
        args=args,
        component_id=component_id,
        package_root=package_root,
        package=package,
        bundle=_local_target_bundle(args),
    )
    print(f"started component source: {source_path}")
    print(f"updated component intent: {intent_path}")
    return 0


def _component_check(args: argparse.Namespace) -> int:
    local_contracts = getattr(args, "local_contracts", False)
    compare_baseline = getattr(args, 'compare_baseline', False)
    conditional = getattr(args, "conditional", False)
    if compare_baseline and (not args.source or local_contracts or conditional):
        raise ValueError('component check --compare-baseline requires --source and cannot combine with --conditional or --local-contracts')
    regions = getattr(args, 'region', None)
    query_timeout = getattr(args, 'query_timeout', None)
    entry_query_timeout = getattr(args, 'entry_query_timeout', None)
    if (regions or query_timeout is not None or entry_query_timeout is not None) and not conditional:
        raise ValueError('component check --region, --query-timeout and --entry-query-timeout require --conditional')
    selection = None
    if regions:
        from ..components.conditional_check_result import checked_obligation_selection
        parsed = [value.split('/') for value in regions]
        if any(len(row) != 2 or not all(row) for row in parsed):
            raise ValueError('component check --region requires OPERATION/OBLIGATION')
        selection = checked_obligation_selection([
            {'operation_id': operation, 'obligation_id': obligation} for operation, obligation in parsed])
    if conditional and (args.source or local_contracts):
        raise ValueError("component check --conditional cannot be combined with source-only checking")
    if local_contracts and not args.source:
        raise ValueError("component check --local-contracts requires --source; local results do not qualify a provider")
    identity, row = _component_selection(args)
    if compare_baseline:
        if 'sourceEditCheck' not in row.get('products', []):
            raise ValueError(f'component {identity!r} has no configured source-edit baseline and boundary')
        from ..operator.source_edit import render_component_source_edit
        path, payload = _realize_artifact(args,
            f'components.units.{_attr_segment(identity)}.sourceEditCheck', 'source-edit-check.json')
        return render_component_source_edit(path=path, payload=payload, target_id=args.target,
                                            component_id=identity, as_json=args.json)
    if conditional:
        if "conditionalCheck" not in row.get("products", []):
            raise ValueError(f"component {identity!r} has no configured conditional-check product")
        from ..operator.conditional_check import render_component_conditional_check
        if selection is not None or query_timeout is not None or entry_query_timeout is not None:
            if 'conditionalCheckFor' not in row.get('products', []):
                raise ValueError(f'component {identity!r} has no parameterized conditional-check product')
            request = {'obligations': selection}
            if query_timeout is not None:
                request['queryTimeoutSeconds'] = query_timeout
            if entry_query_timeout is not None:
                request['entryQueryTimeoutSeconds'] = entry_query_timeout
            path, payload = _realize_artifact(args,
                f'components.units.{_attr_segment(identity)}.conditionalCheckFor', 'conditional-check.json',
                apply_arguments=request)
        else:
            path, payload = _realize_artifact(args,
                f"components.units.{_attr_segment(identity)}.conditionalCheck", "conditional-check.json")
        return render_component_conditional_check(path=path, payload=payload, target_id=args.target,
                                                 component_id=identity, as_json=args.json)
    if args.source:
        product = "sourceContractCheck" if local_contracts else "sourceCheck"
        if product not in row.get("products", []):
            raise ValueError(f"component {identity!r} has no source-check product; author source first")
        from ..operator.source_check import render_component_source_check

        path, payload = _realize_artifact(
            args, f"components.units.{_attr_segment(identity)}.{product}", "source-check.json",
        )
        return render_component_source_check(path=path, payload=payload, target_id=args.target,
                                             component_id=identity, as_json=args.json)
    if args.json:
        raise ValueError("component check --json requires --source; use component status --json for qualification")
    if "qualification" not in row.get("products", []):
        from ..operator.proof_diagnostics import component_binding_details

        details = []
        if "bindingIntent" in row.get("products", []):
            path, binding = _realize_artifact(
                args, f"components.units.{_attr_segment(identity)}.bindingIntent",
            )
            details = component_binding_details(value=binding, path=path, component_id=identity)
        details.append("Next: " + shlex.join([
            "component", "status", str(args.target), identity, "--development",
            "--target-flake", str(args.target_flake),
            *(["--local"] if args.local else []),
        ]))
        raise ValueError(
            f"component {identity!r} has no provider qualification product"
            + "\n" + "\n".join(details)
        )
    from ..semantic_providers.qualification_v2 import (
        SemanticProviderQualificationV2,
    )

    path, payload = _realize_artifact(
        args,
        f"components.units.{_attr_segment(identity)}.qualification",
        "semantic-provider-qualification.json",
    )
    qualification = SemanticProviderQualificationV2.parse(payload)
    if not qualification.provider_id.endswith(f".{identity}.portable-c"):
        raise ValueError("component qualification binds another component")
    if qualification.payload["status"] != "complete":
        from ..operator.proof_diagnostics import component_failure_details

        details = component_failure_details(
            qualification=qualification.payload, qualification_path=path, component_id=identity,
        )
        raise ValueError(
            f"component {identity!r} qualification is incomplete with "
            f"{len(qualification.payload['blockers'])} blocker(s)"
            + ("\n" + "\n".join(details) if details else "")
        )
    return 0


def _boundary_index(args: argparse.Namespace) -> Mapping[str, Any]:
    boundaries = _operator_index(args).get("boundaries")
    subjects = boundaries.get("subjects") if isinstance(boundaries, Mapping) else None
    if not isinstance(boundaries, Mapping) or not isinstance(subjects, Mapping):
        raise ValueError("target boundary index is malformed")
    return boundaries


def _boundary_subject(args: argparse.Namespace) -> Mapping[str, Any]:
    boundaries = _boundary_index(args)
    subjects = boundaries.get("subjects")
    row = subjects.get(args.subject) if isinstance(subjects, Mapping) else None
    canonical = args.subject
    matched_component = False
    if not isinstance(row, Mapping) and args.subject.startswith("component-seed:"):
        rva = _component_seed_rva(args.subject)
        components = _component_index(args).get("units")
        matches = [
            identity for identity, raw in (
                components.items() if isinstance(components, Mapping) else []
            )
            if isinstance(raw, Mapping) and rva in raw.get("entryRvas", [])
        ]
        if len(matches) > 1:
            raise ValueError("component seed RVA resolves to multiple configured units")
        if matches:
            matched_component = True
            canonical = f"component:{matches[0]}"
            row = subjects.get(canonical) if isinstance(subjects, Mapping) else None
    if not isinstance(row, Mapping):
        if args.subject.startswith("component-seed:") and not matched_component:
            return {
                "kind": "component_seed_proposal",
                "dynamic": True,
                "canonicalSubject": args.subject,
            }
        if matched_component:
            raise ValueError(
                f"component seed resolves to {canonical!r}, which has no boundary product"
            )
        available = ", ".join(sorted(subjects)) if isinstance(subjects, Mapping) else "none"
        raise ValueError(
            f"unknown boundary subject {args.subject!r}; available: {available}"
        )
    return {**row, "canonicalSubject": canonical}


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
    candidates = package.proposals_at_rva(rva)
    if not candidates:
        raise ValueError(f"component seed RVA 0x{rva:08x} has no proposal")
    requested = getattr(args, "proposal", None)
    if requested is not None:
        selected = next((row for row in candidates if row["id"] == requested), None)
        if selected is None:
            raise ValueError("selected proposal is not an alternative for this seed")
        return rva, selected
    return rva, candidates[0]


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
            "author the proposed boundary as canonical component intent"
            if not blockers else "repair the first proposal blocker"
        ),
    }


def _write_component_seed_editable_package(
    *, output: Path, subject: str, rva: int, proposal: Mapping[str, Any],
) -> None:
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise ValueError("boundary proposal output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    (output / "include").mkdir()
    (output / "src").mkdir()
    inspection = _component_seed_inspection(subject, rva, proposal)
    interface = proposal.get("interface_hint", {})
    parameters = interface.get("parameters", []) if isinstance(interface, Mapping) else []
    objects = interface.get("objects", []) if isinstance(interface, Mapping) else []
    services = interface.get("services", []) if isinstance(interface, Mapping) else []
    symbol = f"spx_component_{rva:08x}_operation"
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
        "Refine the draft types, then author the canonical component interface,",
        "machine binding, and lifting intent. Once that configured unit has a",
        "checked V6 package, use `component start UNIT --apply`.",
        "",
        f"Proposal forms: {', '.join(str(item) for item in proposal.get('proposal_kinds', []))}",
        f"Candidate units: {proposal.get('membership', {}).get('unit_count')}",
        f"Expected proof cost: {proposal.get('score', {}).get('vector', {}).get('expected_proof_cost')}",
        "",
    ])
    (output / "component-proposal-inspection.json").write_text(
        json.dumps(inspection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "include/component.h").write_text(header, encoding="utf-8")
    (output / "src/component.c").write_text(source, encoding="utf-8")
    (output / "README.md").write_text(readme, encoding="utf-8")


def _boundary_status(args: argparse.Namespace) -> int:
    _boundary_index(args)
    payload = _realize_json(args, "boundaries.status", "boundary-status.json")
    if payload.get("format") != OPERATOR_WORK_STATUS_FORMAT:
        raise ValueError("boundary status format is unsupported")
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
            f"authority={row.get('authority')}"
        )
        blockers = row.get("blockers", {})
        groups = blockers.get("groups", []) if isinstance(blockers, Mapping) else []
        for blocker in groups:
            if isinstance(blocker, Mapping):
                print(
                    f"  blocker: {blocker.get('family')}:{blocker.get('code')} "
                    f"count={blocker.get('count')}"
                )
        if not groups and row.get("next_action"):
            print(f"  next: {row.get('next_action')}")
    return 0


def _boundary_inspect(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    if args.proposal is not None and subject.get("dynamic") is not True:
        raise ValueError("--proposal requires an unconfigured component seed")
    canonical = str(subject["canonicalSubject"])
    if subject.get("dynamic") is True:
        rva, proposal = _component_seed_proposal(args)
        payload = _component_seed_inspection(args.subject, rva, proposal)
    else:
        artifact = {
            "checked_protocol": "call-inspection.json",
            "checked_schema": "boundary-status.json",
            "component": "component-work-package-v6.json",
        }.get(str(subject.get("kind")))
        if artifact is None:
            raise ValueError("boundary subject kind is unsupported")
        _, payload = _realize_artifact(
            args,
            f"boundaries.subjects.{_attr_segment(canonical)}.source",
            artifact,
        )
    if payload.get("format") == COMPONENT_WORK_PACKAGE_V6_FORMAT:
        from ..components.work_package_v6 import ComponentWorkPackageV6

        payload = dict(ComponentWorkPackageV6.parse(payload).payload)
        if canonical != f"component:{payload.get('component_id')}":
            raise ValueError("boundary component source binds another subject")
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
    if payload.get("format") == COMPONENT_WORK_PACKAGE_V6_FORMAT:
        if canonical != args.subject:
            print(f"resolved {args.subject} -> {canonical}")
        print(
            f"{canonical}: status={'complete' if not payload.get('blockers') else 'incomplete'} "
            f"authority=not-applicable "
            f"component={payload.get('component_id')} "
            f"mode={payload.get('proof_classification')}"
        )
        for operation in payload.get("operations", []):
            print(
                f"  operation: {operation.get('operation_id')} "
                f"symbol={operation.get('symbol')}"
            )
        for issue in payload.get("blockers", []):
            print(f"  blocker: {issue}")
        return 0
    print(
        f"{canonical}: status={payload.get('status')} "
        f"dialect={payload.get('abi_dialect')} "
        f"convention={payload.get('calling_convention')}"
    )
    faithful = payload.get("faithful_prototype")
    if faithful:
        print(f"  faithful: {faithful}")
    idiomatic = payload.get("idiomatic_prototype")
    if idiomatic:
        print(f"  idiomatic: {idiomatic}")
    for issue in payload.get("issues", payload.get("blockers", [])):
        print(f"  blocker: {issue}")
    return 0


def _boundary_propose(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    if args.proposal is not None and subject.get("dynamic") is not True:
        raise ValueError("--proposal requires an unconfigured component seed")
    canonical = str(subject["canonicalSubject"])
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
        f"boundaries.subjects.{_attr_segment(canonical)}.source",
        no_link=True,
    )


def _boundary_adopt(args: argparse.Namespace) -> int:
    subject = _boundary_subject(args)
    canonical = str(subject["canonicalSubject"])
    if args.output is None:
        raise ValueError("boundary adopt requires --output FILE")
    configured_seed = (subject.get("kind") == "component"
                       and args.subject.startswith("component-seed:"))
    if subject.get("dynamic") is True or (configured_seed and args.input is not None):
        if args.input is None:
            raise ValueError("component seed adoption requires --input DIR with "
                             "reviewed interface.json and binding.json")
        from .component_review import reviewed_seed_identity, write_reviewed_component_inputs
        args.proposal = reviewed_seed_identity(args.input)
        _rva, proposal = _component_seed_proposal(args)
        write_reviewed_component_inputs(draft=args.input, proposal=proposal,
                                       program_id=args.target, output=args.output.resolve(),
                                       expected_component_id=(canonical.removeprefix("component:")
                                                              if configured_seed else None))
        print(f"wrote canonical component draft inputs: {args.output.resolve()}")
        print("authority=no; update the configured inputs and check the edited source"
              if configured_seed else "authority=no; configure these inputs, then use component start")
        return 0
    if args.input is not None:
        raise ValueError("--input is supported only for component seeds")
    if subject.get("kind") == "component":
        component_id = canonical.removeprefix("component:")
        raise ValueError(
            "component adoption was replaced by the writable transition: "
            f"component start {args.target} {component_id} --apply"
        )
    if "intent" not in subject.get("products", []):
        raise ValueError(f"boundary subject {canonical!r} has no adoptable intent")
    _, payload = _realize_artifact(
        args, f"boundaries.subjects.{_attr_segment(canonical)}.intent"
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
    canonical = str(subject["canonicalSubject"])
    if subject.get("dynamic") is True:
        _component_seed_proposal(args)
        raise ValueError(
            "component seed is a non-authorizing proposal; author a checked "
            "interface and binding, then start and check the resulting component"
        )
    if "check" not in subject.get("products", []):
        raise ValueError(f"boundary subject {canonical!r} has no checked product")
    kind = str(subject.get("kind"))
    artifact = {
        "checked_protocol": "call-status.json",
        "checked_schema": "boundary-status.json",
        "component": "semantic-provider-qualification.json",
    }.get(kind)
    if artifact is None:
        raise ValueError("boundary subject kind is unsupported")
    _, payload = _realize_artifact(
        args,
        f"boundaries.subjects.{_attr_segment(canonical)}.check",
        artifact,
    )
    if kind == "component":
        from ..semantic_providers.qualification_v2 import (
            SemanticProviderQualificationV2,
        )

        qualification = SemanticProviderQualificationV2.parse(payload)
        component_id = canonical.removeprefix("component:")
        if not qualification.provider_id.endswith(f".{component_id}.portable-c"):
            raise ValueError("boundary qualification binds another component")
        state = qualification.payload["status"]
    else:
        state = payload.get("status")
    if state != "complete":
        raise ValueError(f"boundary subject {canonical!r} is not complete")
    return 0


def _library_index(args: argparse.Namespace) -> Mapping[str, Any]:
    libraries = _operator_index(args).get("libraries")
    if not isinstance(libraries, Mapping):
        raise ValueError(
            f"library recognition is not configured for target {args.target!r}"
        )
    return libraries


def _library_status_payload(args: argparse.Namespace) -> dict[str, Any]:
    _library_index(args)
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
    from ..target_bundles.metadata import TargetMetadata, TargetMetadataError

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
            "this mutation requires a writable local --target-flake path"
        )
    root = root.resolve()
    direct = root if (root / "target.json").is_file() else root / args.target
    candidates = [direct]
    if root.is_dir():
        candidates.extend(
            child for child in sorted(root.iterdir())
            if child.is_dir() and child != direct and (child / "target.json").is_file()
        )
    matches = []
    for candidate in candidates:
        if not (candidate / "target.json").is_file():
            continue
        try:
            metadata = TargetMetadata.load(candidate / "target.json")
        except TargetMetadataError:
            if candidate == direct:
                raise
            continue
        if metadata.identity == args.target:
            matches.append(candidate.resolve())
    matches = list(dict.fromkeys(matches))
    if len(matches) != 1:
        raise ValueError(
            f"local target bundle lookup for {args.target!r} found {len(matches)} matches"
        )
    return matches[0]


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
    libraries = _library_index(args)
    if args.selection is None:
        return _build(args, "libraries.check", no_link=True)
    available = libraries.get("selections", {})
    if not isinstance(available, Mapping):
        raise ValueError("library selection index is malformed")
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
    suffix = f"libraries.selections.{_attr_segment(selection)}.check"
    return _build(args, suffix, no_link=True)


def _candidate_configuration(
    args: argparse.Namespace,
) -> tuple[str, Mapping[str, Any]]:
    index = _operator_index(args)
    candidate = index.get("candidate")
    configurations = (
        candidate.get("configurations", {})
        if isinstance(candidate, Mapping)
        else {}
    )
    configuration = args.configuration or index.get("defaultConfiguration")
    row = configurations.get(configuration) if isinstance(configurations, Mapping) else None
    if not isinstance(row, Mapping):
        raise ValueError(
            f"unknown candidate configuration {configuration!r}; "
            f"available: {', '.join(configurations)}"
        )
    return str(configuration), row


def _candidate_build(args: argparse.Namespace) -> int:
    configuration, _ = _candidate_configuration(args)
    return _build(
        args,
        f"candidate.configurations.{_attr_segment(configuration)}.realization",
    )


def _candidate_list(args: argparse.Namespace) -> int:
    index = _operator_index(args)
    candidate = index.get("candidate")
    if not isinstance(candidate, Mapping):
        raise ValueError("target has no candidate index")
    if args.json:
        print(json.dumps(index, indent=2, sort_keys=True))
        return 0
    default = index.get("defaultConfiguration")
    configurations = candidate.get("configurations", {})
    suites = candidate.get("testSuites", {})
    if not isinstance(configurations, Mapping) or not isinstance(suites, Mapping):
        raise ValueError("target candidate index is malformed")
    for configuration, raw in configurations.items():
        row = dict(raw) if isinstance(raw, Mapping) else {}
        marker = "default" if configuration == default else ""
        declared = sorted(
            identity
            for identity, row in suites.items()
            if isinstance(row, Mapping)
            and row.get("configurationId") == configuration
        )
        print(
            f"configuration {str(configuration):32} {marker:8} "
            f"mode={row.get('mode')} "
            f"tests={','.join(declared) if declared else 'none'}"
        )
    return 0


def _candidate_status(args: argparse.Namespace) -> int:
    configuration, configuration_row = _candidate_configuration(args)
    path, selection_payload = _realize_artifact(
        args,
        f"candidate.configurations.{_attr_segment(configuration)}.selection",
        "implementation-selection.json",
    )
    payload, raw_blockers = project_candidate_selection(
        target_id=args.target,
        configuration_id=configuration,
        path=path,
        value=selection_payload,
    )
    subject = _single_status_subject(payload)
    coverage = payload.get("provider_coverage")
    definitions = (
        coverage.get("definitions", {})
        if isinstance(coverage, Mapping)
        else {}
    )
    by_kind = (
        definitions.get("by_kind", {})
        if isinstance(definitions, Mapping)
        else {}
    )
    headline = (
        f"{args.target}: status={payload.get('status')} "
        f"configuration={configuration} "
        f"mode={configuration_row.get('mode')} "
        f"exact-selection={subject.get('state')} "
        f"portable-progress={coverage.get('portable_progress', 'unknown') if isinstance(coverage, Mapping) else 'unknown'} "
        f"fallback-free={str(coverage.get('fallback_free') is True).lower() if isinstance(coverage, Mapping) else 'unknown'} "
        f"realization-ready={str(selection_payload.get('ready_for_realization') is True).lower()} "
        f"definitions={definitions.get('selected', 0)} "
        f"portable-c={by_kind.get('qualified_portable_c', 0)} "
        f"generated-c={by_kind.get('generated_behavioral_c', 0)} "
        f"external={by_kind.get('external_environment', 0)} "
        f"runtime={by_kind.get('qualified_runtime', 0)} "
        f"pinned={by_kind.get('pinned_binary', 0)} "
        f"blockers={subject.get('blockers', {}).get('count', 0)}"
    )
    return _render_operator_status(
        args,
        payload,
        headline=headline,
        raw_blockers=raw_blockers,
        default_family="provider-selection",
        default_code="provider_selection_blocker",
    )


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
        args, f"candidate.testSuites.{_attr_segment(args.suite)}", no_link=True
    )


def _add_component_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("unit", type=_identifier, help="component unit id")


def _add_progress_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--limit", type=_positive, default=20)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--family")
    parser.add_argument("--code")
    parser.add_argument("--details", action="store_true")


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
        parser.add_argument("--near", type=_parse_rva, metavar="RVA",
                            help="list bounded boundary alternatives at this instruction")
        parser.add_argument("--json", action="store_true")
        return _component_list
    if name in {
        "component status", "component build", "component start", "component check",
    }:
        _add_component_selector(parser)
        if name == "component status":
            _add_progress_arguments(parser)
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
        if name == "component start":
            destination = parser.add_mutually_exclusive_group(required=True)
            destination.add_argument(
                "--output", type=Path, metavar="DIR",
                help="copy the checked package into a writable directory",
            )
            destination.add_argument(
                "--apply", action="store_true",
                help="atomically add the skeleton and its canonical source intent",
            )
            return _component_start
        parser.add_argument("--source", action="store_true",
                            help="check source compilation/profile without requiring or granting qualification")
        parser.add_argument('--compare-baseline', action='store_true',
                            help='with --source, compare a configured source edit; does not import baseline application proofs')
        parser.add_argument("--conditional", action="store_true",
                            help="check under configured runtime contracts without provider or activation authority")
        parser.add_argument('--region', action='append', metavar='OPERATION/OBLIGATION',
                            help='with --conditional, check selected existing regions and keep other coverage unresolved (repeatable)')
        parser.add_argument('--query-timeout', type=_positive, metavar='SECONDS',
                            help='with --conditional, override the per-query timeout, not the whole-command duration')
        parser.add_argument('--entry-query-timeout', type=_positive, metavar='SECONDS',
                            help='with --conditional, give independent entry queries their own timeout; defaults to --query-timeout')
        parser.add_argument("--local-contracts", action="store_true",
                            help="with --source, check configured local memory and service contracts without provider authority")
        parser.add_argument("--json", action="store_true", help="show structured --source or --conditional feedback")
        return _component_check
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
        if name in {"boundary inspect", "boundary propose"}:
            parser.add_argument("--proposal", type=_opaque_identity, metavar="ID",
                                help="select an explicit component-seed alternative")
        if name == "boundary inspect":
            parser.add_argument("--json", action="store_true")
            return _boundary_inspect
        if name == "boundary propose":
            parser.add_argument("--output", type=Path, metavar="DIR")
            return _boundary_propose
        if name == "boundary adopt":
            parser.add_argument("--input", type=Path, metavar="DIR",
                                help="edited component seed with canonical interface and binding")
            parser.add_argument("--output", type=Path, metavar="PATH")
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
    if name == "candidate test":
        parser.add_argument("--suite", type=_identifier)
        return _candidate_test
    raise ValueError(f"unsupported operator workflow: {name}")


__all__ = ["configure_command"]
