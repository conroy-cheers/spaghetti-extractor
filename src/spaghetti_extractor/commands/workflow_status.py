"""Present checked operator status without owning SDK realization or command dispatch."""
from __future__ import annotations

import argparse
import copy
import json
from collections.abc import Sequence
from typing import Any, Mapping

from ..operator.formats import OPERATOR_WORK_STATUS_FORMAT
from ..operator.projections import normalize_blocker
from ..operator.work_status import build_operator_blocker_detail_v1


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
