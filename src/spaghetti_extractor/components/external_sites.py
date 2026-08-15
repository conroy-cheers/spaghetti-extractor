"""Local, checked external-site slices for independently lifted components.

The authority graph owns external-call truth.  Component work must consume that
truth without depending semantically on every unrelated site in the program.
This module validates a canonical v3 authority artifact, projects only records
for one resolved lift unit, and emits a small content-addressable JSON boundary.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.io import open_artifact_reader_v3
from ..external.site_authority import (
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    parse_canonical_external_site_record,
)
from ..external.contracts import CheckedExternalSiteContract
from ..util import write_json
from .formats import (
    COMPONENT_EXTERNAL_SITE_SLICE_V1_FORMAT,
    COMPONENT_RESOLUTION_SLICE_V1_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from .intent import ComponentIntentError


@dataclass(frozen=True)
class ComponentExternalSite:
    site_id: str
    unit_id: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    status: str
    authorizing: bool
    identity: Mapping[str, Any]
    contract: CheckedExternalSiteContract | None
    primary_blocker: Mapping[str, Any] | None


@dataclass(frozen=True)
class ComponentExternalSiteSlice:
    lift_unit_id: str
    status: str
    projection_sha256: str
    unit_ids: tuple[str, ...]
    sites: tuple[ComponentExternalSite, ...]
    issues: tuple[Mapping[str, Any], ...]

    def by_event(self) -> dict[tuple[str, int], tuple[ComponentExternalSite, ...]]:
        grouped: dict[tuple[str, int], list[ComponentExternalSite]] = {}
        for site in self.sites:
            grouped.setdefault((site.unit_id, site.event_index), []).append(site)
        return {
            key: tuple(sorted(rows, key=lambda row: row.alternative_index))
            for key, rows in grouped.items()
        }


def project_component_external_sites(
    *,
    canonical_external_sites: Path | str,
    resolution: Path | str | Mapping[str, object],
    lift_unit_id: str,
    out: Path | str,
) -> dict[str, object]:
    """Project exact canonical records for one resolved component or group."""

    resolved = _load_resolution(resolution)
    lift_unit = _find_lift_unit(resolved, lift_unit_id)
    unit_ids = tuple(sorted(_string_array(lift_unit.get("unit_ids"), "unit IDs")))
    reader = open_artifact_reader_v3(canonical_external_sites)
    if reader.manifest.artifact_kind != CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3:
        raise ComponentIntentError(
            "component external-site projection requires canonical-external-sites-v3"
        )

    records: list[dict[str, object]] = []
    issues: list[dict[str, object]] = []
    for unit_id in unit_ids:
        artifact_record = reader.find_record(unit_id)
        if artifact_record is None:
            issues.append(
                {
                    "status": "incomplete",
                    "code": "component_external_site_record_missing",
                    "unit_id": unit_id,
                    "remediation": (
                        "rebuild canonical external-site authority for the exact "
                        "machine-IR inventory"
                    ),
                }
            )
            continue
        decoded = parse_canonical_external_site_record(
            artifact_record.value.to_value()
        )
        if decoded.record_id != unit_id:
            raise ComponentIntentError(
                f"canonical external-site record {decoded.record_id!r} is stored "
                f"under component unit {unit_id!r}"
            )
        payload = copy.deepcopy(dict(decoded.payload))
        records.append(
            {
                "unit_id": unit_id,
                "record_sha256": _canonical_sha256(payload),
                "record": payload,
            }
        )
        if decoded.status != "complete" or not decoded.authorizing:
            blocker = (
                copy.deepcopy(decoded.primary_blocker)
            )
            issues.append(
                {
                    "status": decoded.status,
                    "code": "component_external_site_record_not_authorizing",
                    "unit_id": unit_id,
                    "primary_blocker": blocker,
                    "remediation": (
                        "close the canonical external-site authority frontier before "
                        "using this site in component evidence"
                    ),
                }
            )

    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    core: dict[str, object] = {
        "format": COMPONENT_EXTERNAL_SITE_SLICE_V1_FORMAT,
        "status": status,
        "lift_unit_id": lift_unit_id,
        "executes_original_binary": False,
        "bindings": {
            "resolution_sha256": resolved["resolution_sha256"],
            "unit_ids": list(unit_ids),
            "source_artifact_kind": reader.manifest.artifact_kind,
            # Deliberately omit the whole-program artifact identity.  Each copied
            # canonical record is self-contained and content-bound; unrelated
            # site changes must not invalidate this component's descendants.
            "selected_record_sha256s": {
                str(row["unit_id"]): str(row["record_sha256"])
                for row in records
            },
        },
        "authority": {
            "source": "canonical_external_site_checker_v3",
            "can_supply_component_call_contracts": status == "checked",
            "can_authorize_candidate_runtime": False,
        },
        "records": records,
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("unit_id")),
            ),
        ),
    }
    result = {**core, "projection_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def load_component_external_site_slice(
    value: Path | str | Mapping[str, object],
) -> ComponentExternalSiteSlice:
    payload = _load_json(value, "component external-site slice")
    if payload.get("format") != COMPONENT_EXTERNAL_SITE_SLICE_V1_FORMAT:
        raise ComponentIntentError("unsupported component external-site slice format")
    core = copy.deepcopy(dict(payload))
    observed_hash = core.pop("projection_sha256", None)
    if observed_hash != _canonical_sha256(core):
        raise ComponentIntentError("component external-site slice self-hash is stale")
    status = _string(payload.get("status"), "component external-site status")
    if status not in {"checked", "incomplete", "violated"}:
        raise ComponentIntentError("component external-site status is invalid")
    bindings = _object(payload.get("bindings"), "component external-site bindings")
    unit_ids = tuple(_string_array(bindings.get("unit_ids"), "bound unit IDs"))
    sites: list[ComponentExternalSite] = []
    for raw_record in _array(payload.get("records"), "external-site records"):
        record_row = _object(raw_record, "external-site projected record")
        record_payload = _object(
            record_row.get("record"), "canonical external-site record"
        )
        if record_row.get("record_sha256") != _canonical_sha256(record_payload):
            raise ComponentIntentError(
                "projected canonical external-site record hash is stale"
            )
        record = parse_canonical_external_site_record(record_payload)
        if record.record_id != record_row.get("unit_id"):
            raise ComponentIntentError(
                "projected canonical external-site record identity is stale"
            )
        for site in record.sites:
            sites.append(
                ComponentExternalSite(
                    site_id=site.site_id,
                    unit_id=site.unit_id,
                    event_index=site.event_index,
                    alternative_index=site.alternative_index,
                    event_sha256=site.event_sha256,
                    target_sha256=site.target_sha256,
                    status=site.status,
                    authorizing=site.authorizing,
                    identity=copy.deepcopy(dict(site.identity)),
                    contract=site.contract,
                    primary_blocker=copy.deepcopy(site.primary_blocker),
                )
            )
    ordered = tuple(
        sorted(
            sites,
            key=lambda row: (row.unit_id, row.event_index, row.alternative_index),
        )
    )
    if len({row.site_id for row in ordered}) != len(ordered):
        raise ComponentIntentError("component external-site IDs are duplicated")
    return ComponentExternalSiteSlice(
        lift_unit_id=_string(payload.get("lift_unit_id"), "lift-unit ID"),
        status=status,
        projection_sha256=_string(observed_hash, "external-site projection SHA-256"),
        unit_ids=unit_ids,
        sites=ordered,
        issues=tuple(
            copy.deepcopy(_object(row, "external-site issue"))
            for row in _array(payload.get("issues"), "external-site issues")
        ),
    )


def _load_resolution(value: Path | str | Mapping[str, object]) -> dict[str, object]:
    payload = _load_json(value, "component resolution")
    if payload.get("format") not in {
        COMPONENT_RESOLUTION_V2_FORMAT,
        COMPONENT_RESOLUTION_SLICE_V1_FORMAT,
    }:
        raise ComponentIntentError("unsupported component resolution format")
    core = copy.deepcopy(dict(payload))
    observed_hash = core.pop("resolution_sha256", None)
    if observed_hash != _canonical_sha256(core):
        raise ComponentIntentError("component resolution self-hash is stale")
    return payload


def _find_lift_unit(
    payload: Mapping[str, object], lift_unit_id: str
) -> Mapping[str, object]:
    matches = [
        row
        for field in ("components", "groups")
        for row in _array(payload.get(field, []), f"resolved {field}")
        if isinstance(row, Mapping) and row.get("id") == lift_unit_id
    ]
    if len(matches) != 1:
        raise ComponentIntentError(
            f"lift unit {lift_unit_id!r} resolved to {len(matches)} definitions"
        )
    return matches[0]


def _load_json(
    value: Path | str | Mapping[str, object], description: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    path = Path(value)
    if path.is_dir():
        path = path / "external-sites.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc
    return _object(payload, description)


def _object(value: object, description: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return copy.deepcopy(dict(value))


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


def _string_array(value: object, description: str) -> list[str]:
    values = _array(value, description)
    if any(not isinstance(item, str) or not item for item in values):
        raise ComponentIntentError(f"{description} contains an invalid string")
    result = [str(item) for item in values]
    if result != sorted(set(result)):
        raise ComponentIntentError(f"{description} must be sorted and unique")
    return result


def _canonical_sha256(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "ComponentExternalSite",
    "ComponentExternalSiteSlice",
    "load_component_external_site_slice",
    "project_component_external_sites",
]
