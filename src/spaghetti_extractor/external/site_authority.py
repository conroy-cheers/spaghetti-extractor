"""Public consumer schema for canonical external-site authority records.

The terminal authority package produces these records, but consumers must not
depend on checker implementation modules.  This module owns the stable wire
boundary used by candidate and component tooling.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from ..errors import StageAInputError
from .contracts import (
    CheckedExternalSiteContract,
    checked_external_site_contract_from_authority,
)

class CanonicalExternalSiteRecordError(StageAInputError):
    """A canonical external-site record violates its public wire schema."""


@dataclass(frozen=True)
class CheckedCanonicalExternalSite:
    site_id: str
    unit_id: str
    event_index: int
    alternative_index: int
    event_sha256: str
    target_sha256: str
    identity: Mapping[str, Any]
    status: str
    authorizing: bool
    contract: CheckedExternalSiteContract | None
    primary_blocker: Mapping[str, Any] | None


@dataclass(frozen=True)
class CheckedCanonicalExternalSiteRecord:
    record_id: str
    unit_sha256: str
    status: str
    authorizing: bool
    sites: tuple[CheckedCanonicalExternalSite, ...]
    primary_blocker: Mapping[str, Any] | None
    payload: Mapping[str, Any]


def parse_canonical_external_site_record(
    value: object,
) -> CheckedCanonicalExternalSiteRecord:
    row = _strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "status",
            "authorizing",
            "sites",
            "primary_blocker",
            "dependencies",
        },
        "canonical external-site record",
    )
    if row["schema"] != CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA:
        raise CanonicalExternalSiteRecordError(
            "record is not canonical-external-site-record-v3"
        )
    record_id = _text(row["id"], "canonical external-site unit ID")
    unit_sha256 = _digest(row["unit_sha256"], "canonical external-site unit hash")
    status = _status(row["status"], "canonical external-site status")
    authorizing = _boolean(row["authorizing"], "canonical external-site authority")
    blocker = _blocker(row["primary_blocker"], status=status)
    _check_decision(status=status, authorizing=authorizing, blocker=blocker)
    _dependencies(row["dependencies"])

    sites = tuple(
        _parse_site(item, record_id=record_id)
        for item in _array(row["sites"], "canonical external sites")
    )
    if sites != tuple(sorted(sites, key=lambda item: item.site_id)) or len(
        {site.site_id for site in sites}
    ) != len(sites):
        raise CanonicalExternalSiteRecordError(
            "canonical external sites must be sorted and unique"
        )
    if authorizing != all(site.authorizing for site in sites):
        raise CanonicalExternalSiteRecordError(
            "record authority disagrees with its external-site inventory"
        )
    return CheckedCanonicalExternalSiteRecord(
        record_id=record_id,
        unit_sha256=unit_sha256,
        status=status,
        authorizing=authorizing,
        sites=sites,
        primary_blocker=blocker,
        payload=copy.deepcopy(row),
    )


def _parse_site(
    value: object, *, record_id: str
) -> CheckedCanonicalExternalSite:
    row = _strict_object(
        value,
        {
            "id",
            "unit_id",
            "event_index",
            "alternative_index",
            "event_sha256",
            "target_sha256",
            "identity",
            "status",
            "authorizing",
            "contract",
            "primary_blocker",
        },
        "canonical external site",
    )
    unit_id = _text(row["unit_id"], "canonical external-site unit ID")
    if unit_id != record_id:
        raise CanonicalExternalSiteRecordError(
            "canonical external-site record mixes source units"
        )
    event_index = _uint(row["event_index"], "external event index")
    alternative_index = _uint(
        row["alternative_index"], "external alternative index"
    )
    event_sha256 = _digest(row["event_sha256"], "external event hash")
    target_sha256 = _digest(row["target_sha256"], "external target hash")
    identity = _strict_mapping(row["identity"], "external identity")
    # target_sha256 binds the complete target/event descriptor used by the
    # authority checker.  identity is its normalized public import/protocol
    # identity and intentionally omits arguments, effects, and control data.
    # The complete descriptor is not present on this consumer boundary, so the
    # target digest can only be checked through the canonical site ID below.
    site_id = _text(row["id"], "canonical external-site ID")
    expected_site_id = "external-site-v3:" + canonical_sha256_v3(
        {
            "unit_id": unit_id,
            "event_index": event_index,
            "alternative_index": alternative_index,
            "target_sha256": target_sha256,
        }
    )
    if site_id != expected_site_id:
        raise CanonicalExternalSiteRecordError(
            "canonical external-site ID does not bind its identity"
        )
    status = _status(row["status"], "canonical external-site status")
    authorizing = _boolean(row["authorizing"], "canonical external-site authority")
    blocker = _blocker(row["primary_blocker"], status=status)
    _check_decision(status=status, authorizing=authorizing, blocker=blocker)
    contract = (
        None
        if row["contract"] is None
        else checked_external_site_contract_from_authority(
            _strict_mapping(row["contract"], "canonical external contract"),
            context=f"canonical external site {site_id}",
        )
    )
    if authorizing != (contract is not None):
        raise CanonicalExternalSiteRecordError(
            "canonical external-site authority disagrees with its contract"
        )
    if contract is not None and {
        key: item
        for key, item in contract.identity.payload().items()
        if item is not None
    } != {key: item for key, item in identity.items() if item is not None}:
        raise CanonicalExternalSiteRecordError(
            "canonical external contract identity disagrees with its site"
        )
    return CheckedCanonicalExternalSite(
        site_id=site_id,
        unit_id=unit_id,
        event_index=event_index,
        alternative_index=alternative_index,
        event_sha256=event_sha256,
        target_sha256=target_sha256,
        identity=copy.deepcopy(identity),
        status=status,
        authorizing=authorizing,
        contract=contract,
        primary_blocker=blocker,
    )


def _check_decision(
    *, status: str, authorizing: bool, blocker: Mapping[str, Any] | None
) -> None:
    if status == "complete":
        if not authorizing or blocker is not None:
            raise CanonicalExternalSiteRecordError(
                "complete external-site decision is not authorizing"
            )
    elif authorizing or blocker is None:
        raise CanonicalExternalSiteRecordError(
            "non-complete external-site decision fails open"
        )


def _blocker(value: object, *, status: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    row = _strict_object(
        value,
        {"status", "code", "input", "record_id"},
        "external-site blocker",
    )
    if _status(row["status"], "external-site blocker status") != status:
        raise CanonicalExternalSiteRecordError(
            "external-site blocker status disagrees with its record"
        )
    _text(row["code"], "external-site blocker code")
    if (row["input"] is None) != (row["record_id"] is None):
        raise CanonicalExternalSiteRecordError(
            "external-site blocker has a partial dependency"
        )
    if row["input"] is not None:
        _text(row["input"], "external-site blocker input")
        _text(row["record_id"], "external-site blocker record ID")
    return copy.deepcopy(row)


def _dependencies(value: object) -> None:
    rows = _array(value, "external-site dependencies")
    normalized: list[tuple[str, str]] = []
    for item in rows:
        row = _strict_object(
            item, {"input", "record_id"}, "external-site dependency"
        )
        normalized.append(
            (
                _text(row["input"], "external-site dependency input"),
                _text(row["record_id"], "external-site dependency record ID"),
            )
        )
    if normalized != sorted(set(normalized)):
        raise CanonicalExternalSiteRecordError(
            "external-site dependencies must be sorted and unique"
        )


def _strict_object(
    value: object, fields: set[str], description: str
) -> dict[str, Any]:
    row = _strict_mapping(value, description)
    if set(row) != fields:
        raise CanonicalExternalSiteRecordError(
            f"{description} fields differ: expected={sorted(fields)!r}, "
            f"observed={sorted(row)!r}"
        )
    return row


def _strict_mapping(value: object, description: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CanonicalExternalSiteRecordError(f"{description} must be an object")
    return copy.deepcopy(dict(value))


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise CanonicalExternalSiteRecordError(f"{description} must be an array")
    return value


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise CanonicalExternalSiteRecordError(
            f"{description} must be a nonempty string"
        )
    return value


def _digest(value: object, description: str) -> str:
    result = _text(value, description)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise CanonicalExternalSiteRecordError(
            f"{description} must be a lowercase SHA-256"
        )
    return result


def _uint(value: object, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CanonicalExternalSiteRecordError(
            f"{description} must be an unsigned integer"
        )
    return value


def _boolean(value: object, description: str) -> bool:
    if not isinstance(value, bool):
        raise CanonicalExternalSiteRecordError(f"{description} must be Boolean")
    return value


def _status(value: object, description: str) -> str:
    result = _text(value, description)
    if result not in {"complete", "incomplete", "violated"}:
        raise CanonicalExternalSiteRecordError(f"{description} is invalid")
    return result


__all__ = [
    "CANONICAL_EXTERNAL_SITE_RECORD_V3_SCHEMA",
    "CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3",
    "CanonicalExternalSiteRecordError",
    "CheckedCanonicalExternalSite",
    "CheckedCanonicalExternalSiteRecord",
    "parse_canonical_external_site_record",
]
