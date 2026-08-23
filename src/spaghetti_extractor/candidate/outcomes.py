"""Checked native-boundary outcome and IA-32 SEH protocols."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT,
    CHECKED_SEH_PROTOCOL_FORMAT,
)
from ..errors import ToolkitInputError


_OUTCOMES = frozenset({"normal", "no_return", "exceptional", "nonlocal"})
_PROJECTION_FIELDS = frozenset(
    {"registers", "flags", "x87", "stack", "exception_record", "context"}
)


class CheckedOutcomeProtocolError(ToolkitInputError):
    """An outcome or SEH contract is malformed, stale, or fail-open."""


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CheckedOutcomeProtocolError(f"{context} must be a nonempty string")
    return value


def _digest(value: Any, context: str) -> str:
    text = _text(value, context)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise CheckedOutcomeProtocolError(f"{context} must be lowercase SHA-256")
    return text


def _u32(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise CheckedOutcomeProtocolError(f"{context} must fit uint32")
    return int(value)


def _canonical_strings(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CheckedOutcomeProtocolError(f"{context} must be a list")
    result = tuple(_text(item, context) for item in value)
    if result != tuple(sorted(set(result))):
        raise CheckedOutcomeProtocolError(f"{context} must be sorted and unique")
    return result


@dataclass(frozen=True)
class CheckedBoundaryOutcomeProtocolV1:
    protocol_id: str
    outcomes: tuple[str, ...]
    normal_projection_id: str | None
    no_return_disposition: str | None
    seh_protocol_ids: tuple[str, ...]
    nonlocal_protocol_ids: tuple[str, ...]
    issues: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        outcomes: Sequence[str],
        normal_projection_id: str | None = None,
        no_return_disposition: str | None = None,
        seh_protocol_ids: Sequence[str] = (),
        nonlocal_protocol_ids: Sequence[str] = (),
        issues: Sequence[str] = (),
    ) -> "CheckedBoundaryOutcomeProtocolV1":
        kinds = tuple(sorted(set(_text(item, "outcome kind") for item in outcomes)))
        if not kinds or not set(kinds) <= _OUTCOMES:
            raise CheckedOutcomeProtocolError("outcome protocol has unsupported outcomes")
        seh = tuple(sorted(set(_text(item, "SEH protocol ID") for item in seh_protocol_ids)))
        nonlocal_ids = tuple(sorted(set(_text(item, "nonlocal protocol ID") for item in nonlocal_protocol_ids)))
        if ("exceptional" in kinds) != bool(seh):
            raise CheckedOutcomeProtocolError("exceptional outcome requires exactly its SEH authority inventory")
        if ("nonlocal" in kinds) != bool(nonlocal_ids):
            raise CheckedOutcomeProtocolError("nonlocal outcome requires an explicit protocol inventory")
        if ("normal" in kinds) != (normal_projection_id is not None):
            raise CheckedOutcomeProtocolError("normal outcome requires a result projection ID")
        if ("no_return" in kinds) != (no_return_disposition is not None):
            raise CheckedOutcomeProtocolError("no-return outcome requires a disposition")
        if no_return_disposition is not None and no_return_disposition not in {
            "terminate_process", "terminate_thread", "unreachable",
        }:
            raise CheckedOutcomeProtocolError("no-return disposition is unsupported")
        issue_values = tuple(sorted(set(_text(item, "outcome issue") for item in issues)))
        core = {
            "format": CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT,
            "status": "complete" if not issue_values else "incomplete",
            "outcomes": list(kinds),
            "normal_projection_id": normal_projection_id,
            "no_return_disposition": no_return_disposition,
            "seh_protocol_ids": list(seh),
            "nonlocal_protocol_ids": list(nonlocal_ids),
            "issues": list(issue_values),
        }
        return cls(
            f"checked-boundary-outcome-protocol-v1:{canonical_sha256_v3(core)}",
            kinds,
            normal_projection_id,
            no_return_disposition,
            seh,
            nonlocal_ids,
            issue_values,
        )

    @classmethod
    def parse(cls, value: object) -> "CheckedBoundaryOutcomeProtocolV1":
        fields = {
            "format", "id", "status", "outcomes", "normal_projection_id",
            "no_return_disposition", "seh_protocol_ids", "nonlocal_protocol_ids",
            "issues",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise CheckedOutcomeProtocolError("checked outcome protocol has invalid fields")
        if value["format"] != CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT:
            raise CheckedOutcomeProtocolError("unsupported checked outcome protocol format")
        for optional in ("normal_projection_id", "no_return_disposition"):
            if value[optional] is not None and not isinstance(value[optional], str):
                raise CheckedOutcomeProtocolError(f"outcome protocol {optional} is invalid")
        result = cls.create(
            outcomes=_canonical_strings(value["outcomes"], "outcomes"),
            normal_projection_id=value["normal_projection_id"],
            no_return_disposition=value["no_return_disposition"],
            seh_protocol_ids=_canonical_strings(value["seh_protocol_ids"], "SEH protocol IDs"),
            nonlocal_protocol_ids=_canonical_strings(value["nonlocal_protocol_ids"], "nonlocal protocol IDs"),
            issues=_canonical_strings(value["issues"], "outcome issues"),
        )
        if value["id"] != result.protocol_id or value["status"] != result.status:
            raise CheckedOutcomeProtocolError("checked outcome protocol is stale")
        return result

    @property
    def status(self) -> str:
        return "complete" if not self.issues else "incomplete"

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CHECKED_BOUNDARY_OUTCOME_PROTOCOL_FORMAT,
            "id": self.protocol_id,
            "status": self.status,
            "outcomes": list(self.outcomes),
            "normal_projection_id": self.normal_projection_id,
            "no_return_disposition": self.no_return_disposition,
            "seh_protocol_ids": list(self.seh_protocol_ids),
            "nonlocal_protocol_ids": list(self.nonlocal_protocol_ids),
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class CheckedSEHProtocolV1:
    protocol_id: str
    transition_id: str
    transition_sha256: str
    exception: Mapping[str, object]
    projections: Mapping[str, tuple[str, ...]]
    handler_unit_id: str | None
    handler_rva: int | None
    resumption_unit_id: str | None
    resumption_rva: int | None
    unwind_effect_ids: tuple[str, ...]
    escape_disposition: str
    gateway_handler_symbol: str
    portals: tuple[Mapping[str, object], ...]
    observed_address_fields: tuple[str, ...]
    address_policy: str
    issues: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        transition_id: str,
        transition_sha256: str,
        exception: Mapping[str, object],
        projections: Mapping[str, Sequence[str]],
        handler_unit_id: str | None,
        handler_rva: int | None,
        resumption_unit_id: str | None,
        resumption_rva: int | None,
        unwind_effect_ids: Sequence[str],
        escape_disposition: str,
        gateway_handler_symbol: str,
        portals: Sequence[Mapping[str, object]],
        observed_address_fields: Sequence[str] = (),
        address_policy: str = "candidate_portal_mapping",
        issues: Sequence[str] = (),
    ) -> "CheckedSEHProtocolV1":
        transition_id = _text(transition_id, "exceptional transition ID")
        transition_sha256 = _digest(transition_sha256, "exceptional transition SHA-256")
        exception_row = _parse_exception(exception)
        if set(projections) != _PROJECTION_FIELDS:
            raise CheckedOutcomeProtocolError("SEH projections are incomplete")
        projection_rows = {
            key: tuple(sorted(set(_text(item, f"SEH {key} projection") for item in projections[key])))
            for key in sorted(_PROJECTION_FIELDS)
        }
        if handler_unit_id is not None:
            handler_unit_id = _text(handler_unit_id, "SEH handler unit ID")
        if (handler_unit_id is None) != (handler_rva is None):
            raise CheckedOutcomeProtocolError(
                "SEH handler unit and RVA must be supplied together"
            )
        if handler_rva is not None:
            handler_rva = _u32(handler_rva, "SEH handler RVA")
        if resumption_unit_id is not None:
            resumption_unit_id = _text(resumption_unit_id, "SEH resumption unit ID")
        if (resumption_unit_id is None) != (resumption_rva is None):
            raise CheckedOutcomeProtocolError(
                "SEH resumption unit and RVA must be supplied together"
            )
        if resumption_rva is not None:
            resumption_rva = _u32(resumption_rva, "SEH resumption RVA")
        if resumption_unit_id is not None and not exception_row["continuable"]:
            raise CheckedOutcomeProtocolError("noncontinuable exception cannot name a resumption unit")
        if escape_disposition not in {"terminate_process_root", "escape_callable_root", "continue_search"}:
            raise CheckedOutcomeProtocolError("SEH escape disposition is unsupported")
        gateway_handler_symbol = _text(
            gateway_handler_symbol, "SEH gateway handler symbol"
        )
        unwind = tuple(sorted(set(_text(item, "unwind effect ID") for item in unwind_effect_ids)))
        portal_rows = _parse_portals(portals)
        observed = tuple(sorted(set(_text(item, "observed address field") for item in observed_address_fields)))
        if address_policy not in {"candidate_portal_mapping", "pinned_original_layout"}:
            raise CheckedOutcomeProtocolError("SEH address policy is unsupported")
        issue_values = set(_text(item, "SEH issue") for item in issues)
        numeric_fields = {"ExceptionAddress", "Eip"} & set(observed)
        if numeric_fields and address_policy != "pinned_original_layout":
            issue_values.add("numeric_original_exception_address_requires_pinned_layout")
        issue_tuple = tuple(sorted(issue_values))
        core = {
            "format": CHECKED_SEH_PROTOCOL_FORMAT,
            "status": "complete" if not issue_tuple else "incomplete",
            "exceptional_transition": {"id": transition_id, "sha256": transition_sha256},
            "exception": exception_row,
            "projections": {key: list(value) for key, value in projection_rows.items()},
            "handler_unit_id": handler_unit_id,
            "handler_rva": handler_rva,
            "resumption_unit_id": resumption_unit_id,
            "resumption_rva": resumption_rva,
            "unwind_effect_ids": list(unwind),
            "escape_disposition": escape_disposition,
            "gateway_handler_symbol": gateway_handler_symbol,
            "portals": [dict(row) for row in portal_rows],
            "observed_address_fields": list(observed),
            "address_policy": address_policy,
            "issues": list(issue_tuple),
        }
        return cls(
            f"checked-seh-protocol-v1:{canonical_sha256_v3(core)}",
            transition_id,
            transition_sha256,
            exception_row,
            projection_rows,
            handler_unit_id,
            handler_rva,
            resumption_unit_id,
            resumption_rva,
            unwind,
            escape_disposition,
            gateway_handler_symbol,
            portal_rows,
            observed,
            address_policy,
            issue_tuple,
        )

    @classmethod
    def parse(cls, value: object) -> "CheckedSEHProtocolV1":
        fields = {
            "format", "id", "status", "exceptional_transition", "exception",
            "projections", "handler_unit_id", "handler_rva",
            "resumption_unit_id", "resumption_rva",
            "unwind_effect_ids", "escape_disposition", "portals",
            "gateway_handler_symbol",
            "observed_address_fields", "address_policy", "issues",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise CheckedOutcomeProtocolError("checked SEH protocol has invalid fields")
        if value["format"] != CHECKED_SEH_PROTOCOL_FORMAT:
            raise CheckedOutcomeProtocolError("unsupported checked SEH protocol format")
        transition = value["exceptional_transition"]
        if not isinstance(transition, Mapping) or set(transition) != {"id", "sha256"}:
            raise CheckedOutcomeProtocolError("SEH exceptional-transition binding is malformed")
        projection = value["projections"]
        if not isinstance(projection, Mapping):
            raise CheckedOutcomeProtocolError("SEH projections are malformed")
        result = cls.create(
            transition_id=str(transition["id"]),
            transition_sha256=str(transition["sha256"]),
            exception=value["exception"] if isinstance(value["exception"], Mapping) else {},
            projections={key: value for key, value in projection.items() if isinstance(value, list)},
            handler_unit_id=value["handler_unit_id"] if isinstance(value["handler_unit_id"], str) else None,
            handler_rva=value["handler_rva"] if isinstance(value["handler_rva"], int) else None,
            resumption_unit_id=value["resumption_unit_id"] if isinstance(value["resumption_unit_id"], str) else None,
            resumption_rva=value["resumption_rva"] if isinstance(value["resumption_rva"], int) else None,
            unwind_effect_ids=_canonical_strings(value["unwind_effect_ids"], "unwind effects"),
            escape_disposition=str(value["escape_disposition"]),
            gateway_handler_symbol=str(value["gateway_handler_symbol"]),
            portals=value["portals"] if isinstance(value["portals"], list) else (),
            observed_address_fields=_canonical_strings(value["observed_address_fields"], "observed address fields"),
            address_policy=str(value["address_policy"]),
            issues=_canonical_strings(value["issues"], "SEH issues"),
        )
        if value["id"] != result.protocol_id or value["status"] != result.status:
            raise CheckedOutcomeProtocolError("checked SEH protocol is stale")
        return result

    @property
    def status(self) -> str:
        return "complete" if not self.issues else "incomplete"

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CHECKED_SEH_PROTOCOL_FORMAT,
            "id": self.protocol_id,
            "status": self.status,
            "exceptional_transition": {"id": self.transition_id, "sha256": self.transition_sha256},
            "exception": dict(self.exception),
            "projections": {key: list(value) for key, value in self.projections.items()},
            "handler_unit_id": self.handler_unit_id,
            "handler_rva": self.handler_rva,
            "resumption_unit_id": self.resumption_unit_id,
            "resumption_rva": self.resumption_rva,
            "unwind_effect_ids": list(self.unwind_effect_ids),
            "escape_disposition": self.escape_disposition,
            "gateway_handler_symbol": self.gateway_handler_symbol,
            "portals": [dict(row) for row in self.portals],
            "observed_address_fields": list(self.observed_address_fields),
            "address_policy": self.address_policy,
            "issues": list(self.issues),
        }


def _parse_exception(value: Mapping[str, object]) -> dict[str, object]:
    fields = {"code", "flags_mask", "flags_value", "parameter_count", "continuable", "access_violation"}
    if set(value) != fields:
        raise CheckedOutcomeProtocolError("SEH exception selector has invalid fields")
    result: dict[str, object] = {
        "code": _u32(value["code"], "exception code"),
        "flags_mask": _u32(value["flags_mask"], "exception flags mask"),
        "flags_value": _u32(value["flags_value"], "exception flags value"),
        "parameter_count": _u32(value["parameter_count"], "exception parameter count"),
        "continuable": value["continuable"],
        "access_violation": copy.deepcopy(value["access_violation"]),
    }
    if not isinstance(result["continuable"], bool):
        raise CheckedOutcomeProtocolError("exception continuability must be Boolean")
    if int(result["parameter_count"]) > 15:
        raise CheckedOutcomeProtocolError(
            "x86 exception parameter count exceeds EXCEPTION_MAXIMUM_PARAMETERS"
        )
    access = result["access_violation"]
    if access is not None and (
        not isinstance(access, Mapping)
        or set(access) != {"operation_parameter", "address_parameter"}
        or any(not isinstance(access[key], int) or isinstance(access[key], bool) or access[key] < 0 for key in access)
    ):
        raise CheckedOutcomeProtocolError("access-violation metadata is malformed")
    if access is not None and any(
        int(access[key]) >= int(result["parameter_count"]) for key in access
    ):
        raise CheckedOutcomeProtocolError(
            "access-violation metadata indexes outside the exception parameters"
        )
    return result


def _parse_portals(value: Sequence[Mapping[str, object]]) -> tuple[Mapping[str, object], ...]:
    result: list[dict[str, object]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping) or set(row) != {"source_rva", "candidate_symbol"}:
            raise CheckedOutcomeProtocolError(f"exception portal {index} is malformed")
        result.append({
            "source_rva": _u32(row["source_rva"], f"exception portal {index} source RVA"),
            "candidate_symbol": _text(row["candidate_symbol"], f"exception portal {index} symbol"),
        })
    ordered = tuple(sorted(result, key=lambda row: (int(row["source_rva"]), str(row["candidate_symbol"]))))
    if tuple(result) != ordered or len({int(row["source_rva"]) for row in ordered}) != len(ordered):
        raise CheckedOutcomeProtocolError("exception portals must be sorted and unique by source RVA")
    return ordered


__all__ = [
    "CheckedBoundaryOutcomeProtocolV1",
    "CheckedOutcomeProtocolError",
    "CheckedSEHProtocolV1",
]
