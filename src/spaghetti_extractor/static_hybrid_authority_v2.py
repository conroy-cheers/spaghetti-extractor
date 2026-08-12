"""Strict, replayed v2 authority gate for static hybrid reconstruction.

This module is the high-level authority boundary.  It accepts exact machine IR
and independently checked v2 evidence, converts the remaining canonical site
reports into immutable authority records, and replays the v2 authority builder.
Legacy completeness data is retained only as inert diagnostic context.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .analysis.scc_worklist import decompose_scc
from .checked_external_site_contract import (
    CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT,
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    parse_checked_external_site_contract,
)
from .analysis_schema_v2 import interprocedural_authority_signature_v2
from .authority_bindings_v2 import (
    IndirectExitBinding,
    match_indirect_recovery_v2,
)
from .call_site_effects import parse_call_site_effects
from .exception_invariants_v2 import (
    EXCEPTION_INVARIANT_CHECK_V2_FORMAT,
    canonical_sha256 as exception_sha256,
)
from .external_profile_authority_v2 import (
    ExternalProfileAuthorityV2,
    ExternalProfileAuthorityV2Error,
)
from .hybrid_authority_builder_v2 import (
    HybridAuthorityBuilderV2Error,
    build_hybrid_authority_v2,
    machine_ir_sha256,
    recompute_event_binding,
    recompute_unit_binding,
)
from .hybrid_authority_v2 import (
    AuthorityBundle,
    AuthorityDataError,
    AuthorityRecord,
    AuthorityStatus,
    BinaryBinding,
    CallFrameSummary,
    CheckedExternalSite,
    EntryStateContract,
    EventBinding,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    GlobalSlotInvariant,
    IndirectExitCertificate,
    ProfileBinding,
    UnitBinding,
    ValueFact,
    canonical_json_bytes,
    parse_authority_bundle_json,
    parse_authority_record,
)
from .hybrid_diagnostics_v2 import (
    build_hybrid_diagnostics_v2,
    make_blocker_record,
)
from .isa_kernel_selection import (
    ISAKernelSelectionAuthority,
    ISAKernelSelectionAuthorityCheck,
    ISAKernelSelectionAuthorityError,
    SelectionAuthorityStatus,
    parse_isa_kernel_selection_authority,
)
from .machine_ir_isa_requirements_v2 import (
    MachineIRISARequirementsV2,
    MachineIRISARequirementsV2Error,
    build_machine_ir_isa_extraction_request_v2,
    compare_selection_to_machine_ir_requirements_v2,
    parse_machine_ir_isa_requirements_v2,
)
from .machine_ir_isa_selection_v2 import (
    MACHINE_IR_ISA_SELECTION_CERTIFICATE_V2_FORMAT,
    MachineIRISASelectionCertificateV2,
    MachineIRISASelectionV2Error,
    compare_isa_selection_certificate_to_requirements_v2,
    parse_machine_ir_isa_selection_certificate_v2,
)
from .machine_ir_authority_v2 import MACHINE_IR_AUTHORITY_BINDINGS_FORMAT
from .machine_abi import (
    NormalCallABIPremise,
    parse_normal_call_abi_premise,
)


STATIC_HYBRID_AUTHORITY_V2_FORMAT = (
    "spaghetti-extractor-static-hybrid-authority-v2"
)
ENTRY_STATE_ANALYSIS_V2_FORMAT = "stage-a-entry-state-analysis-v2"
INTERPROCEDURAL_ANALYSIS_V2_FORMAT = "stage-a-interprocedural-analysis-v2"

_DIGEST_CHARS = frozenset("0123456789abcdef")
_RECORD_TYPES = (
    EntryStateContract,
    ValueFact,
    GlobalSlotInvariant,
    CallFrameSummary,
    IndirectExitCertificate,
    CheckedExternalSite,
)


class StaticHybridAuthorityV2Error(ValueError):
    """A serialized gate artifact is malformed or has stale derived fields."""


@dataclass(frozen=True)
class _PreparedMachineIRAuthority:
    binary: BinaryBinding
    units: tuple[UnitBinding, ...]


def build_static_hybrid_authority_v2(
    *,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    machine_ir_manifest: Mapping[str, Any],
    exact_unit_preparation: Mapping[str, Any] | None = None,
    pe_sha256: str,
    behavioral_roots: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    entry_state_analysis: Mapping[str, Any] | None,
    interprocedural_result: Any,
    checked_external_sites: Sequence[Mapping[str, Any]] = (),
    external_profile_authority: ExternalProfileAuthorityV2 | None = None,
    checked_exception_reports: Sequence[Mapping[str, Any]] = (),
    checked_exception_records: Sequence[AuthorityRecord | Mapping[str, Any]] = (),
    isa_selection_authority: (
        ISAKernelSelectionAuthority
        | ISAKernelSelectionAuthorityCheck
        | Mapping[str, Any]
        | None
    ),
    isa_requirements: Mapping[str, Any] | None = None,
    v1_diagnostics: Any = None,
) -> dict[str, Any]:
    """Build and replay the sole v2 static candidate-generation authority.

    Missing evidence is represented by deterministic ``incomplete`` blockers.
    Malformed, stale, contradictory, or duplicate evidence is ``violated``.
    No field from ``v1_diagnostics`` participates in either decision.
    """

    blockers: list[dict[str, Any]] = []
    manifest = _mapping_input(
        machine_ir_manifest,
        blockers=blockers,
        category="machine_ir_manifest",
        missing_code="machine_ir_manifest_missing",
        corrupt_code="machine_ir_manifest_corrupt",
    )
    roots = _behavioral_roots(behavioral_roots, blockers=blockers)
    valid_pe_sha = _digest(pe_sha256)
    if not valid_pe_sha:
        blockers.append(_blocker(
            status="violated",
            category="binary_binding",
            code="pe_sha256_corrupt",
            message="the exact PE binding is not a lowercase SHA-256 digest",
            next_action="recompute the PE digest from the exact input binary",
            details={"observed": _safe_json(pe_sha256)},
        ))

    prepared = _prepared_machine_ir_authority(
        exact_unit_preparation,
        machine_ir_rows=machine_ir_rows,
        manifest=manifest,
        pe_sha256=pe_sha256 if valid_pe_sha else None,
        blockers=blockers,
    )
    rows = _machine_rows(
        machine_ir_rows,
        blockers,
        prevalidated=prepared is not None,
    )

    binary: BinaryBinding | None = None
    unit_by_id: dict[str, UnitBinding] = {}
    row_by_id: dict[str, Mapping[str, Any]] = {}
    if rows and valid_pe_sha:
        try:
            binary = (
                prepared.binary
                if prepared is not None
                else BinaryBinding(pe_sha256, machine_ir_sha256(rows))
            )
            units = (
                prepared.units
                if prepared is not None
                else tuple(
                    recompute_unit_binding(row, binary=binary) for row in rows
                )
            )
            unit_by_id = {unit.unit_id: unit for unit in units}
            row_by_id = {
                str(row.get("id")): row for row in rows
                if isinstance(row.get("id"), str)
            }
            if len(unit_by_id) != len(rows) or len(row_by_id) != len(rows):
                raise HybridAuthorityBuilderV2Error(
                    "machine-IR unit identities are duplicated or malformed"
                )
        except (AuthorityDataError, HybridAuthorityBuilderV2Error, TypeError, ValueError) as exc:
            blockers.append(_blocker(
                status="violated",
                category="machine_ir_binding",
                code="machine_ir_binding_corrupt",
                message="machine-IR units cannot be bound to the exact PE",
                next_action="regenerate exact machine IR and its v2 bindings",
                details={"reason": str(exc)},
            ))
            binary = None
            unit_by_id = {}
            row_by_id = {}

    entries, globals_ = _entry_authority_records(
        entry_state_analysis,
        blockers=blockers,
    )
    interprocedural = _interprocedural_payload(
        interprocedural_result,
        blockers=blockers,
        row_by_id=row_by_id,
    )
    external_records = _external_authority_records(
        checked_external_sites,
        profile_authority=external_profile_authority,
        interprocedural=interprocedural,
        unit_by_id=unit_by_id,
        row_by_id=row_by_id,
        blockers=blockers,
    )
    exceptional_records = _exception_authority_records(
        checked_exception_reports,
        checked_exception_records,
        unit_by_id=unit_by_id,
        row_by_id=row_by_id,
        blockers=blockers,
    )
    isa, exact_isa_requirements = _isa_authority(
        isa_selection_authority,
        exact_requirements=isa_requirements,
        pe_sha256=pe_sha256 if valid_pe_sha else None,
        machine_ir_rows=rows,
        expected_machine_ir_sha256=(
            None if binary is None else binary.machine_ir_sha256
        ),
        blockers=blockers,
    )

    bundle: AuthorityBundle | None = None
    replay_status = "incomplete"
    replay_reason: str | None = "exact inputs are incomplete"
    if rows and manifest is not None and valid_pe_sha and binary is not None:
        build_kwargs = {
            "machine_ir_rows": rows,
            "machine_ir_manifest": manifest,
            "pe_sha256": pe_sha256,
            "root_records": roots,
            "interprocedural_result": interprocedural,
            "checked_external_site_rows": external_records,
            "global_slot_records": globals_,
            "entry_records": entries,
            "exceptional_records": exceptional_records,
            "validated_isa_authority": isa,
            "validated_isa_requirements": exact_isa_requirements,
            "prepared_binary": None if prepared is None else prepared.binary,
            "prepared_units": None if prepared is None else prepared.units,
        }
        try:
            first = build_hybrid_authority_v2(**build_kwargs)
            parsed = parse_authority_bundle_json(first.to_json())
            if first.to_payload() != parsed.to_payload():
                raise AuthorityDataError(
                    "serialized authority replay produced a different bundle"
                )
            bundle = parsed
            replay_status = "complete"
            replay_reason = None
        except (AuthorityDataError, HybridAuthorityBuilderV2Error, ISAKernelSelectionAuthorityError, TypeError, ValueError) as exc:
            replay_status = "violated"
            replay_reason = str(exc)
            blockers.append(_blocker(
                status="violated",
                category="authority_replay",
                code="authority_builder_replay_failed",
                message="the v2 authority builder could not deterministically replay its inputs",
                next_action="regenerate the stale or contradictory v2 evidence",
                details={"reason": str(exc)},
            ))

    if bundle is not None:
        blockers.extend(_bundle_blockers(bundle, upstream_blockers=blockers))

    preclosure_ids = tuple(sorted({str(row["id"]) for row in blockers}))
    if bundle is None or bundle.status is not AuthorityStatus.COMPLETE or blockers:
        blockers.append(_blocker(
            status=(
                "violated"
                if replay_status == "violated"
                or (bundle is not None and bundle.status is AuthorityStatus.VIOLATED)
                or any(row["status"] == "violated" for row in blockers)
                else "incomplete"
            ),
            category="candidate_generation",
            code="v2_static_authority_not_closed",
            message="candidate generation is blocked until the v2 static authority graph closes",
            next_action="resolve the listed primary v2 evidence blockers",
            blocked_by=preclosure_ids,
            details={
                "bundle_status": None if bundle is None else bundle.status.value,
                "replay_status": replay_status,
            },
        ))

    diagnostics = build_hybrid_diagnostics_v2(blockers)
    status = _gate_status(bundle, replay_status, diagnostics)
    authorizes = (
        status == "complete"
        and replay_status == "complete"
        and bundle is not None
        and bundle.authorizes
    )
    body: dict[str, Any] = {
        "format": STATIC_HYBRID_AUTHORITY_V2_FORMAT,
        "schema_version": 2,
        "status": status,
        "authorizes_candidate_generation": authorizes,
        "v1_authorizes": False,
        "binary": None if binary is None else binary.to_payload(),
        "authority_bundle": None if bundle is None else bundle.to_payload(),
        "replay": {
            "status": replay_status,
            "deterministic": replay_status == "complete",
            "bundle_content_id": None if bundle is None else bundle.content_id,
            "reason": replay_reason,
        },
        "diagnostics": diagnostics,
        "primary_blocker_ids": list(diagnostics["primary_blocker_ids"]),
        "legacy_v1_diagnostics": _legacy_diagnostics(v1_diagnostics),
    }
    report = {**body, "content_sha256": _canonical_sha256(body)}
    return validate_static_hybrid_authority_v2(report)


def validate_static_hybrid_authority_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    """Replay all derived fields of a serialized high-level authority report."""

    if not isinstance(value, Mapping):
        raise StaticHybridAuthorityV2Error("static authority report must be an object")
    expected_fields = {
        "format",
        "schema_version",
        "status",
        "authorizes_candidate_generation",
        "v1_authorizes",
        "binary",
        "authority_bundle",
        "replay",
        "diagnostics",
        "primary_blocker_ids",
        "legacy_v1_diagnostics",
        "content_sha256",
    }
    if set(value) != expected_fields:
        raise StaticHybridAuthorityV2Error(
            "static authority report has noncanonical fields"
        )
    if (
        value.get("format") != STATIC_HYBRID_AUTHORITY_V2_FORMAT
        or value.get("schema_version") != 2
        or value.get("v1_authorizes") is not False
    ):
        raise StaticHybridAuthorityV2Error(
            "only strict v2 static authority reports are accepted"
        )
    normalized = _canonical_value(value, context="static authority report")
    body = dict(normalized)
    observed_hash = body.pop("content_sha256")
    if observed_hash != _canonical_sha256(body):
        raise StaticHybridAuthorityV2Error(
            "static authority report content hash is stale"
        )

    bundle_payload = normalized["authority_bundle"]
    bundle = None
    if bundle_payload is not None:
        try:
            bundle = AuthorityBundle.parse(bundle_payload)
        except AuthorityDataError as exc:
            raise StaticHybridAuthorityV2Error(
                f"authority bundle replay failed: {exc}"
            ) from exc

    diagnostics = normalized["diagnostics"]
    if not isinstance(diagnostics, Mapping):
        raise StaticHybridAuthorityV2Error("diagnostics must be an object")
    replayed_diagnostics = build_hybrid_diagnostics_v2(
        diagnostics.get("blockers", ())
    )
    if replayed_diagnostics != diagnostics:
        raise StaticHybridAuthorityV2Error(
            "dependency diagnostics do not replay exactly"
        )
    if normalized["primary_blocker_ids"] != diagnostics["primary_blocker_ids"]:
        raise StaticHybridAuthorityV2Error(
            "primary blocker inventory is stale"
        )

    replay = normalized["replay"]
    if not isinstance(replay, Mapping) or set(replay) != {
        "status", "deterministic", "bundle_content_id", "reason"
    }:
        raise StaticHybridAuthorityV2Error("authority replay fields are malformed")
    replay_status = replay.get("status")
    if replay_status not in {"complete", "incomplete", "violated"}:
        raise StaticHybridAuthorityV2Error("authority replay status is unsupported")
    expected_deterministic = replay_status == "complete"
    expected_bundle_id = None if bundle is None else bundle.content_id
    if (
        replay.get("deterministic") is not expected_deterministic
        or replay.get("bundle_content_id") != expected_bundle_id
    ):
        raise StaticHybridAuthorityV2Error("authority replay claim is stale")

    expected_status = _gate_status(bundle, str(replay_status), diagnostics)
    expected_authorizes = (
        expected_status == "complete"
        and replay_status == "complete"
        and bundle is not None
        and bundle.authorizes
    )
    if (
        normalized["status"] != expected_status
        or normalized["authorizes_candidate_generation"] is not expected_authorizes
    ):
        raise StaticHybridAuthorityV2Error(
            "static authority status or authorization claim is stale"
        )
    return normalized


def _machine_rows(
    value: Sequence[Mapping[str, Any]],
    blockers: list[dict[str, Any]],
    *,
    prevalidated: bool = False,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        blockers.append(_blocker(
            status="violated",
            category="machine_ir",
            code="machine_ir_inventory_corrupt",
            message="the exact machine-IR inventory is not an array",
            next_action="regenerate the machine-IR artifact",
        ))
        return ()
    if not value:
        blockers.append(_blocker(
            status="incomplete",
            category="machine_ir",
            code="machine_ir_inventory_missing",
            message="the exact machine-IR inventory is empty",
            next_action="extract every rooted reachable machine-IR unit",
        ))
        return ()
    result: list[Mapping[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            blockers.append(_blocker(
                status="violated",
                category="machine_ir",
                code="machine_ir_unit_corrupt",
                message="a machine-IR unit is not an object",
                next_action="regenerate exact machine IR",
                details={"row_index": index},
            ))
            continue
        if prevalidated:
            result.append(row)
            continue
        try:
            result.append(
                _canonical_value(row, context=f"machine-IR row {index}")
            )
        except StaticHybridAuthorityV2Error as exc:
            blockers.append(_blocker(
                status="violated",
                category="machine_ir",
                code="machine_ir_unit_corrupt",
                message="a machine-IR unit is not canonical JSON data",
                next_action="regenerate exact machine IR",
                details={"row_index": index, "reason": str(exc)},
            ))
    return tuple(result)


def _prepared_machine_ir_authority(
    value: Mapping[str, Any] | None,
    *,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any] | None,
    pe_sha256: str | None,
    blockers: list[dict[str, Any]],
) -> _PreparedMachineIRAuthority | None:
    """Consume the exact-unit phase as an opaque checked identity handle."""

    if value is None:
        return None
    try:
        payload = _required_mapping(value, "exact unit preparation")
        if set(payload) != {
            "format",
            "status",
            "binary",
            "machine_ir",
            "authority_bindings",
            "issues",
        }:
            raise StaticHybridAuthorityV2Error(
                "exact unit preparation field inventory is invalid"
            )
        if payload.get("format") != "spaghetti-extractor-exact-unit-preparation-v2":
            raise StaticHybridAuthorityV2Error(
                "exact unit preparation format is unsupported"
            )
        if payload.get("status") != "complete" or payload.get("issues") != []:
            raise StaticHybridAuthorityV2Error(
                "exact unit preparation is not complete"
            )
        binary_row = _required_mapping(payload.get("binary"), "prepared binary")
        machine_row = _required_mapping(
            payload.get("machine_ir"), "prepared machine IR"
        )
        if set(binary_row) != {"sha256"} or set(machine_row) != {
            "sha256", "units"
        }:
            raise StaticHybridAuthorityV2Error(
                "exact unit preparation bindings are malformed"
            )
        authority = _required_mapping(
            payload.get("authority_bindings"), "prepared authority bindings"
        )
        if set(authority) != {
            "format",
            "binary",
            "units",
            "events",
            "indirect_exits",
        }:
            raise StaticHybridAuthorityV2Error(
                "prepared authority binding fields are malformed"
            )
        if authority.get("format") != MACHINE_IR_AUTHORITY_BINDINGS_FORMAT:
            raise StaticHybridAuthorityV2Error(
                "prepared authority binding format is unsupported"
            )
        binary = BinaryBinding.parse(authority.get("binary"))
        if (
            pe_sha256 is None
            or binary.pe_sha256 != pe_sha256
            or binary_row.get("sha256") != pe_sha256
            or machine_row.get("sha256") != binary.machine_ir_sha256
        ):
            raise StaticHybridAuthorityV2Error(
                "exact unit preparation binds different binary inputs"
            )
        raw_units = authority.get("units")
        raw_events = authority.get("events")
        raw_indirect_exits = authority.get("indirect_exits")
        if (
            not isinstance(raw_units, list)
            or not isinstance(raw_events, list)
            or not isinstance(raw_indirect_exits, list)
        ):
            raise StaticHybridAuthorityV2Error(
                "prepared units and events must be arrays"
            )
        units = tuple(UnitBinding.parse(row) for row in raw_units)
        events = tuple(EventBinding.parse(row) for row in raw_events)
        indirect_exits = tuple(
            IndirectExitBinding.parse(row) for row in raw_indirect_exits
        )
        row_ids = tuple(
            str(row.get("id"))
            for row in machine_ir_rows
            if isinstance(row, Mapping)
        )
        if (
            len(row_ids) != len(machine_ir_rows)
            or len(units) != len(machine_ir_rows)
            or machine_row.get("units") != len(units)
            or tuple(unit.unit_id for unit in units) != row_ids
            or len(set(row_ids)) != len(row_ids)
            or any(unit.binary != binary for unit in units)
            or any(event.unit.binary != binary for event in events)
            or any(exit_.unit.binary != binary for exit_ in indirect_exits)
            or len({exit_.exit_id for exit_ in indirect_exits})
            != len(indirect_exits)
        ):
            raise StaticHybridAuthorityV2Error(
                "prepared unit/event inventory does not bind the supplied rows"
            )
        if manifest is None:
            raise StaticHybridAuthorityV2Error(
                "prepared authority requires an exact machine-IR manifest"
            )
        artifact = _required_mapping(
            _required_mapping(
                manifest.get("artifacts"), "manifest artifacts"
            ).get(
                "machine_ir"
            ),
            "manifest machine-IR artifact",
        )
        if (
            artifact.get("sha256") != binary.machine_ir_sha256
            or manifest.get("authority_bindings") != authority
        ):
            raise StaticHybridAuthorityV2Error(
                "prepared authority contradicts the machine-IR manifest"
            )
        return _PreparedMachineIRAuthority(binary=binary, units=units)
    except (AuthorityDataError, StaticHybridAuthorityV2Error, TypeError, ValueError) as exc:
        blockers.append(_blocker(
            status="violated",
            category="machine_ir_binding",
            code="exact_unit_preparation_corrupt",
            message="the cached exact-unit authority cannot be replayed",
            next_action="rebuild exact unit preparation from the exact machine IR",
            details={"reason": str(exc)},
        ))
        return None


def _required_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise StaticHybridAuthorityV2Error(f"{context} must be an object")
    return value


def _behavioral_roots(
    value: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    *,
    blockers: list[dict[str, Any]],
) -> Sequence[Mapping[str, Any]] | Mapping[str, Any]:
    if isinstance(value, Mapping):
        raw_roots = value.get("roots")
        try:
            container: Sequence[Mapping[str, Any]] | Mapping[str, Any] = (
                _canonical_value(value, context="behavioral roots")
            )
        except StaticHybridAuthorityV2Error as exc:
            blockers.append(_blocker(
                status="violated",
                category="behavioral_roots",
                code="behavioral_root_inventory_corrupt",
                message="behavioral roots are not canonical JSON evidence",
                next_action="regenerate exact PE and callback roots",
                details={"reason": str(exc)},
            ))
            return []
    else:
        raw_roots = value
        container = value
    if not isinstance(raw_roots, Sequence) or isinstance(raw_roots, (str, bytes)):
        blockers.append(_blocker(
            status="violated",
            category="behavioral_roots",
            code="behavioral_root_inventory_corrupt",
            message="behavioral roots are not an exact array",
            next_action="regenerate exact PE and callback roots",
        ))
        return []
    if not raw_roots:
        blockers.append(_blocker(
            status="incomplete",
            category="behavioral_roots",
            code="behavioral_root_inventory_missing",
            message="no behavioral execution roots are declared",
            next_action="bind the PE entrypoint and all declared exports, TLS entries, and callbacks",
        ))
        return container
    seen: set[tuple[str, int, int]] = set()
    for index, raw in enumerate(raw_roots):
        if not isinstance(raw, Mapping):
            blockers.append(_blocker(
                status="violated",
                category="behavioral_roots",
                code="behavioral_root_corrupt",
                message="a behavioral root is not an object",
                next_action="regenerate exact behavioral roots",
                details={"root_index": index},
            ))
            continue
        kind = raw.get("kind")
        rva = raw.get("rva", raw.get("target_rva"))
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(rva, int)
            or isinstance(rva, bool)
            or not 0 <= rva <= 0xFFFFFFFF
        ):
            blockers.append(_blocker(
                status="violated",
                category="behavioral_roots",
                code="behavioral_root_binding_corrupt",
                message="a behavioral root lacks an exact kind and RVA",
                next_action="regenerate exact behavioral roots",
                details={"root_index": index},
            ))
            continue
        key = (kind, rva)
        if key in seen:
            blockers.append(_blocker(
                status="violated",
                category="behavioral_roots",
                code="behavioral_root_duplicated",
                message="a behavioral root is declared more than once",
                next_action="canonicalize the root inventory",
                details={"kind": kind, "rva": rva},
            ))
        seen.add(key)
    try:
        return _canonical_value(container, context="behavioral roots")
    except StaticHybridAuthorityV2Error as exc:
        blockers.append(_blocker(
            status="violated",
            category="behavioral_roots",
            code="behavioral_root_inventory_corrupt",
            message="behavioral roots are not canonical JSON evidence",
            next_action="regenerate exact PE and callback roots",
            details={"reason": str(exc)},
        ))
        return []


def _entry_authority_records(
    analysis: Mapping[str, Any] | None,
    *,
    blockers: list[dict[str, Any]],
) -> tuple[tuple[EntryStateContract, ...], tuple[GlobalSlotInvariant, ...]]:
    if analysis is None:
        blockers.append(_blocker(
            status="incomplete",
            category="entry_state",
            code="entry_state_analysis_missing",
            message="root and callback entry-state authority is missing",
            next_action="run checked entry-state analysis v2",
        ))
        return (), ()
    if not isinstance(analysis, Mapping):
        blockers.append(_blocker(
            status="violated",
            category="entry_state",
            code="entry_state_analysis_corrupt",
            message="entry-state analysis is not an object",
            next_action="regenerate entry-state analysis v2",
        ))
        return (), ()
    try:
        payload = _canonical_value(analysis, context="entry-state analysis")
    except StaticHybridAuthorityV2Error as exc:
        blockers.append(_blocker(
            status="violated",
            category="entry_state",
            code="entry_state_analysis_corrupt",
            message="entry-state analysis is not canonical JSON evidence",
            next_action="regenerate entry-state analysis v2",
            details={"reason": str(exc)},
        ))
        return (), ()
    if payload.get("format") != ENTRY_STATE_ANALYSIS_V2_FORMAT:
        blockers.append(_blocker(
            status="violated",
            category="entry_state",
            code="entry_state_analysis_format_mismatch",
            message="entry-state evidence is not a v2 analysis artifact",
            next_action="regenerate entry-state analysis v2",
        ))
        return (), ()
    observed_hash = payload.get("analysis_sha256")
    hash_body = dict(payload)
    hash_body.pop("analysis_sha256", None)
    if not _digest(observed_hash) or observed_hash != _canonical_sha256(hash_body):
        blockers.append(_blocker(
            status="violated",
            category="entry_state",
            code="entry_state_analysis_hash_mismatch",
            message="entry-state analysis content differs from its exact hash",
            next_action="discard stale entry-state evidence and replay the analysis",
        ))

    issues = payload.get("issues")
    issue_rows = issues if isinstance(issues, list) else []
    if not isinstance(issues, list):
        blockers.append(_blocker(
            status="violated",
            category="entry_state",
            code="entry_state_issue_inventory_corrupt",
            message="entry-state issues are not an exact array",
            next_action="regenerate entry-state analysis v2",
        ))
    derived_status = _issue_status(issue_rows)
    if payload.get("status") != derived_status:
        blockers.append(_blocker(
            status="violated",
            category="entry_state",
            code="entry_state_status_contradiction",
            message="entry-state status disagrees with its checked issue inventory",
            next_action="replay entry-state analysis instead of copying status fields",
            details={"declared": payload.get("status"), "derived": derived_status},
        ))
    for issue in issue_rows:
        if not isinstance(issue, Mapping):
            blockers.append(_blocker(
                status="violated",
                category="entry_state",
                code="entry_state_issue_corrupt",
                message="an entry-state issue is malformed",
                next_action="regenerate entry-state analysis v2",
            ))
            continue
        status = issue.get("status")
        if status not in {"incomplete", "violated"}:
            blockers.append(_blocker(
                status="violated",
                category="entry_state",
                code="entry_state_issue_status_corrupt",
                message="an entry-state issue has an unsupported status",
                next_action="regenerate entry-state analysis v2",
                details={"issue": _safe_json(issue)},
            ))
            continue
        if status in {"incomplete", "violated"}:
            code = str(issue.get("code", "entry_state_evidence_missing"))
            blockers.append(_blocker(
                status=str(status),
                category="entry_state",
                code=code,
                message=f"entry-state analysis reports {code}",
                next_action="supply or repair the exact root, callback, or slot evidence",
                details={"issue": _safe_json(issue)},
            ))

    entries: list[EntryStateContract] = []
    globals_: list[GlobalSlotInvariant] = []
    raw_records = payload.get("authority_records")
    if not isinstance(raw_records, list):
        blockers.append(_blocker(
            status="incomplete",
            category="entry_state",
            code="entry_state_authority_records_missing",
            message="entry-state analysis contains no v2 authority records",
            next_action="emit immutable entry and global-slot authority records",
        ))
        return (), ()
    for index, raw in enumerate(raw_records):
        try:
            record = parse_authority_record(raw)
        except (AuthorityDataError, TypeError, ValueError) as exc:
            blockers.append(_blocker(
                status="violated",
                category="entry_state",
                code="entry_state_authority_record_corrupt",
                message="an entry-state authority record does not replay",
                next_action="regenerate the stale v2 record",
                details={"record_index": index, "reason": str(exc)},
            ))
            continue
        if isinstance(record, EntryStateContract):
            entries.append(record)
        elif isinstance(record, GlobalSlotInvariant):
            globals_.append(record)
        else:
            blockers.append(_blocker(
                status="violated",
                category="entry_state",
                code="entry_state_authority_kind_corrupt",
                message="entry-state analysis contains an authority record owned by another phase",
                next_action="emit only entry-state and global-slot records from this phase",
                details={"record_index": index, "record_kind": record.KIND},
            ))
    return tuple(entries), tuple(globals_)


def _interprocedural_payload(
    value: Any,
    *,
    blockers: list[dict[str, Any]],
    row_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = dict(value)
    elif value is not None:
        payload = {
            "call_summaries": getattr(value, "call_summaries", None),
            "recovered_targets": getattr(value, "recovered_targets", None),
            "fixed_point": getattr(value, "fixed_point", None),
            "operation_provenance": getattr(value, "operation_provenance", None),
        }
    else:
        payload = {}
    try:
        payload = _canonical_value(payload, context="interprocedural result")
    except StaticHybridAuthorityV2Error as exc:
        blockers.append(_blocker(
            status="violated",
            category="interprocedural",
            code="interprocedural_result_corrupt",
            message="the interprocedural result is not canonical JSON evidence",
            next_action="replay the v2 SCC interprocedural analysis",
            details={"reason": str(exc)},
        ))
        return {}
    fixed = payload.get("fixed_point")
    if not isinstance(fixed, Mapping):
        blockers.append(_blocker(
            status="incomplete",
            category="interprocedural",
            code="interprocedural_result_missing",
            message="the unified interprocedural fixed point is missing",
            next_action="run the unseeded SCC interprocedural analysis",
        ))
        return payload
    if fixed.get("format") != INTERPROCEDURAL_ANALYSIS_V2_FORMAT:
        blockers.append(_blocker(
            status="violated",
            category="interprocedural",
            code="interprocedural_format_mismatch",
            message="the fixed point is not a v2 interprocedural artifact",
            next_action="regenerate it with the v2 SCC analyzer",
        ))
    failure_reasons = fixed.get("failure_reasons")
    failures = failure_reasons if isinstance(failure_reasons, list) else []
    dependencies = fixed.get("dependencies")
    raw_normal_call_abi_premise = fixed.get("normal_call_abi_premise")
    normal_call_abi_premise: NormalCallABIPremise | None = None
    if raw_normal_call_abi_premise is not None:
        try:
            normal_call_abi_premise = parse_normal_call_abi_premise(
                raw_normal_call_abi_premise
            )
        except (TypeError, ValueError) as exc:
            blockers.append(_blocker(
                status="violated",
                category="interprocedural",
                code="normal_call_abi_premise_invalid",
                message="the selected normal-call ABI premise does not replay",
                next_action="select a canonical reviewed machine-ABI premise",
                details={"reason": str(exc)},
            ))
    summaries = payload.get("call_summaries")
    recoveries = payload.get("recovered_targets")
    operation_provenance = payload.get("operation_provenance")
    memory_access_facts = (
        operation_provenance.get("checked_memory_access_facts", [])
        if isinstance(operation_provenance, Mapping)
        else []
    )
    memory_address_domains = (
        operation_provenance.get("checked_memory_address_domains", [])
        if isinstance(operation_provenance, Mapping)
        else []
    )
    call_site_effects = (
        operation_provenance.get("call_site_effects", [])
        if isinstance(operation_provenance, Mapping)
        else []
    )
    if isinstance(call_site_effects, list) and all(
        isinstance(row, Mapping) for row in call_site_effects
    ):
        try:
            parsed_effects = parse_call_site_effects(
                call_site_effects,
                finite_value_budget=256,
            )
            for site, effect in parsed_effects.items():
                unit = row_by_id.get(site.unit_id)
                semantics = unit.get("semantics") if isinstance(unit, Mapping) else None
                external_events = (
                    semantics.get("external_events")
                    if isinstance(semantics, Mapping)
                    else None
                )
                if (
                    not isinstance(external_events, list)
                    or not 0 <= site.event_index < len(external_events)
                    or not isinstance(external_events[site.event_index], Mapping)
                    or external_events[site.event_index].get("kind")
                    != effect.transfer_kind
                ):
                    raise ValueError(
                        "call-site effect does not bind an exact external event"
                    )
                if (
                    normal_call_abi_premise is not None
                    and effect.transfer_kind
                    in normal_call_abi_premise.transfer_kinds
                    and effect.register_frame_status == "complete"
                    and normal_call_abi_premise.dependency_id
                    not in effect.dependencies
                ):
                    missing_preserved = sorted(
                        set(normal_call_abi_premise.preserved_registers)
                        - set(effect.preserved_registers)
                    )
                    if missing_preserved:
                        blockers.append(_blocker(
                            status="violated",
                            category="interprocedural",
                            code="normal_call_abi_premise_contradicted",
                            message=(
                                "a checked call contradicts the selected "
                                "normal-return preservation premise"
                            ),
                            next_action=(
                                "remove the premise for this target or classify "
                                "the call with an exact machine ABI"
                            ),
                            details={
                                "unit_id": site.unit_id,
                                "event_index": site.event_index,
                                "missing_preserved_registers": missing_preserved,
                            },
                        ))
        except (TypeError, ValueError) as exc:
            blockers.append(_blocker(
                status="violated",
                category="interprocedural",
                code="interprocedural_call_site_effect_invalid",
                message="an interprocedural call-site effect does not replay",
                next_action="regenerate the v2 interprocedural authority artifact",
                details={"reason": str(exc)},
            ))
    artifact_inputs_valid = (
        isinstance(dependencies, list)
        and all(isinstance(row, Mapping) for row in dependencies)
        and isinstance(summaries, Mapping)
        and isinstance(recoveries, list)
        and all(isinstance(row, Mapping) for row in recoveries)
        and isinstance(memory_access_facts, list)
        and all(isinstance(row, Mapping) for row in memory_access_facts)
        and isinstance(memory_address_domains, list)
        and all(isinstance(row, Mapping) for row in memory_address_domains)
        and isinstance(call_site_effects, list)
        and all(isinstance(row, Mapping) for row in call_site_effects)
        and isinstance(fixed.get("root_unit_ids"), list)
        and all(isinstance(value, str) for value in fixed["root_unit_ids"])
    )
    premise_dependency_rows = (
        [
            row
            for row in dependencies
            if isinstance(row, Mapping)
            and (
                row.get("kind") == "normal_call_abi_premise"
                or str(row.get("id", "")).startswith(
                    "normal-call-abi-premise:"
                )
            )
        ]
        if isinstance(dependencies, list)
        else []
    )
    expected_premise_dependency_id = (
        None
        if normal_call_abi_premise is None
        else normal_call_abi_premise.dependency_id
    )
    premise_dependency_valid = (
        not premise_dependency_rows
        if expected_premise_dependency_id is None
        else len(premise_dependency_rows) == 1
        and premise_dependency_rows[0].get("id")
        == expected_premise_dependency_id
        and premise_dependency_rows[0].get("kind")
        == "normal_call_abi_premise"
        and premise_dependency_rows[0].get("status") == "complete"
        and premise_dependency_rows[0].get("lattice_complete") is True
        and premise_dependency_rows[0].get("dependencies") == []
    )
    if not premise_dependency_valid:
        blockers.append(_blocker(
            status="violated",
            category="interprocedural",
            code="normal_call_abi_premise_dependency_mismatch",
            message=(
                "the normal-call ABI premise and typed dependency inventory "
                "do not agree"
            ),
            next_action="rerun the interprocedural authority analysis",
            details={
                "expected_dependency_id": expected_premise_dependency_id,
                "observed": _safe_json(premise_dependency_rows),
            },
        ))
    observed_authority_sha256 = fixed.get("authority_artifact_sha256")
    expected_authority_sha256 = (
        interprocedural_authority_signature_v2(
            root_unit_ids=fixed["root_unit_ids"],
            dependency_inventory=dependencies,
            call_summaries=summaries,
            recovered_targets=recoveries,
            memory_access_facts=memory_access_facts,
            memory_address_domains=memory_address_domains,
            call_site_effects=call_site_effects,
            normal_call_abi_premise=(
                None
                if normal_call_abi_premise is None
                else normal_call_abi_premise.as_json()
            ),
        )
        if artifact_inputs_valid
        else None
    )
    if (
        expected_authority_sha256 is not None
        and observed_authority_sha256 != expected_authority_sha256
    ):
        blockers.append(_blocker(
            status="violated",
            category="interprocedural",
            code="interprocedural_authority_hash_mismatch",
            message="the interprocedural outputs do not match their authority digest",
            next_action="discard the stale artifact and replay the affected SCC authority certificates",
            details={
                "expected": expected_authority_sha256,
                "observed": _safe_json(observed_authority_sha256),
            },
        ))
    if isinstance(memory_access_facts, list) and any(
        row.get("interprocedural_authority_sha256")
        != observed_authority_sha256
        for row in memory_access_facts
        if isinstance(row, Mapping)
    ):
        blockers.append(_blocker(
            status="violated",
            category="interprocedural",
            code="memory_access_authority_binding_mismatch",
            message="a checked memory-access fact is bound to another replay",
            next_action="regenerate the unseeded interprocedural authority artifact",
        ))
    inductive = fixed.get("inductive_replay")
    raw_accepted_nodes = (
        inductive.get("accepted_nodes")
        if isinstance(inductive, Mapping)
        else None
    )
    accepted_nodes: list[Any] = (
        raw_accepted_nodes if isinstance(raw_accepted_nodes, list) else []
    )
    raw_reproduced_ids = (
        inductive.get("reproduced_ids")
        if isinstance(inductive, Mapping)
        else None
    )
    reproduced_ids: list[Any] = (
        raw_reproduced_ids if isinstance(raw_reproduced_ids, list) else []
    )
    accepted_hypothesis_ids = {
        value for value in accepted_nodes
        if isinstance(value, str)
        and (
            value.startswith("indirect-exit:")
            or value.startswith("call-frame-hypothesis:")
        )
    }
    inductive_authority_valid = bool(
        accepted_nodes
        and isinstance(inductive, Mapping)
        and inductive.get("executed") is True
        and inductive.get("converged") is True
        and inductive.get("proof_authority") is True
        and accepted_hypothesis_ids <= {
            value for value in reproduced_ids if isinstance(value, str)
        }
    )
    discovery_signature = fixed.get("discovery_signature")
    replay_identity_valid = (
        (
            fixed.get("cold_initial_recoveries_empty") is True
            and fixed.get("static_recovery_authority_seeded") is False
            and (
                discovery_signature is None
                or discovery_signature == fixed.get("cold_replay_signature")
            )
        )
        if not accepted_nodes
        else inductive_authority_valid
    )
    replay_authoritative = (
        fixed.get("cold_replay_validated") is True
        and fixed.get("authority_replay_validated") is True
        and fixed.get("global_slot_promotion") is False
        and replay_identity_valid
        and expected_authority_sha256 is not None
        and observed_authority_sha256 == expected_authority_sha256
        and isinstance(failure_reasons, list)
    )
    if fixed.get("status") == "complete" and (
        not replay_authoritative or failures
    ):
        blockers.append(_blocker(
            status="violated",
            category="interprocedural",
            code="interprocedural_completion_contradiction",
            message="the fixed point claims completion without a bound cold or dependency-closed SCC replay",
            next_action="discard proposal-only facts and rerun the affected SCC authority certificates",
            details={"fixed_point": _safe_json(fixed)},
            frontiers=_scc_frontier(fixed),
        ))
    elif not replay_authoritative:
        blockers.append(_blocker(
            status="incomplete",
            category="interprocedural",
            code="interprocedural_replay_incomplete",
            message="the unified interprocedural cold replay is not authoritative",
            next_action="repair the unseeded replay binding and rerun the affected SCCs",
            details={"failure_reasons": _safe_json(failures)},
            frontiers=_scc_frontier(fixed),
        ))
    else:
        local_failure_codes = {
            "interprocedural_lattice_overflow_or_conflict",
            "reachable_indirect_targets_incomplete",
        }
        unexplained_failures = sorted(
            str(reason) for reason in failures if reason not in local_failure_codes
        )
        if unexplained_failures:
            blockers.append(_blocker(
                status="incomplete",
                category="interprocedural",
                code="interprocedural_fixed_point_incomplete",
                message="the unified interprocedural analysis has not converged",
                next_action="repair the affected SCC transfer and replay cold",
                details={"failure_reasons": unexplained_failures},
                frontiers=_scc_frontier(fixed),
            ))
    return payload


def _external_authority_records(
    rows: Sequence[Mapping[str, Any]],
    *,
    profile_authority: ExternalProfileAuthorityV2 | None,
    interprocedural: Mapping[str, Any],
    unit_by_id: Mapping[str, UnitBinding],
    row_by_id: Mapping[str, Mapping[str, Any]],
    blockers: list[dict[str, Any]],
) -> tuple[CheckedExternalSite, ...]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        blockers.append(_blocker(
            status="violated",
            category="external_site",
            code="external_site_inventory_corrupt",
            message="checked external sites are not an array",
            next_action="regenerate canonical external-site contracts",
        ))
        return ()
    result: list[CheckedExternalSite] = []
    seen: set[tuple[str, int]] = set()
    for index, raw in enumerate(rows):
        unit_id: str | None = None
        event_index: int | None = None
        alternative_index: int | None = None
        alternative_sha256: str | None = None
        instruction_rva: int | None = None
        try:
            if not isinstance(raw, Mapping):
                raise StaticHybridAuthorityV2Error("site row is not an object")
            raw_unit_id = raw.get("unit_id")
            raw_event_index = raw.get("event_index")
            raw_alternative_index = raw.get("target_alternative_index")
            raw_alternative_sha256 = raw.get("target_alternative_sha256")
            if (
                not isinstance(raw_unit_id, str)
                or not isinstance(raw_event_index, int)
                or isinstance(raw_event_index, bool)
                or not isinstance(raw_alternative_index, int)
                or isinstance(raw_alternative_index, bool)
                or raw_alternative_index < 0
                or not isinstance(raw_alternative_sha256, str)
                or len(raw_alternative_sha256) != 64
                or any(
                    character not in _DIGEST_CHARS
                    for character in raw_alternative_sha256
                )
            ):
                raise StaticHybridAuthorityV2Error("site identity is malformed")
            unit_id = raw_unit_id
            event_index = raw_event_index
            alternative_index = raw_alternative_index
            alternative_sha256 = raw_alternative_sha256
            key = (unit_id, event_index, alternative_index)
            if key in seen:
                raise StaticHybridAuthorityV2Error("site identity is duplicated")
            seen.add(key)
            unit = unit_by_id.get(unit_id)
            unit_row = row_by_id.get(unit_id)
            if unit is None or unit_row is None:
                raise StaticHybridAuthorityV2Error("site unit is absent from exact machine IR")
            semantics = unit_row.get("semantics")
            events = semantics.get("external_events") if isinstance(semantics, Mapping) else None
            if not isinstance(events, list) or not 0 <= event_index < len(events):
                raise StaticHybridAuthorityV2Error("site event is absent from exact machine IR")
            event = events[event_index]
            if not isinstance(event, Mapping):
                raise StaticHybridAuthorityV2Error("site event is malformed")
            raw_instruction_rva = event.get("instruction_rva")
            if isinstance(raw_instruction_rva, int) and not isinstance(
                raw_instruction_rva, bool
            ):
                instruction_rva = raw_instruction_rva
            contract_payload = raw.get("contract")
            if not isinstance(contract_payload, Mapping) or contract_payload.get("format") != CHECKED_EXTERNAL_SITE_CONTRACT_FORMAT:
                raise StaticHybridAuthorityV2Error("site has no canonical checked contract")
            if contract_payload.get("abi_template") is None:
                blockers.append(_external_site_blocker(
                    status="incomplete",
                    code="external_site_abi_missing",
                    message="a reachable external site has no exact machine ABI",
                    next_action="recover the target, ABI, argument words, and stack disposition",
                    site_index=index,
                    unit_id=unit_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                ))
                continue
            contract = parse_checked_external_site_contract(
                contract_payload, context=f"checked external site {unit_id}:{event_index}"
            )
            target_binding = _external_target_binding_status(
                contract,
                event=event,
                unit=unit,
                unit_id=unit_id,
                event_index=event_index,
                alternative_index=alternative_index,
                alternative_sha256=alternative_sha256,
                interprocedural=interprocedural,
            )
            if target_binding is not None:
                binding_status, binding_code, binding_message = target_binding
                blockers.append(_external_site_blocker(
                    status=binding_status,
                    code=binding_code,
                    message=binding_message,
                    next_action=(
                        "complete the unique finite external-target recovery"
                        if binding_status == "incomplete"
                        else "regenerate the site from the exact recovered target"
                    ),
                    site_index=index,
                    unit_id=unit_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                ))
                continue
            if profile_authority is None:
                blockers.append(_external_site_blocker(
                    status="incomplete",
                    code="external_profile_evidence_missing",
                    message="a reachable external site has no exact-artifact profile index",
                    next_action="build the v2 external-profile authority from the pinned profile files",
                    site_index=index,
                    unit_id=unit_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                ))
                continue
            if not isinstance(profile_authority, ExternalProfileAuthorityV2):
                raise ExternalProfileAuthorityV2Error(
                    "external-profile authority input is not a v2 exact-artifact index"
                )
            replay = profile_authority.replay_lookup(
                contract,
                context=f"checked external site {unit_id}:{event_index}",
            )
            if replay.status != "complete" or replay.entry is None:
                blockers.append(_external_site_blocker(
                    status=replay.status,
                    code=replay.reason_code or "external_profile_replay_failed",
                    message=(
                        replay.message
                        or "the checked external site did not replay against its exact profile"
                    ),
                    next_action=(
                        "supply the exact profile ABI/effect entry"
                        if replay.status == "incomplete"
                        else "discard stale copied profile fields and regenerate this site"
                    ),
                    site_index=index,
                    unit_id=unit_id,
                    event_index=event_index,
                    instruction_rva=instruction_rva,
                    details={
                        "target_alternative_index": alternative_index,
                        "profile_authority_id": profile_authority.authority_id,
                        "profile_entry_id": (
                            None if replay.entry is None else replay.entry.entry_id
                        ),
                    },
                ))
                continue
            profile_entry = replay.entry
            binding = recompute_event_binding(
                unit, event, event_index=event_index
            )
            record = CheckedExternalSite(
                site=binding,
                profile=ProfileBinding(
                    profile_id=profile_entry.profile_id,
                    profile_sha256=profile_entry.profile_sha256,
                    entry_id=profile_entry.entry_id,
                ),
                transfer_kind=contract.transfer_kind,
                alternatives=FiniteAlternatives.of(
                    [contract.payload()], maximum=1
                ),
                target_alternative_index=alternative_index,
                target_alternative_sha256=alternative_sha256,
            )
            if record.status is AuthorityStatus.VIOLATED:
                raise StaticHybridAuthorityV2Error(
                    "site contract contradicts its exact transfer event"
                )
            result.append(record)
        except (AuthorityDataError, CheckedExternalSiteContractError, ExternalProfileAuthorityV2Error, StaticHybridAuthorityV2Error, TypeError, ValueError) as exc:
            blockers.append(_external_site_blocker(
                status="violated",
                code="external_site_contract_corrupt",
                message="a submitted external-site contract does not bind its exact event and profile",
                next_action="regenerate the canonical site contract after target resolution",
                site_index=index,
                unit_id=unit_id,
                event_index=event_index,
                instruction_rva=instruction_rva,
                details={
                    "reason": str(exc),
                    "target_alternative_index": alternative_index,
                },
            ))
    return tuple(result)


def _external_target_binding_status(
    contract: Any,
    *,
    event: Mapping[str, Any],
    unit: UnitBinding,
    unit_id: str,
    event_index: int,
    alternative_index: int,
    alternative_sha256: str,
    interprocedural: Mapping[str, Any],
) -> tuple[str, str, str] | None:
    event_kind = event.get("kind")
    if event_kind in {"external_call", "external_jump"}:
        if alternative_index != 0:
            return (
                "violated",
                "external_direct_target_alternative_index_invalid",
                "a direct external event must use target alternative zero",
            )
        if contract.identity.kind != "import":
            return (
                "violated",
                "external_site_direct_identity_mismatch",
                "a direct external event is bound to a non-import site identity",
            )
        try:
            observed = ExternalSiteIdentity.imported(
                event, context=f"{unit_id}:{event_index} exact external event"
            )
        except CheckedExternalSiteContractError as exc:
            return "violated", "external_event_identity_corrupt", str(exc)
        if observed != contract.identity:
            return (
                "violated",
                "external_site_direct_identity_mismatch",
                "the checked site import differs from the exact machine-IR event",
            )
        expected_sha256 = hashlib.sha256(
            canonical_json_bytes(observed.payload())
        ).hexdigest()
        if alternative_sha256 != expected_sha256:
            return (
                "violated",
                "external_target_alternative_hash_mismatch",
                "the direct external target identity hash is stale",
            )
        return None
    if event_kind not in {"indirect_call", "indirect_jump"}:
        return (
            "violated",
            "external_site_event_kind_mismatch",
            "the checked external site does not name an external or indirect transfer",
        )
    raw_recoveries = interprocedural.get("recovered_targets")
    recoveries = raw_recoveries if isinstance(raw_recoveries, list) else []
    try:
        exit_binding = IndirectExitBinding.from_exact(
            unit=unit,
            source_event_index=event_index,
            transfer_kind=str(event_kind),
            instruction_rva=(
                event["instruction_rva"]
                if isinstance(event.get("instruction_rva"), int)
                and not isinstance(event.get("instruction_rva"), bool)
                else unit.rva_start
            ),
            target_expression=event.get("target"),
        )
    except AuthorityDataError as exc:
        return "violated", "external_indirect_binding_corrupt", str(exc)
    match_status, recovery, match_code = match_indirect_recovery_v2(
        recoveries, exit_binding
    )
    if match_status != "complete" or recovery is None:
        return (
            match_status,
            match_code or "external_target_recovery_missing",
            (
                "the indirect external site recovery contradicts its exact binding"
                if match_status == "violated"
                else "the indirect external site has no unique complete target recovery"
            ),
        )
    if recovery.get("status") != "recovered":
        return (
            "incomplete",
            "external_target_recovery_incomplete",
            "the indirect external site target recovery is incomplete",
        )
    raw_targets = recovery.get("external_targets")
    if not isinstance(raw_targets, list) or any(
        not isinstance(target, Mapping) for target in raw_targets
    ):
        return (
            "violated",
            "external_target_recovery_corrupt",
            "the finite external target inventory is malformed",
        )
    targets = sorted(
        raw_targets,
        key=lambda target: hashlib.sha256(
            canonical_json_bytes(target)
        ).hexdigest(),
    )
    if not targets:
        return (
            "incomplete",
            "external_target_recovery_missing",
            "the indirect external site has no finite external target",
        )
    if alternative_index >= len(targets):
        return (
            "violated",
            "external_target_alternative_index_invalid",
            "the checked site refers beyond the finite target inventory",
        )
    target = targets[alternative_index]
    expected_sha256 = hashlib.sha256(canonical_json_bytes(target)).hexdigest()
    if alternative_sha256 != expected_sha256:
        return (
            "violated",
            "external_target_alternative_hash_mismatch",
            "the checked site target hash differs from target recovery",
        )
    try:
        recovered_identity, recovered_profile, recovered_transfer = (
            _recovered_external_identity(target)
        )
    except (CheckedExternalSiteContractError, TypeError, ValueError) as exc:
        return "violated", "external_target_recovery_corrupt", str(exc)
    if recovered_identity != contract.identity:
        return (
            "violated",
            "external_target_identity_mismatch",
            "the checked site identity differs from target recovery",
        )
    if recovered_transfer is not None and recovered_transfer != contract.transfer_kind:
        return (
            "violated",
            "external_target_transfer_mismatch",
            "the checked site call/jump kind differs from target recovery",
        )
    profile = contract.profile_binding
    if recovered_profile is not None and (
        not isinstance(profile, Mapping)
        or profile.get("profile_id") != recovered_profile[0]
        or profile.get("profile_sha256") != recovered_profile[1]
    ):
        return (
            "violated",
            "external_target_profile_mismatch",
            "the checked site profile binding differs from target recovery",
        )
    target_abi = target.get("abi")
    if isinstance(target_abi, Mapping) and target_abi.get("template") != contract.abi_template:
        return (
            "violated",
            "external_target_abi_mismatch",
            "the checked site ABI differs from target recovery",
        )
    target_words = target.get("argument_words")
    if target_words is not None and target_words != contract.argument_words:
        return (
            "violated",
            "external_target_arity_mismatch",
            "the checked site arity differs from target recovery",
        )
    return None


def _recovered_external_identity(
    target: Mapping[str, Any],
) -> tuple[ExternalSiteIdentity, tuple[str, str] | None, str | None]:
    protocol = target.get("external_protocol")
    if isinstance(protocol, Mapping):
        kind = protocol.get("kind")
        if kind == "pe32-operation":
            profile_id = protocol.get("profile_id")
            profile_sha = protocol.get("profile_sha256")
            operation = protocol.get("operation_id")
            if (
                not isinstance(profile_id, str)
                or not _digest(profile_sha)
                or not isinstance(operation, str)
                or not operation
            ):
                raise StaticHybridAuthorityV2Error(
                    "recovered external operation identity is malformed"
                )
            return (
                ExternalSiteIdentity(
                    kind="interface",
                    protocol="pe32-operation",
                    profile_id=profile_id,
                    profile_sha256=str(profile_sha),
                    operation=operation,
                ),
                (profile_id, str(profile_sha)),
                (
                    str(protocol["transfer_kind"])
                    if protocol.get("transfer_kind") in {"call", "jump"}
                    else None
                ),
            )
        identity = ExternalSiteIdentity.interface(
            protocol, context="recovered external protocol"
        )
        profile = (
            (identity.profile_id, identity.profile_sha256)
            if identity.profile_id is not None and identity.profile_sha256 is not None
            else None
        )
        transfer = protocol.get("transfer_kind")
        return (
            identity,
            profile,
            str(transfer) if transfer in {"call", "jump"} else None,
        )
    imported = target.get("import", target)
    if not isinstance(imported, Mapping):
        raise StaticHybridAuthorityV2Error(
            "recovered external import identity is malformed"
        )
    return (
        ExternalSiteIdentity.imported(
            imported, context="recovered external import"
        ),
        None,
        None,
    )


def _external_site_blocker(
    *,
    status: str,
    code: str,
    message: str,
    next_action: str,
    site_index: int,
    unit_id: str | None,
    event_index: int | None,
    instruction_rva: int | None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    location = {
        "site_index": site_index,
        "unit_id": unit_id,
        "event_index": event_index,
        "instruction_rva": instruction_rva,
    }
    return _blocker(
        status=status,
        category="external_site",
        code=code,
        message=message,
        next_action=next_action,
        details={**location, **({} if details is None else dict(details))},
        frontiers={"environment": [{
            "id": (
                f"environment:{unit_id}:{event_index}"
                if unit_id is not None and event_index is not None
                else f"environment:site:{site_index}"
            ),
        }]},
    )


def _exception_authority_records(
    reports: Sequence[Mapping[str, Any]],
    records: Sequence[AuthorityRecord | Mapping[str, Any]],
    *,
    unit_by_id: Mapping[str, UnitBinding],
    row_by_id: Mapping[str, Mapping[str, Any]],
    blockers: list[dict[str, Any]],
) -> tuple[ValueFact, ...]:
    result: list[ValueFact] = []
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        blockers.append(_blocker(
            status="violated",
            category="exceptional_control",
            code="exception_authority_inventory_corrupt",
            message="exception authority records are not an array",
            next_action="regenerate v2 exceptional-control records",
        ))
        records = ()
    for index, raw in enumerate(records):
        try:
            record = raw if isinstance(raw, _RECORD_TYPES) else parse_authority_record(raw)
            if (
                not isinstance(record, ValueFact)
                or not isinstance(record.binding, EventBinding)
                or record.binding.event_kind != "fault"
                or record.location != "exceptional_control"
            ):
                raise AuthorityDataError("record is not an exceptional-control value fact")
            result.append(record)
        except (AuthorityDataError, TypeError, ValueError) as exc:
            blockers.append(_blocker(
                status="violated",
                category="exceptional_control",
                code="exception_authority_record_corrupt",
                message="an exceptional-control authority record does not replay",
                next_action="regenerate the v2 exceptional-control record",
                details={"record_index": index, "reason": str(exc)},
            ))
    if not isinstance(reports, Sequence) or isinstance(reports, (str, bytes)):
        blockers.append(_blocker(
            status="violated",
            category="exceptional_control",
            code="exception_report_inventory_corrupt",
            message="checked exception reports are not an array",
            next_action="regenerate checked exception reports",
        ))
        reports = ()
    seen = {
        (binding.unit.unit_id, binding.event_index)
        for record in result
        for binding in (record.binding,)
        if isinstance(binding, EventBinding)
    }
    for report_index, raw in enumerate(reports):
        if not isinstance(raw, Mapping):
            blockers.append(_exception_blocker(
                "violated", "exception_report_corrupt", report_index,
                "checked exception report is not an object",
            ))
            continue
        try:
            report = _canonical_value(
                raw, context=f"exception report {report_index}"
            )
        except StaticHybridAuthorityV2Error as exc:
            blockers.append(_exception_blocker(
                "violated", "exception_report_corrupt", report_index,
                str(exc),
            ))
            continue
        if report.get("format") != EXCEPTION_INVARIANT_CHECK_V2_FORMAT:
            blockers.append(_exception_blocker(
                "violated", "exception_report_format_mismatch", report_index,
                "checked exception report has the wrong format",
            ))
            continue
        issues = report.get("issues")
        faults = report.get("faults")
        derived = _issue_status(issues if isinstance(issues, list) else [])
        if isinstance(faults, list) and any(
            isinstance(row, Mapping) and row.get("status") == "violated"
            for row in faults
        ):
            derived = "violated"
        elif derived == "complete" and isinstance(faults, list) and any(
            not isinstance(row, Mapping) or row.get("status") != "complete"
            for row in faults
        ):
            derived = "incomplete"
        if (
            report.get("status") != derived
            or report.get("uses_bounded_paths") is not False
            or not _digest(report.get("certificate_sha256"))
        ):
            blockers.append(_exception_blocker(
                "violated", "exception_report_status_contradiction", report_index,
                "exception report copied a stale status or lacks unbounded checked evidence",
            ))
            continue
        if derived != "complete":
            blockers.append(_exception_blocker(
                derived, "exception_report_incomplete", report_index,
                "exception invariant or fault outcome remains unresolved",
            ))
            continue
        if not isinstance(faults, list):
            blockers.append(_exception_blocker(
                "violated", "exception_fault_inventory_corrupt", report_index,
                "exception report fault inventory is malformed",
            ))
            continue
        for fault_result in faults:
            try:
                if not isinstance(fault_result, Mapping):
                    raise StaticHybridAuthorityV2Error("fault result is malformed")
                unit_id = fault_result.get("source_unit_id")
                fault_index = fault_result.get("fault_index")
                if not isinstance(unit_id, str) or not isinstance(fault_index, int) or isinstance(fault_index, bool):
                    raise StaticHybridAuthorityV2Error("fault identity is malformed")
                key = (unit_id, fault_index)
                if key in seen:
                    raise StaticHybridAuthorityV2Error("fault authority is duplicated")
                unit = unit_by_id.get(unit_id)
                unit_row = row_by_id.get(unit_id)
                semantics = unit_row.get("semantics") if isinstance(unit_row, Mapping) else None
                fault_rows = semantics.get("faults") if isinstance(semantics, Mapping) else None
                if unit is None or not isinstance(fault_rows, list) or not 0 <= fault_index < len(fault_rows):
                    raise StaticHybridAuthorityV2Error("fault is absent from exact machine IR")
                fault = fault_rows[fault_index]
                if not isinstance(fault, Mapping) or fault_result.get("fault_sha256") != exception_sha256(fault):
                    raise StaticHybridAuthorityV2Error("fault digest contradicts exact machine IR")
                if fault_result.get("outcome") not in {
                    "checked_infeasible",
                    "observable_terminal_fault",
                    "finite_supported_seh_target",
                } or fault_result.get("reason_code") is not None:
                    raise StaticHybridAuthorityV2Error("fault has no supported closed outcome")
                binding = recompute_event_binding(
                    unit,
                    fault,
                    event_index=fault_index,
                    event_kind="fault",
                )
                result.append(ValueFact(
                    binding=binding,
                    location="exceptional_control",
                    width_bits=1,
                    alternatives=FiniteAlternatives.of([{
                        "certificate_sha256": report["certificate_sha256"],
                        "fault_sha256": fault_result["fault_sha256"],
                        "outcome": fault_result["outcome"],
                        "target_unit_ids": fault_result.get("target_unit_ids", []),
                    }], maximum=1),
                ))
                seen.add(key)
            except (AuthorityDataError, StaticHybridAuthorityV2Error, TypeError, ValueError) as exc:
                blockers.append(_exception_blocker(
                    "violated", "exception_fault_binding_corrupt", report_index,
                    str(exc),
                ))
    return tuple(result)


def _isa_authority(
    value: (
        ISAKernelSelectionAuthority
        | ISAKernelSelectionAuthorityCheck
        | MachineIRISASelectionCertificateV2
        | Mapping[str, Any]
        | None
    ),
    *,
    exact_requirements: Mapping[str, Any] | None,
    pe_sha256: str | None,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    expected_machine_ir_sha256: str | None,
    blockers: list[dict[str, Any]],
) -> tuple[
    ISAKernelSelectionAuthority | MachineIRISASelectionCertificateV2 | None,
    MachineIRISARequirementsV2 | None,
]:
    requirements, requirements_authorize = _exact_isa_requirements(
        exact_requirements,
        pe_sha256=pe_sha256,
        machine_ir_rows=machine_ir_rows,
        expected_machine_ir_sha256=expected_machine_ir_sha256,
        blockers=blockers,
    )
    if isinstance(value, ISAKernelSelectionAuthorityCheck):
        expected_check_status = (
            SelectionAuthorityStatus.INCOMPLETE
            if value.authority is None
            else value.authority.status
        )
        if value.status is not expected_check_status:
            blockers.append(_blocker(
                status="violated",
                category="isa",
                code="isa_selection_check_contradiction",
                message="ISA authority-check status contradicts its embedded authority",
                next_action="replay ISA selection authority validation",
                details={
                    "declared": value.status.value,
                    "derived": expected_check_status.value,
                },
                frontiers={"isa": [{"id": "isa:selection"}]},
            ))
        if value.authority is None:
            status = (
                "violated"
                if value.status is SelectionAuthorityStatus.VIOLATED
                else "incomplete"
            )
            blockers.append(_blocker(
                status=status,
                category="isa",
                code="isa_selection_authority_unusable",
                message="ISA selection authority has no replayable artifact",
                next_action="qualify and select every reachable instruction form",
                details={"check": value.to_payload()},
                frontiers={"isa": [{"id": "isa:selection"}]},
            ))
            return None, requirements
        value = value.authority
    if value is None:
        blockers.append(_blocker(
            status="incomplete",
            category="isa",
            code="isa_selection_authority_missing",
            message="binary-specific ISA selection authority is missing",
            next_action="qualify and select every reachable instruction form",
            frontiers={"isa": [{"id": "isa:selection"}]},
        ))
        return None, requirements
    try:
        if isinstance(value, MachineIRISASelectionCertificateV2):
            authority: ISAKernelSelectionAuthority | MachineIRISASelectionCertificateV2 = value
        elif isinstance(value, ISAKernelSelectionAuthority):
            authority = value
        elif value.get("format") == MACHINE_IR_ISA_SELECTION_CERTIFICATE_V2_FORMAT:
            authority = parse_machine_ir_isa_selection_certificate_v2(value)
        else:
            authority = parse_isa_kernel_selection_authority(value)
    except (
        ISAKernelSelectionAuthorityError,
        MachineIRISASelectionV2Error,
        AttributeError,
        TypeError,
        ValueError,
    ) as exc:
        blockers.append(_blocker(
            status="violated",
            category="isa",
            code="isa_selection_authority_corrupt",
            message="ISA selection authority cannot be strictly replayed",
            next_action="regenerate the binary-specific ISA authority",
            details={"reason": str(exc)},
            frontiers={"isa": [{"id": "isa:selection"}]},
        ))
        return None, requirements
    authority_binary_sha256 = (
        authority.binary_sha256
        if isinstance(authority, MachineIRISASelectionCertificateV2)
        else authority.requirements.binary_sha256
    )
    if pe_sha256 is not None and authority_binary_sha256 != pe_sha256:
        blockers.append(_blocker(
            status="violated",
            category="isa",
            code="isa_binary_binding_mismatch",
            message="ISA authority binds a different PE binary",
            next_action="rebuild ISA selection for the exact input PE",
            details={
                "expected": pe_sha256,
                "observed": authority_binary_sha256,
            },
            frontiers={"isa": [{"id": "isa:selection"}]},
        ))
    authority_qualified = (
        authority.status == "qualified"
        if isinstance(authority, MachineIRISASelectionCertificateV2)
        else authority.status is SelectionAuthorityStatus.QUALIFIED
    )
    if not authority_qualified:
        authority_violated = (
            authority.status == "violated"
            if isinstance(authority, MachineIRISASelectionCertificateV2)
            else authority.status is SelectionAuthorityStatus.VIOLATED
        )
        blockers.append(_blocker(
            status=(
                "violated"
                if authority_violated
                else "incomplete"
            ),
            category="isa",
            code="isa_selection_not_qualified",
            message="one or more reachable instruction forms lack uncontested qualified semantics",
            next_action="resolve the reported ISA form and oracle frontiers",
            details={
                "issues": [
                    str(issue.get("code"))
                    if isinstance(issue, Mapping)
                    else issue.code
                    for issue in authority.issues
                ]
            },
            frontiers={
                "isa": [
                    {
                        "id": "isa:" + str(
                            issue.get("form_id") or "selection"
                            if isinstance(issue, Mapping)
                            else issue.form_id or "selection"
                        ),
                        "code": str(
                            issue.get("code")
                            if isinstance(issue, Mapping)
                            else issue.code
                        ),
                    }
                    for issue in authority.issues
                ] or [{"id": "isa:selection"}],
            },
        ))
    if requirements is not None and requirements.status == "complete":
        comparison_issues = (
            compare_isa_selection_certificate_to_requirements_v2(
                authority, requirements
            )
            if isinstance(authority, MachineIRISASelectionCertificateV2)
            else compare_selection_to_machine_ir_requirements_v2(
                requirements, authority
            )
        )
        for issue in comparison_issues:
            blockers.append(_blocker(
                status=str(issue["status"]),
                category="isa",
                code=str(issue["code"]),
                message="ISA selection does not replay from exact Lean-derived requirements",
                next_action="regenerate qualification and selection from the exact ISA requirements",
                details={"comparison": issue},
                frontiers={"isa": [{"id": "isa:selection"}]},
            ))
    if requirements is not None:
        _check_isa_location_coverage(
            requirements
            if isinstance(authority, MachineIRISASelectionCertificateV2)
            else authority.requirements,
            machine_ir_rows=machine_ir_rows,
            pe_sha256=pe_sha256,
            blockers=blockers,
        )
    return (
        authority if requirements_authorize else None,
        requirements if requirements_authorize else None,
    )


def _exact_isa_requirements(
    value: Mapping[str, Any] | None,
    *,
    pe_sha256: str | None,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    expected_machine_ir_sha256: str | None,
    blockers: list[dict[str, Any]],
) -> tuple[MachineIRISARequirementsV2 | None, bool]:
    if value is None:
        blockers.append(_blocker(
            status="incomplete",
            category="isa",
            code="isa_exact_requirements_missing",
            message="exact Lean-derived ISA requirements are missing",
            next_action="extract every reachable instruction form from the exact PE in Lean",
            frontiers={"isa": [{"id": "isa:requirements"}]},
        ))
        return None, False
    try:
        requirements = parse_machine_ir_isa_requirements_v2(value)
    except (MachineIRISARequirementsV2Error, TypeError, ValueError) as exc:
        blockers.append(_blocker(
            status="violated",
            category="isa",
            code="isa_exact_requirements_corrupt",
            message="exact ISA requirements cannot be strictly replayed",
            next_action="regenerate the Lean-derived ISA requirements artifact",
            details={"reason": str(exc)},
            frontiers={"isa": [{"id": "isa:requirements"}]},
        ))
        return None, False

    authorizes = True
    if expected_machine_ir_sha256 is None:
        expected_machine_ir_sha256 = machine_ir_sha256(machine_ir_rows)
    binding_mismatches: dict[str, dict[str, str | None]] = {}
    if pe_sha256 is not None and requirements.binary_sha256 != pe_sha256:
        binding_mismatches["binary_sha256"] = {
            "expected": pe_sha256,
            "observed": requirements.binary_sha256,
        }
    if requirements.machine_ir_sha256 != expected_machine_ir_sha256:
        binding_mismatches["machine_ir_sha256"] = {
            "expected": expected_machine_ir_sha256,
            "observed": requirements.machine_ir_sha256,
        }
    expected_request_sha256: str | None = None
    if pe_sha256 is not None:
        try:
            expected_request_sha256 = str(
                build_machine_ir_isa_extraction_request_v2(
                    units=machine_ir_rows,
                    binary_sha256=pe_sha256,
                )["request_sha256"]
            )
        except (MachineIRISARequirementsV2Error, TypeError, ValueError) as exc:
            authorizes = False
            blockers.append(_blocker(
                status="violated",
                category="isa",
                code="isa_exact_request_replay_failed",
                message="the exact ISA extraction request cannot be replayed from machine IR",
                next_action="repair the reachable instruction inventory and regenerate ISA requirements",
                details={"reason": str(exc)},
                frontiers={"isa": [{"id": "isa:requirements"}]},
            ))
    if (
        expected_request_sha256 is not None
        and requirements.request_sha256 != expected_request_sha256
    ):
        binding_mismatches["request_sha256"] = {
            "expected": expected_request_sha256,
            "observed": requirements.request_sha256,
        }
    if binding_mismatches:
        authorizes = False
        blockers.append(_blocker(
            status="violated",
            category="isa",
            code="isa_exact_requirements_binding_mismatch",
            message="exact ISA requirements bind different PE or machine-IR inputs",
            next_action="rebuild ISA requirements from the exact current inputs",
            details={"mismatches": binding_mismatches},
            frontiers={"isa": [{"id": "isa:requirements"}]},
        ))

    if requirements.status != "complete":
        authorizes = False
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for issue in requirements.issues:
            proposal = issue.get("diagnostic_proposal")
            group_key = json.dumps(
                proposal if isinstance(proposal, Mapping) else {
                    "code": issue.get("code")
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            grouped.setdefault(group_key, []).append(issue)
        for group in grouped.values():
            first = group[0]
            locations = [
                {
                    "rva": issue.get("rva"),
                    "byte_length": issue.get("byte_length"),
                    "unit_id": issue.get("unit_id"),
                    "instruction_index": issue.get("instruction_index"),
                }
                for issue in group
                if isinstance(issue.get("rva"), int)
                and isinstance(issue.get("byte_length"), int)
            ]
            status = (
                "violated"
                if any(issue.get("status") == "violated" for issue in group)
                else "incomplete"
            )
            blockers.append(_blocker(
                status=status,
                category="isa",
                code=str(first.get("code", "isa_exact_requirement_incomplete")),
                message="a reachable instruction family lacks exact qualified Lean semantics",
                next_action="implement and qualify this instruction family, then replay exact extraction",
                details={
                    "diagnostic_proposal": first.get("diagnostic_proposal"),
                    "locations": locations,
                    "occurrence_count": len(group),
                    "requirements_status": requirements.status,
                },
                frontiers={
                    "isa": [
                        {
                            "id": f"isa:location:{location['rva']:x}:{location['byte_length']}"
                        }
                        for location in locations
                    ] or [{"id": "isa:requirements"}],
                },
            ))
    return requirements, authorizes


def _check_isa_location_coverage(
    requirements: Any,
    *,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    pe_sha256: str | None,
    blockers: list[dict[str, Any]],
) -> None:
    required_locations: dict[tuple[int, int], list[str]] = {}
    wrong_binary: list[dict[str, Any]] = []
    for form in requirements.forms:
        for location in form.source_locations:
            if pe_sha256 is not None and location.image_sha256 != pe_sha256:
                wrong_binary.append({
                    "form_id": form.form_id,
                    "rva": location.rva,
                    "image_sha256": location.image_sha256,
                })
                continue
            key = (location.rva, location.byte_length)
            required_locations.setdefault(key, []).append(form.form_id)

    instruction_locations: set[tuple[int, int]] = set()
    malformed: list[dict[str, Any]] = []
    for row in machine_ir_rows:
        if row.get("reachable") is not True:
            continue
        instructions = row.get("instructions")
        if not isinstance(instructions, list):
            malformed.append({"unit_id": row.get("id"), "reason": "instructions_missing"})
            continue
        for index, instruction in enumerate(instructions):
            if not isinstance(instruction, Mapping):
                malformed.append({"unit_id": row.get("id"), "instruction_index": index})
                continue
            start = instruction.get("rva_start", instruction.get("rva"))
            end = instruction.get("rva_end")
            size = instruction.get("size")
            if (
                isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(end, int)
                and not isinstance(end, bool)
                and end > start
            ):
                length = end - start
            elif (
                isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(size, int)
                and not isinstance(size, bool)
                and size > 0
            ):
                length = size
            else:
                malformed.append({"unit_id": row.get("id"), "instruction_index": index})
                continue
            instruction_locations.add((start, length))

    duplicates = {
        key: sorted(ids)
        for key, ids in required_locations.items()
        if len(ids) != 1
    }
    if wrong_binary or malformed or duplicates:
        blockers.append(_blocker(
            status="violated",
            category="isa",
            code="isa_location_inventory_contradiction",
            message="ISA location authority contradicts the exact reachable instruction inventory",
            next_action="regenerate binary-specific ISA requirements from exact machine IR",
            details={
                "wrong_binary": wrong_binary,
                "malformed_instructions": malformed,
                "duplicate_form_locations": [
                    {"rva": key[0], "byte_length": key[1], "form_ids": ids}
                    for key, ids in sorted(duplicates.items())
                ],
            },
            frontiers={"isa": [{"id": "isa:location-inventory"}]},
        ))
    missing = sorted(instruction_locations - set(required_locations))
    if missing:
        blockers.append(_blocker(
            status="incomplete",
            category="isa",
            code="isa_reachable_location_missing",
            message="reachable machine-IR instructions lack qualified ISA form bindings",
            next_action="add every missing exact instruction location to ISA selection",
            details={
                "locations": [
                    {"rva": rva, "byte_length": length}
                    for rva, length in missing
                ]
            },
            frontiers={
                "isa": [
                    {"id": f"isa:location:{rva:x}:{length}"}
                    for rva, length in missing
                ]
            },
        ))
    extra = sorted(set(required_locations) - instruction_locations)
    if extra:
        blockers.append(_blocker(
            status="violated",
            category="isa",
            code="isa_location_not_reachable_instruction",
            message="ISA selection includes locations absent from reachable exact machine IR",
            next_action="regenerate the binary-specific ISA location inventory",
            details={
                "locations": [
                    {"rva": rva, "byte_length": length}
                    for rva, length in extra
                ]
            },
            frontiers={"isa": [{"id": "isa:location-inventory"}]},
        ))


def _bundle_blockers(
    bundle: AuthorityBundle,
    *,
    upstream_blockers: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    intrinsic: dict[str, list[str]] = {}
    records = {record.content_id: record for record in bundle.records}
    upstream_by_code: dict[str, list[str]] = {}
    for blocker in upstream_blockers:
        details = blocker.get("details")
        code = details.get("code") if isinstance(details, Mapping) else None
        blocker_id = blocker.get("id")
        if isinstance(code, str) and isinstance(blocker_id, str):
            upstream_by_code.setdefault(code, []).append(blocker_id)
    shared_missing: dict[tuple[str, str], str] = {}

    def issue_dependencies(
        issue: EvidenceIssue,
        extra_dependencies: Sequence[str] = (),
    ) -> list[str]:
        direct = upstream_by_code.get(issue.code, ())
        aliases = {
            "interprocedural_replay_invalid": (
                "interprocedural_replay_incomplete",
            ),
            "exceptional_record_missing": ("exception_report_incomplete",),
            "isa_kernel_selection_missing": (
                "isa_selection_authority_missing",
                "isa_selection_not_qualified",
            ),
        }
        aliased = [
            blocker_id
            for code in aliases.get(issue.code, ())
            for blocker_id in upstream_by_code.get(code, ())
        ]
        result = sorted(set([*direct, *aliased, *extra_dependencies]))
        if result or issue.code != "mutable_slot_invariant_missing":
            return result
        key = (issue.code, issue.detail)
        blocker_id = shared_missing.get(key)
        if blocker_id is None:
            primary = _blocker(
                status="incomplete",
                category="global_slot_invariant",
                code=issue.code,
                message=issue.detail,
                next_action=(
                    "classify every reachable write, prove dominated initialization, "
                    "and emit the exact bounded slot invariant"
                ),
                details={"slot_requirement": issue.detail},
            )
            blockers.append(primary)
            blocker_id = str(primary["id"])
            shared_missing[key] = blocker_id
        return [blocker_id]

    def emit_intrinsic(
        record: AuthorityRecord,
        *,
        extra_by_issue: Mapping[str, Sequence[str]] | None = None,
    ) -> list[str]:
        local: list[str] = []
        for issue in record.issues:
            blocked_by = issue_dependencies(
                issue,
                () if extra_by_issue is None else extra_by_issue.get(issue.code, ()),
            )
            blocker = _blocker(
                status=(
                    "incomplete"
                    if issue.kind is EvidenceIssueKind.MISSING
                    else "violated"
                ),
                category=record.KIND,
                code=issue.code,
                message=issue.detail,
                next_action=f"repair the exact {record.KIND} evidence",
                blocked_by=blocked_by,
                details={"authority_content_id": record.content_id},
                frontiers=_record_frontiers(record),
            )
            blockers.append(blocker)
            local.append(str(blocker["id"]))
        if record.status is not AuthorityStatus.COMPLETE and not local:
            blocker = _blocker(
                status=(
                    "violated"
                    if record.status is AuthorityStatus.VIOLATED
                    else "incomplete"
                ),
                category=record.KIND,
                code=f"{record.KIND}_not_closed",
                message=f"the {record.KIND} record is not complete",
                next_action=f"complete the exact {record.KIND} alternatives and bindings",
                details={"authority_content_id": record.content_id},
                frontiers=_record_frontiers(record),
            )
            blockers.append(blocker)
            local.append(str(blocker["id"]))
        return local

    indirect_by_fact_id: dict[str, list[str]] = {}
    indirect_by_site: dict[tuple[str, int], list[str]] = {}
    for record in bundle.records:
        if not isinstance(record, IndirectExitCertificate):
            continue
        local = emit_intrinsic(record)
        intrinsic[record.content_id] = local
        indirect_by_fact_id[record.analysis_fact_id] = local
        indirect_by_site[
            (record.exit_site.unit.unit_id, record.exit_site.event_index)
        ] = local

    summary_blockers, summary_dependency_ids = _call_summary_scc_blockers(
        records=bundle.records,
        indirect_by_fact_id=indirect_by_fact_id,
    )
    blockers.extend(summary_blockers)

    for record in bundle.records:
        if isinstance(record, IndirectExitCertificate):
            continue
        extra_by_issue: dict[str, Sequence[str]] = {}
        if isinstance(record, CallFrameSummary):
            site = (record.call_site.unit.unit_id, record.call_site.event_index)
            extra_by_issue["call_target_missing"] = indirect_by_site.get(site, ())
            summary_ids = {
                f"call-summary:{value.get('callee', {}).get('unit_id')}"
                for value in _alternative_mappings(record.alternatives)
                if isinstance(value.get("callee"), Mapping)
                and isinstance(value["callee"].get("unit_id"), str)
            }
            extra_by_issue["call_summary_missing"] = sorted({
                summary_dependency_ids[summary_id]
                for summary_id in summary_ids
                if summary_id in summary_dependency_ids
            })
        intrinsic[record.content_id] = emit_intrinsic(
            record,
            extra_by_issue=extra_by_issue,
        )

    representative: dict[str, list[str]] = {}
    dependency_edges = {
        (dependency.content_id, content_id)
        for content_id, record in records.items()
        for dependency in record.dependencies
        if dependency.content_id in records
    }
    decomposition = decompose_scc(records.keys(), dependency_edges)
    cycle_reported = False
    for component_index, members in enumerate(decomposition.components):
        inherited: set[str] = set()
        for predecessor in decomposition.predecessors(component_index):
            for dependency_content_id in decomposition.components[predecessor]:
                inherited.update(representative[dependency_content_id])

        missing_by_record: dict[str, list[str]] = {}
        for content_id in members:
            missing_ids = sorted({
                dependency.content_id
                for dependency in records[content_id].dependencies
                if dependency.content_id not in records
            })
            if not missing_ids:
                continue
            missing_by_record[content_id] = missing_ids
            missing = _blocker(
                status="incomplete",
                category="authority_dependency",
                code="authority_dependency_missing",
                message="an authority record references absent evidence",
                next_action="supply the exact dependency records",
                details={
                    "authority_content_id": content_id,
                    "missing_content_ids": missing_ids,
                },
            )
            blockers.append(missing)
            inherited.add(str(missing["id"]))

        cyclic = len(members) > 1 or any(
            (content_id, content_id) in dependency_edges
            for content_id in members
        )
        if cyclic:
            cycle_reported = True
            cycle = _blocker(
                status="violated",
                category="authority_dependency",
                code="authority_dependency_cycle",
                message="authority records contain a cyclic evidence dependency",
                next_action="replace the cycle with one checked SCC certificate",
                blocked_by=sorted(inherited),
                details={"authority_content_ids": list(members)},
            )
            blockers.append(cycle)
            cycle_id = str(cycle["id"])
            for content_id in members:
                representative[content_id] = sorted(set([
                    *intrinsic[content_id],
                    cycle_id,
                ]))
            continue

        content_id = members[0]
        record = records[content_id]
        dependency_ids = sorted(inherited)
        if dependency_ids:
            consequence = _blocker(
                status=(
                    "violated"
                    if record.status is AuthorityStatus.VIOLATED
                    else "incomplete"
                ),
                category="authority_dependency",
                code="authority_record_blocked",
                message=f"the {record.KIND} record is blocked by prerequisite evidence",
                next_action="resolve its primary dependency blockers",
                blocked_by=dependency_ids,
                details={"authority_content_id": content_id},
            )
            blockers.append(consequence)
            representative[content_id] = sorted(set([
                *intrinsic[content_id],
                str(consequence["id"]),
            ]))
        else:
            representative[content_id] = list(intrinsic[content_id])

    explained = {"record_incomplete", "record_violated"}
    if cycle_reported:
        explained.add("dependency_cycle")
    for diagnostic in bundle.diagnostics:
        if diagnostic in explained and any(representative.values()):
            continue
        blockers.append(_blocker(
            status=(
                "violated"
                if diagnostic in {
                    "binary_binding_conflict",
                    "contradictory_subject_claims",
                    "dependency_cycle",
                    "unrooted_record",
                }
                else "incomplete"
            ),
            category="authority_bundle",
            code=diagnostic,
            message=f"the v2 authority bundle reports {diagnostic}",
            next_action="repair the exact authority graph and replay it",
            details={"bundle_content_id": bundle.content_id},
        ))
    return _deduplicate_blockers(blockers)


def _record_frontiers(record: AuthorityRecord) -> dict[str, list[dict[str, Any]]]:
    if isinstance(record, CheckedExternalSite):
        return {"environment": [{
            "id": f"environment:{record.site.unit.unit_id}:{record.site.event_index}"
        }]}
    if isinstance(record, (CallFrameSummary, IndirectExitCertificate)):
        binding = record.call_site if isinstance(record, CallFrameSummary) else record.exit_site
        return {"scc": [{"id": f"scc:{binding.unit.unit_id}", "members": [binding.unit.unit_id]}]}
    if isinstance(record, ValueFact) and record.location.startswith("isa_"):
        return {"isa": [{"id": f"isa:{record.location}"}]}
    return {}


def _alternative_mappings(
    alternatives: FiniteAlternatives | None,
) -> tuple[Mapping[str, Any], ...]:
    if alternatives is None:
        return ()
    return tuple(
        value
        for item in alternatives.values
        if isinstance((value := item.to_value()), Mapping)
    )


def _call_summary_scc_blockers(
    *,
    records: Sequence[AuthorityRecord],
    indirect_by_fact_id: Mapping[str, Sequence[str]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Collapse repeated incomplete call-site views into dependency SCC tasks."""

    node_dependencies: dict[str, set[str]] = {}
    node_blocker_codes: dict[str, set[str]] = {}
    for record in records:
        if not isinstance(record, CallFrameSummary):
            continue
        for alternative in _alternative_mappings(record.alternatives):
            if alternative.get("status") == "complete":
                continue
            callee = alternative.get("callee")
            unit_id = callee.get("unit_id") if isinstance(callee, Mapping) else None
            if not isinstance(unit_id, str):
                continue
            node_id = f"call-summary:{unit_id}"
            node_dependencies.setdefault(node_id, set()).update(
                value
                for value in alternative.get("target_dependencies", ())
                if isinstance(value, str)
            )
            node_blocker_codes.setdefault(node_id, set()).update(
                value
                for value in alternative.get("blocker_codes", ())
                if isinstance(value, str)
            )

    nodes = set(node_dependencies)
    dependency_edges = {
        (dependency, node_id)
        for node_id, dependencies in node_dependencies.items()
        for dependency in dependencies
        if dependency.startswith("call-summary:") and dependency in nodes
    }
    if not nodes:
        return [], {}

    decomposition = decompose_scc(nodes, dependency_edges)
    component_blocker_ids: dict[int, str] = {}
    node_blocker_ids: dict[str, str] = {}
    blockers: list[dict[str, Any]] = []
    for component_index, members in enumerate(decomposition.components):
        blocked_by = {
            component_blocker_ids[source]
            for source in decomposition.predecessors(component_index)
        }
        unresolved_dependencies: set[str] = set()
        blocker_codes: set[str] = set()
        for node_id in members:
            blocker_codes.update(node_blocker_codes.get(node_id, ()))
            for dependency in node_dependencies.get(node_id, ()):
                if dependency.startswith("indirect-exit:"):
                    matched = indirect_by_fact_id.get(dependency)
                    if matched:
                        blocked_by.update(matched)
                    else:
                        unresolved_dependencies.add(dependency)
                elif dependency.startswith("call-summary:"):
                    if dependency not in nodes:
                        unresolved_dependencies.add(dependency)
                else:
                    unresolved_dependencies.add(dependency)
        blocker = _blocker(
            status="incomplete",
            category="call_summary_scc",
            code="call_summary_scc_incomplete",
            message=(
                "an interprocedural call-summary SCC has incomplete frame facts"
            ),
            next_action=(
                "repair its unresolved target or local frame family and replay the SCC"
            ),
            blocked_by=sorted(blocked_by),
            details={
                "analysis_fact_ids": list(members),
                "blocker_codes": sorted(blocker_codes),
                "unresolved_dependency_ids": sorted(unresolved_dependencies),
            },
            frontiers={
                "scc": [{
                    "id": "scc:call-summary:" + hashlib.sha256(
                        canonical_json_bytes(list(members))
                    ).hexdigest()[:20],
                    "members": list(members),
                }]
            },
        )
        blockers.append(blocker)
        blocker_id = str(blocker["id"])
        component_blocker_ids[component_index] = blocker_id
        for node_id in members:
            node_blocker_ids[node_id] = blocker_id
    return blockers, node_blocker_ids


def _gate_status(
    bundle: AuthorityBundle | None,
    replay_status: str,
    diagnostics: Mapping[str, Any],
) -> str:
    statuses = {
        replay_status,
        str(diagnostics.get("status")),
        "incomplete" if bundle is None else bundle.status.value,
    }
    if "violated" in statuses:
        return "violated"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


def _mapping_input(
    value: Any,
    *,
    blockers: list[dict[str, Any]],
    category: str,
    missing_code: str,
    corrupt_code: str,
) -> Mapping[str, Any] | None:
    if value is None:
        blockers.append(_blocker(
            status="incomplete",
            category=category,
            code=missing_code,
            message=f"{category.replace('_', ' ')} evidence is missing",
            next_action=f"regenerate {category.replace('_', ' ')} evidence",
        ))
        return None
    if not isinstance(value, Mapping):
        blockers.append(_blocker(
            status="violated",
            category=category,
            code=corrupt_code,
            message=f"{category.replace('_', ' ')} evidence is malformed",
            next_action=f"regenerate {category.replace('_', ' ')} evidence",
        ))
        return None
    try:
        return _canonical_value(value, context=category)
    except StaticHybridAuthorityV2Error as exc:
        blockers.append(_blocker(
            status="violated",
            category=category,
            code=corrupt_code,
            message=f"{category.replace('_', ' ')} evidence is not canonical JSON",
            next_action=f"regenerate {category.replace('_', ' ')} evidence",
            details={"reason": str(exc)},
        ))
        return None


def _blocker(
    *,
    status: str,
    category: str,
    code: str,
    message: str,
    next_action: str,
    blocked_by: Sequence[str] = (),
    details: Mapping[str, Any] | None = None,
    frontiers: Mapping[str, Sequence[Mapping[str, Any] | str]] | None = None,
) -> dict[str, Any]:
    return make_blocker_record(
        status=status,
        category=category,
        message=message,
        next_action=next_action,
        blocked_by=blocked_by,
        details={"code": code, **(dict(details) if details else {})},
        frontiers=frontiers,
    )


def _exception_blocker(
    status: str, code: str, index: int, message: str
) -> dict[str, Any]:
    return _blocker(
        status=status,
        category="exceptional_control",
        code=code,
        message=message,
        next_action="replay the SCC exception certificate against exact machine IR",
        details={"report_index": index},
        frontiers={"scc": [{"id": f"scc:exception-report:{index}"}]},
    )


def _issue_status(issues: Sequence[Any]) -> str:
    statuses = {
        row.get("status") for row in issues if isinstance(row, Mapping)
    }
    if "violated" in statuses:
        return "violated"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


def _scc_frontier(fixed: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    roots = fixed.get("recursive_summary_roots")
    members = sorted(str(item) for item in roots) if isinstance(roots, list) else []
    return {
        "scc": [{"id": "scc:interprocedural", "members": members}]
    }


def _legacy_diagnostics(value: Any) -> Any:
    if value is None:
        return None
    try:
        return _canonical_value(value, context="legacy v1 diagnostics")
    except StaticHybridAuthorityV2Error:
        return {
            "status": "discarded",
            "reason": "legacy diagnostics are not canonical JSON",
        }


def _canonical_value(value: Any, *, context: str) -> Any:
    try:
        return json.loads(canonical_json_bytes(value).decode("ascii"))
    except (AuthorityDataError, TypeError, ValueError) as exc:
        raise StaticHybridAuthorityV2Error(
            f"{context} is not canonical JSON data: {exc}"
        ) from exc


def _safe_json(value: Any) -> Any:
    try:
        return _canonical_value(value, context="diagnostic value")
    except StaticHybridAuthorityV2Error:
        return repr(value)


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _DIGEST_CHARS
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _deduplicate_blockers(
    blockers: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_id = {str(row["id"]): copy.deepcopy(dict(row)) for row in blockers}
    return [by_id[key] for key in sorted(by_id)]


__all__ = [
    "STATIC_HYBRID_AUTHORITY_V2_FORMAT",
    "StaticHybridAuthorityV2Error",
    "build_static_hybrid_authority_v2",
    "validate_static_hybrid_authority_v2",
]
