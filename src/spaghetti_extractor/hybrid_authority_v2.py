"""Immutable, content-addressed authority evidence for static hybrid closure.

This module deliberately has no integration with the v1 completeness checker.
It defines the v2 data boundary only: exact binary/unit/event identities,
immutable finite evidence alternatives, explicit dependencies, strict parsers,
and a closed bundle whose authorization bit is derived from those inputs.

Missing evidence is representable and derives ``incomplete``. Contradictory or
semantically corrupt evidence derives ``violated``. Structurally malformed JSON
is rejected instead of being normalized into a different record. No v1 format
is accepted by these parsers, so a v1 artifact can never authorize a v2 bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Any, ClassVar, Mapping, Sequence, TypeAlias

from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    CanonicalJson,
    EventBinding,
    IndirectExitBinding,
    ImageSpanBinding,
    ScopeBinding,
    UnitBinding,
    _array,
    _binding_unit,
    _json_value,
    _object,
    _parse_scope,
    _scope_payload,
    _sha256,
    _text,
    _token,
    _uint,
    canonical_json,
    canonical_json_bytes,
    parse_canonical_json,
)
from .authority_record_core_v2 import (
    HYBRID_AUTHORITY_SCHEMA_VERSION,
    MAX_FINITE_ALTERNATIVES,
    AuthorityDependency,
    AuthorityRecordMixin as _AuthorityRecordMixin,
    AuthorityStatus,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    ProfileBinding,
    _check_dependencies,
    _check_issues,
    _checked_content_id,
    _content_id,
    _content_id_kind,
    _derive_status,
    _finish_record_parse,
    _has_undeclared_references,
    _parse_record_parts,
    _record_core,
)
from .authority_dependencies_v2 import (
    CALL_SUMMARY_FAMILY_NODE_PREFIX,
    call_summary_family_node_id,
)
from .entry_state_contract_v2 import (
    ENTRY_STATE_CONTRACT_FORMAT,
    EntryStateContract,
)
from .global_slot_contract_v2 import (
    GLOBAL_SLOT_INVARIANT_FORMAT,
    GlobalSlotInvariant,
)


VALUE_FACT_FORMAT = "spaghetti-extractor-value-fact-v2"
CALL_FRAME_SUMMARY_FORMAT = "spaghetti-extractor-call-frame-summary-v2"
INDIRECT_EXIT_CERTIFICATE_FORMAT = (
    "spaghetti-extractor-indirect-exit-certificate-v2"
)
CHECKED_EXTERNAL_SITE_FORMAT = "spaghetti-extractor-checked-external-site-v2"
AUTHORITY_BUNDLE_FORMAT = "spaghetti-extractor-hybrid-authority-bundle-v2"


def _parse_call_summary_family_node_id(
    value: object,
) -> tuple[str, str, str | None] | None:
    if not isinstance(value, str) or not value.startswith(
        CALL_SUMMARY_FAMILY_NODE_PREFIX
    ):
        return None
    try:
        payload = parse_canonical_json(
            value.removeprefix(CALL_SUMMARY_FAMILY_NODE_PREFIX)
        )
    except AuthorityDataError:
        return None
    if not isinstance(payload, list) or len(payload) != 3:
        return None
    try:
        canonical = call_summary_family_node_id(
            payload[0], payload[1], payload[2]
        )
    except ValueError:
        return None
    return tuple(payload) if canonical == value else None

@dataclass(frozen=True)
class ValueFact(_AuthorityRecordMixin):
    binding: ScopeBinding
    location: str
    width_bits: int
    alternatives: FiniteAlternatives | None
    dependencies: tuple[AuthorityDependency, ...] = ()
    issues: tuple[EvidenceIssue, ...] = ()

    KIND: ClassVar[str] = "value_fact"
    FORMAT: ClassVar[str] = VALUE_FACT_FORMAT

    def __post_init__(self) -> None:
        _scope_payload(self.binding)
        _text(self.location, "value location", maximum=256)
        width = _uint(self.width_bits, "value width", maximum=0x10000)
        if width == 0:
            raise AuthorityDataError("value width must be positive")
        if self.alternatives is not None and not isinstance(
            self.alternatives, FiniteAlternatives
        ):
            raise AuthorityDataError("value alternatives are malformed")
        _check_dependencies(self.dependencies)
        _check_issues(self.issues)

    @property
    def status(self) -> AuthorityStatus:
        return _derive_status(
            missing=(
                self.alternatives is None
                or _has_undeclared_references(
                    self.alternatives, self.dependencies
                )
            ),
            violated=False,
            issues=self.issues,
        )

    def _core_payload(self) -> dict[str, Any]:
        return _record_core(
            format_name=self.FORMAT,
            status=self.status,
            binding=_scope_payload(self.binding),
            dependencies=self.dependencies,
            alternatives=self.alternatives,
            issues=self.issues,
            fields={"location": self.location, "width_bits": self.width_bits},
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "ValueFact":
        parts = _parse_record_parts(
            value, format_name=cls.FORMAT, fields={"location", "width_bits"}
        )
        result = cls(
            binding=_parse_scope(parts.binding),
            location=_text(value["location"], "value location", maximum=256),
            width_bits=_uint(value["width_bits"], "value width", maximum=0x10000),
            alternatives=parts.alternatives,
            dependencies=parts.dependencies,
            issues=parts.issues,
        )
        _finish_record_parse(result, value)
        return result


@dataclass(frozen=True)
class CallFrameSummary(_AuthorityRecordMixin):
    call_site: EventBinding
    analysis_fact_id: str
    callee: UnitBinding | None
    abi: str
    alternatives: FiniteAlternatives | None
    dependencies: tuple[AuthorityDependency, ...] = ()
    issues: tuple[EvidenceIssue, ...] = ()

    KIND: ClassVar[str] = "call_frame_summary"
    FORMAT: ClassVar[str] = CALL_FRAME_SUMMARY_FORMAT

    def __post_init__(self) -> None:
        if not isinstance(self.call_site, EventBinding):
            raise AuthorityDataError("call frame requires an exact event binding")
        _text(self.analysis_fact_id, "call-frame analysis fact ID", maximum=512)
        if self.callee is not None and not isinstance(self.callee, UnitBinding):
            raise AuthorityDataError("call-frame callee binding is malformed")
        _text(self.abi, "call-frame ABI", maximum=128)
        if self.alternatives is not None and not isinstance(
            self.alternatives, FiniteAlternatives
        ):
            raise AuthorityDataError("call-frame alternatives are malformed")
        _check_dependencies(self.dependencies)
        _check_issues(self.issues)

    @property
    def status(self) -> AuthorityStatus:
        family_scope = _parse_call_summary_family_node_id(self.analysis_fact_id)
        malformed_family_scope = self.analysis_fact_id.startswith(
            CALL_SUMMARY_FAMILY_NODE_PREFIX
        ) and (
            family_scope is None
            or self.callee is None
            or self.callee.unit_id != family_scope[0]
        )
        corrupt_alternative = self.alternatives is not None and any(
            _call_frame_alternative_corrupt(
                value.to_value(), source=self.call_site.unit
            )
            for value in self.alternatives.values
        )
        mismatched_callee = (
            self.callee is not None
            and self.alternatives is not None
            and any(
                _call_frame_alternative_callee(value.to_value()) != self.callee
                for value in self.alternatives.values
            )
        )
        corrupt_family_alternative = (
            family_scope is not None
            and self.callee is not None
            and self.alternatives is not None
            and (
                self.alternatives.maximum != 1
                or len(self.alternatives.values) != 1
                or any(
                    _call_frame_family_alternative_corrupt(
                        value.to_value(),
                        callee=self.callee,
                        family=family_scope[1],
                        subject=family_scope[2],
                    )
                    for value in self.alternatives.values
                )
            )
        )
        incomplete_alternative = self.alternatives is not None and any(
            not _call_frame_alternative_complete(value.to_value())
            for value in self.alternatives.values
        )
        contradictory_binding = self.callee is not None and (
            self.callee.binary != self.call_site.unit.binary
        )
        wrong_event = self.call_site.event_kind not in {
            "internal_call",
            "indirect_call",
            "external_call",
        }
        return _derive_status(
            missing=(
                self.alternatives is None
                or incomplete_alternative
                or _has_undeclared_references(
                    self.alternatives, self.dependencies
                )
            ),
            violated=(
                corrupt_alternative
                or mismatched_callee
                or malformed_family_scope
                or corrupt_family_alternative
                or contradictory_binding
                or wrong_event
            ),
            issues=self.issues,
        )

    def _core_payload(self) -> dict[str, Any]:
        binding = {
            "call_site": self.call_site.to_payload(),
            "callee": None if self.callee is None else self.callee.to_payload(),
        }
        return _record_core(
            format_name=self.FORMAT,
            status=self.status,
            binding=binding,
            dependencies=self.dependencies,
            alternatives=self.alternatives,
            issues=self.issues,
            fields={"abi": self.abi, "analysis_fact_id": self.analysis_fact_id},
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "CallFrameSummary":
        parts = _parse_record_parts(
            value,
            format_name=cls.FORMAT,
            fields={"abi", "analysis_fact_id"},
        )
        binding = _object(
            parts.binding, {"call_site", "callee"}, "call-frame binding"
        )
        result = cls(
            call_site=EventBinding.parse(binding["call_site"]),
            analysis_fact_id=_text(
                value["analysis_fact_id"],
                "call-frame analysis fact ID",
                maximum=512,
            ),
            callee=(
                None
                if binding["callee"] is None
                else UnitBinding.parse(binding["callee"])
            ),
            abi=_text(value["abi"], "call-frame ABI", maximum=128),
            alternatives=parts.alternatives,
            dependencies=parts.dependencies,
            issues=parts.issues,
        )
        _finish_record_parse(result, value)
        return result


def _call_frame_alternative_corrupt(
    value: Any, *, source: UnitBinding | None = None
) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "format",
        "status",
        "callee",
        "return_behavior",
        "stack_cleanup",
        "register_preservation",
        "result_origins",
        "memory_effects",
        "callback_effects",
        "world_effects",
        "target_dependencies",
        "blocker_codes",
    }:
        return True
    if value.get("format") != "spaghetti-extractor-call-frame-families-v2":
        return True
    try:
        target = UnitBinding.parse(value.get("callee"))
    except AuthorityDataError:
        return True
    if source is not None and target.binary != source.binary:
        return True
    if value.get("status") not in {"complete", "incomplete", "violated"}:
        return True
    for family in (
        "return_behavior",
        "stack_cleanup",
        "register_preservation",
        "result_origins",
        "memory_effects",
        "callback_effects",
        "world_effects",
    ):
        row = value.get(family)
        if (
            not isinstance(row, dict)
            or row.get("status")
            not in {"complete", "incomplete", "not_applicable", "violated"}
        ):
            return True
    return not all(
        isinstance(values, list)
        and all(isinstance(item, str) for item in values)
        for values in (
            value.get("target_dependencies"),
            value.get("blocker_codes"),
        )
    )


def _call_frame_alternative_complete(value: Any) -> bool:
    if _call_frame_alternative_corrupt(value) or value["status"] != "complete":
        return False
    return all(
        value[family]["status"] in {"complete", "not_applicable"}
        for family in (
            "return_behavior",
            "stack_cleanup",
            "register_preservation",
            "result_origins",
            "memory_effects",
            "callback_effects",
            "world_effects",
        )
    )


def _call_frame_alternative_callee(value: Any) -> UnitBinding | None:
    if not isinstance(value, dict):
        return None
    try:
        return UnitBinding.parse(value.get("callee"))
    except AuthorityDataError:
        return None


def _call_frame_family_alternative_corrupt(
    value: Any,
    *,
    callee: UnitBinding,
    family: str,
    subject: str | None,
) -> bool:
    if _call_frame_alternative_corrupt(value):
        return True
    assert isinstance(value, dict)
    if _call_frame_alternative_callee(value) != callee:
        return True

    selected = {
        "memory": "memory_effects",
        "register": "register_preservation",
        "result": "result_origins",
        "return": "return_behavior",
        "stack": "stack_cleanup",
    }[family]
    family_fields = (
        "return_behavior",
        "stack_cleanup",
        "register_preservation",
        "result_origins",
        "memory_effects",
        "callback_effects",
        "world_effects",
    )
    if any(
        value[field] != {"status": "not_applicable"}
        for field in family_fields
        if field != selected
    ):
        return True
    if value.get("target_dependencies") != []:
        return True

    projection = value[selected]
    if value["status"] == "complete" and projection.get("status") != "complete":
        return True
    if family == "register":
        return (
            set(projection) != {"status", "registers"}
            or projection.get("registers")
            != ([] if projection.get("status") != "complete" else [subject])
        )
    if family == "stack":
        delta = projection.get("stack_delta")
        return set(projection) != {"status", "stack_delta"} or (
            projection.get("status") == "complete"
            and (
                not isinstance(delta, int)
                or isinstance(delta, bool)
                or not 0 <= delta <= 0xFFFF_FFFF
            )
        )
    if family == "return":
        return projection.get("status") == "complete" and (
            set(projection) != {"status", "may_return", "may_not_return"}
            or not isinstance(projection.get("may_return"), bool)
            or not isinstance(projection.get("may_not_return"), bool)
        )
    if family == "result":
        if projection.get("status") != "complete":
            return set(projection) != {
                "status", "registers", "memory_locations"
            }
        registers = projection.get("registers")
        locations = projection.get("memory_locations")
        return (
            set(projection) != {"status", "registers", "memory_locations"}
            or not isinstance(registers, dict)
            or not isinstance(locations, list)
            or not (registers or locations)
        )
    return projection.get("status") not in {
        "complete", "incomplete", "violated"
    }


def internal_target(unit: UnitBinding) -> CanonicalJson:
    if not isinstance(unit, UnitBinding):
        raise AuthorityDataError("internal target requires a unit binding")
    return CanonicalJson.of({"kind": "internal_unit", "unit": unit.to_payload()})


def external_target(site_content_id: str) -> CanonicalJson:
    content_id = _checked_content_id(
        site_content_id, "external target content ID"
    )
    if _content_id_kind(content_id) != CheckedExternalSite.KIND:
        raise AuthorityDataError(
            "external target must identify a checked external-site record"
        )
    return CanonicalJson.of(
        {
            "kind": "external_site",
            "site_content_id": content_id,
        }
    )


def infeasible_target(reason: str) -> CanonicalJson:
    return CanonicalJson.of(
        {"kind": "infeasible", "reason": _text(reason, "infeasibility reason")}
    )


def _indirect_target_is_corrupt(value: CanonicalJson, source: EventBinding) -> bool:
    target = value.to_value()
    if not isinstance(target, dict):
        return True
    kind = target.get("kind")
    try:
        if kind == "internal_unit" and set(target) == {"kind", "unit"}:
            unit = UnitBinding.parse(target["unit"])
            return unit.binary != source.unit.binary
        if kind == "external_site" and set(target) == {"kind", "site_content_id"}:
            content_id = _checked_content_id(
                target["site_content_id"], "external target content ID"
            )
            return _content_id_kind(content_id) != CheckedExternalSite.KIND
        if kind == "infeasible" and set(target) == {"kind", "reason"}:
            _text(target["reason"], "infeasibility reason")
            return False
    except AuthorityDataError:
        return True
    return True


@dataclass(frozen=True)
class IndirectExitCertificate(_AuthorityRecordMixin):
    exit_site: EventBinding
    analysis_fact_id: str
    target_expression_sha256: str
    alternatives: FiniteAlternatives | None
    dependencies: tuple[AuthorityDependency, ...] = ()
    issues: tuple[EvidenceIssue, ...] = ()

    KIND: ClassVar[str] = "indirect_exit_certificate"
    FORMAT: ClassVar[str] = INDIRECT_EXIT_CERTIFICATE_FORMAT

    def __post_init__(self) -> None:
        if not isinstance(self.exit_site, EventBinding):
            raise AuthorityDataError("indirect exit requires an exact event binding")
        _text(self.analysis_fact_id, "indirect-exit analysis fact ID", maximum=512)
        _sha256(self.target_expression_sha256, "target-expression SHA-256")
        if self.alternatives is not None and not isinstance(
            self.alternatives, FiniteAlternatives
        ):
            raise AuthorityDataError("indirect-target alternatives are malformed")
        _check_dependencies(self.dependencies)
        _check_issues(self.issues)

    @property
    def status(self) -> AuthorityStatus:
        wrong_event = self.exit_site.event_kind not in {
            "indirect_call",
            "indirect_jump",
        }
        corrupt_target = self.alternatives is not None and any(
            _indirect_target_is_corrupt(value, self.exit_site)
            for value in self.alternatives.values
        )
        return _derive_status(
            missing=(
                self.alternatives is None
                or _has_undeclared_references(
                    self.alternatives, self.dependencies
                )
            ),
            violated=wrong_event or corrupt_target,
            issues=self.issues,
        )

    def _core_payload(self) -> dict[str, Any]:
        return _record_core(
            format_name=self.FORMAT,
            status=self.status,
            binding=self.exit_site.to_payload(),
            dependencies=self.dependencies,
            alternatives=self.alternatives,
            issues=self.issues,
            fields={
                "analysis_fact_id": self.analysis_fact_id,
                "target_expression_sha256": self.target_expression_sha256,
            },
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "IndirectExitCertificate":
        parts = _parse_record_parts(
            value,
            format_name=cls.FORMAT,
            fields={"analysis_fact_id", "target_expression_sha256"},
        )
        result = cls(
            exit_site=EventBinding.parse(parts.binding),
            analysis_fact_id=_text(
                value["analysis_fact_id"],
                "indirect-exit analysis fact ID",
                maximum=512,
            ),
            target_expression_sha256=_sha256(
                value["target_expression_sha256"], "target-expression SHA-256"
            ),
            alternatives=parts.alternatives,
            dependencies=parts.dependencies,
            issues=parts.issues,
        )
        _finish_record_parse(result, value)
        return result


@dataclass(frozen=True)
class CheckedExternalSite(_AuthorityRecordMixin):
    site: EventBinding
    profile: ProfileBinding | None
    transfer_kind: str
    alternatives: FiniteAlternatives | None
    target_alternative_index: int
    target_alternative_sha256: str | None
    dependencies: tuple[AuthorityDependency, ...] = ()
    issues: tuple[EvidenceIssue, ...] = ()

    KIND: ClassVar[str] = "checked_external_site"
    FORMAT: ClassVar[str] = CHECKED_EXTERNAL_SITE_FORMAT

    def __post_init__(self) -> None:
        if not isinstance(self.site, EventBinding):
            raise AuthorityDataError("external site requires an exact event binding")
        if self.profile is not None and not isinstance(self.profile, ProfileBinding):
            raise AuthorityDataError("external-site profile binding is malformed")
        if self.transfer_kind not in {"call", "jump"}:
            raise AuthorityDataError("external-site transfer kind is unsupported")
        _uint(
            self.target_alternative_index, "external target alternative index"
        )
        if self.target_alternative_sha256 is not None:
            _sha256(
                self.target_alternative_sha256,
                "external target alternative SHA-256",
            )
        if self.alternatives is not None and not isinstance(
            self.alternatives, FiniteAlternatives
        ):
            raise AuthorityDataError("external-site alternatives are malformed")
        _check_dependencies(self.dependencies)
        _check_issues(self.issues)

    @property
    def status(self) -> AuthorityStatus:
        allowed_events = {
            "external_call",
            "external_jump",
            "indirect_call",
            "indirect_jump",
        }
        wrong_event = self.site.event_kind not in allowed_events or (
            self.transfer_kind == "call"
            and self.site.event_kind not in {"external_call", "indirect_call"}
        ) or (
            self.transfer_kind == "jump"
            and self.site.event_kind not in {"external_jump", "indirect_jump"}
        )
        corrupt_contract = self.alternatives is not None and any(
            not isinstance(value.to_value(), dict) or not value.to_value()
            for value in self.alternatives.values
        )
        if self.alternatives is not None and len(self.alternatives.values) != 1:
            corrupt_contract = True
        return _derive_status(
            missing=(
                self.profile is None
                or self.alternatives is None
                or self.target_alternative_sha256 is None
                or _has_undeclared_references(
                    self.alternatives, self.dependencies
                )
            ),
            violated=wrong_event or corrupt_contract,
            issues=self.issues,
        )

    def _core_payload(self) -> dict[str, Any]:
        binding = {
            "site": self.site.to_payload(),
            "profile": None if self.profile is None else self.profile.to_payload(),
        }
        return _record_core(
            format_name=self.FORMAT,
            status=self.status,
            binding=binding,
            dependencies=self.dependencies,
            alternatives=self.alternatives,
            issues=self.issues,
            fields={
                "transfer_kind": self.transfer_kind,
                "target_alternative_index": self.target_alternative_index,
                "target_alternative_sha256": self.target_alternative_sha256,
            },
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "CheckedExternalSite":
        parts = _parse_record_parts(
            value,
            format_name=cls.FORMAT,
            fields={
                "transfer_kind",
                "target_alternative_index",
                "target_alternative_sha256",
            },
        )
        binding = _object(
            parts.binding, {"site", "profile"}, "external-site binding"
        )
        transfer_kind = value["transfer_kind"]
        if transfer_kind not in {"call", "jump"}:
            raise AuthorityDataError("external-site transfer kind is unsupported")
        result = cls(
            site=EventBinding.parse(binding["site"]),
            profile=(
                None
                if binding["profile"] is None
                else ProfileBinding.parse(binding["profile"])
            ),
            transfer_kind=transfer_kind,
            alternatives=parts.alternatives,
            target_alternative_index=_uint(
                value["target_alternative_index"],
                "external target alternative index",
            ),
            target_alternative_sha256=(
                None
                if value["target_alternative_sha256"] is None
                else _sha256(
                    value["target_alternative_sha256"],
                    "external target alternative SHA-256",
                )
            ),
            dependencies=parts.dependencies,
            issues=parts.issues,
        )
        _finish_record_parse(result, value)
        return result


AuthorityRecord: TypeAlias = (
    EntryStateContract
    | ValueFact
    | GlobalSlotInvariant
    | CallFrameSummary
    | IndirectExitCertificate
    | CheckedExternalSite
)

_RECORD_PARSERS = {
    ENTRY_STATE_CONTRACT_FORMAT: EntryStateContract.parse,
    VALUE_FACT_FORMAT: ValueFact.parse,
    GLOBAL_SLOT_INVARIANT_FORMAT: GlobalSlotInvariant.parse,
    CALL_FRAME_SUMMARY_FORMAT: CallFrameSummary.parse,
    INDIRECT_EXIT_CERTIFICATE_FORMAT: IndirectExitCertificate.parse,
    CHECKED_EXTERNAL_SITE_FORMAT: CheckedExternalSite.parse,
}


def parse_authority_record(value: Mapping[str, Any]) -> AuthorityRecord:
    if not isinstance(value, Mapping):
        raise AuthorityDataError("authority record must be an object")
    format_name = value.get("format")
    parser = _RECORD_PARSERS.get(format_name)
    if parser is None:
        if isinstance(format_name, str) and format_name.endswith("-v1"):
            raise AuthorityDataError("v1 authority data is not authorizing")
        raise AuthorityDataError("unsupported authority record format")
    return parser(value)


def parse_authority_record_json(data: str | bytes) -> AuthorityRecord:
    value = parse_canonical_json(data)
    if not isinstance(value, Mapping):
        raise AuthorityDataError("authority record JSON must contain an object")
    return parse_authority_record(value)


def _record_binary(record: AuthorityRecord) -> BinaryBinding:
    if isinstance(record, EntryStateContract):
        return record.entry.binary
    if isinstance(record, ValueFact):
        return _binding_unit(record.binding).binary
    if isinstance(record, GlobalSlotInvariant):
        return (
            record.binding.binary
            if isinstance(record.binding, ImageSpanBinding)
            else _binding_unit(record.binding).binary
        )
    if isinstance(record, CallFrameSummary):
        return record.call_site.unit.binary
    if isinstance(record, IndirectExitCertificate):
        return record.exit_site.unit.binary
    if isinstance(record, CheckedExternalSite):
        return record.site.unit.binary
    raise AuthorityDataError("unsupported authority record type")


def _record_subject(record: AuthorityRecord) -> bytes:
    if isinstance(record, EntryStateContract):
        value = {
            "kind": record.KIND,
            "binding": record.entry.to_payload(),
            "entry_kind": record.entry_kind,
            "entry_event": (
                None
                if record.entry_event is None
                else record.entry_event.to_payload()
            ),
        }
    elif isinstance(record, ValueFact):
        value = {
            "kind": record.KIND,
            "binding": _scope_payload(record.binding),
            "location": record.location,
            "width_bits": record.width_bits,
        }
    elif isinstance(record, GlobalSlotInvariant):
        value = {
            "kind": record.KIND,
            "binding": _scope_payload(record.binding),
            "slot_rva": record.slot_rva,
            "width_bytes": record.width_bytes,
            "invariant_kind": record.invariant_kind,
        }
    elif isinstance(record, CallFrameSummary):
        value = {"kind": record.KIND, "binding": record.call_site.to_payload()}
        family_scope = _parse_call_summary_family_node_id(record.analysis_fact_id)
        if family_scope is not None:
            value["family_scope"] = {
                "target_unit_id": family_scope[0],
                "family": family_scope[1],
                "subject": family_scope[2],
            }
    elif isinstance(record, IndirectExitCertificate):
        value = {"kind": record.KIND, "binding": record.exit_site.to_payload()}
    elif isinstance(record, CheckedExternalSite):
        value = {
            "kind": record.KIND,
            "binding": record.site.to_payload(),
            "target_alternative_index": record.target_alternative_index,
            "target_alternative_sha256": record.target_alternative_sha256,
        }
    else:
        raise AuthorityDataError("unsupported authority record type")
    return canonical_json_bytes(value)


def _bundle_state(
    *,
    binary: BinaryBinding,
    records: tuple[AuthorityRecord, ...],
    required_content_ids: tuple[str, ...],
) -> tuple[AuthorityStatus, tuple[str, ...]]:
    by_id = {record.content_id: record for record in records}
    violations: set[str] = set()
    missing: set[str] = set()

    if not records:
        missing.add("record_inventory_missing")
    if not required_content_ids:
        missing.add("authority_roots_missing")
    if any(_record_binary(record) != binary for record in records):
        violations.add("binary_binding_conflict")
    if any(record.status is AuthorityStatus.VIOLATED for record in records):
        violations.add("record_violated")
    if any(record.status is AuthorityStatus.INCOMPLETE for record in records):
        missing.add("record_incomplete")

    subjects: dict[bytes, str] = {}
    for record in records:
        subject = _record_subject(record)
        previous = subjects.get(subject)
        if previous is not None and previous != record.content_id:
            violations.add("contradictory_subject_claims")
        subjects[subject] = record.content_id

    roots = set(required_content_ids)
    missing_roots = roots - by_id.keys()
    if missing_roots:
        missing.add("required_record_missing")

    visited: set[str] = set()
    active: set[str] = set()

    def visit(content_id: str) -> None:
        record = by_id.get(content_id)
        if record is None:
            missing.add("dependency_missing")
            return
        if content_id in active:
            violations.add("dependency_cycle")
            return
        if content_id in visited:
            return
        active.add(content_id)
        for dependency in record.dependencies:
            visit(dependency.content_id)
        active.remove(content_id)
        visited.add(content_id)

    for root in sorted(roots):
        visit(root)
    if set(by_id) - visited:
        violations.add("unrooted_record")

    diagnostics = tuple(sorted(violations | missing))
    if violations:
        return AuthorityStatus.VIOLATED, diagnostics
    if missing:
        return AuthorityStatus.INCOMPLETE, diagnostics
    return AuthorityStatus.COMPLETE, diagnostics


@dataclass(frozen=True)
class AuthorityBundle:
    """One exact, dependency-closed v2 authority graph."""

    binary: BinaryBinding
    records: tuple[AuthorityRecord, ...]
    required_content_ids: tuple[str, ...]

    FORMAT: ClassVar[str] = AUTHORITY_BUNDLE_FORMAT

    def __post_init__(self) -> None:
        if not isinstance(self.binary, BinaryBinding):
            raise AuthorityDataError("authority bundle requires a binary binding")
        if not isinstance(self.records, tuple) or any(
            not isinstance(
                item,
                (
                    EntryStateContract,
                    ValueFact,
                    GlobalSlotInvariant,
                    CallFrameSummary,
                    IndirectExitCertificate,
                    CheckedExternalSite,
                ),
            )
            for item in self.records
        ):
            raise AuthorityDataError("authority records must be an immutable typed tuple")
        if self.records != tuple(sorted(self.records, key=lambda item: item.content_id)):
            raise AuthorityDataError("authority records must be sorted by content ID")
        record_ids = tuple(record.content_id for record in self.records)
        if len(record_ids) != len(set(record_ids)):
            raise AuthorityDataError("authority bundle contains duplicate records")
        if not isinstance(self.required_content_ids, tuple):
            raise AuthorityDataError("required content IDs must be an immutable tuple")
        for content_id in self.required_content_ids:
            _checked_content_id(content_id, "required content ID")
        if self.required_content_ids != tuple(sorted(set(self.required_content_ids))):
            raise AuthorityDataError("required content IDs must be sorted and unique")

    @classmethod
    def of(
        cls,
        *,
        binary: BinaryBinding,
        records: Sequence[AuthorityRecord],
        required_content_ids: Sequence[str],
    ) -> "AuthorityBundle":
        return cls(
            binary=binary,
            records=tuple(sorted(records, key=lambda item: item.content_id)),
            required_content_ids=tuple(sorted(set(required_content_ids))),
        )

    @cached_property
    def _state(self) -> tuple[AuthorityStatus, tuple[str, ...]]:
        return _bundle_state(
            binary=self.binary,
            records=self.records,
            required_content_ids=self.required_content_ids,
        )

    @property
    def status(self) -> AuthorityStatus:
        return self._state[0]

    @property
    def diagnostics(self) -> tuple[str, ...]:
        return self._state[1]

    @property
    def authorizes(self) -> bool:
        return self.status is AuthorityStatus.COMPLETE

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": self.FORMAT,
            "schema_version": HYBRID_AUTHORITY_SCHEMA_VERSION,
            "status": self.status.value,
            "authorizes": self.authorizes,
            "v1_authorizes": False,
            "binary": self.binary.to_payload(),
            "required_content_ids": list(self.required_content_ids),
            "records": [record.to_payload() for record in self.records],
            "diagnostics": list(self.diagnostics),
        }

    @cached_property
    def content_id(self) -> str:
        return _content_id("authority_bundle", self._core_payload())

    def to_payload(self) -> dict[str, Any]:
        core = self._core_payload()
        return {**core, "content_id": self.content_id}

    def to_json(self) -> str:
        return canonical_json(self.to_payload())

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "AuthorityBundle":
        row = _object(
            value,
            {
                "format",
                "schema_version",
                "content_id",
                "status",
                "authorizes",
                "v1_authorizes",
                "binary",
                "required_content_ids",
                "records",
                "diagnostics",
            },
            "authority bundle",
        )
        if row["format"] != cls.FORMAT or row["schema_version"] != 2:
            raise AuthorityDataError("v1 and unknown authority bundles are not authorizing")
        if row["v1_authorizes"] is not False:
            raise AuthorityDataError("v1 authority data cannot authorize a v2 bundle")
        records = tuple(
            parse_authority_record(item)
            for item in _array(row["records"], "authority records")
        )
        required = tuple(
            _checked_content_id(item, "required content ID")
            for item in _array(
                row["required_content_ids"], "required authority content IDs"
            )
        )
        result = cls(
            binary=BinaryBinding.parse(row["binary"]),
            records=records,
            required_content_ids=required,
        )
        if result.to_payload() != _json_value(value, context="authority bundle"):
            raise AuthorityDataError(
                "authority bundle status, authorization, closure, or content ID is stale"
            )
        return result

    @classmethod
    def from_json(cls, data: str | bytes) -> "AuthorityBundle":
        value = parse_canonical_json(data)
        if not isinstance(value, Mapping):
            raise AuthorityDataError("authority bundle JSON must contain an object")
        return cls.parse(value)


def parse_authority_bundle(value: Mapping[str, Any]) -> AuthorityBundle:
    return AuthorityBundle.parse(value)


def parse_authority_bundle_json(data: str | bytes) -> AuthorityBundle:
    return AuthorityBundle.from_json(data)


__all__ = [
    "AUTHORITY_BUNDLE_FORMAT",
    "CALL_FRAME_SUMMARY_FORMAT",
    "CHECKED_EXTERNAL_SITE_FORMAT",
    "ENTRY_STATE_CONTRACT_FORMAT",
    "GLOBAL_SLOT_INVARIANT_FORMAT",
    "HYBRID_AUTHORITY_SCHEMA_VERSION",
    "INDIRECT_EXIT_CERTIFICATE_FORMAT",
    "MAX_FINITE_ALTERNATIVES",
    "VALUE_FACT_FORMAT",
    "AuthorityBundle",
    "AuthorityDataError",
    "AuthorityDependency",
    "AuthorityRecord",
    "AuthorityStatus",
    "BinaryBinding",
    "CallFrameSummary",
    "CanonicalJson",
    "CheckedExternalSite",
    "EntryStateContract",
    "EventBinding",
    "EvidenceIssue",
    "EvidenceIssueKind",
    "FiniteAlternatives",
    "GlobalSlotInvariant",
    "ImageSpanBinding",
    "IndirectExitBinding",
    "IndirectExitCertificate",
    "ProfileBinding",
    "ScopeBinding",
    "UnitBinding",
    "ValueFact",
    "canonical_json",
    "canonical_json_bytes",
    "external_target",
    "infeasible_target",
    "internal_target",
    "parse_authority_bundle",
    "parse_authority_bundle_json",
    "parse_authority_record",
    "parse_authority_record_json",
    "parse_canonical_json",
]
