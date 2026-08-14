"""Native typed records for SCC-local inductive authority.

The records in this module are intentionally independent of the retired v2
certificate model.  Proposal facts remain untrusted data.  The phase checker
in :mod:`spaghetti_extractor.authority.inductive` reconstructs initiation, preservation, target
coverage, and export evidence from exact v3 transition and memory records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

from ..artifact_set_v3 import CanonicalValueV3, canonical_json_bytes_v3
from ..phase_framework_v3 import RecordCodecV3
from ._schema import (
    boolean,
    canonical_strings,
    canonical_values,
    digest,
    fail,
    mapping,
    optional_text,
    sequence,
    stable_id,
    strict_object,
    text,
    uint,
)


INDUCTIVE_INPUT_CONFIG_V3_SCHEMA = "spaghetti-extractor-inductive-config-v3"
INDUCTIVE_INPUT_CUTPOINT_V3_SCHEMA = "spaghetti-extractor-inductive-cutpoint-v3"
INDUCTIVE_AUTHORITY_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-inductive-authority-record-v3"
)
INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT = (
    "spaghetti-extractor-inductive-authority-check-v3"
)
INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3 = "inductive-authority-v3"

InductiveAuthorityKindV3: TypeAlias = Literal["scc_authority"]

_PREDICATE_KINDS = frozenset(
    {"exact", "finite", "range", "congruence", "resource_lifecycle"}
)
_DISCHARGE_KINDS = frozenset(
    {
        "callback",
        "external",
        "indirect_target",
        "incoming_control",
        "resource",
    }
)


def _require_stable_id(value: str, prefix: str, payload: Any, context: str) -> None:
    expected = stable_id(prefix, payload)
    if value != expected:
        fail(
            "stale_record_id",
            f"{context} ID {value!r} does not bind its payload",
            f"recreate it as {expected!r}",
        )


def _positive(value: Any, context: str) -> int:
    result = uint(value, context)
    if result == 0:
        fail(
            "record_schema_mismatch",
            f"{context} must be positive",
            "use a positive finite checker budget",
        )
    return result


def _canonical_facts(
    facts: tuple["InvariantFactV3", ...], context: str
) -> tuple["InvariantFactV3", ...]:
    if facts != tuple(sorted(set(facts), key=lambda row: row.fact_id)):
        fail(
            "noncanonical_record_order",
            f"{context} are not sorted and unique",
            "sort and deduplicate facts by stable ID",
        )
    subjects = tuple(row.subject for row in facts)
    if len(subjects) != len(set(subjects)):
        fail(
            "ambiguous_invariant_subject",
            f"{context} contain multiple predicates for one subject",
            "combine alternatives into one finite predicate",
        )
    return facts


def _validate_predicate(value: Any) -> None:
    row = mapping(value, "invariant predicate")
    kind = text(row.get("kind"), "invariant predicate kind")
    if kind not in _PREDICATE_KINDS:
        fail(
            "unsupported_invariant_predicate",
            f"invariant predicate kind {kind!r} is unsupported",
            "use exact, finite, range, congruence, or resource_lifecycle",
        )
    if kind == "exact":
        strict_object(row, {"kind", "value"}, "exact invariant predicate")
        CanonicalValueV3.of(row["value"])
        return
    if kind == "finite":
        strict_object(row, {"kind", "values"}, "finite invariant predicate")
        values = canonical_values(row["values"], "finite invariant values")
        if not values:
            fail(
                "record_schema_mismatch",
                "finite invariant predicate is empty",
                "include at least one canonical value",
            )
        return
    if kind == "range":
        strict_object(row, {"kind", "lower", "upper"}, "range invariant predicate")
        lower = row["lower"]
        upper = row["upper"]
        if (
            not isinstance(lower, int)
            or isinstance(lower, bool)
            or not isinstance(upper, int)
            or isinstance(upper, bool)
            or lower > upper
        ):
            fail(
                "record_schema_mismatch",
                "range invariant predicate is malformed",
                "emit integer lower and upper bounds with lower <= upper",
            )
        return
    if kind == "congruence":
        strict_object(
            row,
            {"kind", "modulus", "remainder"},
            "congruence invariant predicate",
        )
        modulus = _positive(row["modulus"], "congruence modulus")
        remainder = row["remainder"]
        if (
            not isinstance(remainder, int)
            or isinstance(remainder, bool)
            or not 0 <= remainder < modulus
        ):
            fail(
                "record_schema_mismatch",
                "congruence invariant remainder is malformed",
                "use an integer remainder in [0, modulus)",
            )
        return
    strict_object(
        row,
        {"kind", "resource_id", "states"},
        "resource lifecycle invariant predicate",
    )
    text(row["resource_id"], "resource lifecycle ID")
    if not canonical_strings(row["states"], "resource lifecycle states"):
        fail(
            "record_schema_mismatch",
            "resource lifecycle state set is empty",
            "include every permitted finite resource state",
        )


@dataclass(frozen=True, order=True)
class InvariantFactV3:
    subject: str
    predicate: CanonicalValueV3
    fact_id: str

    def __post_init__(self) -> None:
        text(self.subject, "invariant fact subject", maximum=512)
        _validate_predicate(self.predicate.to_value())
        _require_stable_id(
            self.fact_id, "fact", self.identity_payload(), "invariant fact"
        )

    @classmethod
    def exact(cls, subject: str, value: Any) -> "InvariantFactV3":
        return cls.create(subject, {"kind": "exact", "value": value})

    @classmethod
    def finite(cls, subject: str, values: tuple[Any, ...]) -> "InvariantFactV3":
        canonical = sorted(
            {canonical_json_bytes_v3(value): value for value in values}.items()
        )
        return cls.create(
            subject,
            {"kind": "finite", "values": [value for _, value in canonical]},
        )

    @classmethod
    def range(cls, subject: str, lower: int, upper: int) -> "InvariantFactV3":
        return cls.create(
            subject, {"kind": "range", "lower": lower, "upper": upper}
        )

    @classmethod
    def congruence(
        cls, subject: str, modulus: int, remainder: int
    ) -> "InvariantFactV3":
        return cls.create(
            subject,
            {"kind": "congruence", "modulus": modulus, "remainder": remainder},
        )

    @classmethod
    def resource_lifecycle(
        cls, subject: str, resource_id: str, states: tuple[str, ...]
    ) -> "InvariantFactV3":
        return cls.create(
            subject,
            {
                "kind": "resource_lifecycle",
                "resource_id": resource_id,
                "states": list(sorted(set(states))),
            },
        )

    @classmethod
    def create(cls, subject: str, predicate: Any) -> "InvariantFactV3":
        canonical = CanonicalValueV3.of(predicate)
        payload = {"subject": subject, "predicate": canonical.to_value()}
        return cls(subject, canonical, stable_id("fact", payload))

    def identity_payload(self) -> dict[str, Any]:
        return {"subject": self.subject, "predicate": self.predicate.to_value()}

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.fact_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "InvariantFactV3":
        row = strict_object(value, {"id", "subject", "predicate"}, "invariant fact")
        return cls(
            text(row["subject"], "invariant fact subject", maximum=512),
            CanonicalValueV3.of(row["predicate"]),
            text(row["id"], "invariant fact ID"),
        )


@dataclass(frozen=True, order=True)
class InvariantBudgetsV3:
    maximum_members: int = 128
    maximum_transitions: int = 1024
    maximum_facts_per_cutpoint: int = 128
    maximum_finite_values: int = 64
    maximum_resource_states: int = 32
    maximum_dependencies: int = 1024

    def __post_init__(self) -> None:
        for name, value in self.to_payload().items():
            _positive(value, name)

    def to_payload(self) -> dict[str, int]:
        return {
            "maximum_dependencies": self.maximum_dependencies,
            "maximum_facts_per_cutpoint": self.maximum_facts_per_cutpoint,
            "maximum_finite_values": self.maximum_finite_values,
            "maximum_members": self.maximum_members,
            "maximum_resource_states": self.maximum_resource_states,
            "maximum_transitions": self.maximum_transitions,
        }

    @classmethod
    def parse(cls, value: Any) -> "InvariantBudgetsV3":
        fields = {
            "maximum_dependencies",
            "maximum_facts_per_cutpoint",
            "maximum_finite_values",
            "maximum_members",
            "maximum_resource_states",
            "maximum_transitions",
        }
        row = strict_object(value, fields, "invariant budgets")
        return cls(**{name: _positive(row[name], name) for name in fields})


@dataclass(frozen=True, order=True)
class DependencyDischargeV3:
    dependency_id: str
    kind: str
    binding_sha256: str
    authority_artifact_id: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        text(self.dependency_id, "dependency discharge ID", maximum=512)
        if self.kind not in _DISCHARGE_KINDS:
            fail(
                "unsupported_dependency_discharge",
                f"dependency discharge kind {self.kind!r} is unsupported",
                "use a native v3 callback, external, target, incoming-control, or resource receipt",
            )
        digest(self.binding_sha256, "dependency discharge binding")
        text(self.authority_artifact_id, "dependency authority artifact", maximum=512)
        digest(self.evidence_sha256, "dependency discharge evidence")

    def to_payload(self) -> dict[str, str]:
        return {
            "authority_artifact_id": self.authority_artifact_id,
            "binding_sha256": self.binding_sha256,
            "dependency_id": self.dependency_id,
            "evidence_sha256": self.evidence_sha256,
            "kind": self.kind,
        }

    @classmethod
    def parse(cls, value: Any) -> "DependencyDischargeV3":
        row = strict_object(
            value,
            {
                "authority_artifact_id",
                "binding_sha256",
                "dependency_id",
                "evidence_sha256",
                "kind",
            },
            "dependency discharge",
        )
        return cls(
            text(row["dependency_id"], "dependency discharge ID", maximum=512),
            text(row["kind"], "dependency discharge kind"),
            digest(row["binding_sha256"], "dependency discharge binding"),
            text(
                row["authority_artifact_id"],
                "dependency authority artifact",
                maximum=512,
            ),
            digest(row["evidence_sha256"], "dependency discharge evidence"),
        )


@dataclass(frozen=True, order=True)
class EntryFactsV3:
    entry_id: str
    kind: str
    target_cutpoint: str
    transition_id: str | None
    facts: tuple[InvariantFactV3, ...]
    exit_id: str | None = None

    def __post_init__(self) -> None:
        text(self.entry_id, "entry fact ID", maximum=512)
        if self.kind not in {"root", "incoming"}:
            fail(
                "record_schema_mismatch",
                f"entry fact kind {self.kind!r} is unsupported",
                "use root or incoming",
            )
        text(self.target_cutpoint, "entry target", maximum=512)
        if self.kind == "root":
            if self.transition_id is not None or self.exit_id is not None:
                fail(
                    "record_schema_mismatch",
                    "root entry binds an incoming transition",
                    "clear transition_id and exit_id for root entries",
                )
        elif self.transition_id is None or self.exit_id is None:
            fail(
                "record_schema_mismatch",
                "incoming entry lacks its transition or exit ID",
                "bind the exact checked incoming transition and exit",
            )
        else:
            text(self.transition_id, "entry transition ID")
            text(self.exit_id, "entry exit ID")
        _canonical_facts(self.facts, "entry facts")

    def to_payload(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "facts": [row.to_payload() for row in self.facts],
            "kind": self.kind,
            "target_cutpoint": self.target_cutpoint,
            "transition_id": self.transition_id,
            "exit_id": self.exit_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "EntryFactsV3":
        row = strict_object(
            value,
            {
                "entry_id",
                "exit_id",
                "facts",
                "kind",
                "target_cutpoint",
                "transition_id",
            },
            "entry facts",
        )
        return cls(
            text(row["entry_id"], "entry fact ID", maximum=512),
            text(row["kind"], "entry fact kind"),
            text(row["target_cutpoint"], "entry target", maximum=512),
            optional_text(row["transition_id"], "entry transition ID"),
            tuple(
                sorted(
                    (InvariantFactV3.parse(item) for item in sequence(row["facts"], "entry facts")),
                    key=lambda item: item.fact_id,
                )
            ),
            optional_text(row["exit_id"], "entry exit ID"),
        )


@dataclass(frozen=True, order=True)
class ExportRequirementV3:
    cutpoint: str
    fact: InvariantFactV3
    export_id: str

    def __post_init__(self) -> None:
        text(self.cutpoint, "export cutpoint", maximum=512)
        _require_stable_id(
            self.export_id,
            "invariant-export",
            {"cutpoint": self.cutpoint, "fact": self.fact.to_payload()},
            "invariant export",
        )

    @classmethod
    def create(
        cls, cutpoint: str, fact: InvariantFactV3
    ) -> "ExportRequirementV3":
        payload = {"cutpoint": cutpoint, "fact": fact.to_payload()}
        return cls(cutpoint, fact, stable_id("invariant-export", payload))

    def to_payload(self) -> dict[str, Any]:
        return {
            "cutpoint": self.cutpoint,
            "fact": self.fact.to_payload(),
            "id": self.export_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "ExportRequirementV3":
        row = strict_object(
            value, {"cutpoint", "fact", "id"}, "invariant export"
        )
        return cls(
            text(row["cutpoint"], "export cutpoint", maximum=512),
            InvariantFactV3.parse(row["fact"]),
            text(row["id"], "export ID"),
        )


@dataclass(frozen=True, order=True)
class CutpointInvariantV3:
    cutpoint: str
    facts: tuple[InvariantFactV3, ...]

    def __post_init__(self) -> None:
        text(self.cutpoint, "invariant cutpoint", maximum=512)
        _canonical_facts(self.facts, "cutpoint facts")

    def to_payload(self) -> dict[str, Any]:
        return {
            "cutpoint": self.cutpoint,
            "facts": [row.to_payload() for row in self.facts],
        }

    @classmethod
    def parse(cls, value: Any) -> "CutpointInvariantV3":
        row = strict_object(value, {"cutpoint", "facts"}, "cutpoint invariant")
        return cls(
            text(row["cutpoint"], "invariant cutpoint", maximum=512),
            tuple(
                sorted(
                    (InvariantFactV3.parse(item) for item in sequence(row["facts"], "cutpoint facts")),
                    key=lambda item: item.fact_id,
                )
            ),
        )


@dataclass(frozen=True)
class InductiveConfigV3:
    record_id: str
    profile_sha256: str
    root_unit_ids: tuple[str, ...]
    root_entry_facts: tuple[EntryFactsV3, ...]
    required_exports: tuple[ExportRequirementV3, ...]
    dependency_discharges: tuple[DependencyDischargeV3, ...]
    budgets: InvariantBudgetsV3

    def __post_init__(self) -> None:
        if self.record_id != "inductive-config":
            fail(
                "stale_record_id",
                "inductive config must use record ID 'inductive-config'",
                "emit exactly one canonical inductive config record",
            )
        digest(self.profile_sha256, "inductive profile SHA-256")
        if self.root_unit_ids != tuple(sorted(set(self.root_unit_ids))):
            fail(
                "noncanonical_record_order",
                "inductive roots are not sorted and unique",
                "sort and deduplicate root unit IDs",
            )
        if self.root_entry_facts != tuple(
            sorted(set(self.root_entry_facts), key=lambda row: row.entry_id)
        ):
            fail(
                "noncanonical_record_order",
                "inductive root entries are not sorted and unique",
                "sort and deduplicate entry facts by entry_id",
            )
        if self.required_exports != tuple(
            sorted(set(self.required_exports), key=lambda row: row.export_id)
        ):
            fail(
                "noncanonical_record_order",
                "inductive exports are not sorted and unique",
                "sort and deduplicate required exports by export ID",
            )
        if self.dependency_discharges != tuple(
            sorted(set(self.dependency_discharges))
        ):
            fail(
                "noncanonical_record_order",
                "inductive dependency discharges are not sorted and unique",
                "sort and deduplicate dependency discharges",
            )


@dataclass(frozen=True)
class InductiveCutpointV3:
    record_id: str
    invariant: CutpointInvariantV3

    def __post_init__(self) -> None:
        if self.record_id != self.invariant.cutpoint:
            fail(
                "stale_record_id",
                f"inductive cutpoint record {self.record_id!r} does not bind {self.invariant.cutpoint!r}",
                "use the cutpoint ID as the input record ID",
            )


InductiveInputV3: TypeAlias = InductiveConfigV3 | InductiveCutpointV3


def _encode_inductive_input(value: InductiveInputV3) -> dict[str, Any]:
    if isinstance(value, InductiveConfigV3):
        return {
            "schema": INDUCTIVE_INPUT_CONFIG_V3_SCHEMA,
            "id": value.record_id,
            "profile_sha256": value.profile_sha256,
            "root_unit_ids": list(value.root_unit_ids),
            "root_entry_facts": [row.to_payload() for row in value.root_entry_facts],
            "required_exports": [row.to_payload() for row in value.required_exports],
            "dependency_discharges": [
                row.to_payload() for row in value.dependency_discharges
            ],
            "budgets": value.budgets.to_payload(),
        }
    return {
        "schema": INDUCTIVE_INPUT_CUTPOINT_V3_SCHEMA,
        "id": value.record_id,
        **value.invariant.to_payload(),
    }


def _decode_inductive_input(value: Any) -> InductiveInputV3:
    row = mapping(value, "inductive input record")
    schema = row.get("schema")
    if schema == INDUCTIVE_INPUT_CONFIG_V3_SCHEMA:
        strict_object(
            row,
            {
                "schema",
                "id",
                "profile_sha256",
                "root_unit_ids",
                "root_entry_facts",
                "required_exports",
                "dependency_discharges",
                "budgets",
            },
            "inductive config",
        )
        return InductiveConfigV3(
            record_id=text(row["id"], "inductive config ID"),
            profile_sha256=digest(
                row["profile_sha256"], "inductive profile SHA-256"
            ),
            root_unit_ids=canonical_strings(
                row["root_unit_ids"], "inductive root unit IDs"
            ),
            root_entry_facts=tuple(
                sorted(
                    (
                        EntryFactsV3.parse(item)
                        for item in sequence(
                            row["root_entry_facts"], "root entry facts"
                        )
                    ),
                    key=lambda item: item.entry_id,
                )
            ),
            required_exports=tuple(
                sorted(
                    (
                        ExportRequirementV3.parse(item)
                        for item in sequence(
                            row["required_exports"], "required exports"
                        )
                    ),
                    key=lambda item: item.export_id,
                )
            ),
            dependency_discharges=tuple(
                sorted(
                    DependencyDischargeV3.parse(item)
                    for item in sequence(
                        row["dependency_discharges"], "dependency discharges"
                    )
                )
            ),
            budgets=InvariantBudgetsV3.parse(row["budgets"]),
        )
    if schema == INDUCTIVE_INPUT_CUTPOINT_V3_SCHEMA:
        strict_object(row, {"schema", "id", "cutpoint", "facts"}, "inductive cutpoint")
        invariant = CutpointInvariantV3.parse(
            {"cutpoint": row["cutpoint"], "facts": row["facts"]}
        )
        return InductiveCutpointV3(
            record_id=text(row["id"], "inductive cutpoint ID"),
            invariant=invariant,
        )
    fail(
        "wrong_record_schema",
        f"unsupported inductive input schema {schema!r}",
        "emit one config and typed cutpoint-v3 records",
    )


INDUCTIVE_INPUT_CODEC_V3 = RecordCodecV3[InductiveInputV3](
    decode=_decode_inductive_input,
    encode=_encode_inductive_input,
)


@dataclass(frozen=True, order=True)
class InductiveIssueV3:
    status: str
    code: str
    subject_id: str
    dependencies: tuple[str, ...] = ()
    detail: CanonicalValueV3 | None = None

    def __post_init__(self) -> None:
        if self.status not in {"incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"inductive issue status {self.status!r} is unsupported",
                "use incomplete or violated",
            )
        text(self.code, "inductive issue code", maximum=128)
        text(self.subject_id, "inductive issue subject", maximum=512)
        if self.dependencies != tuple(sorted(set(self.dependencies))):
            fail(
                "noncanonical_record_order",
                "inductive issue dependencies are not sorted and unique",
                "sort and deduplicate dependency IDs",
            )

    def to_payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "status": self.status,
            "subject_id": self.subject_id,
        }
        if self.dependencies:
            result["dependencies"] = list(self.dependencies)
        if self.detail is not None:
            result["detail"] = self.detail.to_value()
        return result


@dataclass(frozen=True, order=True)
class InductiveCertificateReportV3:
    certificate_id: str
    status: str
    member_cutpoints: tuple[str, ...]
    transition_summary_ids: tuple[str, ...]
    initiation_witnesses: tuple[str, ...]
    preservation_witnesses: tuple[str, ...]
    target_witnesses: tuple[str, ...]
    checked_export_ids: tuple[str, ...]
    issues: tuple[InductiveIssueV3, ...]

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"inductive certificate status {self.status!r} is unsupported",
                "use complete, incomplete, or violated",
            )
        for values, label in (
            (self.member_cutpoints, "certificate members"),
            (self.transition_summary_ids, "certificate transitions"),
            (self.initiation_witnesses, "initiation witnesses"),
            (self.preservation_witnesses, "preservation witnesses"),
            (self.target_witnesses, "target witnesses"),
            (self.checked_export_ids, "checked exports"),
        ):
            if values != tuple(sorted(set(values))):
                fail(
                    "noncanonical_record_order",
                    f"{label} are not sorted and unique",
                    f"sort and deduplicate {label}",
                )
        if self.issues != tuple(
            sorted(set(self.issues), key=lambda row: canonical_json_bytes_v3(row.to_payload()))
        ):
            fail(
                "noncanonical_record_order",
                "certificate issues are not canonically sorted and unique",
                "sort and deduplicate issues by canonical payload",
            )
        expected = (
            "violated"
            if any(row.status == "violated" for row in self.issues)
            else "incomplete"
            if self.issues
            else "complete"
        )
        if self.status != expected:
            fail(
                "fail_open_inductive_authority",
                "certificate status contradicts its checked issues",
                "derive status from the canonical issue inventory",
            )
        _require_stable_id(
            self.certificate_id,
            "inductive-certificate",
            self.identity_payload(),
            "inductive certificate",
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "member_cutpoints": list(self.member_cutpoints),
            "transition_summary_ids": list(self.transition_summary_ids),
            "initiation_witnesses": list(self.initiation_witnesses),
            "preservation_witnesses": list(self.preservation_witnesses),
            "target_witnesses": list(self.target_witnesses),
            "checked_export_ids": list(self.checked_export_ids),
            "issues": [row.to_payload() for row in self.issues],
        }

    @classmethod
    def create(cls, **fields: Any) -> "InductiveCertificateReportV3":
        normalized = {
            **fields,
            "member_cutpoints": tuple(sorted(set(fields["member_cutpoints"]))),
            "transition_summary_ids": tuple(
                sorted(set(fields["transition_summary_ids"]))
            ),
            "initiation_witnesses": tuple(
                sorted(set(fields["initiation_witnesses"]))
            ),
            "preservation_witnesses": tuple(
                sorted(set(fields["preservation_witnesses"]))
            ),
            "target_witnesses": tuple(sorted(set(fields["target_witnesses"]))),
            "checked_export_ids": tuple(
                sorted(set(fields["checked_export_ids"]))
            ),
            "issues": tuple(
                sorted(
                    set(fields["issues"]),
                    key=lambda row: canonical_json_bytes_v3(row.to_payload()),
                )
            ),
        }
        payload = {
            key: (
                [row.to_payload() for row in value]
                if key == "issues"
                else list(value)
                if isinstance(value, tuple)
                else value
            )
            for key, value in normalized.items()
        }
        return cls(
            certificate_id=stable_id("inductive-certificate", payload),
            **normalized,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.certificate_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "InductiveCertificateReportV3":
        row = strict_object(
            value,
            {
                "id",
                "status",
                "member_cutpoints",
                "transition_summary_ids",
                "initiation_witnesses",
                "preservation_witnesses",
                "target_witnesses",
                "checked_export_ids",
                "issues",
            },
            "inductive certificate report",
        )
        issues = tuple(
            sorted(
                (_parse_issue(item) for item in sequence(row["issues"], "certificate issues")),
                key=lambda item: canonical_json_bytes_v3(item.to_payload()),
            )
        )
        return cls(
            certificate_id=text(row["id"], "inductive certificate ID"),
            status=text(row["status"], "inductive certificate status"),
            member_cutpoints=canonical_strings(
                row["member_cutpoints"], "certificate members"
            ),
            transition_summary_ids=canonical_strings(
                row["transition_summary_ids"], "certificate transitions"
            ),
            initiation_witnesses=canonical_strings(
                row["initiation_witnesses"], "initiation witnesses"
            ),
            preservation_witnesses=canonical_strings(
                row["preservation_witnesses"], "preservation witnesses"
            ),
            target_witnesses=canonical_strings(
                row["target_witnesses"], "target witnesses"
            ),
            checked_export_ids=canonical_strings(
                row["checked_export_ids"], "checked exports"
            ),
            issues=issues,
        )


def _parse_issue(value: Any) -> InductiveIssueV3:
    row = mapping(value, "inductive issue")
    allowed = {"code", "status", "subject_id", "dependencies", "detail"}
    if not set(row).issubset(allowed) or not {"code", "status", "subject_id"}.issubset(row):
        fail(
            "record_schema_mismatch",
            "inductive issue contains unsupported or missing fields",
            "emit status, code, subject_id, and optional dependencies/detail",
        )
    return InductiveIssueV3(
        status=text(row["status"], "inductive issue status"),
        code=text(row["code"], "inductive issue code", maximum=128),
        subject_id=text(row["subject_id"], "inductive issue subject", maximum=512),
        dependencies=(
            ()
            if "dependencies" not in row
            else canonical_strings(row["dependencies"], "inductive issue dependencies")
        ),
        detail=(
            None if "detail" not in row else CanonicalValueV3.of(row["detail"])
        ),
    )


@dataclass(frozen=True)
class InductiveAuthorityBodyV3:
    authority_id: str
    status: str
    authorizing: bool
    profile_sha256: str | None
    binary_pe_sha256: str | None
    memory_version_graph_id: str | None
    transition_summary_ids: tuple[str, ...]
    root_unit_ids: tuple[str, ...]
    certificate_reports: tuple[InductiveCertificateReportV3, ...]
    checked_exports: tuple[str, ...]
    dependency_discharges: tuple[DependencyDischargeV3, ...]
    issues: tuple[InductiveIssueV3, ...]
    structural_unit_count: int
    reachable_unit_count: int

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"inductive authority status {self.status!r} is unsupported",
                "use complete, incomplete, or violated",
            )
        if self.authorizing != (self.status == "complete"):
            fail(
                "fail_open_inductive_authority",
                "inductive authority flag contradicts its status",
                "authorize exactly complete checked reports",
            )
        if self.status == "complete" and (
            self.profile_sha256 is None
            or self.binary_pe_sha256 is None
            or self.memory_version_graph_id is None
            or not self.transition_summary_ids
            or not self.certificate_reports
            or self.structural_unit_count == 0
            or any(row.status != "complete" for row in self.certificate_reports)
        ):
            fail(
                "fail_open_inductive_authority",
                "complete inductive authority lacks checked binary, memory, transition, or certificate evidence",
                "mark it incomplete or include one complete native certificate over a nonempty SCC",
            )
        if self.profile_sha256 is not None:
            digest(self.profile_sha256, "inductive profile SHA-256")
        if self.binary_pe_sha256 is not None:
            digest(self.binary_pe_sha256, "inductive binary PE SHA-256")
        if self.memory_version_graph_id is not None:
            text(self.memory_version_graph_id, "memory-version graph ID")
        for values, label in (
            (self.transition_summary_ids, "authority transitions"),
            (self.root_unit_ids, "authority roots"),
            (self.checked_exports, "authority exports"),
        ):
            if values != tuple(sorted(set(values))):
                fail(
                    "noncanonical_record_order",
                    f"{label} are not sorted and unique",
                    f"sort and deduplicate {label}",
                )
        if self.certificate_reports != tuple(
            sorted(self.certificate_reports, key=lambda row: row.certificate_id)
        ) or len({row.certificate_id for row in self.certificate_reports}) != len(
            self.certificate_reports
        ):
            fail(
                "noncanonical_record_order",
                "certificate reports are not sorted and unique",
                "sort and deduplicate certificate reports by stable ID",
            )
        if self.dependency_discharges != tuple(sorted(set(self.dependency_discharges))):
            fail(
                "noncanonical_record_order",
                "dependency discharges are not sorted and unique",
                "sort and deduplicate dependency discharges",
            )
        if self.issues != tuple(
            sorted(set(self.issues), key=lambda row: canonical_json_bytes_v3(row.to_payload()))
        ):
            fail(
                "noncanonical_record_order",
                "authority issues are not sorted and unique",
                "sort and deduplicate issues by canonical payload",
            )
        expected = (
            "violated"
            if any(row.status == "violated" for row in self.issues)
            else "incomplete"
            if self.issues
            else "complete"
        )
        if self.status != expected:
            fail(
                "fail_open_inductive_authority",
                "authority status contradicts its checked issue inventory",
                "derive status from the canonical issues",
            )
        uint(self.structural_unit_count, "inductive structural unit count")
        uint(self.reachable_unit_count, "inductive reachable unit count")
        _require_stable_id(
            self.authority_id,
            "inductive-authority-v3",
            self.identity_payload(),
            "inductive authority",
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "format": INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT,
            "status": self.status,
            "authorizing": self.authorizing,
            "profile_sha256": self.profile_sha256,
            "binary_pe_sha256": self.binary_pe_sha256,
            "memory_version_graph_id": self.memory_version_graph_id,
            "transition_summary_ids": list(self.transition_summary_ids),
            "root_unit_ids": list(self.root_unit_ids),
            "certificate_reports": [
                row.to_payload() for row in self.certificate_reports
            ],
            "checked_exports": list(self.checked_exports),
            "dependency_discharges": [
                row.to_payload() for row in self.dependency_discharges
            ],
            "issues": [row.to_payload() for row in self.issues],
            "counts": {
                "certificates": len(self.certificate_reports),
                "complete_certificates": sum(
                    row.status == "complete" for row in self.certificate_reports
                ),
                "structural_units": self.structural_unit_count,
                "reachable_units": self.reachable_unit_count,
            },
        }

    @classmethod
    def create(cls, **fields: Any) -> "InductiveAuthorityBodyV3":
        normalized = {
            **fields,
            "transition_summary_ids": tuple(
                sorted(set(fields["transition_summary_ids"]))
            ),
            "root_unit_ids": tuple(sorted(set(fields["root_unit_ids"]))),
            "certificate_reports": tuple(
                sorted(
                    fields["certificate_reports"],
                    key=lambda row: row.certificate_id,
                )
            ),
            "checked_exports": tuple(sorted(set(fields["checked_exports"]))),
            "dependency_discharges": tuple(
                sorted(set(fields["dependency_discharges"]))
            ),
            "issues": tuple(
                sorted(
                    set(fields["issues"]),
                    key=lambda row: canonical_json_bytes_v3(row.to_payload()),
                )
            ),
        }
        reports = normalized["certificate_reports"]
        payload = {
            "format": INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT,
            "status": normalized["status"],
            "authorizing": normalized["authorizing"],
            "profile_sha256": normalized["profile_sha256"],
            "binary_pe_sha256": normalized["binary_pe_sha256"],
            "memory_version_graph_id": normalized["memory_version_graph_id"],
            "transition_summary_ids": list(normalized["transition_summary_ids"]),
            "root_unit_ids": list(normalized["root_unit_ids"]),
            "certificate_reports": [row.to_payload() for row in reports],
            "checked_exports": list(normalized["checked_exports"]),
            "dependency_discharges": [
                row.to_payload() for row in normalized["dependency_discharges"]
            ],
            "issues": [row.to_payload() for row in normalized["issues"]],
            "counts": {
                "certificates": len(reports),
                "complete_certificates": sum(
                    row.status == "complete" for row in reports
                ),
                "structural_units": normalized["structural_unit_count"],
                "reachable_units": normalized["reachable_unit_count"],
            },
        }
        return cls(
            authority_id=stable_id("inductive-authority-v3", payload),
            **normalized,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.authority_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "InductiveAuthorityBodyV3":
        row = strict_object(
            value,
            {
                "id",
                "format",
                "status",
                "authorizing",
                "profile_sha256",
                "binary_pe_sha256",
                "memory_version_graph_id",
                "transition_summary_ids",
                "root_unit_ids",
                "certificate_reports",
                "checked_exports",
                "dependency_discharges",
                "issues",
                "counts",
            },
            "inductive authority body",
        )
        if row["format"] != INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT:
            fail(
                "wrong_record_schema",
                "inductive authority body has an unsupported checker format",
                "emit the native v3 checked report",
            )
        counts = strict_object(
            row["counts"],
            {
                "certificates",
                "complete_certificates",
                "structural_units",
                "reachable_units",
            },
            "inductive authority counts",
        )
        reports = tuple(
            sorted(
                (
                    InductiveCertificateReportV3.parse(item)
                    for item in sequence(
                        row["certificate_reports"], "inductive certificate reports"
                    )
                ),
                key=lambda item: item.certificate_id,
            )
        )
        if uint(counts["certificates"], "certificate count") != len(reports) or uint(
            counts["complete_certificates"], "complete certificate count"
        ) != sum(item.status == "complete" for item in reports):
            fail(
                "record_count_mismatch",
                "inductive authority certificate counts are stale",
                "derive counts from the exact report inventory",
            )
        return cls(
            authority_id=text(row["id"], "inductive authority ID"),
            status=text(row["status"], "inductive authority status"),
            authorizing=boolean(row["authorizing"], "inductive authority flag"),
            profile_sha256=(
                None
                if row["profile_sha256"] is None
                else digest(row["profile_sha256"], "inductive profile SHA-256")
            ),
            binary_pe_sha256=(
                None
                if row["binary_pe_sha256"] is None
                else digest(row["binary_pe_sha256"], "inductive binary PE SHA-256")
            ),
            memory_version_graph_id=optional_text(
                row["memory_version_graph_id"], "memory-version graph ID"
            ),
            transition_summary_ids=canonical_strings(
                row["transition_summary_ids"], "authority transitions"
            ),
            root_unit_ids=canonical_strings(row["root_unit_ids"], "authority roots"),
            certificate_reports=reports,
            checked_exports=canonical_strings(
                row["checked_exports"], "authority exports"
            ),
            dependency_discharges=tuple(
                sorted(
                    DependencyDischargeV3.parse(item)
                    for item in sequence(
                        row["dependency_discharges"], "dependency discharges"
                    )
                )
            ),
            issues=tuple(
                sorted(
                    (_parse_issue(item) for item in sequence(row["issues"], "authority issues")),
                    key=lambda item: canonical_json_bytes_v3(item.to_payload()),
                )
            ),
            structural_unit_count=uint(
                counts["structural_units"], "inductive structural unit count"
            ),
            reachable_unit_count=uint(
                counts["reachable_units"], "inductive reachable unit count"
            ),
        )


@dataclass(frozen=True)
class InductiveAuthorityRecordV3:
    record_id: str
    record_kind: InductiveAuthorityKindV3
    authority_set_id: str
    status: str
    authorizing: bool
    body: CanonicalValueV3

    def __post_init__(self) -> None:
        text(self.record_id, "inductive SCC ID")
        if self.record_kind != "scc_authority":
            fail(
                "record_schema_mismatch",
                f"unsupported inductive authority kind {self.record_kind!r}",
                "emit exactly one checked authority record per dependency SCC",
            )
        parsed = InductiveAuthorityBodyV3.parse(self.body.to_value())
        if (
            parsed.authority_id != self.authority_set_id
            or parsed.status != self.status
            or parsed.authorizing != self.authorizing
        ):
            fail(
                "fail_open_inductive_authority",
                "inductive authority envelope contradicts its checked body",
                "derive envelope fields from the native v3 checker report",
            )


def _encode_authority(value: InductiveAuthorityRecordV3) -> dict[str, Any]:
    return {
        "schema": INDUCTIVE_AUTHORITY_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "kind": value.record_kind,
        "authority_set_id": value.authority_set_id,
        "status": value.status,
        "authorizing": value.authorizing,
        "body": value.body.to_value(),
    }


def _decode_authority(value: Any) -> InductiveAuthorityRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "kind",
            "authority_set_id",
            "status",
            "authorizing",
            "body",
        },
        "inductive authority record",
    )
    if row["schema"] != INDUCTIVE_AUTHORITY_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an inductive-authority-record-v3",
            "use INDUCTIVE_AUTHORITY_CODEC_V3 with authority artifacts",
        )
    return InductiveAuthorityRecordV3(
        record_id=text(row["id"], "inductive authority record ID"),
        record_kind=text(row["kind"], "inductive authority kind"),  # type: ignore[arg-type]
        authority_set_id=text(
            row["authority_set_id"], "inductive authority-set ID"
        ),
        status=text(row["status"], "inductive authority status"),
        authorizing=boolean(row["authorizing"], "inductive authority flag"),
        body=CanonicalValueV3.of(row["body"]),
    )


INDUCTIVE_AUTHORITY_CODEC_V3 = RecordCodecV3[InductiveAuthorityRecordV3](
    decode=_decode_authority,
    encode=_encode_authority,
)


__all__ = [
    "INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3",
    "INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT",
    "INDUCTIVE_AUTHORITY_CODEC_V3",
    "INDUCTIVE_AUTHORITY_RECORD_V3_SCHEMA",
    "INDUCTIVE_INPUT_CODEC_V3",
    "INDUCTIVE_INPUT_CONFIG_V3_SCHEMA",
    "INDUCTIVE_INPUT_CUTPOINT_V3_SCHEMA",
    "CutpointInvariantV3",
    "DependencyDischargeV3",
    "EntryFactsV3",
    "ExportRequirementV3",
    "InductiveAuthorityBodyV3",
    "InductiveAuthorityRecordV3",
    "InductiveCertificateReportV3",
    "InductiveConfigV3",
    "InductiveCutpointV3",
    "InductiveIssueV3",
    "InvariantBudgetsV3",
    "InvariantFactV3",
]
