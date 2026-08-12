"""Generic bounded induction certificates over exact transition summaries.

This module deliberately separates three roles:

* exact transition summaries describe the checked structural transition system;
* synthesis deterministically packages untrusted invariant proposals; and
* the checker reconstructs all inventories and checks initiation, preservation,
  target coverage, exports, dependencies, and finite budgets independently.

The abstract facts are predicates over concrete values.  They are not runtime
tags, and a certificate never authorizes itself.  A complete checker receipt is
the only authority produced by this layer.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .analysis.scc_worklist import decompose_scc
from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    CanonicalJson,
    canonical_json_bytes,
)
from .memory_version_graph_v2 import MemoryVersionGraphV2
from .transition_summary_v2 import TransitionSummaryV2


INVARIANT_CERTIFICATE_PROPOSAL_V2_FORMAT = (
    "spaghetti-extractor-invariant-certificate-proposal-v2"
)
INVARIANT_CERTIFICATE_CHECK_V2_FORMAT = (
    "spaghetti-extractor-invariant-certificate-check-v2"
)
TRANSITION_WITNESS_INVENTORY_V2_FORMAT = (
    "spaghetti-extractor-transition-witness-inventory-v2"
)

_FACT_KINDS = frozenset(
    {"exact", "finite", "range", "congruence", "resource_lifecycle"}
)
_DEPENDENCY_NODE_KINDS = frozenset(
    {
        "invariant",
        "value",
        "memory_version",
        "indirect_target",
        "call_summary",
        "callback_entry",
        "resource",
        "external_site",
    }
)
_DEPENDENCY_EDGE_KINDS = frozenset(
    {"consumes", "establishes", "preserves", "invalidates", "exports"}
)
_EXTERNALLY_DISCHARGEABLE_DEPENDENCY_KINDS = frozenset(
    {"indirect_target", "call_summary", "callback_entry", "resource", "external_site"}
)
_DIGEST_LENGTH = 64


class InvariantCertificateV2Error(AuthorityDataError):
    """A v2 invariant artifact or caller option is malformed."""


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _identity(prefix: str, value: Any) -> str:
    return f"{prefix}:{canonical_sha256(value)[:24]}"


def _text(value: Any, context: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise InvariantCertificateV2Error(
            f"{context} must be nonempty bounded text"
        )
    return value


def _digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise InvariantCertificateV2Error(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _positive(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise InvariantCertificateV2Error(
            f"{context} must be a positive integer"
        )
    return value


def _canonical_strings(
    values: Sequence[str], context: str, *, maximum: int = 256
) -> tuple[str, ...]:
    result = tuple(values)
    for value in result:
        _text(value, context, maximum=maximum)
    if result != tuple(sorted(set(result))):
        raise InvariantCertificateV2Error(f"{context} is noncanonical")
    return result


def _canonical_objects(
    values: Sequence[Any], context: str
) -> tuple[CanonicalJson, ...]:
    result = tuple(
        value if isinstance(value, CanonicalJson) else CanonicalJson.of(value)
        for value in values
    )
    if result != tuple(sorted(set(result))):
        raise InvariantCertificateV2Error(f"{context} is noncanonical")
    return result


def _object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InvariantCertificateV2Error(
            f"{context} has noncanonical fields"
        )
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise InvariantCertificateV2Error(f"{context} must be an array")
    return value


@dataclass(frozen=True, order=True)
class InvariantFactV2:
    """One bounded predicate over a named concrete-state observation."""

    subject: str
    predicate: CanonicalJson
    fact_id: str

    def __post_init__(self) -> None:
        _text(self.subject, "fact subject", maximum=512)
        if not isinstance(self.predicate, CanonicalJson):
            raise InvariantCertificateV2Error(
                "fact predicate must be canonical JSON"
            )
        _validate_predicate(self.predicate.to_value())
        expected = _identity("fact", self.identity_payload())
        if self.fact_id != expected:
            raise InvariantCertificateV2Error("fact ID is stale")

    @classmethod
    def exact(cls, subject: str, value: Any) -> "InvariantFactV2":
        return cls._create(subject, {"kind": "exact", "value": value})

    @classmethod
    def finite(
        cls, subject: str, values: Sequence[Any]
    ) -> "InvariantFactV2":
        canonical = _canonical_objects(values, "finite fact values")
        return cls._create(
            subject,
            {
                "kind": "finite",
                "values": [value.to_value() for value in canonical],
            },
        )

    @classmethod
    def range(
        cls, subject: str, lower: int, upper: int
    ) -> "InvariantFactV2":
        return cls._create(
            subject, {"kind": "range", "lower": lower, "upper": upper}
        )

    @classmethod
    def congruence(
        cls, subject: str, modulus: int, remainder: int
    ) -> "InvariantFactV2":
        return cls._create(
            subject,
            {
                "kind": "congruence",
                "modulus": modulus,
                "remainder": remainder,
            },
        )

    @classmethod
    def resource_lifecycle(
        cls, subject: str, resource_id: str, states: Sequence[str]
    ) -> "InvariantFactV2":
        return cls._create(
            subject,
            {
                "kind": "resource_lifecycle",
                "resource_id": resource_id,
                "states": list(_canonical_strings(states, "resource states")),
            },
        )

    @classmethod
    def _create(cls, subject: str, predicate: Any) -> "InvariantFactV2":
        canonical = CanonicalJson.of(predicate)
        payload = {"subject": subject, "predicate": canonical.to_value()}
        return cls(subject, canonical, _identity("fact", payload))

    def identity_payload(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "predicate": self.predicate.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.fact_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "InvariantFactV2":
        row = _object(value, {"id", "subject", "predicate"}, "fact")
        return cls(
            subject=_text(row["subject"], "fact subject", maximum=512),
            predicate=CanonicalJson.of(row["predicate"]),
            fact_id=_text(row["id"], "fact ID"),
        )


def _validate_predicate(value: Any) -> None:
    if not isinstance(value, Mapping) or value.get("kind") not in _FACT_KINDS:
        raise InvariantCertificateV2Error("fact predicate kind is unsupported")
    kind = str(value["kind"])
    if kind == "exact":
        _object(value, {"kind", "value"}, "exact predicate")
        CanonicalJson.of(value["value"])
        return
    if kind == "finite":
        row = _object(value, {"kind", "values"}, "finite predicate")
        values = _array(row["values"], "finite values")
        if not values:
            raise InvariantCertificateV2Error("finite fact cannot be empty")
        _canonical_objects(values, "finite fact values")
        return
    if kind == "range":
        row = _object(value, {"kind", "lower", "upper"}, "range predicate")
        lower = row["lower"]
        upper = row["upper"]
        if (
            not isinstance(lower, int)
            or isinstance(lower, bool)
            or not isinstance(upper, int)
            or isinstance(upper, bool)
            or lower > upper
        ):
            raise InvariantCertificateV2Error("range predicate is malformed")
        return
    if kind == "congruence":
        row = _object(
            value, {"kind", "modulus", "remainder"}, "congruence predicate"
        )
        modulus = _positive(row["modulus"], "congruence modulus")
        remainder = row["remainder"]
        if (
            not isinstance(remainder, int)
            or isinstance(remainder, bool)
            or not 0 <= remainder < modulus
        ):
            raise InvariantCertificateV2Error(
                "congruence remainder is malformed"
            )
        return
    row = _object(
        value,
        {"kind", "resource_id", "states"},
        "resource-lifecycle predicate",
    )
    _text(row["resource_id"], "resource ID")
    states = _array(row["states"], "resource states")
    if not states:
        raise InvariantCertificateV2Error("resource states cannot be empty")
    _canonical_strings(states, "resource states")


@dataclass(frozen=True, order=True)
class InvariantBudgetsV2:
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
    def parse(cls, value: Any) -> "InvariantBudgetsV2":
        fields = {
            "maximum_dependencies",
            "maximum_facts_per_cutpoint",
            "maximum_finite_values",
            "maximum_members",
            "maximum_resource_states",
            "maximum_transitions",
        }
        row = _object(value, fields, "invariant budgets")
        return cls(**{name: _positive(row[name], name) for name in fields})


@dataclass(frozen=True, order=True)
class DependencyNodeV2:
    node_id: str
    kind: str
    binding_sha256: str

    def __post_init__(self) -> None:
        _text(self.node_id, "dependency node ID", maximum=512)
        if self.kind not in _DEPENDENCY_NODE_KINDS:
            raise InvariantCertificateV2Error(
                "dependency node kind is unsupported"
            )
        _digest(self.binding_sha256, "dependency node binding")

    def to_payload(self) -> dict[str, str]:
        return {
            "binding_sha256": self.binding_sha256,
            "id": self.node_id,
            "kind": self.kind,
        }


@dataclass(frozen=True, order=True)
class DependencyDischargeV2:
    """Typed receipt from the checker that owns one external dependency."""

    dependency_id: str
    kind: str
    binding_sha256: str
    authority_artifact_id: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        _text(self.dependency_id, "dependency discharge ID", maximum=512)
        if self.kind not in _EXTERNALLY_DISCHARGEABLE_DEPENDENCY_KINDS:
            raise InvariantCertificateV2Error(
                "dependency discharge kind is not externally dischargeable"
            )
        _digest(self.binding_sha256, "dependency discharge binding")
        _text(self.authority_artifact_id, "dependency authority artifact", maximum=512)
        _digest(self.evidence_sha256, "dependency discharge evidence")

    def to_payload(self) -> dict[str, str]:
        return {
            "authority_artifact_id": self.authority_artifact_id,
            "binding_sha256": self.binding_sha256,
            "dependency_id": self.dependency_id,
            "evidence_sha256": self.evidence_sha256,
            "kind": self.kind,
        }

    @classmethod
    def parse(cls, value: Any) -> "DependencyDischargeV2":
        row = _object(
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
            dependency_id=_text(
                row["dependency_id"], "dependency discharge ID", maximum=512
            ),
            kind=_text(row["kind"], "dependency discharge kind"),
            binding_sha256=_digest(
                row["binding_sha256"], "dependency discharge binding"
            ),
            authority_artifact_id=_text(
                row["authority_artifact_id"],
                "dependency authority artifact",
                maximum=512,
            ),
            evidence_sha256=_digest(
                row["evidence_sha256"], "dependency discharge evidence"
            ),
        )


@dataclass(frozen=True, order=True)
class DependencyEdgeV2:
    source_id: str
    target_id: str
    kind: str

    def __post_init__(self) -> None:
        _text(self.source_id, "dependency edge source", maximum=512)
        _text(self.target_id, "dependency edge target", maximum=512)
        if self.kind not in _DEPENDENCY_EDGE_KINDS:
            raise InvariantCertificateV2Error(
                "dependency edge kind is unsupported"
            )

    def to_payload(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "source_id": self.source_id,
            "target_id": self.target_id,
        }


@dataclass(frozen=True, order=True)
class TypedDependencySCCV2:
    members: tuple[str, ...]
    internal_edges: tuple[DependencyEdgeV2, ...]
    incoming_edges: tuple[DependencyEdgeV2, ...]
    outgoing_edges: tuple[DependencyEdgeV2, ...]
    scc_id: str

    def __post_init__(self) -> None:
        _canonical_strings(self.members, "dependency SCC members", maximum=512)
        if not self.members:
            raise InvariantCertificateV2Error(
                "dependency SCC must have at least one member"
            )
        for name, edges in (
            ("internal", self.internal_edges),
            ("incoming", self.incoming_edges),
            ("outgoing", self.outgoing_edges),
        ):
            if edges != tuple(sorted(set(edges))):
                raise InvariantCertificateV2Error(
                    f"dependency SCC {name} edges are noncanonical"
                )
        if self.scc_id != _identity("dependency-scc", self.identity_payload()):
            raise InvariantCertificateV2Error("dependency SCC ID is stale")

    def identity_payload(self) -> dict[str, Any]:
        return {
            "incoming_edges": [edge.to_payload() for edge in self.incoming_edges],
            "internal_edges": [edge.to_payload() for edge in self.internal_edges],
            "members": list(self.members),
            "outgoing_edges": [edge.to_payload() for edge in self.outgoing_edges],
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.scc_id, **self.identity_payload()}


def derive_typed_dependency_sccs_v2(
    nodes: Sequence[DependencyNodeV2], edges: Sequence[DependencyEdgeV2]
) -> tuple[TypedDependencySCCV2, ...]:
    """Reconstruct canonical dependency SCCs from the complete typed graph."""

    node_ids = tuple(node.node_id for node in nodes)
    if node_ids != tuple(sorted(set(node_ids))):
        raise InvariantCertificateV2Error(
            "dependency nodes must be unique and canonically ordered"
        )
    if tuple(edges) != tuple(sorted(set(edges))):
        raise InvariantCertificateV2Error(
            "dependency edges must be unique and canonically ordered"
        )
    known = frozenset(node_ids)
    if any(edge.source_id not in known or edge.target_id not in known for edge in edges):
        raise InvariantCertificateV2Error(
            "dependency edge references an unknown node"
        )
    decomposition = decompose_scc(
        node_ids, ((edge.source_id, edge.target_id) for edge in edges)
    )
    outgoing_by_source: dict[str, list[DependencyEdgeV2]] = {}
    incoming_by_target: dict[str, list[DependencyEdgeV2]] = {}
    for edge in edges:
        outgoing_by_source.setdefault(edge.source_id, []).append(edge)
        incoming_by_target.setdefault(edge.target_id, []).append(edge)
    result: list[TypedDependencySCCV2] = []
    for members in decomposition.components:
        member_set = frozenset(members)
        internal = tuple(sorted(
            edge
            for source in members
            for edge in outgoing_by_source.get(source, ())
            if edge.target_id in member_set
        ))
        incoming = tuple(sorted(
            edge
            for target in members
            for edge in incoming_by_target.get(target, ())
            if edge.source_id not in member_set
        ))
        outgoing = tuple(sorted(
            edge
            for source in members
            for edge in outgoing_by_source.get(source, ())
            if edge.target_id not in member_set
        ))
        payload = {
            "incoming_edges": [edge.to_payload() for edge in incoming],
            "internal_edges": [edge.to_payload() for edge in internal],
            "members": list(members),
            "outgoing_edges": [edge.to_payload() for edge in outgoing],
        }
        result.append(
            TypedDependencySCCV2(
                members=tuple(members),
                internal_edges=internal,
                incoming_edges=incoming,
                outgoing_edges=outgoing,
                scc_id=_identity("dependency-scc", payload),
            )
        )
    return tuple(result)


@dataclass(frozen=True, order=True)
class ExitTargetSetV2:
    """Targets and evidence dependencies for one exact transition exit."""

    exit_id: str
    target_cutpoints: tuple[str, ...]
    dependency_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.exit_id, "transition exit ID")
        _canonical_strings(
            self.target_cutpoints, "exit target cutpoints", maximum=512
        )
        _canonical_strings(
            self.dependency_ids, "exit target dependencies", maximum=512
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "exit_id": self.exit_id,
            "target_cutpoints": list(self.target_cutpoints),
            "dependency_ids": list(self.dependency_ids),
        }

    @classmethod
    def create(
        cls,
        *,
        exit_id: str,
        target_cutpoints: Sequence[str],
        dependency_ids: Sequence[str] = (),
    ) -> "ExitTargetSetV2":
        return cls(
            exit_id,
            tuple(sorted(set(target_cutpoints))),
            tuple(sorted(set(dependency_ids))),
        )

    @classmethod
    def parse(cls, value: Any) -> "ExitTargetSetV2":
        row = _object(
            value,
            {"exit_id", "target_cutpoints", "dependency_ids"},
            "exit target set",
        )
        return cls(
            exit_id=_text(row["exit_id"], "transition exit ID"),
            target_cutpoints=_parse_strings(
                row["target_cutpoints"], "exit targets", maximum=512
            ),
            dependency_ids=_parse_strings(
                row["dependency_ids"], "exit dependencies", maximum=512
            ),
        )


@dataclass(frozen=True, order=True)
class TransitionControlWitnessV2:
    """Certificate-side CFG evidence bound to one canonical summary.

    This is intentionally not a semantic summary.  Register, flag, memory,
    external-event, and fault effects remain exclusively authoritative in
    :class:`TransitionSummaryV2`.
    """

    summary_id: str
    source_cutpoint: str
    exit_targets: tuple[ExitTargetSetV2, ...]
    dependency_ids: tuple[str, ...]
    witness_id: str

    def __post_init__(self) -> None:
        _text(self.summary_id, "canonical transition summary ID")
        _text(self.source_cutpoint, "transition source", maximum=512)
        if self.exit_targets != tuple(
            sorted(self.exit_targets, key=lambda row: row.exit_id)
        ) or len({row.exit_id for row in self.exit_targets}) != len(
            self.exit_targets
        ):
            raise InvariantCertificateV2Error(
                "exit target sets are duplicated or noncanonical"
            )
        _canonical_strings(
            self.dependency_ids, "transition dependencies", maximum=512
        )
        if self.witness_id != _identity(
            "transition-control", self.identity_payload()
        ):
            raise InvariantCertificateV2Error(
                "transition control witness ID is stale"
            )

    @classmethod
    def create(
        cls,
        *,
        summary: TransitionSummaryV2,
        target_cutpoints: Sequence[str] | None = None,
        exit_targets: Sequence[ExitTargetSetV2] | None = None,
        dependency_ids: Sequence[str] = (),
    ) -> "TransitionControlWitnessV2":
        if (target_cutpoints is None) == (exit_targets is None):
            raise InvariantCertificateV2Error(
                "control witness requires exactly one target representation"
            )
        if exit_targets is None:
            exit_targets = (
                ExitTargetSetV2.create(
                    exit_id=_outcome_exit(summary).exit_id,
                    target_cutpoints=target_cutpoints or (),
                    dependency_ids=dependency_ids,
                ),
            )
        fields = {
            "summary_id": summary.summary_id,
            "source_cutpoint": summary.unit.unit_id,
            "exit_targets": tuple(
                sorted(exit_targets, key=lambda row: row.exit_id)
            ),
            "dependency_ids": tuple(sorted(set(dependency_ids))),
        }
        return cls(
            **fields,
            witness_id=_identity(
                "transition-control", _control_witness_payload(**fields)
            ),
        )

    def identity_payload(self) -> dict[str, Any]:
        return _control_witness_payload(
            summary_id=self.summary_id,
            source_cutpoint=self.source_cutpoint,
            exit_targets=self.exit_targets,
            dependency_ids=self.dependency_ids,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.witness_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "TransitionControlWitnessV2":
        row = _object(
            value,
            {
                "dependency_ids",
                "exit_targets",
                "id",
                "source_cutpoint",
                "summary_id",
            },
            "transition control witness",
        )
        return cls(
            summary_id=_text(row["summary_id"], "canonical transition summary ID"),
            source_cutpoint=_text(
                row["source_cutpoint"], "transition source", maximum=512
            ),
            exit_targets=tuple(
                ExitTargetSetV2.parse(item)
                for item in _array(row["exit_targets"], "exit target sets")
            ),
            dependency_ids=_parse_strings(
                row["dependency_ids"], "transition dependencies", maximum=512
            ),
            witness_id=_text(row["id"], "transition control witness ID"),
        )

    @property
    def target_cutpoints(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    target
                    for exit_targets in self.exit_targets
                    for target in exit_targets.target_cutpoints
                }
            )
        )


def _control_witness_payload(**fields: Any) -> dict[str, Any]:
    return {
        "dependency_ids": list(fields["dependency_ids"]),
        "exit_targets": [row.to_payload() for row in fields["exit_targets"]],
        "source_cutpoint": fields["source_cutpoint"],
        "summary_id": fields["summary_id"],
    }


@dataclass(frozen=True)
class TransitionWitnessInventoryV2:
    """Exact canonical summaries plus certificate-side control witnesses."""

    binary: BinaryBinding
    structural_universe_sha256: str
    summaries: tuple[TransitionSummaryV2, ...]
    control_witnesses: tuple[TransitionControlWitnessV2, ...]
    inventory_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary, BinaryBinding):
            raise InvariantCertificateV2Error(
                "transition inventory requires a binary binding"
            )
        _digest(self.structural_universe_sha256, "structural universe binding")
        if self.summaries != tuple(
            sorted(self.summaries, key=lambda item: item.summary_id)
        ) or len({summary.summary_id for summary in self.summaries}) != len(
            self.summaries
        ):
            raise InvariantCertificateV2Error(
                "canonical summaries are duplicated or noncanonical"
            )
        if self.control_witnesses != tuple(
            sorted(self.control_witnesses, key=lambda item: item.witness_id)
        ) or len({row.witness_id for row in self.control_witnesses}) != len(
            self.control_witnesses
        ):
            raise InvariantCertificateV2Error(
                "control witnesses are duplicated or noncanonical"
            )
        by_summary = {summary.summary_id: summary for summary in self.summaries}
        if len({summary.unit.unit_id for summary in self.summaries}) != len(
            self.summaries
        ):
            raise InvariantCertificateV2Error(
                "canonical summaries duplicate a structural unit"
            )
        for summary in self.summaries:
            if summary.unit.binary != self.binary:
                raise InvariantCertificateV2Error(
                    "summary and inventory binary bindings differ"
                )
        seen_summaries: set[str] = set()
        known_cutpoints = {summary.unit.unit_id for summary in self.summaries}
        for witness in self.control_witnesses:
            summary = by_summary.get(witness.summary_id)
            if summary is None or witness.source_cutpoint != summary.unit.unit_id:
                raise InvariantCertificateV2Error(
                    "control witness contradicts its canonical summary"
                )
            if witness.summary_id in seen_summaries:
                raise InvariantCertificateV2Error(
                    "canonical summary has multiple control witnesses"
                )
            seen_summaries.add(witness.summary_id)
            expected_exit_ids = {row.exit_id for row in summary.exits}
            if {row.exit_id for row in witness.exit_targets} != expected_exit_ids:
                raise InvariantCertificateV2Error(
                    "control witness does not cover every exact exit"
                )
            if any(target not in known_cutpoints for target in witness.target_cutpoints):
                raise InvariantCertificateV2Error(
                    "control witness references an unknown cutpoint"
                )
        if self.inventory_id != _identity(
            "transition-witness-inventory", self.identity_payload()
        ):
            raise InvariantCertificateV2Error(
                "transition witness inventory ID is stale"
            )

    @classmethod
    def create(
        cls,
        *,
        binary: BinaryBinding,
        structural_universe_sha256: str,
        summaries: Sequence[TransitionSummaryV2],
        control_witnesses: Sequence[TransitionControlWitnessV2],
    ) -> "TransitionWitnessInventoryV2":
        fields = {
            "binary": binary,
            "structural_universe_sha256": structural_universe_sha256,
            "summaries": tuple(
                sorted(summaries, key=lambda item: item.summary_id)
            ),
            "control_witnesses": tuple(
                sorted(control_witnesses, key=lambda item: item.witness_id)
            ),
        }
        return cls(
            **fields,
            inventory_id=_identity(
                "transition-witness-inventory",
                _transition_inventory_payload(**fields),
            ),
        )

    @property
    def cutpoints(self) -> tuple[str, ...]:
        return tuple(sorted(summary.unit.unit_id for summary in self.summaries))

    @property
    def complete_sources(self) -> tuple[str, ...]:
        witnessed = {row.summary_id for row in self.control_witnesses}
        return tuple(
            sorted(
                summary.unit.unit_id
                for summary in self.summaries
                if summary.status == "complete" and summary.summary_id in witnessed
            )
        )

    def identity_payload(self) -> dict[str, Any]:
        return _transition_inventory_payload(
            binary=self.binary,
            structural_universe_sha256=self.structural_universe_sha256,
            summaries=self.summaries,
            control_witnesses=self.control_witnesses,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": TRANSITION_WITNESS_INVENTORY_V2_FORMAT,
            "id": self.inventory_id,
            "binary": self.binary.to_payload(),
            "control_witnesses": [
                row.to_payload() for row in self.control_witnesses
            ],
            "structural_universe_sha256": self.structural_universe_sha256,
            "summaries": [
                summary.to_payload() for summary in self.summaries
            ],
        }

    @classmethod
    def parse(cls, value: Any) -> "TransitionWitnessInventoryV2":
        row = _object(
            value,
            {
                "binary",
                "control_witnesses",
                "format",
                "id",
                "structural_universe_sha256",
                "summaries",
            },
            "transition witness inventory",
        )
        if row["format"] != TRANSITION_WITNESS_INVENTORY_V2_FORMAT:
            raise InvariantCertificateV2Error(
                "transition witness inventory format is unsupported"
            )
        return cls(
            binary=BinaryBinding.parse(row["binary"]),
            structural_universe_sha256=_digest(
                row["structural_universe_sha256"],
                "structural universe binding",
            ),
            summaries=tuple(
                TransitionSummaryV2.parse(item)
                for item in _array(row["summaries"], "canonical summaries")
            ),
            control_witnesses=tuple(
                TransitionControlWitnessV2.parse(item)
                for item in _array(
                    row["control_witnesses"], "transition control witnesses"
                )
            ),
            inventory_id=_text(row["id"], "transition witness inventory ID"),
        )


def _transition_inventory_payload(**fields: Any) -> dict[str, Any]:
    return {
        "binary": fields["binary"].to_payload(),
        "control_witnesses": [
            row.to_payload() for row in fields["control_witnesses"]
        ],
        "structural_universe_sha256": fields["structural_universe_sha256"],
        "summary_ids": [
            summary.summary_id for summary in fields["summaries"]
        ],
    }


def _transition_pairs(
    inventory: TransitionWitnessInventoryV2,
) -> tuple[tuple[TransitionSummaryV2, TransitionControlWitnessV2], ...]:
    by_summary = {summary.summary_id: summary for summary in inventory.summaries}
    return tuple(
        (by_summary[witness.summary_id], witness)
        for witness in inventory.control_witnesses
    )


def _outcome_exit(summary: TransitionSummaryV2) -> Any:
    outcomes = tuple(
        exit_row for exit_row in summary.exits if exit_row.source_kind == "outcome"
    )
    if len(outcomes) != 1:
        raise InvariantCertificateV2Error(
            "canonical transition summary has no unique outcome"
        )
    return outcomes[0]


def check_transition_witness_inventory_v2(
    value: TransitionWitnessInventoryV2 | Mapping[str, Any],
    *,
    canonical_summaries: Sequence[TransitionSummaryV2],
    binary: BinaryBinding,
    structural_universe_sha256: str,
    dependency_nodes: Sequence[DependencyNodeV2] = (),
    source_cutpoints: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Recheck one serialized witness phase against canonical summary authority."""

    try:
        submitted = (
            value
            if isinstance(value, TransitionWitnessInventoryV2)
            else TransitionWitnessInventoryV2.parse(value)
        )
        canonical = tuple(
            sorted(canonical_summaries, key=lambda summary: summary.summary_id)
        )
        expected = TransitionWitnessInventoryV2.create(
            binary=binary,
            structural_universe_sha256=structural_universe_sha256,
            summaries=canonical,
            control_witnesses=submitted.control_witnesses,
        )
    except (AuthorityDataError, TypeError, ValueError) as exc:
        return _phase_report(
            None, [_issue("violated", "witness_inventory_malformed", str(exc))]
        )
    issues: list[dict[str, str]] = []
    if submitted.binary != binary:
        issues.append(_issue("violated", "binary_binding_contradiction"))
    if submitted.structural_universe_sha256 != structural_universe_sha256:
        issues.append(
            _issue("violated", "structural_universe_binding_contradiction")
        )
    if submitted.summaries != canonical:
        issues.append(_issue("violated", "canonical_summary_inventory_contradiction"))
    if submitted != expected:
        issues.append(_issue("violated", "witness_inventory_identity_contradiction"))
    _check_control_witness_bindings(
        expected,
        dependency_nodes=dependency_nodes,
        source_cutpoints=(
            expected.cutpoints if source_cutpoints is None else source_cutpoints
        ),
        issues=issues,
    )
    return _phase_report(submitted.inventory_id, issues)


def _phase_report(
    inventory_id: str | None, issues: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    normalized = sorted(
        {
            canonical_json_bytes(issue): dict(issue)
            for issue in issues
        }.values(),
        key=_canonical_key,
    )
    status = (
        "violated"
        if any(issue["status"] == "violated" for issue in normalized)
        else "incomplete"
        if normalized
        else "complete"
    )
    payload = {
        "format": "spaghetti-extractor-transition-witness-check-v2",
        "inventory_id": inventory_id,
        "status": status,
        "authorizing": status == "complete",
        "issues": normalized,
    }
    return {**payload, "report_sha256": canonical_sha256(payload)}


@dataclass(frozen=True, order=True)
class CutpointInvariantV2:
    cutpoint: str
    facts: tuple[InvariantFactV2, ...]

    def __post_init__(self) -> None:
        _text(self.cutpoint, "invariant cutpoint", maximum=512)
        _canonical_facts(self.facts, "cutpoint facts")

    def to_payload(self) -> dict[str, Any]:
        return {
            "cutpoint": self.cutpoint,
            "facts": [fact.to_payload() for fact in self.facts],
        }

    @classmethod
    def parse(cls, value: Any) -> "CutpointInvariantV2":
        row = _object(value, {"cutpoint", "facts"}, "cutpoint invariant")
        return cls(
            cutpoint=_text(row["cutpoint"], "invariant cutpoint", maximum=512),
            facts=_parse_facts(row["facts"], "cutpoint facts"),
        )


@dataclass(frozen=True, order=True)
class EntryFactsV2:
    """Checked root or predecessor facts supplied independently of a proposal."""

    entry_id: str
    kind: str
    target_cutpoint: str
    transition_id: str | None
    facts: tuple[InvariantFactV2, ...]
    exit_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.entry_id, "entry fact ID", maximum=512)
        if self.kind not in {"root", "incoming"}:
            raise InvariantCertificateV2Error("entry fact kind is unsupported")
        _text(self.target_cutpoint, "entry target", maximum=512)
        if self.kind == "root":
            if self.transition_id is not None or self.exit_id is not None:
                raise InvariantCertificateV2Error(
                    "root entry cannot bind an incoming transition"
                )
        elif self.transition_id is None or self.exit_id is None:
            raise InvariantCertificateV2Error(
                "incoming entry requires transition and exit IDs"
            )
        else:
            _text(self.transition_id, "entry transition ID")
            _text(self.exit_id, "entry exit ID")
        _canonical_facts(self.facts, "entry facts")

    def to_payload(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "facts": [fact.to_payload() for fact in self.facts],
            "kind": self.kind,
            "target_cutpoint": self.target_cutpoint,
            "transition_id": self.transition_id,
            "exit_id": self.exit_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "EntryFactsV2":
        row = _object(
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
        transition = row["transition_id"]
        if transition is not None:
            transition = _text(transition, "entry transition ID")
        exit_id = row["exit_id"]
        if exit_id is not None:
            exit_id = _text(exit_id, "entry exit ID")
        return cls(
            entry_id=_text(row["entry_id"], "entry fact ID", maximum=512),
            kind=_text(row["kind"], "entry fact kind"),
            target_cutpoint=_text(
                row["target_cutpoint"], "entry target", maximum=512
            ),
            transition_id=transition,
            facts=_parse_facts(row["facts"], "entry facts"),
            exit_id=exit_id,
        )


@dataclass(frozen=True, order=True)
class ExportRequirementV2:
    cutpoint: str
    fact: InvariantFactV2
    export_id: str

    def __post_init__(self) -> None:
        _text(self.cutpoint, "export cutpoint", maximum=512)
        if not isinstance(self.fact, InvariantFactV2):
            raise InvariantCertificateV2Error("export requires a typed fact")
        expected = _identity(
            "invariant-export",
            {"cutpoint": self.cutpoint, "fact": self.fact.to_payload()},
        )
        if self.export_id != expected:
            raise InvariantCertificateV2Error("export ID is stale")

    @classmethod
    def create(
        cls, cutpoint: str, fact: InvariantFactV2
    ) -> "ExportRequirementV2":
        payload = {"cutpoint": cutpoint, "fact": fact.to_payload()}
        return cls(cutpoint, fact, _identity("invariant-export", payload))

    def to_payload(self) -> dict[str, Any]:
        return {
            "cutpoint": self.cutpoint,
            "fact": self.fact.to_payload(),
            "id": self.export_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "ExportRequirementV2":
        row = _object(value, {"cutpoint", "fact", "id"}, "invariant export")
        return cls(
            cutpoint=_text(row["cutpoint"], "export cutpoint", maximum=512),
            fact=InvariantFactV2.parse(row["fact"]),
            export_id=_text(row["id"], "export ID"),
        )


@dataclass(frozen=True)
class InvariantCertificateV2:
    """A non-authorizing bounded invariant proposal."""

    binary: BinaryBinding
    profile_sha256: str
    transition_inventory_id: str
    dependency_scc_id: str
    members: tuple[str, ...]
    control_inventory: CanonicalJson
    cutpoint_invariants: tuple[CutpointInvariantV2, ...]
    initiation: tuple[str, ...]
    preservation: tuple[str, ...]
    target_coverage: CanonicalJson
    exports: tuple[ExportRequirementV2, ...]
    dependencies: tuple[str, ...]
    budgets: InvariantBudgetsV2
    certificate_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary, BinaryBinding):
            raise InvariantCertificateV2Error(
                "certificate requires a binary binding"
            )
        _digest(self.profile_sha256, "profile binding")
        _text(self.transition_inventory_id, "transition inventory ID")
        _text(self.dependency_scc_id, "dependency SCC ID")
        _canonical_strings(self.members, "certificate members", maximum=512)
        if not isinstance(self.control_inventory, CanonicalJson):
            raise InvariantCertificateV2Error(
                "control inventory must be canonical JSON"
            )
        if self.cutpoint_invariants != tuple(
            sorted(
                set(self.cutpoint_invariants),
                key=lambda invariant: invariant.cutpoint,
            )
        ):
            raise InvariantCertificateV2Error(
                "cutpoint invariants are noncanonical"
            )
        _canonical_strings(self.initiation, "initiation inventory", maximum=768)
        _canonical_strings(
            self.preservation, "preservation inventory", maximum=768
        )
        if not isinstance(self.target_coverage, CanonicalJson):
            raise InvariantCertificateV2Error(
                "target coverage must be canonical JSON"
            )
        if self.exports != tuple(
            sorted(set(self.exports), key=lambda item: item.export_id)
        ):
            raise InvariantCertificateV2Error("exports are noncanonical")
        _canonical_strings(
            self.dependencies, "certificate dependencies", maximum=512
        )
        if not isinstance(self.budgets, InvariantBudgetsV2):
            raise InvariantCertificateV2Error(
                "certificate requires typed finite budgets"
            )
        if self.certificate_id != _identity(
            "invariant-certificate", self.identity_payload()
        ):
            raise InvariantCertificateV2Error("certificate ID is stale")

    @classmethod
    def create(cls, **fields: Any) -> "InvariantCertificateV2":
        normalized = {
            **fields,
            "members": tuple(fields["members"]),
            "cutpoint_invariants": tuple(fields["cutpoint_invariants"]),
            "initiation": tuple(fields["initiation"]),
            "preservation": tuple(fields["preservation"]),
            "exports": tuple(fields["exports"]),
            "dependencies": tuple(fields["dependencies"]),
        }
        payload = _certificate_payload(**normalized)
        return cls(
            **normalized,
            certificate_id=_identity("invariant-certificate", payload),
        )

    def identity_payload(self) -> dict[str, Any]:
        return _certificate_payload(
            binary=self.binary,
            profile_sha256=self.profile_sha256,
            transition_inventory_id=self.transition_inventory_id,
            dependency_scc_id=self.dependency_scc_id,
            members=self.members,
            control_inventory=self.control_inventory,
            cutpoint_invariants=self.cutpoint_invariants,
            initiation=self.initiation,
            preservation=self.preservation,
            target_coverage=self.target_coverage,
            exports=self.exports,
            dependencies=self.dependencies,
            budgets=self.budgets,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": INVARIANT_CERTIFICATE_PROPOSAL_V2_FORMAT,
            "id": self.certificate_id,
            **self.identity_payload(),
        }

    @classmethod
    def parse(cls, value: Any) -> "InvariantCertificateV2":
        fields = {
            "binary",
            "budgets",
            "control_inventory",
            "cutpoint_invariants",
            "dependencies",
            "dependency_scc_id",
            "exports",
            "format",
            "id",
            "initiation",
            "members",
            "preservation",
            "profile_sha256",
            "target_coverage",
            "transition_inventory_id",
        }
        row = _object(value, fields, "invariant certificate proposal")
        if row["format"] != INVARIANT_CERTIFICATE_PROPOSAL_V2_FORMAT:
            raise InvariantCertificateV2Error(
                "invariant certificate format is unsupported"
            )
        return cls(
            binary=BinaryBinding.parse(row["binary"]),
            profile_sha256=_digest(row["profile_sha256"], "profile binding"),
            transition_inventory_id=_text(
                row["transition_inventory_id"], "transition inventory ID"
            ),
            dependency_scc_id=_text(
                row["dependency_scc_id"], "dependency SCC ID"
            ),
            members=_parse_strings(
                row["members"], "certificate members", maximum=512
            ),
            control_inventory=CanonicalJson.of(row["control_inventory"]),
            cutpoint_invariants=tuple(
                CutpointInvariantV2.parse(item)
                for item in _array(
                    row["cutpoint_invariants"], "cutpoint invariants"
                )
            ),
            initiation=_parse_strings(
                row["initiation"], "initiation inventory", maximum=768
            ),
            preservation=_parse_strings(
                row["preservation"], "preservation inventory", maximum=768
            ),
            target_coverage=CanonicalJson.of(row["target_coverage"]),
            exports=tuple(
                ExportRequirementV2.parse(item)
                for item in _array(row["exports"], "exports")
            ),
            dependencies=_parse_strings(
                row["dependencies"], "certificate dependencies", maximum=512
            ),
            budgets=InvariantBudgetsV2.parse(row["budgets"]),
            certificate_id=_text(row["id"], "certificate ID"),
        )


def _certificate_payload(**fields: Any) -> dict[str, Any]:
    return {
        "binary": fields["binary"].to_payload(),
        "budgets": fields["budgets"].to_payload(),
        "control_inventory": fields["control_inventory"].to_value(),
        "cutpoint_invariants": [
            invariant.to_payload() for invariant in fields["cutpoint_invariants"]
        ],
        "dependencies": list(fields["dependencies"]),
        "dependency_scc_id": fields["dependency_scc_id"],
        "exports": [item.to_payload() for item in fields["exports"]],
        "initiation": list(fields["initiation"]),
        "members": list(fields["members"]),
        "preservation": list(fields["preservation"]),
        "profile_sha256": fields["profile_sha256"],
        "target_coverage": fields["target_coverage"].to_value(),
        "transition_inventory_id": fields["transition_inventory_id"],
    }


@dataclass
class InvariantCertificateContextV2:
    """One checked, indexed view shared by every SCC certificate in a phase.

    This object is deliberately not serializable.  It is reconstructed from
    the exact transition inventory and typed dependency graph in each checker
    process, so generated certificates cannot submit or forge its indexes.
    """

    transition_inventory: TransitionWitnessInventoryV2
    canonical_summaries: tuple[TransitionSummaryV2, ...]
    dependency_nodes: tuple[DependencyNodeV2, ...]
    dependency_edges: tuple[DependencyEdgeV2, ...]
    dependency_sccs: Mapping[tuple[str, ...], TypedDependencySCCV2]
    pairs_by_source: Mapping[
        str, tuple[TransitionSummaryV2, TransitionControlWitnessV2]
    ]
    transition_by_id: Mapping[
        str, tuple[TransitionSummaryV2, TransitionControlWitnessV2]
    ]
    edge_rows_by_source: Mapping[str, tuple[dict[str, Any], ...]]
    incoming_rows_by_target: Mapping[str, tuple[dict[str, Any], ...]]
    known_dependency_ids: frozenset[str]
    available_dependency_ids: frozenset[str]
    global_issues: tuple[dict[str, str], ...]
    source_issues: Mapping[str, tuple[dict[str, str], ...]]

    @classmethod
    def create(
        cls,
        *,
        transition_inventory: TransitionWitnessInventoryV2,
        canonical_summaries: Sequence[TransitionSummaryV2],
        dependency_nodes: Sequence[DependencyNodeV2],
        dependency_edges: Sequence[DependencyEdgeV2],
        memory_version_graph: MemoryVersionGraphV2 | None = None,
        dependency_discharges: Sequence[DependencyDischargeV2] = (),
    ) -> "InvariantCertificateContextV2":
        canonical = tuple(
            sorted(canonical_summaries, key=lambda summary: summary.summary_id)
        )
        nodes = tuple(dependency_nodes)
        edges = tuple(dependency_edges)
        report = check_transition_witness_inventory_v2(
            transition_inventory,
            canonical_summaries=canonical,
            binary=transition_inventory.binary,
            structural_universe_sha256=(
                transition_inventory.structural_universe_sha256
            ),
            dependency_nodes=nodes,
            source_cutpoints=transition_inventory.cutpoints,
        )
        # Structural contradictions invalidate the shared index globally.
        # Ordinary incompleteness remains source-local and is reported by the
        # rooted orchestration/checks, so an unreachable frontier cannot block
        # an otherwise closed rooted certificate.
        issues = [
            dict(row)
            for row in report["issues"]
            if row.get("status") == "violated"
        ]
        if memory_version_graph is not None:
            expected_summary_ids = tuple(
                summary.summary_id for summary in canonical
            )
            if memory_version_graph.binary != transition_inventory.binary:
                issues.append(_issue(
                    "violated", "memory_graph_binary_binding_contradiction"
                ))
            if memory_version_graph.transition_summary_ids != expected_summary_ids:
                issues.append(_issue(
                    "violated", "memory_graph_summary_binding_contradiction"
                ))
        available = set(
            _checked_memory_dependency_ids(nodes, memory_version_graph)
        )
        discharged, discharge_issues = _checked_dependency_discharge_ids(
            nodes, dependency_discharges
        )
        available.update(discharged)
        issues.extend(discharge_issues)
        source_issues: dict[str, tuple[dict[str, str], ...]] = {}
        _check_control_witness_bindings(
            transition_inventory,
            dependency_nodes=nodes,
            source_cutpoints=transition_inventory.cutpoints,
            issues=[],
            issues_by_source=source_issues,
        )

        dependency_sccs = {
            row.members: row
            for row in derive_typed_dependency_sccs_v2(nodes, edges)
        }
        pairs_by_source: dict[
            str, tuple[TransitionSummaryV2, TransitionControlWitnessV2]
        ] = {}
        transition_by_id: dict[
            str, tuple[TransitionSummaryV2, TransitionControlWitnessV2]
        ] = {}
        rows_by_source: dict[str, list[dict[str, Any]]] = {}
        rows_by_target: dict[str, list[dict[str, Any]]] = {}
        for summary, witness in _transition_pairs(transition_inventory):
            pair = (summary, witness)
            pairs_by_source[witness.source_cutpoint] = pair
            transition_by_id[witness.witness_id] = pair
            exits_by_id = {row.exit_id: row for row in summary.exits}
            source_rows = rows_by_source.setdefault(
                witness.source_cutpoint, []
            )
            for target_set in witness.exit_targets:
                exit_row = exits_by_id[target_set.exit_id]
                targets: tuple[str | None, ...] = (
                    target_set.target_cutpoints
                    if target_set.target_cutpoints
                    else (None,)
                )
                for target in targets:
                    row = _edge_row(
                        summary, witness, exit_row, target
                    )
                    source_rows.append(row)
                    if target is not None:
                        rows_by_target.setdefault(target, []).append(row)
        return cls(
            transition_inventory=transition_inventory,
            canonical_summaries=canonical,
            dependency_nodes=nodes,
            dependency_edges=edges,
            dependency_sccs=dependency_sccs,
            pairs_by_source=pairs_by_source,
            transition_by_id=transition_by_id,
            edge_rows_by_source={
                key: tuple(sorted(value, key=_canonical_key))
                for key, value in rows_by_source.items()
            },
            incoming_rows_by_target={
                key: tuple(sorted(value, key=_canonical_key))
                for key, value in rows_by_target.items()
            },
            known_dependency_ids=frozenset(
                node.node_id for node in nodes
            ),
            available_dependency_ids=frozenset(available),
            global_issues=tuple(sorted(
                {
                    canonical_json_bytes(row): row for row in issues
                }.values(),
                key=_canonical_key,
            )),
            source_issues=source_issues,
        )

    def select_dependency_scc(
        self, requested_members: Sequence[str]
    ) -> TypedDependencySCCV2:
        members = tuple(sorted(set(requested_members)))
        result = self.dependency_sccs.get(members)
        if result is None:
            raise InvariantCertificateV2Error(
                "requested dependency members do not form one exact SCC"
            )
        return result

    def control_inventory(
        self, member_cutpoints: Sequence[str]
    ) -> dict[str, Any]:
        members = tuple(sorted(set(member_cutpoints)))
        if not members or any(
            member not in self.pairs_by_source for member in members
        ):
            raise InvariantCertificateV2Error(
                "control members must be known nonempty cutpoints"
            )
        member_set = frozenset(members)
        internal: list[dict[str, Any]] = []
        outgoing: list[dict[str, Any]] = []
        for source in members:
            for row in self.edge_rows_by_source.get(source, ()):
                target = row["target_cutpoint"]
                if target is not None and target in member_set:
                    internal.append(row)
                else:
                    outgoing.append(row)
        incoming = [
            row
            for target in members
            for row in self.incoming_rows_by_target.get(target, ())
            if row["source_cutpoint"] not in member_set
        ]
        return {
            "incoming": sorted(incoming, key=_canonical_key),
            "internal": sorted(internal, key=_canonical_key),
            "member_transitions": sorted(
                self.pairs_by_source[member][1].witness_id
                for member in members
            ),
            "members": list(members),
            "outgoing": sorted(outgoing, key=_canonical_key),
        }

    def target_coverage(
        self, members: Sequence[str]
    ) -> list[dict[str, Any]]:
        return _derive_target_coverage_from_pairs(
            tuple(
                self.pairs_by_source[member]
                for member in sorted(set(members))
            )
        )

    def dependencies(
        self,
        members: Sequence[str],
        dependency_scc: TypedDependencySCCV2,
    ) -> tuple[str, ...]:
        values = {
            dependency
            for member in sorted(set(members))
            for _summary, witness in (self.pairs_by_source[member],)
            for dependency in (
                *witness.dependency_ids,
                *(
                    dependency
                    for target_set in witness.exit_targets
                    for dependency in target_set.dependency_ids
                ),
            )
        }
        values.update(
            edge.source_id for edge in dependency_scc.incoming_edges
        )
        return tuple(sorted(values))


def synthesize_invariant_certificate_v2(
    *,
    transition_inventory: TransitionWitnessInventoryV2,
    dependency_nodes: Sequence[DependencyNodeV2],
    dependency_edges: Sequence[DependencyEdgeV2],
    member_cutpoints: Sequence[str],
    dependency_members: Sequence[str],
    cutpoint_facts: Mapping[str, Sequence[InvariantFactV2]],
    entry_facts: Sequence[EntryFactsV2],
    required_exports: Sequence[ExportRequirementV2] = (),
    profile_sha256: str,
    budgets: InvariantBudgetsV2 = InvariantBudgetsV2(),
    context: InvariantCertificateContextV2 | None = None,
) -> InvariantCertificateV2:
    """Deterministically package a non-authorizing invariant proposal."""

    _digest(profile_sha256, "profile binding")
    members = tuple(sorted(set(member_cutpoints)))
    checked = context or InvariantCertificateContextV2.create(
        transition_inventory=transition_inventory,
        canonical_summaries=transition_inventory.summaries,
        dependency_nodes=dependency_nodes,
        dependency_edges=dependency_edges,
    )
    _require_context_bindings(
        checked,
        transition_inventory=transition_inventory,
        dependency_nodes=dependency_nodes,
        dependency_edges=dependency_edges,
    )
    dependency_scc = checked.select_dependency_scc(dependency_members)
    control = checked.control_inventory(members)
    invariants = tuple(
        CutpointInvariantV2(
            cutpoint,
            tuple(sorted(set(cutpoint_facts.get(cutpoint, ())))),
        )
        for cutpoint in members
        if cutpoint in cutpoint_facts
    )
    initiation = tuple(
        sorted(
            _entry_witness_id(entry)
            for entry in entry_facts
            if entry.target_cutpoint in set(members)
        )
    )
    preservation = tuple(
        sorted(_edge_witness_id(row) for row in control["internal"])
    )
    target_coverage = checked.target_coverage(members)
    dependencies = checked.dependencies(members, dependency_scc)
    return InvariantCertificateV2.create(
        binary=transition_inventory.binary,
        profile_sha256=profile_sha256,
        transition_inventory_id=transition_inventory.inventory_id,
        dependency_scc_id=dependency_scc.scc_id,
        members=members,
        control_inventory=CanonicalJson.of(control),
        cutpoint_invariants=invariants,
        initiation=initiation,
        preservation=preservation,
        target_coverage=CanonicalJson.of(target_coverage),
        exports=tuple(
            sorted(set(required_exports), key=lambda item: item.export_id)
        ),
        dependencies=dependencies,
        budgets=budgets,
    )


def derive_control_inventory_v2(
    transition_inventory: TransitionWitnessInventoryV2,
    member_cutpoints: Sequence[str],
) -> dict[str, Any]:
    """Derive all member, internal, incoming, and outgoing rows exactly."""

    members = tuple(sorted(set(member_cutpoints)))
    if not members or any(
        member not in transition_inventory.cutpoints for member in members
    ):
        raise InvariantCertificateV2Error(
            "control members must be known nonempty cutpoints"
        )
    member_set = frozenset(members)
    member_transitions: list[str] = []
    internal: list[dict[str, Any]] = []
    incoming: list[dict[str, Any]] = []
    outgoing: list[dict[str, Any]] = []
    for summary, witness in _transition_pairs(transition_inventory):
        source_inside = witness.source_cutpoint in member_set
        if source_inside:
            member_transitions.append(witness.witness_id)
        exits_by_id = {row.exit_id: row for row in summary.exits}
        for target_set in witness.exit_targets:
            exit_row = exits_by_id[target_set.exit_id]
            if not target_set.target_cutpoints and source_inside:
                outgoing.append(
                    _edge_row(summary, witness, exit_row, None)
                )
            for target in target_set.target_cutpoints:
                target_inside = target in member_set
                row = _edge_row(summary, witness, exit_row, target)
                if source_inside and target_inside:
                    internal.append(row)
                elif source_inside:
                    outgoing.append(row)
                elif target_inside:
                    incoming.append(row)
    return {
        "incoming": sorted(incoming, key=_canonical_key),
        "internal": sorted(internal, key=_canonical_key),
        "member_transitions": sorted(member_transitions),
        "members": list(members),
        "outgoing": sorted(outgoing, key=_canonical_key),
    }


def _edge_row(
    summary: TransitionSummaryV2,
    witness: TransitionControlWitnessV2,
    exit_row: Any,
    target: str | None,
) -> dict[str, Any]:
    return {
        "exit_id": exit_row.exit_id,
        "source_cutpoint": witness.source_cutpoint,
        "summary_id": summary.summary_id,
        "target_cutpoint": target,
        "transfer_kind": exit_row.transfer_kind,
        "transition_id": witness.witness_id,
    }


def _canonical_key(value: Any) -> bytes:
    return canonical_json_bytes(value)


def _edge_witness_id(row: Mapping[str, Any]) -> str:
    return _identity("preservation", row)


def _entry_witness_id(entry: EntryFactsV2) -> str:
    return _identity("initiation", entry.to_payload())


def _derive_target_coverage(
    transition_inventory: TransitionWitnessInventoryV2,
    members: Sequence[str],
) -> list[dict[str, Any]]:
    member_set = frozenset(members)
    return _derive_target_coverage_from_pairs(tuple(
        (summary, witness)
        for summary, witness in _transition_pairs(transition_inventory)
        if witness.source_cutpoint in member_set
    ))


def _derive_target_coverage_from_pairs(
    pairs: Sequence[
        tuple[TransitionSummaryV2, TransitionControlWitnessV2]
    ],
) -> list[dict[str, Any]]:
    return [
        {
            "exit_id": exit_row.exit_id,
            "summary_id": summary.summary_id,
            "targets": list(target_set.target_cutpoints),
            "transition_id": witness.witness_id,
        }
        for summary, witness in pairs
        for exit_row in summary.exits
        for target_set in witness.exit_targets
        if target_set.exit_id == exit_row.exit_id
        and "indirect" in exit_row.transfer_kind
    ]


def _require_context_bindings(
    context: InvariantCertificateContextV2,
    *,
    transition_inventory: TransitionWitnessInventoryV2,
    dependency_nodes: Sequence[DependencyNodeV2],
    dependency_edges: Sequence[DependencyEdgeV2],
    canonical_summaries: Sequence[TransitionSummaryV2] | None = None,
) -> None:
    if context.transition_inventory != transition_inventory:
        raise InvariantCertificateV2Error(
            "invariant checker context binds a different transition inventory"
        )
    if context.dependency_nodes != tuple(dependency_nodes) or (
        context.dependency_edges != tuple(dependency_edges)
    ):
        raise InvariantCertificateV2Error(
            "invariant checker context binds a different dependency graph"
        )
    if canonical_summaries is not None and context.canonical_summaries != tuple(
        sorted(canonical_summaries, key=lambda summary: summary.summary_id)
    ):
        raise InvariantCertificateV2Error(
            "invariant checker context binds different canonical summaries"
        )


def _derive_dependencies(
    transition_inventory: TransitionWitnessInventoryV2,
    members: Sequence[str],
    dependency_scc: TypedDependencySCCV2,
) -> tuple[str, ...]:
    member_set = frozenset(members)
    values = {
        dependency
        for _summary, witness in _transition_pairs(transition_inventory)
        if witness.source_cutpoint in member_set
        for dependency in (
            *witness.dependency_ids,
            *(
                dependency
                for target_set in witness.exit_targets
                for dependency in target_set.dependency_ids
            ),
        )
    }
    values.update(edge.source_id for edge in dependency_scc.incoming_edges)
    return tuple(sorted(values))


def _select_dependency_scc(
    nodes: Sequence[DependencyNodeV2],
    edges: Sequence[DependencyEdgeV2],
    requested_members: Sequence[str],
) -> TypedDependencySCCV2:
    members = tuple(sorted(set(requested_members)))
    for component in derive_typed_dependency_sccs_v2(nodes, edges):
        if component.members == members:
            return component
    raise InvariantCertificateV2Error(
        "requested dependency members do not form one exact SCC"
    )


def check_invariant_certificate_v2(
    certificate: InvariantCertificateV2 | Mapping[str, Any],
    *,
    transition_inventory: TransitionWitnessInventoryV2,
    canonical_summaries: Sequence[TransitionSummaryV2],
    dependency_nodes: Sequence[DependencyNodeV2],
    dependency_edges: Sequence[DependencyEdgeV2],
    dependency_discharges: Sequence[DependencyDischargeV2] = (),
    memory_version_graph: MemoryVersionGraphV2 | None = None,
    expected_member_cutpoints: Sequence[str],
    expected_dependency_members: Sequence[str],
    entry_facts: Sequence[EntryFactsV2],
    required_exports: Sequence[ExportRequirementV2] = (),
    profile_sha256: str,
    budgets: InvariantBudgetsV2 = InvariantBudgetsV2(),
    context: InvariantCertificateContextV2 | None = None,
) -> dict[str, Any]:
    """Independently check a bounded induction proposal.

    Submitted transition, target, and dependency inventories are never used as
    authority.  They are compared with inventories reconstructed from the
    supplied exact summaries and typed dependency graph.
    """

    try:
        proposal = (
            certificate
            if isinstance(certificate, InvariantCertificateV2)
            else InvariantCertificateV2.parse(certificate)
        )
    except (AuthorityDataError, TypeError, ValueError) as exc:
        return _report(
            None,
            [_issue("violated", "certificate_malformed", str(exc))],
        )

    checked = context or InvariantCertificateContextV2.create(
        transition_inventory=transition_inventory,
        canonical_summaries=canonical_summaries,
        dependency_nodes=dependency_nodes,
        dependency_edges=dependency_edges,
        memory_version_graph=memory_version_graph,
        dependency_discharges=dependency_discharges,
    )
    try:
        _require_context_bindings(
            checked,
            transition_inventory=transition_inventory,
            canonical_summaries=canonical_summaries,
            dependency_nodes=dependency_nodes,
            dependency_edges=dependency_edges,
        )
    except InvariantCertificateV2Error as exc:
        return _report(
            proposal,
            [_issue("violated", "checker_context_contradiction", str(exc))],
        )

    issues: list[dict[str, str]] = [
        dict(row) for row in checked.global_issues
    ]
    obligations: list[dict[str, Any]] = []
    checked_exports: list[dict[str, Any]] = []
    expected_members = tuple(sorted(set(expected_member_cutpoints)))
    issues.extend(
        dict(issue)
        for member in expected_members
        for issue in checked.source_issues.get(member, ())
        if issue.get("status") != "violated"
    )

    if proposal.binary != transition_inventory.binary:
        issues.append(_issue("violated", "binary_binding_contradiction"))
    if proposal.profile_sha256 != profile_sha256:
        issues.append(_issue("violated", "profile_binding_contradiction"))
    if proposal.transition_inventory_id != transition_inventory.inventory_id:
        issues.append(
            _issue("violated", "transition_inventory_binding_contradiction")
        )
    if proposal.budgets != budgets:
        issues.append(_issue("violated", "budget_binding_contradiction"))
    _compare_ordered_inventory(
        proposal.members,
        expected_members,
        "member",
        issues,
    )

    try:
        dependency_scc = checked.select_dependency_scc(
            expected_dependency_members
        )
    except InvariantCertificateV2Error as exc:
        return _report(
            proposal,
            [*issues, _issue("violated", "dependency_graph_corrupt", str(exc))],
        )
    if proposal.dependency_scc_id != dependency_scc.scc_id:
        issues.append(_issue("violated", "dependency_scc_binding_contradiction"))
    expected_invariant_binding = canonical_sha256(
        {"control_scc": list(expected_members)}
    )
    internal_nodes = {
        node.node_id: node
        for node in checked.dependency_nodes
        if node.node_id in dependency_scc.members
    }
    if (
        len(internal_nodes) != 1
        or any(node.kind != "invariant" for node in internal_nodes.values())
        or any(
            node.binding_sha256 != expected_invariant_binding
            for node in internal_nodes.values()
        )
    ):
        issues.append(
            _issue("violated", "invariant_dependency_scc_contradiction")
        )

    try:
        control = checked.control_inventory(expected_members)
    except InvariantCertificateV2Error as exc:
        return _report(
            proposal,
            [*issues, _issue("violated", "control_inventory_corrupt", str(exc))],
        )
    _compare_control_inventory(
        proposal.control_inventory.to_value(), control, issues
    )

    transition_by_id = checked.transition_by_id
    for member in expected_members:
        if member not in transition_inventory.complete_sources:
            issues.append(
                _issue("incomplete", "source_transition_inventory_incomplete", member)
            )

    invariant_by_cutpoint: dict[str, tuple[InvariantFactV2, ...]] = {}
    for invariant in proposal.cutpoint_invariants:
        if invariant.cutpoint not in expected_members:
            issues.append(
                _issue(
                    "violated",
                    "cutpoint_invariant_contradiction",
                    invariant.cutpoint,
                )
            )
            continue
        if invariant.cutpoint in invariant_by_cutpoint:
            issues.append(
                _issue(
                    "violated",
                    "cutpoint_invariant_duplicate",
                    invariant.cutpoint,
                )
            )
            continue
        invariant_by_cutpoint[invariant.cutpoint] = invariant.facts
        if _facts_contradict(invariant.facts):
            issues.append(
                _issue(
                    "violated",
                    "cutpoint_invariant_contradictory",
                    invariant.cutpoint,
                )
            )
    for member in expected_members:
        if member not in invariant_by_cutpoint:
            issues.append(
                _issue("incomplete", "cutpoint_invariant_missing", member)
            )

    _check_budgets(
        budgets,
        members=expected_members,
        transitions=control["member_transitions"],
        invariants=invariant_by_cutpoint,
        dependencies=proposal.dependencies,
        issues=issues,
    )

    expected_dependencies = checked.dependencies(
        expected_members, dependency_scc
    )
    known_dependency_ids = checked.known_dependency_ids
    for dependency in expected_dependencies:
        if dependency not in known_dependency_ids:
            issues.append(
                _issue(
                    "violated", "transition_dependency_unknown", dependency
                )
            )
    _compare_ordered_inventory(
        proposal.dependencies,
        expected_dependencies,
        "dependency",
        issues,
    )
    internal_dependencies = frozenset(dependency_scc.members)
    required_external = set(expected_dependencies) - internal_dependencies
    available = set(checked.available_dependency_ids)
    for dependency in sorted(required_external - available):
        issues.append(
            _issue("incomplete", "external_dependency_unavailable", dependency)
        )

    expected_preservation = tuple(
        sorted(_edge_witness_id(row) for row in control["internal"])
    )
    _compare_ordered_inventory(
        proposal.preservation,
        expected_preservation,
        "preservation",
        issues,
    )
    for row in control["internal"]:
        summary, witness = transition_by_id[row["transition_id"]]
        source_facts = invariant_by_cutpoint.get(
            witness.source_cutpoint
        )
        target = str(row["target_cutpoint"])
        target_facts = invariant_by_cutpoint.get(target)
        if source_facts is None or target_facts is None:
            continue
        result = _check_transition_implication(
            source_facts,
            target_facts,
            summary,
            memory_version_graph=memory_version_graph,
        )
        identity = _edge_witness_id(row)
        obligations.append(
            {
                "id": identity,
                "kind": "preservation",
                "status": result["status"],
            }
        )
        if result["status"] != "complete":
            issues.append(
                _issue(
                    str(result["status"]),
                    str(result["code"]),
                    identity,
                )
            )

    _check_initiation_v2(
        proposal,
        control=control,
        transition_by_id=transition_by_id,
        invariant_by_cutpoint=invariant_by_cutpoint,
        entry_facts=entry_facts,
        memory_version_graph=memory_version_graph,
        issues=issues,
        obligations=obligations,
    )
    _check_target_coverage_v2(
        proposal,
        transition_inventory=transition_inventory,
        members=expected_members,
        expected=checked.target_coverage(expected_members),
        budgets=budgets,
        issues=issues,
    )
    checked_exports.extend(
        _check_exports_v2(
            proposal,
            required_exports=required_exports,
            invariant_by_cutpoint=invariant_by_cutpoint,
            issues=issues,
            obligations=obligations,
        )
    )
    return _report(
        proposal,
        issues,
        obligations=obligations,
        checked_exports=checked_exports,
        dependency_scc=dependency_scc,
    )


def _check_initiation_v2(
    proposal: InvariantCertificateV2,
    *,
    control: Mapping[str, Any],
    transition_by_id: Mapping[
        str, tuple[TransitionSummaryV2, TransitionControlWitnessV2]
    ],
    invariant_by_cutpoint: Mapping[str, tuple[InvariantFactV2, ...]],
    entry_facts: Sequence[EntryFactsV2],
    memory_version_graph: MemoryVersionGraphV2 | None,
    issues: list[dict[str, str]],
    obligations: list[dict[str, Any]],
) -> None:
    entries: dict[str, EntryFactsV2] = {}
    for entry in entry_facts:
        if entry.entry_id in entries:
            issues.append(_issue("violated", "entry_fact_duplicate", entry.entry_id))
        entries[entry.entry_id] = entry
    incoming_rows = control["incoming"]
    incoming_keys = {
        (
            str(row["transition_id"]),
            str(row["exit_id"]),
            str(row["target_cutpoint"]),
        )
        for row in incoming_rows
    }
    relevant: list[EntryFactsV2] = []
    for entry in entries.values():
        if entry.target_cutpoint not in invariant_by_cutpoint:
            continue
        if entry.kind == "incoming" and (
            str(entry.transition_id), str(entry.exit_id), entry.target_cutpoint
        ) not in incoming_keys:
            issues.append(
                _issue("violated", "incoming_entry_contradiction", entry.entry_id)
            )
            continue
        relevant.append(entry)
    expected_ids = tuple(sorted(_entry_witness_id(entry) for entry in relevant))
    _compare_ordered_inventory(
        proposal.initiation, expected_ids, "initiation", issues
    )

    entry_by_edge = {
        (
            str(entry.transition_id),
            str(entry.exit_id),
            entry.target_cutpoint,
        ): entry
        for entry in relevant
        if entry.kind == "incoming"
    }
    for key in sorted(incoming_keys):
        if key not in entry_by_edge:
            issues.append(
                _issue(
                    "incomplete",
                    "incoming_initiation_missing",
                    f"{key[0]}:{key[1]}->{key[2]}",
                )
            )
    roots = [entry for entry in relevant if entry.kind == "root"]
    if not incoming_keys and not roots:
        issues.append(_issue("incomplete", "root_initiation_missing"))

    for entry in relevant:
        target_facts = invariant_by_cutpoint[entry.target_cutpoint]
        if _facts_contradict(entry.facts):
            issues.append(
                _issue("violated", "entry_facts_contradictory", entry.entry_id)
            )
            continue
        if entry.kind == "root":
            proved = _facts_imply(entry.facts, target_facts)
        else:
            transition_pair = transition_by_id.get(str(entry.transition_id))
            if transition_pair is None:
                issues.append(
                    _issue(
                        "violated",
                        "incoming_transition_unknown",
                        entry.entry_id,
                    )
                )
                continue
            summary, _witness = transition_pair
            implication = _check_transition_implication(
                entry.facts,
                target_facts,
                summary,
                memory_version_graph=memory_version_graph,
            )
            proved = implication["status"] == "complete"
        status = "complete" if proved else "incomplete"
        obligations.append(
            {"id": _entry_witness_id(entry), "kind": "initiation", "status": status}
        )
        if not proved:
            issues.append(
                _issue("incomplete", "initiation_not_proved", entry.entry_id)
            )


def _check_control_witness_bindings(
    inventory: TransitionWitnessInventoryV2,
    *,
    dependency_nodes: Sequence[DependencyNodeV2],
    source_cutpoints: Sequence[str],
    issues: list[dict[str, str]],
    issues_by_source: dict[str, tuple[dict[str, str], ...]] | None = None,
) -> None:
    """Check CFG and effect dependencies against canonical summary records."""

    by_rva = {summary.unit.rva_start: summary.unit.unit_id for summary in inventory.summaries}
    node_by_id = {node.node_id: node for node in dependency_nodes}
    nodes_by_binding: dict[tuple[str, str], set[str]] = {}
    sources = frozenset(source_cutpoints)
    for node in dependency_nodes:
        nodes_by_binding.setdefault((node.kind, node.binding_sha256), set()).add(
            node.node_id
        )
    for summary, witness in _transition_pairs(inventory):
        if witness.source_cutpoint not in sources:
            continue
        issue_start = len(issues)
        if summary.status != "complete":
            issues.append(
                _issue(
                    "incomplete",
                    "canonical_transition_summary_incomplete",
                    summary.summary_id,
                )
            )
        for dependency in witness.dependency_ids:
            if dependency not in node_by_id:
                issues.append(
                    _issue(
                        "violated",
                        "transition_dependency_unknown",
                        dependency,
                    )
                )
        for access in summary.memory_accesses:
            _require_bound_dependency_ids(
                witness.dependency_ids,
                subject_id=access.access_id,
                kind="memory_version",
                binding_sha256=canonical_sha256(access.to_payload()),
                nodes_by_binding=nodes_by_binding,
                code="memory_version_dependency_missing",
                issues=issues,
            )
        target_sets = {row.exit_id: row for row in witness.exit_targets}
        for target_set in witness.exit_targets:
            for dependency in target_set.dependency_ids:
                if dependency not in node_by_id:
                    issues.append(
                        _issue(
                            "violated",
                            "exit_target_dependency_unknown",
                            dependency,
                        )
                    )

        for exit_row in summary.exits:
            target_set = target_sets[exit_row.exit_id]
            exact_record = exit_row.exact_record.to_value()
            direct_rvas = _exact_target_rvas(exact_record)
            is_external_boundary = exit_row.source_kind == "external_event"
            if direct_rvas and not is_external_boundary:
                unresolved = sorted(
                    rva for rva in direct_rvas if rva not in by_rva
                )
                for rva in unresolved:
                    issues.append(
                        _issue(
                            "incomplete",
                            "direct_target_absent_from_structural_universe",
                            f"{exit_row.exit_id}:0x{rva:x}",
                        )
                    )
                expected_targets = tuple(
                    sorted(by_rva[rva] for rva in direct_rvas if rva in by_rva)
                )
                _compare_ordered_inventory(
                    target_set.target_cutpoints,
                    expected_targets,
                    "direct_target",
                    issues,
                )
            elif "indirect" in exit_row.transfer_kind:
                _require_bound_dependency_ids(
                    target_set.dependency_ids,
                    subject_id=exit_row.exit_id,
                    kind="indirect_target",
                    binding_sha256=canonical_sha256(exit_row.to_payload()),
                    nodes_by_binding=nodes_by_binding,
                    code="indirect_target_dependency_missing",
                    issues=issues,
                )
                if not target_set.target_cutpoints and not is_external_boundary:
                    issues.append(
                        _issue(
                            "incomplete",
                            "indirect_target_set_missing",
                            exit_row.exit_id,
                        )
                    )
            elif target_set.target_cutpoints and exit_row.transfer_kind in {
                "return",
                "process_exit",
                "terminal",
                "fault",
            }:
                issues.append(
                    _issue(
                        "violated",
                        "terminal_target_contradiction",
                        exit_row.exit_id,
                    )
                )
            elif (
                not target_set.target_cutpoints
                and not is_external_boundary
                and exit_row.transfer_kind
                not in {"return", "process_exit", "terminal", "fault"}
            ):
                issues.append(
                    _issue(
                        "incomplete",
                        "control_target_not_reconstructed",
                        exit_row.exit_id,
                    )
                )

            if exit_row.source_kind != "external_event":
                if exit_row.category == "call":
                    _require_bound_dependency_ids(
                        witness.dependency_ids,
                        subject_id=exit_row.exit_id,
                        kind="call_summary",
                        binding_sha256=canonical_sha256(exit_row.to_payload()),
                        nodes_by_binding=nodes_by_binding,
                        code="call_summary_dependency_missing",
                        issues=issues,
                    )
                continue
            _require_bound_dependency_ids(
                witness.dependency_ids,
                subject_id=exit_row.exit_id,
                kind="external_site",
                binding_sha256=canonical_sha256(exit_row.to_payload()),
                nodes_by_binding=nodes_by_binding,
                code="external_site_dependency_missing",
                issues=issues,
            )
            if exit_row.category == "callback":
                _require_bound_dependency_ids(
                    witness.dependency_ids,
                    subject_id=exit_row.exit_id,
                    kind="callback_entry",
                    binding_sha256=canonical_sha256(exit_row.to_payload()),
                    nodes_by_binding=nodes_by_binding,
                    code="callback_entry_dependency_missing",
                    issues=issues,
                )
        if summary.faults:
            issues.append(
                _issue(
                    "incomplete",
                    "fault_effect_requires_checked_dependency",
                    summary.summary_id,
                )
            )
        if issues_by_source is not None:
            issues_by_source[witness.source_cutpoint] = tuple(
                dict(row) for row in issues[issue_start:]
            )


def _require_bound_dependency_ids(
    dependency_ids: Sequence[str],
    *,
    subject_id: str,
    kind: str,
    binding_sha256: str,
    nodes_by_binding: Mapping[tuple[str, str], set[str]],
    code: str,
    issues: list[dict[str, str]],
) -> None:
    matching = nodes_by_binding.get((kind, binding_sha256), set())
    if not matching or not matching.intersection(dependency_ids):
        issues.append(_issue("incomplete", code, subject_id))


def _exact_target_rvas(value: Any) -> tuple[int, ...]:
    if not isinstance(value, Mapping):
        return ()
    values: set[int] = set()
    for key in (
        "target_rva",
        "fallthrough_rva",
        "continuation_rva",
        "return_rva",
    ):
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            values.add(item)
    direct_targets = value.get("direct_targets")
    if isinstance(direct_targets, list):
        values.update(
            item
            for item in direct_targets
            if isinstance(item, int) and not isinstance(item, bool) and item >= 0
        )
    return tuple(sorted(values))


def _summary_post_facts(
    summary: TransitionSummaryV2,
    memory_version_graph: MemoryVersionGraphV2 | None,
) -> tuple[InvariantFactV2, ...]:
    facts: list[InvariantFactV2] = []
    for output in summary.outputs:
        # A stack output records the checked ESP delta, not the resulting ESP
        # value.  It invalidates register:esp through _output_subject, but can
        # establish a post-state value only once the semantic summary carries
        # an explicit normalized expression for new_esp.
        if output.category == "stack":
            continue
        expression = output.value.to_value()
        exact = _constant_expression_value(expression)
        if exact is not _NO_EXACT_VALUE:
            facts.append(InvariantFactV2.exact(_output_subject(output.category, output.destination), exact))
    if memory_version_graph is not None:
        ranges_by_access = _memory_ranges_by_access(memory_version_graph)
        for access in summary.memory_accesses:
            if access.memory_kind not in {"write", "read_write"}:
                continue
            ranges = ranges_by_access.get(access.access_id, ())
            if len(ranges) != 1 or access.value is None:
                continue
            exact = _constant_expression_value(access.value.to_value())
            if exact is _NO_EXACT_VALUE:
                continue
            start, end = ranges[0]
            facts.append(
                InvariantFactV2.exact(
                    _memory_range_subject(start, end), exact
                )
            )
    return tuple(sorted(set(facts)))


_NO_EXACT_VALUE = object()


def _constant_expression_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if value.get("op") in {"const", "constant"} and "value" in value:
            return value["value"]
        if value.get("kind") in {"exact", "constant"} and "value" in value:
            return value["value"]
    return _NO_EXACT_VALUE


def _output_subject(category: str, destination: str) -> str:
    return f"register:{destination}" if category == "stack" else f"{category}:{destination}"


def _subject_preserved_by_summary(
    subject: str,
    summary: TransitionSummaryV2,
    *,
    memory_version_graph: MemoryVersionGraphV2 | None,
) -> bool:
    written = {
        _output_subject(output.category, output.destination)
        for output in summary.outputs
    }
    if subject in written:
        return False
    if subject.startswith(("register:", "flag:")):
        return True
    has_memory_write = any(
        access.memory_kind in {"write", "read_write"}
        for access in summary.memory_accesses
    )
    has_external_effect = any(
        exit_row.source_kind == "external_event" for exit_row in summary.exits
    )
    memory_range = _parse_memory_range_subject(subject)
    if memory_range is not None:
        if memory_version_graph is None or has_external_effect:
            return False
        ranges_by_access = _memory_ranges_by_access(memory_version_graph)
        for access in summary.memory_accesses:
            if access.memory_kind not in {"write", "read_write"}:
                continue
            write_ranges = ranges_by_access.get(access.access_id, ())
            if not write_ranges:
                return False
            if any(_ranges_overlap(memory_range, written) for written in write_ranges):
                return False
        return True
    if subject.startswith("resource:"):
        return not has_external_effect
    return not has_memory_write and not has_external_effect


def _check_transition_implication(
    source_facts: Sequence[InvariantFactV2],
    target_facts: Sequence[InvariantFactV2],
    transition: TransitionSummaryV2,
    *,
    memory_version_graph: MemoryVersionGraphV2 | None,
) -> dict[str, str]:
    antecedents = tuple(source_facts)
    preserved = tuple(
        fact
        for fact in antecedents
        if _subject_preserved_by_summary(
            fact.subject,
            transition,
            memory_version_graph=memory_version_graph,
        )
    )
    outputs = tuple(
        sorted(
            set(
                (
                    *preserved,
                    *_summary_post_facts(transition, memory_version_graph),
                )
            )
        )
    )
    if _facts_imply(outputs, target_facts):
        return {"status": "complete", "code": "preserved"}
    return {"status": "incomplete", "code": "preservation_not_proved"}


def _memory_range_subject(start: int, end: int) -> str:
    return f"memory-range:{start}:{end}"


def _parse_memory_range_subject(subject: str) -> tuple[int, int] | None:
    prefix = "memory-range:"
    if not subject.startswith(prefix):
        return None
    parts = subject[len(prefix) :].split(":")
    if len(parts) != 2:
        return None
    try:
        start, end = (int(value, 10) for value in parts)
    except ValueError:
        return None
    if start < 0 or end <= start or end > 1 << 32:
        return None
    return start, end


def _memory_ranges_by_access(
    graph: MemoryVersionGraphV2,
) -> dict[str, tuple[tuple[int, int], ...]]:
    grouped: dict[str, set[tuple[int, int]]] = {}
    for link in graph.access_versions:
        grouped.setdefault(link.access_id, set()).update(
            (row.start, row.end) for row in link.ranges
        )
    return {
        access_id: tuple(sorted(ranges))
        for access_id, ranges in grouped.items()
    }


def _checked_memory_dependency_ids(
    nodes: Sequence[DependencyNodeV2],
    graph: MemoryVersionGraphV2 | None,
) -> frozenset[str]:
    if graph is None:
        return frozenset()
    concrete = {
        link.access_id for link in graph.access_versions if link.ranges
    }
    killed = {row.access_id for row in graph.unknown_write_kills}
    expected = concrete - killed
    return frozenset(
        node.node_id
        for node in nodes
        if node.kind == "memory_version"
        and node.node_id.startswith("memory-access:")
        and node.node_id.removeprefix("memory-access:") in expected
    )


def _checked_dependency_discharge_ids(
    nodes: Sequence[DependencyNodeV2],
    discharges: Sequence[DependencyDischargeV2],
) -> tuple[set[str], list[dict[str, str]]]:
    """Bind owner-issued receipts to the exact dependency graph nodes."""

    issues: list[dict[str, str]] = []
    rows = tuple(discharges)
    if rows != tuple(sorted(set(rows))):
        issues.append(_issue("violated", "dependency_discharge_inventory_noncanonical"))
    by_id = {node.node_id: node for node in nodes}
    accepted: set[str] = set()
    for discharge in rows:
        node = by_id.get(discharge.dependency_id)
        if node is None:
            issues.append(
                _issue(
                    "violated",
                    "dependency_discharge_unknown",
                    discharge.dependency_id,
                )
            )
            continue
        if (
            node.kind != discharge.kind
            or node.binding_sha256 != discharge.binding_sha256
        ):
            issues.append(
                _issue(
                    "violated",
                    "dependency_discharge_binding_contradiction",
                    discharge.dependency_id,
                )
            )
            continue
        accepted.add(discharge.dependency_id)
    return accepted, issues


def _ranges_overlap(
    left: tuple[int, int], right: tuple[int, int]
) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _check_target_coverage_v2(
    proposal: InvariantCertificateV2,
    *,
    transition_inventory: TransitionWitnessInventoryV2,
    members: Sequence[str],
    expected: Sequence[Mapping[str, Any]] | None = None,
    budgets: InvariantBudgetsV2,
    issues: list[dict[str, str]],
) -> None:
    expected_rows = (
        _derive_target_coverage(transition_inventory, members)
        if expected is None
        else list(expected)
    )
    submitted = proposal.target_coverage.to_value()
    _compare_rows(submitted, expected_rows, "target_coverage", issues)
    for row in expected_rows:
        targets = row["targets"]
        if len(targets) > budgets.maximum_finite_values:
            issues.append(
                _issue(
                    "incomplete",
                    "target_alternative_budget_exceeded",
                    str(row["transition_id"]),
                )
            )


def _check_exports_v2(
    proposal: InvariantCertificateV2,
    *,
    required_exports: Sequence[ExportRequirementV2],
    invariant_by_cutpoint: Mapping[str, tuple[InvariantFactV2, ...]],
    issues: list[dict[str, str]],
    obligations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    expected = tuple(sorted(set(required_exports), key=lambda item: item.export_id))
    submitted_ids = tuple(item.export_id for item in proposal.exports)
    expected_ids = tuple(item.export_id for item in expected)
    _compare_ordered_inventory(submitted_ids, expected_ids, "export", issues)
    expected_by_id = {item.export_id: item for item in expected}
    checked: list[dict[str, Any]] = []
    for submitted in proposal.exports:
        required = expected_by_id.get(submitted.export_id)
        if required is None:
            continue
        if submitted != required:
            issues.append(
                _issue("violated", "export_binding_contradiction", submitted.export_id)
            )
            continue
        invariant = invariant_by_cutpoint.get(required.cutpoint)
        if invariant is None:
            continue
        complete = _facts_imply(invariant, (required.fact,))
        obligations.append(
            {
                "id": required.export_id,
                "kind": "export",
                "status": "complete" if complete else "incomplete",
            }
        )
        if complete:
            checked.append(required.to_payload())
        else:
            issues.append(
                _issue(
                    "incomplete",
                    "export_not_implied",
                    required.export_id,
                )
            )
    return checked


def _check_budgets(
    budgets: InvariantBudgetsV2,
    *,
    members: Sequence[str],
    transitions: Sequence[str],
    invariants: Mapping[str, Sequence[InvariantFactV2]],
    dependencies: Sequence[str],
    issues: list[dict[str, str]],
) -> None:
    if len(members) > budgets.maximum_members:
        issues.append(_issue("incomplete", "member_budget_exceeded"))
    if len(transitions) > budgets.maximum_transitions:
        issues.append(_issue("incomplete", "transition_budget_exceeded"))
    if len(dependencies) > budgets.maximum_dependencies:
        issues.append(_issue("incomplete", "dependency_budget_exceeded"))
    for cutpoint, facts in invariants.items():
        if len(facts) > budgets.maximum_facts_per_cutpoint:
            issues.append(
                _issue("incomplete", "fact_budget_exceeded", cutpoint)
            )
        for fact in facts:
            predicate = fact.predicate.to_value()
            if (
                predicate["kind"] == "finite"
                and len(predicate["values"]) > budgets.maximum_finite_values
            ):
                issues.append(
                    _issue(
                        "incomplete",
                        "finite_value_budget_exceeded",
                        fact.fact_id,
                    )
                )
            if (
                predicate["kind"] == "resource_lifecycle"
                and len(predicate["states"]) > budgets.maximum_resource_states
            ):
                issues.append(
                    _issue(
                        "incomplete",
                        "resource_state_budget_exceeded",
                        fact.fact_id,
                    )
                )


def _compare_control_inventory(
    submitted: Any,
    expected: Mapping[str, Any],
    issues: list[dict[str, str]],
) -> None:
    if not isinstance(submitted, Mapping):
        issues.append(_issue("violated", "control_inventory_malformed"))
        return
    if set(submitted) != set(expected):
        issues.append(_issue("violated", "control_inventory_fields_contradict"))
    for field in ("members", "member_transitions"):
        _compare_ordered_inventory(
            submitted.get(field, ()), expected[field], f"control_{field}", issues
        )
    for field in ("internal", "incoming", "outgoing"):
        _compare_rows(
            submitted.get(field), expected[field], f"control_{field}", issues
        )


def _compare_rows(
    submitted: Any,
    expected: Sequence[Mapping[str, Any]],
    label: str,
    issues: list[dict[str, str]],
) -> None:
    if not isinstance(submitted, list):
        issues.append(_issue("violated", f"{label}_malformed"))
        return
    submitted_keys = [_canonical_key(row) for row in submitted]
    expected_keys = [_canonical_key(row) for row in expected]
    if submitted_keys != sorted(set(submitted_keys)):
        issues.append(_issue("violated", f"{label}_noncanonical"))
    submitted_set = set(submitted_keys)
    expected_set = set(expected_keys)
    for key in sorted(expected_set - submitted_set):
        issues.append(
            _issue("incomplete", f"{label}_missing", key.decode("ascii"))
        )
    for key in sorted(submitted_set - expected_set):
        issues.append(
            _issue("violated", f"{label}_contradiction", key.decode("ascii"))
        )


def _compare_ordered_inventory(
    submitted: Sequence[str],
    expected: Sequence[str],
    label: str,
    issues: list[dict[str, str]],
) -> None:
    if not isinstance(submitted, (list, tuple)) or not all(
        isinstance(value, str) for value in submitted
    ):
        issues.append(_issue("violated", f"{label}_inventory_malformed"))
        return
    if tuple(submitted) != tuple(sorted(set(submitted))):
        issues.append(_issue("violated", f"{label}_inventory_noncanonical"))
    submitted_set = set(submitted)
    expected_set = set(expected)
    for value in sorted(expected_set - submitted_set):
        issues.append(_issue("incomplete", f"{label}_missing", value))
    for value in sorted(submitted_set - expected_set):
        issues.append(_issue("violated", f"{label}_contradiction", value))


def _canonical_facts(
    facts: Sequence[InvariantFactV2], context: str
) -> tuple[InvariantFactV2, ...]:
    result = tuple(facts)
    if any(not isinstance(fact, InvariantFactV2) for fact in result):
        raise InvariantCertificateV2Error(f"{context} must contain typed facts")
    if result != tuple(sorted(set(result))):
        raise InvariantCertificateV2Error(f"{context} is noncanonical")
    return result


def _parse_facts(value: Any, context: str) -> tuple[InvariantFactV2, ...]:
    return _canonical_facts(
        tuple(InvariantFactV2.parse(item) for item in _array(value, context)),
        context,
    )


def _parse_strings(
    value: Any, context: str, *, maximum: int
) -> tuple[str, ...]:
    values = _array(value, context)
    if not all(isinstance(item, str) for item in values):
        raise InvariantCertificateV2Error(f"{context} must contain strings")
    return _canonical_strings(values, context, maximum=maximum)


@dataclass
class _SubjectDomain:
    category: str
    finite: dict[bytes, Any] | None
    lower: int | None
    upper: int | None
    congruences: list[tuple[int, int]]
    resource_id: str | None
    resource_states: set[str] | None
    inconsistent: bool = False


def _domain(facts: Sequence[InvariantFactV2]) -> _SubjectDomain:
    domain = _SubjectDomain("value", None, None, None, [], None, None)
    for fact in facts:
        predicate = fact.predicate.to_value()
        kind = predicate["kind"]
        if kind == "resource_lifecycle":
            if domain.category != "value" or any(
                value is not None
                for value in (domain.finite, domain.lower, domain.upper)
            ) or domain.congruences:
                domain.inconsistent = True
                continue
            if domain.resource_id is None:
                domain.category = "resource"
                domain.resource_id = predicate["resource_id"]
                domain.resource_states = set(predicate["states"])
            elif domain.resource_id != predicate["resource_id"]:
                domain.inconsistent = True
            else:
                assert domain.resource_states is not None
                domain.resource_states.intersection_update(predicate["states"])
                if not domain.resource_states:
                    domain.inconsistent = True
            continue
        if domain.category == "resource":
            domain.inconsistent = True
            continue
        if kind in {"exact", "finite"}:
            raw_values = (
                [predicate["value"]]
                if kind == "exact"
                else predicate["values"]
            )
            values = {canonical_json_bytes(value): value for value in raw_values}
            domain.finite = (
                values
                if domain.finite is None
                else {
                    key: value
                    for key, value in domain.finite.items()
                    if key in values
                }
            )
            if not domain.finite:
                domain.inconsistent = True
        elif kind == "range":
            domain.lower = (
                predicate["lower"]
                if domain.lower is None
                else max(domain.lower, predicate["lower"])
            )
            domain.upper = (
                predicate["upper"]
                if domain.upper is None
                else min(domain.upper, predicate["upper"])
            )
            if domain.lower > domain.upper:
                domain.inconsistent = True
        elif kind == "congruence":
            domain.congruences.append(
                (predicate["modulus"], predicate["remainder"])
            )
    if domain.category == "resource":
        return domain
    if domain.finite is not None:
        domain.finite = {
            key: value
            for key, value in domain.finite.items()
            if _value_satisfies_numeric_constraints(value, domain)
        }
        if not domain.finite:
            domain.inconsistent = True
    elif not _numeric_constraints_consistent(domain):
        domain.inconsistent = True
    return domain


def _value_satisfies_numeric_constraints(
    value: Any, domain: _SubjectDomain
) -> bool:
    if domain.lower is None and domain.upper is None and not domain.congruences:
        return True
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    if domain.lower is not None and value < domain.lower:
        return False
    if domain.upper is not None and value > domain.upper:
        return False
    return all(value % modulus == remainder for modulus, remainder in domain.congruences)


def _combine_congruences(
    congruences: Sequence[tuple[int, int]],
) -> tuple[int, int] | None:
    modulus, remainder = 1, 0
    for next_modulus, next_remainder in congruences:
        common = math.gcd(modulus, next_modulus)
        if (next_remainder - remainder) % common:
            return None
        left = modulus // common
        right = next_modulus // common
        if right == 1:
            step = 0
        else:
            step = (
                ((next_remainder - remainder) // common)
                * pow(left, -1, right)
            ) % right
        remainder += modulus * step
        modulus *= right
        remainder %= modulus
    return modulus, remainder


def _numeric_constraints_consistent(domain: _SubjectDomain) -> bool:
    combined = _combine_congruences(domain.congruences)
    if combined is None:
        return False
    if domain.lower is None or domain.upper is None:
        return True
    modulus, remainder = combined
    first = domain.lower + ((remainder - domain.lower) % modulus)
    return first <= domain.upper


def _facts_by_subject(
    facts: Sequence[InvariantFactV2],
) -> dict[str, tuple[InvariantFactV2, ...]]:
    grouped: dict[str, list[InvariantFactV2]] = {}
    for fact in facts:
        grouped.setdefault(fact.subject, []).append(fact)
    return {
        subject: tuple(sorted(values)) for subject, values in grouped.items()
    }


def _facts_contradict(facts: Sequence[InvariantFactV2]) -> bool:
    return any(
        _domain(subject_facts).inconsistent
        for subject_facts in _facts_by_subject(facts).values()
    )


def _facts_imply(
    known: Sequence[InvariantFactV2],
    required: Sequence[InvariantFactV2],
) -> bool:
    if _facts_contradict(known):
        return True
    by_subject = _facts_by_subject(known)
    return all(
        _domain_implies(
            _domain(by_subject.get(fact.subject, ())),
            fact.predicate.to_value(),
        )
        for fact in required
    )


def _domain_implies(domain: _SubjectDomain, predicate: Mapping[str, Any]) -> bool:
    if domain.inconsistent:
        return True
    kind = predicate["kind"]
    if kind == "resource_lifecycle":
        return (
            domain.category == "resource"
            and domain.resource_id == predicate["resource_id"]
            and domain.resource_states is not None
            and domain.resource_states <= set(predicate["states"])
        )
    if domain.category != "value":
        return False
    finite_values = None if domain.finite is None else list(domain.finite.values())
    if kind == "exact":
        return (
            finite_values is not None
            and len(finite_values) == 1
            and canonical_json_bytes(finite_values[0])
            == canonical_json_bytes(predicate["value"])
        )
    if kind == "finite":
        allowed = {canonical_json_bytes(value) for value in predicate["values"]}
        return finite_values is not None and {
            canonical_json_bytes(value) for value in finite_values
        } <= allowed
    if kind == "range":
        if finite_values is not None:
            return all(
                isinstance(value, int)
                and not isinstance(value, bool)
                and predicate["lower"] <= value <= predicate["upper"]
                for value in finite_values
            )
        return (
            domain.lower is not None
            and domain.upper is not None
            and predicate["lower"] <= domain.lower
            and domain.upper <= predicate["upper"]
        )
    if finite_values is not None:
        return all(
            isinstance(value, int)
            and not isinstance(value, bool)
            and value % predicate["modulus"] == predicate["remainder"]
            for value in finite_values
        )
    combined = _combine_congruences(domain.congruences)
    if combined is None:
        return True
    modulus, remainder = combined
    if domain.lower is not None and domain.upper == domain.lower:
        return domain.lower % predicate["modulus"] == predicate["remainder"]
    return (
        modulus % predicate["modulus"] == 0
        and remainder % predicate["modulus"] == predicate["remainder"]
    )


def _issue(status: str, code: str, detail: str = "") -> dict[str, str]:
    result = {"status": status, "code": code}
    if detail:
        result["detail"] = detail
    return result


def _report(
    proposal: InvariantCertificateV2 | None,
    issues: Sequence[Mapping[str, Any]],
    *,
    obligations: Sequence[Mapping[str, Any]] = (),
    checked_exports: Sequence[Mapping[str, Any]] = (),
    dependency_scc: TypedDependencySCCV2 | None = None,
) -> dict[str, Any]:
    normalized = sorted(
        {
            canonical_json_bytes(issue): dict(issue)
            for issue in issues
        }.values(),
        key=_canonical_key,
    )
    status = (
        "violated"
        if any(issue["status"] == "violated" for issue in normalized)
        else "incomplete"
        if normalized
        else "complete"
    )
    payload = {
        "format": INVARIANT_CERTIFICATE_CHECK_V2_FORMAT,
        "certificate_id": None if proposal is None else proposal.certificate_id,
        "status": status,
        "authorizing": status == "complete",
        "issues": normalized,
        "obligations": sorted(obligations, key=_canonical_key),
        "checked_exports": sorted(checked_exports, key=_canonical_key),
        "dependency_scc": (
            None if dependency_scc is None else dependency_scc.to_payload()
        ),
    }
    return {**payload, "report_sha256": canonical_sha256(payload)}
