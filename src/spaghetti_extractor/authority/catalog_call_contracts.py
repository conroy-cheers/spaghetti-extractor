"""Checked call-frame contracts transferred from exact linked-library bodies.

Catalog recognition remains a proposal until this adapter independently
replays relocation-aware span matching against the exact target PE.  Only an
unambiguous match carrying checked physical-ABI facts is exported.  Facts are
kept independently usable: a certificate may prove preservation and cleanup
without yet proving arguments or results.  The resulting records are inputs to
interprocedural checking, not claims copied from a later authority result.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol

from ..abi.catalog import PhysicalAbiCatalogV1
from ..abi.model import (
    AbiFactV1,
    AbiValueV1,
    BoundaryEffectsV1,
    PhysicalAbiProfileV1,
    StackCleanupV1,
    VariadicPolicyV1,
)
from ..artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
)
from ..artifacts.formats import CATALOG_CALL_CONTRACT_SET_FORMAT
from ..artifacts.phases import RecordCodecV3
from ..libraries.abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3
from ..libraries.signature_graph import TARGET_SIGNATURE_GRAPH_CODEC_V3
from ..libraries.span_matching import discover_static_span_matches
from ._schema import (
    canonical_strings,
    digest,
    require_stable_id,
    stable_id,
    strict_object,
    text,
)


CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3 = "catalog-call-contracts-v3"
CATALOG_CALL_CONTRACT_RECORD_V1_SCHEMA = (
    "spaghetti-extractor-catalog-call-contract-record-v1"
)


class CatalogCallBoundaryUnitV1(Protocol):
    returns: bool
    return_cleanup_bytes: int | None


@dataclass(frozen=True, order=True)
class CatalogCallContractV1:
    contract_id: str
    binary_sha256: str
    match_id: str
    target_region_id: str
    target_entry_unit_id: str
    target_unit_ids: tuple[str, ...]
    catalog_id: str
    catalog_sha256: str
    catalog_function_id: str
    certificate_id: str
    exact_facts: tuple[AbiFactV1, ...]
    profile: PhysicalAbiProfileV1 | None = None
    boundary_effects: BoundaryEffectsV1 | None = None

    def exact_fact(self, field: str) -> AbiFactV1 | None:
        return next((row for row in self.exact_facts if row.field == field), None)

    @property
    def preserved_registers(self) -> tuple[str, ...] | None:
        if self.profile is not None:
            return self.profile.preserved_state
        fact = self.exact_fact("preserved_state")
        if fact is None:
            return None
        value = fact.values[0]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ValueError("catalog-call preserved-state fact is malformed")
        return tuple(sorted(set(value)))

    @property
    def stack_cleanup(self) -> StackCleanupV1 | None:
        if self.profile is not None:
            return self.profile.stack_cleanup
        fact = self.exact_fact("stack_cleanup")
        if fact is None:
            return None
        return StackCleanupV1.parse(fact.values[0])

    @property
    def calling_convention(self) -> str | None:
        if self.profile is not None:
            return self.profile.calling_convention
        fact = self.exact_fact("calling_convention")
        if fact is None or not isinstance(fact.values[0], str):
            return None
        return fact.values[0]

    @property
    def arguments(self) -> tuple[AbiValueV1, ...] | None:
        if self.profile is not None:
            return self.profile.arguments
        fact = self.exact_fact("arguments")
        if fact is None or not isinstance(fact.values[0], list):
            return None
        return tuple(AbiValueV1.parse(item) for item in fact.values[0])

    @property
    def results(self) -> tuple[AbiValueV1, ...] | None:
        if self.profile is not None:
            return self.profile.results
        fact = self.exact_fact("results")
        if fact is None or not isinstance(fact.values[0], list):
            return None
        return tuple(AbiValueV1.parse(item) for item in fact.values[0])

    @property
    def variadic_policy(self) -> VariadicPolicyV1 | None:
        if self.profile is not None:
            return self.profile.variadic
        fact = self.exact_fact("variadic")
        if fact is None:
            return None
        return VariadicPolicyV1.parse(fact.values[0])

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "binary_sha256": self.binary_sha256,
            "match_id": self.match_id,
            "target_region_id": self.target_region_id,
            "target_entry_unit_id": self.target_entry_unit_id,
            "target_unit_ids": list(self.target_unit_ids),
            "catalog_id": self.catalog_id,
            "catalog_sha256": self.catalog_sha256,
            "catalog_function_id": self.catalog_function_id,
            "certificate_id": self.certificate_id,
            "exact_fact_ids": [
                stable_id("catalog-call-exact-fact-v1", row.to_payload())
                for row in self.exact_facts
            ],
            "profile_id": None if self.profile is None else self.profile.profile_id,
            "boundary_effects_id": (
                None
                if self.boundary_effects is None
                else self.boundary_effects.effects_id
            ),
        }

    def __post_init__(self) -> None:
        digest(self.binary_sha256, "catalog-call contract binary SHA-256")
        digest(self.catalog_sha256, "catalog-call contract catalog SHA-256")
        for value, label in (
            (self.match_id, "catalog-call match"),
            (self.target_region_id, "catalog-call target region"),
            (self.target_entry_unit_id, "catalog-call target entry"),
            (self.catalog_id, "catalog-call catalog"),
            (self.catalog_function_id, "catalog-call function"),
            (self.certificate_id, "catalog-call certificate"),
        ):
            text(value, label)
        if self.target_unit_ids != tuple(sorted(set(self.target_unit_ids))):
            raise ValueError("catalog-call target units are not canonical")
        if self.target_entry_unit_id not in self.target_unit_ids:
            raise ValueError("catalog-call entry is outside its exact target span")
        if self.exact_facts != tuple(
            sorted(self.exact_facts, key=lambda row: row.field)
        ):
            raise ValueError("catalog-call exact facts are not canonical")
        if len({row.field for row in self.exact_facts}) != len(self.exact_facts):
            raise ValueError("catalog-call exact facts contain duplicate fields")
        if any(
            row.status != "exact" or row.subject_id != self.catalog_function_id
            for row in self.exact_facts
        ):
            raise ValueError("catalog-call contract contains non-exact or foreign facts")
        if self.profile is None and not self.exact_facts:
            raise ValueError("catalog-call contract contains no checked ABI facts")
        require_stable_id(
            self.contract_id,
            "catalog-call-contract-v1",
            self.identity_payload,
            "catalog-call contract",
        )

    @classmethod
    def create(
        cls,
        *,
        binary_sha256: str,
        match_id: str,
        target_region_id: str,
        target_entry_unit_id: str,
        target_unit_ids: Iterable[str],
        catalog_id: str,
        catalog_sha256: str,
        catalog_function_id: str,
        certificate_id: str,
        exact_facts: Iterable[AbiFactV1] = (),
        profile: PhysicalAbiProfileV1 | None = None,
        boundary_effects: BoundaryEffectsV1 | None = None,
    ) -> "CatalogCallContractV1":
        units = tuple(sorted(set(target_unit_ids)))
        facts = tuple(sorted(exact_facts, key=lambda row: row.field))
        identity = {
            "binary_sha256": binary_sha256,
            "match_id": match_id,
            "target_region_id": target_region_id,
            "target_entry_unit_id": target_entry_unit_id,
            "target_unit_ids": list(units),
            "catalog_id": catalog_id,
            "catalog_sha256": catalog_sha256,
            "catalog_function_id": catalog_function_id,
            "certificate_id": certificate_id,
            "exact_fact_ids": [
                stable_id("catalog-call-exact-fact-v1", row.to_payload())
                for row in facts
            ],
            "profile_id": None if profile is None else profile.profile_id,
            "boundary_effects_id": (
                None if boundary_effects is None else boundary_effects.effects_id
            ),
        }
        return cls(
            stable_id("catalog-call-contract-v1", identity),
            binary_sha256,
            match_id,
            target_region_id,
            target_entry_unit_id,
            units,
            catalog_id,
            catalog_sha256,
            catalog_function_id,
            certificate_id,
            facts,
            profile,
            boundary_effects,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": CATALOG_CALL_CONTRACT_RECORD_V1_SCHEMA,
            "id": self.contract_id,
            **self.identity_payload,
            "exact_facts": [row.to_payload() for row in self.exact_facts],
            "profile": None if self.profile is None else self.profile.to_payload(),
            "boundary_effects": (
                None
                if self.boundary_effects is None
                else self.boundary_effects.to_payload()
            ),
        }

    @classmethod
    def parse(cls, value: Any) -> "CatalogCallContractV1":
        row = strict_object(
            value,
            {
                "schema",
                "id",
                "binary_sha256",
                "match_id",
                "target_region_id",
                "target_entry_unit_id",
                "target_unit_ids",
                "catalog_id",
                "catalog_sha256",
                "catalog_function_id",
                "certificate_id",
                "exact_fact_ids",
                "exact_facts",
                "profile_id",
                "profile",
                "boundary_effects_id",
                "boundary_effects",
            },
            "catalog-call contract",
        )
        if row["schema"] != CATALOG_CALL_CONTRACT_RECORD_V1_SCHEMA:
            raise ValueError("catalog-call contract schema is unsupported")
        raw_facts = row["exact_facts"]
        if not isinstance(raw_facts, list):
            raise ValueError("catalog-call exact facts must be an array")
        facts = tuple(
            sorted(
                (AbiFactV1.parse(item) for item in raw_facts),
                key=lambda item: item.field,
            )
        )
        if row["exact_fact_ids"] != [
            stable_id("catalog-call-exact-fact-v1", item.to_payload())
            for item in facts
        ]:
            raise ValueError("catalog-call exact-fact identities are stale")
        profile = (
            None
            if row["profile"] is None
            else PhysicalAbiProfileV1.parse(row["profile"])
        )
        if row["profile_id"] != (None if profile is None else profile.profile_id):
            raise ValueError("catalog-call profile identity is stale")
        effects = (
            None
            if row["boundary_effects"] is None
            else BoundaryEffectsV1.parse(row["boundary_effects"])
        )
        if row["boundary_effects_id"] != (
            None if effects is None else effects.effects_id
        ):
            raise ValueError("catalog-call boundary-effects identity is stale")
        result = cls(
            text(row["id"], "catalog-call contract ID"),
            digest(row["binary_sha256"], "catalog-call binary SHA-256"),
            text(row["match_id"], "catalog-call match"),
            text(row["target_region_id"], "catalog-call target region"),
            text(row["target_entry_unit_id"], "catalog-call target entry"),
            canonical_strings(row["target_unit_ids"], "catalog-call target units"),
            text(row["catalog_id"], "catalog-call catalog"),
            digest(row["catalog_sha256"], "catalog-call catalog SHA-256"),
            text(row["catalog_function_id"], "catalog-call function"),
            text(row["certificate_id"], "catalog-call certificate"),
            facts,
            profile,
            effects,
        )
        return result


def catalog_call_contract_machine_contradictions_v1(
    contract: CatalogCallContractV1,
    units: Mapping[str, CatalogCallBoundaryUnitV1],
) -> tuple[str, ...]:
    """Return exact machine facts that contradict a transferred contract."""

    contradictions: set[str] = set()
    if contract.target_entry_unit_id not in units or any(
        unit_id not in units for unit_id in contract.target_unit_ids
    ):
        contradictions.add("target_unit_missing")
        return tuple(sorted(contradictions))
    cleanup = contract.stack_cleanup
    if cleanup is not None:
        expected = 0 if cleanup.kind in {"caller", "none"} else cleanup.bytes
        observed = {
            unit.return_cleanup_bytes
            for unit_id in contract.target_unit_ids
            for unit in (units[unit_id],)
            if unit.returns and unit.return_cleanup_bytes is not None
        }
        if any(value != expected for value in observed):
            contradictions.add("stack_cleanup")
    return tuple(sorted(contradictions))


CATALOG_CALL_CONTRACT_CODEC_V1 = RecordCodecV3(
    decode=CatalogCallContractV1.parse,
    encode=lambda value: value.to_payload(),
)


def build_checked_catalog_call_contracts_v1(
    *,
    binary: Path | str,
    binary_identity: str,
    target_signature_graph: Path | str,
    catalog_search_index: Path | str,
    physical_abi_catalogs: Sequence[Path | str],
    out: Path | str,
) -> tuple[CatalogCallContractV1, ...]:
    """Independently derive unambiguous ABI contracts from exact PE spans."""

    binary_path = Path(binary)
    binary_sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    graph = TARGET_SIGNATURE_GRAPH_CODEC_V3.read(target_signature_graph)
    if graph.binary_sha256 != binary_sha256:
        raise ValueError("catalog-call target graph is bound to another PE")
    search = CATALOG_SEARCH_INDEX_CODEC_V3.read(catalog_search_index)
    catalogs = tuple(PhysicalAbiCatalogV1.read(path) for path in physical_abi_catalogs)
    certificates: dict[str, tuple[PhysicalAbiCatalogV1, Any]] = {}
    function_metadata: dict[str, Any] = {}
    for catalog in catalogs:
        for function in catalog.function_subjects:
            function_id = str(function.get("function_id", ""))
            if function_id:
                function_metadata[function_id] = function
        for certificate in catalog.certificates:
            if certificate.subject_id in certificates:
                raise ValueError("catalog-call ABI subject appears in two catalogs")
            certificates[certificate.subject_id] = (catalog, certificate)

    spans = discover_static_span_matches(
        target_graph=graph,
        search_index=search,
        target_pe=binary_path,
    )
    by_entry: dict[str, list[CatalogCallContractV1]] = {}
    unit_by_start = {row.rva_start: row.unit_id for row in graph.unit_spans}
    function_by_span = {
        (row.rva_start, row.rva_end, tuple(sorted(row.unit_ids))): row.function_id
        for row in graph.functions
    }
    for match in spans:
        catalog_and_certificate = certificates.get(match.catalog_function_id)
        if catalog_and_certificate is None:
            continue
        catalog, certificate = catalog_and_certificate
        exact_facts = tuple(
            row for row in certificate.facts if row.status == "exact"
        )
        if certificate.status == "violated" or (
            certificate.profile is None and not exact_facts
        ):
            continue
        entry = unit_by_start.get(match.target_rva_start)
        if entry is None:
            continue
        region_id = function_by_span.get(
            (
                match.target_rva_start,
                match.target_rva_end,
                tuple(sorted(match.target_unit_ids)),
            ),
            stable_id(
                "catalog-call-target-region-v1",
                {
                    "rva_start": match.target_rva_start,
                    "rva_end": match.target_rva_end,
                    "target_unit_ids": list(match.target_unit_ids),
                },
            ),
        )
        contract = CatalogCallContractV1.create(
            binary_sha256=binary_sha256,
            match_id=match.match_id,
            target_region_id=region_id,
            target_entry_unit_id=entry,
            target_unit_ids=match.target_unit_ids,
            catalog_id=catalog.catalog_id,
            catalog_sha256=catalog.catalog_sha256,
            catalog_function_id=match.catalog_function_id,
            certificate_id=certificate.certificate_id,
            exact_facts=exact_facts,
            profile=certificate.profile,
            boundary_effects=(
                None
                if function_metadata.get(match.catalog_function_id, {}).get(
                    "boundary_effects"
                )
                is None
                else BoundaryEffectsV1.parse(
                    function_metadata[match.catalog_function_id][
                        "boundary_effects"
                    ]
                )
            ),
        )
        by_entry.setdefault(entry, []).append(contract)

    records: list[ArtifactRecordV3] = []
    for entry, candidates in sorted(by_entry.items()):
        semantic_signatures = {
            (
                tuple(
                    stable_id(
                        "catalog-call-exact-fact-semantics-v1",
                        {"field": fact.field, "values": list(fact.values)},
                    )
                    for fact in row.exact_facts
                ),
                row.identity_payload["profile_id"],
                row.identity_payload["boundary_effects_id"],
                row.target_unit_ids,
                row.target_region_id,
            )
            for row in candidates
        }
        if len(semantic_signatures) != 1:
            # Multiple byte-identical catalog members may name the same body.
            # They authorize a shared ABI only when every transferred fact and
            # effect agrees. Otherwise the call boundary remains incomplete.
            continue
        contract = min(
            candidates,
            key=lambda row: (row.catalog_function_id, row.contract_id),
        )
        records.append(
            CATALOG_CALL_CONTRACT_CODEC_V1.write(contract.contract_id, contract)
        )

    binding = ArtifactBindingV3(
        "binary", "pe32", text(binary_identity, "binary identity"), binary_sha256
    )
    destination = Path(out)
    ArtifactSetWriterV3(
        artifact_kind=CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3,
        bindings=(binding,),
        status="complete",
    ).write(destination, records)
    return tuple(
        CATALOG_CALL_CONTRACT_CODEC_V1.read(row).value
        for row in sorted(records, key=lambda item: item.record_id)
    )


__all__ = [
    "CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3",
    "CATALOG_CALL_CONTRACT_CODEC_V1",
    "CATALOG_CALL_CONTRACT_RECORD_V1_SCHEMA",
    "CatalogCallBoundaryUnitV1",
    "CatalogCallContractV1",
    "build_checked_catalog_call_contracts_v1",
    "catalog_call_contract_machine_contradictions_v1",
]
