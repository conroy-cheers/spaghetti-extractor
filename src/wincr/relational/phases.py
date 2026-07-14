from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .ir import ProductGraphIR
from .schema import SchemaError


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{field} must be an object")
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class AnalysisArtifact:
    format: str
    status: str
    raw: Mapping[str, Any]

    @classmethod
    def parse(
        cls,
        payload: Mapping[str, Any],
        *,
        expected_format: str,
    ) -> "AnalysisArtifact":
        format_id = payload.get("format")
        status = payload.get("status")
        if format_id != expected_format:
            raise SchemaError(
                f"expected {expected_format} analysis artifact, got {format_id!r}"
            )
        if not isinstance(status, str) or not status:
            raise SchemaError(f"{expected_format}.status must be a non-empty string")
        return cls(format=format_id, status=status, raw=_mapping(payload, expected_format))


@dataclass(frozen=True)
class ExtractedProgramPair:
    contract: Mapping[str, Any]
    region_ids: tuple[str, ...]
    behaviors: tuple[Mapping[str, Any], ...]
    extraction: Mapping[str, Any]

    @classmethod
    def create(
        cls,
        *,
        contract: Mapping[str, Any],
        behaviors: list[dict[str, Any]],
        extraction: Mapping[str, Any],
    ) -> "ExtractedProgramPair":
        regions = contract.get("regions")
        if not isinstance(regions, list) or not regions:
            raise SchemaError("relational contract regions must be a non-empty list")
        region_ids = tuple(
            region.get("id") if isinstance(region, Mapping) else None
            for region in regions
        )
        if any(not isinstance(item, str) or not item for item in region_ids):
            raise SchemaError("every relational contract region must have a non-empty id")
        if len(region_ids) != len(set(region_ids)):
            raise SchemaError("relational contract region ids must be unique")
        if not behaviors:
            raise SchemaError("decoded relational behavior inventory must not be empty")
        if len(behaviors) != len(region_ids):
            raise SchemaError("decoded behavior count must match relational contract regions")
        rows = tuple(_mapping(row, "behaviors[]") for row in behaviors)
        return cls(
            contract=_mapping(contract, "contract"),
            region_ids=tuple(str(item) for item in region_ids),
            behaviors=rows,
            extraction=_mapping(extraction, "extraction"),
        )

    def mutable_contract(self) -> dict[str, Any]:
        return dict(self.contract)

    def behavior_rows(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.behaviors]


@dataclass(frozen=True)
class StateAnalysisProducts:
    extracted: ExtractedProgramPair
    register_relations: AnalysisArtifact
    stack_windows: AnalysisArtifact
    machine_import_calls: AnalysisArtifact
    external_call_sites: AnalysisArtifact
    semantic_ir: AnalysisArtifact
    memory_contracts: AnalysisArtifact
    invariants: AnalysisArtifact

    @classmethod
    def create(
        cls,
        *,
        extracted: ExtractedProgramPair,
        register_relations: Mapping[str, Any],
        stack_windows: Mapping[str, Any],
        machine_import_calls: Mapping[str, Any],
        external_call_sites: Mapping[str, Any],
        semantic_ir: Mapping[str, Any],
        memory_contracts: Mapping[str, Any],
        invariants: Mapping[str, Any],
    ) -> "StateAnalysisProducts":
        return cls(
            extracted=extracted,
            register_relations=AnalysisArtifact.parse(
                register_relations,
                expected_format="stage-a-relational-register-relations-v1",
            ),
            stack_windows=AnalysisArtifact.parse(
                stack_windows,
                expected_format="stage-a-relational-stack-windows-v1",
            ),
            machine_import_calls=AnalysisArtifact.parse(
                machine_import_calls,
                expected_format="stage-a-relational-machine-import-calls-v1",
            ),
            external_call_sites=AnalysisArtifact.parse(
                external_call_sites,
                expected_format="stage-a-relational-external-call-sites-v1",
            ),
            semantic_ir=AnalysisArtifact.parse(
                semantic_ir,
                expected_format="stage-a-relational-semantic-ir-v1",
            ),
            memory_contracts=AnalysisArtifact.parse(
                memory_contracts,
                expected_format="stage-a-relational-memory-contracts-v1",
            ),
            invariants=AnalysisArtifact.parse(
                invariants,
                expected_format="stage-a-relational-invariants-v1",
            ),
        )


@dataclass(frozen=True)
class CompositionProducts:
    state: StateAnalysisProducts
    product_graph: ProductGraphIR
    segment_candidates: tuple[Mapping[str, Any], ...]

    @classmethod
    def create(
        cls,
        *,
        state: StateAnalysisProducts,
        product_graph: Mapping[str, Any],
        segment_candidates: list[dict[str, Any]],
    ) -> "CompositionProducts":
        candidates = tuple(
            _mapping(candidate, "segment_candidates[]")
            for candidate in segment_candidates
        )
        ids = [candidate.get("id") for candidate in candidates]
        present_ids = [item for item in ids if item is not None]
        if any(not isinstance(item, str) or not item for item in present_ids):
            raise SchemaError("segment candidate ids must be non-empty strings")
        if len(present_ids) != len(set(present_ids)):
            raise SchemaError("segment candidate ids must be unique")
        return cls(
            state=state,
            product_graph=ProductGraphIR.parse(product_graph),
            segment_candidates=candidates,
        )
