"""Format-free internal result for one contextual-proof facet."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import (
    BoundaryModelError,
    canonical,
    digest,
    identifier,
    object_,
)


_PROOF_FACETS = frozenset({"semantic_refinement", "induction"})


@dataclass(frozen=True)
class ComponentProofFacetResult:
    component_id: str
    facet: str
    status: str
    inputs: tuple[tuple[str, str], ...]
    checks: tuple[Mapping[str, object], ...]
    receipt_sha256: str

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        facet: str,
        status: str,
        inputs: Mapping[str, str],
        checks: Sequence[Mapping[str, object]],
    ) -> "ComponentProofFacetResult":
        identity = identifier(facet, "component proof facet")
        if identity not in _PROOF_FACETS:
            raise BoundaryModelError("component proof facet is unsupported")
        if status not in {"checked", "incomplete", "violated"}:
            raise BoundaryModelError("component proof facet status is unsupported")
        bound_inputs = tuple(
            sorted(
                (
                    identifier(name, "component proof input"),
                    digest(value, "component proof input digest"),
                )
                for name, value in inputs.items()
            )
        )
        normalized_checks = tuple(
            canonical(dict(object_(item, f"component proof check {index}")))
            for index, item in enumerate(checks)
        )
        core = {
            "model": "component-proof-facet-result-v1",
            "component_id": identifier(component_id, "component proof component"),
            "facet": identity,
            "status": status,
            "inputs": [
                {"name": name, "sha256": value}
                for name, value in bound_inputs
            ],
            "checks": [canonical(dict(item)) for item in normalized_checks],
            "tests_authorize": False,
        }
        return cls(
            str(core["component_id"]),
            identity,
            status,
            bound_inputs,
            normalized_checks,
            canonical_sha256_v3(core),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "model": "component-proof-facet-result-v1",
            "component_id": self.component_id,
            "facet": self.facet,
            "status": self.status,
            "inputs": [
                {"name": name, "sha256": value}
                for name, value in self.inputs
            ],
            "checks": [canonical(dict(item)) for item in self.checks],
            "tests_authorize": False,
            "receipt_sha256": self.receipt_sha256,
        }


__all__ = ["ComponentProofFacetResult"]
