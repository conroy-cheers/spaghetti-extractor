from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ..stage_binary import StageAInputError
from ..util import sha256_bytes
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


REGION_FACTS_ARTIFACT_FORMAT = "stage-a-relational-region-facts-v1"
REGION_FACTS_ARTIFACT_STATUS = "untrusted_proposal_requires_global_analysis"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_FIELDS = {
    "format",
    "profile",
    "model",
    "status",
    "original_sha256",
    "candidate_sha256",
    "input_relation_contract_sha256",
    "normalized_behaviors_sha256",
    "region_facts_semantics_sha256",
    "region_count",
    "contract",
    "initial_static_code_pointer_analysis",
    "indirect_call_candidates",
    "table_call_proposals",
    "dynamic_call_candidates",
    "import_register_seeds",
    "machine_call_analysis",
}
_CANDIDATE_LIST_FIELDS = (
    "indirect_call_candidates",
    "table_call_proposals",
    "dynamic_call_candidates",
    "import_register_seeds",
)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str,
) -> None:
    observed = set(payload)
    missing = sorted(expected - observed)
    extra = sorted(observed - expected, key=repr)
    if not missing and not extra:
        return
    details: list[str] = []
    if missing:
        details.append(f"missing fields {missing}")
    if extra:
        details.append(f"unexpected fields {extra}")
    raise StageAInputError(f"{context} has " + " and ".join(details))


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be 64 lowercase hex characters")
    return value


def _region_count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageAInputError(
            "region facts region_count must be a non-negative integer"
        )
    return value


def _freeze_json(value: Any, context: str) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StageAInputError(f"{context} contains a non-finite number")
        return value
    if isinstance(value, list):
        return tuple(
            _freeze_json(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        )
    if isinstance(value, Mapping):
        items = list(value.items())
        if any(not isinstance(key, str) for key, _item in items):
            raise StageAInputError(f"{context} object keys must be strings")
        return MappingProxyType({
            key: _freeze_json(item, f"{context}.{key}")
            for key, item in sorted(items)
        })
    raise StageAInputError(f"{context} contains a non-JSON value")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _candidate_rows(value: Any, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"region facts {field_name} must be a list")
    rows: list[Mapping[str, Any]] = []
    for index, row in enumerate(value):
        context = f"region facts {field_name}[{index}]"
        _object(row, context)
        rows.append(_freeze_json(row, context))
    return tuple(rows)


def _validate_contract(
    contract: Mapping[str, Any], region_count: int,
) -> None:
    regions = contract.get("regions")
    if not isinstance(regions, list):
        raise StageAInputError("region facts contract regions must be a list")
    if len(regions) != region_count:
        raise StageAInputError(
            "region facts region_count does not match the contract"
        )

    region_ids: list[str] = []
    for index, row in enumerate(regions):
        region = _object(row, f"region facts contract region {index}")
        region_id = region.get("id")
        if not isinstance(region_id, str) or not region_id:
            raise StageAInputError(
                f"region facts contract region {index} id must be a nonempty string"
            )
        region_ids.append(region_id)
    if len(region_ids) != len(set(region_ids)):
        raise StageAInputError("region facts contract region ids must be unique")


@dataclass(frozen=True)
class RegionFactsArtifact:
    original_sha256: str
    candidate_sha256: str
    input_relation_contract_sha256: str
    normalized_behaviors_sha256: str
    region_facts_semantics_sha256: str
    region_count: int
    contract: Mapping[str, Any]
    initial_static_code_pointer_analysis: Mapping[str, Any]
    indirect_call_candidates: tuple[Mapping[str, Any], ...]
    table_call_proposals: tuple[Mapping[str, Any], ...]
    dynamic_call_candidates: tuple[Mapping[str, Any], ...]
    import_register_seeds: tuple[Mapping[str, Any], ...]
    machine_call_analysis: Mapping[str, Any]
    format: str = field(default=REGION_FACTS_ARTIFACT_FORMAT, init=False)
    profile: str = field(default=STAGE_A_RELATIONAL_PROFILE_ID, init=False)
    model: str = field(default=STAGE_A_RELATIONAL_MODEL_ID, init=False)
    status: str = field(default=REGION_FACTS_ARTIFACT_STATUS, init=False)

    @classmethod
    def parse(
        cls,
        payload: Any,
        *,
        expected_original_sha256: str | None = None,
        expected_candidate_sha256: str | None = None,
        expected_input_relation_contract_sha256: str | None = None,
        expected_normalized_behaviors_sha256: str | None = None,
        expected_region_facts_semantics_sha256: str | None = None,
    ) -> "RegionFactsArtifact":
        artifact = _object(payload, "region facts artifact")
        _exact_fields(
            artifact, _TOP_LEVEL_FIELDS, "region facts artifact"
        )
        expected_constants = {
            "format": REGION_FACTS_ARTIFACT_FORMAT,
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "status": REGION_FACTS_ARTIFACT_STATUS,
        }
        for field_name, expected in expected_constants.items():
            if artifact[field_name] != expected:
                raise StageAInputError(
                    f"region facts artifact {field_name} mismatch"
                )

        hashes = {
            field_name: _sha256(
                artifact[field_name], f"region facts artifact {field_name}"
            )
            for field_name in (
                "original_sha256",
                "candidate_sha256",
                "input_relation_contract_sha256",
                "normalized_behaviors_sha256",
                "region_facts_semantics_sha256",
            )
        }
        expected_hashes = {
            "original_sha256": expected_original_sha256,
            "candidate_sha256": expected_candidate_sha256,
            "input_relation_contract_sha256": (
                expected_input_relation_contract_sha256
            ),
            "normalized_behaviors_sha256": expected_normalized_behaviors_sha256,
            "region_facts_semantics_sha256": (
                expected_region_facts_semantics_sha256
            ),
        }
        for field_name, raw_expected in expected_hashes.items():
            if raw_expected is None:
                continue
            expected = _sha256(raw_expected, f"expected {field_name}")
            if hashes[field_name] != expected:
                raise StageAInputError(
                    f"region facts artifact {field_name} mismatch"
                )

        count = _region_count(artifact["region_count"])
        contract = _object(artifact["contract"], "region facts contract")
        _validate_contract(contract, count)
        initial_analysis = _object(
            artifact["initial_static_code_pointer_analysis"],
            "region facts initial_static_code_pointer_analysis",
        )
        machine_analysis = _object(
            artifact["machine_call_analysis"],
            "region facts machine_call_analysis",
        )

        try:
            candidates = {
                field_name: _candidate_rows(artifact[field_name], field_name)
                for field_name in _CANDIDATE_LIST_FIELDS
            }
            frozen_contract = _freeze_json(contract, "region facts contract")
            frozen_initial_analysis = _freeze_json(
                initial_analysis,
                "region facts initial_static_code_pointer_analysis",
            )
            frozen_machine_analysis = _freeze_json(
                machine_analysis, "region facts machine_call_analysis"
            )
        except RecursionError as exc:
            raise StageAInputError(
                "region facts artifact exceeds the supported JSON nesting depth"
            ) from exc

        return cls(
            original_sha256=hashes["original_sha256"],
            candidate_sha256=hashes["candidate_sha256"],
            input_relation_contract_sha256=(
                hashes["input_relation_contract_sha256"]
            ),
            normalized_behaviors_sha256=hashes["normalized_behaviors_sha256"],
            region_facts_semantics_sha256=(
                hashes["region_facts_semantics_sha256"]
            ),
            region_count=count,
            contract=frozen_contract,
            initial_static_code_pointer_analysis=frozen_initial_analysis,
            indirect_call_candidates=candidates["indirect_call_candidates"],
            table_call_proposals=candidates["table_call_proposals"],
            dynamic_call_candidates=candidates["dynamic_call_candidates"],
            import_register_seeds=candidates["import_register_seeds"],
            machine_call_analysis=frozen_machine_analysis,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "profile": self.profile,
            "model": self.model,
            "status": self.status,
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "input_relation_contract_sha256": (
                self.input_relation_contract_sha256
            ),
            "normalized_behaviors_sha256": self.normalized_behaviors_sha256,
            "region_facts_semantics_sha256": (
                self.region_facts_semantics_sha256
            ),
            "region_count": self.region_count,
            "contract": _thaw_json(self.contract),
            "initial_static_code_pointer_analysis": _thaw_json(
                self.initial_static_code_pointer_analysis
            ),
            "indirect_call_candidates": _thaw_json(
                self.indirect_call_candidates
            ),
            "table_call_proposals": _thaw_json(self.table_call_proposals),
            "dynamic_call_candidates": _thaw_json(
                self.dynamic_call_candidates
            ),
            "import_register_seeds": _thaw_json(self.import_register_seeds),
            "machine_call_analysis": _thaw_json(self.machine_call_analysis),
        }

    def mutable_payload(self) -> dict[str, Any]:
        """Return independent mutable region facts for global analysis."""

        return {
            "contract": _thaw_json(self.contract),
            "initial_static_code_pointer_analysis": _thaw_json(
                self.initial_static_code_pointer_analysis
            ),
            "indirect_call_candidates": _thaw_json(
                self.indirect_call_candidates
            ),
            "table_call_proposals": _thaw_json(self.table_call_proposals),
            "dynamic_call_candidates": _thaw_json(
                self.dynamic_call_candidates
            ),
            "import_register_seeds": _thaw_json(self.import_register_seeds),
            "machine_call_analysis": _thaw_json(self.machine_call_analysis),
        }


def region_facts_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    input_relation_contract_sha256: str,
    normalized_behaviors_sha256: str,
    region_facts_semantics_sha256: str,
    region_count: int,
    contract: Mapping[str, Any],
    initial_static_code_pointer_analysis: Mapping[str, Any],
    indirect_call_candidates: list[Mapping[str, Any]],
    table_call_proposals: list[Mapping[str, Any]],
    dynamic_call_candidates: list[Mapping[str, Any]],
    import_register_seeds: list[Mapping[str, Any]],
    machine_call_analysis: Mapping[str, Any],
) -> dict[str, Any]:
    payload = {
        "format": REGION_FACTS_ARTIFACT_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": REGION_FACTS_ARTIFACT_STATUS,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "input_relation_contract_sha256": input_relation_contract_sha256,
        "normalized_behaviors_sha256": normalized_behaviors_sha256,
        "region_facts_semantics_sha256": region_facts_semantics_sha256,
        "region_count": region_count,
        "contract": contract,
        "initial_static_code_pointer_analysis": (
            initial_static_code_pointer_analysis
        ),
        "indirect_call_candidates": indirect_call_candidates,
        "table_call_proposals": table_call_proposals,
        "dynamic_call_candidates": dynamic_call_candidates,
        "import_register_seeds": import_register_seeds,
        "machine_call_analysis": machine_call_analysis,
    }
    return RegionFactsArtifact.parse(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_input_relation_contract_sha256=(
            input_relation_contract_sha256
        ),
        expected_normalized_behaviors_sha256=normalized_behaviors_sha256,
        expected_region_facts_semantics_sha256=(
            region_facts_semantics_sha256
        ),
    ).to_payload()


def region_facts_artifact_sha256(
    artifact: RegionFactsArtifact | Mapping[str, Any],
) -> str:
    parsed = (
        artifact
        if isinstance(artifact, RegionFactsArtifact)
        else RegionFactsArtifact.parse(artifact)
    )
    encoded = json.dumps(
        parsed.to_payload(),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256_bytes(encoded)


__all__ = [
    "REGION_FACTS_ARTIFACT_FORMAT",
    "REGION_FACTS_ARTIFACT_STATUS",
    "RegionFactsArtifact",
    "region_facts_artifact_sha256",
    "region_facts_payload",
]
