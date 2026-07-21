from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..relational.schema import RELATIONAL_APPROVED_AXIOMS
from ..relational.executor import _run_lean_relational
from ..relational.lean.definitions import _lean_counterexample_source
from ..stage_binary import StageAInputError, _parse_stage_a_pe
from ..util import sha256_file
from .model import (
    CaseManifest,
    _exact_fields,
    _identifier,
    _integer,
    _nonempty_string,
    _object,
    _sha256,
    _string_tuple,
)


VIOLATION_WITNESS_FORMAT = "stage-a-violation-witness-v1"
VIOLATION_CHECK_FORMAT = "stage-a-violation-check-v1"
_HEX_BYTES_RE = re.compile(r"(?:[0-9a-f]{2})+")
_MISMATCH_KINDS = frozenset({
    "register_relation",
    "flag_relation",
    "memory_write_relation",
    "branch_destination",
    "external_event",
    "termination",
    "fault",
})


def produce_checked_violation(
    *,
    witness_path: Path,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
    out: Path,
) -> dict[str, Any]:
    """Replay a proposed concrete mismatch through exact Lean PE semantics."""

    witness_path = Path(witness_path)
    case_root = Path(case_root)
    prepared = Path(prepared)
    out = Path(out)
    witness = ViolationWitness.parse(_load_object(witness_path, "violation witness"))
    _validate_witness_input_bindings(
        witness=witness,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    if witness.location.original.region_index != witness.location.candidate.region_index:
        raise StageAInputError(
            "violation replay currently requires one paired relation region"
        )
    region_index = witness.location.original.region_index
    contract = _load_object(
        prepared / "relation-contract.json", "normalized relation contract"
    )
    decoded = _load_object(
        prepared / "relational-decoded-behaviors.json", "decoded behaviors"
    )
    regions = contract.get("regions")
    decoded_regions = decoded.get("regions")
    if not isinstance(regions, list) or region_index >= len(regions):
        raise StageAInputError("violation witness region is outside the relation contract")
    if not isinstance(decoded_regions, list) or region_index >= len(decoded_regions):
        raise StageAInputError("violation witness region is outside decoded behaviors")
    region = regions[region_index]
    decoded_region = decoded_regions[region_index]
    if not isinstance(region, dict) or not isinstance(decoded_region, dict):
        raise StageAInputError("violation replay region records are malformed")
    if decoded_region.get("index") != region_index:
        raise StageAInputError("decoded violation region index is not canonical")
    original_term = decoded_region.get("original_term")
    candidate_term = decoded_region.get("candidate_term")
    if not isinstance(original_term, str) or not isinstance(candidate_term, str):
        raise StageAInputError("decoded violation region omits Lean behavior terms")
    for side, location in (
        ("original", witness.location.original),
        ("candidate", witness.location.candidate),
    ):
        span = region.get(side)
        if (
            not isinstance(span, dict)
            or location.rva != span.get("rva_start")
            or len(bytes.fromhex(location.bytes_hex)) != span.get("size")
        ):
            raise StageAInputError(
                f"violation {side} location must bind the complete relation region"
            )
    assignment = {
        f"{side_prefix}{register}": value
        for side_prefix, state in (
            ("o", witness.original_pre_state),
            ("c", witness.candidate_pre_state),
        )
        for register, value in state.registers
    }
    original_binary_path = case.artifact("original_pe").verify(case_root)
    candidate_binary_path = case.artifact("candidate_pe").verify(case_root)
    original_bin = _parse_stage_a_pe(original_binary_path)
    candidate_bin = _parse_stage_a_pe(candidate_binary_path)
    source = _lean_counterexample_source(
        original_bin,
        candidate_bin,
        original_binary_path.read_bytes(),
        candidate_binary_path.read_bytes(),
        contract.get("code_targets", []),
        contract.get("machine_import_call_contracts", []),
        region,
        region_index,
        {"original": original_term, "candidate": candidate_term},
        assignment,
        original_state=witness.original_pre_state.to_payload(),
        candidate_state=witness.candidate_pre_state.to_payload(),
    )
    lean_dir = out / "lean"
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(prepared / "lean", lean_dir)
    source_path = lean_dir / "StageA" / "RelationalCounterexample.lean"
    source_path.write_text(source, encoding="utf-8")
    checked = _run_lean_relational(lean_dir, bundle="RelationalCounterexample")
    combined = str(checked.get("stdout") or "") + "\n" + str(
        checked.get("stderr") or ""
    )
    observed_axioms: set[str] = set()
    for match in re.findall(r"depends on axioms: \[(.*?)\]", combined, re.DOTALL):
        observed_axioms.update(
            item.strip()
            for item in match.replace("\n", " ").split(",")
            if item.strip()
        )
    unexpected_axioms = sorted(observed_axioms - RELATIONAL_APPROVED_AXIOMS)
    audit = {
        "format": VIOLATION_CHECK_FORMAT,
        "status": "checked" if checked.get("status") == "checked" else "incomplete",
        "witness_sha256": sha256_file(witness_path),
        "theorem": (
            "StageA.GeneratedRelationalCounterexample.exactCounterexample"
        ),
        "lean_trust": 0,
        "observed_axioms": sorted(observed_axioms),
        "unexpected_axioms": unexpected_axioms,
        "decoded_behaviors_sha256": sha256_file(
            prepared / "relational-decoded-behaviors.json"
        ),
        "original_sha256": original_bin.sha256,
        "candidate_sha256": candidate_bin.sha256,
    }
    out.mkdir(parents=True, exist_ok=True)
    audit_path = out / "audit.json"
    from ..util import write_json

    write_json(audit_path, audit)
    return {
        "format": "stage-a-violation-production-v1",
        "status": audit["status"],
        "audit": str(audit_path),
        "source": str(source_path),
        "source_sha256": sha256_file(source_path),
        "lean": checked,
    }


@dataclass(frozen=True)
class BinaryBindings:
    original_sha256: str
    candidate_sha256: str
    relation_contract_sha256: str
    decoded_behaviors_sha256: str
    capability_profile: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "BinaryBindings":
        _exact_fields(payload, {
            "original_sha256", "candidate_sha256", "relation_contract_sha256",
            "decoded_behaviors_sha256", "capability_profile",
        }, context)
        return cls(
            original_sha256=_sha256(payload["original_sha256"], f"{context}.original_sha256"),
            candidate_sha256=_sha256(payload["candidate_sha256"], f"{context}.candidate_sha256"),
            relation_contract_sha256=_sha256(
                payload["relation_contract_sha256"],
                f"{context}.relation_contract_sha256",
            ),
            decoded_behaviors_sha256=_sha256(
                payload["decoded_behaviors_sha256"],
                f"{context}.decoded_behaviors_sha256",
            ),
            capability_profile=_identifier(
                payload["capability_profile"], f"{context}.capability_profile"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "relation_contract_sha256": self.relation_contract_sha256,
            "decoded_behaviors_sha256": self.decoded_behaviors_sha256,
            "capability_profile": self.capability_profile,
        }


@dataclass(frozen=True)
class SemanticLocation:
    semantic_id: str
    region_index: int
    rva: int
    bytes_hex: str
    path: tuple[str, ...]

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "SemanticLocation":
        _exact_fields(payload, {"semantic_id", "region_index", "rva", "bytes_hex", "path"}, context)
        bytes_hex = payload["bytes_hex"]
        if not isinstance(bytes_hex, str) or _HEX_BYTES_RE.fullmatch(bytes_hex) is None:
            raise StageAInputError(f"{context}.bytes_hex must be nonempty lowercase bytes")
        return cls(
            semantic_id=_identifier(payload["semantic_id"], f"{context}.semantic_id"),
            region_index=_integer(payload["region_index"], f"{context}.region_index"),
            rva=_integer(payload["rva"], f"{context}.rva"),
            bytes_hex=bytes_hex,
            path=_string_tuple(
                payload["path"], f"{context}.path", identifiers=True, unique=False
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "region_index": self.region_index,
            "rva": self.rva,
            "bytes_hex": self.bytes_hex,
            "path": list(self.path),
        }


@dataclass(frozen=True)
class WitnessLocation:
    original: SemanticLocation
    candidate: SemanticLocation

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "WitnessLocation":
        _exact_fields(payload, {"original", "candidate"}, context)
        return cls(
            original=SemanticLocation.parse(
                _object(payload["original"], f"{context}.original"),
                context=f"{context}.original",
            ),
            candidate=SemanticLocation.parse(
                _object(payload["candidate"], f"{context}.candidate"),
                context=f"{context}.candidate",
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "original": self.original.to_payload(),
            "candidate": self.candidate.to_payload(),
        }


@dataclass(frozen=True)
class ConcreteState:
    registers: tuple[tuple[str, int], ...]
    eflags: int
    memory_words: tuple[tuple[int, int], ...]
    path_guards: tuple[str, ...]
    world_state_sha256: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ConcreteState":
        _exact_fields(payload, {
            "registers", "eflags", "memory_words", "path_guards",
            "world_state_sha256",
        }, context)
        raw_registers = _object(payload["registers"], f"{context}.registers")
        expected_registers = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
        _exact_fields(raw_registers, expected_registers, f"{context}.registers")
        registers = tuple(
            (register, _word(raw_registers[register], f"{context}.registers.{register}"))
            for register in sorted(expected_registers)
        )
        raw_memory = payload["memory_words"]
        if not isinstance(raw_memory, list):
            raise StageAInputError(f"{context}.memory_words must be a list")
        memory_words: list[tuple[int, int]] = []
        for index, item in enumerate(raw_memory):
            item_context = f"{context}.memory_words[{index}]"
            row = _object(item, item_context)
            _exact_fields(row, {"address", "value"}, item_context)
            memory_words.append((
                _word(row["address"], f"{item_context}.address"),
                _word(row["value"], f"{item_context}.value"),
            ))
        if len({address for address, _value in memory_words}) != len(memory_words):
            raise StageAInputError(f"{context}.memory_words addresses must be unique")
        return cls(
            registers=registers,
            eflags=_word(payload["eflags"], f"{context}.eflags"),
            memory_words=tuple(memory_words),
            path_guards=_string_tuple(
                payload["path_guards"], f"{context}.path_guards",
                identifiers=True, unique=False
            ),
            world_state_sha256=_sha256(
                payload["world_state_sha256"], f"{context}.world_state_sha256"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "registers": dict(self.registers),
            "eflags": self.eflags,
            "memory_words": [
                {"address": address, "value": value}
                for address, value in self.memory_words
            ],
            "path_guards": list(self.path_guards),
            "world_state_sha256": self.world_state_sha256,
        }


@dataclass(frozen=True)
class MismatchEffect:
    kind: str
    location: str
    value: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "MismatchEffect":
        _exact_fields(payload, {"kind", "location", "value"}, context)
        kind = payload["kind"]
        if kind not in {"word", "boolean", "control_target", "event_identity"}:
            raise StageAInputError(f"{context}.kind is unsupported")
        return cls(
            kind=str(kind),
            location=_nonempty_string(payload["location"], f"{context}.location"),
            value=_word(payload["value"], f"{context}.value"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "location": self.location, "value": self.value}


@dataclass(frozen=True)
class Mismatch:
    kind: str
    relation_atom: str
    original_effect: MismatchEffect
    candidate_effect: MismatchEffect
    observation: str
    event_index: int | None

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "Mismatch":
        _exact_fields(payload, {
            "kind", "relation_atom", "original_effect", "candidate_effect",
            "observation", "event_index",
        }, context)
        kind = payload["kind"]
        if kind not in _MISMATCH_KINDS:
            raise StageAInputError(f"{context}.kind is unsupported")
        event_index_raw = payload["event_index"]
        event_index = (
            None
            if event_index_raw is None
            else _integer(event_index_raw, f"{context}.event_index")
        )
        if (kind == "external_event") != (event_index is not None):
            raise StageAInputError(
                f"{context}.event_index is required exactly for external-event mismatches"
            )
        return cls(
            kind=str(kind),
            relation_atom=_identifier(payload["relation_atom"], f"{context}.relation_atom"),
            original_effect=MismatchEffect.parse(
                _object(payload["original_effect"], f"{context}.original_effect"),
                context=f"{context}.original_effect",
            ),
            candidate_effect=MismatchEffect.parse(
                _object(payload["candidate_effect"], f"{context}.candidate_effect"),
                context=f"{context}.candidate_effect",
            ),
            observation=_identifier(payload["observation"], f"{context}.observation"),
            event_index=event_index,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "relation_atom": self.relation_atom,
            "original_effect": self.original_effect.to_payload(),
            "candidate_effect": self.candidate_effect.to_payload(),
            "observation": self.observation,
            "event_index": self.event_index,
        }


@dataclass(frozen=True)
class ViolationWitness:
    id: str
    obligation_id: str
    family: str
    bindings: BinaryBindings
    location: WitnessLocation
    original_pre_state: ConcreteState
    candidate_pre_state: ConcreteState
    mismatch: Mismatch
    replay: tuple[str, ...]
    format: str = VIOLATION_WITNESS_FORMAT

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ViolationWitness":
        context = "Stage A violation witness"
        _exact_fields(payload, {
            "format", "id", "obligation_id", "family", "bindings", "location",
            "original_pre_state", "candidate_pre_state", "mismatch", "replay",
        }, context)
        if payload["format"] != VIOLATION_WITNESS_FORMAT:
            raise StageAInputError("unsupported Stage A violation witness format")
        replay = _string_tuple(
            payload["replay"], f"{context}.replay", unique=False
        )
        if not replay:
            raise StageAInputError("Stage A violation replay command must not be empty")
        witness = cls(
            id=_identifier(payload["id"], f"{context}.id"),
            obligation_id=_nonempty_string(
                payload["obligation_id"], f"{context}.obligation_id"
            ),
            family=_identifier(payload["family"], f"{context}.family"),
            bindings=BinaryBindings.parse(
                _object(payload["bindings"], f"{context}.bindings"),
                context=f"{context}.bindings",
            ),
            location=WitnessLocation.parse(
                _object(payload["location"], f"{context}.location"),
                context=f"{context}.location",
            ),
            original_pre_state=ConcreteState.parse(
                _object(payload["original_pre_state"], f"{context}.original_pre_state"),
                context=f"{context}.original_pre_state",
            ),
            candidate_pre_state=ConcreteState.parse(
                _object(payload["candidate_pre_state"], f"{context}.candidate_pre_state"),
                context=f"{context}.candidate_pre_state",
            ),
            mismatch=Mismatch.parse(
                _object(payload["mismatch"], f"{context}.mismatch"),
                context=f"{context}.mismatch",
            ),
            replay=replay,
        )
        if witness.mismatch.original_effect.value == witness.mismatch.candidate_effect.value:
            raise StageAInputError("violation witness effects do not conflict")
        return witness

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "id": self.id,
            "obligation_id": self.obligation_id,
            "family": self.family,
            "bindings": self.bindings.to_payload(),
            "location": self.location.to_payload(),
            "original_pre_state": self.original_pre_state.to_payload(),
            "candidate_pre_state": self.candidate_pre_state.to_payload(),
            "mismatch": self.mismatch.to_payload(),
            "replay": list(self.replay),
        }


def _validate_witness_input_bindings(
    *,
    witness: ViolationWitness,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
) -> None:
    normalized_relation_path = Path(prepared) / "relation-contract.json"
    decoded_path = Path(prepared) / "relational-decoded-behaviors.json"
    if not normalized_relation_path.is_file():
        raise StageAInputError(
            "violation replay requires the normalized relation contract"
        )
    if not decoded_path.is_file():
        raise StageAInputError("violation replay requires bound decoded behaviors")
    expected = {
        "original": case.artifact("original_pe").sha256,
        "candidate": case.artifact("candidate_pe").sha256,
        "relation": sha256_file(normalized_relation_path),
        "decoded": sha256_file(decoded_path),
    }
    observed = {
        "original": witness.bindings.original_sha256,
        "candidate": witness.bindings.candidate_sha256,
        "relation": witness.bindings.relation_contract_sha256,
        "decoded": witness.bindings.decoded_behaviors_sha256,
    }
    if observed != expected:
        raise StageAInputError("violation witness input bindings are stale")
    if witness.bindings.capability_profile != case.capability_profile:
        raise StageAInputError("violation witness capability profile does not match")
    if case.mutation is None:
        raise StageAInputError("violation witness requires a declared negative mutation")
    if (
        witness.location.original.semantic_id != case.mutation.location_id
        or witness.location.candidate.semantic_id != case.mutation.location_id
    ):
        raise StageAInputError("violation witness semantic location does not match mutation")
    if not _location_bytes_match(
        case.artifact("original_pe").verify(case_root), witness.location.original
    ):
        raise StageAInputError("violation witness original bytes do not match the PE")
    if not _location_bytes_match(
        case.artifact("candidate_pe").verify(case_root), witness.location.candidate
    ):
        raise StageAInputError("violation witness candidate bytes do not match the PE")


def validate_checked_violation(
    *,
    witness_path: Path,
    audit_path: Path,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
) -> dict[str, Any]:
    witness_path = Path(witness_path)
    audit_path = Path(audit_path)
    witness = ViolationWitness.parse(_load_object(witness_path, "violation witness"))
    audit = _load_object(audit_path, "violation Lean audit")
    _validate_witness_input_bindings(
        witness=witness,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    _exact_fields(audit, {
        "format", "status", "witness_sha256", "theorem", "lean_trust",
        "observed_axioms", "unexpected_axioms", "decoded_behaviors_sha256",
        "original_sha256", "candidate_sha256",
    }, "violation Lean audit")
    if audit["format"] != VIOLATION_CHECK_FORMAT:
        raise StageAInputError("unsupported violation Lean audit format")
    expected_original = case.artifact("original_pe").sha256
    expected_candidate = case.artifact("candidate_pe").sha256
    normalized_relation_path = Path(prepared) / "relation-contract.json"
    expected_relation = sha256_file(normalized_relation_path)
    decoded_path = Path(prepared) / "relational-decoded-behaviors.json"
    checks = {
        "audit_checked": audit["status"] == "checked",
        "witness_hash_matches": audit["witness_sha256"] == sha256_file(witness_path),
        "lean_trust_zero": audit["lean_trust"] == 0,
        "theorem_is_violation_witness": (
            audit["theorem"] == (
                "StageA.GeneratedRelationalCounterexample.exactCounterexample"
            )
        ),
        "axioms_approved": (
            isinstance(audit["observed_axioms"], list)
            and set(audit["observed_axioms"]).issubset(RELATIONAL_APPROVED_AXIOMS)
            and audit["unexpected_axioms"] == []
        ),
        "original_binding": (
            witness.bindings.original_sha256 == expected_original
            and audit["original_sha256"] == expected_original
        ),
        "candidate_binding": (
            witness.bindings.candidate_sha256 == expected_candidate
            and audit["candidate_sha256"] == expected_candidate
        ),
        "relation_binding": witness.bindings.relation_contract_sha256 == expected_relation,
        "decoded_binding": (
            witness.bindings.decoded_behaviors_sha256 == sha256_file(decoded_path)
            and audit["decoded_behaviors_sha256"] == sha256_file(decoded_path)
        ),
        "expected_family": case.expectation.witness_family == witness.family,
        "original_bytes_match": _location_bytes_match(
            case.artifact("original_pe").verify(case_root), witness.location.original
        ),
        "candidate_bytes_match": _location_bytes_match(
            case.artifact("candidate_pe").verify(case_root), witness.location.candidate
        ),
    }
    status = "violated" if all(checks.values()) else "incomplete"
    return {
        "format": "stage-a-checked-violation-result-v1",
        "status": status,
        "violation_id": witness.id,
        "obligation_id": witness.obligation_id,
        "family": witness.family,
        "checks": checks,
        "first_proved_mismatch": {
            "original": witness.location.original.to_payload(),
            "candidate": witness.location.candidate.to_payload(),
            "relation_atom": witness.mismatch.relation_atom,
            "original_effect": witness.mismatch.original_effect.to_payload(),
            "candidate_effect": witness.mismatch.candidate_effect.to_payload(),
        },
        "trust": {
            "role": "checked_inequivalence_witness",
            "can_authorize_pass": False,
            "raw_solver_status_sufficient": False,
        },
    }


def _location_bytes_match(binary_path: Path, location: SemanticLocation) -> bool:
    binary = _parse_stage_a_pe(binary_path)
    expected = bytes.fromhex(location.bytes_hex)
    return binary.pe.get_data(location.rva, len(expected)) == expected


def _word(value: Any, context: str) -> int:
    result = _integer(value, context)
    if result >= 2**32:
        raise StageAInputError(f"{context} must be a 32-bit word")
    return result


def _load_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc
    return _object(payload, context)
