from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ...stage_binary import StageAInputError


RELATIONAL_EXACT_IDENTITY_FORMAT = "stage-a-relational-exact-identity-v2"
RELATIONAL_IDENTITY_FORMAT = RELATIONAL_EXACT_IDENTITY_FORMAT

_ROOT_FIELDS = frozenset({
    "format",
    "source_module",
    "context",
    "launch",
    "decoded_segment_ids",
    "reachable_segment_ids",
    "mappings_identity",
    "decoded_segment_ids_bound",
    "pe32_region_semantics_identity",
    "pe32_transition_system_identity",
    "original",
    "candidate",
})
_SIDE_FIELDS = frozenset({
    "pe_sha256",
    "pe_bytes",
    "program",
    "environment",
    "protocol_environment",
})
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise StageAInputError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise StageAInputError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _lean_name(value: object, context: str) -> str:
    if not isinstance(value, str) or _LEAN_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a qualified Lean identifier")
    return value


def _natural_ids(value: object, context: str, *, nonempty: bool) -> tuple[int, ...]:
    if not isinstance(value, list) or (nonempty and not value):
        requirement = "a non-empty" if nonempty else "a"
        raise StageAInputError(f"{context} must be {requirement} JSON array")
    result: list[int] = []
    for index, item in enumerate(value):
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise StageAInputError(f"{context}[{index}] must be a natural number")
        result.append(item)
    if len(set(result)) != len(result):
        raise StageAInputError(f"{context} contains duplicates")
    if result != sorted(result):
        raise StageAInputError(f"{context} must be in canonical ascending order")
    return tuple(result)


def _side(value: object, context: str) -> dict[str, str]:
    side = _object(value, context)
    _require_exact_fields(side, _SIDE_FIELDS, context)
    digest = side["pe_sha256"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise StageAInputError(
            f"{context} pe_sha256 must be a canonical SHA-256 digest"
        )
    return {
        "pe_sha256": digest,
        "pe_bytes": _lean_name(side["pe_bytes"], f"{context} pe_bytes"),
        "program": _lean_name(side["program"], f"{context} program"),
        "environment": _lean_name(
            side["environment"], f"{context} environment"
        ),
        "protocol_environment": _lean_name(
            side["protocol_environment"],
            f"{context} protocol_environment",
        ),
    }


def _validated_artifact(
    payload: object,
) -> tuple[
    dict[str, str],
    dict[str, str],
    dict[str, str],
    tuple[int, ...],
    tuple[int, ...],
]:
    artifact = _object(payload, "relational exact-identity artifact")
    _require_exact_fields(
        artifact, _ROOT_FIELDS, "relational exact-identity artifact"
    )
    if artifact["format"] != RELATIONAL_EXACT_IDENTITY_FORMAT:
        raise StageAInputError(
            "unsupported relational exact-identity artifact format"
        )
    names = {
        field: _lean_name(artifact[field], field)
        for field in (
            "source_module",
            "context",
            "launch",
            "mappings_identity",
            "decoded_segment_ids_bound",
            "pe32_region_semantics_identity",
            "pe32_transition_system_identity",
        )
    }
    decoded = _natural_ids(
        artifact["decoded_segment_ids"], "decoded_segment_ids", nonempty=True
    )
    reachable = _natural_ids(
        artifact["reachable_segment_ids"],
        "reachable_segment_ids",
        nonempty=True,
    )
    missing = sorted(set(reachable) - set(decoded))
    if missing:
        rendered = ", ".join(str(segment_id) for segment_id in missing)
        raise StageAInputError(
            f"reachable_segment_ids are absent from decoded_segment_ids: {rendered}"
        )
    return (
        names,
        _side(artifact["original"], "original identity side"),
        _side(artifact["candidate"], "candidate identity side"),
        decoded,
        reachable,
    )


def relational_exact_identity_source(payload: object) -> str:
    """Render checked current-world identity evidence and an intermediate theorem.

    Coverage, reachability, launch, and instruction adequacy remain explicit
    Lean premises.  This generator never emits a current Stage A acceptance
    theorem or a `WholeProgramCertificate`.
    """
    names, original, candidate, decoded, reachable = _validated_artifact(payload)
    decoded_literal = ", ".join(str(segment_id) for segment_id in decoded)
    reachable_literal = ", ".join(str(segment_id) for segment_id in reachable)
    original_hash = json.dumps(original["pe_sha256"])
    candidate_hash = json.dumps(candidate["pe_sha256"])
    original_program = original["program"]
    candidate_program = candidate["program"]
    context = names["context"]
    launch = names["launch"]

    evidence_arguments = (
        "exactIdentityOriginalPESha256 exactIdentityCandidatePESha256\n"
        f"    {original['pe_bytes']} {candidate['pe_bytes']}\n"
        "    exactIdentityDecodedSegmentIds exactIdentityReachableSegmentIds\n"
        f"    {context} {original_program} {candidate_program}\n"
        f"    {original['environment']} {candidate['environment']}\n"
        f"    {original['protocol_environment']}\n"
        f"      {candidate['protocol_environment']}"
    )

    return (
        "import StageA.RelationalIdentity\n"
        f"import {names['source_module']}\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        f"def exactIdentityOriginalPESha256 : String := {original_hash}\n\n"
        f"def exactIdentityCandidatePESha256 : String := {candidate_hash}\n\n"
        "def exactIdentityDecodedSegmentIds : List Nat :=\n"
        f"  [{decoded_literal}]\n\n"
        "def exactIdentityReachableSegmentIds : List Nat :=\n"
        f"  [{reachable_literal}]\n\n"
        "def exactIdentityEvidence : ExactPE32WorldIdentityEvidence\n"
        f"    {evidence_arguments} := {{\n"
        "  originalPEBytesBound := by rfl\n"
        "  candidatePEBytesBound := by rfl\n"
        "  peHashesIdentical := by decide\n"
        "  peBytesIdentical := by rfl\n"
        "  typedPEsIdentical := by rfl\n"
        f"  mappingsIdentical := {names['mappings_identity']}\n"
        "  originalContextBound := by rfl\n"
        "  candidateContextBound := by rfl\n"
        "  originalSide := by decide\n"
        "  candidateSide := by decide\n"
        f"  decodedSegmentIdsBound := {names['decoded_segment_ids_bound']}\n"
        "  decodedSegmentIdsNonempty := by decide\n"
        "  regionsIdentical := by rfl\n"
        "  reachableSegmentsCovered := by decide\n"
        "  externalCallSitesIdentical := by rfl\n"
        "  originalEnvironmentBound := by rfl\n"
        "  candidateEnvironmentBound := by rfl\n"
        "  worldEnvironmentsIdentical := by rfl\n"
        "  originalProtocolEnvironmentBound := by rfl\n"
        "  candidateProtocolEnvironmentBound := by rfl\n"
        "  protocolEnvironmentsIdentical := by rfl\n"
        "  pe32RegionSemanticsIdentical :=\n"
        f"    {names['pe32_region_semantics_identity']}\n"
        "  pe32TransitionSystemsIdentical :=\n"
        f"    {names['pe32_transition_system_identity']}\n"
        "}\n\n"
        "theorem exactIdentityPE32WorldReflexivityIntermediate\n"
        "    {graph : RelationalProductGraph}\n"
        "    {invariants : ProductInvariantTable}\n"
        "    {reachability : RelationalProductReachabilityEvidence}\n"
        "    {control : ProductControlProfile}\n"
        "    (frontier : ExactIdentityPE32CheckedFrontier\n"
        f"      {context} graph {original_program}.regions\n"
        "      exactIdentityReachableSegmentIds invariants reachability\n"
        f"      control {launch} {original_program} {candidate_program}) :\n"
        "    ExactIdentityPE32WorldReflexivityIntermediate\n"
        "      exactIdentityOriginalPESha256 exactIdentityCandidatePESha256\n"
        f"      {original['pe_bytes']} {candidate['pe_bytes']}\n"
        "      exactIdentityDecodedSegmentIds exactIdentityReachableSegmentIds\n"
        f"      {context} graph {original_program}.regions invariants reachability\n"
        f"      control {launch} {original_program} {candidate_program}\n"
        f"      {original['environment']} {candidate['environment']}\n"
        f"      {original['protocol_environment']}\n"
        f"      {candidate['protocol_environment']} :=\n"
        "  exactIdentityEvidence.worldReflexivityIntermediate frontier\n\n"
        "end StageA.GeneratedRelational\n"
    )


def relational_identity_source(payload: object) -> str:
    return relational_exact_identity_source(payload)
