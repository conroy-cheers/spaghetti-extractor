from __future__ import annotations

from pathlib import Path


def test_mixed_context_keeps_static_authorities_independent() -> None:
    source = (
        Path(__file__).parents[1]
        / "src/spaghetti_extractor/lean/StageA"
        / "RelationalInterpreterMixedContext.lean"
    ).read_text(encoding="utf-8")

    candidate_start = source.index("structure ExactNativeCandidateAuthority")
    candidate_end = source.index("structure NativeExternalBoundary")
    candidate_authority = source[candidate_start:candidate_end]

    assert "StaticProofContext" not in candidate_authority
    assert "StaticCodeMap" not in candidate_authority
    assert "candidate.pe" in candidate_authority
    assert "candidate.imports" in candidate_authority
    assert "ProgramTableCertificate" in candidate_authority
    assert (
        "semanticRecords : List StageA.Relational.Interpreter.ProgramRecord"
        in candidate_authority
    )
    assert "  status :" not in source
    assert "authorized : Bool" not in source


def test_mixed_observation_relation_fails_closed_on_blocked_execution() -> None:
    source = (
        Path(__file__).parents[1]
        / "src/spaghetti_extractor/lean/StageA"
        / "RelationalInterpreterMixedContext.lean"
    ).read_text(encoding="utf-8")

    assert "| _, _ => False" in source
    assert "proofBlocked_left_is_unrelated" in source
    assert "proofBlocked_right_is_unrelated" in source
    assert "original.eventIndex = candidate.eventIndex" in source
    assert "original.imported = normalizeImport candidate.event.imported" in source
