from __future__ import annotations

from pathlib import Path


_SOURCE = (
    Path(__file__).parents[1]
    / "src/spaghetti_extractor/lean/StageA"
    / "RelationalInterpreterMixedWorldBridge.lean"
)


def test_mixed_world_bridge_excludes_paired_candidate_authority() -> None:
    source = _SOURCE.read_text(encoding="utf-8")

    assert "ExactOriginalDecodedAuthority" in source
    assert "ExactNativeCandidateAuthority" in source
    assert "DirectExactOriginalDecodedLaunchRoot" in source
    assert "DirectExactCandidateNativeLaunchRoot" in source
    assert "resolveRawEip true" not in source
    assert "context.candidatePe" not in source
    assert "context.candidateImports" not in source
    assert "worldRelationalObservationsRelated" not in source
    assert "launch.StatesRelated" not in source


def test_mixed_world_bridge_is_operational_and_fail_closed() -> None:
    source = _SOURCE.read_text(encoding="utf-8")

    assert "original.pe32TransitionSystem" in source
    assert "candidate.transitionSystem" in source
    assert "contract.eventObservationsRelated" in source
    assert "ChunkedRelatedTrace" in source
    assert "chunkedRelationalBisimulation_trace" in source
    assert "| .blocked _ => False" in source
    assert "  status :" not in source
    assert "authorized : Bool" not in source
    assert "simulate :" not in source
