from __future__ import annotations

import json
from pathlib import Path

import pytest

from spaghetti_extractor.relational.lean.interpreter_mixed_relation_core import (
    INTERPRETER_MIXED_RELATION_CORE_FORMAT,
    InterpreterMixedRelationCoreGenerationError,
    InterpreterMixedRelationCoreSpec,
    relational_interpreter_mixed_relation_core_source,
    write_interpreter_mixed_relation_core_bundle,
)


def _spec() -> InterpreterMixedRelationCoreSpec:
    return InterpreterMixedRelationCoreSpec(
        binding_module="StageA.GeneratedBinding",
        namespace="StageA.Generated.RelationCore",
        output_module="GeneratedRelationCore",
        parameter_name="requirements",
        parameter_type="StageA.GeneratedBinding.Requirements",
        original_context="requirements.original",
        original_authority="requirements.originalAuthority",
        original_program="requirements.originalProgram",
        candidate="requirements.candidate",
        candidate_authority="requirements.candidateAuthority",
        program_binding="requirements.programBinding",
        concrete_abi="requirements.abi",
        launch="requirements.launch",
        original_root="requirements.originalRoot",
        reachability="requirements.reachability",
        launch_memory_profile="requirements.launchMemoryProfile",
    )


def test_emits_checked_parser_derived_core_without_status_authority() -> None:
    source = relational_interpreter_mixed_relation_core_source(_spec())
    assert "canonicalMixedLaunchAnchors? requirements.candidate" in source
    assert "canonicalMixedLaunchAnchors?_eq_some_get" in source
    assert "canonicalMixedLaunchAnchors?_complete" in source
    assert "MixedNativeCodeAnchorsValid" in source
    assert "CanonicalMixedRelationCore" in source
    assert "decide +kernel" in source
    for forbidden in ("sorry", "axiom ", "native_decide", "status", "verdict"):
        assert forbidden not in source


def test_writer_is_deterministic_and_non_accepting(tmp_path: Path) -> None:
    first = tmp_path / "first" / "StageA"
    second = tmp_path / "second" / "StageA"
    first_source, first_plan = write_interpreter_mixed_relation_core_bundle(
        first, _spec()
    )
    second_source, second_plan = write_interpreter_mixed_relation_core_bundle(
        second, _spec()
    )
    assert first_source.read_bytes() == second_source.read_bytes()
    first_payload = json.loads(first_plan.read_text(encoding="utf-8"))
    second_payload = json.loads(second_plan.read_text(encoding="utf-8"))
    assert first_payload == second_payload
    assert first_payload["format"] == INTERPRETER_MIXED_RELATION_CORE_FORMAT
    assert first_payload["acceptance_authority"] is False
    assert first_payload["lean_check_required"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("binding_module", "GeneratedBinding"),
        ("namespace", "bad namespace"),
        ("output_module", "StageA.GeneratedRelationCore"),
        ("parameter_name", "requirements value"),
        ("candidate", ""),
    ),
)
def test_rejects_malformed_spec(field: str, value: str) -> None:
    values = dict(_spec().__dict__)
    values[field] = value
    with pytest.raises(InterpreterMixedRelationCoreGenerationError):
        relational_interpreter_mixed_relation_core_source(
            InterpreterMixedRelationCoreSpec(**values)
        )
