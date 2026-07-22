from __future__ import annotations

import json
import shutil
import unittest
from dataclasses import dataclass
import tempfile
from pathlib import Path
from unittest import mock

from spaghetti_extractor.cli import main
from spaghetti_extractor.roundtrip_fuzz.generator import generate_spike_corpus
from spaghetti_extractor.roundtrip_fuzz.model import (
    CaseExpectation,
    CaseManifest,
    ExpectedDisposition,
    NegativeMutation,
    artifact_refs,
    load_case_manifest,
    write_case_manifest,
)
from spaghetti_extractor.roundtrip_fuzz.reducer import (
    ArtifactPredicate,
    DeterministicPredicate,
    NondeterministicReductionPredicate,
    PredicateRun,
    PredicateObservation,
    ReductionCandidate,
    ReductionCandidateRejected,
    TransformationMetadata,
    StablePredicateSpec,
    evaluate_stable_predicate,
    reduce_case_manifest,
    reduce_roundtrip_case,
    reduce_roundtrip_case_artifacts,
)
from spaghetti_extractor.roundtrip_fuzz.semantic import (
    AssignRegister,
    Branch,
    Jump,
    Nop,
    RegisterArithmetic,
    Return,
    ScalarValue,
    SemanticBlock,
    SemanticProgram,
    StaticObject,
    ValueKind,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


@dataclass(frozen=True)
class _Regenerated:
    candidate_sha256: str
    required_operation_present: bool
    transformations: tuple[str, ...]


def _program() -> SemanticProgram:
    return SemanticProgram.parse(SemanticProgram(
        id="reducer-program",
        entry="entry",
        blocks=(
            SemanticBlock(
                id="entry",
                operations=(
                    Nop(),
                    AssignRegister(
                        register="eax",
                        value=ScalarValue(ValueKind.CONSTANT, 32, 7),
                    ),
                ),
                terminator=Branch("zero", "left", "right"),
            ),
            SemanticBlock(
                id="left",
                operations=(RegisterArithmetic("eax", "add", 1),),
                terminator=Jump("done"),
            ),
            SemanticBlock(
                id="right",
                operations=(RegisterArithmetic("eax", "sub", 1),),
                terminator=Jump("done"),
            ),
            SemanticBlock(id="done", operations=(), terminator=Return()),
            SemanticBlock(
                id="dead",
                operations=(Nop(),),
                terminator=Return(),
            ),
        ),
        static_objects=(
            StaticObject("dead-data", "read_only", 4, b"unused"),
        ),
        observations=("eax",),
        capabilities=("direct-control", "register-arithmetic"),
    ).to_payload())


def _regenerate(candidate: ReductionCandidate) -> _Regenerated:
    reparsed = SemanticProgram.parse(candidate.program.to_payload())
    required = any(
        isinstance(operation, AssignRegister)
        and operation.register == "eax"
        and operation.value.value == 7
        for block in reparsed.blocks
        for operation in block.operations
    )
    return _Regenerated(
        candidate_sha256=candidate.sha256,
        required_operation_present=required,
        transformations=tuple(item.id for item in candidate.transformations),
    )


def _case_run_result(
    *,
    expected: str,
    actual: str,
    case_id: str = "reduced-case",
    phases: list[dict[str, object]] | None = None,
    frontiers: list[dict[str, object]] | None = None,
    violation: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-roundtrip-run-result-v1",
        "status": "incomplete",
        "cases": [{
            "format": "stage-a-roundtrip-case-result-v1",
            "case_id": case_id,
            "mode": "proof-core",
            "expected_disposition": expected,
            "actual_disposition": actual,
            "expectation_matched": expected == actual,
            "phases": phases or [],
            "acceptance": {"theorem": None, "authority": None},
            "frontiers": frontiers or [],
            "violation": violation,
            "error": None,
        }],
    }
class StageARoundTripFuzzReducerTests(unittest.TestCase):
    def test_stable_predicate_grammar_and_observations(self) -> None:
        frontier = StablePredicateSpec.parse("proof-frontier=missing-call-frame")
        result = _case_run_result(
            expected="pass",
            actual="incomplete",
            frontiers=[{"category": "missing-call-frame"}],
        )
        observation = evaluate_stable_predicate(
            frontier, PredicateRun(result=result)
        )
        self.assertTrue(observation.satisfied)
        self.assertEqual(observation.identity, "missing-call-frame")
        self.assertEqual(observation.family, "proof-frontier")

        duration = StablePredicateSpec.parse(
            "phase-duration=proof-preparation,1.25"
        )
        observation = evaluate_stable_predicate(
            duration,
            PredicateRun(result=_case_run_result(
                expected="pass",
                actual="incomplete",
                phases=[{
                    "id": "proof-preparation",
                    "duration_seconds": 1.5,
                    "cache_key": "a",
                    "cache_hit": False,
                }],
            )),
        )
        self.assertTrue(observation.satisfied)
        self.assertEqual(duration.to_argument(), "phase-duration=proof-preparation,1.25")

        with self.assertRaisesRegex(StageAInputError, "supported predicates"):
            StablePredicateSpec.parse("arbitrary-python-expression")
        with self.assertRaisesRegex(StageAInputError, "phase-id,seconds"):
            StablePredicateSpec.parse("phase-duration=proof-preparation")

    def test_selected_violation_predicate_requires_checked_identity(self) -> None:
        specification = StablePredicateSpec.parse("violation-id=counterexample-17")
        checked = {
            "status": "violated",
            "violation_id": "counterexample-17",
            "family": "register-relation-v1",
            "checks": {"lean_replay": True, "binary_binding": True},
            "first_proved_mismatch": {"relation_atom": "register-eax"},
        }
        self.assertTrue(evaluate_stable_predicate(
            specification,
            PredicateRun(result=_case_run_result(
                expected="violated", actual="violated", violation=checked,
            )),
        ).satisfied)
        unchecked = {**checked, "checks": {"lean_replay": False}}
        self.assertFalse(evaluate_stable_predicate(
            specification,
            PredicateRun(result=_case_run_result(
                expected="violated", actual="violated", violation=unchecked,
            )),
        ).satisfied)

    def test_cache_predicate_requires_stable_keys_and_warm_hits(self) -> None:
        specification = StablePredicateSpec.parse("cache-key-mismatch")
        cold = _case_run_result(
            expected="pass", actual="pass",
            phases=[{
                "id": "proof-preparation", "cache_key": "before",
                "cache_hit": False, "duration_seconds": 1.0,
            }],
        )
        warm = _case_run_result(
            expected="pass", actual="pass",
            phases=[{
                "id": "proof-preparation", "cache_key": "after",
                "cache_hit": True, "duration_seconds": 0.01,
            }],
        )
        observation = evaluate_stable_predicate(
            specification, PredicateRun(result=cold, repeated_result=warm)
        )
        self.assertTrue(observation.satisfied)
        self.assertEqual(
            observation.details["mismatches"][0]["reason"], "cache-key-changed"
        )

    def test_transformation_metadata_is_canonical_and_strict(self) -> None:
        metadata = TransformationMetadata.parse({
            "id": "layout-change",
            "family": "layout",
            "parameters": {"alignment": 16, "enabled": True},
        })
        self.assertEqual(
            metadata.parameters,
            (("alignment", 16), ("enabled", True)),
        )
        with self.assertRaises(StageAInputError):
            TransformationMetadata.parse({
                "id": 1,
                "family": "layout",
                "parameters": {},
            })

    def test_reduces_typed_structure_and_preserves_lineage(self) -> None:
        callback_inputs: list[ReductionCandidate] = []

        def regenerate(candidate: ReductionCandidate) -> _Regenerated:
            callback_inputs.append(candidate)
            return _regenerate(candidate)

        mutation = NegativeMutation(
            id="wrong-constant",
            semantic_delta="constant differs",
            location_id="entry",
        )
        result = reduce_roundtrip_case(
            case_id="case-reducer",
            parent_seed=17,
            program=_program(),
            transformations=(
                TransformationMetadata.named("register-reassignment"),
                TransformationMetadata.named("temporary-stack-spill"),
            ),
            mutation=mutation,
            regenerate=regenerate,
            predicate=DeterministicPredicate(
                id="required-constant-remains",
                evaluate=lambda regenerated: regenerated.required_operation_present,
            ),
        )

        reduced = result.candidate
        self.assertEqual(reduced.transformations, ())
        self.assertIsNone(reduced.mutation)
        self.assertIn(
            "remove_negative_mutation",
            {step.action for step in reduced.lineage.steps},
        )
        self.assertEqual(reduced.program.static_objects, ())
        self.assertNotIn("dead", {block.id for block in reduced.program.blocks})
        self.assertEqual(
            sum(len(block.operations) for block in reduced.program.blocks),
            1,
        )
        self.assertTrue(result.regenerated.required_operation_present)
        self.assertGreater(result.accepted_steps, 0)
        self.assertGreaterEqual(result.attempts, result.accepted_steps)
        self.assertEqual(len(callback_inputs), result.attempts + 1)

        lineage = reduced.lineage
        self.assertEqual(lineage.case_id, "case-reducer")
        self.assertEqual(lineage.parent_seed, 17)
        self.assertEqual(lineage.predicate_id, "required-constant-remains")
        self.assertEqual(
            tuple(step.sequence for step in lineage.steps),
            tuple(range(1, result.accepted_steps + 1)),
        )
        for previous, following in zip(lineage.steps, lineage.steps[1:]):
            self.assertEqual(previous.after_sha256, following.before_sha256)
        self.assertEqual(lineage.steps[-1].after_sha256, reduced.sha256)

    def test_regenerator_can_reject_failed_transformation_preconditions(self) -> None:
        def regenerate(candidate: ReductionCandidate) -> _Regenerated:
            if not candidate.transformations:
                raise ReductionCandidateRejected("lowering requires one transform")
            return _regenerate(candidate)

        result = reduce_roundtrip_case(
            case_id="case-regenerator-rejection",
            parent_seed=3,
            program=_program(),
            transformations=(TransformationMetadata.named("required-layout"),),
            mutation=None,
            regenerate=regenerate,
            predicate=DeterministicPredicate(
                id="constant-remains",
                evaluate=lambda regenerated: regenerated.required_operation_present,
            ),
        )

        self.assertEqual(
            tuple(item.id for item in result.candidate.transformations),
            ("required-layout",),
        )
        self.assertGreater(result.rejected_by_regenerator, 0)

    def test_detects_nondeterministic_predicate(self) -> None:
        answers = iter((True, False))
        with self.assertRaises(NondeterministicReductionPredicate):
            reduce_roundtrip_case(
                case_id="case-nondeterministic",
                parent_seed=1,
                program=_program(),
                transformations=(),
                mutation=None,
                regenerate=_regenerate,
                predicate=DeterministicPredicate(
                    id="unstable-predicate",
                    evaluate=lambda _regenerated: next(answers),
                ),
            )

    def test_reduction_is_reproducible(self) -> None:
        arguments = {
            "case_id": "case-reproducible",
            "parent_seed": 99,
            "program": _program(),
            "transformations": (
                TransformationMetadata.named("block-reordering"),
            ),
            "mutation": None,
            "regenerate": _regenerate,
            "predicate": DeterministicPredicate(
                id="constant-remains",
                evaluate=lambda regenerated: regenerated.required_operation_present,
            ),
        }
        first = reduce_roundtrip_case(**arguments)
        second = reduce_roundtrip_case(**arguments)

        self.assertEqual(first.to_payload(), second.to_payload())
        self.assertEqual(first.regenerated, second.regenerated)

    def test_artifact_reducer_regenerates_complete_hash_bound_case_each_attempt(self) -> None:
        roots: list[Path] = []

        def materialize(candidate: ReductionCandidate, root: Path) -> Path:
            roots.append(root)
            return _materialize_case(candidate, root)

        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "reduced"
            result = reduce_roundtrip_case_artifacts(
                case_id="case-artifact-reducer",
                parent_seed=17,
                program=_program(),
                transformations=(TransformationMetadata.named("layout-change"),),
                mutation=None,
                materialize=materialize,
                predicate=ArtifactPredicate(
                    id="required-constant-remains",
                    required_identity="register-eax-constant-7",
                    required_family="semantic-operation",
                    evaluate=lambda regenerated: PredicateObservation(
                        satisfied=any(
                            isinstance(operation, AssignRegister)
                            and operation.register == "eax"
                            and operation.value.value == 7
                            for block in regenerated.reduction_program.blocks
                            for operation in block.operations
                        ),
                        identity="register-eax-constant-7",
                        family="semantic-operation",
                        details={"candidate_sha256": regenerated.candidate_sha256},
                    ),
                ),
                out=out,
                replay=("spaghetti-extractor", "stage-a-fuzz-reduce", "--case", "case.json"),
            )

            self.assertTrue(result.output_case_manifest.is_file())
            self.assertTrue(result.reduction.regenerated.root.is_dir())
            self.assertGreater(result.reduction.accepted_steps, 0)
            self.assertEqual(
                len(roots),
                result.reduction.attempts + 1,
            )
            self.assertEqual(len(roots), len(set(roots)))
            self.assertTrue(all(root.parent.name == "attempts" for root in roots))
            self.assertTrue(result.predicate_observation.satisfied)
            self.assertEqual(result.report["status"], "reduced")
            self.assertTrue(
                result.report["trust"]["contracts_regenerated_after_every_typed_change"]
            )

    def test_artifact_reducer_rejects_stale_relation_contract(self) -> None:
        def stale_materializer(candidate: ReductionCandidate, root: Path) -> Path:
            manifest = _materialize_case(candidate, root)
            relation = root / "relation-contract.json"
            write_json(relation, {
                "format": "stage-a-relational-contract-v3",
                "provenance": {"mapping_sha256": "0" * 64},
            })
            # Rebind the manifest to the stale contract so only the cross-artifact
            # provenance check can detect the error.
            _rewrite_manifest_artifact_hash(manifest, "relation_contract", relation)
            return manifest

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(StageAInputError, "stale mapping provenance"):
                reduce_roundtrip_case_artifacts(
                    case_id="case-stale-artifacts",
                    parent_seed=17,
                    program=_program(),
                    transformations=(),
                    mutation=None,
                    materialize=stale_materializer,
                    predicate=ArtifactPredicate(
                        id="always",
                        evaluate=lambda _case: PredicateObservation(
                            True, "same", "test", {},
                        ),
                    ),
                    out=Path(temporary) / "reduced",
                    replay=("replay",),
                )

    def test_cli_dispatches_structure_aware_reducer(self) -> None:
        expected = {"format": "stage-a-roundtrip-reduction-v1", "status": "reduced"}
        with mock.patch(
            "spaghetti_extractor.cli.reduce_case_manifest", return_value=expected,
        ) as reduce:
            status = main([
                "stage-a-fuzz-reduce",
                "--case", "case.json",
                "--predicate", "proof-frontier=missing-frame",
                "--mode", "proof-core",
                "--max-accepted-steps", "7",
                "--out", "reduced",
            ])
        self.assertEqual(status, 0)
        reduce.assert_called_once_with(
            case=Path("case.json"),
            predicate="proof-frontier=missing-frame",
            out=Path("reduced"),
            mode="proof-core",
            toolchain=None,
            compiler=None,
            linker=None,
            flake=None,
            builders_file=None,
            max_accepted_steps=7,
            force=False,
        )

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc"),
        "MinGW compiler is required for standalone reducer regeneration",
    )
    def test_command_adapter_emits_deterministic_standalone_case_and_replay(self) -> None:
        def incomplete_run(**kwargs):
            corpus = Path(kwargs["corpus"])
            case_id = kwargs["case_ids"][0]
            self.assertTrue(corpus.is_file())
            return _case_run_result(expected="pass", actual="incomplete", case_id=case_id)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "generated"
            generate_spike_corpus(out=generated, seed=41, count=1, toolchain="gnu")
            case = generated / "cases" / "spike-000-positive-straight-line-arithmetic" / "case.json"
            first = root / "first"
            report = reduce_case_manifest(
                case=case,
                predicate="expected-positive-not-accepted",
                out=first,
                max_accepted_steps=2,
                _run=incomplete_run,
            )
            self.assertEqual(report["status"], "reduced")
            self.assertEqual(report["reduction"]["accepted_steps"], 2)
            self.assertEqual(
                [step["sequence"] for step in report["reduction"]["lineage"]["steps"]],
                [1, 2],
            )
            self.assertEqual(
                report["predicate"]["argument"], "expected-positive-not-accepted"
            )
            self.assertEqual(report["replay"][3], "case/corpus.json")
            self.assertEqual(report["reduction"]["lineage"]["parent_seed"], 41)
            self.assertTrue((first / "case" / "corpus.json").is_file())
            persisted = load_case_manifest(first / "case" / "case.json")
            persisted.verify_artifacts(first / "case")
            self.assertEqual(
                persisted.replay[:3],
                ("spaghetti-extractor", "stage-a-fuzz-run", "--corpus"),
            )

            second = root / "second"
            replayed = reduce_case_manifest(
                case=first / "case" / "case.json",
                predicate="expected-positive-not-accepted",
                out=second,
                max_accepted_steps=0,
                _run=incomplete_run,
            )
            first_case = load_case_manifest(first / "case" / "case.json")
            second_case = load_case_manifest(second / "case" / "case.json")
            self.assertEqual(
                first_case.artifact("candidate_pe").sha256,
                second_case.artifact("candidate_pe").sha256,
            )
            self.assertEqual(
                report["reduction"]["candidate_sha256"],
                replayed["reduction"]["candidate_sha256"],
            )

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc"),
        "MinGW compiler is required for negative reducer regeneration",
    )
    def test_command_adapter_reapplies_declared_negative_semantic_delta(self) -> None:
        def missing_witness(**kwargs):
            return _case_run_result(
                expected="violated",
                actual="incomplete",
                case_id=kwargs["case_ids"][0],
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "generated"
            generate_spike_corpus(out=generated, seed=7, count=3, toolchain="gnu")
            source = generated / "cases" / "spike-002-negative-bounded-loop" / "case.json"
            out = root / "reduced"
            report = reduce_case_manifest(
                case=source,
                predicate="expected-violated-without-checked-witness",
                out=out,
                max_accepted_steps=1,
                _run=missing_witness,
            )
            manifest = load_case_manifest(out / "case" / "case.json")
            artifacts = manifest.verify_artifacts(out / "case")
            self.assertEqual(report["reduction"]["accepted_steps"], 1)
            self.assertIsNotNone(manifest.mutation)
            self.assertEqual(
                report["reduction"]["mutation"]["id"], manifest.mutation.id
            )
            self.assertNotEqual(
                json.loads(artifacts["semantic_program"].read_text()),
                json.loads(artifacts["candidate_semantic_program"].read_text()),
            )


def _materialize_case(candidate: ReductionCandidate, root: Path) -> Path:
    semantic = root / "semantic-program.json"
    candidate_semantic = root / "candidate-semantic-program.json"
    write_json(semantic, candidate.program.to_payload())
    write_json(candidate_semantic, candidate.program.to_payload())
    artifact_paths: dict[str, Path] = {
        "original_source": root / "original.S",
        "candidate_source": root / "candidate.S",
        "original_object": root / "original.o",
        "candidate_object": root / "candidate.o",
        "original_pe": root / "original.exe",
        "candidate_pe": root / "candidate.exe",
        "original_linker_map": root / "original.map",
        "candidate_linker_map": root / "candidate.map",
    }
    for role, path in artifact_paths.items():
        path.write_bytes((role + ":" + candidate.sha256).encode())
    proposal = root / "relation-proposal.json"
    write_json(proposal, {
        "format": "stage-a-block-map-v1",
        "original": {"sha256": sha256_file(artifact_paths["original_pe"])},
        "candidate": {"sha256": sha256_file(artifact_paths["candidate_pe"])},
        "blocks": [{
            "id": "entry",
            "original": {"rva": 0x1000, "size": 1},
            "candidate": {"rva": 0x1000, "size": 1},
        }],
    })
    relation = root / "relation-contract.json"
    write_json(relation, {
        "format": "stage-a-relational-contract-v3",
        "provenance": {"mapping_sha256": sha256_file(proposal)},
    })
    artifacts = artifact_refs(root=root, artifacts=(
        ("semantic_program", semantic),
        ("candidate_semantic_program", candidate_semantic),
        *((role, path) for role, path in artifact_paths.items()),
        ("relation_proposal", proposal),
        ("relation_contract", relation),
    ))
    manifest = CaseManifest(
        id="regenerated-case",
        semantic_program_sha256=sha256_file(semantic),
        parent_seed=candidate.lineage.parent_seed,
        template="typed-reduction",
        transformations=tuple(item.id for item in candidate.transformations),
        expectation=CaseExpectation(
            ExpectedDisposition.PASS if candidate.mutation is None else ExpectedDisposition.VIOLATED,
            None if candidate.mutation is None else "relational-behavior-mismatch-v1",
            None,
        ),
        mutation=candidate.mutation,
        capability_profile="x86-pe32-relational-v3",
        capabilities=candidate.program.capabilities,
        proof_families=("whole-program-acceptance",),
        artifacts=artifacts,
        replay=("replay",),
        shard=0,
    )
    manifest_path = root / "case.json"
    write_case_manifest(manifest_path, manifest)
    return manifest_path


def _rewrite_manifest_artifact_hash(
    manifest_path: Path, role: str, artifact_path: Path,
) -> None:
    payload = json.loads(manifest_path.read_text())
    for artifact in payload["artifacts"]:
        if artifact["role"] == role:
            artifact["sha256"] = sha256_file(artifact_path)
            artifact["bytes"] = artifact_path.stat().st_size
            break
    write_json(manifest_path, payload)


if __name__ == "__main__":
    unittest.main()
