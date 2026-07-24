from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_exact_decoded_native_adapter import (
    INTERPRETER_EXACT_DECODED_NATIVE_ADAPTER_MODULE,
    InterpreterExactDecodedNativeAdapterGenerationError,
    InterpreterExactDecodedNativeAdapterSpec,
    relational_interpreter_exact_decoded_native_adapter_source,
    write_relational_interpreter_exact_decoded_native_adapter,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


def _spec(
    **changes: str | None,
) -> InterpreterExactDecodedNativeAdapterSpec:
    base = InterpreterExactDecodedNativeAdapterSpec(
        binding_module="StageA.Bindings",
        namespace="StageA.Generated.ExactDecodedNativeAdapter",
        context="requirements.context",
        graph="requirements.graph",
        regions="requirements.regions",
        reachability="requirements.reachability",
        external_call_sites="requirements.externalCallSites",
        launch="requirements.launch",
        candidate_environment="requirements.candidateEnvironment",
        candidate_protocol_environment=(
            "requirements.candidateProtocolEnvironment"
        ),
        native_program="requirements.nativeProgram",
        candidate_pe_bound="requirements.candidatePeBound",
        candidate_imports_bound="requirements.candidateImportsBound",
        native_authority="requirements.nativeAuthority",
        program_table="requirements.programTable",
        kernel_core="requirements.kernelCore",
        operations="requirements.operations",
        candidate_root_rva="requirements.candidateRootRva",
        candidate_root="requirements.candidateRoot",
        frame_count="requirements.frameCount",
        relation="requirements.relation",
        classifier="requirements.classifier",
        roots_related="requirements.rootsRelated",
        launch_chunk="requirements.launchChunk",
        kernel_chunk="requirements.kernelChunk",
        external_boundary_chunk="requirements.externalBoundaryChunk",
        x87_replay_chunk="requirements.x87ReplayChunk",
        requirement_parameter="requirements",
        requirement_type="StageA.Bindings.RequiredTerms",
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterExactDecodedNativeAdapterTests(
    unittest.TestCase
):
    def test_layer_assembles_mechanical_evidence_and_fails_closed(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterExactDecodedNativeAdapter.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "ExactDecodedNativeKernelEvidence",
            "ExactCompiledProgramTable",
            "ExactCompiledInterpreterKernelCore",
            "CheckedKernelOperationRefinementFamily",
            "ExactDecodedCandidateProgramBinding",
            "exactDecodedCandidateProgramBinding",
            "candidateNativeLaunchCallFrames?_exists",
            "ExactDecodedNativeSourceCase",
            "kernelOperation",
            "externalBoundary",
            "x87Replay",
            "ExactDecodedNativeComponentPremises",
            "evidence.operations.combinedRefines operation",
            "ExactDecodedNativeChunkAdapter",
            "toChunkAdapter",
        ):
            self.assertIn(required, source)

        source_cases = source.split(
            "inductive ExactDecodedNativeSourceCase", 1
        )[1].split(
            "structure ExactDecodedNativeComponentPremises", 1
        )[0]
        for forbidden_case in ("unknown", "blocked", "fallback", "other"):
            self.assertNotRegex(source_cases, rf"\|\s*{forbidden_case}\b")

        for forbidden in (
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\badmit\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_emits_candidate_view_premises_and_adapter(self) -> None:
        source = relational_interpreter_exact_decoded_native_adapter_source(
            _spec()
        )

        for required in (
            "ExactDecodedNativeKernelEvidence",
            "decodedCandidateProgram",
            "ExactDecodedCandidateProgramBinding",
            "ExactDecodedNativeComponentPremises",
            "classify :=",
            "kernelChunk :=",
            "externalBoundaryChunk :=",
            "x87ReplayChunk :=",
            "toChunkAdapter",
        ):
            self.assertIn(required, source)
        for forbidden in (r"\bsorry\b", r"\bstatus\b", r"\bverdict\b"):
            self.assertNotRegex(source, forbidden)

    def test_writer_is_deterministic(self) -> None:
        spec = _spec()
        expected = relational_interpreter_exact_decoded_native_adapter_source(
            spec
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_relational_interpreter_exact_decoded_native_adapter(
                root, spec
            )
            first_bytes = first.read_bytes()
            second = write_relational_interpreter_exact_decoded_native_adapter(
                root, spec
            )
            second_bytes = second.read_bytes()

        self.assertEqual(
            first.name,
            f"{INTERPRETER_EXACT_DECODED_NATIVE_ADAPTER_MODULE}.lean",
        )
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_generator_rejects_malformed_names(self) -> None:
        for change in (
            {"binding_module": "Bindings"},
            {"namespace": "StageA.Bad-Namespace"},
            {"classifier": "requirements.bad term"},
            {"adapter_name": "StageA.adapter"},
            {"requirement_type": None},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    InterpreterExactDecodedNativeAdapterGenerationError
                ):
                    relational_interpreter_exact_decoded_native_adapter_source(
                        _spec(**change)
                    )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_layer_compiles_and_has_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterExactDecodedNativeAdapter",
            )
            (
                stage_a
                / "RelationalInterpreterExactDecodedNativeAdapterAudit.lean"
            ).write_text(_AUDIT_FIXTURE, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterExactDecodedNativeAdapterAudit",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for theorem in (
            "exactDecodedCandidateProgramBinding",
            "exactDecodedNativeLaunchCalls_exact",
            "ExactDecodedNativeComponentPremises.component",
            "ExactDecodedNativeComponentPremises.toChunkAdapter",
        ):
            self.assertIn(theorem, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_AUDIT_FIXTURE = r"""import StageA.RelationalInterpreterExactDecodedNativeAdapter

namespace StageA.Relational.InterpreterExactDecodedNativeAdapterAudit

open StageA.Relational.InterpreterExactDecodedNativeAdapter

#check ExactDecodedNativeKernelEvidence
#check ExactDecodedCandidateProgramBinding
#check exactDecodedCandidateProgramBinding
#check exactDecodedNativeLaunchCalls_exact
#check ExactDecodedNativeComponentChunk
#check ExactDecodedNativeSourceCase
#check ExactDecodedNativeComponentPremises
#check ExactDecodedNativeComponentPremises.component
#check ExactDecodedNativeComponentPremises.toChunkAdapter

#print axioms exactDecodedCandidateProgramBinding
#print axioms exactDecodedNativeLaunchCalls_exact
#print axioms ExactDecodedNativeComponentPremises.component
#print axioms ExactDecodedNativeComponentPremises.toChunkAdapter

end StageA.Relational.InterpreterExactDecodedNativeAdapterAudit
"""


if __name__ == "__main__":
    unittest.main()
