from __future__ import annotations

import json
import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image

from spaghetti_extractor.relational.lean.interpreter_mixed_launch_refinement import (
    MixedLaunchCandidateLeanBinding,
    MixedLaunchRefinementSpec,
    build_relational_interpreter_mixed_launch_refinement_plan,
    relational_interpreter_mixed_launch_refinement_source,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_native_launch import (
    NativeLaunchGraphRouteSpec,
    NativeLaunchGraphSpec,
    RelationalInterpreterNativeLaunchGenerationError,
    build_relational_interpreter_native_launch_graph_plan,
)
from spaghetti_extractor.util import sha256_bytes


_CURRENT_CANDIDATE = Path(
    "/nix/store/2gkgcbxrdrhxvd7rfxypnhwkxys48565-"
    "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
)
_CURRENT_ENGINE_SEGMENTS = Path(
    "/nix/store/07a3m89mypaixyr27w4rlc8zrdzskxdi-"
    "stage-a-gnu-hello-roundtrip-engine-segments/engine-segments.json"
)
_CURRENT_CANDIDATE_SHA256 = (
    "9da6e93d4ad8886d5ea76c08c7111f820dead1dd8a1242caa162ab8086c32eca"
)
_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _branching_candidate(*, entry: bytes | None = None) -> bytes:
    code = bytearray(b"\x90" * 0x60)
    # Both arms join at 0x1010, then dispatch by direct call to 0x1050.
    code[0:2] = b"\x85\xc0"
    code[2:4] = b"\x74\x05"  # 0x1002 -> 0x1009
    code[4] = 0x90
    code[5:7] = b"\xeb\x03"  # 0x1005 -> 0x100a
    code[9] = 0x90
    code[0x0A:0x0F] = b"\xe8" + struct.pack("<i", 0x1050 - 0x100F)
    code[0x20] = 0xC3
    code[0x30:0x36] = b"\xff\x25" + struct.pack("<I", 0x402040)
    code[0x50] = 0xC3
    if entry is not None:
        code[: len(entry)] = entry
    return pe32_import_image(bytes(code), symbol="TerminateProcess")


def _graph_spec() -> NativeLaunchGraphSpec:
    return NativeLaunchGraphSpec(
        routes=(
            NativeLaunchGraphRouteSpec("entry", "dispatch", 0x1050),
            NativeLaunchGraphRouteSpec(
                "stable_cutpoint", "returned", source_rva=0x1020
            ),
            NativeLaunchGraphRouteSpec(
                "stable_cutpoint", "terminated", source_rva=0x1030
            ),
        )
    )


def _write_engine_segments(path: Path, image: bytes, **updates: object) -> None:
    payload: dict[str, object] = {
        "format": "stage-a-engine-segment-evidence-v1",
        "acceptance_authority": False,
        "candidate": {
            "pe_sha256": sha256_bytes(image),
            "bitness": 32,
            "machine": "i386",
        },
        "control_sites": [],
        "issues": [],
    }
    payload.update(updates)
    path.write_text(json.dumps(payload), encoding="utf-8")


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


class StageARelationalInterpreterMixedLaunchRefinementTests(unittest.TestCase):
    def test_recovers_both_guarded_paths_and_terminal_wrappers(self) -> None:
        image = _branching_candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(evidence, image)
            plan = build_relational_interpreter_mixed_launch_refinement_plan(
                candidate_pe=candidate,
                engine_segments=evidence,
                spec=MixedLaunchRefinementSpec(_graph_spec()),
            )

        entry = plan.graph.routes[0]
        branch = next(
            node for node in entry.nodes if node.instruction.rva == 0x1002
        )
        self.assertEqual(branch.successors, (0x1009, 0x1004))
        self.assertEqual(entry.nodes[-1].terminal, "dispatch")
        self.assertEqual(plan.graph.routes[1].nodes[-1].terminal, "returned")
        self.assertEqual(plan.graph.routes[2].nodes[-1].terminal, "terminated")
        self.assertEqual(
            plan.cutpoints,
            (
                ("dispatch", 0x1050),
                ("return_wrapper", 0x1020),
                ("termination_wrapper", 0x1030),
            ),
        )
        self.assertEqual(plan.payload()["status"], "incomplete")
        self.assertIsNone(
            plan.payload()["lean_terms"]["launch_wrapper_refinements"]
        )

        source = relational_interpreter_mixed_launch_refinement_source(plan)
        for required in (
            "ExactNativeLaunchGraphCertificate",
            "generatedMixedLaunchGraphStaticChecked",
            "GeneratedLaunchWrapperRefinements",
            "CanonicalMixedLaunchWrapperRefinement",
            "successors := [4105, 4100]",
            "terminal := some .terminated",
            "decide +kernel",
        ):
            self.assertIn(required, source)
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source), forbidden)

        bridge = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterMixedLaunchRefinement.lean"
        ).read_text(encoding="utf-8")
        self.assertIn("canonicalNativeInitialLaunchRoot", bridge)
        self.assertIn(
            "directExactCandidateNativeLaunchRoot_canonicalRootExact", bridge
        )
        self.assertNotIn("Classical.choice", bridge)

    def test_mixed_generator_requires_return_and_termination_wrappers(self) -> None:
        image = _branching_candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(evidence, image)
            with self.assertRaisesRegex(
                ValueError, "missing: returned, terminated"
            ):
                build_relational_interpreter_mixed_launch_refinement_plan(
                    candidate_pe=candidate,
                    engine_segments=evidence,
                    spec=MixedLaunchRefinementSpec(
                        NativeLaunchGraphSpec(
                            routes=(
                                NativeLaunchGraphRouteSpec(
                                    "entry", "dispatch", 0x1050
                                ),
                            )
                        )
                    ),
                )

    def test_existing_candidate_authority_avoids_duplicate_pe_bytes(self) -> None:
        image = _branching_candidate()
        binding = MixedLaunchCandidateLeanBinding(
            module="StageA.GeneratedCandidate",
            namespace="StageA.GeneratedCandidate",
            pe="candidatePe",
            imports="candidateImports",
            pe_parsed="candidateParsed",
            imports_parsed="importsParsed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(evidence, image)
            plan = build_relational_interpreter_mixed_launch_refinement_plan(
                candidate_pe=candidate,
                engine_segments=evidence,
                spec=MixedLaunchRefinementSpec(
                    _graph_spec(), candidate_binding=binding
                ),
            )

        source = relational_interpreter_mixed_launch_refinement_source(plan)
        self.assertIn("import StageA.GeneratedCandidate", source)
        self.assertIn(
            "StageA.GeneratedCandidate.candidatePe", source
        )
        self.assertNotIn("generatedMixedLaunchCandidateBytesPack", source)
        self.assertLess(len(source), 50_000)

    def test_fails_closed_on_stale_indirect_faulting_and_cyclic_routes(self) -> None:
        cases = (
            (b"\xff\xe0", "indirect jump"),
            (b"\x0f\x0b", "faulting or unsupported instruction ud2"),
            (b"\xeb\xfe", "unranked cycle"),
        )
        for entry, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                image = _branching_candidate(entry=entry)
                candidate = root / "candidate.exe"
                evidence = root / "engine-segments.json"
                candidate.write_bytes(image)
                _write_engine_segments(evidence, image)
                with self.assertRaisesRegex(
                    RelationalInterpreterNativeLaunchGenerationError, message
                ):
                    build_relational_interpreter_native_launch_graph_plan(
                        candidate_pe=candidate,
                        engine_segments=evidence,
                        spec=NativeLaunchGraphSpec(
                            routes=(
                                NativeLaunchGraphRouteSpec(
                                    "entry", "dispatch", 0x1050
                                ),
                            )
                        ),
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = _branching_candidate()
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(
                evidence,
                image,
                candidate={
                    "pe_sha256": "0" * 64,
                    "bitness": 32,
                    "machine": "i386",
                },
            )
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "different candidate PE",
            ):
                build_relational_interpreter_native_launch_graph_plan(
                    candidate_pe=candidate,
                    engine_segments=evidence,
                    spec=_graph_spec(),
                )

    def test_fails_closed_on_missing_root_and_overlapping_engine_issue(self) -> None:
        image = _branching_candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(evidence, image)
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "cover entry",
            ):
                build_relational_interpreter_native_launch_graph_plan(
                    candidate_pe=candidate,
                    engine_segments=evidence,
                    spec=NativeLaunchGraphSpec(routes=()),
                )

            _write_engine_segments(
                evidence,
                image,
                issues=[
                    {
                        "code": "fixture_gap",
                        "message": "fixture",
                        "rva_start": 0x1002,
                        "rva_end": 0x1004,
                    }
                ],
            )
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "fixture_gap overlaps",
            ):
                build_relational_interpreter_native_launch_graph_plan(
                    candidate_pe=candidate,
                    engine_segments=evidence,
                    spec=_graph_spec(),
                )

    @unittest.skipUnless(
        _CURRENT_CANDIDATE.is_file() and _CURRENT_ENGINE_SEGMENTS.is_file(),
        "current GNU round-trip candidate is not present",
    )
    def test_current_gnu_candidate_root_routes_are_exact_and_guard_complete(self) -> None:
        roots = NativeLaunchGraphSpec(
            routes=(
                NativeLaunchGraphRouteSpec("entry", "dispatch", 0x496BD),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x4979F, source_index=0
                ),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x4979F, source_index=1
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x353FC
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x359E7
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x35F29
                ),
            )
        )
        plan = build_relational_interpreter_native_launch_graph_plan(
            candidate_pe=_CURRENT_CANDIDATE,
            engine_segments=_CURRENT_ENGINE_SEGMENTS,
            spec=roots,
        )
        self.assertEqual(plan.candidate_sha256, _CURRENT_CANDIDATE_SHA256)
        self.assertEqual(plan.entrypoint_rva, 0x1420)
        self.assertEqual(plan.tls_callback_rvas, (0xA2F0, 0xA2A0))
        self.assertEqual(
            [len(route.nodes) for route in plan.routes],
            [287, 331, 331, 16, 71, 71],
        )
        self.assertEqual(
            [
                sum(
                    node.instruction_kind != "ordinary"
                    for node in route.nodes
                )
                for route in plan.routes
            ],
            [2, 2, 2, 1, 2, 2],
        )
        self.assertEqual(
            [
                node.instruction.rva
                for route in plan.routes[1:]
                for node in route.nodes
                if len(node.successors) == 2
            ],
            [0x35ACA, 0x35B13, 0x35BC4, 0x35F0A,
             0x35588, 0x355D1, 0x35682, 0x359C8,
             0x359EF, 0x359F7, 0x35A00, 0x35A0C, 0x35A2C, 0x35A7C,
             0x35F31, 0x35F39, 0x35F42, 0x35F4E, 0x35F6E, 0x35FBE],
        )
        self.assertEqual(plan.routes[3].nodes[-1].terminal, "returned")
        self.assertEqual(plan.routes[4].nodes[-1].terminal, "returned")
        self.assertEqual(plan.routes[5].nodes[-1].terminal, "returned")

    @unittest.skipUnless(
        _CURRENT_CANDIDATE.is_file() and _CURRENT_ENGINE_SEGMENTS.is_file(),
        "current GNU round-trip candidate is not present",
    )
    def test_current_gnu_candidate_has_modeled_termination_route(self) -> None:
        spec = NativeLaunchGraphSpec(
            routes=(
                NativeLaunchGraphRouteSpec("entry", "dispatch", 0x496BD),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x4979F, source_index=0
                ),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x4979F, source_index=1
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "terminated", source_rva=0x35430
                ),
            )
        )
        plan = build_relational_interpreter_native_launch_graph_plan(
            candidate_pe=_CURRENT_CANDIDATE,
            engine_segments=_CURRENT_ENGINE_SEGMENTS,
            spec=spec,
        )
        termination = plan.routes[-1]
        self.assertEqual(len(termination.nodes), 3)
        self.assertEqual(termination.nodes[-1].instruction.rva, 0x35433)
        self.assertEqual(termination.nodes[-1].terminal, "terminated")


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalInterpreterMixedLaunchRefinementKernelTests(
    unittest.TestCase
):
    def test_guard_complete_graph_is_checked_and_replayed_without_axioms(
        self,
    ) -> None:
        image = _branching_candidate()
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(evidence, image)
            plan = build_relational_interpreter_mixed_launch_refinement_plan(
                candidate_pe=candidate,
                engine_segments=evidence,
                spec=MixedLaunchRefinementSpec(_graph_spec()),
            )

            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedProfile",
            )
            generated = plan.spec.module_name
            (stage_a / f"{generated}.lean").write_text(
                relational_interpreter_mixed_launch_refinement_source(plan),
                encoding="utf-8",
            )
            (stage_a / "RelationalInterpreterMixedLaunchRefinementKernel.lean").write_text(
                _KERNEL_FIXTURE.format(generated=generated),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterMixedLaunchRefinementKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertIn("replay?_sound", output)
        self.assertIn("generatedEntryReplayExists", output)


_KERNEL_FIXTURE = r"""import StageA.{generated}

namespace StageA.Relational.InterpreterMixedLaunchRefinementKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterMixedLaunchRefinement

def zeroWord : Word := BitVec.ofNat 32 0

def zeroRegisters : Registers Word := {{
  eax := zeroWord
  ebx := zeroWord
  ecx := zeroWord
  edx := zeroWord
  esi := zeroWord
  edi := zeroWord
  ebp := zeroWord
  esp := zeroWord
}}

def zeroMachine : MachineState := {{
  registers := zeroRegisters
  memory := fun _ => BitVec.ofNat 8 0
}}

def blockingEnvironment : NativeWorldEnvironment := {{
  action := fun _ _ _ => .blocked (.unclassifiedNativeFault 0)
}}

def generatedProgram : ExactNativeWorldProgram := {{
  pe := generatedMixedLaunchCandidatePe
  imports := generatedMixedLaunchImports
  environment := blockingEnvironment
}}

def entryBefore : NativeWorldExecution :=
  .running 0x1000 0 zeroMachine [] 0 [] RelationalWorld.empty

theorem generatedEntryReplayExists :
    (generatedMixedLaunchRoute0000.replay? generatedProgram
      generatedMixedLaunchCutpoints entryBefore).isSome = true := by
  decide +kernel

theorem generatedEntryReplaySound :
    exists result,
      generatedMixedLaunchRoute0000.replay? generatedProgram
          generatedMixedLaunchCutpoints entryBefore = some result /\
        NonemptyRelatedPath generatedProgram.transitionSystem entryBefore
          result.observations result.after := by
  have present := generatedEntryReplayExists
  cases replayed : generatedMixedLaunchRoute0000.replay? generatedProgram
      generatedMixedLaunchCutpoints entryBefore with
  | none => simp [replayed] at present
  | some result =>
      refine ⟨result, rfl, ?_⟩
      exact (generatedMixedLaunchRoute0000.replay?_sound generatedProgram
        generatedMixedLaunchCutpoints entryBefore result replayed).2.2

#print axioms ReflectedNativeLaunchGraphRoute.replay?_sound
#print axioms generatedMixedLaunchGraphStaticChecked
#print axioms generatedEntryReplayExists
#print axioms generatedEntryReplaySound

end StageA.Relational.InterpreterMixedLaunchRefinementKernel
"""


if __name__ == "__main__":
    unittest.main()
