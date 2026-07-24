from __future__ import annotations

import json
import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image
from tests.stage_a_relational_support import _pe32_tls_image

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_native_launch import (
    INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME,
    NativeLaunchGraphRouteSpec,
    NativeLaunchGraphSpec,
    RelationalInterpreterNativeLaunchGenerationError,
    build_relational_interpreter_native_launch_graph_plan,
    native_launch_graph_spec_from_engine_artifacts,
    relational_interpreter_native_launch_graph_source,
    write_relational_interpreter_native_launch_graph,
)
from spaghetti_extractor.util import sha256_bytes


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _branching_candidate(*, entry: bytes | None = None) -> bytes:
    code = bytearray(b"\x90" * 0x60)
    code[0:2] = b"\x85\xc0"
    code[2:4] = b"\x74\x05"
    code[4] = 0x90
    code[5:7] = b"\xeb\x03"
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


def _write_native_engine_plan(path: Path, *, omit_rva: int | None = None) -> None:
    callbacks = [
        {
            "rva": rva,
            "dispatch_return_symbol": f"stage_b_callback_return_{rva:04x}",
        }
        for rva in (0x1030, 0x1020)
        if rva != omit_rva
    ]
    path.write_text(
        json.dumps(
            {
                "format": "stage-b-native-engine-plan-v1",
                "status": "ready",
                "blockers": [],
                "callback_abis": callbacks,
                "launch_wrapper_symbols": {
                    "entry_return": "stage_b_entry_return",
                    "termination": "stage_b_termination",
                    "callback_dispatch_returns": [
                        row["dispatch_return_symbol"] for row in callbacks
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def _write_native_linker_map(path: Path, *, ambiguous: bool = False) -> None:
    rows = [
        (0x401000, "stage_b_native_run_entry"),
        (0x401004, "stage_b_native_run_callback"),
        (0x401008, "stage_b_entry_return"),
        (0x40100C, "stage_b_callback_return_1020"),
        (0x401010, "stage_b_callback_return_1030"),
        (0x401014, "stage_b_termination"),
    ]
    if ambiguous:
        rows.append((0x401018, "stage_b_entry_return"))
    path.write_text(
        "\n".join(f"0x{address:08x} {symbol}" for address, symbol in rows)
        + "\n",
        encoding="ascii",
    )


def _build(
    root: Path,
    *,
    image: bytes | None = None,
    spec: NativeLaunchGraphSpec | None = None,
):
    image = _branching_candidate() if image is None else image
    candidate = root / "candidate.exe"
    evidence = root / "engine-segments.json"
    candidate.write_bytes(image)
    _write_engine_segments(evidence, image)
    return build_relational_interpreter_native_launch_graph_plan(
        candidate_pe=candidate,
        engine_segments=evidence,
        spec=_graph_spec() if spec is None else spec,
    )


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


class StageARelationalInterpreterNativeLaunchGraphTests(unittest.TestCase):
    def test_engine_artifacts_derive_routes_in_exact_pe_root_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            engine = root / "native-engine-plan.json"
            linker_map = root / "candidate.map"
            candidate.write_bytes(_pe32_tls_image((0x1020, 0x1030)))
            _write_native_engine_plan(engine)
            _write_native_linker_map(linker_map)
            binding = native_launch_graph_spec_from_engine_artifacts(
                candidate_pe=candidate,
                linker_map=linker_map,
                native_engine_plan=engine,
            )

        self.assertEqual(binding.tls_callback_rvas, (0x1020, 0x1030))
        self.assertEqual(
            binding.spec.routes,
            (
                NativeLaunchGraphRouteSpec("entry", "dispatch", 0x1000),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x1004, source_index=0
                ),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x1004, source_index=1
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x1008
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x100C
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x1010
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "terminated", source_rva=0x1014
                ),
            ),
        )
        self.assertFalse(binding.payload()["acceptance_authority"])

    def test_engine_artifact_binding_rejects_missing_tls_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            engine = root / "native-engine-plan.json"
            linker_map = root / "candidate.map"
            candidate.write_bytes(_pe32_tls_image((0x1020, 0x1030)))
            _write_native_engine_plan(engine, omit_rva=0x1020)
            _write_native_linker_map(linker_map)
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "omits candidate TLS callback ABIs",
            ):
                native_launch_graph_spec_from_engine_artifacts(
                    candidate_pe=candidate,
                    linker_map=linker_map,
                    native_engine_plan=engine,
                )

    def test_engine_artifact_binding_rejects_ambiguous_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            engine = root / "native-engine-plan.json"
            linker_map = root / "candidate.map"
            candidate.write_bytes(_pe32_tls_image((0x1020, 0x1030)))
            _write_native_engine_plan(engine)
            _write_native_linker_map(linker_map, ambiguous=True)
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "ambiguous RVAs",
            ):
                native_launch_graph_spec_from_engine_artifacts(
                    candidate_pe=candidate,
                    linker_map=linker_map,
                    native_engine_plan=engine,
                )

    def test_emits_every_node_route_and_exact_checked_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = _build(Path(temporary))

        self.assertEqual(
            plan.cutpoints,
            (
                ("dispatch", 0x1050),
                ("return_wrapper", 0x1020),
                ("termination_wrapper", 0x1030),
            ),
        )
        self.assertEqual(
            [route.spec.destination_kind for route in plan.routes],
            ["dispatch", "returned", "terminated"],
        )
        branch = next(
            node
            for node in plan.routes[0].nodes
            if node.instruction.rva == 0x1002
        )
        self.assertEqual(branch.successors, (0x1009, 0x1004))

        payload = plan.payload()
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["canonical_roots"]["entrypoint_rva"], 0x1000)
        self.assertEqual(payload["canonical_roots"]["tls_callback_rvas"], [])

        source = relational_interpreter_native_launch_graph_source(plan)
        node_count = sum(len(route.nodes) for route in plan.routes)
        self.assertEqual(
            source.count(" : ReflectedNativeLaunchGraphNode := {"), node_count
        )
        self.assertEqual(
            source.count(" : ReflectedNativeLaunchGraphRoute := {"),
            len(plan.routes),
        )
        for required in (
            "parsePE32Tree generatedNativeLaunchGraphCandidateBytes",
            "parseImports generatedNativeLaunchGraphCandidatePe",
            "generatedNativeLaunchGraphCertificate",
            "generatedNativeLaunchGraphStaticChecked",
            "generatedNativeLaunchGraphRoute0000ReplaySound",
            "successors := [4105, 4100]",
            "terminal := some .terminated",
            "decide +kernel",
        ):
            self.assertIn(required, source)
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source), forbidden)

    def test_canonical_tls_roots_are_emitted_in_pe_order(self) -> None:
        image = bytearray(_pe32_tls_image((0x1020, 0x1030)))
        text = 0x200
        image[text : text + 2] = b"\xeb\x0e"
        image[text + 0x20 : text + 0x22] = b"\xeb\xee"
        image[text + 0x30 : text + 0x32] = b"\xeb\xde"
        spec = NativeLaunchGraphSpec(
            routes=(
                NativeLaunchGraphRouteSpec("entry", "dispatch", 0x1010),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x1010, source_index=0
                ),
                NativeLaunchGraphRouteSpec(
                    "tls_callback", "dispatch", 0x1010, source_index=1
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            plan = _build(Path(temporary), image=bytes(image), spec=spec)

        self.assertEqual(plan.tls_callback_rvas, (0x1020, 0x1030))
        self.assertEqual(
            [route.spec.source_kind for route in plan.routes],
            ["entry", "tls_callback", "tls_callback"],
        )
        source = relational_interpreter_native_launch_graph_source(plan)
        self.assertIn(".canonicalRoot (.tlsCallback 0)", source)
        self.assertIn(".canonicalRoot (.tlsCallback 1)", source)

    def test_writer_is_byte_deterministic_for_json_and_lean(self) -> None:
        image = _branching_candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            evidence = root / "engine-segments.json"
            candidate.write_bytes(image)
            _write_engine_segments(evidence, image)
            outputs = (root / "first", root / "second")
            plans = [
                write_relational_interpreter_native_launch_graph(
                    output,
                    candidate_pe=candidate,
                    engine_segments=evidence,
                    spec=_graph_spec(),
                )
                for output in outputs
            ]

            self.assertEqual(plans[0].payload(), plans[1].payload())
            self.assertEqual(
                (
                    outputs[0]
                    / INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME
                ).read_bytes(),
                (
                    outputs[1]
                    / INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME
                ).read_bytes(),
            )
            module = _graph_spec().module_name
            self.assertEqual(
                (outputs[0] / "StageA" / f"{module}.lean").read_bytes(),
                (outputs[1] / "StageA" / f"{module}.lean").read_bytes(),
            )

    def test_rejects_overlapping_decodes_and_cutpoint_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "overlapping decodes",
            ):
                _build(
                    root,
                    image=_branching_candidate(entry=b"\x74\x02\xe9\x49"),
                    spec=NativeLaunchGraphSpec(
                        routes=(
                            NativeLaunchGraphRouteSpec(
                                "entry", "dispatch", 0x1050
                            ),
                        )
                    ),
                )

        collision = NativeLaunchGraphSpec(
            routes=(
                NativeLaunchGraphRouteSpec("entry", "dispatch", 0x1050),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x1050
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "globally unique",
            ):
                _build(Path(temporary), spec=collision)

    def test_rejects_malformed_names_and_noncanonical_wrapper_order(self) -> None:
        bad_name = NativeLaunchGraphSpec(
            routes=_graph_spec().routes,
            module_name="bad-name",
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "module_name",
            ):
                _build(Path(temporary), spec=bad_name)

        wrong_order = NativeLaunchGraphSpec(
            routes=(
                NativeLaunchGraphRouteSpec("entry", "dispatch", 0x1050),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "terminated", source_rva=0x1030
                ),
                NativeLaunchGraphRouteSpec(
                    "stable_cutpoint", "returned", source_rva=0x1020
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "canonical order",
            ):
                _build(Path(temporary), spec=wrong_order)


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalInterpreterNativeLaunchGraphKernelTests(
    unittest.TestCase
):
    def test_generated_graph_checks_and_replays_without_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _build(root)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedLaunchRefinement",
            )
            generated = plan.spec.module_name
            (stage_a / f"{generated}.lean").write_text(
                relational_interpreter_native_launch_graph_source(plan),
                encoding="utf-8",
            )
            (stage_a / "RelationalInterpreterNativeLaunchGraphKernel.lean").write_text(
                _KERNEL_FIXTURE.format(generated=generated),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterNativeLaunchGraphKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertIn("generatedEntryReplaySound", output)


_KERNEL_FIXTURE = r"""import StageA.{generated}

namespace StageA.Relational.InterpreterNativeLaunchGraphKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterNativeLaunchGraph

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
  pe := generatedNativeLaunchGraphCandidatePe
  imports := generatedNativeLaunchGraphImports
  environment := blockingEnvironment
}}

def entryBefore : NativeWorldExecution :=
  .running 0x1000 0 zeroMachine [] 0 [] RelationalWorld.empty

theorem generatedEntryReplayExists :
    (generatedNativeLaunchGraphRoute0000.replay? generatedProgram
      generatedNativeLaunchGraphCutpoints entryBefore).isSome = true := by
  decide +kernel

theorem generatedEntryReplaySound :
    exists result,
      generatedNativeLaunchGraphRoute0000.replay? generatedProgram
          generatedNativeLaunchGraphCutpoints entryBefore = some result /\
        NonemptyRelatedPath generatedProgram.transitionSystem entryBefore
          result.observations result.after := by
  have present := generatedEntryReplayExists
  cases replayed : generatedNativeLaunchGraphRoute0000.replay? generatedProgram
      generatedNativeLaunchGraphCutpoints entryBefore with
  | none => simp [replayed] at present
  | some result =>
      refine ⟨result, rfl, ?_⟩
      exact (generatedNativeLaunchGraphRoute0000ReplaySound generatedProgram
        entryBefore result replayed).2.2

#print axioms generatedNativeLaunchGraphStaticChecked
#print axioms generatedEntryReplaySound

end StageA.Relational.InterpreterNativeLaunchGraphKernel
"""


if __name__ == "__main__":
    unittest.main()
