from __future__ import annotations

import re
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image
from tests.stage_a_relational_support import _pe32_tls_image

from spaghetti_extractor.relational.lean.interpreter_native_launch import (
    INTERPRETER_NATIVE_LAUNCH_MODULE,
    NativeLaunchCertificateSpec,
    NativeLaunchCutpointSpec,
    NativeLaunchPathSpec,
    RelationalInterpreterNativeLaunchGenerationError,
    build_relational_interpreter_native_launch_plan,
    relational_interpreter_native_launch_source,
    write_relational_interpreter_native_launch,
)


def _candidate_image() -> bytes:
    code = bytearray(b"\x90" * 0x40)
    code[0:5] = b"\xe9\x0b\x00\x00\x00"  # 0x1000 -> 0x1010
    code[0x10] = 0xC3
    code[0x20] = 0xC3
    code[0x30:0x36] = b"\xff\x25" + struct.pack("<I", 0x402040)
    return pe32_import_image(bytes(code), symbol="Terminate")


def _spec() -> NativeLaunchCertificateSpec:
    return NativeLaunchCertificateSpec(
        cutpoints=(
            NativeLaunchCutpointSpec("dispatch", 0x1010),
            NativeLaunchCutpointSpec("return_wrapper", 0x1020),
            NativeLaunchCutpointSpec("termination_wrapper", 0x1030),
        ),
        paths=(
            NativeLaunchPathSpec(
                "entry",
                "stable_cutpoint",
                (0x1000,),
                destination_index=0,
            ),
            NativeLaunchPathSpec(
                "stable_cutpoint",
                "returned",
                (0x1020,),
                source_index=1,
            ),
            NativeLaunchPathSpec(
                "stable_cutpoint",
                "terminated",
                (0x1030,),
                source_index=2,
            ),
        ),
    )


class StageARelationalInterpreterNativeLaunchGenerationTests(unittest.TestCase):
    def test_binds_exact_bytes_and_emits_reflected_semantic_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.exe"
            candidate.write_bytes(_candidate_image())
            plan = build_relational_interpreter_native_launch_plan(
                candidate_pe=candidate, spec=_spec()
            )

        self.assertEqual(plan.entrypoint_rva, 0x1000)
        self.assertEqual(plan.tls_callback_rvas, ())
        self.assertEqual(
            [
                instruction.data
                for path in plan.paths
                for instruction in path.instructions
            ],
            [
                b"\xe9\x0b\x00\x00\x00",
                b"\xc3",
                b"\xff\x25\x40\x20\x40\x00",
            ],
        )
        payload = plan.payload()
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["canonical_roots"]["entrypoint_rva"], 0x1000)

        source = relational_interpreter_native_launch_source(plan)
        for required in (
            "import StageA.RelationalInterpreterNativeLaunch",
            "parsePE32Tree generatedNativeLaunchCandidateBytes",
            "parseImports generatedNativeLaunchCandidatePe",
            "ReflectedNativeLaunchPathCertificate",
            "generatedNativeLaunchCertificateStaticChecked",
            "generatedNativeLaunchCertificateSemanticSound",
            "bytes := [233, 11, 0, 0, 0]",
            "destination := .terminated",
            "decide +kernel",
            "#print axioms",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_canonical_tls_paths_are_required_in_image_order(self) -> None:
        image = bytearray(_pe32_tls_image((0x1020,)))
        text = 0x200
        image[text : text + 5] = b"\xe9\x0b\x00\x00\x00"
        image[text + 8] = 0xC3
        image[text + 0x20 : text + 0x22] = b"\xeb\xee"
        spec = NativeLaunchCertificateSpec(
            cutpoints=(
                NativeLaunchCutpointSpec("dispatch", 0x1010),
                NativeLaunchCutpointSpec("return_wrapper", 0x1008),
            ),
            paths=(
                NativeLaunchPathSpec(
                    "entry",
                    "stable_cutpoint",
                    (0x1000,),
                    destination_index=0,
                ),
                NativeLaunchPathSpec(
                    "tls_callback",
                    "stable_cutpoint",
                    (0x1020,),
                    source_index=0,
                    destination_index=0,
                ),
                NativeLaunchPathSpec(
                    "stable_cutpoint",
                    "returned",
                    (0x1008,),
                    source_index=1,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "tls.exe"
            candidate.write_bytes(image)
            plan = build_relational_interpreter_native_launch_plan(
                candidate_pe=candidate, spec=spec
            )
            self.assertEqual(plan.tls_callback_rvas, (0x1020,))

            missing_tls = NativeLaunchCertificateSpec(
                cutpoints=spec.cutpoints,
                paths=(spec.paths[0], spec.paths[2]),
            )
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError,
                "canonical order",
            ):
                build_relational_interpreter_native_launch_plan(
                    candidate_pe=candidate, spec=missing_tls
                )

            mutable = Path(temporary) / "mutable-tls.exe"
            mutable.write_bytes(
                _pe32_tls_image((0x1020,), callback_array_writable=True)
            )
            with self.assertRaisesRegex(
                RelationalInterpreterNativeLaunchGenerationError, "not immutable"
            ):
                build_relational_interpreter_native_launch_plan(
                    candidate_pe=mutable, spec=spec
                )

    def test_rejects_empty_stale_and_misshaped_routes(self) -> None:
        cases = (
            (
                NativeLaunchCertificateSpec(
                    cutpoints=_spec().cutpoints,
                    paths=(
                        NativeLaunchPathSpec(
                            "entry", "stable_cutpoint", (), destination_index=0
                        ),
                        *_spec().paths[1:],
                    ),
                ),
                "no reflected instructions",
            ),
            (
                NativeLaunchCertificateSpec(
                    cutpoints=_spec().cutpoints,
                    paths=(
                        NativeLaunchPathSpec(
                            "entry",
                            "stable_cutpoint",
                            (0x1001,),
                            destination_index=0,
                        ),
                        *_spec().paths[1:],
                    ),
                ),
                "starts at",
            ),
            (
                NativeLaunchCertificateSpec(
                    cutpoints=_spec().cutpoints,
                    paths=(
                        _spec().paths[0],
                        NativeLaunchPathSpec(
                            "stable_cutpoint",
                            "terminated",
                            (0x1020,),
                            source_index=1,
                        ),
                        _spec().paths[2],
                    ),
                ),
                "must end at returned",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.exe"
            candidate.write_bytes(_candidate_image())
            for spec, message in cases:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(
                        RelationalInterpreterNativeLaunchGenerationError, message
                    ):
                        build_relational_interpreter_native_launch_plan(
                            candidate_pe=candidate, spec=spec
                        )

    def test_writer_uses_only_the_requested_generated_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            candidate.write_bytes(_candidate_image())
            destination = write_relational_interpreter_native_launch(
                root / "out", candidate_pe=candidate, spec=_spec()
            )
            self.assertEqual(
                destination.name, f"{INTERPRETER_NATIVE_LAUNCH_MODULE}.lean"
            )
            self.assertEqual(
                sorted(path.name for path in destination.parent.iterdir()),
                [destination.name],
            )

    def test_proof_core_is_generic_and_has_no_claimed_path_field(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterNativeLaunch.lean"
        ).read_text(encoding="utf-8")
        self.assertIn("parseTlsCallbackRvas pe", source)
        self.assertIn("instruction.decode? program.pe", source)
        self.assertIn("program.transitionSystem", source)
        self.assertIn("runRelatedSteps", source)
        self.assertIn("replay?_sound", source)
        self.assertIn("candidatePELaunchRoots? candidate.pe", source)
        self.assertIn("DirectExactCandidateNativeLaunchRoot", source)
        direct_binding = source.split(
            "def DirectExactCandidateNativeLaunchRoot", 1
        )[1].split("def directExactCandidateNativeLaunchRootChecked", 1)[0]
        self.assertNotIn("StaticProofContext", direct_binding)
        self.assertNotIn("codeMap", direct_binding)
        self.assertNotRegex(source, re.compile(r"(?i)gnu|mingw|stage_b_payload"))
        structure = source.split(
            "structure ReflectedNativeLaunchPathCertificate where", 1
        )[1].split("deriving", 1)[0]
        self.assertEqual(
            [
                line.strip().split(" :", 1)[0]
                for line in structure.splitlines()
                if " :" in line
            ],
            ["source", "destination", "steps"],
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)


if __name__ == "__main__":
    unittest.main()
