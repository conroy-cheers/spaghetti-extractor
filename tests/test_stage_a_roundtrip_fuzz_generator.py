from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from spaghetti_extractor.roundtrip_fuzz.generator import (
    SPIKE_CASES,
    TEMPLATES,
    TRANSFORMATIONS,
    candidate_program_for_spec,
    generate_spike_corpus,
    lowering_variant_for_spec,
    semantic_program_for_spec,
    spike_case_specs,
)
from spaghetti_extractor.roundtrip_fuzz.lowering import (
    AssemblyLoweringVariant,
    lower_semantic_program_to_gnu_assembly,
)
from spaghetti_extractor.roundtrip_fuzz.model import (
    ExpectedDisposition,
    load_corpus_manifest,
)


class StageARoundTripFuzzGeneratorTests(unittest.TestCase):
    def test_full_spike_schedule_is_balanced_and_covers_declared_axes(self) -> None:
        specs = spike_case_specs(seed=100, count=SPIKE_CASES)

        self.assertEqual(len(specs), 36)
        self.assertEqual(
            Counter(spec.negative_ordinal is not None for spec in specs),
            {False: 24, True: 12},
        )
        self.assertEqual({spec.template for spec in specs}, set(TEMPLATES))
        self.assertEqual(
            {spec.transformation for spec in specs}, set(TRANSFORMATIONS)
        )
        self.assertEqual(len({spec.case_id for spec in specs}), len(specs))

    def test_negative_schedule_has_one_typed_semantic_delta(self) -> None:
        negatives = [
            spec for spec in spike_case_specs(seed=500, count=SPIKE_CASES)
            if spec.negative_ordinal is not None
        ]
        by_template: dict[str, set[str]] = {template: set() for template in TEMPLATES}
        for spec in negatives:
            original = semantic_program_for_spec(spec)
            candidate, mutation = candidate_program_for_spec(spec, original)
            self.assertIsNotNone(mutation)
            assert mutation is not None
            self.assertNotEqual(candidate.to_payload(), original.to_payload())
            self.assertTrue(mutation.location_id)
            by_template[spec.template].add(mutation.id)

        self.assertTrue(all(len(mutations) == 3 for mutations in by_template.values()))

    def test_lowering_variants_emit_real_structural_differences(self) -> None:
        sources: dict[str, str] = {}
        for spec in spike_case_specs(seed=0, count=SPIKE_CASES):
            if spec.transformation in sources:
                continue
            program = semantic_program_for_spec(spec)
            original = lower_semantic_program_to_gnu_assembly(
                program,
                variant=AssemblyLoweringVariant("original"),
            )
            candidate = lower_semantic_program_to_gnu_assembly(
                program, variant=lowering_variant_for_spec(spec, program)
            )
            self.assertNotEqual(original, candidate, spec.transformation)
            sources[spec.transformation] = candidate

        self.assertEqual(set(sources), set(TRANSFORMATIONS))
        self.assertIn("xchg eax, edx", sources["register-reassignment"])
        self.assertIn("lea esp, [esp - 4]", sources["temporary-stack-spill"])
        self.assertIn("_split", sources["basic-block-split"])
        self.assertRegex(sources["branch-inversion"], r"\n\s+jne ")
        self.assertIn(".byte 0x05", sources["equivalent-instruction-selection"])
        self.assertIn(".balign 16, 0x90", sources["code-alignment-change"])
        self.assertIn("_bridge", sources["changed-jump-layout"])

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc"),
        "MinGW compiler is required for deterministic PE generation",
    )
    def test_small_real_pe_corpus_regenerates_byte_identically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = generate_spike_corpus(
                out=root / "first", seed=31, count=4, toolchain="gnu"
            )
            second = generate_spike_corpus(
                out=root / "second", seed=31, count=4, toolchain="gnu"
            )

            self.assertEqual(first["corpus_sha256"], second["corpus_sha256"])
            manifest = load_corpus_manifest(root / "first" / "corpus.json")
            self.assertEqual(manifest.shard_count, 4)
            self.assertEqual(
                manifest.expected_counts.to_payload(),
                {"pass": 3, "violated": 1, "incomplete": 0},
            )
            for case, case_root in manifest.load_cases(root / "first"):
                case.verify_artifacts(case_root)
                self.assertTrue((case_root / "original.exe").read_bytes().startswith(b"MZ"))
                self.assertTrue((case_root / "candidate.exe").read_bytes().startswith(b"MZ"))
                if case.expectation.disposition is ExpectedDisposition.VIOLATED:
                    self.assertIsNotNone(case.mutation)


if __name__ == "__main__":
    unittest.main()
