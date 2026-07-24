from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.register_indirect_mixed_original_composition import (
    REGISTER_INDIRECT_MIXED_ORIGINAL_COMPOSITION_LEAN_FILENAME,
    RegisterIndirectMixedOriginalCompositionBinding,
    RegisterIndirectMixedOriginalCompositionError,
    register_indirect_mixed_original_composition_source,
    write_register_indirect_mixed_original_composition,
)


def _binding() -> RegisterIndirectMixedOriginalCompositionBinding:
    return RegisterIndirectMixedOriginalCompositionBinding(
        dependency_module="StageA.GeneratedRegisterAuthority",
        namespace="StageA.Generated.RegisterMixedComposition",
        context_term="StageA.GeneratedRegisterAuthority.originalContext",
        authority_term="StageA.GeneratedRegisterAuthority.checkedAuthority",
    )


class StageARegisterIndirectMixedOriginalCompositionTests(unittest.TestCase):
    def test_adapter_keeps_runtime_and_reachability_as_lean_premises(self) -> None:
        source = register_indirect_mixed_original_composition_source(_binding())

        for expected in (
            "RelationalRegisterIndirectMixedOriginalComposition",
            "checkedAuthority",
            "ActualMixedOriginalRegisterSource",
            "MixedRuntimeClosurePremise",
            "MixedTargetMembershipPremise",
            "RuntimeInventoryPopulated",
            "generatedFiniteComposition",
            "generatedFiniteCompositionFromRuntime",
            "generatedUnreachableComposition",
            "sourceUninhabited",
        ):
            self.assertIn(expected, source)
        for forbidden in (
            "proposal_report",
            "report_status",
            "runtime_complete",
            "original_sha256",
            "state_machine_sha256",
        ):
            self.assertNotIn(forbidden, source.lower())
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_invalid_lean_names_are_rejected(self) -> None:
        for field in (
            "dependency_module",
            "namespace",
            "context_term",
            "authority_term",
        ):
            values = _binding().__dict__ | {field: "invalid term()"}
            with self.assertRaisesRegex(
                RegisterIndirectMixedOriginalCompositionError,
                "qualified Lean name",
            ):
                register_indirect_mixed_original_composition_source(
                    RegisterIndirectMixedOriginalCompositionBinding(**values)
                )

    def test_writer_uses_the_dedicated_module_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = write_register_indirect_mixed_original_composition(
                temporary, _binding()
            )
            source = path.read_text(encoding="utf-8")

        self.assertEqual(
            path.name,
            REGISTER_INDIRECT_MIXED_ORIGINAL_COMPOSITION_LEAN_FILENAME,
        )
        self.assertIn("generatedRegisterAuthority", source)


if __name__ == "__main__":
    unittest.main()
