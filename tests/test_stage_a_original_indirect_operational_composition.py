from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.original_indirect_operational_composition import (
    ORIGINAL_INDIRECT_OPERATIONAL_COMPOSITION_LEAN_FILENAME,
    OriginalIndirectOperationalCompositionBinding,
    OriginalIndirectOperationalCompositionError,
    OriginalIndirectOperationalCompositionKind,
    original_indirect_operational_composition_source,
    write_original_indirect_operational_composition,
)


def _binding(
    kind: OriginalIndirectOperationalCompositionKind,
) -> OriginalIndirectOperationalCompositionBinding:
    return OriginalIndirectOperationalCompositionBinding(
        dependency_module="StageA.ExactIndirectFixture",
        namespace="StageA.GeneratedRelational.ExactIndirectFixture",
        kind=kind,
        context_term="Fixture.context",
        program_term="Fixture.program",
        carrier_binding_term="Fixture.carrierBinding",
        reachability_target_ids_term="Fixture.reachableTargetIds",
        contract_term="Fixture.contract",
        invariant_term="Fixture.invariant",
        authority_term="Fixture.authority",
        composition_term="Fixture.composition",
    )


class StageAOriginalIndirectOperationalCompositionTests(unittest.TestCase):
    def test_all_authority_kinds_emit_typed_runtime_premises(self) -> None:
        expected = {
            OriginalIndirectOperationalCompositionKind.REGISTER: (
                "CheckedAuthority generatedContext",
                "GeneratedRegisterExpressionPremise",
                "RegisterIndirectMixedOriginalComposition.operationalTarget",
            ),
            OriginalIndirectOperationalCompositionKind.STACK_CARRY: (
                "CheckedStackCarryAuthority generatedContext",
                "MixedOriginalStackCarryTarget",
                "StackCarryMixedOriginalComposition.operationalTarget",
            ),
            OriginalIndirectOperationalCompositionKind.DYNAMIC_CALLBACK: (
                "CheckedDynamicCallbackAuthority generatedContext",
                "MixedOriginalDynamicCallbackTarget",
                "DynamicCallbackMixedOriginalComposition.operationalTarget",
            ),
        }

        for kind, fragments in expected.items():
            with self.subTest(kind=kind):
                source = original_indirect_operational_composition_source(
                    _binding(kind)
                )
                for fragment in fragments:
                    self.assertIn(fragment, source)
                for fragment in (
                    "ActualMixedOriginalOperationalSource",
                    "OriginalIndirectReachabilityPremise",
                    "ExactOriginalIndirectStepPremise",
                    "exactOriginalInternalOperationalClosure_of_step",
                ):
                    self.assertIn(fragment, source)
                for forbidden in (
                    "native_decide",
                    "report.status",
                    "sorry",
                    "axiom ",
                ):
                    self.assertNotIn(forbidden, source)

    def test_writer_is_reproducible(self) -> None:
        binding = _binding(
            OriginalIndirectOperationalCompositionKind.STACK_CARRY
        )
        expected = original_indirect_operational_composition_source(binding)
        with tempfile.TemporaryDirectory() as temporary:
            written = write_original_indirect_operational_composition(
                Path(temporary), binding
            )
            self.assertEqual(
                written.name,
                ORIGINAL_INDIRECT_OPERATIONAL_COMPOSITION_LEAN_FILENAME,
            )
            self.assertEqual(written.read_text(encoding="utf-8"), expected)

    def test_invalid_or_authority_like_names_fail_closed(self) -> None:
        binding = _binding(OriginalIndirectOperationalCompositionKind.REGISTER)
        for field, value in (
            ("namespace", "Injected\naxiom falseProof : False"),
            ("composition_term", "Fixture.reportedResult"),
            ("authority_term", "Fixture.statusAuthority"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(
                    OriginalIndirectOperationalCompositionError
                ):
                    original_indirect_operational_composition_source(
                        replace(binding, **{field: value})
                    )

        with self.assertRaises(OriginalIndirectOperationalCompositionError):
            original_indirect_operational_composition_source(
                replace(binding, kind="register")  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
