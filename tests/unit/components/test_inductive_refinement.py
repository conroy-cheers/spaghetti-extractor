from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.inductive_certificate import (
    materialize_inductive_certificate,
)
from spaghetti_extractor.components.inductive_contract import (
    check_inductive_operation_certificate,
)
from spaghetti_extractor.components.inductive_package import (
    materialize_inductive_package,
)
from spaghetti_extractor.components.inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
    CheckedInductiveRefinementReceiptV1,
    CheckedInductiveSourceReceiptV1,
    InductiveReceiptError,
    finalize_inductive_refinement_receipt,
)
from spaghetti_extractor.components.inductive_refinement import (
    _render_expression,
    check_inductive_source_refinement,
)
from spaghetti_extractor.components.inductive_relation import (
    InductiveCutpointRelationV1,
)
from spaghetti_extractor.components.inductive_source import InductiveSourcePlanV1
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import check_component_source_profile

from .test_inductive_package import _declaration, _semantic_contract
from .test_inductive_relation import _interface, _operation


_SOURCE = r"""
spx_countdown_run_control_v1 countdown_initialize(
    spx_countdown_run_state_v1 *state,
    spx_countdown_context_v2 *context,
    uint32_t count) {
  (void)context;
  state->n = count;
  if (count == 0u) {
    return (spx_countdown_run_control_v1) {
      SPX_COUNTDOWN_RUN_CONTROL_COMPLETE,
      SPX_COUNTDOWN_RUN_PHASE_LOOP,
      SPX_COUNTDOWN_RUN_COMPLETION_RETURN
    };
  }
  return (spx_countdown_run_control_v1) {
    SPX_COUNTDOWN_RUN_CONTROL_RUNNING,
    SPX_COUNTDOWN_RUN_PHASE_LOOP,
    SPX_COUNTDOWN_RUN_COMPLETION_RETURN
  };
}

spx_countdown_run_control_v1 countdown_step(
    spx_countdown_run_state_v1 *state,
    uint32_t phase_id,
    spx_countdown_context_v2 *context,
    uint32_t count) {
  (void)phase_id;
  (void)context;
  (void)count;
  if (state->n == 0u) {
    return (spx_countdown_run_control_v1) {
      SPX_COUNTDOWN_RUN_CONTROL_COMPLETE,
      SPX_COUNTDOWN_RUN_PHASE_LOOP,
      SPX_COUNTDOWN_RUN_COMPLETION_RETURN
    };
  }
  state->n -= 1u;
  return (spx_countdown_run_control_v1) {
    SPX_COUNTDOWN_RUN_CONTROL_RUNNING,
    SPX_COUNTDOWN_RUN_PHASE_LOOP,
    SPX_COUNTDOWN_RUN_COMPLETION_RETURN
  };
}

uint32_t countdown_finish(
    const spx_countdown_run_state_v1 *state,
    uint32_t completion_id,
    spx_countdown_context_v2 *context,
    uint32_t count) {
  (void)completion_id;
  (void)context;
  (void)count;
  return state->n;
}
"""


def _proof_declaration(*, noninductive: bool = False) -> dict[str, object]:
    invariant = (
        {
            "op": "eq",
            "args": [
                {"op": "loop_variable", "name": "n"},
                {"op": "parameter", "name": "count"},
            ],
        }
        if noninductive
        else {
            "op": "ule32",
            "args": [
                {"op": "loop_variable", "name": "n"},
                {"op": "parameter", "name": "count"},
            ],
        }
    )
    return {
        "format": "spaghetti-extractor-inductive-proof-declaration-v1",
        "invariants": [{
            "id": "invariant:n-bounded",
            "owner_cutpoint_id": "head",
            "expression": invariant,
        }],
        "measures": [{
            "id": "measure:n",
            "owner_cutpoint_id": "head",
            "variable_id": "n",
            "expression": {"op": "loop_variable", "name": "n"},
        }],
    }


@unittest.skipUnless(shutil.which("cbmc"), "CBMC unavailable")
@unittest.skipUnless(shutil.which("cc"), "C preprocessor unavailable")
class InductiveRefinementTests(unittest.TestCase):
    def test_sign_extension_uses_defined_unsigned_bitvector_arithmetic(self) -> None:
        rendered = _render_expression({
            "op": "sign_extend",
            "args": [8, {"op": "parameter", "name": "value"}],
        })
        self.assertNotIn("(int8_t)", rendered)
        self.assertNotIn("(int32_t)", rendered)
        self.assertIn("UINT32_C(255)", rendered)
        self.assertIn("UINT32_C(128)", rendered)

    def _run(
        self, root: Path, source_text: str, *, noninductive_invariant: bool = False
    ) -> dict[str, object]:
        interface = _interface()
        semantic = _semantic_contract()
        induction = materialize_inductive_package(
            declaration=_declaration(),
            interface=interface.to_payload(),
            semantic_contract=semantic,
        )
        plan = InductiveSourcePlanV1.parse(induction["source_plan"])
        machine = CheckedInductiveMachineReceiptV1.parse(
            induction["machine_receipt"]
        )
        relation = InductiveCutpointRelationV1.parse(
            induction["cutpoint_relation"]
        )
        source_path = root / "countdown.c"
        source_path.write_text(source_text, encoding="ascii")
        package = root / "source"
        source = build_component_source_package(
            lift_unit_id="countdown",
            files={"countdown.c": source_path},
            shared_inputs={},
            operation_symbols={"run": "countdown_run"},
            out_dir=package,
        )
        profile = check_component_source_profile(package=package)
        proof = _proof_declaration(noninductive=noninductive_invariant)
        draft = materialize_inductive_certificate(
            proof_declaration=proof,
            semantic_contract=semantic,
            interface=interface.to_payload(),
            source_package=package,
            source_plan=plan,
            machine_receipt=machine,
            cutpoint_relation=relation,
        )
        receipt = check_inductive_source_refinement(
            operation=_operation(),
            service_bindings=[],
            interface=interface,
            source_package=package,
            source_profile=profile,
            source_plan=plan,
            machine_receipt=machine,
            relation=relation,
            certificate=draft,
            cbmc=Path(shutil.which("cbmc") or "cbmc"),
            timeout_seconds=60,
        )
        return {
            "receipt": receipt,
            "interface": interface,
            "plan": plan,
            "machine": machine,
            "relation": relation,
            "source": source,
            "source_package": package,
            "semantic_contract": semantic,
            "proof_declaration": proof,
            "draft_certificate": draft,
        }

    def test_universal_source_step_closes_exact_machine_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._run(Path(temporary), _SOURCE)
            receipt = fixture["receipt"]
            self.assertEqual(receipt["status"], "satisfied", receipt)
            parsed = CheckedInductiveSourceReceiptV1.parse(receipt)
            self.assertEqual(parsed.to_payload(), receipt)
            self.assertEqual(parsed.component_id, "countdown")
            self.assertEqual(parsed.interface_sha256, fixture["interface"].sha256)

            final = materialize_inductive_certificate(
                proof_declaration=fixture["proof_declaration"],
                semantic_contract=fixture["semantic_contract"],
                interface=fixture["interface"].to_payload(),
                source_package=fixture["source_package"],
                source_plan=fixture["plan"],
                machine_receipt=fixture["machine"],
                cutpoint_relation=fixture["relation"],
                source_receipt=receipt,
            )
            check = check_inductive_operation_certificate(
                final,
                receipt_payloads={
                    "machine-check": fixture["machine"].to_payload(),
                    "source-check": receipt,
                },
            )
            self.assertEqual(check.status, "complete", check.to_payload())
            self.assertTrue(
                check.assurance.to_value()[
                    "receipt_contents_replayed_by_this_checker"
                ]
            )
            aggregate = finalize_inductive_refinement_receipt(
                certificate=final,
                certificate_check=check,
                machine_receipt=fixture["machine"],
                source_receipt=receipt,
            )
            parsed_aggregate = CheckedInductiveRefinementReceiptV1.parse(
                aggregate
            )
            self.assertTrue(aggregate["activation_authorized"])
            self.assertEqual(parsed_aggregate.to_payload(), aggregate)

    def test_corrupted_step_produces_source_mapped_violation(self) -> None:
        broken = _SOURCE.replace("state->n -= 1u;", "state->n -= 2u;")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._run(Path(temporary), broken)
            receipt = fixture["receipt"]
        self.assertEqual(receipt["status"], "violated", receipt)
        self.assertEqual(receipt["issues"][0]["code"], "cbmc_counterexample")
        self.assertIsInstance(receipt["issues"][0]["source"], dict)
        draft_check = check_inductive_operation_certificate(
            fixture["draft_certificate"],
            receipt_payloads={
                "machine-check": fixture["machine"].to_payload(),
            },
        )
        aggregate = finalize_inductive_refinement_receipt(
            certificate=fixture["draft_certificate"],
            certificate_check=draft_check,
            machine_receipt=fixture["machine"],
            source_receipt=receipt,
        )
        self.assertEqual(aggregate["status"], "violated")
        self.assertFalse(aggregate["activation_authorized"])
        with self.assertRaises(InductiveReceiptError):
            CheckedInductiveRefinementReceiptV1.parse(aggregate)

    def test_noninductive_target_invariant_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = self._run(
                Path(temporary), _SOURCE, noninductive_invariant=True
            )["receipt"]
        self.assertEqual(receipt["status"], "violated", receipt)
        self.assertEqual(receipt["issues"][0]["code"], "cbmc_counterexample")


if __name__ == "__main__":
    unittest.main()
