"""Dispatch must name the entry and overlay covered by the supplier theorem."""

import copy
import unittest

from spaghetti_extractor.components.bisimulation_call_entry import call_entry_checks, validate_call_entry_contract


class CallEntryDispatchTests(unittest.TestCase):
    def row(self):
        # Renderer inputs have already passed checked_call_entry_contract. This
        # test isolates dispatch correspondence, not proof-system qualification.
        return {"component_id": "reader", "operation_id": "read", "entry_rva": 4096,
            "summary_strategy": "image-readable-body-free-v1",
            "symbol": "spx_component_reader_00001000", "entry_contract": {
                "operations": [{"operation_id": "read", "entry_rvas": [4096, 4097],
                    "domain": "readable-wide", "private_high_offset": 4096,
                    "machine_image": {"preferred_base": 0x400000, "image_size": 0x10000}}],
                "proof_system": {"proof": {"models": {"operation_models": [{
                    "operation_id": "read", "exact_entry_rva": 4096,
                    "overlay_symbol": "spx_component_reader_00001000"}]}}}}}

    def test_covered_dispatch_emits_actual_call_state_assertion_before_assumption(self):
        lines = call_entry_checks(self.row())
        self.assertIn("call_state.esp", lines[0])
        self.assertIn("rt->image_base", lines[0])
        self.assertIn("spx-bisimulation-connected-callee-stack-entry:reader:read", lines[1])
        self.assertEqual(lines[2], "      __CPROVER_assume(entry_admitted);")

    def test_binding_entry_declaration_does_not_substitute_for_checked_dispatch(self):
        original = self.row()
        for mutation in ("symbol", "entry", "operation", "missing", "duplicate"):
            row = copy.deepcopy(original)
            models = row["entry_contract"]["proof_system"]["proof"]["models"]["operation_models"]
            if mutation == "symbol": row["symbol"] = "spx_component_other_00001000"
            elif mutation == "entry": row["entry_rva"] = 4097
            elif mutation == "operation": row["operation_id"] = "other"
            elif mutation == "missing": models.clear()
            else: models.append(copy.deepcopy(models[0]))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "not covered|checked supplier operation"):
                call_entry_checks(row)

    def test_machine_renderer_inputs_are_not_a_provider_entry_receipt(self):
        with self.assertRaisesRegex(ValueError, "contract fields differ"):
            validate_call_entry_contract(self.row()["entry_contract"], connected={})
