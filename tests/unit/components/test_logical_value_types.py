"""A C pointer typedef does not imply a shared view extent or access contract."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection


def bundle_for_views(reverse=False, *, references=False, nullable_view=False):
    def value(identity, extent, access):
        return {"id": identity, "type_id": "byte_pointer", "interpretation": "view", "access": access,
                "nullable": False, "provider_domain": None, "resource_kind": None,
                "extent": {"kind": extent, "bytes": 4 if extent == "fixed" else None, "value_id": None}}
    values = [value("text", "nul_terminated", "read_write"), value("count", "fixed", "read")]
    if nullable_view:
        values[0]["nullable"] = True
    if references:
        for row in values:
            row["interpretation"] = "reference"
            row["extent"] = {"kind": "none", "bytes": None, "value_id": None}
        values[0]["nullable"] = True
    if reverse: values.reverse()
    schema = BoundarySchemaV1.create(schema_id="shared_pointer", types=[
        {"id": "unit", "kind": "void"},
        {"id": "u8", "kind": "integer", "width_bits": 8, "signed": False},
        {"id": "byte_pointer", "kind": "pointer", "pointee_type_id": "u8", "qualifiers": []},
        {"id": "run.fn", "kind": "function", "calling_convention": "cdecl", "parameter_type_ids": ["byte_pointer"] * 2,
         "result_type_id": "unit", "variadic": False}],
        signatures=[{"id": "run", "function_type_id": "run.fn", "parameters": values, "results": []}])
    intent = ComponentInterfaceIntentV1.create(component_id="views", schema=schema,
        state=[], services=[], effects=[], protocol_states=["ready"], initial_protocol_state="ready", operations=[{
            "id": "run", "signature_id": "run", "source_values": values,
            "projection_entries": [{"source_id": v["id"], "target": {"root": "parameter", "value_id": v["id"], "fields": []}} for v in values],
            "lifecycle_bindings": [], "lifecycle_additional_roots": {"state": []}, "checked_interaction_contract_ids": [],
            "effect_ids": [], "allowed_service_ids": [], "pre_states": ["ready"], "post_states": ["ready"]}])
    return compile_component_interface_v5(intent)


class LogicalValueTypeTests(unittest.TestCase):
    def test_shared_reference_pointer_keeps_access_and_nullability(self):
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle_for_views(references=True)))
        types = interface.type_index()
        parameters = {v.identity: types[v.type_id] for v in interface.operations[0].parameters}
        self.assertTrue(parameters["text"].nullable)
        self.assertFalse(parameters["count"].nullable)
        self.assertEqual(parameters["text"].access, "read_write")
        self.assertEqual(parameters["count"].access, "read")

    def test_nullable_view_is_not_silently_restricted_to_nonnull(self):
        with self.assertRaisesRegex(ValueError, "nullable logical view contract"):
            _logical_projection(bundle_for_views(nullable_view=True))

    def test_shared_pointer_keeps_fixed_extent_separate_from_nul_termination(self):
        previous = None
        for reverse in (False, True):
            bundle = bundle_for_views(reverse)
            # The normalized machine contract chooses byte-view representation
            # for text only. It must not promote other uses of the C typedef.
            contract = SimpleNamespace(machine_semantics=[SimpleNamespace(operation_id="run", machine_projection={
                "operation": {"parameters": [{"id": "text", "projection": {"kind": "bytes_view"}},
                                              {"id": "count", "projection": {"kind": "view"}}]}})])
            for representation in (None, contract):
                with self.subTest(reverse=reverse, byte_view=representation is not None):
                    projected = _logical_projection(bundle, contract=representation)
                    interface = ProofKernelComponentInterface.parse(projected)
                    types = interface.type_index()
                    parameters = {v.identity: types[v.type_id] for v in interface.operations[0].parameters}
                    self.assertNotEqual(parameters["text"].identity, parameters["count"].identity)
                    self.assertTrue(parameters["text"].nul_terminated or parameters["text"].extent_kind == "nul_terminated")
                    self.assertEqual(parameters["text"].access, "read_write")
                    self.assertEqual(parameters["count"].kind, "view")
                    self.assertEqual(parameters["count"].extent_kind, "fixed")
                    self.assertEqual(parameters["count"].fixed_extent, 4)
                    self.assertEqual(parameters["count"].access, "read")
                    if representation is contract:
                        current = {key: value.identity for key, value in parameters.items()}
                        if previous is not None: self.assertEqual(current, previous)
                        previous = current


if __name__ == "__main__":
    unittest.main()
