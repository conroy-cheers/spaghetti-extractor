import copy
import unittest

from spaghetti_extractor.native_realization.context_link import (
    ExactContextLinkError, bind_context_objects, finish_context, selected_context,
    validate_context_receipt, validate_realized_contexts,
)
from spaghetti_extractor.semantic_providers.selection_v2 import ImplementationSelectionV2
from tests.unit.semantic_providers import test_qualification_and_selection_v2 as fixtures
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.native_realization.receipt_v2 import NativeRealizationV2, NativeRealizationV2Error, build_native_realization_v2
from tests.unit.native_realization.test_receipt_v2 import _facts, _linked, _selection


class ExactContextLinkTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.ExactContextSelectionTests()
        fixture.setUp()
        generated = fixture.context_provider()
        self.provider = fixture.portable
        self.context = selected_context(
            qualification=fixture.portable,
            selection=ImplementationSelectionV2.parse(fixture.select(generated)),
            qualifications=[fixture.portable, fixture.runtime, generated],
        )
        definition = self.context["definitions"][0]
        self.object_row = {
            "object_sha256": definition["object_sha256s"][0],
            "selected_provider": {
                "provider_ids": [definition["provider_id"]],
                "qualification_sha256s": [definition["qualification_sha256"]],
                "definition_ids": [definition["definition_id"]],
            },
        }
        self.owners = {definition["native_symbol"]: [("strong", None, self.object_row)]}
        self.bound = bind_context_objects(self.context, object_rows=[self.object_row], symbol_owners=self.owners)
        self.linked = finish_context(self.bound, linked_symbols={definition["native_symbol"]: 8192},
                                     selection_sha256=self.bound["implementation_selection_sha256"])

    def facts(self):
        definition = self.linked["definitions"][0]
        return {
            "selection_sha256": self.linked["implementation_selection_sha256"],
            "entries": [{"provider_id": self.provider.provider_id, "owned_unit_ids": ["body"], "exact_context": self.linked}],
            "providers": [{"provider_id": self.provider.provider_id, "exact_context": self.provider.payload["exact_context"]}],
            "definitions": [{**definition, "provider_kind": "generated_behavioral_c", "implementation_rva": 8192}],
            "objects": [{"object_sha256": self.object_row["object_sha256"], **self.object_row["selected_provider"]}],
        }

    def test_selected_generated_objects_and_linked_symbols_discharge_context(self):
        validate_context_receipt(self.linked)
        validate_realized_contexts(**self.facts())

    def test_context_symbol_requires_one_strong_selected_owner(self):
        symbol = self.context["definitions"][0]["native_symbol"]
        for owners in ([], [("weak", None, self.object_row)], self.owners[symbol] * 2,
                       [("strong", None, {"object_sha256": "f" * 64})]):
            with self.subTest(owners=owners), self.assertRaises(ExactContextLinkError):
                bind_context_objects(self.context, object_rows=[self.object_row], symbol_owners={symbol: owners})
        with self.assertRaisesRegex(ExactContextLinkError, "object is absent"):
            bind_context_objects(self.context, object_rows=[], symbol_owners=self.owners)
        with self.assertRaisesRegex(ExactContextLinkError, "linker map"):
            finish_context(self.bound, linked_symbols={}, selection_sha256=self.bound["implementation_selection_sha256"])
        with self.assertRaisesRegex(ExactContextLinkError, "selection changed"):
            finish_context(self.bound, linked_symbols={symbol: 8192}, selection_sha256="f" * 64)

    def test_native_receipt_rejects_removed_replaced_and_unlinked_context(self):
        for mutation in ("removed", "invented", "slice", "selection", "symbol", "rva", "object", "owned", "selection_digest"):
            facts = copy.deepcopy(self.facts())
            if mutation == "removed": del facts["entries"][0]["exact_context"]
            elif mutation == "invented": del facts["providers"][0]["exact_context"]
            elif mutation == "slice": facts["entries"][0]["exact_context"]["semantic_slice_sha256"] = "a" * 64
            elif mutation == "selection": facts["definitions"][0]["provider_kind"] = "qualified_portable_c"
            elif mutation == "symbol": facts["definitions"][0]["native_symbol"] = "other"
            elif mutation == "rva": facts["definitions"][0]["implementation_rva"] += 1
            elif mutation == "object": facts["objects"] = []
            elif mutation == "owned": facts["entries"][0]["owned_unit_ids"] = ["continuation"]
            elif mutation == "selection_digest": facts["selection_sha256"] = "f" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ExactContextLinkError):
                validate_realized_contexts(**facts)


    def test_complete_native_receipt_rechecks_its_context_bindings(self):
        facts = _facts()
        selection = _selection()
        linked_context = {**self.linked, "implementation_selection_sha256": selection.identity}
        body = facts["definitions"][0]
        body["provider_kind"] = "qualified_portable_c"
        selection.payload["definition_selections"][0]["provider_kind"] = "qualified_portable_c"
        facts["providers"][0].update(provider_kind="qualified_portable_c", exact_context=self.provider.payload["exact_context"])
        context = self.linked["definitions"][0]
        context_choice = {key: context[key] for key in ("definition_id", "symbol_id", "provider_id", "qualification_sha256", "native_symbol")}
        context_choice["provider_kind"] = "generated_behavioral_c"
        selection.payload["definition_selections"].append(context_choice)
        selection.payload["qualification_sha256s"].append(context["qualification_sha256"])
        facts["definitions"].append({**context_choice, "address": {"kind": "linked_rva", "rva": 8192},
                                     "implementation_rva": 8192, "bridge_class_id": None})
        facts["providers"].append({
            **{key: context[key] for key in ("provider_id", "qualification_sha256")},
            "provider_kind": "generated_behavioral_c", "artifact_sha256": "a" * 64,
            "semantic_slice_sha256": self.linked["semantic_slice_sha256"], "tool_sha256s": ["b" * 64],
            "definition_ids": [context["definition_id"]], "obligation_ids": [],
        })
        facts["native_objects"].extend([
            {"object_sha256": self.object_row["object_sha256"], "role": "generated_behavioral_c",
             "provider_ids": [context["provider_id"]], "definition_ids": [context["definition_id"]], "obligation_ids": [], "section_ids": []},
            {"object_sha256": "0" * 64, "role": "loader_support", "provider_ids": [], "definition_ids": [], "obligation_ids": [], "section_ids": []},
        ])
        portable = facts["portable_dispatch_link_receipt"]
        portable["registry"] = {"source_sha256": "1" * 64, "object_sha256": "0" * 64,
                               "symbol_rvas": {"spx_region_override_count": 100, "spx_region_override_lookup": 104, "spx_region_overrides": 108}}
        portable["entries"] = [{
            "component_id": "fixture", "operation_id": "run", "entry_unit_id": "entry", "owned_unit_ids": ["entry"],
            "entry_rva": 4096, "native_symbol": body["native_symbol"], "provider_id": body["provider_id"],
            "qualification_sha256": body["qualification_sha256"], "contextual_refinement_sha256": "4" * 64,
            "contextual_proof_sha256": "5" * 64, "provider_object_manifest_sha256": "6" * 64,
            "implementation_source_sha256": "7" * 64, "implementation_object_sha256": "e" * 64,
            "linked_rva": body["implementation_rva"], "exact_context": linked_context,
        }]

        def rehash(value, field):
            value[field] = canonical_sha256_v3({key: item for key, item in value.items() if key != field})

        rehash(portable, "receipt_sha256")
        payload = build_native_realization_v2(linked_semantic_module=_linked(), implementation_selection=selection, **facts)
        NativeRealizationV2.parse(payload)
        for mutation in ("removed", "symbol", "object"):
            altered = copy.deepcopy(payload)
            context = altered["portable_dispatch_link_receipt"]["entries"][0]["exact_context"]
            if mutation == "removed": del altered["portable_dispatch_link_receipt"]["entries"][0]["exact_context"]
            elif mutation == "symbol": context["definitions"][0]["native_symbol"] = "wrong"
            else:
                context["definitions"][0]["object_sha256s"] = ["e" * 64]
                context["definitions"][0]["implementation_object_sha256"] = "e" * 64
            rehash(altered["portable_dispatch_link_receipt"], "receipt_sha256")
            rehash(altered, "native_realization_sha256")
            with self.subTest(mutation=mutation), self.assertRaises(NativeRealizationV2Error):
                NativeRealizationV2.parse(altered)


if __name__ == "__main__":
    unittest.main()
