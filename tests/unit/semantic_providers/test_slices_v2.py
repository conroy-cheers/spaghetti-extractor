from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.semantic_link.module_v2 import (
    LinkedSemanticModuleV2,
    build_linked_semantic_module_v2,
)
from spaghetti_extractor.semantic_link.may_link import (
    compile_semantic_may_link_facts_v2,
)
from spaghetti_extractor.semantic_providers.slices_v2 import (
    SemanticSliceV2,
    SemanticSliceV2Error,
    build_semantic_slice_v2,
)
from tests.unit.semantic_link.fixture import SemanticLinkFixture


class SemanticSliceV2Tests(unittest.TestCase):
    def _module(self, root: Path) -> LinkedSemanticModuleV2:
        SemanticLinkFixture().linked_facts(root)
        semantic, link_facts = compile_semantic_may_link_facts_v2(
            semantic_object=root / "semantic-object.json"
        )
        payload = build_linked_semantic_module_v2(
            semantic=semantic, link_facts=link_facts,
        )
        return LinkedSemanticModuleV2.parse(payload)

    def test_definition_slice_is_content_addressed_not_module_addressed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = self._module(Path(temporary))
        definition_id = module.payload["definitions"][0]["definition_id"]
        first = build_semantic_slice_v2(
            linked_semantic_module=module, definition_ids=[definition_id]
        )
        changed = copy.deepcopy(module.payload)
        changed["link_provenance"]["root_inventory_sha256"] = "f" * 64
        changed["linked_semantic_module_sha256"] = canonical_sha256_v3({
            key: value for key, value in changed.items()
            if key != "linked_semantic_module_sha256"
        })
        second = build_semantic_slice_v2(
            linked_semantic_module=LinkedSemanticModuleV2.parse(changed),
            definition_ids=[definition_id],
        )

        self.assertEqual(first, second)
        self.assertNotIn("linked_semantic_module_sha256", first)
        self.assertEqual(
            SemanticSliceV2.parse(first).identity,
            first["semantic_slice_sha256"],
        )

    def test_unrelated_definition_does_not_invalidate_slice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = self._module(Path(temporary))
        definition_id = module.payload["definitions"][0]["definition_id"]
        first = build_semantic_slice_v2(
            linked_semantic_module=module, definition_ids=[definition_id]
        )
        changed = copy.deepcopy(module.payload)
        unrelated = copy.deepcopy(changed["definitions"][-1])
        unrelated_id = "semantic-definition-v2:" + "9" * 64
        unrelated["definition_id"] = unrelated_id
        unrelated["symbol_id"] = "original:function:unrelated"
        unrelated["definition_sha256"] = "8" * 64
        changed["definitions"].append(unrelated)
        changed["definition_requirements"].append({
            "definition_id": unrelated_id,
            "symbol_id": "original:function:unrelated",
            "allowed_provider_kinds": ["generated_behavioral_c"],
            "dependency_contract_sha256s": list(
                unrelated["dependency_contract_sha256s"]
            ),
        })
        changed["linked_semantic_module_sha256"] = "7" * 64

        second = build_semantic_slice_v2(
            linked_semantic_module=LinkedSemanticModuleV2(payload=changed),
            definition_ids=[definition_id],
        )
        self.assertEqual(first, second)

    def test_unknown_or_empty_slice_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = self._module(Path(temporary))
        with self.assertRaisesRegex(SemanticSliceV2Error, "cannot be empty"):
            build_semantic_slice_v2(linked_semantic_module=module)
        with self.assertRaisesRegex(SemanticSliceV2Error, "unknown definitions"):
            build_semantic_slice_v2(
                linked_semantic_module=module,
                definition_ids=["semantic-definition-v2:missing"],
            )

        inactive = copy.deepcopy(module.payload)
        inactive_definition = copy.deepcopy(inactive["definitions"][0])
        inactive_definition["definition_id"] = (
            "semantic-definition-v2:" + "9" * 64
        )
        inactive["definitions"].append(inactive_definition)
        with self.assertRaisesRegex(
            SemanticSliceV2Error, "outside active implementation requirements"
        ):
            build_semantic_slice_v2(
                linked_semantic_module=LinkedSemanticModuleV2(payload=inactive),
                definition_ids=[inactive_definition["definition_id"]],
            )

    def test_slice_dependency_catalog_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = self._module(Path(temporary))
        payload = build_semantic_slice_v2(
            linked_semantic_module=module,
            definition_ids=[module.payload["definitions"][0]["definition_id"]],
        )
        stale = copy.deepcopy(payload)
        stale["dependency_contract_sha256s"] = []
        stale["semantic_slice_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "semantic_slice_sha256"
        })
        with self.assertRaisesRegex(SemanticSliceV2Error, "catalog is stale"):
            SemanticSliceV2.parse(stale)


if __name__ == "__main__":
    unittest.main()
