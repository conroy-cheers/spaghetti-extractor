from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.semantic_providers.qualification_v2 import (
    SemanticProviderQualificationV2,
    SemanticProviderQualificationV2Error,
    build_semantic_provider_qualification_v2,
)
from spaghetti_extractor.semantic_providers.selection_v2 import (
    ImplementationSelectionV2,
    ImplementationSelectionV2Error,
    build_implementation_selection_v2,
)
from spaghetti_extractor.semantic_providers.slices_v2 import (
    SemanticSliceV2,
    build_semantic_slice_v2,
)


_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_E = "e" * 64
_DEFINITION_ID = f"semantic-definition-v2:{'1' * 64}"
_OBLIGATION_ID = f"residual-obligation-v2:{'2' * 64}"


def _module() -> LinkedSemanticModuleV2:
    return LinkedSemanticModuleV2(payload={
        "linked_semantic_module_sha256": "3" * 64,
        "status": "complete",
        "semantic_holes": [],
        "definitions": [{
            "definition_id": _DEFINITION_ID,
            "symbol_id": "original:function:entry",
            "definition_kind": "transfer_v2",
            "definition_sha256": _B,
            "dependency_contract_sha256s": [_A],
        }],
        "definition_requirements": [{
            "definition_id": _DEFINITION_ID,
            "symbol_id": "original:function:entry",
            "allowed_provider_kinds": [
                "generated_behavioral_c", "qualified_portable_c",
            ],
            "dependency_contract_sha256s": [_A],
        }],
        "residual_obligations": [{
            "obligation_id": _OBLIGATION_ID,
            "class": "internal_code_dispatch",
            "subjects": ["transfer:1:dispatch:0"],
            "semantic_contract_sha256": _C,
            "admitted_domain": {
                "kind": "finite_targets", "targets": [4096, 8192],
            },
            "evidence_dependencies": [f"transfer-plan:{_D}"],
            "allowed_provider_kinds": ["qualified_runtime"],
        }],
    })


def _facets(kind: str) -> list[dict[str, str]]:
    names = {
        "external_environment": ["external_contract"],
        "generated_behavioral_c": [
            "compile", "native_objects", "ownership", "semantic_lowering",
            "source",
        ],
        "pinned_binary": ["native_objects", "pinned_layout"],
        "qualified_portable_c": [
            "compile", "contextual_refinement", "induction", "lifecycle",
            "native_objects", "object_binding", "ownership", "relations",
            "services", "source",
        ],
        "qualified_runtime": [
            "reviewed_native_primitive", "runtime_qualification",
        ],
    }[kind]
    return [{
        "name": name, "status": "checked", "receipt_sha256": _E,
    } for name in names]


def _definition_slice(module: LinkedSemanticModuleV2) -> SemanticSliceV2:
    return SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=module, definition_ids=[_DEFINITION_ID]
    ))


def _obligation_slice(module: LinkedSemanticModuleV2) -> SemanticSliceV2:
    return SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=module, obligation_ids=[_OBLIGATION_ID]
    ))


def _definition_qualification(
    module: LinkedSemanticModuleV2, *, kind: str = "generated_behavioral_c",
    provider_id: str = "generated.main",
) -> SemanticProviderQualificationV2:
    return SemanticProviderQualificationV2.parse(
        build_semantic_provider_qualification_v2(
            semantic_slice=_definition_slice(module),
            provider_id=provider_id,
            provider_kind=kind,
            provider_artifact_sha256=_A,
            facets=_facets(kind),
            definition_materializations=[{
                "definition_id": _DEFINITION_ID,
                "native_symbol": f"spx_{provider_id.replace('.', '_')}",
                "source_sha256s": [_B],
                "object_sha256s": [_C],
            }],
            tool_sha256s=[_D],
        )
    )


def _runtime_qualification(
    module: LinkedSemanticModuleV2,
) -> SemanticProviderQualificationV2:
    return SemanticProviderQualificationV2.parse(
        build_semantic_provider_qualification_v2(
            semantic_slice=_obligation_slice(module),
            provider_id="runtime.checked",
            provider_kind="qualified_runtime",
            provider_artifact_sha256=_A,
            facets=_facets("qualified_runtime"),
            obligation_implementations=[{
                "obligation_id": _OBLIGATION_ID,
                "native_symbol": "spx_runtime_dispatch",
                "receipt_sha256": _B,
                "source_sha256s": [_C],
                "object_sha256s": [_D],
            }],
            tool_sha256s=[_E],
        )
    )


class SemanticProviderQualificationV2Tests(unittest.TestCase):
    def test_exact_slice_qualifications_are_complete(self) -> None:
        module = _module()
        generated = _definition_qualification(module)
        runtime = _runtime_qualification(module)

        self.assertEqual(generated.payload["status"], "complete")
        self.assertEqual(runtime.payload["status"], "complete")
        self.assertNotIn(
            "linked_semantic_module_sha256", generated.payload["bindings"]
        )
        self.assertEqual(
            generated.payload["bindings"]["semantic_slice_sha256"],
            generated.semantic_slice.identity,
        )

    def test_missing_facets_artifacts_and_coverage_are_honest(self) -> None:
        module = _module()
        payload = build_semantic_provider_qualification_v2(
            semantic_slice=_definition_slice(module),
            provider_id="generated.draft",
            provider_kind="generated_behavioral_c",
            provider_artifact_sha256=_A,
            facets=[],
        )
        self.assertEqual(payload["status"], "incomplete")
        codes = {row["code"] for row in payload["blockers"]}
        self.assertEqual(codes, {
            "provider_definition_missing", "provider_facet_missing",
            "provider_tool_identity_missing",
        })
        SemanticProviderQualificationV2.parse(payload)

    def test_disallowed_provider_kind_and_self_hash_fail_closed(self) -> None:
        module = _module()
        payload = build_semantic_provider_qualification_v2(
            semantic_slice=_definition_slice(module),
            provider_id="environment.wrong",
            provider_kind="external_environment",
            provider_artifact_sha256=_A,
            facets=_facets("external_environment"),
            definition_materializations=[{
                "definition_id": _DEFINITION_ID,
                "native_symbol": "spx_environment_wrong",
                "source_sha256s": [],
                "object_sha256s": [],
            }],
        )
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["blockers"][0]["code"], "provider_kind_not_allowed")

        stale = copy.deepcopy(payload)
        stale["provider_id"] = "environment.changed"
        with self.assertRaisesRegex(
            SemanticProviderQualificationV2Error, "self hash is stale"
        ):
            SemanticProviderQualificationV2.parse(stale)


class ImplementationSelectionV2Tests(unittest.TestCase):
    def _selection(
        self, module: LinkedSemanticModuleV2, *, definition_kind: str,
        mode: str,
    ) -> dict[str, object]:
        definition = _definition_qualification(
            module,
            kind=definition_kind,
            provider_id=(
                "portable.component" if definition_kind == "qualified_portable_c"
                else "generated.main"
            ),
        )
        runtime = _runtime_qualification(module)
        return build_implementation_selection_v2(
            linked_semantic_module=module,
            qualifications=[definition, runtime],
            definition_choices={_DEFINITION_ID: definition.provider_id},
            obligation_choices={_OBLIGATION_ID: runtime.provider_id},
            mode=mode,
        )

    def test_faithful_selection_is_explicit_total_and_complete(self) -> None:
        payload = self._selection(
            _module(), definition_kind="generated_behavioral_c",
            mode="faithful",
        )
        selection = ImplementationSelectionV2.parse(payload)
        self.assertTrue(selection.payload["ready_for_realization"])
        self.assertEqual(len(selection.payload["definition_selections"]), 1)
        self.assertEqual(len(selection.payload["obligation_selections"]), 1)

    def test_missing_obligation_selection_has_no_silent_fallback(self) -> None:
        module = _module()
        generated = _definition_qualification(module)
        payload = build_implementation_selection_v2(
            linked_semantic_module=module,
            qualifications=[generated],
            definition_choices={_DEFINITION_ID: generated.provider_id},
            mode="faithful",
        )
        self.assertEqual(payload["status"], "incomplete")
        self.assertIn(
            "obligation_selection_missing",
            {row["code"] for row in payload["blockers"]},
        )

    def test_analysis_only_module_change_reuses_qualifications(self) -> None:
        original = _module()
        generated = _definition_qualification(original)
        runtime = _runtime_qualification(original)
        changed = LinkedSemanticModuleV2(payload={
            **original.payload,
            "linked_semantic_module_sha256": "4" * 64,
            "link_provenance": {"algorithm": "different"},
        })
        payload = build_implementation_selection_v2(
            linked_semantic_module=changed,
            qualifications=[generated, runtime],
            definition_choices={_DEFINITION_ID: generated.provider_id},
            obligation_choices={_OBLIGATION_ID: runtime.provider_id},
        )
        self.assertEqual(payload["status"], "complete")
        self.assertEqual(
            payload["bindings"]["linked_semantic_module_sha256"], "4" * 64
        )

    def test_changed_definition_contract_rejects_stale_slice(self) -> None:
        original = _module()
        generated = _definition_qualification(original)
        runtime = _runtime_qualification(original)
        changed_payload = copy.deepcopy(original.payload)
        changed_payload["definitions"][0]["definition_sha256"] = _E
        changed_payload["linked_semantic_module_sha256"] = "4" * 64
        payload = build_implementation_selection_v2(
            linked_semantic_module=LinkedSemanticModuleV2(changed_payload),
            qualifications=[generated, runtime],
            definition_choices={_DEFINITION_ID: generated.provider_id},
            obligation_choices={_OBLIGATION_ID: runtime.provider_id},
        )
        self.assertEqual(payload["status"], "incomplete")
        self.assertIn(
            "provider_qualification_slice_stale",
            {row["code"] for row in payload["blockers"]},
        )

    def test_faithful_hybrid_and_portable_modes_are_distinct(self) -> None:
        module = _module()
        faithful_portable = self._selection(
            module, definition_kind="qualified_portable_c", mode="faithful"
        )
        self.assertIn(
            "faithful_mode_original_definition_not_generated",
            {row["code"] for row in faithful_portable["blockers"]},
        )
        self.assertEqual(self._selection(
            module, definition_kind="qualified_portable_c", mode="hybrid"
        )["status"], "complete")
        self.assertEqual(self._selection(
            module, definition_kind="qualified_portable_c", mode="portable"
        )["status"], "complete")
        generated_portable = self._selection(
            module, definition_kind="generated_behavioral_c", mode="portable"
        )
        self.assertIn(
            "portable_mode_generated_behavioral_c",
            {row["code"] for row in generated_portable["blockers"]},
        )

    def test_broken_overlay_does_not_poison_faithful_fallback(self) -> None:
        module = _module()
        broken_portable = SemanticProviderQualificationV2.parse(
            build_semantic_provider_qualification_v2(
                semantic_slice=_definition_slice(module),
                provider_id="portable.broken",
                provider_kind="qualified_portable_c",
                provider_artifact_sha256=_A,
                facets=[],
            )
        )
        runtime = _runtime_qualification(module)
        hybrid = build_implementation_selection_v2(
            linked_semantic_module=module,
            qualifications=[broken_portable, runtime],
            definition_choices={_DEFINITION_ID: broken_portable.provider_id},
            obligation_choices={_OBLIGATION_ID: runtime.provider_id},
            mode="hybrid",
        )
        self.assertEqual(hybrid["status"], "incomplete")
        self.assertIn(
            "provider_qualification_incomplete",
            {row["code"] for row in hybrid["blockers"]},
        )

        generated = _definition_qualification(module)
        faithful = build_implementation_selection_v2(
            linked_semantic_module=module,
            qualifications=[generated, runtime, broken_portable],
            definition_choices={_DEFINITION_ID: generated.provider_id},
            obligation_choices={_OBLIGATION_ID: runtime.provider_id},
            mode="faithful",
        )
        self.assertEqual(faithful["status"], "complete")
        self.assertTrue(faithful["ready_for_realization"])
        self.assertNotIn(
            broken_portable.identity, faithful["qualification_sha256s"]
        )

    def test_selection_self_hash_is_checked(self) -> None:
        payload = self._selection(
            _module(), definition_kind="generated_behavioral_c",
            mode="faithful",
        )
        payload["mode"] = "portable"
        with self.assertRaisesRegex(
            ImplementationSelectionV2Error, "self hash is stale"
        ):
            ImplementationSelectionV2.parse(payload)


if __name__ == "__main__":
    unittest.main()
