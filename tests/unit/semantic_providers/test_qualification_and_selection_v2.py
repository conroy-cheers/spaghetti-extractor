from __future__ import annotations

import copy
import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.semantic_providers.exact_context import (
    build_exact_context, exact_context_blockers, validate_proof_exact_context,
)
from spaghetti_extractor.semantic_providers.slices_v2 import SemanticSliceV2Error

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
            "bisimulation", "compile", "contextual_refinement", "lifecycle",
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


class ExactContextSelectionTests(unittest.TestCase):
    def setUp(self):
        self.context_id = f"semantic-definition-v2:{'5' * 64}"
        self.module = _module()
        self.module.payload["definitions"].append({
            **self.module.payload["definitions"][0],
            "definition_id": self.context_id, "symbol_id": "original:function:continuation",
        })
        self.module.payload["definition_requirements"].append({
            **self.module.payload["definition_requirements"][0],
            "definition_id": self.context_id, "symbol_id": "original:function:continuation",
        })
        self.plan = {"operations": [{"continuation": {"unit_ids": ["continuation"]}}]}
        self.context = build_exact_context(
            proof_plan=self.plan, linked=self.module, owned=_definition_slice(self.module),
        )
        payload = dict(_definition_qualification(
            self.module, kind="qualified_portable_c", provider_id="portable.body",
        ).payload)
        payload["exact_context"] = self.context
        self.portable = self.reparse(payload)
        self.runtime = _runtime_qualification(self.module)

    @staticmethod
    def reparse(payload):
        payload["qualification_sha256"] = canonical_sha256_v3({
            key: value for key, value in payload.items() if key != "qualification_sha256"
        })
        return SemanticProviderQualificationV2.parse(payload)

    def context_provider(self, kind="generated_behavioral_c"):
        return SemanticProviderQualificationV2.parse(build_semantic_provider_qualification_v2(
            semantic_slice=SemanticSliceV2.parse(self.context),
            provider_id="context.provider", provider_kind=kind,
            provider_artifact_sha256=_A, facets=_facets(kind), tool_sha256s=[_B],
            definition_materializations=[{
                "definition_id": self.context_id, "native_symbol": "spx_context",
                "source_sha256s": [_C], "object_sha256s": [_D],
            }],
        ))

    def select(self, context=None, module=None, mode="hybrid"):
        return build_implementation_selection_v2(
            linked_semantic_module=module or self.module,
            qualifications=[self.portable, self.runtime, *([context] if context else [])],
            definition_choices={
                _DEFINITION_ID: self.portable.provider_id,
                **({self.context_id: context.provider_id} if context else {}),
            },
            obligation_choices={_OBLIGATION_ID: self.runtime.provider_id}, mode=mode,
        )

    def test_generated_context_is_required_by_final_choices(self):
        self.assertEqual(self.select(self.context_provider())["status"], "complete")
        replaced = self.select(self.context_provider("qualified_portable_c"))
        self.assertIn("provider_exact_context_replaced", {row["code"] for row in replaced["blockers"]})
        missing = self.select()
        self.assertIn("provider_exact_context_selection_missing", {row["code"] for row in missing["blockers"]})
        self.assertEqual(self.select(self.context_provider(), mode="portable")["status"], "incomplete")

    def test_context_change_invalidates_but_unrelated_analysis_does_not(self):
        generated = self.context_provider()
        changed = copy.deepcopy(self.module)
        changed.payload["linked_semantic_module_sha256"] = _D
        self.assertEqual(self.select(generated, module=changed)["status"], "complete")
        changed.payload["definitions"][1]["definition_sha256"] = _E
        result = self.select(generated, module=changed)
        self.assertIn("provider_exact_context_stale", {row["code"] for row in result["blockers"]})

    def test_unselected_conditional_provider_does_not_reserve_context(self):
        body = _definition_qualification(self.module)
        context = self.context_provider("qualified_portable_c")
        result = build_implementation_selection_v2(
            linked_semantic_module=self.module,
            qualifications=[body, context, self.portable, self.runtime],
            definition_choices={_DEFINITION_ID: body.provider_id, self.context_id: context.provider_id},
            obligation_choices={_OBLIGATION_ID: self.runtime.provider_id}, mode="hybrid",
        )
        self.assertEqual(result["status"], "complete")

    def test_context_cannot_be_owned_or_missing_or_require_a_service(self):
        for context in (_definition_slice(self.module).payload, _obligation_slice(self.module).payload):
            payload = copy.deepcopy(self.portable.payload)
            payload["exact_context"] = context
            with self.assertRaisesRegex(SemanticProviderQualificationV2Error, "unowned generated"):
                self.reparse(payload)
        for linked in (None, _module()):
            with self.assertRaises(SemanticSliceV2Error):
                build_exact_context(proof_plan=self.plan, linked=linked, owned=_definition_slice(self.module))
        payload = copy.deepcopy(self.portable.payload)
        payload["provider_kind"] = "generated_behavioral_c"
        with self.assertRaisesRegex(SemanticProviderQualificationV2Error, "only portable"):
            self.reparse(payload)

    def test_context_selected_qualification_and_native_symbol_are_bound(self):
        context = self.context_provider()
        selection = self.select(context)
        choices = copy.deepcopy(selection["definition_selections"])
        next(row for row in choices if row["definition_id"] == self.context_id)["native_symbol"] = "wrong"
        result = exact_context_blockers(
            qualifications=[self.portable, self.runtime, context], definition_selections=choices,
        )
        self.assertEqual(result[0]["code"], "provider_exact_context_qualification_mismatch")

    def test_dispatch_context_inventory_must_match_the_actual_proof(self):
        validate_proof_exact_context(proof_plan=self.plan, qualification=self.portable)
        stripped = copy.deepcopy(self.portable.payload)
        del stripped["exact_context"]
        with self.assertRaisesRegex(SemanticSliceV2Error, "omits its proof"):
            validate_proof_exact_context(proof_plan=self.plan, qualification=self.reparse(stripped))
        for plan in ({"operations": []}, {"operations": [{"continuation": {"unit_ids": ["different"]}}]}):
            with self.assertRaises(SemanticSliceV2Error):
                validate_proof_exact_context(proof_plan=plan, qualification=self.portable)

    def test_native_consumers_recheck_rehashed_selection_with_blockers_removed(self):
        from spaghetti_extractor.candidate.build_workflow import _selected_provider_object_sources
        from spaghetti_extractor.candidate.build_model import CandidateNativeBuildError
        from spaghetti_extractor.native_realization.receipt_v2 import write_native_realization_v2, NativeRealizationV2Error

        context = self.context_provider("qualified_portable_c")
        selection = self.select(context)
        selection.update(status="complete", ready_for_realization=True, blockers=[])
        selection["selection_sha256"] = canonical_sha256_v3({
            key: value for key, value in selection.items() if key != "selection_sha256"
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection_path = root / "selection.json"
            selection_path.write_text(json.dumps(selection))
            paths = []
            for index, qualification in enumerate([self.portable, self.runtime, context]):
                path = root / f"qualification-{index}.json"
                path.write_text(json.dumps(qualification.payload))
                paths.append(path)
            with self.assertRaisesRegex(CandidateNativeBuildError, "exact context is unsatisfied"):
                _selected_provider_object_sources(implementation_selection=selection_path, provider_qualifications=paths)
            with patch.object(LinkedSemanticModuleV2, "load", return_value=self.module):
                with self.assertRaisesRegex(NativeRealizationV2Error, "exact context is unsatisfied"):
                    write_native_realization_v2(
                        linked_semantic_module=root / "linked.json", implementation_selection=selection_path,
                        provider_qualifications=paths, candidate_module=root / "unused.exe", out=root / "receipt.json",
                    )


if __name__ == "__main__":
    unittest.main()
