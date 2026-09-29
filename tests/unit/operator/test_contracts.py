from __future__ import annotations

import unittest

from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.operator.formats import (
    OPERATOR_BLOCKER_DETAIL_FORMAT,
    OPERATOR_INDEX_FORMAT,
    OPERATOR_WORK_STATUS_FORMAT,
)
from spaghetti_extractor.operator.index_v1 import parse_operator_index_v1
from spaghetti_extractor.operator.work_status import (
    build_operator_blocker_detail_v1,
    build_operator_work_status_v2,
)


def _index() -> dict[str, object]:
    return {
        "format": OPERATOR_INDEX_FORMAT,
        "targetId": "fixture",
        "defaultConfiguration": "faithful",
        "project": {
            "products": [
                "acceptanceCheck",
                "analysis",
                "regressionCheck",
                "semanticModule",
                "status",
            ],
        },
        "components": {
            "products": ["proposals"],
            "units": {
                "leaf": {
                    "label": "Leaf",
                    "entryRvas": [4096],
                    "products": ["workPackage"],
                },
            },
        },
        "boundaries": {
            "products": ["check", "status"],
            "subjects": {
                "component:leaf": {
                    "kind": "component",
                    "products": ["source"],
                },
            },
        },
        "libraries": None,
        "candidate": {
            "products": [],
            "configurations": {
                "faithful": {
                    "label": "Faithful machine baseline",
                    "mode": "faithful",
                    "selectedComponentIds": [],
                    "products": ["realization", "selection"],
                },
            },
            "testSuites": {},
        },
    }


class OperatorIndexV1Tests(unittest.TestCase):
    def test_optional_authoring_paths_require_distinct_target_relative_files(self) -> None:
        value = _index()
        paths = {'intent': 'intent/components.json', 'interface_index': 'contracts/interfaces-v5/index.json',
                 'binding_index': 'contracts/bindings-v5/index.json'}
        value['components']['authoringPaths'] = paths
        self.assertEqual(parse_operator_index_v1(value), value)
        for bad in ('../outside.json', '/outside.json', '.', 'a/../b.json', 'a//b.json', paths['binding_index']):
            value['components']['authoringPaths'] = {**paths, 'intent': bad}
            with self.subTest(path=bad), self.assertRaises(ToolkitInputError):
                parse_operator_index_v1(value)

    def test_exact_product_index_parses_without_realizing_products(self) -> None:
        self.assertEqual(parse_operator_index_v1(_index()), _index())

    def test_unknown_fields_and_ambiguous_component_aliases_fail_closed(self) -> None:
        extra = _index()
        extra["compatibility"] = {}
        with self.assertRaisesRegex(ToolkitInputError, "fields are incomplete"):
            parse_operator_index_v1(extra)

        duplicate_rva = _index()
        duplicate_rva["components"]["units"]["second"] = {
            "label": "Second",
            "entryRvas": [4096],
            "products": [],
        }
        with self.assertRaisesRegex(ToolkitInputError, "entry RVA.*shared"):
            parse_operator_index_v1(duplicate_rva)

    def test_candidate_references_only_indexed_component_units(self) -> None:
        value = _index()
        value["candidate"]["configurations"]["faithful"][
            "selectedComponentIds"
        ] = ["missing"]
        with self.assertRaisesRegex(ToolkitInputError, "selected components"):
            parse_operator_index_v1(value)


class OperatorWorkStatusV2Tests(unittest.TestCase):
    def test_status_groups_source_native_blockers_without_copying_details(self) -> None:
        digest = "a" * 64
        payload = build_operator_work_status_v2(
            target_id="fixture",
            scope="component-development",
            subjects=[{
                "subject": "component:leaf",
                "kind": "component",
                "state": "incomplete",
                "authority": "not-applicable",
                "stage": "source",
                "sources": [{
                    "role": "component-work-package",
                    "format": "fixture-work-package-v1",
                    "sha256": digest,
                }],
                "blockers": [
                    {"family": "source", "code": "missing", "location": "b.c"},
                    {"family": "abi", "code": "unknown", "location": "entry"},
                    {"family": "source", "code": "missing", "location": "a.c"},
                ],
                "next_action": "author source",
            }],
        )
        self.assertEqual(payload["format"], OPERATOR_WORK_STATUS_FORMAT)
        self.assertEqual(payload["counts"]["blockers"], 3)
        self.assertEqual(payload["subjects"][0]["blockers"], {
            "count": 3,
            "groups": [
                {
                    "family": "abi",
                    "code": "unknown",
                    "count": 1,
                    "example_location": "entry",
                },
                {
                    "family": "source",
                    "code": "missing",
                    "count": 2,
                    "example_location": "b.c",
                },
            ],
        })

    def test_incomplete_subject_cannot_claim_authority(self) -> None:
        value = {
            "subject": "component:leaf",
            "kind": "component",
            "state": "incomplete",
            "authority": "held",
            "stage": None,
            "sources": [],
            "blockers": [],
            "next_action": None,
        }
        with self.assertRaisesRegex(ToolkitInputError, "authority is inconsistent"):
            build_operator_work_status_v2(
                target_id="fixture", scope="component", subjects=[value]
            )

    def test_detail_envelope_is_source_bound_and_explicitly_limited(self) -> None:
        blockers = [{"code": "missing", "detail": str(index)} for index in range(3)]
        payload = build_operator_blocker_detail_v1(
            target_id="fixture",
            subject="component:leaf",
            source_format="fixture-work-package-v1",
            source_sha256="b" * 64,
            blockers=blockers,
            family="source",
            code="missing",
            limit=2,
        )
        self.assertEqual(payload["format"], OPERATOR_BLOCKER_DETAIL_FORMAT)
        self.assertEqual(payload["total"], 3)
        self.assertEqual(payload["returned"], 2)
        self.assertEqual(payload["blockers"], blockers[:2])


if __name__ == "__main__":
    unittest.main()
