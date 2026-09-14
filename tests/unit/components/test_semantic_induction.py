from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace

from spaghetti_extractor.components.semantic_induction import (
    SemanticInductionError,
    build_inductive_machine_shape,
    build_inductive_segment_inventory,
)
from spaghetti_extractor.components.semantic_contract_transfer import _operation_units


def _unit(identity: str, rva: int, edges: list[tuple[int, object]]) -> dict[str, object]:
    return {
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "semantics": {
            "edge_conditions": [
                {"target_rva": target, "condition": condition}
                for target, condition in edges
            ],
            "outcome": (
                {"kind": "return"}
                if not edges
                else {"kind": "jump", "target_rva": edges[0][0]}
            ),
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
        },
    }


def _operation() -> dict[str, object]:
    return {
        "operation_id": "count",
        "entry_unit_ids": ["entry"],
        "exit_unit_ids": ["exit"],
        "units": [
            _unit("entry", 0x1000, [(0x1010, {"op": "true"})]),
            _unit(
                "head",
                0x1010,
                [
                    (0x1020, {"op": "parameter", "name": "continue"}),
                    (0x1030, {"op": "not", "args": [{"op": "parameter", "name": "continue"}]}),
                ],
            ),
            _unit("body", 0x1020, [(0x1010, {"op": "true"})]),
            _unit("exit", 0x1030, []),
        ],
    }


class SemanticInductionTests(unittest.TestCase):
    @staticmethod
    def _early_exit_loop():
        condition = {"op": "parameter", "name": "continue"}
        return {"operation_id": "scan", "entry_unit_ids": ["entry"], "exit_unit_ids": ["entry", "step"],
            "units": [_unit("entry", 0x1000, [(0x2000, condition), (0x1010, {"op": "not", "args": [condition]})]),
                      _unit("step", 0x1010, [(0x1010, condition), (0x2000, {"op": "not", "args": [condition]})])]}

    def test_exit_blocks_retain_internal_entry_and_back_edges(self):
        operation = self._early_exit_loop()
        shape = build_inductive_machine_shape(operation)
        self.assertTrue(shape['requires_induction'])
        self.assertEqual([(row['source_unit_id'], row['target_unit_id']) for row in shape['control_edges']],
                         [('entry', 'step'), ('step', 'step')])
        self.assertEqual(shape['cyclic_sccs'][0]['member_unit_ids'], ['step'])
        # The superseded path builder must not silently stop at the header.
        with self.assertRaisesRegex(SemanticInductionError, 'contextual cut checking'):
            build_inductive_segment_inventory(operation, cutpoint_unit_ids=['step'])

    def test_owned_closure_separates_continuation_and_requires_total_reachability(self):
        operation = self._early_exit_loop()
        selected = {row['id']: row for row in operation['units']}
        selected['context'] = _unit('context', 0x2000, [(0x3000, {'op': 'true'})])
        binding = SimpleNamespace(entry_unit_ids=['entry'], exit_unit_ids=['entry', 'step'], continuation_unit_ids=['context'])
        self.assertIsNone(_operation_units(binding, selected))
        checked = _operation_units(binding, selected, owned_unit_ids=['entry', 'step'])
        self.assertEqual([row['id'] for row in checked], ['entry', 'step'])
        for owned in ([], ['entry'], ['entry', 'step', 'context'], ['entry', 'step', 'missing'], ['entry', 'step', 'step']):
            with self.subTest(owned=owned):
                self.assertIsNone(_operation_units(binding, selected, owned_unit_ids=owned))
        selected['orphan'] = _unit('orphan', 0x4000, [(0x1010, {'op': 'true'})])
        self.assertIsNone(_operation_units(binding, selected, owned_unit_ids=['entry', 'step', 'orphan']))
        binding.exit_unit_ids = ['step']
        self.assertIsNone(_operation_units(binding, selected, owned_unit_ids=['entry', 'step']))

    def test_exit_label_cannot_hide_an_internal_cycle_or_an_undeclared_exit(self):
        operation = self._early_exit_loop()
        operation['exit_unit_ids'] = ['step']
        with self.assertRaisesRegex(SemanticInductionError, 'leaves the operation'):
            build_inductive_machine_shape(operation)
        operation = self._early_exit_loop()
        operation['units'][1] = _unit('step', 0x1010, [(0x1010, {'op': 'true'})])
        with self.assertRaisesRegex(SemanticInductionError, 'no outgoing boundary edge'):
            build_inductive_machine_shape(operation)

    def test_owned_closure_retains_nonowned_exact_return_epilogue(self):
        selected = {'body': _unit('body', 0x1000, [(0x1010, {'op': 'true'})]),
                    'epilogue': _unit('epilogue', 0x1010, [])}
        binding = SimpleNamespace(entry_unit_ids=['body'], exit_unit_ids=['epilogue'], continuation_unit_ids=[])
        checked = _operation_units(binding, selected, owned_unit_ids=['body'])
        self.assertEqual(checked, _operation_units(binding, selected))
        self.assertEqual([row['id'] for row in checked], ['body', 'epilogue'])

    def test_derives_exact_cyclic_scc_and_condensation(self) -> None:
        shape = build_inductive_machine_shape(_operation())
        self.assertTrue(shape["requires_induction"])
        self.assertEqual(len(shape["cyclic_sccs"]), 1)
        scc = shape["cyclic_sccs"][0]
        self.assertEqual(scc["member_unit_ids"], ["head", "body"])
        self.assertEqual(scc["entry_unit_ids"], ["head"])
        self.assertEqual(len(scc["internal_edges"]), 2)
        self.assertEqual(len(scc["exit_edges"]), 1)
        self.assertEqual(len(shape["control_edges"]), 4)
        self.assertEqual(len(shape["shape_sha256"]), 64)

    def test_rejects_edge_outside_selected_operation(self) -> None:
        operation = _operation()
        operation["units"][2]["semantics"]["edge_conditions"][0][
            "target_rva"
        ] = 0x9999
        with self.assertRaisesRegex(SemanticInductionError, "leaves the operation"):
            build_inductive_machine_shape(operation)

    def test_rejects_unreachable_selected_unit(self) -> None:
        operation = _operation()
        operation["units"].append(_unit("orphan", 0x1040, [(0x1030, {"op": "true"})]))
        with self.assertRaisesRegex(SemanticInductionError, "unreachable units"):
            build_inductive_machine_shape(operation)

    def test_rejects_closed_nonterminating_scc(self) -> None:
        operation = _operation()
        broken = copy.deepcopy(operation)
        broken["units"][1] = _unit("head", 0x1010, [(0x1020, {"op": "true"})])
        with self.assertRaisesRegex(
            SemanticInductionError, "unreachable units|no path to"
        ):
            build_inductive_machine_shape(broken)

    def test_acyclic_operation_does_not_require_induction(self) -> None:
        operation = {
            "operation_id": "direct",
            "entry_unit_ids": ["entry"],
            "exit_unit_ids": ["exit"],
            "units": [
                _unit("entry", 0x1000, [(0x1010, {"op": "true"})]),
                _unit("exit", 0x1010, []),
            ],
        }
        shape = build_inductive_machine_shape(operation)
        self.assertFalse(shape["requires_induction"])
        self.assertEqual(shape["cyclic_sccs"], [])

    def test_cutpoint_segments_cover_every_direct_edge_once_or_more(self) -> None:
        inventory = build_inductive_segment_inventory(
            _operation(), cutpoint_unit_ids=["head"]
        )
        self.assertEqual(inventory["control_edge_count"], 4)
        self.assertEqual(inventory["covered_control_edge_count"], 4)
        self.assertEqual(len(inventory["segments"]), 3)
        kinds = {
            (row["source"]["kind"], row["target"]["kind"])
            for row in inventory["segments"]
        }
        self.assertEqual(
            kinds,
            {
                ("operation_entry", "cutpoint"),
                ("cutpoint", "cutpoint"),
                ("cutpoint", "operation_exit"),
            },
        )
        self.assertFalse(inventory["policy"]["bounded_unrolling_used"])

    def test_rejects_cyclic_scc_without_a_cutpoint(self) -> None:
        with self.assertRaisesRegex(SemanticInductionError, "has no selected cutpoint"):
            build_inductive_segment_inventory(
                _operation(), cutpoint_unit_ids=["entry"]
            )

    def test_rejects_path_that_cycles_between_selected_cutpoints(self) -> None:
        operation = _operation()
        with self.assertRaisesRegex(SemanticInductionError, "unknown semantic units"):
            build_inductive_segment_inventory(
                operation, cutpoint_unit_ids=["not-a-unit"]
            )


if __name__ == "__main__":
    unittest.main()
