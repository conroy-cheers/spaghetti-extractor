from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.original_cutpoint_graph_ir import (
    OriginalCutpointEdge,
    OriginalCutpointGraphIR,
    OriginalCutpointRegion,
)


def _load_driver():
    path = (
        Path(__file__).parents[1]
        / "targets/gnu-hello/nix/gnu-hello-stack-dynamic-authority.py"
    )
    specification = importlib.util.spec_from_file_location(
        "gnu_hello_stack_dynamic_authority_rooted_tests",
        path,
    )
    if specification is None or specification.loader is None:
        raise AssertionError("cannot load GNU stack/dynamic authority driver")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


DRIVER = _load_driver()


def _region(
    target_id: int,
    successors: tuple[int, ...],
    *,
    root: bool = False,
) -> OriginalCutpointRegion:
    return OriginalCutpointRegion(
        target_id=target_id,
        rva=0x1000 + target_id * 0x10,
        size=0x10,
        alias_rvas=(),
        successor_target_ids=successors,
        root=root,
        synthetic_terminal_padding=False,
        semantic_contract_sha256=f"{target_id + 1:064x}",
        instruction_bytes_sha256=f"{target_id + 17:064x}",
    )


def _edge(
    edge_index: int,
    source: int,
    target: int,
) -> OriginalCutpointEdge:
    return OriginalCutpointEdge(
        edge_index=edge_index,
        source_target_id=source,
        target_target_id=target,
        kind="direct",
        machine_contract_id=None,
        transition_role="immediate",
        execution_successor=True,
    )


def _graph() -> OriginalCutpointGraphIR:
    successors = {
        0: (1,),
        1: (2, 4),
        2: (3,),
        3: (3, 6),
        4: (5, 7),
        5: (8,),
        6: (4,),
        7: (),
        8: (5, 7),
    }
    pairs = [
        (source, target)
        for source, targets in successors.items()
        for target in targets
    ]
    return OriginalCutpointGraphIR(
        original_pe_sha256="a" * 64,
        state_machine_sha256="b" * 64,
        regions=(
            *(
                _region(
                    target_id,
                    successors[target_id],
                    root=target_id == 0,
                )
                for target_id in range(9)
            ),
        ),
        edges=tuple(
            _edge(index, source, target)
            for index, (source, target) in enumerate(pairs)
        ),
        root_target_ids=(0,),
        reachable_target_ids=tuple(range(9)),
    )


def _scanner_semantic_transfers():
    register = DRIVER._semantic_register
    constant = DRIVER._semantic_constant
    table_base = 0x402000
    return {
        0x1010: {
            "register_writes": [{
                "register": "ebx",
                "value": {
                    "address": constant(table_base),
                    "op": "load",
                    "width": 4,
                },
            }],
        },
        0x1020: {
            "register_writes": [{
                "register": "eax",
                "value": constant(0),
            }],
        },
        0x1030: {
            "register_writes": [
                {
                    "register": "eax",
                    "value": {
                        "args": [register("eax"), constant(1)],
                        "op": "add32",
                    },
                },
                {
                    "register": "ebx",
                    "value": register("eax"),
                },
                {
                    "register": "edx",
                    "value": {
                        "address": {
                            "args": [constant(table_base), register("eax")],
                            "op": "add32",
                        },
                        "op": "load",
                        "width": 4,
                    },
                },
            ],
        },
        0x1040: {"register_writes": []},
        0x1060: {"register_writes": []},
    }


def _gnu_shape_graph() -> OriginalCutpointGraphIR:
    return OriginalCutpointGraphIR(
        original_pe_sha256="c" * 64,
        state_machine_sha256="d" * 64,
        regions=tuple(
            _region(
                target_id,
                (
                    (2595,)
                    if target_id == 2594
                    else (2596,)
                    if target_id == 2595
                    else (2595,)
                    if target_id == 2596
                    else ()
                ),
                root=target_id == 2594,
            )
            for target_id in range(2597)
        ),
        edges=tuple(sorted((
            _edge(0, 2594, 2595),
            _edge(1, 2595, 2596),
            _edge(2, 2596, 2595),
        ))),
        root_target_ids=(2594,),
        reachable_target_ids=(2594, 2595, 2596),
    )


def _empty_site(*, allowed_target_ids: tuple[int, ...] = ()):
    table = SimpleNamespace(
        address_scale=4,
        header_words=(2**32 - 1,),
    )
    finding = SimpleNamespace(
        indexed_empty_table=table,
        static_facts={
            "checked_empty_interval_candidate": True,
            "index_register": "ebx",
            "table_base_va": 0x402000,
            "word_0": 2**32 - 1,
            "word_1": 0,
        },
        stable_id="stack-dynamic-fixture",
        source_target_id=5,
        instruction_rva=0x1050,
    )
    return SimpleNamespace(
        closure_mode="empty_indexed_source",
        allowed_target_ids=allowed_target_ids,
        finding=finding,
        premise_type="CompleteEmptyIndexedSourcePredecessorPremise",
    )


def _dynamic_site():
    return SimpleNamespace(
        closure_mode="finite_dynamic_targets",
        allowed_target_ids=(7,),
        finding=SimpleNamespace(
            stable_id="dynamic-fixture",
            instruction_rva=0x2000,
        ),
        premise_type="CompleteDynamicCallbackPremise",
    )


class StageAGnuStackDynamicRootedUnreachabilityTests(unittest.TestCase):
    def test_stack_call_write_inventory_is_complete_and_normalized(self) -> None:
        row = {
            "original": {"rva_start": 0x1000},
            "instructions": [
                {"mnemonic": "mov"},
                {"mnemonic": "call"},
            ],
            "memory_events": [{
                "kind": "write",
                "width": 4,
                "address": {"op": "reg", "name": "esp"},
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            state_machine = Path(temporary) / "state-machine.jsonl"
            state_machine.write_text(
                json.dumps(row) + "\n",
                encoding="utf-8",
            )

            self.assertEqual(
                DRIVER._stack_call_write_adjustments(
                    state_machine,
                    source_rva=0x1000,
                ),
                (("identity", 0), ("add", 2**32 - 4)),
            )

    def test_stack_call_write_inventory_rejects_non_stack_writes(self) -> None:
        row = {
            "original": {"rva_start": 0x1000},
            "instructions": [{"mnemonic": "call"}],
            "memory_events": [{
                "kind": "write",
                "width": 4,
                "address": {"op": "reg", "name": "eax"},
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            state_machine = Path(temporary) / "state-machine.jsonl"
            state_machine.write_text(
                json.dumps(row) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "non-ESP-relative write",
            ):
                DRIVER._stack_call_write_adjustments(
                    state_machine,
                    source_rva=0x1000,
                )

    def test_empty_table_emits_exact_rooted_authority_and_frontier(self) -> None:
        closure = SimpleNamespace(sites=(_empty_site(), _dynamic_site()))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authorities, report, resources = (
                DRIVER._rooted_unreachability_authorities(
                    out=root,
                    closure=closure,
                    graph=_graph(),
                    semantic_transfers=_scanner_semantic_transfers(),
                )
            )
            frontiers = DRIVER._runtime_frontiers(
                closure,
                authorities,
            )

            self.assertEqual(len(authorities), 1)
            authority = authorities[0]
            self.assertEqual(authority.root_target_ids, (0,))
            self.assertEqual(
                authority.root_path_target_ids,
                (0, 1, 4, 5),
            )
            self.assertEqual(authority.forward_target_ids, (5, 7, 8))
            self.assertEqual(authority.scc_target_ids, (5, 8))
            self.assertEqual(
                tuple(
                    (edge.source_target_id, edge.target_target_id)
                    for edge in authority.incoming_edges
                ),
                ((4, 5), (8, 5), (5, 8)),
            )
            self.assertEqual(
                frontiers[0]["premise_type"],
                "CheckedRootedScannerSccExecution",
            )
            self.assertIn("Authority", frontiers[0]["authority_term"])
            self.assertEqual(
                frontiers[1]["premise_type"],
                "CompleteDynamicCallbackPremise",
            )

            source = (
                root
                / "StageA"
                / (
                    "GeneratedRelationalNullableCodePointer"
                    "RootedUnreachability0.lean"
                )
            ).read_text(encoding="utf-8")
            for fragment in (
                "rootTargetIds := [0]",
                "sourceTargetId := 4, targetTargetId := 5",
                "rootPathTargetIds := [0, 1, 4, 5]",
                "forwardTargetIds := [5, 7, 8]",
                "sccTargetIds := [5, 8]",
                "CheckedRootedScannerSccExecution",
                "scannerRegister := .eax",
                "countRegister := .ebx",
                "loadedRegister := .edx",
                "generatedOriginalStackDynamicClosure0EmptyIndexedAuthority",
            ):
                self.assertIn(fragment, source)
            for forbidden in (
                "generatedNullableCodePointerDispatch",
                "StaticProofContext",
                "DecodedDispatchCluster",
            ):
                self.assertNotIn(forbidden, source)

            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["format"],
                (
                    "stage-a-relational-nullable-code-pointer-"
                    "rooted-scc-v4"
                ),
            )
            self.assertEqual(
                payload["entries"][0]["forward_target_ids"],
                [5, 7, 8],
            )
            self.assertEqual(
                payload["entries"][0]["scc_target_ids"],
                [5, 8],
            )
            self.assertEqual(
                payload["entries"][0]["incoming_edges"],
                [
                    {"source_target_id": 4, "target_target_id": 5},
                    {"source_target_id": 8, "target_target_id": 5},
                    {"source_target_id": 5, "target_target_id": 8},
                ],
            )
            self.assertIn(
                "GeneratedRelationalNullableCodePointer"
                "RootedUnreachability0",
                resources,
            )

    def test_nonempty_table_is_rejected_before_authority_emission(self) -> None:
        submitted_target = _empty_site(allowed_target_ids=(9,))
        nonzero_row = _empty_site()
        nonzero_row.finding.static_facts["word_1"] = 0x401000
        for name, site, message in (
            ("submitted target", submitted_target, "submits nonempty targets"),
            ("nonzero table row", nonzero_row, "is not the exact PE32"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(
                    DRIVER.RootedUnreachabilityDriverError,
                    message,
                ):
                    DRIVER._rooted_unreachability_authorities(
                        out=Path(temporary),
                        closure=SimpleNamespace(sites=(site,)),
                        graph=_graph(),
                        semantic_transfers=_scanner_semantic_transfers(),
                    )

    def test_missing_or_inconsistent_graph_evidence_fails_closed(self) -> None:
        closure = SimpleNamespace(sites=(_empty_site(),))
        graph = _graph()
        corruptions = {
            "missing edge record": OriginalCutpointGraphIR(
                graph.original_pe_sha256,
                graph.state_machine_sha256,
                graph.regions,
                tuple(
                    edge
                    for edge in graph.edges
                    if not (
                        edge.source_target_id == 4
                        and edge.target_target_id == 5
                    )
                ),
                graph.root_target_ids,
                graph.reachable_target_ids,
            ),
            "missing SCC edge record": OriginalCutpointGraphIR(
                graph.original_pe_sha256,
                graph.state_machine_sha256,
                graph.regions,
                tuple(
                    edge for edge in graph.edges
                    if not (
                        edge.source_target_id == 8
                        and edge.target_target_id == 5
                    )
                ),
                graph.root_target_ids,
                graph.reachable_target_ids,
            ),
            "inconsistent roots": OriginalCutpointGraphIR(
                graph.original_pe_sha256,
                graph.state_machine_sha256,
                graph.regions,
                graph.edges,
                (1,),
                graph.reachable_target_ids,
            ),
        }
        for name, corrupted in corruptions.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(
                    DRIVER.RootedUnreachabilityDriverError
                ):
                    DRIVER._rooted_unreachability_authorities(
                        out=Path(temporary),
                        closure=closure,
                        graph=corrupted,
                        semantic_transfers=_scanner_semantic_transfers(),
                    )

        unnamed = _empty_site()
        unnamed.finding.stable_id = ""
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                DRIVER.RootedUnreachabilityDriverError,
                "has no stable name",
            ):
                DRIVER._rooted_unreachability_authorities(
                    out=Path(temporary),
                    closure=SimpleNamespace(sites=(unnamed,)),
                    graph=graph,
                    semantic_transfers=_scanner_semantic_transfers(),
                )

    def test_actual_gnu_predecessor_and_loopback_form_one_scc(self) -> None:
        root_path, forward, scc, incoming = DRIVER._rooted_dispatch_graph(
            _gnu_shape_graph(),
            2595,
        )

        self.assertEqual(root_path, (2594, 2595))
        self.assertEqual(forward, (2595, 2596))
        self.assertEqual(scc, (2595, 2596))
        self.assertEqual(
            tuple(
                (edge.source_target_id, edge.target_target_id)
                for edge in incoming
            ),
            ((2594, 2595), (2596, 2595), (2595, 2596)),
        )


if __name__ == "__main__":
    unittest.main()
