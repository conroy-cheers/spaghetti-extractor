from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.abi_records import (
    LibraryAbiError,
    CallbackSlotV3,
)
from spaghetti_extractor.libraries.constellations import (
    match_library_constellations,
)
from spaghetti_extractor.libraries.signature_graph import (
    TARGET_SIGNATURE_GRAPH_CODEC_V3,
    build_target_signature_graph,
)
from spaghetti_extractor.artifacts.formats import LIBRARY_ARTIFACT_INPUTS_FORMAT
from spaghetti_extractor.libraries.catalog import (
    bind_library_artifact_inputs,
    index_library_artifacts,
)
from spaghetti_extractor.util import sha256_file, write_json
from tests.pe_fixtures import pe32_import_image
from tests.unit.libraries._support import coff_object

from .library_fixture_support import (
    abi_profile,
    catalog,
    function_signature,
    machine_unit,
    procedure_candidates,
    write_machine,
)


class AbiFirstMatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _graph(self, units: list[dict[str, object]]):
        machine = write_machine(self.root, units)
        candidates = procedure_candidates(
            machine,
            tuple(
                (f"procedure:{unit['id']}", (str(unit["id"]),))
                for unit in units
            ),
        )
        graph = build_target_signature_graph(
            machine,
            self.root / "target-signatures.json",
            procedure_candidates=candidates,
        )
        return machine, graph

    def _match(self, graph, catalog_record):
        catalog_path = self.root / "catalog.json"
        LIBRARY_ABI_CATALOG_CODEC_V3.write(catalog_path, catalog_record)
        index = build_catalog_search_index(
            catalog_path, self.root / "search-index.json"
        )
        hypotheses = match_library_constellations(
            graph, index, self.root / "hypotheses.json"
        )
        return index, hypotheses

    def test_unit_merkle_match_is_complete_and_file_bound(self) -> None:
        _machine, graph = self._graph(
            [machine_unit("common", 0x1000, "a" * 64, abi_profile())]
        )
        function = function_signature(
            function_id="catalog-common",
            release="1.0",
            exact_hash=graph.functions[0].exact_bytes_sha256,
            unit_merkle_hash=graph.functions[0].unit_merkle_sha256,
            cfg_hash=graph.functions[0].cfg_sha256,
        )
        index, hypotheses = self._match(graph, catalog((function,)))

        self.assertEqual(graph.status, "complete")
        self.assertEqual(index.status, "complete")
        self.assertEqual(hypotheses.status, "complete")
        self.assertEqual(len(hypotheses.hypotheses), 1)
        self.assertEqual(hypotheses.hypotheses[0].status, "complete")
        reread = TARGET_SIGNATURE_GRAPH_CODEC_V3.read(
            self.root / "target-signatures.json"
        )
        self.assertEqual(reread, graph)

    def test_multi_block_candidate_matches_one_catalog_function(self) -> None:
        machine = write_machine(
            self.root,
            [
                machine_unit(
                    "block-a",
                    0x1000,
                    "a" * 64,
                    abi_profile(),
                    direct_targets=(0x1008,),
                    control_kind="branch",
                ),
                machine_unit("block-b", 0x1008, "b" * 64, abi_profile()),
            ],
        )
        partition = procedure_candidates(
            machine,
            (("procedure:multi-block", ("block-a", "block-b")),),
        )
        graph = build_target_signature_graph(
            machine,
            self.root / "multi-target-signatures.json",
            procedure_candidates=partition,
        )
        self.assertEqual(len(graph.functions), 1)
        self.assertEqual(graph.functions[0].unit_ids, ("block-a", "block-b"))
        function = function_signature(
            function_id="catalog-multi-block",
            release="1.0",
            exact_hash=None,
            unit_merkle_hash=graph.functions[0].unit_merkle_sha256,
            cfg_hash=graph.functions[0].cfg_sha256,
        )
        catalog_path = self.root / "multi-catalog.json"
        LIBRARY_ABI_CATALOG_CODEC_V3.write(catalog_path, catalog((function,)))
        index = build_catalog_search_index(
            catalog_path, self.root / "multi-search-index.json"
        )
        hypotheses = match_library_constellations(
            graph, index, self.root / "multi-hypotheses.json"
        )
        self.assertEqual(len(hypotheses.hypotheses), 1)
        self.assertIn(
            "unit_merkle", hypotheses.hypotheses[0].matches[0].evidence
        )

    def test_ambiguous_overlapping_procedure_candidates_remain_explicit(self) -> None:
        machine = write_machine(
            self.root,
            [
                machine_unit("a", 0x1000, "a" * 64, abi_profile()),
                machine_unit("shared", 0x1008, "b" * 64, abi_profile()),
                machine_unit("b", 0x1010, "c" * 64, abi_profile()),
            ],
        )
        partition = procedure_candidates(
            machine,
            (
                ("procedure:left", ("a", "shared")),
                ("procedure:right", ("shared", "b")),
            ),
        )
        graph = build_target_signature_graph(
            machine,
            self.root / "overlap-target-signatures.json",
            procedure_candidates=partition,
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertEqual(len(graph.functions), 2)
        self.assertTrue(
            all("shared" in function.unit_ids for function in graph.functions)
        )
        self.assertIn(
            "procedure_partition_ambiguous", {issue.code for issue in graph.issues}
        )

    def test_absent_partition_uses_conservative_cfg_candidate_and_is_incomplete(self) -> None:
        machine = write_machine(
            self.root,
            [
                machine_unit(
                    "entry",
                    0x1000,
                    "a" * 64,
                    abi_profile(),
                    direct_targets=(0x1008,),
                    control_kind="branch",
                ),
                machine_unit("return", 0x1008, "b" * 64, abi_profile()),
            ],
        )
        graph = build_target_signature_graph(
            machine, self.root / "inferred-target-signatures.json"
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertEqual(len(graph.functions), 1)
        self.assertEqual(graph.functions[0].candidate_kind, "structural_cfg")
        self.assertEqual(graph.functions[0].unit_ids, ("entry", "return"))
        self.assertIn(
            "procedure_partition_missing", {issue.code for issue in graph.issues}
        )

    def test_contiguous_pe_bytes_match_legacy_catalog_bytes_like_for_like(self) -> None:
        code = bytes.fromhex("5589e583ec08b82a000000c9c3")
        pe_bytes = pe32_import_image(code, symbol="WriteFile")
        machine = write_machine(
            self.root,
            [
                machine_unit(
                    "first-half", 0x1000, "a" * 64, abi_profile()
                ),
                {
                    **machine_unit(
                        "second-half", 0x1008, "b" * 64, abi_profile()
                    ),
                    "source": {
                        "original": {
                            "rva_start": 0x1008,
                            "rva_end": 0x1000 + len(code),
                        },
                        "instruction_bytes_sha256": "b" * 64,
                    },
                },
            ],
            binary_bytes=pe_bytes,
        )
        first = json.loads(
            (machine / "machine-ir.jsonl").read_text(encoding="utf-8").splitlines()[0]
        )
        first["source"]["original"]["rva_end"] = 0x1008
        rows = [
            first,
            json.loads(
                (machine / "machine-ir.jsonl").read_text(encoding="utf-8").splitlines()[1]
            ),
        ]
        ir = machine / "machine-ir.jsonl"
        ir.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        manifest = json.loads(
            (machine / "machine-ir-manifest.json").read_text(encoding="utf-8")
        )
        manifest["artifacts"]["machine_ir"]["sha256"] = sha256_file(ir)
        write_json(machine / "machine-ir-manifest.json", manifest)
        partition = procedure_candidates(
            machine,
            (("procedure:contiguous", ("first-half", "second-half")),),
        )
        graph = build_target_signature_graph(
            machine,
            self.root / "pe-target-signatures.json",
            procedure_candidates=partition,
            original_pe=self.root / "fixture.exe",
        )
        self.assertIsNotNone(graph.functions[0].exact_bytes_sha256)

        artifacts = self.root / "legacy-artifacts"
        artifacts.mkdir()
        (artifacts / "runtime.obj").write_bytes(
            coff_object(code, symbol="_fixture")
        )
        declaration = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "legacy-runtime",
                "artifacts": [{"id": "runtime", "path": "runtime.obj"}],
            }
        )
        legacy_index = self.root / "legacy-index.json"
        index_library_artifacts(
            inputs=declaration,
            artifact_root=artifacts,
            out=legacy_index,
        )
        search = build_catalog_search_index(
            legacy_index, self.root / "legacy-search.json"
        )
        hypotheses = match_library_constellations(
            graph, search, self.root / "legacy-hypotheses.json"
        )

        self.assertTrue(hypotheses.hypotheses)
        self.assertIn("exact_bytes", hypotheses.hypotheses[0].matches[0].evidence)
        self.assertNotIn(
            "unit_merkle", hypotheses.hypotheses[0].matches[0].evidence
        )
        self.assertEqual(hypotheses.hypotheses[0].status, "incomplete")

    def test_version_ambiguous_exact_match_remains_incomplete(self) -> None:
        _machine, graph = self._graph(
            [machine_unit("common", 0x1000, "a" * 64, abi_profile())]
        )
        functions = tuple(
            function_signature(
                function_id=f"catalog-common-{release}",
                release=release,
                exact_hash=graph.functions[0].exact_bytes_sha256,
                unit_merkle_hash=graph.functions[0].unit_merkle_sha256,
                cfg_hash=graph.functions[0].cfg_sha256,
            )
            for release in ("1.0", "2.0")
        )
        _index, hypotheses = self._match(graph, catalog(functions))

        self.assertEqual(hypotheses.status, "incomplete")
        self.assertEqual(len(hypotheses.hypotheses), 2)
        self.assertIn(
            "constellation_version_ambiguous",
            {issue.code for issue in hypotheses.issues},
        )

    def test_unique_anchor_disambiguates_a_common_function(self) -> None:
        _machine, graph = self._graph(
            [
                machine_unit("common", 0x1000, "a" * 64, abi_profile()),
                machine_unit("unique", 0x1010, "b" * 64, abi_profile()),
            ]
        )
        by_rva = {item.rva_start: item for item in graph.functions}
        functions = (
            function_signature(
                function_id="v1-common",
                release="1.0",
                exact_hash=by_rva[0x1000].exact_bytes_sha256,
                unit_merkle_hash=by_rva[0x1000].unit_merkle_sha256,
                cfg_hash=by_rva[0x1000].cfg_sha256,
            ),
            function_signature(
                function_id="v1-unique",
                release="1.0",
                exact_hash=by_rva[0x1010].exact_bytes_sha256,
                unit_merkle_hash=by_rva[0x1010].unit_merkle_sha256,
                cfg_hash=by_rva[0x1010].cfg_sha256,
            ),
            function_signature(
                function_id="v2-common",
                release="2.0",
                exact_hash=by_rva[0x1000].exact_bytes_sha256,
                unit_merkle_hash=by_rva[0x1000].unit_merkle_sha256,
                cfg_hash=by_rva[0x1000].cfg_sha256,
            ),
        )
        _index, hypotheses = self._match(graph, catalog(functions))

        self.assertEqual(hypotheses.hypotheses[0].release_id, "1.0")
        self.assertEqual(len(hypotheses.hypotheses[0].target_function_ids), 2)
        self.assertGreater(
            hypotheses.hypotheses[0].diagnostic_score,
            hypotheses.hypotheses[1].diagnostic_score,
        )

    def test_abi_contradictions_are_violated_with_locations(self) -> None:
        cases = {
            "calling convention": abi_profile(preserved_registers=("ebp",)),
            "hidden sret": abi_profile(hidden_sret=True),
            "varargs": abi_profile(variadic="format"),
        }
        for label, target_abi in cases.items():
            with self.subTest(label=label):
                root = self.root / label.replace(" ", "-")
                root.mkdir()
                machine = write_machine(
                    root,
                    [machine_unit("function", 0x1000, "a" * 64, target_abi)],
                )
                graph = build_target_signature_graph(
                    machine,
                    root / "target-signatures.json",
                    procedure_candidates=procedure_candidates(
                        machine, (("procedure:function", ("function",)),)
                    ),
                )
                function = function_signature(
                    function_id="catalog-function",
                    release="1.0",
                    exact_hash=graph.functions[0].exact_bytes_sha256,
                    unit_merkle_hash=graph.functions[0].unit_merkle_sha256,
                    cfg_hash=graph.functions[0].cfg_sha256,
                )
                catalog_path = root / "catalog.json"
                LIBRARY_ABI_CATALOG_CODEC_V3.write(
                    catalog_path, catalog((function,))
                )
                index = build_catalog_search_index(
                    catalog_path, root / "search-index.json"
                )
                hypotheses = match_library_constellations(
                    graph, index, root / "hypotheses.json"
                )
                contradictions = [
                    issue
                    for issue in hypotheses.issues
                    if issue.code == "function_abi_contradiction"
                ]
                self.assertEqual(len(contradictions), 1)
                self.assertEqual(contradictions[0].status, "violated")
                self.assertIn("target-function:", contradictions[0].location)

    def test_callback_slots_are_hard_abi_evidence(self) -> None:
        target_abi = abi_profile(
            callback_slots=(CallbackSlotV3(0, "x86-cdecl", False),)
        )
        _machine, graph = self._graph(
            [machine_unit("callback-user", 0x1000, "a" * 64, target_abi)]
        )
        function = function_signature(
            function_id="catalog-function",
            release="1.0",
            exact_hash=graph.functions[0].exact_bytes_sha256,
            unit_merkle_hash=graph.functions[0].unit_merkle_sha256,
            cfg_hash=graph.functions[0].cfg_sha256,
        )
        _index, hypotheses = self._match(graph, catalog((function,)))
        self.assertEqual(hypotheses.status, "violated")
        self.assertTrue(
            any("callback_slots" in issue.message for issue in hypotheses.issues)
        )

    def test_missing_target_abi_is_incomplete(self) -> None:
        _machine, graph = self._graph(
            [machine_unit("unknown-abi", 0x1000, "a" * 64, None)]
        )
        self.assertEqual(graph.status, "incomplete")
        self.assertEqual(graph.issues[0].code, "target_function_abi_missing")

    def test_native_path_cannot_drop_an_unknown_abi_candidate(self) -> None:
        class EmptyNativeBackend:
            def generate_library_candidates(self, target_graph, search_index):
                return ()

        _machine, graph = self._graph(
            [machine_unit("unknown-abi", 0x1000, "a" * 64, None)]
        )
        function = function_signature(
            function_id="catalog-function",
            release="1.0",
            exact_hash=None,
            cfg_hash=graph.functions[0].cfg_sha256,
            abi_profile_id=None,
            unit_merkle_hash=graph.functions[0].unit_merkle_sha256,
        )
        catalog_path = self.root / "unknown-abi-catalog.json"
        LIBRARY_ABI_CATALOG_CODEC_V3.write(
            catalog_path,
            catalog((function,)),
        )
        index = build_catalog_search_index(
            catalog_path, self.root / "unknown-abi-index.json"
        )
        hypotheses = match_library_constellations(
            graph,
            index,
            self.root / "unknown-abi-hypotheses.json",
            native_backend=EmptyNativeBackend(),
        )
        self.assertEqual(len(hypotheses.hypotheses), 1)
        self.assertEqual(
            hypotheses.hypotheses[0].matches[0].abi_status,
            "incomplete",
        )

    def test_strict_codec_rejects_unknown_fields(self) -> None:
        _machine, graph = self._graph(
            [machine_unit("common", 0x1000, "a" * 64, abi_profile())]
        )
        payload = graph.to_payload()
        payload["unchecked_hint"] = True
        with self.assertRaisesRegex(LibraryAbiError, "unknown fields"):
            TARGET_SIGNATURE_GRAPH_CODEC_V3.decode(payload, "corrupt-graph")


if __name__ == "__main__":
    unittest.main()
