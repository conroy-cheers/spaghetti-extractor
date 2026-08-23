from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.build_objects import _payload_symbol_rvas
from spaghetti_extractor.candidate.build_workflow import (
    build_spx_interpreter_native_candidate,
    prepare_spx_interpreter_native_object_graph,
)
from spaghetti_extractor.candidate.native_build import _link_flags


class NativeModuleBuildContractTests(unittest.TestCase):
    def test_public_build_is_ingress_plan_and_module_name_driven(self) -> None:
        parameters = inspect.signature(
            build_spx_interpreter_native_candidate
        ).parameters
        self.assertIn("native_ingress_plan", parameters)
        self.assertIn("candidate_filename", parameters)
        self.assertNotIn("anchor_manifest", parameters)
        self.assertNotIn("entry_symbol", parameters)

        graph_parameters = inspect.signature(
            prepare_spx_interpreter_native_object_graph
        ).parameters
        self.assertIn("entry_symbol", graph_parameters)
        self.assertIs(graph_parameters["entry_symbol"].default, inspect.Parameter.empty)

    def test_linker_map_is_the_symbol_rva_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            linker_map = Path(temporary) / "module.map"
            linker_map.write_text(
                "                0x00405000                _spx_ingress_0000\n"
                "                0x00406120                _spx_native_tls_index_cell_pointer\n",
                encoding="ascii",
            )
            self.assertEqual(
                _payload_symbol_rvas(linker_map, image_base=0x400000),
                {
                    "spx_ingress_0000": 0x5000,
                    "spx_native_tls_index_cell_pointer": 0x6120,
                },
            )

    def test_linker_entry_is_generic_ingress(self) -> None:
        flags = _link_flags(
            entry_symbol="spx_ingress_0000",
            image_base=0x400000,
            payload_rva=0x5000,
            section_alignment=0x1000,
            file_alignment=0x200,
            linker_map=Path("module.map"),
        )
        self.assertIn("-Wl,--entry,_spx_ingress_0000", flags)
        self.assertFalse(any("spx_payload_entry" in item for item in flags))


if __name__ == "__main__":
    unittest.main()
