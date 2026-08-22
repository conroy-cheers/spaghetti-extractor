from __future__ import annotations

import unittest

from spaghetti_extractor.calls.source import SourceNamingV1, render_call_header
from tests.unit.calls._support import graph


class CallSourceRenderingTests(unittest.TestCase):
    def test_names_are_separate_from_type_identity_and_render_idiomatic_c(self) -> None:
        types = graph(result="pair", parameters=("p_u8", "u32"))
        naming = SourceNamingV1.create(
            type_names={"pair": "pair_result", "p_u8": "byte_pointer", "u32": "byte_count"},
            field_names={("pair", "first"): "begin", ("pair", "second"): "end"},
            value_names={"arg0": "data", "arg1": "length"},
        )
        header = render_call_header(type_graph=types, naming=naming, function_type_id="call", function_name="inspect_bytes")
        self.assertIn("struct pair_result", header)
        self.assertIn("byte_count begin;", header)
        self.assertIn("pair_result inspect_bytes(byte_pointer data, byte_count length);", header)
        self.assertEqual(SourceNamingV1.parse(naming.to_payload()), naming)

    def test_faithful_header_spells_nondefault_calling_convention(self) -> None:
        types = graph(
            convention="stdcall", result="u32", parameters=("p_u8",)
        )
        header = render_call_header(
            type_graph=types,
            naming=SourceNamingV1.create(),
            function_type_id="call",
            function_name="exception_filter",
        )
        self.assertIn("#define SPX_STDCALL __stdcall", header)
        self.assertIn("spx_u32 SPX_STDCALL exception_filter", header)


if __name__ == "__main__":
    unittest.main()
