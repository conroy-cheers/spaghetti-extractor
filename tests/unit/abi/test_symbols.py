from __future__ import annotations

import unittest

from spaghetti_extractor.abi.symbols import infer_pe32_symbol_abi


class SymbolAbiTests(unittest.TestCase):
    def test_cdecl_identifier_may_begin_with_underscores(self) -> None:
        result = infer_pe32_symbol_abi(
            subject_id="function:mingw-printf",
            subject_kind="library_member",
            symbols=("___mingw_printf",),
            decoration_model="pe32-coff-gnu-v1",
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.undecorated_symbol, "__mingw_printf")
        facts = {row.field: row for row in result.facts}
        self.assertEqual(facts["calling_convention"].values, ("cdecl",))
        self.assertEqual(
            facts["preserved_state"].values,
            (["ebp", "ebx", "edi", "esi"],),
        )

    def test_import_address_symbol_is_not_a_function_abi(self) -> None:
        result = infer_pe32_symbol_abi(
            subject_id="slot:printf",
            subject_kind="library_member",
            symbols=("__imp__printf",),
            decoration_model="pe32-coff-gnu-v1",
        )

        self.assertIsNone(result)

    def test_compiler_local_clone_name_does_not_authorize_public_abi(self) -> None:
        result = infer_pe32_symbol_abi(
            subject_id="function:local-clone",
            subject_kind="library_member",
            symbols=("___mingwthr_run_key_dtors.part.0",),
            decoration_model="pe32-coff-gnu-v1",
        )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
