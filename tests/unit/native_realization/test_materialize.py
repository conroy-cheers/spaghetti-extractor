from __future__ import annotations

import unittest

from spaghetti_extractor.native_realization.materialize import (
    NativeMaterializationError,
    _required_symbols_for_source,
)


class NativeMaterializationTests(unittest.TestCase):
    def test_native_ingress_symbols_follow_checked_seh_inventory(self) -> None:
        without_seh = _required_symbols_for_source(
            "native-ingress-bridges.S", {"seh_protocols": []}
        )
        self.assertEqual(
            without_seh,
            (
                "spx_native_exception_recovery",
                "spx_native_raise_exception_gateway",
            ),
        )
        with_seh = _required_symbols_for_source(
            "native-ingress-bridges.S",
            {"seh_protocols": [{
                "gateway_handler_symbol": "spx_native_seh_gateway",
            }]},
        )
        self.assertEqual(
            with_seh,
            (
                "spx_native_exception_recovery",
                "spx_native_raise_exception_gateway",
                "spx_native_seh_gateway",
            ),
        )

        with self.assertRaisesRegex(
            NativeMaterializationError, "SEH protocol omits"
        ):
            _required_symbols_for_source(
                "native-ingress-bridges.S", {"seh_protocols": [{}]}
            )

if __name__ == "__main__":
    unittest.main()
