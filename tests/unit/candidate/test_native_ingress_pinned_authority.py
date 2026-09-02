from __future__ import annotations

import unittest

from spaghetti_extractor.candidate.outcomes import (
    CheckedSEHProtocolV1,
    PinnedCodeLayoutAuthorityV2,
)
from spaghetti_extractor.errors import ToolkitInputError


class PinnedCodeLayoutAuthorityTests(unittest.TestCase):
    def test_numeric_exception_addresses_require_content_bound_pinned_authority(self) -> None:
        authority = PinnedCodeLayoutAuthorityV2.create(
            original_module_sha256="1" * 64,
            resolved_external_environment_sha256="4" * 64,
            required_image_base=0x400000,
            rva_bindings=[
                {"source_rva": 0x1010, "candidate_rva": 0x1010},
                {"source_rva": 0x1120, "candidate_rva": 0x1120},
            ],
            observed_fields=["Eip", "ExceptionAddress"],
        )
        self.assertEqual(
            PinnedCodeLayoutAuthorityV2.parse(authority.to_payload()), authority
        )
        protocol = CheckedSEHProtocolV1.create(
            transition_id="exception:divide", transition_sha256="a" * 64,
            exception={
                "code": 0xC0000094, "flags_mask": 0, "flags_value": 0,
                "parameter_count": 0, "continuable": True,
                "access_violation": None,
            },
            projections={
                "registers": ["eax"], "flags": ["eflags"], "x87": [],
                "stack": ["esp"], "exception_record": ["ExceptionAddress"],
                "context": ["Eip"],
            },
            handler_unit_id="unit:handler", handler_rva=0x1100,
            resumption_unit_id="unit:resume", resumption_rva=0x1120,
            unwind_effect_ids=[], escape_disposition="escape_callable_root",
            gateway_handler_symbol="spx_seh_gateway_divide",
            portals=[{"source_rva": 0x1010, "candidate_symbol": "spx_exception_1010"}],
            observed_address_fields=["Eip", "ExceptionAddress"],
            address_policy="pinned_original_layout",
            pinned_layout_authority_id=authority.authority_id,
        )
        self.assertEqual(protocol.status, "complete")
        self.assertEqual(
            CheckedSEHProtocolV1.parse(protocol.to_payload()), protocol
        )

        with self.assertRaisesRegex(
            ToolkitInputError, "exact source/candidate RVA equality"
        ):
            PinnedCodeLayoutAuthorityV2.create(
                original_module_sha256="1" * 64,
                resolved_external_environment_sha256="4" * 64,
                required_image_base=0x400000,
                rva_bindings=[{"source_rva": 0x1010, "candidate_rva": 0x2010}],
                observed_fields=["Eip"],
            )


if __name__ == "__main__":
    unittest.main()
