"""Pinned numeric-address realization across ingress, link, and deployment."""

from __future__ import annotations

import unittest

from tests.unit.candidate.native_ingress_support import (
    native_ingress_plan as _native_ingress_plan,
)

from spaghetti_extractor.native_realization.build import _pinned_layout_blockers
from spaghetti_extractor.candidate.native_ingress_runtime import (
    _seh_projection_masks,
    render_native_ingress_assembly,
    render_native_ingress_source,
)
from spaghetti_extractor.candidate.outcomes import PinnedCodeLayoutAuthorityV2


class NativeIngressPinnedLayoutTests(unittest.TestCase):
    def test_pinned_layout_is_authorized_only_by_the_observed_link(self) -> None:
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
        plan = {
            "pinned_code_layout_authorities": [authority.to_payload()],
            "seh_protocols": [{
                "pinned_layout_authority_id": authority.authority_id,
                "observed_address_fields": ["Eip", "ExceptionAddress"],
                "resumption_rva": 0x1120,
                "portals": [{
                    "source_rva": 0x1010,
                    "candidate_symbol": "spx_exception_1010",
                }],
            }],
        }
        original = {
            "identity": {"pe_sha256": "1" * 64},
            "loader": {"preferred_base": 0x400000},
        }
        candidate = {"loader": {"preferred_base": 0x400000}}
        blockers = _pinned_layout_blockers(
            ingress=plan,
            original_interface=original,
            candidate_interface=candidate,
            resolved_environment_sha256="4" * 64,
        )
        self.assertEqual(blockers, [])

        incomplete_authority = PinnedCodeLayoutAuthorityV2.create(
            original_module_sha256="1" * 64,
            resolved_external_environment_sha256="4" * 64,
            required_image_base=0x400000,
            rva_bindings=[
                {"source_rva": 0x1010, "candidate_rva": 0x1010},
            ],
            observed_fields=["Eip", "ExceptionAddress"],
        )
        incomplete_plan = {
            **plan,
            "pinned_code_layout_authorities": [
                incomplete_authority.to_payload()
            ],
            "seh_protocols": [{
                **plan["seh_protocols"][0],
                "pinned_layout_authority_id": incomplete_authority.authority_id,
            }],
        }
        missing_continuation = _pinned_layout_blockers(
            ingress=incomplete_plan,
            original_interface=original,
            candidate_interface=candidate,
            resolved_environment_sha256="4" * 64,
        )
        self.assertEqual(
            {row["code"] for row in missing_continuation},
            {"pinned_layout_rva_binding_missing"},
        )
        masks = _seh_projection_masks({
            "handler_rva": 0x1100,
            "resumption_rva": 0x1120,
            "address_policy": "pinned_original_layout",
            "pinned_layout_authority_id": authority.authority_id,
            "projections": {
                "registers": [],
                "flags": [],
                "stack": [],
                "context": ["Eip"],
                "x87": [],
                "exception_record": ["ExceptionAddress"],
            },
        })
        self.assertEqual(masks[4:], (0x008, 0x400))
        source = render_native_ingress_source(_native_ingress_plan(0x1010))
        self.assertIn(
            "if (context[46] == source_address)\n"
            "      *continuation_rva = seh->source_rva;",
            source,
        )
        self.assertIn(
            "else if (context[46] == resumption_address)\n"
            "      *continuation_rva = seh->resumption_rva;",
            source,
        )
        self.assertIn(
            "spx_native_runtime_run_at_rva(\n"
            "        continuation_rva, frame->output, frame->output)",
            source,
        )
        pinned_plan = _native_ingress_plan(0x1010)
        pinned_plan["seh_protocols"] = [{
            "id": "pinned-eip",
            "exception": {
                "code": 0xC0000094,
                "flags_mask": 0,
                "flags_value": 0,
                "parameter_count": 0,
                "continuable": True,
                "access_violation": None,
            },
            "projections": {
                "registers": [],
                "flags": [],
                "stack": [],
                "context": ["Eip"],
                "x87": [],
                "exception_record": ["ExceptionAddress"],
            },
            "escape_disposition": "continue_search",
            "handler_rva": 0x1100,
            "resumption_rva": 0x1120,
            "unwind_effect_ids": [],
            "gateway_handler_symbol": "spx_seh_gateway_checked",
            "address_policy": "pinned_original_layout",
            "pinned_layout_authority_id": authority.authority_id,
            "portals": [{
                "source_rva": 0x1010,
                "candidate_symbol": "spx_exception_1010",
            }],
        }]
        for ingress in pinned_plan["ingresses"]:
            ingress["bridge_equivalence_class"] = "pinned-fixture-frame"
        assembly = render_native_ingress_assembly(pinned_plan)
        self.assertIn(
            ".globl _spx_exception_continuation_00001120",
            assembly,
        )
        pinned_source = render_native_ingress_source(pinned_plan)
        self.assertNotIn(
            "extern const uint8_t spx_exception_continuation_00001120[];",
            pinned_source,
        )
        self.assertIn("spx_native_module_base_pointer", pinned_source)
        self.assertIn("spx_native_checked_exception_address", pinned_source)


if __name__ == "__main__":
    unittest.main()
