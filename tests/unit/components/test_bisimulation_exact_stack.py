"""Exact stack access derivation across calls and selected barriers."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from spaghetti_extractor.components.bisimulation_exact import _exact_stack_accesses


class ExactStackAccessTests(unittest.TestCase):
    def test_exact_stack_accesses_are_derived_from_affine_generated_ssa(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "behavioral.c"
            source.write_text(
                "  spx_proof_words[0] = state->esp;\n"
                "  spx_proof_words[1] = 4U;\n"
                "  spx_proof_words[2] = ((spx_proof_words[0]) + "
                "(spx_proof_words[1]));\n"
                "  spx_proof_words[3] = 7U;\n"
                "  spx_write(rt, spx_proof_words[2], 4U, "
                "spx_proof_words[3], &fault);\n"
                "  spx_proof_words[4] = 8U;\n"
                "  spx_proof_words[5] = (spx_proof_words[0]) + "
                "(spx_proof_words[4]);\n"
                "  spx_proof_words[6] = spx_read(rt, spx_proof_words[5], 4U, "
                "&fault);\n",
                encoding="ascii",
            )

            accesses = _exact_stack_accesses(
                exact_files=(source,), service_bindings=()
            )

        self.assertEqual(accesses, [(4, 4), (8, 4)])

    def test_exact_stack_accesses_ignore_calls_beyond_the_selected_barrier(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "behavioral.c"
            source.write_text(
                "spx_unit_00001000:\n"
                "  spx_proof_words[0] = state->esp;\n"
                "  spx_proof_words[1] = 4U;\n"
                "  spx_proof_words[2] = (spx_proof_words[0]) + "
                "(spx_proof_words[1]);\n"
                "  spx_proof_words[3] = spx_read(rt, spx_proof_words[2], 4U, "
                "&fault);\n"
                "spx_unit_00002000:\n"
                "  const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00002000U, 0x00002000U, 0U, 0x00003000U, "
                "0x00002005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n",
                encoding="ascii",
            )

            accesses = _exact_stack_accesses(
                exact_files=(source,),
                service_bindings=(),
                selected_unit_rvas={0x1000},
            )

        self.assertEqual(accesses, [(4, 4)])

    def test_exact_stack_accesses_keep_pre_call_facts_and_transport_admitted_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            affine = Path(temporary) / "affine.c"
            affine.write_text(
                "  spx_proof_words[0] = state->esp;\n"
                "  spx_proof_words[1] = 7U;\n"
                "  spx_write(rt, spx_proof_words[0], 4U, "
                "spx_proof_words[1], &fault);\n",
                encoding="ascii",
            )
            direct = Path(temporary) / "direct.c"
            direct.write_text(
                "const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00001000U, 0x00001000U, 0U, 0x00002000U, "
                "0x00001005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n",
                encoding="ascii",
            )
            self.assertEqual(
                _exact_stack_accesses(
                    exact_files=(affine, direct), service_bindings=()
                ),
                [(0, 4)],
            )
            post_call = Path(temporary) / "post-call.c"
            post_call.write_text(
                "  spx_proof_words[0] = state->esp;\n"
                "    call_input.esp = spx_proof_words[0];\n"
                "  const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00001000U, 0x00001000U, 0U, 0x00002000U, "
                "0x00001005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n"
                "  spx_proof_words[1] = call_output.esp;\n"
                "  spx_proof_words[2] = 4U;\n"
                "  spx_proof_words[3] = ((spx_proof_words[1]) + "
                "(spx_proof_words[2]));\n"
                "  spx_proof_words[4] = spx_read(rt, spx_proof_words[3], "
                "4U, &fault);\n",
                encoding="ascii",
            )
            self.assertEqual(
                _exact_stack_accesses(
                    exact_files=(affine, post_call), service_bindings=()
                ),
                [(0, 4)],
            )
            cleanup_binding = {
                "provider_kind": "external_call",
                "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
                "external_contract_identity_sha256": "b" * 64,
                "service_id": "service",
                "argument_offsets": [0],
                "abi_template": "x86-stdcall",
                "events": [{
                    "instruction_rva": 0x1000,
                    "event_index": 0,
                    "return_rva": 0x1005,
                }],
            }
            self.assertEqual(
                _exact_stack_accesses(
                    exact_files=(affine,),
                    service_bindings=(cleanup_binding,),
                ),
                [(0, 4)],
            )
            external = post_call.read_text().replace("SPX_CALL_INTERNAL_DIRECT", "SPX_CALL_EXTERNAL_IMPORT")
            post_call.write_text(external)
            self.assertEqual(_exact_stack_accesses(exact_files=(affine, post_call),
                service_bindings=(cleanup_binding,)), [(0, 4), (8, 4)])
            # An unbound site must not inherit a different site's cleanup.
            post_call.write_text(external.replace("0x00001000U", "0x00003000U"))
            self.assertEqual(_exact_stack_accesses(exact_files=(affine, post_call),
                service_bindings=(cleanup_binding,)), [(0, 4)])
