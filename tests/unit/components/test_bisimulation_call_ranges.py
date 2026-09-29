"""Hand-defined public buffer effects, without inferred string guarantees."""

import shutil
import copy
import json
from .jq_reader import run as run_jq_reader
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.bisimulation_typed_services import _trusted_adapter_lowering_receipt
from spaghetti_extractor.components.contextual_bisimulation import _trusted_adapter_lowering_used
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_hand_defined_boundaries import shared_buffer_bundle

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text", "nix/jq/strong-contextual-proof.jq")}


def buffer_binding():
    # The real resource helper's ABI and footprint, with fixture identities.
    # This neither selects a production profile nor proves LoadStringA itself.
    return {"service_id": "load_string", "provider_kind": "external_call",
        "abi_template": "pe32-stdcall-v1", "abi_sha256": "a" * 64,
        "argument_offsets": [0, 4, 8, 12],
        "external_effect_contract": {"memory_effect": "argumentRanges", "world_effect": "none",
            "memory_footprints": [{"access": "write", "base_argument": 2, "offset": 0,
                "size": {"kind": "argument", "argument": 3, "scale": 1}, "nullable": False}]},
        "external_contract_identity_sha256": "b" * 64,
        "events": [{"instruction_rva": 100, "event_index": 0, "return_rva": 105}]}


def buffer_authority():
    return MachineObjectAuthorityV2(machine_backend="x86-pe32",
        bindings={"original_pe_sha256": "a" * 64}, rules=[{
            "id": "buffer", "kind": "image", "domain": 1, "object": 2,
            "generation": 17, "extent": 500, "permissions": 3, "lifetime": "image",
            "locator": {"kind": "image_rva", "image_id": "test", "rva": 0x13d20},
            "interior_pointers": True, "evidence_sha256": "a" * 64}]).to_payload()


def buffer_world(binding=None, *, authority=None, max_private_writes=1, **kwargs):
    return _world_source(max_writes=6, max_private_writes=max_private_writes, max_calls=2,
        max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
        service_bindings=[binding or buffer_binding()], private_ranges=(),
        reference_authority=authority or buffer_authority(), image_size=0x20000, **kwargs)


def check_buffer_program(body, *, binding=None, typed=False, world_options=None, extra_source=""):
    selected = binding or buffer_binding()
    spec = _proof_call_specs([selected])[0]["spec_id"]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_cbmc_stdint(root / "stdint.h")
        (root / "state-machine-runtime.h").write_text(exact_runtime_header())
        source = root / "buffer.c"
        source.write_text('#include "state-machine-runtime.h"\n'
            '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' +
            buffer_world(selected, typed_exact_recording=typed, **(world_options or {})) + extra_source + f'''
static void original(uint32_t base, uint32_t size) {{
  spx_stack_input args[4] = {{{{0, 4, 7}}, {{4, 4, 42}}, {{8, 4, base}}, {{12, 4, size}}}};
  spx_call_event event = {{0}};
  event.kind = SPX_CALL_EXTERNAL_IMPORT; event.instruction_rva = 100;
  event.return_rva = 105; event.stack_inputs = args; event.stack_input_count = 4;
  spx_machine_state input = {{0}}, output;
  input.esp = 0x800000;
  spx_runtime runtime = spx_proof_runtime(&spx_exact_world);
  spx_proof_exact_external_call(&runtime, &event, &input, &output);
}}
static void portable(uint32_t base, uint32_t size) {{
  spx_proof_typed_service_begin(&spx_source_world, UINT32_C({spec}));
  spx_proof_typed_service_argument(0, 7);
  spx_proof_typed_service_argument(1, 42);
  spx_proof_typed_service_argument(2, base);
  spx_proof_typed_service_argument(3, size);
  (void)spx_proof_typed_service_result();
  spx_proof_typed_service_finish();
}}
int main(void) {{
  spx_proof_reset_worlds(0x800000U, 256U);
  uint32_t fault = 0;
  uint32_t address = spx_nondet_u32();
''' + body + '\n}\n')
        return run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--json-ui",
            "--trace", "--unwind", "4", "--unwinding-assertions", "--bounds-check",
            "--pointer-check", "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=30)


class CallRangeTests(unittest.TestCase):
    def test_readonly_footprints_cannot_smuggle_writes(self):
        from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
        selected = buffer_binding()
        selected['external_effect_contract']['memory_effect'] = 'readOnly'
        with self.assertRaisesRegex(BisimulationRefinementError, 'readOnly footprints must have read access'):
            buffer_world(selected)

    def test_readonly_malformed_empty_footprints_do_not_erase_the_contract(self):
        from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
        for footprints in (None, {}, '', 0, False):
            selected = buffer_binding()
            selected['external_effect_contract']['memory_effect'] = 'readOnly'
            selected['external_effect_contract']['memory_footprints'] = footprints
            with self.subTest(footprints=footprints):
                with self.assertRaisesRegex(BisimulationRefinementError, 'readOnly requires explicit footprints'):
                    buffer_world(selected)

    def test_explicit_readonly_ranges_require_readable_authority_and_preserve_bytes(self):
        selected = buffer_binding()
        selected['external_effect_contract']['memory_effect'] = 'readOnly'
        selected['external_effect_contract']['memory_footprints'][0]['access'] = 'read'
        result = check_buffer_program('''
  uint8_t before = spx_proof_exact_byte(address);
  original(0x413d20U, 500U);
  portable(0x413d20U, 500U);
  __CPROVER_assert(spx_proof_exact_byte(address) == before &&
      spx_proof_source_byte(address) == before, "read-only call preserves every current byte");
  __CPROVER_assert(spx_exact_world.write_count == 0U && spx_source_world.write_count == 0U,
      "read-only footprint adds no write event");
''', binding=selected)
        self.assertEqual(result['status'], 'satisfied', result)
        for base, size in (('0x413d20U', '501U'), ('0xffffffffU', '2U'), ('0x800000U', '4U')):
            result = check_buffer_program(f'  original({base}, {size});', binding=selected)
            self.assertEqual(result['status'], 'violated', (base, size, result))
            self.assertIn('call-readable-range', result['detail'])

    def test_stdcall_image_write_preserves_cached_private_word_and_updates_public_bytes(self):
        result = check_buffer_program("""
  uint32_t saved = spx_nondet_u32(), replacement = spx_nondet_u32() & 255U;
  spx_proof_exact_write(0, 0x800004U, 4U, saved, &fault);
  original(0x413d20U, 500U);
  __CPROVER_assert(spx_proof_exact_read(0, 0x800004U, 4U, &fault) == saved,
      "service preserves cached private bytes");
  __CPROVER_assume(address >= 0x413d20U && address < 0x413d20U + 500U);
  __CPROVER_assert(spx_proof_exact_byte(address) == __CPROVER_uninterpreted_spx_call_byte(0U, address),
      "service image bytes stay current");
  spx_proof_exact_write(0, 0x800005U, 1U, replacement, &fault);
  __CPROVER_assert(spx_proof_exact_read(0, 0x800004U, 4U, &fault) ==
      ((saved & 0xffff00ffU) | (replacement << 8U)), "partial post-call cache replacement");
""", world_options={'exact_stack_accesses': ((4, 4),), 'max_private_writes': 4})
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_both_readers_require_the_buffer_semantics_implementation(self):
        interface = ProofKernelComponentInterface.parse(_logical_projection(shared_buffer_bundle()))
        selected = {**buffer_binding(), "symbol": "load_string"}
        receipt = _trusted_adapter_lowering_receipt(interface=interface, service_bindings=[selected],
            production_overlay_source="production fixture", proof_overlay_source="proof fixture")
        for omitted in (None, "bisimulation_call_ranges.py", "bisimulation_world.py",
                        "bisimulation_world_memory.py", "bisimulation_call_memory.py",
                        "bisimulation_reference_origins.py", "bisimulation_allocation_lifetime.py"):
            altered = copy.deepcopy(receipt)
            if omitted is not None:
                renderer = altered["renderer"]
                renderer["implementation_files"] = [row for row in renderer["implementation_files"] if row["path"] != omitted]
                renderer["implementation_closure_sha256"] = canonical_sha256_v3(renderer["implementation_files"])
                altered["receipt_sha256"] = canonical_sha256_v3({k:v for k,v in altered.items() if k != "receipt_sha256"})
            model = {"interface_sha256": interface.sha256,
                "machine_overlay_sha256": altered["production_overlay_sha256"],
                "proof_overlay_sha256": altered["proof_overlay_sha256"], "trusted_adapter_lowering": altered}
            if omitted is None:
                self.assertTrue(_trusted_adapter_lowering_used(model))
            else:
                with self.assertRaisesRegex(ValueError, "renderer closure"):
                    _trusted_adapter_lowering_used(model)
            checked = run_jq_reader([shutil.which("jq"), "-L", str(Path(__file__).parents[3]/"nix/jq"),
                'include "strong-contextual-proof"; spx_typed_adapter_renderer_inventory'],
                input=json.dumps(altered), text=True, capture_output=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(json.loads(checked.stdout), omitted is None)

    def test_unknown_footprints_and_missing_authority_fail_closed(self):
        for mutation in ("missing", "size", "argument", "offset", "condition", "lifetime"):
            selected = buffer_binding()
            payload = selected["external_effect_contract"]
            row = payload["memory_footprints"][0]
            if mutation == "missing": payload.pop("memory_footprints")
            elif mutation == "size": row["size"]["kind"] = "bounded_terminated"
            elif mutation == "argument": row["base_argument"] = 9
            elif mutation == "offset": row["offset"] = -1
            elif mutation == "condition": row["success_only"] = True
            else: payload["world_effect"] = "dynamicRanges"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                buffer_world(selected)
        with self.assertRaisesRegex(ValueError, "canonical object authority"):
            _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                max_shadow_bytes=1, max_nul_views=1, service_bindings=[buffer_binding()], private_ranges=())

    def test_buffer_extent_does_not_expand_the_model(self):
        small, large = buffer_binding(), buffer_binding()
        small["external_effect_contract"]["memory_footprints"][0]["size"] = {"kind": "fixed", "bytes": 5}
        large["external_effect_contract"]["memory_footprints"][0]["size"] = {"kind": "fixed", "bytes": 500}
        self.assertEqual(buffer_world(small).count("\n"), buffer_world(large).count("\n"))
        self.assertLess(abs(len(buffer_world(small)) - len(buffer_world(large))), 1000)
        self.assertIn("#define SPX_PROOF_MAX_WRITES UINT32_C(8)", buffer_world(large))

    def test_paired_buffer_alias_frame_and_later_write_order(self):
        result = check_buffer_program('''
  original(0x413d20U, 500U);
  spx_proof_exact_write(0, 0x413d21U, 1, 93, &fault);
  original(0x413d22U, 498U);
  portable(0x413d20U, 500U);
  spx_proof_source_write(0, 0x413d21U, 1, 93, &fault);
  portable(0x413d22U, 498U);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "paired buffer memory");
  __CPROVER_assert(spx_proof_source_byte(0x413d21U) == 93U, "earlier alias write outside second span");
  if (address >= 0x413d22U && address < 0x413f14U)
    __CPROVER_assert(spx_proof_source_byte(address) ==
        __CPROVER_uninterpreted_spx_call_byte(1, address), "later call through old alias");
  if (address < 0x413d20U || address >= 0x413f14U)
    __CPROVER_assert(spx_proof_source_byte(address) == spx_proof_initial_byte(address), "outside frame preserved");
  __CPROVER_assert(spx_source_world.write_count == 3, "one event per footprint");
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_no_zero_termination_or_unchanged_failure_bytes_are_assumed(self):
        for claim in ("spx_proof_source_byte(0x413f13U) == 0",
                      "spx_proof_source_byte(0x413d20U) == spx_proof_initial_byte(0x413d20U)"):
            result = check_buffer_program('''
  original(0x413d20U, 500U);
  __CPROVER_assume(spx_exact_world.calls[0].response_eax == 0U);
  portable(0x413d20U, 500U);
  __CPROVER_assert(''' + claim + ''', "invented service guarantee");''')
            self.assertEqual(result["status"], "violated", result)
            self.assertIn("invented service guarantee", result["detail"])

    def test_range_overflow_and_mismatched_replay_are_rejected(self):
        for body, diagnostic in (
            ("original(0x413d20U, 501U);", "buffer-authority"),
            ("original(0xfffffffeU, 500U);", "buffer-authority"),
            ("original(0x413d20U, 500U); portable(0x413d21U, 499U);", "buffer-typed-arguments")):
            result = check_buffer_program(body)
            self.assertEqual(result["status"], "violated", result)
            self.assertIn(diagnostic, result["detail"])

    def test_overlapping_footprints_share_one_final_byte_function(self):
        selected = buffer_binding()
        selected["external_effect_contract"]["memory_footprints"].append({
            "access": "write", "base_argument": 2, "offset": 100,
            "size": {"kind": "fixed", "bytes": 250}, "nullable": False})
        result = check_buffer_program('''
  original(0x413d20U, 500U); portable(0x413d20U, 500U);
  if (address >= 0x413d20U && address < 0x413f14U)
    __CPROVER_assert(spx_proof_source_byte(address) ==
        __CPROVER_uninterpreted_spx_call_byte(0, address), "overlapping footprint alias");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "overlapping paired memory");
''', binding=selected)
        self.assertEqual(result["status"], "satisfied", result)

    def test_changed_input_bytes_cannot_be_hidden_by_a_service_overwrite(self):
        result = check_buffer_program('''
  original(0x413d20U, 500U);
  spx_proof_source_write(0, 0x413d20U, 1U, 0U, &fault);
  portable(0x413d20U, 500U);
''')
        self.assertEqual(result["status"], "violated", result)
        self.assertIn("buffer-typed-arguments", result["detail"])

    def test_typed_recording_applies_writes_once_before_replay(self):
        spec = _proof_call_specs([buffer_binding()])[0]["spec_id"]
        result = check_buffer_program(f'''
  spx_proof_typed_service_begin(&spx_exact_world, UINT32_C({spec}));
  spx_proof_typed_service_argument(0, 7);
  spx_proof_typed_service_argument(1, 42);
  spx_proof_typed_service_argument(2, 0x413d20U);
  spx_proof_typed_service_argument(3, 500U);
  (void)spx_proof_typed_service_result();
  spx_proof_typed_service_finish();
  portable(0x413d20U, 500U);
  __CPROVER_assert(spx_exact_world.write_count == 1U && spx_source_world.write_count == 1U,
      "typed call applies one range");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "typed buffer replay");
''', typed=True)
        self.assertEqual(result["status"], "satisfied", result)

    def test_service_writes_obey_the_enclosing_physical_frame(self):
        result = check_buffer_program('''
  __CPROVER_spx_exact_frame_active = 1U;
  original(0x413d20U, 500U);
''', world_options={"probe_empty_frame": True})
        self.assertEqual(result["status"], "violated", result)
        self.assertIn("exact-empty-memory-frame", result["detail"])

    def test_permissions_and_image_lifetime_are_not_inferred_from_addresses(self):
        payload = buffer_authority()
        # Rebuild the canonical authority after each deliberate policy change.
        for mutation in ("permissions", "lifetime", "interior"):
            row = dict(payload["rules"][0])
            if mutation == "permissions": row["permissions"] = 1
            elif mutation == "lifetime": row["lifetime"] = "allocation"
            else: row["interior_pointers"] = False
            authority = MachineObjectAuthorityV2(machine_backend="x86-pe32",
                bindings=payload["bindings"], rules=[row]).to_payload()
            if mutation == "lifetime":
                with self.assertRaisesRegex(ValueError, "fixed image objects"):
                    buffer_world(authority=authority)
            else:
                result = check_buffer_program("original(0x413d21U, 499U);",
                    world_options={"authority": authority})
                self.assertEqual(result["status"], "violated", result)
                self.assertIn("buffer-authority", result["detail"])


if __name__ == "__main__":
    unittest.main()
