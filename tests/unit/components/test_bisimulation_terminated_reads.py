"""Hand-defined string result boundaries checked against current memory."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from spaghetti_extractor.components.contextual_bisimulation import _trusted_adapter_lowering_used
from spaghetti_extractor.components.bisimulation_typed_services import _trusted_adapter_lowering_receipt
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from . import test_bisimulation_service_effects as effects_fixture
from .test_bisimulation_reference_authority import authority_payload
from spaghetti_extractor.components.bisimulation_view_extent import shared_view_initialization, shared_view_admission_source
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json", "nix/jq/strong-contextual-proof.jq")}


def binding():
    return effects_fixture.binding({"memory_effect": "readOnly", "world_effect": "none",
        "disposition": "returns", "memory_footprints": [],
        "result_register_relations": [{"register": "eax", "relation": "terminated_byte_offset",
                                       "base_argument": 0, "nullable": False}]})


def check_program(body, *, typed_exact=False, selected=None, before="", world_options=None, text_address=4096,
                  enrollment=None, property_ids=()):
    selected = selected or binding()
    spec = _proof_call_specs([selected])[0]["spec_id"]
    world = _world_source(max_writes=8, max_private_writes=1, max_calls=2, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, reference_origin_capacity=1,
        service_bindings=[selected], private_ranges=(), typed_exact_recording=typed_exact, **(world_options or {}))
    default_enrollment = f'''
  spx_machine_reference_v1 exact_ref, source_ref;
  __CPROVER_assert(spx_proof_resolve_reference(&spx_exact_world, {text_address}U, 16U, 1U, 0, 0U, 0U,
      &exact_ref) == SPX_BOUNDARY_OK, "fixture exact origin");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, {text_address}U, 16U, 1U, 0, 0U, 0U,
      &source_ref) == SPX_BOUNDARY_OK, "fixture source origin");'''
    admission = ('' if enrollment is None else '\nconst uint32_t spx_proof_private_high_offset = 256U;\n' +
        shared_view_admission_source(private_ranges=(), image_base=0x400000, image_size=65536))
    terminator = (f'''spx_proof_exact_write(0, {text_address + 15}U, 1U, 0U, &fault);
  spx_proof_source_write(0, {text_address + 15}U, 1U, 0U, &fault);''' if enrollment is None else
        f'''__CPROVER_assume(spx_proof_exact_byte({text_address + 15}U) == 0U &&
      spx_proof_source_byte({text_address + 15}U) == 0U);''')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_cbmc_stdint(root / "stdint.h")
        (root / "state-machine-runtime.h").write_text(exact_runtime_header())
        source = root / "terminated.c"
        source.write_text('#include "state-machine-runtime.h"\n'
            '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + world + admission + f'''
static uint32_t machine(spx_proof_world *world, uint32_t base) {{
  spx_stack_input argument = {{0, 4, base}};
  spx_call_event event = {{.kind = SPX_CALL_EXTERNAL_IMPORT,
    .instruction_rva = 100, .return_rva = 105, .stack_inputs = &argument, .stack_input_count = 1}};
  spx_machine_state input = {{.esp = 0x800000U}}, output;
  if (world == &spx_exact_world) spx_proof_exact_external_call(0, &event, &input, &output);
  else spx_proof_source_external_call(0, &event, &input, &output);
  return output.eax;
}}
static uint32_t typed(spx_proof_world *world, uint32_t base) {{
  spx_proof_typed_service_begin(world, {spec}U);
  spx_proof_typed_service_argument(0, base);
  uint32_t result = spx_proof_typed_service_result();
  spx_proof_typed_service_finish(); return result;
}}
int main(void) {{
  spx_proof_reset_worlds(0x800000U, 256U);
  uint32_t fault = 0U;
  {before}
  {terminator}
  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent({text_address}U) == 16U);
  spx_proof_register_nul_view({text_address}U, 16U);
''' + (default_enrollment if enrollment is None else enrollment) + body + '\n}\n')
        return run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--json-ui", "--trace",
            "--unwind", "3", "--unwinding-assertions", "--bounds-check", "--pointer-check",
            "--signed-overflow-check", "--sat-solver", "cadical",
            *(argument for identity in property_ids for argument in ("--property", identity)),
            *reference_authority_unwind_arguments((world_options or {}).get('reference_authority'))], timeout_seconds=45)


class TerminatedReadTests(unittest.TestCase):
    def test_recording_span_proof_does_not_discharge_replay_span(self):
        # An issued exact origin says nothing about the replay world's origin
        # registry. Separate query sites must retain the replay counterexample.
        for replay in ('machine', 'typed'):
            body = f'''
  machine(&spx_exact_world, 4096U);
  spx_source_origins.count = 0U;
  {replay}(&spx_source_world, 4096U);
'''
            with self.subTest(replay=replay):
                recording = check_program(body, property_ids=(
                    'spx_proof_apply_terminated_read.assertion.2',))
                self.assertEqual(recording['status'], 'satisfied', recording)
                replay_result = check_program(body, property_ids=(
                    'spx_proof_apply_terminated_read.assertion.3',))
                self.assertEqual(replay_result['status'], 'violated', replay_result)
                complete = check_program(body)
                self.assertEqual(complete['status'], 'violated', complete)
                for result in (replay_result, complete):
                    self.assertEqual(result['detail'], 'spx-bisimulation-terminated-read-current-span')

    def test_generated_paired_origin_enrollment_preserves_aliases_and_current_memory(self):
        address = 0x401000
        parameters = [SimpleNamespace(identity=name, type_id='text') for name in ('left', 'right')]
        interface = SimpleNamespace(
            operation_index=lambda: {'run': SimpleNamespace(parameters=parameters)},
            type_index=lambda: {'text': SimpleNamespace(nullable=False, nul_terminated=True, extent_kind='nul_terminated')})
        projection = {'kind': 'view', 'base': {'kind': 'register', 'register': 'esi', 'width': 32, 'at': 'entry'},
                      'requested_extent': {'kind': 'constant', 'value': 1, 'width': 32},
                      'extent': {'kind': 'origin_remainder'}}
        initialization = '\n'.join(shared_view_initialization(interface=interface, operation_id='run',
            operation_projection={'parameters': [{'id': p.identity, 'projection': projection} for p in parameters]},
            sync=None, proof_function='check',
            native_specs={p.identity: {'permissions': 1, 'selector': '"image-buffer"'} for p in parameters}))
        setup = f'''spx_machine_state initial_state = {{.esi = {address}U, .esp = 0x800000U}};
  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);
  uint32_t original_byte = spx_proof_exact_byte({address + 5}U);
'''
        options = {'reference_authority': authority_payload(), 'image_size': 65536, 'max_exposed_stack_views': 2}
        for mutation, status in (('', 'satisfied'), ('spx_exact_origins.count = 0U;', 'violated'),
                (f'spx_proof_exact_write(0, {address + 15}U, 1U, 9U, &fault);', 'violated')):
            with self.subTest(mutation=mutation):
                result = check_program(f'''
  __CPROVER_assert(spx_exact_origins.count == 1U && spx_source_origins.count == 1U,
      "overlapping native views share one issued origin in each world");
  __CPROVER_assert(spx_proof_exact_byte({address + 5}U) == original_byte &&
      spx_proof_source_byte({address + 5}U) == original_byte, "arbitrary admitted contents survive enrollment");
  {mutation}
  uint32_t length = machine(&spx_exact_world, {address + 4}U);
  __CPROVER_assert(length < 12U && typed(&spx_source_world, {address + 4}U) == length,
      "resumed service uses the current interior span");''', enrollment=setup + initialization,
                    world_options=options, text_address=address)
                self.assertEqual(result['status'], status, result.get('detail'))
                if mutation:
                    self.assertIn('terminated-read-current-span', result['detail'])
        for field in ('domain', 'object', 'generation', 'offset', 'extent', 'permissions'):
            with self.subTest(incoherent_field=field):
                changed = initialization.replace('  __CPROVER_assert(',
                    f'  __CPROVER_spx_exact_view_reference_0.{field} ^= 1U;\n  __CPROVER_assert(', 1)
                result = check_program('', enrollment=setup + changed, world_options=options,
                                       text_address=address)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertEqual(result['detail'], 'spx-bisimulation-shared-view-inputs:run:check')
        # Equal enrolled references cannot hide later disagreement through an alias.
        result = check_program(f'''
  spx_proof_exact_write(0, {address + 5}U, 1U, 7U, &fault);
  spx_proof_source_write(0, {address + 5}U, 1U, 8U, &fault);
  __CPROVER_assert(spx_proof_exact_byte({address + 5}U) == 7U &&
      spx_proof_source_byte({address + 5}U) == 8U, "distinct current bytes remain visible");
  machine(&spx_exact_world, {address + 4}U);
  typed(&spx_source_world, {address + 4}U);''',
            enrollment=setup + initialization,
            world_options=options, text_address=address)
        self.assertEqual(result['status'], 'violated', result)
        self.assertRegex(result['detail'], 'call-public-memory|terminated-read-arguments')

    def test_current_span_bounds_result_and_allocation_without_scanning_a_string_body(self):
        for original, portable, typed_exact in (("machine", "machine", False),
                                               ("machine", "typed", False), ("typed", "typed", True)):
            with self.subTest(original=original, portable=portable):
                result = check_program(f'''
  uint32_t n = {original}(&spx_exact_world, 4100U);
  __CPROVER_assert(n < 12U && n + 1U != 0U, "length plus terminator fits allocation");
  __CPROVER_assert(spx_proof_exact_byte(4100U + n) == 0U, "result points to current zero");
  spx_proof_exact_write(0, 4111U, 1U, 9U, &fault);
  uint32_t other = {portable}(&spx_source_world, 4100U);
  __CPROVER_assert(n == other, "paired string response");
  spx_proof_source_write(0, 4111U, 1U, 9U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "readonly frame and later alias write");
''', typed_exact=typed_exact)
                self.assertEqual(result["status"], "satisfied", result)

    def test_dead_unreadable_missing_or_unterminated_origins_fail_at_call(self):
        for mutation in ("spx_exact_origins.count = 0U;", "spx_exact_origins.entries[0].permissions = 2U;",
                         "spx_exact_origins.entries[0].extent = 8U;",
                         "spx_proof_exact_write(0, 4111U, 1U, 9U, &fault);",
                         "spx_proof_release_allocation(&spx_exact_world, 4096U, 7U, 0U, 1U);"):
            with self.subTest(mutation=mutation):
                result = check_program(mutation + "\n  machine(&spx_exact_world, 4096U);", before='''
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 4096U, 16U, 7U, 0U, 0U) == SPX_BOUNDARY_OK,
      "fixture exact birth");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 7U, 0U, 0U) == SPX_BOUNDARY_OK,
      "fixture source birth");''')
                self.assertEqual(result["status"], "violated", result)
                self.assertIn("terminated-read-current-span", result["detail"])

    def test_matching_pointers_and_later_repair_do_not_hide_changed_input(self):
        for replay in ("machine", "typed"):
            result = check_program(f'''
  spx_proof_exact_write(0, 4101U, 1U, 7U, &fault);
  machine(&spx_exact_world, 4100U);
  spx_proof_source_write(0, 4101U, 1U, 8U, &fault);
  {replay}(&spx_source_world, 4100U);
  spx_proof_source_write(0, 4101U, 1U, 7U, &fault);
''')
            self.assertEqual(result["status"], "violated", result)
            self.assertRegex(result["detail"], "call-public-memory|terminated-read-arguments")

    def test_contract_does_not_invent_first_zero_or_repeatability(self):
        for claim in ("first == 0U", "first == second"):
            result = check_program('''
  spx_proof_exact_write(0, 4096U, 1U, 0U, &fault);
  uint32_t first = machine(&spx_exact_world, 4096U);
  uint32_t second = machine(&spx_exact_world, 4096U);
  __CPROVER_assert(''' + claim + ''', "unproved stronger string contract");''')
            self.assertEqual(result["status"], "violated", result)
            self.assertIn("unproved stronger string contract", result["detail"])

    def test_null_policy_and_unsupported_effects_are_explicit(self):
        selected = binding()
        result = check_program("machine(&spx_exact_world, 0U);")
        self.assertEqual(result["status"], "violated", result)
        selected["external_effect_contract"]["result_register_relations"][0]["nullable"] = True
        result = check_program('''
  uint32_t n = machine(&spx_exact_world, 0U);
  __CPROVER_assert(n == 0U && typed(&spx_source_world, 0U) == 0U, "explicit null result");''', selected=selected)
        self.assertEqual(result["status"], "satisfied", result)
        for change in ({"memory_effect": "none"}, {"world_effect": "opaqueResources"},
                       {"disposition": "noreturn"}, {"memory_footprints": [{}]}):
            invalid = binding(); invalid["external_effect_contract"].update(change)
            with self.assertRaisesRegex(ValueError, "read-only"):
                _proof_call_specs([invalid])

    def test_result_constraint_does_not_authorize_a_restricted_read_footprint(self):
        for active, address, status in ((0, 4096, "satisfied"), (1, 4096, "violated"), (1, 0x410000, "violated")):
            result = check_program(f'''
  __CPROVER_spx_image_private_access_active = {active}U;
  machine(&spx_exact_world, {address}U);
''', world_options={"probe_image_frame": True, "image_size": 0x20000}, text_address=address)
            self.assertEqual(result["status"], status, result)
            if active:
                self.assertIn("image-private-access-frame", result["detail"])

    def test_both_readers_bind_result_semantics_and_reject_weakened_contracts(self):
        fixture = effects_fixture.preconditions_fixture.ServicePreconditionTests()
        fixture.setUp()
        selected = {**fixture.binding, "abi_sha256": "a" * 64,
                    "external_effect_contract": binding()["external_effect_contract"]}
        receipt = _trusted_adapter_lowering_receipt(interface=fixture.interface, service_bindings=[selected],
            production_overlay_source="fixture", proof_overlay_source="proof fixture")
        program = Path("nix/jq/strong-contextual-proof.jq").read_text()
        for omitted in (None, "terminated_reads.py", "bisimulation_terminated_reads.py", "bisimulation_call_memory.py",
                        "bisimulation_image_frame.py"):
            model = {"interface_sha256": fixture.interface.sha256,
                "machine_overlay_sha256": receipt["production_overlay_sha256"],
                "proof_overlay_sha256": receipt["proof_overlay_sha256"], "trusted_adapter_lowering": copy.deepcopy(receipt)}
            altered = model["trusted_adapter_lowering"]
            if omitted:
                renderer = altered["renderer"]
                renderer["implementation_files"] = [row for row in renderer["implementation_files"] if row["path"] != omitted]
                renderer["implementation_closure_sha256"] = canonical_sha256_v3(renderer["implementation_files"])
                effects_fixture.rehash_model(model)
                with self.assertRaisesRegex(ValueError, "renderer closure"):
                    _trusted_adapter_lowering_used(model)
            else:
                self.assertTrue(_trusted_adapter_lowering_used(model))
            checked = subprocess.run([shutil.which("jq"), program + "\nspx_typed_adapter_renderer_inventory"],
                input=json.dumps(altered), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(checked.stdout), omitted is None)
        for mutation in ({}, {"nullable": 0}, {"base_argument": True}, {"base_argument": 2},
                         {"register": "edx"}, {"first_zero": True}):
            payload = copy.deepcopy(selected["external_effect_contract"])
            payload["result_register_relations"][0].update(mutation)
            invalid = {**selected, "external_effect_contract": payload}
            if mutation:
                with self.assertRaises(ValueError): _proof_call_specs([invalid])
            else:
                _proof_call_specs([invalid])
            checked = subprocess.run([shutil.which("jq"), program + "\nspx_terminated_read_effect(2)"],
                input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(checked.stdout), not mutation)
        for change in ({"memory_footprints": None}, {"out_pointer_relations": None},
                       {"out_interface_relations": None}, {"effect_model": {}},
                       {"world_effect_argument": 0}, {"callback_effect": "explicit"}):
            payload = {**selected["external_effect_contract"], **change}
            with self.assertRaises(ValueError):
                _proof_call_specs([{**selected, "external_effect_contract": payload}])
            checked = subprocess.run([shutil.which("jq"), program + "\nspx_terminated_read_effect(2)"],
                input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=10)
            self.assertFalse(json.loads(checked.stdout))

    def test_raw_indirect_oracle_does_not_authorize_an_unchecked_typed_target(self):
        fixture = effects_fixture.preconditions_fixture.ServicePreconditionTests()
        fixture.setUp()
        captured = {"kind": "register", "register": "esi", "width": 32, "at": "entry"}
        selected = {**fixture.binding, "abi_sha256": "a" * 64, "captured_target_projection": captured}
        self.assertTrue(_proof_call_specs([selected])[0]["compare_target"])
        from spaghetti_extractor.components.bisimulation_typed_services import build_typed_proof_service_thunk_renderer
        with self.assertRaisesRegex(ValueError, "captured_target_unsupported"):
            build_typed_proof_service_thunk_renderer(interface=fixture.interface, service_bindings=[selected])
        with self.assertRaisesRegex(ValueError, "captured_target_unsupported"):
            _trusted_adapter_lowering_receipt(interface=fixture.interface, service_bindings=[selected],
                production_overlay_source="fixture", proof_overlay_source="proof fixture")
        model = effects_fixture.typed_model()
        adapter = model["trusted_adapter_lowering"]["adapter_plan"][0]
        adapter["checked_binding"]["captured_target_projection"] = captured
        adapter["proof_call_specs"] = _proof_call_specs([adapter["checked_binding"]])
        effects_fixture.rehash_model(model)
        with self.assertRaisesRegex(ValueError, "captured_target_unsupported"):
            _trusted_adapter_lowering_used(model)
        program = Path("nix/jq/strong-contextual-proof.jq").read_text()
        checked = subprocess.run([shutil.which("jq"), program + "\nspx_declared_external_range_effects({})"],
            input=json.dumps(adapter), text=True, capture_output=True, check=True, timeout=10)
        self.assertFalse(json.loads(checked.stdout))
