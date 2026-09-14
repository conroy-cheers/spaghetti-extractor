"""Normal proof runtime consumes canonical native object-authority rules."""

import shutil
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
from spaghetti_extractor.components.bisimulation_issued_access import issued_access_assurance
from spaghetti_extractor.components.bisimulation_world_memory import allocation_byte_projection_assurance
from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def authority_payload(*, interior=True, permissions=3, locator="image_rva", ambiguous=False,
                      backend="x86-pe32"):
    rule = {"id": "image-buffer", "kind": "image", "domain": 0x100000003,
            "object": 0x200000037, "generation": 17, "extent": 16, "permissions": permissions,
            "lifetime": "image", "locator": {"kind": locator, "image_id": "test", "rva": 4096},
            "interior_pointers": interior, "evidence_sha256": "a" * 64}
    if locator == "external_allocation":
        rule.update(kind="external", lifetime="allocation",
                    locator={"kind": locator, "allocation_id": "incoming", "offset": 0})
    rules = [rule]
    if ambiguous:
        rules.append({**rule, "id": "overlap", "object": rule["object"] + 1,
                      "extent": 8, "locator": {"kind": "image_rva", "image_id": "test", "rva": 4100}})
    return MachineObjectAuthorityV2(machine_backend=backend, bindings={"original_pe_sha256": "b" * 64},
                                    rules=rules).to_payload()


class ReferenceAuthorityTests(unittest.TestCase):
    def check(self, body, *, authority=None, failure=None, assurance=None, reference_capacity=None):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        authority = authority if authority is not None else authority_payload()
        world = _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
            max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
            reference_authority=authority, image_size=131072,
            reference_origin_capacity=reference_capacity, runtime_assurance=assurance)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "authority.c"
            source.write_text('''#include "state-machine-runtime.h"
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)
''' + world + '''
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference;
  uint32_t address;
''' + body + '\n  __CPROVER_cover(1);\n}\n')
            command = [cbmc, str(source), '--json-ui', '--unwind', '2', '--sat-solver', 'cadical',
                       *runtime_assurance_defines(assurance),
                       *reference_authority_unwind_arguments(authority)]
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check'], timeout_seconds=30)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertIn(failure, result['detail'])
            else:
                cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                                       expected_functions=['main'], timeout_seconds=30)
                self.assertEqual(cover['status'], 'satisfied', cover)

    def test_conditional_issued_access_retains_offset_permissions_null_and_frames(self):
        body = '''
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4198400U, 16U, 1U,
      "image-buffer", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "issue native origin");
  uint64_t offset = ((uint64_t)spx_nondet_u32() << 32U) | spx_nondet_u32();
  uint32_t permission = spx_nondet_u32(), one_past = spx_nondet_u32();
  __CPROVER_assume(permission <= 7U && one_past <= 1U);
  reference.offset = offset;
  spx_boundary_status status = runtime.realize_reference(runtime.context, &reference,
      permission, 0U, one_past, &address);
  __CPROVER_assert((status == SPX_BOUNDARY_OK) ==
      ((permission & 3U) == permission && offset <= 16U && (offset < 16U || one_past)),
      "full-width offset and requested permissions retain native acceptance");
  if (status == SPX_BOUNDARY_OK)
    __CPROVER_assert(address == 4198400U + offset, "native address retained");
  __CPROVER_assert(spx_source_origins.count == 1U && spx_source_world.write_count == 0U &&
      spx_source_world.call_count == 0U && spx_source_world.allocation_count == 0U,
      "realization leaves origins and effects unchanged");
  reference = (spx_machine_reference_v1){0};
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 1U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 0U, "canonical nullable reference");
  reference.generation = 1U;
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 1U, 0U, &address)
      != SPX_BOUNDARY_OK, "malformed null rejected");
'''
        combined = issued_access_assurance()
        combined['contracts'] = allocation_byte_projection_assurance()['contracts'] + combined['contracts']
        combined['contracts'] += world_reference_assurance()['contracts']
        for assurance in (None, issued_access_assurance(), world_reference_assurance(), combined):
            with self.subTest(conditional=assurance is not None):
                self.check(body, assurance=assurance,
                           authority=authority_payload(backend='x86-pe32-loader-relative-v2'))

    def test_conditional_domain_requires_issued_exact_metadata(self):
        for field in ('unissued', 'extent', 'permissions', 'generation'):
            body = '''
  reference = (spx_machine_reference_v1){UINT64_C(4294967299), UINT64_C(8589934647), 17U, 0U, 16U, 3U};
'''
            if field != 'unissued':
                body += '''  __CPROVER_assume(runtime.resolve_reference(runtime.context, 4198400U, 16U, 1U,
      "image-buffer", 0U, 0U, &reference) == SPX_BOUNDARY_OK);
'''
                body += f'  reference.{field} += 1U;\n'
            body += '  (void)runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address);\n'
            with self.subTest(field=field):
                self.check(body, assurance=issued_access_assurance(),
                           failure='spx-bisimulation-issued-access-contract-domain')

    def test_conditional_capacity_includes_the_fifth_native_origin(self):
        base = authority_payload()
        rules = [{**base['rules'][0], 'id': f'buffer-{i}', 'object': base['rules'][0]['object'] + i,
                  'locator': {'kind': 'image_rva', 'image_id': 'test', 'rva': 4096 + 32*i}}
                 for i in range(5)]
        authority = MachineObjectAuthorityV2(machine_backend='x86-pe32', bindings=base['bindings'], rules=rules).to_payload()
        body = '\n'.join(f'''  __CPROVER_assert(runtime.resolve_reference(runtime.context, {4198400+32*i}U, 16U,
      1U, "buffer-{i}", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "issue origin {i}");''' for i in range(5))
        body += '''
  __CPROVER_assert(spx_source_origins.count == 5U, "five distinct native origins");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 4198528U, "last configured origin remains usable");
'''
        self.check(body, authority=authority, assurance=issued_access_assurance(), reference_capacity=5)

    def test_conditional_lowering_rejects_unsupported_contracts_and_namespaces(self):
        options = dict(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
            max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
            reference_authority=authority_payload(), image_size=131072,
            runtime_assurance=issued_access_assurance())
        for kind in ('digest', 'revision', 'extra-contract', 'missing-authority', 'interior', 'capacity', 'backend'):
            changed = copy.deepcopy(options)
            if kind == 'digest': changed['runtime_assurance']['contracts'][0]['contract_sha256'] = 'a'*64
            elif kind == 'revision': changed['runtime_assurance']['contracts'][0]['revision'] = 1
            elif kind == 'extra-contract':
                changed['runtime_assurance']['contracts'].append({'id': 'unknown', 'revision': 1, 'contract_sha256': 'b'*64})
            elif kind == 'missing-authority': changed['reference_authority'] = None
            elif kind == 'interior': changed['reference_authority'] = authority_payload(interior=False)
            elif kind == 'backend': changed['reference_authority'] = authority_payload(backend='x86-64')
            else: changed['reference_origin_capacity'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                _world_source(**changed)

    def test_conditional_model_does_not_depend_on_native_realization_body(self):
        from spaghetti_extractor.transfer import reference_namespace
        options = dict(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
            max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
            reference_authority=authority_payload(), image_size=131072)
        original = _world_source(**options)
        conditional = _world_source(**options, runtime_assurance=issued_access_assurance())
        self.assertIn('spx_proof_authority_realize_reference(', original)
        self.assertNotIn('spx_proof_authority_realize_reference(', conditional)
        native = reference_namespace._reference_realization_source
        def grown(prefix):
            source = native(prefix)
            at = source.index('{') + 1
            growth = '\n'.join(f'  permissions ^= {i}U; permissions ^= {i}U;' for i in range(128))
            return source[:at] + '\n' + growth + source[at:]
        with patch.object(reference_namespace, '_reference_realization_source', side_effect=grown):
            self.assertNotEqual(_world_source(**options), original)
            self.assertEqual(_world_source(**options, runtime_assurance=issued_access_assurance()), conditional)

    def test_byte_projection_alone_preserves_native_reference_admission(self):
        self.check('''
  reference = (spx_machine_reference_v1){UINT64_C(4294967299), UINT64_C(8589934647), 17U, 4U, 16U, 3U};
  __CPROVER_assert(spx_source_origins.count == 0U, "initially unissued reference");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 4198404U, "byte selection does not enable issued-only access");
''', assurance=allocation_byte_projection_assurance())

    def test_resolver_preserves_native_identity_extent_and_permissions(self):
        self.check('''
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U,
      "image-buffer", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "selected authority resolves");
  __CPROVER_assert(reference.domain == UINT64_C(4294967299) &&
      reference.object == UINT64_C(8589934647) && reference.generation == 17U &&
      reference.offset == 4U && reference.extent == 16U && reference.permissions == 5U,
      "native canonical tuple survives proof resolution");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 4198404U, "native reference round trip");
''', authority=authority_payload(permissions=5))

    def test_valid_native_reference_does_not_require_an_earlier_resolve(self):
        self.check('''
  reference = (spx_machine_reference_v1){UINT64_C(4294967299), UINT64_C(8589934647), 17U, 4U, 16U, 3U};
  __CPROVER_assert(spx_source_origins.count == 0U, "no previously issued origin");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 4198404U, "authority validates an initially available reference");
  __CPROVER_assert(spx_source_origins.count == 1U, "validated origin is enrolled");
''')

    def test_unknown_selector_and_ambiguous_lookup_reject(self):
        self.check('''
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U,
      "unknown-selector", 0U, 0U, &reference) == SPX_BOUNDARY_TYPE_MISMATCH,
      "unknown selector is rejected");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U,
      0, 0U, 0U, &reference) == SPX_BOUNDARY_TYPE_MISMATCH, "ambiguous authority is rejected");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U,
      "image-buffer", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "selector disambiguates");
''', authority=authority_payload(ambiguous=True))

    def test_native_interior_and_one_past_policy_is_enforced(self):
        for interior in (False, True):
            with self.subTest(interior=interior):
                expected = 'SPX_BOUNDARY_OK' if interior else 'SPX_BOUNDARY_MEMORY_FAULT'
                self.check('''
  reference = (spx_machine_reference_v1){UINT64_C(4294967299), UINT64_C(8589934647), 17U, 4U, 16U, 3U};
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == EXPECTED, "interior policy");
  reference.offset = 16U;
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 1U, &address)
      == EXPECTED, "one-past policy");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_MEMORY_FAULT, "one-past must be explicitly requested");
'''.replace('EXPECTED', expected), authority=authority_payload(interior=interior))

    def test_unqualified_runtime_locator_is_an_explicit_proof_failure(self):
        self.check('''
  (void)runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U, 0, 0U, 0U, &reference);
''', authority=authority_payload(locator='external_allocation'),
                   failure='spx-bisimulation-reference-locator-qualified')

    def test_full_contextual_checker_uses_native_reference_authority(self):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        for locator in ("image_rva", "external_allocation"):
            with self.subTest(locator=locator), tempfile.TemporaryDirectory() as temporary:
                result = check_normal_exit(Path(temporary), cbmc=Path(cbmc),
                    reference_authority=authority_payload(locator=locator), reference_probe=True)
                self.assertEqual(result["status"], "satisfied" if locator == "image_rva" else "violated",
                                 result.get("issues"))
                if locator != "image_rva":
                    self.assertIn("spx-bisimulation-reference-locator-qualified", str(result["issues"]))
