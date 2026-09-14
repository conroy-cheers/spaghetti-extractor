"""Actual native image namespace exercised by the real logical consumer.

Only image origins are admitted. Raw memory and the LoadStringA interaction are
controlled fixtures; this does not qualify the native service bridge or loader.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.candidate.runtime_memory_access import range_predicates_source
from spaghetti_extractor.transfer.reference_namespace import reference_namespace_source
from ..candidate.test_runtime_allocation_lifetime import _function
from .test_shared_logical_transport import write_logical_fixture

NATIVE_FIXTURE = Path(__file__).parents[2]/'fixtures/native-image-shared-transport'


def image_namespace():
    authority = json.loads((NATIVE_FIXTURE/'reference-authority.json').read_text())
    rows = []
    for rule in authority['rules']:
        assert rule['kind'] == rule['lifetime'] == 'image'
        assert rule['locator']['kind'] == 'image_rva'
        rows.append('  {' + json.dumps(rule['id']) + ', ' + ', '.join(
            f'UINT64_C({rule[key]})' for key in ('domain', 'object', 'generation')) + ', ' + ', '.join(
            f'{value}U' for value in (rule['extent'], rule['permissions'], 1, rule['locator']['rva'],
                                    0, int(rule['interior_pointers']), 0)) + '},')
    prelude = '''
typedef struct {
  uint32_t start, size, producer_rva, producer_action, generation;
  uint32_t external_range_rule_selector;
  uint64_t object_id;
  uint32_t ownership_family, ownership_owner;
} spx_native_external_range;
typedef struct {
  uint32_t image_base, image_size, external_range_count;
  spx_native_external_range external_ranges[1];
} spx_native_context;
typedef struct {
  const char *identity;
  uint64_t domain, object_id, generation;
  uint32_t extent, permissions, locator_kind, locator_offset;
  uint32_t locator_subject_rva, interior_pointers, extent_mode;
} spx_native_object_authority_rule;
static const spx_native_object_authority_rule spx_native_object_authority_rules[] = {
''' + '\n'.join(rows) + '''
};
static const uint32_t spx_native_object_authority_rule_count = 4U;
static const uint32_t spx_native_tls_total_bytes = 0U;
static void *spx_native_module_tls_base_current(void) {
  assert(0 && "image-only fixture reached TLS"); return 0;
}
static uint32_t spx_native_u32(uint32_t address) {
  (void)address; assert(0 && "image-only fixture reached IAT"); return 0;
}
static uint32_t spx_native_captured_stack_rule_base(uint32_t subject, uint32_t offset,
    uint32_t extent, uint32_t *base, uint32_t *generation) {
  (void)subject; (void)offset; (void)extent; (void)base; (void)generation;
  assert(0 && "image-only fixture reached stack origin"); return 0;
}
'''
    core = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=()))
    return prelude + _function(range_predicates_source(), 'spx_native_range_end') + _function(
        core, 'spx_native_object_rule_base') + reference_namespace_source()


def write_image_logical_fixture(root):
    source = write_logical_fixture(root)
    text = source.read_text()
    text = text.replace('struct fixture {', image_namespace() + '\nstruct fixture {\n  spx_native_context native;')
    start = text.index('static spx_boundary_status resolve(')
    end = text.index('static uint32_t read_memory(', start)
    text = text[:start] + '''
static spx_boundary_status resolve(void *opaque, uint32_t address, uint32_t extent,
    uint32_t permissions, const char *selector, uint32_t nullable, uint32_t one_past,
    spx_machine_reference_v1 *result) {
  struct fixture *fixture = opaque;
  return spx_native_resolve_reference(&fixture->native, address, extent, permissions,
      selector, nullable, one_past, result);
}
static spx_boundary_status realize(void *opaque, const spx_machine_reference_v1 *ref,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  struct fixture *fixture = opaque;
  return spx_native_realize_reference(&fixture->native, ref, permissions, nullable, one_past, address);
}
''' + text[end:]
    text = text.replace('uint8_t byte0, byte1, last;', 'uint8_t bytes[500];')
    for field, offset in (('byte0', 0), ('byte1', 1), ('last', 499)):
        text = text.replace('fixture.' + field, f'fixture.bytes[{offset}]')
    start = text.index('static uint32_t read_memory(')
    end = text.index('static uint32_t interaction(', start)
    text = text[:start] + '''
static uint32_t read_memory(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
  struct fixture *fixture = opaque;
  if (address == 0x410150U && width == 4U) return fixture->module;
  if (width >= 1U && width <= 4U && address >= 0x413d20U &&
      (uint64_t)address + width <= 0x413f14U) {
    uint32_t value = 0U;
    for (uint32_t i = 0; i < width; ++i)
      value |= (uint32_t)fixture->bytes[address - 0x413d20U + i] << (8U*i);
    return value;
  }
  *fault = 1U; return 0U;
}
static void write_memory(void *opaque, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  struct fixture *fixture = opaque;
  if (width >= 1U && width <= 4U && address >= 0x413d20U &&
      (uint64_t)address + width <= 0x413f14U) {
    for (uint32_t i = 0; i < width; ++i)
      fixture->bytes[address - 0x413d20U + i] = (uint8_t)(value >> (8U*i));
    return;
  }
  *fault = 1U;
}
''' + text[end:]
    text = text.replace('"module"', '"image:metapad:section:2"').replace('"buffer"', '"image:metapad:section:2"')
    text = text.replace('fixture->generation++;', 'fixture->native.image_size = 0U;')
    text = text.replace('fixture.generation++;', 'fixture.native.image_size = 0U;')
    text = text.replace('struct fixture fixture = {.module = 11, .generation = 7};',
        'struct fixture fixture = {.native = {.image_base = 4194304U, .image_size = 225280U}, .module = 11};')
    text = text.replace('fixture.bytes[499] = 0xa5;', '''
  uint32_t observed_offset;
  uint8_t old_byte;
#ifdef __CPROVER__
  __CPROVER_assume(observed_offset < 500U);
#else
  observed_offset = 499U; old_byte = 0xa5;
#endif
  fixture.bytes[observed_offset] = old_byte;''')
    text = text.replace('assert(fixture.bytes[499] == 0xa5);', '''
  assert(spx_view_read_u8(&saved, observed_offset, &byte) == 0);
  assert(byte == (observed_offset == 0U ? 66U : observed_offset == 1U ? 67U : old_byte));
  assert(spx_view_read_u8(&saved, 500U, &byte) != 0);
  assert(spx_view_read_u8(&saved, UINT32_MAX, &byte) != 0);''')
    text = text.replace('return (spx_step_result){SPX_RETURN,0,(uint32_t)(saved->base.object+saved->base.offset)};', '''
  uint32_t word;
  assert(realize(rt->context, (const spx_machine_reference_v1 *)&(spx_machine_reference_v1){
      saved->base.domain, saved->base.object, saved->base.generation, saved->base.offset,
      saved->base.extent, saved->base.permissions}, 3U, 0U, 0U, &word) == SPX_BOUNDARY_OK);
  return (spx_step_result){SPX_RETURN,0,word};''')
    text = text.replace('assert(first.kind == SPX_RETURN && first.value == 0x413d20U);', '''
  assert(first.kind == SPX_RETURN && first.value == 0x413d20U);
  assert(saved.base.object == UINT64_C(2134217653344611032));
  assert(saved.base.offset == 0x3d20U && saved.base.extent == 18272U);
  assert(saved.extent == 500U && saved.base.permissions == 3U);
  spx_machine_reference_v1 module;
  assert(resolve(&fixture, 0x410150U, 4U, 1U, "image:metapad:section:2", 0U, 0U, &module) == SPX_BOUNDARY_OK);
  assert(module.object == saved.base.object && module.offset == 0x150U && module.permissions == 3U);
''')
    # Current contents are checked before and after remapping. Image generations
    # are fixed in the actual authority; inventing a generation counter would
    # fail to test the production cached-address guard.
    text = text.replace('fixture.native.image_size = 0U;\n  assert', '''
  fixture.native.image_base += 4096U;
  assert(spx_view_read_u8(&saved, 0, &byte) != 0);
  fixture.native.image_base -= 4096U;
  assert(spx_view_read_u8(&saved, 0, &byte) == 0 && byte == 66);
  fixture.native.image_size = 0U;
  assert''')
    source.write_text(text)
    return source
