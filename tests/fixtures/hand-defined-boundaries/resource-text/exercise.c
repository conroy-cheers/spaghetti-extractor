/* Concrete authoring checks, not a machine adapter or a LoadStringA model. */
#include "portable-component-implementation.h"
#include <assert.h>
#include <string.h>

struct fixture {
  uint8_t bytes[500];
  uint32_t module;
  uint32_t calls;
  uint32_t observed_module[2];
};

static uint32_t read_fixture(void *opaque, spx_ref_v5 reference,
    uint64_t offset, uint32_t width, uint64_t *value) {
  struct fixture *fixture = opaque;
  if (reference.domain != 1 || reference.generation != 7 ||
      reference.offset != 0 || !(reference.permissions & 1)) return 1;
  if (reference.object == 1 && reference.extent == 500 &&
      width == 1 && offset < 500) {
    *value = fixture->bytes[offset];
    return 0;
  }
  if (reference.object == 2 && reference.extent == 4 &&
      width == 4 && offset == 0) {
    *value = fixture->module;
    return 0;
  }
  return 1;
}

static uint32_t write_fixture(void *opaque, spx_ref_v5 reference,
    uint64_t offset, uint32_t width, uint64_t value) {
  struct fixture *fixture = opaque;
  if (reference.domain != 1 || reference.object != 1 ||
      reference.generation != 7 || reference.offset != 0 ||
      reference.extent != 500 || !(reference.permissions & 2) ||
      width != 1 || offset >= 500) return 1;
  fixture->bytes[offset] = (uint8_t)value;
  return 0;
}

static uint32_t supplied_interaction(void *opaque, uint32_t module, uint32_t id,
    const spx_view_v5 *buffer, uint32_t maximum) {
  struct fixture *fixture = opaque;
  assert(fixture->calls < 2);
  assert(maximum == 500 && buffer->extent == 500);
  fixture->observed_module[fixture->calls] = module;
  assert(spx_view_write_u8(buffer, 0, (uint8_t)id) == 0);
  /* Exercise both scalar outcomes without promising string contents. */
  return fixture->calls++;
}

static spx_view_v5 buffer_view(struct fixture *fixture) {
  return (spx_view_v5){
    .base = {.domain = 1, .object = 1, .generation = 7,
             .offset = 0, .extent = 500, .permissions = 3},
    .extent = 500, .element_width = 1, .access_context = fixture,
    .read = read_fixture, .write = write_fixture,
  };
}

static spx_resource_text_context_v5 caller_context(struct fixture *fixture,
    const spx_resource_text_services_v5 *services) {
  spx_resource_text_context_v5 context = {
    .services = services, .protocol_state = SPX_RESOURCE_TEXT_PROTOCOL_READY,
  };
  context.state.buffer = buffer_view(fixture);
  context.state.module = (spx_view_v5){
    .base = {.domain = 1, .object = 2, .generation = 7,
             .offset = 0, .extent = 4, .permissions = 1},
    .extent = 4, .element_width = 1, .access_context = fixture,
    .read = read_fixture,
  };
  return context;
}

static void same_view(spx_view_v5 left, spx_view_v5 right) {
  assert(left.base.domain == right.base.domain);
  assert(left.base.object == right.base.object);
  assert(left.base.generation == right.base.generation);
  assert(left.base.offset == right.base.offset);
  assert(left.base.extent == right.base.extent);
  assert(left.base.permissions == right.base.permissions);
  assert(left.extent == right.extent);
  assert(left.element_width == right.element_width);
  assert(left.access_context == right.access_context);
  assert(left.read == right.read && left.write == right.write);
}

int main(void) {
  struct fixture fixture = {.module = 11};
  memset(fixture.bytes, 0xa5, sizeof(fixture.bytes));
  spx_resource_text_services_v5 services = {
    .context = &fixture, .load_string = supplied_interaction,
  };
  spx_resource_text_context_v5 first = caller_context(&fixture, &services);
  spx_resource_text_context_v5 second = caller_context(&fixture, &services);
  spx_view_v5 old_result = resource_text(&first, 65);
  same_view(old_result, first.state.buffer);
  uint8_t byte;
  assert(spx_view_read_u8(&old_result, 0, &byte) == 0 && byte == 65);

  fixture.module = 22;
  spx_view_v5 new_result = resource_text(&second, 66);
  same_view(old_result, new_result);
  assert(fixture.calls == 2);
  assert(fixture.observed_module[0] == 11 && fixture.observed_module[1] == 22);
  assert(spx_view_read_u8(&old_result, 0, &byte) == 0 && byte == 66);
  assert(spx_view_write_u8(&old_result, 1, 67) == 0);
  assert(spx_view_read_u8(&second.state.buffer, 1, &byte) == 0 && byte == 67);
  for (unsigned i = 2; i < 500; ++i) assert(fixture.bytes[i] == 0xa5);
  return 0;
}
