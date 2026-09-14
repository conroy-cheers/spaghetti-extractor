/* Controlled runtime/service fixture for the real helper's generated boundary. */
struct fixture {
  uint8_t byte0, byte1, last;
  uint32_t module, calls, generation, observed[2];
};

static spx_boundary_status resolve(void *opaque, uint32_t address, uint32_t extent,
    uint32_t permissions, const char *selector, uint32_t nullable, uint32_t one_past,
    spx_machine_reference_v1 *result) {
  struct fixture *fixture = opaque;
  (void)nullable; (void)one_past;
  uint32_t size = address == 0x413d20U ? 500U : 4U;
  uint32_t access = address == 0x413d20U ? 3U : 1U;
  if ((address != 0x413d20U && address != 0x410150U) || extent != size ||
      permissions != access || selector == 0 ||
      strcmp(selector, size == 500U ? "buffer" : "module")) return SPX_BOUNDARY_MEMORY_FAULT;
  *result = (spx_machine_reference_v1){1, address, fixture->generation, 0, size, access};
  return SPX_BOUNDARY_OK;
}

static spx_boundary_status realize(void *opaque, const spx_machine_reference_v1 *ref,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  struct fixture *fixture = opaque;
  (void)nullable; (void)one_past;
  uint32_t size = ref->object == 0x413d20U ? 500U : 4U;
  uint32_t access = ref->object == 0x413d20U ? 3U : 1U;
  if (ref->domain != 1 || (ref->object != 0x413d20U && ref->object != 0x410150U) ||
      ref->generation != fixture->generation || ref->offset >= size ||
      ref->extent != size || ref->permissions != access || (permissions & access) != permissions)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = (uint32_t)(ref->object + ref->offset);
  return SPX_BOUNDARY_OK;
}

static uint32_t read_memory(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
  struct fixture *fixture = opaque;
  if (address == 0x410150U && width == 4) return fixture->module;
  if (address == 0x413d20U && width == 1) return fixture->byte0;
  if (address == 0x413d21U && width == 1) return fixture->byte1;
  if (address == 0x413d20U + 499U && width == 1) return fixture->last;
  *fault = 1;
  return 0;
}

static void write_memory(void *opaque, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  struct fixture *fixture = opaque;
  if (address == 0x413d20U && width == 1) fixture->byte0 = (uint8_t)value;
  else if (address == 0x413d21U && width == 1) fixture->byte1 = (uint8_t)value;
  else *fault = 1;
}

static uint32_t interaction(void *opaque, uint32_t module, uint32_t id,
    const spx_view_v5 *buffer, uint32_t maximum) {
  struct fixture *fixture = opaque;
  assert(maximum == 500 && fixture->calls < 2);
  fixture->observed[fixture->calls] = module;
  assert(spx_view_write_u8(buffer, 0, (uint8_t)id) == 0);
  return fixture->calls++;
}

static void mutate(spx_resource_text_context_v5 *context, spx_view_v5 *result,
    struct fixture *fixture, uint32_t mutation) {
  switch (mutation) {
    case 1: result->base.generation++; break;
    case 2: result->base.offset++; break;
    case 3: result->extent--; break;
    case 4: result->read = 0; break;
    case 5: result->access_context = 0; break;
    case 6: context->state.buffer.base.object++; break;
    case 7: context->state.module.extent--; break;
    case 8: fixture->generation++; break;
    case 9: result->base.permissions = 1; break;
    case 10: result->base.extent--; break;
    case 11: result->element_width = 2; break;
    default: break;
  }
}

/* The test generator inserts the actual state and result transducers here. */
GENERATED_BOUNDARY

static void exercise(uint32_t mutation) {
  struct fixture fixture = {.module = 11, .generation = 7};
  fixture.byte1 = 0xa5;
  fixture.last = 0xa5;
  spx_runtime runtime = {
    .context = &fixture, .read = read_memory, .write = write_memory,
    .resolve_reference = resolve, .realize_reference = realize,
  };
  spx_resource_text_services_v5 services = {.context = &fixture, .load_string = interaction};
  spx_view_v5 saved = {0};
  spx_step_result first = invoke(&runtime, &services, 65, mutation, &saved);
  if (mutation != 0) {
    assert(first.kind == SPX_MEMORY_FAULT);
    return;
  }
  assert(first.kind == SPX_RETURN && first.value == 0x413d20U);
  fixture.module = 22;
  spx_view_v5 second = {0};
  spx_step_result next = invoke(&runtime, &services, 66, 0, &second);
  assert(next.kind == SPX_RETURN && next.value == first.value);
  assert(fixture.calls == 2 && fixture.observed[0] == 11 && fixture.observed[1] == 22);
  uint8_t byte;
  assert(spx_view_read_u8(&saved, 0, &byte) == 0 && byte == 66);
  assert(spx_view_write_u8(&saved, 1, 67) == 0);
  assert(spx_view_read_u8(&second, 1, &byte) == 0 && byte == 67);
  assert(fixture.last == 0xa5);
  fixture.generation++;
  assert(spx_view_read_u8(&saved, 0, &byte) != 0);
}

int main(void) {
#ifdef __CPROVER__
  /* The runner covers every mutation separately to avoid merging unrelated
   * accessor and origin corruptions into a single symbolic pointer graph. */
  exercise(SPX_TEST_MUTATION);
#else
  for (uint32_t mutation = 0; mutation <= 11; ++mutation) exercise(mutation);
#endif
  return 0;
}
