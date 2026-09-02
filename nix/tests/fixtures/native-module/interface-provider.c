#include <stdint.h>
#include <windows.h>

typedef struct fixture_interface fixture_interface;
typedef struct fixture_interface_vtable fixture_interface_vtable;
typedef struct fixture_record fixture_record;
typedef uint32_t (__stdcall *fixture_enum_callback)(
    fixture_interface *, uint32_t);

struct fixture_record {
  uint32_t input;
  uint32_t output;
};

struct fixture_interface_vtable {
  int32_t (__stdcall *clone)(fixture_interface *, fixture_interface **);
  int32_t (__stdcall *set_value)(fixture_interface *, uint32_t);
  uint32_t (__stdcall *get_value)(fixture_interface *);
  uint32_t (__stdcall *release)(fixture_interface *);
  uint32_t (__stdcall *enumerate)(
      fixture_interface *, fixture_enum_callback, uint32_t);
  int32_t (__stdcall *fill_record)(fixture_interface *, fixture_record *);
};

struct fixture_interface {
  const fixture_interface_vtable *vtable;
  uint32_t value;
  uint32_t released;
};

static int32_t __stdcall fixture_clone(
    fixture_interface *self, fixture_interface **result);
static int32_t __stdcall fixture_set_value(
    fixture_interface *self, uint32_t value);
static uint32_t __stdcall fixture_get_value(fixture_interface *self);
static uint32_t __stdcall fixture_release(fixture_interface *self);
static uint32_t __stdcall fixture_enumerate(
    fixture_interface *self, fixture_enum_callback callback, uint32_t cookie);
static int32_t __stdcall fixture_fill_record(
    fixture_interface *self, fixture_record *record);

static const fixture_interface_vtable fixture_vtable = {
    fixture_clone,
    fixture_set_value,
    fixture_get_value,
    fixture_release,
    fixture_enumerate,
    fixture_fill_record,
};

static fixture_interface fixture_objects[2] = {
    {&fixture_vtable, 0U, 1U},
    {&fixture_vtable, 0U, 1U},
};
static volatile uint32_t fixture_stale_call_count;
static volatile uint32_t fixture_create_count;
static volatile uint32_t fixture_clone_count;
static volatile uint32_t fixture_set_count;
static volatile uint32_t fixture_get_count;
static volatile uint32_t fixture_release_count;
static volatile uint32_t fixture_enumerate_count;
static volatile uint32_t fixture_fill_record_count;
static volatile uint32_t fixture_last_record_input;
static volatile uint32_t fixture_last_record_output;
static fixture_enum_callback fixture_saved_callback;
static uint32_t fixture_saved_cookie;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)instance;
  (void)reason;
  (void)reserved;
  return TRUE;
}

int32_t __stdcall FixtureCreate(fixture_interface **result) {
  ++fixture_create_count;
  if (result == NULL) return (int32_t)0x80004003U;
  fixture_objects[0].value = 0x10203040U;
  fixture_objects[0].released = 0U;
  *result = &fixture_objects[0];
  return 0;
}

static int32_t __stdcall fixture_clone(
    fixture_interface *self, fixture_interface **result) {
  ++fixture_clone_count;
  if (self == NULL || result == NULL || self->released != 0U)
    return (int32_t)0x80004005U;
  fixture_objects[1].value = self->value;
  fixture_objects[1].released = 0U;
  *result = &fixture_objects[1];
  return 0;
}

static int32_t __stdcall fixture_set_value(
    fixture_interface *self, uint32_t value) {
  ++fixture_set_count;
  if (self == NULL || self->released != 0U) {
    ++fixture_stale_call_count;
    return (int32_t)0x80004005U;
  }
  self->value = value;
  return 0;
}

static uint32_t __stdcall fixture_get_value(fixture_interface *self) {
  ++fixture_get_count;
  if (self == NULL || self->released != 0U) {
    ++fixture_stale_call_count;
    return 0xdeadc0deU;
  }
  return self->value;
}

static uint32_t __stdcall fixture_release(fixture_interface *self) {
  ++fixture_release_count;
  if (self == NULL || self->released != 0U) {
    ++fixture_stale_call_count;
    return 1U;
  }
  self->released = 1U;
  return 0U;
}

static uint32_t __stdcall fixture_enumerate(
    fixture_interface *self, fixture_enum_callback callback, uint32_t cookie) {
  ++fixture_enumerate_count;
  if (self == NULL || self->released != 0U || callback == NULL)
    return 0U;
  fixture_objects[1].value = 0x0badc0deU;
  fixture_objects[1].released = 0U;
  fixture_saved_callback = callback;
  fixture_saved_cookie = cookie;
  return callback(&fixture_objects[1], cookie);
}

static int32_t __stdcall fixture_fill_record(
    fixture_interface *self, fixture_record *record) {
  ++fixture_fill_record_count;
  if (record == NULL) return (int32_t)0x80004003U;
  fixture_last_record_input = record->input;
  record->output = record->input ^ 0xcafebabeU;
  fixture_last_record_output = record->output;
  if (self == NULL || self->released != 0U) {
    ++fixture_stale_call_count;
    return (int32_t)0x80004005U;
  }
  return 0;
}

uint32_t __stdcall FixtureProviderInvokeStaleCallback(void) {
  if (fixture_saved_callback == NULL) return 0xffffffffU;
  return fixture_saved_callback(&fixture_objects[1], fixture_saved_cookie);
}

uint32_t __stdcall FixtureProviderStaleCallCount(void) {
  return fixture_stale_call_count;
}

uint32_t __stdcall FixtureProviderTrace(void) {
  return (fixture_create_count & 15U) |
      ((fixture_clone_count & 15U) << 4U) |
      ((fixture_set_count & 15U) << 8U) |
      ((fixture_get_count & 15U) << 12U) |
      ((fixture_release_count & 15U) << 16U) |
      ((fixture_enumerate_count & 15U) << 20U) |
      ((fixture_fill_record_count & 15U) << 24U);
}

uint32_t __stdcall FixtureProviderLastRecordInput(void) {
  return fixture_last_record_input;
}

uint32_t __stdcall FixtureProviderLastRecordOutput(void) {
  return fixture_last_record_output;
}
