/* Test-only, single-threaded PE32 interception. No trampoline executes the old
 * entry. Caller supplies a pinned, whole-instruction five-byte prefix. This is
 * executable fixture machinery, never a production adapter or proof summary.
 */
#ifndef SPX_FIXTURE_PE32_ENTRY_HOOK_H
#define SPX_FIXTURE_PE32_ENTRY_HOOK_H
#include <windows.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  unsigned char *entry;
  unsigned char original[4096];
  unsigned char *saved;
  size_t length;
} spx_fixture_entry_hook;

/* The address variant supports reviewed internal entries in a pinned loaded
 * image. Its caller checks the image range; it is not an untrusted-pointer API. */
static inline int spx_fixture_redirect_address_body_with_storage(spx_fixture_entry_hook *hook,
    unsigned char *entry, const unsigned char expected[5],
    size_t length, void (*replacement)(void), unsigned char *storage, size_t capacity) {
  _Static_assert(sizeof(void *) == 4, "fixture interception requires PE32");
  DWORD protection;
  uint64_t start = (uintptr_t)entry, saved = (uintptr_t)storage;
  if (!hook || !storage || !expected || length < 5 || length > capacity || !entry || !replacement ||
      (start < saved + length && saved < start + length) || memcmp(entry, expected, 5) ||
      !VirtualProtect(entry, length, PAGE_EXECUTE_READWRITE, &protection))
    return 0;
  memcpy(storage, entry, length);
  hook->saved = storage;
  hook->entry = entry;
  hook->length = length;
  uint32_t displacement = (uint32_t)(uintptr_t)replacement - (uint32_t)(uintptr_t)(entry + 5);
  memset(entry, 0xcc, length); /* Any entry into the removed body traps. */
  entry[0] = 0xe9;
  memcpy(entry + 1, &displacement, 4);
  DWORD ignored;
  int restored = VirtualProtect(entry, length, protection, &ignored);
  return restored && FlushInstructionCache(GetCurrentProcess(), entry, length);
}

/* The caller-owned storage variant admits larger reviewed bodies. Storage must
 * remain live, disjoint from the entry bytes and unchanged until restoration.
 * The original convenience API retains its fixed capacity and behavior. */
static inline int spx_fixture_redirect_address_body(spx_fixture_entry_hook *hook,
    unsigned char *entry, const unsigned char expected[5],
    size_t length, void (*replacement)(void)) {
  if (!hook) return 0;
  return spx_fixture_redirect_address_body_with_storage(hook, entry, expected,
      length, replacement, hook->original, sizeof(hook->original));
}

static inline int spx_fixture_redirect_body(spx_fixture_entry_hook *hook,
    const char *module, const char *symbol, const unsigned char expected[5],
    size_t length, void (*replacement)(void)) {
  HMODULE library = GetModuleHandleA(module);
  unsigned char *entry = library ? (unsigned char *)GetProcAddress(library, symbol) : NULL;
  return spx_fixture_redirect_address_body(hook, entry, expected, length, replacement);
}

static inline int spx_fixture_redirect_entry(spx_fixture_entry_hook *hook,
    const char *module, const char *symbol, const unsigned char expected[5], void (*replacement)(void)) {
  return spx_fixture_redirect_body(hook, module, symbol, expected, 5, replacement);
}

static inline int spx_fixture_restore_entry(spx_fixture_entry_hook *hook) {
  DWORD protection, ignored;
  if (!hook->entry || !hook->saved || !VirtualProtect(hook->entry, hook->length, PAGE_EXECUTE_READWRITE, &protection))
    return 0;
  memcpy(hook->entry, hook->saved, hook->length);
  int restored = VirtualProtect(hook->entry, hook->length, protection, &ignored);
  return restored && FlushInstructionCache(GetCurrentProcess(), hook->entry, hook->length);
}
#endif
