/* Test-only interception of one resolved PE32 import, for single-threaded
 * native fixtures. The original function remains callable. This changes the
 * fixture environment, not the original allocator or a production adapter. */
#ifndef SPX_FIXTURE_PE32_IMPORT_HOOK_H
#define SPX_FIXTURE_PE32_IMPORT_HOOK_H
#include <windows.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  DWORD *slot;
  DWORD original, replacement;
} spx_fixture_import_hook;

static inline int spx_fixture_image_span(DWORD size, DWORD rva, size_t length) {
  return rva <= size && length <= size - rva;
}

static inline const char *spx_fixture_image_string(unsigned char *base, DWORD size, DWORD rva) {
  return rva < size && memchr(base + rva, 0, size - rva) ? (const char *)(base + rva) : NULL;
}

static inline int spx_fixture_write_import(DWORD *slot, DWORD value) {
  DWORD protection, ignored;
  if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &protection)) return 0;
  *slot = value;
  return VirtualProtect(slot, sizeof(*slot), protection, &ignored) != 0;
}

static inline int spx_fixture_redirect_import(spx_fixture_import_hook *hook,
    const char *module, const char *imported_module, const char *symbol,
    void (*replacement)(void)) {
  _Static_assert(sizeof(void *) == 4, "fixture import interception requires PE32");
  if (hook->slot || !replacement) return 0;
  unsigned char *base = (unsigned char *)GetModuleHandleA(module);
  HMODULE library = GetModuleHandleA(imported_module);
  FARPROC expected = library ? GetProcAddress(library, symbol) : NULL;
  if (!base || !expected) return 0;
  /* The Windows loader has already admitted this image; this is not a parser
   * for untrusted file bytes. All directory/name/thunk reads are image-bounded. */
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < (LONG)sizeof(*dos)) return 0;
  IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return 0;
  DWORD size = nt->OptionalHeader.SizeOfImage;
  IMAGE_DATA_DIRECTORY directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!directory.VirtualAddress || !spx_fixture_image_span(size, directory.VirtualAddress, directory.Size)) return 0;
  DWORD *selected = NULL;
  int terminated = 0;
  for (DWORD n = 0; n < directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); ++n) {
    IMAGE_IMPORT_DESCRIPTOR *entry = (IMAGE_IMPORT_DESCRIPTOR *)(base + directory.VirtualAddress) + n;
    if (!entry->Name && !entry->FirstThunk && !entry->OriginalFirstThunk) { terminated = 1; break; }
    const char *name = spx_fixture_image_string(base, size, entry->Name);
    if (!name) return 0;
    if (lstrcmpiA(name, imported_module)) continue;
    if (!entry->OriginalFirstThunk || !entry->FirstThunk ||
        !spx_fixture_image_span(size, entry->OriginalFirstThunk, sizeof(DWORD)) ||
        !spx_fixture_image_span(size, entry->FirstThunk, sizeof(DWORD))) return 0;
    DWORD *names = (DWORD *)(base + entry->OriginalFirstThunk);
    DWORD *slots = (DWORD *)(base + entry->FirstThunk);
    DWORD i = 0;
    for (;;) {
      if (i >= (size - entry->OriginalFirstThunk) / sizeof(DWORD) ||
          i >= (size - entry->FirstThunk) / sizeof(DWORD)) return 0;
      DWORD thunk = names[i];
      if (!thunk) break;
      int matches = 0;
      if (thunk & IMAGE_ORDINAL_FLAG32) {
        /* Old clients often import COM factories by ordinal. Resolve against
         * the declared DLL, then require the same expected export and slot;
         * the caller does not need target-specific ordinal/address knowledge. */
        matches = GetProcAddress(library, (const char *)(uintptr_t)(thunk & 0xffff)) == expected;
      } else {
        if (!spx_fixture_image_span(size, thunk, sizeof(WORD) + 1)) return 0;
        const char *import_name = spx_fixture_image_string(base, size, thunk + sizeof(WORD));
        if (!import_name) return 0;
        matches = !strcmp(import_name, symbol);
      }
      if (matches) {
        /* Ambiguous slots or a previous interception are unsupported. */
        if (selected || slots[i] != (DWORD)(uintptr_t)expected) return 0;
        selected = &slots[i];
      }
      ++i;
    }
  }
  if (!terminated || !selected) return 0;
  DWORD original = *selected, target = (DWORD)(uintptr_t)replacement;
  if (!spx_fixture_write_import(selected, target)) {
    (void)spx_fixture_write_import(selected, original);
    return 0;
  }
  hook->slot = selected;
  hook->original = original;
  hook->replacement = target;
  return 1;
}

static inline int spx_fixture_restore_import(spx_fixture_import_hook *hook) {
  if (!hook->slot || *hook->slot != hook->replacement ||
      !spx_fixture_write_import(hook->slot, hook->original)) return 0;
  memset(hook, 0, sizeof(*hook));
  return 1;
}
#endif
