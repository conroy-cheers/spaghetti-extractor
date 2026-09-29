"""Interception binds an expected entry and bypasses the supplier's body."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.testkit import fixture
from spaghetti_extractor.components.comparison_environment import native_adapter_headers

TESTKIT = {'fixtures': ('compiler', 'headless-wine')}

SUPPLIER = r'''
int body_calls;
__declspec(dllexport) int body_count(void) { return body_calls; }
__declspec(dllexport) __attribute__((naked)) int supplier(int ignored __attribute__((unused))) {
  __asm__ volatile("nop\nnop\nnop\nnop\nnop\nincl _body_calls\n"
                   "movl 4(%esp), %eax\naddl $1, %eax\nret");
}
'''

CONSUMER = r'''
#include <stdio.h>
#include "pe32-entry-hook.h"
__declspec(dllimport) int supplier(int);
__declspec(dllimport) int body_count(void);
static int controlled_calls;
static int controlled(int argument) {
  if (argument != 3) ExitProcess(42);
  ++controlled_calls;
  return 9;
}
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d\n", __LINE__); return 42; } } while (0)
int main(void) {
  spx_fixture_entry_hook hook = {0};
  const unsigned char good[5] = {0x90,0x90,0x90,0x90,0x90};
  const unsigned char bad[5] = {0x90,0x90,0x90,0x90,0xcc};
  CHECK(supplier(3) == 4 && body_count() == 1);
  CHECK(!spx_fixture_redirect_entry(&hook, "supplier.dll", "supplier", bad, (void (*)(void))controlled));
  CHECK(!spx_fixture_redirect_entry(&hook, "absent.dll", "supplier", good, (void (*)(void))controlled));
  CHECK(!spx_fixture_redirect_body(&hook, "supplier.dll", "supplier", good, 4097, (void (*)(void))controlled));
  CHECK(spx_fixture_redirect_body(&hook, "supplier.dll", "supplier", good, 19, (void (*)(void))controlled));
  for (int i = 5; i < 19; ++i) CHECK(hook.entry[i] == 0xcc);
  CHECK(supplier(3) == 9 && supplier(3) == 9);
  CHECK(body_count() == 1 && controlled_calls == 2);
  CHECK(spx_fixture_restore_entry(&hook));
  CHECK(supplier(3) == 4 && body_count() == 2);
  /* Reviewed internal entries need not be exports. The address variant uses
   * the same prefix/body checks and is used by the Hello routine fixture. */
  unsigned char *entry = (unsigned char *)GetProcAddress(GetModuleHandleA("supplier.dll"), "supplier");
  CHECK(!spx_fixture_redirect_address_body(&hook, NULL, good, 19, (void (*)(void))controlled));
  CHECK(!spx_fixture_redirect_address_body(&hook, entry, bad, 19, (void (*)(void))controlled));
  CHECK(spx_fixture_redirect_address_body(&hook, entry, good, 19, (void (*)(void))controlled));
  CHECK(supplier(3) == 9 && body_count() == 2 && controlled_calls == 3);
  CHECK(spx_fixture_restore_entry(&hook));
  CHECK(supplier(3) == 4 && body_count() == 3);
  /* A real quoting body exceeds the convenience hook's 4 KiB capacity. */
  unsigned char saved[6006];
  unsigned char *large=VirtualAlloc(NULL,sizeof(saved),MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
  CHECK(large!=NULL);memset(large,0x90,6000);
  memcpy(large+6000,"\xb8\x04\0\0\0\xc3",6);
  CHECK(FlushInstructionCache(GetCurrentProcess(),large,sizeof(saved)));
  int (*invoke)(int)=(void *)large;
  CHECK(invoke(3)==4);
  CHECK(!spx_fixture_redirect_address_body_with_storage(&hook,large,good,sizeof(saved),
      (void (*)(void))controlled,saved,sizeof(saved)-1));
  CHECK(!spx_fixture_redirect_address_body_with_storage(&hook,large,good,sizeof(saved),
      (void (*)(void))controlled,large+1,sizeof(saved)));
  CHECK(spx_fixture_redirect_address_body_with_storage(&hook,large,good,sizeof(saved),
      (void (*)(void))controlled,saved,sizeof(saved)));
  for(unsigned i=5;i<sizeof(saved);++i)CHECK(large[i]==0xcc);
  CHECK(invoke(3)==9);
  CHECK(spx_fixture_restore_entry(&hook));
  CHECK(!memcmp(large,saved,sizeof(saved)) && invoke(3)==4);
  CHECK(VirtualFree(large,0,MEM_RELEASE));
  puts("entry bound; supplier body bypassed; original restored");
  return 0;
}
'''


class Pe32EntryHookTests(unittest.TestCase):
    def test_resolved_import_forwarding_rejection_and_restoration(self):
        compiler = fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine')/'bin/spaghetti-headless-wine'
        supplier = r'''
#include <stdlib.h>
__declspec(dllexport) int allocate(unsigned size) {
  void *p = malloc(size);
  if (!p) return 0;
  free(p);
  return 1;
}
'''
        consumer = r'''
#include <stdio.h>
#include "pe32-import-hook.h"
__declspec(dllimport) int allocate(unsigned);
static spx_fixture_import_hook hook;
static unsigned calls;
static void *controlled(size_t size) {
  ++calls;
  return size == 17 ? NULL : ((void *(*)(size_t))(uintptr_t)hook.original)(size);
}
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed line %d\n", __LINE__); return 42; } } while (0)
int main(void) {
  CHECK(allocate(17) == 1);
  CHECK(!spx_fixture_redirect_import(&hook,"absent.dll","msvcrt.dll","malloc",(void(*)(void))controlled));
  CHECK(!spx_fixture_redirect_import(&hook,"supplier.dll","msvcrt.dll","absent",(void(*)(void))controlled));
  CHECK(!spx_fixture_redirect_import(&hook,"supplier.dll","KERNEL32.dll","malloc",(void(*)(void))controlled));
  CHECK(spx_fixture_redirect_import(&hook,"supplier.dll","msvcrt.dll","malloc",(void(*)(void))controlled));
  CHECK(!spx_fixture_redirect_import(&hook,"supplier.dll","msvcrt.dll","malloc",(void(*)(void))controlled));
  spx_fixture_import_hook other = {0};
  CHECK(!spx_fixture_redirect_import(&other,"supplier.dll","msvcrt.dll","malloc",(void(*)(void))controlled));
  CHECK(allocate(17) == 0 && allocate(18) == 1 && calls == 2);
  CHECK(spx_fixture_write_import(hook.slot,hook.original));
  CHECK(!spx_fixture_restore_import(&hook));
  CHECK(spx_fixture_write_import(hook.slot,hook.replacement));
  CHECK(spx_fixture_restore_import(&hook));
  CHECK(!spx_fixture_restore_import(&hook));
  CHECK(allocate(17) == 1 && calls == 2);
  puts("resolved import forwarded; failure injected; stale hook rejected; restored");
  return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='pe32-import-hook-') as temporary:
            root = Path(temporary)
            shutil.copyfile(native_adapter_headers()['pe32-import-hook.h'], root/'pe32-import-hook.h')
            (root/'supplier.c').write_text(supplier)
            (root/'consumer.c').write_text(consumer)
            for arguments in [
                    ['-shared', 'supplier.c', '-Wl,--out-implib,libsupplier.dll.a', '-o', 'supplier.dll'],
                    ['consumer.c', 'libsupplier.dll.a', '-o', 'consumer.exe']]:
                result = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror', *arguments],
                    cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root/'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')
            result = subprocess.run([str(runner), str(root/'consumer.exe')], cwd=root,
                env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('failure injected; stale hook rejected; restored', result.stdout)

    def test_actual_dll_entry_binding_body_bypass_and_restoration(self):
        compiler = fixture('compiler')/'bin/i686-w64-mingw32-gcc'
        runner = fixture('headless-wine')/'bin/spaghetti-headless-wine'
        with tempfile.TemporaryDirectory(prefix='pe32-entry-hook-') as temporary:
            root = Path(temporary)
            shutil.copyfile(native_adapter_headers()['pe32-entry-hook.h'], root/'pe32-entry-hook.h')
            (root/'supplier.c').write_text(SUPPLIER)
            (root/'consumer.c').write_text(CONSUMER)
            commands = [
                ['-shared', 'supplier.c', '-Wl,--out-implib,libsupplier.dll.a', '-o', 'supplier.dll'],
                ['consumer.c', 'libsupplier.dll.a', '-o', 'consumer.exe'],
            ]
            for arguments in commands:
                result = subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror', *arguments],
                    cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
            environment = dict(os.environ, WINEPREFIX=str(root/'wine'), WINEDEBUG='-all',
                WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=')
            result = subprocess.run([str(runner), str(root/'consumer.exe')], cwd=root,
                env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('supplier body bypassed', result.stdout)
