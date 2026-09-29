/* Test-only fault below the unchanged original _rpl_malloc/_xmalloc bodies.
 * The pinned PE calls its malloc import from RVA 0x6636 (return RVA 0x663b).
 * Other malloc callers and all real diagnostics/termination remain intact. */
#include "pe32-import-hook.h"
#include "allocation-fault.h"

static spx_fixture_import_hook allocation;
static unsigned char *image;

static void *fault_malloc(size_t size) {
    if (__builtin_return_address(0)==image+0x663b && spx_fault_visit(size)) {
        errno=ENOMEM;
        return NULL;
    }
    void *(*original)(size_t)=(void *)(uintptr_t)allocation.original;
    return original(size);
}

__declspec(dllexport) void spx_hello_allocation_fault(void) {}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void *reserved) {
    (void)module; (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) {
        image=(void *)GetModuleHandleA(NULL);
        spx_fault_begin();
        if (!spx_fixture_redirect_import(&allocation,NULL,"msvcrt.dll","malloc",
                (void (*)(void))fault_malloc)) return FALSE;
    }
    return TRUE;
}
