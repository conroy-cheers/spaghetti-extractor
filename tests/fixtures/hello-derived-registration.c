#include <windows.h>

typedef void (*mingw_key_destructor)(void *);

extern int mingw_add_key_destructor(
    DWORD key,
    mingw_key_destructor destructor
) __asm__("____w64_mingwthr_add_key_dtor");

extern int mingw_tls_callback(
    HINSTANCE module,
    DWORD reason,
    void *reserved
) __asm__("___mingw_TLScallback");

static DWORD fixture_key = TLS_OUT_OF_INDEXES;
static volatile LONG destructor_runs;

static void registered_destructor(void *value) {
    static const char message[] = "registered destructor ran\n";
    DWORD written = 0;

    if (value != (void *)(UINT_PTR)0x1234) {
        ExitProcess(31);
    }
    /* The callback is driven synchronously on this thread in this fixture. */
    destructor_runs += 1;
    TlsSetValue(fixture_key, NULL);
    WriteFile(
        GetStdHandle(STD_OUTPUT_HANDLE),
        message,
        (DWORD)(sizeof(message) - 1),
        &written,
        NULL
    );
}

int main(void) {
    /*
     * The loader has already delivered process attach in a native run.  Repeat
     * it here because the execution-closure root is intentionally analyzable
     * without assuming hidden loader state; MinGW's callback is idempotent for
     * an initialized process.  Thread detach below must therefore be connected
     * to registration by ordinary machine-visible state.
     */
    if (!mingw_tls_callback(NULL, DLL_PROCESS_ATTACH, NULL)) {
        return 20;
    }
    fixture_key = TlsAlloc();
    if (fixture_key == TLS_OUT_OF_INDEXES) {
        return 21;
    }
    if (!TlsSetValue(fixture_key, (void *)(UINT_PTR)0x1234)) {
        return 22;
    }
    if (mingw_add_key_destructor(fixture_key, registered_destructor) != 0) {
        return 23;
    }

    /* Drive the same MinGW thread-detach path the loader invokes. */
    if (!mingw_tls_callback(NULL, DLL_THREAD_DETACH, NULL)) {
        return 24;
    }
    if (destructor_runs != 1) {
        return 25;
    }
    TlsFree(fixture_key);
    return 0;
}
