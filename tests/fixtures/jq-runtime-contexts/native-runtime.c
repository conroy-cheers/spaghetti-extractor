#include <windows.h>
#include "context-inputs.h"
#include "context-services.h"
void *spx_native_address(uint32_t rva) { HMODULE module=GetModuleHandleA("libjq-1.dll"); if (!module) ExitProcess(84); return (unsigned char *)module+rva; }
int spx_context_atexit(void (*cleanup)(void)) {
    return ((int (*)(void (*)(void)))spx_native_address(0x1340))(cleanup);
}
void jv_tsd_dec_ctx_init(void) { ((void (*)(void))spx_native_address(0x26144))(); }
void jv_tsd_dec_ctx_fini(void) { ((void (*)(void))spx_native_address(0x26111))(); }
decContext * spx_native_decimal_context(void) { typedef decContext *(__attribute__((regparm(1))) *getter)(void *); return ((getter)spx_native_address(0x265a0))(spx_native_address(0x7501c)); }
void jv_tsd_dtoa_ctx_init(void) { ((void (*)(void))spx_native_address(0x46e70))(); }
void jv_tsd_dtoa_ctx_fini(void) { ((void (*)(void))spx_native_address(0x46e3d))(); }
struct dtoa_context * tsd_dtoa_context_get(void) { return ((struct dtoa_context * (*)(void))spx_native_address(0x46ecf))(); }
uint32_t jvp_hash_seed(void) { return ((uint32_t (*)(void))spx_native_address(0x2627b))(); }
decContext * decContextDefault(decContext *context, int32_t kind) { return ((decContext * (*)(decContext *context, int32_t kind))spx_native_address(0x46ffc))(context,kind); }
void jvp_dtoa_context_init(struct dtoa_context *context) { ((void (*)(struct dtoa_context *context))spx_native_address(0x36f83))(context); }
void jvp_dtoa_context_free(struct dtoa_context *context) { ((void (*)(struct dtoa_context *context))spx_native_address(0x36ff6))(context); }
