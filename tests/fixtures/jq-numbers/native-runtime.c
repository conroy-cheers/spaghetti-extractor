#include <stdint.h>
#include <windows.h>
#include "jv.h"
#include "jv_dtoa.h"
#include "jv_dtoa_tsd.h"
#define DECNUMDIGITS 1
#include "decNumber.h"
static void *entry(uint32_t rva) { (void)&jv_is_valid; HMODULE image=GetModuleHandleA("libjq-1.dll"); if(!image)ExitProcess(84); return (unsigned char *)image+rva; }
/* The private getter receives its key address in EAX in the pinned image. */
decContext *spx_decimal_context(void) { typedef decContext *(__attribute__((regparm(1))) *getter)(void *); return ((getter)entry(0x265a0))(entry(0x7501c)); }
decContext * decContextDefault(decContext *context, int32_t kind) { return ((decContext * (*)(decContext *, int32_t))entry(0x46ffc))(context,kind); }
decContext * decContextClearStatus(decContext *context, uint32_t status) { return ((decContext * (*)(decContext *, uint32_t))entry(0x46f70))(context,status); }
decNumber * decNumberFromString(decNumber *out, const char *text, decContext *context) { return ((decNumber * (*)(decNumber *, const char *, decContext *))entry(0x4b19f))(out,text,context); }
decNumber * decNumberReduce(decNumber *out, const decNumber *in, decContext *context) { return ((decNumber * (*)(decNumber *, const decNumber *, decContext *))entry(0x4a7ab))(out,in,context); }
char * decNumberToString(const decNumber *number, char *text) { return ((char * (*)(const decNumber *, char *))entry(0x491a9))(number,text); }
decNumber * decNumberAbs(decNumber *out, const decNumber *in, decContext *context) { return ((decNumber * (*)(decNumber *, const decNumber *, decContext *))entry(0x4c129))(out,in,context); }
decNumber * decNumberMinus(decNumber *out, const decNumber *in, decContext *context) { return ((decNumber * (*)(decNumber *, const decNumber *, decContext *))entry(0x4f87c))(out,in,context); }
decNumber * decNumberCompare(decNumber *out, const decNumber *first, const decNumber *second, decContext *context) { return ((decNumber * (*)(decNumber *, const decNumber *, const decNumber *, decContext *))entry(0x4c52a))(out,first,second,context); }
double jvp_strtod(struct dtoa_context *context, const char *text, char **end) { return ((double (*)(struct dtoa_context *, const char *, char **))entry(0x37041))(context,text,end); }
struct dtoa_context * tsd_dtoa_context_get(void) { return ((struct dtoa_context * (*)(void))entry(0x46ecf))(); }
int jvp_number_is_nan(jv number) { return ((int (*)(jv))entry(0x2737a))(number); }
int jvp_number_cmp(jv first, jv second) { return ((int (*)(jv, jv))entry(0x275fa))(first,second); }
void jvp_number_free(jv number) { ((void (*)(jv))entry(0x26067))(number); }
