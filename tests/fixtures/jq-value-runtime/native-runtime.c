#include <stdint.h>
#include <windows.h>
#include "jv.h"
#include "jv_unicode.h"
static void *entry(uint32_t rva) { (void)&jv_is_valid; HMODULE image=GetModuleHandleA("libjq-1.dll"); if(!image)ExitProcess(84); return (unsigned char *)image+rva; }
uint32_t spx_string_hash_seed(void) { return ((uint32_t (*)(void))entry(0x2627b))(); }
/* Fix both native sides to one reviewed seed before any keys are created. */
void spx_test_hash_seed(uint32_t seed) { (void)spx_string_hash_seed(); *(uint32_t *)entry(0x75014)=seed; }
jv jvp_object_new(int size) { typedef void (__attribute__((regparm(2))) *create_fn)(jv *,int); jv output; ((create_fn)entry(0x25f23))(&output,size); return output; }
jv jvp_object_unshare(jv value) { typedef void (__attribute__((regparm(1))) *unshare_fn)(jv *,jv); jv output; ((unshare_fn)entry(0x2a7e3))(&output,value); return output; }
const char * jvp_utf8_next(const char *first, const char *last, int *code) { return ((const char * (*)(const char *, const char *, int *))entry(0x3fcf9))(first,last,code); }
int jvp_utf8_is_valid(const char *first, const char *last) { return ((int (*)(const char *, const char *))entry(0x3fe35))(first,last); }
int jvp_utf8_encode(int code, char *buffer) { return ((int (*)(int, char *))entry(0x3fedf))(code,buffer); }
void jvp_string_free(jv value) { ((void (*)(jv))entry(0x26021))(value); }
void jvp_invalid_free(jv value) { ((void (*)(jv))entry(0x2ba29))(value); }
void spx_value_array_release(jv value) { ((void (*)(jv))entry(0x281a2))(value); }
void jvp_number_free(jv value) { ((void (*)(jv))entry(0x26067))(value); }
void jvp_object_free(jv value) { ((void (*)(jv))entry(0x2a696))(value); }

jv parse_slice(jv value,jv slice,int *start,int *end) {
    typedef void (__attribute__((regparm(1))) *slice_fn)(jv *,jv,jv,int *,int *);
    jv result; ((slice_fn)entry(0x2d816))(&result,value,slice,start,end); return result;
}
