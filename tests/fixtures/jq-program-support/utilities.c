/* Source-assisted from jq 1.8.1 util.c; see COPYING. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "support-inputs.h"
#include "jv_alloc.h"
#include "windows-paths.h"

jv portable_jq_realpath(jv path) {
    /* The pinned PE32 entry always allocates PATH_MAX == 260 bytes. */
    char *buffer = jv_mem_alloc(260);
    if (!spx_path_full(buffer, jv_string_value(path), 260)) {
        jv_mem_free(buffer);
        return path;
    }
    jv_free(path);
    jv result = jv_string(buffer);
    jv_mem_free(buffer);
    return result;
}

/* Keep the original Windows environment policy on every host. The returned
 * value owns a copy; no getenv pointer survives this operation. */
jv portable_get_home(void) {
    const char *home=getenv("HOME");
    if (home) return jv_string(home);
    home=getenv("USERPROFILE");
    if (home) return jv_string(home);
    home=getenv("HOMEPATH");
    if (!home) return jv_invalid_with_msg(jv_string("Could not find home directory."));
    const char *drive=getenv("HOMEDRIVE");
    return jv_string_fmt("%s%s",drive ? drive : "",home);
}

jv portable_expand_path(jv path) {
    assert(jv_get_kind(path)==JV_KIND_STRING);
    const char *text=jv_string_value(path);
    if (jv_string_length_bytes(jv_copy(path))<=1 || text[0]!='~' || text[1]!='/')
        return path;
    jv home=portable_get_home(), result;
    if (jv_is_valid(home)) {
        result=jv_string_fmt("%s/%s",jv_string_value(home),text+2);
        jv_free(home);
    } else {
        jv message=jv_invalid_get_msg(home);
        result=jv_invalid_with_msg(jv_string_fmt("Could not expand %s. (%s)",
            text,jv_string_value(message)));
        jv_free(message);
    }
    jv_free(path);
    return result;
}

const void *portable_jq_memmem(const void *haystack, size_t haystack_length,
                              const void *needle, size_t needle_length) {
    if (!haystack_length || haystack_length<needle_length) return NULL;
    const unsigned char *bytes=haystack;
    for (size_t offset=0; offset<=haystack_length-needle_length; ++offset)
        if (!needle_length || memcmp(bytes+offset,needle,needle_length)==0)
            return bytes+offset;
    return NULL;
}
