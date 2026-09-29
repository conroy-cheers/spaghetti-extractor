#ifndef SPX_JQ_VALUE_RUNTIME_INPUTS_H
#define SPX_JQ_VALUE_RUNTIME_INPUTS_H
#include "jv.h"
struct spx_opaque_value_input_v5 { jv first, second, third; const char *text; int count; uint32_t codepoint; jv_kind kind; va_list *args; int *start, *end; };
struct spx_opaque_value_output_v5 { jv value; const char *text; int integer; unsigned long hash; jv_kind kind; };
jv_kind portable_jv_get_kind(jv first);
const char * portable_jv_kind_name(jv_kind kind);
jv portable_jv_true(void);
jv portable_jv_false(void);
jv portable_jv_null(void);
jv portable_jv_bool(int count);
jv portable_jv_invalid(void);
jv portable_jv_invalid_with_msg(jv first);
jv portable_jv_invalid_get_msg(jv first);
int portable_jv_invalid_has_msg(jv first);
void portable_jvp_invalid_free(jv first);
jv portable_jv_array(void);
jv portable_jv_array_append(jv first, jv second);
jv portable_jv_array_concat(jv first, jv second);
jv portable_jv_string_sized(const char *text, int count);
jv portable_jv_string_empty(int count);
jv portable_jv_string(const char *text);
jv portable_jv_string_repeat(jv first, int count);
jv portable_jv_string_explode(jv first);
jv portable_jv_string_implode(jv first);
unsigned long portable_jv_string_hash(jv first);
const char * portable_jv_string_value(jv first);
jv portable_jv_string_concat(jv first, jv second);
jv portable_jv_string_append_buf(jv first, const char *text, int count);
jv portable_jv_string_append_codepoint(jv first, uint32_t codepoint);
jv portable_jv_string_append_str(jv first, const char *text);
jv portable_jv_string_vfmt(const char *text, va_list args);
void portable_jvp_string_free(jv first);
jv portable_jv_object(void);
int portable_jv_object_has(jv first, jv second);
jv portable_jv_object_set(jv first, jv second, jv third);
int portable_jv_object_length(jv first);
int portable_jv_object_iter(jv first);
int portable_jv_object_iter_valid(jv first, int count);
int portable_jv_object_iter_next(jv first, int count);
jv portable_jv_object_iter_key(jv first, int count);
jv portable_jv_object_iter_value(jv first, int count);
int portable_jv_get_refcnt(jv first);
void portable_jv_free(jv value);
jv portable_parse_slice(jv value, jv slice, int *start, int *end);
#endif
