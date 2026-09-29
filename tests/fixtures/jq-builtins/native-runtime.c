#include <stdint.h>
#include <windows.h>
#include "compile.h"
#include "jq_parser.h"
#include "jv_unicode.h"
#include "jv_dtoa.h"
#include "jv_dtoa_tsd.h"
#include "jv_private.h"
#include <time.h>
static void *entry(uint32_t rva) { (void)&jv_is_valid; HMODULE image=GetModuleHandleA("libjq-1.dll"); if(!image)ExitProcess(84); return (unsigned char *)image+rva; }
void block_append(block * b, block b2) { ((void (*)(block *, block))entry(0x158c0))(b, b2); }
block block_bind_library(block binder, block body, int bindflags, const char * libname) { return ((block (*)(block, block, int, const char *))entry(0x15bdd))(binder, body, bindflags, libname); }
block block_bind_referenced(block binder, block body, int bindflags) { return ((block (*)(block, block, int))entry(0x16d9a))(binder, body, bindflags); }
block block_bind_self(block binder, int bindflags) { return ((block (*)(block, int))entry(0x15d7a))(binder, bindflags); }
jv block_const(block b) { return ((jv (*)(block))entry(0x15600))(b); }
jv_kind block_const_kind(block b) { return ((jv_kind (*)(block))entry(0x155a2))(b); }
block block_drop_unreferenced(block body) { return ((block (*)(block))entry(0x16f0d))(body); }
void block_free(block b) { ((void (*)(block))entry(0x16d7a))(b); }
int block_has_main(block top) { return ((int (*)(block))entry(0x1675f))(top); }
int block_has_only_binders(block binders, int bindflags) { return ((int (*)(block, int))entry(0x15a1e))(binders, bindflags); }
int block_has_only_binders_and_imports(block binders, int bindflags) { return ((int (*)(block, int))entry(0x159cb))(binders, bindflags); }
int block_is_const(block b) { return ((int (*)(block))entry(0x15575))(b); }
int block_is_funcdef(block b) { return ((int (*)(block))entry(0x16786))(b); }
int block_is_noop(block b) { return ((int (*)(block))entry(0x152f2))(b); }
int block_is_single(block b) { return ((int (*)(block))entry(0x14f0f))(b); }
block block_join(block a, block b) { return ((block (*)(block, block))entry(0x15900))(a, b); }
jv block_list_funcs(block body, int omit_underscores) { return ((jv (*)(block, int))entry(0x15e2f))(body, omit_underscores); }
jv block_module_meta(block b) { return ((jv (*)(block))entry(0x15fa6))(b); }
jv block_take_imports(block * body) { return ((jv (*)(block *))entry(0x16f7c))(body); }
block gen_and(block a, block b) { return ((block (*)(block, block))entry(0x1683d))(a, b); }
block gen_array_matcher(block left, block curr) { return ((block (*)(block, block))entry(0x174b7))(left, curr); }
block gen_both(block a, block b) { return ((block (*)(block, block))entry(0x1631f))(a, b); }
block gen_call(const char * name, block args) { return ((block (*)(const char *, block))entry(0x162e2))(name, args); }
block gen_cbinding(const struct cfunction * cfunctions, int ncfunctions, block code) { return ((block (*)(const struct cfunction *, int, block))entry(0x16cf3))(cfunctions, ncfunctions, code); }
block gen_collect(block expr) { return ((block (*)(block))entry(0x18569))(expr); }
block gen_cond(block cond, block iftrue, block iffalse) { return ((block (*)(block, block, block))entry(0x17754))(cond, iftrue, iffalse); }
block gen_condbranch(block iftrue, block iffalse) { return ((block (*)(block, block))entry(0x1679c))(iftrue, iffalse); }
block gen_const(jv constant) { return ((block (*)(jv))entry(0x153d4))(constant); }
block gen_const_global(jv constant, const char * name) { return ((block (*)(jv, const char *))entry(0x15451))(constant, name); }
block gen_const_object(block expr) { return ((block (*)(block))entry(0x17fa2))(expr); }
block gen_definedor(block a, block b) { return ((block (*)(block, block))entry(0x163c2))(a, b); }
block gen_destructure(block var, block matchers, block body) { return ((block (*)(block, block, block))entry(0x18ef8))(var, matchers, body); }
block gen_destructure_alt(block matcher) { return ((block (*)(block))entry(0x16b77))(matcher); }
block gen_dictpair(block k, block v) { return ((block (*)(block, block))entry(0x1742c))(k, v); }
block gen_error(jv constant) { return ((block (*)(jv))entry(0x15354))(constant); }
block gen_foreach(block source, block matcher, block init, block update, block extract) { return ((block (*)(block, block, block, block, block))entry(0x18d09))(source, matcher, init, update, extract); }
block gen_function(const char * name, block formals, block body) { return ((block (*)(const char *, block, block))entry(0x19079))(name, formals, body); }
block gen_import(const char * name, const char * as, int is_data) { return ((block (*)(const char *, const char *, int))entry(0x15ff7))(name, as, is_data); }
block gen_import_meta(block import, block metadata) { return ((block (*)(block, block))entry(0x17222))(import, metadata); }
block gen_label(const char * label, block exp) { return ((block (*)(const char *, block))entry(0x191db))(label, exp); }
block gen_lambda(block body) { return ((block (*)(block))entry(0x191a7))(body); }
block gen_location(location loc, struct locfile * l, block b) { return ((block (*)(location, struct locfile *, block))entry(0x151f3))(loc, l, b); }
block gen_module(block metadata) { return ((block (*)(block))entry(0x170ab))(metadata); }
block gen_noop(void) { return ((block (*)(void))entry(0x15262))(); }
block gen_object_matcher(block name, block curr) { return ((block (*)(block, block))entry(0x176b5))(name, curr); }
block gen_op_bound(opcode op, block binder) { return ((block (*)(opcode, block))entry(0x15865))(op, binder); }
block gen_op_pushk_under(jv constant) { return ((block (*)(jv))entry(0x154f5))(constant); }
block gen_op_simple(opcode op) { return ((block (*)(opcode))entry(0x15311))(op); }
block gen_op_target(opcode op, block target) { return ((block (*)(opcode, block))entry(0x1566a))(op, target); }
block gen_op_unbound(opcode op, const char * name) { return ((block (*)(opcode, const char *))entry(0x157b9))(op, name); }
block gen_op_var_fresh(opcode op, const char * name) { return ((block (*)(opcode, const char *))entry(0x15818))(op, name); }
block gen_or(block a, block b) { return ((block (*)(block, block))entry(0x169da))(a, b); }
block gen_param(const char * name) { return ((block (*)(const char *))entry(0x162c7))(name); }
block gen_param_regular(const char * name) { return ((block (*)(const char *))entry(0x162ac))(name); }
block gen_reduce(block source, block matcher, block init, block body) { return ((block (*)(block, block, block, block))entry(0x18ae0))(source, matcher, init, body); }
block gen_subexp(block a) { return ((block (*)(block))entry(0x1734a))(a); }
block gen_try(block exp, block handler) { return ((block (*)(block, block))entry(0x16bcd))(exp, handler); }
block gen_var_binding(block var, const char * name, block body) { return ((block (*)(block, const char *, block))entry(0x1902e))(var, name, body); }
struct locfile * locfile_init(jq_state * state, const char * name, const char * text, int size) { return ((struct locfile * (*)(jq_state *, const char *, const char *, int))entry(0x442ea))(state, name, text, size); }
void locfile_free(struct locfile * file) { ((void (*)(struct locfile *))entry(0x44419))(file); }
int jq_parse_library(struct locfile * file, block * program) { return ((int (*)(struct locfile *, block *))entry(0x588af))(file, program); }
jv load_module_meta(jq_state * state, jv value) { return ((jv (*)(jq_state *, jv))entry(0x436ee))(state, value); }
jv _jq_path_append(jq_state *state, jv value, jv key, jv result) { return ((jv (*)(jq_state *,jv,jv,jv))entry(0x1b71b))(state,value,key,result); }
const char * jvp_utf8_next(const char * first, const char * end, int * code) { return ((const char * (*)(const char *, const char *, int *))entry(0x3fcf9))(first, end, code); }
int jvp_utf8_encode(int value, char * out) { return ((int (*)(int, char *))entry(0x3fedf))(value, out); }
double jvp_strtod(struct dtoa_context * ctx, const char * text, char ** end) { return ((double (*)(struct dtoa_context *, const char *, char **))entry(0x37041))(ctx, text, end); }
struct dtoa_context * tsd_dtoa_context_get(void) { return ((struct dtoa_context * (*)(void))entry(0x46ecf))(); }
char *strptime(const char *text, const char *format, struct tm *time) { return ((char *(*)(const char *,const char *,struct tm *))entry(0x45e5e))(text,format,time); }
int jvp_utf8_is_valid(const char *text, const char *end) { return ((int (*)(const char *,const char *))entry(0x3fe35))(text,end); }
int jvp_utf8_decode_length(char first) { return ((int (*)(char))entry(0x3fe76))(first); }
int jvp_codepoint_is_whitespace(int value) { return ((int (*)(int))entry(0x3ffce))(value); }
const char *jvp_utf8_backtrack(const char *first, const char *end, int *missing) { return ((const char *(*)(const char *,const char *,int *))entry(0x3fc60))(first,end,missing); }
int jvp_number_is_nan(jv value) { return ((int (*)(jv))entry(0x2737a))(value); }
