#include "portable-component-implementation.h"
#include "ir-inputs.h"
#include "observations.h"
void block_append(block * b, block b2) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.owner0 = b, .block0 = b2};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_append(&context, &input, &output);

}
block block_bind_library(block binder, block body, int bindflags, const char * libname) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binder, .block1 = body, .integer0 = bindflags, .text0 = libname};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_bind_library(&context, &input, &output);
    return output.block;
}
block block_bind_referenced(block binder, block body, int bindflags) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binder, .block1 = body, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_bind_referenced(&context, &input, &output);
    return output.block;
}
block block_bind_self(block binder, int bindflags) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binder, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_bind_self(&context, &input, &output);
    return output.block;
}
jv block_const(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_const(&context, &input, &output);
    return output.value;
}
jv_kind block_const_kind(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_const_kind(&context, &input, &output);
    return output.kind;
}
block block_drop_unreferenced(block body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_drop_unreferenced(&context, &input, &output);
    return output.block;
}
void block_free(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_free(&context, &input, &output);

}
int block_has_main(block top) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = top};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_has_main(&context, &input, &output);
    return output.integer;
}
int block_has_only_binders(block binders, int bindflags) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binders, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_has_only_binders(&context, &input, &output);
    return output.integer;
}
int block_has_only_binders_and_imports(block binders, int bindflags) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binders, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_has_only_binders_and_imports(&context, &input, &output);
    return output.integer;
}
int block_is_const(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_const(&context, &input, &output);
    return output.integer;
}
int block_is_funcdef(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_funcdef(&context, &input, &output);
    return output.integer;
}
int block_is_noop(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_noop(&context, &input, &output);
    return output.integer;
}
int block_is_single(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_single(&context, &input, &output);
    return output.integer;
}
block block_join(block a, block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_join(&context, &input, &output);
    return output.block;
}
jv block_list_funcs(block body, int omit_underscores) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = body, .integer0 = omit_underscores};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_list_funcs(&context, &input, &output);
    return output.value;
}
jv block_module_meta(block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_module_meta(&context, &input, &output);
    return output.value;
}
jv block_take_imports(block * body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.owner0 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_take_imports(&context, &input, &output);
    return output.value;
}
block gen_and(block a, block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_and(&context, &input, &output);
    return output.block;
}
block gen_array_matcher(block left, block curr) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = left, .block1 = curr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_array_matcher(&context, &input, &output);
    return output.block;
}
block gen_both(block a, block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_both(&context, &input, &output);
    return output.block;
}
block gen_call(const char * name, block args) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name, .block0 = args};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_call(&context, &input, &output);
    return output.block;
}
block gen_cbinding(const struct cfunction * cfunctions, int ncfunctions, block code) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.functions0 = cfunctions, .integer0 = ncfunctions, .block0 = code};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_cbinding(&context, &input, &output);
    return output.block;
}
block gen_collect(block expr) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = expr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_collect(&context, &input, &output);
    return output.block;
}
block gen_cond(block cond, block iftrue, block iffalse) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = cond, .block1 = iftrue, .block2 = iffalse};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_cond(&context, &input, &output);
    return output.block;
}
block gen_condbranch(block iftrue, block iffalse) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = iftrue, .block1 = iffalse};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_condbranch(&context, &input, &output);
    return output.block;
}
block gen_const(jv constant) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_const(&context, &input, &output);
    return output.block;
}
block gen_const_global(jv constant, const char * name) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant, .text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_const_global(&context, &input, &output);
    return output.block;
}
block gen_const_object(block expr) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = expr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_const_object(&context, &input, &output);
    return output.block;
}
block gen_definedor(block a, block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_definedor(&context, &input, &output);
    return output.block;
}
block gen_destructure(block var, block matchers, block body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = var, .block1 = matchers, .block2 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_destructure(&context, &input, &output);
    return output.block;
}
block gen_destructure_alt(block matcher) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = matcher};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_destructure_alt(&context, &input, &output);
    return output.block;
}
block gen_dictpair(block k, block v) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = k, .block1 = v};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_dictpair(&context, &input, &output);
    return output.block;
}
block gen_error(jv constant) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_error(&context, &input, &output);
    return output.block;
}
block gen_foreach(block source, block matcher, block init, block update, block extract) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = source, .block1 = matcher, .block2 = init, .block3 = update, .block4 = extract};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_foreach(&context, &input, &output);
    return output.block;
}
block gen_function(const char * name, block formals, block body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name, .block0 = formals, .block1 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_function(&context, &input, &output);
    return output.block;
}
block gen_import(const char * name, const char * as, int is_data) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name, .text1 = as, .integer0 = is_data};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_import(&context, &input, &output);
    return output.block;
}
block gen_import_meta(block import, block metadata) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = import, .block1 = metadata};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_import_meta(&context, &input, &output);
    return output.block;
}
block gen_label(const char * label, block exp) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = label, .block0 = exp};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_label(&context, &input, &output);
    return output.block;
}
block gen_lambda(block body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_lambda(&context, &input, &output);
    return output.block;
}
block gen_location(location loc, struct locfile * l, block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.location0 = loc, .file0 = l, .block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_location(&context, &input, &output);
    return output.block;
}
block gen_module(block metadata) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = metadata};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_module(&context, &input, &output);
    return output.block;
}
block gen_noop(void) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {0};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_noop(&context, &input, &output);
    return output.block;
}
block gen_object_matcher(block name, block curr) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = name, .block1 = curr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_object_matcher(&context, &input, &output);
    return output.block;
}
block gen_op_bound(opcode op, block binder) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .block0 = binder};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_bound(&context, &input, &output);
    return output.block;
}
block gen_op_pushk_under(jv constant) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_pushk_under(&context, &input, &output);
    return output.block;
}
block gen_op_simple(opcode op) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_simple(&context, &input, &output);
    return output.block;
}
block gen_op_target(opcode op, block target) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .block0 = target};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_target(&context, &input, &output);
    return output.block;
}
block gen_op_unbound(opcode op, const char * name) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_unbound(&context, &input, &output);
    return output.block;
}
block gen_op_var_fresh(opcode op, const char * name) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_var_fresh(&context, &input, &output);
    return output.block;
}
block gen_or(block a, block b) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_or(&context, &input, &output);
    return output.block;
}
block gen_param(const char * name) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_param(&context, &input, &output);
    return output.block;
}
block gen_param_regular(const char * name) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_param_regular(&context, &input, &output);
    return output.block;
}
block gen_reduce(block source, block matcher, block init, block body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = source, .block1 = matcher, .block2 = init, .block3 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_reduce(&context, &input, &output);
    return output.block;
}
block gen_subexp(block a) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_subexp(&context, &input, &output);
    return output.block;
}
block gen_try(block exp, block handler) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = exp, .block1 = handler};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_try(&context, &input, &output);
    return output.block;
}
block gen_var_binding(block var, const char * name, block body) {
    static unsigned slot;
    portable_component_entry("compiler-ir", &slot);
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = var, .text0 = name, .block1 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_var_binding(&context, &input, &output);
    return output.block;
}
