#include "portable-component-implementation.h"
#include "ir-inputs.h"
/* Internal native callers can retain volatile GPRs across known leaf calls.
 * Preserve them in the comparison adapter; portable production entries use
 * their platform ABI without this target-specific attribute. */
#define NATIVE_ENTRY __attribute__((no_caller_saved_registers, target("general-regs-only")))
void spx_observe_ir_entry(const char *);
NATIVE_ENTRY void spx_entry_block_append(block * b, block b2) {
    spx_observe_ir_entry("block_append");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.owner0 = b, .block0 = b2};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_append(&context, &input, &output);

}
NATIVE_ENTRY block spx_entry_block_bind_library(block binder, block body, int bindflags, const char * libname) {
    spx_observe_ir_entry("block_bind_library");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binder, .block1 = body, .integer0 = bindflags, .text0 = libname};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_bind_library(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_block_bind_referenced(block binder, block body, int bindflags) {
    spx_observe_ir_entry("block_bind_referenced");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binder, .block1 = body, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_bind_referenced(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_block_bind_self(block binder, int bindflags) {
    spx_observe_ir_entry("block_bind_self");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binder, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_bind_self(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY jv spx_entry_block_const(block b) {
    spx_observe_ir_entry("block_const");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_const(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv_kind spx_entry_block_const_kind(block b) {
    spx_observe_ir_entry("block_const_kind");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_const_kind(&context, &input, &output);
    return output.kind;
}
NATIVE_ENTRY block spx_entry_block_drop_unreferenced(block body) {
    spx_observe_ir_entry("block_drop_unreferenced");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_drop_unreferenced(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY void spx_entry_block_free(block b) {
    spx_observe_ir_entry("block_free");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_free(&context, &input, &output);

}
NATIVE_ENTRY int spx_entry_block_has_main(block top) {
    spx_observe_ir_entry("block_has_main");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = top};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_has_main(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_block_has_only_binders(block binders, int bindflags) {
    spx_observe_ir_entry("block_has_only_binders");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binders, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_has_only_binders(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_block_has_only_binders_and_imports(block binders, int bindflags) {
    spx_observe_ir_entry("block_has_only_binders_and_imports");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = binders, .integer0 = bindflags};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_has_only_binders_and_imports(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_block_is_const(block b) {
    spx_observe_ir_entry("block_is_const");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_const(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_block_is_funcdef(block b) {
    spx_observe_ir_entry("block_is_funcdef");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_funcdef(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_block_is_noop(block b) {
    spx_observe_ir_entry("block_is_noop");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_noop(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY int spx_entry_block_is_single(block b) {
    spx_observe_ir_entry("block_is_single");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_is_single(&context, &input, &output);
    return output.integer;
}
NATIVE_ENTRY block spx_entry_block_join(block a, block b) {
    spx_observe_ir_entry("block_join");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_join(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY jv spx_entry_block_list_funcs(block body, int omit_underscores) {
    spx_observe_ir_entry("block_list_funcs");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = body, .integer0 = omit_underscores};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_list_funcs(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_block_module_meta(block b) {
    spx_observe_ir_entry("block_module_meta");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_module_meta(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY jv spx_entry_block_take_imports(block * body) {
    spx_observe_ir_entry("block_take_imports");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.owner0 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_block_take_imports(&context, &input, &output);
    return output.value;
}
NATIVE_ENTRY block spx_entry_gen_and(block a, block b) {
    spx_observe_ir_entry("gen_and");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_and(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_array_matcher(block left, block curr) {
    spx_observe_ir_entry("gen_array_matcher");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = left, .block1 = curr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_array_matcher(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_both(block a, block b) {
    spx_observe_ir_entry("gen_both");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_both(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_call(const char * name, block args) {
    spx_observe_ir_entry("gen_call");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name, .block0 = args};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_call(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_cbinding(const struct cfunction * cfunctions, int ncfunctions, block code) {
    spx_observe_ir_entry("gen_cbinding");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.functions0 = cfunctions, .integer0 = ncfunctions, .block0 = code};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_cbinding(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_collect(block expr) {
    spx_observe_ir_entry("gen_collect");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = expr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_collect(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_cond(block cond, block iftrue, block iffalse) {
    spx_observe_ir_entry("gen_cond");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = cond, .block1 = iftrue, .block2 = iffalse};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_cond(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_condbranch(block iftrue, block iffalse) {
    spx_observe_ir_entry("gen_condbranch");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = iftrue, .block1 = iffalse};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_condbranch(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_const(jv constant) {
    spx_observe_ir_entry("gen_const");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_const(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_const_global(jv constant, const char * name) {
    spx_observe_ir_entry("gen_const_global");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant, .text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_const_global(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_const_object(block expr) {
    spx_observe_ir_entry("gen_const_object");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = expr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_const_object(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_definedor(block a, block b) {
    spx_observe_ir_entry("gen_definedor");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_definedor(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_destructure(block var, block matchers, block body) {
    spx_observe_ir_entry("gen_destructure");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = var, .block1 = matchers, .block2 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_destructure(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_destructure_alt(block matcher) {
    spx_observe_ir_entry("gen_destructure_alt");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = matcher};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_destructure_alt(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_dictpair(block k, block v) {
    spx_observe_ir_entry("gen_dictpair");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = k, .block1 = v};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_dictpair(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_error(jv constant) {
    spx_observe_ir_entry("gen_error");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_error(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_foreach(block source, block matcher, block init, block update, block extract) {
    spx_observe_ir_entry("gen_foreach");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = source, .block1 = matcher, .block2 = init, .block3 = update, .block4 = extract};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_foreach(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_function(const char * name, block formals, block body) {
    spx_observe_ir_entry("gen_function");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name, .block0 = formals, .block1 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_function(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_import(const char * name, const char * as, int is_data) {
    spx_observe_ir_entry("gen_import");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name, .text1 = as, .integer0 = is_data};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_import(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_import_meta(block import, block metadata) {
    spx_observe_ir_entry("gen_import_meta");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = import, .block1 = metadata};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_import_meta(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_label(const char * label, block exp) {
    spx_observe_ir_entry("gen_label");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = label, .block0 = exp};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_label(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_lambda(block body) {
    spx_observe_ir_entry("gen_lambda");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_lambda(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_location(location loc, struct locfile * l, block b) {
    spx_observe_ir_entry("gen_location");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.location0 = loc, .file0 = l, .block0 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_location(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_module(block metadata) {
    spx_observe_ir_entry("gen_module");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = metadata};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_module(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_noop(void) {
    spx_observe_ir_entry("gen_noop");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {0};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_noop(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_object_matcher(block name, block curr) {
    spx_observe_ir_entry("gen_object_matcher");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = name, .block1 = curr};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_object_matcher(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_op_bound(opcode op, block binder) {
    spx_observe_ir_entry("gen_op_bound");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .block0 = binder};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_bound(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_op_pushk_under(jv constant) {
    spx_observe_ir_entry("gen_op_pushk_under");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.value0 = constant};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_pushk_under(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_op_simple(opcode op) {
    spx_observe_ir_entry("gen_op_simple");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_simple(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_op_target(opcode op, block target) {
    spx_observe_ir_entry("gen_op_target");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .block0 = target};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_target(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_op_unbound(opcode op, const char * name) {
    spx_observe_ir_entry("gen_op_unbound");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_unbound(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_op_var_fresh(opcode op, const char * name) {
    spx_observe_ir_entry("gen_op_var_fresh");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.opcode0 = op, .text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_op_var_fresh(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_or(block a, block b) {
    spx_observe_ir_entry("gen_or");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a, .block1 = b};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_or(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_param(const char * name) {
    spx_observe_ir_entry("gen_param");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_param(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_param_regular(const char * name) {
    spx_observe_ir_entry("gen_param_regular");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.text0 = name};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_param_regular(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_reduce(block source, block matcher, block init, block body) {
    spx_observe_ir_entry("gen_reduce");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = source, .block1 = matcher, .block2 = init, .block3 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_reduce(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_subexp(block a) {
    spx_observe_ir_entry("gen_subexp");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = a};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_subexp(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_try(block exp, block handler) {
    spx_observe_ir_entry("gen_try");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = exp, .block1 = handler};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_try(&context, &input, &output);
    return output.block;
}
NATIVE_ENTRY block spx_entry_gen_var_binding(block var, const char * name, block body) {
    spx_observe_ir_entry("gen_var_binding");
    spx_compiler_ir_context_v5 context = {0};
    struct spx_opaque_ir_input_v5 input = {.block0 = var, .text0 = name, .block1 = body};
    struct spx_opaque_ir_output_v5 output;
    (void)&jv_is_valid;
    lifted_compiler_ir_gen_var_binding(&context, &input, &output);
    return output.block;
}
