#include "portable-component-implementation.h"
#include "ir-inputs.h"
void lifted_compiler_ir_block_append(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_block_append(input->owner0, input->block0);
}
void lifted_compiler_ir_block_bind_library(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_block_bind_library(input->block0, input->block1, input->integer0, input->text0);
}
void lifted_compiler_ir_block_bind_referenced(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_block_bind_referenced(input->block0, input->block1, input->integer0);
}
void lifted_compiler_ir_block_bind_self(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_block_bind_self(input->block0, input->integer0);
}
void lifted_compiler_ir_block_const(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_block_const(input->block0);
}
void lifted_compiler_ir_block_const_kind(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->kind = portable_block_const_kind(input->block0);
}
void lifted_compiler_ir_block_drop_unreferenced(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_block_drop_unreferenced(input->block0);
}
void lifted_compiler_ir_block_free(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    portable_block_free(input->block0);
}
void lifted_compiler_ir_block_has_main(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_has_main(input->block0);
}
void lifted_compiler_ir_block_has_only_binders(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_has_only_binders(input->block0, input->integer0);
}
void lifted_compiler_ir_block_has_only_binders_and_imports(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_has_only_binders_and_imports(input->block0, input->integer0);
}
void lifted_compiler_ir_block_is_const(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_is_const(input->block0);
}
void lifted_compiler_ir_block_is_funcdef(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_is_funcdef(input->block0);
}
void lifted_compiler_ir_block_is_noop(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_is_noop(input->block0);
}
void lifted_compiler_ir_block_is_single(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->integer = portable_block_is_single(input->block0);
}
void lifted_compiler_ir_block_join(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_block_join(input->block0, input->block1);
}
void lifted_compiler_ir_block_list_funcs(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_block_list_funcs(input->block0, input->integer0);
}
void lifted_compiler_ir_block_module_meta(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_block_module_meta(input->block0);
}
void lifted_compiler_ir_block_take_imports(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->value = portable_block_take_imports(input->owner0);
}
void lifted_compiler_ir_gen_and(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_and(input->block0, input->block1);
}
void lifted_compiler_ir_gen_array_matcher(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_array_matcher(input->block0, input->block1);
}
void lifted_compiler_ir_gen_both(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_both(input->block0, input->block1);
}
void lifted_compiler_ir_gen_call(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_call(input->text0, input->block0);
}
void lifted_compiler_ir_gen_cbinding(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_cbinding(input->functions0, input->integer0, input->block0);
}
void lifted_compiler_ir_gen_collect(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_collect(input->block0);
}
void lifted_compiler_ir_gen_cond(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_cond(input->block0, input->block1, input->block2);
}
void lifted_compiler_ir_gen_condbranch(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_condbranch(input->block0, input->block1);
}
void lifted_compiler_ir_gen_const(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_const(input->value0);
}
void lifted_compiler_ir_gen_const_global(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_const_global(input->value0, input->text0);
}
void lifted_compiler_ir_gen_const_object(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_const_object(input->block0);
}
void lifted_compiler_ir_gen_definedor(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_definedor(input->block0, input->block1);
}
void lifted_compiler_ir_gen_destructure(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_destructure(input->block0, input->block1, input->block2);
}
void lifted_compiler_ir_gen_destructure_alt(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_destructure_alt(input->block0);
}
void lifted_compiler_ir_gen_dictpair(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_dictpair(input->block0, input->block1);
}
void lifted_compiler_ir_gen_error(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_error(input->value0);
}
void lifted_compiler_ir_gen_foreach(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_foreach(input->block0, input->block1, input->block2, input->block3, input->block4);
}
void lifted_compiler_ir_gen_function(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_function(input->text0, input->block0, input->block1);
}
void lifted_compiler_ir_gen_import(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_import(input->text0, input->text1, input->integer0);
}
void lifted_compiler_ir_gen_import_meta(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_import_meta(input->block0, input->block1);
}
void lifted_compiler_ir_gen_label(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_label(input->text0, input->block0);
}
void lifted_compiler_ir_gen_lambda(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_lambda(input->block0);
}
void lifted_compiler_ir_gen_location(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_location(input->location0, input->file0, input->block0);
}
void lifted_compiler_ir_gen_module(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_module(input->block0);
}
void lifted_compiler_ir_gen_noop(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_noop();
}
void lifted_compiler_ir_gen_object_matcher(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_object_matcher(input->block0, input->block1);
}
void lifted_compiler_ir_gen_op_bound(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_op_bound(input->opcode0, input->block0);
}
void lifted_compiler_ir_gen_op_pushk_under(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_op_pushk_under(input->value0);
}
void lifted_compiler_ir_gen_op_simple(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_op_simple(input->opcode0);
}
void lifted_compiler_ir_gen_op_target(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_op_target(input->opcode0, input->block0);
}
void lifted_compiler_ir_gen_op_unbound(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_op_unbound(input->opcode0, input->text0);
}
void lifted_compiler_ir_gen_op_var_fresh(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_op_var_fresh(input->opcode0, input->text0);
}
void lifted_compiler_ir_gen_or(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_or(input->block0, input->block1);
}
void lifted_compiler_ir_gen_param(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_param(input->text0);
}
void lifted_compiler_ir_gen_param_regular(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_param_regular(input->text0);
}
void lifted_compiler_ir_gen_reduce(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_reduce(input->block0, input->block1, input->block2, input->block3);
}
void lifted_compiler_ir_gen_subexp(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_subexp(input->block0);
}
void lifted_compiler_ir_gen_try(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_try(input->block0, input->block1);
}
void lifted_compiler_ir_gen_var_binding(spx_compiler_ir_context_v5 *context,
    struct spx_opaque_ir_input_v5 *input, struct spx_opaque_ir_output_v5 *output) {
    (void)context; (void)input; (void)output; (void)&jv_is_valid;
    output->block = portable_gen_var_binding(input->block0, input->text0, input->block1);
}
