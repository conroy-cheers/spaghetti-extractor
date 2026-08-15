"""C source rendering for Stage B interpreter packages."""

from __future__ import annotations

from .c_backend import _runtime_header, _runtime_helpers
from .interpreter_model import (
    StageBInterpreterError,
    _Action,
    _Node,
    _Transfer,
)
from .interpreter_values import _c_string


def _interpreter_runtime_header() -> str:
    header = _runtime_header()
    replay_record = """#define STAGE_B_MACHINE_STATE_HAS_X87 1

typedef struct stage_b_typed_x87_operation {
  uint32_t image_base, rva_start, rva_end, source_size;
  const char *operation_identity;
  const char *contract_sha256;
  const char *checked_decoder;
  const char *checked_executor;
  const char *mnemonic;
  uint32_t operand_kind, operand_width;
  uint32_t stack_register_count, stack_register_0, stack_register_1;
  uint32_t base_register, index_register, scale;
  int32_t displacement;
  uint32_t image_rva, has_image_rva;
} stage_b_typed_x87_operation;

"""
    replay_handler = """typedef stage_b_call_status (*stage_b_typed_x87_handler)(
    stage_b_runtime *runtime,
    const stage_b_typed_x87_operation *program,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

"""
    replacements = (
        (
            "typedef struct stage_b_runtime stage_b_runtime;\n",
            replay_record + "typedef struct stage_b_runtime stage_b_runtime;\n",
        ),
        (
            "typedef uint32_t (*stage_b_code_target_resolver)(\n",
            replay_handler + "typedef uint32_t (*stage_b_code_target_resolver)(\n",
        ),
        (
            "  stage_b_code_target_resolver resolve_code_target;\n",
            "  stage_b_code_target_resolver resolve_code_target;\n"
            "  stage_b_typed_x87_handler execute_typed_x87_operation;\n",
        ),
    )
    for old, new in replacements:
        if old not in header:
            raise StageBInterpreterError(
                "shared runtime header changed before x87 replay ABI injection",
                code="interpreter_runtime_abi_drift",
                next_action="reconcile the interpreter replay ABI with stage_b_c_backend",
            )
        header = header.replace(old, new, 1)
    return header


def _interpreter_header() -> str:
    return """#ifndef STAGE_B_SEMANTIC_INTERPRETER_H
#define STAGE_B_SEMANTIC_INTERPRETER_H

#include "state-machine-runtime.h"

typedef struct stage_b_program_transfer stage_b_program_transfer;
typedef stage_b_step_result (*stage_b_region_override_fn)(
    stage_b_runtime *, stage_b_machine_state *);
typedef struct stage_b_region_override {
  uint32_t entry_rva;
  stage_b_region_override_fn function;
  uint32_t fallback_on_unimplemented;
  const char *replacement_id;
  const char *cluster_id;
} stage_b_region_override;

const stage_b_program_transfer *stage_b_program_lookup(uint32_t source_rva);
const stage_b_region_override *stage_b_region_override_lookup(uint32_t entry_rva);
uint32_t stage_b_native_machine_fallback_allowed(uint32_t source_rva)
    __attribute__((weak));
stage_b_step_result stage_b_interpreter_step(
    stage_b_runtime *runtime, stage_b_machine_state *state, uint32_t source_rva);
stage_b_call_status stage_b_run_function(
    stage_b_runtime *runtime, uint32_t entry_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output);

#endif
"""


# The opcode/action enums and evaluator are emitted from the same fixed table as
# the data source.  Keeping this kernel invariant is the main cache boundary.
_WORD_OPS = (
    "const", "reg", "flag", "true", "false", "undefined_bv", "undefined_flag",
    "call_response", "call_flag", "load", "sub32", "ult32", "eq", "xor_bool",
    "eq_bool", "add32", "mul32", "xor32", "and32", "or32", "not32", "neg32",
    "shl32", "lshr32", "sar", "sign_extend", "ite", "msb", "not", "and_bool",
    "or_bool", "parity", "bool_to_bit", "add_overflow", "sub_overflow",
    "imul_low32", "mul_low32", "imul_high32", "mul_high32", "imul_overflow",
    "mul_carry", "udiv_quot32", "udiv_rem32", "udiv_valid32", "bsr_index",
    "tzcnt", "sbb_borrow", "sbb_overflow", "shift_cf", "shift_of",
    "fpu_control", "fpu_control_init", "fpu_status", "fpu_status_init", "fpu_tag",
    "fpu_pending_exception", "fpu_last_opcode", "fpu_instruction_pointer",
    "fpu_code_selector", "fpu_data_pointer", "fpu_data_selector", "fpu_control_load",
    "fpu_control_word", "fpu_status_word", "fpu_bits_lo32", "fpu_bits_hi32",
    "fpu_cmp_cf", "fpu_cmp_pf", "fpu_cmp_zf", "fpu_fxam", "fpu_int32",
    "adc_carry", "adc_overflow",
    "fs_base",
)
_X87_OPS = (
    "fpu_reg", "fpu_empty", "fpu_const", "fpu_mem", "fpu_int", "fpu_mem64",
    "fpu_neg", "fpu_add", "fpu_sub", "fpu_subr", "fpu_mul", "fpu_div", "fpu_divr",
)
_ACTIONS = (
    "eval_word", "eval_x87", "memory_write", "divide_if", "call", "rep_movsd",
    "set_reg", "set_flag", "set_x87", "set_x87_tag", "set_x87_control",
    "set_x87_status", "set_x87_pending", "set_x87_opcode", "set_x87_ip",
    "set_x87_cs", "set_x87_dp", "set_x87_ds", "sync_eflags", "outcome_fallthrough",
    "outcome_jump", "outcome_branch", "outcome_return", "outcome_indirect",
    # Opcode 25 retains its historical ABI label. Its payload is now a typed,
    # byte-free operation and all newly generated capability metadata says so.
    "outcome_external", "replay_x87", "rep_stosd", "rep_movs", "rep_stos",
    "rep_scas",
)


def _program_source(transfers: tuple[_Transfer, ...]) -> str:
    # Flatten while rewriting local node and call references remains unnecessary:
    # each transfer points at slices and all references are transfer-local.
    lines = [
        '#include "state-machine-interpreter-internal.h"',
        "",
    ]
    for index, row in enumerate(transfers):
        prefix = f"stage_b_t{index:04d}"
        lines.extend(_render_transfer_data(prefix, row))
    lines.extend([
        "",
        "const stage_b_program_transfer stage_b_program_transfers[] = {",
    ])
    for index, row in enumerate(transfers):
        prefix = f"stage_b_t{index:04d}"
        lines.append(
            f"  {{ 0x{row.rva_start:08x}U, {len(row.nodes)}U, {len(row.x87_nodes)}U, "
            f"{len(row.actions)}U, {len(row.x87_operations)}U, {prefix}_nodes, "
            f"{prefix}_x87_nodes, {prefix}_actions, {prefix}_calls, {prefix}_x87_operations }},"
        )
    if not transfers:
        lines.append("  { 0U,0U,0U,0U,0U,0,0,0,0,0 },")
    lines.extend([
        "};",
        f"const uint32_t stage_b_program_transfer_count = {len(transfers)}U;",
        "",
    ])
    return "\n".join(lines)


def _render_transfer_data(prefix: str, row: _Transfer) -> list[str]:
    lines = [f"/* {row.identity.replace('*/', '* /')} */"]
    lines.append(f"static const stage_b_word_node {prefix}_nodes[] = {{")
    lines.extend("  " + _c_node(node, _WORD_OPS) + "," for node in row.nodes)
    if not row.nodes:
        lines.append("  { 0U, 0U, 0U, 0U, {0U,0U,0U,0U,0U} },")
    lines.append("};")
    lines.append(f"static const stage_b_x87_node {prefix}_x87_nodes[] = {{")
    lines.extend("  " + _c_node(node, _X87_OPS) + "," for node in row.x87_nodes)
    if not row.x87_nodes:
        lines.append("  { 0U, 0U, 0U, 0U, {0U,0U,0U,0U,0U} },")
    lines.append("};")
    for index, call in enumerate(row.calls):
        name = f"{prefix}_call_{index}"
        lines.append(f"static const uint32_t {name}_regs[] = {{ {', '.join(str(x)+'U' for x in call.register_nodes)} }};")
        lines.append(f"static const uint32_t {name}_flags[] = {{ {', '.join(str(x)+'U' for x in call.flag_nodes)} }};")
        arg_values = ", ".join(str(x) + "U" for x in call.argument_nodes) or "0U"
        lines.append(f"static const uint32_t {name}_args[] = {{ {arg_values} }};")
        stack_values = ", ".join(
            f"{{ {offset}U, {width}U, {node}U }}" for offset, width, node in call.stack_inputs
        ) or "{ 0U, 0U, 0U }"
        lines.append(f"static const stage_b_program_stack_input {name}_stack[] = {{ {stack_values} }};")
    lines.append(f"static const stage_b_program_call {prefix}_calls[] = {{")
    for index, call in enumerate(row.calls):
        name = f"{prefix}_call_{index}"
        kind = {"external_call": 0, "internal_call": 1, "indirect_call": 2}[call.kind]
        target = call.target_node if call.target_node is not None else 0
        lines.append(
            "  { "
            f"{kind}U, 0x{call.instruction_rva:08x}U, {call.call_index}U, {target}U, "
            f"0x{call.target_rva:08x}U, 0x{call.return_rva:08x}U, "
            f"{_c_string(call.dll)}, {_c_string(call.symbol)}, {call.ordinal or 0}U, "
            f"{1 if call.ordinal is not None else 0}U, {name}_regs, {name}_flags, "
            f"{name}_args, {len(call.argument_nodes)}U, {name}_stack, {len(call.stack_inputs)}U "
            "},"
        )
    if not row.calls:
        lines.append("  { 0U,0U,0U,0U,0U,0U,0,0,0U,0U,0,0,0,0U,0,0U },")
    lines.append("};")
    lines.append(
        f"static const stage_b_typed_x87_operation {prefix}_x87_operations[] = {{"
    )
    for operation in row.x87_operations:
        operand = operation.operation.operand
        register_codes = {
            None: 0,
            "eax": 1,
            "ebx": 2,
            "ecx": 3,
            "edx": 4,
            "esi": 5,
            "edi": 6,
            "ebp": 7,
            "esp": 8,
        }
        operand_kinds = {"none": 0, "ax": 1, "stack": 2, "memory": 3}
        stack_registers = (*operand.registers, 0, 0)
        lines.append(
            "  { "
            f"0x{operation.image_base:08x}U, 0x{operation.rva_start:08x}U, "
            f"0x{operation.rva_end:08x}U, {operation.operation.source_size}U, "
            f"{_c_string(operation.operation.identity)}, "
            f"{_c_string(operation.contract_sha256)}, "
            f"{_c_string(operation.checked_decoder)}, "
            f"{_c_string(operation.checked_executor)}, "
            f"{_c_string(operation.operation.mnemonic)}, "
            f"{operand_kinds[operand.kind]}U, {operand.width}U, "
            f"{len(operand.registers)}U, {stack_registers[0]}U, "
            f"{stack_registers[1]}U, {register_codes[operand.base]}U, "
            f"{register_codes[operand.index]}U, {operand.scale}U, "
            f"{operand.displacement}, {operand.image_rva or 0}U, "
            f"{1 if operand.image_rva is not None else 0}U "
            "},"
        )
    if not row.x87_operations:
        lines.append("  { 0 },")
    lines.append("};")
    lines.append(f"static const stage_b_program_action {prefix}_actions[] = {{")
    lines.extend("  " + _c_action(action) + "," for action in row.actions)
    lines.append("};")
    lines.append("")
    return lines


def _c_node(node: _Node, inventory: tuple[str, ...]) -> str:
    if node.op not in inventory:
        raise StageBInterpreterError(f"interpreter opcode inventory lacks {node.op}")
    args = list(node.args) + [0] * (5 - len(node.args))
    return (
        f"{{ {inventory.index(node.op)}U, {len(node.args)}U, {node.aux}U, "
        f"0x{node.immediate & 0xffffffff:08x}U, "
        "{" + ",".join(f"{value}U" for value in args) + "} }"
    )


def _c_action(action: _Action) -> str:
    opcode_name = "replay_x87" if action.op == "typed_x87" else action.op
    if opcode_name not in _ACTIONS:
        raise StageBInterpreterError(f"interpreter action inventory lacks {action.op}")
    args = list(action.args) + [0] * (5 - len(action.args))
    return (
        f"{{ {_ACTIONS.index(opcode_name)}U, {len(action.args)}U, {action.aux}U, "
        "{" + ",".join(f"{value}U" for value in args) + "} }"
    )


def _interpreter_source(*, max_word_nodes: int) -> str:
    if not 1 <= max_word_nodes <= 1024:
        raise StageBInterpreterError(
            f"interpreter word-node capacity {max_word_nodes} is outside 1..1024",
            code="word_node_capacity_exceeded",
            next_action=(
                "split the oversized transfer or raise the checked interpreter "
                "profile limit"
            ),
        )
    return (
        '#include "state-machine-interpreter-internal.h"\n\n'
        + f"#define STAGE_B_MAX_WORD_NODES {max_word_nodes}U\n"
        + _interpreter_runtime_helpers()
        + "\n"
        + _INTERPRETER_KERNEL
    )


def _interpreter_runtime_helpers() -> str:
    """Reuse the integer helper kernel without compiling host x87 arithmetic."""
    helpers = _runtime_helpers()
    if "long double" in helpers or "stage_b_x87_" in helpers:
        raise StageBInterpreterError(
            "host x87 arithmetic leaked into the interpreter helper kernel",
            code="interpreter_runtime_helper_drift",
        )
    return helpers


_INTERPRETER_INTERNAL_HEADER = r'''#ifndef STAGE_B_SEMANTIC_INTERPRETER_INTERNAL_H
#define STAGE_B_SEMANTIC_INTERPRETER_INTERNAL_H

#include "state-machine-interpreter.h"

typedef struct stage_b_word_node {
  uint32_t op, arity, aux, immediate, args[5];
} stage_b_word_node;
typedef stage_b_word_node stage_b_x87_node;
typedef struct stage_b_program_action {
  uint32_t op, arity, aux, args[5];
} stage_b_program_action;
typedef struct stage_b_program_stack_input {
  uint32_t offset, width, value_node;
} stage_b_program_stack_input;
typedef struct stage_b_program_call {
  uint32_t kind, instruction_rva, call_index, target_node, target_rva, return_rva;
  const char *dll, *symbol;
  uint32_t ordinal, has_ordinal;
  const uint32_t *register_nodes, *flag_nodes, *argument_nodes;
  uint32_t argument_count;
  const stage_b_program_stack_input *stack_inputs;
  uint32_t stack_input_count;
} stage_b_program_call;
struct stage_b_program_transfer {
  uint32_t source_rva, word_count, x87_count, action_count, x87_operation_count;
  const stage_b_word_node *nodes;
  const stage_b_x87_node *x87_nodes;
  const stage_b_program_action *actions;
  const stage_b_program_call *calls;
  const stage_b_typed_x87_operation *x87_operations;
};
extern const stage_b_program_transfer stage_b_program_transfers[];
extern const uint32_t stage_b_program_transfer_count;

#endif
'''


# The kernel deliberately has no host floating-point implementation. Every x87
# transition crosses the exact checked replay boundary; legacy x87-node opcodes
# remain reserved in the stable data ABI and fail closed if encountered.
_INTERPRETER_KERNEL = r'''
#define STAGE_B_MAX_CALL_ARGUMENTS 64U

static uint32_t stage_b_state_reg(const stage_b_machine_state *state, uint32_t index) {
  const uint32_t *registers = &state->eax;
  return registers[index];
}
static void stage_b_set_reg(stage_b_machine_state *state, uint32_t index, uint32_t value) {
  uint32_t *registers = &state->eax;
  registers[index] = value;
}
static uint32_t stage_b_state_flag(const stage_b_machine_state *state, uint32_t index) {
  static const uint32_t offsets[6] = { 0U,1U,2U,3U,4U,5U };
  const uint32_t *flags = &state->cf;
  if (index == 6U) return (state->eflags >> 4) & 1U;
  if (index >= 6U) return 0U;
  return flags[offsets[index]] & 1U;
}
static void stage_b_set_flag(stage_b_machine_state *state, uint32_t index, uint32_t value) {
  uint32_t *flags = &state->cf;
  if (index == 6U) {
    state->eflags = (state->eflags & ~(1U << 4)) | ((value & 1U) << 4);
    return;
  }
  if (index >= 6U) return;
  flags[index] = value & 1U;
}
static uint32_t stage_b_eval_word_index(
    stage_b_runtime *rt, const stage_b_machine_state *input,
    const stage_b_machine_state *current,
    const stage_b_machine_state *call_output, uint32_t *words,
    uint8_t *word_valid, const stage_b_word_node *nodes,
    uint32_t node_count, uint32_t index, uint32_t *memory_fault,
    uint32_t *semantic_fault);

#define W(i) stage_b_eval_word_index( \
    rt, input, current, call_output, words, word_valid, nodes, node_count, \
    node->args[(i)], memory_fault, semantic_fault)

static uint32_t stage_b_eval_word_uncached(
    stage_b_runtime *rt, const stage_b_machine_state *input,
    const stage_b_machine_state *current,
    const stage_b_machine_state *call_output, uint32_t *words,
    uint8_t *word_valid, const stage_b_word_node *nodes,
    uint32_t node_count, const stage_b_word_node *node,
    uint32_t *memory_fault, uint32_t *semantic_fault) {
  uint32_t op = node->op;
  if (op == 0U) return node->immediate;
  if (op == 1U) return stage_b_state_reg(node->immediate?current:input, node->aux);
  if (op == 2U) return stage_b_state_flag(node->immediate?current:input, node->aux);
  if (op == 3U) return 1U;
  if (op == 4U) return 0U;
  if (op == 5U || op == 6U)
    return stage_b_undefined(
        rt, node->immediate, input, node->arity == 1U ? W(0) : 0U);
  if (op == 7U) return stage_b_state_reg(call_output, node->aux);
  if (op == 8U) return stage_b_state_flag(call_output, node->aux);
  if (op == 9U) return stage_b_read(rt, W(0), node->aux, memory_fault);
  if (op == 10U) return W(0) - W(1);
  if (op == 11U) return W(0) < W(1);
  if (op == 12U || op == 14U) return W(0) == W(1);
  if (op == 13U) return W(0) != W(1);
  if (op == 15U) { uint32_t i, v=0U; for(i=0;i<node->arity;++i)v+=W(i); return v; }
  if (op == 16U) { uint32_t i, v=1U; for(i=0;i<node->arity;++i)v*=W(i); return v; }
  if (op == 17U) { uint32_t i, v=0U; for(i=0;i<node->arity;++i)v^=W(i); return v; }
  if (op == 18U) { uint32_t i, v=0xffffffffU; for(i=0;i<node->arity;++i)v&=W(i); return v; }
  if (op == 19U) { uint32_t i, v=0U; for(i=0;i<node->arity;++i)v|=W(i); return v; }
  if (op == 20U) return ~W(0);
  if (op == 21U) return 0U-W(0);
  if (op == 22U) return W(0) << (W(1)&31U);
  if (op == 23U) return W(0) >> (W(1)&31U);
  if (op == 24U) return stage_b_sar(W(0),W(1),W(2));
  if (op == 25U) return stage_b_sign_extend(W(0),W(1));
  if (op == 26U) return W(0)?W(1):W(2);
  if (op == 27U) return stage_b_msb(node->arity==2U?W(0):32U,node->arity==2U?W(1):W(0));
  if (op == 28U) return !W(0);
  if (op == 29U) { uint32_t i; for(i=0;i<node->arity;++i)if(!W(i))return 0U;return 1U; }
  if (op == 30U) { uint32_t i; for(i=0;i<node->arity;++i)if(W(i))return 1U;return 0U; }
  if (op == 31U) return stage_b_parity(W(1));
  if (op == 32U) return W(0)?1U:0U;
  if (op == 33U) return stage_b_add_overflow(W(0),W(1),W(2),W(3));
  if (op == 34U) return stage_b_sub_overflow(W(0),W(1),W(2),W(3));
  if (op == 35U || op == 36U) return (uint32_t)((uint64_t)W(0)*(uint64_t)W(1));
  if (op == 37U) return stage_b_imul_high(W(0),W(1));
  if (op == 38U) return stage_b_mul_high(W(0),W(1));
  if (op == 39U) return W(4)!=((int32_t)W(3)<0?0xffffffffU:0U);
  if (op == 40U) return W(3)!=0U;
  if (op == 41U) return stage_b_udiv_quot(W(0),W(1),W(2));
  if (op == 42U) return stage_b_udiv_rem(W(0),W(1),W(2));
  if (op == 43U) return stage_b_udiv_valid(W(0),W(1),W(2));
  if (op == 44U) return stage_b_bsr(W(node->arity-1U));
  if (op == 45U) return stage_b_tzcnt(W(node->arity-1U));
  if (op == 46U) return stage_b_sbb_borrow(W(0),W(1),W(2),W(3),W(4));
  if (op == 47U) return stage_b_sbb_overflow(W(0),W(1),W(2),W(3),W(4));
  if (op == 48U) return stage_b_shift_cf(node->aux>>8,node->aux&255U,W(0),W(1));
  if (op == 49U) return stage_b_shift_of(node->aux>>8,node->aux&255U,W(0),W(1),W(2));
  if (op == 50U) return (node->immediate?current:input)->x87_control;
  if (op == 51U) return 0x037fU;
  if (op == 52U) return (node->immediate?current:input)->x87_status;
  if (op == 53U) return 0U;
  if (op == 54U) return (node->immediate?current:input)->x87_stack[node->aux].tag;
  if (op == 55U) return (node->immediate?current:input)->x87_pending_exception;
  if (op == 56U) return (node->immediate?current:input)->x87_last_opcode;
  if (op == 57U) return (node->immediate?current:input)->x87_instruction_pointer;
  if (op == 58U) return (node->immediate?current:input)->x87_code_selector;
  if (op == 59U) return (node->immediate?current:input)->x87_data_pointer;
  if (op == 60U) return (node->immediate?current:input)->x87_data_selector;
  if (op >= 61U && op <= 63U) return W(0)&0xffffU;
  if (op == 71U) {
    uint32_t width = W(0);
    uint64_t mask, sum;
    if (width == 0U || width > 32U || W(3) > 1U) {
      *semantic_fault = 1U;
      return 0U;
    }
    mask = width == 32U ? 0xffffffffULL : ((1ULL << width) - 1ULL);
    sum = ((uint64_t)W(1) & mask) + ((uint64_t)W(2) & mask) + (uint64_t)W(3);
    if (((uint32_t)sum & (uint32_t)mask) != (W(4) & (uint32_t)mask)) {
      *semantic_fault = 1U;
      return 0U;
    }
    return (uint32_t)((sum >> width) & 1ULL);
  }
  if (op == 72U) {
    uint32_t width = W(0), mask, left, right, result, sign;
    uint64_t sum;
    if (width == 0U || width > 32U || W(3) > 1U) {
      *semantic_fault = 1U;
      return 0U;
    }
    mask = width == 32U ? 0xffffffffU : ((1U << width) - 1U);
    left = W(1) & mask;
    right = W(2) & mask;
    result = W(4) & mask;
    sum = (uint64_t)left + (uint64_t)right + (uint64_t)W(3);
    if (((uint32_t)sum & mask) != result) {
      *semantic_fault = 1U;
      return 0U;
    }
    sign = 1U << (width - 1U);
    return ((~(left ^ right) & (left ^ result) & sign) != 0U) ? 1U : 0U;
  }
  if (op == 73U) return (node->immediate?current:input)->fs_base;
  *semantic_fault = 1U;
  return 0U;
}
#undef W

static uint32_t stage_b_eval_word_index(
    stage_b_runtime *rt, const stage_b_machine_state *input,
    const stage_b_machine_state *current,
    const stage_b_machine_state *call_output, uint32_t *words,
    uint8_t *word_valid, const stage_b_word_node *nodes,
    uint32_t node_count, uint32_t index, uint32_t *memory_fault,
    uint32_t *semantic_fault) {
  uint32_t value;
  const stage_b_word_node *node;
  if (index >= node_count || words == 0 || word_valid == 0 || nodes == 0) {
    *semantic_fault = 1U;
    return 0U;
  }
  if (word_valid[index] != 0U) return words[index];
  node = &nodes[index];
  value = stage_b_eval_word_uncached(
      rt, input, current, call_output, words, word_valid, nodes, node_count,
      node, memory_fault, semantic_fault);
  words[index] = value;
  word_valid[index] = 1U;
  return value;
}

__attribute__((weak)) const stage_b_region_override *
stage_b_region_override_lookup(uint32_t entry_rva) {
  (void)entry_rva;
  return (const stage_b_region_override *)0;
}

static uint32_t stage_b_region_override_result_valid(stage_b_step_result result) {
  if (result.kind > STAGE_B_EXTERNAL_JUMP) return 0U;
  if (result.kind <= STAGE_B_BRANCH)
    return result.target_rva != 0U && result.value == 0U;
  if (result.kind == STAGE_B_RETURN)
    return result.target_rva == 0U;
  if (result.kind == STAGE_B_INDIRECT_JUMP)
    return result.target_rva == 0U && result.value != 0U;
  if (result.kind == STAGE_B_UNIMPLEMENTED)
    return result.value == 0U;
  return result.target_rva == 0U && result.value == 0U;
}

const stage_b_program_transfer *stage_b_program_lookup(uint32_t source_rva) {
  uint32_t low=0U,high=stage_b_program_transfer_count;
  while(low<high){uint32_t mid=low+(high-low)/2U;uint32_t r=stage_b_program_transfers[mid].source_rva;
    if(r<source_rva)low=mid+1U;else high=mid;}
  return low<stage_b_program_transfer_count&&stage_b_program_transfers[low].source_rva==source_rva
      ? &stage_b_program_transfers[low] : 0;
}

stage_b_step_result stage_b_interpreter_step(
    stage_b_runtime *rt, stage_b_machine_state *state, uint32_t source_rva) {
  const stage_b_region_override *override;
  const stage_b_program_transfer *t;
  stage_b_machine_state input,call_output;
  uint32_t words[STAGE_B_MAX_WORD_NODES],memory_fault=0U,semantic_fault=0U,i;
  uint8_t word_valid[STAGE_B_MAX_WORD_NODES] = {0};
  if(!state)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  override=stage_b_region_override_lookup(source_rva);
  if(override){
    stage_b_machine_state overridden=*state;
    stage_b_step_result result;
    if(override->entry_rva!=source_rva||!override->function)
      return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    result=override->function(rt,&overridden);
    if(!stage_b_region_override_result_valid(result))
      return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    if(result.kind==STAGE_B_UNIMPLEMENTED&&override->fallback_on_unimplemented){
      if(result.target_rva!=source_rva||result.value!=0U)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    }else{
      *state=overridden;
      return result;
    }
  }
  if(stage_b_native_machine_fallback_allowed!=0&&
      !stage_b_native_machine_fallback_allowed(source_rva))
    return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  t=stage_b_program_lookup(source_rva);
  if(!t||t->word_count>STAGE_B_MAX_WORD_NODES||t->x87_count!=0U)
    return (stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  input=*state;call_output=input;state->original_rva=source_rva;
  for(i=0U;i<t->action_count;++i){
    const stage_b_program_action *a=&t->actions[i];
    if(a->op==0U)stage_b_eval_word_index(
      rt,&input,state,&call_output,words,word_valid,t->nodes,t->word_count,
      a->args[0],&memory_fault,&semantic_fault);
    else if(a->op==1U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    else if(a->op==2U)stage_b_write(rt,words[a->args[0]],a->aux,words[a->args[1]],&memory_fault);
    else if(a->op==3U){
      if(words[a->args[0]])return(stage_b_step_result){STAGE_B_DIVIDE_ERROR,0U,0U};
    }
    else if(a->op==4U){
      const stage_b_program_call*c=&t->calls[a->args[0]];stage_b_machine_state ci=*state;stage_b_call_event e;stage_b_stack_input si[64];uint32_t av[64],j;
      if(c->argument_count>64U||c->stack_input_count>64U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,0U,0U};
      for(j=0U;j<8U;++j)stage_b_set_reg(&ci,j,words[c->register_nodes[j]]);
      for(j=0U;j<6U;++j)stage_b_set_flag(&ci,j,words[c->flag_nodes[j]]);
      for(j=0U;j<c->argument_count;++j)av[j]=words[c->argument_nodes[j]];
      for(j=0U;j<c->stack_input_count;++j){si[j].offset=c->stack_inputs[j].offset;si[j].width=c->stack_inputs[j].width;si[j].value=words[c->stack_inputs[j].value_node];}
      e.kind=(stage_b_call_event_kind)c->kind;e.instruction_rva=c->instruction_rva;e.call_index=c->call_index;
      e.target_rva=c->kind==2U?words[c->target_node]:c->target_rva;e.return_rva=c->return_rva;e.dll=c->dll;e.symbol=c->symbol;
      e.ordinal=c->ordinal;e.has_ordinal=c->has_ordinal;e.arguments=av;e.argument_count=c->argument_count;e.stack_inputs=si;e.stack_input_count=c->stack_input_count;
      call_output=ci;{stage_b_call_status s=stage_b_invoke_call(rt,&e,&ci,&call_output);if(s!=STAGE_B_CALL_OK){*state=call_output;return(stage_b_step_result){s==STAGE_B_CALL_DIVIDE_ERROR?STAGE_B_DIVIDE_ERROR:s==STAGE_B_CALL_MEMORY_FAULT?STAGE_B_MEMORY_FAULT:s==STAGE_B_CALL_EXTERNAL_FAULT?STAGE_B_EXTERNAL_FAULT:STAGE_B_UNIMPLEMENTED,call_output.original_rva,0U};}}*state=call_output;
    } else if(a->op==5U){
      uint32_t s=words[a->args[0]],d=words[a->args[1]],n=words[a->args[2]],step=words[a->args[3]]?0xfffffffcU:4U;
      stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){uint32_t v=stage_b_read(rt,s,4U,&memory_fault);if(memory_fault)break;stage_b_write(rt,d,4U,v,&memory_fault);if(memory_fault)break;s+=step;d+=step;--n;stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);}}
    else if(a->op==6U)stage_b_set_reg(state,a->aux,words[a->args[0]]);
    else if(a->op==7U)stage_b_set_flag(state,a->aux,words[a->args[0]]);
    else if(a->op>=8U&&a->op<=17U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    else if(a->op==18U)stage_b_sync_eflags(state);
    else if(a->op==19U)return(stage_b_step_result){STAGE_B_FALLTHROUGH,a->args[0],0U};
    else if(a->op==20U)return(stage_b_step_result){STAGE_B_JUMP,a->args[0],0U};
    else if(a->op==21U)return(stage_b_step_result){STAGE_B_BRANCH,words[a->args[0]]?a->args[1]:a->args[2],0U};
    else if(a->op==22U)return(stage_b_step_result){STAGE_B_RETURN,0U,words[a->args[0]]};
    else if(a->op==23U)return(stage_b_step_result){STAGE_B_INDIRECT_JUMP,0U,words[a->args[0]]};
    else if(a->op==24U)return(stage_b_step_result){STAGE_B_EXTERNAL_JUMP,0U,0U};
    else if(a->op==25U){
      const stage_b_typed_x87_operation*p;stage_b_machine_state operation_output;stage_b_call_status s;
      if(a->arity!=1U||a->args[0]>=t->x87_operation_count||!rt||!rt->execute_typed_x87_operation)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      p=&t->x87_operations[a->args[0]];
      if(p->rva_end<=p->rva_start||p->source_size!=p->rva_end-p->rva_start||
          !p->operation_identity||!p->contract_sha256||
          !p->checked_decoder||!p->checked_executor)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      operation_output=*state;s=rt->execute_typed_x87_operation(rt,p,state,&operation_output);
      if(s!=STAGE_B_CALL_OK)return(stage_b_step_result){s==STAGE_B_CALL_DIVIDE_ERROR?STAGE_B_DIVIDE_ERROR:s==STAGE_B_CALL_MEMORY_FAULT?STAGE_B_MEMORY_FAULT:s==STAGE_B_CALL_EXTERNAL_FAULT?STAGE_B_EXTERNAL_FAULT:STAGE_B_UNIMPLEMENTED,source_rva,0U};
      *state=operation_output;
    } else if(a->op==26U){
      uint32_t d=words[a->args[0]],v=words[a->args[1]];
      uint32_t n=words[a->args[2]],step=words[a->args[3]]?0xfffffffcU:4U;
      stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        stage_b_write(rt,d,4U,v,&memory_fault);
        if(memory_fault)break;
        d+=step;
        --n;
        stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      }
    } else if(a->op==27U){
      uint32_t s=words[a->args[0]],d=words[a->args[1]],n=words[a->args[2]],w=a->aux;
      uint32_t step=words[a->args[3]]?0U-w:w;
      if(w!=1U&&w!=2U&&w!=4U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        uint32_t v=stage_b_read(rt,s,w,&memory_fault);
        if(memory_fault)break;
        stage_b_write(rt,d,w,v,&memory_fault);
        if(memory_fault)break;
        s+=step;d+=step;--n;
        stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      }
    } else if(a->op==28U){
      uint32_t d=words[a->args[0]],v=words[a->args[1]],n=words[a->args[2]],w=a->aux;
      uint32_t step=words[a->args[3]]?0U-w:w;
      if(w!=1U&&w!=2U&&w!=4U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        stage_b_write(rt,d,w,v,&memory_fault);
        if(memory_fault)break;
        d+=step;--n;
        stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      }
    } else if(a->op==29U){
      uint32_t d,al,n,step;
      if(a->arity!=4U||a->aux!=1U)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      al=words[a->args[0]]&0xffU;d=words[a->args[1]];
      n=words[a->args[2]];step=words[a->args[3]]?0xffffffffU:1U;
      stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        uint32_t m=stage_b_read(rt,d,1U,&memory_fault)&0xffU,result;
        if(memory_fault)break;
        result=(al-m)&0xffU;d+=step;--n;
        stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
        stage_b_set_flag(state,0U,al<m);
        stage_b_set_flag(state,1U,result==0U);
        stage_b_set_flag(state,2U,(result>>7)&1U);
        stage_b_set_flag(state,3U,((al^m)&(al^result)&0x80U)!=0U);
        stage_b_set_flag(state,4U,stage_b_parity(result));
        stage_b_set_flag(state,6U,((al^m^result)>>4)&1U);
        stage_b_sync_eflags(state);
        if(result==0U)break;
      }
    } else return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    if(memory_fault)return(stage_b_step_result){STAGE_B_MEMORY_FAULT,source_rva,0U};
    if(semantic_fault)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  }
  return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
}

static stage_b_call_status stage_b_run_function_checked(
    stage_b_runtime *rt, uint32_t rva, const stage_b_machine_state *in,
    stage_b_machine_state *out, uint32_t expected_return_rva,
    uint32_t check_return_rva) {
  stage_b_machine_state s;
  if (!in || !out) return STAGE_B_CALL_UNIMPLEMENTED;
  s = *in;
  for (;;) {
    if (rt && rt->trace_transfer)
      rt->trace_transfer(rt->context, rva, &s);
    stage_b_step_result r = stage_b_interpreter_step(rt, &s, rva);
    if (r.kind <= STAGE_B_BRANCH) {
      rva = r.target_rva;
      continue;
    }
    if (r.kind == STAGE_B_INDIRECT_JUMP) {
      uint32_t next_rva;
      if (!rt || !rt->resolve_code_target ||
          rt->resolve_code_target(rt, r.value, &next_rva)) {
        stage_b_call_status external_status = STAGE_B_CALL_UNIMPLEMENTED;
        stage_b_machine_state external_output = s;
        if (rt && rt->invoke_callable_external_jump) {
          external_status = rt->invoke_callable_external_jump(
              rt, rva, r.value, &s, &external_output);
          if (external_status == STAGE_B_CALL_OK) {
            *out = external_output;
            return STAGE_B_CALL_OK;
          }
        }
        *out = s;
        out->original_rva = rva;
        return external_status;
      }
      rva = next_rva;
      continue;
    }
    *out = s;
    out->original_rva = r.target_rva != 0U ? r.target_rva : rva;
    if (r.kind == STAGE_B_RETURN) {
      if (check_return_rva && r.value != expected_return_rva) {
        /* Failure-only payload consumed by the candidate diagnostic trap. */
        out->esi = expected_return_rva;
        out->edi = r.value;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }
      return STAGE_B_CALL_OK;
    }
    if (r.kind == STAGE_B_EXTERNAL_JUMP) return STAGE_B_CALL_OK;
    if (r.kind == STAGE_B_DIVIDE_ERROR) return STAGE_B_CALL_DIVIDE_ERROR;
    if (r.kind == STAGE_B_MEMORY_FAULT) return STAGE_B_CALL_MEMORY_FAULT;
    if (r.kind == STAGE_B_EXTERNAL_FAULT) return STAGE_B_CALL_EXTERNAL_FAULT;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }
}

stage_b_call_status stage_b_run_function(
    stage_b_runtime *rt, uint32_t rva, const stage_b_machine_state *in,
    stage_b_machine_state *out) {
  return stage_b_run_function_checked(rt, rva, in, out, 0U, 0U);
}

static stage_b_call_status stage_b_invoke_internal_call(
    stage_b_runtime *rt, const stage_b_call_event *event, uint32_t target_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  stage_b_machine_state call_input;
  stage_b_call_status status;
  uint32_t memory_fault = 0U;
  if (!rt || !event || !input || !output || input->esp < 4U)
    return STAGE_B_CALL_UNIMPLEMENTED;
  call_input = *input;
  call_input.esp -= 4U;
  stage_b_write(
      rt, call_input.esp, 4U, event->return_rva, &memory_fault);
  if (memory_fault) {
    *output = call_input;
    output->original_rva = event->instruction_rva;
    return STAGE_B_CALL_MEMORY_FAULT;
  }
  status = stage_b_run_function_checked(
      rt, target_rva, &call_input, output, event->return_rva, 1U);
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  if (status == STAGE_B_CALL_OK && output->esp < input->esp) {
    output->esi = input->esp;
    output->edi = output->esp;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }
#endif
  return status;
}

stage_b_call_status stage_b_invoke_call(
    stage_b_runtime *rt, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  uint32_t target_rva;
  if (!event) return STAGE_B_CALL_UNIMPLEMENTED;
  if (event->kind == STAGE_B_CALL_INTERNAL_DIRECT)
    return stage_b_invoke_internal_call(
        rt, event, event->target_rva, input, output);
  if (event->kind == STAGE_B_CALL_INDIRECT && rt && rt->resolve_code_target &&
      !rt->resolve_code_target(rt, event->target_rva, &target_rva))
    return stage_b_invoke_internal_call(
        rt, event, target_rva, input, output);
  return stage_b_dispatch_external_call(rt, event, input, output);
}
'''
