"""C expression and transition rendering for the semantic backend."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .c_domains import (
    _CALL_EVENT_KINDS,
    _FLAG_NAMES,
    _REGISTER_NAMES,
    _X87_VALUE_OPS,
    _X87_WORD_OPS,
    c_string as _c_string,
    valid_rep_scas_event as _valid_rep_scas_event,
)


def _runtime_helpers() -> str:
    helpers = """static uint32_t spx_mask(uint32_t width) {
  return width >= 32U ? 0xffffffffU : ((1U << width) - 1U);
}

static uint32_t spx_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }
  return rt->read(rt->context, address, width, fault);
}

static void spx_write(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  if (rt == 0 || rt->write == 0) { *fault = 1U; return; }
  rt->write(rt->context, address, width, value, fault);
}

static uint32_t spx_undefined(spx_runtime *rt, uint32_t slot,
    const spx_machine_state *input, uint32_t defined_value) {
  return rt != 0 && rt->undefined_value != 0
      ? rt->undefined_value(rt->context, slot, input, defined_value) : slot;
}

static void spx_sync_eflags(spx_machine_state *state) {
  const uint32_t represented =
      (1U << 0) | (1U << 2) | (1U << 6) | (1U << 7) |
      (1U << 10) | (1U << 11);
  state->eflags = (state->eflags & ~represented) |
      ((state->cf & 1U) << 0) |
      ((state->pf & 1U) << 2) |
      ((state->zf & 1U) << 6) |
      ((state->sf & 1U) << 7) |
      ((state->df & 1U) << 10) |
      ((state->of & 1U) << 11);
}

static uint32_t spx_sign_extend(uint32_t width, uint32_t value) {
  uint32_t mask = spx_mask(width);
  uint32_t sign = 1U << (width - 1U);
  value &= mask;
  return (value ^ sign) - sign;
}

static uint32_t spx_sar(uint32_t width, uint32_t value, uint32_t amount) {
  amount &= 31U;
  return (uint32_t)(((int32_t)spx_sign_extend(width, value)) >> amount) & spx_mask(width);
}

static uint32_t spx_msb(uint32_t width, uint32_t value) {
  return (value >> (width - 1U)) & 1U;
}

static uint32_t spx_parity(uint32_t value) {
  value ^= value >> 4U;
  value &= 0xfU;
  return (0x9669U >> value) & 1U;
}

static uint32_t spx_add_overflow(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {
  return ((~(left ^ right) & (left ^ result)) >> (width - 1U)) & 1U;
}

static uint32_t spx_sub_overflow(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {
  return (((left ^ right) & (left ^ result)) >> (width - 1U)) & 1U;
}

static uint32_t spx_imul_high(uint32_t left, uint32_t right) {
  return (uint32_t)(((int64_t)(int32_t)left * (int64_t)(int32_t)right) >> 32U);
}

static uint32_t spx_mul_high(uint32_t left, uint32_t right) {
  return (uint32_t)(((uint64_t)left * (uint64_t)right) >> 32U);
}

static uint32_t spx_udiv_pair(
    uint32_t high, uint32_t low, uint32_t divisor, uint32_t *remainder) {
  uint64_t rest = high;
  uint32_t quotient = 0U;
  uint32_t index;
  if (divisor == 0U || high >= divisor) {
    if (remainder != 0) *remainder = 0U;
    return 0U;
  }
  for (index = 0U; index < 32U; ++index) {
    rest = (rest << 1U) | ((low >> 31U) & 1U);
    low <<= 1U;
    quotient <<= 1U;
    if (rest >= divisor) {
      rest -= divisor;
      quotient |= 1U;
    }
  }
  if (remainder != 0) *remainder = (uint32_t)rest;
  return quotient;
}

static uint32_t spx_udiv_quot(uint32_t high, uint32_t low, uint32_t divisor) {
  return spx_udiv_pair(high, low, divisor, 0);
}

static uint32_t spx_udiv_rem(uint32_t high, uint32_t low, uint32_t divisor) {
  uint32_t remainder = 0U;
  (void)spx_udiv_pair(high, low, divisor, &remainder);
  return remainder;
}

static uint32_t spx_udiv_valid(uint32_t high, uint32_t low, uint32_t divisor) {
  (void)low;
  return divisor != 0U && high < divisor;
}

static uint32_t spx_bsr(uint32_t value) {
  uint32_t index = 0U;
  while (value >>= 1U) { ++index; }
  return index;
}

static uint32_t spx_tzcnt(uint32_t value) {
  uint32_t count = 0U;
  if (value == 0U) return 32U;
  while ((value & 1U) == 0U) { value >>= 1U; ++count; }
  return count;
}

static uint32_t spx_shift_cf(uint32_t kind, uint32_t width, uint32_t value, uint32_t count) {
  count &= 31U;
  value &= spx_mask(width);
  if (count == 0U || count > width) return 0U;
  if (kind == 0U) return (value >> (width - count)) & 1U;
  return (value >> (count - 1U)) & 1U;
}

static uint32_t spx_shift_of(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count, uint32_t result) {
  count &= 31U;
  if (count != 1U) return 0U;
  if (kind == 0U) return spx_msb(width, result) ^ spx_shift_cf(kind, width, value, count);
  if (kind == 1U) return spx_msb(width, value);
  return 0U;
}

static uint32_t spx_sbb_borrow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry, uint32_t result) {
  uint32_t mask = spx_mask(width);
  uint64_t subtrahend = (uint64_t)(right & mask) + (uint64_t)(carry & 1U);
  (void)result;
  return (uint64_t)(left & mask) < subtrahend;
}

static uint32_t spx_sbb_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry, uint32_t result) {
  uint32_t mask = spx_mask(width);
  (void)carry;
  return ((((left & mask) ^ (right & mask)) & ((left & mask) ^ (result & mask)))
      >> (width - 1U)) & 1U;
}"""
    prefix = """#if defined(__GNUC__) || defined(__clang__)
#define SPX_INTERNAL_HELPER static __attribute__((unused))
#else
#define SPX_INTERNAL_HELPER static
#endif

"""
    return prefix + helpers.replace("static ", "SPX_INTERNAL_HELPER ") + (
        "\n#undef SPX_INTERNAL_HELPER\n"
    )


@dataclass
class _ExpressionRenderer:
    lines: list[str] = field(default_factory=list)
    memo: dict[str, str] = field(default_factory=dict)
    x87_memo: dict[str, str] = field(default_factory=dict)
    call_outputs: set[int] = field(default_factory=set)
    counter: int = 0
    x87_counter: int = 0

    def render(self, expr: Any) -> str:
        if not isinstance(expr, dict):
            if isinstance(expr, bool):
                return "1U" if expr else "0U"
            if isinstance(expr, int):
                return f"{expr & 0xFFFFFFFF}U"
            raise ValueError(f"unsupported semantic expression leaf {expr!r}")
        key = json.dumps(expr, sort_keys=True, separators=(",", ":"))
        if key in self.memo:
            return self.memo[key]
        op = str(expr.get("op") or "")
        if op == "const":
            return f"{int(expr.get('value') or 0) & 0xFFFFFFFF}U"
        if op == "reg":
            name = str(expr.get("name") or "")
            if name not in _REGISTER_NAMES:
                raise ValueError(f"unsupported register {name!r}")
            return f"input.{name}"
        if op == "flag":
            name = str(expr.get("name") or "")
            if name == "af":
                return "((input.eflags >> 4) & 1U)"
            if name not in _FLAG_NAMES:
                raise ValueError(f"unsupported flag {name!r}")
            return f"input.{name}"
        if op == "true":
            return "1U"
        if op == "false":
            return "0U"
        if op in {"undefined_bv", "undefined_flag"}:
            slot = _stable_slot(str(expr.get("id") or expr.get("reason") or "undefined"))
            defined_value = expr.get("defined_value")
            rendered = "0U" if defined_value is None else self.render(defined_value)
            return f"spx_undefined(rt, {slot}U, &input, {rendered})"
        if op == "call_response":
            call_index = _required_nonnegative_int(expr.get("call_index"), "call_response call_index")
            register = str(expr.get("register") or "")
            if register not in _REGISTER_NAMES:
                raise ValueError(f"unsupported call-response register {register!r}")
            if call_index not in self.call_outputs:
                raise ValueError(f"call_response references unavailable call index {call_index}")
            return f"call_output_{call_index}.{register}"
        if op == "call_flag":
            call_index = _required_nonnegative_int(expr.get("call_index"), "call_flag call_index")
            flag = str(expr.get("flag") or "")
            if flag not in _FLAG_NAMES and flag != "af":
                raise ValueError(f"unsupported call-response flag {flag!r}")
            if call_index not in self.call_outputs:
                raise ValueError(f"call_flag references unavailable call index {call_index}")
            if flag == "af":
                return f"((call_output_{call_index}.eflags >> 4) & 1U)"
            return f"call_output_{call_index}.{flag}"
        if op in _X87_WORD_OPS:
            raise ValueError("x87 expressions require the checked replay interpreter")
        if op in _X87_VALUE_OPS:
            raise ValueError(f"x87 value operation {op!r} used as a 32-bit expression")
        if op in {"shift_cf", "shift_of"}:
            raw_args = expr.get("args") if isinstance(expr.get("args"), list) else []
            expected = 4 if op == "shift_cf" else 5
            if len(raw_args) != expected or raw_args[0] not in {"shl", "sal", "shr", "sar", "shld", "shrd"}:
                raise ValueError(f"unsupported {op} expression shape")
            width = raw_args[1]
            if not isinstance(width, int) or isinstance(width, bool) or width not in {8, 16, 32}:
                raise ValueError(f"unsupported {op} operand width")
            kind = {
                "shl": 0,
                "sal": 0,
                "shld": 0,
                "shr": 1,
                "shrd": 1,
                "sar": 2,
            }[str(raw_args[0])]
            left = self.render(raw_args[2])
            count = self.render(raw_args[3])
            if op == "shift_cf":
                value = f"spx_shift_cf({kind}U, {width}U, {left}, {count})"
            else:
                result = self.render(raw_args[4])
                value = f"spx_shift_of({kind}U, {width}U, {left}, {count}, {result})"
            return self._bind(key, value)
        args = expr.get("args") if isinstance(expr.get("args"), list) else []
        rendered = [self.render(arg) for arg in args]
        value = self._operation(op, expr, rendered)
        return self._bind(key, value)

    def render_x87(self, expr: Any) -> str:
        if not isinstance(expr, dict):
            raise ValueError(f"unsupported x87 expression leaf {expr!r}")
        key = json.dumps(expr, sort_keys=True, separators=(",", ":"))
        if key in self.x87_memo:
            return self.x87_memo[key]
        op = str(expr.get("op") or "")
        args = self._x87_args(expr, op)
        if op == "fpu_reg":
            self._require_x87_arg_count(op, args, 1)
            index = args[0]
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 8:
                raise ValueError("fpu_reg index must be an integer from 0 through 7")
            return f"input.x87_stack[{index}]"
        if op == "fpu_empty":
            self._require_x87_arg_count(op, args, 1)
            slot = args[0]
            if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < 8:
                raise ValueError("fpu_empty slot must be an integer from 0 through 7")
            return self._bind_x87(key, f"spx_x87_empty({slot}U)")
        if op == "fpu_const":
            self._require_x87_arg_count(op, args, 1)
            if args[0] not in {"0", "1"}:
                raise ValueError(f"unsupported fpu_const value {args[0]!r}")
            return self._bind_x87(key, f"spx_x87_number({args[0]}.0L)")
        if op in {"fpu_mem", "fpu_int"}:
            self._require_x87_arg_count(op, args, 2)
            width = args[0]
            if not isinstance(width, int) or isinstance(width, bool):
                raise ValueError(f"{op} width must be an integer")
            raw = self.render(args[1])
            if op == "fpu_mem":
                if width != 32:
                    raise ValueError(f"unsupported fpu_mem width {width}")
                value = f"spx_x87_mem32({raw})"
            else:
                if width not in {8, 16, 32}:
                    raise ValueError(f"unsupported fpu_int width {width}")
                value = f"spx_x87_int({width}U, {raw}, &x87_fault)"
            return self._bind_x87(key, value)
        if op == "fpu_mem64":
            self._require_x87_arg_count(op, args, 2)
            low = self.render(args[0])
            high = self.render(args[1])
            return self._bind_x87(key, f"spx_x87_mem64({low}, {high})")
        if op == "fpu_neg":
            self._require_x87_arg_count(op, args, 1)
            value = self.render_x87(args[0])
            return self._bind_x87(key, f"spx_x87_neg({value}, &x87_fault)")
        if op in {"fpu_add", "fpu_sub", "fpu_subr", "fpu_mul", "fpu_div", "fpu_divr"}:
            self._require_x87_arg_count(op, args, 2)
            operation = {
                "fpu_add": 0,
                "fpu_sub": 1,
                "fpu_subr": 1,
                "fpu_mul": 2,
                "fpu_div": 3,
                "fpu_divr": 3,
            }[op]
            left = self.render_x87(args[0])
            right = self.render_x87(args[1])
            return self._bind_x87(
                key,
                f"spx_x87_binary({operation}U, {left}, {right}, &x87_fault)",
            )
        raise ValueError(f"unsupported x87 value operation {op!r}")

    def _render_x87_word(self, key: str, op: str, expr: dict[str, Any]) -> str:
        args = self._x87_args(expr, op)
        if op in {"fpu_control", "fpu_control_init", "fpu_status", "fpu_status_init"}:
            self._require_x87_arg_count(op, args, 0)
            return {
                "fpu_control": "input.x87_control",
                "fpu_control_init": "0x037fU",
                "fpu_status": "input.x87_status",
                "fpu_status_init": "0U",
            }[op]
        if op == "fpu_tag":
            self._require_x87_arg_count(op, args, 1)
            index = args[0]
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 8:
                raise ValueError("fpu_tag index must be an integer from 0 through 7")
            return f"input.x87_stack[{index}].tag"
        metadata_inputs = {
            "fpu_pending_exception": "input.x87_pending_exception",
            "fpu_last_opcode": "input.x87_last_opcode",
            "fpu_instruction_pointer": "input.x87_instruction_pointer",
            "fpu_code_selector": "input.x87_code_selector",
            "fpu_data_pointer": "input.x87_data_pointer",
            "fpu_data_selector": "input.x87_data_selector",
        }
        if op in metadata_inputs:
            self._require_x87_arg_count(op, args, 0)
            return metadata_inputs[op]
        if op in {"fpu_control_load", "fpu_control_word", "fpu_status_word"}:
            self._require_x87_arg_count(op, args, 1)
            return self._bind(key, f"({self.render(args[0])}) & 0xffffU")
        if op in {"fpu_bits_lo32", "fpu_bits_hi32"}:
            self._require_x87_arg_count(op, args, 1)
            value = self.render_x87(args[0])
            high = 1 if op == "fpu_bits_hi32" else 0
            return self._bind(key, f"spx_x87_bits({value}, {high}U, &x87_fault)")
        if op in {"fpu_cmp_cf", "fpu_cmp_pf", "fpu_cmp_zf"}:
            self._require_x87_arg_count(op, args, 2)
            bit = {"fpu_cmp_cf": 0, "fpu_cmp_pf": 1, "fpu_cmp_zf": 2}[op]
            left = self.render_x87(args[0])
            right = self.render_x87(args[1])
            return self._bind(
                key,
                f"spx_x87_compare({bit}U, {left}, {right}, &x87_fault)",
            )
        if op == "fpu_fxam":
            self._require_x87_arg_count(op, args, 1)
            value = self.render_x87(args[0])
            return self._bind(key, f"spx_x87_fxam({value}, input.x87_status)")
        if op == "fpu_int32":
            self._require_x87_arg_count(op, args, 2)
            value = self.render_x87(args[0])
            control = self.render(args[1])
            return self._bind(
                key,
                f"spx_x87_int32({value}, {control}, &x87_fault)",
            )
        raise ValueError(f"unsupported x87 word operation {op!r}")

    @staticmethod
    def _x87_args(expr: dict[str, Any], op: str) -> list[Any]:
        args = expr.get("args")
        if not isinstance(args, list):
            raise ValueError(f"{op} args must be a list")
        return args

    @staticmethod
    def _require_x87_arg_count(op: str, args: list[Any], expected: int) -> None:
        if len(args) != expected:
            raise ValueError(f"{op} requires {expected} arguments, got {len(args)}")

    def _bind(self, key: str, value: str) -> str:
        name = f"v{self.counter}"
        self.counter += 1
        self.lines.append(f"  uint32_t {name} = {value};")
        self.memo[key] = name
        return name

    def _bind_x87(self, key: str, value: str) -> str:
        name = f"x87_v{self.x87_counter}"
        self.x87_counter += 1
        self.lines.append(f"  spx_x87_value {name} = {value};")
        self.x87_memo[key] = name
        return name

    def _operation(self, op: str, expr: dict[str, Any], args: list[str]) -> str:
        if op == "load":
            return f"spx_read(rt, {self.render(expr.get('address'))}, {int(expr.get('width') or 4)}U, &memory_fault)"
        infix = {"sub32": "-", "ult32": "<", "eq": "==", "xor_bool": "!=", "eq_bool": "=="}
        if op in infix and len(args) == 2:
            return f"(({args[0]}) {infix[op]} ({args[1]}))"
        associative = {"add32": "+", "mul32": "*", "xor32": "^", "and32": "&", "or32": "|"}
        if op in associative and len(args) >= 2:
            operator = associative[op]
            return "(" + f") {operator} (".join(args) + ")"
        if op in {"not32", "neg32"} and len(args) == 1:
            return f"({'~' if op == 'not32' else '-'}({args[0]}))"
        if op in {"shl32", "lshr32"} and len(args) == 2:
            operator = "<<" if op == "shl32" else ">>"
            return f"(({args[0]}) {operator} (({args[1]}) & 31U))"
        if op == "sar" and len(args) == 3:
            return f"spx_sar({args[0]}, {args[1]}, {args[2]})"
        if op == "sign_extend" and len(args) == 2:
            return f"spx_sign_extend({args[0]}, {args[1]})"
        if op == "ite" and len(args) == 3:
            return f"(({args[0]}) ? ({args[1]}) : ({args[2]}))"
        if op == "msb":
            width, value = (args[0], args[1]) if len(args) == 2 else ("32U", args[0])
            return f"spx_msb({width}, {value})"
        if op == "not" and len(args) == 1:
            return f"(!({args[0]}))"
        if op in {"and_bool", "or_bool"} and args:
            operator = "&&" if op == "and_bool" else "||"
            return "(" + f") {operator} (".join(args) + ")"
        if op == "parity" and len(args) == 2:
            return f"spx_parity({args[1]})"
        if op == "bool_to_bit" and len(args) == 1:
            return f"(({args[0]}) ? 1U : 0U)"
        if op in {"add_overflow", "sub_overflow"} and len(args) == 4:
            helper = "spx_add_overflow" if op == "add_overflow" else "spx_sub_overflow"
            return f"{helper}({', '.join(args)})"
        if op in {"imul_low32", "mul_low32"} and len(args) == 2:
            return f"((uint32_t)((uint64_t)({args[0]}) * (uint64_t)({args[1]})))"
        if op == "imul_high32" and len(args) == 2:
            return f"spx_imul_high({args[0]}, {args[1]})"
        if op == "mul_high32" and len(args) == 2:
            return f"spx_mul_high({args[0]}, {args[1]})"
        if op == "imul_overflow" and len(args) == 5:
            return f"(({args[4]}) != ((int32_t)({args[3]}) < 0 ? 0xffffffffU : 0U))"
        if op == "mul_carry" and len(args) == 4:
            return f"(({args[3]}) != 0U)"
        if op in {"udiv_quot32", "udiv_rem32", "udiv_valid32"} and len(args) == 3:
            helper = {"udiv_quot32": "spx_udiv_quot", "udiv_rem32": "spx_udiv_rem", "udiv_valid32": "spx_udiv_valid"}[op]
            return f"{helper}({', '.join(args)})"
        if op == "bsr_index" and len(args) >= 1:
            return f"spx_bsr({args[-1]})"
        if op == "tzcnt" and len(args) >= 1:
            return f"spx_tzcnt({args[-1]})"
        if op == "sbb_borrow" and len(args) == 5:
            return f"spx_sbb_borrow({', '.join(args)})"
        if op == "sbb_overflow" and len(args) == 5:
            return f"spx_sbb_overflow({', '.join(args)})"
        raise ValueError(f"unsupported semantic operation {op!r} with {len(args)} arguments")


def _render_transfer(row: dict[str, Any], symbol: str) -> str:
    renderer = _ExpressionRenderer()
    updates: list[str] = []
    external_index = 0
    ordered_events = row.get("ordered_events") if isinstance(row.get("ordered_events"), list) else []
    owned_register_outputs = {
        output
        for event in ordered_events
        if isinstance(event, dict) and event.get("kind") == "rep_scas"
        for output in event.get("owned_register_outputs", [])
    }
    owned_flag_outputs = {
        output
        for event in ordered_events
        if isinstance(event, dict) and event.get("kind") == "rep_scas"
        for output in event.get("owned_flag_outputs", [])
    }
    if ordered_events:
        for event in ordered_events:
            if not isinstance(event, dict):
                continue
            family = event.get("family")
            if family == "memory":
                _render_ordered_memory_event(renderer, event)
            elif family == "fault":
                _render_ordered_fault_event(renderer, event)
            elif family == "external":
                _render_ordered_external_event(renderer, event, external_index)
                external_index += 1
    else:
        for event in row.get("memory_events", []):
            if isinstance(event, dict):
                _render_ordered_memory_event(renderer, event)
        for fault in row.get("faults", []):
            if isinstance(fault, dict):
                _render_ordered_fault_event(renderer, fault)

    for write in row.get("register_writes", []):
        if not isinstance(write, dict):
            continue
        register = str(write.get("register") or "")
        if register in _REGISTER_NAMES and register not in owned_register_outputs:
            updates.append(f"  state->{register} = {renderer.render(write.get('value'))};")
    for write in row.get("flag_writes", []):
        if not isinstance(write, dict):
            continue
        flag = str(write.get("flag") or "")
        if flag in _FLAG_NAMES and flag not in owned_flag_outputs:
            updates.append(f"  state->{flag} = ({renderer.render(write.get('value'))}) & 1U;")

    fpu_state = row.get("fpu_state")
    if fpu_state is not None:
        raise ValueError("x87_checked_replay_required")

    outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
    result = _render_outcome(renderer, outcome)
    identity = _c_comment(str(row.get("id") or row.get("block_id") or symbol))
    body = [
        f"/* {identity} */",
        f"spx_step_result {symbol}(spx_runtime *rt, spx_machine_state *state) {{",
        "  spx_machine_state input = *state;",
        "  (void)rt;",
        "  (void)input;",
        "  uint32_t memory_fault = 0U;",
        *renderer.lines,
        "  if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
    ]
    body.extend(updates)
    body.append("  spx_sync_eflags(state);")
    body.append(f"  return {result};")
    body.append("}")
    return "\n".join(body)


def _render_ordered_memory_event(renderer: _ExpressionRenderer, event: dict[str, Any]) -> None:
    address = renderer.render(event.get("address"))
    width = int(event.get("width") or 4)
    if event.get("kind") == "read":
        load = {"op": "load", "width": width, "address": event.get("address")}
        renderer.render(load)
    elif event.get("kind") == "write":
        value = renderer.render(event.get("value"))
        renderer.lines.append(f"  spx_write(rt, {address}, {width}U, {value}, &memory_fault);")
    renderer.lines.append("  if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };")


def _render_ordered_fault_event(renderer: _ExpressionRenderer, event: dict[str, Any]) -> None:
    condition = renderer.render(event.get("condition"))
    if event.get("kind") == "divide_error":
        renderer.lines.append(f"  if ({condition}) return (spx_step_result){{ SPX_DIVIDE_ERROR, 0U, 0U }};")


def _render_ordered_external_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    kind = str(event.get("kind") or "")
    if kind == "rep_movsd":
        _render_rep_movsd_event(renderer, event, event_index)
        return
    if kind == "rep_movs":
        _render_rep_movs_event(renderer, event, event_index)
        return
    if kind == "rep_scas":
        _render_rep_scas_event(renderer, event, event_index)
        return
    if kind == "rep_stos":
        _render_rep_stos_event(renderer, event, event_index)
        return
    if kind not in _CALL_EVENT_KINDS:
        raise ValueError(f"unsupported external event {kind!r}")

    register_inputs = event.get("register_inputs")
    flag_inputs = event.get("flag_inputs")
    if not isinstance(register_inputs, dict) or not isinstance(flag_inputs, dict):
        raise ValueError(f"call event {event_index} has incomplete machine-state inputs")

    renderer.lines.append(f"  spx_machine_state call_input_{event_index} = *state;")
    for register in _REGISTER_NAMES:
        if register not in register_inputs:
            raise ValueError(f"call event {event_index} is missing register input {register}")
        value = renderer.render(register_inputs[register])
        renderer.lines.append(f"  call_input_{event_index}.{register} = {value};")
    for flag in _FLAG_NAMES:
        if flag not in flag_inputs:
            raise ValueError(f"call event {event_index} is missing flag input {flag}")
        value = renderer.render(flag_inputs[flag])
        renderer.lines.append(f"  call_input_{event_index}.{flag} = ({value}) & 1U;")

    arguments = event.get("arguments") if isinstance(event.get("arguments"), list) else []
    rendered_arguments = [renderer.render(value) for value in arguments]
    if rendered_arguments:
        renderer.lines.append(
            f"  const uint32_t call_arguments_{event_index}[] = {{ {', '.join(rendered_arguments)} }};"
        )

    stack_inputs = event.get("stack_inputs") if isinstance(event.get("stack_inputs"), list) else []
    rendered_stack_inputs: list[str] = []
    for stack_input in stack_inputs:
        if not isinstance(stack_input, dict):
            raise ValueError(f"call event {event_index} has an invalid stack input")
        offset = _required_nonnegative_int(stack_input.get("offset"), "stack input offset")
        width = _required_nonnegative_int(stack_input.get("width"), "stack input width")
        value = renderer.render(stack_input.get("value"))
        rendered_stack_inputs.append(f"{{ {offset}U, {width}U, {value} }}")
    if rendered_stack_inputs:
        renderer.lines.append(
            f"  const spx_stack_input call_stack_inputs_{event_index}[] = "
            f"{{ {', '.join(rendered_stack_inputs)} }};"
        )

    event_kind = {
        "external_call": "SPX_CALL_EXTERNAL_IMPORT",
        "internal_call": "SPX_CALL_INTERNAL_DIRECT",
        "indirect_call": "SPX_CALL_INDIRECT",
    }[kind]
    target = (
        renderer.render(event.get("target"))
        if kind == "indirect_call"
        else f"{int(event.get('target_rva') or 0)}U"
    )
    return_rva = int(event.get("return_rva") or 0)
    instruction_rva = int(event.get("instruction_rva") or 0)
    ordinal = event.get("ordinal")
    has_ordinal = isinstance(ordinal, int)
    dll = _c_string(str(event.get("dll"))) if isinstance(event.get("dll"), str) else "0"
    symbol = _c_string(str(event.get("symbol"))) if isinstance(event.get("symbol"), str) else "0"
    argument_pointer = f"call_arguments_{event_index}" if rendered_arguments else "0"
    stack_pointer = f"call_stack_inputs_{event_index}" if rendered_stack_inputs else "0"
    renderer.lines.extend(
        [
            f"  const spx_call_event call_event_{event_index} = {{",
            f"    {event_kind}, {instruction_rva}U, {event_index}U, {target}, {return_rva}U,",
            f"    {dll}, {symbol}, {int(ordinal) if has_ordinal else 0}U, {1 if has_ordinal else 0}U,",
            f"    {argument_pointer}, {len(rendered_arguments)}U,",
            f"    {stack_pointer}, {len(rendered_stack_inputs)}U",
            "  };",
            f"  spx_machine_state call_output_{event_index} = call_input_{event_index};",
            f"  spx_call_status call_status_{event_index} = spx_invoke_call(",
            f"      rt, &call_event_{event_index}, &call_input_{event_index}, &call_output_{event_index});",
            f"  if (call_status_{event_index} == SPX_CALL_UNIMPLEMENTED)",
            "    return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            f"  if (call_status_{event_index} == SPX_CALL_DIVIDE_ERROR)",
            "    return (spx_step_result){ SPX_DIVIDE_ERROR, 0U, 0U };",
            f"  if (call_status_{event_index} == SPX_CALL_MEMORY_FAULT)",
            "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            f"  if (call_status_{event_index} != SPX_CALL_OK)",
            "    return (spx_step_result){ SPX_EXTERNAL_FAULT, 0U, 0U };",
            f"  *state = call_output_{event_index};",
        ]
    )
    renderer.call_outputs.add(event_index)


def _render_rep_movsd_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    _render_rep_movs_event(
        renderer,
        {
            **event,
            "kind": "rep_movs",
            "element_width": 4,
            "address_size": 32,
            "effect_model": "symbolic_string_copy_v2",
            "restart_semantics": "element_committed_v1",
        },
        event_index,
    )


def _render_rep_movs_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    if event.get("effect_model") != "symbolic_string_copy_v2":
        raise ValueError("rep_movs requires symbolic_string_copy_v2")
    _validate_restartable_string_event(event, event_index, "rep_movs")
    width = _required_nonnegative_int(
        event.get("element_width"), "string-copy element width"
    )
    if width not in {1, 2, 4}:
        raise ValueError(f"unsupported string-copy element width {width}")
    source = renderer.render(event.get("source"))
    destination = renderer.render(event.get("destination"))
    count = renderer.render(event.get("count"))
    direction = renderer.render(event.get("direction_flag"))
    instruction_rva = int(event["instruction_rva"])
    backward_step = (-width) & 0xFFFFFFFF
    renderer.lines.extend(
        [
            f"  uint32_t copy_source_{event_index} = {source};",
            f"  uint32_t copy_destination_{event_index} = {destination};",
            f"  uint32_t copy_count_{event_index} = {count};",
            f"  uint32_t copy_step_{event_index} = ({direction}) ? 0x{backward_step:08x}U : {width}U;",
            f"  state->esi = copy_source_{event_index};",
            f"  state->edi = copy_destination_{event_index};",
            f"  state->ecx = copy_count_{event_index};",
            f"  while (copy_count_{event_index} != 0U) {{",
            f"    uint32_t copy_value_{event_index} = spx_read(rt, copy_source_{event_index}, {width}U, &memory_fault);",
            f"    if (memory_fault) return (spx_step_result){{ SPX_MEMORY_FAULT, {instruction_rva}U, 0U }};",
            f"    spx_write(rt, copy_destination_{event_index}, {width}U, copy_value_{event_index}, &memory_fault);",
            "    if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            f"    copy_source_{event_index} += copy_step_{event_index};",
            f"    copy_destination_{event_index} += copy_step_{event_index};",
            f"    --copy_count_{event_index};",
            f"    state->esi = copy_source_{event_index};",
            f"    state->edi = copy_destination_{event_index};",
            f"    state->ecx = copy_count_{event_index};",
            "  }",
        ]
    )


def _render_rep_stos_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    if event.get("effect_model") != "symbolic_string_fill_v2":
        raise ValueError("rep_stos requires symbolic_string_fill_v2")
    _validate_restartable_string_event(event, event_index, "rep_stos")
    width = _required_nonnegative_int(
        event.get("element_width"), "string-fill element width"
    )
    if width not in {1, 2, 4}:
        raise ValueError(f"unsupported string-fill element width {width}")
    destination = renderer.render(event.get("destination"))
    value = renderer.render(event.get("value"))
    count = renderer.render(event.get("count"))
    direction = renderer.render(event.get("direction_flag"))
    instruction_rva = int(event["instruction_rva"])
    backward_step = (-width) & 0xFFFFFFFF
    renderer.lines.extend(
        [
            f"  uint32_t fill_destination_{event_index} = {destination};",
            f"  uint32_t fill_value_{event_index} = {value};",
            f"  uint32_t fill_count_{event_index} = {count};",
            f"  uint32_t fill_step_{event_index} = ({direction}) ? 0x{backward_step:08x}U : {width}U;",
            f"  state->edi = fill_destination_{event_index};",
            f"  state->ecx = fill_count_{event_index};",
            f"  while (fill_count_{event_index} != 0U) {{",
            f"    spx_write(rt, fill_destination_{event_index}, {width}U, fill_value_{event_index}, &memory_fault);",
            f"    if (memory_fault) return (spx_step_result){{ SPX_MEMORY_FAULT, {instruction_rva}U, 0U }};",
            f"    fill_destination_{event_index} += fill_step_{event_index};",
            f"    --fill_count_{event_index};",
            f"    state->edi = fill_destination_{event_index};",
            f"    state->ecx = fill_count_{event_index};",
            "  }",
        ]
    )


def _render_rep_scas_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    if not _valid_rep_scas_event(
        event,
        event_index,
        require_instruction_rva=True,
    ):
        raise ValueError("malformed rep_scas event")
    destination = renderer.render(event.get("destination"))
    accumulator = renderer.render(event.get("accumulator"))
    count = renderer.render(event.get("count"))
    direction = renderer.render(event.get("direction_flag"))
    instruction_rva = int(event["instruction_rva"])
    renderer.lines.extend(
        [
            f"  uint32_t scan_destination_{event_index} = {destination};",
            f"  uint32_t scan_accumulator_{event_index} = ({accumulator}) & 0xffU;",
            f"  uint32_t scan_count_{event_index} = {count};",
            f"  uint32_t scan_step_{event_index} = ({direction}) ? 0xffffffffU : 1U;",
            f"  state->edi = scan_destination_{event_index};",
            f"  state->ecx = scan_count_{event_index};",
            f"  while (scan_count_{event_index} != 0U) {{",
            f"    uint32_t scan_memory_{event_index} = spx_read(rt, scan_destination_{event_index}, 1U, &memory_fault) & 0xffU;",
            f"    if (memory_fault) return (spx_step_result){{ SPX_MEMORY_FAULT, {instruction_rva}U, 0U }};",
            f"    uint32_t scan_result_{event_index} = (scan_accumulator_{event_index} - scan_memory_{event_index}) & 0xffU;",
            f"    scan_destination_{event_index} += scan_step_{event_index};",
            f"    --scan_count_{event_index};",
            f"    state->edi = scan_destination_{event_index};",
            f"    state->ecx = scan_count_{event_index};",
            f"    state->cf = scan_accumulator_{event_index} < scan_memory_{event_index};",
            f"    state->zf = scan_result_{event_index} == 0U;",
            f"    state->sf = (scan_result_{event_index} >> 7) & 1U;",
            f"    state->of = (((scan_accumulator_{event_index} ^ scan_memory_{event_index}) & (scan_accumulator_{event_index} ^ scan_result_{event_index}) & 0x80U) != 0U);",
            f"    state->pf = spx_parity(scan_result_{event_index});",
            f"    state->eflags = (state->eflags & ~(1U << 4)) | ((((scan_accumulator_{event_index} ^ scan_memory_{event_index} ^ scan_result_{event_index}) >> 4) & 1U) << 4);",
            "    spx_sync_eflags(state);",
            "    if (state->zf != 0U) break;",
            "  }",
        ]
    )


def _validate_restartable_string_event(
    event: dict[str, Any], event_index: int, kind: str
) -> None:
    if _required_nonnegative_int(event.get("index"), f"{kind} event index") != event_index:
        raise ValueError(f"{kind} event index does not match ordered position")
    if event.get("address_size") != 32:
        raise ValueError(f"{kind} requires 32-bit address size")
    if event.get("restart_semantics") != "element_committed_v1":
        raise ValueError(f"{kind} requires element_committed_v1 restart semantics")


def _render_outcome(renderer: _ExpressionRenderer, outcome: dict[str, Any]) -> str:
    kind = str(outcome.get("kind") or "")
    if kind == "fallthrough":
        return f"(spx_step_result){{ SPX_FALLTHROUGH, {int(outcome.get('target_rva') or 0)}U, 0U }}"
    if kind == "jump":
        return f"(spx_step_result){{ SPX_JUMP, {int(outcome.get('target_rva') or 0)}U, 0U }}"
    if kind == "branch":
        condition = renderer.render(outcome.get("condition"))
        true_target = int(outcome.get("true_target_rva") or 0)
        false_target = int(outcome.get("false_target_rva") or 0)
        return f"(spx_step_result){{ SPX_BRANCH, ({condition}) ? {true_target}U : {false_target}U, 0U }}"
    if kind == "return":
        value = renderer.render(outcome.get("value"))
        return f"(spx_step_result){{ SPX_RETURN, 0U, {value} }}"
    if kind == "indirect_jump":
        target = renderer.render(outcome.get("target"))
        return f"(spx_step_result){{ SPX_INDIRECT_JUMP, 0U, {target} }}"
    if kind == "external_jump":
        return "(spx_step_result){ SPX_EXTERNAL_JUMP, 0U, 0U }"
    raise ValueError(f"unsupported semantic outcome {kind!r}")


def _stable_slot(value: str) -> int:
    result = 2166136261
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def _required_nonnegative_int(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{description} must be a nonnegative integer")
    return value


def _c_comment(value: str) -> str:
    return value.replace("*/", "* /").replace("\n", " ")
