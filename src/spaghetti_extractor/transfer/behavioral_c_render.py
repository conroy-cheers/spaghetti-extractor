"""Direct C rendering from the canonical checked transfer IR.

This module contains no semantic decoder.  It renders the already checked
nodes and scheduled actions produced by :class:`_TransferCompiler` as ordinary
C expressions, statements, branches, and labels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .behavioral_c_model import BehavioralCFunction, BehavioralCPlan
from .runtime_helpers import runtime_helpers
from .model import (
    TransferPlanError,
    _AF_FLAG_INDEX,
    _Action,
    _Call,
    _FLAGS,
    _Node,
    _REGISTERS,
    _Transfer,
)
from .values import _c_string
from .interpretation import (
    DomainOperationCoverageV2,
    total_domain_coverage_v2,
)


def behavioral_c_operation_coverage_v2() -> DomainOperationCoverageV2:
    return total_domain_coverage_v2("behavioral_c")


def behavioral_c_dispatch_abi_declarations() -> tuple[str, ...]:
    """Return the shared ABI used by generated and portable dispatch tables."""

    return (
        "typedef spx_step_result (*spx_region_override_fn)(",
        "    spx_runtime *, spx_machine_state *);",
        "typedef struct spx_region_override {",
        "  uint32_t entry_rva;",
        "  spx_region_override_fn function;",
        "  uint32_t fallback_on_unimplemented;",
        "  const char *replacement_id;",
        "  const char *cluster_id;",
        "} spx_region_override;",
    )


def behavioral_c_header(plan: BehavioralCPlan) -> str:
    declarations = [
        f"spx_step_result {function.symbol}("
        "spx_runtime *runtime, spx_machine_state *state, uint32_t entry_rva);"
        for function in plan.functions
    ]
    return "\n".join(
        [
            "#ifndef SPX_BEHAVIORAL_C_H",
            "#define SPX_BEHAVIORAL_C_H",
            "",
            '#include "state-machine-runtime.h"',
            "",
            *_SHARED_HELPER_DECLARATIONS.splitlines(),
            "",
            *behavioral_c_dispatch_abi_declarations(),
            "",
            *declarations,
            "",
            "extern const uint32_t spx_behavioral_transfer_count;",
            "uint32_t spx_behavioral_has_unit(uint32_t source_rva);",
            "uint32_t spx_behavioral_function_owner(",
            "    uint32_t source_rva, uint32_t *owner_rva);",
            "spx_step_result spx_behavioral_step(",
            "    spx_runtime *runtime, spx_machine_state *state, uint32_t source_rva);",
            "spx_call_status spx_behavioral_run(",
            "    spx_runtime *runtime, uint32_t entry_rva,",
            "    const spx_machine_state *input, spx_machine_state *output);",
            "",
            "#endif",
            "",
        ]
    )


def behavioral_c_source(
    transfers: Iterable[_Transfer], plan: BehavioralCPlan
) -> tuple[str, dict[int, tuple[int, int]]]:
    by_rva = {row.rva_start: row for row in transfers}
    lines = [
        '#include "behavioral-c.h"',
        "",
        *runtime_helpers().splitlines(),
        "",
        *_DIRECT_HELPERS.splitlines(),
    ]
    for transfer in sorted(by_rva.values(), key=lambda row: row.rva_start):
        lines.extend(_typed_x87_definitions(transfer))
    spans: dict[int, tuple[int, int]] = {}
    for function in plan.functions:
        lines.append("")
        renderer = _FunctionRenderer(
            function=function,
            by_rva=by_rva,
            forced_labels=frozenset(plan.forced_labels),
        )
        rendered, local_spans = renderer.render()
        offset = len(lines)
        lines.extend(rendered)
        spans.update(
            {rva: (start + offset, end + offset) for rva, (start, end) in local_spans.items()}
        )
    lines.extend(["", *_dispatch_source(plan).splitlines()])
    return "\n".join(lines).rstrip() + "\n", spans


def behavioral_c_translation_units(
    transfers: Iterable[_Transfer], plan: BehavioralCPlan
) -> tuple[dict[str, str], dict[int, dict[str, object]]]:
    """Emit one stable translation unit per derived function plus dispatch."""

    by_rva = {row.rva_start: row for row in transfers}
    files: dict[str, str] = {}
    source_map: dict[int, dict[str, object]] = {}
    for function in plan.functions:
        primary = min(function.unit_rvas)
        filename = f"behavioral-fn-{primary:08x}.c"
        lines = [
            '#include "behavioral-c.h"',
        ]
        for rva in function.unit_rvas:
            lines.extend(_typed_x87_definitions(by_rva[rva]))
        lines.append("")
        rendered, spans = _FunctionRenderer(
            function=function,
            by_rva=by_rva,
            forced_labels=frozenset(plan.forced_labels),
        ).render()
        offset = len(lines)
        lines.extend(rendered)
        files[filename] = "\n".join(lines).rstrip() + "\n"
        for rva, (start, end) in spans.items():
            transfer = by_rva[rva]
            source_map[rva] = {
                "unit_id": transfer.identity,
                "rva": rva,
                "function_id": function.identity,
                "symbol": function.symbol,
                "file": filename,
                "line_start": start + offset,
                "line_end": end + offset,
            }
    files["behavioral-dispatch.c"] = (
        '#include "behavioral-c.h"\n\n' + _dispatch_source(plan).rstrip() + "\n"
    )
    files["behavioral-support.c"] = behavioral_c_support_source()
    if set(source_map) != set(by_rva):
        raise TransferPlanError(
            "behavioral-C translation-unit source map is not total",
            code="behavioral_c_source_map_incomplete",
        )
    return dict(sorted(files.items())), source_map


def behavioral_c_support_source() -> str:
    """Emit common semantic helpers once for the whole generated module."""

    direct = _DIRECT_HELPERS.replace(
        "#if defined(__GNUC__) || defined(__clang__)\n"
        "#define SPX_DIRECT_HELPER static __attribute__((unused))\n"
        "#else\n#define SPX_DIRECT_HELPER static\n#endif\n\n",
        "",
    ).replace("SPX_DIRECT_HELPER ", "").replace("\n\n#undef SPX_DIRECT_HELPER", "")
    return "\n".join((
        '#include "behavioral-c.h"',
        "",
        runtime_helpers(external_linkage=True).rstrip(),
        "",
        direct.rstrip(),
        "",
    ))


@dataclass
class _FunctionRenderer:
    function: BehavioralCFunction
    by_rva: dict[int, _Transfer]
    forced_labels: frozenset[int] = frozenset()
    lines: list[str] = field(default_factory=list)
    materialized: dict[int, set[int]] = field(default_factory=dict)
    current: _Transfer | None = None

    def render(self) -> tuple[list[str], dict[int, tuple[int, int]]]:
        self.lines.extend(
            [
                f"spx_step_result {self.function.symbol}(",
                "    spx_runtime *rt, spx_machine_state *state, uint32_t entry_rva) {",
                "  spx_machine_state input, call_output;",
                "  uint32_t memory_fault = 0U, semantic_fault = 0U;",
                "  (void)rt;",
                "  (void)call_output;",
            ]
        )
        for rva in self.function.unit_rvas:
            transfer = self.by_rva[rva]
            if transfer.x87_nodes:
                raise TransferPlanError(
                    f"{transfer.identity}: legacy symbolic x87 nodes cannot be emitted as faithful C",
                    code="behavioral_c_legacy_x87_unavailable",
                    next_action="use typed exact x87 operations and an exact support runtime",
                )
            for index in range(len(transfer.nodes)):
                self.lines.append(f"  uint32_t {_word_name(rva, index)} = 0U;")
        self.lines.extend(
            [
                "  if (state == 0) return (spx_step_result){ SPX_UNIMPLEMENTED, entry_rva, 0U };",
                "  switch (entry_rva) {",
            ]
        )
        # The public step API may enter any checked unit.  Function entries in
        # the plan remain the semantic roots; this one selector also supports
        # diagnostics and external resumptions without a program-counter loop.
        for entry in self.function.unit_rvas:
            self.lines.append(f"    case 0x{entry:08x}U: goto {_label(entry)};")
        self.lines.extend(
            [
                "    default: return (spx_step_result){ SPX_UNIMPLEMENTED, entry_rva, 0U };",
                "  }",
            ]
        )
        spans: dict[int, tuple[int, int]] = {}
        for rva in self.function.unit_rvas:
            self.current = self.by_rva[rva]
            self.materialized[rva] = set()
            start = len(self.lines) + 1
            self.lines.extend(
                [
                    f"{_label(rva)}:",
                    "  input = *state;",
                    "  call_output = input;",
                    "  memory_fault = 0U;",
                    "  semantic_fault = 0U;",
                    "  (void)memory_fault;",
                    "  (void)semantic_fault;",
                    f"  state->original_rva = 0x{rva:08x}U;",
                ]
            )
            for action in self.current.actions:
                self._action(action)
            spans[rva] = (start, len(self.lines))
        self.lines.append("}")
        return self.lines, spans

    @property
    def transfer(self) -> _Transfer:
        assert self.current is not None
        return self.current

    def _word(self, index: int) -> str:
        if not 0 <= index < len(self.transfer.nodes):
            raise TransferPlanError(
                f"{self.transfer.identity}: word node reference {index} is out of range",
                code="behavioral_c_node_reference_invalid",
            )
        done = self.materialized[self.transfer.rva_start]
        if index in done:
            return _word_name(self.transfer.rva_start, index)
        node = self.transfer.nodes[index]
        arguments = [self._word(value) for value in node.args]
        value = self._node_expression(node, arguments)
        name = _word_name(self.transfer.rva_start, index)
        self.lines.append(f"  {name} = {value};")
        # Some canonical helpers carry checked structural operands (for
        # example, an explicit width) which disappear in the corresponding C
        # helper call.  Keep every scheduled SSA evaluation visible to C while
        # remaining warning-clean when such a value has no later data use.
        self.lines.append(f"  (void){name};")
        done.add(index)
        return name

    def _node_expression(self, node: _Node, args: list[str]) -> str:
        op = node.op
        current = "state->" if node.immediate else "input."
        if op == "const":
            return f"0x{node.immediate & 0xFFFFFFFF:08x}U"
        if op == "reg":
            return current + _index(_REGISTERS, node.aux, "register", self.transfer)
        if op == "flag":
            if node.aux == _AF_FLAG_INDEX:
                source = "state->eflags" if node.immediate else "input.eflags"
                return f"(({source} >> 4U) & 1U)"
            return current + _index(_FLAGS, node.aux, "flag", self.transfer)
        if op == "fs_base":
            return current + "fs_base"
        if op == "true":
            return "1U"
        if op == "false":
            return "0U"
        if op in {"undefined_bv", "undefined_flag"}:
            defined = args[0] if args else "0U"
            return f"spx_undefined(rt, {node.immediate}U, &input, {defined})"
        if op == "call_response":
            return "call_output." + _index(_REGISTERS, node.aux, "call register", self.transfer)
        if op == "call_flag":
            if node.aux == _AF_FLAG_INDEX:
                return "((call_output.eflags >> 4U) & 1U)"
            return "call_output." + _index(_FLAGS, node.aux, "call flag", self.transfer)
        if op == "load":
            _arity(self.transfer, node, args, 1)
            return f"spx_read(rt, {args[0]}, {node.aux}U, &memory_fault)"
        infix = {
            "sub32": "-", "ult32": "<", "eq": "==", "xor_bool": "!=",
            "eq_bool": "==",
        }
        if op in infix:
            _arity(self.transfer, node, args, 2)
            if args[0] == args[1]:
                if op in {"eq", "eq_bool"}:
                    return "1U"
                if op in {"ult32", "xor_bool"}:
                    return "0U"
            return f"(({args[0]}) {infix[op]} ({args[1]}))"
        associative = {"add32": "+", "mul32": "*", "xor32": "^", "and32": "&", "or32": "|"}
        if op in associative and args:
            return "(" + f") {associative[op]} (".join(args) + ")"
        if op in {"not32", "neg32"}:
            _arity(self.transfer, node, args, 1)
            return f"({'~' if op == 'not32' else '0U - '}({args[0]}))"
        if op in {"shl32", "lshr32"}:
            _arity(self.transfer, node, args, 2)
            return f"(({args[0]}) {'<<' if op == 'shl32' else '>>'} (({args[1]}) & 31U))"
        if op == "sar":
            _arity(self.transfer, node, args, 3)
            return f"spx_sar({', '.join(args)})"
        if op == "sign_extend":
            _arity(self.transfer, node, args, 2)
            return f"spx_sign_extend({', '.join(args)})"
        if op == "ite":
            _arity(self.transfer, node, args, 3)
            return f"(({args[0]}) ? ({args[1]}) : ({args[2]}))"
        if op == "msb":
            if len(args) == 1:
                return f"spx_msb(32U, {args[0]})"
            _arity(self.transfer, node, args, 2)
            return f"spx_msb({args[0]}, {args[1]})"
        if op == "not":
            _arity(self.transfer, node, args, 1)
            return f"(!({args[0]}))"
        if op in {"and_bool", "or_bool"} and args:
            operator = "&&" if op == "and_bool" else "||"
            return "(" + f") {operator} (".join(args) + ")"
        if op == "parity":
            _arity(self.transfer, node, args, 2)
            return f"spx_parity({args[1]})"
        if op == "bool_to_bit":
            _arity(self.transfer, node, args, 1)
            return f"(({args[0]}) ? 1U : 0U)"
        helpers = {
            "add_overflow": "spx_add_overflow", "sub_overflow": "spx_sub_overflow",
            "imul_high32": "spx_imul_high", "mul_high32": "spx_mul_high",
            "udiv_quot32": "spx_udiv_quot", "udiv_rem32": "spx_udiv_rem",
            "udiv_valid32": "spx_udiv_valid", "sbb_borrow": "spx_sbb_borrow",
            "sbb_overflow": "spx_sbb_overflow",
        }
        if op in helpers:
            return f"{helpers[op]}({', '.join(args)})"
        if op in {"imul_low32", "mul_low32"}:
            _arity(self.transfer, node, args, 2)
            return f"((uint32_t)((uint64_t)({args[0]}) * (uint64_t)({args[1]})))"
        if op == "imul_overflow":
            _arity(self.transfer, node, args, 5)
            return f"(({args[4]}) != ((int32_t)({args[3]}) < 0 ? 0xffffffffU : 0U))"
        if op == "mul_carry":
            _arity(self.transfer, node, args, 4)
            return f"(({args[3]}) != 0U)"
        if op == "bsr_index":
            return f"spx_bsr({args[-1]})"
        if op == "tzcnt":
            return f"spx_tzcnt({args[-1]})"
        if op == "shift_cf":
            _arity(self.transfer, node, args, 2)
            return f"spx_shift_cf({node.aux >> 8}U, {node.aux & 255}U, {args[0]}, {args[1]})"
        if op == "shift_of":
            _arity(self.transfer, node, args, 3)
            return f"spx_shift_of({node.aux >> 8}U, {node.aux & 255}U, {args[0]}, {args[1]}, {args[2]})"
        if op in {"adc_carry", "adc_overflow"}:
            _arity(self.transfer, node, args, 5)
            helper = "spx_adc_carry_checked" if op == "adc_carry" else "spx_adc_overflow_checked"
            return f"{helper}({', '.join(args)}, &semantic_fault)"
        x87_fields = {
            "fpu_control": "x87_control", "fpu_status": "x87_status",
            "fpu_pending_exception": "x87_pending_exception",
            "fpu_last_opcode": "x87_last_opcode",
            "fpu_instruction_pointer": "x87_instruction_pointer",
            "fpu_code_selector": "x87_code_selector",
            "fpu_data_pointer": "x87_data_pointer", "fpu_data_selector": "x87_data_selector",
        }
        if op in x87_fields:
            return current + x87_fields[op]
        if op == "fpu_control_init":
            return "0x037fU"
        if op == "fpu_status_init":
            return "0U"
        if op == "fpu_tag":
            if not 0 <= node.aux < 8:
                raise TransferPlanError(f"{self.transfer.identity}: x87 tag index is invalid")
            return f"{current}x87_stack[{node.aux}].tag"
        if op in {"fpu_control_load", "fpu_control_word", "fpu_status_word"}:
            _arity(self.transfer, node, args, 1)
            return f"(({args[0]}) & 0xffffU)"
        raise TransferPlanError(
            f"{self.transfer.identity}: behavioral-C renderer lacks word op {op!r}",
            code="behavioral_c_word_op_unavailable",
            next_action="add direct faithful lowering for the checked canonical word operation",
        )

    def _action(self, action: _Action) -> None:
        op = action.op
        if op == "eval_word":
            _arity(self.transfer, action, list(action.args), 1)
            self._word(action.args[0])
            self.lines.extend(self._fault_checks())
        elif op == "memory_write":
            address, value = (self._word(index) for index in action.args)
            self.lines.extend(
                [
                    f"  spx_write(rt, {address}, {action.aux}U, {value}, &memory_fault);",
                    *self._fault_checks(),
                ]
            )
        elif op == "divide_if":
            condition = self._word(action.args[0])
            self.lines.append(
                f"  if ({condition}) return (spx_step_result){{ SPX_DIVIDE_ERROR, 0U, 0U }};"
            )
        elif op == "access_violation_if":
            condition, operation, address = (
                self._word(index) for index in action.args
            )
            self.lines.extend([
                f"  if ({condition}) {{",
                "    if (rt == 0 || rt->record_access_violation == 0 ||",
                f"        rt->record_access_violation(rt->context, {operation}, {address}) == 0U)",
                "      return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
                "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                "  }",
            ])
        elif op == "call":
            self._call(self.transfer.calls[action.args[0]], action.args[0])
        elif op in {"rep_movsd", "rep_movs", "rep_stosd", "rep_stos", "rep_scas"}:
            self._string_action(action)
        elif op == "set_reg":
            value = self._word(action.args[0])
            name = _index(_REGISTERS, action.aux, "register", self.transfer)
            self.lines.append(f"  state->{name} = {value};")
        elif op == "set_flag":
            value = self._word(action.args[0])
            if action.aux == _AF_FLAG_INDEX:
                self.lines.append(
                    "  state->eflags = (state->eflags & ~(1U << 4U)) | "
                    f"((({value}) & 1U) << 4U);"
                )
            else:
                name = _index(_FLAGS, action.aux, "flag", self.transfer)
                self.lines.append(f"  state->{name} = ({value}) & 1U;")
        elif op == "sync_eflags":
            self.lines.append("  spx_sync_eflags(state);")
        elif op == "typed_x87":
            self._typed_x87(action)
        elif op in {"atomic_compare_exchange", "atomic_exchange"}:
            self._atomic(action)
        elif op.startswith("outcome_"):
            self._outcome(action)
        else:
            raise TransferPlanError(
                f"{self.transfer.identity}: behavioral-C renderer lacks action {op!r}",
                code="behavioral_c_action_unavailable",
                next_action="add direct faithful lowering for the checked canonical action",
            )

    def _call(self, call: _Call, local_index: int) -> None:
        refs = [
            *call.register_nodes,
            *call.flag_nodes,
            *call.argument_nodes,
            *(value for _offset, _width, value in call.stack_inputs),
        ]
        if call.target_node is not None:
            refs.append(call.target_node)
        for ref in refs:
            self._word(ref)
        suffix = f"{self.transfer.rva_start:08x}_{local_index}"
        args = ", ".join(self._word(value) for value in call.argument_nodes)
        stack = ", ".join(
            f"{{ {offset}U, {width}U, {self._word(value)} }}"
            for offset, width, value in call.stack_inputs
        )
        kind = {"external_call": "SPX_CALL_EXTERNAL_IMPORT", "internal_call": "SPX_CALL_INTERNAL_DIRECT", "indirect_call": "SPX_CALL_INDIRECT"}[call.kind]
        target = self._word(call.target_node) if call.target_node is not None else f"0x{call.target_rva:08x}U"
        self.lines.extend(
            [
                "  {",
                "    spx_machine_state call_input = *state;",
                *(
                    [
                        f"    call_input.original_rva = 0x{call.instruction_rva:08x}U;"
                    ]
                    if call.native_exception_operations else []
                ),
            ]
        )
        for index, name in enumerate(_REGISTERS):
            self.lines.append(f"    call_input.{name} = {self._word(call.register_nodes[index])};")
        for index, name in enumerate(_FLAGS):
            self.lines.append(f"    call_input.{name} = ({self._word(call.flag_nodes[index])}) & 1U;")
        if args:
            self.lines.append(
                f"    const uint32_t call_arguments_{suffix}[] = {{ {args} }};"
            )
        if stack:
            self.lines.append(
                f"    const spx_stack_input call_stack_{suffix}[] = {{ {stack} }};"
            )
        self.lines.extend(
            [
                f"    const spx_call_event event = {{ {kind}, 0x{self.transfer.rva_start:08x}U, 0x{call.instruction_rva:08x}U,",
                f"      {call.call_index}U, {target}, 0x{call.return_rva:08x}U,",
                f"      {_c_string(call.dll)}, {_c_string(call.symbol)}, {call.ordinal or 0}U, {1 if call.ordinal is not None else 0}U,",
                f"      {'call_arguments_' + suffix if call.argument_nodes else '0'}, {len(call.argument_nodes)}U,",
                f"      {'call_stack_' + suffix if call.stack_inputs else '0'}, {len(call.stack_inputs)}U }};",
                "    spx_call_status status;",
                "    call_output = call_input;",
                "    status = spx_invoke_call(rt, &event, &call_input, &call_output);",
                "    if (status != SPX_CALL_OK) {",
                "      *state = call_output;",
                "      return spx_call_status_result(status, state->original_rva);",
                "    }",
                "    *state = call_output;",
                f"    state->original_rva = 0x{self.transfer.rva_start:08x}U;",
                "  }",
            ]
        )

    def _atomic(self, action: _Action) -> None:
        for index in action.args[:-1]:
            self._word(index)
        observed_index = action.args[-1]
        done = self.materialized[self.transfer.rva_start]
        if observed_index in done:
            raise TransferPlanError(
                f"{self.transfer.identity}: atomic observation was materialized before its RMW",
                code="behavioral_c_atomic_order_violation",
            )
        observed = _word_name(self.transfer.rva_start, observed_index)
        if action.op == "atomic_compare_exchange":
            address, expected, desired = (self._word(index) for index in action.args[:3])
            self.lines.extend(
                [
                    "  {",
                    "    uint32_t exchanged = 0U;",
                    f"    spx_runtime_atomic_compare_exchange(rt, {address}, {action.aux}U, {expected}, {desired},",
                    f"        &{observed}, &exchanged, &memory_fault);",
                    "    (void)exchanged;",
                    "  }",
                ]
            )
        else:
            address, desired = (self._word(index) for index in action.args[:2])
            self.lines.extend(
                [
                    f"  spx_runtime_atomic_exchange(rt, {address}, {action.aux}U, {desired},",
                    f"      &{observed}, &memory_fault);",
                ]
            )
        done.add(observed_index)
        self.lines.extend(self._fault_checks())

    def _typed_x87(self, action: _Action) -> None:
        index = action.args[0]
        if not 0 <= index < len(self.transfer.x87_operations):
            raise TransferPlanError(
                f"{self.transfer.identity}: typed x87 action index is invalid",
                code="behavioral_c_typed_x87_invalid",
            )
        symbol = _x87_symbol(self.transfer.rva_start, index)
        self.lines.extend(
            [
                "  {",
                "    spx_machine_state operation_output = *state;",
                "    spx_call_status status;",
                "    if (rt == 0 || rt->execute_typed_x87_operation == 0)",
                f"      return (spx_step_result){{ SPX_UNIMPLEMENTED, 0x{self.transfer.rva_start:08x}U, 0U }};",
                f"    status = rt->execute_typed_x87_operation(rt, &{symbol}, state, &operation_output);",
                "    if (status != SPX_CALL_OK) return spx_call_status_result(status, state->original_rva);",
                "    *state = operation_output;",
                "  }",
            ]
        )

    def _string_action(self, action: _Action) -> None:
        values = [self._word(index) for index in action.args]
        op = action.op
        if op in {"rep_movsd", "rep_movs"}:
            width = 4 if op == "rep_movsd" else action.aux
            source, destination, count, direction = values
            self.lines.extend(_render_rep_movs(source, destination, count, direction, width))
        elif op in {"rep_stosd", "rep_stos"}:
            width = 4 if op == "rep_stosd" else action.aux
            destination, value, count, direction = values
            self.lines.extend(_render_rep_stos(destination, value, count, direction, width))
        else:
            accumulator, destination, count, direction = values
            self.lines.extend(_render_rep_scas(accumulator, destination, count, direction))

    def _outcome(self, action: _Action) -> None:
        internal = set(self.function.unit_rvas)
        if action.op in {"outcome_fallthrough", "outcome_jump"}:
            target = action.args[0]
            if target in internal and target not in self.forced_labels:
                self.lines.append(f"  goto {_label(target)};")
            else:
                kind = "SPX_FALLTHROUGH" if action.op == "outcome_fallthrough" else "SPX_JUMP"
                self.lines.append(f"  return (spx_step_result){{ {kind}, 0x{target:08x}U, 0U }};")
        elif action.op == "outcome_branch":
            condition = self._word(action.args[0])
            true_target, false_target = action.args[1:3]
            true_result = _edge_statement(
                true_target, internal, self.forced_labels, "SPX_BRANCH"
            )
            false_result = _edge_statement(
                false_target, internal, self.forced_labels, "SPX_BRANCH"
            )
            self.lines.extend([f"  if ({condition}) {true_result}", f"  {false_result}"])
        elif action.op == "outcome_return":
            value = self._word(action.args[0])
            self.lines.append(f"  return (spx_step_result){{ SPX_RETURN, 0U, {value} }};")
        elif action.op == "outcome_indirect":
            value = self._word(action.args[0])
            self.lines.append(f"  return (spx_step_result){{ SPX_INDIRECT_JUMP, 0U, {value} }};")
        elif action.op == "outcome_nonlocal":
            target = self._word(action.args[0])
            value = self._word(action.args[1])
            self.lines.append(
                "  return (spx_step_result){ SPX_NONLOCAL, "
                f"{target}, {value} }};"
            )
        elif action.op == "outcome_external":
            self.lines.append("  return (spx_step_result){ SPX_EXTERNAL_JUMP, 0U, 0U };")
        else:
            raise TransferPlanError(f"{self.transfer.identity}: invalid outcome action")

    @staticmethod
    def _fault_checks() -> list[str]:
        return [
            "  if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            "  if (semantic_fault) return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
        ]


def _typed_x87_definitions(transfer: _Transfer) -> list[str]:
    lines: list[str] = []
    for index, program in enumerate(transfer.x87_operations):
        operation = program.operation
        operand = operation.operand
        register_codes = {None: 0, "eax": 1, "ebx": 2, "ecx": 3, "edx": 4, "esi": 5, "edi": 6, "ebp": 7, "esp": 8}
        operand_kinds = {"none": 0, "ax": 1, "stack": 2, "memory": 3}
        registers = (*operand.registers, 0, 0)
        lines.extend(
            [
                "",
                f"static const spx_typed_x87_operation {_x87_symbol(transfer.rva_start, index)} = {{",
                f"  0x{program.image_base:08x}U, 0x{program.rva_start:08x}U, 0x{program.rva_end:08x}U, {operation.source_size}U,",
                f"  {_c_string(operation.identity)}, {_c_string(program.contract_sha256)},",
                f"  {_c_string(program.checked_decoder)}, {_c_string(program.checked_executor)}, {_c_string(operation.mnemonic)},",
                f"  {operand_kinds[operand.kind]}U, {operand.width}U, {len(operand.registers)}U, {registers[0]}U, {registers[1]}U,",
                f"  {register_codes[operand.base]}U, {register_codes[operand.index]}U, {operand.scale}U, {operand.displacement},",
                f"  {operand.image_rva or 0}U, {1 if operand.image_rva is not None else 0}U",
                "};",
            ]
        )
    return lines


def _dispatch_source(plan: BehavioralCPlan) -> str:
    cases = []
    for function in plan.functions:
        for rva in function.unit_rvas:
            cases.append(f"    case 0x{rva:08x}U: return {function.symbol}(rt, state, source_rva);")
    return "\n".join(
        [
            "extern const spx_region_override *spx_region_override_lookup(",
            "    uint32_t entry_rva) __attribute__((weak));",
            "extern uint32_t spx_native_machine_fallback_allowed(",
            "    uint32_t source_rva) __attribute__((weak));",
            "",
            f"const uint32_t spx_behavioral_transfer_count = {sum(len(function.unit_rvas) for function in plan.functions)}U;",
            "",
            "static uint32_t spx_behavioral_override_result_valid(spx_step_result result) {",
            "  if (result.kind > SPX_NONLOCAL) return 0U;",
            "  if (result.kind <= SPX_BRANCH)",
            "    return result.target_rva != 0U && result.value == 0U;",
            "  if (result.kind == SPX_RETURN) return result.target_rva == 0U;",
            "  if (result.kind == SPX_INDIRECT_JUMP)",
            "    return result.target_rva == 0U && result.value != 0U;",
            "  if (result.kind == SPX_NONLOCAL)",
            "    return result.target_rva != 0U;",
            "  if (result.kind == SPX_UNIMPLEMENTED) return result.value == 0U;",
            "  return result.target_rva == 0U && result.value == 0U;",
            "}",
            "",
            "uint32_t spx_behavioral_has_unit(uint32_t source_rva) {",
            "  switch (source_rva) {",
            *(f"    case 0x{rva:08x}U: return 1U;" for function in plan.functions for rva in function.unit_rvas),
            "    default: return 0U;",
            "  }",
            "}",
            "",
            "uint32_t spx_behavioral_function_owner(",
            "    uint32_t source_rva, uint32_t *owner_rva) {",
            "  if (owner_rva == 0) return 0U;",
            "  switch (source_rva) {",
            *(
                f"    case 0x{rva:08x}U: *owner_rva = "
                f"0x{min(function.unit_rvas):08x}U; return 1U;"
                for function in plan.functions
                for rva in function.unit_rvas
            ),
            "    default: return 0U;",
            "  }",
            "}",
            "",
            "spx_step_result spx_behavioral_step(",
            "    spx_runtime *rt, spx_machine_state *state, uint32_t source_rva) {",
            "  if (state == 0)",
            "    return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };",
            "  const spx_region_override *override =",
            "      spx_region_override_lookup == 0 ? 0 : spx_region_override_lookup(source_rva);",
            "  if (override != 0) {",
            "    spx_machine_state overridden = *state;",
            "    spx_step_result result;",
            "    if (override->entry_rva != source_rva || override->function == 0)",
            "      return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };",
            "    result = override->function(rt, &overridden);",
            "    if (!spx_behavioral_override_result_valid(result))",
            "      return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };",
            "    if (!(result.kind == SPX_UNIMPLEMENTED &&",
            "          override->fallback_on_unimplemented != 0U)) {",
            "      *state = overridden;",
            "      return result;",
            "    }",
            "  }",
            "  if (spx_native_machine_fallback_allowed != 0 &&",
            "      !spx_native_machine_fallback_allowed(source_rva))",
            "    return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };",
            "  switch (source_rva) {",
            *cases,
            "    default: return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };",
            "  }",
            "}",
            "",
            "spx_call_status spx_behavioral_run(",
            "    spx_runtime *rt, uint32_t entry_rva,",
            "    const spx_machine_state *input, spx_machine_state *output) {",
            "  spx_machine_state state;",
            "  uint32_t rva = entry_rva;",
            "  if (input == 0 || output == 0) return SPX_CALL_UNIMPLEMENTED;",
            "  state = *input;",
            "  for (;;) {",
            # A rendered function may execute several transfer units through
            # local C gotos before returning one step result.  Seed the
            # metadata with the requested unit, then preserve the exact last
            # unit written by the generated transfer body.  Using the outer
            # dispatch RVA here loses the semantic site identity for an
            # indirect/nonlocal terminator reached later in the same function.
            "    state.original_rva = rva;",
            "    spx_step_result result = spx_behavioral_step(rt, &state, rva);",
            "    const uint32_t source_rva =",
            "        result.kind == SPX_NONLOCAL && result.target_rva == 0U",
            "        ? rva : state.original_rva;",
            "    if (result.kind <= SPX_BRANCH) { rva = result.target_rva; continue; }",
            "    if (result.kind == SPX_INDIRECT_JUMP) {",
            "      uint32_t next_rva;",
            "      if (rt != 0 && rt->resolve_code_target != 0 &&",
            "          rt->resolve_code_target(",
            "              rt, SPX_CODE_SITE_INDIRECT_JUMP, source_rva, source_rva, 0U,",
            "              result.value, &next_rva) == 0U) {",
            "        rva = next_rva;",
            "        continue;",
            "      }",
            "      if (rt != 0 && rt->invoke_callable_external_jump != 0) {",
            "        spx_machine_state external_output = state;",
            "        spx_call_status status = rt->invoke_callable_external_jump(",
            "            rt, source_rva, result.value, &state, &external_output);",
            "        if (status == SPX_CALL_OK) { *output = external_output; return status; }",
            "        *output = state; output->original_rva = source_rva; return status;",
            "      }",
            "    }",
            "    if (result.kind == SPX_NONLOCAL) {",
            "      uint32_t resume_rva = 0U, route = 2U;",
            "      if (rt != 0 && rt->route_nonlocal != 0)",
            "        route = rt->route_nonlocal(",
            "            rt, source_rva, result.target_rva, result.value,",
            "            entry_rva, &state, &resume_rva);",
            "      if (route == 0U) { rva = resume_rva; continue; }",
            "      *output = state; output->original_rva = source_rva;",
            "      return route == 1U ? SPX_CALL_NONLOCAL : SPX_CALL_UNIMPLEMENTED;",
            "    }",
            "    *output = state;",
            "    output->original_rva =",
            "        result.target_rva != 0U ? result.target_rva : source_rva;",
            "    if (result.kind == SPX_RETURN) {",
            # The transfer's state effects already materialize EAX.  The
            # outcome value is control metadata and may intentionally refer
            # to the pre-effect input, so copying it back would undo a checked
            # register write at the return transfer.
            "      return SPX_CALL_OK;",
            "    }",
            "    if (result.kind == SPX_EXTERNAL_JUMP) return SPX_CALL_OK;",
            "    if (result.kind == SPX_DIVIDE_ERROR) return SPX_CALL_DIVIDE_ERROR;",
            "    if (result.kind == SPX_MEMORY_FAULT) return SPX_CALL_MEMORY_FAULT;",
            "    if (result.kind == SPX_EXTERNAL_FAULT) return SPX_CALL_EXTERNAL_FAULT;",
            "    return SPX_CALL_UNIMPLEMENTED;",
            "  }",
            "}",
            "",
            "spx_call_status spx_invoke_call(",
            "    spx_runtime *rt, const spx_call_event *event,",
            "    const spx_machine_state *input, spx_machine_state *output) {",
            "  uint32_t target_rva;",
            "  spx_machine_state call_input;",
            "  spx_call_status status;",
            "  uint32_t return_address, fault = 0U;",
            "  if (event == 0 || input == 0 || output == 0)",
            "    return SPX_CALL_UNIMPLEMENTED;",
            "  if (event->kind == SPX_CALL_INTERNAL_DIRECT ||",
            "      (event->kind == SPX_CALL_INDIRECT && rt != 0 &&",
            "       rt->resolve_code_target != 0 &&",
            "       rt->resolve_code_target(",
            "           rt, SPX_CODE_SITE_INDIRECT_CALL, event->source_rva,",
            "           event->instruction_rva, event->call_index,",
            "           event->target_rva, &target_rva) == 0U)) {",
            "    if (rt == 0 || rt->write == 0 || input->esp < 4U ||",
            "        event->return_rva == 0U ||",
            "        rt->image_base > 0xffffffffU - event->return_rva) {",
            "      *output = *input;",
            "      return SPX_CALL_UNIMPLEMENTED;",
            "    }",
            "    return_address = rt->image_base + event->return_rva;",
            "    call_input = *input;",
            "    call_input.esp -= 4U;",
            "    rt->write(rt->context, call_input.esp, 4U, return_address, &fault);",
            "    if (fault != 0U) {",
            "      *output = call_input;",
            "      return SPX_CALL_MEMORY_FAULT;",
            "    }",
            "    status = spx_behavioral_run(rt,",
            "        event->kind == SPX_CALL_INTERNAL_DIRECT",
            "            ? event->target_rva : target_rva,",
            "        &call_input, output);",
            "    if (status == SPX_CALL_NONLOCAL)",
            "      output->esp = input->esp;",
            "    return status;",
            "  }",
            "  if (event->kind == SPX_CALL_EXTERNAL_IMPORT ||",
            "      event->kind == SPX_CALL_INDIRECT)",
            "    return spx_dispatch_external_call(rt, event, input, output);",
            "  return SPX_CALL_UNIMPLEMENTED;",
            "}",
        ]
    )


def _render_rep_movs(source: str, destination: str, count: str, direction: str, width: int) -> list[str]:
    return [
        "  {",
        f"    uint32_t source = {source}, destination = {destination}, count = {count};",
        f"    uint32_t step = {direction} ? 0U - {width}U : {width}U;",
        "    state->esi = source; state->edi = destination; state->ecx = count;",
        "    while (count != 0U) {",
        f"      uint32_t value = spx_read(rt, source, {width}U, &memory_fault);",
        "      if (memory_fault) break;",
        f"      spx_write(rt, destination, {width}U, value, &memory_fault);",
        "      if (memory_fault) break;",
        "      source += step; destination += step; --count;",
        "      state->esi = source; state->edi = destination; state->ecx = count;",
        "    }",
        "  }",
        "  if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
    ]


def _render_rep_stos(destination: str, value: str, count: str, direction: str, width: int) -> list[str]:
    return [
        "  {",
        f"    uint32_t destination = {destination}, value = {value}, count = {count};",
        f"    uint32_t step = {direction} ? 0U - {width}U : {width}U;",
        "    state->edi = destination; state->ecx = count;",
        "    while (count != 0U) {",
        f"      spx_write(rt, destination, {width}U, value, &memory_fault);",
        "      if (memory_fault) break;",
        "      destination += step; --count;",
        "      state->edi = destination; state->ecx = count;",
        "    }",
        "  }",
        "  if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
    ]


def _render_rep_scas(accumulator: str, destination: str, count: str, direction: str) -> list[str]:
    return [
        "  {",
        f"    uint32_t al = ({accumulator}) & 0xffU, destination = {destination}, count = {count};",
        f"    uint32_t step = {direction} ? 0xffffffffU : 1U;",
        "    state->edi = destination; state->ecx = count;",
        "    while (count != 0U) {",
        "      uint32_t memory = spx_read(rt, destination, 1U, &memory_fault) & 0xffU, result;",
        "      if (memory_fault) break;",
        "      result = (al - memory) & 0xffU; destination += step; --count;",
        "      state->edi = destination; state->ecx = count;",
        "      state->cf = al < memory; state->zf = result == 0U; state->sf = (result >> 7U) & 1U;",
        "      state->of = ((al ^ memory) & (al ^ result) & 0x80U) != 0U;",
        "      state->pf = spx_parity(result);",
        "      state->eflags = (state->eflags & ~(1U << 4U)) | (((al ^ memory ^ result) >> 4U) & 1U) << 4U;",
        "      spx_sync_eflags(state);",
        "      if (result == 0U) break;",
        "    }",
        "  }",
        "  if (memory_fault) return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
    ]


def _edge_statement(
    target: int,
    internal: set[int],
    forced_labels: frozenset[int],
    kind: str,
) -> str:
    if target in internal and target not in forced_labels:
        return f"goto {_label(target)};"
    return f"return (spx_step_result){{ {kind}, 0x{target:08x}U, 0U }};"


def _index(values: tuple[str, ...], index: int, kind: str, transfer: _Transfer) -> str:
    if not 0 <= index < len(values):
        raise TransferPlanError(
            f"{transfer.identity}: invalid {kind} index {index}",
            code="behavioral_c_node_reference_invalid",
        )
    return values[index]


def _arity(transfer: _Transfer, value: _Node | _Action, args: list[object], expected: int) -> None:
    if len(args) != expected:
        raise TransferPlanError(
            f"{transfer.identity}: {value.op} requires {expected} arguments, got {len(args)}",
            code="behavioral_c_ir_shape_invalid",
        )


def _word_name(rva: int, index: int) -> str:
    return f"w_{rva:08x}_{index}"


def _label(rva: int) -> str:
    return f"spx_unit_{rva:08x}"


def _x87_symbol(rva: int, index: int) -> str:
    return f"spx_x87_{rva:08x}_{index}"


_DIRECT_HELPERS = r'''#if defined(__GNUC__) || defined(__clang__)
#define SPX_DIRECT_HELPER static __attribute__((unused))
#else
#define SPX_DIRECT_HELPER static
#endif

SPX_DIRECT_HELPER spx_step_result spx_call_status_result(
    spx_call_status status, uint32_t source_rva) {
  if (status == SPX_CALL_DIVIDE_ERROR)
    return (spx_step_result){ SPX_DIVIDE_ERROR, source_rva, 0U };
  if (status == SPX_CALL_MEMORY_FAULT)
    return (spx_step_result){ SPX_MEMORY_FAULT, source_rva, 0U };
  if (status == SPX_CALL_EXTERNAL_FAULT)
    return (spx_step_result){ SPX_EXTERNAL_FAULT, source_rva, 0U };
  if (status == SPX_CALL_NONLOCAL)
    return (spx_step_result){ SPX_NONLOCAL, 0U, 0U };
  return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };
}

SPX_DIRECT_HELPER uint32_t spx_adc_carry_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault) {
  uint64_t mask, sum;
  if (width == 0U || width > 32U || carry > 1U) {
    *semantic_fault = 1U;
    return 0U;
  }
  mask = width == 32U ? 0xffffffffULL : ((1ULL << width) - 1ULL);
  sum = ((uint64_t)left & mask) + ((uint64_t)right & mask) + carry;
  if (((uint32_t)sum & (uint32_t)mask) != (result & (uint32_t)mask)) {
    *semantic_fault = 1U;
    return 0U;
  }
  return (uint32_t)((sum >> width) & 1ULL);
}

SPX_DIRECT_HELPER uint32_t spx_adc_overflow_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault) {
  uint32_t mask, sign;
  uint64_t sum;
  if (width == 0U || width > 32U || carry > 1U) {
    *semantic_fault = 1U;
    return 0U;
  }
  mask = width == 32U ? 0xffffffffU : ((1U << width) - 1U);
  left &= mask; right &= mask; result &= mask;
  sum = (uint64_t)left + (uint64_t)right + carry;
  if (((uint32_t)sum & mask) != result) {
    *semantic_fault = 1U;
    return 0U;
  }
  sign = 1U << (width - 1U);
  return ((~(left ^ right) & (left ^ result) & sign) != 0U) ? 1U : 0U;
}

#undef SPX_DIRECT_HELPER'''


_SHARED_HELPER_DECLARATIONS = r'''uint32_t spx_mask(uint32_t width);
uint32_t spx_read(
    spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault);
void spx_write(
    spx_runtime *rt, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault);
uint32_t spx_undefined(
    spx_runtime *rt, uint32_t slot, const spx_machine_state *input,
    uint32_t defined_value);
void spx_sync_eflags(spx_machine_state *state);
uint32_t spx_sign_extend(uint32_t width, uint32_t value);
uint32_t spx_sar(uint32_t width, uint32_t value, uint32_t amount);
uint32_t spx_msb(uint32_t width, uint32_t value);
uint32_t spx_parity(uint32_t value);
uint32_t spx_add_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t result);
uint32_t spx_sub_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t result);
uint32_t spx_imul_high(uint32_t left, uint32_t right);
uint32_t spx_mul_high(uint32_t left, uint32_t right);
uint32_t spx_udiv_quot(uint32_t high, uint32_t low, uint32_t divisor);
uint32_t spx_udiv_rem(uint32_t high, uint32_t low, uint32_t divisor);
uint32_t spx_udiv_valid(uint32_t high, uint32_t low, uint32_t divisor);
uint32_t spx_bsr(uint32_t value);
uint32_t spx_tzcnt(uint32_t value);
uint32_t spx_shift_cf(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count);
uint32_t spx_shift_of(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count,
    uint32_t result);
uint32_t spx_sbb_borrow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result);
uint32_t spx_sbb_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result);
spx_step_result spx_call_status_result(
    spx_call_status status, uint32_t source_rva);
uint32_t spx_adc_carry_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault);
uint32_t spx_adc_overflow_checked(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry,
    uint32_t result, uint32_t *semantic_fault);'''


__all__ = [
    "behavioral_c_header",
    "behavioral_c_operation_coverage_v2",
    "behavioral_c_source",
    "behavioral_c_support_source",
    "behavioral_c_translation_units",
]
