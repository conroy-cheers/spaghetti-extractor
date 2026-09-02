//! Private native projection of executable-transfer-plan-v2.
//!
//! This is deliberately not another artifact or semantic IR.  Python first
//! performs the authoritative v2 codec validation; the native closure kernel
//! then consumes the same serialized bytes and projects dense execution data
//! for its resident fixed point.  The inspection entry point exists only to
//! differential-test that projection while the full kernel is being ported.

use std::collections::{BTreeMap, BTreeSet};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyBytesMethods};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const OPERATION_REGISTRY_SHA256: &str =
    "a533c5e268bdcbc566557511b44b902adb9a34b52adfd554eb3e711cbe25eb54";
const TRANSFER_PLAN_FORMAT: &str = "spaghetti-extractor-executable-transfer-plan-v2";
const MAX_TRANSFERS: usize = 1_000_000;
const MAX_EXPRESSIONS_PER_TRANSFER: usize = 1_000_000;
const MAX_EFFECTS_PER_TRANSFER: usize = 1_000_000;
const MAX_CALLS_PER_TRANSFER: usize = 1_000_000;

const EXPRESSION_OPERATION_NAMES: &[&str] = &[
    "adc_carry",
    "adc_overflow",
    "add32",
    "add_overflow",
    "and32",
    "and_bool",
    "bool_to_bit",
    "bsr_index",
    "call_flag",
    "call_response",
    "const",
    "eq",
    "eq_bool",
    "false",
    "flag",
    "fpu_code_selector",
    "fpu_control",
    "fpu_control_init",
    "fpu_control_load",
    "fpu_control_word",
    "fpu_data_pointer",
    "fpu_data_selector",
    "fpu_instruction_pointer",
    "fpu_last_opcode",
    "fpu_pending_exception",
    "fpu_status",
    "fpu_status_init",
    "fpu_status_word",
    "fpu_tag",
    "fs_base",
    "imul_high32",
    "imul_low32",
    "imul_overflow",
    "ite",
    "load",
    "lshr32",
    "msb",
    "mul32",
    "mul_carry",
    "mul_high32",
    "mul_low32",
    "neg32",
    "not",
    "not32",
    "or32",
    "or_bool",
    "parity",
    "reg",
    "sar",
    "sbb_borrow",
    "sbb_overflow",
    "shift_cf",
    "shift_of",
    "shl32",
    "sign_extend",
    "sub32",
    "sub_overflow",
    "true",
    "tzcnt",
    "udiv_quot32",
    "udiv_rem32",
    "udiv_valid32",
    "ult32",
    "undefined_bv",
    "undefined_flag",
    "xor32",
    "xor_bool",
];
const EFFECT_OPERATION_NAMES: &[&str] = &[
    "access_violation_if",
    "atomic_compare_exchange",
    "atomic_exchange",
    "call",
    "divide_if",
    "eval_word",
    "memory_write",
    "rep_movs",
    "rep_movsd",
    "rep_scas",
    "rep_stos",
    "rep_stosd",
    "set_flag",
    "set_reg",
    "sync_eflags",
    "typed_x87",
];
const TERMINATOR_OPERATION_NAMES: &[&str] = &[
    "outcome_branch",
    "outcome_external",
    "outcome_fallthrough",
    "outcome_indirect",
    "outcome_jump",
    "outcome_nonlocal",
    "outcome_return",
];

fn malformed(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(format!(
        "native reference-plan projection is malformed: {}",
        message.into()
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferPlan {
    format: String,
    status: String,
    bindings: Value,
    unit_inventory: Vec<Value>,
    pub(crate) transfers: Vec<Transfer>,
    direct_control_edges: Vec<DirectControlEdge>,
    finite_control_routes: Vec<FiniteControlRouteInventory>,
    atomic_effect_authority: Vec<Value>,
    entry_targets: Vec<u32>,
    runtime_provider_requirements: Vec<String>,
    operation_registry_sha256: String,
    diagnostics: Value,
    semantic_blockers: Vec<Value>,
    counts: Value,
    authority: String,
    plan_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectControlEdge {
    pub(crate) kind: String,
    pub(crate) source_rva: u32,
    pub(crate) target_rva: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FiniteControlRouteInventory {
    pub(crate) unit_id: String,
    pub(crate) source_rva: u32,
    pub(crate) routes: Vec<FiniteControlRoute>,
    route_inventory_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FiniteControlRoute {
    pub(crate) selector_value: u32,
    pub(crate) target_rva: u32,
    target_address: u32,
}

impl TransferPlan {
    pub(crate) fn finite_control_targets(&self) -> BTreeMap<u32, BTreeSet<u32>> {
        self.finite_control_routes
            .iter()
            .map(|inventory| {
                (
                    inventory.source_rva,
                    inventory
                        .routes
                        .iter()
                        .map(|route| route.target_rva)
                        .collect(),
                )
            })
            .collect()
    }

    pub(crate) fn runtime_provider_requirements(&self) -> &[String] {
        &self.runtime_provider_requirements
    }

    pub(crate) fn direct_control_edges(&self) -> &[DirectControlEdge] {
        &self.direct_control_edges
    }

    pub(crate) fn finite_control_routes(&self) -> &[FiniteControlRouteInventory] {
        &self.finite_control_routes
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transfer {
    identity: String,
    source: Source,
    pub(crate) expressions: Vec<Expression>,
    pub(crate) effects: Vec<Action>,
    pub(crate) calls: Vec<Call>,
    exception_occurrences: Vec<ExceptionOccurrence>,
    pub(crate) x87_intrinsics: Vec<X87Intrinsic>,
    pub(crate) terminator: Terminator,
}

impl Transfer {
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn rva_start(&self) -> u32 {
        self.source.rva_start
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    pub(crate) rva_start: u32,
    rva_end: u32,
    unit_ir_sha256: String,
    contract_sha256: String,
    instruction_bytes_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expression {
    id: usize,
    pub(crate) op: String,
    pub(crate) operands: Vec<usize>,
    result_sort: String,
    width_bits: u32,
    pub(crate) parameters: ExpressionParameters,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpressionParameters {
    pub(crate) aux: u32,
    pub(crate) immediate: u32,
    pub(crate) identity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    #[serde(default)]
    id: Option<usize>,
    pub(crate) op: String,
    pub(crate) operands: Vec<usize>,
    pub(crate) parameters: ActionParameters,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionParameters {
    pub(crate) aux: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionOccurrence {
    fault_index: usize,
    fault_sha256: String,
    occurrence_kind: String,
    effect_index: usize,
    operation: String,
    call_id: Option<usize>,
    call_event_index: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Terminator {
    pub(crate) op: String,
    pub(crate) operands: Vec<usize>,
    pub(crate) parameters: ActionParameters,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Call {
    pub(crate) id: usize,
    pub(crate) kind: String,
    pub(crate) instruction_rva: u32,
    pub(crate) event_index: usize,
    pub(crate) target_node: Option<usize>,
    pub(crate) target_rva: u32,
    pub(crate) return_rva: u32,
    pub(crate) dll: Option<String>,
    pub(crate) symbol: Option<String>,
    pub(crate) ordinal: Option<u32>,
    pub(crate) register_nodes: Vec<usize>,
    pub(crate) flag_nodes: Vec<usize>,
    pub(crate) argument_nodes: Vec<usize>,
    pub(crate) stack_inputs: Vec<(u32, u32, usize)>,
    #[serde(default)]
    pub(crate) native_exception_operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct X87Intrinsic {
    checked_decoder: String,
    checked_executor: String,
    contract_sha256: String,
    id: usize,
    pub(crate) image_base: u32,
    pub(crate) operation: X87Operation,
    rva_end: u32,
    rva_start: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct X87Operation {
    format: String,
    identity: String,
    pub(crate) mnemonic: String,
    pub(crate) operand: X87Operand,
    source_size: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct X87Operand {
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) width: u32,
    #[serde(default)]
    stack_registers: Vec<u8>,
    #[serde(default)]
    pub(crate) address: Option<X87Address>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct X87Address {
    pub(crate) base: Option<String>,
    pub(crate) displacement: i64,
    pub(crate) image_rva: Option<u32>,
    pub(crate) index: Option<String>,
    pub(crate) scale: u32,
}

#[derive(Debug, Serialize)]
struct ProjectionReceipt {
    operation_registry_sha256: &'static str,
    transfers: usize,
    expressions: usize,
    effects: usize,
    calls: usize,
    x87_intrinsics: usize,
    expression_operations: BTreeMap<String, usize>,
    effect_operations: BTreeMap<String, usize>,
    terminator_operations: BTreeMap<String, usize>,
    supported_expression_operations: &'static [&'static str],
    supported_effect_operations: &'static [&'static str],
    supported_terminator_operations: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct OperationSpec {
    minimum_arity: usize,
    maximum_arity: usize,
    result_sort: Option<&'static str>,
    width_bits: Option<u32>,
}

fn exact(
    arity: usize,
    result_sort: Option<&'static str>,
    width_bits: Option<u32>,
) -> OperationSpec {
    OperationSpec {
        minimum_arity: arity,
        maximum_arity: arity,
        result_sort,
        width_bits,
    }
}

fn ranged(
    minimum_arity: usize,
    maximum_arity: usize,
    result_sort: Option<&'static str>,
    width_bits: Option<u32>,
) -> OperationSpec {
    OperationSpec {
        minimum_arity,
        maximum_arity,
        result_sort,
        width_bits,
    }
}

fn expression_spec(name: &str) -> Option<OperationSpec> {
    let predicate = |arity| exact(arity, Some("predicate"), Some(1));
    let word = |arity| exact(arity, Some("bitvector"), Some(32));
    Some(match name {
        "true" | "false" | "flag" | "call_flag" | "fpu_pending_exception" => predicate(0),
        "undefined_flag" => ranged(0, 1, Some("predicate"), Some(1)),
        "ult32" | "eq" | "eq_bool" | "xor_bool" | "parity" => predicate(2),
        "not" => predicate(1),
        "and_bool" | "or_bool" => ranged(1, 5, Some("predicate"), Some(1)),
        "add_overflow" | "sub_overflow" | "mul_carry" => predicate(4),
        "imul_overflow" | "sbb_borrow" | "sbb_overflow" | "adc_carry" | "adc_overflow" => {
            predicate(5)
        }
        "udiv_valid32" | "shift_of" => predicate(3),
        "shift_cf" => predicate(2),
        "const"
        | "reg"
        | "fs_base"
        | "call_response"
        | "fpu_control"
        | "fpu_control_init"
        | "fpu_status"
        | "fpu_status_init"
        | "fpu_tag"
        | "fpu_last_opcode"
        | "fpu_instruction_pointer"
        | "fpu_code_selector"
        | "fpu_data_pointer"
        | "fpu_data_selector" => word(0),
        "undefined_bv" => ranged(0, 1, Some("bitvector"), Some(32)),
        "load" | "not32" | "neg32" | "bool_to_bit" | "fpu_control_load" | "fpu_control_word"
        | "fpu_status_word" => word(1),
        "sub32" | "shl32" | "lshr32" | "imul_low32" | "mul_low32" | "imul_high32"
        | "mul_high32" | "bsr_index" | "tzcnt" => word(2),
        "add32" | "mul32" | "xor32" | "and32" | "or32" => ranged(2, 4, Some("bitvector"), Some(32)),
        "sar" | "ite" | "udiv_quot32" | "udiv_rem32" => word(3),
        "sign_extend" => word(2),
        "msb" => ranged(1, 2, Some("bitvector"), Some(32)),
        _ => return None,
    })
}

fn effect_spec(name: &str) -> Option<OperationSpec> {
    Some(match name {
        "eval_word" | "divide_if" | "call" | "set_reg" | "set_flag" | "typed_x87" => {
            exact(1, None, None)
        }
        "access_violation_if" => exact(3, None, None),
        "memory_write" => exact(2, None, None),
        "rep_movsd"
        | "rep_movs"
        | "rep_stosd"
        | "rep_stos"
        | "rep_scas"
        | "atomic_compare_exchange" => exact(4, None, None),
        "atomic_exchange" => exact(3, None, None),
        "sync_eflags" => exact(0, None, None),
        _ => return None,
    })
}

fn terminator_spec(name: &str) -> Option<OperationSpec> {
    Some(match name {
        "outcome_fallthrough" | "outcome_jump" | "outcome_return" | "outcome_indirect" => {
            exact(1, None, None)
        }
        "outcome_branch" => exact(3, None, None),
        "outcome_nonlocal" => exact(2, None, None),
        "outcome_external" => exact(0, None, None),
        _ => return None,
    })
}

fn check_spec(
    operation: &str,
    arity: usize,
    spec: Option<OperationSpec>,
) -> PyResult<OperationSpec> {
    let spec = spec.ok_or_else(|| malformed(format!("unsupported operation {operation:?}")))?;
    if !(spec.minimum_arity..=spec.maximum_arity).contains(&arity) {
        return Err(malformed(format!(
            "operation {operation:?} has invalid arity {arity}"
        )));
    }
    Ok(spec)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn check_node_reference(reference: usize, expression_count: usize, context: &str) -> PyResult<()> {
    if reference >= expression_count {
        Err(malformed(format!(
            "{context} references an unknown expression"
        )))
    } else {
        Ok(())
    }
}

fn validate_x87_intrinsic(row: &X87Intrinsic, index: usize, transfer: &Transfer) -> PyResult<()> {
    const GPRS: &[&str] = &["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    let operation = &row.operation;
    let operand = &operation.operand;
    if row.id != index
        || row.checked_decoder != "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
        || row.checked_executor != "SpaghettiExtractor.ISA.Formal.executeInstruction"
        || !is_sha256(&row.contract_sha256)
        || row.rva_start < transfer.source.rva_start
        || row.rva_end > transfer.source.rva_end
        || row.rva_end <= row.rva_start
        || row.rva_end - row.rva_start != operation.source_size
        || operation.format != "spaghetti-extractor-typed-native-x87-operation-v1"
        || !is_sha256(&operation.identity)
        || operation.mnemonic.is_empty()
        || operation.mnemonic != operation.mnemonic.to_lowercase()
        || operation.source_size == 0
    {
        return Err(malformed("typed x87 intrinsic binding is invalid"));
    }
    match operand.kind.as_str() {
        "none" => {
            if operand.width != 0
                || !operand.stack_registers.is_empty()
                || operand.address.is_some()
            {
                return Err(malformed("operand-free typed x87 form is invalid"));
            }
        }
        "ax" => {
            if operand.width != 2
                || !operand.stack_registers.is_empty()
                || operand.address.is_some()
            {
                return Err(malformed("typed x87 AX form is invalid"));
            }
        }
        "stack" => {
            if operand.width != 10
                || !(1..=2).contains(&operand.stack_registers.len())
                || operand.stack_registers.iter().any(|register| *register > 7)
                || operand.address.is_some()
            {
                return Err(malformed("typed x87 stack form is invalid"));
            }
        }
        "memory" => {
            let Some(address) = &operand.address else {
                return Err(malformed("typed x87 memory address is absent"));
            };
            if operand.width == 0
                || !operand.stack_registers.is_empty()
                || !matches!(address.scale, 1 | 2 | 4 | 8)
                || (address.index.is_none() && address.scale != 1)
                || address
                    .base
                    .as_deref()
                    .is_some_and(|name| !GPRS.contains(&name))
                || address
                    .index
                    .as_deref()
                    .is_some_and(|name| !GPRS.contains(&name))
                || address.image_rva.is_some() && address.displacement != 0
                || row
                    .image_base
                    .checked_add(address.image_rva.unwrap_or(0))
                    .is_none()
            {
                return Err(malformed("typed x87 memory form is invalid"));
            }
        }
        _ => return Err(malformed("typed x87 operand kind is unsupported")),
    }
    Ok(())
}

fn validate_transfer(transfer: &Transfer, previous_rva: Option<u32>) -> PyResult<()> {
    if transfer.identity.is_empty()
        || transfer.source.rva_end <= transfer.source.rva_start
        || previous_rva.is_some_and(|rva| transfer.source.rva_start <= rva)
        || !is_sha256(&transfer.source.unit_ir_sha256)
        || !is_sha256(&transfer.source.contract_sha256)
        || !is_sha256(&transfer.source.instruction_bytes_sha256)
    {
        return Err(malformed("transfer identity or source binding is invalid"));
    }
    if transfer.expressions.len() > MAX_EXPRESSIONS_PER_TRANSFER
        || transfer.effects.len() > MAX_EFFECTS_PER_TRANSFER
        || transfer.calls.len() > MAX_CALLS_PER_TRANSFER
    {
        return Err(malformed("transfer exceeds a structural limit"));
    }
    for (index, node) in transfer.expressions.iter().enumerate() {
        if node.id != index || node.operands.iter().any(|operand| *operand >= index) {
            return Err(malformed("expression graph is not dense and acyclic"));
        }
        let spec = check_spec(&node.op, node.operands.len(), expression_spec(&node.op))?;
        if node.result_sort != spec.result_sort.unwrap_or("")
            || Some(node.width_bits) != spec.width_bits
            || matches!(node.op.as_str(), "undefined_bv" | "undefined_flag")
                != node.parameters.identity.is_some()
        {
            return Err(malformed("expression type or undefined identity is stale"));
        }
        if node.op == "load" && !matches!(node.parameters.aux, 1 | 2 | 4) {
            return Err(malformed("load width is unsupported"));
        }
        let _checked_parameters = (node.parameters.immediate, &node.parameters.identity);
    }
    for (index, call) in transfer.calls.iter().enumerate() {
        if call.id != index
            || call.register_nodes.len() != 8
            || call.flag_nodes.len() != 6
            || !matches!(
                call.kind.as_str(),
                "internal_call" | "indirect_call" | "external_call"
            )
        {
            return Err(malformed(
                "call identity, kind, or physical frame is invalid",
            ));
        }
        let references = call
            .target_node
            .iter()
            .chain(&call.register_nodes)
            .chain(&call.flag_nodes)
            .chain(&call.argument_nodes)
            .copied()
            .chain(call.stack_inputs.iter().map(|row| row.2));
        for reference in references {
            check_node_reference(reference, transfer.expressions.len(), "call")?;
        }
        if call
            .stack_inputs
            .iter()
            .any(|row| !matches!(row.1, 1 | 2 | 4))
        {
            return Err(malformed("call stack-input width is unsupported"));
        }
        if (!call.native_exception_operations.is_empty()
            && !matches!(call.kind.as_str(), "external_call" | "indirect_call"))
            || call
                .native_exception_operations
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || call
                .native_exception_operations
                .iter()
                .any(|operation| !matches!(operation.as_str(), "access_violation_if" | "divide_if"))
        {
            return Err(malformed("call native-exception inventory is invalid"));
        }
        let _checked_metadata = (
            call.instruction_rva,
            call.event_index,
            call.target_rva,
            call.return_rva,
            &call.dll,
            &call.symbol,
            call.ordinal,
        );
    }
    for (index, row) in transfer.x87_intrinsics.iter().enumerate() {
        validate_x87_intrinsic(row, index, transfer)?;
    }
    for (index, action) in transfer.effects.iter().enumerate() {
        if action.id != Some(index) {
            return Err(malformed("effect IDs are not dense"));
        }
        check_spec(&action.op, action.operands.len(), effect_spec(&action.op))?;
        if matches!(
            action.op.as_str(),
            "memory_write"
                | "rep_movs"
                | "rep_stos"
                | "rep_scas"
                | "atomic_compare_exchange"
                | "atomic_exchange"
        ) && !matches!(action.parameters.aux, 1 | 2 | 4)
        {
            return Err(malformed("effect width is unsupported"));
        }
        if action.op == "call" {
            if action.operands[0] >= transfer.calls.len() {
                return Err(malformed("call effect references an unknown call"));
            }
        } else if action.op == "typed_x87" {
            if action.operands[0] >= transfer.x87_intrinsics.len() {
                return Err(malformed(
                    "typed x87 effect references an unknown intrinsic",
                ));
            }
        } else {
            for reference in &action.operands {
                check_node_reference(*reference, transfer.expressions.len(), "effect")?;
            }
        }
    }
    let expected_exception_occurrences = transfer
        .effects
        .iter()
        .filter(|effect| matches!(effect.op.as_str(), "access_violation_if" | "divide_if"))
        .count()
        + transfer
            .calls
            .iter()
            .map(|call| call.native_exception_operations.len())
            .sum::<usize>();
    if transfer.exception_occurrences.len() != expected_exception_occurrences {
        return Err(malformed(
            "exception occurrence inventory does not cover executable effects",
        ));
    }
    for (fault_index, occurrence) in transfer.exception_occurrences.iter().enumerate() {
        let Some(effect) = transfer.effects.get(occurrence.effect_index) else {
            return Err(malformed("exception occurrence names an unknown effect"));
        };
        if occurrence.fault_index != fault_index || !is_sha256(&occurrence.fault_sha256) {
            return Err(malformed("exception occurrence identity is malformed"));
        }
        let valid = match occurrence.occurrence_kind.as_str() {
            "effect" => {
                occurrence.call_id.is_none()
                    && occurrence.call_event_index.is_none()
                    && effect.op == occurrence.operation
                    && matches!(effect.op.as_str(), "access_violation_if" | "divide_if")
                    && effect.parameters.aux as usize == fault_index
            }
            "call" => occurrence
                .call_id
                .and_then(|call_id| {
                    let call = transfer.calls.get(call_id)?;
                    Some(
                        occurrence.call_event_index == Some(call.event_index)
                            && effect.op == "call"
                            && effect.operands.as_slice() == [call_id]
                            && call
                                .native_exception_operations
                                .contains(&occurrence.operation),
                    )
                })
                .unwrap_or(false),
            _ => false,
        };
        if !valid {
            return Err(malformed(
                "exception occurrence contradicts its executable effect",
            ));
        }
    }
    check_spec(
        &transfer.terminator.op,
        transfer.terminator.operands.len(),
        terminator_spec(&transfer.terminator.op),
    )?;
    let references: &[usize] = match transfer.terminator.op.as_str() {
        "outcome_branch" => &transfer.terminator.operands[..1],
        "outcome_return" | "outcome_indirect" | "outcome_nonlocal" => &transfer.terminator.operands,
        _ => &[],
    };
    for reference in references {
        check_node_reference(*reference, transfer.expressions.len(), "terminator")?;
    }
    let _checked_terminator_aux = transfer.terminator.parameters.aux;
    Ok(())
}

pub(crate) fn parse_transfer_plan(payload: &[u8]) -> PyResult<TransferPlan> {
    let plan: TransferPlan = serde_json::from_slice(payload)
        .map_err(|error| malformed(format!("cannot decode JSON: {error}")))?;
    let completion_is_consistent = match plan.status.as_str() {
        "complete" => plan.semantic_blockers.is_empty(),
        "incomplete" => !plan.semantic_blockers.is_empty(),
        _ => false,
    };
    if plan.format != TRANSFER_PLAN_FORMAT
        || !completion_is_consistent
        || plan.operation_registry_sha256 != OPERATION_REGISTRY_SHA256
        || !is_sha256(&plan.plan_sha256)
        || plan.transfers.len() > MAX_TRANSFERS
    {
        return Err(malformed(
            "format, completion, registry, hash, or transfer count is invalid",
        ));
    }
    let mut previous_rva = None;
    for transfer in &plan.transfers {
        validate_transfer(transfer, previous_rva)?;
        previous_rva = Some(transfer.source.rva_start);
    }
    if plan.entry_targets
        != plan
            .transfers
            .iter()
            .map(|transfer| transfer.source.rva_start)
            .collect::<Vec<_>>()
    {
        return Err(malformed("entry targets disagree with transfer order"));
    }
    let transfers_by_rva = plan
        .transfers
        .iter()
        .map(|transfer| (transfer.source.rva_start, transfer))
        .collect::<BTreeMap<_, _>>();
    let mut previous_route_key = None;
    for inventory in &plan.finite_control_routes {
        let key = (inventory.source_rva, inventory.unit_id.as_str());
        if previous_route_key.is_some_and(|previous| previous >= key)
            || !is_sha256(&inventory.route_inventory_sha256)
            || inventory.routes.is_empty()
        {
            return Err(malformed(
                "finite-control inventories are empty, unordered, duplicated, or unbound",
            ));
        }
        let Some(transfer) = transfers_by_rva.get(&inventory.source_rva) else {
            return Err(malformed(
                "finite-control source is outside the transfer universe",
            ));
        };
        if transfer.identity != inventory.unit_id || transfer.terminator.op != "outcome_indirect" {
            return Err(malformed(
                "finite-control inventory does not bind its indirect transfer",
            ));
        }
        let mut previous_selector = None;
        for route in &inventory.routes {
            if previous_selector.is_some_and(|previous| previous >= route.selector_value) {
                return Err(malformed(
                    "finite-control routes are unordered or duplicated",
                ));
            }
            // A checked machine target can remain outside the lowered transfer
            // universe (for example, when the target cutpoint is absent).  The
            // closure kernel must retain that route and emit the same
            // execution_edge_outside_exact_universe blocker as the Python
            // reference implementation; rejecting the whole canonical plan
            // here would turn an honest downstream blocker into parser drift.
            let _checked_target_rva = route.target_rva;
            let _checked_target_address = route.target_address;
            previous_selector = Some(route.selector_value);
        }
        previous_route_key = Some(key);
    }
    let _checked_top_level_shape = (
        &plan.bindings,
        &plan.unit_inventory,
        &plan.direct_control_edges,
        &plan.finite_control_routes,
        &plan.atomic_effect_authority,
        &plan.runtime_provider_requirements,
        &plan.diagnostics,
        &plan.counts,
        &plan.authority,
    );
    Ok(plan)
}

fn increment(rows: &mut BTreeMap<String, usize>, operation: &str) {
    *rows.entry(operation.to_owned()).or_default() += 1;
}

#[pyfunction]
pub(crate) fn inspect_reference_transfer_plan<'py>(
    py: Python<'py>,
    payload: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let plan = parse_transfer_plan(payload.as_bytes())?;
    let mut receipt = ProjectionReceipt {
        operation_registry_sha256: OPERATION_REGISTRY_SHA256,
        transfers: plan.transfers.len(),
        expressions: 0,
        effects: 0,
        calls: 0,
        x87_intrinsics: 0,
        expression_operations: BTreeMap::new(),
        effect_operations: BTreeMap::new(),
        terminator_operations: BTreeMap::new(),
        supported_expression_operations: EXPRESSION_OPERATION_NAMES,
        supported_effect_operations: EFFECT_OPERATION_NAMES,
        supported_terminator_operations: TERMINATOR_OPERATION_NAMES,
    };
    let mut identities = BTreeSet::new();
    for transfer in plan.transfers {
        if !identities.insert(transfer.identity) {
            return Err(malformed("transfer identity is duplicated"));
        }
        receipt.expressions += transfer.expressions.len();
        receipt.effects += transfer.effects.len();
        receipt.calls += transfer.calls.len();
        receipt.x87_intrinsics += transfer.x87_intrinsics.len();
        for node in transfer.expressions {
            increment(&mut receipt.expression_operations, &node.op);
        }
        for action in transfer.effects {
            increment(&mut receipt.effect_operations, &action.op);
        }
        increment(&mut receipt.terminator_operations, &transfer.terminator.op);
    }
    let encoded = serde_json::to_vec(&receipt)
        .map_err(|error| malformed(format!("cannot encode result: {error}")))?;
    Ok(PyBytes::new(py, &encoded))
}
