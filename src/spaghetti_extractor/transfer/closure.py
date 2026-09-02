# ruff: noqa: F401
"""Public facade for canonical transfer-plan execution closure."""

from .formats import MODULE_EXECUTION_CLOSURE_FORMAT

from .closure_model import (
    OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1,
    ExecutionClosureContextV1,
    ExecutionFunctionContextV1,
    execution_closure_context_with_roots_v1,
    _reference_state_kernel_payload_v1,
    _execution_closure_kernel_context_payload_v1,
    _boundary_reference_state_v1,
    _effect_summary_state_v1,
    _state_object_identities_v1,
    _implicit_memory_value_v1,
    _normalize_reference_memory_v1,
    _reference_states_equal_v1,
    join_reference_states_v1,
)
from .closure_calls import (
    _direct_successors,
    _reference_targets,
    _external_reference_targets,
    _reference_target_resolution_v1,
    _external_tail_return_state_v1,
    _call_targets,
    _external_call_targets,
    _call_target_resolution,
    _call_argument_values,
    _callback_targets,
    _callback_root_state,
    _stack_frame_identity_v1,
    _expire_stack_frame_value_v1,
    _call_parameter_identity_v1,
    _parameterizable_call_value_v1,
    _explicit_outgoing_stack_cells_v1,
    _outgoing_stack_projection_exceeds_limit_v1,
    _raw_outgoing_stack_projection_v1,
    _parameterized_call_inputs_v1,
    _instantiate_parameter_value_v1,
    _instantiate_parameter_key_v1,
    _instantiate_parameter_range_v1,
    _return_state_for_caller_v1,
    _callee_state,
    _transfer_rpo_priorities_v1,
)
from .closure_fixed_point import (
    build_module_execution_closure_v1,
)
from .closure_context import (
    _canonical_external_transport_v1,
    _external_write_authority_selector_v1,
    derive_execution_closure_context_v1,
    _root_reference_state_v1,
    _initial_image_storage_v1,
    _external_function_iat_memory_v1,
)
from .closure_io import (
    _json_object,
    _native_module_execution_closure_v1,
    _native_semantic_link_closure_v1,
    _native_semantic_link_kernel_v1,
    _observed_native_module_execution_closure_v1,
    benchmark_native_module_execution_closure_v1,
    check_python_reference_closure_parity_v1,
    write_bound_module_execution_closure_v1,
    write_bound_semantic_link_closure_v1,
    write_bound_semantic_link_kernel_v1,
    write_module_execution_closure_v1,
    check_module_execution_closure_v1,
    validate_module_execution_closure_v1,
)

__all__ = [
    "ExecutionClosureContextV1",
    "MODULE_EXECUTION_CLOSURE_FORMAT",
    "benchmark_native_module_execution_closure_v1",
    "build_module_execution_closure_v1",
    "check_python_reference_closure_parity_v1",
    "check_module_execution_closure_v1",
    "derive_execution_closure_context_v1",
    "execution_closure_context_with_roots_v1",
    "join_reference_states_v1",
    "validate_module_execution_closure_v1",
    "write_bound_module_execution_closure_v1",
    "write_bound_semantic_link_closure_v1",
    "write_bound_semantic_link_kernel_v1",
    "write_module_execution_closure_v1",
]
