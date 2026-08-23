"""Shared exact-runtime ABI for generated candidate C backends.

The interpreter and behavioral-C renderer deliberately share this header.  A
backend may change how checked transfers are represented, but it must not
silently change the machine state, call, atomic, boundary, or typed-x87
protocols used by the rest of the candidate runtime.
"""

from __future__ import annotations

from .c_backend import _runtime_header
from .interpreter_model import CandidateInterpreterError


def exact_runtime_header() -> str:
    """Return the stable runtime header used by every faithful C backend."""

    header = _runtime_header()
    replay_record = """#define SPX_MACHINE_STATE_HAS_X87 1

typedef struct spx_typed_x87_operation {
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
} spx_typed_x87_operation;

"""
    replay_handler = """typedef spx_call_status (*spx_typed_x87_handler)(
    spx_runtime *runtime,
    const spx_typed_x87_operation *program,
    const spx_machine_state *input,
    spx_machine_state *output);

"""
    replacements = (
        (
            "typedef struct spx_runtime spx_runtime;\n",
            replay_record + "typedef struct spx_runtime spx_runtime;\n",
        ),
        (
            "typedef uint32_t (*spx_code_target_resolver)(\n",
            replay_handler + "typedef uint32_t (*spx_code_target_resolver)(\n",
        ),
        (
            "  spx_code_target_resolver resolve_code_target;\n",
            "  spx_code_target_resolver resolve_code_target;\n"
            "  spx_typed_x87_handler execute_typed_x87_operation;\n",
        ),
    )
    for old, new in replacements:
        if old not in header:
            raise CandidateInterpreterError(
                "shared runtime header changed before typed x87 ABI injection",
                code="candidate_runtime_abi_drift",
                next_action="reconcile the exact runtime ABI with spx_c_backend",
            )
        header = header.replace(old, new, 1)
    return header


__all__ = ["exact_runtime_header"]
