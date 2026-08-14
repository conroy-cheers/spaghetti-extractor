"""Public machine-IR reconstruction API.

Implementation lives in direct-import submodules grouped by responsibility;
this module preserves the established import surface.
"""

from .ir_decoding import (
    _Instruction,
    _recover_unknown_fallthrough,
    _sanitize_schedule,
)
from .ir_evidence import _binary_inventory
from .ir_export import export_machine_ir_package
from .ir_inventory import _exceptional_control_inventory
from .ir_materialization import _classify_executable_data_before_control
from .ir_model import (
    DECODED_CONTROL_RECONCILIATION_FORMAT,
    INDIRECT_TARGET_PROFILE_FORMAT,
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
    PREPARED_MACHINE_IR_FILENAME,
    PREPARED_MACHINE_IR_FORMAT,
    PREPARED_MACHINE_IR_MANIFEST_FILENAME,
    X87_MICRO_OP_FORMAT,
    ExportIssue,
    MachineIRExportError,
    MachineIRPackage,
    PreparedMachineIRPackage,
    RvaSpan,
    SourceLocation,
    _assert_byte_free,
)
from .ir_preparation import prepare_machine_ir_units_package
from .ir_recovery import (
    _callback_root_proposals_from_provenance,
    _local_callback_cutpoint_proposals,
    _newly_eligible_callback_roots,
    _recovery_failure_message,
)
from ..recovered_executable_data import RECOVERED_EXECUTABLE_DATA_FILENAME
from ..static_indirect_replay_v2 import (
    bounded_predecessor_instruction_history as _bounded_predecessor_instruction_history,
)


__all__ = [
    "MACHINE_IR_FILENAME",
    "MACHINE_IR_FORMAT",
    "MACHINE_IR_MANIFEST_FILENAME",
    "PREPARED_MACHINE_IR_FILENAME",
    "PREPARED_MACHINE_IR_FORMAT",
    "PREPARED_MACHINE_IR_MANIFEST_FILENAME",
    "RECOVERED_EXECUTABLE_DATA_FILENAME",
    "MachineIRExportError",
    "MachineIRPackage",
    "PreparedMachineIRPackage",
    "X87_MICRO_OP_FORMAT",
    "export_machine_ir_package",
    "prepare_machine_ir_units_package",
]
