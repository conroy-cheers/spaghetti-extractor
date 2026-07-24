"""Emit the generic x87 replay-kernel execution theorem interface.

The emitted declarations add no target-specific execution witnesses.  They
specialize the generic endpoint authority to the generated, PE-checked runtime
inventory and use the reviewed Lean theorem to inhabit the kernel execution
goal.
"""

from __future__ import annotations


def interpreter_kernel_x87_execution_lean_snippet() -> str:
    """Return declarations that connect checked endpoints to the generated goal."""

    return """def GeneratedX87ReplayBridgeKernelEndpointAuthorityGoal
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop :=
  ExactNativeX87ReplayKernelEndpointAuthority
    generatedX87ReplayBridgeRuntimeInventory program handler sourceInvariant

theorem generatedX87ReplayBridgeKernelExecution
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop)
    (authority : GeneratedX87ReplayBridgeKernelEndpointAuthorityGoal
      program handler sourceInvariant) :
    GeneratedX87ReplayBridgeKernelExecutionGoal
      program handler sourceInvariant := by
  exact authority.kernelExecution

#print axioms generatedX87ReplayBridgeKernelExecution"""
