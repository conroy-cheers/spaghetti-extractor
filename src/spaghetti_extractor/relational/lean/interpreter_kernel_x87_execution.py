"""Emit the generated fixed-template x87 replay theorem interface.

The runtime generator supplies finite, target-indexed checked-success data.
These declarations use its assembled executor to close the generic executor
boundary while leaving source-frame admission explicit in the target checks.
The generic Lean reduction constructs the fault-free split mixed post-state;
generated code never supplies an `afterRelated` proposition.
"""

from __future__ import annotations


def interpreter_kernel_x87_execution_lean_snippet() -> str:
    """Connect finite checked target terms to the generic reduction proof."""

    return """def generatedX87ReplayBridgeNestedProgram
    (carrier : ExactNestedNativeWorldProgram) : ExactNestedNativeWorldProgram :=
  bindExactNativeX87ReplayNestedProgram
    generatedX87ReplayBridgeRuntimeInventory carrier

theorem generatedX87ReplayBridgeNestedProgramPeExact
    (carrier : ExactNestedNativeWorldProgram) :
    (generatedX87ReplayBridgeNestedProgram carrier).pe =
      generatedInterpreterKernelCandidatePe :=
  rfl

theorem generatedX87ReplayBridgeNestedProgramImportsExact
    (carrier : ExactNestedNativeWorldProgram) :
    (generatedX87ReplayBridgeNestedProgram carrier).imports =
      generatedInterpreterKernelImports :=
  rfl

theorem generatedX87ReplayBridgeNestedProgramTargetInventoryExact
    (carrier : ExactNestedNativeWorldProgram) :
    (generatedX87ReplayBridgeNestedProgram carrier).indirectTargets.targetSet?
        generatedX87ReplayBridgeTable.callInstruction.rva .call =
      some generatedX87ReplayBridgeTable.nativeTargetSet :=
  bindExactNativeX87ReplayNestedProgram_targetInventory
    generatedX87ReplayBridgeRuntimeInventory carrier

def generatedX87ReplayBridgeKernelProgramBinding
    (carrier : ExactNestedNativeWorldProgram) :
    ExactNativeX87ReplayKernelProgramBinding
      generatedX87ReplayBridgeRuntimeInventory
      (generatedX87ReplayBridgeNestedProgram carrier) := {
  peExact := generatedX87ReplayBridgeNestedProgramPeExact carrier
  importsExact := generatedX87ReplayBridgeNestedProgramImportsExact carrier
  imageBounded := by decide +kernel
  targetInventory :=
    generatedX87ReplayBridgeNestedProgramTargetInventoryExact carrier
}

def GeneratedX87ReplayBridgeFixedTemplateChecksGoal
    (carrier : ExactNestedNativeWorldProgram) : Prop :=
  GeneratedX87ReplayBridgeFixedTemplateChecks carrier

theorem generatedX87ReplayBridgeKernelExecution
    (carrier : ExactNestedNativeWorldProgram)
    (checked : GeneratedX87ReplayBridgeFixedTemplateChecksGoal carrier) :
    GeneratedX87ReplayBridgeKernelExecutionGoal
      (generatedX87ReplayBridgeNestedProgram carrier) := by
  exact (generatedX87ReplayBridgeFixedTemplateExecutor carrier checked).kernelExecution
    (generatedX87ReplayBridgeKernelProgramBinding carrier)
    generatedX87ReplayBridgeHandlerInventoryCorrespondence

theorem generatedX87ReplayBridgeKernelExecutionClosed
    (carrier : ExactNestedNativeWorldProgram) :
    GeneratedX87ReplayBridgeKernelExecutionGoal
      (generatedX87ReplayBridgeNestedProgram carrier) :=
  generatedX87ReplayBridgeKernelExecution carrier
    (generatedX87ReplayBridgeFixedTemplateChecks carrier)

theorem generatedX87ReplayBridgeTemplateExecution
    (carrier : ExactNestedNativeWorldProgram)
    (checked : GeneratedX87ReplayBridgeFixedTemplateChecksGoal carrier) :
    GeneratedX87ReplayBridgeTemplateExecutionGoal
      (generatedX87ReplayBridgeNestedProgram carrier) := by
  exact (generatedX87ReplayBridgeFixedTemplateExecutor carrier checked).templateExecution
    (generatedX87ReplayBridgeKernelProgramBinding carrier)
    generatedX87ReplayBridgeHandlerInventoryCorrespondence

#print axioms generatedX87ReplayBridgeNestedProgramTargetInventoryExact
#print axioms generatedX87ReplayBridgeKernelProgramBinding
#print axioms generatedX87ReplayBridgeKernelExecution
#print axioms generatedX87ReplayBridgeKernelExecutionClosed
#print axioms generatedX87ReplayBridgeTemplateExecution"""
