import StageA.RelationalInterpreterKernelCallback
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelCallbackNativeWorldBridge

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterNativeWorld

/-! The compiled-kernel callback inventory and the native-world transition
system describe the same candidate indirect calls at different layers.  This
module makes their relationship explicit without trusting generated status:
exact callback sites become call target sets whose members are executable
candidate RVAs. -/

def callbackTargetNativeDescriptor
    (target : CallbackTargetEntry) : NativeIndirectTargetDescriptor :=
  .internalRva target.entry.rva

def kernelCallbackSiteNativeTargetSet
    (site : KernelIndirectCallbackSite) : NativeIndirectTargetSet := {
  sourceRva := site.instruction.rva
  transfer := .call
  targets := site.targets.entries.map callbackTargetNativeDescriptor
}

def kernelCallbackNativeTargetInventory
    (inventory : KernelCallbackInventory) : NativeIndirectTargetInventory := {
  targetSets := inventory.sites.map kernelCallbackSiteNativeTargetSet
}

/-- The checked link needed by exact native execution.  `callbackChecked`
re-decodes every submitted call site and target entry from the PE;
`candidateTargets` prevents the operational transition system from using a
different inventory; `nativeTargetsValid` checks finite nonempty target sets
and unique source/transfer routes. -/
structure ExactKernelCallbackNativeWorldBinding
    (inventory : KernelCallbackInventory)
    (program : CompiledKernelProgram)
    (candidate : ExactNativeWorldProgram) : Prop where
  callbackChecked : inventory.checked program candidate.pe
    candidate.imports = true
  candidateTargets : candidate.indirectTargets =
    kernelCallbackNativeTargetInventory inventory
  nativeTargetsValid :
    (kernelCallbackNativeTargetInventory inventory).valid candidate.pe = true

theorem ExactKernelCallbackNativeWorldBinding.targetInventoryValid
    (binding : ExactKernelCallbackNativeWorldBinding inventory program candidate) :
    candidate.indirectTargets.valid candidate.pe = true := by
  rw [binding.candidateTargets]
  exact binding.nativeTargetsValid

#print axioms ExactKernelCallbackNativeWorldBinding.targetInventoryValid

end StageA.Relational.InterpreterKernelCallbackNativeWorldBridge
