import StageA.RelationalInterpreterKernel

namespace StageA.Relational.InterpreterKernelBlock

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

structure ReflectedKernelInstruction where
  submitted : KernelInstruction
  decoded : DecodedInstruction
deriving Repr, DecidableEq

def reflectKernelInstruction? (pe : PE32)
    (instruction : KernelInstruction) : Option ReflectedKernelInstruction := do
  let decoded <- instruction.decode? pe
  pure { submitted := instruction, decoded }

structure ReflectedKernelBlock where
  block : KernelBlock
  instructions : List ReflectedKernelInstruction
  behavior : SymbolicBehavior
deriving Repr, DecidableEq

/-- Reflect a finite basic block entirely in Lean.  `KernelBlock.checked`
establishes a nonempty, no-duplicate, linear instruction prefix with one final
control exit.  Each instruction is then decoded again from its submitted exact
bytes, and the complete prefix is symbolically executed. -/
def reflectKernelBlock? (pe : PE32) (imports : List PEImport)
    (block : KernelBlock) : Option ReflectedKernelBlock := do
  if !block.checked pe imports then none else
  let instructions <- block.instructions.mapM (reflectKernelInstruction? pe)
  let behavior <- block.symbolicBehavior? pe imports
  pure { block, instructions, behavior }

def ReflectedKernelBlock.Exact (pe : PE32) (imports : List PEImport)
    (reflection : ReflectedKernelBlock) : Prop :=
  reflectKernelBlock? pe imports reflection.block = some reflection

/-! A certificate for one finite compiled-kernel basic block.  Exact decoding
and symbolic execution are recomputed by Lean.  The `agrees` field is the
semantic trust boundary: it is universally quantified over concrete machine
states and therefore cannot be populated by a Python status bit. -/
structure ReflectiveBlockCertificate (pe : PE32) (imports : List PEImport)
    (block : KernelBlock) where
  reflection : ReflectedKernelBlock
  reflected : reflectKernelBlock? pe imports block = some reflection
  blockExact : reflection.block = block
  symbolicExact : block.symbolicBehavior? pe imports = some reflection.behavior
  agrees : ∀ input,
    block.symbolicConcreteAgree reflection.behavior input
      (runKernelBlockConcrete pe imports 0 input block.instructions)

theorem ReflectiveBlockCertificate.sound
    {pe : PE32} {imports : List PEImport} {block : KernelBlock}
    (certificate : ReflectiveBlockCertificate pe imports block) :
    block.SymbolicExecutionSound pe imports := by
  intro behavior symbolic input
  rw [certificate.symbolicExact] at symbolic
  cases symbolic
  exact certificate.agrees input

theorem ReflectiveBlockCertificate.exact
    {pe : PE32} {imports : List PEImport} {block : KernelBlock}
    (certificate : ReflectiveBlockCertificate pe imports block) :
    certificate.reflection.Exact pe imports := by
  simpa [ReflectedKernelBlock.Exact, certificate.blockExact] using
    certificate.reflected

end StageA.Relational.InterpreterKernelBlock
