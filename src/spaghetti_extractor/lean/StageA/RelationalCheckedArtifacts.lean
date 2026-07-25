import StageA.RelationalSemanticsChecker

namespace StageA.Relational.CheckedArtifacts

open StageA.Formal StageA.Relational
open StageA.Relational.SemanticsChecker

/-- Stable public identity. Generated graph growth must not change the type of
an already checked artifact. -/
structure ArtifactId where
  value : String
deriving Repr, DecidableEq

/-- The exact machine effects exposed to downstream certificate checkers.
This is a projection of checked symbolic semantics, not an independently
trusted summary. -/
structure TransitionEffects where
  registers : Registers Expr
  x87 : SymbolicX87State
  writes : List (Expr × Expr)
  comparison : Option (Expr × Expr)
  flags : Option FlagsExpr
  outcome : Option OutcomeExpr
deriving Repr, DecidableEq

def TransitionEffects.ofBehavior
    (behavior : SymbolicBehavior) : TransitionEffects := {
  registers := behavior.registers
  x87 := behavior.x87
  writes := behavior.writes
  comparison := behavior.comparison
  flags := behavior.flags
  outcome := behavior.outcome
}

/-- Compact input to a semantic leaf. It intentionally contains no full PE
value: changing an unrelated image byte must not invalidate this artifact. -/
structure RegionSemanticInput where
  imageBase : Nat
  span : Span
  bytes : Bytes
deriving Repr, DecidableEq

def RegionSemanticInput.context
    (input : RegionSemanticInput) : SymbolicImageContext := {
  imageBase := input.imageBase
  immutableImageWord := fun _ _ => none
}

def RegionSemanticInput.evaluate
    (input : RegionSemanticInput) (imports : List PEImport)
    (contracts : List MachineImportCallContract) : Option SymbolicBehavior :=
  regionBehaviorFromBytesWithMachineCallContracts input.context imports
    contracts input.span input.bytes

/-- The semantic leaf evaluates its compact input once. Downstream artifacts
consume this checked value and its projected effects without decoding or
symbolically executing the region again. -/
structure CheckedLocalRegionSemantics
    (input : RegionSemanticInput) (imports : List PEImport)
    (contracts : List MachineImportCallContract) where
  artifactId : ArtifactId
  behavior : SymbolicBehavior
  effects : TransitionEffects
  replayExact : input.evaluate imports contracts = some behavior
  effectsExact : effects = TransitionEffects.ofBehavior behavior

def CheckedLocalRegionSemantics.ofReplay
    (input : RegionSemanticInput) (imports : List PEImport)
    (contracts : List MachineImportCallContract)
    (artifactId : ArtifactId) (behavior : SymbolicBehavior)
    (replay :
      input.evaluate imports contracts = some behavior) :
    CheckedLocalRegionSemantics input imports contracts := {
  artifactId
  behavior
  effects := TransitionEffects.ofBehavior behavior
  replayExact := replay
  effectsExact := rfl
}

/-- A cheap certificate ties a cached local semantic result to exact bytes in
one PE. The first profile is deliberately fail-closed for instructions whose
semantics read immutable image data; those regions remain on the legacy path
until they carry an explicit finite image-read certificate. -/
structure CheckedRegionImageBinding
    (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract)
    {input : RegionSemanticInput}
    (semantics : CheckedLocalRegionSemantics input imports contracts) where
  artifactId : ArtifactId
  spanBytesExact : spanBytes pe input.span = some input.bytes
  imageBaseExact : pe.imageBase = input.imageBase
  imageContextIndependent :
    codeImageContextIndependent (input.bytes.length + 1) input.bytes = true

theorem CheckedRegionImageBinding.behavior_exact
    {pe : PE32} {imports : List PEImport}
    {contracts : List MachineImportCallContract}
    {input : RegionSemanticInput}
    {semantics : CheckedLocalRegionSemantics input imports contracts}
    (binding :
      CheckedRegionImageBinding pe imports contracts semantics) :
    regionBehaviorWithMachineCallContracts pe imports contracts input.span =
      some semantics.behavior := by
  have contextEqual :
      regionBehaviorFromBytesWithContext (.ofPE pe) imports input.span
          input.bytes =
        regionBehaviorFromBytesWithContext input.context imports input.span
          input.bytes :=
    regionBehaviorFromBytesWithContext_eq_of_imageContextIndependent
      (.ofPE pe) input.context imports input.span input.bytes
      binding.imageBaseExact binding.imageContextIndependent
  calc
    regionBehaviorWithMachineCallContracts pe imports contracts input.span =
        regionBehaviorFromBytesWithMachineCallContracts (.ofPE pe) imports
          contracts input.span input.bytes := by
            simp [regionBehaviorWithMachineCallContracts,
              regionBehaviorWithImports,
              regionBehaviorFromBytesWithMachineCallContracts,
              binding.spanBytesExact, Bind.bind, Option.bind]
    _ = input.evaluate imports contracts := by
          unfold RegionSemanticInput.evaluate
          unfold regionBehaviorFromBytesWithMachineCallContracts
          rw [contextEqual]
    _ = some semantics.behavior := semantics.replayExact

theorem CheckedLocalRegionSemantics.effects_eq
    {input : RegionSemanticInput} {imports : List PEImport}
    {contracts : List MachineImportCallContract}
    (semantics : CheckedLocalRegionSemantics input imports contracts) :
    semantics.effects = TransitionEffects.ofBehavior semantics.behavior :=
  semantics.effectsExact

/-- Legacy compatibility certificate. New generated proof leaves must use
`CheckedLocalRegionSemantics` plus `CheckedRegionImageBinding`. -/
structure CheckedRegionSemantics
    (pe : PE32) (imports : List PEImport) where
  artifactId : ArtifactId
  span : Span
  behavior : SymbolicBehavior
  effects : TransitionEffects
  decodedExactly :
    regionBehaviorWithImports pe imports span = some behavior
  effectsExact : effects = TransitionEffects.ofBehavior behavior

def CheckedRegionSemantics.ofDecoded
    (pe : PE32) (imports : List PEImport)
    (artifactId : ArtifactId) (span : Span) (behavior : SymbolicBehavior)
    (decoded :
      regionBehaviorWithImports pe imports span = some behavior) :
    CheckedRegionSemantics pe imports := {
  artifactId
  span
  behavior
  effects := TransitionEffects.ofBehavior behavior
  decodedExactly := decoded
  effectsExact := rfl
}

/-- Machine-call contracts are part of the semantic identity when the region
contains a contracted external boundary. -/
structure CheckedContractedRegionSemantics
    (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract) where
  artifactId : ArtifactId
  span : Span
  behavior : SymbolicBehavior
  effects : TransitionEffects
  decodedExactly :
    regionBehaviorWithMachineCallContracts pe imports contracts span =
      some behavior
  effectsExact : effects = TransitionEffects.ofBehavior behavior

def CheckedContractedRegionSemantics.ofDecoded
    (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract)
    (artifactId : ArtifactId) (span : Span) (behavior : SymbolicBehavior)
    (decoded :
      regionBehaviorWithMachineCallContracts pe imports contracts span =
        some behavior) :
    CheckedContractedRegionSemantics pe imports contracts := {
  artifactId
  span
  behavior
  effects := TransitionEffects.ofBehavior behavior
  decodedExactly := decoded
  effectsExact := rfl
}

theorem CheckedRegionSemantics.effects_eq
    {pe : PE32} {imports : List PEImport}
    (semantics : CheckedRegionSemantics pe imports) :
    semantics.effects = TransitionEffects.ofBehavior semantics.behavior :=
  semantics.effectsExact

theorem CheckedContractedRegionSemantics.effects_eq
    {pe : PE32} {imports : List PEImport}
    {contracts : List MachineImportCallContract}
    (semantics : CheckedContractedRegionSemantics pe imports contracts) :
    semantics.effects = TransitionEffects.ofBehavior semantics.behavior :=
  semantics.effectsExact

end StageA.Relational.CheckedArtifacts
