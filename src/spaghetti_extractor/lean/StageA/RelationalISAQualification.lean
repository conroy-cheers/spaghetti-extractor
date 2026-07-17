import Lean
import StageA.ISAQualification
import StageA.RelationalPEExecution

namespace StageA.Formal

structure InstructionFormOccurrence where
  offset : Nat
  size : Nat
  bytes : Bytes
  form : InstructionSemanticForm
deriving Repr, DecidableEq

end StageA.Formal

namespace StageA.Relational

open StageA.Formal
open Lean

def decodeInstructionFormsFuel (pe : PE32) (stop : Nat) :
    Nat -> Nat -> Option (List InstructionFormOccurrence)
  | 0, _ => none
  | fuel + 1, rva =>
      if rva == stop then some []
      else if stop < rva then none
      else do
        let bytes <- executableSpanInstructionWindow pe rva stop
        let decoded <- decodeInstructionExact bytes
        if decoded.size == 0 || stop < rva + decoded.size then none else
        let tail <- decodeInstructionFormsFuel pe stop fuel (rva + decoded.size)
        pure ({
          offset := rva
          size := decoded.size
          bytes := bytes.take decoded.size
          form := decoded.instruction.semanticForm
        } :: tail)

/-- Re-decode one exact PE span into the Lean semantic-form inventory. -/
def decodeInstructionFormsSpan (pe : PE32)
    (span : Span) : Option (List InstructionFormOccurrence) :=
  decodeInstructionFormsFuel pe span.stop (span.size + 1) span.start

structure ISARequirementRegion where
  nodeId : Nat
  occurrences : List InstructionFormOccurrence
deriving Repr, DecidableEq

def ISARequirementRegion.Replays (requirement : ISARequirementRegion)
    (pe : PE32) (candidate : Bool) (region : RegionRelation) : Prop :=
  requirement.nodeId = region.id ∧
    decodeInstructionFormsSpan pe
      (if candidate then region.candidate else region.original) =
        some requirement.occurrences

def AllISARequirementRegionsReplay (pe : PE32) (candidate : Bool) :
    List RegionRelation -> List ISARequirementRegion -> Prop
  | [], [] => True
  | region :: regions, requirement :: requirements =>
      requirement.Replays pe candidate region ∧
        AllISARequirementRegionsReplay pe candidate regions requirements
  | _, _ => False

theorem allISARequirementRegionsReplay_append (pe : PE32) (candidate : Bool)
    (leftRegions rightRegions : List RegionRelation)
    (leftRequirements rightRequirements : List ISARequirementRegion)
    (left : AllISARequirementRegionsReplay pe candidate
      leftRegions leftRequirements)
    (right : AllISARequirementRegionsReplay pe candidate
      rightRegions rightRequirements) :
    AllISARequirementRegionsReplay pe candidate
      (leftRegions ++ rightRegions) (leftRequirements ++ rightRequirements) := by
  induction leftRegions generalizing leftRequirements with
  | nil =>
      cases leftRequirements with
      | nil => exact right
      | cons _ _ => simp [AllISARequirementRegionsReplay] at left
  | cons region regions ih =>
      cases leftRequirements with
      | nil => simp [AllISARequirementRegionsReplay] at left
      | cons requirement requirements =>
          simp only [List.cons_append, AllISARequirementRegionsReplay] at left ⊢
          exact ⟨left.1, ih requirements left.2⟩

structure ISARequirementReplayCertificate
    (originalPe candidatePe : PE32) (regions : List RegionRelation) where
  originalRequirements : List ISARequirementRegion
  candidateRequirements : List ISARequirementRegion
  originalReplayed : AllISARequirementRegionsReplay originalPe false
    regions originalRequirements
  candidateReplayed : AllISARequirementRegionsReplay candidatePe true
    regions candidateRequirements

def instructionFormOccurrenceJson (occurrence : InstructionFormOccurrence) : Json :=
  Json.mkObj [
    ("rva", toJson occurrence.offset),
    ("size", toJson occurrence.size),
    ("bytes", toJson occurrence.bytes),
    ("form", toJson (reprStr occurrence.form))
  ]

def instructionFormInventoryJson
    (occurrences : List InstructionFormOccurrence) : Json :=
  Json.arr (occurrences.map instructionFormOccurrenceJson).toArray

end StageA.Relational
