import Lean
import StageA.ISAQualification

namespace StageA.ISAInventory

open Lean StageA.Formal

abbrev Bytes := List Nat

structure Span where
  start : Nat
  size : Nat

def Span.stop (span : Span) : Nat := span.start + span.size

structure InstructionFormOccurrence where
  offset : Nat
  size : Nat
  bytes : Bytes
  form : InstructionSemanticForm
deriving Repr, DecidableEq

def decodeInstructionFormsBytesFuel (stop : Nat) :
    Nat -> Nat -> Bytes -> Option (List InstructionFormOccurrence)
  | 0, _, _ => none
  | fuel + 1, rva, bytes =>
      if rva == stop then
        if bytes.isEmpty then some [] else none
      else if stop < rva then none
      else do
        let decoded <- decodeInstructionExact bytes
        if decoded.size == 0 ||
            bytes.length < decoded.size ||
            stop < rva + decoded.size then
          none
        else
          let tail <- decodeInstructionFormsBytesFuel stop fuel
            (rva + decoded.size) (bytes.drop decoded.size)
          pure ({
            offset := rva
            size := decoded.size
            bytes := bytes.take decoded.size
            form := decoded.instruction.semanticForm
          } :: tail)

def decodeInstructionFormsBytes (start : Nat) (bytes : Bytes) :
    Option (List InstructionFormOccurrence) :=
  decodeInstructionFormsBytesFuel (start + bytes.length)
    (bytes.length + 1) start bytes

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

end StageA.ISAInventory
