import StageA.Formal

namespace StageA.Relational.NullableCodePointerTable

open StageA.Formal

/-- Evidence marked `unknown` is never accepted. -/
inductive Knowledge (alpha : Type) where
  | unknown
  | exact (value : alpha)
deriving Repr, DecidableEq, BEq

structure RvaRange where
  startRva : Nat
  endRva : Nat
deriving Repr, DecidableEq, BEq

structure CodeTarget where
  targetId : Nat
  rva : Nat
deriving Repr, DecidableEq, BEq

structure DispatchEdge where
  sourceContextId : Nat
  targetId : Nat
deriving Repr, DecidableEq, BEq

structure TableWriter where
  sourceRva : Nat
  writtenRange : RvaRange
deriving Repr, DecidableEq, BEq

structure TableAlias where
  aliasRva : Nat
  canonicalRva : Nat
deriving Repr, DecidableEq, BEq

structure LoopFacts where
  lowerInclusive : Nat
  upperExclusive : Nat
  step : Nat
  addressBaseRva : Nat
  addressScale : Nat
  alignment : Nat
deriving Repr, DecidableEq, BEq

inductive GuardKind where
  | zero
  | nonzero
deriving Repr, DecidableEq, BEq

/-- A finite proposal. Acceptance is computed only from the Lean-resident PE
bytes and these explicit context facts. -/
structure Certificate where
  peBytes : Bytes
  contextId : Nat
  dispatchRva : Nat
  tableRva : Nat
  headerWords : List Nat
  callerRange : Knowledge RvaRange
  codeMap : Knowledge (List CodeTarget)
  nonNullTargetIds : Knowledge (List Nat)
  edges : Knowledge (List DispatchEdge)
  writers : Knowledge (List TableWriter)
  aliases : Knowledge (List TableAlias)
  loop : Knowledge LoopFacts
  guard : Knowledge GuardKind
deriving Repr, DecidableEq

def noDuplicates [BEq alpha] (items : List alpha) : Bool :=
  items.length == items.eraseDups.length

def sameFiniteSet [BEq alpha] (left right : List alpha) : Bool :=
  noDuplicates left && noDuplicates right &&
    left.all right.contains && right.all left.contains

/-- Read a word only when all four bytes are present in the file and the PE
immutable-image reader independently accepts the same value. -/
def readImmutableExactRvaU32 (pe : PE32) (rva : Nat) : Option Nat := do
  let rawValue <- readExactRvaU32 pe rva
  let immutableValue <- readImmutableImageWord pe (pe.imageBase + rva) 4
  if rawValue == immutableValue then pure rawValue else none

def relocationCount (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation =>
    relocation.rva == rva && relocation.kind == 3).length

def codeMapChecked (pe : PE32) (targets : List CodeTarget) : Bool :=
  noDuplicates (targets.map (·.targetId)) &&
    noDuplicates (targets.map (·.rva)) &&
    targets.all fun target =>
      pe.executableRva target.rva && pe.imageBase + target.rva < 2 ^ 32

def mappedTargetId (pe : PE32) (targets : List CodeTarget)
    (value : Nat) : Option Nat :=
  match targets.filter fun target => pe.imageBase + target.rva == value with
  | [target] => some target.targetId
  | _ => none

/-- Zero is a genuine nullable entry and must not carry relocation evidence.
Every nonzero entry must have one HIGHLOW relocation and one mapped code
target. -/
def resolveNullableEntry (pe : PE32) (relocations : List BaseRelocation)
    (targets : List CodeTarget) (rva : Nat) : Option (Option Nat) := do
  let value <- readImmutableExactRvaU32 pe rva
  if value == 0 then
    if relocationCount relocations rva == 0 then pure none else none
  else
    if relocationCount relocations rva != 1 then none
    else
      let targetId <- mappedTargetId pe targets value
      pure (some targetId)

def resolveNullableEntries (pe : PE32) (relocations : List BaseRelocation)
    (targets : List CodeTarget) : Nat -> Nat -> Option (List (Option Nat))
  | _, 0 => some []
  | rva, count + 1 => do
      let head <- resolveNullableEntry pe relocations targets rva
      let tail <- resolveNullableEntries pe relocations targets (rva + 4) count
      pure (head :: tail)

def resolvedTargetIds (entries : List (Option Nat)) : List Nat :=
  entries.filterMap id |>.eraseDups

def headerWordsChecked (pe : PE32) : Nat -> List Nat -> Bool
  | _, [] => true
  | rva, word :: tail =>
      readImmutableExactRvaU32 pe rva == some word &&
        headerWordsChecked pe (rva + 4) tail

def rangeShapeChecked (pe : PE32) (tableRva : Nat)
    (headerWords : List Nat) (range : RvaRange) : Bool :=
  tableRva % 4 == 0 && range.startRva % 4 == 0 &&
    range.endRva % 4 == 0 &&
    tableRva + headerWords.length * 4 == range.startRva &&
    range.startRva <= range.endRva && range.endRva <= pe.sizeOfImage &&
    pe.imageBase + range.endRva <= 2 ^ 32 &&
    exactRvaSpan pe tableRva (range.endRva - tableRva)

def entryCount (range : RvaRange) : Nat :=
  (range.endRva - range.startRva) / 4

def loopFactsChecked (range : RvaRange) (loop : LoopFacts) : Bool :=
  loop.step == 1 && loop.addressBaseRva == range.startRva &&
    loop.addressScale == 4 && loop.alignment == 4 &&
    loop.addressBaseRva % loop.alignment == 0 &&
    loop.upperExclusive == loop.lowerInclusive + entryCount range

def expectedEdges (contextId : Nat) (targetIds : List Nat) :
    List DispatchEdge :=
  targetIds.map fun targetId => { sourceContextId := contextId, targetId }

def Certificate.checkedParsed (certificate : Certificate) (pe : PE32)
    (relocations : List BaseRelocation) (range : RvaRange)
    (targets : List CodeTarget) (contextTargetIds : List Nat)
    (edges : List DispatchEdge) (loop : LoopFacts)
    (guard : GuardKind) : Bool :=
  pe.executableRva certificate.dispatchRva &&
    codeMapChecked pe targets &&
    rangeShapeChecked pe certificate.tableRva certificate.headerWords range &&
    headerWordsChecked pe certificate.tableRva certificate.headerWords &&
    loopFactsChecked range loop && guard == .nonzero &&
    match resolveNullableEntries pe relocations targets range.startRva
        (entryCount range) with
    | none => false
    | some entries =>
        sameFiniteSet contextTargetIds (resolvedTargetIds entries) &&
          sameFiniteSet edges
            (expectedEdges certificate.contextId contextTargetIds)

/-- The top-level checker rejects every incomplete inventory before parsing the
exact PE and relocation directory. Writers and aliases are accepted only as
known-complete empty inventories. -/
def Certificate.checked (certificate : Certificate) : Bool :=
  match certificate.callerRange, certificate.codeMap,
      certificate.nonNullTargetIds, certificate.edges, certificate.writers,
      certificate.aliases, certificate.loop, certificate.guard with
  | .exact range, .exact targets, .exact contextTargetIds, .exact edges,
      .exact writers, .exact aliases, .exact loop, .exact guard =>
      writers.isEmpty && aliases.isEmpty &&
        match parsePE32 certificate.peBytes with
        | none => false
        | some pe =>
            match parseRelocations pe with
            | none => false
            | some relocations =>
                certificate.checkedParsed pe relocations range targets
                  contextTargetIds edges loop guard
  | _, _, _, _, _, _, _, _ => false

/-- Re-derive the context's non-null inventory directly from the exact PE.
`none` is treated as potentially reachable by the fail-closed result below. -/
def Certificate.resolvedNonNullTargetIds
    (certificate : Certificate) : Option (List Nat) := do
  let range <- match certificate.callerRange with
    | .exact range => some range
    | .unknown => none
  let targets <- match certificate.codeMap with
    | .exact targets => some targets
    | .unknown => none
  let pe <- parsePE32 certificate.peBytes
  let relocations <- parseRelocations pe
  let entries <- resolveNullableEntries pe relocations targets range.startRva
    (entryCount range)
  pure (resolvedTargetIds entries)

/-- This result is true only after full acceptance and an independently
re-parsed empty non-null inventory. -/
def Certificate.indirectDispatchUnreachable
    (certificate : Certificate) : Bool :=
  certificate.checked && certificate.resolvedNonNullTargetIds == some []

def Certificate.IndirectDispatchReachable
    (certificate : Certificate) : Prop :=
  ∃ targetIds targetId,
    certificate.resolvedNonNullTargetIds = some targetIds ∧
      targetId ∈ targetIds

theorem Certificate.noIndirectDispatch_of_unreachable
    (certificate : Certificate)
    (checked : certificate.indirectDispatchUnreachable = true) :
    ¬ certificate.IndirectDispatchReachable := by
  simp only [Certificate.indirectDispatchUnreachable, Bool.and_eq_true,
    beq_iff_eq] at checked
  intro reachable
  rcases reachable with ⟨targetIds, targetId, parsed, member⟩
  have targetIdsEmpty : targetIds = [] := by
    exact Option.some.inj (parsed.symm.trans checked.2)
  simpa [targetIdsEmpty] using member

end StageA.Relational.NullableCodePointerTable
