import StageA.RelationalInterpreterKernelProgramIndex
import StageA.RelationalInterpreterKernelProgramTableProjection

namespace StageA.Relational.InterpreterKernelActionCursor

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelProgramIndex
open StageA.Relational.InterpreterKernelProgramTableProjection

/-!
# Checked semantic/native action cursors

The compiled Stage B interpreter walks a fixed-width raw action array while
the authoritative semantic interpreter walks `SemanticTransfer.body` and then
executes one terminal `SemanticOutcome`.  This module is the single bridge
between those views.

Generated proofs may provide list decompositions and compiler-frame offsets,
but Lean checks:

* the semantic transfer came from the canonical checked program record;
* the raw actions came from the exact loaded candidate PE;
* the current raw body action decodes to the current semantic action;
* the final raw action decodes to the transfer outcome; and
* the native loop index and frame storage represent the semantic runtime.

No C source, symbol name, or submitted machine value is authoritative.
-/

/-- One semantic transfer paired with the exact loaded action array from which
it was decoded.  `recordExact` prevents a generated module from pairing a
checked semantic record with another table entry that happens to have the same
source RVA. -/
structure CheckedLoadedSemanticTransfer
    (pe : PE32) (tableRva index : Nat) (data : TransferCertificateData)
    (records : List ProgramRecord) (memory : Memory) where
  semantic : CheckedSemanticProgramRecord records data.descriptor.sourceRva
  recordExact : semantic.record = data.compiled.record
  sourceIndexExact :
    (records.map (fun record => record.sourceRva))[index]? =
      some data.descriptor.sourceRva
  loaded : LoadedTransferActionsAt pe tableRva index data memory

def CheckedLoadedSemanticTransfer.transfer
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory) : SemanticTransfer :=
  checked.semantic.semantic.transfer

theorem CheckedLoadedSemanticTransfer.decodeExact
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory) :
    data.compiled.record.decode = some checked.transfer := by
  rw [← checked.recordExact]
  exact checked.semantic.semantic.decodeExact

theorem CheckedLoadedSemanticTransfer.checkedExact
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory) :
    checked.transfer.checked = true :=
  checked.semantic.semantic.checkedExact

theorem CheckedLoadedSemanticTransfer.sourceRvaExact
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory) :
    checked.transfer.sourceRva = data.descriptor.sourceRva := by
  have decoded := checked.decodeExact
  unfold ProgramRecord.decode at decoded
  split at decoded <;> simp_all
  next =>
    split at decoded <;> simp_all
    next final reverseBody actionsReverse =>
      cases wordNodesExact :
          data.compiled.record.wordNodes.mapM RawWordNode.decode with
      | none =>
          simp [wordNodesExact] at decoded
      | some wordNodes =>
          cases callsExact :
              data.compiled.record.calls.mapM RawCall.decode with
          | none =>
              simp [wordNodesExact, callsExact] at decoded
          | some calls =>
              cases bodyExact :
                  reverseBody.reverse.mapM RawAction.decodeBody with
              | none =>
                  simp [wordNodesExact, callsExact, bodyExact] at decoded
              | some body =>
                  cases outcomeExact : final.decodeOutcome with
                  | none =>
                      simp [wordNodesExact, callsExact, bodyExact,
                        outcomeExact] at decoded
                  | some outcome =>
                      simp [wordNodesExact, callsExact, bodyExact,
                        outcomeExact] at decoded
                      exact
                        (congrArg SemanticTransfer.sourceRva decoded).symm

/-- A semantic body cursor and its exact raw-action decomposition.  The raw
prefix is retained because its length is the native loop index.  The terminal
raw action is retained in every cursor, so structural induction over the body
cannot accidentally omit the final outcome action. -/
structure CheckedRawBodyCursor
    (data : TransferCertificateData) (transfer : SemanticTransfer)
    (remaining : List SemanticAction) where
  rawPrefix : List RawAction
  semanticPrefix : List SemanticAction
  rawAction : RawAction
  rawTail : List RawAction
  rawOutcome : RawAction
  rawActionsExact :
    data.actions = rawPrefix ++ rawAction :: rawTail ++ [rawOutcome]
  semanticBodyExact :
    transfer.body = semanticPrefix ++ remaining
  prefixDecodes :
    rawPrefix.mapM RawAction.decodeBody = some semanticPrefix
  prefixLengthsExact : rawPrefix.length = semanticPrefix.length
  currentDecodes :
    remaining.head? = rawAction.decodeBody
  tailDecodes :
    rawTail.mapM RawAction.decodeBody = some remaining.tail
  outcomeDecodes : rawOutcome.decodeOutcome = some transfer.outcome

/-- The current native action index is definitionally the number of checked
body actions already consumed. -/
def CheckedRawBodyCursor.actionIndex
    (cursor : CheckedRawBodyCursor data transfer remaining) : Nat :=
  cursor.rawPrefix.length

theorem CheckedRawBodyCursor.currentSemanticAction
    (cursor : CheckedRawBodyCursor data transfer (action :: tail)) :
    cursor.rawAction.decodeBody = some action := by
  simpa using cursor.currentDecodes.symm

theorem CheckedLoadedSemanticTransfer.loadedBodyAction
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory)
    (cursor : CheckedRawBodyCursor data checked.transfer (action :: tail)) :
    LoadedRawActionAt pe
      (checked.loaded.actionRva + cursor.actionIndex * actionSize)
      cursor.rawAction memory := by
  apply checked.loaded.actions.action cursor.actionIndex cursor.rawAction
  rw [cursor.rawActionsExact]
  simp [CheckedRawBodyCursor.actionIndex]

/-- Cursor after every semantic body action has completed.  The next and final
native iteration must execute the raw outcome action, not merely leave the
loop. -/
structure CheckedRawOutcomeCursor
    (data : TransferCertificateData) (transfer : SemanticTransfer) where
  rawBody : List RawAction
  rawOutcome : RawAction
  rawActionsExact : data.actions = rawBody ++ [rawOutcome]
  bodyDecodes : rawBody.mapM RawAction.decodeBody = some transfer.body
  outcomeDecodes : rawOutcome.decodeOutcome = some transfer.outcome

def CheckedRawOutcomeCursor.actionIndex
    (cursor : CheckedRawOutcomeCursor data transfer) : Nat :=
  cursor.rawBody.length

theorem CheckedLoadedSemanticTransfer.loadedOutcomeAction
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory)
    (cursor : CheckedRawOutcomeCursor data checked.transfer) :
    LoadedRawActionAt pe
      (checked.loaded.actionRva + cursor.actionIndex * actionSize)
      cursor.rawOutcome memory := by
  apply checked.loaded.actions.action cursor.actionIndex cursor.rawOutcome
  rw [cursor.rawActionsExact]
  simp [CheckedRawOutcomeCursor.actionIndex]

/-- Recover the canonical raw body/outcome split from the checked semantic
decode.  This is proved once in the stable kernel; generated transfer modules
do not submit a second action partition. -/
noncomputable def CheckedLoadedSemanticTransfer.outcomeCursor
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory) :
    CheckedRawOutcomeCursor data checked.transfer := by
  have decoded := checked.decodeExact
  unfold ProgramRecord.decode at decoded
  split at decoded <;> simp_all
  next =>
    split at decoded <;> simp_all
    next final reverseBody actionsReverse =>
      cases wordNodesExact :
          data.compiled.record.wordNodes.mapM RawWordNode.decode with
      | none =>
          simp [wordNodesExact] at decoded
      | some wordNodes =>
          cases callsExact :
              data.compiled.record.calls.mapM RawCall.decode with
          | none =>
              simp [wordNodesExact, callsExact] at decoded
          | some calls =>
              cases bodyExact :
                  reverseBody.reverse.mapM RawAction.decodeBody with
              | none =>
                  simp [wordNodesExact, callsExact, bodyExact] at decoded
              | some body =>
                  cases outcomeExact : final.decodeOutcome with
                  | none =>
                      simp [wordNodesExact, callsExact, bodyExact,
                        outcomeExact] at decoded
                  | some outcome =>
                      simp [wordNodesExact, callsExact, bodyExact,
                        outcomeExact] at decoded
                      have transferExact :
                          checked.transfer = {
                            sourceRva := data.descriptor.sourceRva
                            wordNodes := wordNodes
                            calls := calls
                            body := body
                            outcome := outcome
                          } := decoded.symm
                      exact {
                        rawBody := reverseBody.reverse
                        rawOutcome := final
                        rawActionsExact := actionsReverse
                        bodyDecodes := by
                          simpa [transferExact] using bodyExact
                        outcomeDecodes := by
                          simpa [transferExact] using outcomeExact
                      }

/-- The first semantic body action has one canonical raw action cursor. -/
noncomputable def CheckedLoadedSemanticTransfer.initialBodyCursor
    (checked : CheckedLoadedSemanticTransfer pe tableRva index data records
      memory) (action : SemanticAction) (tail : List SemanticAction)
    (bodyExact : checked.transfer.body = action :: tail) :
    CheckedRawBodyCursor data checked.transfer (action :: tail) := by
  let outcome := checked.outcomeCursor
  cases rawBodyExact : outcome.rawBody with
  | nil =>
      have impossible := outcome.bodyDecodes
      simp [rawBodyExact, bodyExact] at impossible
  | cons rawAction rawTail =>
      have decoded := outcome.bodyDecodes
      rw [rawBodyExact, bodyExact] at decoded
      cases currentExact : rawAction.decodeBody with
      | none =>
          simp [currentExact] at decoded
      | some decodedAction =>
          cases tailExact : rawTail.mapM RawAction.decodeBody with
          | none =>
              simp [currentExact, tailExact] at decoded
          | some decodedTail =>
              simp [currentExact, tailExact] at decoded
              rcases decoded with ⟨actionExact, tailResultExact⟩
              subst decodedAction
              subst decodedTail
              exact {
                rawPrefix := []
                semanticPrefix := []
                rawAction
                rawTail
                rawOutcome := outcome.rawOutcome
                rawActionsExact := by
                  simpa [rawBodyExact] using outcome.rawActionsExact
                semanticBodyExact := by simpa using bodyExact
                prefixDecodes := by simp
                prefixLengthsExact := rfl
                currentDecodes := by simpa using currentExact.symm
                tailDecodes := tailExact
                outcomeDecodes := outcome.outcomeDecodes
              }

/-- Advance only the static action decomposition.  The native transition proof
must separately establish the incremented machine cursor. -/
noncomputable def CheckedRawBodyCursor.advance
    (cursor : CheckedRawBodyCursor data transfer
      (action :: nextAction :: tail)) :
    CheckedRawBodyCursor data transfer (nextAction :: tail) := by
  cases rawTailExact : cursor.rawTail with
  | nil =>
      have impossible := cursor.tailDecodes
      simp [rawTailExact] at impossible
  | cons nextRawAction nextRawTail =>
      have tailDecoded := cursor.tailDecodes
      rw [rawTailExact] at tailDecoded
      cases currentExact : nextRawAction.decodeBody with
      | none =>
          simp [currentExact] at tailDecoded
      | some decodedAction =>
          cases remainingExact :
              nextRawTail.mapM RawAction.decodeBody with
          | none =>
              simp [currentExact, remainingExact] at tailDecoded
          | some decodedTail =>
              simp [currentExact, remainingExact] at tailDecoded
              rcases tailDecoded with ⟨actionExact, tailResultExact⟩
              subst decodedAction
              subst decodedTail
              exact {
                rawPrefix := cursor.rawPrefix ++ [cursor.rawAction]
                semanticPrefix := cursor.semanticPrefix ++ [action]
                rawAction := nextRawAction
                rawTail := nextRawTail
                rawOutcome := cursor.rawOutcome
                rawActionsExact := by
                  rw [cursor.rawActionsExact]
                  simp [rawTailExact, List.append_assoc]
                semanticBodyExact := by
                  rw [cursor.semanticBodyExact]
                  simp [List.append_assoc]
                prefixDecodes := by
                  rw [List.mapM_append, cursor.prefixDecodes]
                  simp [cursor.currentSemanticAction]
                prefixLengthsExact := by
                  simp [cursor.prefixLengthsExact]
                currentDecodes := by simpa using currentExact.symm
                tailDecodes := remainingExact
                outcomeDecodes := cursor.outcomeDecodes
              }

/-- After the final body action, the static cursor points at the mandatory
terminal outcome action. -/
noncomputable def CheckedRawBodyCursor.finish
    (cursor : CheckedRawBodyCursor data transfer [action]) :
    CheckedRawOutcomeCursor data transfer := by
  have rawTailEmpty : cursor.rawTail = [] := by
    cases rawTailExact : cursor.rawTail with
    | nil => rfl
    | cons rawAction rawTail =>
        have impossible := cursor.tailDecodes
        rw [rawTailExact] at impossible
        cases currentExact : rawAction.decodeBody with
        | none =>
            simp [currentExact] at impossible
        | some decodedAction =>
            cases remainingExact :
                rawTail.mapM RawAction.decodeBody with
            | none =>
                simp [currentExact, remainingExact] at impossible
            | some decodedTail =>
                simp [currentExact, remainingExact] at impossible
  exact {
    rawBody := cursor.rawPrefix ++ [cursor.rawAction]
    rawOutcome := cursor.rawOutcome
    rawActionsExact := by
      rw [cursor.rawActionsExact]
      simp [rawTailEmpty]
    bodyDecodes := by
      rw [List.mapM_append, cursor.prefixDecodes]
      simp [cursor.currentSemanticAction, cursor.semanticBodyExact]
    outcomeDecodes := cursor.outcomeDecodes
  }

#print axioms CheckedLoadedSemanticTransfer.decodeExact
#print axioms CheckedLoadedSemanticTransfer.sourceRvaExact
#print axioms CheckedLoadedSemanticTransfer.loadedBodyAction
#print axioms CheckedLoadedSemanticTransfer.loadedOutcomeAction
#print axioms CheckedLoadedSemanticTransfer.outcomeCursor
#print axioms CheckedLoadedSemanticTransfer.initialBodyCursor
#print axioms CheckedRawBodyCursor.advance
#print axioms CheckedRawBodyCursor.finish

end StageA.Relational.InterpreterKernelActionCursor
