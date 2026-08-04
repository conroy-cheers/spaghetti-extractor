import StageA.RelationalInterpreterMixedLaunchLexicographicInvariant

namespace StageA.Targets.GnuHello.TransferValidationRank

open StageA.Relational.InterpreterMixedLaunchLexicographicInvariant

def rankSpec : LexicographicLoopRankSpec := {
  recordCount := 5697
  lookupRankBound := 5697
}

theorem rankSpec_exact :
    rankSpec.recordCount = 5697 /\ rankSpec.lookupRankBound = 5697 := by
  decide

theorem step_rank_decreases
    (kind : LexicographicLoopStep)
    (before after : LexicographicLoopRankState)
    (checked : rankSpec.stepChecked kind before after = true) :
    rankSpec.rank after < rankSpec.rank before :=
  rankSpec.stepChecked_rank_decreases kind before after checked

#print axioms rankSpec_exact
#print axioms step_rank_decreases

end StageA.Targets.GnuHello.TransferValidationRank
