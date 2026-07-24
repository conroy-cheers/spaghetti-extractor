import StageA.Formal

namespace StageA.Relational.ArtifactBytePacks

open StageA.Formal

/-- Exact arbitrary artifact bytes resident in Lean.  This storage layer makes
no identity claim: authoritative consumers must check the complete value with
their reviewed hash or range predicate. -/
structure ExactArtifactBytes where
  bytes : Bytes

def ExactArtifactBytes.empty : ExactArtifactBytes := {
  bytes := []
}

/-- Definitionally ordered concatenation of two exact artifacts.  Combining
already checked shards requires no inspection of their byte literals. -/
def ExactArtifactBytes.append
    (left right : ExactArtifactBytes) : ExactArtifactBytes := {
  bytes := left.bytes ++ right.bytes
}

theorem ExactArtifactBytes.append_bytes
    (left right : ExactArtifactBytes) :
    (left.append right).bytes = left.bytes ++ right.bytes :=
  rfl

end StageA.Relational.ArtifactBytePacks
