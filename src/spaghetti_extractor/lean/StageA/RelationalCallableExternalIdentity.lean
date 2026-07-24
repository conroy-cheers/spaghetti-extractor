import StageA.RelationalEnvironment

namespace StageA.Relational

open StageA.Formal

/-! # Shared callable-external observation identity

These types sit below both world execution systems. A resolved opaque
callable is not an import and must not be normalized into an `ExternalTarget`.
The capability, resource, ABI contract, transfer kind, and global event index
therefore remain explicit in the observation checked by composition. -/

inductive ResolvedExternalTransfer where
  | call
  | jump
deriving Repr, DecidableEq

inductive CallableExternalIdentity where
  | imported (siteId machineContractId : Nat) (imported : ExternalTarget)
      (transfer : ResolvedExternalTransfer)
  | resolver (siteId resolverContractId capabilityId : Nat)
  | resolved (capabilityId resourceId abiContractId : Nat)
      (transfer : ResolvedExternalTransfer)
deriving Repr, DecidableEq

structure CallableExternalObservation where
  globalExternalIndex : Nat
  identity : CallableExternalIdentity
  arguments : List Word
  world : RelationalWorld
deriving Repr, DecidableEq

end StageA.Relational
