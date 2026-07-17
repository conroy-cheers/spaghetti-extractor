import StageA.Formal

namespace StageA.Formal

/-- Concrete ISA conformance cases are test evidence only. They can reject a
machine-semantics profile, but no value in this module can authorize a Stage A
proof obligation. -/
inductive ISAConformanceAuthority where
  | vetoOnly
deriving Repr, DecidableEq

inductive ISAConformanceX87Profile where
  /-- The current Lean-owned x87 semantics profile. This profile is deliberately
  not described as hardware-conformant until its conformance corpus passes. -/
  | formalDefaultV1
deriving Repr, DecidableEq

structure ISAConformanceMemoryByte where
  address : Nat
  value : Nat
deriving Repr, DecidableEq

structure ISAConformanceWordWrite where
  address : Nat
  value : Nat
deriving Repr, DecidableEq

structure ISAConformanceInput where
  bytes : Bytes
  pc : Nat
  imageBase : Nat := 0x400000
  registers : Registers Nat
  eflags : Nat
  fsBase : Nat := 0
  memory : List ISAConformanceMemoryByte := []
  undefinedStartSlot : Nat := 0
  undefinedValues : List Nat := []
  undefinedDefault : Nat := 0
  x87Stack : List Nat := List.replicate 8 0
  x87Control : Nat := 0x037f
  x87Status : Nat := 0
  x87Profile : ISAConformanceX87Profile := .formalDefaultV1
  observeMemory : List Nat := []
deriving Repr, DecidableEq

inductive ISAConformanceControl where
  | next (rva : Nat)
  | returned (target : Nat)
  | jump (targetRva : Nat)
  | branch (condition : Bool) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Nat) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Nat)
  | bulkCopy (destination source count : Nat) (direction : Bool)
      (continuationRva : Nat)
  | indirectCall (target : Nat) (continuationRva returnAddress : Nat)
  | indirectJump (target : Nat)
  | checkedContinue (valid : Bool) (continuationRva : Nat)
  | atomicCompareExchange (address expected replacement : Nat)
      (continuationRva : Nat)
deriving Repr, DecidableEq

inductive ISAConformanceFault where
  | none
  | divideError
deriving Repr, DecidableEq

structure ISAConformanceObservation where
  authority : ISAConformanceAuthority := .vetoOnly
  registers : Registers Nat
  eflags : Nat
  fsBase : Nat
  x87Stack : List Nat
  x87Control : Nat
  x87Status : Nat
  memory : List ISAConformanceMemoryByte
  writes : List ISAConformanceWordWrite
  control : ISAConformanceControl
  fault : ISAConformanceFault
deriving Repr, DecidableEq

structure ISAConformanceMaskedWord where
  value : Nat
  mask : Nat
deriving Repr, DecidableEq

structure ISAConformanceMaskedByte where
  address : Nat
  value : Nat
  mask : Nat
deriving Repr, DecidableEq

structure ISAConformanceExpectation where
  registers : Registers (Option ISAConformanceMaskedWord) := {
    eax := none
    ebx := none
    ecx := none
    edx := none
    esi := none
    edi := none
    ebp := none
    esp := none
  }
  eflags : Option ISAConformanceMaskedWord := none
  fsBase : Option Nat := none
  x87Stack : List (Option ISAConformanceMaskedWord) := List.replicate 8 none
  x87Control : Option ISAConformanceMaskedWord := none
  x87Status : Option ISAConformanceMaskedWord := none
  memory : List ISAConformanceMaskedByte := []
  writes : Option (List ISAConformanceWordWrite) := none
  control : Option ISAConformanceControl := none
  fault : Option ISAConformanceFault := none
deriving Repr, DecidableEq

inductive ISAConformanceRunResult where
  | observed (observation : ISAConformanceObservation)
  | modeledFault (fault : ISAConformanceFault)
  | unsupported (phase detail : String)
  | internalError (detail : String)
deriving Repr, DecidableEq

def ISAConformanceObservation.authorizesProof
    (_ : ISAConformanceObservation) : Bool := false

theorem ISAConformanceObservation.never_authorizes_proof
    (observation : ISAConformanceObservation) :
    observation.authorizesProof = false := rfl

def ISAConformanceMaskedWord.checked
    (bits : Nat) (expected : ISAConformanceMaskedWord) : Bool :=
  expected.value < 2 ^ bits && expected.mask < 2 ^ bits

def ISAConformanceMaskedWord.matches
    (expected : ISAConformanceMaskedWord) (observed : Nat) : Bool :=
  (observed &&& expected.mask) == (expected.value &&& expected.mask)

def optionalMaskedWordMatches
    (expected : Option ISAConformanceMaskedWord) (observed : Nat) : Bool :=
  expected.all (·.matches observed)

def ISAConformanceMaskedByte.checked
    (expected : ISAConformanceMaskedByte) : Bool :=
  expected.address < 2 ^ 32 && expected.value < 256 && expected.mask < 256

def ISAConformanceMaskedByte.matches
    (expected : ISAConformanceMaskedByte)
    (observed : List ISAConformanceMemoryByte) : Bool :=
  match observed.find? (fun byte => byte.address == expected.address) with
  | none => false
  | some byte =>
      (byte.value &&& expected.mask) == (expected.value &&& expected.mask)

def ISAConformanceExpectation.checked
    (expected : ISAConformanceExpectation) : Bool :=
  [expected.registers.eax, expected.registers.ebx, expected.registers.ecx,
    expected.registers.edx, expected.registers.esi, expected.registers.edi,
    expected.registers.ebp, expected.registers.esp].all fun value =>
      value.all (ISAConformanceMaskedWord.checked 32) &&
  expected.eflags.all (ISAConformanceMaskedWord.checked 32) &&
  expected.fsBase.all (· < 2 ^ 32) &&
  expected.x87Stack.length == 8 &&
  expected.x87Stack.all fun value =>
    value.all (ISAConformanceMaskedWord.checked 80) &&
  expected.x87Control.all (ISAConformanceMaskedWord.checked 16) &&
  expected.x87Status.all (ISAConformanceMaskedWord.checked 16) &&
  expected.memory.all ISAConformanceMaskedByte.checked &&
  decide (expected.memory.map (fun byte => byte.address)).Nodup &&
  expected.writes.all fun writes =>
    writes.all (fun write => write.address < 2 ^ 32 && write.value < 2 ^ 32)

def ISAConformanceExpectation.matches
    (expected : ISAConformanceExpectation)
    (observed : ISAConformanceObservation) : Bool :=
  expected.checked &&
  optionalMaskedWordMatches expected.registers.eax observed.registers.eax &&
  optionalMaskedWordMatches expected.registers.ebx observed.registers.ebx &&
  optionalMaskedWordMatches expected.registers.ecx observed.registers.ecx &&
  optionalMaskedWordMatches expected.registers.edx observed.registers.edx &&
  optionalMaskedWordMatches expected.registers.esi observed.registers.esi &&
  optionalMaskedWordMatches expected.registers.edi observed.registers.edi &&
  optionalMaskedWordMatches expected.registers.ebp observed.registers.ebp &&
  optionalMaskedWordMatches expected.registers.esp observed.registers.esp &&
  expected.eflags.all (·.matches observed.eflags) &&
  expected.fsBase.all (· == observed.fsBase) &&
  observed.x87Stack.length == expected.x87Stack.length &&
  (expected.x87Stack.zip observed.x87Stack).all fun values =>
    optionalMaskedWordMatches values.1 values.2 &&
  expected.x87Control.all (·.matches observed.x87Control) &&
  expected.x87Status.all (·.matches observed.x87Status) &&
  expected.memory.all (·.matches observed.memory) &&
  expected.writes.all (· == observed.writes) &&
  expected.control.all (· == observed.control) &&
  expected.fault.all (· == observed.fault)

def ISAConformanceInput.checked (input : ISAConformanceInput) : Bool :=
  !input.bytes.isEmpty && input.bytes.length <= 15 &&
    input.bytes.all (fun byte => byte < 256) &&
    input.pc < 2 ^ 32 && input.imageBase < 2 ^ 32 &&
    input.eflags < 2 ^ 32 && input.fsBase < 2 ^ 32 &&
    (input.registers.eax < 2 ^ 32) &&
    (input.registers.ebx < 2 ^ 32) &&
    (input.registers.ecx < 2 ^ 32) &&
    (input.registers.edx < 2 ^ 32) &&
    (input.registers.esi < 2 ^ 32) &&
    (input.registers.edi < 2 ^ 32) &&
    (input.registers.ebp < 2 ^ 32) &&
    (input.registers.esp < 2 ^ 32) &&
    input.memory.all (fun byte => byte.address < 2 ^ 32 && byte.value < 256) &&
    decide (input.memory.map (fun byte => byte.address)).Nodup &&
    input.undefinedDefault < 2 ^ 32 &&
    input.undefinedValues.all (fun value => value < 2 ^ 32) &&
    input.x87Stack.length == 8 &&
    input.x87Stack.all (fun value => value < 2 ^ 80) &&
    input.x87Control < 2 ^ 16 && input.x87Status < 2 ^ 16 &&
    input.observeMemory.all (fun address => address < 2 ^ 32) &&
    decide input.observeMemory.Nodup

def ISAConformanceInput.memoryFunction
    (input : ISAConformanceInput) : Memory := fun address =>
  match input.memory.find? (fun byte => byte.address == address.toNat) with
  | some byte => BitVec.ofNat 8 byte.value
  | none => BitVec.ofNat 8 0

def ISAConformanceInput.machineState
    (input : ISAConformanceInput) : MachineState := {
  registers := {
    eax := BitVec.ofNat 32 input.registers.eax
    ebx := BitVec.ofNat 32 input.registers.ebx
    ecx := BitVec.ofNat 32 input.registers.ecx
    edx := BitVec.ofNat 32 input.registers.edx
    esi := BitVec.ofNat 32 input.registers.esi
    edi := BitVec.ofNat 32 input.registers.edi
    ebp := BitVec.ofNat 32 input.registers.ebp
    esp := BitVec.ofNat 32 input.registers.esp
  }
  memory := input.memoryFunction
  undefinedValue := fun slot =>
    let value := if input.undefinedStartSlot <= slot then
      input.undefinedValues.getD (slot - input.undefinedStartSlot)
        input.undefinedDefault
    else input.undefinedDefault
    BitVec.ofNat 32 value
  x87 := {
    stack := fun index => BitVec.ofNat 80 (input.x87Stack.getD index 0)
    control := BitVec.ofNat 16 input.x87Control
    status := BitVec.ofNat 16 input.x87Status
  }
  eflags := BitVec.ofNat 32 input.eflags
  fsBase := BitVec.ofNat 32 input.fsBase
}

def ISAConformanceInput.syntheticPE
    (input : ISAConformanceInput) : PE32 := {
  bytes := ByteTree.ofBytes input.bytes
  peOffset := 0
  entrypointRva := input.pc
  imageBase := input.imageBase
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := input.bytes.length
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def concreteOutcomeToISAConformanceControl :
    ConcreteOutcome -> ISAConformanceControl
  | .returned target => .returned target.toNat
  | .jump targetRva => .jump targetRva
  | .branch condition trueTargetRva falseTargetRva =>
      .branch condition trueTargetRva falseTargetRva
  | .call targetRva returnRva returnAddress =>
      .call targetRva returnRva returnAddress
  | .externalCall imported arguments returnRva =>
      .externalCall imported (arguments.map BitVec.toNat) returnRva
  | .externalJump imported arguments =>
      .externalJump imported (arguments.map BitVec.toNat)
  | .bulkCopy destination source count direction continuationRva =>
      .bulkCopy destination.toNat source.toNat count.toNat direction continuationRva
  | .indirectCall target continuationRva returnAddress =>
      .indirectCall target.toNat continuationRva returnAddress
  | .indirectJump target => .indirectJump target.toNat
  | .checkedContinue valid continuationRva =>
      .checkedContinue valid continuationRva
  | .atomicCompareExchange address expected replacement continuationRva =>
      .atomicCompareExchange address.toNat expected.toNat replacement.toNat
        continuationRva

def ISAConformanceInput.run
    (input : ISAConformanceInput) : ISAConformanceRunResult :=
  if !input.checked then
    .unsupported "input" "input failed finite-state validation"
  else match decodeInstructionExact input.bytes with
  | none => .unsupported "decode" "decodeInstructionExact rejected the bytes"
  | some decoded =>
    match executeInstruction input.syntheticPE [] input.pc
        input.undefinedStartSlot decoded initialSymbolic with
    | none => .unsupported "execute" "executeInstruction rejected the decoded form"
    | some result =>
      let behavior := match result with
        | .next behavior => behavior
        | .stop behavior => behavior
      let concrete := behavior.eval input.machineState
      let control := match result, concrete.outcome with
        | .next _, _ =>
            some (ISAConformanceControl.next (input.pc + decoded.size))
        | .stop _, some outcome =>
            some (concreteOutcomeToISAConformanceControl outcome)
        | .stop _, none => none
      let fault := match concrete.outcome with
        | some (.checkedContinue false _) => ISAConformanceFault.divideError
        | _ => ISAConformanceFault.none
      if fault != .none then .modeledFault fault
      else match control with
      | none =>
          .internalError "stopped symbolic behavior produced no concrete outcome"
      | some control => .observed {
        registers := {
          eax := concrete.registers.eax.toNat
          ebx := concrete.registers.ebx.toNat
          ecx := concrete.registers.ecx.toNat
          edx := concrete.registers.edx.toNat
          esi := concrete.registers.esi.toNat
          edi := concrete.registers.edi.toNat
          ebp := concrete.registers.ebp.toNat
          esp := concrete.registers.esp.toNat
        }
        eflags := concrete.eflags.toNat
        fsBase := input.fsBase
        x87Stack := concrete.x87.stack.map BitVec.toNat
        x87Control := concrete.x87.control.toNat
        x87Status := concrete.x87.status.toNat
        memory := input.observeMemory.map fun address => {
          address
          value := (concrete.memory (BitVec.ofNat 32 address)).toNat
        }
        writes := behavior.writes.map fun write => {
          address := (write.1.eval input.machineState).toNat
          value := (write.2.eval input.machineState).toNat
        }
        control
        fault
      }

def ISAConformanceInput.matches
    (input : ISAConformanceInput)
    (expected : ISAConformanceExpectation) : Bool :=
  match input.run with
  | .observed observation => expected.matches observation
  | .modeledFault fault => expected.fault == some fault
  | .unsupported _ _ | .internalError _ => false

end StageA.Formal
