import Lean
import StageA.ISAConformance
import StageA.ISAQualification

namespace StageA.Formal

open Lean

private def jsonArray (values : List Json) : Json :=
  .arr values.toArray

private def memoryByteJson (byte : ISAConformanceMemoryByte) : Json :=
  Json.mkObj [
    ("address", toJson byte.address),
    ("value", toJson byte.value)
  ]

private def wordWriteJson (write : ISAConformanceWordWrite) : Json :=
  Json.mkObj [
    ("address", toJson write.address),
    ("value", toJson write.value)
  ]

private def registersJson (registers : Registers Nat) : Json :=
  Json.mkObj [
    ("eax", toJson registers.eax),
    ("ebx", toJson registers.ebx),
    ("ecx", toJson registers.ecx),
    ("edx", toJson registers.edx),
    ("esi", toJson registers.esi),
    ("edi", toJson registers.edi),
    ("ebp", toJson registers.ebp),
    ("esp", toJson registers.esp)
  ]

private def importNameJson : ImportName -> Json
  | .symbol bytes => Json.mkObj [
      ("kind", toJson "symbol"),
      ("bytes", toJson bytes)
    ]
  | .ordinal value => Json.mkObj [
      ("kind", toJson "ordinal"),
      ("value", toJson value)
    ]

private def importJson (imported : PEImport) : Json :=
  Json.mkObj [
    ("dll", toJson imported.dll),
    ("name", importNameJson imported.name),
    ("iat_rva", toJson imported.iatRva)
  ]

private def controlJson : ISAConformanceControl -> Json
  | .next rva => Json.mkObj [
      ("kind", toJson "next"),
      ("rva", toJson rva)
    ]
  | .returned target => Json.mkObj [
      ("kind", toJson "returned"),
      ("target", toJson target)
    ]
  | .jump targetRva => Json.mkObj [
      ("kind", toJson "jump"),
      ("target_rva", toJson targetRva)
    ]
  | .branch condition trueTargetRva falseTargetRva => Json.mkObj [
      ("kind", toJson "branch"),
      ("condition", toJson condition),
      ("true_target_rva", toJson trueTargetRva),
      ("false_target_rva", toJson falseTargetRva)
    ]
  | .call targetRva returnRva returnAddress => Json.mkObj [
      ("kind", toJson "call"),
      ("target_rva", toJson targetRva),
      ("return_rva", toJson returnRva),
      ("return_address", toJson returnAddress)
    ]
  | .externalCall imported arguments returnRva => Json.mkObj [
      ("kind", toJson "external_call"),
      ("import", importJson imported),
      ("arguments", toJson arguments),
      ("return_rva", toJson returnRva)
    ]
  | .externalJump imported arguments => Json.mkObj [
      ("kind", toJson "external_jump"),
      ("import", importJson imported),
      ("arguments", toJson arguments)
    ]
  | .bulkCopy destination source count direction continuationRva => Json.mkObj [
      ("kind", toJson "bulk_copy"),
      ("destination", toJson destination),
      ("source", toJson source),
      ("count", toJson count),
      ("direction", toJson direction),
      ("continuation_rva", toJson continuationRva)
    ]
  | .indirectCall target continuationRva returnAddress => Json.mkObj [
      ("kind", toJson "indirect_call"),
      ("target", toJson target),
      ("continuation_rva", toJson continuationRva),
      ("return_address", toJson returnAddress)
    ]
  | .indirectJump target => Json.mkObj [
      ("kind", toJson "indirect_jump"),
      ("target", toJson target)
    ]
  | .checkedContinue valid continuationRva => Json.mkObj [
      ("kind", toJson "checked_continue"),
      ("valid", toJson valid),
      ("continuation_rva", toJson continuationRva)
    ]
  | .atomicCompareExchange address expected replacement continuationRva =>
      Json.mkObj [
        ("kind", toJson "atomic_compare_exchange"),
        ("address", toJson address),
        ("expected", toJson expected),
        ("replacement", toJson replacement),
        ("continuation_rva", toJson continuationRva)
      ]

private def faultJson : ISAConformanceFault -> Json
  | .none => toJson "none"
  | .divideError => toJson "divide_error"

private def observationJson (observation : ISAConformanceObservation) : Json :=
  Json.mkObj [
    ("registers", registersJson observation.registers),
    ("eflags", toJson observation.eflags),
    ("fs_base", toJson observation.fsBase),
    ("x87_stack", toJson observation.x87Stack),
    ("x87_control", toJson observation.x87Control),
    ("x87_status", toJson observation.x87Status),
    ("memory", jsonArray (observation.memory.map memoryByteJson)),
    ("writes", jsonArray (observation.writes.map wordWriteJson)),
    ("control", controlJson observation.control),
    ("fault", faultJson observation.fault),
    ("proof_authority", toJson observation.authorizesProof)
  ]

private def resultJson : ISAConformanceRunResult -> Json
  | .observed observation => Json.mkObj [
      ("status", toJson "observed"),
      ("observation", observationJson observation)
    ]
  | .modeledFault fault => Json.mkObj [
      ("status", toJson "modeled_fault"),
      ("fault", faultJson fault)
    ]
  | .unsupported phase detail => Json.mkObj [
      ("status", toJson "unsupported"),
      ("phase", toJson phase),
      ("detail", toJson detail)
    ]
  | .internalError detail => Json.mkObj [
      ("status", toJson "internal_error"),
      ("detail", toJson detail)
    ]

/-- Emit one machine-readable evidence row. The result is deliberately
veto-only and is not imported by the Stage A acceptance theorem. -/
def emitISAConformanceCase (caseId : String)
    (input : ISAConformanceInput) : IO Unit :=
  IO.println <| Json.compress <| Json.mkObj [
    ("case_id", toJson caseId),
    ("authority", toJson "veto_only"),
    ("semantic_form", match decodeInstructionExact input.bytes with
      | some decoded => toJson (reprStr decoded.instruction.semanticForm)
      | none => Json.null),
    ("result", resultJson input.run)
  ]

end StageA.Formal
