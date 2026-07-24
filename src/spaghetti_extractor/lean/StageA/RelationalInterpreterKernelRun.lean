import StageA.RelationalInterpreterKernelIndirect
import StageA.RelationalInterpreterKernelStep
import StageA.RelationalInterpreterNativeWorld
import StageA.RelationalInterpreterKernelInvokeNative

namespace StageA.Relational.InterpreterKernelRun

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelStep
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SymbolicSoundness

/-!
Reflective and semantic proof interface for the compiled `runFunction`
operation.  The generated template contains only exact candidate data.  The
operation theorem is obtained by induction over `AbstractRunFunction`, using
separate entry, interpreter-step, completion-dispatch, loop, exit, and epilogue
proofs.  No generated or handwritten certificate field can directly assert
the final operation refinement.
-/

def decodedRunDirectCallTargets (pe : PE32)
    (function : KernelFunction) : List Nat :=
  function.instructions.filterMap fun instruction =>
    match instruction.decode? pe with
    | some decoded =>
        match decoded.instruction with
        | .callRel32 displacement =>
            some (relativeTarget32 (instruction.rva + decoded.size) displacement)
        | _ => none
    | none => none

def relativeX87FrameOffsets (entryRva : Nat)
    (function : KernelFunction) : List Nat :=
  function.x87Frames.map (fun instruction => instruction.rva - entryRva)

def relativeX87CommandOffsets (entryRva : Nat)
    (function : KernelFunction) : List Nat :=
  function.x87Commands.map (fun instruction => instruction.rva - entryRva)

structure RunFunctionMachineTemplate where
  entryRva : Nat
  functionBytes : Bytes
  blocks : List RelativeKernelBlockShape
  loops : List RelativeKernelLoopShape
  directCallOffsets : List Nat
  directCallTargets : List Nat
  indirectCallOffsets : List Nat
  returnOffsets : List Nat
  framePushOffset : Nat
  frameSetupOffset : Nat
  frameTeardownOffsets : List Nat
  frameReturnOffsets : List Nat
  x87FrameOffsets : List Nat
  x87CommandOffsets : List Nat
deriving Repr, DecidableEq

def RunFunctionMachineTemplate.indirectSiteRvas
    (template : RunFunctionMachineTemplate) : List Nat :=
  template.indirectCallOffsets.map (template.entryRva + ·)

def runFunctionLoopShapeChecked (loop : RelativeKernelLoopShape) : Bool :=
  loop.bodyOffsets.head? == some loop.headerOffset &&
    loop.bodyOffsets.reverse.head? == some loop.latchOffset

/-- `runFunction` has one semantic action-loop header.  The reviewed backend
shapes expose either one backedge latch or two exact latches after copying
terminal output state.  No other loop cardinality or mixed-header inventory is
accepted. -/
def runFunctionLoopInventoryChecked
    (loops : List RelativeKernelLoopShape) : Bool :=
  match loops with
  | [loop] => runFunctionLoopShapeChecked loop
  | [first, second] =>
      runFunctionLoopShapeChecked first &&
        runFunctionLoopShapeChecked second &&
        first.headerOffset == second.headerOffset &&
        first.latchOffset != second.latchOffset
  | _ => false

/-- This checker binds all reflected data to the exact candidate PE.  Native
x87 in `runFunction` remains unsupported by this proof profile and therefore
fails closed.  The resolver call is accepted only when the checked callback
inventory covers its exact decoded instruction RVA. -/
def RunFunctionMachineTemplate.checked
    (template : RunFunctionMachineTemplate)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (callbacks : KernelCallbackInventory) (function : KernelFunction) : Bool :=
  function ∈ program.functions && function.role == .runFunction &&
    function.span.start == template.entryRva &&
    function.span.size == template.functionBytes.length &&
    function.bytes == template.functionBytes &&
    spanBytes pe function.span == some template.functionBytes &&
    function.padding.isEmpty && function.checked pe imports &&
    function.blocks.map (relativeBlockShape template.entryRva) == template.blocks &&
    function.loops.map (relativeLoopShape template.entryRva) == template.loops &&
    decodedCallOffsets pe template.entryRva function ==
      template.directCallOffsets ++ template.indirectCallOffsets &&
    decodedIndirectCallOffsets pe template.entryRva function ==
      template.indirectCallOffsets &&
    decodedRunDirectCallTargets pe function == template.directCallTargets &&
    decodedReturnOffsets pe template.entryRva function == template.returnOffsets &&
    function.frame.required &&
    function.frame.pushRva == template.entryRva + template.framePushOffset &&
    function.frame.setupRva == template.entryRva + template.frameSetupOffset &&
    function.frame.teardownRvas.map (fun rva => rva - template.entryRva) ==
      template.frameTeardownOffsets &&
    function.frame.returnRvas.map (fun rva => rva - template.entryRva) ==
      template.frameReturnOffsets &&
    relativeX87FrameOffsets template.entryRva function == template.x87FrameOffsets &&
    relativeX87CommandOffsets template.entryRva function ==
      template.x87CommandOffsets &&
    template.x87FrameOffsets.isEmpty && template.x87CommandOffsets.isEmpty &&
    runFunctionLoopInventoryChecked template.loops &&
    template.directCallOffsets.length == 1 &&
    template.indirectCallOffsets.length == 1 && template.returnOffsets.length == 1 &&
    callbacks.checked program pe imports &&
    template.indirectSiteRvas.all
      (callbackSitesContainRva callbacks.sites) &&
    match program.functionEntry? .interpreterStep with
    | none => false
    | some stepRva => template.directCallTargets == [stepRva]

structure RunFunctionTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  template : RunFunctionMachineTemplate
  callbacks : KernelCallbackInventory
  checked : template.checked program pe imports callbacks function = true
  exactDecodes : ExactDecodeInventory pe function.instructions

/-! ## Canonical native O0 template

The reviewed Stage B backend emits one deliberately simple IA-32 implementation
of `runFunction`.  Absolute RVAs are intentionally absent from this template.
Only the four-byte `call rel32` displacement varies with layout; its target is
checked independently by `RunFunctionMachineTemplate.checked`.
-/

def runFunctionNativeO0Prefix : Bytes := [
  0x55, 0x89, 0xe5, 0x57, 0x56, 0x53, 0x81, 0xec,
  0x2c, 0x01, 0x00, 0x00, 0x83, 0x7d, 0x10, 0x00,
  0x74, 0x06, 0x83, 0x7d, 0x14, 0x00, 0x75, 0x0a,
  0xb8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x24, 0x01,
  0x00, 0x00, 0x8b, 0x55, 0x10, 0x8d, 0x85, 0xec,
  0xfe, 0xff, 0xff, 0x89, 0xd3, 0xba, 0x3f, 0x00,
  0x00, 0x00, 0x89, 0xc7, 0x89, 0xde, 0x89, 0xd1,
  0xf3, 0xa5, 0x8d, 0x85, 0xe0, 0xfe, 0xff, 0xff,
  0x8b, 0x55, 0x0c, 0x89, 0x54, 0x24, 0x0c, 0x8d,
  0x95, 0xec, 0xfe, 0xff, 0xff, 0x89, 0x54, 0x24,
  0x08, 0x8b, 0x55, 0x08, 0x89, 0x54, 0x24, 0x04,
  0x89, 0x04, 0x24, 0xe8
]

def runFunctionNativeO0Suffix : Bytes := [
  0x8b, 0x85, 0xe0, 0xfe, 0xff, 0xff, 0x83, 0xf8,
  0x02, 0x77, 0x0e, 0x8b, 0x85, 0xe4, 0xfe, 0xff,
  0xff, 0x89, 0x45, 0x0c, 0xe9, 0xc8, 0x00, 0x00,
  0x00, 0x8b, 0x85, 0xe0, 0xfe, 0xff, 0xff, 0x83,
  0xf8, 0x04, 0x75, 0x4b, 0x83, 0x7d, 0x08, 0x00,
  0x74, 0x30, 0x8b, 0x45, 0x08, 0x8b, 0x40, 0x14,
  0x85, 0xc0, 0x74, 0x26, 0x8b, 0x45, 0x08, 0x8b,
  0x40, 0x14, 0x8b, 0x95, 0xe8, 0xfe, 0xff, 0xff,
  0x8d, 0x8d, 0xdc, 0xfe, 0xff, 0xff, 0x89, 0x4c,
  0x24, 0x08, 0x89, 0x54, 0x24, 0x04, 0x8b, 0x55,
  0x08, 0x89, 0x14, 0x24, 0xff, 0xd0, 0x85, 0xc0,
  0x74, 0x0a, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xe9,
  0x82, 0x00, 0x00, 0x00, 0x8b, 0x85, 0xdc, 0xfe,
  0xff, 0xff, 0x89, 0x45, 0x0c, 0xeb, 0x72, 0x8b,
  0x85, 0xe0, 0xfe, 0xff, 0xff, 0x83, 0xf8, 0x03,
  0x74, 0x0b, 0x8b, 0x85, 0xe0, 0xfe, 0xff, 0xff,
  0x83, 0xf8, 0x09, 0x75, 0x1f, 0x8b, 0x45, 0x14,
  0x89, 0xc3, 0x8d, 0x85, 0xec, 0xfe, 0xff, 0xff,
  0xba, 0x3f, 0x00, 0x00, 0x00, 0x89, 0xdf, 0x89,
  0xc6, 0x89, 0xd1, 0xf3, 0xa5, 0xb8, 0x00, 0x00,
  0x00, 0x00, 0xeb, 0x42, 0x8b, 0x85, 0xe0, 0xfe,
  0xff, 0xff, 0x83, 0xf8, 0x05, 0x74, 0x2b, 0x8b,
  0x85, 0xe0, 0xfe, 0xff, 0xff, 0x83, 0xf8, 0x06,
  0x74, 0x19, 0x8b, 0x85, 0xe0, 0xfe, 0xff, 0xff,
  0x83, 0xf8, 0x08, 0x75, 0x07, 0xb8, 0x04, 0x00,
  0x00, 0x00, 0xeb, 0x1a, 0xb8, 0x01, 0x00, 0x00,
  0x00, 0xeb, 0x13, 0xb8, 0x03, 0x00, 0x00, 0x00,
  0xeb, 0x0c, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xeb,
  0x05, 0xe9, 0xf4, 0xfe, 0xff, 0xff, 0x81, 0xc4,
  0x2c, 0x01, 0x00, 0x00, 0x5b, 0x5e, 0x5f, 0x5d,
  0x31, 0xd2, 0x31, 0xc9, 0xc3
]

def runFunctionNativeO0BlockOffsets : List Nat :=
  [0, 18, 24, 34, 58, 96, 107, 121, 132, 138, 148, 182, 186,
    196, 207, 218, 229, 260, 271, 282, 293, 300, 307, 314, 321, 326]

def runFunctionNativeO0BlockInstructionCounts : List Nat :=
  [8, 2, 2, 8, 9, 3, 3, 3, 2, 4, 9, 2, 2,
    3, 3, 3, 10, 3, 3, 3, 2, 2, 2, 2, 1, 8]

def runFunctionNativeO0LoopBodyOffsets : List Nat :=
  [58, 96, 107, 121, 132, 138, 148, 182, 186, 196, 207,
    218, 229, 260, 271, 282, 293, 300, 307, 314, 321]

def runFunctionNativeOutputStateO0Prefix : Bytes := [
  0x55, 0x89, 0xe5, 0x57, 0x56, 0x53, 0x81, 0xec,
  0x2c, 0x01, 0x00, 0x00, 0x8b, 0x45, 0x0c, 0x89,
  0x45, 0xe4, 0x83, 0x7d, 0x10, 0x00, 0x74, 0x06,
  0x83, 0x7d, 0x14, 0x00, 0x75, 0x0a, 0xb8, 0x01,
  0x00, 0x00, 0x00, 0xe9, 0x57, 0x01, 0x00, 0x00,
  0x8b, 0x55, 0x10, 0x8d, 0x85, 0xe8, 0xfe, 0xff,
  0xff, 0x89, 0xd3, 0xba, 0x3f, 0x00, 0x00, 0x00,
  0x89, 0xc7, 0x89, 0xde, 0x89, 0xd1, 0xf3, 0xa5,
  0x8d, 0x85, 0xdc, 0xfe, 0xff, 0xff, 0x8b, 0x55,
  0x0c, 0x89, 0x54, 0x24, 0x0c, 0x8d, 0x95, 0xe8,
  0xfe, 0xff, 0xff, 0x89, 0x54, 0x24, 0x08, 0x8b,
  0x55, 0x08, 0x89, 0x54, 0x24, 0x04, 0x89, 0x04,
  0x24, 0xe8
]

def runFunctionNativeOutputStateO0Suffix : Bytes := [
  0x8b, 0x85, 0xdc, 0xfe, 0xff, 0xff, 0x83, 0xf8,
  0x02, 0x77, 0x0e, 0x8b, 0x85, 0xe0, 0xfe, 0xff,
  0xff, 0x89, 0x45, 0x0c, 0xe9, 0xfb, 0x00, 0x00,
  0x00, 0x8b, 0x85, 0xdc, 0xfe, 0xff, 0xff, 0x83,
  0xf8, 0x04, 0x75, 0x72, 0x83, 0x7d, 0x08, 0x00,
  0x74, 0x30, 0x8b, 0x45, 0x08, 0x8b, 0x40, 0x14,
  0x85, 0xc0, 0x74, 0x26, 0x8b, 0x45, 0x08, 0x8b,
  0x40, 0x14, 0x8b, 0x95, 0xe4, 0xfe, 0xff, 0xff,
  0x8d, 0x8d, 0xd8, 0xfe, 0xff, 0xff, 0x89, 0x4c,
  0x24, 0x08, 0x89, 0x54, 0x24, 0x04, 0x8b, 0x55,
  0x08, 0x89, 0x14, 0x24, 0xff, 0xd0, 0x85, 0xc0,
  0x74, 0x2e, 0x8b, 0x45, 0x14, 0x89, 0xc3, 0x8d,
  0x85, 0xe8, 0xfe, 0xff, 0xff, 0xba, 0x3f, 0x00,
  0x00, 0x00, 0x89, 0xdf, 0x89, 0xc6, 0x89, 0xd1,
  0xf3, 0xa5, 0x8b, 0x45, 0x14, 0x8b, 0x55, 0xe4,
  0x89, 0x90, 0xf8, 0x00, 0x00, 0x00, 0xb8, 0x01,
  0x00, 0x00, 0x00, 0xe9, 0x91, 0x00, 0x00, 0x00,
  0x8b, 0x85, 0xd8, 0xfe, 0xff, 0xff, 0x89, 0x45,
  0x0c, 0xe9, 0x44, 0xff, 0xff, 0xff, 0x8b, 0x45,
  0x14, 0x89, 0xc3, 0x8d, 0x85, 0xe8, 0xfe, 0xff,
  0xff, 0xba, 0x3f, 0x00, 0x00, 0x00, 0x89, 0xdf,
  0x89, 0xc6, 0x89, 0xd1, 0xf3, 0xa5, 0x8b, 0x45,
  0x14, 0x8b, 0x55, 0xe4, 0x89, 0x90, 0xf8, 0x00,
  0x00, 0x00, 0x8b, 0x85, 0xdc, 0xfe, 0xff, 0xff,
  0x83, 0xf8, 0x03, 0x74, 0x0b, 0x8b, 0x85, 0xdc,
  0xfe, 0xff, 0xff, 0x83, 0xf8, 0x09, 0x75, 0x07,
  0xb8, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x42, 0x8b,
  0x85, 0xdc, 0xfe, 0xff, 0xff, 0x83, 0xf8, 0x05,
  0x75, 0x07, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xeb,
  0x30, 0x8b, 0x85, 0xdc, 0xfe, 0xff, 0xff, 0x83,
  0xf8, 0x06, 0x75, 0x07, 0xb8, 0x03, 0x00, 0x00,
  0x00, 0xeb, 0x1e, 0x8b, 0x85, 0xdc, 0xfe, 0xff,
  0xff, 0x83, 0xf8, 0x08, 0x75, 0x07, 0xb8, 0x04,
  0x00, 0x00, 0x00, 0xeb, 0x0c, 0xb8, 0x01, 0x00,
  0x00, 0x00, 0xeb, 0x05, 0xe9, 0xc1, 0xfe, 0xff,
  0xff, 0x81, 0xc4, 0x2c, 0x01, 0x00, 0x00, 0x5b,
  0x5e, 0x5f, 0x5d, 0x31, 0xd2, 0x31, 0xc9, 0xc3
]

def runFunctionNativeOutputStateO0BlockOffsets : List Nat :=
  [0, 24, 30, 40, 64, 102, 113, 127, 138, 144, 154, 188, 192,
    238, 252, 299, 310, 317, 328, 335, 346, 353, 364, 371, 378, 383]

def runFunctionNativeOutputStateO0BlockInstructionCounts : List Nat :=
  [10, 2, 2, 8, 9, 3, 3, 3, 2, 4, 9, 2, 13,
    3, 14, 3, 2, 3, 2, 3, 2, 3, 2, 2, 1, 8]

def runFunctionNativeOutputStateO0FirstLoopBodyOffsets : List Nat :=
  [64, 102, 113, 127, 138, 144, 154, 188, 192, 238]

def runFunctionNativeOutputStateO0SecondLoopBodyOffsets : List Nat :=
  [64, 102, 113, 127, 138, 144, 154, 188, 192, 238, 252,
    299, 310, 317, 328, 335, 346, 353, 364, 371, 378]

def RunFunctionMachineTemplate.blockInstructionCounts
    (template : RunFunctionMachineTemplate) : List Nat :=
  template.blocks.map (fun block => block.instructions.length)

/-- Exact legacy canonical-template check.  It fixes all bytes except the rel32
displacement.  The base reflected certificate separately proves the decoded
call target is `interpreterStep`. -/
def runFunctionNativeLegacyO0TemplateChecked
    (template : RunFunctionMachineTemplate) : Bool :=
  template.functionBytes.length == 341 &&
    template.functionBytes.take 92 == runFunctionNativeO0Prefix &&
    template.functionBytes.drop 96 == runFunctionNativeO0Suffix &&
    template.blocks.map (fun block => block.entryOffset) ==
      runFunctionNativeO0BlockOffsets &&
    template.blockInstructionCounts == runFunctionNativeO0BlockInstructionCounts &&
    template.loops == [{
      headerOffset := 58
      latchOffset := 321
      bodyOffsets := runFunctionNativeO0LoopBodyOffsets
    }] &&
    template.directCallOffsets == [91] &&
    template.indirectCallOffsets == [180] &&
    template.returnOffsets == [340] &&
    template.framePushOffset == 0 && template.frameSetupOffset == 1 &&
    template.frameTeardownOffsets == [335] &&
    template.frameReturnOffsets == [340] &&
    template.x87FrameOffsets.isEmpty && template.x87CommandOffsets.isEmpty

/-- Exact output-state-correct canonical template.  Both natural-loop records
are fixed: they share one semantic header and identify the resolver and ordinary
completion backedge latches independently. -/
def runFunctionNativeOutputStateO0TemplateChecked
    (template : RunFunctionMachineTemplate) : Bool :=
  template.functionBytes.length == 398 &&
    template.functionBytes.take 98 == runFunctionNativeOutputStateO0Prefix &&
    template.functionBytes.drop 102 == runFunctionNativeOutputStateO0Suffix &&
    template.blocks.map (fun block => block.entryOffset) ==
      runFunctionNativeOutputStateO0BlockOffsets &&
    template.blockInstructionCounts ==
      runFunctionNativeOutputStateO0BlockInstructionCounts &&
    template.loops == [{
      headerOffset := 64
      latchOffset := 238
      bodyOffsets := runFunctionNativeOutputStateO0FirstLoopBodyOffsets
    }, {
      headerOffset := 64
      latchOffset := 378
      bodyOffsets := runFunctionNativeOutputStateO0SecondLoopBodyOffsets
    }] &&
    template.directCallOffsets == [97] &&
    template.indirectCallOffsets == [186] &&
    template.returnOffsets == [397] &&
    template.framePushOffset == 0 && template.frameSetupOffset == 1 &&
    template.frameTeardownOffsets == [392] &&
    template.frameReturnOffsets == [397] &&
    template.x87FrameOffsets.isEmpty && template.x87CommandOffsets.isEmpty

/-- Public exact-template check for the finite reviewed native profile set. -/
def runFunctionNativeO0TemplateChecked
    (template : RunFunctionMachineTemplate) : Bool :=
  runFunctionNativeLegacyO0TemplateChecked template ||
    runFunctionNativeOutputStateO0TemplateChecked template

def runFunctionNativeUsesOutputStateLayout
    (template : RunFunctionMachineTemplate) : Bool :=
  runFunctionNativeOutputStateO0TemplateChecked template

def runFunctionNativeResolverCallOffset
    (template : RunFunctionMachineTemplate) : Nat :=
  if runFunctionNativeUsesOutputStateLayout template then 186 else 180

structure RunFunctionNativeTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  reflected : RunFunctionTemplateCertificate program pe imports function
  nativeChecked : runFunctionNativeO0TemplateChecked reflected.template = true

def callbackTargetRvasAt (callbacks : KernelCallbackInventory) (siteRva : Nat) :
    List Nat :=
  callbacks.sites.filter (fun site => site.instruction.rva == siteRva) |>.flatMap
    (fun site => site.targets.entries.map (fun target => target.entry.rva))

def RunFunctionNativeTemplateCertificate.resolverTargets
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction}
    (certificate : RunFunctionNativeTemplateCertificate program pe imports
      function) : List Nat :=
  callbackTargetRvasAt certificate.reflected.callbacks
    (certificate.reflected.template.entryRva +
      runFunctionNativeResolverCallOffset certificate.reflected.template)

/-! ## Exact native chunks and nested calls -/

/-- A local native chunk has a fixed fuel index and no submitted endpoint or
path.  Both are computed by the exact candidate transition system. -/
structure RunFunctionNativeChunk
    (candidate : ExactNativeWorldProgram) (before : NativeWorldExecution)
    (fuel : Nat) : Prop where
  positive : 0 < fuel

def RunFunctionNativeChunk.result
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    {fuel : Nat} (_chunk : RunFunctionNativeChunk candidate before fuel) :
    NativeWorldExecution × List WorldRelationalObservable :=
  runRelatedSteps candidate.transitionSystem fuel before

def RunFunctionNativeChunk.after
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    {fuel : Nat} (chunk : RunFunctionNativeChunk candidate before fuel) :
    NativeWorldExecution := chunk.result.1

def RunFunctionNativeChunk.observations
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    {fuel : Nat} (chunk : RunFunctionNativeChunk candidate before fuel) :
    List WorldRelationalObservable := chunk.result.2

theorem RunFunctionNativeChunk.path
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    {fuel : Nat} (chunk : RunFunctionNativeChunk candidate before fuel) :
    NonemptyRelatedPath candidate.transitionSystem before chunk.observations
      chunk.after := by
  exact ⟨fuel, chunk.positive, rfl⟩

/-- Runtime context preserved around one nested kernel operation.  The event
prefix and call-frame tail are authoritative state, not diagnostic metadata. -/
structure RunFunctionNativeRuntime where
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld

def RunFunctionNativeRuntime.running (runtime : RunFunctionNativeRuntime)
    (rva : Nat) (state : MachineState) : NativeWorldExecution :=
  .running rva 0 state runtime.calls runtime.eventIndex runtime.events runtime.world

/-- Detailed result of a nested operation.  It starts with one exact hardware
call frame and returns to the checked continuation while preserving the tail. -/
structure RunFunctionNativeNestedResult
    (candidate : ExactNativeWorldProgram) (runtime : RunFunctionNativeRuntime)
    (continuationRva : Nat) (returnAddress : Word) (entryRva : Nat)
    (before after : MachineState) (emitted : List NativeExternalEvent) where
  afterWorld : RelationalWorld
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem
    (.running entryRva 0 before
      ({ continuationRva, returnAddress } :: runtime.calls)
      runtime.eventIndex runtime.events runtime.world)
    observations
    (.running continuationRva 0 after runtime.calls
      (runtime.eventIndex + emitted.length) (runtime.events ++ emitted) afterWorld)

def RunFunctionNativeNestedDispatches
    (candidate : ExactNativeWorldProgram) (runtime : RunFunctionNativeRuntime)
    (continuationRva : Nat) (returnAddress : Word) : KernelDispatchRelation :=
  fun entryRva before after emitted =>
    Nonempty (RunFunctionNativeNestedResult candidate runtime continuationRva
      returnAddress entryRva before after emitted)

/-- The step proof must be reusable below arbitrary already-proved call frames
and event prefixes.  The current standalone Step bridge is a special case; this
universal family is the exact remaining interface needed by the run loop. -/
structure RunFunctionNativeStepOperation
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) : Prop where
  refines : forall runtime continuationRva returnAddress,
    KernelOperationRefinesUsing program abi
      (RunFunctionNativeNestedDispatches candidate runtime continuationRva
        returnAddress) .interpreterStep

def runFunctionNativeReturnAddress (candidate : ExactNativeWorldProgram)
    (template : RunFunctionMachineTemplate) : Word :=
  BitVec.ofNat 32 (candidate.pe.imageBase + template.entryRva + 96)

/-- The canonical prologue has eighteen exact instructions on every valid ABI
entry and stops immediately before the first loop call setup. -/
structure RunFunctionNativeEntryPhase
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (invariant : Nat -> InterpreterMachine -> NativeWorldExecution -> Prop)
    (outerFrame : NativeCallFrame) (sourceRva : Nat)
    (logical : InterpreterMachine) (before : MachineState)
    (world : RelationalWorld) where
  chunk : RunFunctionNativeChunk candidate
    (.running template.entryRva 0 before [outerFrame] 0 [] world) 18
  loopState : MachineState
  atLoop : chunk.after =
    .running (template.entryRva + 58) 0 loopState [outerFrame] 0 [] world
  silent : chunk.observations = []
  invariantHolds : invariant sourceRva logical chunk.after

/-- Nine exact instructions marshal the copied interpreter state, source RVA,
environment, and result pointer before entering `interpreterStep`. -/
structure RunFunctionNativeStepPrelude
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (stepEntryRva : Nat) (loopState : MachineState)
    (runtime : RunFunctionNativeRuntime) where
  chunk : RunFunctionNativeChunk candidate
    (runtime.running (template.entryRva + 58) loopState) 9
  calleeState : MachineState
  atCallee : chunk.after =
    .running stepEntryRva 0 calleeState
      ({ continuationRva := template.entryRva + 96
         returnAddress := runFunctionNativeReturnAddress candidate template } ::
        runtime.calls)
      runtime.eventIndex runtime.events runtime.world
  silent : chunk.observations = []
  requestRelated : abi.requestRelated
    (.interpreterStep records environment sourceRva logical) calleeState

structure RunFunctionNativeStepPhase
    (abi : KernelABIRelation) (candidate : ExactNativeWorldProgram)
    (template : RunFunctionMachineTemplate) (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (loopState : MachineState) (runtime : RunFunctionNativeRuntime) where
  calleeBefore : MachineState
  after : MachineState
  emitted : List NativeExternalEvent
  afterWorld : RelationalWorld
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem
    (runtime.running (template.entryRva + 58) loopState) observations
    (.running (template.entryRva + 96) 0 after runtime.calls
      (runtime.eventIndex + emitted.length) (runtime.events ++ emitted) afterWorld)
  responseRelated : abi.responseRelated
    (.interpreterStep records environment sourceRva logical)
    (.interpreterStep
      (abstractInterpreterStep records environment sourceRva logical)) after emitted
  memoryFrame : MemoryAgreesOutside
    (abi.scratchFootprint
      (.interpreterStep records environment sourceRva logical))
    after.memory calleeBefore.memory

/-- Compose the exact nine-instruction call prelude with the already-proved
nested `interpreterStep` operation.  The callee endpoint, emitted events, and
successor world are obtained from that theorem. -/
theorem RunFunctionNativeStepPrelude.execute
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {sourceRva : Nat} {logical : InterpreterMachine} {stepEntryRva : Nat}
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (stepEntryExact : program.functionEntry? .interpreterStep = some stepEntryRva)
    (operation : RunFunctionNativeStepOperation program abi candidate)
    (prelude : RunFunctionNativeStepPrelude program abi candidate template records
      environment sourceRva logical stepEntryRva loopState runtime) :
    Nonempty (RunFunctionNativeStepPhase abi candidate template records environment
      sourceRva logical loopState runtime) := by
  let request : AbstractKernelRequest :=
    .interpreterStep records environment sourceRva logical
  let response : AbstractKernelResponse :=
    .interpreterStep (abstractInterpreterStep records environment sourceRva logical)
  obtain ⟨entryRva, after, emitted, entryExact, nested, responseRelated,
      memoryFrame⟩ :=
    operation.refines runtime (template.entryRva + 96)
      (runFunctionNativeReturnAddress candidate template) request prelude.calleeState
      rfl prelude.requestRelated response
      (.interpreterStep records environment sourceRva logical)
  have entryRvaExact : entryRva = stepEntryRva := by
    have stepEntryExact' :
        program.functionEntry? KernelOperation.interpreterStep.role =
          some stepEntryRva := by
      simpa [KernelOperation.role] using stepEntryExact
    rw [stepEntryExact'] at entryExact
    exact Option.some.inj entryExact.symm
  subst entryRva
  obtain ⟨nestedResult⟩ := nested
  have preludePath := prelude.chunk.path
  rw [prelude.atCallee, prelude.silent] at preludePath
  exact ⟨{
    calleeBefore := prelude.calleeState
    after := after
    emitted := emitted
    afterWorld := nestedResult.afterWorld
    observations := nestedResult.observations
    path := by simpa using preludePath.trans nestedResult.path
    responseRelated := responseRelated
    memoryFrame := memoryFrame
  }⟩

/-! ## Completion, resolver, and terminal chunks -/

def runFunctionNativeTerminalFuel
    (result : Option MacroResult) (status : CallStatus) : Option Nat :=
  match result with
  | none => if status == .unimplemented then some 23 else none
  | some macroResult =>
      match macroResult.completion, status with
      | .returned _, .ok => some 19
      | .externalJump, .ok => some 22
      | .divideError, .divideError => some 17
      | .memoryFault, .memoryFault => some 20
      | .externalFault, .externalFault => some 23
      | .unimplemented, .unimplemented => some 23
      | _, _ => none

structure RunFunctionNativeDirectContinuationExecution
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (beforeState : MachineState) (runtime : RunFunctionNativeRuntime) where
  chunk : RunFunctionNativeChunk candidate
    (runtime.running (template.entryRva + 96) beforeState) 7
  nextState : MachineState
  atLoop : chunk.after =
    runtime.running (template.entryRva + 58) nextState
  silent : chunk.observations = []

structure RunFunctionNativeResolverExecution
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (allowedTargets : List Nat) (beforeState : MachineState)
    (runtime : RunFunctionNativeRuntime) where
  targetRva : Nat
  targetMember : targetRva ∈ allowedTargets
  targetState : MachineState
  prelude : RunFunctionNativeChunk candidate
    (runtime.running (template.entryRva + 96) beforeState) 21
  atTarget : prelude.after =
    .running targetRva 0 targetState
      ({ continuationRva := template.entryRva + 182
         returnAddress := BitVec.ofNat 32
           (candidate.pe.imageBase + template.entryRva + 182) } :: runtime.calls)
      runtime.eventIndex runtime.events runtime.world
  preludeSilent : prelude.observations = []
  callbackFuel : Nat
  callbackFuelPositive : 0 < callbackFuel
  callbackState : MachineState
  callback : RunFunctionNativeChunk candidate
    (.running targetRva 0 targetState
      ({ continuationRva := template.entryRva + 182
         returnAddress := BitVec.ofNat 32
           (candidate.pe.imageBase + template.entryRva + 182) } :: runtime.calls)
      runtime.eventIndex runtime.events runtime.world) callbackFuel
  callbackReturned : callback.after =
    runtime.running (template.entryRva + 182) callbackState
  callbackSilent : callback.observations = []
  suffix : RunFunctionNativeChunk candidate
    (runtime.running (template.entryRva + 182) callbackState) 6
  nextState : MachineState
  atLoop : suffix.after =
    runtime.running (template.entryRva + 58) nextState
  suffixSilent : suffix.observations = []

theorem RunFunctionNativeResolverExecution.path
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {allowedTargets : List Nat} {beforeState : MachineState}
    {runtime : RunFunctionNativeRuntime}
    (execution : RunFunctionNativeResolverExecution candidate template
      allowedTargets beforeState runtime) :
    NonemptyRelatedPath candidate.transitionSystem
      (runtime.running (template.entryRva + 96) beforeState) []
      (runtime.running (template.entryRva + 58) execution.nextState) := by
  have preludePath := execution.prelude.path
  rw [execution.atTarget, execution.preludeSilent] at preludePath
  have callbackPath := execution.callback.path
  rw [execution.callbackReturned, execution.callbackSilent] at callbackPath
  have suffixPath := execution.suffix.path
  rw [execution.atLoop, execution.suffixSilent] at suffixPath
  simpa only [List.nil_append] using
    (preludePath.trans callbackPath).trans suffixPath

inductive RunFunctionNativeContinuationLocal
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (allowedTargets : List Nat) (beforeState nextState : MachineState)
    (runtime : RunFunctionNativeRuntime) : Prop
  | direct
      (execution : RunFunctionNativeDirectContinuationExecution candidate template
        beforeState runtime)
      (nextExact : execution.nextState = nextState) :
      RunFunctionNativeContinuationLocal candidate template allowedTargets
        beforeState nextState runtime
  | resolver
      (execution : RunFunctionNativeResolverExecution candidate template
        allowedTargets beforeState runtime)
      (nextExact : execution.nextState = nextState) :
      RunFunctionNativeContinuationLocal candidate template allowedTargets
        beforeState nextState runtime

theorem RunFunctionNativeContinuationLocal.path
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {allowedTargets : List Nat} {beforeState nextState : MachineState}
    {runtime : RunFunctionNativeRuntime}
    (evidence : RunFunctionNativeContinuationLocal candidate template allowedTargets
      beforeState nextState runtime) :
    NonemptyRelatedPath candidate.transitionSystem
      (runtime.running (template.entryRva + 96) beforeState) []
      (runtime.running (template.entryRva + 58) nextState) := by
  cases evidence with
  | direct execution nextExact =>
      have path := execution.chunk.path
      rw [execution.atLoop, execution.silent, nextExact] at path
      exact path
  | resolver execution nextExact =>
      simpa [nextExact] using execution.path

inductive RunFunctionNativeContinuationKind
    (resolveCodeTarget : Word -> Option Nat) :
    Completion -> Nat -> Prop
  | fallthrough (target) :
      RunFunctionNativeContinuationKind resolveCodeTarget
        (.fallthrough target) target
  | jump (target) :
      RunFunctionNativeContinuationKind resolveCodeTarget
        (.jump target) target
  | branch (target) :
      RunFunctionNativeContinuationKind resolveCodeTarget
        (.branch target) target
  | indirect (target : Word) (continuation : Nat)
      (resolved : resolveCodeTarget target = some continuation) :
      RunFunctionNativeContinuationKind resolveCodeTarget
        (.indirectJump target) continuation

theorem RunFunctionNativeContinuationKind.exact
    {resolveCodeTarget : Word -> Option Nat}
    {completion : Completion} {continuation : Nat}
    (kind : RunFunctionNativeContinuationKind resolveCodeTarget
      completion continuation) :
    completionContinuation? resolveCodeTarget completion = some continuation := by
  cases kind <;> simp [completionContinuation?, *]

structure RunFunctionNativeContinuationPhase
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (invariant : Nat -> InterpreterMachine -> NativeWorldExecution -> Prop)
    (allowedTargets : List Nat) (resolveCodeTarget : Word -> Option Nat)
    (result : MacroResult) (continuation : Nat) (beforeState : MachineState)
    (runtime : RunFunctionNativeRuntime) where
  nextState : MachineState
  kind : RunFunctionNativeContinuationKind resolveCodeTarget
    result.completion continuation
  localEvidence : RunFunctionNativeContinuationLocal candidate template allowedTargets
    beforeState nextState runtime
  invariantHolds : invariant continuation result.state
    (runtime.running (template.entryRva + 58) nextState)

structure RunFunctionNativeTerminalPhase
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (result : Option MacroResult) (status : CallStatus)
    (beforeState : MachineState) (runtime : RunFunctionNativeRuntime) where
  fuel : Nat
  fuelExact : runFunctionNativeTerminalFuel result status = some fuel
  chunk : RunFunctionNativeChunk candidate
    (runtime.running (template.entryRva + 96) beforeState) fuel
  epilogueState : MachineState
  atEpilogue : chunk.after =
    runtime.running (template.entryRva + 326) epilogueState
  silent : chunk.observations = []

structure RunFunctionNativeEpiloguePhase
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (abi : KernelABIRelation) (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState) (outerFrame : NativeCallFrame)
    (world : RelationalWorld) (afterLoop : NativeWorldExecution) where
  chunk : RunFunctionNativeChunk candidate afterLoop 8
  after : MachineState
  nativeEvents : List NativeExternalEvent
  afterWorld : RelationalWorld
  atCaller : chunk.after =
    .running outerFrame.continuationRva 0 after [] nativeEvents.length
      nativeEvents afterWorld
  silent : chunk.observations = []
  responseRelated : abi.responseRelated
    (.runFunction records environment resolveCodeTarget sourceRva logical)
    (.call result) after nativeEvents
  memoryFrame : MemoryAgreesOutside
    (abi.scratchFootprint
      (.runFunction records environment resolveCodeTarget sourceRva logical))
    after.memory before.memory

def RunFunctionNativeStepPhase.runtimeAfter
    {abi : KernelABIRelation} {candidate : ExactNativeWorldProgram}
    {template : RunFunctionMachineTemplate} {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {sourceRva : Nat} {logical : InterpreterMachine}
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (phase : RunFunctionNativeStepPhase abi candidate template records environment
      sourceRva logical loopState runtime) : RunFunctionNativeRuntime := {
  calls := runtime.calls
  eventIndex := runtime.eventIndex + phase.emitted.length
  events := runtime.events ++ phase.emitted
  world := phase.afterWorld
}

structure RunFunctionNativeLoopResult
    (candidate : ExactNativeWorldProgram) (before : NativeWorldExecution) where
  afterLoop : NativeWorldExecution
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem before observations afterLoop

/-- Universal local laws for the canonical template.  Every ordinary path is
an exact computed chunk.  The only non-fixed computation is one checked finite
resolver target, isolated by `RunFunctionNativeResolverExecution`. -/
structure RunFunctionNativeLocalSemantics
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (records : List ProgramRecord) (stepEntryRva : Nat)
    (allowedResolverTargets : List Nat) where
  invariant : Nat -> InterpreterMachine -> NativeWorldExecution -> Prop
  stepOperation : RunFunctionNativeStepOperation program abi candidate
  stepPrelude : forall environment sourceRva logical loopState runtime,
    invariant sourceRva logical
      (runtime.running (template.entryRva + 58) loopState) ->
    Nonempty (RunFunctionNativeStepPrelude program abi candidate template records
      environment sourceRva logical stepEntryRva loopState runtime)
  unavailableExit : forall environment sourceRva logical loopState runtime
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime),
    abstractInterpreterStep records environment sourceRva logical = none ->
    Nonempty (RunFunctionNativeTerminalPhase candidate template none .unimplemented
      stepPhase.after stepPhase.runtimeAfter)
  terminalExit : forall environment sourceRva logical loopState runtime result status
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime),
    abstractInterpreterStep records environment sourceRva logical = some result ->
    completionCallStatus? result.completion = some status ->
    Nonempty (RunFunctionNativeTerminalPhase candidate template (some result) status
      stepPhase.after stepPhase.runtimeAfter)
  continuation : forall environment resolveCodeTarget sourceRva logical loopState
      runtime result continuationRva
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime),
    abstractInterpreterStep records environment sourceRva logical = some result ->
    completionContinuation? resolveCodeTarget result.completion =
      some continuationRva ->
    Nonempty (RunFunctionNativeContinuationPhase candidate template invariant
      allowedResolverTargets resolveCodeTarget result continuationRva
      stepPhase.after stepPhase.runtimeAfter)

theorem RunFunctionNativeLocalSemantics.execute
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {records : List ProgramRecord} {stepEntryRva : Nat}
    {allowedResolverTargets : List Nat}
    (stepEntryExact : program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeLocalSemantics program abi candidate template
      records stepEntryRva allowedResolverTargets)
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result)
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (invariantHolds : semantics.invariant sourceRva logical
      (runtime.running (template.entryRva + 58) loopState)) :
    Nonempty (RunFunctionNativeLoopResult candidate
      (runtime.running (template.entryRva + 58) loopState)) := by
  induction derivation generalizing loopState runtime with
  | unavailable sourceRva logical unavailable =>
      obtain ⟨prelude⟩ := semantics.stepPrelude environment sourceRva logical
        loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ := prelude.execute stepEntryExact semantics.stepOperation
      obtain ⟨terminal⟩ := semantics.unavailableExit environment sourceRva logical
        loopState runtime stepPhase unavailable
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        afterLoop := stepPhase.runtimeAfter.running (template.entryRva + 326)
          terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
      }⟩
  | terminal sourceRva logical result status stepResult terminalStatus =>
      obtain ⟨prelude⟩ := semantics.stepPrelude environment sourceRva logical
        loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ := prelude.execute stepEntryExact semantics.stepOperation
      obtain ⟨terminal⟩ := semantics.terminalExit environment sourceRva logical
        loopState runtime result status stepPhase stepResult terminalStatus
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        afterLoop := stepPhase.runtimeAfter.running (template.entryRva + 326)
          terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
      }⟩
  | next sourceRva logical result continuation final stepResult nextTarget tail
      induction =>
      obtain ⟨prelude⟩ := semantics.stepPrelude environment sourceRva logical
        loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ := prelude.execute stepEntryExact semantics.stepOperation
      obtain ⟨continuationPhase⟩ := semantics.continuation environment
        resolveCodeTarget sourceRva logical loopState runtime result continuation
        stepPhase stepResult nextTarget
      have continuationPath := continuationPhase.localEvidence.path
      obtain ⟨tailResult⟩ := induction continuationPhase.invariantHolds
      exact ⟨{
        afterLoop := tailResult.afterLoop
        observations := stepPhase.observations ++ tailResult.observations
        path := by
          simpa only [List.append_assoc, List.append_nil] using
            stepPhase.path.trans (continuationPath.trans tailResult.path)
      }⟩

/-! ## Result-indexed local execution

`RunFunctionNativeLocalSemantics.execute` predates the concrete operation-result
layer and intentionally returns only an exact path.  The compatible enrichment
below retains a predicate about the semantic `CallResult` at the exact terminal
state.  The predicate is supplied once as part of the local semantic authority;
neither the terminal state nor the result can be selected by the caller of the
execution theorem.

For a concrete ABI, instantiate `resultEncoding` with
`CallResultEncodingResidual abi sourceRva`.  This keeps the instruction-level
terminal proof independent of the later cdecl response/environment certificate.
-/

/-- Result-indexed facts established by the exact terminal dispatch.  The base
semantics remains available unchanged to existing callers. -/
structure RunFunctionNativeResultIndexedLocalSemantics
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (records : List ProgramRecord) (stepEntryRva : Nat)
    (allowedResolverTargets : List Nat)
    (resultEncoding : CallResult -> MachineState -> Prop) where
  base : RunFunctionNativeLocalSemantics program abi candidate template records
    stepEntryRva allowedResolverTargets
  unavailableEncoding : forall environment sourceRva logical loopState runtime
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime)
      (unavailable :
        abstractInterpreterStep records environment sourceRva logical = none)
      (terminal : RunFunctionNativeTerminalPhase candidate template none
        .unimplemented stepPhase.after stepPhase.runtimeAfter),
    resultEncoding { status := .unimplemented, state := logical }
      terminal.epilogueState
  terminalEncoding : forall environment sourceRva logical loopState runtime
      macroResult status
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime)
      (stepResult :
        abstractInterpreterStep records environment sourceRva logical =
          some macroResult)
      (terminalStatus :
        completionCallStatus? macroResult.completion = some status)
      (terminal : RunFunctionNativeTerminalPhase candidate template
        (some macroResult) status stepPhase.after stepPhase.runtimeAfter),
    resultEncoding { status := status, state := macroResult.state }
      terminal.epilogueState

/-- Exact terminating Run path together with result evidence at its computed
epilogue-entry state. -/
structure RunFunctionNativeResultIndexedLoopResult
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (before : NativeWorldExecution)
    (resultEncoding : CallResult -> MachineState -> Prop)
    (result : CallResult) where
  terminalRuntime : RunFunctionNativeRuntime
  terminalState : MachineState
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem before observations
    (terminalRuntime.running (template.entryRva + 326) terminalState)
  encoding : resultEncoding result terminalState

def RunFunctionNativeResultIndexedLoopResult.toLoopResult
    (result :
      RunFunctionNativeResultIndexedLoopResult candidate template before
        resultEncoding semanticResult) :
    RunFunctionNativeLoopResult candidate before := {
  afterLoop := result.terminalRuntime.running
    (template.entryRva + 326) result.terminalState
  observations := result.observations
  path := result.path
}

/-- Execute the native Run loop while retaining the terminal result encoding.
The proof follows the abstract derivation, so the final result is fixed by
`AbstractRunFunction`; recursive continuations merely compose exact paths. -/
theorem RunFunctionNativeResultIndexedLocalSemantics.execute
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {records : List ProgramRecord} {stepEntryRva : Nat}
    {allowedResolverTargets : List Nat}
    {resultEncoding : CallResult -> MachineState -> Prop}
    (stepEntryExact : program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeResultIndexedLocalSemantics program abi
      candidate template records stepEntryRva allowedResolverTargets
      resultEncoding)
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result)
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (invariantHolds : semantics.base.invariant sourceRva logical
      (runtime.running (template.entryRva + 58) loopState)) :
    Nonempty (RunFunctionNativeResultIndexedLoopResult candidate template
      (runtime.running (template.entryRva + 58) loopState)
      resultEncoding result) := by
  induction derivation generalizing loopState runtime with
  | unavailable sourceRva logical unavailable =>
      obtain ⟨prelude⟩ := semantics.base.stepPrelude environment sourceRva
        logical loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ :=
        prelude.execute stepEntryExact semantics.base.stepOperation
      obtain ⟨terminal⟩ := semantics.base.unavailableExit environment sourceRva
        logical loopState runtime stepPhase unavailable
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        terminalRuntime := stepPhase.runtimeAfter
        terminalState := terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
        encoding := semantics.unavailableEncoding environment sourceRva logical
          loopState runtime stepPhase unavailable terminal
      }⟩
  | terminal sourceRva logical macroResult status stepResult terminalStatus =>
      obtain ⟨prelude⟩ := semantics.base.stepPrelude environment sourceRva
        logical loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ :=
        prelude.execute stepEntryExact semantics.base.stepOperation
      obtain ⟨terminal⟩ := semantics.base.terminalExit environment sourceRva
        logical loopState runtime macroResult status stepPhase stepResult
        terminalStatus
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        terminalRuntime := stepPhase.runtimeAfter
        terminalState := terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
        encoding := semantics.terminalEncoding environment sourceRva logical
          loopState runtime macroResult status stepPhase stepResult
          terminalStatus terminal
      }⟩
  | next sourceRva logical macroResult continuation final stepResult nextTarget
      tail induction =>
      obtain ⟨prelude⟩ := semantics.base.stepPrelude environment sourceRva
        logical loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ :=
        prelude.execute stepEntryExact semantics.base.stepOperation
      obtain ⟨continuationPhase⟩ := semantics.base.continuation environment
        resolveCodeTarget sourceRva logical loopState runtime macroResult
        continuation stepPhase stepResult nextTarget
      have continuationPath := continuationPhase.localEvidence.path
      obtain ⟨tailResult⟩ := induction continuationPhase.invariantHolds
      exact ⟨{
        terminalRuntime := tailResult.terminalRuntime
        terminalState := tailResult.terminalState
        observations := stepPhase.observations ++ tailResult.observations
        path := by
          simpa only [List.append_assoc, List.append_nil] using
            stepPhase.path.trans (continuationPath.trans tailResult.path)
        encoding := tailResult.encoding
      }⟩

def runFunctionNativeOuterFrame (continuationRva : Nat)
    (returnAddress : Word) : NativeCallFrame := {
  continuationRva
  returnAddress
}

/-- Final native operation certificate.  It contains static identity, local
phase laws, and ABI endpoint laws, but no whole-function execution field. -/
structure RunFunctionNativeMachineCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) (outerContinuationRva : Nat)
    (outerReturnAddress : Word) where
  function : KernelFunction
  reflected : RunFunctionNativeTemplateCertificate program candidate.pe
    candidate.imports function
  entryRvaExact : program.functionEntry? .runFunction = some function.span.start
  templateEntryExact : reflected.reflected.template.entryRva = function.span.start
  stepEntryRva : Nat
  stepEntryExact : program.functionEntry? .interpreterStep = some stepEntryRva
  establishRecords : forall records environment resolveCodeTarget sourceRva logical
      before,
    abi.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical) before ->
      records = semanticRecords
  semantics : forall environment resolveCodeTarget,
    RunFunctionNativeLocalSemantics program abi candidate
      reflected.reflected.template semanticRecords stepEntryRva
      reflected.resolverTargets
  entry : forall environment resolveCodeTarget sourceRva logical before,
    abi.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
      before ->
    RunFunctionNativeEntryPhase candidate reflected.reflected.template
      (semantics environment resolveCodeTarget).invariant
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
      sourceRva logical before world
  epilogue : forall environment resolveCodeTarget sourceRva logical result before
      (requestRelated : abi.requestRelated
        (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
        before)
      (derivation : AbstractRunFunction semanticRecords environment resolveCodeTarget
        sourceRva logical result)
      (entryPhase : RunFunctionNativeEntryPhase candidate
        reflected.reflected.template
        (semantics environment resolveCodeTarget).invariant
        (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
        sourceRva logical before world)
      (afterLoop : NativeWorldExecution),
    RunFunctionNativeEpiloguePhase candidate reflected.reflected.template abi
      semanticRecords environment resolveCodeTarget sourceRva logical result before
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress) world
      afterLoop

theorem RunFunctionNativeMachineCertificate.refines
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {semanticRecords : List ProgramRecord} {candidate : ExactNativeWorldProgram}
    {world : RelationalWorld} {outerContinuationRva : Nat}
    {outerReturnAddress : Word}
    (certificate : RunFunctionNativeMachineCertificate program abi semanticRecords
      candidate world outerContinuationRva outerReturnAddress) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world outerContinuationRva
        outerReturnAddress) .runFunction := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      have recordsExact := certificate.establishRecords records environment
        resolveCodeTarget sourceRva logical before requestRelated
      subst records
      cases transition with
      | runFunction _ _ _ _ _ result derivation =>
          let semantics := certificate.semantics environment resolveCodeTarget
          let entryPhase := certificate.entry environment resolveCodeTarget sourceRva
            logical before requestRelated
          let initialRuntime : RunFunctionNativeRuntime := {
            calls := [runFunctionNativeOuterFrame outerContinuationRva
              outerReturnAddress]
            eventIndex := 0
            events := []
            world := world
          }
          have entryInvariant : semantics.invariant sourceRva logical
              (initialRuntime.running
                (certificate.reflected.reflected.template.entryRva + 58)
                entryPhase.loopState) := by
            have invariant := entryPhase.invariantHolds
            rw [entryPhase.atLoop] at invariant
            simpa [semantics, initialRuntime,
              RunFunctionNativeRuntime.running] using invariant
          obtain ⟨loopResult⟩ := semantics.execute certificate.stepEntryExact
            derivation entryInvariant
          let epilogue := certificate.epilogue environment resolveCodeTarget sourceRva
            logical result before requestRelated derivation entryPhase
            loopResult.afterLoop
          have entryPath := entryPhase.chunk.path
          rw [entryPhase.atLoop, entryPhase.silent] at entryPath
          have loopPath := loopResult.path
          change NonemptyRelatedPath candidate.transitionSystem
            (.running (certificate.reflected.reflected.template.entryRva + 58) 0
              entryPhase.loopState
              [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
              0 [] world) loopResult.observations loopResult.afterLoop at loopPath
          have epiloguePath := epilogue.chunk.path
          rw [epilogue.atCaller, epilogue.silent] at epiloguePath
          have completePath :=
            (entryPath.trans loopPath).trans epiloguePath
          refine ⟨certificate.function.span.start, epilogue.after,
            epilogue.nativeEvents, certificate.entryRvaExact, ?_,
            epilogue.responseRelated, epilogue.memoryFrame⟩
          refine ⟨{
            afterWorld := epilogue.afterWorld
            observations := loopResult.observations
            path := ?_
          }⟩
          rw [← certificate.templateEntryExact]
          simpa only [List.nil_append, List.append_nil] using completePath

#print axioms RunFunctionNativeChunk.path
#print axioms RunFunctionNativeStepPrelude.execute
#print axioms RunFunctionNativeResolverExecution.path
#print axioms RunFunctionNativeContinuationLocal.path
#print axioms RunFunctionNativeLocalSemantics.execute
#print axioms RunFunctionNativeResultIndexedLocalSemantics.execute
#print axioms RunFunctionNativeMachineCertificate.refines

/-- The function prologue establishes the loop invariant after binding the
abstract input state to the candidate's copied local state. -/
structure RunFunctionEntryPhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (invariant : Nat -> InterpreterMachine -> NativeExecution -> Prop)
    (entryRva sourceRva : Nat) (logical : InterpreterMachine)
    (before : MachineState) where
  loopStart : NativeExecution
  path : steps (.running entryRva 0 before [] 0 []) loopStart
  invariantHolds : invariant sourceRva logical loopStart

/-- One exact call of the already specified `interpreterStep` operation.  Its
result index is the definition-level abstract result for this iteration. -/
structure RunFunctionStepPhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (before : NativeExecution) where
  afterStep : NativeExecution
  result : Option MacroResult
  path : steps before afterStep
  resultExact :
    result = abstractInterpreterStep records environment sourceRva logical

/-- Semantic classification of the action-loop continuation.  In particular,
an indirect continuation carries both the exact resolver equation and a member
of the statically checked candidate callback-site inventory. -/
inductive RunFunctionContinuationKind
    (indirectSites : List Nat) (resolveCodeTarget : Word -> Option Nat) :
    Completion -> Nat -> Prop
  | fallthrough (target) :
      RunFunctionContinuationKind indirectSites resolveCodeTarget
        (.fallthrough target) target
  | jump (target) :
      RunFunctionContinuationKind indirectSites resolveCodeTarget
        (.jump target) target
  | branch (target) :
      RunFunctionContinuationKind indirectSites resolveCodeTarget
        (.branch target) target
  | indirect (target : Word) (continuation siteRva : Nat)
      (siteCovered : siteRva ∈ indirectSites)
      (resolved : resolveCodeTarget target = some continuation) :
      RunFunctionContinuationKind indirectSites resolveCodeTarget
        (.indirectJump target) continuation

theorem RunFunctionContinuationKind.exact
    {indirectSites : List Nat} {resolveCodeTarget : Word -> Option Nat}
    {completion : Completion} {continuation : Nat}
    (kind : RunFunctionContinuationKind indirectSites resolveCodeTarget
      completion continuation) :
    completionContinuation? resolveCodeTarget completion = some continuation := by
  cases kind <;> simp [completionContinuation?, *]

structure RunFunctionContinuationPhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (invariant : Nat -> InterpreterMachine -> NativeExecution -> Prop)
    (indirectSites : List Nat) (resolveCodeTarget : Word -> Option Nat)
    (result : MacroResult) (continuation : Nat)
    (before : NativeExecution) where
  nextLoop : NativeExecution
  kind : RunFunctionContinuationKind indirectSites resolveCodeTarget
    result.completion continuation
  path : steps before nextLoop
  invariantHolds : invariant continuation result.state nextLoop

structure RunFunctionExitPhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (before : NativeExecution) where
  afterLoop : NativeExecution
  path : steps before afterLoop

/-- These are the only semantic inhabitants required from the machine-level
symbolic executor.  They are local and reusable: no field states that the
whole operation simulates `AbstractRunFunction`. -/
structure RunFunctionLoopPhases
    (steps : NativeExecution -> NativeExecution -> Prop)
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (indirectSites : List Nat) where
  invariant : Nat -> InterpreterMachine -> NativeExecution -> Prop
  step : forall sourceRva logical before,
    invariant sourceRva logical before ->
      Nonempty (RunFunctionStepPhase steps records environment sourceRva
        logical before)
  unavailableExit : forall sourceRva logical before
      (stepPhase : RunFunctionStepPhase steps records environment sourceRva
        logical before),
    stepPhase.result = none ->
      Nonempty (RunFunctionExitPhase steps stepPhase.afterStep)
  terminalExit : forall sourceRva logical before result status
      (stepPhase : RunFunctionStepPhase steps records environment sourceRva
        logical before),
    stepPhase.result = some result ->
    completionCallStatus? result.completion = some status ->
      Nonempty (RunFunctionExitPhase steps stepPhase.afterStep)
  continuation : forall sourceRva logical before result continuationRva
      (stepPhase : RunFunctionStepPhase steps records environment sourceRva
        logical before),
    stepPhase.result = some result ->
    completionContinuation? resolveCodeTarget result.completion =
      some continuationRva ->
      Nonempty (RunFunctionContinuationPhase steps invariant indirectSites
        resolveCodeTarget result continuationRva stepPhase.afterStep)

structure RunFunctionLoopResult
    (steps : NativeExecution -> NativeExecution -> Prop)
    (before : NativeExecution) where
  afterLoop : NativeExecution
  path : steps before afterLoop

/-- Induction over the authoritative abstract semantics composes only the
phase-local executions above.  This is the semantic core of the operation
proof and prevents generated data from choosing a final postcondition. -/
theorem RunFunctionLoopPhases.execute
    {steps : NativeExecution -> NativeExecution -> Prop}
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {indirectSites : List Nat}
    (execution : ComposableKernelExecution steps dispatches)
    (phases : RunFunctionLoopPhases steps records environment resolveCodeTarget
      indirectSites)
    {sourceRva : Nat} {logical : InterpreterMachine} {result : CallResult}
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result)
    {before : NativeExecution}
    (invariantHolds : phases.invariant sourceRva logical before) :
    Nonempty (RunFunctionLoopResult steps before) := by
  induction derivation generalizing before with
  | unavailable sourceRva logical unavailable =>
      obtain ⟨stepPhase⟩ := phases.step sourceRva logical before invariantHolds
      have resultNone : stepPhase.result = none := by
        rw [stepPhase.resultExact, unavailable]
      obtain ⟨exitPhase⟩ := phases.unavailableExit sourceRva logical before
        stepPhase resultNone
      exact ⟨{
        afterLoop := exitPhase.afterLoop
        path := execution.trans stepPhase.path exitPhase.path
      }⟩
  | terminal sourceRva logical result status stepResult terminalStatus =>
      obtain ⟨stepPhase⟩ := phases.step sourceRva logical before invariantHolds
      have resultSome : stepPhase.result = some result := by
        rw [stepPhase.resultExact, stepResult]
      obtain ⟨exitPhase⟩ := phases.terminalExit sourceRva logical before result
        status stepPhase resultSome terminalStatus
      exact ⟨{
        afterLoop := exitPhase.afterLoop
        path := execution.trans stepPhase.path exitPhase.path
      }⟩
  | next sourceRva logical result continuation final stepResult nextTarget
      tail ih =>
      obtain ⟨stepPhase⟩ := phases.step sourceRva logical before invariantHolds
      have resultSome : stepPhase.result = some result := by
        rw [stepPhase.resultExact, stepResult]
      obtain ⟨continuationPhase⟩ := phases.continuation sourceRva logical before
        result continuation stepPhase resultSome nextTarget
      obtain ⟨tailResult⟩ := ih continuationPhase.invariantHolds
      exact ⟨{
        afterLoop := tailResult.afterLoop
        path := execution.trans stepPhase.path
          (execution.trans continuationPhase.path tailResult.path)
      }⟩

structure RunFunctionEpiloguePhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (abi : KernelABIRelation) (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState) (afterLoop : NativeExecution) where
  after : MachineState
  nativeEvents : List NativeExternalEvent
  path : steps afterLoop (.returned after nativeEvents)
  responseRelated : abi.responseRelated
    (.runFunction records environment resolveCodeTarget sourceRva logical)
    (.call result) after nativeEvents
  memoryFrame : MemoryAgreesOutside
    (abi.scratchFootprint
      (.runFunction records environment resolveCodeTarget sourceRva logical))
    after.memory before.memory

structure RunFunctionEntryInvariant
    (semanticRecords records : List ProgramRecord) : Prop where
  recordsExact : records = semanticRecords

/-- Complete operation proof assembled from reflected bytes and local phases.
There is intentionally no `simulate`, `refines`, or operation-level execution
field in this structure. -/
structure RunFunctionMachineCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord)
    (steps : NativeExecution -> NativeExecution -> Prop)
    (dispatches : KernelDispatchRelation) where
  function : KernelFunction
  reflected : RunFunctionTemplateCertificate program pe imports function
  execution : ComposableKernelExecution steps dispatches
  entryRvaExact : program.functionEntry? .runFunction = some function.span.start
  establishEntry : forall records environment resolveCodeTarget sourceRva logical
      before,
    abi.requestRelated
        (.runFunction records environment resolveCodeTarget sourceRva logical)
        before -> RunFunctionEntryInvariant semanticRecords records
  phases : forall environment resolveCodeTarget,
    RunFunctionLoopPhases steps semanticRecords environment resolveCodeTarget
      reflected.template.indirectSiteRvas
  entry : forall environment resolveCodeTarget sourceRva logical before,
    abi.requestRelated (.runFunction semanticRecords environment resolveCodeTarget
      sourceRva logical) before ->
      RunFunctionEntryPhase steps (phases environment resolveCodeTarget).invariant
        function.span.start sourceRva logical before
  epilogue : forall environment resolveCodeTarget sourceRva logical result before
      (requestRelated : abi.requestRelated
        (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
        before)
      (derivation : AbstractRunFunction semanticRecords environment resolveCodeTarget
        sourceRva logical result)
      (entryPhase : RunFunctionEntryPhase steps
        (phases environment resolveCodeTarget).invariant function.span.start
        sourceRva logical before)
      (loopResult : RunFunctionLoopResult steps entryPhase.loopStart),
    RunFunctionEpiloguePhase steps abi semanticRecords environment
      resolveCodeTarget sourceRva logical result before loopResult.afterLoop

theorem RunFunctionMachineCertificate.refines
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {abi : KernelABIRelation} {semanticRecords : List ProgramRecord}
    {steps : NativeExecution -> NativeExecution -> Prop}
    {dispatches : KernelDispatchRelation}
    (certificate : RunFunctionMachineCertificate program pe imports abi
      semanticRecords steps dispatches) :
    KernelOperationRefinesUsing program abi dispatches .runFunction := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      have entryInvariant := certificate.establishEntry records environment
        resolveCodeTarget sourceRva logical before requestRelated
      have recordsExact := entryInvariant.recordsExact
      subst records
      cases transition with
      | runFunction _ _ _ _ _ result derivation =>
          let phaseSet := certificate.phases environment resolveCodeTarget
          let entryPhase := certificate.entry environment resolveCodeTarget
            sourceRva logical before requestRelated
          obtain ⟨loopResult⟩ := phaseSet.execute certificate.execution derivation
            entryPhase.invariantHolds
          let epilogue := certificate.epilogue environment resolveCodeTarget
            sourceRva logical result before requestRelated derivation entryPhase
            loopResult
          have throughLoop : steps
              (.running certificate.function.span.start 0 before [] 0 [])
              loopResult.afterLoop :=
            certificate.execution.trans entryPhase.path loopResult.path
          have complete : steps
              (.running certificate.function.span.start 0 before [] 0 [])
              (.returned epilogue.after epilogue.nativeEvents) :=
            certificate.execution.trans throughLoop epilogue.path
          exact ⟨certificate.function.span.start, epilogue.after,
            epilogue.nativeEvents, certificate.entryRvaExact,
            certificate.execution.dispatch certificate.function.span.start before
              epilogue.after epilogue.nativeEvents complete,
            epilogue.responseRelated, epilogue.memoryFrame⟩

#print axioms RunFunctionContinuationKind.exact
#print axioms RunFunctionLoopPhases.execute
#print axioms RunFunctionMachineCertificate.refines

end StageA.Relational.InterpreterKernelRun
