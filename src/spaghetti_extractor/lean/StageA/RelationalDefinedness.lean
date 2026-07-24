import StageA.Formal

namespace StageA.Relational.Definedness

/-! A certificate kernel for undefined-value noninterference over a finite
dependency graph. Extraction and dependency discovery are untrusted. The
checker validates liveness propagation, observation independence, guarded CFG
closure, return/termination policy, and finite SCC closure. Exact instruction
semantics must separately discharge `StepDependencySound`; no JSON status can
close that semantic boundary. -/

inductive Location where
  | eax | ebx | ecx | edx | esi | edi | ebp | esp
  | cf | zf | sf | of | pf | df
deriving Repr, DecidableEq

inductive SlotPolicy where
  | arbitrary
  | synchronized
deriving Repr, DecidableEq

def SlotPolicy.valuesRelated (policy : SlotPolicy) (left right : Nat) : Prop :=
  match policy with
  | .arbitrary => True
  | .synchronized => left = right

structure DependencySpec where
  locations : List Location
  slot : Bool := false
deriving Repr, DecidableEq

def DependencySpec.independent (spec : DependencySpec)
    (policy : SlotPolicy) (live : List Location) : Bool :=
  (!spec.slot || policy == .synchronized) &&
    !spec.locations.any live.contains

structure WriteSpec where
  target : Location
  dependencies : DependencySpec
deriving Repr, DecidableEq

structure ObservationSpec where
  kind : String
  dependencies : DependencySpec
deriving Repr, DecidableEq

structure EdgeSpec where
  successor : String
  guard : DependencySpec
deriving Repr, DecidableEq

inductive TerminalPolicy where
  | none
  | returnState
  | terminate
deriving Repr, DecidableEq

structure FlowStep where
  id : String
  writes : List WriteSpec
  observations : List ObservationSpec
  edges : List EdgeSpec
  terminal : TerminalPolicy := .none
deriving Repr, DecidableEq

def FlowStep.writeTargets (step : FlowStep) : List Location :=
  step.writes.map (fun write => write.target)

def canonicalLocations : List Location :=
  [.cf, .df, .of, .pf, .sf, .zf,
   .eax, .ebp, .ebx, .ecx, .edi, .edx, .esi, .esp]

def normalizeLocations (locations : List Location) : List Location :=
  canonicalLocations.filter locations.contains

def WriteSpec.dependsOnLive (write : WriteSpec) (policy : SlotPolicy)
    (live : List Location) : Bool :=
  (write.dependencies.slot && policy == .arbitrary) ||
    write.dependencies.locations.any live.contains

def FlowStep.liveAfter (step : FlowStep) (policy : SlotPolicy)
    (live : List Location) : List Location :=
  normalizeLocations
    ((live.filter fun location => !(step.writeTargets.contains location)) ++
    (step.writes.filterMap fun write =>
      if write.dependsOnLive policy live then some write.target else none))

def FlowStep.observationsIndependent (step : FlowStep)
    (policy : SlotPolicy) (live : List Location) : Bool :=
  step.observations.all
    (fun observation => observation.dependencies.independent policy live)

def FlowStep.guardsIndependent (step : FlowStep)
    (policy : SlotPolicy) (live : List Location) : Bool :=
  step.edges.all (fun edge => edge.guard.independent policy live)

def FlowStep.structuralChecked (step : FlowStep) : Bool :=
  !step.id.isEmpty &&
    decide step.writeTargets.Nodup &&
    decide (step.edges.map (fun edge => edge.successor)).Nodup

structure CertifiedNode where
  key : String
  step : FlowStep
  liveIn : List Location
  liveOut : List Location
deriving Repr, DecidableEq

def CertifiedNode.localChecked (node : CertifiedNode) (policy : SlotPolicy) : Bool :=
  !node.key.isEmpty && decide node.liveIn.Nodup && decide node.liveOut.Nodup &&
    node.step.structuralChecked &&
    node.liveOut == node.step.liveAfter policy node.liveIn &&
    node.step.observationsIndependent policy node.liveIn &&
    node.step.guardsIndependent policy node.liveIn &&
    match node.step.terminal with
    | .none => !node.step.edges.isEmpty || node.liveOut.isEmpty
    | .returnState => node.step.edges.isEmpty
    | .terminate => node.step.edges.isEmpty

structure GraphCertificate where
  roots : List String
  nodes : List CertifiedNode
deriving Repr, DecidableEq

def GraphCertificate.find? (certificate : GraphCertificate)
    (key : String) : Option CertifiedNode :=
  certificate.nodes.find? (fun node => node.key == key)

def GraphCertificate.edgeClosed (certificate : GraphCertificate)
    (node : CertifiedNode) (edge : EdgeSpec) : Bool :=
  match certificate.find? edge.successor with
  | some target => target.liveIn == node.liveOut
  | none => node.liveOut.isEmpty

def GraphCertificate.nodeClosed (certificate : GraphCertificate)
    (node : CertifiedNode) : Bool :=
  node.step.edges.all (certificate.edgeClosed node)

def GraphCertificate.checked (certificate : GraphCertificate)
    (policy : SlotPolicy) : Bool :=
  !certificate.roots.isEmpty && !certificate.nodes.isEmpty &&
    decide certificate.roots.Nodup &&
    decide (certificate.nodes.map (fun node => node.key)).Nodup &&
    certificate.roots.all (fun root => (certificate.find? root).isSome) &&
    certificate.nodes.all (fun node =>
      node.localChecked policy && certificate.nodeClosed node)

structure RelevantSite where
  transferId : String
  rva : Nat
  jsonPointer : String
  category : String
deriving Repr, DecidableEq

inductive ProofObligationKind where
  | exactReplayTransfer
  | callFrameNoninterference
  | faultDominance
  | returnContinuationNoninterference
deriving Repr, DecidableEq

structure ProofObligation where
  kind : ProofObligationKind
  transferId : String
  rva : Nat
  jsonPointer : String
  detail : String
deriving Repr, DecidableEq

structure RelatedMachineInputChoice where
  location : Location
  instructionRva : Nat
  instructionBytes : List Nat
deriving Repr, DecidableEq

def Location.x86RegisterCode? : Location -> Option Nat
  | .eax => some 0 | .ecx => some 1 | .edx => some 2 | .ebx => some 3
  | .esp => some 4 | .ebp => some 5 | .esi => some 6 | .edi => some 7
  | _ => none

def RelatedMachineInputChoice.bsrEncodingChecked
    (choice : RelatedMachineInputChoice) : Bool :=
  match choice.instructionBytes, choice.location.x86RegisterCode? with
  | 15 :: 189 :: modrm :: _, some registerCode =>
      (modrm / 8) % 8 == registerCode
  | _, _ => false

def RelatedMachineInputChoice.checked (choice : RelatedMachineInputChoice) : Bool :=
  !choice.instructionBytes.isEmpty && choice.instructionBytes.length <= 15 &&
    choice.instructionBytes.all (fun byte => byte < 256) &&
    choice.bsrEncodingChecked

inductive ChoiceSource where
  | noninterferingZero
  | relatedMachineInput (choice : RelatedMachineInputChoice)
deriving Repr, DecidableEq

def ChoiceSource.checked (source : ChoiceSource) (policy : SlotPolicy) : Bool :=
  match source, policy with
  | .noninterferingZero, .arbitrary => true
  | .relatedMachineInput choice, .synchronized => choice.checked
  | _, _ => false

structure DefinednessCertificate where
  slot : Nat
  undefinedId : String
  policy : SlotPolicy
  choiceSource : ChoiceSource
  relevantSites : List RelevantSite
  obligations : List ProofObligation
  graphs : List GraphCertificate
deriving Repr, DecidableEq

def DefinednessCertificate.obligationLocated (certificate : DefinednessCertificate)
    (obligation : ProofObligation) : Bool :=
  certificate.graphs.any fun graph =>
    graph.nodes.any fun node => node.step.id == obligation.transferId

def DefinednessCertificate.obligationsLocatedChecked
    (certificate : DefinednessCertificate) : Bool :=
  certificate.obligations.all certificate.obligationLocated

def DefinednessCertificate.checked (certificate : DefinednessCertificate) : Bool :=
  !certificate.undefinedId.isEmpty && !certificate.graphs.isEmpty &&
    certificate.choiceSource.checked certificate.policy &&
    (match certificate.policy with
      | .arbitrary => certificate.relevantSites.isEmpty
      | .synchronized => !certificate.relevantSites.isEmpty) &&
    certificate.obligationsLocatedChecked &&
    certificate.graphs.all (fun graph => graph.checked certificate.policy)

abbrev Machine := Location -> Nat

abbrev ChoiceFunction := Machine -> Nat -> Nat

def ChoiceSource.expectedValue (source : ChoiceSource) (input : Machine) : Nat :=
  match source with
  | .noninterferingZero => 0
  | .relatedMachineInput choice => input choice.location

def ChoiceSource.inputsRelated (source : ChoiceSource)
    (original candidate : Machine) : Prop :=
  match source with
  | .noninterferingZero => True
  | .relatedMachineInput choice =>
      original choice.location = candidate choice.location

def ChoiceSource.exactInstructionBound (source : ChoiceSource)
    (pe : StageA.Formal.PE32) : Prop :=
  match source with
  | .noninterferingZero => True
  | .relatedMachineInput choice =>
      StageA.Formal.spanBytes pe {
        start := choice.instructionRva
        size := choice.instructionBytes.length
      } =
        some choice.instructionBytes

def AgreeOutside (live : List Location) (left right : Machine) : Prop :=
  forall location, location ∉ live -> left location = right location

/- The semantic bridge supplies concrete observations, selected control, and
the post-state for one exact decoded transfer. -/
structure StepResult where
  machine : Machine
  observations : List Nat
  successor : Option String
  terminated : Bool

abbrev StepTransition := FlowStep -> Nat -> Machine -> StepResult

/- This is the sole local semantic premise. It must be proved from exact
decoded semantics. It says the submitted dependency inventory is complete:
changing the selected undefined slot and currently-live locations cannot alter
an admitted observation or guard, and cannot escape the computed live set. -/
def StepDependencySound (policy : SlotPolicy) (step : FlowStep)
    (transition : StepTransition) : Prop :=
  forall live slotLeft slotRight left right,
    policy.valuesRelated slotLeft slotRight ->
    step.observationsIndependent policy live = true ->
    step.guardsIndependent policy live = true ->
    AgreeOutside live left right ->
    let leftResult := transition step slotLeft left
    let rightResult := transition step slotRight right
    leftResult.observations = rightResult.observations ∧
      leftResult.successor = rightResult.successor ∧
      leftResult.terminated = rightResult.terminated ∧
      AgreeOutside (step.liveAfter policy live)
        leftResult.machine rightResult.machine

/- Each exceptional boundary retains a family-specific semantic consequence.
The common exact step theorem is deliberately stronger than every consequence,
so an x87 replay, call-frame, fault, or return bridge cannot close an obligation
by matching only a status or transfer name. -/
def ProofObligation.SemanticConsequence (policy : SlotPolicy) (step : FlowStep)
    (transition : StepTransition) (obligation : ProofObligation) : Prop :=
  match obligation.kind with
  | .exactReplayTransfer => StepDependencySound policy step transition
  | .callFrameNoninterference =>
      forall live slotLeft slotRight left right,
        policy.valuesRelated slotLeft slotRight ->
        step.observationsIndependent policy live = true ->
        step.guardsIndependent policy live = true ->
        AgreeOutside live left right ->
        (transition step slotLeft left).observations =
          (transition step slotRight right).observations
  | .faultDominance =>
      forall live slotLeft slotRight left right,
        policy.valuesRelated slotLeft slotRight ->
        step.observationsIndependent policy live = true ->
        step.guardsIndependent policy live = true ->
        AgreeOutside live left right ->
        (transition step slotLeft left).successor =
            (transition step slotRight right).successor ∧
          (transition step slotLeft left).terminated =
            (transition step slotRight right).terminated
  | .returnContinuationNoninterference =>
      forall live slotLeft slotRight left right,
        policy.valuesRelated slotLeft slotRight ->
        step.observationsIndependent policy live = true ->
        step.guardsIndependent policy live = true ->
        AgreeOutside live left right ->
        AgreeOutside (step.liveAfter policy live)
          (transition step slotLeft left).machine
          (transition step slotRight right).machine

theorem ProofObligation.semanticConsequence_of_stepDependencySound
    (policy : SlotPolicy) (step : FlowStep) (transition : StepTransition)
    (obligation : ProofObligation)
    (sound : StepDependencySound policy step transition) :
    obligation.SemanticConsequence policy step transition := by
  rcases obligation with ⟨kind, transferId, rva, jsonPointer, detail⟩
  cases kind <;> simp only [ProofObligation.SemanticConsequence]
  · exact sound
  · intro live slotLeft slotRight left right choices observations guards agreement
    exact (sound live slotLeft slotRight left right choices observations guards
      agreement).1
  · intro live slotLeft slotRight left right choices observations guards agreement
    exact ⟨(sound live slotLeft slotRight left right choices observations guards
      agreement).2.1, (sound live slotLeft slotRight left right choices observations
      guards agreement).2.2.1⟩
  · intro live slotLeft slotRight left right choices observations guards agreement
    exact (sound live slotLeft slotRight left right choices observations guards
      agreement).2.2.2

def ProofObligation.DischargedBy (certificate : DefinednessCertificate)
    (transition : StepTransition) (obligation : ProofObligation) : Prop :=
  exists graph, graph ∈ certificate.graphs ∧ exists node,
    node ∈ graph.nodes ∧ node.step.id = obligation.transferId ∧
      obligation.SemanticConsequence certificate.policy node.step transition

structure DefinednessSemanticClosure (certificate : DefinednessCertificate)
    (transition : StepTransition) : Prop where
  localSound : forall graph, graph ∈ certificate.graphs ->
    forall node, node ∈ graph.nodes ->
      StepDependencySound certificate.policy node.step transition

/- This is the static/runtime trust boundary.  Choice functions are indexed by
the machine input of the instruction invocation.  Noninterfering values are
implemented as zero.  A behavior-relevant BSR result is reconstructed from the
same related destination register on each side; no arbitrary provider can
inhabit this structure. -/
structure RuntimeChoiceBound (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction) : Prop where
  sourceChecked : certificate.choiceSource.checked certificate.policy = true
  runtimeRealized : forall input,
    runtimeChoice input certificate.slot =
      certificate.choiceSource.expectedValue input
  candidateRealized : forall input,
    candidateChoice input certificate.slot =
      certificate.choiceSource.expectedValue input
  originalSynchronized : certificate.policy = .synchronized -> forall input,
    originalChoice input certificate.slot =
      certificate.choiceSource.expectedValue input

abbrev DefinednessChoiceBinding (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction) : Prop :=
  RuntimeChoiceBound certificate originalChoice candidateChoice runtimeChoice

theorem definednessChoiceBinding_of_runtime_bound
    (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)
    (bound : RuntimeChoiceBound certificate originalChoice candidateChoice
      runtimeChoice) :
    DefinednessChoiceBinding certificate originalChoice candidateChoice runtimeChoice :=
  bound

theorem RuntimeChoiceBound.valuesRelated
    {certificate : DefinednessCertificate}
    {originalChoice candidateChoice runtimeChoice : ChoiceFunction}
    (bound : RuntimeChoiceBound certificate originalChoice candidateChoice runtimeChoice)
    (originalInput candidateInput : Machine)
    (inputsRelated : certificate.choiceSource.inputsRelated originalInput candidateInput) :
    certificate.policy.valuesRelated
      (originalChoice originalInput certificate.slot)
      (candidateChoice candidateInput certificate.slot) := by
  cases policy : certificate.policy with
  | arbitrary => simp [SlotPolicy.valuesRelated]
  | synchronized =>
      have original := bound.originalSynchronized policy originalInput
      rw [original, bound.candidateRealized candidateInput]
      cases source : certificate.choiceSource with
      | noninterferingZero =>
          have checked := bound.sourceChecked
          simp [ChoiceSource.checked, policy, source] at checked
      | relatedMachineInput choice =>
          simpa [ChoiceSource.inputsRelated, ChoiceSource.expectedValue, source,
            SlotPolicy.valuesRelated] using inputsRelated

/- `checked` establishes only well-formed diagnostic evidence.  Acceptance
also requires exact transfer semantics and an exact candidate choice binding. -/
structure DefinednessCertificate.AcceptanceClosed
    (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)
    (transition : StepTransition) (originalPe : StageA.Formal.PE32) : Prop where
  checked : certificate.checked = true
  choiceInstruction : certificate.choiceSource.exactInstructionBound originalPe
  choice : DefinednessChoiceBinding certificate originalChoice candidateChoice
    runtimeChoice
  semantics : DefinednessSemanticClosure certificate transition

def NodeSemanticNoninterference (policy : SlotPolicy) (node : CertifiedNode)
    (transition : StepTransition) : Prop :=
  forall slotLeft slotRight left right,
    policy.valuesRelated slotLeft slotRight ->
    AgreeOutside node.liveIn left right ->
    let leftResult := transition node.step slotLeft left
    let rightResult := transition node.step slotRight right
    leftResult.observations = rightResult.observations ∧
      leftResult.successor = rightResult.successor ∧
      leftResult.terminated = rightResult.terminated ∧
      AgreeOutside node.liveOut leftResult.machine rightResult.machine

theorem CertifiedNode.checked_noninterference
    (policy : SlotPolicy) (node : CertifiedNode) (transition : StepTransition)
    (checked : node.localChecked policy = true)
    (localSound : StepDependencySound policy node.step transition) :
    NodeSemanticNoninterference policy node transition := by
  intro slotLeft slotRight left right choicesRelated related
  have checkedPrefix := (Bool.and_eq_true_iff.mp checked).1
  have guardsIndependent := (Bool.and_eq_true_iff.mp checkedPrefix).2
  have checkedPrefix := (Bool.and_eq_true_iff.mp checkedPrefix).1
  have observationsIndependent := (Bool.and_eq_true_iff.mp checkedPrefix).2
  have checkedPrefix := (Bool.and_eq_true_iff.mp checkedPrefix).1
  have liveAfterChecked := (Bool.and_eq_true_iff.mp checkedPrefix).2
  have liveAfter : node.liveOut = node.step.liveAfter policy node.liveIn :=
    beq_iff_eq.mp liveAfterChecked
  have result := localSound node.liveIn slotLeft slotRight left right
    choicesRelated observationsIndependent guardsIndependent related
  simpa [liveAfter] using result

theorem GraphCertificate.checked_nodes
    (certificate : GraphCertificate) (policy : SlotPolicy)
    (checked : certificate.checked policy = true) :
    forall node, node ∈ certificate.nodes -> node.localChecked policy = true := by
  intro node member
  have nodesChecked := (Bool.and_eq_true_iff.mp checked).2
  exact (Bool.and_eq_true_iff.mp
    (List.all_eq_true.mp nodesChecked node member)).1

theorem GraphCertificate.checked_edge_relation
    (certificate : GraphCertificate) (policy : SlotPolicy)
    (checked : certificate.checked policy = true)
    (node target : CertifiedNode) (nodeMember : node ∈ certificate.nodes)
    (edge : EdgeSpec) (edgeMember : edge ∈ node.step.edges)
    (found : certificate.find? edge.successor = some target) :
    target.liveIn = node.liveOut := by
  have nodesChecked := (Bool.and_eq_true_iff.mp checked).2
  have nodeCheck := List.all_eq_true.mp nodesChecked node nodeMember
  have closed := (Bool.and_eq_true_iff.mp nodeCheck).2
  have edgeCheck := List.all_eq_true.mp closed edge edgeMember
  simp [GraphCertificate.edgeClosed, found] at edgeCheck
  exact edgeCheck

theorem GraphCertificate.checked_noninterference
    (certificate : GraphCertificate) (policy : SlotPolicy)
    (transition : StepTransition)
    (checked : certificate.checked policy = true)
    (localSound : forall node, node ∈ certificate.nodes ->
      StepDependencySound policy node.step transition) :
    forall node, node ∈ certificate.nodes ->
      NodeSemanticNoninterference policy node transition := by
  intro node member
  exact node.checked_noninterference policy transition
    (certificate.checked_nodes policy checked node member)
    (localSound node member)

theorem DefinednessCertificate.checked_graphs
    (certificate : DefinednessCertificate) (checked : certificate.checked = true) :
    forall graph, graph ∈ certificate.graphs ->
      graph.checked certificate.policy = true := by
  have graphsChecked := (Bool.and_eq_true_iff.mp checked).2
  exact List.all_eq_true.mp graphsChecked

theorem DefinednessCertificate.checked_obligation_located
    (certificate : DefinednessCertificate) (checked : certificate.checked = true)
    (obligation : ProofObligation) (member : obligation ∈ certificate.obligations) :
    exists graph, graph ∈ certificate.graphs ∧ exists node,
      node ∈ graph.nodes ∧ node.step.id = obligation.transferId := by
  have checkedPrefix := (Bool.and_eq_true_iff.mp checked).1
  have obligationsChecked := (Bool.and_eq_true_iff.mp checkedPrefix).2
  have located := List.all_eq_true.mp obligationsChecked obligation member
  obtain ⟨graph, graphMember, nodeLocated⟩ := List.any_eq_true.mp located
  obtain ⟨node, nodeMember, nodeMatches⟩ := List.any_eq_true.mp nodeLocated
  exact ⟨graph, graphMember, node, nodeMember, beq_iff_eq.mp nodeMatches⟩

theorem DefinednessCertificate.obligations_discharged_of_localSound
    (certificate : DefinednessCertificate) (transition : StepTransition)
    (checked : certificate.checked = true)
    (localSound : forall graph, graph ∈ certificate.graphs ->
      forall node, node ∈ graph.nodes ->
        StepDependencySound certificate.policy node.step transition) :
    forall obligation, obligation ∈ certificate.obligations ->
      obligation.DischargedBy certificate transition := by
  intro obligation member
  obtain ⟨graph, graphMember, node, nodeMember, transferId⟩ :=
    certificate.checked_obligation_located checked obligation member
  exact ⟨graph, graphMember, node, nodeMember, transferId,
    obligation.semanticConsequence_of_stepDependencySound certificate.policy
      node.step transition (localSound graph graphMember node nodeMember)⟩

theorem DefinednessCertificate.acceptance_choices_related
    (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)
    (transition : StepTransition)
    (originalPe : StageA.Formal.PE32)
    (closed : certificate.AcceptanceClosed originalChoice candidateChoice
      runtimeChoice transition originalPe)
    (originalInput candidateInput : Machine)
    (inputsRelated : certificate.choiceSource.inputsRelated originalInput
      candidateInput) :
    certificate.policy.valuesRelated
      (originalChoice originalInput certificate.slot)
      (candidateChoice candidateInput certificate.slot) :=
  closed.choice.valuesRelated originalInput candidateInput inputsRelated

theorem DefinednessCertificate.acceptance_runtime_choice_exact
    (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)
    (transition : StepTransition)
    (originalPe : StageA.Formal.PE32)
    (closed : certificate.AcceptanceClosed originalChoice candidateChoice
      runtimeChoice transition originalPe) (input : Machine) :
    runtimeChoice input certificate.slot =
      candidateChoice input certificate.slot := by
  rw [closed.choice.runtimeRealized input, closed.choice.candidateRealized input]

theorem DefinednessCertificate.acceptance_obligations_discharged
    (certificate : DefinednessCertificate)
    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)
    (transition : StepTransition)
    (originalPe : StageA.Formal.PE32)
    (closed : certificate.AcceptanceClosed originalChoice candidateChoice
      runtimeChoice transition originalPe) :
    forall obligation, obligation ∈ certificate.obligations ->
      obligation.DischargedBy certificate transition := by
  exact certificate.obligations_discharged_of_localSound transition closed.checked
    closed.semantics.localSound

theorem DefinednessCertificate.checked_noninterference
    (certificate : DefinednessCertificate) (transition : StepTransition)
    (checked : certificate.checked = true)
    (localSound : forall graph, graph ∈ certificate.graphs ->
      forall node, node ∈ graph.nodes ->
        StepDependencySound certificate.policy node.step transition) :
    forall graph, graph ∈ certificate.graphs ->
      forall node, node ∈ graph.nodes ->
        NodeSemanticNoninterference certificate.policy node transition := by
  intro graph graphMember
  exact graph.checked_noninterference certificate.policy transition
    (certificate.checked_graphs checked graph graphMember)
    (localSound graph graphMember)

#print axioms CertifiedNode.checked_noninterference
#print axioms GraphCertificate.checked_edge_relation
#print axioms GraphCertificate.checked_noninterference
#print axioms DefinednessCertificate.checked_noninterference
#print axioms DefinednessCertificate.acceptance_choices_related
#print axioms DefinednessCertificate.acceptance_runtime_choice_exact
#print axioms DefinednessCertificate.obligations_discharged_of_localSound
#print axioms DefinednessCertificate.acceptance_obligations_discharged

end StageA.Relational.Definedness
