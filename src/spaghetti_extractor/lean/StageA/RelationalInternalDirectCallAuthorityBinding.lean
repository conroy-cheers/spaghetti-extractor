import StageA.RelationalInternalDirectCallRegisterSummary

namespace StageA.Relational.InternalDirectCallRegisterSummary

open StageA.Formal StageA.Relational

/-- Type-directed wrapper used by generated authority-binding artifacts.  The
checked authority fixes the otherwise implicit static context without exposing
or duplicating a generated context term. -/
def FiniteOriginCallDependency.authorityTargetCertificatesCheckedFor
    (dependency : FiniteOriginCallDependency)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (_authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (nested : List Certificate) : Bool :=
  dependency.authorityTargetCertificatesChecked context nested

/-- Recombine independently checked finite-origin call facts without asking
Lean to normalize the PE bindings, target inventory, and both decoded sides in
one reduction.  Generated proposal modules use this theorem as their narrow
cache boundary; every premise still states one conjunct of the authoritative
checker. -/
theorem Certificate.finiteOriginCallAuthorityBound_of_components
    (certificate : Certificate) (nested : List SummaryTree)
    (dependencyId : Nat)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (dependency : FiniteOriginCallDependency)
    (dependenciesChecked :
      certificate.finiteOriginCallDependencies.filter
        (fun candidate => candidate.id == dependencyId) = [dependency])
    (originalPeBound : context.originalPe = originalPe)
    (candidatePeBound : context.candidatePe = candidatePe)
    (originalImportsBound : context.originalImports = originalImports)
    (candidateImportsBound : context.candidateImports = candidateImports)
    (shapeChecked :
      dependency.authorityShapeChecked authority.certificate = true)
    (targetsChecked :
      dependency.authorityTargetCertificatesChecked context
        (nested.map SummaryTree.certificate) = true)
    (originalSideChecked :
      dependency.authoritySideChecked authority.certificate
        originalPe originalImports false certificate.calleeRegions = true)
    (candidateSideChecked :
      dependency.authoritySideChecked authority.certificate
        candidatePe candidateImports true certificate.calleeRegions = true) :
    certificate.finiteOriginCallAuthorityBound nested dependencyId authority
      originalPe candidatePe originalImports candidateImports = true := by
  subst originalPe
  subst candidatePe
  subst originalImports
  subst candidateImports
  simp only [Certificate.finiteOriginCallAuthorityBound,
    Certificate.finiteOriginCallAuthorityBoundCertificates,
    dependenciesChecked, beq_self_eq_true, shapeChecked,
    targetsChecked, originalSideChecked, candidateSideChecked,
    Bool.true_and]

end StageA.Relational.InternalDirectCallRegisterSummary
