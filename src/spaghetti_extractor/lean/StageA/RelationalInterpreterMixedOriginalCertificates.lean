import StageA.RelationalIndexedCertificateComposition
import StageA.RelationalInterpreterMixedContext

namespace StageA.Relational.InterpreterMixedContext

open StageA.Formal StageA.Relational

/-- Proof-oriented form of `OriginalCodeMapCertificate`.  Expensive predicates
are exposed as theorem functions, allowing generated shards to establish them
independently.  The checked range coverage remains a small Boolean fact. -/
structure OriginalCodeMapProofCertificate (pe : PE32) (imports : List PEImport)
    (mapping : OriginalCodeMap) where
  entriesStructurallyValid : mapping.entries.structurallyValid 16 = true
  addressesStructurallyValid : mapping.addresses.structurallyValid 16 = true
  entryChecks : IndexedBoolCertificate
  entryChecksCoverage :
    indexedRangesCover mapping.entries.size 0 entryChecks.ranges = true
  entriesValid :
    entryChecks.Holds mapping.entryAtValid mapping.entries.size
  addressCountExact : mapping.addresses.size = mapping.expectedAddressCount
  addressChecks : IndexedBoolCertificate
  addressChecksCoverage :
    indexedRangesCover mapping.addresses.size 0 addressChecks.ranges = true
  addressesValid :
    addressChecks.Holds (mapping.addressAtValid pe) mapping.addresses.size
  roundTripChecks : IndexedBoolCertificate
  roundTripChecksCoverage :
    indexedRangesCover mapping.entries.size 0 roundTripChecks.ranges = true
  targetsRoundTrip :
    roundTripChecks.Holds (mapping.targetRoundTripsAt pe) mapping.entries.size
  aliasChecks : IndexedBoolCertificate
  aliasChecksCoverage :
    indexedRangesCover mapping.entries.size 0 aliasChecks.ranges = true
  aliasesValid :
    aliasChecks.Holds (mapping.aliasesSemanticallyValidAt pe imports)
      mapping.entries.size

def OriginalCodeMapProofCertificate.toBooleanCertificate
    (certificate : OriginalCodeMapProofCertificate pe imports mapping) :
    OriginalCodeMapCertificate pe imports mapping := {
  entriesStructurallyValid := certificate.entriesStructurallyValid
  addressesStructurallyValid := certificate.addressesStructurallyValid
  entryChecks := certificate.entryChecks
  entryChecksValid := certificate.entryChecks.checked_of_holds
    mapping.entryAtValid mapping.entries.size
    certificate.entryChecksCoverage certificate.entriesValid
  addressCountExact := certificate.addressCountExact
  addressChecks := certificate.addressChecks
  addressChecksValid := certificate.addressChecks.checked_of_holds
    (mapping.addressAtValid pe) mapping.addresses.size
    certificate.addressChecksCoverage certificate.addressesValid
  roundTripChecks := certificate.roundTripChecks
  roundTripChecksValid := certificate.roundTripChecks.checked_of_holds
    (mapping.targetRoundTripsAt pe) mapping.entries.size
    certificate.roundTripChecksCoverage certificate.targetsRoundTrip
  aliasChecks := certificate.aliasChecks
  aliasChecksValid := certificate.aliasChecks.checked_of_holds
    (mapping.aliasesSemanticallyValidAt pe imports) mapping.entries.size
    certificate.aliasChecksCoverage certificate.aliasesValid
}

/-- Proof-oriented exact original authority.  Its compatibility conversion is
the sole path to the established authority type used by downstream proofs. -/
structure ExactOriginalDecodedProofAuthority
    (context : OriginalDecodedStaticContext) where
  peParsed : parsePE32Tree context.pe.bytes = some context.pe
  importsParsed : importTableValid context.pe context.importCertificate = true
  relocationsParsed : parseRelocations context.pe = some context.relocations
  loaderImageValid : preferredBaseLoaderImageValid context.pe = true
  codeMap :
    OriginalCodeMapProofCertificate context.pe context.imports context.codeMap
  regionsStructurallyValid : context.regions.structurallyValid 16 = true
  sourceChecks : IndexedBoolCertificate
  sourceChecksCoverage :
    indexedRangesCover context.codeMap.entries.size 0 sourceChecks.ranges = true
  sourcesValid :
    sourceChecks.Holds context.sourceAtValid context.codeMap.entries.size
  machineContractsValid :
    machineImportCallContractsValid context.imports
      context.machineImportCallContracts = true

def ExactOriginalDecodedProofAuthority.toBooleanAuthority
    (authority : ExactOriginalDecodedProofAuthority context) :
    ExactOriginalDecodedAuthority context := {
  peParsed := authority.peParsed
  importsParsed := authority.importsParsed
  relocationsParsed := authority.relocationsParsed
  loaderImageValid := authority.loaderImageValid
  codeMap := authority.codeMap.toBooleanCertificate
  regionsStructurallyValid := authority.regionsStructurallyValid
  sourceChecks := authority.sourceChecks
  sourceChecksValid := authority.sourceChecks.checked_of_holds
    context.sourceAtValid context.codeMap.entries.size
    authority.sourceChecksCoverage authority.sourcesValid
  machineContractsValid := authority.machineContractsValid
}

end StageA.Relational.InterpreterMixedContext
