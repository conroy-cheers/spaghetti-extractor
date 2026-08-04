# Architecture And Assurance

## Objective

Produce a faithful, progressively portable reimplementation of an opaque PE32
program while minimizing silent reconstruction mistakes. Full automation is not
required: operator or LLM-guided component selection, type recovery, and source
repair are expected. The tooling must make those interventions local,
reviewable, reproducible, and testable.

## Canonical Pipeline

```text
original PE32
  -> exact static inventory and ISA requirements
  -> original-only reference contract
  -> canonical machine IR
  -> generated baseline/interpreter
  -> linked-library and interface recognition
  -> semantic components with explicit boundaries
  -> portable C replacements
  -> rebuilt candidate
  -> static candidate contract check
  -> candidate-only behavioral suites
  -> assurance report
```

The original may be parsed and disassembled statically. Repair iteration must
not execute or trace it. Runtime diagnosis is candidate-only and uses public or
curated expectations.

## Trust Boundaries

- Raw PE bytes and content hashes are authoritative inputs.
- Capstone, `pefile`, Ghidra, symbols, linker maps, Z3, and library matchers make
  proposals. Their output is validated structurally and fails closed.
- The compact Lean ISA model is authoritative only for the instruction forms it
  implements. It is qualified against Unicorn, Bochs, and hardware corpora;
  oracle agreement is evidence, not a candidate correctness claim.
- CBMC establishes bounded component claims under explicit finite domains. It
  does not silently generalize them.
- Source rendering and library substitutions require exact catalog/profile
  bindings and never qualify a candidate on their own.
- Candidate behavior tests cannot establish exhaustive correctness, but a
  failure vetoes qualification. A statically qualified candidate that fails a
  public behavior test is a tooling defect or an under-specified contract.

## Status Vocabulary

- `qualified`: every requirement in the artifact's declared scope was checked.
- `incomplete`: evidence is missing, unsupported, ambiguous, or out of scope.
- `violated`: evidence contradicts an expected contract or behavior.
- `not_applicable`: a checked family does not apply to this artifact.
- `pass` / `fail`: reserved for ordinary command execution and behavior-test
  cases, not static assurance claims.

No Python status field grants stronger authority than the checker named by the
artifact. Hashes bind artifacts but do not prove semantic correctness.

## Completion Criteria

A target is ready for release qualification when:

1. Every executable byte has a static classification.
2. Every required ISA form is supported and qualified.
3. Roots, direct control flow, finite indirect targets, imports, callbacks, and
   data/pointer provenance have no material unresolved frontier.
4. Every retained machine-oriented region or source component has a checked
   interface and implementation path.
5. Candidate static checks are `qualified` with no stale or ambiguous binding.
6. Curated and upstream candidate-only suites pass under headless Wine.
7. Generated artifacts are reproducible through the pinned Nix graph.

This is an assurance claim, not a universal theorem over all executions. The
architecture intentionally prioritizes useful, localized evidence and a viable
lifting workflow over an impractical whole-program bisimulation requirement.

## Caching

The Nix graph separates extraction, ISA qualification, machine IR, component
analysis, source checks, candidate builds, and behavior suites. Original-side
artifacts should remain unchanged during source repair. Content-addressed
derivations allow local and remote builders to substitute identical work.

Generated files belong under Nix outputs or ignored `build/` workspaces. Authored
intent and source belong in target bundles. Private binaries belong under the
ignored `private/` tree and must never be copied into source or target data.
