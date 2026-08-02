# Stage A Source-Relative Equivalence Experiment

> **Status:** This remains an optional stronger proof track. It is not the
> primary reimplementation completion gate. See
> [high-assurance-reimplementation-direction.md](high-assurance-reimplementation-direction.md)
> for the current project direction, which uses formal methods selectively to
> minimize reconstruction mistakes and permits explicitly labeled
> high-assurance results without a final whole-program theorem.

## Objective

This branch evaluates a narrower acceptance theorem than the main
binary-to-binary prover:

```text
exact original PE
  -> Lean-checked ProgramRecord semantics
  -> exact canonical C0 source
  -> compiled PE, conditional on a pinned toolchain-correctness hypothesis
```

The existing binary-to-binary path remains authoritative for unconditional
`pass`. The source-relative path can only produce `conditional_pass`, never
`pass`.

## Trust Boundary

Lean remains responsible for:

- parsing and binding the exact original PE bytes;
- decoding each accepted original path;
- proving each `ProgramRecord` macro-step equal to exact original execution;
- checking root and reachable-control closure;
- checking that the source bytes are exactly the canonical rendering of the
  checked program records;
- composing local facts into the source whole-program theorem;
- deriving the conditional compiled-artifact theorem from an explicit
  toolchain-correctness parameter.

The initial `i686-mingw-freestanding-c0-v1` hypothesis covers the complete
pinned lowering stack: C0 translation, C compiler, assembler, linker, ABI
lowering, and the minimal freestanding C0 runtime shim. It is not installed as
a Lean axiom. The final theorem is universally quantified over a witness of
that hypothesis, and the report records the exact profile and derivation used.

Windows and imported APIs remain abstract external events. They are not part
of the compiler assumption. Original and source execution must emit the same
event identity, arguments, order, continuation, result use, and fault class.

## C0 v1

C0 v1 is generated, canonical source. It is not arbitrary C and is not meant
to be pleasant to edit. A program is a checked `ProgramRecord` inventory plus
an entry RVA. Its translation unit contains a length-delimited numeric encoding
of every record and invokes the pinned C0 runtime. Lean independently renders
the same translation unit and checks byte-for-byte equality.

The encoding includes nodes, calls, stack inputs, actions, strings, and all
control outcomes. It does not contain original instruction bytes. Static
non-code image data is emitted separately with exact provenance; bytes from an
executable section require an explicit data classification.

Unsupported records, x87 records without a C0 primitive, unresolved indirect
control, incomplete reachable control, missing API contracts, ambiguous data,
or source-rendering differences produce `incomplete` or `violated`.

## Artifacts

- `stage-b-c0-source-manifest-v1` binds the state-machine export, canonical
  renderer, source files, transfer records, entry RVA, runtime profile, and
  static-data provenance.
- `stage-a-c0-compilation-attestation-v1` binds the source manifest, Nix
  derivation and NAR identity, exact tools, flags, runtime inputs, and output PE.
- `stage-a-source-equivalence-report-v1` records the checked theorem,
  dependency provenance, blockers, verdict, and explicit toolchain hypothesis.

Artifact hashes identify content and invalidation boundaries. They are not
proofs. Only the named Lean theorem can authorize `conditional_pass`.

For content-addressed derivations, the attestation records both the exact
derivation selected by the flake and the deriver currently registered for the
shared output path. These can differ when multiple recipes reproduce the same
NAR. The proof binds the selected recipe, while the output path, PE hash, and
NAR hash bind the resulting bytes.

## Acceptance

`conditional_pass` requires all of the following:

1. A Lean-checked exact-original-to-C0 whole-program theorem.
2. Exact canonical source attestation in Lean.
3. Complete rooted control and external-event closure under the selected
   profile.
4. A reproducible pinned compilation attestation whose source and output hashes
   match the theorem report.
5. A Lean-checked conditional compiled-artifact theorem with no unapproved
   axioms.

Candidate-only behavior tests are gated on `conditional_pass`. The original is
never executed or traced during generation, repair, or runtime testing. Wine
tests run only in a headless Wayland/X session.

## Experiment Milestones

1. Prove and compile a freestanding `mov eax, 7; ret` PE fixture.
2. Produce a standalone GNU hello C0 source project, then extend the generic C0
   profile until it can carry a conditional theorem.
3. Compare proof graph size, clean build time, incremental invalidation, and
   truthful frontiers with the binary-to-binary path.
4. Decide whether the simplification is sufficient before attempting jq.

This experiment does not claim a verified compiler. It measures the practical
benefit of moving compiled-candidate equivalence behind a precise, pinned, and
auditable compiler-correctness assumption.

## Current Feasibility Result

The first milestone is complete. The exact original PE contains
`mov eax, 7; ret`; the state-machine record is extracted from that PE, the
instruction path and normalized semantics are checked in Lean, and Lean proves
the exact canonical C0 source. The final generated theorem is conditional on
`CorrectPinnedCompilation`. Its axiom audit contains only the repository's
approved Lean foundations. The pinned MinGW build produces PE32, and a gated
candidate-only Wine smoke exits with status 7 under headless X.

The GNU hello frontend also completes without executing the original. Its
current static export contains 5,697 transfers. C0 v1 serializes 5,384 ordinary
transfers and deliberately omits 313 x87-bearing transfers. All 5,384 ordinary
transfers remain outside the bootstrap runtime, so the manifest is
`incomplete` and no source-equivalence proof or runtime test is permitted. Each
blocker carries its exact RVA and a stable reason code.

This establishes the theorem and provenance shape, but not the GNU hello
milestone. The experiment has removed candidate-binary relational proof work
only by making the correctness of the complete pinned C0 lowering stack an
explicit premise. It does not remove the need to obtain complete, exact
original semantics, close reachable control, or implement and specify a C0
lowering/runtime for every accepted record form. Expanding that generic source
profile, rather than adding binary-pair mappings, is the next material task.

The source proof currently closes through 39 Lean modules. The exact/fused
semantic-refinement split avoids importing the symbolic relational engine, but
the lightweight transfer layer still reaches a broad environment module
closure. Further performance work should split that stable dependency before
scaling the proof to GNU hello; it is not a correctness blocker for the tiny
milestone.
