# Stage A Generic ISA Qualification

## Purpose And Authority

The ISA qualification pipeline tests one revision of the reviewed Lean x86
semantic kernel against independent concrete executors. It is evidence only:
qualification artifacts and Nix manifests record `proof_authority: false` and
`closes_stage_a_proof: false`. Catalogs and generated corpora are untrusted
inputs. Stage A acceptance still comes only from the checked Lean equivalence
theorem over the exact program bytes.

The pipeline never launches, traces, or probes an original application. It
executes synthetic, single-instruction machine states. A binary selection reads
an already-produced instruction-requirement inventory and attaches evidence to
exact binary hashes and RVAs; it does not execute either binary.

## Pipeline

1. **Inventory proposal.** The pinned `xed-isa-catalog` tool enumerates Intel
   XED templates valid for `PENTIUMPRO`, `LEGACY_32`, a 32-bit stack-address
   width, and CPL 3 (`ring3`). The parser requires that exact
   `pe32-i686-v1` profile, derives stable content-based form IDs, and preserves
   duplicate XED table rows as aliases of one form.
2. **Profile disposition.** Generic XED metadata classifies forms as `core`,
   `separately_qualified`, `external_platform`, or `excluded_unsupported`.
   Classification uses operand, state, category, privilege, and flag
   properties, not mnemonic-specific dispatch.
3. **Reviewed enrichment.** An executable form catalog adds exact instruction
   bytes, an encoding ID, required features, defined-output masks, and generic
   effects. Supported effect descriptors are register, memory, branch, divide,
   and x87. XED and the enrichment remain untrusted proposals.
4. **Boundary corpus.** The generic generator expands each effect into
   deterministic structural cells: integer zero/one/maximum/sign/alternating
   values, aligned and page-edge memory, taken and not-taken branches,
   successful and faulting divide cases, and x87 special values. The seed,
   catalog hash, form, bytes, complete initial state, mappings, masks, and
   expected control/fault class determine canonical case IDs and corpus hashes.
5. **Independent execution.** Lean, Unicorn, and one headless Bochs guest
   execute the same corpus. Bochs boots once, injects every case through its
   private batch protocol, and executes exactly one instruction per case.
6. **Raw masked consensus.** Qualification ignores a complete report's legacy
   `match` or `mismatch` against the generator's deliberately neutral expected
   state. It compares the actual control/fault result and masked GPR, EIP,
   EFLAGS, FS, x87, and memory outputs. Undefined bits cannot create agreement
   or disagreement.
7. **Selection and planning.** Qualified semantic forms can be selected for
   exact original and candidate instruction occurrences. The complete XED
   inventory then remains visible through a deterministic campaign frontier.

## Exact Profiles

The execution profile is an exact tuple, currently
`x86/i686/protected-32/pe32` with no feature overrides. Reports are rejected if
architecture, CPU, execution mode, environment, or feature tuple differs from
the corpus. Backend identity and CPU profile are separate bindings.

Neither executor offers a Pentium Pro preset. For `i686`, Bochs uses
`p2_klamath` and Unicorn uses `UC_CPU_X86_PENTIUM2`, the nearest available
architectural supersets. Applicability therefore also depends on the XED
PENTIUMPRO inventory excluding MMX and later forms. These substitutions do not
broaden the declared profile.

## Consensus Status

- `qualified`: Bochs, Unicorn, and Lean produced complete observations and all
  masked results agree.
- `incomplete`: a backend is missing, unsupported, errored, lacks actual state,
  or the form has no consensus cases.
- `disputed`: Bochs and Unicorn disagree on an architecturally defined output.
  No judgment about Lean is made from that case.
- `vetoed`: Bochs and Unicorn agree, but Lean differs. The semantic kernel
  revision must be repaired or explained before reuse.

Aggregation is fail closed with precedence `vetoed`, `disputed`, `incomplete`,
then `qualified`. Diagnostics retain backend/result hashes, JSON paths, values,
form and case IDs, and selected binary locations.

The aggregate status describes the entire supplied corpus. Final Stage A
acceptance depends on the exact original and candidate selections instead. An
unrelated incomplete or vetoed form remains visible in the campaign but cannot
block a program that does not decode to that semantic form.

## Kernel Identity And Invalidation

Every observation is bound to one semantic-kernel identity containing the
kernel ID, Lean version, decoder SHA-256, and semantics SHA-256. The Nix
identity derives the decoder hash from the compiled `ISAQualification` node
and the semantics hash from the `X87`, `Formal`, `ISAConformance`, and
`ISAConformanceRunner` nodes.

A decoder or semantics change produces a different content-addressed kernel
identity and qualification derivation. Parsers also require exact identity
equality across observations, forms, qualification, and selection. Stale
evidence therefore cannot be silently reused after a semantic-kernel change.

## Nix DAG And Selection Gate

`nix/stage-a-isa-qualification-graph.nix` builds separate content-addressed
Lean, Unicorn, Bochs, qualification, campaign, and bundle nodes. The
qualification check accepts only `status: qualified`. When an ISA requirement
inventory is supplied, separate original and candidate selections bind the
binary SHA-256, exact semantic form, and every source RVA; the selection check
requires both sides to be `qualified`. Missing forms, semantic-form mismatches,
or identity mismatches fail closed.

An acceptance-ready whole-program build additionally requires
`--isa-kernel-qualification` and `--isa-semantic-kernel`. Before invoking Nix,
the build verifies that the compiled kernel uses the same reviewed Lean source,
reselects every exact form for both binaries, and returns `incomplete` if
either selection is not qualified. Focused `--target-node` builds remain
available without this gate because they cannot emit a whole-program `pass`.

The final report embeds the qualification, semantic-kernel identity, compiled
kernel bundle manifest, exact selection prerequisite, and their hashes.
`stage-a-check-proof` recomputes the kernel identities, checks the
bundle modules against the proof graph, and reselects both binaries. Omitting
or modifying any artifact invalidates a claimed `pass`.

The checked-in end-to-end catalog is intentionally a one-form core smoke test,
not broad i686 coverage. The full pinned XED inventory is used by the campaign
artifact to expose all remaining work. The current pinned campaign contains
924 normalized forms: the smoke qualifies one core form and leaves 923 visible
frontiers.

## Campaign Frontier

The campaign covers every normalized XED form and reports counts by profile
disposition, category, ISA set, and qualification status. Pending work is
ranked deterministically:

1. exact semantic forms required by a selected binary;
2. remaining core forms;
3. separately qualified forms.

Within a priority, category, ISA set, and form ID provide stable ordering. Each
item carries a reason and next action for missing evidence, incomplete backend
support, external-oracle disputes, or Lean vetoes. External-platform and
excluded forms stay visible but unranked until a platform contract is defined
or the profile is deliberately expanded.

## Current Limits

- **x87:** catalogs and corpus generation can describe x87 effects and boundary
  values, but Bochs does not capture x87 state, Unicorn rejects x87
  instructions, and the current Lean x87 semantics are not hardware-qualified.
- **Faults:** divide-error cases can be generated, and some backends classify
  them, but Bochs does not yet recover complete pre-delivery architectural
  fault state. Such cases remain incomplete.
- **FS:** the schemas represent FS selector/base and FS-relative addressing,
  but current concrete backends do not support nonzero per-case FS state or FS
  output masks; Lean also does not represent an FS selector output.

Other current Bochs exclusions include vector state, I/O, far control,
repeated instructions, system effects, and cases outside its bounded mapped
memory policy.

## Commands

Build and inspect the current content-addressed artifacts:

```console
nix build .#stage-a-isa-xed-catalog --no-link --print-out-paths
nix build .#stage-a-isa-core-smoke-corpus --no-link --print-out-paths
nix build .#stage-a-isa-core-smoke-bundle --no-link --print-out-paths
nix build .#stage-a-isa-core-smoke-campaign --no-link --print-out-paths
```

Run the qualification gates and focused tests:

```console
nix build .#stage-a-isa-core-smoke-qualification --no-link
nix build .#stage-a-relational-tests-isa-qualification-tooling --no-link
nix build .#stage-a-isa-conformance-bochs-80386 --no-link
```

For a final build, pass the raw qualification artifact for the binary's exact
forms and the identity of the compiled kernel that produced its Lean
observations:

```console
qualification=$(
  nix build .#stage-a-isa-core-smoke-bundle --no-link --print-out-paths
)
kernel=$(
  nix build .#stage-a-isa-kernel-identity --no-link --print-out-paths
)
nix develop --command spaghetti-extractor stage-a-build-relational \
  --prepared prepared-proof \
  --isa-kernel-qualification "$qualification/qualification.json" \
  --isa-semantic-kernel "$kernel/kernel.json" \
  --out report
```

The smoke qualification is suitable only for a requirement inventory
containing its single `movRegImm` semantic form. A real binary needs a generated
corpus and qualification covering every semantic form selected from that
binary's exact instruction inventory.

The direct command surface is:

```text
stage-a-normalize-isa-catalog
stage-a-generate-isa-corpus
stage-a-build-isa-kernel-qualification
stage-a-select-isa-kernel-qualification
stage-a-plan-isa-qualification
```

Use `nix develop --command spaghetti-extractor <command> --help` for the exact
artifact arguments. Selection is run once with `--side original` and once with
`--side candidate`.
