# Clean-Room Boundaries

This stage produces a detailed private dirty corpus and catalog first.
A later cleanup pass rewrites, strips, or aggregates that corpus into a safer
public distribution.

The detailed private corpus may contain:

- Binary filenames, SHA256 hashes, sizes, PE metadata, section names, RVAs, imports, exports, resource hashes, and role labels.
- Function labels, inferred signatures, calling conventions, side-effect tags, block identities, CFG edge identities, call edge identities, and data-reference addresses.
- Disassembly listings and raw static-analysis context, organized as private
  module/routine/basic-block packets for review.
- Decompiled C, p-code, per-instruction metadata, variables, inferred types,
  stack/global references, strings, callsites, and dynamic value traces when
  imported through private semantic tooling.
- Sanitized internal routine contracts: public names, purpose summaries,
  inferred input/output shapes, preconditions, postconditions, state effects,
  fixtures, evidence sources, confidence, taint level, and review status.
- Dirty internal routine-contract drafts that may include private labels, raw
  RVAs, unresolved names, and inference notes.
- Behavior-derived detailed specs, fixtures, mocks, and tests.
- Per-row dirty review packets for behavior contracts, JSON observations,
  process observations, oracle rows, interface cases, data/state cases, mutation
  cases, and internal harness rows. These packets may include raw sidecar logs
  or result files when they are private, text-like evidence.
- Coverage ledgers that identify original module SHA256 plus RVA and map those private oracle addresses to stable labels.
- Waivers with evidence, reviewers, and revalidation triggers.

A sanitized public distribution should prefer:

- Stable 1:1 labels over raw RVAs.
- Human-readable module, function, block, edge, data-structure, global, endpoint, and test names where possible.
- Reviewed functional names and short purpose summaries for internal routines
  when they describe behavior rather than implementation expression.
- Behavior-derived specs/tests that do not require readers to inspect private decompiler artifacts.

Generated `build/reports/specs.json`, `build/reports/specs.md`,
`build/reports/tests.json`, and `build/reports/tests.md` are the label-first
report surfaces. They summarize observed functions, control-flow items, dynamic
coverage observations, interfaces, data-state specs, oracle tests, harnesses,
mutations, waivers, trace probes, and test runs without emitting raw RVAs, image
bases, or module hashes. They are automated reports, not the reviewed final
clean distribution. The private SQLite catalog retains `oracle_mappings` for
validation against the original binary oracle.

Generated `private/wincr-artifacts/` bundles are different: they are the primary
private dirty corpus and may contain raw disassembly, module hashes, RVAs,
coverage mappings, harness/oracle details, raw test sidecars, and draft
contracts. Internal routine contracts are also emitted as discrete dirty review
packets with adjacent clean templates. Basic blocks are emitted as discrete
private packets with block-local disassembly, CFG/coverage context, decompiler
availability status, instruction metadata, p-code/data-flow/xref sidecars,
semantic summaries, and a clean rewrite template. Each packet is small enough
to be read by a human or LLM and rewritten into a clean equivalent using the
adjacent `clean-template.json`. Root-level `dirty-specs.json`/`dirty-specs.md`,
`dirty-tests.json`/`dirty-tests.md`, `reimplementation-plan.*`, `cli-index.json`,
and `review-html/` index those packets as the private dirty workbench. They may
link to private evidence and are review input, not publication output. The
`publication-clean` gate applies to generated public reports, not to this
private corpus.

`validate-dirty-corpus` is the integrity check for that private intermediate
artifact. It does not sanitize or approve content for publication. Instead it
checks that the corpus is reviewable: root manifests and content hashes match,
module/routine/basic-block dossiers are present, block-local disassembly and
context files exist, dirty review packets have sibling indexes and clean
templates, evidence sidecars are copied or still reachable, and taint metadata
uses known dirty/review levels. A corpus should pass this validation before it
is handed to a human or LLM for cleanup.

The clean derivation stage consumes those packet-local `clean-template.json`
files after review. It emits only templates marked `review_status = reviewed`,
`taint_level = reviewed_public`, and an approved publication decision. Drafts are
skipped, and publishable templates are rejected if they still contain private
paths, redacted private-path placeholders, raw oracle identity fields,
disassembly references, copied pseudocode markers, or harness-sensitive field
names.

`promote-clean-templates` is a review bookkeeping helper for this stage. It
does not convert dirty evidence into clean facts; it marks selected templates as
publishable only after the template already contains reviewed clean content and
passes the same public-field validation used by clean derivation.
`validate-clean-specs` then checks derived `specs.json`/`tests.json` for private
leaks, count mismatches, duplicate labels, malformed behavior/process records,
and orphaned observations before the clean artifacts are used as public
reimplementation tests.

No repository or distribution may contain:

- Original Halo CE binaries, maps, assets, CD keys, registry secrets, or installer payloads.
- Decompiled bodies, copied pseudocode, original instruction byte dumps, or proprietary instruction/control-flow expression inside blocks.
- LLM-generated or human-written algorithm walkthroughs that mirror proprietary
  control flow rather than stating observable behavior.
- Private harness internals when publishing them would reveal proprietary expression rather than behavior.

Ghidra, radare2/rizin, LLVM, Frida, and debuggers are discovery tools. The
correctness oracle is execution of the original PE runtime, identified by
module SHA256 and RVA, under declarative Wine prefixes and targeted private
harnesses when process-level tests cannot reach a routine. Specs and tests refer
to stable labels first; private tooling keeps the label-to-oracle-address
mapping needed for validation.

See `docs/internal-routine-contracts.md` for the detailed policy on sanitized
internal APIs and LLM-assisted routine descriptions.
