# Clean-Room Boundaries

This stage produces a detailed private catalog/spec/test corpus first. A later
cleanup pass can strip or aggregate that corpus into a safer public
distribution.

The detailed private corpus may contain:

- Binary filenames, SHA256 hashes, sizes, PE metadata, section names, RVAs, imports, exports, resource hashes, and role labels.
- Function labels, inferred signatures, calling conventions, side-effect tags, block identities, CFG edge identities, call edge identities, and data-reference addresses.
- Behavior-derived detailed specs, fixtures, mocks, and tests.
- Coverage ledgers that identify original module SHA256 plus RVA and map those private oracle addresses to stable labels.
- Waivers with evidence, reviewers, and revalidation triggers.

A sanitized public distribution should prefer:

- Stable 1:1 labels over raw RVAs.
- Human-readable module, function, block, edge, data-structure, global, endpoint, and test names where possible.
- Behavior-derived specs/tests that do not require readers to inspect private decompiler artifacts.

No repository or distribution may contain:

- Original Halo CE binaries, maps, assets, CD keys, registry secrets, or installer payloads.
- Decompiled bodies, copied pseudocode, original instruction byte dumps, or proprietary instruction/control-flow expression inside blocks.
- Private harness internals when publishing them would reveal proprietary expression rather than behavior.

Ghidra, radare2/rizin, LLVM, Frida, and debuggers are discovery tools. The
correctness oracle is execution of the original PE runtime, identified by
module SHA256 and RVA, under declarative Wine prefixes and targeted private
harnesses when process-level tests cannot reach a routine. Specs and tests refer
to stable labels first; private tooling keeps the label-to-oracle-address
mapping needed for validation.
