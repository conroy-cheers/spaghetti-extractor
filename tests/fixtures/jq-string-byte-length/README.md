# Lift a lower string operation without making its adapter recursive

This operator trial replaces the retained `jv_string_length_bytes` dependency of
the existing jq string subsystem. The C implementation is small; establishing a
nonrecursive executable boundary is the useful part of the trial.

The previous shared `contents` adapter obtained length by calling this function.
Reusing it for the new component would call the replacement recursively. The
contract alone did not expose that implementation dependency. The reviewed
[shared string view](../jq-string-slice/string-storage.h) now reads the existing
allocation directly. Slice, codepoint length and byte length reuse that one
layout definition and the existing contents/release contracts. The algorithm
does not know the native object layout. [BOUNDARY.md](BOUNDARY.md) records its
inputs, native body, aliases, lifetime and exclusions.

Current workspace guides link `contents` to its C implementation and show its
written calls. The older adapter exposes `jv_string_length_bytes`; the current
adapter links `spx_jq_string_contents` to `headers/string-storage.h`. Use public
status after source edits to refresh these locations. This is a source-navigation
aid; it does not resolve macros/indirect calls or establish independence itself.

This requires ordinary C adapter work and a source-program symbol binding, with
no changes to the checker, artifact formats or compiler infrastructure. The
layout was established using pinned native disassembly and source assistance;
this is not automatic recovery or an independent human usability study.

The current preparer uses `native_entry_header` to derive entry-hook glue from the
pinned DLL and this operation's reviewed RVA range. The driver no longer repeats
the opcode prefix, saved-body storage or trap checks. That shared authoring helper
does not infer the operation's extent, signature or live-state behavior.

## Reproduce and edit

Enter `nix develop .#lifting`. Supply a pinned string-length workspace, as
prepared by the [existing recipe](../jq-string-length/README.md), for reusable
contracts, tools and native libraries. Use a newly prepared workspace containing
`headers/string-storage.h`; an older workspace whose `contents` adapter calls
byte length needs the shared adapter migration first. Review that implementation
through `component status` before reuse. Then:

```sh
python tests/fixtures/jq-string-byte-length/prepare.py build/length build/bytes-package
spaghetti-extractor component start jq string-byte-length \
  --comparison-package build/bytes-package/string-byte-length --output build/bytes
spaghetti-extractor component status jq string-byte-length --comparison-package build/bytes
spaghetti-headless-wayland spaghetti-extractor component check jq string-byte-length \
  --comparison-package build/bytes --output build/bytes-check
spaghetti-extractor component status jq string-byte-length --comparison-result build/bytes-check
```

For your own project, copy `prepare.py`, `length.c`, `driver.c` and `BOUNDARY.md`
into one directory and enter `nix develop /path/to/spaghetti-extractor#lifting`.
Run the local `prepare.py` with the reviewed workspace path. The installed
`retained_service_inputs` helper supplies explicitly selected service definitions,
transports, bindings, C adapters and runtime files. Preparation reads no sibling
fixture directories. The new interface, native entry, resource observations and
cases remain explicit in the local recipe.

Shared value and string-view declarations now come from those selected services.
The local `component_interface` call declares only its signed length result; it
does not copy the previous component's type schema. The builder checks exact
agreement when services share a type and reports conflicting declarations by
origin. This authoring simplification preserves this recipe's existing interface,
service contracts and generated C.

Edit `build/bytes/source/length.c` using its generated editor configuration.
The prepared cases cover cached/uncached string hashes, unique/shared references,
embedded NUL, malformed bytes and actual interpreter consumers. They observe
returned lengths, retained contents/references and allocation lifetime. Source
execution traps the complete original byte-length body.

The complete local workflow is:

```sh
spaghetti-headless-wayland python tests/fixtures/jq-string-byte-length/walkthrough.py \
  build/length build/bytes-workflow
```

It starts and inspects a workspace, checks a compatible edit, reuses an unaffected
codepoint-length neighbor, diagnoses an omitted release, replays the failure
after repairing the editable C, and reuses the repaired result. The defect keeps
all returned lengths correct; retained reference counts, allocation observations
and lifecycle diagnostics detect it. Only one file compiles for the local edit.
Neighbor reuse applies to its unchanged retained fixture. Adopting the new shared
adapter changes that fixture's inputs; the affected slice/codepoint suites were
separately prepared and rerun. Program integration also reruns affected consumers.

## Integrate through the source program

The reviewed jq source recipe accepts the byte-length binding alongside the
existing connected storage/path network and codepoint-length selection:

```sh
python tests/fixtures/jq-portable/prepare.py \
  --comparison build/jq-portable-subsystem-2026-09-22/workflow-v3/network-edit \
  --extra-comparison build/component-workspace-2026-09-22/public-workflow-v3/local-repaired \
  --extra-comparison build/bytes-workflow/repaired \
  --original-derivation build/jq-portable-subsystem-2026-09-22/original-derivation.json \
  --output /tmp/my-jq-with-byte-length
```

Follow the [portable build/run instructions](../jq-portable/README.md). Preparation
removes the original source definition and supplies the selected C binding. The
shared view works with both the native DLL and the reviewed source backend;
other target layouts need an explicit adapter. A changed selection needs fresh
assembly review. Subsequent compatible edits use `candidate export --update`.

Evidence is retained under `build/jq-string-byte-length-2026-09-23/`, including
disassembly, inputs, local commands, rejected edit and separate phase costs.
The local sequence passes in 30.458s; the compatible edit compiles one file and
the unchanged neighbor does zero compiler/link/execution/model/solver work.
Both x86-64 and AArch64 under QEMU pass the existing 61 CLI, 32 live-value and seven
allocation-failure comparisons. The new operation executes 8,697 times in each
CLI run. The affected existing slice/codepoint comparisons and seven repository
gates also pass. No extraction/proof pilot is rebuilt.

The subsequent service-input handoff in
`build/component-service-inputs-2026-09-23/` uses those four files in an external
project, with test-fixture imports and Python checkout reads blocked. The new
preparation reproduces all 37 package files exactly. Public start/status and the
existing native interpreter case pass; the same helper preserves DX-Ball's
context-bearing blit service and passes its eight retained-C cases. The combined
sequence takes 8.088s. It changes no program inputs, so the earlier integration
receipts remain applicable; no additional program or pilot rebuild was needed.

First boundary analysis and adapter work are distinct from warm edit timings.
The larger jq parser/VM, non-array objects, allocator and other runtime services
remain the explicit unlifted backend. Finite comparisons do not establish a
complete jq lift or stronger qualification.
