# DX-Ball MDS parser continuation

The container parser is now 57 lines of ordinary C in
[`parser.c`](../tests/fixtures/dxball-mds-parser/parser.c), replacing the complete
body at `0x401b60..0x401d5d`. It shares its event descriptor and invokes the
independently lifted `mds-events` component through a declared service dependency.
No original application source was consulted; the implementation follows the
pinned PE32 instructions and binary assets.

The [boundary](../tests/fixtures/dxball-mds-parser/BOUNDARY.md) exposes the info
object, typed header collection, payload bytes and explicit allocation services.
Target transport relates these to the native contiguous headers without putting
PE32 pointer arithmetic into the implementation. Allocator history, uninitialized
fields and opaque historical pointer words remain explicit. The original chunk
bounds and unsigned arithmetic are preserved, including paths that read beyond
an incorrectly declared length where physically readable backing is supplied.

All 42 local cases match the first C unchanged, including all six music files.
Failure cases exercise partial metadata and payload writes, allocation and lock
failures, leaked allocations, repeated parsing, failed unlock/free and dangling
buffer references after cleanup. A deliberate cleanup that clears the dangling
pointer is caught by one local replay. Successful locks require complete storage
for the admitted header geometry; these comparisons do not cover arbitrary
faulting pointers or concurrent mutation.

Both x86-64 and emulated AArch64 source consumers pass. The selection now has
42 components, 158 entries and 956 retained cases. `candidate apply` preserves all
41 preceding implementations, 135 objects and 48 consumer binaries on both
architectures. Forty component records remain identical; only the event expander's
comparison reference is rebound to the new parser consumer. Its interface,
implementation and object are unchanged. The shared backend is also reused.

Normal execution reaches the parser through the actual file loader, expands 25
buffers and consumes them through the native MIDI lifecycle. Both candidates
match all 64 frames, all 40 preceding observation fields, the added parser results
and all 766 platform interactions. No end-to-end correction to the parser C was
needed. The comparison compiles three affected translation units and retains
88 objects. Reports remain below the existing 8 MiB limit.

No workbench internals or shared platform extensions were needed. The practical
executable profile supports this component; its optional formal source profile
remains incomplete. The comparisons provide experimental evidence, not a checked
universal heap summary or strong activation authority.

Reproduction commands are in the [fixture README](../tests/fixtures/dxball-mds-parser/README.md).
Evidence under `build/dxball-mds-parser-2026-09-29/` includes the local comparison,
deliberate defect, normal comparison, both export receipts and phase timings.
`validation.json` records exact input binding, reuse and dirty-tree preservation.
Repository metadata, production Python lint and format-registry checks pass.

The remaining MDS loader, release, stream start/pause/stop and completion callback
are the next connected units. Their shared storage and MIDI APIs already exist
in the candidate-neutral test environment. Production portable platform backends
and a complete standalone game remain outstanding; the full goal stays active.
