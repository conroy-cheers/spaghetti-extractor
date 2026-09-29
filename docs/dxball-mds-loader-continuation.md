# DX-Ball MDS loader continuation

The file/memory loader is now 34 lines of ordinary C in
[`loader.c`](../tests/fixtures/dxball-mds-loader/loader.c), replacing the complete
body at `0x401a20..0x401b60`. It composes two independently lifted dependencies:
loader → container parser → event expander. The shared info/header definitions
and both neighboring implementations are reused. No original application source
was consulted.

The [boundary](../tests/fixtures/dxball-mds-loader/BOUNDARY.md) distinguishes the
caller-owned output slot, filename or memory input, newly allocated info object,
mapped file bytes and persistent buffer allocations. Failure preserves the output
slot; success publishes the new info before file cleanup. Parser failure frees
info before unmapping, then closes mapping and file handles in order. Cleanup
failures are ignored by the original and retained by the C. The adapter snapshots
info while live and does not infer readable memory from historical pointer words.

All 41 local cases match the first C unchanged. Each of the six bundled music
files runs through both file and memory paths. Generated cases cover invalid and
ignored flag bits, allocation/open/mapping failures, failed size queries, malformed
input, partial parsing, failed cleanup and repeated output-slot updates. Clearing
the output slot on failure is deliberately introduced and caught by one local
replay. Successful parsing still requires the declared readable backing and
header geometry from the existing parser boundary.

Both x86-64 and emulated AArch64 source consumers pass. The selection now contains
43 components, 159 entries and 997 retained cases. All 42 preceding implementations
remain unchanged. Forty component records remain identical; the parser and event
expander's comparison references bind the new enclosing consumer. Their source
and object contents are reused, along with every preceding consumer binary.

Normal execution reaches the loader through the actual music controller, then
uses the selected parser and expander before the native MIDI lifecycle consumes
the buffers. All 64 frames, all 41 preceding observation fields, the added loader
results and all 766 platform interactions match. No end-to-end behavioral C
correction was needed. The normal check compiles three affected translation units
and reuses 90 objects. All Wine runs use the headless Wayland desktop.

No checker, compiler, artifact-format or shared-backend change was needed. The
platform environment continues to see candidate API calls; target adapters own
layouts and boundary identities. This demonstrates practical composition across
three components, with executable comparisons and portable source consumers.
Optional formal source eligibility remains incomplete and grants no strong
activation authority.

The [fixture README](../tests/fixtures/dxball-mds-loader/README.md) contains the
public preparation, comparison, defect replay, assembly and normal-run commands.
`build/dxball-mds-loader-2026-09-29/validation.json` records exact source bindings,
separate preparation/compiler/execution/link costs, export reuse and dirty-tree
preservation. Repository metadata, production Python lint and format-registry
checks pass.

Next are info release, stream start/pause/stop and completion callbacks. These
should use the existing shared storage/MIDI services and current object boundary.
A complete standalone game and production portable platform backends remain
outstanding. The full DX-Ball lifting goal stays active.
