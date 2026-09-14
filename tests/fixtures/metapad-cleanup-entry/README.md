# Retained Metapad cleanup entry

This fixture compares the actual entry at RVA 0x55b7 with the ordinary C in
`../metapad-authored-call/cleanup.c`, stopping at the existing loop cut 0x5606.
The exact slice is retained from the executable transfer plan whose digest is
recorded in `component-exact-c-slice-v1.json`. Its forced outgoing label is a
proof barrier. The original and authored prefix contain length, allocation,
length, and the signed-length-controlled two-copy path.

The comparison is conditional on a readable nonwrapping text span containing a
NUL at the returned length; deterministic, readonly length calls; and a nullable
fresh, disjoint, zero-filled allocation of length + 1 bytes. The fresh storage
is inaccessible before allocation. Zero extent represents failure in this local
view relation, not a qualified portable null-reference ABI. The native length
IAT slot contains an arbitrary nonzero target with the declared stdcall behavior.
Service call order, actual arguments, caller-clobbered registers and stack pops
are checked. The incoming direction flag is a native bit (either zero or one),
and the complete undeclared machine frame is preserved. Concrete IAT/service binding and allocation lifetime qualification
remain separate obligations.

Arbitrary initial text/public bytes are shared through the same uninterpreted
function. Two sparse writes suffice for this finite prefix; capacity and loop
unwinding assertions are part of the complete query. The outgoing observer
checks cursor/count values and every view field. The query checks faults, the
whole public post-memory, saved frame and the loop's cursor/zero-suffix domain.
The source footprint admits no unmodeled context reads, descriptor stores or
services. It is not a functional proof by itself.

This remains a proof region within the cleanup authoring component. Neither a
successful query nor source correspondence authorizes activation or establishes
whole-component coverage. The companion loop proof must still be composed with
this entry and the remaining tail through checked evidence and runtime contracts.
