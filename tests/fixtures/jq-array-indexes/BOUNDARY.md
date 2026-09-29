# Consuming array subsequence search

Original: pinned jq 1.8.1 PE32 libjq, SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
`jv_array_indexes` owns RVA `0x2c226..0x2c5e3`, through the final return.
The local source-side entry hook traps that complete body. Native disassembly
and the retained patched jq source assisted this manual lift; see COPYING.jq.

Consume one live array reference for each parameter and return an owned array of
numeric match positions. Distinct owned references may share an allocation;
elements may themselves be shared arrays, objects or strings. Existing array
lengths fit signed 32 bits. Invalid descriptors, corrupt storage and concurrent
mutation are outside this boundary. Retained aliases keep contents and lose only
the references consumed by the call. No exclusive-access rule is imposed.

Keep the pinned operation's empty-pattern result (empty), overlapping positions,
invalid out-of-range element comparisons and complete inner traversal after a
mismatch. Read the pattern element before the candidate element, then call the
consuming equality service. Preserve 32-bit index addition with defined C.
The result array is created before length reads; release value then pattern.

Services reuse the network's exact copy, length, array-get and release contracts.
Native equality, result creation, numeric construction and append remain explicit
lower services. Local checking uses native array services; connected checking
also selects the existing authored storage under the surrounding value/path
consumers. Selection and C bindings are reviewed separately from signatures.

The C driver observes results, retained input contents/reference counts and live
allocations after cleanup, including alias and actual interpreter contexts.
Allocation failures/nonlocal exits are declared but not covered by this trial;
returning handlers, arbitrary callbacks, reentrancy and concurrency remain outside
its execution scope. Finite comparisons provide no strong qualification.
