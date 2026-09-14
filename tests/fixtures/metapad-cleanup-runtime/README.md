# Complete cleanup adapter integration fixture

The retained 35 transfer rows belong to the actual Metapad `0x55b7` operation.
`inputs.json` retains their original plan identity, the existing resolved external
environment and object-authority input, and an updated binding for the current
ordinary-C interface. Copy now returns its projected EAX reference; release
returns its scalar result. The older interface is retained only as a rejected
ABI control. These are test inputs, not new proof or activation receipts.

The integration test regenerates the complete production overlay and compiles it
with `metapad-authored-call/cleanup.c`, current portable reference helpers, and
actual native allocation/resolve/realize/release functions. The runtime fixture
calls PE32 Wine `GlobalAlloc`, `GlobalFree`, `lstrlenA`, `lstrcpyA` and `SetFocus`.
It checks six complete source-operation executions: empty and short strings,
one and two CR/CR/LF removals, and injected allocation failure with empty and
nonempty input. It checks resulting bytes, counts, service order, return-stack
transport and expired scratch references after successful release.

Notice delivery is suppressed and the focus target is null. Resource and message
services must not be called. Static image references and memory admission use
fixture implementations, not a mapped original application or qualified loader.
Allocation failure in these two operation cases is injected; actual maximum-width
Win32 failure is covered separately by the existing issued-reference contract
integration test. Finite cases do not prove local original-code equivalence,
universal lifetime/frame behavior, UI callback compatibility or real caller
admission. Reconstructed references are never treated as evidence of contents.

Negative controls change the ordinary-C allocation flags, omit native release
registration, and combine the current adapter with the older service table ABI.
