# External Operations

Imports, vtable calls, callbacks, resolver-returned function pointers, and
resource handles are represented as machine-level external operations. The
generic model records call identity, ABI, arguments, pointed-to memory,
permitted writes, return values, resource updates, and callback behavior.

## Recognition

Direct imports come from the PE import table. Indirect operations require value
provenance that can identify import slots, COM/interface table offsets, callback
registrations, linked-library tables, or bounded custom dispatch sets. SDK and
library catalogs map those identities to source-level names and types.

A known COM slot can therefore render as an idiomatic call such as
`IDirectDrawSurface_Lock(...)`; an import cached in `edi` can render as
`MessageBoxA(...)`; and a nullable writable slot can render as a typed optional
callback. Concrete pointers and handles remain runtime values, not static type
tags.

## Qualification

Catalog rendering is non-authoritative. Candidate qualification still requires:

- an exact import/interface/catalog identity;
- a checked calling convention and argument layout;
- bounded memory read/write footprints;
- preserved/clobbered register information where machine adapters remain;
- explicit out parameters and callback targets;
- resource creation, use, and release consistency;
- a candidate runtime adapter or linked implementation.

Unknown or ambiguous calls remain `incomplete`. The initial candidate may use
exactly corresponding APIs and call order to reduce risk. Later refactors can be
validated against the established source baseline with broader regression tests.
