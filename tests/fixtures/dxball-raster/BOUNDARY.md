# Line rasterization and rectangular fill

Complete pinned bodies `40d850..40d981` and `40d990..40d9f0` use the existing
surface identity, pixel view and rectangle types. Binary SHA-256:
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
No original application source is consulted.

The line obtains a description, ignores its status, retries Lock until status is
exactly zero, and uses the *post-lock* pitch and pixels. It writes one byte per
iteration and always calls Unlock, ignoring its status. Coordinates, deltas,
errors and strides wrap at 32 bits. The two major-axis branches use different
strict thresholds; conventional Bresenham or endpoint interpolation is not an
equivalent replacement. INT32_MIN negation remains wrapped.

The caller supplies live surface storage covering every actual computed address.
Coordinates need not lie within nominal dimensions: existing padding and negative
pitch are valid transported storage. The C computes offsets as integers and forms
only pointers used by actual writes; it does not clip or form a pointer after the
last write. Arbitrary invalid addresses and never-successful locks require a
different outcome experiment. Uninitialized descriptor fields unconsumed by the
API flags are preserved by transport and excluded from API observations.

Fill sends the four coordinates unchanged, a 100-byte effects descriptor,
COLORFILL and the full 32-bit color. Only the fields consumed by those flags are
inputs; unrelated native stack bytes are not invented C state. The result is
ignored. Rectangles are not reordered or clipped by this component.

Platform behavior comes from the shared candidate-neutral DirectDraw backend.
Target adapters define surface correspondence and caller inputs, not COM vtables
or pixel-fill emulation. Observations retain whole seeded backing storage,
including padding, and ordered API calls, outputs, lock state and failures.
These are executable comparisons, not universal platform qualification.
