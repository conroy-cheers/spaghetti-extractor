# Shared palette effects boundary

Five complete original entries are selected: fade `0x402770..0x402a4a`, right
shift `0x402a50..0x402af0`, left shift `0x402af0..0x402b95`, sequence rotation
`0x402ba0..0x402c03`, and RGB update `0x402c10..0x402c55`.
The pinned image is SHA-256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Original application source is not an input. The retained disassembly and real
machine entries supply the oracle.

The component borrows the existing `pcx_state` current/staged palettes and
`flow_state.windowed`. They are the same objects used by the image loaders,
animations, scenes and frame logic. Both palettes contain 256 four-byte entries.
All their bytes are observed; RGB arithmetic never silently resets flags.
Windowed mode is exactly one; other nonzero modes still execute these bodies.
The mode test occurs at entry, not on every fade iteration.

Palette index/ranges refer to live entries. Shifts admit first <= last; fade
also admits an empty range with first == last + 1 and first <= 256. Its zero-count
upload remains observable. Rotation borrows a disjoint live array of at least
`count` uint32_t values, with 3 <= count <= 66 in the retained cases. It rotates
three words, including when the word count is not divisible by three; the next
three low bytes form a single RGB entry. No pointer narrowing or reconstructed
storage is used by C. Cases preserve guards around the entire sequence.

`apply` publishes the selected current-palette range and `wait` invokes the
application's existing wait helper. Their ordered inputs, before/after memory
and callback mutations belong to the boundary. Return statuses are ignored by
the original. These are component services, not a DirectDraw emulator: the
normal consumer delegates to the actual palette object and native wait helper.
Local adapters bind those same machine calls to controlled callbacks. Callback
mutations may change palette bytes and mode, but not replace the borrowed objects
or destroy their storage while a call is active. No asynchronous palette writer
is claimed. The MIDI worker owns different storage.

Fade retains byte wrapping, signed step comparison, direction 0/1 versus other
values, and the last unchanged publish/wait iteration. Positive steps normally
converge. Zero/negative steps can diverge in the original; retained cases either
start converged or use an explicit callback that makes the next iteration
converge. Finite comparisons are experimental evidence, not termination or
whole-program equivalence proofs. Palette creation, clocks, raster helpers and
the full source-program assembly remain separate dependencies.
