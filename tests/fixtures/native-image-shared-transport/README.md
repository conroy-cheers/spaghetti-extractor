# Retained Metapad image origins for native logical transport

`reference-authority.json` is copied byte-for-byte from the retained v15 provider's
`proof-diagnostics/reference-authority.json`; its SHA-256 is
`a3b250527dd5006b3175e6511f7c5bef37a5a8b72aaa71fd706ad29bcc1d3fdc`.
It binds the original Metapad image and all four image-section origins.
The native-image logical-transport tests execute the production image locator,
resolver and realizer with these rules and the generated logical-call adapters.
Module and buffer are interior views of section 2, not separate native objects.

Those tests use a minimal context with no external allocations, controlled raw
memory and a controlled service. A symbolic byte offset spans the complete
500-byte buffer. They check current aliases across two calls, descriptor
corruption, bounds and rejection after image remapping or removal. They do not
establish actual loader teardown, native memory admission, LoadStringA semantics,
stdcall transport, caller reachability or runtime qualification.

These additional inputs live outside the common resource-text fixture so edits
to native-namespace evidence do not invalidate unrelated shared-buffer tests.
