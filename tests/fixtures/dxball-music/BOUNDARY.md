# Music controller boundary

Oracle: pinned DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Play is `0x402100..0x402197`, resume `0x4021a0..0x4021c8`, pause
`0x4021d0..0x4021f2` and stop `0x402200..0x40223e`. The shared current
record is the pointer at `0x42c144`. Each native record has a stream pointer
and a playing word; portable C uses a typed object rather than PE32 layout.
No original application source is used.

Record allocation/disposal and the existing MDS library's load/start/pause/stop/
release operations are application/runtime service boundaries. The controller
requests the original eight-byte record allocation; the adapter represents that
logical record with the host's typed storage. The filename is a readable terminated
string, retained through synchronous calls. The library stream is opaque here.
These service scenarios do not implement WinMM, MIDI scheduling or file mapping.
Those platform facilities remain the responsibility of a shared environment.

Services may change the current root and records synchronously. All later reads
reload the current root as the machine does. Every dereferenced current record
must remain live and nonnull, including after a successful load/start/pause and
between stop/release calls. Live aliases and historical playing words are preserved.
A failed load may receive a null allocation and then free null; successful loading
through null would fault and is outside this typed domain. Failed stream start
releases the current stream then frees the current record. Failed stop/release
results are ignored. A free callback may change the root, which is then still
cleared by the controller. Released or freed storage is observed through retained
fixture bookkeeping, never assumed to remain dereferenceable in production.

Local cases provide explicit record/stream identities, mutable state, disposal
histories and service outcomes, including callback-driven root redirection.
The lower library implementation and asynchronous MIDI callbacks are not qualified
by these cases. Normal integration must use the actual retained library services;
standalone consumers use the declared controlled application services. Finite
comparisons do not establish arbitrary unsafe heap behavior or a complete portable
game, and do not authorize strong activation.
