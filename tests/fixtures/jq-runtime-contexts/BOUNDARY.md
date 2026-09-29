# jq numeric contexts and seed lifetime

Seven original entries share one module's decimal/dtoa thread-local context
registries and process seed. Ordinary C owns the pthread keys, once state,
initialization, cached pointers and destruction. Returned pointers refer to real
allocated objects with the pinned decContext/dtoa_context layouts. A pointer is
borrowed until the owning thread exits or explicitly finalizes that context.
Successive callers on the same thread share sticky status and dtoa caches;
different live threads have distinct contexts. A reconstructed address does not
establish any of these properties.

The original private decimal getter accepts its one module key. The native
adapter checks that exact key identity and returns the component's live context;
the old key's bytes are not cloned into a new registry. Init entries are preserved,
including their original repeated-key-creation behavior. Call them only at runtime
startup, before any context is allocated. Finalization requires initialized keys.
After finalization, a getter lazily allocates another object under the same key.
Worker exit and process exit remain distinct cleanup paths.

Pthreads, allocation, the runtime's exit-callback registry and conversion/decimal
libraries remain executable services. Native replacements register callbacks in
the same DLL registry as their neighbors; the standalone build shares its CRT
registry. Moving a callback to an unrelated executable registry changes ordering.
The decimal allocator is unguarded and may return NULL; dtoa allocation uses the
existing guarded jq allocator. Destruction uses that same allocation identity.
The original seed algorithm reads four bytes from /dev/urandom, or uses the XOR
of its process id and 32-bit time if open/read fails. Read bytes are interpreted
little-endian explicitly. Closing the descriptor happens even after a short or
failed read. Successful once-initialization preserves the seed for all callers.
Native comparison supplies the same deterministic entropy interactions to both
sides; this does not claim identical random values in independent processes.

The native replacement disables all selected entry bodies plus private seed
initialization and dtoa destruction. It runs before any worker or tested context
exists. Real numeric/serializer consumers, mutable status, identity, heap effects,
thread cleanup and complete process teardown are observed. Process restart is the
only fixture reset. OS key numbers and addresses are not compared across runs.

This is source-assisted from pinned jq 1.8.1 under COPYING. The profile excludes
invalid/cross-thread pointer use, concurrent finalization of a context, cancellation,
DLL unload/reload, and exhaustive pthread/atexit failures. Finite observations and
declared state ownership remain distinct from formal qualification.
