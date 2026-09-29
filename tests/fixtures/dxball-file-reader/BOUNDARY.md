# DX-Ball file reader boundary

The oracle is the pinned PE32 image SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`,
entry `0x40d9f0..0x40db13`. Its embedded fallback prefix at `0x416064`
is `..\`. No original application source is used.

The filename is a readable terminated string. If the first open fails, its length
is at most 256 bytes so the prefix and terminator fit the original 260-byte stack
buffer. The original prefix remains those four bytes during the call; changing
that global requires a revised input mapping. Filename storage does not overlap
writable input buffers or provider outputs. The implementation is synchronous.

The second argument supplies a buffer; the third is a nonzero allocate flag,
not an offset or an ownership promise. Supplied and allocated buffers have
readable/writable storage for the requested read. Null is admitted for a zero-byte
read. Providers retain the bytes untouched by a short or failing read. Allocation
and disposal are explicit runtime services, with object identity and retained
bytes; disposal may receive a supplied buffer. Access after disposal is outside
this typed input domain. The retained backing storage used to observe disposal
is a fixture premise, not evidence that an arbitrary freed native heap stays live.

GetFileSize's low word is passed straight to allocation and ReadFile, including
`0xffffffff`. The read count is ignored. Successful short reads therefore return
the destination without filling its remaining bytes. Allocation failure leaks
the open handle. Read failure frees the destination, even when supplied by the
caller, and also leaks the handle. CloseHandle's result is ignored. These are
preserved native behaviors, not repaired by the C or shared environment.

The component owns the fallback, allocation decision and cleanup policy. Win32
arguments, contents, error/output schedules, handle identities and lifetimes
come from the shared candidate-neutral Wine backend. The local tests admit its
synchronous read-only file profile and explicitly initialized buffer contents.
Output-count partial-write experiments belong to the generic backend consumer;
the reader does not use that word, so its cases use complete count outputs.
Comparisons establish finite experimental behavior, not universal qualification
or a complete standalone game runtime.
