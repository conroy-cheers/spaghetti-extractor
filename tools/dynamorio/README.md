# WinCR DynamoRIO Trace Client

`halo_trace` is the private bulk coverage collector for the clean-room catalog.
The library name remains for compatibility, but the JSONL format and ingestion
commands are target-neutral.
It emits newline-delimited JSON records for:

- module loads, including module path and SHA256 when the file is readable;
- deduplicated dynamic basic blocks;
- deduplicated taken CFG edges for direct branches, conditional branches,
  conditional fallthroughs, indirect branches, and call transfers;
- deduplicated direct and indirect call edges when DynamoRIO exposes the runtime
  target;
- optional block-conformance state records when the runner is invoked with
  `--block-state-trace`. These emit `block_entry` and `block_exit` records with
  register/flag state and a small stack window. `block_exit` is emitted at the
  next traced block entry, which captures the post-state at the control-flow
  boundary for the previously executed block. `block_exit.side_effects` now
  includes bounded byte-level memory reads, memory writes with before/after
  bytes, and call-boundary records with callee module/RVA, export symbol when
  resolved from the module's ELF/PE export tables, semantic class, operation,
  sampled stack arguments, return values, thread error-state before/after
  (`errno` on native Linux, Win32 last-error in the Windows client), post-call
  stack words, Win32 handle/resource identity for decoded file, std-handle,
  window, DC, and GDI-object lifecycle APIs, per-argument resource refs for
  multi-handle calls, typed drawing effects for decoded GDI draw/blit/text/pixel
  calls, typed framebuffer/presentation geometry for decoded `BitBlt`,
  `StretchBlt`, `PatBlt`, `SwapBuffers`, `SetDIBitsToDevice`, and
  `StretchDIBits` calls, GDI DIB pixel-transfer effects for `SetDIBits`,
  `SetDIBitsToDevice`, `StretchDIBits`, and `GetDIBits` with bitmap header
  and pixel payload sample/digest evidence, `CreateDIBSection` bitmap creation
  with `BITMAPINFO` and returned pixel-pointer evidence, semantic
  `gdi_bitmap_pixels` region labels on later memory reads/writes into that
  mapped pixel range, typed message effects for decoded user32 message-loop APIs, and
  typed registry effects for decoded advapi32 key/value APIs, typed window
  lifecycle/state effects for decoded create/destroy/show/update user32 APIs,
  client-rect/invalidation/quit-message effects for decoded window APIs,
  typed per-window long-slot mutations for decoded `SetWindowLong*`/
  `SetWindowLongPtr*` APIs, including WndProc subclass registration,
  typed paint effects for decoded `BeginPaint`/`EndPaint` HWND/HDC/
  `PAINTSTRUCT` transitions, typed input effects for decoded key-state,
  cursor-position, and raw-input registration/read APIs, typed audio-output effects
  for decoded `PlaySound*`/`sndPlaySound*`/`MessageBeep` and WinMM
  `waveOut*` device/header/payload APIs, typed timer effects for decoded
  `SetTimer`/`KillTimer` creation/destruction obligations for window and thread
  timer targets, non-null `TIMERPROC` callback entry context, typed
  time/scheduling effects for decoded tick/performance-counter/timeval/sleep
  APIs, typed process command-line, environment-variable,
  environment-expansion, current-directory, and temp-path effects for decoded
  process APIs, process-termination effects for non-returning `ExitProcess`,
  typed process-creation effects for decoded `CreateProcess*`, `WinExec`, and
  `ShellExecute*` APIs, including launch strings, current directory, creation
  flags/show command, custom environment-block digest, startup-info digest, and
  returned child process/thread handles and IDs where the API exposes them,
  typed Winsock/network API effects for decoded `WSAStartup`, `WSACleanup`,
  `socket`, `accept`, `closesocket`, `connect`, `bind`, `listen`, `shutdown`,
  `send`, `recv`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`,
  `ioctlsocket`, `getsockname`, and `getpeername` calls, including Winsock
  startup/cleanup state, socket resource identity, WSADATA/payload/address/
  option/ioctl buffers, transfer counts, and socket/network/caller-buffer
  mutation flags,
  typed file effects for decoded `CreateFile*`, `GetStdHandle`, `ReadFile`,
  `WriteFile`, `FlushFileBuffers`, file-size, file-pointer, EOF, file-info,
  and file-type APIs, including target/result resources, transfer counts,
  file-size/position evidence, and data/position/size/caller-buffer mutation
  flags,
  typed heap, virtual-memory, CRT, and Local/Global allocation/free/size/lock/
  protection effects for decoded `GetProcessHeap`, `HeapAlloc`,
  `HeapReAlloc`, `HeapFree`, `HeapSize`, `VirtualAlloc`, `VirtualFree`,
  `VirtualProtect`, `malloc`, `calloc`, `free`, `_msize`, `Local*`, and
  `Global*` APIs with semantic region labels on later memory reads/writes into
  byte-addressable allocated ranges, typed thread last-error effects for
  decoded `GetLastError`/`SetLastError` Win32 reads/writes and
  `WSAGetLastError`/`WSASetLastError` Winsock reads/writes, typed thread
  effects for decoded `CreateThread` and `WaitForSingleObject*` handle/timeout
  obligations, thread-start callback entry context for observed `CreateThread`
  start routines, typed dynamic-loading effects for decoded `LoadLibrary*`,
  `GetModuleHandle*`, `GetProcAddress`, and `FreeLibrary` module/export
  obligations, typed COM/vtable dispatch effects for unresolved calls into
  DirectX-style modules such as `dsound`, `dinput`, `ddraw`, `d3d`, and `dxgi`,
  including receiver, vtable pointer, matched slot, vtable-prefix digest,
  subsystem, return value, DirectSound/DirectInput/DirectDraw/D3D8 method
  candidates or exact methods, semantic method kind, ambiguity marker, known
  COM receiver interface, exact method name when object provenance proves it,
  factory/object-output provenance, IID-based `QueryInterface` propagation, and
  bounded method-local before/after buffer evidence for known audio/input/
  graphics pointer arguments, including D3D/DirectDraw lock-output structures
  and mapped payload bytes submitted at unlock when the lock size is known or
  can be derived from D3D resource geometry,
  typed synchronization effects for decoded event/mutex/
  semaphore create/open/state APIs and `WaitForMultipleObjects*` handle-array
  wait evidence, typed GDI DC-state effects for decoded
  `SelectObject`/`SetTextColor`/`SetBkMode`,
  typed window-class registration
  effects for decoded `RegisterClass*`/`UnregisterClass*` class metadata and
  WndProc callbacks, typed WndProc entry callback effects with HWND/message/
  WPARAM/LPARAM context for registered and subclassed window procedures, typed timer callback
  effects with HWND/message/timer-id/elapsed-time context, typed cursor resource
  effects for decoded `LoadCursor*`, plus before/after samples and full-buffer
  SHA256 digests for decoded pointer buffers. Unknown
  external APIs, APIs without a semantic decoder, unresolved handles/resources,
  incomplete drawing/message/registry/window/window-long/paint/input/raw-input/audio/timer/time/thread-error/process/network/memory/dynamic-loading/thread/synchronization/GDI-state/class/cursor effects,
  unreadable pointer buffers, and truncated samples without full digest evidence
  remain partial side-effect models. Memory writes are completed at the instruction post hook when
  available and again at block/thread exit as a boundary fallback, so ordinary
  post-callback misses do not leave write effects pending.
- syscall external events with syscall number, semantic class, operation,
  arguments, whether a result is expected, result, errno, fd/resource identity,
  path arguments, returned fds, socket resource identity, network payload and
  sockaddr samples, decoded pointer-buffer samples, typed iovec element samples
  for scatter/gather file I/O, and bounded `msghdr` header/name/control/iovec
  samples for `sendmsg`/`recvmsg` and bounded `mmsghdr` batches for
  `sendmmsg`/`recvmmsg`, plus request-shaped `ioctl` samples for encoded
  `_IOC` buffers and selected tty/FIONREAD/FIONBIO/socket-ifreq legacy requests.
  Pointer-buffer records include bounded inline samples and full-buffer SHA256
  digests when the entire pointed-to memory range is readable. Overflow syscall
  pointer-buffer samples are retained in `buffer_aggregate` with source/index
  metadata and before/after SHA256 transition evidence when readable. Whole
  API-call and syscall events that exceed the inline fast-path arrays are
  retained as exact overflow records; `api_call_dropped` and `syscall_dropped`
  now indicate allocation failure rather than ordinary event volume.
  Non-returning process APIs/syscalls such as Win32 `ExitProcess` and native
  `exit` are recorded at call/syscall entry rather than waiting for an impossible
  post-call callback. Unknown syscalls,
  unknown ioctl request codes, request-dependent syscalls without a decoder,
  unresolved fd resources, truncated path arguments, unreadable pointer buffers,
  over-bound message-header batches, oversized iovec arrays, and truncated
  samples without full digest evidence remain partial side-effect models.

The client intentionally records module hash plus RVA, not instruction bytes or
decompiled expression. Import the output with:

Strict completeness is intentionally fail-closed. As of this pass, unresolved
API exports, APIs/syscalls without argument decoders, unresolved syscall
resources, unresolved Win32 API handles/resources, unknown request-code driven
calls such as unrecognized `ioctl` requests, over-bound network message-header
batches, buffers whose full digest cannot be read, oversized iovec arrays,
audio APIs outside the current WinMM/simple-sound decoders, synchronization APIs
outside the current event/mutex/semaphore and single/multiple wait decoders,
memory APIs outside the current heap/virtual/CRT/Local/Global allocation/free/
size/lock/protection decoder,
thread error-state APIs outside the current Win32 `GetLastError`/`SetLastError`
and Winsock `WSAGetLastError`/`WSASetLastError` decoder,
process APIs outside the current command-line/environment/current-directory/
temp-path/exit/create-process decoder,
network APIs outside the current Winsock startup/cleanup/socket/connect/send/
recv/option/ioctl/name decoder,
file APIs outside the current create/read/write/flush/size/pointer/EOF/info/type
decoder,
dynamic loader APIs outside the current `LoadLibrary*`/`GetModuleHandle*`/
`GetProcAddress`/`FreeLibrary` decoder, COM/vtable-dispatched subsystem calls
outside the current DirectX-style module decoder, calls with unreadable/unmatched
vtable evidence, calls whose exact COM interface identity is still ambiguous
after slot matching, method-local buffers whose full bounded digest cannot be
read, graphics unlocks without a matched lock payload, unregistered
callback/asynchronous effects, and whole-frame framebuffer pixel snapshots/diffs outside
decoded DIB/DirectX payload and typed presentation-geometry boundaries are not
considered complete evidence.

```sh
python -m wincr ingest-trace \
  --db build/catalog/catalog.db \
  --log build/traces/client-startup.jsonl
```

The flake builds Linux 32-bit and 64-bit clients plus a Windows 32-bit
`halo_trace.dll`:

```sh
nix build .#halo-trace-client
nix build .#halo-trace-client-win32
```

Use `wincr-trace-run --arch 32` for direct 32-bit Linux processes and
`--arch auto` or `--arch 64` for native 64-bit smoke tests. Halo CE/Wine traces
can still use `halo-trace-run` as a compatibility command surface. The Windows
DLL is kept reproducible so the same client can be tested under a Windows
runtime or a future Wine/DynamoRIO combination without changing the JSONL
format.

For block-conformance characterization, use:

```sh
wincr-trace-run \
  --out build/traces/block-state.jsonl \
  --test-id block-state-smoke \
  --arch 32 \
  --block-state-trace \
  --block-state-max-records 8192 \
  -- /path/to/target [args...]
```

Then build a private generated block-conformance suite through the target
manifest. This is the normal workflow: it resolves included binaries, rejects
unknown loaded modules unless they have explicit external provenance, filters
each trace by module hash, runs the Rust block engine, and writes `gaps.json`
plus `next-traces.json` for the next capture pass.

```sh
wincr generate-block-suite \
  --target-config target.toml \
  --binary-root /path/to/runtime-root \
  --trace-dir build/traces \
  --out-dir build/block-suite
wincr block-suite-gate --suite build/block-suite
```

When the gate fails, capture more traces from the suggested manifest targets in
`build/block-suite/next-traces.json`, then rerun `generate-block-suite`. Direct
`wincr-block characterize` remains available as the lower-level one-binary
engine:

```sh
wincr-block characterize \
  --binary /path/to/target.exe \
  --trace build/traces/block-state.jsonl \
  --trace build/traces/extra-scenario.jsonl \
  --out build/block-suite
```

Coverage is fail-closed. Every recovered block must have a complete original
pre/post case or a reviewed waiver file:

```sh
wincr-block coverage \
  --suite build/block-suite \
  --waivers build/block-suite/waivers.json
```

Waivers use `waivers.schema.json` from the suite and require a non-empty reason
plus private evidence. `--allow-incomplete-side-effects` is available only for
intermediate development; the strict gate fails while side-effect cases carry
capture limitations such as missing API returns or dropped bounded memory
effects.

Candidate validation has two layers. First, every non-waived original block
obligation must be mapped to a candidate semantic point, state adapter, and
side-effect adapter. Second, when a candidate trace is supplied, every complete
original case must have a matching `candidate_block_result` with identical
post-state, successor, and side-effect JSON:

```sh
wincr-block validate-candidate \
  --suite build/block-suite \
  --mapping candidate/mapping.json \
  --candidate-trace build/candidate/results.jsonl \
  --waivers build/block-suite/waivers.json
```

## Wine Compatibility Notes

The upstream DynamoRIO documentation describes native deployment modes: Linux
tools such as `drrun`/`drinject` for Linux processes, and Windows tools such as
`drrun.exe`/`drinject.exe` for Windows processes. It does not document Linux
DynamoRIO tracing a Windows PE inside Wine as a supported contract. Treat that
path as an empirically tested compatibility layer until the public PE fixture
produces expected module SHA256/RVA records.

Nix Wine packages may expose `bin/wine` as a shell wrapper that sets
`WINELOADER=.../bin/.wine`. DynamoRIO cannot execute that shell script as the
application ELF, so the Wine probe normalizes such wrappers to the hidden ELF
loader and records both paths in provenance. A row that reaches the hidden
loader but still reports only `wine-preloader`, `ntdll.so`, and host libraries
with no expected PE module is a Wine/DynamoRIO runtime failure, not a wrapper
failure and not Halo-specific evidence. The probe records a direct
non-instrumented Wine launch beside the traced launch so candidate Wine builds
can be rejected only after separating ordinary PE execution from DynamoRIO
compatibility.

For Wine processes, the Linux client also scans `/proc/self/cmdline` for the
original `.exe` path and falls back to anonymous in-memory MZ/PE image headers
when `/proc/self/maps` does not expose a path-backed PE mapping. That fallback
still records the original file SHA256 from the command-line path; it does not
dump PE bytes or instruction bytes.

Use `nix run .#halo-trace-wine-probe` for the pinned local Wine matrix. Current
pinned-Wine evidence shows the pure 32-bit launcher can crash inside DynamoRIO
even with stock `drcov` or an empty sample client, while the WOW64 path can fail
in Wine's preloader signal handling before any expected PE module record
appears.

Use `nix run .#halo-trace-wine-probe-i386-late` for the current
DynamoRIO/i386-late proof and `nix run .#halo-trace-wine-probe-dr8-i386-late`
for the exact DR8/i386-late control. Both verify that the target launcher is a
real ELF 32-bit process and default to `WINEARCH=win32`,
`GLIBC_TUNABLES=glibc.pthread.rseq=0`, and an isolated Wine prefix. The
current-DR i386-late runner uses `bin32/drrun -late` and leaves child following
off by default because Wine services such as `wineboot.exe`, `services.exe`,
and `winedevice.exe` can otherwise dominate fresh-prefix traces. Set
`HALOCE_TRACE_FOLLOW_CHILDREN=1` or pass `--follow-children` to the runner when
the target process tree needs it. The flake probe apps isolate catalog
generation and trace proof into helper processes, and the direct Wine warm-up
captures stdout/stderr through temporary files rather than Python pipes; this
keeps fresh-prefix Wine bootstrap from replacing the target PE in the traced
run. On the current Nix Wine 11.0/glibc 2.42 runtime, non-instrumented i386
Wine runs the PE fixture and current DR records the expected PE
module/block/edge evidence, but the DR8 client path crashes inside DynamoRIO
before any JSONL module records are emitted. Stock DR8
`drcov` is not a substitute: early injection aborts in the rseq/glibc path,
while `-late` lets the process run but produces only empty process logs.

Treat Wine probe rows as compatibility diagnostics until they contain the
expected PE module SHA256 plus nonzero mapped block, CFG-edge, and call-edge
rows. The objective coverage gate still requires a successful original-binary
trace, not just a successful tracer build.
