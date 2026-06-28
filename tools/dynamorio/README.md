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
  target.

The client intentionally records module hash plus RVA, not instruction bytes or
decompiled expression. Import the output with:

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
