# Portable Windows runtime services

These are ordinary reusable C backends, exercised through standalone Hello and
independent native-service comparisons. They are not solver models or qualified
summaries. Keep the selected Windows runtime/profile explicit.

## Observable sorting behavior

`windows-sort.c`/`.h` provides a namespaced C sorting service, derived from
[Wine 11.0's MSVCRT implementation](https://github.com/wine-mirror/wine/blob/wine-11.0/dlls/msvcrt/misc.c).
It retains that runtime's comparison/swap sequence, removing the platform
dependencies and unused callback-context wrapper. The valid-buffer API has no
jq dependency. Its source is LGPL-2.1-or-later; preserve the notice and distribute
`COPYING.LGPL-2.1` with source projects using it.

The [jq value algorithms](../jq-value-algorithms/README.md) are its real consumer.
jq's NaN comparison is inconsistent, so replacing the sorting service with an
arbitrary host `qsort` changes visible element/group order. The native reference
and both standalone architectures now execute the same selected runtime policy.
This does not claim identical behavior for every Windows CRT version or model
its invalid-parameter callbacks. No comparator repair or result normalization
is applied; the pinned target's numeric behavior is retained.

## File lookup and input streams

`windows-files.c`/`.h` is ordinary C with a POSIX namespace backend and a native
Windows branch. It has no jq dependency. jq's independently authored
[file loader](../jq-file-input/README.md), [multi-file input](../jq-input-stream/README.md)
and module search use one linked instance of this library.

`spx_file_resolve` returns a caller-owned pathname and `spx_file_stat` inspects it.
The host backend resolves segments with ASCII case folding, preferring an exact
spelling and rejecting ambiguous folded matches. Non-ASCII spelling must match
exactly. Drive and UNC mappings use the shared path environment described below.
Unicode case tables, concurrent namespace changes and Windows permission/sharing
rules remain outside this profile. An unmapped drive or share fails explicitly.

`spx_input_open` owns its stream; `spx_input_attach` borrows or takes a caller's
stream as explicitly requested. Text mode folds CRLF and ends at Ctrl-Z; binary
mode keeps bytes intact. `read` and `gets` share the handle's decoder and EOF state.
Clearing stdio errors retains the CRT Ctrl-Z end marker. All aliases must use the
same decoder; do not mix these calls with raw stdio reads on the same FILE.
The jq runtime therefore owns one stdin decoder for the process and shares it
across component states and repeated `-` arguments. Its existing `--binary`
parser configures that provider before the first read.

Close consumes the wrapper and closes only an owned FILE. Detach consumes the
wrapper and returns its live FILE, transferring responsibility to the caller.
That distinction retains jq's original early-destroy behavior: an active owned
input FILE survives until CRT shutdown, while the extra decoder wrapper is freed.
Borrowed stdin remains runtime-owned until process teardown. Allocation failures,
read errors and fopen failures are returned through normal C results and errno;
the finite validation does not cover every host failure or interleaving.

The implementation and [jq continuation](../../../docs/jq-file-runtime-continuation.md)
are checked through actual consumers on PE32, x86-64 and AArch64. Host default
stdout/stderr policy remains separate; text-input support does not imply complete
Windows text-output or console emulation.

## Paths and namespace mappings

`windows-paths.c` and `windows-path-parts.c` provide lexical full-path expansion,
Windows path classification, and MinGW-compatible dirname/basename. Their shared
header describes ownership: expanded paths are caller-owned; path parts borrow
the input, literals, or dirname's module scratch buffer. A later dirname call can
invalidate that scratch result. Concurrent calls need external serialization.
Full-path expansion does not require the file to exist. The caller chooses its
buffer capacity; jq preserves the original PE32 limit of 260 bytes and returns its
input unchanged if expansion fails.

Path classification follows `PathIsRelativeA` for the selected non-DBCS profile.
A drive prefix or leading backslash is absolute; a leading forward slash alone
is relative under that API. Consumers use this rule consistently with the path
producer rather than a host-specific leading-slash test.

`windows-path-environment.c` separates path syntax from host namespace mapping.
Windows uses its native current directories and file calls. POSIX defaults to
drive Z mapped to `/`, with the host working directory expressed on that drive.
Set `SPX_WINDOWS_DRIVE_Q=/absolute/host/root` to map another drive, or
`SPX_WINDOWS_UNC_ROOT=/absolute/share/root` to map `\\server\share\file` to
`/absolute/share/root/server/share/file`. `SPX_WINDOWS_CWD` selects a logical
absolute current directory; `SPX_WINDOWS_CWD_Q` selects Q's drive-relative current
directory. These declarations must describe the same filesystem state as the
consumer, and must not change concurrently with a call. NUL maps to `/dev/null`;
other device I/O remains unsupported. Empty file names fail, although an empty
full-path expansion returns the current directory.

The profile handles UTF-8/single-byte path syntax, ASCII case folding, drive and
UNC roots, relative paths, dot segments, trailing dots/spaces and the retained
device-name expansion rules. It does not emulate DBCS encodings, all Unicode
filesystem comparisons, reparse-point behavior or the entire Win32 namespace.
Native comparisons and real jq module/file consumers exercise the selected
profile on x86-64 and AArch64; they do not prove arbitrary filesystem equivalence.

The path implementation adapts Wine 11.0 and MinGW-w64 13.0.0. Preserve the source
notices, `COPYING.LGPL-2.1`, `DISCLAIMER.PD` and `windows-path-provenance.json` when
distributing a project that uses it.

## Windows-1252 arguments and output

`windows-1252.h` supplies 16-bit single-byte decoding with four-byte initial state
and redirected stdout/stderr behavior. Initialize its stream backend once, before
using its output functions, and close each stream once. It owns 4096-target-byte
buffering, CRLF expansion and the pinned runtime's pipe-error behavior. It does
not implement arbitrary FILE streams or other narrow code pages.

POSIX stdout/stderr terminals use an experimental UTF-8 presentation backend.
Its contract is a fresh line at column zero, fixed nonzero terminal width, one
writer, and ordinary single-cell Windows-1252 text with BEL/BS/TAB/CR/LF. It checks
each descriptor independently; redirected streams keep exact target bytes.
Descriptors for the same terminal share column state. Tabs overwrite spaces and
stop at the right edge. The pinned CRT commits a wrap at a write boundary, while
CR/backspace within that write can act on its last occupied column. `_putws`
writes its string and appended newline separately. These distinctions were found
through actual console comparisons, not inferred from matching output encodings.

`native/console-launch.c` observes a private Win32 screen buffer after an actual
child exits, using [ReadConsoleOutputCharacterW](https://learn.microsoft.com/en-us/windows/console/readconsoleoutputcharacter).
`terminal-screen.c` observes the portable process's real PTY bytes with
[libvterm](https://www.leonerd.org.uk/code/libvterm/), supplied by the Nix
`terminal-screen` test fixture. Both capture Unicode cells and cursor positions;
glyph pixels, fonts, colors, bell delivery and general terminal control APIs are
unobserved. The separate CRT consumer exercises wide/narrow output, shared and
mixed streams, tabs, line edges, carriage returns, backspaces and scrolling.

The full Hello console comparison deliberately retains a **mismatch** for its
all-byte sweep: other C0/C1 controls and DEL do not have the same cell semantics
in classic consoles and VT terminals. That case is not filtered or counted as
passing. Arbitrary controls, initial cursor positions, resized terminals,
concurrent writers, terminal failure paths and other console implementations
remain unsupported. An input such as ESC may be interpreted by the host terminal;
this backend does not establish literal classic-console rendering for it.
The backend is ordinary C with POSIX terminal detection; libvterm and Wine are
test dependencies only. The redirected-stream profile keeps its separate coverage.

Pending count, prior error and consuming close are separate lower services.
The assembled Hello stream adapter provides `spx_target_close` by calling the
locally compared [stream-close component](../hello-stream-close/README.md);
the backend no longer duplicates that policy. `stream-view.h` supplies a shared
call-scoped reference to an existing handle. Borrow/take does not recreate FILE
contents, prove lifetime correspondence or validate independently fabricated views.
The assembly recipe copies this adapter-only header with the shared backend;
it is not an authored algorithm dependency inferred by source export.

`windows-argv.h` is independent of that output backend and any Hello body:

| Boundary | Contract |
| --- | --- |
| Inputs | Stable readable NUL-terminated UTF-8 strings; no overlong forms, surrogate encodings or values above U+10FFFF |
| Result | Windows-1252 narrow bytes using the selected best-fit table and replacement behavior; required capacity includes NUL |
| Frames/aliases | Size query has no output writes; invalid input and insufficient capacity leave output untouched; disjoint buffers or exact in-place conversion are supported |
| Owner | One allocation contains argv and all strings; the vector may be reordered; dispose exactly that allocation after all users, including shutdown callbacks |
| Failure | Explicit invalid-input, capacity and allocation results; no implicit replacement of malformed UTF-8 |
| Shared assumptions | Eight-bit bytes, the pinned Wine Windows-1252 API, synchronous stable inputs; no ambient locale lookup or Wine dependency during portable execution |

The same encoding function works on an individual string or a complete argument
vector. Its table contains 473 exceptions to ASCII/Latin-1 identity and `?`
replacement. `generate-best-fit.py` can reproduce the header from the reviewed
65,536-byte native unit mapping. That initial probe and its runtime/source hashes
are retained at `build/hello-utf8-entry-2026-09-22/probe.json`.

`windows-argv-probe.c` compares the complete Windows service with the portable
consumer for all 1,112,063 non-NUL Unicode scalars and 1,024 generated multi-scalar
strings. Supplementary scalars become two target replacement bytes in this
selected profile. The integration test additionally checks malformed/truncated
UTF-8, capacity frames, in-place conversion, vector permutation and disposal with
AddressSanitizer and UndefinedBehaviorSanitizer. The existing decoder test checks
all 256 input byte values against MSVCRT. These finite checks do not prove all
possible strings, resource failures or Windows versions.

Every native Windows probe/test runs within the repository's headless Wayland
desktop. No Windows service is required by the compiled portable backends.
