# jq command-line component

The process entry accepts argc and live, NUL-terminated UTF-8 argv strings from
startup. It parses options, creates one jq context and input state, registers
callbacks that borrow its live stack, compiles/executes filters, releases state
and terminates through the process runtime. It is entered once per process and
does not return. Earlier options can affect later errors and early exits.

The ordinary C is source-assisted from the pinned jq 1.8.1 main.c under COPYING.
Runtime services own locale, regex depth policy, stdio modes, terminal flags,
process termination and the original CLI import-thunk callback identity. Values,
compiler, interpreter, filesystem, input, serialization and the internal test
runner remain independently executable dependencies. The observable version and
configuration strings preserve the original target metadata; actual source-build
provenance is recorded separately. They do not describe the host compiler build.

Native comparison uses actual PE process startup and TLS. The Windows wide-argv
to UTF-8 conversion remains startup infrastructure. The authored process body and
all original CLI private helpers are disabled on the replacement side. Unchanged
native libraries provide the surrounding system. Untouched-original controls
check instrumentation transparency; stdout, stderr and exit codes compare byte
for byte. Body removal and selected-call counts are also checked.

The portable delivery uses a shared Windows text-output provider for both stdout
and stderr, including writes from neighboring components. It translates each LF
to CRLF; --binary flushes then preserves bytes. The host cookie-stream backend is
an explicit libc adapter; the CLI itself uses ordinary C. Stream installation
occurs before any retained FILE pointers, with one process owner and no concurrent
mode changes. The existing input runtime supplies Windows text-input behavior.

Tests cover redirected file/pipe operation, UTF-8 arguments, options, errors,
early termination, callbacks and file consumers. Console APIs, arbitrary Windows
namespaces, signal equivalence, interactive terminal behavior, code-page locales
and exhaustive I/O/allocation failures are outside this finite profile. Neither
an opaque pointer nor passing workloads constitutes a formal checked summary or
universal equivalence claim. Strong qualification is a separate obligation.
