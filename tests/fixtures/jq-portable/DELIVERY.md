# jq source delivery

This project contains the complete jq command-line pipeline as portable C
components, generated syntax machinery and explicit C libraries. The application
includes normal CLI entry, module loading, parsing, compiler IR and bytecode,
execution, values, serialization, allocation, runtime state and `--run-tests`.
It is a source-assisted translation of the pinned patched jq 1.8.1 target.
Generated parser/lexer code and established numeric/regex libraries are retained
as such; this is not an entirely handwritten rewrite or automatic binary recovery.

Build from a fresh directory with a C11 compiler, GNU make, binutils and the
ordinary POSIX configure tools:

```sh
make -j2 jq live-values
printf '{"items":[1,2,3]}\n' | ./jq --binary '[.items[] | . * 2]'
./jq --binary -n 'def factorial: if . < 2 then 1 else . * ((.-1)|factorial) end; 6|factorial'
```

The source project does not run the extractor, Python, Nix, Wine or the original
binary to build or execute. Configure and generated parser/lexer C are included.
Cross-compile in a separate copy using `CC`, `AR`, `RANLIB` and
`CONFIGURE_FLAGS=--host=aarch64-linux-gnu`. Use `LDFLAGS=-static` where supported.
`make clean` removes build outputs before changing toolchains or flags.

`COMPONENTS.md` and `lifted/components/*/README.md` expose each local boundary,
source files and retained comparison provenance. Their source snapshots retain
historical assumptions from the comparisons; read the runtime profile below and
the accompanying program receipts for the assembled configuration. Source edits
are ordinary C edits. Recomparison and integration use the unified `candidate
apply` workflow described in `README.md`; the original comparison inputs are
separate development artifacts, not runtime dependencies.

## Explicit reuse

`provenance/library-reuse.json` binds the reviewed source inputs. The retained
backend archive contributes only these classes of executable code:

- `jv.o`: three thin accessors forwarding to selected object, seed and decimal
  context implementations. No original value implementation remains there.
- `jv_dtoa.o`: David M. Gay's decimal/binary conversion library.
- `decNumber.o` and `decContext.o`: IBM decNumber arithmetic and context library.
- `lexer.o`: Flex 2.6.4 output from the retained jq lexer definition.

Oniguruma 6.9.10 supplies regular expressions. The selected language-parser
component retains Bison 3.8.2 generated syntax tables and grammar actions with
component adapters and a refactored metadata helper. Its grammar is included for
reference; regenerating it requires reapplying those adaptations and comparison.
The old backend parser object is not linked. Windows sorting/path services are
namespaced portable adaptations of Wine and MinGW code. Their license notices,
upstream identities, jq's COPYING, Oniguruma's COPYING, and generated-parser
notices accompany the source. The host C/math/pthread libraries remain platform
dependencies.

## Runtime profile

The delivered configuration preserves the selected Windows behavior, including
CRLF output by default, `--binary` byte output, text-input Ctrl-Z/CRLF handling,
the observed CLI callback-identity quirk, 32-bit calendar policy, and lexical
Windows paths. It uses live host objects, shared contents, reference counts and
callbacks; pointers are not reconstructed from numeric identities.

The POSIX namespace maps Z to `/`. Set `SPX_WINDOWS_DRIVE_Q=/absolute/root` for
Q paths and `SPX_WINDOWS_UNC_ROOT=/absolute/shares` for UNC server/share trees.
`SPX_WINDOWS_CWD` and `SPX_WINDOWS_CWD_Q` describe logical current directories.
Directory spelling uses ASCII case folding; non-ASCII bytes require exact
matches. UTF-8/single-byte path syntax is supported. DBCS encodings, arbitrary
Unicode filesystem equivalence, native terminal presentation, Windows sharing
rules and all device APIs are outside this delivery profile. NUL is supported.

The target-width allocation limits and well-formed-object assumptions remain.
Thread-local numeric contexts and jq's threaded test runner are exercised;
concurrent use of one jq state, mutation of process environment/current-directory
state, and concurrent dirname scratch use are not promised. Finite comparisons
cover observed outputs, errors, memory/lifetime and interactions. They do not
establish universal equivalence, unrestricted Win32 portability or strong formal
qualification. The delivery's run receipts identify the exact tested sources,
architectures and workloads.
