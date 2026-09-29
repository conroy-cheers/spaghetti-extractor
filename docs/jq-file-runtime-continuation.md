# jq continuation: shared file runtime and input components

The file-input gap from the [module-loader attempt](jq-module-loader-continuation.md)
is resolved for the recorded filesystem/text-input profile using the existing
component workflow and ordinary C. No checker, compiler, artifact format, proof
rule or source-assembly infrastructure changed. A missing runtime implementation
was work to perform through those facilities, not a demonstrated tooling blocker.

The continuation also lifts jq's multi-file input state. **Nineteen file-loader,
25 module-loader and 11 input-state native scenarios match.** Both standalone
projects match **120 CLI cases and 32 live-value scenarios** on x86-64 and AArch64
under QEMU. The projects contain 31 selected components, with all **28 unrelated
component records and files unchanged**. This remains source-assisted partial jq
lifting; finite comparisons and source compilation do not establish strong
qualification or complete recovery from machine code.

## One reusable library, two further components

[`windows-files.c`](../tests/fixtures/portable-runtime/windows-files.c) and its C
header supply file lookup and stream decoding without a jq dependency. The host
backend resolves path segments with ASCII case folding; exact spelling wins,
and ambiguous folded matches fail. Text streams translate CRLF and stop at Ctrl-Z;
binary streams preserve bytes. Handles own decoder/EOF state and distinguish
owned files from borrowed streams. Close and detach have different ownership
effects. Normal C/stdio and the selected namespace backend supply the lower
services, rather than new solver models.

The [file-input component](../tests/fixtures/jq-file-input/README.md) replaces
`jv_load_file`: it owns the stream and optional JSON parser, completes UTF-8
sequences crossing the 4096-byte decoded buffer, and returns an owned value or
error. Its source package carries the library once. The module loader changes
only its file-existence calls to use that shared provider; search and import
logic retain their existing organization.

The [input-stream component](../tests/fixtures/jq-input-stream/README.md) owns
jq's multi-file input state. Ten native entries map to nine operations; direct
and callback reads share one operation. Private helpers remain private C. Raw
input, JSON input, slurping, copied filenames, counters, parser buffers, callbacks
and teardown stay together under a real state owner. Components borrow the same
process-owned stdin decoder, so aliases and repeated `-` arguments share EOF state.
The existing CLI option parser configures its text/binary mode before reading.

These library calls are executable C dependencies, described in the boundaries
and retained in comparison/assembly inputs. Their declarations are not checked
formal summaries. The portable assembly links one provider from file-input;
the other consumers do not each embed another implementation or registry.

## Differences found and repaired through consumers

The original stopping case now matches without changing its observations:

| Operation | Original and current portable result |
| --- | --- |
| Load a raw CRLF file | LF-decoded string |
| Load a raw file containing Ctrl-Z | String ending before Ctrl-Z |
| Query `MATH` with `math.jq` present | Module metadata found |

Additional normal-entry cases cover mixed case in parent directories, module
source containing CRLF/Ctrl-Z, `-f`, `--rawfile`, `--slurpfile`, named CLI inputs,
long lines, embedded NUL, invalid UTF-8, binary stdin and repeated stdin aliases.
The native input-state consumer uses two real jq contexts and observes successful
values, filenames/positions, error callbacks, cleared owner pointers and jq heap
lifetime. It also checks early teardown and two states sharing stdin.

Integration caught two concrete errors in the first input-state adaptation:

- A plain `abort()` lost the existing platform assertion behavior for a wrong
  callback identity. The component now calls the established diagnostic backend.
  The pinned CLI's import thunk still triggers its original assertion in affected
  cases, including its exact diagnostic and exit status. Native scenarios with
  the actual DLL callback exercise successful metadata queries separately.
- A fresh decoder for each `-` incorrectly exposed bytes after a previous Ctrl-Z.
  Sharing one runtime-owned stdin decoder and retaining the CRT end marker fixes
  repeated aliases and transfer between input states. `clearerr` does not imply
  a fresh underlying input resource.

The pinned input-state destructor also leaves an active FILE open until CRT
shutdown. That target behavior is retained. The added decoder wrapper is detached
without closing its file; borrowed stdin remains owned by the runtime.

Large native fixture payloads initially caused the launcher to exit with signal
11 before original output. The driver now constructs those same bytes from short
selectors; `fixture-bytes.json` retains the full input bytes. This changes fixture
transport, not the compared program values. The failed attempt is retained.

## Practical reuse and costs

No pilot rebuild was needed. Initial standalone integration changes 14 objects
and takes 0.865 seconds on x86-64 or 9.580 seconds for AArch64. The subsequent
stdin/diagnostic repair changes six objects, taking 0.365 or 4.622 seconds. All
318 host and 315 ARM files belonging to the 28 unrelated components retain their
recorded bytes. Existing application startup edits survive binding refresh.

The last shared-library edit recompiles one native object and reuses five for
file-input, or six for the module loader. Its compiler/link costs are about
0.032/0.064 seconds for each comparison. Execution takes 2.835 and 6.858 seconds,
respectively; Wine startup adds about 3.9 seconds. Input-state repair recompiles
three objects and reuses three. Model and solver work are zero throughout.
These timings are execution costs, not measurements of manual analysis or C
adapter preparation. Some independent comparisons/builds ran concurrently.

Fresh checked-in recipes reproduce both components' checked C from the current
source project. A fresh input-state handoff matches all 11 native scenarios,
reuses all six compiler objects and links/runs through the public command. This
is a reproducible handoff of the newly prepared boundary, not an unfamiliar
operator study. First-time native entry/ABI analysis remains manual.

## Explicit runtime scope

The shared provider covers the exercised ASCII case-insensitive namespace and
Windows text-input behavior. Drive mappings, UNC/device paths, Unicode case
tables, Windows sharing/permission rules, concurrent namespace mutation and all
resource failures remain outside its coverage. Non-ASCII host path bytes can
match exactly; native code-page equivalence is not established. Other namespace
providers can use the same C boundary.

Default stdout/stderr policy remains separate. Two raw-output probes without
`--binary` still show Windows CRLF output versus the host backend's LF output.
Their mismatch is retained for both final architectures under `output-policy/`;
it is not counted as passing or treated as a tooling blocker. The stdin value
cases ask jq itself for `tojson`, exposing the decoded string with escaped line
endings. Both programs run that same query and their bytes are compared exactly.
The comparator does not normalize output. Existing binary-output workloads and
the original filesystem stopping case remain unchanged.

Unlifted jq values, builtins, formatting/math/regex and other runtime/backend
dependencies still need independent treatment. Further component work need not
wait for complete Windows runtime emulation; retain the selected runtime policy
and extend shared C providers when a real consumer needs it.

## Handoff and validation

The checked-in file/input recipes, C, native adapters and portable binding
declarations are linked above. The retained experiment is
`build/jq-file-runtime-2026-09-26/`:

- `file-input/authoring/`, `file-input/comparison-final/` and
  `input-stream/authoring/`, `input-stream/comparison/` are editable workspaces.
- `file-input/repaired/`, `input-stream/repaired/`, `module-repaired/` retain
  authoritative current native comparisons and exact source/runtime inputs.
- `handoff-file-input/`, `handoff-input-stream/`, `handoff-check/` reproduce the
  public preparation and local compilation reuse.
- `program/`, `arm-project/` are standalone source projects; `*-build-final/`
  and `*-run-final/` retain their executables and program evidence.
- `program-run/` and `arm-run/` retain the first integration's discrepancies;
  `output-policy/` retains the separate default-output differences.
- Recipes, concrete input files, build phase costs and `result.json` retain the
  handoff and dirty-tree audit. Full original/source output remains available.

All Wine applications ran in headless Wayland desktops. Validation focuses on
the changed components, shared runtime and actual program assembly. Tool internals
and proof standards are unchanged; no new formal qualification is claimed.
Repository metadata refresh reports current metadata. The Nix repository-metadata,
format-registry and production-Python-lint gates pass, as does `git diff --check`.
The broad proof/repository matrix was not rerun for unchanged tool internals.
