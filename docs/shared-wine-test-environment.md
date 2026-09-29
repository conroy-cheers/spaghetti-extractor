# Shared Wine test environment

The operator's direction is explicit: component definitions and boundaries are
target-specific; the test environment, DirectSound integration and other Win32
platform behavior belong to the reusable Wine environment. The sound bank and
setup consumers now use that split for their supported DirectSound surface.
Other platform families still need migration; this is not a universal Win32 model.

The backend sees candidate binaries and their API interactions. It has no
original/replacement flag, target addresses or component identities. The comparison
runner selects binaries and labels results. Target adapters map application state
and enter the selected body; under Wine, authored C bindings invoke the same
SDK-typed COM proxy entry points as machine callers. A different candidate does
not get a different platform implementation.

Normal-program capture also runs identically for every candidate. Application
stdout/stderr, Wine host diagnostics and generated service/resource traces are
retained separately. The shared launcher streams the existing reserved
instrumentation prefixes to a bounded `.trace` file without consuming the
application-output budget. It does not select bodies or interpret component
contracts; those remain comparison-runner responsibilities. See the
[capture workflow](component-workflow.md) for the limits and retained-evidence
compatibility. The regression consumer exercises fragmented prefixes, binary
application output, more than 9 MiB of instrumentation and explicit trace overflow.

## Ownership

| Target boundary and test data | Shared test environment |
| --- | --- |
| Original image/entry identity, calling convention and arguments | Entry/import interception and native invocation mechanisms |
| Application layouts, roots, aliases, state correspondence and assumptions | Execution of those mappings, memory observation and diagnostic machinery |
| Which application services correspond to platform APIs | Win32/COM ABI bindings, native call-through and platform resource handling |
| Initial application state, API outcome schedules and expected callbacks into application components | Scenario execution, fault injection, callback dispatch, ordered interaction recording and replay |
| Application-specific observations and relevant cases | Common API result, output-memory, handle/interface identity and lifetime observations |

Manual boundary analysis and application C adapters remain supported. They must
not become a place to reimplement DirectSound, COM dispatch, platform allocation,
or generic test scheduling for each new target. Application-owned functions such
as releasing a sound bank or loading a game resource remain lifting components;
the shared environment must not know DX-Ball's fifty slots, addresses or filenames.

## Reused foundations

The previous sound fixtures mixed application mappings, handwritten COM vtables,
fault schedules and native invocation. Their component C was retained while those
platform responsibilities moved into installed shared resources.

Reuse the existing systems rather than starting another comparison framework:

- `components/comparison_environment.py` supplies pinned tools, retained inputs
  and common native/observation headers. Its current helper explicitly leaves
  signatures, transport and observations to adapter authors.
- `resources/native/pe32-entry-hook.h`, `pe32-import-hook.h` and
  `pe32-process-observer.h` provide interception and process observation.
- `components/service_authoring.py`, service bridges, resource observations and
  nonlocal outcomes provide existing interface and execution mechanisms.
- `profiles/pe32-mingw-directx-interface-extraction-v1.json` and
  `external/interface_profiles.py` already describe SDK-derived DirectDraw and
  DirectSound interfaces. ABI declarations alone do not supply executable
  behavior, pointed-to memory effects or a comparison backend.
- The comparison runner, retained evidence, public component commands, source
  apply/export and Nix/headless-Wayland environment remain the integration path.

## Delivered interface (2026-09-28)

`components/comparison_wine_environment.py:wine_test_backend()` returns the ordinary
`adapter_files` and `include_files` arguments for `prepare_comparison_package` or
`revise_comparison_package`. Merge them with the target adapter inputs once in the
root consumer; exported component bridges do not duplicate the environment.
Existing comparison receipts hash these C files, headers and scenario inputs.
Changing the backend invalidates affected executions and reuses untouched compiler
objects. No new artifact format or comparison engine is introduced.

```python
backend = wine_test_backend()
prepare_comparison_package(
    # Existing interface, sources, tools, cases and driver arguments ...
    adapter_files={**backend['adapter_files'], 'runtime.c': target_runtime},
    include_files={**backend['include_files'], **target_headers},
)
```

The public C API is `resources/native/spx-wine-test.h`. Create an environment,
select `SPX_WINE_NATIVE` or `SPX_WINE_CONTROLLED`, and install its named imports on
the chosen PE32 module. The shared import hook also resolves ordinal imports
against the declared DLL export. DirectSound-created objects expose SDK-typed COM
proxies. Portable application service adapters use `spx_wine_candidate_call`;
its Win32 binding enters those same proxy methods. Host/AArch64 controlled
consumers compile the same backend without Windows headers or Wine.

Native mode calls the real Wine implementation. Controlled mode takes explicit
initial objects and `spx_wine_rule` inputs: API, optional receiver identity,
occurrence, return result, published object, partial/unwritten word output, and
callback token. Rules compose only when their effects do not conflict. Unknown
callback tokens belong to the target adapter's diagnostic, not a target switch in
the backend. The target callback applies application mutations or calls its real
component; platform outputs are published before that callback. Reentrant API
calls are recorded. Finite schedules are inputs, not production retry bounds.
Replay uses the existing retained case/component-check workflow.

The shared `spaghetti-headless-wayland` runner supplies a private PulseAudio
software output device and monitor input alongside the desktop. This makes real
Wine DirectSound available in Nix sandboxes without host sound hardware or a
running user audio service. Both candidates use that same environment. Audio
startup is checked before launching the command; service diagnostics stay separate
from application streams, and exit/cancellation stops the private server. The
software device supports API and buffer comparisons, not claims about audible
output quality or hardware timing. Its session variables invalidate execution
evidence but are withheld from the C compiler so unchanged objects remain reusable.

`spaghetti-headless-wayland --capture` additionally enables compositor snapshots
inside that private desktop. The generic [desktop driver](../tests/fixtures/wine-desktop/README.md)
supports `snapshot NAME.png`, retaining the complete image, hash, command logs and
reported Win32 client geometry. It sees candidate binaries without application
hooks or original/replacement roles. The next scripted action waits for capture
completion; the application itself continues running. Win32 virtual coordinates
are not assumed to be compositor pixel coordinates. This supplies presentation
observations when GDI omits DirectDraw/GPU output, without changing the application
or replacing deterministic component observations with screenshot heuristics.

For example, a failed status query that writes only the low byte:

```c
spx_wine_add_rule(environment, (spx_wine_rule){
    .api = SPX_DS_STATUS, .occurrence = 1,
    .flags = SPX_RULE_RETURN | SPX_RULE_WORD,
    .result = 0x80004005, .mask = 0xff, .value = 2,
});
```

`spx_wine_observe` emits ordered API identities, arguments, window/object identities,
results, output words and publication, reference-count events, generations,
injected callbacks, descriptors/format bytes and unlocked buffer contents. No raw
host pointer is used as a cross-candidate identity. Externally supplied windows
must be registered with `spx_wine_bind_window(environment, native_value, input_id)`
from the boundary's inputs or application roots, before use or in its before-call
hook. First-appearance numbering could conceal use of the wrong window. Unknown
or conflicting external input bindings stop the experiment. Native output transport keeps
caller bytes on failure; it does not infer an exact native write footprint.
Controlled output masks are explicit. Native reference counts are observations,
not a proof of external ownership or lifetime. The backend does not release
resources on the application's behalf.

Supported now: DirectSound creation, cooperative level, legacy 20-byte buffer
descriptors, setters, play/status/restore/stop, getter words, buffer Lock/Unlock,
AddRef/Release and same-interface/IUnknown queries; MessageBoxA supports native
call-through and explicit controlled return schedules. Native factory calls and
MessageBox dispatch resolve the actual DLL export even when the environment is
linked into the candidate executable itself.

DirectDraw surface support is described below. Explicit limits: PE32 import interception, one importing module per environment,
one application calling thread plus registered native MIDI callbacks, bounded trace
storage, and the listed COM interfaces. Other methods/interface projections,
aggregation and newer descriptor revisions exit with a capability diagnostic
(status 78). Controlled locking currently supports explicit ranges, all output
cells and zero flags; native locking preserves optional output cells. Controlled
use of an expired COM receiver is outside its admitted lifetime experiment and stops;
native mode does not insert that guard into the application. General unsafe heap
transport, arbitrary thread scheduling and arbitrary Win32 platform coverage remain
separate work. No missing method produces an invented success or failure HRESULT.

## Migration and evidence

Retained delivery: `build/shared-wine-backend-2026-09-28/`.

- `bank-accepted` and `setup-accepted`: all 36 + 36 local original-versus-C cases
  match, including original history, callback redirection, retries, failed/partial
  publication, disposal and nonlocal exit. The 95-line bank C and 76-line setup C
  are unchanged. Scenario code describes inputs and application callbacks; it
  no longer implements COM methods or platform effects.
- `bank-defect-check` and `setup-defect-check` retain public-workflow negative
  replays: caching a record across a callback differs at
  `$.audio.calls[1].after.records[0].buffer`; treating positive creation status as
  success differs at `$.audio_setup.calls[1].arguments[0]`. Neither needs the game.
- `normal-accepted`: 64-frame normal execution matches. All 35 preceding state
  fields also equal the previous retained run; `wine_platform` adds 354 matching
  calls, including 26 secondary-buffer Lock/Unlock pairs with observed contents.
  Native WAV loading is still retained, not lifted by this change.
- `program` and `arm-program`: public `candidate apply` refreshes the environment
  bindings, and both standalone consumers pass on x86-64 and emulated AArch64.
  The 37 component implementations remain unchanged; 116 of 118 existing build
  objects are byte-for-byte unchanged on each architecture. The two changed
  objects are the bank/setup boundary runtimes; two shared backend objects are new.
- `tests/fixtures/wine-sound/consumer.c` is an independent secondary-buffer caller
  with no DX-Ball layouts or entry addresses. Two candidate binaries (SDK calls
  and portable bindings) produce identical controlled and real-Wine observations.
  It covers split buffer writes, interface aliasing, reference counts, partially
  written/untouched failed outputs and a callback that reenters another API.
  Deliberately wrong buffer bytes and a different bound input window change the
  shared trace; an unsupported method produces the same explicit capability
  failure for either candidate.

`evidence-summary.json` separates preparation, compiler, link, runtime and
execution costs. The preceding window-binding migration recompiled three objects
per consumer, with no model or solver work: about 0.44 seconds of compilation for
each local consumer, 0.94 seconds for the normal consumer, and 0.064 seconds of
linking each. The local sets each spent about five seconds executing 72 candidate
processes; Wine prefix startup remained a larger cost. These are measured retained
runs, not a general performance guarantee.

The canonical native test shard now passes inside Nix's sandbox, including real
Wine DirectSound for both candidates (4.332 seconds for the test). The original
offline attempt unnecessarily selected a 1,432-derivation bootstrap build; online
cache lookup needed only a 1.5 MiB ShellCheck download and five small builds.
Running the actual test then exposed the missing audio device, now supplied by
the shared runner. The headless environment's stream, exit, cancellation and
interactive-session checks also pass. The original failed logs are retained;
the resolved runs are `build/shared-wine-nix-fix-2026-09-28/native-audio.log` and
`headless-check.log`. Repository metadata, production Python lint and format-
registry checks pass, as do the two native interception regressions and all 13
compiler-reuse tests. `repository-and-import.log` and `compiler-reuse.log` retain
those results; `checks.json` binds the realized Nix outputs.

These results establish reusable platform execution and observation for the
supported surface. They remain finite experimental evidence. Strong qualification
and the portable platform runtime needed for a standalone game are separate.

## Synchronous Win32 files

The same environment now provides `CreateFileA`, `GetFileSize`, `ReadFile` and
`CloseHandle`. Install the required imports with
`spx_wine_install_files(environment, module, SPX_WINE_FILES_ALL)`; individual bits
select a smaller importing surface. This composes with the sound/message imports
in the same environment. Portable bindings are `spx_wine_file_open`, `_size`,
`_read` and `_close`. On Win32 they enter the same SDK-typed functions reached by
intercepted machine imports. No candidate role or target identity is supplied.

For controlled cases, seed named immutable file contents once and add ordinary
rules to the existing schedule. Each successful open creates an independently
tracked handle and cursor; aliases retain their identity, and a successful close
retires the handle. Failed closes and leaked handles remain visible. Read-only
sharing conflicts are modeled. Missing exact path keys return file-not-found;
this finite input map is not a model of the Windows pathname namespace.

```c
spx_wine_seed_file(environment, "input.bin", input_bytes, input_size);
spx_wine_add_rule(environment, (spx_wine_rule){
    .api = SPX_FILE_READ, .occurrence = 1,
    .flags = SPX_RULE_LIMIT, .limit = 13,
});
spx_wine_add_rule(environment, (spx_wine_rule){
    .api = SPX_FILE_READ, .occurrence = 2,
    .flags = SPX_RULE_RETURN | SPX_RULE_ERROR | SPX_RULE_NO_WRITE,
    .result = 0, .last_error = 30,
});
```

`SPX_RULE_BYTES` copies an explicit prefix even on a failing call;
`SPX_RULE_WORD` independently controls the reported count or high size word with
a bit mask. `SPX_RULE_NO_WRITE` preserves both buffer and word outputs. These
explicit injections are experiments, not assertions that every such combination
occurs in real Windows. Rules cannot exceed the supplied output extent. Conflicting
rules stop with a capability diagnostic. Callbacks use the existing reentry path,
with API outputs published before the callback. Last-error state is restored after
instrumentation so the caller can inspect the API result normally.

The trace records paths, access/share/disposition/attribute flags, security-record
presence and inheritance, requested and transferred byte counts, result/error
values, buffer effects, output-word masks, and handle lifetimes. Controlled writes
have known masks. Native reads observe returned bytes and changes relative to
incoming storage; they do not claim an exact native write footprint. Unwritten
bytes are represented by their preservation relation instead of comparing
uninitialized allocation contents. Component-owned memory observations still
belong to the target boundary. Native offsets are queried from the real handle,
so unrelated CRT seeks do not get mistaken for monotonically increasing offsets;
nonseekable handles have an explicit unknown-position flag.

Buffer data remains exact hexadecimal bytes. Masks use hexadecimal `byte_mask`
or lossless `byte_mask_runs` pairs `[length, byte_value]` when runs save space
(at most one run per sixteen bytes). Expanding the runs reconstructs every mask
bit over `buffer_extent`; no sampling or hashing replaces byte observations.
This keeps real resource-loading traces within the existing report limit without
changing the observations or increasing that limit.

Existing input handles use `spx_wine_bind_handle` with declared identities, file
contents/initial position for controlled files, and a native handle for native
execution. Null-path bindings admit opaque resources for CloseHandle. Rebinding
never reanimates a retired record. The operator must establish the initial native
handle and cursor correspondence; a numeric identity alone does not do that.
Fresh native opens retain their real HANDLE values, including address reuse; trace
identities distinguish separate acquisition lifetimes. The backend does not close
leaks on the application's behalf.

An importing module can also close resources acquired through other API families.
Strict mode rejects unbound handles. Native experiments can explicitly request
`SPX_WINE_FILES_NATIVE_UNBOUND_CLOSE` when installing imports: these closes call
Wine unchanged, record the result/error, and carry `handle_known=0`. They do not
acquire invented identities or establish alias/lifetime correspondence. Every
tracked file close remains checked against its acquisition history. This option
is unavailable in controlled mode; a local component that consumes an incoming
handle must bind it or observe its acquisition. The independent consumer covers
both the strict diagnostic and explicitly selected native forwarding. This
coverage distinction is retained in normal-program assumptions and observations.

The present profile is synchronous, buffered, read-only `OPEN_EXISTING`, with
null template handles. Security attributes may be absent or the PE32 twelve-byte
record with a null descriptor and explicit inheritance. Custom security descriptors,
overlapped I/O, file creation/writes and other flags require additional support.
Inputs and individual observed reads are bounded at 4 MiB; 128 input assets and
512 acquired/bound handles fit an environment. Capacity and unsupported-operation
failures use status 78, never an invented Win32 result. Native mode calls real
Wine; host and AArch64 controlled consumers use the same portable implementation.

The SDK contracts consulted are Microsoft's
[ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile),
[CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea),
[GetFileSize](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize)
and [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
references. In particular, ordinary synchronous ReadFile initializes its count
output before work; explicit no-write scenarios must be requested as injections.

The independent `tests/fixtures/wine-files/consumer.c` exercises both SDK and
portable-binding binaries, controlled and native calls, incoming file/opaque
handles, inheritance attributes, short/failed reads, partial/untouched outputs,
reentrant callbacks, expiration and leaks. Wrong request lengths and omitted closes
change the retained observations. The DX-Ball [file reader](dxball-file-reader-continuation.md)
uses these facilities without implementing Win32 behavior in its target adapter.

## WAV continuation status

The subsequent [WAV continuation](dxball-wave-continuation.md) now implements the
parser and loader using this backend, with 52 local cases, x86-64/AArch64 exports
and 26 loads in matching normal execution. The ensuing file-service gap is now
addressed by the shared synchronous file backend above and the file-reader
continuation. Real Wine call-through alone did
not provide those controlled partial-read and lifetime cases.

The loader investigation inspected the pinned original instructions at
`0x403000..0x403204` and `0x403470..0x403543`. Failure paths free the published
sample without clearing its slot; parsing can publish data before writing the
format output. The preceding bank's live-input assumptions did not cover all of
that behavior. These native quirks are boundary requirements, not by themselves
proof that the comparison engine lacks expressive power.

The WAV component's application boundary now represents those allocation,
dangling-slot and parser-output requirements; working COM proxies alone do not
establish them. The original pre-backend investigation remains in
`build/dxball-wave-2026-09-28/`; subsequent comparison evidence and the 38-component
source project are in `build/dxball-wave-lift-2026-09-28/`. Whole-program completion
and arbitrary invalid-memory behavior are not claimed.

## Subsequent music boundary

The [music-controller continuation](dxball-music-continuation.md) independently
lifts application track ownership over the retained MDS library. The next shared
backend gap was mapped-file/global-memory lifetime plus queued WinMM MIDI headers
and completion callbacks. The shared extension below supplies that platform surface;
the target still supplies MDS layouts and callback bodies. This does not itself
translate the MDS library or complete the portable game.

## Mapped storage and queued MIDI (2026-09-29)

`wine_test_backend()` now also retains `spx-wine-memory.c` and `spx-wine-midi.c`.
The normal comparison package, compiler cache and source-assembly inputs bind
these modules exactly as the existing sound and file modules. There is still no
candidate-role parameter or target-specific platform implementation.

Storage operations are `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`,
`LocalAlloc`/`LocalFree`, and `GlobalAlloc`/`GlobalLock`/`GlobalUnlock`/`GlobalFree`/
`GlobalHandle`. Install only the imports required by the consumer with
`spx_wine_install_mappings` and `spx_wine_install_memory`; file handles continue
through `spx_wine_install_files`. Public `spx_wine_*` bindings have the same
dispatch and observations as SDK callers.

- Mappings currently admit unnamed, read-only mappings over observed files,
  default security, bounded extents and `FILE_MAP_READ`. Distinct views retain
  their own addresses and lifetimes, with a shared backing identity and offsets.
  Views made through different handles for the same file share that identity.
  Closing a file or mapping handle does not retire its views. Controlled views
  have real read-only page protection; unmapping makes their pages inaccessible.
  Native mode calls Wine and records the actual mapped bytes. Writable, named,
  paging-file and cross-process mappings require further shared support.
- Fixed local and fixed/movable global allocations retain separate lifetime and
  lock records. A movable handle is distinct from its data pointer. Zero-init,
  repeated locks, unlock-to-zero versus failed unlock, failed frees and freeing
  locked global memory remain observable. Controlled noninitialized allocations
  require explicit `spx_wine_allocation_history` or exact `SPX_RULE_BYTES` inputs.
  Allocation contents containing application pointers use the component's state
  correspondence; raw pointer-containing structures are not compared as bytes.
  Native allocations and leaks remain application-owned.

The generic [desktop workload driver](../tests/fixtures/wine-desktop/README.md)
also exercises candidate binaries through ordinary window messages and cursor
movement. It uses the existing capture/session infrastructure, with separate
controller reports and candidate streams. Headless Weston supplies a virtual
input seat (`--fake-seat`): without one, the DX-Ball normal-entry exercise exposed
an Xwayland cursor-warp crash affecting both original and source binaries. The
environment check now covers X11 warp/query without any application-specific
setup. GDI screenshots may omit DirectDraw presentation and do not by themselves
establish rendered-image equality.

The MIDI surface is stream open/property/restart/pause/close, header preparation,
queueing and unpreparation, reset and function callbacks. It admits one device,
64-byte PE32 header ABI, null/function callbacks, and tempo/time-division
properties. Bind callback/instance pairs and nonzero header user values to their
boundary identities before use. `spx_wine_bind_midi_allocation_user` binds a live
allocation's address and generation, retiring that binding on free; scalar user
bindings remain explicit. Header acquisition, preparation, queue generation,
completion, callback requeue, stream lifetime and retired storage are recorded.
When a portable header representation lives outside the original allocation,
`spx_wine_bind_midi_header_storage(environment, header, allocation_id, offset)`
binds its logical 64-byte extent to checked live allocation storage. This preserves
header lifetime when pointers grow on another architecture, including headers
with zero-length payloads. Moving a retained header or binding outside the
allocation is rejected. The binding supplies location correspondence; it does
not establish header contents, callback ownership or a universal heap relation.
Payloads are retained at preparation, queueing, callback delivery and unpreparation.
Identical MIDI payloads use `data_ref`, a one-based reference to an earlier entry
in `calls` containing the exact same `data` bytes. Every snapshot remains present;
there is no sampling, hash-only comparison or larger observation limit.

Controlled mode supplies a deterministic finite schedule:

```c
spx_wine_bind_midi_callback(environment, on_midi, application_context, 1);
spx_wine_bind_midi_user(environment, application_object, 1);
/* After the candidate has prepared, queued and restarted its stream: */
spx_wine_midi_complete(environment, stream, header_identity);
```

Completion returns the next queued header before invoking application code, which
may queue it again. Reset normally returns the pending generation, with requeued
work kept distinct. `SPX_RULE_DEFER_COMPLETIONS` on reset leaves returns pending
for explicit completion steps or a scheduled successful close. A close that still
has queued buffers normally reports `MIDIERR_STILLPLAYING`; an explicit successful
close scenario returns them before the close callback. These are controlled
provider scenarios, not universal driver guarantees. Payload events are opaque:
the environment does not synthesize music, interpret embedded tempo changes,
simulate hardware time or prove arbitrary concurrent execution. Property output
rules supply observations for scenarios requiring those driver effects.

Native mode calls the Wine exports and forwards registered callbacks on their
actual thread. The shared observation lock protects backend state and is released
around native MIDI calls, because reset/close may wait for callback threads.
Unregistered concurrent application callers still receive a capability diagnostic.
Native callback timing is observed rather than converted into a deterministic
schedule. Close notifications must finish before disposing the environment.
Failed open calls preserve unwritten, null and non-null published outputs without
making a failed publication live. Controlled `SPX_RULE_OBJECT` can publish null,
an existing stream alias, or `SPX_WINE_FAILED_PUBLICATION`. The isolated Nix
environment may have no MIDI device; its actual Wine failure/output behavior is
compared with unintercepted SDK execution, while controlled schedules exercise
the complete queue and callback lifecycle independently of hardware availability.

The independent storage and MIDI consumers are in `tests/fixtures/wine-storage/`
and `tests/fixtures/wine-midi/`; their native test shards use the shared headless
Wayland desktop. SDK and portable-binding binaries cover controlled failures,
partial/unwritten outputs, mapping aliases, memory locks, callback requeue and
cleanup. Unintercepted SDK execution separately checks the native MIDI consumer's
visible results. Wrong requeue and late payload corruption are visible locally;
invalid completion order, unsupported callback delivery and freeing still-owned
buffer storage produce specific diagnostics. Portable consumers also compile and
run on x86-64 and emulated AArch64.

For an application that disposes retained MIDI buffers on an error path, call
`spx_wine_allow_retained_midi_disposal(environment)` before execution in controlled
mode. The comparison then records the actual disposal and marks each affected
header with `storage_invalid_disposal`; queued/prepared state is preserved in the
observation. Later API access or callback delivery through that retired header is
rejected before reading its storage. This explicit experiment does not invent
use-after-free behavior or authorize native execution of unsafe disposal. The
default still rejects the disposal itself. Independent SDK/binding consumers
cover both policies and translated zero-payload headers.

The first actual MDS integration exposed a useful case: Wine reset returned while
buffers remained queued; unprepare returned 65; close subsequently delivered the
buffers and succeeded. The small consumer now reproduces this both as a controlled
schedule and through Wine. The backend retains the failed unprepare results and
prepared flags while allowing storage release after the stream's ownership ends.
It does not change application cleanup to make it appear successful. Still-pending
buffer release remains outside the valid-storage profile, with an explicit
diagnostic; arbitrary use-after-free execution needs a separate boundary.

The retained `build/shared-wine-streaming-2026-09-29/validation.json` binds current
backend inputs to nine SDK/host/AArch64 scenarios, the 64-frame normal comparison,
both source exports and seven focused Nix backend/repository checks. Updating the
source projects reruns 176 connected cases per architecture, preserving all 40
component implementations and 39 neighboring records. Normal execution observes
766 matching platform interactions; its 38 preceding non-platform fields remain
unchanged. Installing unused allocation hooks does not affect observations.

API references:
[mapping and view coherence](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile),
[global unlock outcomes](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalunlock),
[freeing locked storage](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree),
[MIDI buffer preparation](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-midioutprepareheader),
[MIDI reset](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-midioutreset),
and [stream callbacks](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-midistreamopen).

## DirectDraw surface boundaries

The backend supports legacy `IDirectDraw`/`IDirectDrawSurface` creation, normal
cooperative level, surface descriptions, Lock/Unlock and color-fill Blt, plus
same-interface/IUnknown and reference-count operations. Install the factory with
`spx_wine_install_draw`. Portable `spx_wine_candidate_call` bindings enter the same
SDK-typed proxies as native callers. No candidate role or target address is used.

Controlled surfaces own exact backing bytes, including padding and negative
pitch. `spx_wine_seed_surface` accepts explicit initial storage. Supported
uncompressed RGB layouts have 8, 16, 24 or 32 bits per pixel; controlled creation
is limited to offscreen system-memory surfaces. Pixel format masks select fill
bits while the full caller color remains observable. Lock observations use the
actual rectangle and pitch. Unlock retains complete locked pixel contents, and
whole seeded backing, references and outstanding locks remain observable.
Invalid rectangles require an explicit failure schedule. Overlapping locks,
other surface methods, palettes, clippers, display modes and newer interfaces
report a capability gap.

`spx_wine_surface_desc` carries 27 PE32 words with word 9 zero and `pixels`
separately at host pointer width. All history is transported; only flag-selected
fields are API values. Controlled write masks are exact; native write footprints
are not inferred. Rules can preserve failed outputs, publish object identities,
replace the scalar descriptor prefix before `lpSurface`, return chosen outcomes
and invoke registered callbacks.

`spx_wine_bind_surface` admits a borrowed native surface with an explicit boundary
identity. The caller keeps it alive; acquisition and reference-count operations
are outside this boundary. Counts remain unknown and `borrowed_input` is explicit.
A pointer binding does not establish contents or lifetime. The DX-Ball adapter
uses named primary/back/flip/software roots, not view-cache encounter order.

Large byte observations use lossless value encodings:

- `data_ref` names the one-based earlier call with the same complete payload.
- `data_delta_ref` names a same-length payload; apply every ordered `{offset,
  data}` patch from `data_delta` to a copy of those bytes.
- `data_slice_ref: [call, offset, size]` selects an exact earlier byte range.
  Audio uploads can reuse captured ReadFile bytes without knowing file formats.

These encodings neither infer aliases nor omit observations. Byte equality is
checked before sharing a range. Independent consumers verify reconstructed pixels
and audio samples, including corruptions. The 242-line DX-Ball workload initially
produced a 67 MB partial report and timed out; patches and range references bring
it below the existing 8 MiB limit.

Evidence: `build/shared-wine-draw-2026-09-29/`. Independent SDK and binding binaries
exercise real Wine and controlled surfaces, borrowed identities, negative pitch,
subrectangles, failures, aliases and lifetime diagnostics. Controlled consumers
also run on x86-64 and emulated AArch64. The connected
[raster component](../tests/fixtures/dxball-raster/README.md) passes locally and
in normal execution without changing its first C. Production portable graphics
and standalone assembly remain separate obligations.
