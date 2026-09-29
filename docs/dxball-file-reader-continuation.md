# DX-Ball file reader and shared Win32 file services

The missing shared file environment is implemented, and the reader at
`0x40d9f0..0x40db13` now lifts into 28 lines of ordinary C through the public
component workflow. The [recipe and boundary](../tests/fixtures/dxball-file-reader/README.md)
separate application fallback/ownership policy from reusable Win32 behavior.
No original DX-Ball source was consulted. The pinned executable's instructions
and embedded fallback string were the oracle; the first authored reader C passed
all local comparisons and needed no behavioral correction after integration.

The [shared environment](shared-wine-test-environment.md#synchronous-win32-files)
provides CreateFileA, GetFileSize, ReadFile and CloseHandle, with real Wine
call-through and explicit controlled file inputs. It observes paths and flags,
requested/transferred bytes, preserved outputs, error state, cursor positions,
aliases and acquired/bound handle lifetimes. Short reads, failing partial writes,
untouched outputs and failed closes are ordinary scenario inputs. SDK callers
and portable bindings enter the same implementation; the backend has no target
addresses, application layouts or original/replacement role flag.

This retains existing interfaces, service bridges, comparison receipts, compiler
reuse, source assembly and Nix infrastructure. There is no new proof format,
solver model or candidate activation authority. Platform scenarios remain finite
experiments; they are not universal Windows specifications.

## Delivered workflow and evidence

Retained evidence: `build/shared-wine-files-2026-09-28/`.

- `reader-check-final`: 22 original-versus-C comparisons pass without starting the
  game. Allocated and supplied buffers, fallback/missing paths, allocation
  failure, failed/short/empty reads, ignored close failure, invalid size,
  nonboolean success/allocation values, long fallback names and repeated calls
  are covered. Both original failure leaks and freeing a supplied destination
  are preserved. Successful short reads leave the destination's tail intact.
- `reader-defect-check`: an intentionally added CloseHandle on allocation failure
  is detected locally. This is a behavioral change even though it would ordinarily
  be considered a cleanup improvement. The public edit/check workflow reuses the
  other compilation units and retains the exact discrepancy for replay.
  Its first difference is `$.reader.platform.calls` (two original calls versus
  three replacement calls); one unit recompiles and five are reused.
- `program` and `arm-program`: public `candidate apply` updates both standalone
  source projects. Reader, bank, sound-setup and WAV consumers pass 22 + 36 + 36
  + 52 affected cases on x86-64 and emulated AArch64. Other authored components
  are retained. The selection has 39 components, 152 public entries and 850
  covered consumer cases; this delivery reruns the 146 affected cases, not all
  850 cases. Source consumers require neither Wine nor the original executable.
  All 38 preceding component records and authored implementations are unchanged.
  Of 85 previous top-level objects, 81 remain identical on x86-64 and 80 on
  AArch64; changed objects belong to the shared backend and its boundary adapters.
- `normal-check-final`: uninstrumented, original and replacement program runs
  match through 64 frames, including 26 file-reader calls and 26 WAV loads.
  The source reader's entire original body is trapped. All preceding 37 state
  fields remain represented: 36 are identical to the preceding WAV run, and
  the platform field retains all 354 previous sound calls while adding 294
  file-service calls and 44 file-handle histories. No preceding observation is
  discarded or weakened to obtain a match.

The independent `wine-files/consumer.c` uses no DX-Ball boundary. Separate SDK
and portable-binding executables compare controlled and native file operations,
incoming handles, security inheritance, short/failed reads, partial/unwritten
outputs, callbacks, expired handles and leaks. Changed read extents and omitted
closes produce different observations. Unsupported overlapped calls and unbound
strict handles produce actionable capability diagnostics for both candidates.
It also checks lossless compact masks for a larger short-read buffer.

The canonical Nix file and existing sound test shards pass (6.693 and 3.962
seconds respectively), along with repository metadata, production Python lint
and format-registry checks. Every Wine invocation used the headless Wayland
environment. The preservation audit found no deletions or changes to any of
the 2,922 unrelated preexisting files. No commit or publication was performed.

## What integration found

Integration required reusable backend extensions, not changes to the reader C:

1. CRT consumers pass a nonnull SECURITY_ATTRIBUTES record. The shared profile
   now supports the twelve-byte PE32 record with null security descriptor and
   explicit inheritance. The independent consumer reproduces both controlled
   and native use.
2. The importing module closes some handles whose acquisitions were outside the
   observed file API surface. Normal native execution explicitly enables forwarding
   these closes and records `handle_known=0`; two such calls occur in this run.
   Their identities and lifetimes are unqualified. Local controlled cases still
   reject unbound handles, and operators can bind incoming resources when they
   matter to the boundary. Strict and forwarding modes are independently tested.
3. Recording every mask byte made the otherwise matching normal reports exceed
   the existing 8 MiB limit. Lossless run-length encoding retains every mask bit
   and every data byte while reducing report size. The limit and compared state
   remain unchanged. Native cursor queries also observe seeks made outside the
   selected imports instead of assuming that every read follows the previous one.

The original report falls from 11,015,780 to 7,625,726 bytes. Expanding the new
masks reproduces the full earlier report's observations exactly.

These cases are expressible and reproducible through the shared environment
without game startup. A full-program run remains useful evidence of consumer
coverage, but it is not the only way to exercise these platform requirements.

## Costs and remaining scope

Initial preparation took less than half a second using retained inputs. The first
local check compiled six units in 0.62 seconds, linked in 0.064 seconds and spent
4.73 seconds running 44 candidate processes. Paired Wine prefix startup took
6.67 seconds wall time. The final backend refresh recompiled four units and reused
two; the last normal check recompiled one and reused 82. No pilot rebuild, proof
model or solver was involved. Exact final phase costs, receipt hashes, export
checks and preservation results are retained in `validation.json` alongside the
individual logs; these measurements are not performance guarantees.

This closes the documented synchronous read-only file-service blocker. The
controlled filesystem uses exact seeded path keys, not a complete Windows
namespace. Writes, overlapped I/O, custom security descriptors, concurrency and
other platform families remain unsupported. Native untracked closes are explicit
limited coverage, not established resource correspondence. The typed component
domain requires admitted filename and buffer extents and does not qualify arbitrary
invalid-memory behavior.

The new standalone artifacts are component consumers. Normal execution still
uses native allocation, music and remaining runtime/platform services; a complete
portable DX-Ball game remains unfinished. Strong qualification remains a separate
objective from this practically validated lifting workflow.
