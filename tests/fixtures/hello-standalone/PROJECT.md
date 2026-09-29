# Portable Hello source project

Build with `make CC=cc AR=ar`. A C11 compiler, archiver and ordinary Unix build
tools are sufficient; the extractor, Python, Wine and the original PE are not
build/runtime dependencies. `make clean` is required when changing toolchains
or flags. The GNU source and license notices are retained in this project.

Two entries share the same application and lifted components:

| Executable | Argument contract | Output contract |
| --- | --- | --- |
| `hello` | Target Windows-1252 narrow bytes | Windows-1252 bytes and CRLF on redirected streams |
| `hello-utf8` | Valid UTF-8, converted to the selected Windows-1252 best-fit argv contract | The same target bytes and CRLF on redirected streams |

For example, `./hello-utf8 --greeting='café'` accepts normal UTF-8 shell input.
Both entries select the experimental UTF-8 console text backend on POSIX terminals;
see `backends/windows-1252/README.md` for its fixed-width, column-zero, single-writer
contract and the retained control-character mismatch. Redirected bytes keep their
separate target contract. Invalid UTF-8 rejects before application entry rather than
silently introducing a new replacement policy. Other Windows code pages,
general console APIs and localized catalogs remain outside this profile.

`application/entry.c` owns the platform argument adaptation. Its single allocation
contains the mutable argument vector and all strings, remains live through the
application's shutdown callbacks and is then freed. It is distinct from application
allocation counters. `application/application.c` owns the option/control loop.
`application/services.h` defines the shared conversion/runtime state once.

The allocation, conversion, string, release and stream adapters each include the generated
interface of their existing component. They supply live C objects and executable
services; opaque 32-bit release tokens are mapped to full host pointers. The
interfaces, assumptions and comparison identities are retained under `lifted/`.
Exporting a compared component does not qualify a new application/backend binding.

The Windows-1252 backend supplies target-width decoding and redirected output.
Its lower pending/error/close services are separate from the selected stream-close
component's decision logic. `application/stream.c` connects them through a shared
live stream view and the host's EBADF predicate. A successful or failed close
consumes the stream; no further access is valid. The new-boundary recipe records
local native comparisons and shutdown integration separately.
The separate `windows-argv.h` boundary states the UTF-8 adapter's readable input,
capacity/failure behavior, in-place alias allowance and ownership requirements.
Its best-fit table is retained C data checked against the selected Windows API
under Wine; this is not a claim about all Windows runtime versions or code pages.
The GNU option scanner is an explicit reused dependency from the pinned archive.

Source changes to exported component bodies require fresh local checking and
re-export through the public workbench. Ordinary application/backend edits require
affected program comparisons. `standalone-project.json` and
`lifted/source-export.json` describe provenance and assumptions; neither grants
strong qualification. The preparation repository's standalone recipe documents
normal execution, memory observations, deliberate defects, replay and another
architecture. Finite validation, assumptions and proved properties stay separate.
The preparation recipe also accepts an exported library with `--source-export`;
comparison workspaces and original runtime inputs are unnecessary for assembly.

Start from `lifted/README.md` for links to each component's generated boundary
guide beside its C. The guides expose state, services, assumptions, dependencies
and comparison examples; native binding examples are separate from this project's
portable backend. Keep personal notes outside those generated README files.

For an assured component edit, keep its editable comparison workspace and original
oracle separately. If editing C here, run `component start gnu-hello COMPONENT
--comparison-package LOCAL_PACKAGE --reuse-source PROJECT/lifted --output DRAFT`.
This imports the selected C as an unverified draft under the existing boundary;
headers, contracts and source-layout changes need the authoring/refinement workflow.
The installed `revise_comparison_package` API accepts `source_files` for a complete
replacement of the component's authored C/header set while retaining its existing
native comparison setup. Use it for file splits or renames; include unchanged
authored layout headers in that mapping. Start/check the revised package normally.
Run `component check` on that draft inside a headless Wayland desktop, then use `candidate export TARGET
--comparison CHECK --output PROJECT/lifted --update-components`. A local comparison
updates one unit; a connected comparison updates all units it selects. The other
components retain their own source and provenance without reopening their
comparison workspaces. Use `--update` for a complete selection instead.
The update accepts checked C with unchanged boundaries
and headers, preserves operator files and prints the retained backup location.
Changed contracts/headers require integration review; explicitly accept a reviewed
change with `--accept-boundary-change COMPONENT` when updating. Rebuild
the library and run affected program comparisons; export updates do not qualify
the new executable. Application/backend edits here survive the library update.
`standalone-project.json` retains initial preparation provenance; each evidence
build binds the actual current sources and reports changes from that initial set.

For controlled allocation-failure diagnostics, start clean and use the explicit
test overlay:

```sh
make clean
make -f Makefile -f diagnostics/allocation-fault.mk hello-utf8
SPX_ALLOCATION_FAIL_AT=1 SPX_ALLOCATION_FAULT_REPORT="$PWD/fault.json" \
  ./hello-utf8 --greeting='café'
```

This test build requires those two variables. `1` fails the first application
allocation; `0` disables failure. The report records attempts, injected failures
and size even when the process terminates. Help/version can return before the
allocation, so a requested fault is not necessarily reached. The normal failure
diagnostic and exit status 1 come from the application's real fatal path.
This is a controlled service returning NULL/ENOMEM, not physical heap exhaustion.

Ordinary `make` builds omit both GNU linker wrappers and the fault implementation.
The diagnostic selector relies on this reviewed allocation adapter's count/size
publication immediately before `malloc`; it excludes the UTF-8 argument owner,
observation storage and formatting allocations. Recheck the selector if changing
that adapter. The shared fault header is test infrastructure, not a production
allocator. Neither existing component contracts nor their implementations change.
