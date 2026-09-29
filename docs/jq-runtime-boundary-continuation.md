# jq runtime boundary refinement

Two existing components now cover more of jq without adding a new component or
changing tool internals. The same `candidate apply` operation handles their new
entries, source export, backend retirement, program bindings, build and workload
checks. Both delivered architectures match 287 CLI and 32 live-value cases.

## What changed

`value-runtime` grows from 39 to 40 native entries. Its release dispatcher consumes
one reference and calls the existing array, string, object, invalid-value or numeric
destructor. Native comparison disables the original `jv_free` body, including on
recursive crossings through original neighbors. Forty-eight scenarios match;
the added scenario retains aliases into a mixed graph and releases them in
different orders. The comparison observes 128,961 authored release-entry calls.

Standalone assembly preserves the array-storage component's public `jv_free`.
Its guarded foreign-release service calls the new dispatcher as `backend_free`
only for non-arrays. The dispatcher's array service uses selected array storage.
This explicit domain restriction preserves the existing boundary and avoids
adding a second public provider. The old backend dispatcher is absent, while
`jv_free` and `backend_free` each have exactly one linked definition.

`program-support` grows from 17 to 20 entries. The new ordinary C implements
`get_home`, `expand_path` and `_jq_memmem`. Home lookup uses the original Windows
environment precedence on either host: HOME, USERPROFILE, then HOMEDRIVE plus
HOMEPATH. Returned values copy borrowed environment bytes. Expansion consumes
one path reference and preserves other aliases. Only `~/` expands; embedded NULs
and error messages retain the original behavior. Byte search preserves aliased
input buffers, reports an interior pointer, and preserves the original empty
haystack behavior. Sixty-two native scenarios match, with all twenty entry
adapters exercised and their selected original bodies disabled.

The C is source-assisted from pinned jq 1.8.1. Native ABI adapters, environment
observations and source assembly remain ordinary fixture code. Filesystem
canonicalization, entropy and TLS lifetime are not supplied by these additions.
Finite comparison, assumptions and formal qualification remain distinct.

## Application and reuse

`build/jq-runtime-boundary-lifting-2026-09-27/apply.py` runs the installed public
command with both retained comparisons and one desired binding selection per
architecture. It acknowledges each changed boundary explicitly. The ARM project
retains its separately checked hash provider. Build and normal-entry comparisons
run in the staged project before publication. All Wine execution uses headless
Wayland desktops; no pilot rebuild or solver run is needed.

| Evidence | x86-64 | AArch64 |
| --- | ---: | ---: |
| Selected components | 40 | 41 |
| Unchanged neighboring component records | 38 | 39 |
| Unchanged neighboring exported files | 480 | 486 |
| Objects retaining bytes and mtime | 178 | 179 |
| Changed/new objects | 11 | 11 |
| Build wall time | 0.766 s | 11.184 s |
| Program comparison wall time | 22.789 s | 33.054 s |
| CLI cases matched | 287 | 287 |
| Live-value cases matched | 32 | 32 |

The changed objects are the two affected backend files, two entry adapters and
seven source objects from the refined components. The new utility translation
unit accounts for the additional object. Generated binding guides now also
describe the unified apply workflow, including the guides for older components.

Native preparation takes 0.027/0.020 seconds for values/support; compiler child
time is 0.704/0.767 seconds and link time is 0.064/0.064 seconds. Wine startup
takes 9.653/9.456 seconds wall time, and execution takes 8.407/9.809 seconds summed
over the two sides. The independent checks ran concurrently. Model, solver and
pilot-rebuild costs are zero; these measurements exclude operator analysis.

## Remaining delivery work

The current executable's link map identifies the remaining backend consumers:

| Dependency | Actual consumer / remaining responsibility |
| --- | --- |
| `jv.o` | Numeric values require the decimal TLS context; shared hashing needs seed initialization. `spx_object_unshare` forwards to the selected object component. |
| `jv_dtoa_tsd.o` | The serializer requires per-thread dtoa context creation and destruction. |
| `util.o` | Only `jq_realpath` remains; the loader needs a portable path-canonicalization provider with explicit namespace semantics. |
| `jq_test.o` | CLI `--run-tests` still invokes the retained internal test runner. |
| `bindings/native-slice.c` | Get/set retain the source-assisted slice-bound helper, still explicitly unlifted. |
| Generated `lexer.o` | The authored language parser consumes the pinned Flex scanner. |
| `jv_dtoa.o`, decNumber, Oniguruma | Conversion, decimal arithmetic and regex support remain pinned source libraries. |

The generated scanner and established numeric/regex libraries are reasonable
explicit reuse boundaries; rewriting them for component counts would not improve
the operator workflow. Final delivery must retain their sources, versions,
licenses, platform assumptions and actual consumers. Their reuse is not a claim
that their implementations have been independently proved. Existing normal-entry
comparisons already exercise them on both architectures, within the documented
runtime profile. Lifecycle and path behavior still need implementation/review;
classifying those services does not supply missing behavior.

Full jq remains incomplete. No significant tooling impasse was found, and the
active lifting goal remains active. Strong qualification is separate.

Evidence is retained under `build/jq-runtime-boundary-lifting-2026-09-27/`:
`values/checked/`, `support/checked/`, `program/`, `arm-project/`,
`host-integrated-*`, `arm-integrated-*`, `result.json`,
`remaining-linked-backend-functions.json`, `validation.json` and `tree-audit.json`.
