# A new boundary before its comparison fixture

This operator trial starts a previously unprepared `jv_string_split` component
from an interface, authors ordinary C, then attaches a small native comparison
and updates the existing standalone jq project. The point is to exercise first
preparation with documented facilities. It adds no checker, compiler or artifact
machinery, and does not require a pilot rebuild.

Read [BOUNDARY.md](BOUNDARY.md) before editing. In particular, the empty-separator
branch admits well-formed UTF-8; allocation failure is unobserved in this trial.
Inputs can share storage. The native allocator, constructors and reference
counter remain explicit services. The source project retains its jq backend.

## Define the interface and author C

Use a retained path-network workspace containing the reviewed string-slice
services, such as
`build/component-selected-revision-2026-09-24/checked/inputs`. In the lifting shell:

```sh
spaghetti-extractor component list jq --comparison-package /path/to/network \
  --service jq.string.contents --service jq.string.create --service jq.string.release
python tests/fixtures/jq-string-split/prepare.py boundary /path/to/network interface.json
spaghetti-extractor component start jq string-split \
  --interface-intent interface.json --operation-symbol run=lifted_string_split \
  --output authored
cp /path/to/network/dependencies/string-slice/source/string-view.h authored/source/
```

The generated `authored/source/component.c` contains the actual typed prototype
and an explicit unimplemented marker. Its services are visible in `generated/`;
`compile_commands.json` and `AUTHORING.md` provide editor and syntax-check inputs.
There is no comparison plan yet. The generated `prepare.py` is an editable recipe
with the interface, source path and chosen symbol already filled in. Its
`comparison_inputs()` marks the execution setup that still needs operator work;
list `string-view.h` beside `component.c` in `source_inputs()` when using that
recipe directly. The prepared `prepare.py comparison` command below supplies
this trial's reviewed setup through the same API.
Write the implementation here. [split.c](split.c)
is this trial's worked implementation; copy it over `authored/source/component.c`
to reproduce the handoff.

The first command finds the existing string-slice declarations and points to their
C adapter definitions. Review that component's assumptions and shared object view
using the printed status command before choosing the inputs in `prepare.py`.
It does not infer the C file closure or certify that an adapter can be reused.

[prepare.py](prepare.py) defines the interface using existing
`retained_service_inputs`, `ServiceDefinition` and `component_interface` APIs.
Three existing services and the live-object transport are reused without importing
the neighboring slice algorithm. [split-native.h](split-native.h) supplies small
constructor adapters; [contents.c](contents.c) supplies the reusable borrowed view.
The slice component's preallocated-empty constructor would change allocation
behavior, so this boundary explicitly uses the original `jv_string("")` operation.

## Attach observations, check and diagnose

```sh
python tests/fixtures/jq-string-split/prepare.py comparison /path/to/network authored prepared
spaghetti-extractor component start jq string-split \
  --comparison-package prepared/string-split --output work
spaghetti-extractor component status jq string-split --comparison-package work
spaghetti-headless-wayland spaghetti-extractor component check jq string-split \
  --comparison-package work --output baseline
```

The preparation API checks the authored interface against the reviewed setup;
changed boundaries require updating that setup. The driver observes seven direct
calls (including shared input storage) and one normal interpreter workload of five
calls. These are two comparison cases, not a broad conformance matrix. The complete
native body is trapped on the replacement side. Results, alias contents/reference
counts and allocation lifetimes are compared.

The current driver is a ten-line entry wrapper around the
[shared two-value driver](../jq-value-transport/README.md#reusable-comparison-driver-for-two-owned-values).
The seven direct inputs are a JSON batch in `prepare.py`; the interpreter filter
and input are case arguments too. New ordinary inputs can use `--case-arguments`
without editing or recompiling the driver. The current observation fields are
`samples` and `allocation_lifetime`. Batch rows retain their input values while the
batch runs, so reference counts include those aliases. Earlier evidence keeps its
original raw-string setup and observation format; its receipts are not relabelled.

Edit `work/source/component.c` and pass `--reuse-comparison baseline` to the next
check. A useful diagnostic exercise is to omit the terminal empty field by changing
`if (start == text.length)` to `if (0)`. Check `--case retained` and use the printed
`replay:` command, inside `spaghetti-headless-wayland`, to inspect the saved bad
version. Restoring the original C and checking with the baseline receipt reuses its
matching evidence. A missing final field is an observable behavior defect even
though the signature and declared ownership stay the same.

## Update the ordinary source program

Given the existing source project, publish only the new component and explicitly
review its entry/backend choice:

```sh
spaghetti-extractor candidate export jq --comparison repaired \
  --output /path/to/project/lifted --update-components \
  --component string-split --accept-boundary-change string-split
python tests/fixtures/jq-portable/refresh.py /path/to/project \
  --bindings tests/fixtures/jq-string-split/portable-bindings.json
python tests/fixtures/jq-portable/build.py /path/to/project build/split-program \
  --cc "$(command -v cc)" --ar "$(command -v ar)" --ranlib "$(command -v ranlib)"
printf '%s\n' '"a,,b,"' | /path/to/project/jq -c 'split(",")'
```

Use a matching result directory for `repaired`. The export preserves existing
component edits. The refresh recipe removes `jv_string_split` from the backend and
generates its binding from the retained service declarations; no source-recipe
code change is needed. The resulting executable calls the lifted operation through
normal CLI entry. Other platform/backend services remain unlifted.

This is a source-assisted operator trial, not an independent human usability
study. Establishing the initial services, observations, native body range and C
adapters remains appreciably more work than editing the implementation. The
retained walkthrough and measurements are in
`build/component-first-boundary-2026-09-24/`.

The initial installed trial matches both comparison cases. The deliberate edit compiles
one C file and reuses seven; restoring it reuses all comparison work in 0.689s.
Normal CLI output passes on x86-64 and AArch64 under QEMU, with the existing
component objects preserved. The x86-64 incremental program build takes 0.665s.
These measurements exclude manual boundary analysis and adapter authoring. The
retained checkpoint records actual compiler/link/execution costs, assumptions and
the corrected bookkeeping premise about an additional normal-program split call.
