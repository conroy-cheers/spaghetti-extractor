# DX-Ball clock, wait and random state

`clock.c` and `random.c` replace eight remaining application/runtime bodies with
ordinary C. They reuse the existing bootstrap clock cell and application objects.
[BOUNDARY.md](BOUNDARY.md) records the low-word clock policy, explicit scratch
history, callbacks, wrapping comparisons, random recurrence and fault outcomes.
The original application source is not used.

Inside the existing development environment, prepare from retained inputs:

```sh
python tests/fixtures/dxball-runtime/prepare.py /path/to/DXBall.exe \
  /path/to/bootstrap-normal-check/inputs /tmp/runtime
spaghetti-headless-wayland spaghetti-extractor component check dxball runtime-support \
  --comparison-package /tmp/runtime/runtime-support --output /tmp/runtime-check
```

The 46 local cases compare return values, complete boundary state, query storage
and ordered service effects. They cover partial/failed clock writes, divisor
caching, callbacks, wrap behavior, vertical/polling waits, shared random sequences
and the two original arithmetic faults. Native stack-history adapters and fault
capture are fixture code; authored C does not read uninitialized storage or invoke
undefined division. The normal platform adapter requires complete successful
version/counter outputs; failure reports the missing history transport explicitly.

A useful edit/replay replaces the elapsed expression with
`now - previous >= delay`. That seemingly conventional rewrite disagrees with
the original when `previous + delay` wraps:

```sh
spaghetti-extractor component start dxball runtime-support \
  --comparison-package /tmp/runtime-check/inputs \
  --source-file source/clock.c=/path/to/edit.c --output /tmp/runtime-edit
spaghetti-headless-wayland spaghetti-extractor component check dxball runtime-support \
  --comparison-package /tmp/runtime-edit --case elapsed-addition-wrap \
  --reuse-comparison /tmp/runtime-check --output /tmp/runtime-replay
```

Apply the matching selection to a copy of the preceding bootstrap source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/runtime-check --accept-boundary-change runtime-support \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-runtime/assemble.py {project} /tmp/runtime-check' \
  --check-command 'make -C {project} runtime' \
  --check-command 'python {project}/check-runtime.py'
```

For AArch64, provide its `CC` and `AR` in the make command and add
`--runner /path/to/qemu-aarch64` to the check. Existing source consumers and
objects are reused. The exported consumer uses concrete external input schedules;
it does not replace the remaining full-program assembly work.

For the actual game workload:

```sh
python tests/fixtures/dxball-runtime/prepare-normal.py /tmp/runtime-check/inputs \
  /path/to/bootstrap-normal-check/inputs /tmp/runtime-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/runtime-normal/package \
  --reuse-comparison /path/to/bootstrap-normal-check --output /tmp/runtime-normal-check
```

The normal adapter retires four overlapping native observation hooks while keeping
their exact paddle/frame/seed input scopes. Uncontrolled reads execute the actual
original or C clock body. The new observation field records initialization,
wait calls and random state/results. Absolute times and polling counts are not
equated across processes; deterministic clock behavior is covered locally and
consumer-visible effects remain in the existing game observations. Native bodies
remain trapped on the source side. No platform emulation is added here.

Retained evidence is under `build/dxball-runtime-2026-09-29/`: `check` has 46
matching local cases, `defect-check` rejects modular-subtraction elapsed logic,
and `normal-check-v4` preserves all 45 prior observation fields, 64 frames and
766 platform interactions. It records 334 outer runtime operations and retains
20,867,016 bytes of service instrumentation separately from application output.
The shared capture now provides a bounded 64 MiB instrumentation channel.

The run also exposed a MIDI adapter read-baseline race. The local
`provider-read-before` reproduces the lost link, and `provider-read-check` passes
all 50 MDS cases after correcting `mds-transport.c`. `prepare-normal.py` includes
that corrected transport. No authored component C needed a behavioral change.
Both exported projects include the correction and pass the 133 affected MDS
consumer cases as well as the 46 runtime cases. They contain 47 components,
180 entries and 1,153 retained cases; the preceding 46 implementations are reused.

Continue with the [standalone worklist](../dxball-standalone/README.md): math and
line/region-fill helpers, program-owned state, service wiring and reusable
platform backends remain before a source-only desktop game is delivered.
