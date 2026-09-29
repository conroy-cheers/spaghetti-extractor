# jq numeric context and seed component

Seven existing entries now share one ordinary C implementation of decimal/dtoa
thread state and seed initialization. [BOUNDARY.md](BOUNDARY.md) records the
borrowed live contexts, status/caches, initialization, destruction and runtime
services. The existing state-owner declaration names this module; it does not
turn those assumptions into a formal proof.

Use the retained lifting environment and installed toolkit. `project` is an
existing portable jq project with the allocator component, `native` is an existing
native comparison's `inputs/` directory, and `pthread_library` is its reviewed
Winpthreads import archive. Choose fresh output paths:

```sh
python tests/fixtures/jq-runtime-contexts/prepare.py "$project" "$work/contexts" "$toolkit"
python tests/fixtures/jq-runtime-contexts/compare.py \
  "$work/contexts/authoring" "$native" "$pthread_library" "$work/comparison"
spaghetti-headless-wayland "$toolkit" component check jq runtime-contexts \
  --comparison-package "$work/comparison" --output "$work/checked"
```

The twelve cases observe repeated live pointers, per-thread isolation, sticky
decimal status, real numeric/compiler/serializer consumers, explicit finalization
and recreation, worker destruction, and full process teardown. Deterministic
entropy services exercise a complete read, failed open, short read and failed
read; interactions and once-only seed initialization are compared. All selected
old entries plus private seed initialization and dtoa destruction are disabled
on the source side. Allocation observations use the existing shared fixture.

An observed cleanup mismatch exposed a service-boundary error: plain `atexit`
in the harness registered in the executable's registry, ahead of the DLL's
neighboring finalizers. `spx_context_atexit` now uses the same native DLL registry;
the portable project uses its shared CRT registry. The corrected check recompiles
three files and reuses four compiler objects. No checker or compiler changes are
needed. Native key/entry conventions remain in external C adapters.

Integrate through the same action used for local edits:

```sh
"$toolkit" candidate apply jq --project "$project" --comparison "$work/checked" \
  --component runtime-contexts --accept-boundary-change runtime-contexts \
  --assembly-command "python $repo/tests/fixtures/jq-runtime-contexts/assemble.py {project}"
```

Append the affected build and normal-entry workload `--check-command` arguments
to require their success before publication. `assemble.py` retains an exact
provenance record while making the original conditional dtoa linkage ordinary;
the shared recipe then retires the bodies reversibly. Existing number/hash
accessors continue forwarding to the one selected provider. They do not duplicate
keys, seeds or context heaps. Native key numbers are never copied to another host.

The portable service file supplies allocation, exit registration, entropy reads,
process identity and 32-bit time over the selected POSIX environment. Entropy is
environmental input, so independent processes need not have the same random seed.
This does not expand the documented Windows filesystem namespace profile or
qualify every OS failure/interleaving.

Retained evidence is at `build/jq-runtime-contexts-lifting-2026-09-27/`.
`contexts/shared-exit/` contains twelve matching native scenarios. Both standalone
architectures match 288 CLI and 32 live-value cases, including jq's own threaded
tests. All 40/41 neighboring component records remain unchanged. See the
[continuation report](../../../docs/jq-runtime-contexts-continuation.md) for costs,
remaining dependencies and delivery artifacts.
