# Lift the object storage behind existing jq consumers

This replaces three retained runtime bodies used by object mutation and the
interpreter: table creation, final-reference destruction, and copy-on-write.
The [boundary](BOUNDARY.md) records ownership, live layouts, aliases, outcomes and
the original private entry ranges. These are hand-defined responsibilities:

| Component | Authored responsibility | Remaining services |
| --- | --- | --- |
| `object-create` | Initialize the object header, every slot and every bucket | Guarded allocation |
| `object-release` | Decrement the reference count; release active keys/values and dispose the final table | Generic value destruction, deallocation |
| `object-unshare` | Retain a unique allocation, or copy the shared table and its active references, then release the input owner | The two components above, generic value copy |

The shared C layout and value conversion come from the existing array subsystem.
The object table stays compatible with retained jq readers. No global heap model
or new checker rule is added. Ordinary C owns the loops and reference operations;
the PE32 fixture alone expresses the private EAX/EDX/stack calling conventions.
The source backend uses conventional C wrappers. See `COPYING.jq` in the reused
[array fixture](../jq-array-storage/COPYING.jq) for the upstream layout/algorithm
license.

## Prepare and edit

Use a retained jq comparison workspace containing the pinned original DLL,
compiler/runtime inputs and `jv.h`/`jq.h` headers as `BASE`. In the lifting shell:

```sh
python tests/fixtures/jq-object-storage/prepare.py BASE prepared
spaghetti-extractor component start jq object-unshare \
  --comparison-package prepared/object-unshare --output work
spaghetti-headless-wayland spaghetti-extractor component check jq object-unshare \
  --comparison-package work --history checks
```

Edit `work/source/unshare.c` and repeat the check. The preparation API binds the
create/release requirements and retains their source; generated workspace guides
expose the three boundaries. For separate local work, use `object-create` or
`object-release` and its own prepared directory. These checks can execute without
selecting the other component bodies. Partial group checks remain experimental;
the source-program handoff selects the complete representation group.

The four connected cases cover shared aliases, inactive slots after deletion,
growth through the existing rehash consumer, a unique object with an aliased
input/output holder, an actual interpreter caller and nonlocal allocation failure.
The create and release local cases separately exercise failure delivery and
destruction. The fixture traps the selected original bodies, counts their authored
replacements, and observes values, reference counts, allocation identity and
allocation lifetime through cleanup.

Run the complete public editing workflow with:

```sh
spaghetti-headless-wayland python tests/fixtures/jq-object-storage/walkthrough.py \
  BASE WALKTHROUGH
```

Its intentional defect omits release of the transferred input owner after cloning.
Returned values remain correct; retained allocation/lifetime observations expose
the leak. The focused check compiles one file and reuses eight; repair passes, and
the saved failure still replays after repair. An unchanged repeat takes about
0.61s with zero compiler, linker, execution, model or solver work. Automatic
preparation takes about 0.51s including command startup (0.375s internally);
this excludes manual boundary/ABI/adapter work.
The first recorded authoring window, from retained disassembly capture to the
first matching connected check, is recorded separately in the checkpoint. Initial
investigation before that capture is not included and no human timing is claimed.

## Replace the retained source-program bodies

The [portable binding choices](portable-bindings.json) are ordinary operator
inputs. Publish the connected matching result and refresh an existing source
project that already contains the array/path and object lookup/deletion lifts:

```sh
spaghetti-extractor candidate export jq --comparison checks/latest \
  --output PROJECT/lifted --update-components \
  --accept-boundary-change object-create \
  --accept-boundary-change object-release \
  --accept-boundary-change object-unshare
python tests/fixtures/jq-portable/refresh.py PROJECT \
  --bindings tests/fixtures/jq-object-storage/portable-bindings.json
make -j2 -C PROJECT
```

For a retained, reproducible program check, `integrate.py CHECK PROJECT OUTPUT
--prior-build PREVIOUS_BUILD/build.json` copies the project, uses those exact
compiler/binutils paths, publishes the selection, builds and compares a normal
workload to the saved native interpreter observation. For an AArch64 project add
`--runner /path/to/qemu-aarch64`. It checks that all three new bodies execute and
that neighboring component records and compiled objects are retained.

The source recipe previously only recognized public backend definitions and
assumed value-token transport headers for additional components. It now accepts
explicitly selected private definitions, retaining an external prototype where
each body was removed, and lets opaque/scalar entries use their declared C
headers. The operator supplies the compatible wrappers in `*-binding.h`.
They live outside the backend archive: the existing original-body absence and
single-definition checks still apply. Neither conversion semantics nor private
ABI compatibility is inferred from the signature.

The x86-64 and AArch64 normal workloads pass through existing object deletion,
lookup, path mutation and the interpreter while using the new lifecycle bodies.
This removes their native/source implementations as dependencies; guarded
allocation, generic value services, rehash/insertion and the rest of jq remain
explicit dependencies. It is a partial source-assisted lift, with finite evidence
and the stated layout/environment assumptions. Source-program allocation failure,
arbitrary callbacks, corrupt heaps, concurrency and full jq recovery are not
established by this run. Broader prior program matrices are retained evidence,
not claimed as rerun after this change.

Inputs, costs, native/local checks, defect replay and both program executions are
retained under `build/component-object-storage-2026-09-25/`. The initial cursor
defect that formed a broken bucket chain is retained separately with its timeout;
the focused leak case is the reproducible editing demonstration. No pilot rebuild
or model/solver work was needed.
