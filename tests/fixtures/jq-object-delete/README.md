# Lift object deletion through the existing component workflow

This reuses the [object lookup](../jq-object-get/README.md)'s live layout, hash and
release services, value transport, allocation observer and two-value driver for a
mutating operation. Ordinary C owns the complete consuming `jv_object_delete`
entry, including chain traversal and unlinking. The [boundary](BOUNDARY.md) names
copy-on-write, reference ownership, view lifetime, frame and execution assumptions.

The key distinction is executable: `unshare(value, view)` consumes the old object,
returns the live object to use next and fills a view into that returned allocation.
It may preserve a unique allocation or copy a shared one. Keeping a view into the
old object would not establish either its lifetime or permission to mutate it.
The slot layout is defined by the existing lookup header; the new mutable view
adds no global ownership rule or checker model.

## Prepare and work locally

Use a retained object-get result's `inputs/` or an editable workspace as `GET_WORK`.
Enter the pinned lifting shell, then:

```sh
python tests/fixtures/jq-object-delete/prepare.py GET_WORK prepared
spaghetti-extractor component start jq object-delete \
  --comparison-package prepared/object-delete --output work
spaghetti-headless-wayland --interactive bash
spaghetti-extractor component check jq object-delete \
  --comparison-package work --history work-checks
```

Edit `work/source/delete.c` and repeat the check. Its unchanged boundary, driver
and support C reuse. The three cases cover retained aliases, unique ownership
with an explicit storage-address observation, and an actual interpreter caller
that deletes, updates and reads shared objects. Case inputs use the existing
JSON driver convention; `component start --case-file` can add ordinary inputs.

The recorded local edit renames the incoming chain link, compiles one file in
0.016s and reuses seven compiled files. The complete check takes 6.659s, mostly
fresh Wine startup. A repeated matching check takes 0.479s with zero compiler,
linker, execution, model or solver work. Initial automatic preparation takes
0.376s; these measurements exclude manual boundary and ABI analysis.

To demonstrate a meaningful discrepancy, temporarily omit
`value = spx_object_unshare(value);` from the adapter in
`work/headers/object-mutable-native.h`. The deletion result still looks correct,
but `shared-table` reports `$.samples[0].left_after.key0`: an existing owner lost
its key. Restore the adapter and recheck. The printed replay command still
reproduces the retained failure after repair. This exercises actual alias
contents through the standard comparator, with no target-specific checking rule.

The native unshare adapter is explicit operator C. Inspection of the pinned
private helper and its caller establishes the EAX result pointer and stack value
argument; `native-unshare.c` expresses that ABI with the native compiler's
`regparm(1)` adapter. Portable component C uses ordinary C11. The source backend
uses a normal C accessor to its private unshare helper instead of that Win32 ABI.

## Integrate into the existing program

Publish the matching result into an existing [portable jq project](../jq-portable/README.md):

```sh
spaghetti-extractor candidate export jq --comparison work-checks/latest \
  --output PROJECT/lifted --update-components --component object-delete \
  --accept-boundary-change object-delete
python tests/fixtures/jq-portable/refresh.py PROJECT \
  --bindings tests/fixtures/jq-object-delete/portable-bindings.json
make -j2 -C PROJECT
PROJECT/jq -nc '{"a":{"n":7},"b":[1,2]} | . as $old | del(.a) | [., $old.a.n]'
```

The binding removes the original public body, supplies the generated entry and
retains a reviewed backend accessor for copy-on-write. The existing value/path
and object-get components require no C or contract changes. The interpreter
workload matches the retained native result on x86-64 and AArch64 under QEMU.
The two existing projects retain all 19 and 18 neighboring component objects,
respectively; only the new component/binding, entry counters and affected backend
translation unit rebuild. Their incremental builds take 0.565s and 6.525s.

The older AArch64 project exposed an integration gap: refresh refused an unrelated
handwritten seed accessor in `jv.c`, although its proposed transformation already
preserved it. Refresh now binds these edits to the current backend bytes, removes
only the explicitly selected body and changes the checked adapter include block.
Surrounding C is preserved; modified managed blocks and conflicting replacement
headers still require reconciliation. The existing backup and concurrent-change
checks remain. Generated binding/Makefile conflicts keep their manual merge path.
This was a shared source-recipe fix during the trial; it needed no checker,
artifact format or compiler extension.
The same handoff also exposed header ordering changing after binding choices were
saved and reopened. Includes now use a stable order, so repeating refresh without
new inputs leaves the generated C and compiled neighbors intact.

Commands, native disassembly, exact inputs, timings, alias-defect replay and both
program runs are retained in `build/component-object-mutation-2026-09-24/`.
Native execution uses headless Wayland. No pilot or broad input matrix was rebuilt.
Copy-on-write allocation, other object operations and the rest of jq remain
backend dependencies. Failure callbacks, corrupt heaps and concurrency are outside
this handoff; the result is a practical partial lift, not full jq qualification.
