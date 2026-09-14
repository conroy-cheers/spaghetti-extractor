# Guarded cleanup and UI replacement consumer

The five original transfers rooted at 0xb18e include both mode guards, cleanup
at 0xb19c, four outgoing argument pushes and SendMessageA at 0xb1af. Modes 2 and
3 skip cleanup. Three incoming controls all enter at the root; the selected
normal successor is 0xb1b5. `boundary-edges.json` records this structural scope,
not a proof of caller reachability or progress outside the selected operation.

The ordinary C reads the edit-window handle after cleanup. Its record result
separates a cleanup/access fault from every uint32 SendMessage result, including
UINT32_MAX. The model's returning-service contract is conditional: actual UI
applicability, termination/contents after cleanup, callbacks, nonreturn and
invocation faults remain unqualified. No successful-allocation assumption is
introduced, and cleanup-specific admission is required only on its call branch.

`summary-input.json` is input data for unit tests, which replace only the supplier
importer. It is not proof authority. Actual public experiments independently
import the checked supplier product. The exact slice retains callee provenance;
only the five owned transfers and generic runtime support enter the proof.
Private argument words are disjoint from public views and mode storage. Tracking
them separately avoids adding private writes to public-memory history while
still checking the original argument stores and values.
