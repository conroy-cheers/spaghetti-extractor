# Actual Metapad resource-call proof regions

The two retained Behavioral-C regions start at 0x5646 and 0x570e. They push
message flags 48, caption address 0x40e3a4 and resource IDs 31 and 32 respectively,
then call 0x1284 and reach 0x5654 and 0x571c. The pending argument, caption and
flags remain live at those successors. `boundary.json` binds the transfer-plan
input, exact generated files and the supplier's original identity.

These are proof regions inside real callers, not new production APIs or complete
caller components. The test's ordinary C fragments express their resource calls.
The region checker uses a paired shared transition with related arguments and
all declared readable input bytes, arbitrary framed post-memory and the returned
alias. A temporary difference outside that readable union is permitted; restoring
a changed input byte only after the call cannot make that call compatible.
Neither implementation of the supplier is compiled into the caller model.
Its checked private writes lie below all the caller words retained by these cuts.
The memory callbacks reject other caller accesses; no private callee value is
transported across the cut.

`transition.json` retains the domain from a public conditional supplier check as
a test premise. It is not self-validating proof evidence. The application driver
separately validates the actual public source certificate, original comparison,
compiled objects and raw query evidence using `checked_shared_original_transition`.
That supplier proof supplies matched internal effects under its named runtime
and service assumptions. The callers cannot infer effects from a signature alone.

The model does not establish the callers' incoming path coverage, whole cleanup
loop, MessageBox string safety, native service ABI or runtime qualification.
In particular it imposes no current-NUL postcondition on service failure.

`finite-caller/` reuses the ID-31 region at 0x5646 through the common finite caller
checker. Its ordinary C returns the shared view; explicit exit observations check
all pending caption/flags/argument slots. The definition contains no target Python
or C proof predicate. This fixture exercises integration before freezing the rule;
it is not the reserved untouched resource-ID-97 consumer. `supplier-exact.json`
binds the original supplier used by the retained public comparison; the fixture
transition remains a test premise, not self-validating evidence.

`following-service/` extends that already used ID-31 caller through `0x5654` and
MessageBoxA at `0x565c`, continuing at `0x5662`. Ordinary C passes the returned
live view and reads the window after the supplier call. The future window
argument slot overlaps the earlier CALL return word: it is uninitialized at the
supplier invocation and becomes readable only after its actual caller write.
Existing initialized caption/flags/ID slots remain protected from child writes.
The fixture binds the canonical plan identity; its supplier transition remains
a test premise. Real retained source objects were independently rechecked under
that identity without changing their original C bytes or rebuilding the supplier.
MessageBox applicability, termination and reentrancy remain unverified.

`error-notice/` is the reserved acceptance case, authored after the shared rule
freeze on 2026-09-15. It owns the actual transfers `0x12c0` and `0x12ce`, fetches
resource 97 at `0x12c9`, calls MessageBoxA at `0x12d6` and continues at `0x12dc`.
Its exact C was regenerated from the retained plan and matched the preselected
candidate's original bytes, PE identity and recorded incoming edge. No production
Python or Nix rule changed. Public source and boundary edits, rejection, repair,
and compatible supplier reuse exercise this definition independently. Its
`transition.json` and `supplier-exact.json` are regression-test premises; public
checks validate the retained real supplier evidence separately. This is a local
conditional operation, not whole-routine completion or activation permission.

The accepted error-notice definition uses a 500-byte caption view, matching the
bounded span in the retained native fixture. Refining the initial one-byte view
changed the contract and required rechecking despite unchanged ordinary C and C
signature types. It establishes neither string termination nor general MessageBox
applicability. The earlier ID-31 development fixture retains its narrower address
transport experiment and unverified runtime assumptions.
