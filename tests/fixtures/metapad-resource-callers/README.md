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
