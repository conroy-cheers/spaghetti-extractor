# Complete character-quoting caller

This retains the original `_quotearg_char_mem` at RVA `0x5494`, both direct
call events and its complete return. The transfer-plan identity is bound in
`exact/component-exact-c-slice-v1.json`; it is the same retained GNU Hello input
as the neighboring character-setter fixture. The exact slice explicitly stops
body traversal at `0x50e1` and `0x4eb3`. It contains neither callee body.

`caller-contract.json` is an ordinary finite caller definition: fixed shared
defaults, typed private byte storage, one scoped source view, and a return
observation. `caller.c` uses an ordinary 48-byte array and the generated local
view helper. The quote service has explicit **unverified** normal-return,
readonly-options, private-frame and no-escape premises.

`supplier-facts.json` supplies already normalized facts as unit-test premises.
It is not evidence and cannot be passed to the public evidence reader as a
certificate. The public retained-input experiment separately reads the actual
current setter's checked original/C evidence. Conditional caller success does
not establish following-service behavior, object escape/lifetime applicability
or native activation.
