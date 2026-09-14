# Authored Metapad resource call

The complete ordinary `cleanup.c` and its interface are copied from
`build/independent-lifting/real-network/{source,interface}`. The authored file
has SHA256 `e9200c4c183221894f6ecad8e2249f6a3ca79976201441f535bb40e8959b9d8d`.
It is a candidate for original entry 0x55b7, not a qualified replacement.

The manual boundary surrounds the actual resource-text invocation at ID 31.
The existing compiler correspondence checks that its inserted markers are inert
across the entire function, then checks every instruction inside the region.
The selected region returns a live view through local `message`; the next caller
operation reads the window and invokes MessageBox. Incoming service-context
validity, full caller coverage/progress and MessageBox safety remain separate.

This fixture is separate from supplier and machine-caller fixtures to avoid
rebuilding their proofs when ordinary caller source changes. It supplies no
supplier proof, runtime qualification or activation authority.
