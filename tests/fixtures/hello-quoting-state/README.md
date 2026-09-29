# GNU Hello quoting-state source contracts

The [complete slot-operation fixture](slots/README.md) adds ordinary C for the
full quoting operation and a public comparison/edit/reuse workflow through the
real free wrapper. It retains explicit persistent-object/lifetime proof gaps.

These are the ordinary C and canonical interface from the retained real
`_get_quoting_style`, `_set_quoting_style` and `_set_char_quoting` experiment.
Original entry RVAs are `0x50b5`, `0x50c8` and `0x50e1`; the original PE SHA-256 is
`71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`.
The shared view covers the 40-byte style/flags/character-mask prefix. Nullable
options expose the remaining live origin, including permitted aliases.

The source tests prove frames, current-memory dependence and definedness. The
`character-exact` slice adds all seven original setter transfers, including its
return, generated from the retained canonical transfer plan SHA-256
`7be11fac9ce1488cc893f7ac30ba9fde00e23a2fa92cf8f2e2c882965b77be11`.
`character-binding.json` and `character-domain.json` select the existing machine
projections and an explicit conditional callee frame.

The original comparison proves scalar result, current memory and physical return
equivalence with live nullable inputs, including caller-owned storage. Its domain
requires the objects to remain live and disjoint from the private callee frame.
Tests witness both null inputs and the real 48-byte caller object at callee
entry ESP+20; wrong C that passes source frames fails the original comparison.
Neither result establishes caller object creation/lifetime, native admission or
a reusable connected summary. Those remain in `docs/current-goal.md`.

The same source checker is available through
`component check ... --source --local-contracts`. Its sparse write capacity is
asserted; exhausting it or a loop unwind bound leaves the theorem unproved.
