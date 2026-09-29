# String codepoint-length boundary

`run(value)` consumes one live string reference and returns a signed 32-bit count.
The pinned native entry is `jv_string_length_codepoints`, RVA `0x28eac..0x28fc3`.
The original decoder advances over invalid encodings too: this is a count of byte
groups visited, not a UTF-8 validity check. Embedded NUL remains a character.

A legal 2/3/4-byte lead begins a group. If its indicated width exceeds the remaining
span, the original consumes the entire remainder before examining continuation
bytes. Otherwise it consumes the lead and consecutive continuation bytes up to
that width. Other lead bytes form a one-byte group. Overlong encodings, surrogates
and out-of-range codepoints still count as one visited group. The complete span
is readable, length is at most INT32_MAX, and invalid pointers/kinds are excluded.

The `contents` and `release` services, their exact contracts, live `string-view.h`
and ordinary C adapters are reused from the existing string work. Contents remain
valid until release; aliases share the original allocation. No bytes are changed.
Release consumes the incoming reference even for an empty string. A retained
caller alias observes one fewer reference and unchanged contents.

The driver compares unique/shared inputs, generated raw bytes and the real jq
interpreter's `length` and slicing callers. Native construction, UTF-8 sanitation
at parsing, allocation and the interpreter remain explicit dependencies. Native
body trapping is a finite-execution check, not a proof of all incoming call edges.
No new service, transport, checker or proof rule is needed for this boundary.
