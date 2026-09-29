# jq multi-file input owner

Create owns an opaque input-state allocation; add copies file names; set_parser
takes parser ownership and selects raw/JSON and optional slurping. Next returns an
owned value or invalid status, retaining read position and unread parser bytes.
Multiple state objects have independent files, counters, buffers and decoders.
Destroy nulls its owner pointer and frees state, parser, file-name and value data.
Like the pinned original, early destroy leaves an active FILE open until CRT
shutdown; this is a retained target quirk, not an invented cleanup guarantee.

Position/name/line inspect the state attached to jq's public input callback.
The adapter supplies that callback's identity; the component never fabricates
it or copies the underlying state. Wrong callbacks retain original outcomes.
The default error callback writes the existing message to stderr; custom callback
data is borrowed. Calls and destruction are synchronous and single-threaded.

File operations use the shared windows-files provider already selected by the
file-input component. Its stream handles are ordinary C-owned objects, never
serialized FILE pointers. Files are text mode; borrowed stdin uses an explicit
platform configuration controlled by --binary. Repeated '-' borrows the same
stdin and clears its error/EOF state as the original does. Namespace/profile
scope is inherited from the supplied C runtime, not proved by this interface.


All ten public entry bodies and the private read-more helper are disabled on the source side. Two real jq contexts consume state through both direct and callback entries, observing values, positions, errors, owner clearing and jq heap lifetime. Runtime FILE allocations and decoder wrappers are host services outside that jq heap observation.

The runtime owns one decoder for process stdin, shared by all input states and repeated minus entries. Clearing stdio errors preserves its CRT Ctrl-Z end marker. Callback-identity assertions use the existing platform diagnostic backend.
