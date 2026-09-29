# Consuming string hash with a shared mutable cache

Own the complete `jv_string_hash(jv)` entry at RVA `0x29d78..0x29e0a` in the
pinned PE32 jq DLL (SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`).
The authored implementation includes the MurmurHash3 loop previously called
through the private `jvp_string_hash`, cache-hit behavior, cache writes and input
release. Its own path never calls either native hash implementation. Other
unlifted backend operations still use the private helper.

- Consume one live string reference and return the unsigned 32-bit hash, including
  modulo-2^32 arithmetic and the original x86 little-endian byte grouping. The
  native public C API spells the result `unsigned long`; a portable ABI adapter
  must return the zero-extended value when that type is wider.
- A well-formed allocation has four 32-bit header words followed by its byte
  storage. Length is at most INT32_MAX. Embedded NUL and malformed UTF-8 bytes
  are admitted. Aliases may retain the same allocation. The header/view is shared
  with C adapters; no pointer reconstruction or heap copy establishes lifetime.
- When the low length flag is set, return the stored hash without reading the
  process seed or changing the cache. Otherwise compute the hash, set the flag
  and store the hash in the actual allocation, then release the input reference.
  A borrowed view permits this cache mutation; it is not an exclusive borrow.
- The seed service retains the native once-initialization/entropy behavior. Its
  value stays fixed while objects hashed using it remain live. The local fixture
  initializes then controls that native word before creating strings, so both
  processes receive the same seed. Program consumers use their normal process
  seed; cache hashes and bucket layout need not match across processes.
- Calls are single-threaded and synchronous, with no overlapping mutation,
  reentrancy or asynchronous observation of the cache writes. The view expires
  when the owner is released. Native reference/allocation services remain explicit
  dependencies, including their behavior for uniquely held inputs.

The local driver observes exact results, shared cache words and bytes, surviving
reference counts and allocation lifetime. It includes cached sentinel values and
all tail lengths through several loop iterations. Those finite comparisons and
ordinary C adapters do not prove arbitrary heap states, concurrent initialization
or all inputs. Surrounding-code analysis is needed to establish these premises;
ordinary C edits use the recorded boundary.
