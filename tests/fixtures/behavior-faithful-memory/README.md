# Explicit expired-allocation behavior

This labelled semantic fixture uses the existing C memory-view API. Live host
arrays implement a four-byte machine region: logical deallocation leaves its
bytes readable, allocation reuse changes its contents and generation, and
unmapping faults. Both the original model and authored C observe those rules.
No host pointer is dereferenced after its C lifetime ends.

The cases retain `expired_reads` and `faults` as observations. A stale read is
permitted in the selected environment; enabling a source-only lifetime guard
changes behavior and produces a mismatch. This demonstrates how to encode an
unsafe machine effect with defined C. It neither qualifies a real binary nor
establishes universal memory safety, heap correspondence or allocator semantics.
