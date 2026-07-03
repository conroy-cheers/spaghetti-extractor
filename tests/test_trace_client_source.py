from pathlib import Path


def test_api_symbol_resolution_requires_exact_cached_symbol_range():
    source = Path("tools/dynamorio/halo_trace.c").read_text(encoding="utf-8")
    resolver_start = source.index("resolve_api_symbol_locked")
    resolver_end = source.index("static bool\nresolve_api_symbol(", resolver_start)
    resolver = source[resolver_start:resolver_end]

    assert "SIDE_EFFECT_API_SYMBOL_RANGE_GUESS" not in source
    assert "best" not in resolver
    assert "rva >= entry->rva_start && rva < entry->rva_end" in resolver


def test_trace_client_distinguishes_target_internal_calls_from_callbacks():
    source = Path("tools/dynamorio/halo_trace.c").read_text(encoding="utf-8")

    assert '"target_internal_call"' in source
    assert '"module_internal_call"' in source
    assert 'copy_string(effect->operation, sizeof(effect->operation), "internal_call")' in source
