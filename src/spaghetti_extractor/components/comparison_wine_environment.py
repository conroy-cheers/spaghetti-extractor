"""Shared candidate-neutral Wine services, retained by ordinary comparison packages."""
from pathlib import Path

from .comparison_environment import native_adapter_headers, observation_headers

PYTHON_RESOURCES = (
    'src/spaghetti_extractor/resources/native/spx-wine-test.h',
    'src/spaghetti_extractor/resources/native/spx-wine-test-internal.h',
    'src/spaghetti_extractor/resources/native/spx-wine-test.c',
    'src/spaghetti_extractor/resources/native/spx-wine-sound.c',
    'src/spaghetti_extractor/resources/native/spx-wine-files.c',
    'src/spaghetti_extractor/resources/native/spx-wine-memory.c',
    'src/spaghetti_extractor/resources/native/spx-wine-midi.c',
    'src/spaghetti_extractor/resources/native/spx-wine-draw.c',
    'src/spaghetti_extractor/resources/native/spx-wine-draw-sdk.h',
)


def wine_test_backend() -> dict:
    """Return adapter_files/include_files for prepare_comparison_package.

    Retain once in the root consumer, alongside its application boundary adapter.
    The same sources compile for controlled standalone C consumers. Installation
    and native call-through require Win32; scenarios never infer candidate roles.
    """
    root = Path(__file__).resolve().parent.parent / 'resources/native'
    return dict(
        adapter_files={name: root / name for name in (
            'spx-wine-test.c', 'spx-wine-sound.c', 'spx-wine-files.c', 'spx-wine-memory.c', 'spx-wine-midi.c', 'spx-wine-draw.c',
        )},
        include_files={name: root / name for name in ('spx-wine-test.h', 'spx-wine-test-internal.h', 'spx-wine-draw-sdk.h')}
        | native_adapter_headers('pe32-import-hook.h') | observation_headers(),
    )
