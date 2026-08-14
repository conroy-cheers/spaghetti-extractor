"""Typed authority analyses with explicit module-owned public interfaces.

Importing this package must stay cheap and dependency-free.  Consumers import
the phase or codec from its owning module so one implementation change does
not invalidate every Nix phase closure.
"""

__all__: list[str] = []
