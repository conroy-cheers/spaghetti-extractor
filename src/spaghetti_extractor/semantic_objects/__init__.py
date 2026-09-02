"""Relocatable semantic objects whose only executable body is transfer-v2.

Keep the package initializer dependency-free so the format registry can inspect
domain ownership without importing the transfer toolchain.  Production callers
import the closed codec from :mod:`semantic_object` explicitly.
"""

__all__: list[str] = []
