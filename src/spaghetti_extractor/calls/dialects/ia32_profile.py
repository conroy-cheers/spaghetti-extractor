"""Literal supported surface shared by the IA-32 checker and platform catalog."""

from __future__ import annotations


IA32_DIALECTS = frozenset({"pe32-i386-gnu-v1", "pe32-i386-ms-v1"})
IA32_DIALECT_CALLING_CONVENTIONS = {
    dialect: frozenset({"cdecl", "stdcall", "fastcall", "thiscall", "vectorcall"})
    for dialect in IA32_DIALECTS
}


__all__ = ["IA32_DIALECT_CALLING_CONVENTIONS", "IA32_DIALECTS"]
