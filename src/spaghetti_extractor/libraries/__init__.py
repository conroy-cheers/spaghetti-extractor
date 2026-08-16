"""Linked-library recognition and substitution contracts.

Import concrete operations from their owning modules. Keeping package import
side-effect free prevents ABI record consumers from inheriting PE parsing,
native indexing, or target-recognition dependencies.
"""
