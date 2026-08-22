"""Canonical physical ABI analysis records.

Concrete producers and checkers live in their owning modules.  Keeping this
package initializer side-effect free prevents consumers from inheriting PE,
catalog, or native-solver dependencies.
"""
