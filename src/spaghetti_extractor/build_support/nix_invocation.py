"""Canonical Nix invocation and portable builder selection."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


BUILDERS_FILE_ENV = "SPAGHETTI_EXTRACTOR_BUILDERS_FILE"
TRUSTED_PUBLIC_KEYS_FILE_ENV = (
    "SPAGHETTI_EXTRACTOR_TRUSTED_PUBLIC_KEYS_FILE"
)
NIX_FEATURES = "nix-command flakes ca-derivations"
_LOCAL_BUILDERS = Path("nix/builders.local")
_LOCAL_KEYS = Path("nix/trusted-public-keys.local")


class NixInvocationError(ValueError):
    """A requested Nix execution policy is invalid or unavailable."""


@dataclass(frozen=True, slots=True)
class BuilderPolicy:
    source: str
    builders_file: Path | None
    trusted_public_keys_file: Path | None
    trusted_public_keys: tuple[str, ...] = ()

    @property
    def local(self) -> bool:
        return self.builders_file is None

    def nix_arguments(self) -> tuple[str, ...]:
        if self.local:
            return ("--builders", "")
        assert self.builders_file is not None
        arguments = [
            "--builders",
            f"@{self.builders_file}",
            "--option",
            "builders-use-substitutes",
            "true",
        ]
        if self.trusted_public_keys:
            arguments.extend(
                ["--option", "trusted-public-keys", " ".join(self.trusted_public_keys)]
            )
        return tuple(arguments)


def nix_command(*arguments: str) -> list[str]:
    return ["nix", "--extra-experimental-features", NIX_FEATURES, *arguments]


def select_builder_policy(
    *,
    target_flake: str,
    builders_file: Path | str | None = None,
    trusted_public_keys_file: Path | str | None = None,
    local: bool = False,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> BuilderPolicy:
    """Resolve one explicit builder policy shared by every public workflow."""

    if local and (builders_file is not None or trusted_public_keys_file is not None):
        raise NixInvocationError(
            "--local cannot be combined with builder or trusted-key files"
        )
    if local:
        return BuilderPolicy("explicit-local", None, None)

    current = (Path.cwd() if cwd is None else Path(cwd)).resolve()
    env = os.environ if environment is None else environment
    explicit_builders = builders_file
    if explicit_builders is None:
        explicit_builders = env.get(BUILDERS_FILE_ENV)
    explicit_keys = trusted_public_keys_file
    if explicit_keys is None:
        explicit_keys = env.get(TRUSTED_PUBLIC_KEYS_FILE_ENV)

    if explicit_builders is not None:
        selected_builders = _required_file(
            explicit_builders, current, "Nix builders"
        )
        selected_keys = (
            _required_file(explicit_keys, current, "trusted public keys")
            if explicit_keys is not None
            else _discover_companion_file(
                _LOCAL_KEYS,
                target_flake=target_flake,
                cwd=current,
                environment=env,
            )
        )
        source = (
            "explicit"
            if builders_file is not None
            else f"environment:{BUILDERS_FILE_ENV}"
        )
        return _builder_policy(source, selected_builders, selected_keys)

    local_builders = _discover_nearest_file(
        _LOCAL_BUILDERS, target_flake=target_flake, cwd=current
    )
    if local_builders is not None:
        local_keys = local_builders.parent / _LOCAL_KEYS.name
        return _builder_policy(
            "repository-local",
            local_builders,
            local_keys.resolve() if local_keys.is_file() else None,
        )

    xdg_root = Path(
        env.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    ).expanduser()
    xdg_builders = xdg_root / "spaghetti-extractor" / "builders"
    if xdg_builders.is_file():
        xdg_keys = xdg_builders.with_name("trusted-public-keys")
        return _builder_policy(
            "xdg-config",
            xdg_builders.resolve(),
            xdg_keys.resolve() if xdg_keys.is_file() else None,
        )

    if explicit_keys is not None:
        raise NixInvocationError(
            "trusted public keys were configured without a builders file"
        )
    return BuilderPolicy("default-local", None, None)


def builder_arguments(
    *,
    target_flake: str,
    builders_file: Path | str | None,
    local: bool,
    trusted_public_keys_file: Path | str | None = None,
    cwd: Path | None = None,
) -> list[str]:
    return list(
        select_builder_policy(
            target_flake=target_flake,
            builders_file=builders_file,
            trusted_public_keys_file=trusted_public_keys_file,
            local=local,
            cwd=cwd,
        ).nix_arguments()
    )


def _discover_companion_file(
    relative: Path,
    *,
    target_flake: str,
    cwd: Path,
    environment: Mapping[str, str],
) -> Path | None:
    found = _discover_nearest_file(relative, target_flake=target_flake, cwd=cwd)
    if found is not None:
        return found
    xdg_root = Path(
        environment.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    ).expanduser()
    candidate = xdg_root / "spaghetti-extractor" / "trusted-public-keys"
    return candidate.resolve() if candidate.is_file() else None


def _discover_nearest_file(
    relative: Path, *, target_flake: str, cwd: Path
) -> Path | None:
    starts = [cwd]
    flake_path = _local_flake_path(target_flake, cwd)
    if flake_path is not None:
        starts.insert(0, flake_path)
    visited: set[Path] = set()
    for start in starts:
        directory = start if start.is_dir() else start.parent
        for candidate_root in (directory, *directory.parents):
            if candidate_root in visited:
                continue
            visited.add(candidate_root)
            candidate = candidate_root / relative
            if candidate.is_file():
                return candidate.resolve()
    return None


def _trusted_public_keys(path: Path) -> tuple[str, ...]:
    try:
        rows = tuple(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    except OSError as exc:
        raise NixInvocationError(
            f"cannot read trusted public keys file {path}: {exc}"
        ) from exc
    return rows


def _builder_policy(
    source: str, builders_file: Path, trusted_public_keys_file: Path | None
) -> BuilderPolicy:
    return BuilderPolicy(
        source=source,
        builders_file=builders_file,
        trusted_public_keys_file=trusted_public_keys_file,
        trusted_public_keys=(
            ()
            if trusted_public_keys_file is None
            else _trusted_public_keys(trusted_public_keys_file)
        ),
    )


def _required_file(value: Path | str, cwd: Path, label: str) -> Path:
    path = _resolve_path(Path(value).expanduser(), cwd)
    if not path.is_file():
        raise NixInvocationError(f"{label} file does not exist: {path}")
    return path


def _local_flake_path(reference: str, cwd: Path) -> Path | None:
    if reference.startswith("path:"):
        return _resolve_path(Path(reference.removeprefix("path:")), cwd)
    parsed = urlparse(reference)
    if parsed.scheme == "file":
        return Path(parsed.path).resolve()
    if parsed.scheme or "#" in reference:
        return None
    return _resolve_path(Path(reference), cwd)


def _resolve_path(path: Path, cwd: Path) -> Path:
    return (path if path.is_absolute() else cwd / path).resolve()


__all__ = [
    "BUILDERS_FILE_ENV",
    "TRUSTED_PUBLIC_KEYS_FILE_ENV",
    "BuilderPolicy",
    "NIX_FEATURES",
    "NixInvocationError",
    "builder_arguments",
    "nix_command",
    "select_builder_policy",
]
