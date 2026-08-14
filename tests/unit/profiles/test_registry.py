from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.profiles import (
    ProfileRegistryError,
    load_profile_registry,
    validate_profile_inventory,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PROFILE_DIRECTORY = REPOSITORY_ROOT / "profiles"
EXPECTED_PROFILES = {
    "i686-mingw-freestanding-c0-v1.json",
    "pe32-kernel32-callable-resolvers-v1.json",
    "pe32-kernel32-console-lockstep-v1.json",
    "pe32-kernel32-lockstep-v1.json",
    "pe32-kernel32-runtime-v1.json",
    "pe32-mingw-directx-interface-extraction-v1.json",
    "pe32-mingw-win32-function-extraction-v1.json",
    "pe32-msvcrt-lockstep-v1.json",
    "pe32-msvcrt-machine-runtime-v1.json",
    "pe32-native-callthrough-runtime-v1.json",
    "pe32-normal-return-nonvolatile-v1.json",
    "pe32-static-cutpoints-and-paired-callables-v1.json",
    "pe32-win32-console-launch-assumptions-v1.json",
    "pe32-win32-gui-launch-assumptions-v1.json",
    "pe32-win32-system-dll-abi-policy-v1.json",
    "pe32-win32-windowing-runtime-v1.json",
    "pe32-winmm-runtime-v1.json",
}


class ProfileRegistryTests(unittest.TestCase):
    def copy_profiles(self, root: Path) -> Path:
        destination = root / "profiles"
        destination.mkdir()
        for source in PROFILE_DIRECTORY.iterdir():
            if source.is_file():
                # Nix test inputs are read-only store paths. copyfile creates a
                # writable fixture instead of preserving those source modes.
                shutil.copyfile(source, destination / source.name)
        return destination

    def rewrite_catalog(self, directory: Path, transform) -> None:
        path = directory / "catalog.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        transform(payload)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_committed_catalog_validates_exact_inventory(self) -> None:
        registry = validate_profile_inventory(PROFILE_DIRECTORY)

        self.assertEqual(len(registry.profiles), 17)
        self.assertEqual(set(registry.by_path()), EXPECTED_PROFILES)
        for registration in registry.registrations:
            self.assertTrue(registration.role)
            self.assertTrue(registration.validator_id)

    def test_unregistered_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = self.copy_profiles(Path(raw))
            (directory / "unexpected-v1.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ProfileRegistryError, "unregistered: unexpected-v1.json"
            ):
                validate_profile_inventory(directory)

    def test_registered_profile_missing_from_disk_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = self.copy_profiles(Path(raw))
            missing = "pe32-winmm-runtime-v1.json"
            (directory / missing).unlink()

            with self.assertRaisesRegex(
                ProfileRegistryError, f"missing files: {missing}"
            ):
                validate_profile_inventory(directory)

    def test_unknown_validator_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = self.copy_profiles(Path(raw))
            self.rewrite_catalog(
                directory,
                lambda payload: payload["profiles"][0].update(
                    {"validator_id": "missing-validator-v1"}
                ),
            )

            with self.assertRaisesRegex(
                ProfileRegistryError, "validator_id is unknown"
            ):
                load_profile_registry(directory / "catalog.json")

    def test_arbitrary_profile_role_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = self.copy_profiles(Path(raw))
            self.rewrite_catalog(
                directory,
                lambda payload: payload["profiles"][0].update(
                    {"role": "looks-plausible-but-unowned"}
                ),
            )

            with self.assertRaisesRegex(
                ProfileRegistryError, "role is not a supported profile role"
            ):
                load_profile_registry(directory / "catalog.json")

    def test_profile_role_rejects_an_unrelated_validator(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = self.copy_profiles(Path(raw))
            self.rewrite_catalog(
                directory,
                lambda payload: payload["profiles"][0].update(
                    {"validator_id": "machine-import-profile-v1"}
                ),
            )

            with self.assertRaisesRegex(
                ProfileRegistryError, "cannot validate role"
            ):
                load_profile_registry(directory / "catalog.json")

    def test_registered_profile_must_pass_its_validator(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = self.copy_profiles(Path(raw))
            profile_path = directory / "i686-mingw-freestanding-c0-v1.json"
            payload = json.loads(profile_path.read_text(encoding="utf-8"))
            payload["format"] = "unsupported"
            profile_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ProfileRegistryError, "expected profile format"
            ):
                validate_profile_inventory(directory)


if __name__ == "__main__":
    unittest.main()
