from __future__ import annotations

import pytest

from cyber_os.protection.windows_profile import KNOWN_FOLDER_IDS, KnownFolderResolver


def test_known_folder_resolver_returns_fixed_folders_and_redirected_paths() -> None:
    resolved = {
        "desktop": r"D:\OneDrive\Alice\Desktop",
        "downloads": r"D:\OneDrive\Alice\Downloads",
        "startup": r"C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    }
    calls: list[tuple[str, object]] = []
    resolver = KnownFolderResolver(
        lambda folder_id, token: calls.append((folder_id, token)) or resolved[folder_id]
    )

    roots = resolver.resolve("user-token")

    assert tuple(folder_id for folder_id, _path in roots) == KNOWN_FOLDER_IDS
    assert dict(roots) == resolved
    assert calls == [(folder_id, "user-token") for folder_id in KNOWN_FOLDER_IDS]


def test_known_folder_resolution_fails_without_publishing_partial_roots() -> None:
    def resolve(folder_id: str, _token: object) -> str:
        if folder_id == "downloads":
            raise OSError("known folder unavailable")
        return rf"C:\Users\Alice\{folder_id}"

    resolver = KnownFolderResolver(resolve)

    with pytest.raises(OSError, match="downloads"):
        resolver.resolve("user-token")

