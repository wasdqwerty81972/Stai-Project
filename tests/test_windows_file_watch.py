from __future__ import annotations

import struct
import threading
from pathlib import Path

from cyber_os.sensors.windows_file_watch import (
    FILE_ACTION_ADDED,
    FILE_ACTION_MODIFIED,
    FILE_ACTION_RENAMED_NEW_NAME,
    build_file_activity_event,
    monitored_user_roots,
    parse_file_notify_buffer,
    WindowsFileActivityMonitor,
)


def test_file_notify_buffer_decodes_linked_records_and_utf16_names():
    first_name = "Downloads\\payload.exe".encode("utf-16-le")
    second_name = "readme.txt".encode("utf-16-le")
    first_size = 12 + len(first_name)
    first_offset = (first_size + 3) & ~3
    raw = (
        struct.pack("<III", first_offset, FILE_ACTION_ADDED, len(first_name))
        + first_name
        + b"\x00" * (first_offset - first_size)
        + struct.pack("<III", 0, FILE_ACTION_MODIFIED, len(second_name))
        + second_name
    )

    assert parse_file_notify_buffer(raw) == [
        (FILE_ACTION_ADDED, "Downloads\\payload.exe"),
        (FILE_ACTION_MODIFIED, "readme.txt"),
    ]


def test_file_activity_event_keeps_target_transient_and_uses_safe_summary(tmp_path):
    target = tmp_path / "dropper.exe"
    target.write_bytes(b"sample")

    event = build_file_activity_event(target, FILE_ACTION_ADDED)

    assert event.event_type == "file_activity"
    assert event._protection_target == str(target)
    assert "dropper.exe" not in str(event.to_dict())
    assert "executable or script" in event.to_dict()["details"]["summary"]


def test_monitored_roots_include_only_existing_user_drop_folders(tmp_path):
    profile = tmp_path / "profile"
    (profile / "Downloads").mkdir(parents=True)
    (profile / "Desktop").mkdir()

    roots = monitored_user_roots(profile)

    assert roots == [profile / "Downloads", profile / "Desktop"]


def test_monitored_roots_respect_enrolled_users_redirected_known_folders(tmp_path):
    profile = tmp_path / "profile"
    (profile / "Downloads").mkdir(parents=True)
    redirected = profile / "OneDrive" / "Personal Downloads"
    redirected.mkdir(parents=True)

    roots = monitored_user_roots(profile, {"Downloads": r"%USERPROFILE%\OneDrive\Personal Downloads"})

    assert roots[0] == redirected
    assert profile / "Downloads" not in roots


def test_renamed_file_notifications_are_eligible_for_scanning(tmp_path):
    target = tmp_path / "eicar.com"
    target.write_bytes(b"test")

    event = build_file_activity_event(target, FILE_ACTION_RENAMED_NEW_NAME)

    assert event is not None
    assert event._protection_target == str(target)


def test_deleted_notifications_do_not_create_scan_events(tmp_path):
    assert build_file_activity_event(tmp_path / "removed.exe", 2) is None


def test_drop_monitor_coalesces_repeated_write_notifications(tmp_path):
    target = tmp_path / "payload.exe"
    target.write_bytes(b"test")
    events = []
    delivered = threading.Event()

    def receive(event):
        events.append(event)
        delivered.set()

    monitor = WindowsFileActivityMonitor([], receive, settle_seconds=0.1)
    monitor._queue_scan(target, FILE_ACTION_ADDED)
    monitor._queue_scan(target, FILE_ACTION_MODIFIED)

    assert delivered.wait(1.0)
    assert len(events) == 1
    assert events[0]._protection_target == str(target)
