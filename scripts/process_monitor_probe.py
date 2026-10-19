"""Harmless child workload used by verify_process_monitor_windows.ps1."""

from __future__ import annotations

import argparse
import socket
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=12.0)
    args = parser.parse_args()
    # Keep a bounded resident buffer and an owned loopback connection while
    # generating measurable, non-malicious CPU activity.
    memory = bytearray(24 * 1024 * 1024)
    for offset in range(0, len(memory), 4096):
        memory[offset] = 1
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    accepted = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client.connect(listener.getsockname())
        accepted, _ = listener.accept()
        deadline = time.monotonic() + max(3.0, min(args.duration, 30.0))
        value = 0
        while time.monotonic() < deadline:
            for number in range(30_000):
                value = (value + number) & 0xFFFFFFFF
        # Keep references live until the workload exits.
        if value < 0:
            raise RuntimeError("unreachable")
    finally:
        client.close()
        if accepted is not None:
            accepted.close()
        listener.close()
        del memory


if __name__ == "__main__":
    main()
