import time
from threading import Event
from types import SimpleNamespace

from ui.windows_process_events import decode_process_event, WindowsProcessEventSource


def test_process_event_uses_payload_pid_not_event_header_pid():
    event = SimpleNamespace(
        ProcessID=4321,
        ParentProcessID=123,
        ProcessName="sample.exe",
        TIME_CREATED=133801632000000000,
        header_pid=9999,
    )

    decoded = decode_process_event(event, "start")

    assert decoded["pid"] == 4321
    assert decoded["parent_pid"] == 123
    assert decoded["name"] == "sample.exe"
    assert decoded["event_time"] == (133801632000000000 / 10_000_000) - 11644473600


def test_invalid_event_pid_is_rejected():
    assert decode_process_event(SimpleNamespace(ProcessID="bad"), "start") is None


def test_unsupported_host_reports_unavailable_without_starting_threads():
    source = WindowsProcessEventSource(platform_supported=False)

    status = source.start(lambda event: None, lambda event: None)

    assert status.state == "unavailable"
    assert "Windows" in status.error
    source.stop()


def test_trace_events_reach_start_and_stop_callbacks():
    completed = Event()
    received = []
    event = SimpleNamespace(
        ProcessID=4321,
        ParentProcessID=123,
        ProcessName="sample.exe",
        TIME_CREATED=133801632000000000,
    )

    class Stream:
        def __init__(self):
            self.sent = False

        def NextEvent(self, timeout):
            if not self.sent:
                self.sent = True
                return event
            raise RuntimeError("test stream ended")

    class Connection:
        def ExecNotificationQuery(self, query):
            assert query in {
                "SELECT * FROM Win32_ProcessStartTrace",
                "SELECT * FROM Win32_ProcessStopTrace",
            }
            return Stream()

    def callback(action):
        def receive(record):
            received.append((action, record["pid"]))
            if len(received) == 2:
                completed.set()
        return receive

    source = WindowsProcessEventSource(platform_supported=True, wmi_factory=Connection)
    source.start(callback("start"), callback("stop"))

    assert completed.wait(2)
    source.stop()
    assert sorted(received) == [("start", 4321), ("stop", 4321)]


def test_wmi_initialization_failure_is_reported_for_fallback():
    source = WindowsProcessEventSource(
        platform_supported=True,
        wmi_factory=lambda: (_ for _ in ()).throw(OSError("WMI unavailable")),
    )
    source.start(lambda event: None, lambda event: None)
    deadline = time.monotonic() + 2
    while source.status.state == "starting" and time.monotonic() < deadline:
        time.sleep(0.01)

    assert source.status.state == "unavailable"
    assert "WMI unavailable" in source.status.error
    source.stop()


def test_wmi_timeout_keeps_trace_subscription_healthy():
    class TimedOut(Exception):
        hresult = -2147217303  # signed HRESULT for 0x80041069 (WBEM_E_TIMED_OUT)

    class Stream:
        def NextEvent(self, timeout):
            raise TimedOut("no event before timeout")

    class Connection:
        def ExecNotificationQuery(self, query):
            return Stream()

    source = WindowsProcessEventSource(platform_supported=True, wmi_factory=Connection)
    source.start(lambda event: None, lambda event: None)
    deadline = time.monotonic() + 2
    while source.status.state == "starting" and time.monotonic() < deadline:
        time.sleep(0.01)

    assert source.status.state == "running"
    assert source.status.error is None
    source.stop()
