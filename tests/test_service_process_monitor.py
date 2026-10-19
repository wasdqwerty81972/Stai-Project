from ui.service_process_monitor import ServiceProcessMonitor


class PipeClient:
    def __init__(self):
        self.calls = []

    def get_process_snapshot_page(self, *, offset, limit, sequence, timeout):
        self.calls.append((offset, sequence))
        if offset == 0:
            return {
                "sequence": 4,
                "observed_at": "now",
                "processes": [{"pid": 1, "instance_id": "1:0x1p+0"}],
                "next_offset": 1,
                "total": 2,
                "health": {"state": "running"},
                "resync_required": False,
            }
        return {
            "sequence": 4,
            "observed_at": "now",
            "processes": [{"pid": 2, "instance_id": "2:0x2p+0"}],
            "next_offset": None,
            "total": 2,
            "health": {},
            "resync_required": False,
        }

    def get_process_events(self, *, after_sequence, limit, timeout):
        return {"sequence": 9, "events": [], "resync_required": True}


def test_service_snapshot_collects_all_pages_at_one_sequence():
    pipe = PipeClient()
    result = ServiceProcessMonitor(pipe).snapshot()

    assert [process["pid"] for process in result["processes"]] == [1, 2]
    assert result["sequence"] == 4
    assert result["health"]["source"] == "protection_service"
    assert pipe.calls == [(0, None), (1, 4)]


def test_service_event_gap_is_returned_as_resync_requirement():
    monitor = ServiceProcessMonitor(PipeClient())

    result = monitor.read_events(2)

    assert result == {"sequence": 9, "events": [], "resync_required": True}
