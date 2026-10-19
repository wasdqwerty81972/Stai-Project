"""Optional GPU capability detection for high-volume telemetry workloads."""

from __future__ import annotations

import importlib.util
from typing import Any, Dict


def capability_status() -> Dict[str, Any]:
    """Report installed acceleration support without making it a hard dependency."""
    status: Dict[str, Any] = {
        "cuda_driver": False,
        "cudf": importlib.util.find_spec("cudf") is not None,
        "cupy": importlib.util.find_spec("cupy") is not None,
        "torch_cuda": False,
        "mode": "cpu",
    }
    try:
        import torch

        status["torch_cuda"] = bool(torch.cuda.is_available())
    except (ImportError, RuntimeError):
        pass
    status["cuda_driver"] = status["torch_cuda"] or status["cupy"] or status["cudf"]
    if status["cudf"] and status["cuda_driver"]:
        status["mode"] = "cudf"
    elif status["cupy"] and status["cuda_driver"]:
        status["mode"] = "cupy"
    return status