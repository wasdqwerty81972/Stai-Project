"""Endpoint sensor services for CyberOS."""

from cyber_os.sensors.windows_sensor_service import (
    CAPABILITIES,
    SensorEvent,
    WindowsSensorService,
    normalize_windows_event,
)
from cyber_os.sensors.sensor_registry import (
    REGISTRY_VERSION,
    SENSOR_REGISTRY,
    build_runtime_registry,
    validate_registry,
)

__all__ = [
    "CAPABILITIES",
    "REGISTRY_VERSION",
    "SENSOR_REGISTRY",
    "SensorEvent",
    "WindowsSensorService",
    "normalize_windows_event",
    "build_runtime_registry",
    "validate_registry",
]
