"""chp-host — multi-host router and config-driven adapter host server for CHP."""

from .router import (
    MultiHostRouter,
    NoHealthyHostError,
    UnknownCapabilityError,
)
from .serve import AdapterBuildResult, available_adapters, build_adapter_host
from .profile import HostProfile
from .environment import EnvironmentConfig, EnvironmentHostEntry, EnvironmentRemoteEntry, GatewayConfig, list_environments

__all__ = [
    "MultiHostRouter",
    "UnknownCapabilityError",
    "NoHealthyHostError",
    "build_adapter_host",
    "available_adapters",
    "AdapterBuildResult",
    "HostProfile",
    "EnvironmentConfig",
    "EnvironmentHostEntry",
    "EnvironmentRemoteEntry",
    "GatewayConfig",
    "list_environments",
]
