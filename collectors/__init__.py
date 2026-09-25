"""
OmniTriage - Digital Forensics & Incident Response (DFIR) Artifact Collectors
Author: Çınar (prox0959)
Zero-dependency forensic acquisition engine.
"""

from .sysinfo import collect_system_info
from .processes import collect_running_processes
from .execution import collect_execution_artifacts
from .browser import collect_browser_history
from .network import collect_network_artifacts
from .filesystem import collect_filesystem_artifacts
from .persistence import collect_persistence_artifacts
from .dns_cache import collect_dns_cache
from .event_logs import collect_event_logs
from .remote_exec import collect_remote_execution_artifacts
from .shimcache import parse_shimcache
from .tasks import collect_scheduled_tasks

__all__ = [
    "collect_system_info",
    "collect_running_processes",
    "collect_execution_artifacts",
    "collect_browser_history",
    "collect_network_artifacts",
    "collect_filesystem_artifacts",
    "collect_persistence_artifacts",
    "collect_dns_cache",
    "collect_event_logs",
    "collect_remote_execution_artifacts",
    "parse_shimcache",
    "collect_scheduled_tasks"
]
