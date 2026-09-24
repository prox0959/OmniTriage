"""
OmniTriage - Digital Forensics & Incident Response (DFIR) Artifact Collectors
Author: Çınar (prox0959)
Zero-dependency forensic acquisition engine.
"""

from .sysinfo import collect_system_info
from .execution import collect_execution_artifacts
from .browser import collect_browser_history
from .network import collect_network_artifacts
from .filesystem import collect_filesystem_artifacts
from .persistence import collect_persistence_artifacts

__all__ = [
    "collect_system_info",
    "collect_execution_artifacts",
    "collect_browser_history",
    "collect_network_artifacts",
    "collect_filesystem_artifacts",
    "collect_persistence_artifacts"
]
