"""
OmniTriage - Forensic Report Generators
Generates structured JSON and standalone dark-themed interactive HTML dashboards.
Author: Çınar (prox0959)
"""

from .json_reporter import generate_json_report
from .html_reporter import generate_html_report

__all__ = ["generate_json_report", "generate_html_report"]
