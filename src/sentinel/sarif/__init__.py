"""SARIF output format for GitHub Security tab integration."""

from sentinel.sarif.converter import results_to_sarif, results_to_sarif_json

__all__ = ["results_to_sarif", "results_to_sarif_json"]