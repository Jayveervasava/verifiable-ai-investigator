"""vai.evidence - Claude 1 package: parse logs into Events, correlate into Findings, build a timeline.

Contract functions:  ingest(paths) -> [Event]   correlate(events) -> [Finding]   timeline(findings) -> [Finding]
Extras (optional to use):  ingest_with_report(), hash_files(), timeline_text(), EVIDENCE_LIMITATIONS
"""
from .correlate import correlate
from .ingest import hash_files, ingest, ingest_with_report
from .limits import EVIDENCE_LIMITATIONS
from .timeline import timeline, timeline_text

__all__ = ["ingest", "ingest_with_report", "hash_files", "correlate", "timeline", "timeline_text", "EVIDENCE_LIMITATIONS"]
__version__ = "1.0.0"
