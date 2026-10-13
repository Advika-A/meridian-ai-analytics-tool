"""Shared data structures for the assessment pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VendorRecord:
    """One vendor row loaded from the intake spreadsheet."""

    name: str
    product: str | None = None
    website: str | None = None
    vendor_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    row_index: int | None = None


@dataclass
class CriticalityResult:
    """Transparent criticality score derived from intake attributes only."""

    vendor_name: str
    score: float
    level: str
    factors: dict[str, float]
    notes: list[str] = field(default_factory=list)


@dataclass
class SourceCandidate:
    """A public URL or search query to review. Not an OSINT finding."""

    url: str
    source_type: str
    reason: str
    vendor_name: str
    retrieved: bool = False
    retrieval_status: str = "unexamined"  # unexamined, ok, failed, soft_404, empty, empty_js_rendered, skipped
    discovery_method: str = "seed"  # official_intake, homepage_link, sitemap, robots, known_official, search_lead
    source_relevance: str = "general"  # service_direct, documentation, privacy_security, corporate_general, lead


@dataclass
class ExtractedDocument:
    """Plain text extracted from a fetched page with complete provenance."""

    url: str
    status: str  # ok, failed, soft_404, empty, empty_js_rendered, skipped
    final_url: str = ""
    http_status: int | None = None
    title: str | None = None
    text: str = ""
    error: str | None = None
    retrieved_at: str | None = None

    def __post_init__(self) -> None:
        if not self.final_url:
            self.final_url = self.url


@dataclass
class EvidenceItem:
    """A labeled snippet taken from extracted text or manual entry. Traceable provenance."""

    category: str
    snippet: str
    heuristic_score: float
    rationale: str
    source_url: str = ""
    source_title: str = ""
    retrieved_at: str | None = None
    matched_terms: list[str] = field(default_factory=list)
    vendor_name: str = ""
    evidence_id: str = ""
    relevance: str = "ambiguous"  # service_specific, corporate_general, ambiguous, irrelevant
    verification_status: str = "unverified"  # unverified, verified, requires_human_review, rejected, manual_entry
    reviewer_notes: str = ""


@dataclass
class RiskResult:
    """Risk output that stays conservative when evidence is missing."""

    vendor_name: str
    criticality_score: float | None
    risk_score: float | None
    risk_level: str  # not_rated, low, medium, high, critical
    status: str  # not_assessed, insufficient_evidence, corporate_signal_only, service_ai_signal, confirmed_service_ai, heuristic_draft
    drivers: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    linked_evidence_ids: list[str] = field(default_factory=list)
