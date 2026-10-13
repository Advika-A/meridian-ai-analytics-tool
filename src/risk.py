"""Combine intake criticality and verified evidence into a conservative risk view.

Principles:
- Separate intake criticality from AI usage and preliminary AI security risk.
- An explicit ai_capability_claim or confirmed_service_ai is mandatory before calculating an AI risk score.
  A subprocessor disclosure or generic security/privacy text alone is not sufficient to assign an AI risk score.
- No relevant AI evidence means status='insufficient_evidence' and risk_level='not_rated'.
  This is strictly distinct from 'no AI used' or 'low risk'.
- A corporate-level AI announcement or broad marketing blog alone does NOT establish
  that AI is used in the specific contracted service (status='corporate_signal_only', risk_level='not_rated').
- Stronger AI-use status ('heuristic_draft' or 'confirmed_disclosure') is assigned
  when service-relevant evidence is present.
- Every rating explicitly links evidence IDs and documents evidence gaps and caveats.
- No fabricated confidence percentages or synthetic risk assumptions.
"""

from __future__ import annotations

import logging

from src.models import CriticalityResult, EvidenceItem, RiskResult

logger = logging.getLogger(__name__)

# Evidence categories that elevate risk when confirmed in contracted service
ELEVATING_CATEGORIES = {
    "confirmed_service_ai",
    "ai_capability_claim",
    "ai_subprocessor_disclosure",
    "model_training",
    "third_party_sharing",
    "data_processing",
}

MITIGATING_CATEGORIES = {
    "security_control",
    "privacy_commitment",
}


def analyse_risk(
    *,
    vendor_name: str,
    criticality: CriticalityResult | None,
    evidence: list[EvidenceItem],
) -> RiskResult:
    """Produce a conservative, transparent preliminary AI risk assessment.

    Evaluation steps:
    1. Filter out irrelevant evidence.
    2. Check for explicit AI capability claims (ai_capability_claim or confirmed_service_ai).
    3. If no AI capability claim: status='insufficient_evidence', risk_level='not_rated'.
    4. If corporate announcement only: status='corporate_signal_only', risk_level='not_rated'.
    5. If service-specific AI evidence exists: compute preliminary score based on
       intake criticality and observed evidence drivers, with linked evidence IDs.
    """
    caveats = [
        "Public-web heuristics are incomplete and can miss or overstate AI usage.",
        "Keyword matches are not confirmation of product behaviour or control effectiveness.",
        "Absence of public evidence is not proof that the vendor does not use AI.",
        "Treat this as a draft for analyst review, not an audit opinion.",
    ]
    evidence_gaps: list[str] = []
    drivers: list[str] = []
    linked_ids: list[str] = [e.evidence_id for e in evidence if e.evidence_id]

    crit_score = 50.0 if criticality is None else criticality.score
    crit_level = "unrated" if criticality is None else criticality.level
    if criticality is not None:
        drivers.append(f"intake criticality {crit_level} ({crit_score:.1f})")

    # Mandatory check: requires an explicit AI capability claim or confirmed service AI
    ai_claims = [
        e for e in evidence
        if e.category in ("ai_capability_claim", "confirmed_service_ai")
    ]

    # Case 1: No evidence at all
    if not evidence:
        evidence_gaps.append("Public sources have not been fetched or reviewed.")
        return RiskResult(
            vendor_name=vendor_name,
            criticality_score=None if criticality is None else criticality.score,
            risk_score=None,
            risk_level="not_rated",
            status="insufficient_evidence",
            drivers=[],
            caveats=caveats + [
                "No classified public-text evidence was available for this vendor.",
                "Not rated does not mean low risk or no AI usage.",
            ],
            evidence_gaps=evidence_gaps,
            linked_evidence_ids=[],
        )

    # Case 2: Evidence exists, but NO explicit AI capability claim
    # (e.g. only subprocessor cue, or only security/privacy/data processing)
    if not ai_claims:
        evidence_gaps.append("No specific AI feature claim found in public documentation.")
        return RiskResult(
            vendor_name=vendor_name,
            criticality_score=None if criticality is None else criticality.score,
            risk_score=None,
            risk_level="not_rated",
            status="insufficient_evidence",
            drivers=drivers,
            caveats=caveats + [
                "Other keywords or a provider disclosure may be present, but no AI capability claim was identified.",
                "Not rated does not mean low risk or no AI usage.",
            ],
            evidence_gaps=evidence_gaps,
            linked_evidence_ids=linked_ids,
        )

    # Separate evidence by relevance
    service_ai_items = [e for e in ai_claims if e.relevance == "service_specific"]
    corporate_ai_items = [e for e in ai_claims if e.relevance == "corporate_general"]

    # Case 3: AI mentioned ONLY at corporate / general marketing level
    # (e.g. general press release or thought leadership article, not service-specific)
    if not service_ai_items and corporate_ai_items:
        evidence_gaps.append(
            "Corporate-level AI announcements exist, but no evidence was found confirming "
            "AI usage in the specific service Meridian purchases."
        )
        evidence_gaps.append("Service-level data flows, model providers, and processing terms remain unverified.")
        corp_driver = f"corporate AI signal ({len(corporate_ai_items)} item(s) require service verification)"
        return RiskResult(
            vendor_name=vendor_name,
            criticality_score=None if criticality is None else criticality.score,
            risk_score=None,
            risk_level="not_rated",
            status="corporate_signal_only",
            drivers=drivers + [corp_driver],
            caveats=caveats + [
                "Corporate-level AI mentions or blog articles do NOT establish that AI is used in the contracted service.",
                "AI risk is NOT rated until service-level applicability is confirmed by human analyst review.",
            ],
            evidence_gaps=evidence_gaps,
            linked_evidence_ids=linked_ids,
        )

    # Case 4: AI evidence is present
    has_verified = any(
        e.verification_status == "verified" or e.category == "confirmed_service_ai"
        for e in ai_claims
    )
    status = "confirmed_disclosure" if has_verified else "heuristic_draft"

    # Compute preliminary risk score combining intake criticality and evidence drivers
    elevating = [e for e in evidence if e.category in ELEVATING_CATEGORIES]
    mitigating = [e for e in evidence if e.category in MITIGATING_CATEGORIES]

    elevation = min(25.0, 8.0 * len(elevating))
    mitigation = min(15.0, 5.0 * len(mitigating))
    score = round(max(0.0, min(100.0, crit_score * 0.70 + elevation - mitigation)), 2)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    for e in evidence[:8]:
        drivers.append(f"{e.category} (heuristic {e.heuristic_score})")

    # Check evidence gaps
    if not any(e.category == "ai_subprocessor_disclosure" for e in evidence):
        evidence_gaps.append("Named AI model providers and subprocessors are not disclosed.")
    if not any(e.category == "model_training" for e in evidence):
        evidence_gaps.append("Policy regarding model training on customer data is undetermined.")

    logger.info("Risk for %s: score=%s level=%s status=%s", vendor_name, score, level, status)

    return RiskResult(
        vendor_name=vendor_name,
        criticality_score=None if criticality is None else criticality.score,
        risk_score=score,
        risk_level=level,
        status=status,
        drivers=drivers,
        caveats=caveats,
        evidence_gaps=evidence_gaps,
        linked_evidence_ids=linked_ids,
    )
