"""Map the current assessment draft into the supplied Meridian template fields."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from src.excel_handler import MeridianWorkbook
from src.models import CriticalityResult, EvidenceItem, RiskResult, SourceCandidate, VendorRecord


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _clip(value: str, limit: int = 30000) -> str:
    """Stay safely below Excel's 32,767-character cell limit."""
    if len(value) <= limit:
        return value
    return value[: limit - 32].rstrip() + "\n[Truncated for Excel cell limit.]"


def _depth_text(level: str, fetched_count: int) -> str:
    level = level.lower()
    target_depth = {
        "critical": "Target depth: comprehensive public-source sweep and human review.",
        "high": "Target depth: deep public-source review and human review.",
        "medium": "Target depth: standard public-source review.",
        "low": "Target depth: baseline public-source review.",
    }.get(level, "Target depth: manual review required.")
    if fetched_count:
        performed = (
            f"Performed so far: {fetched_count} public page(s) retrieved and keyword-screened; "
            "findings remain preliminary heuristic leads requiring human verification."
        )
    else:
        performed = (
            "Performed so far: source candidates generated only; page retrieval was not executed, "
            "so this is not a completed assessment."
        )
    return f"{target_depth} {performed}"


def build_meridian_updates(
    bundle: MeridianWorkbook,
    *,
    vendors: list[VendorRecord],
    criticality: list[CriticalityResult],
    sources: list[SourceCandidate],
    evidence: list[EvidenceItem],
    risks: list[RiskResult],
    fetched_documents: list[Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Create student-cell updates keyed by original Vendor ID.

    Guarantees:
    - Never converts weak keyword matches into confirmed AI-use conclusions.
    - Clearly distinguishes 'insufficient evidence' from 'does not use AI'.
    - Differentiates corporate-level announcements from service-specific AI usage.
    - Does not export an apparently completed assessment based only on empty evidence.
    """
    real_records = {
        str(record.vendor_id).strip(): record
        for record in bundle.records
        if not record.is_example
    }
    vendors_by_id = {str(v.vendor_id).strip(): v for v in vendors if v.vendor_id is not None}
    criticality_by_name = {item.vendor_name: item for item in criticality}
    risks_by_name = {item.vendor_name: item for item in risks}
    sources_by_name: dict[str, list[SourceCandidate]] = {}
    evidence_by_url: dict[str, list[EvidenceItem]] = {}

    for item in sources:
        sources_by_name.setdefault(item.vendor_name, []).append(item)
    for item in evidence:
        evidence_by_url.setdefault(item.source_url, []).append(item)

    fetched_documents = fetched_documents or []
    fetched_urls = {
        getattr(doc, "url", "")
        for doc in fetched_documents
        if getattr(doc, "status", "") == "ok"
    }

    # Resolve actual workbook header column names
    actual_columns = {_normalise(col.name): col.name for col in bundle.columns}

    def field_name(*needles: str) -> str | None:
        for needle in needles:
            exact = _normalise(needle)
            if exact in actual_columns:
                return actual_columns[exact]
        for actual_norm, actual_name in actual_columns.items():
            if all(_normalise(needle) in actual_norm for needle in needles):
                return actual_name
        return None

    fields = {
        "tier": field_name("Criticality Tier"),
        "criticality_rationale": field_name("Criticality Rationale"),
        "depth": field_name("Assessment Depth Applied"),
        "ai_usage": field_name("AI Usage Detected (Y/N)"),
        "evidence_description": field_name(
            "Evidence Description along with OSINT Source(s) / Evidence Link"
        ),
        "usage_description": field_name("How Vendor May Be Using AI"),
        "providers": field_name("Named AI Sub-processors / Model Providers"),
        "risk_classification": field_name("AI Security Risk Classification"),
        "risk_rationale": field_name("Risk Rationale"),
        "action": field_name("Recommended Action"),
        "assessed_by": field_name("Assessed By / Date", "Assessedd By / Date"),
    }

    updates: dict[str, dict[str, Any]] = {}

    for vendor_id, record in real_records.items():
        vendor = vendors_by_id.get(vendor_id)
        if vendor is None:
            continue

        crit = criticality_by_name.get(vendor.name)
        risk = risks_by_name.get(vendor.name)
        vendor_sources = sources_by_name.get(vendor.name, [])
        source_urls = {item.url for item in vendor_sources}

        # Evidence associated with this vendor
        vendor_evidence = [
            item for item in evidence
            if item.vendor_name == vendor.name or item.source_url in source_urls
        ]

        ai_evidence = [
            item for item in vendor_evidence
            if item.category in {"ai_capability_claim", "confirmed_service_ai", "ai_subprocessor_disclosure"}
        ]
        provider_evidence = [
            item for item in vendor_evidence
            if item.category == "ai_subprocessor_disclosure"
        ]
        fetched_count = len({url for url in fetched_urls if url in source_urls})

        output: dict[str, Any] = {}

        def put(key: str, value: Any) -> None:
            name = fields.get(key)
            if name is not None:
                output[name] = _clip(str(value)) if value is not None else ""

        # 1. Criticality Tier & Rationale
        if crit is not None:
            put("tier", crit.level.title())
            factor_text = "; ".join(
                f"{name.replace('_', ' ').title()}: {value:.0f}/100"
                for name, value in crit.factors.items()
            )
            rationale = (
                f"Proposed heuristic score: {crit.score:.1f}/100. Factors: {factor_text or 'none scored'}. "
                + " ".join(crit.notes)
            )
            put("criticality_rationale", rationale)
            put("depth", _depth_text(crit.level, fetched_count))
        else:
            put("tier", "Requires manual review")
            put("criticality_rationale", "No criticality result was available for this vendor.")
            put("depth", "Manual review required; criticality has not been scored.")

        # 2. AI Usage Detected (Y/N) & How Vendor May Be Using AI
        risk_status = risk.status if risk else "not_assessed"

        if risk_status == "confirmed_service_ai":
            put("ai_usage", "Yes — confirmed service-level AI feature documented; verify contractual scope.")
            usage_lines = [
                f"[{item.category}] {item.snippet} [Source: {item.source_url}]"
                for item in ai_evidence if item.relevance == "service_specific"
            ][:4]
            put("usage_description", "\n".join(usage_lines) or "Service-level AI feature identified in documentation.")
        elif risk_status == "service_ai_signal":
            put("ai_usage", "Potential AI signal — analyst verification required; heuristic match on service terms.")
            usage_lines = [
                f"Potential signal: {item.snippet} [Source: {item.source_url}]"
                for item in ai_evidence[:4]
            ]
            put("usage_description", "\n".join(usage_lines))
        elif risk_status == "corporate_signal_only":
            put(
                "ai_usage",
                "Corporate signal only — vendor publishes general AI announcements/blogs, "
                "but AI usage is NOT established for Meridian's specific service."
            )
            usage_lines = [
                f"Corporate announcement/marketing: {item.snippet} [Source: {item.source_url}]"
                for item in ai_evidence if item.relevance == "corporate_general"
            ][:3]
            put(
                "usage_description",
                "General corporate AI mentions found; no documentation confirms AI is used in the specific "
                f"service Meridian contracts ({vendor.product or 'N/A'}).\n" + "\n".join(usage_lines),
            )
        elif fetched_count > 0:
            put(
                "ai_usage",
                "No AI usage detected in retrieved public sources — insufficient evidence to confirm absence of AI."
            )
            put(
                "usage_description",
                "AI usage was not established in the public pages retrieved and screened. "
                "Formal vendor questionnaire / contract review required."
            )
        else:
            put(
                "ai_usage",
                "Unknown — source candidates have not been fetched; AI usage is not established."
            )
            put(
                "usage_description",
                "Not established from current evidence. Public source candidates have not been fetched and reviewed."
            )

        # 3. Evidence Description & OSINT Sources
        if vendor_evidence:
            lines = []
            for item in vendor_evidence[:8]:
                lines.append(
                    f"[{item.category} | Relevance: {item.relevance}] {item.snippet}\n"
                    f"Source: {item.source_url}\n"
                    f"Note: {item.rationale}"
                )
            put(
                "evidence_description",
                "Retrieved public evidence excerpts (verify context before relying on findings):\n\n"
                + "\n\n".join(lines),
            )
        else:
            candidate_urls = "\n".join(item.url for item in vendor_sources[:6])
            prefix = "No retrieved excerpts available. The following are source candidates/leads, not verified evidence:"
            put("evidence_description", prefix + ("\n" + candidate_urls if candidate_urls else " None."))

        # 4. Named AI Sub-processors / Model Providers
        if provider_evidence:
            provider_lines = []
            for item in provider_evidence[:4]:
                named_terms = [
                    t for t in item.matched_terms
                    if t.lower() not in {
                        "subprocessor", "third-party provider", "ai provider", "model provider",
                        "process data using", "powered by", "provided by", "hosted by", "api"
                    }
                ]
                provider_lines.append(
                    f"Possible provider mention: {', '.join(named_terms) or 'review passage'}; "
                    f"excerpt: {item.snippet} [Source: {item.source_url}]"
                )
            put(
                "providers",
                "Potential disclosure leads — verify relevance to Meridian's contracted service:\n"
                + "\n".join(provider_lines),
            )
        else:
            put(
                "providers",
                "No named AI sub-processors or model providers were detected in reviewed excerpts. "
                "This is not evidence that none are used."
            )

        # 5. AI Security Risk Classification, Risk Rationale & Action
        if risk is None or risk.risk_score is None or risk.risk_level == "not_rated":
            if risk_status == "corporate_signal_only":
                put("risk_classification", "Not rated — corporate announcement only; not confirmed for contracted service.")
                put(
                    "risk_rationale",
                    "Vendor public materials mention AI initiatives or general offerings, but there is no evidence "
                    "that AI features are active in the specific service Meridian procures. "
                    "Do not assign an AI risk score without service-level applicability."
                )
                put(
                    "action",
                    "Issue vendor inquiry to verify whether corporate AI capabilities or third-party AI subprocessors "
                    f"apply to Meridian's contracted service ({vendor.product or 'N/A'})."
                )
            elif fetched_count > 0:
                put("risk_classification", "Not rated — insufficient evidence; no AI usage established.")
                put(
                    "risk_rationale",
                    "Public keyword screening did not identify AI usage in the vendor's service. "
                    "Absence of public disclosures does NOT prove low risk or that AI is not used. "
                    "Heuristics remain incomplete."
                )
                put(
                    "action",
                    "Verify AI usage via vendor security questionnaire or Data Processing Addendum (DPA) "
                    "before concluding that no AI risk exists."
                )
            else:
                put("risk_classification", "Not rated — public sources have not been fetched.")
                put(
                    "risk_rationale",
                    "Candidate URLs have not been fetched and screened. AI usage and risk remain unassessed."
                )
                put("action", "Execute public-source retrieval and review vendor documentation.")
        else:
            put("risk_classification", f"{risk.risk_level.title()} — preliminary heuristic draft; human review required.")
            drivers_text = "; ".join(risk.drivers) if risk.drivers else "intake dependency and matched AI features"
            caveats_text = " ".join(risk.caveats) if risk.caveats else ""
            put(
                "risk_rationale",
                f"Preliminary AI risk scored {risk.risk_score:.1f}/100 based on service-relevant signals. "
                f"Drivers: {drivers_text}. Caveats: {caveats_text}"
            )
            put(
                "action",
                "Validate documented AI capability against Meridian's service configuration. "
                "Review data boundaries, retention/training terms, subprocessor list, and administrative controls."
            )

        put("assessed_by", f"Meridian Assessment Tool — draft generated {date.today().isoformat()}; analyst review required.")
        updates[vendor_id] = output

    return updates
