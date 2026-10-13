"""Classify extracted public text into structured cybersecurity evidence.

Core principles:
- Extract contextual passages (not isolated fragments or whole pages).
- Filter out navigation menus, footer lines, cookie disclaimers, and boilerplate.
- Distinguish service-specific AI usage from corporate-level announcements and broad marketing.
- Requiring contextual evidence: OpenAI, Anthropic, Azure OpenAI, Amazon Bedrock alone
  do NOT establish a data-processing subprocessor relationship.
- Generic encryption, SOC 2, and privacy commitments NEVER count as AI evidence.
- Track explicit relevance ('service_specific', 'corporate_general', 'ambiguous', 'irrelevant').
- Mark ambiguous or corporate-level findings for human review.
- Deduplicate identical snippets across pages or repeated boilerplate.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from typing import Iterable

from src.models import EvidenceItem, ExtractedDocument

logger = logging.getLogger(__name__)

# Categories checked by rule-based heuristic patterns
CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "ai_capability_claim": (
        r"\bgenerative ai\b", r"\bmachine learning\b",
        r"\blarge language model(?:s)?\b", r"\bllm(?:s)?\b",
        r"\bartificial intelligence\b", r"\bAI[- ]powered\b",
        r"\bAI assistant\b", r"\bAI feature(?:s)?\b",
        r"\bAI agent(?:s)?\b", r"\bfrontier AI\b",
        r"\bfoundation model(?:s)?\b", r"\bdeep learning\b",
    ),
    "data_processing": (
        r"\bpersonal data\b", r"\bcustomer data\b",
        r"\bdata processing\b", r"\bretain(?:s|ed|ing)?\b",
        r"\bconfidential information\b",
    ),
    "model_training": (
        r"\btrain(?:s|ed|ing)? (?:our |the |its )?(?:models?|AI systems?|algorithms?)\b",
        r"\bused to (?:improve|train) (?:our |the |its )?(?:models?|AI|algorithms?)\b",
        r"\btraining data\b", r"\bimprove our models\b",
    ),
    "security_control": (
        r"\bencryption\b", r"\bSSO\b", r"\bSOC 2\b",
        r"\bISO 27001\b", r"\baccess control\b",
        r"\bpenetration test(?:ing)?\b", r"\bMFA\b",
    ),
    "privacy_commitment": (
        r"\bprivacy policy\b", r"\bGDPR\b", r"\bCCPA\b",
        r"\bdata subject\b", r"\bdelete your data\b",
    ),
    "third_party_sharing": (
        r"\bthird[- ]party\b", r"\bsubprocessors?\b",
        r"\bshare(?:s|d)? (?:your |customer |personal )?data\b",
        r"\bservice providers?\b",
    ),
}

# Categories representing generic security/privacy/vendor controls, NEVER treated as AI use
NON_AI_CATEGORIES: set[str] = {
    "security_control",
    "privacy_commitment",
    "data_processing",
    "third_party_sharing",
}

# Named AI providers (provider name alone does NOT prove processing)
AI_PROVIDER_PATTERNS: tuple[str, ...] = (
    r"\bOpenAI\b", r"\bAnthropic\b", r"\bAzure OpenAI\b",
    r"\bGoogle Vertex AI\b", r"\bAmazon Bedrock\b",
    r"\bAWS Bedrock\b", r"\bCohere\b", r"\bMistral AI\b",
    r"\bGoogle Gemini\b", r"\bMicrosoft Copilot\b",
)

# Mandatory contextual cues required before classifying as an AI subprocessor disclosure
AI_PROCESSING_CUES: tuple[str, ...] = (
    r"\bsubprocessor\b", r"\bthird[- ]party provider\b",
    r"\bAI provider\b", r"\bmodel provider\b",
    r"\bprocess(?:es|ing)? .*data (?:using|with)\b",
    r"\bpowered by\b", r"\bprovided by\b",
    r"\bhosted by\b", r"\bAPI\b",
)

# Explicit limitations and restrictions (e.g., "we do not train on customer data")
LIMITATION_PATTERNS: tuple[str, ...] = (
    r"\bdo not train\b", r"\bwill not train\b", r"\bnever train\b",
    r"\bdoes not use .* (?:for|to) train\b",
    r"\bnot used to train\b", r"\bopt[- ]out\b",
    r"\bno customer data is used\b",
)

# Patterns that signal boilerplate navigation, cookie notices, or footer text
BOILERPLATE_PATTERNS = re.compile(
    r"(?:©\s*\d{4}|\ball rights reserved\b|\bcopyright \d{4}\b|"
    r"\bprivacy policy\s*\|\s*terms|"
    r"\bcareers\s*\|\s*about\s*\|\s*contact|"
    r"\bcookie preferences\b|\bmanage cookies\b|\bcookie (?:policy|notice|settings)\b|"
    r"\b(?:use|accept|strictly necessary) cookies\b|"
    r"\bconsent to cookies\b|\bwe use cookies\b|"
    r"^\s*(?:home|about|services|solutions|products|resources|contact)\s*[>|/»›]|"
    r"\b(?:skip to (?:main )?content|terms of (?:use|service))\b|"
    r"\bsign in\s*\|\s*register\b)",
    re.IGNORECASE,
)

# Known service tokens for Meridian intake vendors (explicit product & service names)
VENDOR_SERVICE_TOKENS: dict[str, tuple[str, ...]] = {
    "automworx": ("workload automation", "batch scheduling", "appworx", "uc4", "automic automation"),
    "fiserv": ("dna core", "core banking platform", "dna platform", "dna account", "core banking"),
    "fssi": ("statement print", "print and mail", "tax document production", "electronic notice platform", "statement outsourcing"),
    "terrapin": ("wealth management data", "commission calculation", "portfolio tracking", "compensation calculation"),
    "bny": ("rtp transmission", "real time payments transmission", "real-time payments transmission", "rtp payment files"),
    "the clearing house": ("rtp network", "real-time payments network", "ach processing", "epn network", "chips network", "payment network infrastructure"),
    "clearing house": ("rtp network", "real-time payments network", "ach processing", "epn network", "chips network", "payment network infrastructure"),
}


def _sentences(text: str) -> list[str]:
    """Split text into sentences, trimming whitespace."""
    normalized = re.sub(r"\s+", " ", text).strip()
    if not normalized:
        return []
    # Split on sentence boundaries and common button/card delimiters
    parts = re.split(
        r"(?:(?<=[.!?])\s+(?=[A-Z0-9\"'])|\s+(?:Read more|Learn more)\s*>?\s*)",
        normalized,
        flags=re.IGNORECASE,
    )
    return [part.strip() for part in parts if len(part.strip()) >= 15]


def _matching_terms(patterns: Iterable[str], text: str) -> list[str]:
    """Find unique matched terms for a set of regex patterns."""
    terms: list[str] = []
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            term = match.group(0)
            if term.lower() not in {item.lower() for item in terms}:
                terms.append(term)
    return terms


def _is_boilerplate(passage: str) -> bool:
    """Detect navigation links, cookie notices, footers, link lists, or boilerplate."""
    if not passage or not passage.strip():
        return True
    if BOILERPLATE_PATTERNS.search(passage):
        return True

    words = passage.strip().split()
    if not words:
        return True

    # Count delimiter characters (|, >, /, », ›, •, ·)
    delimiters = sum(passage.count(ch) for ch in ("|", ">", "»", "›", "•", "·", "\t"))
    # Link lists or breadcrumb trails
    if delimiters >= 2 and (len(words) < 30 or delimiters / len(words) > 0.15):
        return True
    if passage.count("|") >= 2:
        return True

    # Repeated navigation actions / card links
    action_links = len(re.findall(r"\b(?:read more|learn more|click here|view all)\s*>?\b", passage, re.I))
    if action_links >= 2:
        return True

    return False


def _evaluate_relevance(
    passage: str,
    *,
    vendor_name: str = "",
    service_context: str = "",
    source_url: str = "",
    source_title: str = "",
) -> str:
    """Evaluate whether an excerpt is service-specific, corporate-general, ambiguous, or irrelevant.

    Only classifies as 'service_specific' when the excerpt explicitly connects
    the signal to the actual contracted service Meridian purchases.
    """
    if _is_boilerplate(passage):
        return "irrelevant"

    passage_lower = passage.lower()
    combined_meta = f"{source_url.lower()} {source_title.lower()}"

    # Corporate announcements, blogs, press releases, vision statements, thought leadership, article feeds
    corporate_cues = (
        "press-release", "newsroom", "blog", "news-and-events", "podcast",
        "webinar", "announces", "announced", "partner with", "partnership with",
        "in this article", "in our latest", "vision for", "future of",
        "min read", "read more", "thought leadership", "insights", "resources",
    )
    if any(cue in combined_meta or cue in passage_lower for cue in corporate_cues):
        return "corporate_general"

    # Check for direct service tokens
    vendor_key = vendor_name.lower().strip()
    matched_service_tokens = []
    for key, tokens in VENDOR_SERVICE_TOKENS.items():
        if key in vendor_key:
            for tok in tokens:
                if tok in passage_lower:
                    matched_service_tokens.append(tok)

    # Check if service_context has explicit multi-word key phrases or distinct product tokens in the passage
    if service_context:
        clean_ctx = re.sub(r"[^a-zA-Z0-9\s-]", " ", service_context.lower())
        ctx_words = [
            w for w in clean_ctx.split()
            if len(w) >= 3 and w not in (
                "the", "and", "for", "with", "from", "that", "this",
                "system", "systems", "services", "service", "provider", "providers",
                "data", "hosts", "produces", "distributes", "multiple", "sources"
            )
        ]
        # Multi-word key phrases (e.g. "core banking", "electronic notice", "batch scheduling")
        for i in range(len(ctx_words) - 1):
            phrase = f"{ctx_words[i]} {ctx_words[i+1]}"
            if phrase in passage_lower:
                matched_service_tokens.append(phrase)
        # Distinct product names/tokens
        for token in ("dna", "appworx", "uc4", "automic", "rtp"):
            if token in ctx_words and re.search(rf"\b{re.escape(token)}\b", passage_lower):
                matched_service_tokens.append(token)

    if matched_service_tokens:
        # If the page is a generic legal/privacy/cookie document, do not mark as service-specific
        # unless the excerpt explicitly mentions the contracted product by name
        if any(p in combined_meta for p in ("/privacy", "/cookie", "/terms", "/legal", "privacy policy")):
            has_product = any(
                re.search(rf"\b{re.escape(p)}\b", passage_lower)
                for p in ("dna", "appworx", "uc4", "automic", "rtp", "ach")
            )
            if not has_product:
                return "ambiguous"
        return "service_specific"

    return "ambiguous"


def _expand_context(sentences: list[str], idx: int, max_len: int = 500) -> str:
    """Build a contextual passage centered around the matching sentence."""
    core = sentences[idx]
    if len(core) >= max_len:
        return core[:max_len]

    # Prepend previous sentence if short enough
    prefix = ""
    if idx > 0 and len(sentences[idx - 1]) + len(core) + 1 <= max_len:
        prefix = sentences[idx - 1] + " "

    # Append next sentence if short enough
    suffix = ""
    if idx + 1 < len(sentences) and len(prefix) + len(core) + len(sentences[idx + 1]) + 2 <= max_len:
        suffix = " " + sentences[idx + 1]

    return (prefix + core + suffix).strip()


def classify_text(
    text: str,
    *,
    source_url: str = "",
    source_title: str = "",
    retrieved_at: str | None = None,
    vendor_name: str = "",
    service_context: str = "",
) -> list[EvidenceItem]:
    """Classify text into evidence items using strict contextual passages.

    Guarantees:
    - Rejects boilerplate navigation and footer elements.
    - Categorizes relevance: 'service_specific', 'corporate_general', or 'ambiguous'.
    - Provider name alone NEVER triggers an AI subprocessor disclosure.
    - Generic encryption/security/privacy text NEVER counts as AI evidence.
    - Detects explicit limitation statements (e.g. 'do not train').
    - Deduplicates identical excerpts.
    """
    if not text or not text.strip():
        return []

    sentences = _sentences(text)
    if not sentences:
        return []

    items: list[EvidenceItem] = []
    seen_hashes: set[str] = set()

    def add_item(item: EvidenceItem) -> None:
        # Deduplicate using category and normalized snippet hash
        norm_snippet = re.sub(r"\s+", " ", item.snippet.strip().lower())
        h = hashlib.sha256(norm_snippet.encode("utf-8")).hexdigest()[:16]
        key = (item.category, h)
        if key in seen_hashes:
            return
        seen_hashes.add(key)
        items.append(item)

    # 1. Standard Category Patterns
    for category, patterns in CATEGORY_PATTERNS.items():
        matched_passages: list[tuple[str, str, list[str]]] = []

        for idx, sentence in enumerate(sentences):
            if _is_boilerplate(sentence):
                continue
            terms = _matching_terms(patterns, sentence)
            if terms:
                passage = _expand_context(sentences, idx)
                if _is_boilerplate(passage):
                    continue
                relevance = _evaluate_relevance(
                    passage,
                    vendor_name=vendor_name,
                    service_context=service_context,
                    source_url=source_url,
                    source_title=source_title,
                )
                if relevance == "irrelevant":
                    continue
                matched_passages.append((sentence, passage, terms))
                if len(matched_passages) >= 2:
                    break

        if not matched_passages:
            continue

        sentence, passage, terms = matched_passages[0]
        relevance = _evaluate_relevance(
            passage,
            vendor_name=vendor_name,
            service_context=service_context,
            source_url=source_url,
            source_title=source_title,
        )

        score = min(0.85, 0.35 + 0.10 * len(terms))

        # Check for explicit limitations in the passage
        limits = _matching_terms(LIMITATION_PATTERNS, passage)
        rationale = f"Matched term(s): {', '.join(terms)}. Heuristic match only, not a conclusion."
        if limits:
            rationale += f" Note explicit limitation cue: {', '.join(limits)}."

        # Assign category and verification status based on relevance
        assigned_category = category
        if category == "ai_capability_claim" and relevance == "service_specific":
            assigned_category = "confirmed_service_ai"
            verification_status = "verified"
            rationale += " Explicit mention in service-specific documentation context."
        elif category == "ai_capability_claim" and relevance == "corporate_general":
            verification_status = "requires_human_review"
            rationale += " Mentioned in corporate announcement or general marketing; not confirmed for Meridian's specific service."
        elif category in NON_AI_CATEGORIES:
            # Generic privacy, security, encryption, and third-party-sharing text is never treated as evidence of AI use
            verification_status = "unverified"
            rationale += " Generic non-AI disclosure; not evidence of AI usage; does not establish AI usage."
        elif relevance == "ambiguous":
            verification_status = "requires_human_review"
        else:
            verification_status = "unverified"

        add_item(
            EvidenceItem(
                evidence_id=str(uuid.uuid4())[:8],
                category=assigned_category,
                snippet=sentence[:700],
                heuristic_score=round(score, 2),
                rationale=rationale,
                source_url=source_url,
                source_title=source_title,
                retrieved_at=retrieved_at,
                matched_terms=terms,
                vendor_name=vendor_name,
                relevance=relevance,
                verification_status=verification_status,
            )
        )

    # 2. Strict AI Subprocessor Rule:
    # Requires named AI provider AND explicit processing cue in the SAME passage.
    for idx, sentence in enumerate(sentences):
        if _is_boilerplate(sentence):
            continue
        passage = _expand_context(sentences, idx)
        if _is_boilerplate(passage):
            continue
        providers = _matching_terms(AI_PROVIDER_PATTERNS, passage)
        cues = _matching_terms(AI_PROCESSING_CUES, passage)

        if providers and cues:
            relevance = _evaluate_relevance(
                passage,
                vendor_name=vendor_name,
                service_context=service_context,
                source_url=source_url,
                source_title=source_title,
            )
            if relevance == "irrelevant":
                continue

            verification = "verified" if relevance == "service_specific" else "requires_human_review"
            add_item(
                EvidenceItem(
                    evidence_id=str(uuid.uuid4())[:8],
                    category="ai_subprocessor_disclosure",
                    snippet=sentence[:700],
                    heuristic_score=0.70,
                    rationale=(
                        f"Named AI provider(s): {', '.join(providers)}; processing cue(s): "
                        f"{', '.join(cues)}. Relevance: {relevance}. Heuristic match only, not a conclusion."
                    ),
                    source_url=source_url,
                    source_title=source_title,
                    retrieved_at=retrieved_at,
                    matched_terms=providers + cues,
                    vendor_name=vendor_name,
                    relevance=relevance,
                    verification_status=verification,
                )
            )
            break

    logger.info("Classified %s evidence items from %s", len(items), source_url or "text")
    return items


def classify_documents(
    documents: list[ExtractedDocument],
    vendor_name: str = "",
    service_context: str = "",
) -> list[EvidenceItem]:
    """Classify multiple extracted documents for a vendor.

    Deduplicates evidence from URLs resolving to the same page,
    without deleting distinct evidence.
    """
    evidence: list[EvidenceItem] = []
    seen_evidence_keys: set[tuple[str, str]] = set()
    seen_page_content: set[tuple[str, str]] = set()

    for document in documents:
        if document.status != "ok" or not document.text:
            continue

        # Normalize resolved page URL (stripping fragments, query params, trailing slashes)
        resolved_url = (document.final_url or document.url).split("#")[0].split("?")[0].rstrip("/").lower()
        content_hash = hashlib.sha256(document.text.strip().encode("utf-8")).hexdigest()[:16]
        page_key = (resolved_url, content_hash)
        if page_key in seen_page_content:
            # Skip redundant re-processing of identical content from URLs resolving to the same page
            continue
        seen_page_content.add(page_key)

        items = classify_text(
            document.text,
            source_url=document.final_url or document.url,
            source_title=document.title or "",
            retrieved_at=document.retrieved_at,
            vendor_name=vendor_name,
            service_context=service_context,
        )
        for item in items:
            norm_snip = re.sub(r"\s+", " ", item.snippet.strip().lower())
            ev_key = (item.category, norm_snip)
            if ev_key not in seen_evidence_keys:
                seen_evidence_keys.add(ev_key)
                evidence.append(item)

    return evidence
