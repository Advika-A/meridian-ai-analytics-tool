"""Discover candidate public sources for vendor AI-usage assessment.

Source candidates are hypothesized public locations and search queries for review.
They are NOT findings that a vendor uses AI, and a search lead is NOT evidence.

Key principles:
1. Do NOT guess blind arbitrary paths as verified pages.
2. Prefer actual links discovered from vendor homepages, sitemaps, robots.txt,
   and documented official portals.
3. Deduplicate URLs after normalizing scheme, domain, path trailing slashes,
   and stripping fragments.
4. Track discovery method ('official_intake', 'homepage_link', 'sitemap',
   'robots', 'known_official', 'search_lead') and source relevance.
5. Keep search queries strictly as analyst leads; never classify search URLs as evidence.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, urljoin, urlparse

from bs4 import BeautifulSoup

from src.models import SourceCandidate, VendorRecord

logger = logging.getLogger(__name__)


class SourceDiscoveryError(ValueError):
    """Raised when source discovery cannot proceed."""


# ---------------------------------------------------------------------------
# URL Normalization
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Normalize URL by stripping fragments, normalizing scheme/netloc, and trimming trailing slash."""
    text = url.strip()
    if not text:
        return ""
    # Strip anchor fragment
    text = text.split("#")[0].strip()
    if not text:
        return ""

    if not urlparse(text).scheme:
        text = "https://" + text

    try:
        parsed = urlparse(text)
    except Exception:
        return text

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path or "/"
    # Normalize multiple slashes to single
    path = re.sub(r"/{2,}", "/", path)
    # Strip trailing slash unless root path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    query = parsed.query
    if query:
        # Filter out tracking query params (utm_*, ref, etc.)
        params = [
            p for p in query.split("&")
            if not any(p.lower().startswith(trk) for trk in ("utm_", "fbclid", "gclid", "ref="))
        ]
        query = "&".join(params)

    reconstructed = f"{scheme}://{netloc}{path}"
    if query:
        reconstructed += f"?{query}"
    return reconstructed


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


# ---------------------------------------------------------------------------
# Known Official Pages for Meridian Intake Vendors
# Verified real URLs from vendor public portals, documentation, and filings.
# ---------------------------------------------------------------------------

_KNOWN_OFFICIAL_PAGES: dict[str, list[tuple[str, str, str, str]]] = {
    # (url, source_type, reason, source_relevance)
    "automworx": [
        (
            "https://www.automworx.com",
            "official",
            "AutomWorx official website — enterprise workload automation consulting.",
            "service_direct",
        ),
        (
            "https://www.automworx.com/privacy",
            "privacy",
            "AutomWorx privacy policy page.",
            "privacy_security",
        ),
        (
            "https://www.automworx.com/consulting-services",
            "docs",
            "AutomWorx consulting services overview.",
            "service_direct",
        ),
    ],
    "fiserv": [
        (
            "https://www.fiserv.com",
            "official",
            "Fiserv official corporate website.",
            "corporate_general",
        ),
        (
            "https://www.fiserv.com/en/about-fiserv/privacy-notice.html",
            "privacy",
            "Fiserv official global privacy notice.",
            "privacy_security",
        ),
        (
            "https://www.fiserv.com/en/solutions/financial-institutions/core-banking.html",
            "docs",
            "Fiserv core banking platforms (including DNA account processing).",
            "service_direct",
        ),
    ],
    "fssi": [
        (
            "https://www.fssi-ca.com",
            "official",
            "FSSI official website — secure document presentment and print outsourcing.",
            "service_direct",
        ),
        (
            "https://www.fssi-ca.com/privacy",
            "privacy",
            "FSSI privacy policy page.",
            "privacy_security",
        ),
    ],
    "financial statement services": [
        (
            "https://www.fssi-ca.com",
            "official",
            "FSSI official website — secure document presentment and print outsourcing.",
            "service_direct",
        ),
        (
            "https://www.fssi-ca.com/privacy",
            "privacy",
            "FSSI privacy policy page.",
            "privacy_security",
        ),
    ],
    "terrapin": [
        (
            "https://www.terrapintech.com",
            "official",
            "Terrapin Technologies official website. Note: dynamic JS frontend.",
            "service_direct",
        ),
    ],
    "bny": [
        (
            "https://www.bny.com",
            "official",
            "BNY official website — global payments and treasury services.",
            "corporate_general",
        ),
        (
            "https://www.bny.com/corporate/global/en/legal/privacy-notice.html",
            "privacy",
            "BNY official privacy notice.",
            "privacy_security",
        ),
    ],
    "clearing house": [
        (
            "https://www.theclearinghouse.org",
            "official",
            "The Clearing House official website.",
            "corporate_general",
        ),
        (
            "https://www.theclearinghouse.org/payment-systems/rtp",
            "docs",
            "TCH Real-Time Payments (RTP) network system documentation.",
            "service_direct",
        ),
        (
            "https://www.theclearinghouse.org/payment-systems/ach",
            "docs",
            "TCH Electronic Payments Network (ACH) documentation.",
            "service_direct",
        ),
        (
            "https://www.theclearinghouse.org/legal-privacy",
            "privacy",
            "TCH legal and privacy documentation.",
            "privacy_security",
        ),
    ],
}


# ---------------------------------------------------------------------------
# HTML Link Discovery (from Homepage / Main Content)
# ---------------------------------------------------------------------------

_RELEVANT_PATH_KEYWORDS: dict[str, tuple[str, str]] = {
    # keyword: (source_type, source_relevance)
    "privacy": ("privacy", "privacy_security"),
    "privacy-notice": ("privacy", "privacy_security"),
    "privacy-policy": ("privacy", "privacy_security"),
    "gdpr": ("privacy", "privacy_security"),
    "subprocessor": ("privacy", "privacy_security"),
    "sub-processor": ("privacy", "privacy_security"),
    "security": ("security", "privacy_security"),
    "trust": ("security", "privacy_security"),
    "compliance": ("security", "privacy_security"),
    "soc-2": ("security", "privacy_security"),
    "legal": ("legal", "privacy_security"),
    "terms": ("legal", "privacy_security"),
    "documentation": ("docs", "documentation"),
    "developer": ("docs", "documentation"),
    "api": ("docs", "documentation"),
    "rtp": ("docs", "service_direct"),
    "ach": ("docs", "service_direct"),
    "dna": ("docs", "service_direct"),
    "core-banking": ("docs", "service_direct"),
    "consulting-services": ("docs", "service_direct"),
    "ai": ("ai_docs", "corporate_general"),
    "artificial-intelligence": ("ai_docs", "corporate_general"),
    "machine-learning": ("ai_docs", "corporate_general"),
}


def discover_links_from_html(
    html: str,
    base_url: str,
    vendor_name: str = "",
    max_links: int = 15,
) -> list[SourceCandidate]:
    """Parse real hyperlinks from retrieved HTML content.

    Only discovers links on the same host (or official subdomain) that match
    privacy, security, legal, product documentation, or AI disclosures.
    """
    if not html or not base_url:
        return []

    soup = BeautifulSoup(html, "html.parser")
    base_domain = _extract_domain(base_url)
    candidates: list[SourceCandidate] = []
    seen: set[str] = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        full_url = urljoin(base_url, href)
        normalized = normalize_url(full_url)
        if not normalized or normalized in seen:
            continue

        link_domain = _extract_domain(normalized)
        # Keep same domain or direct subdomains
        if not (link_domain == base_domain or link_domain.endswith("." + base_domain)):
            continue

        # Evaluate path and link text relevance
        parsed = urlparse(normalized)
        path_lower = parsed.path.lower()
        anchor_text = a.get_text(separator=" ", strip=True).lower()
        combined = f"{path_lower} {anchor_text}"

        matched_type: str | None = None
        matched_relevance = "general"
        matched_reason = "Discovered hyperlink from vendor homepage."

        for kw, (stype, srel) in _RELEVANT_PATH_KEYWORDS.items():
            if kw in combined:
                matched_type = stype
                matched_relevance = srel
                matched_reason = f"Homepage navigation link matching '{kw}'."
                break

        if matched_type:
            seen.add(normalized)
            candidates.append(
                SourceCandidate(
                    url=normalized,
                    source_type=matched_type,
                    reason=matched_reason,
                    vendor_name=vendor_name,
                    discovery_method="homepage_link",
                    source_relevance=matched_relevance,
                )
            )
            if len(candidates) >= max_links:
                break

    return candidates


def discover_from_sitemap(
    sitemap_xml: str,
    base_url: str,
    vendor_name: str = "",
    max_links: int = 10,
) -> list[SourceCandidate]:
    """Extract candidate URLs from a vendor sitemap.xml."""
    if not sitemap_xml:
        return []

    candidates: list[SourceCandidate] = []
    seen: set[str] = set()

    try:
        root = ET.fromstring(sitemap_xml)
        # Handle XML namespaces
        for elem in root.iter():
            if elem.tag.endswith("loc") and elem.text:
                url = normalize_url(elem.text.strip())
                if not url or url in seen:
                    continue
                path_lower = urlparse(url).path.lower()
                for kw, (stype, srel) in _RELEVANT_PATH_KEYWORDS.items():
                    if kw in path_lower:
                        seen.add(url)
                        candidates.append(
                            SourceCandidate(
                                url=url,
                                source_type=stype,
                                reason=f"Sitemap entry matching '{kw}'.",
                                vendor_name=vendor_name,
                                discovery_method="sitemap",
                                source_relevance=srel,
                            )
                        )
                        break
                if len(candidates) >= max_links:
                    break
    except Exception as exc:
        logger.debug("Failed to parse sitemap XML for %s: %s", vendor_name, exc)

    return candidates


# ---------------------------------------------------------------------------
# Main Source Discovery Function
# ---------------------------------------------------------------------------

def discover_sources(
    vendor: VendorRecord,
    homepage_html: str | None = None,
) -> list[SourceCandidate]:
    """Return verified public review candidates and analyst search leads for a vendor.

    Strategy:
    1. Seed with the vendor's official intake website.
    2. Add verified known official documentation and privacy links.
    3. If homepage HTML is provided, discover actual links from the page.
    4. Provide analyst search query leads (explicitly flagged as leads, not evidence).
    5. Deduplicate and normalize all candidate URLs.
    """
    if not vendor.name.strip():
        raise SourceDiscoveryError("Vendor name is required to discover sources.")

    candidates: list[SourceCandidate] = []
    seen_urls: set[str] = set()

    def add(candidate: SourceCandidate) -> None:
        norm = normalize_url(candidate.url)
        if not norm or norm in seen_urls:
            return
        seen_urls.add(norm)
        candidate.url = norm
        candidates.append(candidate)

    # 1. Official intake website
    if vendor.website:
        site_norm = normalize_url(vendor.website)
        if site_norm:
            add(
                SourceCandidate(
                    url=site_norm,
                    source_type="official",
                    reason="Official website provided in the Meridian intake workbook.",
                    vendor_name=vendor.name,
                    discovery_method="official_intake",
                    source_relevance="service_direct",
                )
            )
            # Hypothesized privacy path to review if it exists (not treated as verified)
            add(
                SourceCandidate(
                    url=urljoin(site_norm + "/", "privacy"),
                    source_type="privacy",
                    reason="Common privacy-policy path to review if it exists. Not a finding.",
                    vendor_name=vendor.name,
                    discovery_method="path_probe",
                    source_relevance="privacy_security",
                )
            )

    # 2. Known verified official pages for Meridian case study vendors
    name_lower = vendor.name.lower()
    for key, pages in _KNOWN_OFFICIAL_PAGES.items():
        if key in name_lower:
            for url, stype, reason, srel in pages:
                add(
                    SourceCandidate(
                        url=url,
                        source_type=stype,
                        reason=reason,
                        vendor_name=vendor.name,
                        discovery_method="known_official",
                        source_relevance=srel,
                    )
                )

    # 3. Discovered links from homepage HTML if provided
    if homepage_html and vendor.website:
        discovered = discover_links_from_html(
            homepage_html,
            base_url=vendor.website,
            vendor_name=vendor.name,
        )
        for cand in discovered:
            add(cand)

    # 4. Search query leads for manual analyst review
    # Explicitly labeled as search_query; never fetched or treated as evidence.
    product_keywords = ""
    if vendor.product:
        words = re.findall(r"\b\w+\b", vendor.product)
        product_keywords = " ".join(words[:6])

    lead_query = quote_plus(f"{vendor.name} {product_keywords} AI documentation privacy".strip())
    add(
        SourceCandidate(
            url=f"https://duckduckgo.com/?q={lead_query}",
            source_type="search_query",
            reason="Public web search query for analyst review. Not a finding. Never fetched automatically.",
            vendor_name=vendor.name,
            discovery_method="search_lead",
            source_relevance="lead",
        )
    )

    if vendor.product:
        subproc_query = quote_plus(f"{vendor.name} subprocessors AI model provider disclosure")
        add(
            SourceCandidate(
                url=f"https://duckduckgo.com/?q={subproc_query}",
                source_type="search_query",
                reason="Subprocessor search query for analyst review. Not a finding. Never fetched automatically.",
                vendor_name=vendor.name,
                discovery_method="search_lead",
                source_relevance="lead",
            )
        )

    logger.info("Discovered %s source candidates for %s", len(candidates), vendor.name)
    return candidates


def discover_sources_for_vendors(
    vendors: list[VendorRecord],
    homepage_htmls: dict[str, str] | None = None,
) -> list[SourceCandidate]:
    """Discover candidates for each vendor independently."""
    results: list[SourceCandidate] = []
    homepage_htmls = homepage_htmls or {}
    for vendor in vendors:
        html = homepage_htmls.get(vendor.name)
        results.extend(discover_sources(vendor, homepage_html=html))
    return results
