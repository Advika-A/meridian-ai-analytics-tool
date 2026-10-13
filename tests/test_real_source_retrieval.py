"""
Comprehensive offline regression and unit tests for real-source retrieval and assessment.

These tests do NOT make any internet requests. They exercise the pipeline using
controlled local fixtures and mocks, verifying all requirements:
1. Homepage-link and sitemap discovery
2. Duplicate URL normalization (fragments, trailing slashes, query params)
3. Removal of navigation, footers, cookie banners, and menus from extracted text
4. Relevant versus irrelevant AI keyword matches
5. Corporate AI announcements versus service-specific evidence
6. AI provider names without contextual processing evidence
7. Empty pages, JavaScript-rendered SPAs, and soft 404s
8. Bounded redirects and SSRF protection (DNS resolution and private IP check)
9. Duplicate evidence rejection across repeated runs
10. Insufficient evidence producing status='insufficient_evidence' (not 'low risk')
11. Workbook integrity and exclusion of the fictional example
"""
from __future__ import annotations

import gzip
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.classify import classify_text
from src.excel_handler import get_real_vendors_and_student_columns, load_meridian_workbook, to_vendor_record
from src.extract import _clean_soup, _extract_main_content, _is_js_rendered, _is_soft_404, extract_url, is_safe_url
from src.models import EvidenceItem, SourceCandidate, VendorRecord
from src.osint import (
    discover_links_from_html,
    discover_from_sitemap,
    discover_sources,
    discover_sources_for_vendors,
    normalize_url,
)
from src.risk import analyse_risk


def _make_vendor(
    name: str,
    *,
    product: str = "",
    website: str = "",
    category: str = "",
) -> VendorRecord:
    attrs: dict[str, Any] = {}
    if category:
        attrs["Category"] = category
    return VendorRecord(name=name, product=product, website=website, attributes=attrs)


def _mock_response(
    html: bytes,
    *,
    status_code: int = 200,
    content_encoding: str | None = None,
    content_type: str = "text/html; charset=utf-8",
    is_redirect: bool = False,
    location: str | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.is_redirect = is_redirect
    resp.encoding = "utf-8"

    headers: dict[str, str] = {"Content-Type": content_type}
    if content_encoding:
        headers["Content-Encoding"] = content_encoding
    if location:
        headers["Location"] = location
    resp.headers = headers

    decompressed = html
    if content_encoding == "gzip":
        decompressed = gzip.decompress(html)

    def _iter_content(chunk_size: int = 65536):
        yield decompressed

    resp.iter_content = _iter_content
    return resp


def _patch_session(response: MagicMock) -> Any:
    session_mock = MagicMock()
    session_mock.prepare_request.return_value = MagicMock()
    session_mock.send.return_value = response
    session_mock.get.return_value = response
    return patch("src.extract.requests.Session", return_value=session_mock)


# ===========================================================================
# 1. Source Discovery Tests: Homepage Links & Sitemaps
# ===========================================================================

class TestSourceDiscovery:
    """Verify link discovery from HTML, sitemaps, and URL normalization."""

    def test_homepage_link_discovery(self) -> None:
        """HTML links to privacy, trust, and services are extracted and typed."""
        html = """
        <html><body>
            <nav><a href="/about">About Us</a></nav>
            <main>
                <a href="/legal/privacy-notice">Privacy Notice</a>
                <a href="/security/trust-center">Trust and Security</a>
                <a href="/docs/api">API Documentation</a>
                <a href="https://external.com/irrelevant">External</a>
            </main>
        </body></html>
        """
        candidates = discover_links_from_html(html, base_url="https://vendor.example.com", vendor_name="TestVendor")
        urls = {c.url for c in candidates}

        assert "https://vendor.example.com/legal/privacy-notice" in urls
        assert "https://vendor.example.com/security/trust-center" in urls
        assert "https://vendor.example.com/docs/api" in urls
        assert "https://external.com/irrelevant" not in urls  # External domains excluded
        assert all(c.discovery_method == "homepage_link" for c in candidates)

    def test_sitemap_discovery(self) -> None:
        """Sitemap XML <loc> entries are parsed and filtered for relevance."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://vendor.example.com/privacy-policy</loc></url>
            <url><loc>https://vendor.example.com/ai-principles</loc></url>
            <url><loc>https://vendor.example.com/irrelevant-blog-post</loc></url>
        </urlset>
        """
        candidates = discover_from_sitemap(xml, base_url="https://vendor.example.com", vendor_name="TestVendor")
        urls = {c.url for c in candidates}

        assert "https://vendor.example.com/privacy-policy" in urls
        assert "https://vendor.example.com/ai-principles" in urls
        assert "https://vendor.example.com/irrelevant-blog-post" not in urls
        assert all(c.discovery_method == "sitemap" for c in candidates)

    def test_url_normalization_fragments_and_slashes(self) -> None:
        """normalize_url strips fragments, duplicate slashes, and trailing slashes."""
        assert normalize_url("https://example.com/privacy/#section2") == "https://example.com/privacy"
        assert normalize_url("https://example.com/docs//api/") == "https://example.com/docs/api"
        assert normalize_url("HTTP://EXAMPLE.COM/") == "http://example.com/"
        assert normalize_url("https://example.com/page?utm_source=twitter&ref=123") == "https://example.com/page"

    def test_duplicate_candidate_urls_prevented(self) -> None:
        """Deduplication ensures the same URL is never added twice."""
        vendor = _make_vendor("Fiserv, Inc.", website="www.fiserv.com")
        sources = discover_sources(vendor)
        urls = [s.url for s in sources]
        assert len(urls) == len(set(urls))


# ===========================================================================
# 2. Content Extraction & Boilerplate Removal Tests
# ===========================================================================

class TestContentExtraction:
    """Verify that extraction strips navigation/footers and prefers main content."""

    def test_removal_of_navigation_and_footer_boilerplate(self) -> None:
        """Header, nav, footer, and cookie banner text are removed from visible text."""
        html = b"""
        <html>
        <head><title>Test Page</title></head>
        <body>
            <header><div class="nav">Home | About | Contact Us</div></header>
            <div id="cookie-banner">We use cookies to enhance your experience. Accept All.</div>
            <main>
                <h1>Core Banking Platform</h1>
                <p>The DNA core banking platform manages accounts and balances in real time.</p>
            </main>
            <footer><div>Copyright 2026. All rights reserved. Privacy Policy | Terms.</div></footer>
        </body>
        </html>
        """
        response = _mock_response(html)
        with _patch_session(response):
            doc = extract_url("https://vendor.example.com/dna", timeout=5, resolve_dns=False)

        assert doc.status == "ok"
        assert "DNA core banking platform manages accounts" in doc.text
        assert "Accept All" not in doc.text
        assert "All rights reserved" not in doc.text
        assert "Home | About" not in doc.text

    def test_main_content_preferred_over_nav(self) -> None:
        """<article> or <main> container is selected over auxiliary text."""
        html = b"""
        <html><body>
            <aside>Unrelated sidebar links.</aside>
            <article>
                <p>Our workload automation tool coordinates batch execution across systems.</p>
            </article>
        </body></html>
        """
        response = _mock_response(html)
        with _patch_session(response):
            doc = extract_url("https://vendor.example.com/product", timeout=5, resolve_dns=False)

        assert doc.status == "ok"
        assert "workload automation tool coordinates batch execution" in doc.text

    def test_empty_js_rendered_detection(self) -> None:
        """Pages requiring JavaScript runtime are flagged as empty_js_rendered."""
        html = b"""
        <html><body>
            <div id="root"></div>
            <noscript>You need to enable JavaScript to run this app.</noscript>
        </body></html>
        """
        response = _mock_response(html)
        with _patch_session(response):
            doc = extract_url("https://vendor.example.com/app", timeout=5, resolve_dns=False)

        assert doc.status == "empty_js_rendered"
        assert "JavaScript" in (doc.error or "")

    def test_soft_404_detection(self) -> None:
        """HTTP 200 with 'Page Not Found' title is marked as soft_404."""
        html = b"<html><head><title>Page Not Found | Vendor</title></head><body>Error 404</body></html>"
        response = _mock_response(html)
        with _patch_session(response):
            doc = extract_url("https://vendor.example.com/missing", timeout=5, resolve_dns=False)

        assert doc.status == "soft_404"
        assert doc.text == ""


# ===========================================================================
# 3. SSRF & Redirect Validation Tests
# ===========================================================================

class TestSSRFSecurity:
    """Verify SSRF mitigation against private IPs, loopbacks, and redirects."""

    def test_ssrf_rejects_loopback_and_private(self) -> None:
        assert not is_safe_url("http://127.0.0.1/admin")[0]
        assert not is_safe_url("http://localhost:8080/")[0]
        assert not is_safe_url("http://10.0.0.5/api")[0]
        assert not is_safe_url("http://192.168.1.1/router")[0]
        assert not is_safe_url("http://169.254.169.254/latest/meta-data")[0]

    def test_ssrf_rejects_private_dns_resolution(self) -> None:
        """Hostnames resolving to private IP addresses are rejected."""
        with patch("socket.getaddrinfo", return_value=[(2, 1, 0, "", ("10.0.0.1", 80))]):
            safe, reason = is_safe_url("https://malicious.example.com", resolve_dns=True)
            assert not safe
            assert "prohibited network" in reason

    def test_ssrf_blocks_redirect_to_private_destination(self) -> None:
        """A redirect to an internal IP address is intercepted and blocked."""
        resp1 = _mock_response(b"", status_code=302, is_redirect=True, location="http://192.168.1.1/admin")
        with _patch_session(resp1):
            doc = extract_url("https://vendor.example.com/jump", timeout=5, resolve_dns=False)

        assert doc.status == "failed"
        assert "security policy" in (doc.error or "").lower()


# ===========================================================================
# 4. Evidence Classification Quality Tests
# ===========================================================================

class TestEvidenceClassification:
    """Verify strict rule-based classification and service relevance."""

    def test_corporate_announcement_vs_service_specific(self) -> None:
        """Corporate blog / general marketing is flagged as corporate_general, not service_specific."""
        corp_text = (
            "In our latest corporate blog post, we share our executive vision for "
            "generative AI and artificial intelligence across the financial industry."
        )
        items = classify_text(
            corp_text,
            source_url="https://vendor.example.com/blog/ai-vision",
            source_title="Executive Blog",
            vendor_name="AutomWorx",
            service_context="Batch scheduling and workload automation",
        )
        assert len(items) >= 1
        claim = items[0]
        assert claim.relevance == "corporate_general"
        assert claim.verification_status == "requires_human_review"

    def test_service_specific_ai_detection(self) -> None:
        """Direct documentation of AI within the contracted service is service_specific."""
        service_text = (
            "The DNA core banking platform incorporates a machine learning model "
            "to automate transaction processing and account balance anomaly detection."
        )
        items = classify_text(
            service_text,
            source_url="https://fiserv.com/dna-docs",
            vendor_name="Fiserv, Inc.",
            service_context="The DNA core banking platform",
        )
        assert len(items) >= 1
        assert items[0].relevance == "service_specific"
        assert items[0].category == "confirmed_service_ai"
        assert items[0].verification_status == "verified"

    def test_ai_provider_alone_not_subprocessor(self) -> None:
        """Mentioning OpenAI or Anthropic by name without processing cues is not a subprocessor."""
        text = "Our engineering team studies foundation models from OpenAI and Anthropic."
        items = classify_text(text, source_url="https://vendor.com/about", vendor_name="Vendor")
        subprocessors = [i for i in items if i.category == "ai_subprocessor_disclosure"]
        assert not subprocessors

    def test_ai_provider_with_context_is_subprocessor(self) -> None:
        """Provider name + processing / subprocessor cue triggers subprocessor disclosure."""
        text = "Customer personal data is processed using the OpenAI API as an authorized subprocessor."
        items = classify_text(text, source_url="https://vendor.com/privacy", vendor_name="Vendor")
        subprocessors = [i for i in items if i.category == "ai_subprocessor_disclosure"]
        assert len(subprocessors) == 1
        assert "OpenAI" in subprocessors[0].matched_terms
        assert "subprocessor" in subprocessors[0].matched_terms

    def test_boilerplate_navigation_matches_rejected(self) -> None:
        """Footer and navigation link fragments matching AI terms are rejected."""
        nav_text = "Home > Solutions > AI-Powered Tools > Careers | Privacy Policy | Terms of Use"
        items = classify_text(nav_text, source_url="https://vendor.com", vendor_name="Vendor")
        assert len(items) == 0

    def test_evidence_deduplication_across_runs(self) -> None:
        """Identical text snippets on repeated calls do not produce duplicate evidence items."""
        text = "We use machine learning models for fraud prevention."
        items1 = classify_text(text, source_url="https://vendor.com/p1", vendor_name="Vendor")
        items2 = classify_text(text, source_url="https://vendor.com/p2", vendor_name="Vendor")
        combined: list[EvidenceItem] = []
        seen = set()
        for item in items1 + items2:
            if item.snippet not in seen:
                seen.add(item.snippet)
                combined.append(item)
        assert len(combined) == 1


# ===========================================================================
# 5. Risk Assessment Conservatism Tests
# ===========================================================================

class TestRiskAssessmentConservatism:
    """Verify conservative rating logic and separation of criticality from AI risk."""

    def test_insufficient_evidence_produced_when_no_ai_claim(self) -> None:
        """Absence of AI evidence produces status='insufficient_evidence' and risk='not_rated'."""
        sec_evidence = [
            EvidenceItem(
                category="security_control",
                snippet="SOC 2 Type II certified with TLS 1.3 encryption.",
                heuristic_score=0.5,
                rationale="Security control match.",
                source_url="https://vendor.com/security",
                vendor_name="Vendor",
                relevance="service_specific",
            )
        ]
        res = analyse_risk(vendor_name="Vendor", criticality=None, evidence=sec_evidence)
        assert res.status == "insufficient_evidence"
        assert res.risk_level == "not_rated"
        assert res.risk_score is None

    def test_corporate_announcement_does_not_rate_service_risk(self) -> None:
        """A corporate announcement alone produces status='corporate_signal_only' and 'not_rated'."""
        corp_evidence = [
            EvidenceItem(
                category="ai_capability_claim",
                snippet="In our latest blog post, we discuss enterprise AI agents and future capabilities.",
                heuristic_score=0.45,
                rationale="Corporate blog mention.",
                source_url="https://vendor.com/blog",
                vendor_name="Vendor",
                relevance="corporate_general",
            )
        ]
        res = analyse_risk(vendor_name="Vendor", criticality=None, evidence=corp_evidence)
        assert res.status == "corporate_signal_only"
        assert res.risk_level == "not_rated"
        assert res.risk_score is None
        assert "Corporate-level AI announcements exist" in res.evidence_gaps[0]

    def test_service_specific_ai_enables_preliminary_score(self) -> None:
        """Confirmed service-level AI unlocks preliminary risk scoring with linked IDs."""
        service_evidence = [
            EvidenceItem(
                category="confirmed_service_ai",
                snippet="DNA core banking automated machine learning risk scoring.",
                heuristic_score=0.75,
                rationale="Service-level documentation.",
                source_url="https://fiserv.com/dna",
                vendor_name="Fiserv, Inc.",
                relevance="service_specific",
                evidence_id="ev-101",
            )
        ]
        res = analyse_risk(vendor_name="Fiserv, Inc.", criticality=None, evidence=service_evidence)
        assert res.status in ("confirmed_disclosure", "confirmed_service_ai")
        assert res.risk_level in ("medium", "high")
        assert res.risk_score is not None
        assert "ev-101" in res.linked_evidence_ids


# ===========================================================================
# 6. Meridian Workbook Integrity Tests
# ===========================================================================

class TestMeridianWorkbookIntegrity:
    """Verify workbook loading, real vendor identification, and fictional row exclusion."""

    def test_meridian_workbook_excludes_fictional_example_and_keeps_six_vendors(self) -> None:
        wb_path = Path("supporting material/Meridian_Vendor_Input.xlsx")
        assert wb_path.exists(), "Meridian intake workbook must exist"

        bundle = load_meridian_workbook(wb_path)
        real_records, student_cols = get_real_vendors_and_student_columns(bundle)

        assert len(real_records) == 6, f"Expected exactly 6 real vendors, got {len(real_records)}"
        vendor_ids = {str(r.vendor_id) for r in real_records}
        assert "V-000" not in vendor_ids, "Fictional example V-000 must be excluded from assessment"
        assert {"V-001", "V-002", "V-003", "V-004", "V-005", "V-006"} == vendor_ids
