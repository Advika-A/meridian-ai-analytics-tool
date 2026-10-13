"""Classification operates only on supplied text."""

from src.classify import classify_text
from src.extract import _visible_text
from src.models import ExtractedDocument
from src.classify import classify_documents


def test_empty_text_yields_no_evidence() -> None:
    assert classify_text("") == []
    assert classify_text("   ") == []


def test_keywords_label_snippets_without_vendor_verdict() -> None:
    text = "We use generative AI and encryption for customer data."
    items = classify_text(text, source_url="https://example.invalid/security")
    categories = {item.category for item in items}
    assert "ai_capability_claim" in categories
    assert "security_control" in categories
    assert all("not a conclusion" in item.rationale.lower() for item in items)


def test_failed_documents_are_ignored() -> None:
    docs = [
        ExtractedDocument(url="https://x.invalid", status="failed", error="timeout"),
        ExtractedDocument(url="https://y.invalid", status="ok", text="ISO 27001 controls"),
    ]
    items = classify_documents(docs)
    assert len(items) == 1
    assert items[0].category == "security_control"


def test_visible_text_strips_scripts() -> None:
    title, text = _visible_text(
        "<html><head><title>Trust</title></head>"
        "<body><script>secret()</script><p>Privacy policy</p></body></html>"
    )
    assert title == "Trust"
    assert "secret" not in text
    assert "Privacy policy" in text


def test_evidence_keeps_exact_sentence_and_source_metadata() -> None:
    sentence = "Our AI assistant is powered by OpenAI via API."
    items = classify_text(
        "A general introduction. " + sentence + " More unrelated text.",
        source_url="https://example.invalid/trust",
        source_title="Trust Center",
        retrieved_at="2026-10-11T12:00:00+00:00",
    )
    ai_item = next(item for item in items if item.category == "ai_capability_claim")
    assert ai_item.snippet == sentence
    assert ai_item.source_title == "Trust Center"
    assert ai_item.retrieved_at == "2026-10-11T12:00:00+00:00"
    provider_item = next(item for item in items if item.category == "ai_subprocessor_disclosure")
    assert "OpenAI" in provider_item.matched_terms
    assert provider_item.source_url == "https://example.invalid/trust"


def test_provider_name_alone_does_not_trigger_subprocessor_category() -> None:
    items = classify_text("Our staff attended an OpenAI conference.")
    assert all(item.category != "ai_subprocessor_disclosure" for item in items)


def test_generic_security_privacy_sharing_not_ai_evidence() -> None:
    """Generic security, encryption, privacy, and third-party sharing text is never AI evidence."""
    texts = [
        "We maintain SOC 2 Type II compliance and AES-256 encryption at rest.",
        "Our privacy policy complies with GDPR and CCPA data subject access regulations.",
        "We may share data with third-party service providers for payment processing.",
    ]
    for text in texts:
        items = classify_text(text, source_url="https://vendor.com/privacy", vendor_name="AutomWorx")
        assert len(items) >= 1
        for item in items:
            assert item.category not in ("ai_capability_claim", "confirmed_service_ai", "ai_subprocessor_disclosure", "model_training")
            assert "not evidence of ai usage" in item.rationale.lower()


def test_service_specific_requires_explicit_service_connection() -> None:
    """Only excerpts explicitly connecting to the actual purchased service are service_specific."""
    # Generic security text without service connection -> ambiguous
    generic_text = "We protect all customer accounts using end-to-end encryption."
    items_generic = classify_text(
        generic_text,
        source_url="https://vendor.com/privacy",
        vendor_name="Fiserv, Inc.",
        service_context="The DNA core banking platform",
    )
    assert len(items_generic) >= 1
    assert items_generic[0].relevance == "ambiguous"

    # Explicit service connection -> service_specific
    service_text = "The DNA core banking platform uses dedicated machine learning for transaction screening."
    items_service = classify_text(
        service_text,
        source_url="https://vendor.com/dna-docs",
        vendor_name="Fiserv, Inc.",
        service_context="The DNA core banking platform",
    )
    assert len(items_service) >= 1
    assert items_service[0].relevance == "service_specific"
    assert items_service[0].category == "confirmed_service_ai"


def test_cookie_notices_and_boilerplate_link_lists_rejected() -> None:
    """Cookie consent notices and link lists are rejected as boilerplate."""
    cookie_text = "We use cookies and similar technologies to improve your experience. Accept all cookies."
    assert classify_text(cookie_text) == []

    link_list = "Home | Solutions | Products | Services | Contact Us | Privacy Policy | Terms of Service"
    assert classify_text(link_list) == []


def test_deduplicate_urls_resolving_to_same_page_keeps_distinct_evidence() -> None:
    """URLs that resolve to the same page deduplicate identical evidence while keeping distinct evidence."""
    doc1 = ExtractedDocument(
        url="https://vendor.com/privacy",
        final_url="https://vendor.com/legal/privacy",
        status="ok",
        text="We use generative AI assistants for customer support. We also enforce AES-256 encryption.",
    )
    doc2 = ExtractedDocument(
        url="https://vendor.com/legal/privacy",
        final_url="https://vendor.com/legal/privacy",
        status="ok",
        text="We use generative AI assistants for customer support. Our platform requires MFA.",
    )
    items = classify_documents([doc1, doc2], vendor_name="Vendor")

    # Identical generative AI snippet should appear once
    ai_items = [i for i in items if i.category == "ai_capability_claim"]
    assert len(ai_items) == 1

    # Distinct security controls (AES-256 encryption from doc1, MFA from doc2) are both preserved
    sec_items = [i for i in items if i.category == "security_control"]
    assert len(sec_items) == 2
    matched = {term.lower() for i in sec_items for term in i.matched_terms}
    assert "encryption" in matched
    assert "mfa" in matched
