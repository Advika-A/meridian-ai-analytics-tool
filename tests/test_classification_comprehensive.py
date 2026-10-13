"""Tests for classifier precision, ambiguity, and false positive avoidance."""

from src.classify import classify_text
from src.models import EvidenceItem


def test_generic_encryption_not_ai() -> None:
    text = "We use AES-256 encryption at rest and in transit."
    items = classify_text(text)
    categories = [i.category for i in items]
    assert "security_control" in categories
    assert "ai_capability_claim" not in categories
    assert "ai_subprocessor_disclosure" not in categories


def test_generic_soc2_not_ai() -> None:
    text = "Our systems are SOC 2 Type II certified and ISO 27001 compliant."
    items = classify_text(text)
    categories = [i.category for i in items]
    assert "security_control" in categories
    assert "ai_capability_claim" not in categories


def test_generic_privacy_policy_not_ai() -> None:
    text = "Our privacy policy complies with GDPR and CCPA requirements for data subject access requests."
    items = classify_text(text)
    categories = [i.category for i in items]
    assert "privacy_commitment" in categories
    assert "ai_capability_claim" not in categories


def test_provider_name_without_context_not_subprocessor() -> None:
    text = "Our executive team read the latest research paper from OpenAI and Anthropic."
    items = classify_text(text)
    assert not any(i.category == "ai_subprocessor_disclosure" for i in items)


def test_provider_name_with_subprocessor_context_is_detected() -> None:
    text = "Customer inquiries are processed by our AI subprocessor OpenAI via secure API."
    items = classify_text(text)
    assert any(i.category == "ai_subprocessor_disclosure" for i in items)


def test_model_training_explicit_statement() -> None:
    text = "Customer prompts are used to train our models and improve our AI systems."
    items = classify_text(text)
    assert any(i.category == "model_training" for i in items)


def test_explicit_limitation_statement() -> None:
    text = "We will never train our models on customer data."
    items = classify_text(text)
    model_items = [i for i in items if i.category == "model_training"]
    assert len(model_items) > 0
    # Rationale must note the explicit limitation
    assert "limitation" in model_items[0].rationale.lower() or "never train" in model_items[0].rationale.lower()


def test_corporate_ai_announcement_distinction() -> None:
    # A generic corporate statement vs a product feature
    text = "The vendor provides batch scheduling automation for enterprise batch jobs."
    items = classify_text(text)
    # No AI claims in batch scheduling
    assert not any(i.category == "ai_capability_claim" for i in items)


def test_multiple_excerpts_same_source_deduplicated_categories() -> None:
    text = "We use machine learning. We also leverage machine learning for sorting. And machine learning assists agents."
    items = classify_text(text)
    # Should only create one EvidenceItem per category per document/text block
    ai_items = [i for i in items if i.category == "ai_capability_claim"]
    assert len(ai_items) == 1
