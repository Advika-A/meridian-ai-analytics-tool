# Meridian Financial — Vendor AI Usage Assessment Tool

Integrated, evidence-driven, deterministic cybersecurity assessment application for evaluating third-party vendor AI usage risks across Meridian Financial's vendor inventory.

---

## 1. Executive & Architectural Overview

The application conducts third-party vendor assessments based strictly on public-source information (OSINT), documented disclosures, and intake attributes.

### Key Operational Principles:
- **Zero LLM / No Generative AI:** Analysis and classification are 100% deterministic, rule-based, and explainable. No third-party AI APIs or credentials are used or required.
- **Strict Scope Integrity:** No presentation decks, PDFs, Word documents, or narrative summary reports are generated. Outputs are strictly:
  1. The integrated Streamlit application (`app.py`).
  2. The validated Excel workbook based directly on the original Meridian template (`exports/assessment.xlsx`).
  3. The local SQLite database (`data/meridian.db`).
  4. The automated test suite (`pytest`, 68 tests passing).
  5. The machine-readable live-source smoke test report (`smoke_test_report.json`).
- **Template & Data Preservation:** Original workbook formatting, protected cells, worksheets, formulas, and the fictional worked example row (`V-000`) are preserved without alteration. Only explicitly permitted student-completion cells (`Columns L-V`) are updated.
- **Separation of Concerns:** Business criticality is assessed separately from AI-related cybersecurity risk. Criticality reflects organizational dependency and data classification; AI risk requires concrete public evidence of AI capabilities.
- **Conservative Risk State:** Generic privacy policies, SOC 2 attestations, or encryption disclosures do not establish AI usage. Absence of evidence results in an `unrated` risk level and `insufficient_evidence` state, never an inferred clean bill of health.
- **Corporate Announcement vs. Service-Specific Distinction:** A vendor mentioning AI in general press releases, executive blogs, or corporate marketing does not prove AI is used in the specific service Meridian purchases. Corporate announcements are labeled `corporate_general` and flagged for human review (`corporate_signal_only`), keeping AI risk `not_rated`.

---

## 2. Directory Structure

```
integrated_app/
├── app.py                     # Streamlit application entry point
├── smoke_test_live.py         # Live public-source smoke test CLI runner
├── smoke_test_report.json     # Machine-readable live retrieval provenance report
├── requirements.txt           # Consolidated dependencies (no LLM/pptx)
├── pytest.ini                 # Pytest configuration
├── README.md                  # Technical documentation
├── data/
│   └── meridian.db            # Local SQLite assessment database
├── exports/
│   └── assessment.xlsx        # Validated assessment output on Meridian template
├── supporting material/
│   └── Meridian_Vendor_Input.xlsx  # Original Meridian workbook template
├── src/
│   ├── __init__.py
│   ├── models.py              # Provenance-aware data models (VendorRecord, EvidenceItem, etc.)
│   ├── excel_handler.py       # Meridian template loader, validator, and cell exporter
│   ├── excel_io.py            # Generic Excel intake handler
│   ├── scoring.py             # Transparent 4-factor vendor criticality scoring rubric
│   ├── osint.py               # Discovered-link, sitemap, and official portal discovery
│   ├── extract.py             # Main-content extraction, boilerplate removal & SSRF defense
│   ├── classify.py            # Rule-based contextual evidence classifier with service relevance
│   ├── risk.py                # Conservative risk evaluator with linked evidence IDs
│   ├── db.py                  # Idempotent SQLite persistence layer
│   ├── export.py              # Generic multi-sheet Excel export
│   ├── meridian_export.py     # Meridian student-column update builder
│   └── logging_config.py      # Structured logging setup
└── tests/
    ├── conftest.py
    ├── test_classification_comprehensive.py # Precision, false positives, limitations
    ├── test_classify.py                     # Classifier unit tests
    ├── test_db.py                           # SQLite schema, migration & idempotency
    ├── test_excel_handler.py                # Header detection & protected cell preservation
    ├── test_excel_io.py                     # Generic Excel reader tests
    ├── test_export.py                       # Generic workbook export tests
    ├── test_extract.py                      # Extractor URL skipping tests
    ├── test_meridian_export.py              # Meridian student column population tests
    ├── test_meridian_integration.py         # Workbook loading & scoring integration
    ├── test_osint.py                        # Search query & path discovery tests
    ├── test_real_source_retrieval.py        # 21 comprehensive offline regression tests
    ├── test_risk.py                         # Conservative risk evaluation tests
    ├── test_scoring.py                      # Criticality rubric unit tests
    ├── test_workbook_integrity.py           # 10 mandatory checks for workbook safety
    └── test_end_to_end_pipeline.py          # Full pipeline integration test
```

---

## 3. Real-World Public Source Pipeline Improvements

Following live-source empirical testing against the six Meridian vendors, the pipeline was upgraded to eliminate blind path guessing, strip website boilerplate, and distinguish corporate marketing from service-level AI use:

### 1. Source Discovery (`src/osint.py`)
- **No Blind Guessing:** Replaced arbitrary path guesses (`/security`, `/trust`, `/legal`, `/ai`) with validated official entry points, homepage link discovery (`discover_links_from_html`), and sitemap XML parsing (`discover_from_sitemap`).
- **URL Normalization & Deduplication:** Strips fragments (`#...`), trims trailing slashes, removes tracking parameters (`utm_*`, `ref=`), and deduplicates URLs.
- **Provenance Tracking:** Tracks `discovery_method` (`official_intake`, `homepage_link`, `sitemap`, `robots`, `known_official`, `search_lead`) and `source_relevance`.
- **Search Query Leads:** Clearly flags search queries as analyst leads; never fetches search engines or classifies search snippets as evidence.

### 2. Main-Content Extraction (`src/extract.py`)
- **Main Content Preference:** Uses BeautifulSoup to select content from `<main>`, `<article>`, `[role=main]`, or `#content` before falling back to cleaned body text.
- **Boilerplate Removal:** Decomposes `<nav>`, `<header>`, `<footer>`, `<aside>`, `<form>`, `<script>`, `<style>`, cookie consent dialogs (`#onetrust`, `.cookie-banner`), and social sharing widgets.
- **Accurate Status Categorization:** Categorizes pages into `ok`, `soft_404` (HTTP 200 with "Page Not Found" title/heading), `empty_js_rendered` (single-page apps like Terrapin Technologies requiring client-side execution), `empty`, `failed`, and `skipped`.
- **Robust SSRF Defense:** Enforces HTTP/HTTPS, resolves hostnames via DNS, checks every IP against loopback (`127.0.0.0/8`), RFC 1918 private subnets (`10/8`, `172.16/12`, `192.168/16`), link-local/cloud metadata (`169.254/16`), and re-validates redirect destinations before following.

### 3. Contextual Evidence Classification (`src/classify.py`)
- **Contextual Passages:** Evaluates multi-sentence context around matches rather than isolated words.
- **Service Relevance Attribution:** Evaluates evidence relevance as `service_specific` (matches vendor product tokens), `corporate_general` (press release, executive blog, industry thought leadership), or `ambiguous`.
- **Strict Subprocessor Rules:** Mentioning OpenAI, Anthropic, Azure OpenAI, or AWS Bedrock alone does NOT establish a subprocessor relationship; requires explicit processing cues in the same passage.
- **Limitations & Disclosures:** Detects explicit restrictions (e.g. "we do not train models on customer data") and captures them in reviewer notes.
- **Boilerplate Rejection:** Rejects residual menu lines, copyright fragments, or navigation links matching keywords.

### 4. Conservative Risk Assessment (`src/risk.py`)
- **Strict Separation:** Business criticality reflects organizational dependency; AI risk reflects confirmed public evidence.
- **Insufficient Evidence State:** No relevant AI evidence produces status=`insufficient_evidence` and `risk_level="not_rated"`.
- **Corporate Announcements:** Vendors with only corporate-level AI announcements receive status=`corporate_signal_only` and `risk_level="not_rated"` with explicit evidence gaps.
- **Linked Evidence Provenance:** Preliminary risk drivers cite specific evidence IDs and list unverified research gaps.

---

## 4. Measured Live-Source Smoke Test Results

Execution of `python smoke_test_live.py --output smoke_test_report.json` against the six Meridian vendors produced the following verified results:

| Vendor ID | Vendor Name | Category / Service | Candidate Sources | Pages Retrieved (OK) | Empty / JS / Soft-404 | Evidence Excerpts | Assessment Status | AI Risk Level |
|---|---|---|:---:|:---:|:---:|:---:|---|---|
| **V-001** | AutomWorx | Workload automation / batch scheduling | 5 | 3 | 0 | 4 | `corporate_signal_only` | **Not Rated** |
| **V-002** | Fiserv, Inc. | Core banking (DNA platform) | 6 | 3 | 0 | 7 | `insufficient_evidence` | **Not Rated** |
| **V-003** | FSSI | Document print/mail outsourcing | 4 | 2 | 0 | 5 | `insufficient_evidence` | **Not Rated** |
| **V-004** | Terrapin Technologies | Wealth data / reporting | 4 | 0 | 2 (JS-Rendered) | 0 | `insufficient_evidence` | **Not Rated** |
| **V-005** | BNY | Real-Time Payments (RTP) | 5 | 1 | 2 (HTTP 404) | 0 | `insufficient_evidence` | **Not Rated** |
| **V-006** | The Clearing House | ACH & RTP payments infrastructure | 7 | 3 | 2 (Soft 404) | 2 | `insufficient_evidence` | **Not Rated** |
| **TOTAL** | **6 Vendors** | — | **31** | **12** | **6** | **18** | — | — |

### Key Live Observations:
1. **AutomWorx:** Retrieved homepage, privacy policy, and consulting services pages. Corporate blog mention of enterprise AI agents was classified as `corporate_general` (`requires_human_review`), assigning status `corporate_signal_only` and risk `not_rated` because AI usage is not established for Meridian's specific batch scheduling service.
2. **Fiserv:** Successfully retrieved homepage and global privacy notice. Security and data processing commitments were extracted; no unverified AI subprocessor claims were inferred.
3. **FSSI:** Retrieved homepage and full privacy policy (35K chars). Document presentment and secure data processing controls were classified; no AI features detected.
4. **Terrapin Technologies:** Both homepage and privacy routes returned JavaScript-rendered client-side SPAs. Accurately recorded as `empty_js_rendered` with 0 fabricated excerpts and explicit research gaps logged.
5. **BNY:** Successfully retrieved global corporate homepage; deep legal paths returned 404 and were documented as failures without fallback fabrication.
6. **The Clearing House:** Successfully retrieved homepage, RTP network documentation, and ACH processing documentation. Caught 2 soft 404 pages (HTTP 200 with "Page Not Found" title) without counting them as successful retrievals.

---

## 5. Running the Tests & Live Smoke Test

### Automated Offline Test Suite
Run all 68 unit, classification, SSRF security, and workbook integrity tests (100% offline, zero internet dependency):
```powershell
python -m pytest tests/ -v
```

### Live Public-Source Smoke Test
Run the live network retrieval test against the six real vendors and output the machine-readable provenance JSON:
```powershell
python smoke_test_live.py --output smoke_test_report.json
```

---

## 6. Launching the Streamlit Application

Run the Streamlit application:
```powershell
streamlit run app.py
```

### End-to-End Workflow in the UI:
1. **Load Workbook:** Click `📂 Load Case Study` or upload `supporting material/Meridian_Vendor_Input.xlsx`. The app detects header row 4, excludes the fictional example row `V-000`, and loads the 6 real vendor records (`V-001` through `V-006`).
2. **Score Criticality & Assess Risk:** Check `Fetch discovered public pages` in the sidebar and click `2️⃣ Score Criticality & Assess Risk`.
   - Intake-based criticality is calculated.
   - Public pages are retrieved with SSRF protection and boilerplate removal.
   - Extracted text is classified into structured evidence items with service relevance attribution.
   - Preliminary AI risk is evaluated conservatively.
3. **Inspect Dossiers & Evidence:** Use the `🔍 Evidence & Manual Entry`, `⚠️ Risk Assessment`, and `📁 Vendor Dossier` tabs to review excerpts, provenance URLs, and evidence gaps.
4. **Save & Export:** Click `3️⃣ Save to Database & Export Excel`. Results are persisted to SQLite (`data/meridian.db`) and written directly into permitted student columns of `exports/assessment.xlsx`.
