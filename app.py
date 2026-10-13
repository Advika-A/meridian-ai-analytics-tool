"""Streamlit entry point for the Meridian AI assessment application.

Evidence-driven, transparent, deterministic rule-based pipeline for
third-party vendor AI usage assessment. No external AI APIs or LLMs.
"""

from __future__ import annotations

import importlib
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.logging_config import configure_logging

configure_logging()
logger = logging.getLogger("meridian.app")

try:
    import streamlit as st
except ImportError:
    raise SystemExit(
        "Streamlit is not installed. Run: pip install -r requirements.txt"
    ) from None


def _optional_import(module_name: str) -> Any | None:
    try:
        return importlib.import_module(module_name)
    except Exception:
        logger.exception("Module %s is unavailable; UI will run in limited mode", module_name)
        return None


excel_io = _optional_import("src.excel_io")
excel_handler = _optional_import("src.excel_handler")
scoring = _optional_import("src.scoring")
osint = _optional_import("src.osint")
extract = _optional_import("src.extract")
classify = _optional_import("src.classify")
risk = _optional_import("src.risk")
db = _optional_import("src.db")
export = _optional_import("src.export")
meridian_export = _optional_import("src.meridian_export")


def _init_state() -> None:
    defaults: dict[str, Any] = {
        "vendors": [],
        "criticality": [],
        "sources": [],
        "documents": [],
        "evidence": [],
        "risks": [],
        "last_error": None,
        "meridian_bundle": None,
        "workbook_mode": "generic",
        "student_columns": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _rows(items: list[Any]) -> list[dict[str, Any]]:
    return [asdict(item) for item in items]


def _error(message: str) -> None:
    st.session_state.last_error = message
    logger.error(message)
    st.error(message)


st.set_page_config(
    page_title="Meridian AI Usage Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
_init_state()

st.title("🛡️ Meridian Financial — Third-Party Vendor AI Usage Assessment")
st.caption(
    "Preliminary public-source cybersecurity assessment tool. "
    "Rule-based, deterministic analysis. No external LLMs or generative AI. "
    "Public-web findings are heuristic leads requiring human verification."
)

with st.sidebar:
    st.header("⚙️ Configuration")
    db_path = st.text_input("SQLite path", value=str(ROOT / "data" / "meridian.db"))
    export_path = st.text_input("Export path", value=str(ROOT / "exports" / "assessment.xlsx"))
    fetch_pages = st.checkbox(
        "Fetch discovered public pages",
        value=False,
        help="Off by default. Bounded public requests with SSRF protection. Respect access policies.",
    )
    st.divider()
    st.markdown("### 📊 Status Overview")
    st.write(f"**Vendors loaded:** {len(st.session_state.vendors)}")
    st.write(f"**Criticality scored:** {len(st.session_state.criticality)}")
    st.write(f"**Sources candidate:** {len(st.session_state.sources)}")
    st.write(f"**Evidence items:** {len(st.session_state.evidence)}")
    st.write(f"**Risks assessed:** {len(st.session_state.risks)}")

    if st.session_state.last_error:
        st.warning(f"Error: {st.session_state.last_error}")

case_file = ROOT / "supporting material" / "Meridian_Vendor_Input.xlsx"

# Header Actions: Load, Analyse, Export
col_up1, col_up2 = st.columns([3, 1])
with col_up1:
    upload = st.file_uploader("Vendor intake Excel (.xlsx)", type=["xlsx"])
with col_up2:
    st.write("")
    st.write("")
    quick_load = False
    if case_file.exists():
        if st.button("📂 Load Case Study", help="Load supporting material/Meridian_Vendor_Input.xlsx directly"):
            quick_load = True

col_a, col_b, col_c = st.columns(3)

# 1. Load Vendors
if col_a.button("1️⃣ Load & Validate Workbook", type="primary") or quick_load:
    active_source = upload if upload is not None else (case_file if case_file.exists() else None)
    if active_source is None:
        _error("Choose an .xlsx file before loading vendors.")
    else:
        try:
            if excel_handler is not None and excel_handler.is_meridian_workbook(active_source):
                bundle = excel_handler.load_meridian_workbook(active_source)
                inventory_records, student_columns = excel_handler.get_real_vendors_and_student_columns(bundle)
                if not inventory_records:
                    raise ValueError("The Meridian workbook contains no real vendors to assess.")
                st.session_state.vendors = [excel_handler.to_vendor_record(row) for row in inventory_records]
                st.session_state.criticality = []
                st.session_state.sources = []
                st.session_state.documents = []
                st.session_state.evidence = []
                st.session_state.risks = []
                st.session_state.meridian_bundle = bundle
                st.session_state.workbook_mode = "meridian"
                st.session_state.student_columns = student_columns
                st.session_state.last_error = None
                st.success(
                    f"Successfully loaded {len(st.session_state.vendors)} real vendor(s) from Meridian template. "
                    f"Fictional example row (V-000) was preserved and excluded from assessment. Header row: {bundle.header_row}."
                )
            elif excel_io is not None:
                frame = excel_io.load_vendor_workbook(active_source)
                st.session_state.vendors = excel_io.parse_vendors(frame)
                st.session_state.criticality = []
                st.session_state.sources = []
                st.session_state.documents = []
                st.session_state.evidence = []
                st.session_state.risks = []
                st.session_state.meridian_bundle = None
                st.session_state.workbook_mode = "generic"
                st.session_state.student_columns = []
                st.session_state.last_error = None
                st.success(f"Loaded {len(st.session_state.vendors)} vendor(s) from generic format.")
            else:
                _error("Excel module is not available.")
        except Exception as exc:
            _error(str(exc))

# 2. Score, Discover, Classify
if col_b.button("2️⃣ Score Criticality & Assess Risk"):
    if not st.session_state.vendors:
        _error("Load vendors first.")
    elif None in (scoring, osint, classify, risk):
        _error("One or more analysis modules are unavailable.")
    else:
        try:
            vendors = st.session_state.vendors
            st.session_state.criticality = scoring.score_vendors(vendors)
            st.session_state.sources = osint.discover_sources_for_vendors(vendors)

            # Build URL→vendor mapping for accurate provenance attribution
            url_to_vendor: dict[str, str] = {
                s.url: s.vendor_name for s in st.session_state.sources
            }

            documents = []
            if fetch_pages and extract is not None:
                documents = extract.extract_candidates(st.session_state.sources)
            st.session_state.documents = documents

            # Classify extracted documents with correct per-document vendor_name.
            # This ensures every EvidenceItem is attributed to the vendor whose
            # source candidate produced the document — not to a generic empty name.
            all_evidence: list = list(st.session_state.evidence)
            if documents and classify is not None:
                for doc in documents:
                    if doc.status != "ok" or not doc.text:
                        continue
                    vendor_name_for_doc = url_to_vendor.get(doc.url, "")
                    vendor_obj = next((v for v in vendors if v.name == vendor_name_for_doc), None)
                    service_ctx = (vendor_obj.product or "") if vendor_obj else ""
                    doc_evidence = classify.classify_text(
                        doc.text,
                        source_url=doc.url,
                        source_title=doc.title or "",
                        retrieved_at=doc.retrieved_at,
                        vendor_name=vendor_name_for_doc,
                        service_context=service_ctx,
                    )
                    all_evidence.extend(doc_evidence)
            st.session_state.evidence = all_evidence

            # Group evidence by vendor for risk analysis
            evidence_by_vendor: dict[str, list] = {v.name: [] for v in vendors}
            for item in st.session_state.evidence:
                owner = item.vendor_name or url_to_vendor.get(item.source_url)
                if owner and owner in evidence_by_vendor:
                    evidence_by_vendor[owner].append(item)

            crit_by_name = {c.vendor_name: c for c in st.session_state.criticality}
            st.session_state.risks = [
                risk.analyse_risk(
                    vendor_name=vendor.name,
                    criticality=crit_by_name.get(vendor.name),
                    evidence=evidence_by_vendor.get(vendor.name, []),
                )
                for vendor in vendors
            ]
            st.session_state.last_error = None

            # Report retrieval statistics
            total_candidates = len(st.session_state.sources)
            fetched_ok = sum(1 for d in documents if d.status == "ok")
            fetched_fail = sum(1 for d in documents if d.status in ("failed", "soft_404"))
            fetched_skip = sum(1 for d in documents if d.status in ("skipped", "empty"))
            evidence_count = len(st.session_state.evidence)
            if fetch_pages:
                st.success(
                    f"Scoring and risk evaluation complete. "
                    f"Source candidates: {total_candidates} | "
                    f"Pages retrieved: {fetched_ok} | "
                    f"Failed/blocked: {fetched_fail} | "
                    f"Skipped (JS/search): {fetched_skip} | "
                    f"Evidence excerpts: {evidence_count}. "
                    "Conservative rules applied."
                )
            else:
                st.success(
                    f"Scoring complete. {total_candidates} source candidate(s) generated. "
                    "Enable 'Fetch discovered public pages' to retrieve and classify content."
                )
        except Exception as exc:
            _error(str(exc))

# 3. Save & Export
if col_c.button("3️⃣ Save to Database & Export Excel"):
    if not st.session_state.vendors:
        _error("Nothing to save yet.")
    elif db is None or export is None:
        _error("Database or export module is unavailable.")
    else:
        try:
            connection = db.connect(db_path)
            for vendor in st.session_state.vendors:
                vendor_id = db.upsert_vendor(connection, vendor)
                vendor_sources = [
                    item for item in st.session_state.sources if item.vendor_name == vendor.name
                ]
                db.save_sources(connection, vendor_id, vendor_sources)
                vendor_urls = {item.url for item in vendor_sources}
                vendor_evidence = [
                    item
                    for item in st.session_state.evidence
                    if item.vendor_name == vendor.name or item.source_url in vendor_urls
                ]
                db.save_evidence(connection, vendor_id, vendor_evidence)
                crit = next(
                    (c for c in st.session_state.criticality if c.vendor_name == vendor.name),
                    None,
                )
                risk_row = next(
                    (r for r in st.session_state.risks if r.vendor_name == vendor.name),
                    None,
                )
                if risk_row is not None:
                    db.save_assessment(
                        connection, vendor_id=vendor_id, criticality=crit, risk=risk_row
                    )
            connection.close()

            if st.session_state.workbook_mode == "meridian":
                if excel_handler is None or meridian_export is None or st.session_state.meridian_bundle is None:
                    raise RuntimeError("Meridian template export modules are unavailable.")
                updates = meridian_export.build_meridian_updates(
                    st.session_state.meridian_bundle,
                    vendors=st.session_state.vendors,
                    criticality=st.session_state.criticality,
                    sources=st.session_state.sources,
                    evidence=st.session_state.evidence,
                    risks=st.session_state.risks,
                    fetched_documents=st.session_state.documents,
                )
                excel_handler.export_inventory(
                    st.session_state.meridian_bundle,
                    export_path,
                    updates=updates,
                )
                export_description = "updated copy of the original Meridian template"
            else:
                export.export_workbook(
                    export_path,
                    vendors=st.session_state.vendors,
                    criticality=st.session_state.criticality,
                    sources=st.session_state.sources,
                    evidence=st.session_state.evidence,
                    risks=st.session_state.risks,
                )
                export_description = "generic assessment workbook"

            st.session_state.last_error = None
            st.success(f"Persisted to SQLite and exported {export_description} to: {export_path}")
        except Exception as exc:
            _error(str(exc))

# Tabs for detailed inspection and workflow
tabs = st.tabs([
    "📋 Overview",
    "🏢 Vendors",
    "⚖️ Criticality",
    "🌐 Sources",
    "🔍 Evidence & Manual Entry",
    "⚠️ Risk Assessment",
    "📁 Vendor Dossier",
    "📤 Export Review",
])

with tabs[0]:  # Overview
    st.subheader("Assessment Dashboard")
    st.write("Summary of loaded vendor inventory and current assessment progress.")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Vendors", len(st.session_state.vendors))
    with c2:
        crit_done = len(st.session_state.criticality)
        st.metric("Criticality Scored", f"{crit_done}/{len(st.session_state.vendors)}")
    with c3:
        st.metric("Evidence Snippets", len(st.session_state.evidence))
    with c4:
        assessed_risks = sum(1 for r in st.session_state.risks if r.status != "not_assessed")
        st.metric("Risk Evaluations", f"{assessed_risks}/{len(st.session_state.vendors)}")

    if not fetch_pages:
        st.info("ℹ️ Note: Live webpage fetching is currently disabled. Public-source candidates remain unexamined unless explicitly fetched or entered manually.")

with tabs[1]:  # Vendors
    st.subheader("Vendor Inventory")
    if st.session_state.vendors:
        st.dataframe(_rows(st.session_state.vendors), use_container_width=True)
    else:
        st.info("Upload an intake workbook or click 'Load Case Study' above.")

with tabs[2]:  # Criticality
    st.subheader("Vendor Criticality Scoring")
    st.caption("Criticality reflects organizational dependency and data sensitivity to Meridian, independent of AI usage.")
    if st.session_state.criticality:
        st.dataframe(_rows(st.session_state.criticality), use_container_width=True)
    else:
        st.info("Run analysis to compute intake-based criticality scores.")

with tabs[3]:  # Sources
    st.subheader("Public Source Candidates")
    st.caption("Hypothesized documentation, privacy, and trust pages. Candidates are leads, not verified findings.")
    if st.session_state.sources:
        st.dataframe(_rows(st.session_state.sources), use_container_width=True)
    else:
        st.info("No source candidates generated yet.")

with tabs[4]:  # Evidence & Manual Entry
    st.subheader("Evidence Register & Manual Review")
    st.caption("Preserves exact excerpts, source citations, timestamps, and classification rationales.")

    if st.session_state.vendors:
        with st.expander("✍️ Add Manual Evidence Finding", expanded=False):
            e_col1, e_col2 = st.columns([1, 2])
            with e_col1:
                v_names = [v.name for v in st.session_state.vendors]
                selected_v = st.selectbox("Vendor", v_names, key="manual_v")
                custom_url = st.text_input("Source URL or Citation", value="https://example.com/disclosure")
                custom_status = st.selectbox("Verification Status", ["verified", "unverified", "manual_entry"])
            with e_col2:
                custom_text = st.text_area("Exact Source Excerpt (quote verbatim from source)", height=100)
                reviewer_notes = st.text_input("Reviewer Notes / Context")

            if st.button("Classify & Record Evidence"):
                if not custom_text.strip():
                    st.warning("Please provide excerpt text.")
                elif classify is not None:
                    new_items = classify.classify_text(
                        custom_text,
                        source_url=custom_url,
                        source_title="Analyst Manual Entry",
                        vendor_name=selected_v,
                    )
                    if new_items:
                        for item in new_items:
                            item.verification_status = custom_status
                            item.reviewer_notes = reviewer_notes
                        st.session_state.evidence.extend(new_items)
                        from src.models import SourceCandidate
                        if not any(s.url == custom_url for s in st.session_state.sources):
                            st.session_state.sources.append(
                                SourceCandidate(
                                    url=custom_url,
                                    source_type="manual_entry",
                                    reason="Analyst-entered OSINT finding",
                                    vendor_name=selected_v,
                                    retrieved=True,
                                    retrieval_status="ok",
                                )
                            )
                        st.success(f"Recorded {len(new_items)} evidence item(s) for {selected_v}!")
                        st.rerun()
                    else:
                        st.info("No recognizable AI or security pattern found. The text was not classified into known categories.")

    if st.session_state.evidence:
        st.dataframe(_rows(st.session_state.evidence), use_container_width=True)
    else:
        st.info("No evidence collected yet.")

with tabs[5]:  # Risk Assessment
    st.subheader("Conservative Preliminary AI Risk Assessment")
    st.caption("AI-specific risk is rated only when relevant evidence is present. Missing evidence results in an unrated state.")
    if st.session_state.risks:
        cols_m = st.columns(4)
        crit_count = sum(1 for r in st.session_state.risks if r.risk_level == "critical")
        high_count = sum(1 for r in st.session_state.risks if r.risk_level == "high")
        med_count = sum(1 for r in st.session_state.risks if r.risk_level == "medium")
        unrated_count = sum(1 for r in st.session_state.risks if r.risk_level in ("not_rated", "low"))
        cols_m[0].metric("Critical Risk", crit_count)
        cols_m[1].metric("High Risk", high_count)
        cols_m[2].metric("Medium Risk", med_count)
        cols_m[3].metric("Unrated / Low", unrated_count)
        st.dataframe(_rows(st.session_state.risks), use_container_width=True)
    else:
        st.info("Run analysis to evaluate vendor risk.")

with tabs[6]:  # Vendor Dossier
    st.subheader("Vendor Evidence Dossier")
    st.caption("Detailed view of evidence provenance and assessment findings per vendor.")
    if st.session_state.vendors:
        selected_vendor = st.selectbox("Select Vendor for Detailed Dossier", [v.name for v in st.session_state.vendors])
        v_obj = next((v for v in st.session_state.vendors if v.name == selected_vendor), None)
        c_obj = next((c for c in st.session_state.criticality if c.vendor_name == selected_vendor), None)
        r_obj = next((r for r in st.session_state.risks if r.vendor_name == selected_vendor), None)
        v_sources = [s for s in st.session_state.sources if s.vendor_name == selected_vendor]
        v_evidence = [e for e in st.session_state.evidence if e.vendor_name == selected_vendor or any(s.url == e.source_url for s in v_sources)]

        if v_obj:
            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.markdown(f"**Vendor ID:** `{v_obj.vendor_id or 'N/A'}`")
                st.markdown(f"**Product/Service:** `{v_obj.product or 'N/A'}`")
                st.markdown(f"**Website:** `{v_obj.website or 'N/A'}`")
            with d_col2:
                if c_obj:
                    st.markdown(f"**Criticality Tier:** `{c_obj.level.title()}` ({c_obj.score:.1f}/100)")
                if r_obj:
                    st.markdown(f"**AI Risk Level:** `{r_obj.risk_level.title()}` | **Status:** `{r_obj.status}`")

            st.markdown("#### Evidence Items")
            if v_evidence:
                for idx, ev in enumerate(v_evidence, 1):
                    st.markdown(f"**{idx}. [{ev.category}]** (Score: {ev.heuristic_score})")
                    st.markdown(f"> *\"{ev.snippet}\"*")
                    st.caption(f"Source: {ev.source_url} | Status: {ev.verification_status} | Note: {ev.rationale}")
            else:
                st.info("No evidence recorded for this vendor.")

            if r_obj and r_obj.evidence_gaps:
                st.markdown("#### Evidence Gaps & Questions")
                for gap in r_obj.evidence_gaps:
                    st.markdown(f"- ❓ {gap}")
    else:
        st.info("Load vendors to view dossiers.")

with tabs[7]:  # Export Review
    st.subheader("Excel Assessment Export Review")
    st.caption("Review the exported workbook and verify protected content preservation.")
    p = Path(export_path)
    if p.exists():
        st.success(f"Export file is present on disk: `{p.resolve()}` ({p.stat().st_size} bytes)")
    else:
        st.info("Click '3️⃣ Save to Database & Export Excel' to generate the assessment output.")
