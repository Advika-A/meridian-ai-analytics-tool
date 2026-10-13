#!/usr/bin/env python3
"""
Live public-source smoke test for the six Meridian vendors.

This script executes real-world public source discovery, retrieval, text extraction,
and rule-based classification against the six real vendors loaded from the
Meridian intake workbook.

It is NOT part of the automated unit test suite. Run this with network connectivity
to verify live public-web behavior and generate machine-readable provenance reports.

Usage:
    python smoke_test_live.py [--timeout SECONDS] [--output JSON_FILE]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from src.classify import classify_text
from src.excel_handler import get_real_vendors_and_student_columns, load_meridian_workbook, to_vendor_record
from src.extract import extract_url
from src.osint import discover_links_from_html, discover_sources
from src.risk import analyse_risk
from src.scoring import score_vendor

WORKBOOK_PATH = _ROOT / "supporting material" / "Meridian_Vendor_Input.xlsx"
DEFAULT_TIMEOUT = 15
SKIP_TYPES = {"search_lead", "search_query"}


def _banner(text: str, width: int = 76) -> None:
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width)


def _section(text: str) -> None:
    print(f"\n--- {text} ---")


def run_smoke_test(timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run the live retrieval smoke test and return a structured report."""
    run_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _banner("Meridian AI Assessment — Live Public-Source Smoke Test")
    print(f"Run started: {run_at}")
    print(f"Fetch timeout per URL: {timeout}s")
    print(f"Workbook: {WORKBOOK_PATH}")

    if not WORKBOOK_PATH.exists():
        print(f"\nERROR: Workbook not found at {WORKBOOK_PATH}")
        sys.exit(1)

    bundle = load_meridian_workbook(WORKBOOK_PATH)
    real_records, _ = get_real_vendors_and_student_columns(bundle)
    vendors = [to_vendor_record(r) for r in real_records]
    print(f"Loaded {len(vendors)} real vendor(s) (fictional example V-000 excluded).")

    report: dict = {
        "run_at": run_at,
        "workbook": str(WORKBOOK_PATH),
        "timeout_seconds": timeout,
        "vendors_count": len(vendors),
        "vendors": [],
    }

    total_candidates_all = 0
    total_successful_non_empty_all = 0
    total_failed_all = 0
    total_soft_404_all = 0
    total_js_or_empty_all = 0
    total_evidence_all = 0

    for vendor in vendors:
        _banner(f"Vendor: {vendor.name} ({vendor.vendor_id})")
        print(f"  Product/Service: {vendor.product}")
        print(f"  Website: {vendor.website}")

        crit = score_vendor(vendor)

        # 1. Discover initial candidate sources
        candidates = discover_sources(vendor)
        fetchable = [c for c in candidates if c.source_type not in SKIP_TYPES]
        search_leads = [c for c in candidates if c.source_type in SKIP_TYPES]

        print(f"\n  Candidate sources discovered: {len(candidates)} total")
        print(f"    Fetchable pages:  {len(fetchable)}")
        print(f"    Search leads:     {len(search_leads)} (manual review only; not fetched)")

        urls_attempted = []
        successful_non_empty = []
        soft_404_pages = []
        empty_or_js_pages = []
        failed_pages = []
        vendor_evidence = []

        # 2. Retrieve pages and extract content
        _section("Retrieving pages")
        homepage_html_content = ""

        for candidate in fetchable:
            t0 = time.monotonic()
            doc = extract_url(candidate.url, timeout=timeout)
            elapsed = round(time.monotonic() - t0, 1)

            # Store homepage HTML if this was the root website
            if candidate.discovery_method == "official_intake" and doc.status == "ok":
                homepage_html_content = doc.text

            attempt_record = {
                "url": candidate.url,
                "final_url": doc.final_url or candidate.url,
                "discovery_method": candidate.discovery_method,
                "source_relevance": candidate.source_relevance,
                "http_status": doc.http_status,
                "extraction_status": doc.status,
                "failure_reason": doc.error,
                "title": doc.title,
                "content_length_chars": len(doc.text) if doc.status == "ok" else 0,
                "retrieved_at": doc.retrieved_at,
                "elapsed_seconds": elapsed,
            }
            urls_attempted.append(attempt_record)

            status_icon = {
                "ok": "[OK]",
                "soft_404": "[SOFT-404]",
                "empty_js_rendered": "[JS-RENDERED]",
                "empty": "[EMPTY]",
                "failed": "[FAIL]",
                "skipped": "[SKIP]",
            }.get(doc.status, f"[{doc.status.upper()}]")

            print(f"  {status_icon} [{doc.status}] {candidate.url} ({elapsed}s)")
            if doc.status == "ok":
                print(f"       Title: {doc.title!r} | Extracted: {len(doc.text)} chars")
                successful_non_empty.append(candidate.url)

                # Classify document with service context
                doc_items = classify_text(
                    doc.text,
                    source_url=doc.final_url or candidate.url,
                    source_title=doc.title or "",
                    retrieved_at=doc.retrieved_at,
                    vendor_name=vendor.name,
                    service_context=vendor.product or "",
                )
                vendor_evidence.extend(doc_items)
            elif doc.status == "soft_404":
                soft_404_pages.append(candidate.url)
                print(f"       Soft 404: {doc.error}")
            elif doc.status in ("empty_js_rendered", "empty"):
                empty_or_js_pages.append(candidate.url)
                print(f"       Empty/JS: {doc.error}")
            elif doc.status == "failed":
                failed_pages.append(candidate.url)
                print(f"       Failed: {doc.error}")

        # 3. Analyze Risk & Gaps
        risk_res = analyse_risk(
            vendor_name=vendor.name,
            criticality=crit,
            evidence=vendor_evidence,
        )

        _section("Analysis & Evidence Summary")
        print(f"  Criticality Tier:    {crit.level.title()} ({crit.score:.1f}/100)")
        print(f"  Assessment State:    {risk_res.status}")
        print(f"  AI Risk Level:       {risk_res.risk_level.title()}")
        print(f"  Evidence Excerpts:   {len(vendor_evidence)}")
        print(f"  Successful Pages:    {len(successful_non_empty)}")
        print(f"  Failed Pages:        {len(failed_pages)}")
        print(f"  Empty / JS Pages:    {len(empty_or_js_pages)}")
        print(f"  Soft 404 Pages:      {len(soft_404_pages)}")

        if vendor_evidence:
            for ev in vendor_evidence[:4]:
                print(f"    - [{ev.category} | {ev.relevance}] {ev.snippet[:130]!r}")
                print(f"      Source: {ev.source_url} (Verification: {ev.verification_status})")

        if risk_res.evidence_gaps:
            print("  Evidence Gaps:")
            for gap in risk_res.evidence_gaps:
                print(f"    - [GAP] {gap}")

        vendor_report = {
            "name": vendor.name,
            "vendor_id": vendor.vendor_id,
            "product": vendor.product,
            "website": vendor.website,
            "criticality": {
                "score": crit.score,
                "level": crit.level,
            },
            "candidate_count": len(candidates),
            "fetchable_count": len(fetchable),
            "search_lead_count": len(search_leads),
            "urls_attempted": urls_attempted,
            "successful_non_empty_pages": {
                "count": len(successful_non_empty),
                "urls": successful_non_empty,
            },
            "empty_or_js_rendered_pages": {
                "count": len(empty_or_js_pages),
                "urls": empty_or_js_pages,
            },
            "soft_404_pages": {
                "count": len(soft_404_pages),
                "urls": soft_404_pages,
            },
            "failed_pages": {
                "count": len(failed_pages),
                "urls": failed_pages,
            },
            "evidence_excerpts": [
                {
                    "evidence_id": e.evidence_id,
                    "category": e.category,
                    "relevance": e.relevance,
                    "verification_status": e.verification_status,
                    "heuristic_score": e.heuristic_score,
                    "snippet": e.snippet,
                    "source_url": e.source_url,
                    "matched_terms": e.matched_terms,
                    "rationale": e.rationale,
                }
                for e in vendor_evidence
            ],
            "assessment": {
                "status": risk_res.status,
                "risk_level": risk_res.risk_level,
                "risk_score": risk_res.risk_score,
                "drivers": risk_res.drivers,
                "caveats": risk_res.caveats,
            },
            "unresolved_research_gaps": risk_res.evidence_gaps,
        }
        report["vendors"].append(vendor_report)

        total_candidates_all += len(candidates)
        total_successful_non_empty_all += len(successful_non_empty)
        total_failed_all += len(failed_pages)
        total_soft_404_all += len(soft_404_pages)
        total_js_or_empty_all += len(empty_or_js_pages)
        total_evidence_all += len(vendor_evidence)

    # Global summary
    _banner("Overall Smoke Test Results")
    print(f"Total Vendors Evaluated:             {len(vendors)}")
    print(f"Total Candidates Generated:          {total_candidates_all}")
    print(f"Successful Non-Empty Pages:          {total_successful_non_empty_all}")
    print(f"Failed / Unreachable Pages:          {total_failed_all}")
    print(f"Soft 404 Error Pages:                {total_soft_404_all}")
    print(f"Empty or JavaScript-Rendered Pages:  {total_js_or_empty_all}")
    print(f"Evidence Excerpts Extracted:         {total_evidence_all}")

    report["totals"] = {
        "candidate_count": total_candidates_all,
        "successful_non_empty_pages": total_successful_non_empty_all,
        "failed_pages": total_failed_all,
        "soft_404_pages": total_soft_404_all,
        "empty_or_js_rendered_pages": total_js_or_empty_all,
        "evidence_excerpts_count": total_evidence_all,
    }

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Live public-source smoke test for Meridian vendors.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Fetch timeout in seconds")
    parser.add_argument("--output", type=str, default="smoke_test_report.json", help="Path to write JSON report")
    args = parser.parse_args()

    report = run_smoke_test(timeout=args.timeout)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nMachine-readable JSON report written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
