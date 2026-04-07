"""Specialized extractor for IEC 81001-5-1 (Health software security).

IEC 81001-5-1:2021 — Health software and health IT systems safety,
effectiveness and security. Part 5-1: Security — Activities in the
product life cycle.

Structure:
  Clause 4: General requirements (4.1.1-4.1.9, 4.2, 4.3)
  Clause 5: Software development process (5.1-5.8, ~30 sub-clauses)
  Clause 6: Software maintenance process (6.1-6.3)
  Clause 7: Security risk management process (7.1-7.5)
  Clause 8: Software configuration management process
  Clause 9: Software problem resolution process (9.1-9.5)
"""

import io
import logging
import re
import time
from typing import List, Tuple

from security_controls_mcp.extractors.base import (
    BaseExtractor,
    Control,
    ExtractionResult,
    VersionDetection,
)
from security_controls_mcp.extractors.registry import register_extractor

logger = logging.getLogger(__name__)

VERSION_DETECTION_MAX_PAGES = 5
MIN_TITLE_LENGTH = 3
MIN_CONTENT_LENGTH = 3

# Main clauses and their categories
CLAUSE_CATEGORIES = {
    "4": "General Requirements",
    "5": "Software Development Process",
    "6": "Software Maintenance Process",
    "7": "Security Risk Management",
    "8": "Configuration Management",
    "9": "Problem Resolution",
}

# Expected sub-clauses per main clause (for confidence calculation)
EXPECTED_SUBCLAUSES = {
    "4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5", "4.1.6", "4.1.7",
    "4.1.8", "4.1.9", "4.2", "4.3",
    "5.1.1", "5.1.2", "5.1.3",
    "5.2.1", "5.2.2", "5.2.3",
    "5.3.1", "5.3.2", "5.3.3",
    "5.4.1", "5.4.2", "5.4.3", "5.4.4",
    "5.5.1", "5.5.2",
    "5.6",
    "5.7.1", "5.7.2", "5.7.3", "5.7.4", "5.7.5",
    "5.8.1", "5.8.2", "5.8.3", "5.8.4", "5.8.5", "5.8.6", "5.8.7",
    "6.1.1",
    "6.2.1", "6.2.2",
    "6.3.1", "6.3.2", "6.3.3",
    "7.1.1", "7.1.2", "7.2", "7.3", "7.4", "7.5",
    "8",
    "9.1", "9.2", "9.3", "9.4", "9.5",
}


@register_extractor("iec_81001_5_1")
class IEC81001Extractor(BaseExtractor):
    """Specialized extractor for IEC 81001-5-1 (Health software security)."""

    def _detect_version(
        self, pdf_bytes: bytes
    ) -> Tuple[str, VersionDetection, List[str]]:
        evidence: List[str] = []
        text = ""

        try:
            import pdfplumber

            with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
                max_pages = min(VERSION_DETECTION_MAX_PAGES, len(pdf.pages))
                for page in pdf.pages[:max_pages]:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text
        except Exception as e:
            logger.debug("Error during PDF parsing: %s", e)

        if not text:
            try:
                text = pdf_bytes.decode("utf-8", errors="ignore")
            except Exception:
                return ("unknown", VersionDetection.UNKNOWN, evidence)

        if re.search(r"81001-5-1:2021", text):
            evidence.append("Found '81001-5-1:2021' text")
            return ("2021", VersionDetection.DETECTED, evidence)

        if re.search(r"81001-5-1:2022", text):
            evidence.append("Found '81001-5-1:2022' text")
            return ("2022", VersionDetection.DETECTED, evidence)

        if re.search(r"IEC\s+81001-5-1", text, re.IGNORECASE):
            evidence.append("Found IEC 81001-5-1 identifier")
            if re.search(r"2021", text):
                evidence.append("Found '2021' year")
                return ("2021", VersionDetection.DETECTED, evidence)
            if re.search(r"2022", text):
                evidence.append("Found '2022' year")
                return ("2022", VersionDetection.DETECTED, evidence)
            return ("2021", VersionDetection.AMBIGUOUS, evidence)

        if re.search(
            r"[Hh]ealth\s+software.*[Ss]ecurity|[Ss]afety.*effectiveness.*security",
            text,
        ):
            evidence.append("Found health software security keywords")
            return ("2021", VersionDetection.AMBIGUOUS, evidence)

        return ("unknown", VersionDetection.UNKNOWN, evidence)

    def _extract_full_text(self, pdf_bytes: bytes) -> str:
        """Extract all text from PDF, concatenated with page breaks."""
        try:
            import pdfplumber
        except ImportError:
            return pdf_bytes.decode("utf-8", errors="ignore")

        pages: List[str] = []
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    pages.append(page_text)
        return "\n\n".join(pages)

    def _extract_clauses_with_body(self, full_text: str) -> List[Control]:
        """Extract clauses with body text captured between consecutive headings."""
        # IEC 81001-5-1 clause format: X.Y.Z Title
        heading_re = re.compile(
            r"^(\d+(?:\.\d+){0,3})\s+([A-Z][A-Za-z\s,\-\(\)/]+?)$",
            re.MULTILINE,
        )
        headings = list(heading_re.finditer(full_text))
        if not headings:
            return []

        controls: List[Control] = []
        for i, match in enumerate(headings):
            clause_id = match.group(1)
            title = match.group(2).strip()

            if len(title) < MIN_TITLE_LENGTH:
                continue

            main_clause = clause_id.split(".")[0]
            if main_clause not in CLAUSE_CATEGORIES:
                continue

            # Body text: from end of this heading to start of next heading
            body_start = match.end()
            body_end = headings[i + 1].start() if i + 1 < len(headings) else len(full_text)
            body = full_text[body_start:body_end].strip()
            # Clean up artifacts
            body = re.sub(r"\n{3,}", "\n\n", body)
            body = re.sub(r"(?m)^–\s*\d+\s*–$", "", body)
            body = body.strip()

            category = CLAUSE_CATEGORIES.get(main_clause, "General")
            parent = None
            parts = clause_id.split(".")
            if len(parts) > 1:
                parent = ".".join(parts[:-1])

            content = f"{title}\n\n{body}" if body else title

            if len(content) >= MIN_CONTENT_LENGTH:
                controls.append(
                    Control(
                        id=clause_id,
                        title=title,
                        content=content,
                        page=0,
                        category=category,
                        parent=parent,
                    )
                )

        return controls

    def extract(self, pdf_bytes: bytes) -> ExtractionResult:
        start_time = time.time()
        warnings: List[str] = []

        version, detection, evidence = self._detect_version(pdf_bytes)
        if version == "unknown":
            warnings.append("Could not detect IEC 81001-5-1 version")

        full_text = self._extract_full_text(pdf_bytes)
        controls = self._extract_clauses_with_body(full_text)

        # Quality check: flag heading-only extractions
        heading_only = sum(1 for c in controls if c.content.strip() == c.title.strip())
        if heading_only > len(controls) * 0.5 and controls:
            warnings.append(
                f"{heading_only}/{len(controls)} clauses have heading-only content; "
                "body text extraction may have failed"
            )

        # Confidence calculation
        extracted_ids = {c.id for c in controls}
        extracted_count = len(controls)
        confidence_score = 0.0

        if detection == VersionDetection.DETECTED:
            confidence_score += 0.3
        elif detection == VersionDetection.AMBIGUOUS:
            confidence_score += 0.15

        # Coverage of expected sub-clauses
        matched = EXPECTED_SUBCLAUSES & extracted_ids
        coverage_ratio = len(matched) / len(EXPECTED_SUBCLAUSES) if EXPECTED_SUBCLAUSES else 0
        confidence_score += 0.7 * min(coverage_ratio * 1.2, 1.0)

        # Check main clause coverage
        extracted_main = {c.id.split(".")[0] for c in controls}
        expected_main = set(CLAUSE_CATEGORIES.keys())
        missing_main = expected_main - extracted_main
        if missing_main:
            warnings.append(
                f"Missing main clauses: {', '.join(sorted(missing_main))} "
                f"(extracted {len(extracted_main)} of {len(expected_main)})"
            )

        if extracted_count < 20:
            warnings.append(
                f"Sparse extraction: only {extracted_count} clauses "
                f"(expected at least 20)"
            )

        duration = time.time() - start_time

        return ExtractionResult(
            standard_id="iec_81001_5_1",
            version=version,
            version_detection=detection,
            version_evidence=evidence,
            controls=controls,
            expected_control_ids=None,
            missing_control_ids=None,
            confidence_score=confidence_score,
            extraction_method="specialized",
            extraction_duration_seconds=duration,
            warnings=warnings,
        )
