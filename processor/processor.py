"""
EpsteinAnalyzer - Document Processing Pipeline
================================================
OCR, classification, redaction forensics, email chain stitching,
entity extraction, and priority scoring.

Usage:
    python -m processor.processor --dataset 1
    python -m processor.processor --document path/to/file.pdf
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import fitz  # PyMuPDF
import pytesseract
import yaml

# Set Tesseract path explicitly on Windows
if sys.platform == "win32":
    _tess_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.isfile(_tess_path):
        pytesseract.pytesseract.tesseract_cmd = _tess_path
from PIL import Image, ExifTags

try:
    import spacy
    _SPACY_AVAILABLE = True
except ImportError:
    _SPACY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.db import DatabaseManager

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("processor")

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"


def _load_config(path: Path = _CONFIG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# High-value keyword lists used by multiple classes
# ---------------------------------------------------------------------------
HIGH_VALUE_NAMES: List[str] = [
    "epstein", "maxwell", "ghislaine", "jean-luc brunel", "brunel",
    "les wexner", "wexner", "alan dershowitz", "dershowitz",
    "prince andrew", "duke of york", "bill clinton", "donald trump",
    "bill gates", "leon black", "jes staley", "glenn dubin",
    "eva dubin", "nadia marcinkova", "sarah kellen", "lesley groff",
    "jean-luc", "giuffre", "virginia roberts", "courtney wild",
    "little st. james", "little saint james", "zorro ranch",
    "lolita express", "gulfstream", "boeing 727",
]

ISLAND_AND_PROPERTY_KEYWORDS: List[str] = [
    "little st. james", "little saint james", "great st. james",
    "zorro ranch", "new mexico", "71st street", "9 east 71st",
    "el brillo way", "palm beach", "avenue foch", "paris apartment",
    "les wexner compound", "upper east side",
]

# Known codewords and euphemisms flagged for priority review.
# Sources: court filings, investigative journalism, FBI FOIA releases.
CODEWORD_TERMS: List[str] = [
    # Food-related codewords
    "pizza", "hot dog", "hotdog", "pasta", "cheese pizza", "walnut sauce",
    "ice cream", "jerky", "grape soda", "sauce",
    # Common euphemisms from case documents
    "massage", "masseuse", "modeling", "talent scout", "recruiting",
    "young model", "young woman", "young girl", "minor", "underage",
    "schoolgirl", "high school", "middle school",
    # Activity codewords
    "party favor", "party favors", "special guest", "entertainment",
    "arrangement", "appointment", "session", "package",
    # Location/travel euphemisms
    "the island", "the ranch", "down south", "overseas trip",
    "private flight", "charter", "guest list",
]

# Pre-compiled regex for codeword matching (word-boundary aware)
CODEWORD_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b" + re.escape(term) + r"\b", re.I) for term in CODEWORD_TERMS
]

FINANCIAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\$[\d,]+(?:\.\d{2})?", re.I),
    re.compile(r"(?:usd|eur|gbp)\s*[\d,]+(?:\.\d{2})?", re.I),
    re.compile(r"wire\s*transfer", re.I),
    re.compile(r"account\s*(?:no\.?|number|#)\s*[\w\-]+", re.I),
    re.compile(r"routing\s*(?:no\.?|number|#)\s*\d+", re.I),
    re.compile(r"bank\s+(?:of\s+)?[A-Z][\w\s]+", re.I),
    re.compile(r"trust\s+(?:fund|account|agreement)", re.I),
    re.compile(r"foundation\s+(?:fund|grant|donation)", re.I),
    re.compile(r"invoice\s*(?:no\.?|number|#)?\s*[\w\-]+", re.I),
]

CASE_REF_PATTERN = re.compile(
    r"(?:No\.|Case|Docket|Cause)\s*(?:No\.?\s*)?(\d{1,4}[\-:](?:cv|cr|mc|mj|po)[\-:]\d{3,10}(?:[\-:]\w+)?)",
    re.I,
)

FLIGHT_TAIL_PATTERN = re.compile(r"\bN\d{1,5}[A-Z]{0,2}\b")

PHONE_PATTERN = re.compile(
    r"(?:\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}"
)

EMAIL_ADDR_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

ADDRESS_PATTERN = re.compile(
    r"\d{1,5}\s+(?:[A-Z][a-z]+\s?){1,4}"
    r"(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Drive|Dr\.?|"
    r"Road|Rd\.?|Lane|Ln\.?|Way|Court|Ct\.?|Place|Pl\.?|Circle|Cir\.?)"
    r"(?:\s*,?\s*(?:Suite|Ste\.?|Apt\.?|Unit|#)\s*\w+)?",
    re.I,
)

DOLLAR_AMOUNT_PATTERN = re.compile(r"\$[\d,]+(?:\.\d{2})?")

ACCOUNT_NUMBER_PATTERN = re.compile(
    r"(?:account|acct)[\s#:]*(\d[\d\-]{4,})", re.I
)


# ============================================================================
# 1. OCR ENGINE
# ============================================================================
class OCREngine:
    """Extract text from PDFs using direct extraction + Tesseract fallback."""

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.cfg = config.get("processor", {}).get("ocr", {})
        self.languages = self.cfg.get("languages", ["eng"])
        self.dpi = self.cfg.get("dpi", 300)
        self.preprocessing = self.cfg.get("preprocessing", True)

    # ------------------------------------------------------------------
    def process_pdf(
        self,
        file_path: str,
        document_id: int,
        progress_cb: Optional[Callable] = None,
    ) -> List[Dict[str, Any]]:
        """Process every page of *file_path*, return list of page dicts."""
        file_path = str(file_path)
        results: List[Dict[str, Any]] = []

        try:
            doc = fitz.open(file_path)
        except Exception as exc:
            log.error("Failed to open PDF %s: %s", file_path, exc)
            return results

        total_pages = len(doc)
        log.info("OCR: processing %d pages from %s", total_pages, file_path)

        conn = self.db.get_connection()
        try:
            for page_idx in range(total_pages):
                page = doc[page_idx]
                page_num = page_idx + 1

                # --- attempt direct text extraction first ---
                native_text = page.get_text("text").strip()
                ocr_confidence = 1.0  # native text is high-confidence

                if len(native_text) > 30:
                    text = native_text
                    method = "native"
                else:
                    # --- fall back to OCR ---
                    text, ocr_confidence = self._ocr_page(page)
                    method = "tesseract"

                # --- detect embedded images ---
                image_list = page.get_images(full=True)
                has_images = len(image_list) > 0

                # --- detect redaction rectangles ---
                redaction_rects = self._detect_redaction_rects(page)
                has_redactions = len(redaction_rects) > 0

                page_data = {
                    "document_id": document_id,
                    "page_number": page_num,
                    "text_content": text,
                    "ocr_confidence": round(ocr_confidence, 4),
                    "has_redactions": has_redactions,
                    "redaction_count": len(redaction_rects),
                    "method": method,
                    "image_count": len(image_list),
                    "redaction_rects": redaction_rects,
                }
                results.append(page_data)

                # --- save to database ---
                conn.execute(
                    """INSERT OR REPLACE INTO document_pages
                       (document_id, page_number, text_content,
                        ocr_confidence, has_redactions, redaction_count)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        document_id,
                        page_num,
                        text,
                        round(ocr_confidence, 4),
                        int(has_redactions),
                        len(redaction_rects),
                    ),
                )

                if progress_cb:
                    progress_cb("ocr", page_num, total_pages)

            conn.commit()

            # mark document OCR complete
            conn.execute(
                "UPDATE documents SET ocr_completed = 1, page_count = ?, status = 'ocr_complete' WHERE id = ?",
                (total_pages, document_id),
            )
            conn.commit()
        finally:
            conn.close()
            doc.close()

        log.info("OCR complete: %d pages, doc_id=%d", total_pages, document_id)
        return results

    # ------------------------------------------------------------------
    def _ocr_page(self, page: fitz.Page) -> Tuple[str, float]:
        """Render page to image and run Tesseract OCR. Returns (text, confidence)."""
        mat = fitz.Matrix(self.dpi / 72, self.dpi / 72)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

        if self.preprocessing:
            img = img.convert("L")  # grayscale

        lang_str = "+".join(self.languages)

        try:
            tsv_data = pytesseract.image_to_data(
                img, lang=lang_str, output_type=pytesseract.Output.DICT
            )
        except Exception as exc:
            log.warning("Tesseract failed on page: %s", exc)
            return ("", 0.0)

        # build text and compute mean confidence of recognized words
        words = []
        confidences = []
        for i, conf in enumerate(tsv_data["conf"]):
            word = tsv_data["text"][i].strip()
            if word:
                words.append(word)
                try:
                    c = float(conf)
                    if c >= 0:
                        confidences.append(c)
                except (ValueError, TypeError):
                    pass

        text = " ".join(words)
        avg_conf = (sum(confidences) / len(confidences) / 100.0) if confidences else 0.0
        return (text, avg_conf)

    # ------------------------------------------------------------------
    @staticmethod
    def _detect_redaction_rects(page: fitz.Page) -> List[Dict[str, float]]:
        """Detect filled black/dark rectangles that likely represent redactions."""
        rects: List[Dict[str, float]] = []
        drawings = page.get_drawings()
        for d in drawings:
            fill = d.get("fill")
            if fill is None:
                continue
            # Black or very dark fill
            r, g, b = (fill[0] if len(fill) > 0 else 1,
                        fill[1] if len(fill) > 1 else 1,
                        fill[2] if len(fill) > 2 else 1)
            is_dark = (r + g + b) < 0.3
            # Also catch white-out redactions (all near 1.0)
            is_white = (r > 0.95 and g > 0.95 and b > 0.95)
            if not (is_dark or is_white):
                continue
            rect = d.get("rect")
            if rect is None:
                continue
            w = rect.width
            h = rect.height
            # Filter out tiny marks and full-page fills
            if w < 10 or h < 5:
                continue
            if w > page.rect.width * 0.98 and h > page.rect.height * 0.98:
                continue
            rects.append({
                "x": round(rect.x0, 2),
                "y": round(rect.y0, 2),
                "width": round(w, 2),
                "height": round(h, 2),
                "fill_type": "black" if is_dark else "white",
            })

        # Also check annotations for redaction-type annots
        for annot in page.annots() or []:
            if annot.type[0] == fitz.PDF_ANNOT_REDACT or annot.type[0] == fitz.PDF_ANNOT_SQUARE:
                r = annot.rect
                rects.append({
                    "x": round(r.x0, 2),
                    "y": round(r.y0, 2),
                    "width": round(r.width, 2),
                    "height": round(r.height, 2),
                    "fill_type": "annotation",
                })
        return rects


# ============================================================================
# 2. DOCUMENT CLASSIFIER
# ============================================================================
class DocumentClassifier:
    """Classify documents by type using structural + keyword analysis."""

    # Keyword sets for each document type
    _EMAIL_KEYWORDS = {"from:", "to:", "subject:", "date:", "sent:", "cc:", "bcc:"}
    _DEPOSITION_KEYWORDS = {
        "q.", "a.", "deposition", "testimony", "witness", "sworn",
        "direct examination", "cross examination", "redirect",
        "the witness", "court reporter", "do you swear",
    }
    _FLIGHT_LOG_KEYWORDS = {
        "tail number", "n-number", "departure", "arrival",
        "pilot", "passenger", "manifest", "flight log",
        "hobbs", "tach", "nautical",
    }
    _FINANCIAL_KEYWORDS = {
        "invoice", "wire transfer", "bank statement", "account",
        "balance", "transaction", "receipt", "payment", "deposit",
        "withdrawal", "routing number", "swift", "iban",
    }
    _COURT_FILING_KEYWORDS = {
        "united states district court", "plaintiff", "defendant",
        "motion", "order", "judgment", "complaint", "indictment",
        "arraignment", "in the matter of", "case no",
        "memorandum", "exhibit", "declaration", "affidavit",
    }
    _LETTER_KEYWORDS = {
        "dear ", "sincerely", "regards", "yours truly",
        "respectfully", "to whom it may concern", "enclosed",
    }
    _MEMO_KEYWORDS = {
        "memo", "memorandum", "internal", "confidential",
        "re:", "for your information", "action required",
    }

    # Email header regex
    _EMAIL_HEADER_RE = re.compile(
        r"(?:^|\n)\s*(?:From|To|Subject|Date|Sent|CC|BCC)\s*:\s*.+",
        re.I | re.M,
    )
    _FROM_RE = re.compile(r"(?:^|\n)\s*From\s*:\s*(.+)", re.I | re.M)
    _TO_RE = re.compile(r"(?:^|\n)\s*To\s*:\s*(.+)", re.I | re.M)
    _CC_RE = re.compile(r"(?:^|\n)\s*CC\s*:\s*(.+)", re.I | re.M)
    _SUBJECT_RE = re.compile(r"(?:^|\n)\s*Subject\s*:\s*(.+)", re.I | re.M)
    _DATE_RE = re.compile(
        r"(?:^|\n)\s*(?:Date|Sent)\s*:\s*(.+)", re.I | re.M
    )
    _QA_RE = re.compile(r"(?:^|\n)\s*[QA]\.\s+", re.M)

    def classify(
        self, text: str, metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Return {'doc_type': ..., 'confidence': ..., 'email_data': ...}."""
        if not text:
            return {"doc_type": "unknown", "confidence": 0.0}

        text_lower = text.lower()
        metadata = metadata or {}
        scores: Dict[str, float] = defaultdict(float)

        # --- structural checks ---

        # Email: count header lines
        email_headers = self._EMAIL_HEADER_RE.findall(text)
        if len(email_headers) >= 2:
            scores["email"] += 40
        if len(email_headers) >= 4:
            scores["email"] += 20

        # Deposition: Q&A pattern
        qa_matches = self._QA_RE.findall(text)
        if len(qa_matches) >= 5:
            scores["deposition"] += 50
        elif len(qa_matches) >= 2:
            scores["deposition"] += 25

        # --- keyword scoring ---
        for kw in self._EMAIL_KEYWORDS:
            if kw in text_lower:
                scores["email"] += 5
        for kw in self._DEPOSITION_KEYWORDS:
            if kw in text_lower:
                scores["deposition"] += 5
        for kw in self._FLIGHT_LOG_KEYWORDS:
            if kw in text_lower:
                scores["flight_log"] += 8
        for kw in self._FINANCIAL_KEYWORDS:
            if kw in text_lower:
                scores["financial"] += 5
        for kw in self._COURT_FILING_KEYWORDS:
            if kw in text_lower:
                scores["court_filing"] += 5
        for kw in self._LETTER_KEYWORDS:
            if kw in text_lower:
                scores["letter"] += 6
        for kw in self._MEMO_KEYWORDS:
            if kw in text_lower:
                scores["memo"] += 6

        # Flight tail numbers
        if FLIGHT_TAIL_PATTERN.search(text):
            scores["flight_log"] += 15

        # Filename hints
        fname = metadata.get("filename", "").lower()
        if "email" in fname or "mail" in fname:
            scores["email"] += 10
        if "depo" in fname:
            scores["deposition"] += 10
        if "flight" in fname or "log" in fname or "manifest" in fname:
            scores["flight_log"] += 10
        if "invoice" in fname or "bank" in fname or "financial" in fname:
            scores["financial"] += 10
        if "motion" in fname or "order" in fname or "filing" in fname:
            scores["court_filing"] += 10

        if not scores:
            return {"doc_type": "unknown", "confidence": 0.0}

        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
        confidence = min(best_score / 80.0, 1.0)

        result: Dict[str, Any] = {
            "doc_type": best_type,
            "confidence": round(confidence, 3),
            "all_scores": dict(scores),
        }

        if best_type == "email":
            result["email_data"] = self._extract_email_fields(text)

        return result

    # ------------------------------------------------------------------
    def _extract_email_fields(self, text: str) -> Dict[str, Any]:
        """Pull structured fields from email text."""
        def _first_match(pattern, txt):
            m = pattern.search(txt)
            return m.group(1).strip() if m else None

        from_field = _first_match(self._FROM_RE, text)
        to_field = _first_match(self._TO_RE, text)
        cc_field = _first_match(self._CC_RE, text)
        subject = _first_match(self._SUBJECT_RE, text)
        date_field = _first_match(self._DATE_RE, text)

        # Split To / CC into lists
        to_list = [a.strip() for a in to_field.split(";") if a.strip()] if to_field else []
        if not to_list and to_field:
            to_list = [a.strip() for a in to_field.split(",") if a.strip()]

        cc_list = [a.strip() for a in cc_field.split(";") if a.strip()] if cc_field else []
        if not cc_list and cc_field:
            cc_list = [a.strip() for a in cc_field.split(",") if a.strip()]

        # Extract body (everything after headers)
        body = text
        header_end = 0
        for pattern in (self._DATE_RE, self._SUBJECT_RE, self._CC_RE, self._TO_RE, self._FROM_RE):
            m = pattern.search(text)
            if m:
                end_pos = m.end()
                if end_pos > header_end:
                    header_end = end_pos
        if header_end > 0:
            body = text[header_end:].strip()

        # Parse from_field into name + address
        from_name = from_field
        from_address = None
        if from_field:
            email_match = EMAIL_ADDR_PATTERN.search(from_field)
            if email_match:
                from_address = email_match.group(0)
                from_name = from_field.replace(from_address, "").strip(" <>\t\"'")

        return {
            "from_name": from_name,
            "from_address": from_address,
            "to": to_list,
            "cc": cc_list,
            "subject": subject,
            "date": date_field,
            "body": body,
        }


# ============================================================================
# 3. REDACTION FORENSICS
# ============================================================================
class RedactionForensics:
    """Detect and attempt recovery of redacted content in PDFs."""

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.cfg = config.get("processor", {}).get("redaction_forensics", {})

    # ------------------------------------------------------------------
    def detect_redactions(
        self,
        pdf_path: str,
        document_id: int,
        page_results: Optional[List[Dict]] = None,
        progress_cb: Optional[Callable] = None,
    ) -> List[Dict[str, Any]]:
        """Find redacted areas and run the 11-step recovery pipeline on each.

        Steps: 1=text_layer, 2=pdf_layer, 2.5=incremental_save, 3=metadata(deep),
        4=ocr_mismatch, 4.5=rasterize_ocr, 5=copy_paste, 6=font_analysis,
        6.5=char_width_estimation, 7=cross_document(enhanced), 8=ai_inference.
        """
        pdf_path = str(pdf_path)
        all_redactions: List[Dict[str, Any]] = []

        try:
            doc = fitz.open(pdf_path)
        except Exception as exc:
            log.error("RedactionForensics: cannot open %s: %s", pdf_path, exc)
            return all_redactions

        conn = self.db.get_connection()
        try:
            for page_idx in range(len(doc)):
                page = doc[page_idx]
                page_num = page_idx + 1
                full_text = page.get_text("text")

                rects = []
                if page_results and page_idx < len(page_results):
                    rects = page_results[page_idx].get("redaction_rects", [])
                if not rects:
                    rects = OCREngine._detect_redaction_rects(page)

                for rect_info in rects:
                    rx = rect_info["x"]
                    ry = rect_info["y"]
                    rw = rect_info["width"]
                    rh = rect_info["height"]

                    # Context extraction: text before and after the redaction y-position
                    context_before, context_after = self._extract_context(
                        full_text, ry, page.rect.height
                    )

                    # Estimate hidden characters from rectangle size
                    estimated_chars = max(1, int(rw / 6))  # rough: 6pt per char

                    # ---------- 7-step recovery pipeline ----------
                    recovered_text = None
                    recovery_method = "unrecovered"
                    recovery_confidence = 0.0

                    fitz_rect = fitz.Rect(rx, ry, rx + rw, ry + rh)

                    # Step 1: text_layer_extraction
                    if self.cfg.get("text_layer_extraction", True):
                        result = self._step1_text_layer(page, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "text_layer"

                    # Step 2: pdf_layer_analysis
                    if not recovered_text and self.cfg.get("pdf_layer_analysis", True):
                        result = self._step2_pdf_layer(doc, page_idx, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "pdf_layer"

                    # Step 2.5: incremental_save_recovery
                    if not recovered_text and self.cfg.get("incremental_save_recovery", True):
                        result = self._step2_5_incremental_save(doc, page_idx, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "incremental_save"

                    # Step 3: metadata_extraction (deep)
                    if not recovered_text and self.cfg.get("metadata_extraction", True):
                        result = self._step3_metadata(doc, fitz_rect, page_idx)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "metadata"

                    # Step 4: ocr_layer_mismatch
                    if not recovered_text and self.cfg.get("ocr_layer_mismatch", True):
                        result = self._step4_ocr_mismatch(page, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "ocr_mismatch"

                    # Step 4.5: rasterize_ocr
                    if not recovered_text and self.cfg.get("rasterize_ocr", True):
                        result = self._step4_5_rasterize_ocr(page, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "rasterize_ocr"

                    # Step 5: copy_paste_extraction
                    if not recovered_text and self.cfg.get("copy_paste_extraction", True):
                        result = self._step5_copy_paste(page, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "copy_paste"

                    # Step 6: font_character_analysis
                    if not recovered_text and self.cfg.get("font_character_analysis", True):
                        result = self._step6_font_analysis(doc, page_idx, fitz_rect)
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "font_analysis"

                    # Step 6.5: char_width_estimation
                    char_width_estimate = None
                    if self.cfg.get("char_width_estimation", True):
                        char_width_estimate = self._step6_5_char_width(
                            doc, page_idx, fitz_rect
                        )
                        if not recovered_text and char_width_estimate:
                            # Update estimated_chars with better estimate
                            estimated_chars = char_width_estimate["estimated_chars"]

                    # Step 7: cross_document_matching (enhanced)
                    if not recovered_text and self.cfg.get("cross_document_matching", True):
                        result = self._step7_cross_document(
                            conn, context_before, context_after, document_id,
                            expected_chars=estimated_chars,
                        )
                        if result:
                            recovered_text, recovery_confidence = result
                            recovery_method = "cross_document"

                    # Step 8: ai_inference (last resort)
                    ai_candidates = None
                    if not recovered_text and self.cfg.get("ai_inference", True):
                        ai_result = self._step8_ai_inference(
                            context_before, context_after, estimated_chars,
                            char_width_estimate, document_id,
                        )
                        if ai_result:
                            recovered_text, recovery_confidence = ai_result["top_candidate"]
                            recovery_method = "ai_inference"
                            ai_candidates = json.dumps(ai_result.get("candidates", []))

                    is_recovered = recovered_text is not None and len(recovered_text.strip()) > 0
                    status = "recovered" if is_recovered else "unresolved"

                    redaction_record = {
                        "document_id": document_id,
                        "page_number": page_num,
                        "position_x": rx,
                        "position_y": ry,
                        "width": rw,
                        "height": rh,
                        "redaction_type": "text",
                        "estimated_chars": estimated_chars,
                        "context_before": context_before[:500] if context_before else None,
                        "context_after": context_after[:500] if context_after else None,
                        "recovery_method": recovery_method,
                        "recovered_text": recovered_text,
                        "recovery_confidence": round(recovery_confidence, 4),
                        "is_recovered": is_recovered,
                        "status": status,
                        "ai_candidates": ai_candidates,
                    }

                    conn.execute(
                        """INSERT INTO redactions
                           (document_id, page_number, position_x, position_y,
                            width, height, redaction_type, estimated_chars,
                            context_before, context_after,
                            recovery_method, recovered_text, recovery_confidence,
                            is_recovered, status, ai_candidates)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            document_id, page_num, rx, ry, rw, rh,
                            "text", estimated_chars,
                            redaction_record["context_before"],
                            redaction_record["context_after"],
                            recovery_method,
                            recovered_text,
                            round(recovery_confidence, 4),
                            int(is_recovered),
                            status,
                            ai_candidates,
                        ),
                    )
                    all_redactions.append(redaction_record)

                if progress_cb:
                    progress_cb("redaction", page_num, len(doc))

            conn.commit()
        finally:
            conn.close()
            doc.close()

        log.info(
            "Redaction forensics: found %d redactions, recovered %d (doc_id=%d)",
            len(all_redactions),
            sum(1 for r in all_redactions if r["is_recovered"]),
            document_id,
        )
        return all_redactions

    # ---- Step implementations ----

    def _step1_text_layer(
        self, page: fitz.Page, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Check if text exists under the black rectangle in the PDF text layer."""
        try:
            words = page.get_text("words")  # list of (x0, y0, x1, y1, word, ...)
            hidden_words = []
            for w in words:
                word_rect = fitz.Rect(w[0], w[1], w[2], w[3])
                if rect.intersects(word_rect):
                    overlap = rect & word_rect  # intersection
                    overlap_area = overlap.width * overlap.height
                    word_area = word_rect.width * word_rect.height
                    if word_area > 0 and (overlap_area / word_area) > 0.5:
                        hidden_words.append(w[4])
            if hidden_words:
                text = " ".join(hidden_words)
                confidence = 0.95
                log.debug("Step 1 recovery: [%d chars] (conf=%.2f)", len(text), confidence)
                return (text, confidence)
        except Exception as exc:
            log.debug("Step 1 error: %s", exc)
        return None

    def _step2_pdf_layer(
        self, doc: fitz.Document, page_idx: int, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Strip PDF layers and look for content under the redaction layer."""
        try:
            page = doc[page_idx]
            # Get raw page content stream(s) via /Contents references
            contents_xrefs = page.get_contents()
            page_content = None
            if contents_xrefs:
                streams = []
                for cx in contents_xrefs:
                    s = doc.xref_stream(cx)
                    if s:
                        streams.append(s)
                page_content = b"".join(streams) if streams else None
            if not page_content:
                return None

            # Attempt to parse content stream for text operators near redaction coords
            # Look for text-showing operators (Tj, TJ, ', ") near the redaction area
            content_str = page_content.decode("latin-1", errors="replace")

            # Find BT...ET blocks (text blocks)
            text_blocks = re.findall(r"BT(.*?)ET", content_str, re.DOTALL)
            for block in text_blocks:
                # Look for Td/Tm positioning operators with coords in redaction range
                positions = re.findall(r"([\d.]+)\s+([\d.]+)\s+Td", block)
                # Handle escaped parens and hex strings in PDF text operators
                texts = re.findall(r"\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*Tj", block)
                tj_arrays = re.findall(r"\[(.*?)\]\s*TJ", block, re.DOTALL)

                for pos in positions:
                    try:
                        tx, ty = float(pos[0]), float(pos[1])
                        page_height = page.rect.height
                        # PDF coords are bottom-up, fitz rect is top-down
                        ty_converted = page_height - ty
                        if rect.y0 - 5 <= ty_converted <= rect.y1 + 5:
                            # Position is within redaction area
                            extracted = []
                            for t in texts:
                                extracted.append(t)
                            for arr in tj_arrays:
                                # Extract both parenthesized strings and hex strings
                                parts = re.findall(r"\(([^)\\]*(?:\\.[^)\\]*)*)\)", arr)
                                hex_parts = re.findall(r"<([0-9A-Fa-f]+)>", arr)
                                extracted.extend(parts)
                                for hp in hex_parts:
                                    try:
                                        extracted.append(bytes.fromhex(hp).decode("latin-1"))
                                    except (ValueError, UnicodeDecodeError):
                                        pass
                            if extracted:
                                result = "".join(extracted)
                                log.debug("Step 2 recovery: [%d chars]", len(result))
                                return (result, 0.85)
                    except (ValueError, TypeError):
                        continue
        except Exception as exc:
            log.debug("Step 2 error: %s", exc)
        return None

    def _step3_metadata(
        self, doc: fitz.Document, rect: fitz.Rect, page_idx: int
    ) -> Optional[Tuple[str, float]]:
        """Deep metadata mining: XMP, PieceInfo, Marked, EmbeddedFiles, revision history."""
        try:
            xref_count = doc.xref_length()
            for xref_id in range(1, min(xref_count, 500)):
                try:
                    obj_str = doc.xref_object(xref_id, compressed=False)
                    if not obj_str:
                        continue

                    # Check /Contents and /Annot streams for pre-redaction content
                    if "/Contents" in obj_str or "/Annot" in obj_str:
                        stream = doc.xref_stream(xref_id)
                        if stream:
                            decoded = stream.decode("latin-1", errors="replace")
                            readable = re.findall(r"\(([^)]{3,})\)", decoded)
                            if readable:
                                combined = " ".join(readable)
                                if len(combined.strip()) > 2:
                                    log.debug("Step 3 metadata recovery: [%d chars]", len(combined))
                                    return (combined.strip(), 0.6)

                    # Check /PieceInfo and /Marked content for pre-redaction markers
                    if "/PieceInfo" in obj_str or "/Marked" in obj_str:
                        stream = doc.xref_stream(xref_id)
                        if stream:
                            decoded = stream.decode("latin-1", errors="replace")
                            # PieceInfo may contain application-specific data with original text
                            readable = re.findall(r"\(([^)]{3,})\)", decoded)
                            if readable:
                                combined = " ".join(readable)
                                if len(combined.strip()) > 2:
                                    log.debug("Step 3 PieceInfo recovery: [%d chars]", len(combined))
                                    return (combined.strip(), 0.55)

                    # Check /EmbeddedFiles for unredacted versions
                    if "/EmbeddedFiles" in obj_str:
                        stream = doc.xref_stream(xref_id)
                        if stream:
                            decoded = stream.decode("latin-1", errors="replace")
                            readable = re.findall(r"\(([^)]{3,})\)", decoded)
                            if readable:
                                combined = " ".join(readable)
                                if len(combined.strip()) > 2:
                                    log.debug("Step 3 EmbeddedFile recovery: [%d chars]", len(combined))
                                    return (combined.strip(), 0.65)

                except Exception:
                    continue

            # Parse XMP metadata streams for original content references
            try:
                xml_metadata = doc.get_xml_metadata()
                if xml_metadata:
                    # Look for description fields that might reference original content
                    descriptions = re.findall(
                        r"<dc:description[^>]*>(.*?)</dc:description>",
                        xml_metadata, re.DOTALL,
                    )
                    for desc in descriptions:
                        cleaned = re.sub(r"<[^>]+>", "", desc).strip()
                        if cleaned and len(cleaned) > 5:
                            log.debug("Step 3 XMP description: [%d chars]", len(cleaned))
                            return (cleaned, 0.45)
            except Exception:
                pass

        except Exception as exc:
            log.debug("Step 3 error: %s", exc)
        return None

    def _step4_ocr_mismatch(
        self, page: fitz.Page, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Compare OCR text layer with visual layer for mismatches."""
        try:
            # Get text from the raw text layer (what PDF viewers copy)
            raw_text_dict = page.get_text("rawdict")
            blocks = raw_text_dict.get("blocks", [])

            for block in blocks:
                if block.get("type") != 0:  # text block
                    continue
                for line in block.get("lines", []):
                    line_rect = fitz.Rect(line["bbox"])
                    if not rect.intersects(line_rect):
                        continue
                    overlap = rect & line_rect
                    if overlap.width * overlap.height < line_rect.width * line_rect.height * 0.3:
                        continue
                    # This line overlaps with the redaction
                    spans_text = []
                    for span in line.get("spans", []):
                        span_rect = fitz.Rect(span["bbox"])
                        if rect.intersects(span_rect):
                            txt = span.get("text", "").strip()
                            if txt:
                                spans_text.append(txt)
                    if spans_text:
                        result = " ".join(spans_text)
                        log.debug("Step 4 OCR mismatch recovery: [%d chars]", len(result))
                        return (result, 0.9)
        except Exception as exc:
            log.debug("Step 4 error: %s", exc)
        return None

    def _step5_copy_paste(
        self, page: fitz.Page, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Programmatic select-all text extraction from the redacted area."""
        try:
            # Use clip-based text extraction targeting the redacted rectangle
            clip_text = page.get_textbox(rect)
            if clip_text and clip_text.strip():
                cleaned = clip_text.strip()
                # Verify it's actual text, not just whitespace or garbage
                alpha_ratio = sum(1 for c in cleaned if c.isalpha()) / max(len(cleaned), 1)
                if alpha_ratio > 0.3 and len(cleaned) > 1:
                    log.debug("Step 5 copy-paste recovery: [%d chars]", len(cleaned))
                    return (cleaned, 0.88)
        except Exception as exc:
            log.debug("Step 5 error: %s", exc)
        return None

    def _step6_font_analysis(
        self, doc: fitz.Document, page_idx: int, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Parse raw PDF objects for character/glyph definitions at redacted coordinates."""
        try:
            page = doc[page_idx]
            raw = page.get_text("rawdict")
            blocks = raw.get("blocks", [])

            for block in blocks:
                if block.get("type") != 0:
                    continue
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        span_rect = fitz.Rect(span["bbox"])
                        if not rect.intersects(span_rect):
                            continue
                        # Check if span has font info and character codes
                        text = span.get("text", "")
                        font = span.get("font", "")
                        if text.strip() and font:
                            # The font mapping reveals actual characters even if
                            # visually hidden
                            chars = []
                            for ch in text:
                                if ch.isprintable() and ch.strip():
                                    chars.append(ch)
                            if chars:
                                result = "".join(chars)
                                log.debug("Step 6 font analysis recovery: [%d chars]", len(result))
                                return (result, 0.75)

            # Deep dive: parse xref objects for font CMap / ToUnicode mappings
            xref = page.xref
            if xref:
                obj_str = doc.xref_object(xref, compressed=False)
                # Look for /Font references
                font_refs = re.findall(r"/F(\d+)\s+(\d+)\s+\d+\s+R", obj_str)
                for font_ref in font_refs:
                    try:
                        font_xref = int(font_ref[1])
                        font_obj = doc.xref_object(font_xref, compressed=False)
                        if "/ToUnicode" in font_obj:
                            # Extract ToUnicode CMap stream
                            tounicode_ref = re.search(r"/ToUnicode\s+(\d+)\s+\d+\s+R", font_obj)
                            if tounicode_ref:
                                cmap_xref = int(tounicode_ref.group(1))
                                cmap_stream = doc.xref_stream(cmap_xref)
                                if cmap_stream:
                                    # CMap contains character code -> Unicode mappings
                                    cmap_text = cmap_stream.decode("latin-1", errors="replace")
                                    mappings = re.findall(
                                        r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>",
                                        cmap_text,
                                    )
                                    if mappings:
                                        log.debug(
                                            "Found %d font mappings in CMap",
                                            len(mappings),
                                        )
                    except Exception:
                        continue
        except Exception as exc:
            log.debug("Step 6 error: %s", exc)
        return None

    def _step7_cross_document(
        self,
        conn,
        context_before: Optional[str],
        context_after: Optional[str],
        current_doc_id: int,
        expected_chars: Optional[int] = None,
    ) -> Optional[Tuple[str, float]]:
        """Enhanced cross-document matching with multiple anchor lengths and scoring."""
        if not context_before and not context_after:
            return None

        try:
            # Use multiple anchor lengths for better matching
            anchor_lengths = [20, 40, 60]
            candidates: List[Tuple[str, float]] = []  # (text, score)

            for anchor_len in anchor_lengths:
                search_parts = []
                if context_before:
                    anchor = context_before[-anchor_len:].strip()
                    if len(anchor) > 10:
                        search_parts.append(anchor)
                if context_after:
                    anchor = context_after[:anchor_len].strip()
                    if len(anchor) > 10:
                        search_parts.append(anchor)

                if not search_parts:
                    continue

                # Try AND query with both anchors first (most precise)
                if len(search_parts) == 2:
                    safe_parts = []
                    for sp in search_parts:
                        safe = sp.replace('"', '""')
                        if len(safe) > anchor_len:
                            safe = safe[:anchor_len]
                        safe_parts.append(f'"{safe}"')
                    combined_query = " AND ".join(safe_parts)
                    try:
                        rows = conn.execute(
                            """SELECT dp.text_content, dp.document_id, dp.page_number
                               FROM document_pages dp
                               JOIN document_text_fts fts ON dp.rowid = fts.rowid
                               WHERE document_text_fts MATCH ?
                                 AND dp.document_id != ?
                               LIMIT 5""",
                            (combined_query, current_doc_id),
                        ).fetchall()
                        for row in rows:
                            match = self._extract_between_anchors(
                                row["text_content"] or "",
                                context_before, context_after, expected_chars,
                            )
                            if match:
                                candidates.append(match)
                    except Exception:
                        pass

                # Fallback: individual anchor queries
                for search_text in search_parts:
                    safe = search_text.replace('"', '""')
                    if len(safe) > anchor_len:
                        safe = safe[:anchor_len]
                    try:
                        rows = conn.execute(
                            """SELECT dp.text_content, dp.document_id, dp.page_number
                               FROM document_pages dp
                               JOIN document_text_fts fts ON dp.rowid = fts.rowid
                               WHERE document_text_fts MATCH ?
                                 AND dp.document_id != ?
                               LIMIT 5""",
                            (f'"{safe}"', current_doc_id),
                        ).fetchall()
                    except Exception:
                        continue
                    for row in rows:
                        match = self._extract_between_anchors(
                            row["text_content"] or "",
                            context_before, context_after, expected_chars,
                        )
                        if match:
                            candidates.append(match)

            if candidates:
                # Pick the best candidate by score
                best = max(candidates, key=lambda x: x[1])
                log.debug("Step 7 cross-doc recovery: [%d chars] (conf=%.2f)", len(best[0]), best[1])
                return best

        except Exception as exc:
            log.debug("Step 7 error: %s", exc)
        return None

    @staticmethod
    def _extract_between_anchors(
        other_text: str,
        context_before: Optional[str],
        context_after: Optional[str],
        expected_chars: Optional[int] = None,
    ) -> Optional[Tuple[str, float]]:
        """Extract text between context anchors in another document, with scoring."""
        if not (context_before and context_after):
            return None

        # Try multiple anchor lengths for finding the match
        for trim in (30, 50, 80):
            before_anchor = context_before[-trim:]
            after_anchor = context_after[:trim]
            idx_before = other_text.find(before_anchor)
            idx_after = other_text.find(after_anchor, idx_before + len(before_anchor) if idx_before >= 0 else 0)

            if idx_before >= 0 and idx_after > idx_before:
                start = idx_before + len(before_anchor)
                recovered = other_text[start:idx_after].strip()
                if recovered:
                    score = 0.80
                    # Boost score if length matches expected character count
                    if expected_chars and expected_chars > 0:
                        ratio = len(recovered) / expected_chars
                        if 0.7 <= ratio <= 1.3:
                            score += 0.05  # good width match
                    return (recovered, min(score, 0.95))
        return None

    # ---- New step implementations (2.5, 4.5, 6.5, 8) ----

    def _step2_5_incremental_save(
        self, doc: fitz.Document, page_idx: int, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Recover text from older PDF revisions via incremental save history.

        Many PDFs have incremental updates where older page versions may exist
        unredacted. We parse the startxref chain to find all revisions and compare
        page content across them.
        """
        try:
            # Read the raw PDF bytes to find incremental save boundaries
            pdf_bytes = None
            if hasattr(doc, "tobytes"):
                pdf_bytes = doc.tobytes()
            elif hasattr(doc, "write"):
                pdf_bytes = doc.write()
            if not pdf_bytes:
                return None

            # Find all startxref positions (each marks an incremental save)
            startxref_positions = []
            search_start = 0
            while True:
                pos = pdf_bytes.find(b"startxref", search_start)
                if pos < 0:
                    break
                startxref_positions.append(pos)
                search_start = pos + 9

            if len(startxref_positions) < 2:
                # No incremental saves — only one revision
                return None

            log.debug(
                "Step 2.5: found %d revisions in PDF", len(startxref_positions)
            )

            # Get current page text at the redaction rect
            current_page = doc[page_idx]
            current_text = current_page.get_textbox(rect)

            # Try opening the PDF truncated at each earlier startxref
            # to access older revisions
            for sxref_pos in startxref_positions[:-1]:
                # Find the %%EOF after this startxref
                eof_pos = pdf_bytes.find(b"%%EOF", sxref_pos)
                if eof_pos < 0:
                    continue
                truncated = pdf_bytes[: eof_pos + 5]
                if len(truncated) < 100:
                    continue

                try:
                    old_doc = fitz.open(stream=truncated, filetype="pdf")
                    if page_idx >= len(old_doc):
                        old_doc.close()
                        continue
                    old_page = old_doc[page_idx]
                    old_text = old_page.get_textbox(rect)
                    old_doc.close()

                    if old_text and old_text.strip():
                        old_clean = old_text.strip()
                        # Only count as recovery if old version has substantive text
                        # that the current version doesn't have
                        current_clean = (current_text or "").strip()
                        if len(old_clean) > len(current_clean) + 2:
                            alpha_ratio = sum(1 for c in old_clean if c.isalpha()) / max(len(old_clean), 1)
                            if alpha_ratio > 0.3:
                                log.debug(
                                    "Step 2.5 incremental save recovery: [%d chars]",
                                    len(old_clean),
                                )
                                return (old_clean, 0.92)
                except Exception:
                    continue

        except Exception as exc:
            log.debug("Step 2.5 error: %s", exc)
        return None

    def _step4_5_rasterize_ocr(
        self, page: fitz.Page, rect: fitz.Rect
    ) -> Optional[Tuple[str, float]]:
        """Render the redacted area at high DPI and OCR it.

        Some redactions are improperly applied (overlay opacity < 100%, or
        non-pure-black). Rasterizing and applying brightness/contrast adjustments
        can reveal text underneath.
        """
        try:
            # Render just the redaction area at high DPI
            clip = fitz.Rect(rect)
            # Expand clip slightly for better OCR context
            clip.x0 = max(0, clip.x0 - 2)
            clip.y0 = max(0, clip.y0 - 2)
            clip.x1 = min(page.rect.width, clip.x1 + 2)
            clip.y1 = min(page.rect.height, clip.y1 + 2)

            pix = page.get_pixmap(dpi=300, clip=clip)
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)

            # Apply brightness/contrast enhancement to reveal faint text
            from PIL import ImageEnhance, ImageFilter

            results = []

            # Try multiple enhancement levels
            for brightness_factor in (1.5, 2.0, 3.0):
                enhanced = ImageEnhance.Brightness(img).enhance(brightness_factor)
                enhanced = ImageEnhance.Contrast(enhanced).enhance(2.0)
                # Sharpen to improve OCR accuracy
                enhanced = enhanced.filter(ImageFilter.SHARPEN)

                try:
                    ocr_text = pytesseract.image_to_string(
                        enhanced, lang="eng", config="--psm 6"
                    ).strip()
                except Exception:
                    continue

                if ocr_text and len(ocr_text) > 1:
                    alpha_ratio = sum(1 for c in ocr_text if c.isalpha()) / max(len(ocr_text), 1)
                    if alpha_ratio > 0.3:
                        results.append(ocr_text)

            # Also try grayscale + threshold (for non-pure-black redactions)
            gray = img.convert("L")
            # Threshold at multiple levels
            for threshold in (40, 60, 80):
                binary = gray.point(lambda x: 255 if x > threshold else 0, "1")
                try:
                    ocr_text = pytesseract.image_to_string(
                        binary, lang="eng", config="--psm 6"
                    ).strip()
                except Exception:
                    continue
                if ocr_text and len(ocr_text) > 1:
                    alpha_ratio = sum(1 for c in ocr_text if c.isalpha()) / max(len(ocr_text), 1)
                    if alpha_ratio > 0.3:
                        results.append(ocr_text)

            if results:
                # Pick the longest result (most text recovered)
                best = max(results, key=len)
                log.debug("Step 4.5 rasterize-OCR recovery: [%d chars]", len(best))
                return (best, 0.70)

        except ImportError:
            log.debug("Step 4.5 skipped: PIL ImageEnhance not available")
        except Exception as exc:
            log.debug("Step 4.5 error: %s", exc)
        return None

    def _step6_5_char_width(
        self, doc: fitz.Document, page_idx: int, rect: fitz.Rect
    ) -> Optional[Dict[str, Any]]:
        """Estimate character count from font metrics and redaction rectangle width.

        Returns a dict with estimation data (not a recovery tuple) since this
        step provides supplementary data for Steps 7 and 8 rather than direct text.
        """
        try:
            page = doc[page_idx]
            raw = page.get_text("rawdict")
            blocks = raw.get("blocks", [])

            # Find spans near the redaction to determine the font in use
            nearby_spans = []
            search_rect = fitz.Rect(
                rect.x0 - 50, rect.y0 - 5, rect.x1 + 50, rect.y1 + 5
            )
            for block in blocks:
                if block.get("type") != 0:
                    continue
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        span_rect = fitz.Rect(span["bbox"])
                        if search_rect.intersects(span_rect):
                            nearby_spans.append(span)

            if not nearby_spans:
                return None

            # Calculate average character width from nearby spans
            total_chars = 0
            total_width = 0.0
            font_name = None
            font_size = None

            for span in nearby_spans:
                text = span.get("text", "")
                if not text.strip():
                    continue
                span_rect = fitz.Rect(span["bbox"])
                char_count = len(text)
                if char_count > 0:
                    total_chars += char_count
                    total_width += span_rect.width
                    if font_name is None:
                        font_name = span.get("font", "unknown")
                        font_size = span.get("size", 12)

            if total_chars == 0:
                return None

            avg_char_width = total_width / total_chars
            estimated_chars = max(1, int(rect.width / avg_char_width))

            result = {
                "estimated_chars": estimated_chars,
                "avg_char_width": round(avg_char_width, 2),
                "font_name": font_name,
                "font_size": round(font_size, 1) if font_size else None,
                "redaction_width": round(rect.width, 2),
                "confidence": 0.40,
            }

            log.debug(
                "Step 6.5 char width: ~%d chars (%.1fpt %s, avg_w=%.2f, rect_w=%.1f)",
                estimated_chars, font_size or 0, font_name or "?",
                avg_char_width, rect.width,
            )
            return result

        except Exception as exc:
            log.debug("Step 6.5 error: %s", exc)
        return None

    def _step8_ai_inference(
        self,
        context_before: Optional[str],
        context_after: Optional[str],
        estimated_chars: int,
        char_width_info: Optional[Dict] = None,
        document_id: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """AI-powered contextual inference via consensus engine (last resort).

        Builds a rich prompt with surrounding text, character count estimation,
        and partial recovery data, then sends to available AI models.
        Returns dict with top_candidate tuple and candidates list.
        """
        if not context_before and not context_after:
            return None

        try:
            # Import pipeline components
            from ai_pipeline.pipeline import (
                GracefulDegradation,
                ResponseParser,
            )

            cfg = _load_config()
            degradation = GracefulDegradation(cfg)
            runners = degradation.get_available_runners()
            if not runners:
                log.debug("Step 8: no AI models available")
                return None

            # Build the redaction inference prompt
            prompt = self._build_redaction_inference_prompt(
                context_before, context_after, estimated_chars,
                char_width_info, document_id,
            )

            # Run available models
            candidates: List[Dict[str, Any]] = []
            for runner in runners:
                try:
                    response = runner.run(prompt, timeout=120)
                    if not response:
                        continue

                    # Parse the response for candidate names/text
                    parsed = self._parse_redaction_inference(response, runner.get_name())
                    if parsed:
                        candidates.extend(parsed)
                except Exception as exc:
                    log.debug("Step 8 %s error: %s", runner.get_name(), exc)
                    continue

            if not candidates:
                return None

            # Score candidates by agreement across models
            scored = self._score_inference_candidates(candidates)
            if not scored:
                return None

            top = scored[0]
            confidence = min(0.65, max(0.30, top["agreement_score"]))
            log.debug(
                "Step 8 AI inference: '%s' (conf=%.2f, %d models agree)",
                top["text"][:50], confidence, top["model_count"],
            )

            return {
                "top_candidate": (top["text"], confidence),
                "candidates": scored[:5],  # top 5
            }

        except ImportError:
            log.debug("Step 8 skipped: ai_pipeline not available")
        except Exception as exc:
            log.debug("Step 8 error: %s", exc)
        return None

    def _build_redaction_inference_prompt(
        self,
        context_before: Optional[str],
        context_after: Optional[str],
        estimated_chars: int,
        char_width_info: Optional[Dict],
        document_id: int,
    ) -> str:
        """Build a structured prompt for AI redaction inference."""
        parts = [
            "=== REDACTION INFERENCE REQUEST ===",
            "",
            "A redacted section was found in a legal/government document related to",
            "the Jeffrey Epstein case. Analyze the surrounding context and provide",
            "your best inference for what was redacted.",
            "",
        ]

        if context_before:
            parts.append(f"TEXT BEFORE REDACTION:\n\"{context_before[-300:]}\"")
            parts.append("")
        parts.append("[REDACTED]")
        parts.append("")
        if context_after:
            parts.append(f"TEXT AFTER REDACTION:\n\"{context_after[:300]}\"")
            parts.append("")

        parts.append(f"ESTIMATED CHARACTER COUNT: ~{estimated_chars}")
        if char_width_info:
            parts.append(f"FONT: {char_width_info.get('font_name', 'unknown')}")
            parts.append(f"FONT SIZE: {char_width_info.get('font_size', 'unknown')}pt")
        parts.append("")

        parts.extend([
            "Provide your top 5 candidates for what was redacted.",
            "Format each as: CANDIDATE: <text> | CONFIDENCE: <0-100>% | REASONING: <brief>",
            "Consider: names of known associates, locations, dates, legal terms,",
            "financial figures, or other contextually appropriate text.",
            "The text MUST be approximately the right length (~{} chars).".format(estimated_chars),
        ])

        return "\n".join(parts)

    @staticmethod
    def _parse_redaction_inference(
        response: str, model_name: str
    ) -> List[Dict[str, Any]]:
        """Parse AI model response for redaction inference candidates."""
        candidates = []
        # Match patterns like: CANDIDATE: <text> | CONFIDENCE: 85% | REASONING: ...
        pattern = re.compile(
            r"CANDIDATE:\s*(.+?)\s*\|\s*CONFIDENCE:\s*(\d+)%?\s*\|\s*REASONING:\s*(.+)",
            re.IGNORECASE,
        )
        for match in pattern.finditer(response):
            text = match.group(1).strip()
            confidence = int(match.group(2))
            reasoning = match.group(3).strip()
            if text and confidence > 0:
                candidates.append({
                    "text": text,
                    "confidence": confidence / 100.0,
                    "reasoning": reasoning,
                    "model": model_name,
                })

        # Fallback: try numbered list format (1. Name (85%) - reason)
        if not candidates:
            fallback = re.compile(
                r"\d+\.\s+(.+?)\s*\((\d+)%?\)\s*[-–—]\s*(.+)"
            )
            for match in fallback.finditer(response):
                text = match.group(1).strip()
                confidence = int(match.group(2))
                reasoning = match.group(3).strip()
                if text and confidence > 0:
                    candidates.append({
                        "text": text,
                        "confidence": confidence / 100.0,
                        "reasoning": reasoning,
                        "model": model_name,
                    })

        return candidates

    @staticmethod
    def _score_inference_candidates(
        candidates: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Score and rank inference candidates by cross-model agreement."""
        if not candidates:
            return []

        # Group by normalized text
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for c in candidates:
            key = c["text"].lower().strip()
            groups[key].append(c)

        scored = []
        for key, group in groups.items():
            models = set(c["model"] for c in group)
            avg_conf = sum(c["confidence"] for c in group) / len(group)
            # Agreement score: higher if multiple models agree
            agreement = avg_conf * (1.0 + 0.15 * (len(models) - 1))
            scored.append({
                "text": group[0]["text"],
                "agreement_score": round(min(agreement, 0.95), 4),
                "model_count": len(models),
                "models": list(models),
                "avg_confidence": round(avg_conf, 4),
                "reasoning": group[0]["reasoning"],
            })

        scored.sort(key=lambda x: x["agreement_score"], reverse=True)
        return scored

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_context(
        full_text: str, redaction_y: float, page_height: float
    ) -> Tuple[Optional[str], Optional[str]]:
        """Split page text at approximate redaction position to get context."""
        if not full_text:
            return (None, None)
        lines = full_text.split("\n")
        total_lines = len(lines)
        if total_lines == 0:
            return (None, None)

        # Estimate which line corresponds to the redaction y position
        ratio = redaction_y / max(page_height, 1)
        split_line = int(ratio * total_lines)
        split_line = max(0, min(split_line, total_lines - 1))

        before = "\n".join(lines[:split_line])
        after = "\n".join(lines[split_line:])
        return (before[-500:] if before else None, after[:500] if after else None)


# ============================================================================
# 4. IMAGE FORENSICS
# ============================================================================
class ImageForensics:
    """Detect and analyze redacted areas in images, with user-review gating."""

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.cfg = config.get("processor", {}).get("image_forensics", {})
        self.data_dir = Path(config["project"]["data_dir"]).resolve()
        self.quarantine_dir = self.data_dir / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def process_document_images(
        self,
        pdf_path: str,
        document_id: int,
        progress_cb: Optional[Callable] = None,
    ) -> List[Dict[str, Any]]:
        """Extract and analyse every embedded image from a PDF."""
        pdf_path = str(pdf_path)
        results: List[Dict[str, Any]] = []

        try:
            doc = fitz.open(pdf_path)
        except Exception as exc:
            log.error("ImageForensics: cannot open %s: %s", pdf_path, exc)
            return results

        conn = self.db.get_connection()
        try:
            for page_idx in range(len(doc)):
                page = doc[page_idx]
                page_num = page_idx + 1
                image_list = page.get_images(full=True)

                for img_idx, img_info in enumerate(image_list):
                    xref = img_info[0]
                    try:
                        base_image = doc.extract_image(xref)
                    except Exception:
                        continue
                    if not base_image:
                        continue

                    img_bytes = base_image["image"]
                    raw_ext = base_image.get("ext", "png")
                    # Sanitize extension: whitelist only safe image formats
                    _ALLOWED_IMG_EXT = {"png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp"}
                    img_ext = raw_ext.lower().strip(".") if raw_ext else "png"
                    if img_ext not in _ALLOWED_IMG_EXT:
                        img_ext = "png"
                    file_hash = hashlib.sha256(img_bytes).hexdigest()

                    # Check for duplicate
                    existing = conn.execute(
                        "SELECT id FROM images WHERE file_hash = ?", (file_hash,)
                    ).fetchone()
                    if existing:
                        continue

                    # Save image to temp for analysis
                    temp_path = self.data_dir / "temp" / f"img_{document_id}_{page_num}_{img_idx}.{img_ext}"
                    temp_path.parent.mkdir(parents=True, exist_ok=True)
                    temp_path.write_bytes(img_bytes)

                    # Run forensic analysis
                    analysis = self.detect_image_redactions(str(temp_path), img_bytes)

                    # NEVER auto-save. Queue for user review.
                    # If minor detected -> auto-quarantine
                    minor_detected = analysis.get("minor_detected", False)
                    quarantined = False
                    saved_path = str(temp_path)

                    if minor_detected and self.cfg.get("auto_quarantine_minors", True):
                        quarantine_path = self.quarantine_dir / f"{file_hash}.{img_ext}"
                        temp_path.rename(quarantine_path)
                        saved_path = str(quarantine_path)
                        quarantined = True
                        log.warning(
                            "Image auto-quarantined (minor detected): doc=%d page=%d",
                            document_id, page_num,
                        )

                    # Save metadata to images table even if image is discarded
                    conn.execute(
                        """INSERT INTO images
                           (document_id, file_path, file_hash, page_number,
                            original_redacted, recovery_attempted,
                            recovery_method, recovery_successful,
                            user_reviewed, exif_data, ai_description,
                            location_clues, estimated_date,
                            minor_detected, quarantined)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            document_id,
                            saved_path,
                            file_hash,
                            page_num,
                            int(analysis.get("has_redactions", False)),
                            int(analysis.get("recovery_attempted", False)),
                            analysis.get("recovery_method"),
                            int(analysis.get("recovery_successful", False)),
                            0,  # user_reviewed = False, always
                            json.dumps(analysis.get("exif_data", {})),
                            analysis.get("description"),
                            analysis.get("location_clues"),
                            analysis.get("estimated_date"),
                            int(minor_detected),
                            int(quarantined),
                        ),
                    )

                    results.append({
                        "document_id": document_id,
                        "page_number": page_num,
                        "file_hash": file_hash,
                        "has_redactions": analysis.get("has_redactions", False),
                        "recovery_successful": analysis.get("recovery_successful", False),
                        "quarantined": quarantined,
                        "minor_detected": minor_detected,
                    })

                if progress_cb:
                    progress_cb("image_forensics", page_num, len(doc))

            conn.commit()
        finally:
            conn.close()
            doc.close()

        log.info("Image forensics: processed %d images (doc_id=%d)", len(results), document_id)
        return results

    # ------------------------------------------------------------------
    def detect_image_redactions(
        self, image_path: str, raw_bytes: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Run the 5-step image recovery pipeline."""
        result: Dict[str, Any] = {
            "has_redactions": False,
            "recovery_attempted": False,
            "recovery_successful": False,
            "recovery_method": None,
            "exif_data": {},
            "description": None,
            "location_clues": None,
            "estimated_date": None,
            "minor_detected": False,
        }

        try:
            img = Image.open(image_path)
        except Exception as exc:
            log.debug("Cannot open image %s: %s", image_path, exc)
            return result

        # Detect black/white boxes that look like redactions
        redaction_boxes = self._find_redaction_boxes(img)
        result["has_redactions"] = len(redaction_boxes) > 0

        if not result["has_redactions"]:
            # Still extract EXIF even if no redactions
            result["exif_data"] = self._extract_exif(img, image_path)
            return result

        result["recovery_attempted"] = True

        # Step 1: Layer analysis
        if self.cfg.get("layer_analysis", True):
            layer_result = self._step1_layer_analysis(img, image_path)
            if layer_result:
                result["recovery_successful"] = True
                result["recovery_method"] = "layer_analysis"

        # Step 2: EXIF metadata + thumbnail check
        exif_data = self._extract_exif(img, image_path)
        result["exif_data"] = exif_data
        if self.cfg.get("exif_extraction", True):
            thumb = self._step2_exif_thumbnail(img, exif_data, raw_bytes)
            if thumb and not result["recovery_successful"]:
                result["recovery_successful"] = True
                result["recovery_method"] = "exif_thumbnail"

        # Step 3: Black box overlay analysis
        if self.cfg.get("black_box_analysis", True) and not result["recovery_successful"]:
            overlay_result = self._step3_black_box(img)
            if overlay_result:
                result["recovery_successful"] = True
                result["recovery_method"] = "black_box_overlay"

        # Step 4: Cross-reference (placeholder for DB search)
        if self.cfg.get("cross_reference_search", True) and not result["recovery_successful"]:
            result["recovery_method"] = result["recovery_method"] or "cross_reference_pending"

        # Step 5: Contextual analysis - describe everything visible
        result["description"] = self._step5_contextual(img)

        # Extract location/date clues from EXIF
        if exif_data:
            gps = exif_data.get("GPSInfo")
            if gps:
                result["location_clues"] = json.dumps(gps) if isinstance(gps, dict) else str(gps)
            date_taken = exif_data.get("DateTimeOriginal") or exif_data.get("DateTime")
            if date_taken:
                result["estimated_date"] = str(date_taken)

        return result

    # ------------------------------------------------------------------
    def _find_redaction_boxes(self, img: Image.Image) -> List[Dict]:
        """Detect large solid-color rectangles that may be redactions."""
        boxes = []
        try:
            if img.mode != "RGB":
                img = img.convert("RGB")
            width, height = img.size
            pixels = img.load()

            # Scan for horizontal runs of very dark or very bright pixels
            # that form rectangular blocks
            min_run = max(20, width // 20)
            min_height_run = max(10, height // 40)

            # Sample rows
            for y in range(0, height, max(1, height // 100)):
                run_start = None
                run_len = 0
                for x in range(width):
                    r, g, b = pixels[x, y]
                    is_dark = (r + g + b) < 30
                    is_white = (r > 250 and g > 250 and b > 250)
                    if is_dark or is_white:
                        if run_start is None:
                            run_start = x
                        run_len += 1
                    else:
                        if run_len >= min_run and run_start is not None:
                            boxes.append({
                                "x": run_start,
                                "y": y,
                                "width": run_len,
                                "height": min_height_run,
                                "type": "dark" if (pixels[run_start, y][0] + pixels[run_start, y][1] + pixels[run_start, y][2]) < 30 else "white"
                            })
                        run_start = None
                        run_len = 0
                if run_len >= min_run and run_start is not None:
                    boxes.append({
                        "x": run_start,
                        "y": y,
                        "width": run_len,
                        "height": min_height_run,
                    })
        except Exception as exc:
            log.debug("Redaction box detection error: %s", exc)
        return boxes

    def _step1_layer_analysis(
        self, img: Image.Image, path: str
    ) -> Optional[bool]:
        """Check for separate redaction layers (multi-layer TIFF/PSD)."""
        try:
            if hasattr(img, "n_frames") and img.n_frames > 1:
                # Multi-frame image; additional frames may be unredacted layers
                log.info("Image has %d frames/layers - possible unredacted layer", img.n_frames)
                return True
            # Check for alpha channel that might be a redaction mask
            if img.mode in ("RGBA", "LA", "PA"):
                alpha = img.getchannel("A")
                # If alpha has distinct regions, might be overlay
                alpha_extrema = alpha.getextrema()
                if alpha_extrema[0] != alpha_extrema[1]:
                    log.info("Alpha channel has variation - possible removable overlay")
                    return True
        except Exception as exc:
            log.debug("Layer analysis error: %s", exc)
        return None

    def _step2_exif_thumbnail(
        self, img: Image.Image, exif_data: dict, raw_bytes: Optional[bytes]
    ) -> Optional[bool]:
        """Check EXIF data for embedded thumbnails that might be unredacted."""
        try:
            if hasattr(img, "_getexif"):
                exif_raw = img._getexif()
                if exif_raw and 0x0201 in exif_raw:  # JPEGInterchangeFormat = thumbnail offset
                    log.info("EXIF thumbnail found - may contain pre-redaction version")
                    return True

            # Check raw bytes for JFIF thumbnail
            if raw_bytes:
                # JFIF thumbnail marker
                if b"\xff\xd8\xff" in raw_bytes[20:]:
                    second_jpeg = raw_bytes.index(b"\xff\xd8\xff", 20)
                    if second_jpeg > 0:
                        log.info("Embedded JPEG thumbnail found at offset %d", second_jpeg)
                        return True
        except Exception as exc:
            log.debug("EXIF thumbnail check error: %s", exc)
        return None

    def _step3_black_box(self, img: Image.Image) -> Optional[bool]:
        """Check if black boxes are removable overlays via alpha channel."""
        try:
            if img.mode == "RGBA":
                r, g, b, a = img.split()
                # If alpha channel is 0 where black box is, removing alpha reveals content
                # This is a simplistic check
                a_data = list(a.getdata())
                transparent_pixels = sum(1 for p in a_data if p < 128)
                if transparent_pixels > 100:
                    log.info("Transparent regions detected - black box may be overlay")
                    return True
        except Exception as exc:
            log.debug("Black box analysis error: %s", exc)
        return None

    def _step5_contextual(self, img: Image.Image) -> str:
        """Describe visible content of the image for context."""
        try:
            w, h = img.size
            mode = img.mode
            desc_parts = [f"Image {w}x{h} ({mode})"]

            # Basic color analysis
            if img.mode != "RGB":
                img_rgb = img.convert("RGB")
            else:
                img_rgb = img
            colors = img_rgb.getcolors(maxcolors=1000)
            if colors:
                # Dominant color
                sorted_colors = sorted(colors, key=lambda x: x[0], reverse=True)
                dominant = sorted_colors[0][1] if sorted_colors else (0, 0, 0)
                desc_parts.append(f"Dominant color: RGB{dominant}")
                desc_parts.append(f"Unique colors (sample): {len(sorted_colors)}")

            return "; ".join(desc_parts)
        except Exception:
            return f"Image analysis unavailable"

    @staticmethod
    def _extract_exif(img: Image.Image, path: str) -> dict:
        """Extract EXIF metadata from image."""
        exif_dict = {}
        try:
            exif_raw = img._getexif()
            if exif_raw:
                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="replace")
                        except Exception:
                            value = repr(value)
                    elif isinstance(value, dict):
                        value = {str(k): str(v) for k, v in value.items()}
                    elif not isinstance(value, (str, int, float, bool, type(None), list)):
                        value = str(value)
                    exif_dict[tag_name] = value
        except Exception:
            log.debug("EXIF extraction failed", exc_info=True)
        return exif_dict


# ============================================================================
# 5. EMAIL CHAIN STITCHER
# ============================================================================
class EmailChainStitcher:
    """Reconstruct email conversation threads from individual messages."""

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.cfg = config.get("processor", {}).get("email_chain", {})

    # ------------------------------------------------------------------
    def on_new_email(
        self, email_data: Dict[str, Any], document_id: int
    ) -> Dict[str, Any]:
        """Full pipeline: fingerprint -> match -> stitch/create -> detect gaps."""
        fingerprint = self.fingerprint_email(email_data)
        chain_match = self.match_to_chain(fingerprint)

        conn = self.db.get_connection()
        try:
            if chain_match:
                chain_id = chain_match["chain_id"]
                self.stitch(email_data, chain_id, document_id, conn)
                # Re-analyze chain for gaps
                gaps = self.detect_gaps(chain_id, conn)
                if gaps:
                    conn.execute(
                        """UPDATE email_chains
                           SET has_gaps = 1, gap_details = ?,
                               analysis_completed = 0, updated_at = ?
                           WHERE id = ?""",
                        (json.dumps(gaps), datetime.now(tz=timezone.utc).isoformat(), chain_id),
                    )
                conn.commit()
                return {
                    "action": "stitched",
                    "chain_id": chain_id,
                    "gaps": gaps,
                    "fingerprint": fingerprint,
                }
            else:
                chain_id = self._create_chain(fingerprint, email_data, document_id, conn)
                conn.commit()
                return {
                    "action": "new_chain",
                    "chain_id": chain_id,
                    "fingerprint": fingerprint,
                }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    def fingerprint_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a chain fingerprint from normalized subject + participants + body hash."""
        subject = email_data.get("subject", "") or ""
        # Normalize subject: strip Re: Fwd: FW: RE: etc.
        normalized_subject = re.sub(
            r"^(?:re|fw|fwd)\s*:\s*", "", subject, flags=re.I
        ).strip().lower()
        # Remove consecutive whitespace
        normalized_subject = re.sub(r"\s+", " ", normalized_subject)

        # Collect all participants
        participants = set()
        from_addr = email_data.get("from_address") or email_data.get("from_name", "")
        if from_addr:
            participants.add(from_addr.lower().strip())
        for addr in email_data.get("to", []):
            a = addr.lower().strip()
            # Extract email from "Name <email>" format
            m = EMAIL_ADDR_PATTERN.search(a)
            participants.add(m.group(0) if m else a)
        for addr in email_data.get("cc", []):
            a = addr.lower().strip()
            m = EMAIL_ADDR_PATTERN.search(a)
            participants.add(m.group(0) if m else a)

        # Body hash
        body = email_data.get("body", "") or ""
        # Strip quoted content for hash
        body_clean = re.sub(
            r"(?:^>.*$|^On .+ wrote:.*$|^-{3,}.*Original Message.*$)",
            "", body, flags=re.M | re.I,
        ).strip()
        body_hash = hashlib.md5(body_clean.encode("utf-8", errors="replace")).hexdigest()

        # Timestamp
        date_str = email_data.get("date")
        timestamp = self._parse_date(date_str) if date_str else None

        # Chain identifier: hash of normalized subject + sorted participants
        chain_seed = normalized_subject + "|" + ",".join(sorted(participants))
        chain_id_hash = hashlib.sha256(chain_seed.encode()).hexdigest()[:32]

        return {
            "chain_hash": chain_id_hash,
            "normalized_subject": normalized_subject,
            "participants": sorted(participants),
            "body_hash": body_hash,
            "timestamp": timestamp,
            "body_clean": body_clean,
        }

    # ------------------------------------------------------------------
    def match_to_chain(self, fingerprint: Dict[str, Any]) -> Optional[Dict]:
        """Check existing chains for a match (any 2 of: subject, participants, quoted text, timestamp fit)."""
        conn = self.db.get_connection()
        try:
            # First: exact chain_hash match
            row = conn.execute(
                "SELECT id, participants, normalized_subject FROM email_chains WHERE chain_identifier = ?",
                (fingerprint["chain_hash"],),
            ).fetchone()
            if row:
                return {"chain_id": row["id"], "match_type": "exact_hash"}

            # Second: fuzzy match - filter by subject similarity at the SQL level
            # to avoid loading the entire email_chains table into memory
            fp_subj = fingerprint["normalized_subject"]
            subj_like = "%" + fp_subj[:40].replace("%", "").replace("_", "") + "%" if fp_subj else None
            if subj_like:
                chains = conn.execute(
                    "SELECT id, chain_identifier, normalized_subject, participants "
                    "FROM email_chains WHERE normalized_subject LIKE ? ESCAPE '\\'",
                    (subj_like,),
                ).fetchall()
            else:
                chains = conn.execute(
                    "SELECT id, chain_identifier, normalized_subject, participants FROM email_chains"
                ).fetchall()

            for chain in chains:
                match_score = 0
                # Subject match
                chain_subj = (chain["normalized_subject"] or "").lower()
                fp_subj = fingerprint["normalized_subject"]
                if chain_subj and fp_subj:
                    if chain_subj == fp_subj:
                        match_score += 1
                    elif chain_subj in fp_subj or fp_subj in chain_subj:
                        match_score += 1

                # Participant overlap
                chain_parts = set()
                try:
                    chain_parts = set(json.loads(chain["participants"] or "[]"))
                except (json.JSONDecodeError, TypeError):
                    pass
                fp_parts = set(fingerprint["participants"])
                if chain_parts and fp_parts:
                    overlap = chain_parts & fp_parts
                    if len(overlap) >= 1:
                        match_score += 1

                # Quoted text match: check if fingerprint body contains text from chain emails
                if match_score >= 1 and fingerprint.get("body_clean"):
                    msgs = conn.execute(
                        "SELECT body_hash FROM email_messages WHERE chain_id = ?",
                        (chain["id"],),
                    ).fetchall()
                    for msg in msgs:
                        if msg["body_hash"] == fingerprint["body_hash"]:
                            match_score += 1
                            break

                # Timestamp proximity: if within a reasonable window of chain
                if fingerprint.get("timestamp"):
                    chain_row = conn.execute(
                        "SELECT first_email_date, last_email_date FROM email_chains WHERE id = ?",
                        (chain["id"],),
                    ).fetchone()
                    if chain_row and chain_row["first_email_date"] and chain_row["last_email_date"]:
                        try:
                            first = datetime.fromisoformat(chain_row["first_email_date"])
                            last = datetime.fromisoformat(chain_row["last_email_date"])
                            fp_time = fingerprint["timestamp"]
                            # Within 365 days of chain range
                            from datetime import timedelta
                            if (first - timedelta(days=365)) <= fp_time <= (last + timedelta(days=365)):
                                match_score += 1
                        except Exception:
                            logger.debug("Time-range match failed", exc_info=True)

                if match_score >= 2:
                    return {"chain_id": chain["id"], "match_type": "fuzzy", "score": match_score}

            return None
        finally:
            conn.close()

    # ------------------------------------------------------------------
    def stitch(
        self,
        email_data: Dict[str, Any],
        chain_id: int,
        document_id: int,
        conn=None,
    ):
        """Add email to chain in correct chronological position, strip quoted content."""
        own_conn = conn is None
        if own_conn:
            conn = self.db.get_connection()

        try:
            # Get existing messages in chain
            existing = conn.execute(
                "SELECT id, body_text, body_hash FROM email_messages WHERE chain_id = ? ORDER BY email_date",
                (chain_id,),
            ).fetchall()

            # Strip quoted content that already exists in chain
            body = email_data.get("body", "") or ""
            body_new = body
            existing_hashes = {row["body_hash"] for row in existing if row["body_hash"]}

            # Remove "On ... wrote:" quoted blocks
            quoted_pattern = re.compile(
                r"(?:^On .+ wrote:\s*\n)((?:^>.*\n?)+)", re.M | re.I
            )
            quoted_blocks = quoted_pattern.findall(body)
            for block in quoted_blocks:
                block_clean = re.sub(r"^>\s?", "", block, flags=re.M).strip()
                block_hash = hashlib.md5(block_clean.encode("utf-8", errors="replace")).hexdigest()
                if block_hash in existing_hashes:
                    body_new = body_new.replace(block, "").strip()

            # Remove "---Original Message---" blocks
            orig_pattern = re.compile(
                r"-{3,}\s*Original Message\s*-{3,}.*", re.I | re.DOTALL
            )
            m = orig_pattern.search(body_new)
            if m:
                body_new = body_new[:m.start()].strip()

            body_hash = hashlib.md5(
                body_new.encode("utf-8", errors="replace")
            ).hexdigest()

            # Determine position in chain
            timestamp = self._parse_date(email_data.get("date"))
            position = len(existing) + 1

            if timestamp:
                # Find correct insertion point
                for i, ex in enumerate(existing):
                    try:
                        ex_msg = conn.execute(
                            "SELECT email_date FROM email_messages WHERE id = ?",
                            (ex["id"],),
                        ).fetchone()
                        if ex_msg and ex_msg["email_date"]:
                            ex_time = datetime.fromisoformat(ex_msg["email_date"])
                            if timestamp < ex_time:
                                position = i + 1
                                break
                    except Exception:
                        continue

            # Shift existing messages at or after the insertion point
            if position <= len(existing):
                conn.execute(
                    "UPDATE email_messages SET position_in_chain = position_in_chain + 1 "
                    "WHERE chain_id = ? AND position_in_chain >= ?",
                    (chain_id, position),
                )

            conn.execute(
                """INSERT INTO email_messages
                   (chain_id, document_id, position_in_chain,
                    from_address, from_name, to_addresses, cc_addresses,
                    subject, email_date, body_text, body_new_text,
                    body_hash, has_attachments, is_quoted_content_stripped)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    chain_id,
                    document_id,
                    position,
                    email_data.get("from_address"),
                    email_data.get("from_name"),
                    json.dumps(email_data.get("to", [])),
                    json.dumps(email_data.get("cc", [])),
                    email_data.get("subject"),
                    timestamp.isoformat() if timestamp else None,
                    body,
                    body_new,
                    body_hash,
                    int(bool(email_data.get("has_attachments", False))),
                    int(body_new != body),
                ),
            )

            # Update chain metadata
            msg_count = conn.execute(
                "SELECT COUNT(*) FROM email_messages WHERE chain_id = ?",
                (chain_id,),
            ).fetchone()[0]

            all_participants = set()
            try:
                chain_row = conn.execute(
                    "SELECT participants FROM email_chains WHERE id = ?",
                    (chain_id,),
                ).fetchone()
                if chain_row and chain_row["participants"]:
                    all_participants = set(json.loads(chain_row["participants"]))
            except Exception:
                logger.debug("Failed to load chain participants", exc_info=True)
            if email_data.get("from_address"):
                all_participants.add(email_data["from_address"].lower())
            for a in email_data.get("to", []):
                m = EMAIL_ADDR_PATTERN.search(a)
                all_participants.add((m.group(0) if m else a).lower())

            conn.execute(
                """UPDATE email_chains
                   SET email_count = ?,
                       participants = ?,
                       first_email_date = COALESCE(
                           (SELECT MIN(email_date) FROM email_messages WHERE chain_id = ?),
                           first_email_date),
                       last_email_date = COALESCE(
                           (SELECT MAX(email_date) FROM email_messages WHERE chain_id = ?),
                           last_email_date),
                       analysis_completed = 0,
                       updated_at = ?
                   WHERE id = ?""",
                (
                    msg_count,
                    json.dumps(sorted(all_participants)),
                    chain_id,
                    chain_id,
                    datetime.now(tz=timezone.utc).isoformat(),
                    chain_id,
                ),
            )

            if own_conn:
                conn.commit()
        finally:
            if own_conn:
                conn.close()

    # ------------------------------------------------------------------
    def detect_gaps(self, chain_id: int, conn=None) -> List[Dict[str, Any]]:
        """Analyze timestamps for unnaturally long gaps suggesting missing emails."""
        own_conn = conn is None
        if own_conn:
            conn = self.db.get_connection()

        gaps: List[Dict[str, Any]] = []
        try:
            msgs = conn.execute(
                """SELECT id, email_date, from_name, subject
                   FROM email_messages
                   WHERE chain_id = ? AND email_date IS NOT NULL
                   ORDER BY email_date""",
                (chain_id,),
            ).fetchall()

            if len(msgs) < 2:
                return gaps

            from datetime import timedelta

            for i in range(len(msgs) - 1):
                try:
                    t1 = datetime.fromisoformat(msgs[i]["email_date"])
                    t2 = datetime.fromisoformat(msgs[i + 1]["email_date"])
                    delta = t2 - t1

                    # Flag gaps > 7 days as suspicious for active chains
                    if delta > timedelta(days=7):
                        gaps.append({
                            "after_message_id": msgs[i]["id"],
                            "before_message_id": msgs[i + 1]["id"],
                            "gap_days": delta.days,
                            "gap_start": msgs[i]["email_date"],
                            "gap_end": msgs[i + 1]["email_date"],
                            "severity": "high" if delta.days > 30 else "medium",
                        })
                except Exception:
                    continue

            return gaps
        finally:
            if own_conn:
                conn.close()

    # ------------------------------------------------------------------
    def _create_chain(
        self,
        fingerprint: Dict[str, Any],
        email_data: Dict[str, Any],
        document_id: int,
        conn,
    ) -> int:
        """Create a new email chain and add the first message."""
        timestamp = fingerprint.get("timestamp")
        cursor = conn.execute(
            """INSERT INTO email_chains
               (chain_identifier, normalized_subject, participants,
                email_count, first_email_date, last_email_date)
               VALUES (?, ?, ?, 0, ?, ?)""",
            (
                fingerprint["chain_hash"],
                fingerprint["normalized_subject"],
                json.dumps(fingerprint["participants"]),
                timestamp.isoformat() if timestamp else None,
                timestamp.isoformat() if timestamp else None,
            ),
        )
        chain_id = cursor.lastrowid

        # Add the message
        self.stitch(email_data, chain_id, document_id, conn)
        return chain_id

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
        """Try multiple date formats to parse email date strings."""
        if not date_str:
            return None
        date_str = date_str.strip()

        formats = [
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S",
            "%d %b %Y %H:%M:%S %z",
            "%d %b %Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M %p",
            "%m/%d/%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%B %d, %Y",
            "%b %d, %Y",
            "%d-%b-%Y",
            "%d-%b-%y",
        ]

        # Map common timezone abbreviations to UTC offsets before stripping
        _tz_offsets = {
            "EST": "-0500", "EDT": "-0400", "CST": "-0600", "CDT": "-0500",
            "MST": "-0700", "MDT": "-0600", "PST": "-0800", "PDT": "-0700",
            "GMT": "+0000", "UTC": "+0000", "BST": "+0100", "CET": "+0100",
            "CEST": "+0200", "JST": "+0900", "AEST": "+1000", "AEDT": "+1100",
        }
        cleaned = date_str
        tz_match = re.search(r"\s+\(?([A-Z]{2,5})\)?\s*$", cleaned)
        if tz_match:
            abbrev = tz_match.group(1)
            if abbrev not in ("AM", "PM"):
                offset = _tz_offsets.get(abbrev)
                if offset:
                    # Replace abbreviation with numeric offset so strptime %z works
                    cleaned = cleaned[:tz_match.start()] + " " + offset
                else:
                    # Unknown abbreviation — strip it (best-effort, treat as UTC)
                    cleaned = cleaned[:tz_match.start()]

        for fmt in formats:
            try:
                dt = datetime.strptime(cleaned, fmt)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(timezone.utc)
                return dt.replace(tzinfo=None)  # normalize to naive UTC
            except ValueError:
                continue
        return None


# ============================================================================
# 6. ENTITY EXTRACTOR
# ============================================================================
class EntityExtractor:
    """Extract persons, organizations, locations, and other entities from text."""

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.config = config
        self._nlp = None  # lazy-loaded spacy model

    @property
    def nlp(self):
        if self._nlp is None and _SPACY_AVAILABLE:
            try:
                self._nlp = spacy.load("en_core_web_sm")
            except OSError:
                log.warning(
                    "spaCy model 'en_core_web_sm' not found. "
                    "Run: python -m spacy download en_core_web_sm"
                )
                self._nlp = False  # sentinel: tried and failed
        return self._nlp if self._nlp is not False else None

    # ------------------------------------------------------------------
    def extract_entities(
        self, text: str, doc_type: Optional[str], document_id: int
    ) -> List[Dict[str, Any]]:
        """Find all entities in text using spaCy NER + custom regex patterns."""
        if not text:
            return []

        entities: List[Dict[str, Any]] = []
        seen_canonical: Dict[str, int] = {}  # canonical_name -> entity_id from this run

        # --- spaCy NER ---
        if self.nlp:
            try:
                # Process in chunks if text is very long
                max_len = 100000
                chunks = [text[i:i + max_len] for i in range(0, len(text), max_len)]
                for chunk in chunks:
                    doc_nlp = self.nlp(chunk)
                    for ent in doc_nlp.ents:
                        if ent.label_ in ("PERSON", "ORG", "GPE", "LOC", "FAC", "NORP"):
                            entity_type = {
                                "PERSON": "person",
                                "ORG": "organization",
                                "GPE": "location",
                                "LOC": "location",
                                "FAC": "location",
                                "NORP": "organization",
                            }.get(ent.label_, "person")

                            name = ent.text.strip()
                            if len(name) < 2 or len(name) > 200:
                                continue

                            canonical = self._canonicalize(name)
                            if canonical not in seen_canonical:
                                entities.append({
                                    "name": name,
                                    "entity_type": entity_type,
                                    "canonical_name": canonical,
                                    "context": text[max(0, ent.start_char - 100):ent.end_char + 100],
                                })
                                seen_canonical[canonical] = len(entities) - 1
            except Exception as exc:
                log.warning("spaCy NER error: %s", exc)

        # --- custom regex patterns ---

        # Phone numbers
        for m in PHONE_PATTERN.finditer(text):
            phone = m.group(0).strip()
            canonical = re.sub(r"[\s\-\(\)]", "", phone)
            if canonical not in seen_canonical:
                entities.append({
                    "name": phone,
                    "entity_type": "contact_info",
                    "canonical_name": canonical,
                    "context": text[max(0, m.start() - 50):m.end() + 50],
                })
                seen_canonical[canonical] = len(entities) - 1

        # Email addresses
        for m in EMAIL_ADDR_PATTERN.finditer(text):
            addr = m.group(0).lower()
            if addr not in seen_canonical:
                entities.append({
                    "name": addr,
                    "entity_type": "contact_info",
                    "canonical_name": addr,
                    "context": text[max(0, m.start() - 50):m.end() + 50],
                })
                seen_canonical[addr] = len(entities) - 1

        # Dollar amounts
        for m in DOLLAR_AMOUNT_PATTERN.finditer(text):
            amount = m.group(0)
            entities.append({
                "name": amount,
                "entity_type": "financial",
                "canonical_name": amount,
                "context": text[max(0, m.start() - 80):m.end() + 80],
            })

        # Account numbers
        for m in ACCOUNT_NUMBER_PATTERN.finditer(text):
            acct = m.group(1)
            canonical = f"ACCT:{acct}"
            if canonical not in seen_canonical:
                entities.append({
                    "name": f"Account {acct}",
                    "entity_type": "financial",
                    "canonical_name": canonical,
                    "context": text[max(0, m.start() - 50):m.end() + 50],
                })
                seen_canonical[canonical] = len(entities) - 1

        # Case numbers
        for m in CASE_REF_PATTERN.finditer(text):
            case_num = m.group(0).strip()
            canonical = re.sub(r"\s+", " ", case_num).upper()
            if canonical not in seen_canonical:
                entities.append({
                    "name": case_num,
                    "entity_type": "legal_case",
                    "canonical_name": canonical,
                    "context": text[max(0, m.start() - 80):m.end() + 80],
                })
                seen_canonical[canonical] = len(entities) - 1

        # Flight tail numbers (N-numbers)
        for m in FLIGHT_TAIL_PATTERN.finditer(text):
            tail = m.group(0)
            if tail not in seen_canonical:
                entities.append({
                    "name": tail,
                    "entity_type": "aircraft",
                    "canonical_name": tail,
                    "context": text[max(0, m.start() - 80):m.end() + 80],
                })
                seen_canonical[tail] = len(entities) - 1

        # Addresses
        for m in ADDRESS_PATTERN.finditer(text):
            addr = m.group(0).strip()
            canonical = re.sub(r"\s+", " ", addr).upper()
            if canonical not in seen_canonical:
                entities.append({
                    "name": addr,
                    "entity_type": "location",
                    "canonical_name": canonical,
                    "context": text[max(0, m.start() - 50):m.end() + 50],
                })
                seen_canonical[canonical] = len(entities) - 1

        # --- Save entities to database ---
        self._save_entities(entities, document_id)

        log.info("Entity extraction: found %d entities (doc_id=%d)", len(entities), document_id)
        return entities

    # ------------------------------------------------------------------
    def _save_entities(self, entities: List[Dict], document_id: int):
        """Persist entities and link them to the document."""
        conn = self.db.get_connection()
        try:
            for ent in entities:
                canonical = ent["canonical_name"]
                etype = ent["entity_type"]

                # Check if entity already exists (dedup by canonical_name + type)
                existing = conn.execute(
                    "SELECT id FROM entities WHERE canonical_name = ? AND entity_type = ?",
                    (canonical, etype),
                ).fetchone()

                if existing:
                    entity_id = existing["id"]
                    # Increment document count
                    conn.execute(
                        "UPDATE entities SET document_count = document_count + 1, updated_at = ? WHERE id = ?",
                        (datetime.now(tz=timezone.utc).isoformat(), entity_id),
                    )
                else:
                    # Generate external links
                    google_url = self._google_search_url(ent["name"])
                    wikipedia_url = self._wikipedia_url(ent["name"]) if etype == "person" else None

                    cursor = conn.execute(
                        """INSERT INTO entities
                           (name, entity_type, canonical_name,
                            google_url, wikipedia_url,
                            document_count, first_seen_document_id)
                           VALUES (?, ?, ?, ?, ?, 1, ?)""",
                        (
                            ent["name"],
                            etype,
                            canonical,
                            google_url,
                            wikipedia_url,
                            document_id,
                        ),
                    )
                    entity_id = cursor.lastrowid

                # Link entity to document
                context_snippet = ent.get("context", "")[:500]
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO entity_document_links
                           (entity_id, document_id, context_snippet, mention_type)
                           VALUES (?, ?, ?, 'mentioned')""",
                        (entity_id, document_id, context_snippet),
                    )
                except Exception:
                    pass  # unique constraint violation is fine

            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    @staticmethod
    def _canonicalize(name: str) -> str:
        """Normalize a name for deduplication."""
        name = name.strip()
        # Remove titles
        name = re.sub(
            r"^(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Hon\.?|Sen\.?|Rep\.?|Gov\.?|Pres\.?)\s+",
            "", name, flags=re.I,
        )
        # Normalize whitespace
        name = re.sub(r"\s+", " ", name).strip()
        # Uppercase for consistency with knowledge_graph.normalize_name()
        name = name.upper()
        return name

    @staticmethod
    def _google_search_url(name: str) -> str:
        q = urllib.parse.quote_plus(f"{name} Epstein")
        return f"https://www.google.com/search?q={q}"

    @staticmethod
    def _wikipedia_url(name: str) -> Optional[str]:
        slug = name.strip().replace(" ", "_")
        return f"https://en.wikipedia.org/wiki/{urllib.parse.quote(slug)}"


# ============================================================================
# 7. PRIORITY SCORER
# ============================================================================
class PriorityScorer:
    """Calculate 0-100 priority score for each document."""

    def __init__(self, db: DatabaseManager, config: dict):
        self.db = db
        self.cfg = config.get("processor", {}).get("priority_scoring", {})
        self.threshold = self.cfg.get("priority_threshold", 60)

    # ------------------------------------------------------------------
    def score_document(self, document_id: int) -> int:
        """Calculate and save priority score. Returns the score."""
        conn = self.db.get_connection()
        try:
            score = 0

            # Get document record
            doc = conn.execute(
                "SELECT * FROM documents WHERE id = ?", (document_id,)
            ).fetchone()
            if not doc:
                return 0

            # Get full text
            pages = conn.execute(
                "SELECT text_content FROM document_pages WHERE document_id = ?",
                (document_id,),
            ).fetchall()
            full_text = "\n".join(
                (p["text_content"] or "") for p in pages
            ).lower()

            # --- REMOVED from source: highest priority ---
            if doc["is_removed_from_source"]:
                score += self.cfg.get("removed_file_weight", 50)

            # --- High-value names ---
            name_bonus = 0
            for name in HIGH_VALUE_NAMES:
                if name in full_text:
                    name_bonus = self.cfg.get("high_value_names_weight", 30)
                    break
            score += name_bonus

            # --- Contains redactions ---
            redaction_count = conn.execute(
                "SELECT COUNT(*) FROM redactions WHERE document_id = ?",
                (document_id,),
            ).fetchone()[0]
            if redaction_count > 0:
                score += self.cfg.get("redaction_weight", 20)

            # --- Email with attachments ---
            if doc["doc_type"] == "email":
                has_attachment = conn.execute(
                    "SELECT COUNT(*) FROM email_messages WHERE document_id = ? AND has_attachments = 1",
                    (document_id,),
                ).fetchone()[0]
                if has_attachment > 0:
                    score += self.cfg.get("email_attachment_weight", 15)

            # --- Financial references ---
            financial_found = False
            for pat in FINANCIAL_PATTERNS:
                if pat.search(full_text):
                    financial_found = True
                    break
            if financial_found:
                score += self.cfg.get("financial_weight", 15)

            # --- Location mentions ---
            location_found = False
            for loc in ISLAND_AND_PROPERTY_KEYWORDS:
                if loc in full_text:
                    location_found = True
                    break
            if location_found:
                score += self.cfg.get("location_weight", 10)

            # --- Case references ---
            if CASE_REF_PATTERN.search(full_text):
                score += self.cfg.get("case_reference_weight", 10)

            # --- Codeword / euphemism detection ---
            codewords_found = []
            for pat in CODEWORD_PATTERNS:
                m = pat.search(full_text)
                if m:
                    codewords_found.append(m.group(0))
            if codewords_found:
                score += self.cfg.get("codeword_weight", 25)
                log.info(
                    "CODEWORD detected in doc_id=%d '%s': %s",
                    document_id, doc["original_filename"],
                    ", ".join(codewords_found[:10]),
                )

            # Cap at 100
            score = min(score, 100)

            # Save score
            conn.execute(
                "UPDATE documents SET priority_score = ?, updated_at = ? WHERE id = ?",
                (score, datetime.now(tz=timezone.utc).isoformat(), document_id),
            )
            conn.commit()

            if score >= self.threshold:
                log.info(
                    "HIGH PRIORITY document (score=%d, threshold=%d): doc_id=%d '%s'",
                    score, self.threshold, document_id, doc["original_filename"],
                )

            return score
        finally:
            conn.close()


# ============================================================================
# PROCESSOR ENGINE (orchestrator)
# ============================================================================
class ProcessorEngine:
    """Orchestrate the full document processing pipeline."""

    def __init__(self, config: Optional[dict] = None, progress_cb: Optional[Callable] = None):
        self.config = config or _load_config()
        self.db = DatabaseManager()
        self.progress_cb = progress_cb

        # Initialize sub-engines
        self.ocr = OCREngine(self.db, self.config)
        self.classifier = DocumentClassifier()
        self.redaction_forensics = RedactionForensics(self.db, self.config)
        self.image_forensics = ImageForensics(self.db, self.config)
        self.email_stitcher = EmailChainStitcher(self.db, self.config)
        self.entity_extractor = EntityExtractor(self.db, self.config)
        self.priority_scorer = PriorityScorer(self.db, self.config)

    # ------------------------------------------------------------------
    def process_document(
        self,
        file_path: str,
        dataset_id: Optional[int] = None,
        document_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run the full pipeline on a single document.

        Pipeline order:
            OCR -> Classify -> Redaction Forensics -> Image Forensics
            -> Entity Extract -> Chain Stitch (if email) -> Priority Score
        """
        file_path = str(Path(file_path).resolve())
        result: Dict[str, Any] = {"file_path": file_path, "stages": {}}
        t_start = time.time()

        log.info("=" * 60)
        log.info("PROCESSING: %s", file_path)
        log.info("=" * 60)

        # --- ensure document record exists ---
        if document_id is None:
            document_id = self._ensure_document(file_path, dataset_id)
        result["document_id"] = document_id

        had_errors = False

        # --- 1. OCR ---
        self._notify("Starting OCR...")
        try:
            page_results = self.ocr.process_pdf(file_path, document_id, self.progress_cb)
            result["stages"]["ocr"] = {
                "pages": len(page_results),
                "avg_confidence": round(
                    sum(p["ocr_confidence"] for p in page_results) / max(len(page_results), 1), 3
                ),
            }
        except Exception as exc:
            log.error("OCR failed: %s", exc)
            result["stages"]["ocr"] = {"error": str(exc)}
            page_results = []
            had_errors = True

        # Guard: process_pdf may return [] without raising (e.g. fitz.open fails)
        if not page_results and not had_errors:
            log.error("OCR returned 0 pages for %s — treating as failure", file_path)
            result["stages"]["ocr"] = {"error": "OCR returned 0 pages"}
            had_errors = True

        # Combine all text
        full_text = "\n".join(p.get("text_content", "") or "" for p in page_results)

        # --- 2. Classify ---
        self._notify("Classifying document...")
        try:
            classification = self.classifier.classify(
                full_text, {"filename": Path(file_path).name}
            )
            doc_type = classification["doc_type"]
            result["stages"]["classify"] = classification

            # Update document record
            conn = self.db.get_connection()
            try:
                conn.execute(
                    "UPDATE documents SET doc_type = ?, updated_at = ? WHERE id = ?",
                    (doc_type, datetime.now(tz=timezone.utc).isoformat(), document_id),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:
            log.error("Classification failed: %s", exc)
            classification = {"doc_type": "unknown"}
            doc_type = "unknown"
            result["stages"]["classify"] = {"error": str(exc)}
            had_errors = True

        # --- 3. Redaction Forensics ---
        self._notify("Running redaction forensics...")
        try:
            redactions = self.redaction_forensics.detect_redactions(
                file_path, document_id, page_results, self.progress_cb
            )
            result["stages"]["redaction_forensics"] = {
                "total_redactions": len(redactions),
                "recovered": sum(1 for r in redactions if r["is_recovered"]),
                "methods": list({r["recovery_method"] for r in redactions if r["is_recovered"]}),
            }
        except Exception as exc:
            log.error("Redaction forensics failed: %s", exc)
            result["stages"]["redaction_forensics"] = {"error": str(exc)}
            had_errors = True

        # --- 4. Image Forensics ---
        self._notify("Running image forensics...")
        try:
            images = self.image_forensics.process_document_images(
                file_path, document_id, self.progress_cb
            )
            result["stages"]["image_forensics"] = {
                "images_found": len(images),
                "with_redactions": sum(1 for i in images if i.get("has_redactions")),
                "recovered": sum(1 for i in images if i.get("recovery_successful")),
                "quarantined": sum(1 for i in images if i.get("quarantined")),
            }
        except Exception as exc:
            log.error("Image forensics failed: %s", exc)
            result["stages"]["image_forensics"] = {"error": str(exc)}
            had_errors = True

        # --- 5. Entity Extraction ---
        self._notify("Extracting entities...")
        try:
            entities = self.entity_extractor.extract_entities(
                full_text, doc_type, document_id
            )
            result["stages"]["entity_extraction"] = {
                "total_entities": len(entities),
                "by_type": dict(self._count_by_key(entities, "entity_type")),
            }
        except Exception as exc:
            log.error("Entity extraction failed: %s", exc)
            result["stages"]["entity_extraction"] = {"error": str(exc)}
            had_errors = True

        # --- 6. Email Chain Stitching (only for emails) ---
        if doc_type == "email" and classification.get("email_data"):
            self._notify("Stitching email chains...")
            try:
                chain_result = self.email_stitcher.on_new_email(
                    classification["email_data"], document_id
                )
                result["stages"]["email_chain"] = chain_result
            except Exception as exc:
                log.error("Email chain stitching failed: %s", exc)
                result["stages"]["email_chain"] = {"error": str(exc)}
                had_errors = True

            # Update entity mention_type for email senders/recipients
            try:
                edata = classification["email_data"]
                self._tag_email_entity_roles(edata, document_id)
            except Exception as exc:
                log.debug("Email entity role tagging failed: %s", exc)

        # --- 7. Priority Scoring ---
        self._notify("Calculating priority score...")
        try:
            score = self.priority_scorer.score_document(document_id)
            result["stages"]["priority_score"] = score
        except Exception as exc:
            log.error("Priority scoring failed: %s", exc)
            result["stages"]["priority_score"] = {"error": str(exc)}
            had_errors = True

        # --- mark complete ---
        elapsed = round(time.time() - t_start, 2)
        result["elapsed_seconds"] = elapsed

        conn = self.db.get_connection()
        try:
            if had_errors:
                conn.execute(
                    """UPDATE documents
                       SET status = 'error', updated_at = ?
                       WHERE id = ?""",
                    (datetime.now(tz=timezone.utc).isoformat(), document_id),
                )
            else:
                conn.execute(
                    """UPDATE documents
                       SET analysis_completed = 1, status = 'analyzed', updated_at = ?
                       WHERE id = ?""",
                    (datetime.now(tz=timezone.utc).isoformat(), document_id),
                )
            conn.commit()
        finally:
            conn.close()

        self.db.log_action(
            "process_document",
            f"Processed doc_id={document_id} in {elapsed}s, errors={had_errors}, priority={result['stages'].get('priority_score', '?')}",
            user_initiated=False,
        )

        log.info("DONE in %.1fs: doc_id=%d priority=%s", elapsed, document_id, result["stages"].get("priority_score", "?"))
        return result

    # ------------------------------------------------------------------
    def process_dataset(
        self, dataset_number: int
    ) -> Dict[str, Any]:
        """Process all documents in a dataset."""
        conn = self.db.get_connection()
        try:
            dataset = conn.execute(
                "SELECT * FROM datasets WHERE dataset_number = ?",
                (dataset_number,),
            ).fetchone()
            if not dataset:
                log.error("Dataset %d not found", dataset_number)
                return {"error": f"Dataset {dataset_number} not found"}

            dataset_id = dataset["id"]
            docs = conn.execute(
                "SELECT id, file_path FROM documents WHERE dataset_id = ? AND analysis_completed = 0",
                (dataset_id,),
            ).fetchall()
        finally:
            conn.close()

        total = len(docs)
        log.info("Processing dataset %d: %d documents to process", dataset_number, total)

        # Update dataset status
        conn = self.db.get_connection()
        try:
            conn.execute(
                "UPDATE datasets SET status = 'processing', updated_at = ? WHERE id = ?",
                (datetime.now(tz=timezone.utc).isoformat(), dataset_id),
            )
            conn.commit()
        finally:
            conn.close()

        results = []
        for idx, doc in enumerate(docs):
            log.info("[%d/%d] Processing doc_id=%d", idx + 1, total, doc["id"])
            if self.progress_cb:
                self.progress_cb("dataset", idx + 1, total)

            try:
                r = self.process_document(
                    doc["file_path"], dataset_id=dataset_id, document_id=doc["id"]
                )
                results.append(r)
            except Exception as exc:
                log.error("Failed to process doc_id=%d: %s", doc["id"], exc)
                results.append({"document_id": doc["id"], "error": str(exc)})

        # Update dataset status
        conn = self.db.get_connection()
        try:
            conn.execute(
                """UPDATE datasets
                   SET status = 'processed',
                       processed_files = ?,
                       processed_at = ?,
                       updated_at = ?
                   WHERE id = ?""",
                (len(results), datetime.now(tz=timezone.utc).isoformat(), datetime.now(tz=timezone.utc).isoformat(), dataset_id),
            )
            conn.commit()
        finally:
            conn.close()

        summary = {
            "dataset_number": dataset_number,
            "total_documents": total,
            "processed": len(results),
            "errors": sum(1 for r in results if "error" in r),
            "high_priority": sum(
                1 for r in results
                if isinstance(r.get("stages", {}).get("priority_score"), int)
                and r["stages"]["priority_score"] >= self.priority_scorer.threshold
            ),
        }
        log.info("Dataset %d complete: %s", dataset_number, json.dumps(summary, indent=2))
        return summary

    # ------------------------------------------------------------------
    def _ensure_document(self, file_path: str, dataset_id: Optional[int]) -> int:
        """Ensure document record exists, create if not. Returns document_id."""
        file_path = str(Path(file_path).resolve())
        # Stream hash computation to avoid loading entire file into memory
        sha256 = hashlib.sha256()
        file_size = 0
        with open(file_path, "rb") as fh:
            while chunk := fh.read(65536):
                sha256.update(chunk)
                file_size += len(chunk)
        file_hash = sha256.hexdigest()
        filename = Path(file_path).name

        conn = self.db.get_connection()
        try:
            existing = conn.execute(
                "SELECT id, file_path FROM documents WHERE file_hash = ?", (file_hash,)
            ).fetchone()
            if existing:
                if existing["file_path"] != file_path:
                    conn.execute(
                        "UPDATE documents SET file_path = ? WHERE id = ?",
                        (file_path, existing["id"]),
                    )
                    conn.commit()
                return existing["id"]

            # Determine file type
            ext = Path(file_path).suffix.lower()
            file_type_map = {
                ".pdf": "pdf",
                ".jpg": "image", ".jpeg": "image", ".png": "image",
                ".tif": "image", ".tiff": "image", ".bmp": "image",
                ".gif": "image",
                ".mp4": "video", ".avi": "video", ".mov": "video",
                ".mp3": "audio", ".wav": "audio",
                ".txt": "text", ".csv": "text", ".json": "text",
            }
            file_type = file_type_map.get(ext, "other")

            source = "local"
            if dataset_id:
                ds = conn.execute(
                    "SELECT source FROM datasets WHERE id = ?", (dataset_id,)
                ).fetchone()
                if ds:
                    source = ds["source"]

            cursor = conn.execute(
                """INSERT INTO documents
                   (dataset_id, file_hash, original_filename, file_path,
                    file_type, size_bytes, source, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'ocr_processing')""",
                (dataset_id, file_hash, filename, file_path, file_type, file_size, source),
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    # ------------------------------------------------------------------
    def _tag_email_entity_roles(self, email_data: Dict, document_id: int):
        """Update entity_document_links mention_type for email sender/recipients."""
        from_name = (email_data.get("from_name") or "").upper().strip()
        from_addr = (email_data.get("from_address") or "").upper().strip()
        to_raw = email_data.get("to", [])
        cc_raw = email_data.get("cc", [])

        recipient_names: set[str] = set()
        for addr_str in to_raw + cc_raw:
            recipient_names.add(addr_str.upper().strip())

        conn = self.db.get_connection()
        try:
            links = conn.execute(
                """SELECT edl.id, e.canonical_name
                   FROM entity_document_links edl
                   JOIN entities e ON e.id = edl.entity_id
                   WHERE edl.document_id = ? AND edl.mention_type = 'mentioned'""",
                (document_id,),
            ).fetchall()
            for link in links:
                cname = link["canonical_name"]
                if cname and (cname == from_name or cname == from_addr):
                    conn.execute(
                        "UPDATE entity_document_links SET mention_type = 'author' WHERE id = ?",
                        (link["id"],),
                    )
                elif cname and any(cname in rn for rn in recipient_names):
                    conn.execute(
                        "UPDATE entity_document_links SET mention_type = 'recipient' WHERE id = ?",
                        (link["id"],),
                    )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    def _notify(self, message: str):
        log.info(message)
        if self.progress_cb:
            self.progress_cb("status", 0, 0, message)

    @staticmethod
    def _count_by_key(items: List[Dict], key: str) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for item in items:
            counts[item.get(key, "unknown")] += 1
        return counts


# ============================================================================
# CLI ENTRY POINT
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="EpsteinAnalyzer Document Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
    python -m processor.processor --dataset 1
    python -m processor.processor --document path/to/file.pdf
    python -m processor.processor --document file.pdf --verbose
""",
    )
    parser.add_argument(
        "--dataset", type=int, help="Dataset number to process"
    )
    parser.add_argument(
        "--document", type=str, help="Path to single document to process"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.dataset and not args.document:
        parser.error("Provide either --dataset or --document")

    # Progress callback for CLI
    def cli_progress(stage: str, current: int, total: int, message: str = ""):
        if total > 0:
            pct = int(current / total * 100)
            bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct:3d}% {stage}: {current}/{total} {message}", end="", flush=True)
            if current == total:
                print()
        elif message:
            print(f"  >> {message}")

    engine = ProcessorEngine(progress_cb=cli_progress)

    # Ensure DB is initialized
    engine.db.initialize()

    if args.document:
        doc_path = Path(args.document).resolve()
        if not doc_path.exists():
            print(f"ERROR: File not found: {doc_path}")
            sys.exit(1)
        result = engine.process_document(str(doc_path))
        print("\n" + "=" * 60)
        print("PROCESSING RESULT")
        print("=" * 60)
        print(json.dumps(result, indent=2, default=str))

    elif args.dataset:
        result = engine.process_dataset(args.dataset)
        print("\n" + "=" * 60)
        print("DATASET PROCESSING SUMMARY")
        print("=" * 60)
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
