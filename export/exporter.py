"""
EpsteinAnalyzer - Export Module
===============================
Handles all export functionality:
  1. RedditExporter      - Generate formatted Reddit posts from findings
  2. PublicViewerExporter - Export knowledge graph data for the static public viewer
  3. ImageRedactionExporter - Apply redactions to images before export
  4. ExportManager        - CLI orchestrator for all export operations

Usage (CLI):
    python -m export.exporter reddit --entity 42 --template default
    python -m export.exporter viewer --output ./public_viewer/data
    python -m export.exporter images --quarantine-check
    python -m export.exporter full --output ./dist

Dependencies:
    - Pillow (PIL) for image redaction
    - pyyaml for config
    - sqlite3 (stdlib) for database access
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import textwrap
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import sys

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.db import DatabaseManager

logger = logging.getLogger("export.exporter")

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _json_loads_safe(text: Optional[str], default=None):
    """Parse a JSON string, returning *default* on any failure."""
    if text is None:
        return default if default is not None else []
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a numeric value between lo and hi."""
    return max(lo, min(hi, value))


def _load_config(config_path: Optional[str] = None) -> dict:
    """Load the project settings.yaml."""
    import yaml

    if config_path is None:
        config_path = _PROJECT_ROOT / "config" / "settings.yaml"
    with open(config_path, "r") as fh:
        return yaml.safe_load(fh)


def _sanitize_filename(name: str) -> str:
    """Remove characters unsafe for filenames."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip()


def _truncate(text: str, max_len: int = 300) -> str:
    """Truncate text to max_len characters with ellipsis."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _score_to_label(score: float) -> str:
    """Human-readable label for an implication score."""
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 25:
        return "LOW"
    return "MINIMAL"


def _score_to_color(score: float) -> str:
    """CSS hex colour for a score level."""
    if score >= 75:
        return "#e63946"
    if score >= 50:
        return "#f4a261"
    if score >= 25:
        return "#e9c46a"
    return "#999999"


def _entity_type_emoji(entity_type: str) -> str:
    """Map entity type to a Unicode emoji for Reddit formatting."""
    mapping = {
        "person": "\U0001f464",       # bust in silhouette
        "organization": "\U0001f3e2", # office building
        "location": "\U0001f4cd",     # round pushpin
        "aircraft": "\u2708\ufe0f",   # airplane
        "financial": "\U0001f4b0",    # money bag
        "legal_case": "\u2696\ufe0f", # balance scale
        "contact_info": "\U0001f4de", # telephone receiver
        "event": "\U0001f4c5",        # calendar
        "redacted_entity": "\u2588",  # full block
    }
    return mapping.get(entity_type, "\u2022")


# ===================================================================
# 1. RedditExporter
# ===================================================================

# Default Reddit Markdown templates keyed by subreddit style.

_REDDIT_TEMPLATES: Dict[str, Dict[str, str]] = {
    "default": {
        "post_title": "[EpsteinAnalyzer] Evidence Summary: {entity_name}",
        "post_header": (
            "# {entity_name}\n\n"
            "**Type:** {entity_type} | **Implication Score:** {score}/100 ({score_label})\n\n"
            "**Evidence Items:** {evidence_count} | **Documents:** {document_count} | "
            "**Direct Connections:** {connection_count}\n\n"
            "---\n\n"
        ),
        "evidence_section": (
            "## Top Evidence\n\n"
            "{evidence_items}\n\n"
            "---\n\n"
        ),
        "evidence_item": (
            "- **[{doc_type}]** {context} "
            "*(Score: {damning_score}, Source: {source})*\n"
        ),
        "connections_section": (
            "## Key Connections\n\n"
            "{connection_items}\n\n"
            "---\n\n"
        ),
        "connection_item": (
            "- {emoji} **{other_name}** ({other_type}) "
            "\u2014 *{rel_type}* (weight: {weight:.1f}, evidence: {evidence_count})\n"
        ),
        "timeline_section": (
            "## Timeline\n\n"
            "{timeline_items}\n\n"
        ),
        "timeline_item": "- **{date}** \u2014 {doc_type}: {context}\n",
        "footer": (
            "---\n\n"
            "*Generated by EpsteinAnalyzer v{version} on {generated_at}. "
            "All data sourced from publicly released court documents and FOIA disclosures. "
            "This is an automated summary \u2014 always verify against primary sources.*\n"
        ),
    },
    "r/Epstein": {
        "post_title": "{entity_name} \u2014 Evidence Summary ({score_label})",
        "post_header": (
            "# \U0001f50d {entity_name}\n\n"
            "| Metric | Value |\n"
            "|--------|-------|\n"
            "| Type | {entity_type} |\n"
            "| Implication Score | **{score}/100** ({score_label}) |\n"
            "| Evidence Items | {evidence_count} |\n"
            "| Documents | {document_count} |\n"
            "| Connections | {connection_count} |\n\n"
            "---\n\n"
        ),
        "evidence_section": (
            "## \U0001f4cb Evidence Chain\n\n"
            "{evidence_items}\n\n"
            "---\n\n"
        ),
        "evidence_item": (
            "{index}. **[{doc_type}]** {context}\n"
            "   - Damning Score: {damning_score}/100\n"
            "   - Source: {source}\n"
            "   - Document: `{filename}`\n\n"
        ),
        "connections_section": (
            "## \U0001f578\ufe0f Network Connections\n\n"
            "{connection_items}\n\n"
            "---\n\n"
        ),
        "connection_item": (
            "- {emoji} **{other_name}** ({other_type}) "
            "\u2014 {rel_type} *(weight: {weight:.1f})*\n"
        ),
        "timeline_section": (
            "## \U0001f4c5 Activity Timeline\n\n"
            "{timeline_items}\n\n"
        ),
        "timeline_item": "| {date} | {doc_type} | {context} |\n",
        "footer": (
            "\n---\n\n"
            "^(Generated by EpsteinAnalyzer v{version} on {generated_at}. "
            "All data from public DOJ releases, court filings, and FOIA documents.)\n"
        ),
    },
    "r/conspiracy": {
        "post_title": "Evidence deep-dive: {entity_name} ({score_label} implication)",
        "post_header": (
            "# {entity_name}\n\n"
            "**Score: {score}/100** | {evidence_count} evidence items | "
            "{connection_count} connections\n\n"
            "All data below comes from publicly released DOJ documents, "
            "court filings, and FOIA releases. Sources cited.\n\n"
            "---\n\n"
        ),
        "evidence_section": (
            "## Evidence\n\n"
            "{evidence_items}\n\n"
            "---\n\n"
        ),
        "evidence_item": (
            "- [{doc_type}] {context} (Score: {damning_score}) "
            "*\u2014 {source}*\n"
        ),
        "connections_section": (
            "## Connected Entities\n\n"
            "{connection_items}\n\n"
            "---\n\n"
        ),
        "connection_item": (
            "- {other_name} ({other_type}) \u2014 {rel_type}\n"
        ),
        "timeline_section": (
            "## Timeline\n\n"
            "{timeline_items}\n\n"
        ),
        "timeline_item": "- {date}: {doc_type} \u2014 {context}\n",
        "footer": (
            "---\n\n"
            "*Auto-generated from EpsteinAnalyzer. Verify everything against "
            "primary sources. v{version} | {generated_at}*\n"
        ),
    },
}


class RedditExporter:
    """Generate formatted Reddit posts and comment threads from analysis data.

    Supports multiple subreddit templates, custom redaction of sensitive
    content, and structured evidence summaries.
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: Optional[dict] = None,
        template_name: str = "default",
    ):
        self.db = db
        self.config = config or _load_config()
        self.export_config = self.config.get("export", {}).get("reddit", {})
        self.version = self.config.get("project", {}).get("version", "1.0.0")
        self.strip_victim_names: bool = self.export_config.get("strip_victim_names", True)
        self.require_review: bool = self.export_config.get("require_review", True)
        self._template = self._resolve_template(template_name)
        self._custom_redactions: List[str] = []

    # ------------------------------------------------------------------
    # Template management
    # ------------------------------------------------------------------

    @staticmethod
    def available_templates() -> List[str]:
        """Return the names of all built-in templates."""
        return list(_REDDIT_TEMPLATES.keys())

    def _resolve_template(self, name: str) -> Dict[str, str]:
        """Look up a template by name, falling back to *default*."""
        return _REDDIT_TEMPLATES.get(name, _REDDIT_TEMPLATES["default"])

    def set_template(self, template_name: str) -> None:
        """Switch to a different template at runtime."""
        self._template = self._resolve_template(template_name)

    def add_custom_redaction(self, pattern: str) -> None:
        """Register a regex or literal string to be redacted from all output."""
        self._custom_redactions.append(pattern)

    def _apply_redactions(self, text: str) -> str:
        """Strip victim names and custom redactions from the text."""
        if not text:
            return text

        # Strip victim names from the database
        if self.strip_victim_names:
            conn = self.db.get_connection()
            try:
                victims = conn.execute(
                    "SELECT name, canonical_name, aliases FROM entities "
                    "WHERE is_victim = 1 OR is_minor = 1"
                ).fetchall()
                for v in victims:
                    text = text.replace(v["name"], "[REDACTED-VICTIM]")
                    if v["canonical_name"]:
                        text = text.replace(v["canonical_name"], "[REDACTED-VICTIM]")
                    for alias in _json_loads_safe(v["aliases"]):
                        text = text.replace(alias, "[REDACTED-VICTIM]")
            finally:
                conn.close()

        # Custom redactions
        for pattern in self._custom_redactions:
            try:
                text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
            except re.error:
                # Treat as a literal string if regex compilation fails
                text = text.replace(pattern, "[REDACTED]")

        return text

    # ------------------------------------------------------------------
    # Data fetching helpers
    # ------------------------------------------------------------------

    def _fetch_entity(self, entity_id: int) -> Optional[Dict[str, Any]]:
        """Fetch full entity record from the database."""
        conn = self.db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if row is None:
                return None
            entity = dict(row)
            entity["aliases"] = _json_loads_safe(entity.get("aliases"))
            return entity
        finally:
            conn.close()

    def _fetch_top_evidence(
        self, entity_id: int, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Top evidence items sorted by damning_score descending."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT edl.*, d.original_filename, d.doc_type, d.source
                   FROM entity_document_links edl
                   JOIN documents d ON d.id = edl.document_id
                   WHERE edl.entity_id = ?
                   ORDER BY edl.damning_score DESC
                   LIMIT ?""",
                (entity_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _fetch_connections(
        self, entity_id: int, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Relationships for an entity with the connected entity name."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT r.*,
                          CASE WHEN r.source_entity_id = ? THEN et.name ELSE es.name END AS other_name,
                          CASE WHEN r.source_entity_id = ? THEN et.entity_type ELSE es.entity_type END AS other_type,
                          CASE WHEN r.source_entity_id = ? THEN et.id ELSE es.id END AS other_id
                   FROM relationships r
                   JOIN entities es ON es.id = r.source_entity_id
                   JOIN entities et ON et.id = r.target_entity_id
                   WHERE r.source_entity_id = ? OR r.target_entity_id = ?
                   ORDER BY r.weight DESC
                   LIMIT ?""",
                (entity_id, entity_id, entity_id, entity_id, entity_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _fetch_timeline(
        self, entity_id: int, limit: int = 15
    ) -> List[Dict[str, Any]]:
        """Chronological evidence events."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT edl.context_snippet, edl.created_at, edl.damning_score,
                          d.doc_type, d.source, d.original_filename,
                          em.email_date, em.subject
                   FROM entity_document_links edl
                   JOIN documents d ON d.id = edl.document_id
                   LEFT JOIN email_messages em ON em.document_id = d.id
                   WHERE edl.entity_id = ?
                   ORDER BY COALESCE(em.email_date, edl.created_at) ASC
                   LIMIT ?""",
                (entity_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_post(
        self,
        entity_id: int,
        *,
        max_evidence: int = 10,
        max_connections: int = 15,
        max_timeline: int = 10,
        include_timeline: bool = True,
    ) -> Dict[str, str]:
        """Generate a complete Reddit post for a single entity.

        Returns a dict with keys ``title`` and ``body``.
        Applies all configured redactions before returning.
        """
        entity = self._fetch_entity(entity_id)
        if entity is None:
            return {"title": "", "body": f"Entity {entity_id} not found."}

        # Block export of victims
        if entity.get("is_victim") or entity.get("is_minor"):
            return {
                "title": "",
                "body": "Export blocked: entity is flagged as a victim or minor.",
            }

        score = entity.get("implication_score") or 0
        score_label = _score_to_label(score)
        evidence = self._fetch_top_evidence(entity_id, max_evidence)
        connections = self._fetch_connections(entity_id, max_connections)
        timeline = self._fetch_timeline(entity_id, max_timeline) if include_timeline else []

        tpl = self._template

        # --- Build title ---
        title = tpl["post_title"].format(
            entity_name=entity["name"],
            entity_type=entity["entity_type"],
            score=score,
            score_label=score_label,
        )

        # --- Build header ---
        body = tpl["post_header"].format(
            entity_name=entity["name"],
            entity_type=entity["entity_type"],
            score=score,
            score_label=score_label,
            evidence_count=entity.get("evidence_count") or len(evidence),
            document_count=entity.get("document_count") or 0,
            connection_count=len(connections),
        )

        # --- Evidence section ---
        evidence_lines = ""
        for idx, ev in enumerate(evidence, 1):
            context = _truncate(ev.get("context_snippet") or "(no context)", 200)
            evidence_lines += tpl["evidence_item"].format(
                index=idx,
                doc_type=(ev.get("doc_type") or "unknown").upper(),
                context=context,
                damning_score=ev.get("damning_score") or 0,
                source=ev.get("source") or "unknown",
                filename=ev.get("original_filename") or "",
            )
        if evidence_lines:
            body += tpl["evidence_section"].format(evidence_items=evidence_lines.rstrip())

        # --- Connections section ---
        conn_lines = ""
        for conn_row in connections:
            other_type = conn_row.get("other_type") or "unknown"
            emoji = _entity_type_emoji(other_type)
            conn_lines += tpl["connection_item"].format(
                emoji=emoji,
                other_name=conn_row.get("other_name") or "Unknown",
                other_type=other_type,
                rel_type=(conn_row.get("relationship_type") or "associated_with").replace("_", " "),
                weight=conn_row.get("weight") or 1.0,
                evidence_count=conn_row.get("evidence_count") or 0,
            )
        if conn_lines:
            body += tpl["connections_section"].format(connection_items=conn_lines.rstrip())

        # --- Timeline section ---
        if timeline and include_timeline:
            tl_lines = ""
            # If the template uses a table header for r/Epstein style, add it
            if "| {date}" in tpl["timeline_item"]:
                tl_lines += "| Date | Type | Context |\n|------|------|---------|\n"
            for event in timeline:
                date = event.get("email_date") or event.get("created_at") or "Unknown"
                date_str = str(date)[:10]
                context = _truncate(event.get("context_snippet") or event.get("subject") or "", 120)
                tl_lines += tpl["timeline_item"].format(
                    date=date_str,
                    doc_type=(event.get("doc_type") or "doc").upper(),
                    context=context,
                )
            body += tpl["timeline_section"].format(timeline_items=tl_lines.rstrip())

        # --- Footer ---
        body += tpl["footer"].format(
            version=self.version,
            generated_at=_now_iso()[:19],
        )

        # Apply redactions
        title = self._apply_redactions(title)
        body = self._apply_redactions(body)

        return {"title": title, "body": body}

    def generate_comment_thread(
        self,
        entity_id: int,
        *,
        evidence_per_comment: int = 3,
        max_comments: int = 10,
    ) -> List[Dict[str, str]]:
        """Break a large evidence set into a sequence of Reddit comments.

        Each comment contains up to *evidence_per_comment* items and is
        designed to be posted as a reply chain under the main post.

        Returns a list of dicts with ``comment_number`` and ``body``.
        """
        entity = self._fetch_entity(entity_id)
        if entity is None:
            return []

        if entity.get("is_victim") or entity.get("is_minor"):
            return []

        all_evidence = self._fetch_top_evidence(entity_id, limit=evidence_per_comment * max_comments)
        if not all_evidence:
            return []

        comments: List[Dict[str, str]] = []
        total_chunks = math.ceil(len(all_evidence) / evidence_per_comment)
        total_chunks = min(total_chunks, max_comments)

        for chunk_idx in range(total_chunks):
            start = chunk_idx * evidence_per_comment
            end = start + evidence_per_comment
            chunk = all_evidence[start:end]

            lines = f"### Evidence (Part {chunk_idx + 1}/{total_chunks})\n\n"
            for idx, ev in enumerate(chunk, start + 1):
                context = _truncate(ev.get("context_snippet") or "", 300)
                doc_type = (ev.get("doc_type") or "doc").upper()
                lines += (
                    f"{idx}. **[{doc_type}]** {context}\n"
                    f"   - Score: {ev.get('damning_score', 0)}/100\n"
                    f"   - Source: {ev.get('source', 'unknown')}\n"
                    f"   - File: `{ev.get('original_filename', 'N/A')}`\n\n"
                )

            lines = self._apply_redactions(lines)
            comments.append({
                "comment_number": chunk_idx + 1,
                "body": lines,
            })

        return comments

    def format_entity_summary(
        self,
        entity_id: int,
        *,
        compact: bool = False,
    ) -> str:
        """One-paragraph summary of an entity suitable for inline references.

        If *compact* is True, returns a single line.
        """
        entity = self._fetch_entity(entity_id)
        if entity is None:
            return f"(Entity {entity_id} not found)"

        name = entity["name"]
        etype = entity["entity_type"]
        score = entity.get("implication_score") or 0
        label = _score_to_label(score)
        ev_count = entity.get("evidence_count") or 0
        doc_count = entity.get("document_count") or 0

        if compact:
            text = (
                f"**{name}** ({etype}, {label} {score}/100, "
                f"{ev_count} evidence items, {doc_count} docs)"
            )
        else:
            aliases = entity.get("aliases") or []
            alias_str = ", ".join(aliases[:5]) if aliases else "none"
            role = entity.get("role") or "N/A"
            org = entity.get("organization") or "N/A"
            text = (
                f"**{name}** is a **{etype}** with an implication score of "
                f"**{score}/100 ({label})**. They appear across {doc_count} documents "
                f"with {ev_count} evidence items. "
                f"Known aliases: {alias_str}. "
                f"Role: {role}. Organization: {org}."
            )

        return self._apply_redactions(text)

    def format_evidence_chain(
        self,
        entity_id: int,
        *,
        max_items: int = 20,
    ) -> str:
        """A numbered Markdown list of the full evidence chain for an entity.

        Designed for use in long-form posts or wiki pages.
        """
        entity = self._fetch_entity(entity_id)
        if entity is None:
            return ""

        evidence = self._fetch_top_evidence(entity_id, limit=max_items)
        if not evidence:
            return f"No evidence items found for **{entity.get('name', 'Unknown')}**.\n"

        lines = f"## Evidence Chain: {entity['name']}\n\n"
        for idx, ev in enumerate(evidence, 1):
            context = _truncate(ev.get("context_snippet") or "", 400)
            doc_type = (ev.get("doc_type") or "doc").upper()
            source = ev.get("source") or "unknown"
            score = ev.get("damning_score") or 0
            filename = ev.get("original_filename") or "N/A"
            lines += (
                f"**{idx}.** [{doc_type}] {context}\n"
                f"> Score: {score}/100 | Source: {source} | File: `{filename}`\n\n"
            )

        lines = self._apply_redactions(lines)
        return lines

    def generate_multi_entity_post(
        self,
        entity_ids: List[int],
        *,
        title: str = "Entity Connection Analysis",
    ) -> Dict[str, str]:
        """Generate a post comparing/connecting multiple entities."""
        sections: List[str] = []
        for eid in entity_ids:
            summary = self.format_entity_summary(eid)
            sections.append(summary)

        body = f"# {title}\n\n"
        body += "\n\n".join(sections)

        # Show shared connections
        if len(entity_ids) >= 2:
            body += "\n\n---\n\n## Shared Connections\n\n"
            conn = self.db.get_connection()
            try:
                for i, eid_a in enumerate(entity_ids):
                    for eid_b in entity_ids[i + 1:]:
                        shared = conn.execute(
                            """SELECT relationship_type, weight, evidence_count
                               FROM relationships
                               WHERE (source_entity_id = ? AND target_entity_id = ?)
                                  OR (source_entity_id = ? AND target_entity_id = ?)""",
                            (eid_a, eid_b, eid_b, eid_a),
                        ).fetchall()
                        if shared:
                            ea = conn.execute("SELECT name FROM entities WHERE id=?", (eid_a,)).fetchone()
                            eb = conn.execute("SELECT name FROM entities WHERE id=?", (eid_b,)).fetchone()
                            name_a = ea["name"] if ea else str(eid_a)
                            name_b = eb["name"] if eb else str(eid_b)
                            for s in shared:
                                rel = (s["relationship_type"] or "").replace("_", " ")
                                body += (
                                    f"- **{name_a}** <-> **{name_b}**: "
                                    f"{rel} (weight: {s['weight']:.1f}, "
                                    f"evidence: {s['evidence_count']})\n"
                                )
                        else:
                            body += f"- No direct relationship found between entity {eid_a} and {eid_b}\n"
            finally:
                conn.close()

        body += f"\n\n---\n\n*Generated by EpsteinAnalyzer v{self.version}*\n"
        body = self._apply_redactions(body)
        return {"title": title, "body": body}


# ===================================================================
# 2. PublicViewerExporter
# ===================================================================

class PublicViewerExporter:
    """Export knowledge graph data as static JSON files for the GitHub Pages
    public viewer (index.html).

    Generates:
      - data/graph.json       -- nodes and links for D3/Three.js
      - data/timeline.json    -- chronological events
      - data/entities/        -- individual entity card JSON files
      - data/metadata.json    -- build metadata and stats

    All outputs are *redacted*: victim names are stripped, raw OCR text is
    removed, and AI-only inferences can be excluded per config.
    """

    # Expected output JSON schema (documented here for the viewer)
    GRAPH_JSON_SCHEMA_COMMENT = """
    /*
     * graph.json schema:
     * {
     *   "nodes": [
     *     {
     *       "id": <int>,
     *       "name": <string>,
     *       "type": <string>,          // person, organization, location, ...
     *       "score": <float 0-100>,    // implication score
     *       "evidence_count": <int>,
     *       "document_count": <int>,
     *       "role": <string|null>,
     *       "aliases": [<string>, ...],
     *       "radius": <float>,         // computed for D3 (4-30)
     *       "color": <string>,         // hex colour by type
     *       "score_color": <string>,   // hex colour by score level
     *       "x": <float|null>,         // optional pre-computed position
     *       "y": <float|null>,
     *       "z": <float|null>          // for 3D view
     *     }, ...
     *   ],
     *   "links": [
     *     {
     *       "source": <int>,           // entity id
     *       "target": <int>,
     *       "type": <string>,          // relationship_type
     *       "weight": <float>,
     *       "confidence": <float 0-1>,
     *       "evidence_count": <int>,
     *       "inferred": <bool>,
     *       "width": <float>           // stroke width for rendering
     *     }, ...
     *   ],
     *   "metadata": {
     *     "node_count": <int>,
     *     "link_count": <int>,
     *     "generated_at": <iso-string>,
     *     "min_score": <int>,
     *     "version": <string>,
     *     "public": true
     *   }
     * }
     */
    """

    TIMELINE_JSON_SCHEMA_COMMENT = """
    /*
     * timeline.json schema:
     * {
     *   "events": [
     *     {
     *       "id": <int>,
     *       "date": <string>,           // ISO date or YYYY-MM-DD
     *       "entity_id": <int>,
     *       "entity_name": <string>,
     *       "entity_type": <string>,
     *       "doc_type": <string>,
     *       "description": <string>,    // redacted context
     *       "damning_score": <float>,
     *       "source": <string>,
     *       "document_id": <int>
     *     }, ...
     *   ],
     *   "date_range": {
     *     "min": <string>,
     *     "max": <string>
     *   },
     *   "metadata": {
     *     "event_count": <int>,
     *     "generated_at": <iso-string>
     *   }
     * }
     */
    """

    ENTITY_CARD_JSON_SCHEMA_COMMENT = """
    /*
     * entities/<id>.json schema:
     * {
     *   "entity": {
     *     "id": <int>,
     *     "name": <string>,
     *     "type": <string>,
     *     "score": <float>,
     *     "score_label": <string>,
     *     "score_color": <string>,
     *     "role": <string|null>,
     *     "aliases": [<string>],
     *     "evidence_count": <int>,
     *     "document_count": <int>,
     *     "connection_count": <int>
     *   },
     *   "top_evidence": [
     *     {
     *       "doc_type": <string>,
     *       "context": <string>,
     *       "damning_score": <float>,
     *       "source": <string>,
     *       "document_id": <int>
     *     }, ...
     *   ],
     *   "connections": [
     *     {
     *       "entity_id": <int>,
     *       "name": <string>,
     *       "type": <string>,
     *       "rel_type": <string>,
     *       "weight": <float>
     *     }, ...
     *   ],
     *   "timeline": [
     *     {
     *       "date": <string>,
     *       "doc_type": <string>,
     *       "description": <string>
     *     }, ...
     *   ]
     * }
     */
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: Optional[dict] = None,
        output_dir: Optional[str] = None,
    ):
        self.db = db
        self.config = config or _load_config()
        self.version = self.config.get("project", {}).get("version", "1.0.0")
        self.export_config = self.config.get("export", {}).get("public_viewer", {})
        self.min_score: int = self.export_config.get("min_score_for_inclusion", 50)
        self.exclude_ai_inferences: bool = self.export_config.get("exclude_ai_inferences", True)
        self.strip_raw_text: bool = self.export_config.get("strip_raw_text", True)
        self._output_dir = Path(output_dir) if output_dir else (
            _PROJECT_ROOT / "public_viewer" / "data"
        )
        self._victim_ids: Optional[Set[int]] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_victim_ids(self) -> Set[int]:
        """Cache and return the set of entity IDs that are victims/minors."""
        if self._victim_ids is not None:
            return self._victim_ids
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                "SELECT id FROM entities WHERE is_victim = 1 OR is_minor = 1"
            ).fetchall()
            self._victim_ids = {r["id"] for r in rows}
            return self._victim_ids
        finally:
            conn.close()

    def _redact_context(self, text: Optional[str]) -> str:
        """Remove raw OCR text, victim names, and sensitive content."""
        if not text:
            return ""
        if self.strip_raw_text and len(text) > 500:
            text = text[:497] + "..."

        # Strip victim names
        conn = self.db.get_connection()
        try:
            victims = conn.execute(
                "SELECT name FROM entities WHERE is_victim = 1 OR is_minor = 1"
            ).fetchall()
            for v in victims:
                text = text.replace(v["name"], "[REDACTED]")
        finally:
            conn.close()

        return text

    @staticmethod
    def _node_radius(score: float) -> float:
        """Map implication score (0-100) to a visual radius (4-30)."""
        return 4.0 + (score / 100.0) * 26.0

    @staticmethod
    def _edge_width(weight: float) -> float:
        """Map relationship weight to stroke width."""
        return max(0.5, min(8.0, weight * 0.8))

    @staticmethod
    def _type_color(entity_type: str) -> str:
        """Colour palette for entity types."""
        palette = {
            "person": "#e63946",
            "organization": "#457b9d",
            "location": "#2a9d8f",
            "aircraft": "#e9c46a",
            "financial": "#f4a261",
            "legal_case": "#264653",
            "contact_info": "#a8dadc",
            "event": "#6a4c93",
            "redacted_entity": "#6c757d",
        }
        return palette.get(entity_type, "#999999")

    def _compute_positions(
        self, nodes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Pre-compute initial x/y/z positions for stable graph layout.

        Uses a simple radial layout grouped by entity type so the force
        simulation starts from a reasonable state.
        """
        type_groups: Dict[str, List[Dict]] = defaultdict(list)
        for node in nodes:
            type_groups[node["type"]].append(node)

        angle_step = (2 * math.pi) / max(len(type_groups), 1)
        radius_base = 200.0

        for group_idx, (etype, group_nodes) in enumerate(type_groups.items()):
            group_angle = group_idx * angle_step
            group_cx = math.cos(group_angle) * radius_base
            group_cy = math.sin(group_angle) * radius_base

            node_angle_step = (2 * math.pi) / max(len(group_nodes), 1)
            inner_radius = 30.0 + len(group_nodes) * 3.0

            for ni, node in enumerate(group_nodes):
                na = ni * node_angle_step
                node["x"] = group_cx + math.cos(na) * inner_radius
                node["y"] = group_cy + math.sin(na) * inner_radius
                node["z"] = (node.get("score", 0) / 100.0) * 100.0 - 50.0

        return nodes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_graph_data(self) -> Dict[str, Any]:
        """Generate the full graph.json data structure.

        Excludes victims, applies score thresholds, and optionally removes
        AI-inferred relationships.
        """
        victim_ids = self._get_victim_ids()
        conn = self.db.get_connection()
        try:
            # Fetch entities above score threshold
            entity_rows = conn.execute(
                """SELECT id, name, canonical_name, entity_type, implication_score,
                          evidence_count, document_count, role, aliases
                   FROM entities
                   WHERE is_victim = 0 AND is_minor = 0
                     AND (implication_score >= ? OR implication_score IS NULL)
                   ORDER BY implication_score DESC""",
                (self.min_score,),
            ).fetchall()

            entity_ids: Set[int] = set()
            nodes: List[Dict[str, Any]] = []
            for e in entity_rows:
                eid = e["id"]
                if eid in victim_ids:
                    continue
                entity_ids.add(eid)
                score = e["implication_score"] or 0
                aliases = _json_loads_safe(e["aliases"])
                nodes.append({
                    "id": eid,
                    "name": e["name"],
                    "type": e["entity_type"],
                    "score": score,
                    "evidence_count": e["evidence_count"] or 0,
                    "document_count": e["document_count"] or 0,
                    "role": e["role"],
                    "aliases": aliases[:5] if aliases else [],
                    "radius": self._node_radius(score),
                    "color": self._type_color(e["entity_type"]),
                    "score_color": _score_to_color(score),
                    "x": None,
                    "y": None,
                    "z": None,
                })

            # Pre-compute positions
            nodes = self._compute_positions(nodes)

            # Fetch relationships
            rel_sql = "SELECT * FROM relationships"
            if self.exclude_ai_inferences:
                rel_sql += " WHERE is_inferred = 0"

            rel_rows = conn.execute(rel_sql).fetchall()
            links: List[Dict[str, Any]] = []
            for r in rel_rows:
                src = r["source_entity_id"]
                tgt = r["target_entity_id"]
                if src in entity_ids and tgt in entity_ids:
                    if src not in victim_ids and tgt not in victim_ids:
                        links.append({
                            "source": src,
                            "target": tgt,
                            "type": r["relationship_type"],
                            "weight": r["weight"] or 1.0,
                            "confidence": r["confidence"] or 1.0,
                            "evidence_count": r["evidence_count"] or 0,
                            "inferred": bool(r["is_inferred"]),
                            "width": self._edge_width(r["weight"] or 1.0),
                        })

            graph_data = {
                "nodes": nodes,
                "links": links,
                "metadata": {
                    "node_count": len(nodes),
                    "link_count": len(links),
                    "generated_at": _now_iso(),
                    "min_score": self.min_score,
                    "version": self.version,
                    "public": True,
                },
            }
            return graph_data

        finally:
            conn.close()

    def export_timeline(self) -> Dict[str, Any]:
        """Generate timeline.json with chronological events."""
        victim_ids = self._get_victim_ids()
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT edl.id, edl.entity_id, edl.document_id,
                          edl.context_snippet, edl.damning_score, edl.evidence_type,
                          e.name AS entity_name, e.entity_type,
                          e.implication_score,
                          d.doc_type, d.source, d.original_filename,
                          em.email_date
                   FROM entity_document_links edl
                   JOIN entities e ON e.id = edl.entity_id
                   JOIN documents d ON d.id = edl.document_id
                   LEFT JOIN email_messages em ON em.document_id = d.id
                   WHERE e.is_victim = 0 AND e.is_minor = 0
                     AND (e.implication_score >= ? OR e.implication_score IS NULL)
                   ORDER BY COALESCE(em.email_date, edl.created_at) ASC"""
                , (self.min_score,),
            ).fetchall()

            events: List[Dict[str, Any]] = []
            dates: List[str] = []
            event_id = 0
            for r in rows:
                if r["entity_id"] in victim_ids:
                    continue
                date = r["email_date"] or ""
                if not date:
                    continue  # Skip events without dates for timeline
                date_str = str(date)[:10]
                dates.append(date_str)

                event_id += 1
                events.append({
                    "id": event_id,
                    "date": date_str,
                    "entity_id": r["entity_id"],
                    "entity_name": r["entity_name"],
                    "entity_type": r["entity_type"],
                    "doc_type": r["doc_type"],
                    "description": self._redact_context(
                        _truncate(r["context_snippet"] or "", 200)
                    ),
                    "damning_score": r["damning_score"] or 0,
                    "source": r["source"] or "unknown",
                    "document_id": r["document_id"],
                })

            date_range = {
                "min": min(dates) if dates else None,
                "max": max(dates) if dates else None,
            }

            return {
                "events": events,
                "date_range": date_range,
                "metadata": {
                    "event_count": len(events),
                    "generated_at": _now_iso(),
                },
            }

        finally:
            conn.close()

    def export_entity_cards(self) -> Dict[int, Dict[str, Any]]:
        """Generate individual entity card JSON for every qualifying entity.

        Returns a mapping of entity_id -> card data.
        """
        victim_ids = self._get_victim_ids()
        conn = self.db.get_connection()
        try:
            entities = conn.execute(
                """SELECT id, name, entity_type, implication_score,
                          evidence_count, document_count, role, aliases,
                          title, organization, description
                   FROM entities
                   WHERE is_victim = 0 AND is_minor = 0
                     AND (implication_score >= ? OR implication_score IS NULL)
                   ORDER BY implication_score DESC""",
                (self.min_score,),
            ).fetchall()
        finally:
            conn.close()

        cards: Dict[int, Dict[str, Any]] = {}
        for ent in entities:
            eid = ent["id"]
            if eid in victim_ids:
                continue

            score = ent["implication_score"] or 0
            aliases = _json_loads_safe(ent["aliases"])

            # Top evidence
            conn = self.db.get_connection()
            try:
                ev_rows = conn.execute(
                    """SELECT edl.damning_score, edl.context_snippet,
                              d.doc_type, d.source, d.id AS document_id
                       FROM entity_document_links edl
                       JOIN documents d ON d.id = edl.document_id
                       WHERE edl.entity_id = ?
                       ORDER BY edl.damning_score DESC
                       LIMIT 10""",
                    (eid,),
                ).fetchall()
                top_evidence = []
                for ev in ev_rows:
                    top_evidence.append({
                        "doc_type": ev["doc_type"],
                        "context": self._redact_context(
                            _truncate(ev["context_snippet"] or "", 200)
                        ),
                        "damning_score": ev["damning_score"] or 0,
                        "source": ev["source"],
                        "document_id": ev["document_id"],
                    })

                # Connections
                rel_rows = conn.execute(
                    """SELECT
                          CASE WHEN r.source_entity_id = ? THEN r.target_entity_id
                               ELSE r.source_entity_id END AS other_id,
                          CASE WHEN r.source_entity_id = ? THEN et.name
                               ELSE es.name END AS other_name,
                          CASE WHEN r.source_entity_id = ? THEN et.entity_type
                               ELSE es.entity_type END AS other_type,
                          r.relationship_type, r.weight
                       FROM relationships r
                       JOIN entities es ON es.id = r.source_entity_id
                       JOIN entities et ON et.id = r.target_entity_id
                       WHERE (r.source_entity_id = ? OR r.target_entity_id = ?)
                       ORDER BY r.weight DESC
                       LIMIT 20""",
                    (eid, eid, eid, eid, eid),
                ).fetchall()
                connections = []
                for cr in rel_rows:
                    if cr["other_id"] not in victim_ids:
                        connections.append({
                            "entity_id": cr["other_id"],
                            "name": cr["other_name"],
                            "type": cr["other_type"],
                            "rel_type": (cr["relationship_type"] or "").replace("_", " "),
                            "weight": cr["weight"] or 1.0,
                        })

                # Mini timeline
                tl_rows = conn.execute(
                    """SELECT COALESCE(em.email_date, edl.created_at) AS event_date,
                              d.doc_type, edl.context_snippet
                       FROM entity_document_links edl
                       JOIN documents d ON d.id = edl.document_id
                       LEFT JOIN email_messages em ON em.document_id = d.id
                       WHERE edl.entity_id = ?
                       ORDER BY event_date ASC
                       LIMIT 20""",
                    (eid,),
                ).fetchall()
                timeline = []
                for tl in tl_rows:
                    if tl["event_date"]:
                        timeline.append({
                            "date": str(tl["event_date"])[:10],
                            "doc_type": tl["doc_type"],
                            "description": self._redact_context(
                                _truncate(tl["context_snippet"] or "", 120)
                            ),
                        })

            finally:
                conn.close()

            cards[eid] = {
                "entity": {
                    "id": eid,
                    "name": ent["name"],
                    "type": ent["entity_type"],
                    "score": score,
                    "score_label": _score_to_label(score),
                    "score_color": _score_to_color(score),
                    "role": ent["role"],
                    "aliases": aliases[:5] if aliases else [],
                    "evidence_count": ent["evidence_count"] or 0,
                    "document_count": ent["document_count"] or 0,
                    "connection_count": len(connections),
                },
                "top_evidence": top_evidence,
                "connections": connections,
                "timeline": timeline,
            }

        return cards

    def generate_static_site(self, output_dir: Optional[str] = None) -> Path:
        """Write all JSON data files to *output_dir* for the static site.

        Directory structure:
            output_dir/
                graph.json
                timeline.json
                metadata.json
                entities/
                    <id>.json
                    ...
        """
        out = Path(output_dir) if output_dir else self._output_dir
        out.mkdir(parents=True, exist_ok=True)
        entities_dir = out / "entities"
        entities_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Exporting graph data...")
        graph = self.export_graph_data()
        (out / "graph.json").write_text(
            json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info(
            "  graph.json: %d nodes, %d links",
            graph["metadata"]["node_count"],
            graph["metadata"]["link_count"],
        )

        logger.info("Exporting timeline data...")
        timeline = self.export_timeline()
        (out / "timeline.json").write_text(
            json.dumps(timeline, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("  timeline.json: %d events", timeline["metadata"]["event_count"])

        logger.info("Exporting entity cards...")
        cards = self.export_entity_cards()
        for eid, card_data in cards.items():
            card_path = entities_dir / f"{eid}.json"
            card_path.write_text(
                json.dumps(card_data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        logger.info("  %d entity cards exported", len(cards))

        # Metadata file
        metadata = {
            "project": self.config.get("project", {}).get("name", "EpsteinAnalyzer"),
            "version": self.version,
            "generated_at": _now_iso(),
            "node_count": graph["metadata"]["node_count"],
            "link_count": graph["metadata"]["link_count"],
            "event_count": timeline["metadata"]["event_count"],
            "entity_card_count": len(cards),
            "min_score_threshold": self.min_score,
            "ai_inferences_excluded": self.exclude_ai_inferences,
            "raw_text_stripped": self.strip_raw_text,
        }
        (out / "metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        logger.info("Static site data written to %s", out)
        return out

    def package_for_github_pages(
        self,
        output_dir: Optional[str] = None,
        zip_path: Optional[str] = None,
    ) -> Path:
        """Generate the complete GitHub Pages bundle.

        1. Export all JSON data files.
        2. Copy index.html from public_viewer/.
        3. Optionally create a ZIP archive.

        Returns the path to the output directory (or ZIP file).
        """
        out = Path(output_dir) if output_dir else (_PROJECT_ROOT / "dist" / "public_viewer")
        out.mkdir(parents=True, exist_ok=True)

        # Step 1: Generate data files into out/data/
        data_dir = out / "data"
        self.generate_static_site(str(data_dir))

        # Step 2: Copy the HTML viewer
        viewer_source = _PROJECT_ROOT / "public_viewer" / "index.html"
        viewer_dest = out / "index.html"
        if viewer_source.exists():
            shutil.copy2(str(viewer_source), str(viewer_dest))
            logger.info("Copied index.html to %s", viewer_dest)
        else:
            logger.warning(
                "index.html not found at %s -- bundle will be incomplete.",
                viewer_source,
            )

        # Step 3: Create a .nojekyll file for GitHub Pages
        (out / ".nojekyll").write_text("", encoding="utf-8")

        # Step 4: Optional ZIP packaging
        if zip_path:
            zip_target = Path(zip_path)
            zip_target.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(zip_target), "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in out.rglob("*"):
                    if file_path.is_file():
                        arcname = file_path.relative_to(out)
                        zf.write(str(file_path), str(arcname))
            logger.info("GitHub Pages bundle zipped to %s", zip_target)
            return zip_target

        logger.info("GitHub Pages bundle ready at %s", out)
        return out


# ===================================================================
# 3. ImageRedactionExporter
# ===================================================================

class ImageRedactionExporter:
    """Apply visual redactions to images before export.

    Supports:
      - User-specified rectangular redaction regions
      - Automatic quarantine of images flagged as containing minors
      - Saving redacted copies separately from originals

    Requires Pillow (PIL) for image manipulation.
    """

    def __init__(
        self,
        db: DatabaseManager,
        config: Optional[dict] = None,
    ):
        self.db = db
        self.config = config or _load_config()
        self.data_dir = Path(self.config["project"]["data_dir"]).resolve()
        processor_config = self.config.get("processor", {}).get("image_forensics", {})
        self.auto_quarantine_minors: bool = processor_config.get("auto_quarantine_minors", True)
        self.require_user_approval: bool = processor_config.get("require_user_approval", True)
        self._redacted_output_dir = self.data_dir / "export" / "redacted_images"
        self._quarantine_dir = self.data_dir / "export" / "quarantine"

    def _ensure_dirs(self) -> None:
        """Create output directories if they do not exist."""
        self._redacted_output_dir.mkdir(parents=True, exist_ok=True)
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)

    def _load_image(self, image_path: str):
        """Load an image using Pillow. Returns a PIL Image or None."""
        try:
            from PIL import Image
            return Image.open(image_path)
        except ImportError:
            logger.error(
                "Pillow is not installed. Install with: pip install Pillow"
            )
            return None
        except Exception as exc:
            logger.error("Failed to load image %s: %s", image_path, exc)
            return None

    def apply_custom_redactions(
        self,
        image_path: str,
        regions: List[Dict[str, int]],
        *,
        fill_color: Tuple[int, int, int] = (0, 0, 0),
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """Apply rectangular redactions to an image.

        Parameters
        ----------
        image_path : str
            Path to the source image.
        regions : list of dict
            Each dict has keys ``x``, ``y``, ``width``, ``height`` defining
            the rectangular area to redact (in pixels).
        fill_color : tuple
            RGB colour to fill redacted regions (default: black).
        output_path : str, optional
            Where to save the redacted image. If None, a default path is
            generated under the redacted output directory.

        Returns
        -------
        str or None
            Path to the redacted image, or None on failure.
        """
        self._ensure_dirs()

        try:
            from PIL import Image, ImageDraw
        except ImportError:
            logger.error("Pillow is required for image redaction.")
            return None

        img = self._load_image(image_path)
        if img is None:
            return None

        draw = ImageDraw.Draw(img)

        for region in regions:
            x = region.get("x", 0)
            y = region.get("y", 0)
            w = region.get("width", 0)
            h = region.get("height", 0)
            if w <= 0 or h <= 0:
                logger.warning("Skipping invalid redaction region: %s", region)
                continue
            # Clamp to image bounds
            x = max(0, min(x, img.width - 1))
            y = max(0, min(y, img.height - 1))
            x2 = min(x + w, img.width)
            y2 = min(y + h, img.height)
            draw.rectangle([x, y, x2, y2], fill=fill_color)

        # Determine output path
        if output_path is None:
            src_name = Path(image_path).stem
            src_ext = Path(image_path).suffix or ".png"
            output_path = str(
                self._redacted_output_dir / f"{src_name}_redacted{src_ext}"
            )

        # Ensure parent directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            img.save(output_path)
            logger.info("Redacted image saved to %s", output_path)
        except Exception as exc:
            logger.error("Failed to save redacted image: %s", exc)
            return None

        # Log redaction in the database
        self._log_redaction_export(image_path, output_path, len(regions))

        return output_path

    def quarantine_check(self) -> Dict[str, Any]:
        """Scan all images in the database and quarantine any flagged as
        potentially containing minors.

        Returns a summary of actions taken.
        """
        self._ensure_dirs()
        results = {
            "scanned": 0,
            "quarantined": 0,
            "already_quarantined": 0,
            "errors": 0,
            "details": [],
        }

        conn = self.db.get_connection()
        try:
            # Fetch images that have been flagged
            rows = conn.execute(
                """SELECT i.id, i.file_path, i.document_id, i.page_number,
                          i.contains_faces, i.contains_minors_flag,
                          i.user_reviewed, i.quarantined
                   FROM images i
                   WHERE i.recovery_successful = 1"""
            ).fetchall()
        finally:
            conn.close()

        for row in rows:
            results["scanned"] += 1
            image_id = row["id"]
            file_path = row["file_path"]

            # Already quarantined
            if row["quarantined"]:
                results["already_quarantined"] += 1
                continue

            # Check if flagged for minors
            needs_quarantine = False
            reason = ""

            if row["contains_minors_flag"]:
                needs_quarantine = True
                reason = "Flagged as potentially containing minors (auto-detection)"
            elif self.auto_quarantine_minors and row["contains_faces"] and not row["user_reviewed"]:
                # If it has faces and has not been reviewed, quarantine out of caution
                needs_quarantine = True
                reason = "Contains faces, not yet reviewed -- quarantined for safety"

            if needs_quarantine:
                success = self._quarantine_image(image_id, file_path, reason)
                if success:
                    results["quarantined"] += 1
                    results["details"].append({
                        "image_id": image_id,
                        "file_path": file_path,
                        "reason": reason,
                    })
                else:
                    results["errors"] += 1

        logger.info(
            "Quarantine check complete: scanned=%d, quarantined=%d, errors=%d",
            results["scanned"],
            results["quarantined"],
            results["errors"],
        )
        return results

    def _quarantine_image(
        self, image_id: int, file_path: str, reason: str
    ) -> bool:
        """Move an image to the quarantine directory and update the database."""
        self._ensure_dirs()
        src = Path(file_path)
        if not src.exists():
            logger.warning("Image file not found for quarantine: %s", file_path)
            return False

        dest = self._quarantine_dir / f"img_{image_id}_{src.name}"
        try:
            shutil.copy2(str(src), str(dest))
        except Exception as exc:
            logger.error("Failed to copy image to quarantine: %s", exc)
            return False

        conn = self.db.get_connection()
        try:
            conn.execute(
                """UPDATE images SET quarantined = 1, quarantine_reason = ?,
                   quarantine_path = ?, updated_at = ?
                   WHERE id = ?""",
                (reason, str(dest), _now_iso(), image_id),
            )
            conn.commit()
        except sqlite3.OperationalError:
            # If quarantine columns do not exist, log and continue
            logger.warning(
                "Could not update quarantine columns for image %d "
                "(columns may not exist in schema).", image_id,
            )
        finally:
            conn.close()

        logger.info("Image %d quarantined: %s", image_id, reason)
        return True

    def save_redacted_copy(
        self,
        image_id: int,
        *,
        output_dir: Optional[str] = None,
    ) -> Optional[str]:
        """Load redaction regions from the database for a specific image and
        apply them, saving a redacted copy.

        Returns the output path or None on failure.
        """
        conn = self.db.get_connection()
        try:
            img_row = conn.execute(
                "SELECT file_path FROM images WHERE id = ?", (image_id,)
            ).fetchone()
            if img_row is None:
                logger.error("Image ID %d not found.", image_id)
                return None

            file_path = img_row["file_path"]

            # Fetch associated redaction regions
            redaction_rows = conn.execute(
                """SELECT r.bbox_x, r.bbox_y, r.bbox_width, r.bbox_height
                   FROM redactions r
                   JOIN images i ON i.document_id = r.document_id
                                AND i.page_number = r.page_number
                   WHERE i.id = ?
                     AND r.bbox_x IS NOT NULL""",
                (image_id,),
            ).fetchall()
        finally:
            conn.close()

        if not redaction_rows:
            logger.info("No redaction regions found for image %d.", image_id)
            return None

        regions = [
            {
                "x": r["bbox_x"],
                "y": r["bbox_y"],
                "width": r["bbox_width"],
                "height": r["bbox_height"],
            }
            for r in redaction_rows
        ]

        out_dir = Path(output_dir) if output_dir else self._redacted_output_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        src_name = Path(file_path).stem
        src_ext = Path(file_path).suffix or ".png"
        out_path = str(out_dir / f"{src_name}_redacted{src_ext}")

        return self.apply_custom_redactions(file_path, regions, output_path=out_path)

    def batch_redact_for_export(
        self,
        *,
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process all images in the database: quarantine unsafe ones and
        generate redacted copies of the rest.

        Returns a summary of actions.
        """
        self._ensure_dirs()

        # Step 1: Quarantine
        quarantine_results = self.quarantine_check()

        # Step 2: Redact remaining images
        conn = self.db.get_connection()
        try:
            exportable = conn.execute(
                """SELECT id FROM images
                   WHERE recovery_successful = 1
                     AND (quarantined = 0 OR quarantined IS NULL)
                     AND user_reviewed = 1"""
            ).fetchall()
        finally:
            conn.close()

        redacted = 0
        skipped = 0
        errors = 0
        for row in exportable:
            result = self.save_redacted_copy(row["id"], output_dir=output_dir)
            if result is not None:
                redacted += 1
            elif result is None:
                # No regions to redact -- could copy as-is or skip
                skipped += 1

        return {
            "quarantine": quarantine_results,
            "redacted": redacted,
            "skipped": skipped,
            "errors": errors,
        }

    def _log_redaction_export(
        self, source_path: str, output_path: str, region_count: int
    ) -> None:
        """Record the redaction export action in the audit log."""
        self.db.log_action(
            "image_redaction_export",
            json.dumps({
                "source": source_path,
                "output": output_path,
                "regions_redacted": region_count,
                "timestamp": _now_iso(),
            }),
            user_initiated=True,
        )


# ===================================================================
# 4. ExportManager (CLI Orchestrator)
# ===================================================================

class ExportManager:
    """Orchestrates all export operations and provides a CLI interface.

    Commands:
        reddit   -- Generate Reddit posts for one or more entities
        viewer   -- Export data for the public viewer (GitHub Pages)
        images   -- Process images (quarantine + redaction)
        full     -- Run all exports
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = _load_config(config_path)
        self.db = DatabaseManager(config_path)
        self.version = self.config.get("project", {}).get("version", "1.0.0")

    # ------------------------------------------------------------------
    # Progress tracking
    # ------------------------------------------------------------------

    def _log_progress(self, stage: str, status: str, details: str = "") -> None:
        """Write progress updates to the audit log."""
        self.db.log_action(
            f"export_{stage}",
            json.dumps({"status": status, "details": details, "timestamp": _now_iso()}),
            user_initiated=True,
        )

    # ------------------------------------------------------------------
    # Reddit export
    # ------------------------------------------------------------------

    def run_reddit_export(
        self,
        entity_ids: Optional[List[int]] = None,
        *,
        template: str = "default",
        output_dir: Optional[str] = None,
        top_n: int = 10,
    ) -> Dict[str, Any]:
        """Generate Reddit posts and write them to Markdown files.

        If *entity_ids* is None, exports the top N entities by score.
        """
        self._log_progress("reddit", "started")
        exporter = RedditExporter(self.db, self.config, template_name=template)

        out = Path(output_dir) if output_dir else (
            Path(self.config["project"]["data_dir"]).resolve() / "export" / "reddit"
        )
        out.mkdir(parents=True, exist_ok=True)

        # Determine which entities to export
        if entity_ids is None:
            conn = self.db.get_connection()
            try:
                rows = conn.execute(
                    """SELECT id FROM entities
                       WHERE is_victim = 0 AND is_minor = 0
                       ORDER BY implication_score DESC
                       LIMIT ?""",
                    (top_n,),
                ).fetchall()
                entity_ids = [r["id"] for r in rows]
            finally:
                conn.close()

        results = {"exported": 0, "skipped": 0, "errors": 0, "files": []}

        for eid in entity_ids:
            try:
                post = exporter.generate_post(eid)
                if not post["title"]:
                    results["skipped"] += 1
                    continue

                # Write to file
                entity = exporter._fetch_entity(eid)
                safe_name = _sanitize_filename(entity["name"]) if entity else str(eid)
                file_path = out / f"{safe_name}.md"
                file_path.write_text(
                    f"# {post['title']}\n\n{post['body']}",
                    encoding="utf-8",
                )
                results["exported"] += 1
                results["files"].append(str(file_path))

                # Also generate comment thread
                comments = exporter.generate_comment_thread(eid)
                if comments:
                    comments_path = out / f"{safe_name}_comments.md"
                    comment_text = "\n\n---\n\n".join(
                        c["body"] for c in comments
                    )
                    comments_path.write_text(comment_text, encoding="utf-8")

            except Exception as exc:
                logger.error("Failed to export entity %d: %s", eid, exc)
                results["errors"] += 1

        self._log_progress("reddit", "completed", json.dumps(results))
        logger.info(
            "Reddit export: %d exported, %d skipped, %d errors",
            results["exported"],
            results["skipped"],
            results["errors"],
        )
        return results

    # ------------------------------------------------------------------
    # Viewer export
    # ------------------------------------------------------------------

    def run_viewer_export(
        self,
        output_dir: Optional[str] = None,
        *,
        zip_bundle: bool = False,
    ) -> Dict[str, Any]:
        """Export the full public viewer bundle."""
        self._log_progress("viewer", "started")

        exporter = PublicViewerExporter(self.db, self.config, output_dir)
        zip_path = None
        if zip_bundle:
            base_out = Path(output_dir) if output_dir else (
                _PROJECT_ROOT / "dist" / "public_viewer"
            )
            zip_path = str(base_out.parent / "public_viewer.zip")

        result_path = exporter.package_for_github_pages(
            output_dir=output_dir, zip_path=zip_path
        )

        result = {
            "output_path": str(result_path),
            "zip_created": zip_path is not None,
        }
        self._log_progress("viewer", "completed", json.dumps(result))
        logger.info("Viewer export complete: %s", result_path)
        return result

    # ------------------------------------------------------------------
    # Image export
    # ------------------------------------------------------------------

    def run_image_export(
        self,
        *,
        quarantine_only: bool = False,
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process images: quarantine check and optional redaction export."""
        self._log_progress("images", "started")

        exporter = ImageRedactionExporter(self.db, self.config)

        if quarantine_only:
            result = exporter.quarantine_check()
        else:
            result = exporter.batch_redact_for_export(output_dir=output_dir)

        self._log_progress("images", "completed", json.dumps(result, default=str))
        logger.info("Image export complete.")
        return result

    # ------------------------------------------------------------------
    # Full export
    # ------------------------------------------------------------------

    def run_full_export(
        self,
        output_dir: Optional[str] = None,
        *,
        include_reddit: bool = True,
        include_viewer: bool = True,
        include_images: bool = True,
        zip_bundle: bool = True,
    ) -> Dict[str, Any]:
        """Run every export stage and return a combined summary."""
        self._log_progress("full", "started")
        base_out = Path(output_dir) if output_dir else (
            _PROJECT_ROOT / "dist"
        )
        base_out.mkdir(parents=True, exist_ok=True)

        summary: Dict[str, Any] = {"stages": {}}

        if include_images:
            logger.info("=== Stage 1/3: Image Processing ===")
            summary["stages"]["images"] = self.run_image_export(
                output_dir=str(base_out / "images")
            )

        if include_reddit:
            logger.info("=== Stage 2/3: Reddit Export ===")
            summary["stages"]["reddit"] = self.run_reddit_export(
                output_dir=str(base_out / "reddit")
            )

        if include_viewer:
            logger.info("=== Stage 3/3: Public Viewer ===")
            summary["stages"]["viewer"] = self.run_viewer_export(
                output_dir=str(base_out / "public_viewer"),
                zip_bundle=zip_bundle,
            )

        summary["completed_at"] = _now_iso()
        self._log_progress("full", "completed", json.dumps(summary, default=str))
        logger.info("Full export pipeline complete.")
        return summary


# ===================================================================
# CLI entry point
# ===================================================================

def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the export CLI."""
    parser = argparse.ArgumentParser(
        prog="export.exporter",
        description="EpsteinAnalyzer - Export Module CLI",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to settings.yaml (default: auto-detect)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Export command")

    # --- reddit ---
    reddit_parser = subparsers.add_parser("reddit", help="Generate Reddit posts")
    reddit_parser.add_argument(
        "--entity",
        type=int,
        nargs="*",
        default=None,
        help="Entity ID(s) to export. If omitted, exports top N.",
    )
    reddit_parser.add_argument(
        "--template",
        type=str,
        default="default",
        choices=RedditExporter.available_templates(),
        help="Reddit template to use (default: 'default')",
    )
    reddit_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory for Markdown files",
    )
    reddit_parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Number of top entities to export when --entity is not specified",
    )

    # --- viewer ---
    viewer_parser = subparsers.add_parser("viewer", help="Export public viewer data")
    viewer_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory for the static site bundle",
    )
    viewer_parser.add_argument(
        "--zip",
        action="store_true",
        help="Also create a ZIP archive of the bundle",
    )

    # --- images ---
    images_parser = subparsers.add_parser("images", help="Process images for export")
    images_parser.add_argument(
        "--quarantine-check",
        action="store_true",
        help="Only run quarantine check (no redaction export)",
    )
    images_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory for redacted images",
    )

    # --- full ---
    full_parser = subparsers.add_parser("full", help="Run all export stages")
    full_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Base output directory for all exports",
    )
    full_parser.add_argument(
        "--zip",
        action="store_true",
        help="Create ZIP archive of the viewer bundle",
    )
    full_parser.add_argument(
        "--skip-reddit",
        action="store_true",
        help="Skip Reddit export stage",
    )
    full_parser.add_argument(
        "--skip-viewer",
        action="store_true",
        help="Skip public viewer export stage",
    )
    full_parser.add_argument(
        "--skip-images",
        action="store_true",
        help="Skip image processing stage",
    )

    return parser


def _cli() -> None:
    """Main CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    manager = ExportManager(args.config)

    if args.command == "reddit":
        manager.run_reddit_export(
            entity_ids=args.entity,
            template=args.template,
            output_dir=args.output,
            top_n=args.top_n,
        )

    elif args.command == "viewer":
        manager.run_viewer_export(
            output_dir=args.output,
            zip_bundle=args.zip,
        )

    elif args.command == "images":
        manager.run_image_export(
            quarantine_only=args.quarantine_check,
            output_dir=args.output,
        )

    elif args.command == "full":
        manager.run_full_export(
            output_dir=args.output,
            include_reddit=not args.skip_reddit,
            include_viewer=not args.skip_viewer,
            include_images=not args.skip_images,
            zip_bundle=args.zip,
        )


if __name__ == "__main__":
    _cli()
