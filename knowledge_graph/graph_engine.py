"""
EpsteinAnalyzer - Knowledge Graph Engine (Spiderweb Engine)
============================================================
Builds and maintains a living, growing map of connections between all
entities found in documents.  Handles entity resolution, relationship
mapping, pattern detection, redaction resolution, temporal analysis,
evidence scoring, and graph export.

Usage (CLI):
    python -m knowledge_graph.graph_engine --rebuild
    python -m knowledge_graph.graph_engine --detect-patterns
    python -m knowledge_graph.graph_engine --export-d3
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import re
import statistics
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import networkx as nx

# Project imports -- DatabaseManager lives one package up.
import sys

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.db import DatabaseManager

logger = logging.getLogger("knowledge_graph.graph_engine")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_loads_safe(text: Optional[str], default=None):
    """Safely parse a JSON string, returning *default* on failure."""
    if text is None:
        return default if default is not None else []
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _escape_like(s: str) -> str:
    """Escape LIKE wildcard characters so user input is treated literally."""
    return str(s).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _load_config(config_path: Optional[str] = None) -> dict:
    """Load settings.yaml and return the full config dict."""
    import yaml

    if config_path is None:
        config_path = _PROJECT_ROOT / "config" / "settings.yaml"
    with open(config_path, "r") as fh:
        return yaml.safe_load(fh)


# ===================================================================
# 1. GraphEngine -- main orchestrator
# ===================================================================

class GraphEngine:
    """Central knowledge-graph orchestrator.

    Maintains the SQLite-backed graph (entities + relationships) and exposes
    an in-memory ``networkx.Graph`` for algorithmic queries.
    """

    def __init__(self, config_path: str = None):
        self.db = DatabaseManager(config_path)
        self.config = self.db.config
        self.kg_config = self.config.get("knowledge_graph", {})
        self.evidence_config = self.config.get("evidence", {}).get("scoring", {})
        self._nx: Optional[nx.Graph] = None  # lazy-loaded
        self._nx_built_at: float = 0.0  # monotonic time of last build
        self._nx_ttl: float = 300.0  # 5 minute TTL

    # ------------------------------------------------------------------
    # NetworkX in-memory mirror
    # ------------------------------------------------------------------

    def _build_nx_graph(self) -> nx.Graph:
        """Build (or rebuild) a ``networkx.Graph`` from the current DB state."""
        G = nx.Graph()
        conn = self.db.get_connection()
        try:
            rows = conn.execute("SELECT id, name, canonical_name, entity_type, implication_score FROM entities").fetchall()
            for r in rows:
                G.add_node(
                    r["id"],
                    name=r["name"],
                    canonical_name=r["canonical_name"],
                    entity_type=r["entity_type"],
                    score=r["implication_score"] or 0.0,
                )
            rels = conn.execute(
                "SELECT id, source_entity_id, target_entity_id, relationship_type, weight, confidence FROM relationships"
            ).fetchall()
            for r in rels:
                G.add_edge(
                    r["source_entity_id"],
                    r["target_entity_id"],
                    rel_id=r["id"],
                    rel_type=r["relationship_type"],
                    weight=r["weight"] or 1.0,
                    confidence=r["confidence"] or 1.0,
                )
        finally:
            conn.close()
        self._nx = G
        return G

    @property
    def nx_graph(self) -> nx.Graph:
        import time as _time
        if self._nx is None or (_time.monotonic() - self._nx_built_at > self._nx_ttl):
            self._build_nx_graph()
            self._nx_built_at = _time.monotonic()
        return self._nx

    def invalidate_cache(self):
        """Force reload of the in-memory graph on next access."""
        self._nx = None

    # ------------------------------------------------------------------
    # Entity CRUD
    # ------------------------------------------------------------------

    def add_entity(
        self,
        name: str,
        entity_type: str,
        *,
        aliases: Optional[List[str]] = None,
        role: str = None,
        title: str = None,
        organization: str = None,
        description: str = None,
        first_seen_dataset: int = None,
        first_seen_document_id: int = None,
        is_victim: bool = False,
        is_minor: bool = False,
        is_redacted_placeholder: bool = False,
    ) -> int:
        """Create or update an entity.  Deduplication uses *canonical_name*."""
        resolver = EntityResolver(self.config)
        canonical = resolver.normalize_name(name)

        # Check for existing alias match first
        resolved = resolver.resolve_aliases(name, self.db)
        if resolved is not None:
            return resolved

        aliases_json = json.dumps(aliases) if aliases else None
        links = resolver.generate_external_links(name, entity_type)

        conn = self.db.get_connection()
        try:
            existing = conn.execute(
                "SELECT id FROM entities WHERE canonical_name = ? AND entity_type = ?",
                (canonical, entity_type),
            ).fetchone()

            if existing:
                entity_id = existing["id"]
                # Merge new aliases into existing
                old = conn.execute("SELECT aliases FROM entities WHERE id = ?", (entity_id,)).fetchone()
                merged_aliases = _merge_alias_lists(
                    _json_loads_safe(old["aliases"]),
                    aliases or [],
                )
                conn.execute(
                    """UPDATE entities
                       SET aliases = ?, role = COALESCE(?, role),
                           title = COALESCE(?, title),
                           organization = COALESCE(?, organization),
                           description = COALESCE(?, description),
                           updated_at = ?
                       WHERE id = ?""",
                    (
                        json.dumps(merged_aliases),
                        role, title, organization, description,
                        _now_iso(), entity_id,
                    ),
                )
                conn.commit()
            else:
                cur = conn.execute(
                    """INSERT INTO entities
                       (name, entity_type, canonical_name, aliases,
                        google_url, wikipedia_url, external_links,
                        role, title, organization, description,
                        first_seen_dataset, first_seen_document_id,
                        is_victim, is_minor, is_redacted_placeholder,
                        created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        name, entity_type, canonical, aliases_json,
                        links.get("google_url"), links.get("wikipedia_url"),
                        json.dumps(links.get("external_links", [])),
                        role, title, organization, description,
                        first_seen_dataset, first_seen_document_id,
                        int(is_victim), int(is_minor), int(is_redacted_placeholder),
                        _now_iso(), _now_iso(),
                    ),
                )
                entity_id = cur.lastrowid
                # Update FTS
                conn.execute(
                    "INSERT INTO entities_fts(rowid, name, canonical_name, aliases, description, role) "
                    "VALUES (?,?,?,?,?,?)",
                    (entity_id, name, canonical, aliases_json, description, role),
                )
                conn.commit()

            self.invalidate_cache()
            return entity_id
        finally:
            conn.close()

    def add_relationship(
        self,
        source_id: int,
        target_id: int,
        rel_type: str,
        evidence_doc_id: int = None,
        *,
        confidence: float = 1.0,
        is_inferred: bool = False,
        inference_method: str = None,
        notes: str = None,
        observed_date: str = None,
    ) -> int:
        """Create or strengthen a relationship edge."""
        conn = self.db.get_connection()
        try:
            existing = conn.execute(
                """SELECT id, evidence_document_ids, evidence_count, weight,
                          first_observed_date, last_observed_date
                   FROM relationships
                   WHERE source_entity_id = ? AND target_entity_id = ? AND relationship_type = ?""",
                (source_id, target_id, rel_type),
            ).fetchone()

            if existing:
                rel_id = existing["id"]
                doc_ids = _json_loads_safe(existing["evidence_document_ids"])
                if evidence_doc_id and evidence_doc_id not in doc_ids:
                    doc_ids.append(evidence_doc_id)
                new_count = len(doc_ids)
                new_weight = self._compute_weight(new_count, rel_type)

                first_date = existing["first_observed_date"]
                last_date = existing["last_observed_date"]
                if observed_date:
                    if first_date is None or observed_date < first_date:
                        first_date = observed_date
                    if last_date is None or observed_date > last_date:
                        last_date = observed_date

                conn.execute(
                    """UPDATE relationships
                       SET evidence_document_ids = ?, evidence_count = ?, weight = ?,
                           confidence = MAX(confidence, ?), is_inferred = MIN(is_inferred, ?),
                           first_observed_date = ?, last_observed_date = ?,
                           notes = COALESCE(?, notes), updated_at = ?
                       WHERE id = ?""",
                    (
                        json.dumps(doc_ids), new_count, new_weight,
                        confidence, int(is_inferred),
                        first_date, last_date,
                        notes, _now_iso(), rel_id,
                    ),
                )
                conn.commit()
            else:
                doc_ids = [evidence_doc_id] if evidence_doc_id else []
                weight = self._compute_weight(len(doc_ids), rel_type)
                cur = conn.execute(
                    """INSERT INTO relationships
                       (source_entity_id, target_entity_id, relationship_type,
                        weight, confidence, is_inferred, inference_method,
                        evidence_document_ids, evidence_count,
                        first_observed_date, last_observed_date,
                        notes, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        source_id, target_id, rel_type,
                        weight, confidence, int(is_inferred), inference_method,
                        json.dumps(doc_ids), len(doc_ids),
                        observed_date, observed_date,
                        notes, _now_iso(), _now_iso(),
                    ),
                )
                rel_id = cur.lastrowid
                conn.commit()

            self.invalidate_cache()
            return rel_id
        finally:
            conn.close()

    @staticmethod
    def _compute_weight(evidence_count: int, rel_type: str) -> float:
        """Weight grows logarithmically with evidence to prevent runaway scores."""
        base = {
            "flew_with": 3.0,
            "emailed": 1.5,
            "financially_linked": 2.5,
            "employed_by": 2.0,
            "co_occurs_with": 1.0,
            "associated_with": 1.0,
        }.get(rel_type, 1.0)
        if evidence_count <= 0:
            return base
        return base * (1.0 + math.log2(evidence_count))

    def get_entity(self, entity_id: int) -> Optional[Dict[str, Any]]:
        """Full entity record with relationships and evidence links."""
        conn = self.db.get_connection()
        try:
            row = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if row is None:
                return None
            entity = dict(row)
            entity["aliases"] = _json_loads_safe(entity.get("aliases"))
            entity["external_links"] = _json_loads_safe(entity.get("external_links"))

            # Relationships (both directions)
            rels = conn.execute(
                """SELECT r.*, e.name AS other_name, e.entity_type AS other_type
                   FROM relationships r
                   JOIN entities e ON e.id = CASE
                       WHEN r.source_entity_id = ? THEN r.target_entity_id
                       ELSE r.source_entity_id END
                   WHERE r.source_entity_id = ? OR r.target_entity_id = ?""",
                (entity_id, entity_id, entity_id),
            ).fetchall()
            entity["relationships"] = [dict(r) for r in rels]

            # Evidence links
            evidence = conn.execute(
                "SELECT * FROM entity_document_links WHERE entity_id = ? ORDER BY damning_score DESC",
                (entity_id,),
            ).fetchall()
            entity["evidence_links"] = [dict(e) for e in evidence]
            return entity
        finally:
            conn.close()

    def get_entity_evidence(
        self,
        entity_id: int,
        sort_by: str = "damning_score",
        limit: int = None,
    ) -> List[Dict[str, Any]]:
        """All evidence items for an entity, sorted and optionally limited."""
        valid_sorts = {"damning_score", "created_at", "evidence_type"}
        if sort_by not in valid_sorts:
            sort_by = "damning_score"
        order = "DESC" if sort_by == "damning_score" else "ASC"

        sql = f"""
            SELECT edl.*, d.original_filename, d.doc_type, d.file_path,
                   d.source, d.priority_score AS doc_priority
            FROM entity_document_links edl
            JOIN documents d ON d.id = edl.document_id
            WHERE edl.entity_id = ?
            ORDER BY edl.{sort_by} {order}
        """
        if limit:
            sql += f" LIMIT {int(limit)}"

        conn = self.db.get_connection()
        try:
            rows = conn.execute(sql, (entity_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_entity_connections(
        self, entity_id: int, degrees: int = 1
    ) -> Dict[str, Any]:
        """All connected entities up to *degrees* hops away."""
        G = self.nx_graph
        if entity_id not in G:
            return {"center": entity_id, "nodes": [], "edges": []}

        visited = {entity_id}
        frontier = {entity_id}
        collected_edges = []

        for _depth in range(degrees):
            next_frontier = set()
            for node in frontier:
                for neighbor in G.neighbors(node):
                    edge_data = G[node][neighbor]
                    collected_edges.append({
                        "source": node,
                        "target": neighbor,
                        "rel_type": edge_data.get("rel_type"),
                        "weight": edge_data.get("weight", 1.0),
                    })
                    if neighbor not in visited:
                        next_frontier.add(neighbor)
                        visited.add(neighbor)
            frontier = next_frontier

        node_details = []
        conn = self.db.get_connection()
        try:
            for nid in visited:
                row = conn.execute(
                    "SELECT id, name, canonical_name, entity_type, implication_score FROM entities WHERE id = ?",
                    (nid,),
                ).fetchone()
                if row:
                    node_details.append(dict(row))
        finally:
            conn.close()

        return {
            "center": entity_id,
            "nodes": node_details,
            "edges": collected_edges,
        }

    def search_entities(
        self, query: str, entity_type: str = None
    ) -> List[Dict[str, Any]]:
        """Full-text search across entity names, aliases, descriptions."""
        conn = self.db.get_connection()
        try:
            # Wrap in double quotes to disable FTS5 operators
            fts_query = '"' + query.replace('"', '""') + '"'
            if entity_type:
                sql = """
                    SELECT e.*
                    FROM entities e
                    JOIN entities_fts fts ON fts.rowid = e.id
                    WHERE entities_fts MATCH ? AND e.entity_type = ?
                    ORDER BY e.implication_score DESC
                    LIMIT 200
                """
                rows = conn.execute(sql, (fts_query, entity_type)).fetchall()
            else:
                sql = """
                    SELECT e.*
                    FROM entities e
                    JOIN entities_fts fts ON fts.rowid = e.id
                    WHERE entities_fts MATCH ?
                    ORDER BY e.implication_score DESC
                    LIMIT 200
                """
                rows = conn.execute(sql, (fts_query,)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            # Fallback to LIKE if FTS fails (e.g. special characters)
            safe = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{safe}%"
            if entity_type:
                rows = conn.execute(
                    r"SELECT * FROM entities WHERE (name LIKE ? ESCAPE '\' OR canonical_name LIKE ? ESCAPE '\' OR aliases LIKE ? ESCAPE '\') AND entity_type = ? ORDER BY implication_score DESC LIMIT 200",
                    (like, like, like, entity_type),
                ).fetchall()
            else:
                rows = conn.execute(
                    r"SELECT * FROM entities WHERE name LIKE ? ESCAPE '\' OR canonical_name LIKE ? ESCAPE '\' OR aliases LIKE ? ESCAPE '\' ORDER BY implication_score DESC LIMIT 200",
                    (like, like, like),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_implication_rankings(
        self, limit: int = 50, entity_type: str = None
    ) -> List[Dict[str, Any]]:
        """Global leaderboard sorted by implication_score."""
        conn = self.db.get_connection()
        try:
            if entity_type:
                rows = conn.execute(
                    """SELECT id, name, canonical_name, entity_type, implication_score,
                              evidence_count, document_count, role, title, organization,
                              is_victim, is_minor
                       FROM entities
                       WHERE entity_type = ? AND is_victim = 0
                       ORDER BY implication_score DESC
                       LIMIT ?""",
                    (entity_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, name, canonical_name, entity_type, implication_score,
                              evidence_count, document_count, role, title, organization,
                              is_victim, is_minor
                       FROM entities
                       WHERE is_victim = 0
                       ORDER BY implication_score DESC
                       LIMIT ?""",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ===================================================================
# 2. EntityResolver
# ===================================================================

_TITLE_PREFIXES = re.compile(
    r"^(mr\.?|mrs\.?|ms\.?|dr\.?|prof\.?|sir|lord|lady|hon\.?|"
    r"honorable|senator|rep\.?|representative|president|"
    r"governor|gov\.?|judge|justice|gen\.?|general|col\.?|"
    r"colonel|maj\.?|major|cpt\.?|captain|sgt\.?|sergeant|"
    r"prince|princess|king|queen|duke|duchess|"
    r"rev\.?|reverend|bishop|cardinal|rabbi|imam)\s+",
    re.IGNORECASE,
)

_SUFFIX_PATTERNS = re.compile(
    r",?\s+(jr\.?|sr\.?|iii?|iv|esq\.?|phd|md|dds|jd|mba|cpa)\s*$",
    re.IGNORECASE,
)


class EntityResolver:
    """Handles entity name normalisation, alias resolution, and merging."""

    def __init__(self, config: dict = None):
        self.config = config or {}

    @staticmethod
    def normalize_name(name: str) -> str:
        """Produce a canonical form of a name."""
        if not name:
            return ""
        n = name.strip()
        # Strip titles
        n = _TITLE_PREFIXES.sub("", n)
        # Strip suffixes
        n = _SUFFIX_PATTERNS.sub("", n)
        # Collapse whitespace
        n = re.sub(r"\s+", " ", n).strip()
        # Uppercase for canonical storage
        n = n.upper()
        return n

    def resolve_aliases(self, name: str, db: DatabaseManager) -> Optional[int]:
        """Check if *name* is a known alias for an existing entity.

        Returns the entity_id if found, else ``None``.
        """
        canonical = self.normalize_name(name)
        conn = db.get_connection()
        try:
            # Direct canonical match
            row = conn.execute(
                "SELECT id FROM entities WHERE canonical_name = ?", (canonical,)
            ).fetchone()
            if row:
                return row["id"]

            # Filter aliases at DB level using canonical form, then verify with normalization
            rows = conn.execute(
                "SELECT id, aliases FROM entities WHERE aliases LIKE ? ESCAPE '\\' OR aliases LIKE ? ESCAPE '\\'",
                (f"%{_escape_like(name)}%", f"%{_escape_like(canonical)}%"),
            ).fetchall()
            for r in rows:
                aliases = _json_loads_safe(r["aliases"])
                for alias in aliases:
                    if self.normalize_name(alias) == canonical:
                        return r["id"]
            return None
        finally:
            conn.close()

    def merge_entities(
        self, entity_id_1: int, entity_id_2: int, db: DatabaseManager
    ) -> int:
        """Merge *entity_id_2* into *entity_id_1*.

        - All relationships from entity_2 are re-pointed to entity_1.
        - All evidence links are moved.
        - entity_2's aliases are appended to entity_1.
        - entity_2 is deleted.

        Returns *entity_id_1* (the survivor).
        """
        conn = db.get_connection()
        try:
            e1 = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id_1,)).fetchone()
            e2 = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id_2,)).fetchone()
            if not e1 or not e2:
                raise ValueError("Both entity IDs must exist.")

            # Merge aliases
            a1 = _json_loads_safe(e1["aliases"])
            a2 = _json_loads_safe(e2["aliases"])
            merged = _merge_alias_lists(a1, a2 + [e2["name"]])
            conn.execute(
                "UPDATE entities SET aliases = ?, updated_at = ? WHERE id = ?",
                (json.dumps(merged), _now_iso(), entity_id_1),
            )

            # Re-point relationships (source side)
            conn.execute(
                """UPDATE OR IGNORE relationships SET source_entity_id = ?, updated_at = ?
                   WHERE source_entity_id = ?""",
                (entity_id_1, _now_iso(), entity_id_2),
            )
            # Re-point relationships (target side)
            conn.execute(
                """UPDATE OR IGNORE relationships SET target_entity_id = ?, updated_at = ?
                   WHERE target_entity_id = ?""",
                (entity_id_1, _now_iso(), entity_id_2),
            )
            # Delete any remaining dupe relationships (those that already existed
            # on entity_1 and thus failed the OR IGNORE)
            conn.execute(
                "DELETE FROM relationships WHERE source_entity_id = ? OR target_entity_id = ?",
                (entity_id_2, entity_id_2),
            )

            # Re-point entity_document_links
            conn.execute(
                """UPDATE OR IGNORE entity_document_links SET entity_id = ?
                   WHERE entity_id = ?""",
                (entity_id_1, entity_id_2),
            )
            conn.execute(
                "DELETE FROM entity_document_links WHERE entity_id = ?",
                (entity_id_2,),
            )

            # Accumulate scores
            new_evidence_count = (e1["evidence_count"] or 0) + (e2["evidence_count"] or 0)
            new_doc_count = (e1["document_count"] or 0) + (e2["document_count"] or 0)
            conn.execute(
                """UPDATE entities SET evidence_count = ?, document_count = ?, updated_at = ?
                   WHERE id = ?""",
                (new_evidence_count, new_doc_count, _now_iso(), entity_id_1),
            )

            # Remove FTS entry for entity_2
            conn.execute("DELETE FROM entities_fts WHERE rowid = ?", (entity_id_2,))
            # Remove entity_2
            conn.execute("DELETE FROM entities WHERE id = ?", (entity_id_2,))
            conn.commit()
            return entity_id_1
        finally:
            conn.close()

    @staticmethod
    def generate_external_links(name: str, entity_type: str) -> Dict[str, Any]:
        """Generate helpful external URLs for quick researcher lookup."""
        encoded = urllib.parse.quote_plus(name)
        links: Dict[str, Any] = {
            "google_url": f"https://www.google.com/search?q={encoded}",
            "external_links": [],
        }
        if entity_type == "person":
            links["wikipedia_url"] = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(name.replace(' ', '_'))}"
            links["external_links"].append({
                "label": "LinkedIn",
                "url": f"https://www.linkedin.com/search/results/people/?keywords={encoded}",
            })
        elif entity_type == "organization":
            links["wikipedia_url"] = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(name.replace(' ', '_'))}"
            links["external_links"].append({
                "label": "OpenCorporates",
                "url": f"https://opencorporates.com/companies?q={encoded}",
            })
        elif entity_type == "location":
            links["external_links"].append({
                "label": "Google Maps",
                "url": f"https://www.google.com/maps/search/{encoded}",
            })
        return links


def _merge_alias_lists(existing: list, new: list) -> list:
    """Merge two lists of alias strings, dedup by normalised form."""
    seen = set()
    result = []
    for item in existing + new:
        norm = EntityResolver.normalize_name(item)
        if norm and norm not in seen:
            seen.add(norm)
            result.append(item)
    return result


# ===================================================================
# 3. ConnectionMapper
# ===================================================================

class ConnectionMapper:
    """Given a document, creates / updates relationship edges between every
    entity found in that document."""

    def __init__(self, engine: GraphEngine):
        self.engine = engine
        self.db = engine.db

    def map_document_connections(self, document_id: int) -> List[int]:
        """Process all entities in a document and create appropriate edges.

        Returns a list of relationship IDs that were created / updated.
        """
        conn = self.db.get_connection()
        try:
            doc = conn.execute(
                "SELECT id, doc_type FROM documents WHERE id = ?", (document_id,)
            ).fetchone()
            if doc is None:
                return []

            doc_type = doc["doc_type"]

            # All entity-document links for this doc
            links = conn.execute(
                "SELECT entity_id, mention_type FROM entity_document_links WHERE document_id = ?",
                (document_id,),
            ).fetchall()

            entity_ids = [r["entity_id"] for r in links]
            mention_map = {r["entity_id"]: r["mention_type"] for r in links}
            if len(entity_ids) < 2:
                return []

            created_rels: List[int] = []

            # Dispatch to specialised handler based on doc_type
            if doc_type == "email":
                created_rels.extend(self._map_email(document_id, links, conn))
            elif doc_type == "flight_log":
                created_rels.extend(self._map_flight_log(document_id, entity_ids))
            elif doc_type == "financial":
                created_rels.extend(self._map_financial(document_id, entity_ids))

            # Generic co-occurrence for all doc types
            created_rels.extend(self._map_co_occurrence(document_id, entity_ids))

            return created_rels
        finally:
            conn.close()

    def _map_co_occurrence(self, document_id: int, entity_ids: List[int]) -> List[int]:
        """Create ``co_occurs_with`` edges between every pair of entities in the document."""
        rels = []
        for a, b in combinations(sorted(set(entity_ids)), 2):
            rid = self.engine.add_relationship(
                a, b, "co_occurs_with", document_id, confidence=0.6,
            )
            rels.append(rid)
        return rels

    def _map_email(self, document_id: int, links: list, conn) -> List[int]:
        """Create ``emailed`` edges from sender to each recipient."""
        rels = []
        msg = conn.execute(
            "SELECT from_name, to_addresses, cc_addresses, email_date FROM email_messages WHERE document_id = ?",
            (document_id,),
        ).fetchone()
        if msg is None:
            return rels

        observed_date = msg["email_date"]

        senders = [
            lnk["entity_id"]
            for lnk in links
            if lnk["mention_type"] == "author"
        ]
        recipients = [
            lnk["entity_id"]
            for lnk in links
            if lnk["mention_type"] == "recipient"
        ]

        for s in senders:
            for r in recipients:
                if s != r:
                    rid = self.engine.add_relationship(
                        s, r, "emailed", document_id,
                        confidence=0.9,
                        observed_date=observed_date,
                    )
                    rels.append(rid)
        return rels

    def _map_flight_log(self, document_id: int, entity_ids: List[int]) -> List[int]:
        """Create ``flew_with`` edges between all passengers on the same flight."""
        rels = []
        for a, b in combinations(sorted(set(entity_ids)), 2):
            rid = self.engine.add_relationship(
                a, b, "flew_with", document_id, confidence=0.95,
            )
            rels.append(rid)
        return rels

    def _map_financial(self, document_id: int, entity_ids: List[int]) -> List[int]:
        """Create ``financially_linked`` edges between entities in financial docs."""
        rels = []
        for a, b in combinations(sorted(set(entity_ids)), 2):
            rid = self.engine.add_relationship(
                a, b, "financially_linked", document_id, confidence=0.8,
            )
            rels.append(rid)
        return rels

    def update_relationship_weight(self, rel_id: int):
        """Recalculate weight for a relationship based on its total evidence."""
        conn = self.db.get_connection()
        try:
            row = conn.execute(
                "SELECT evidence_count, relationship_type FROM relationships WHERE id = ?",
                (rel_id,),
            ).fetchone()
            if row:
                new_weight = GraphEngine._compute_weight(
                    row["evidence_count"], row["relationship_type"]
                )
                conn.execute(
                    "UPDATE relationships SET weight = ?, updated_at = ? WHERE id = ?",
                    (new_weight, _now_iso(), rel_id),
                )
                conn.commit()
        finally:
            conn.close()


# ===================================================================
# 4. PatternDetector
# ===================================================================

class PatternDetector:
    """Runs analytical queries over the knowledge graph to detect non-obvious
    patterns that human reviewers might miss."""

    def __init__(self, engine: GraphEngine):
        self.engine = engine
        self.db = engine.db

    def detect_all(self):
        """Convenience: run every detector."""
        logger.info("Running all pattern detectors...")
        self.detect_co_occurrence_patterns()
        self.detect_temporal_clusters()
        self.detect_financial_patterns()
        self.detect_communication_spikes()
        self.detect_redaction_patterns()
        self.detect_transitive_connections()
        logger.info("Pattern detection complete.")

    # ------------------------------------------------------------------

    def detect_co_occurrence_patterns(self, min_count: int = 3) -> List[Dict]:
        """Find entity pairs that appear together unusually often."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT source_entity_id, target_entity_id, evidence_count, weight
                   FROM relationships
                   WHERE relationship_type = 'co_occurs_with'
                     AND evidence_count >= ?
                   ORDER BY evidence_count DESC
                   LIMIT 500""",
                (min_count,),
            ).fetchall()

            patterns = []
            for r in rows:
                patterns.append({
                    "source_id": r["source_entity_id"],
                    "target_id": r["target_entity_id"],
                    "co_occurrence_count": r["evidence_count"],
                    "weight": r["weight"],
                })
            logger.info("Co-occurrence patterns found: %d", len(patterns))
            return patterns
        finally:
            conn.close()

    def detect_temporal_clusters(
        self, window_days: int = 3
    ) -> List[Dict]:
        """Find groups of people at the same location within narrow time windows.

        Examines flight logs and events for temporal proximity.
        """
        conn = self.db.get_connection()
        try:
            # Grab all flight_log and event evidence with dates
            rows = conn.execute(
                """SELECT edl.entity_id, d.doc_type, edl.created_at,
                          edl.context_snippet, edl.document_id
                   FROM entity_document_links edl
                   JOIN documents d ON d.id = edl.document_id
                   WHERE d.doc_type IN ('flight_log', 'event')
                   ORDER BY edl.created_at"""
            ).fetchall()

            if not rows:
                return []

            # Group by document date (day granularity)
            by_date: Dict[str, List[dict]] = defaultdict(list)
            for r in rows:
                date_key = (r["created_at"] or "")[:10]
                if date_key:
                    by_date[date_key].append(dict(r))

            clusters = []
            sorted_dates = sorted(by_date.keys())
            for i, d1 in enumerate(sorted_dates):
                window_entities = set()
                window_docs = set()
                for j in range(i, len(sorted_dates)):
                    try:
                        dt1 = datetime.fromisoformat(d1)
                        dt2 = datetime.fromisoformat(sorted_dates[j])
                    except ValueError:
                        continue
                    if (dt2 - dt1).days > window_days:
                        break
                    for item in by_date[sorted_dates[j]]:
                        window_entities.add(item["entity_id"])
                        window_docs.add(item["document_id"])

                if len(window_entities) >= 3:
                    clusters.append({
                        "date_start": d1,
                        "date_end": sorted_dates[min(i + window_days, len(sorted_dates) - 1)],
                        "entity_ids": list(window_entities),
                        "document_ids": list(window_docs),
                        "entity_count": len(window_entities),
                    })

            # Create inferred relationships for cluster members
            for cluster in clusters:
                for a, b in combinations(cluster["entity_ids"], 2):
                    self.engine.add_relationship(
                        a, b, "temporal_cluster",
                        evidence_doc_id=cluster["document_ids"][0] if cluster["document_ids"] else None,
                        is_inferred=True,
                        inference_method="temporal",
                        notes=f"Clustered {cluster['date_start']}..{cluster['date_end']}",
                    )

            logger.info("Temporal clusters found: %d", len(clusters))
            return clusters
        finally:
            conn.close()

    def detect_financial_patterns(self) -> List[Dict]:
        """Detect payment-after-travel sequences and shell company chains."""
        conn = self.db.get_connection()
        try:
            # Find entities with both flight_log and financial evidence
            rows = conn.execute(
                """SELECT edl.entity_id,
                          GROUP_CONCAT(DISTINCT d.doc_type) AS doc_types,
                          COUNT(DISTINCT d.id) AS doc_count
                   FROM entity_document_links edl
                   JOIN documents d ON d.id = edl.document_id
                   WHERE d.doc_type IN ('flight_log', 'financial')
                   GROUP BY edl.entity_id
                   HAVING COUNT(DISTINCT d.doc_type) >= 2"""
            ).fetchall()

            patterns = []
            for r in rows:
                entity_id = r["entity_id"]
                # Get the chronological evidence
                evidence = conn.execute(
                    """SELECT d.doc_type, edl.created_at, edl.document_id
                       FROM entity_document_links edl
                       JOIN documents d ON d.id = edl.document_id
                       WHERE edl.entity_id = ? AND d.doc_type IN ('flight_log', 'financial')
                       ORDER BY edl.created_at""",
                    (entity_id,),
                ).fetchall()

                # Look for flight -> financial sequence
                last_flight = None
                for ev in evidence:
                    if ev["doc_type"] == "flight_log":
                        last_flight = ev["created_at"]
                    elif ev["doc_type"] == "financial" and last_flight:
                        try:
                            t_flight = datetime.fromisoformat(last_flight)
                            t_fin = datetime.fromisoformat(ev["created_at"])
                            gap_days = (t_fin - t_flight).days
                            if 0 <= gap_days <= 30:
                                patterns.append({
                                    "entity_id": entity_id,
                                    "pattern": "payment_after_travel",
                                    "flight_date": last_flight,
                                    "financial_date": ev["created_at"],
                                    "gap_days": gap_days,
                                    "document_id": ev["document_id"],
                                })
                        except (ValueError, TypeError):
                            pass

            # Shell company chains: organizations linked to many financially_linked persons
            org_links = conn.execute(
                """SELECT e.id, e.name, COUNT(r.id) AS link_count
                   FROM entities e
                   JOIN relationships r ON (r.source_entity_id = e.id OR r.target_entity_id = e.id)
                   WHERE e.entity_type = 'organization'
                     AND r.relationship_type = 'financially_linked'
                   GROUP BY e.id
                   HAVING link_count >= 3
                   ORDER BY link_count DESC"""
            ).fetchall()
            for r in org_links:
                patterns.append({
                    "entity_id": r["id"],
                    "entity_name": r["name"],
                    "pattern": "shell_company_hub",
                    "connection_count": r["link_count"],
                })

            logger.info("Financial patterns found: %d", len(patterns))
            return patterns
        finally:
            conn.close()

    def detect_communication_spikes(
        self, z_threshold: float = 2.0
    ) -> List[Dict]:
        """Find periods of intense email activity between entity pairs."""
        conn = self.db.get_connection()
        try:
            # Get email relationships with date ranges
            rels = conn.execute(
                """SELECT id, source_entity_id, target_entity_id,
                          evidence_document_ids, evidence_count
                   FROM relationships
                   WHERE relationship_type = 'emailed' AND evidence_count >= 3"""
            ).fetchall()

            spikes = []
            for rel in rels:
                doc_ids = _json_loads_safe(rel["evidence_document_ids"])
                if not doc_ids:
                    continue

                placeholders = ",".join("?" for _ in doc_ids)
                dates = conn.execute(
                    f"""SELECT em.email_date
                        FROM email_messages em
                        WHERE em.document_id IN ({placeholders})
                          AND em.email_date IS NOT NULL
                        ORDER BY em.email_date""",
                    doc_ids,
                ).fetchall()

                if len(dates) < 3:
                    continue

                # Bucket by month
                monthly: Counter = Counter()
                for d in dates:
                    month_key = (d["email_date"] or "")[:7]
                    if month_key:
                        monthly[month_key] += 1

                if len(monthly) < 2:
                    continue

                counts = list(monthly.values())
                mean = statistics.mean(counts)
                stdev = statistics.stdev(counts) if len(counts) > 1 else 0
                if stdev == 0:
                    continue

                for month, count in monthly.items():
                    z = (count - mean) / stdev
                    if z >= z_threshold:
                        spikes.append({
                            "source_entity_id": rel["source_entity_id"],
                            "target_entity_id": rel["target_entity_id"],
                            "month": month,
                            "email_count": count,
                            "z_score": round(z, 2),
                        })

            logger.info("Communication spikes found: %d", len(spikes))
            return spikes
        finally:
            conn.close()

    def detect_redaction_patterns(self) -> List[Dict]:
        """Find people who appear ONLY in heavily redacted documents."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT e.id, e.name, e.entity_type,
                          COUNT(DISTINCT edl.document_id) AS total_docs,
                          SUM(CASE WHEN dp.has_redactions = 1 THEN 1 ELSE 0 END) AS redacted_docs,
                          COALESCE(SUM(dp.redaction_count), 0) AS total_redactions
                   FROM entities e
                   JOIN entity_document_links edl ON edl.entity_id = e.id
                   JOIN document_pages dp ON dp.document_id = edl.document_id
                   GROUP BY e.id
                   HAVING total_docs > 0"""
            ).fetchall()

            patterns = []
            for r in rows:
                total = r["total_docs"]
                redacted = r["redacted_docs"]
                if total > 0 and redacted / total >= 0.8 and r["total_redactions"] >= 5:
                    patterns.append({
                        "entity_id": r["id"],
                        "entity_name": r["name"],
                        "total_documents": total,
                        "redacted_documents": redacted,
                        "redaction_ratio": round(redacted / total, 2),
                        "total_redactions_near": r["total_redactions"],
                        "pattern": "redaction_concealment",
                    })

            logger.info("Redaction-concealment patterns found: %d", len(patterns))
            return patterns
        finally:
            conn.close()

    def detect_transitive_connections(self, max_degrees: int = 3) -> List[Dict]:
        """If A->B and B->C, map A->C with degrees-of-separation score."""
        G = self.engine.nx_graph
        inferred: List[Dict] = []

        # Only consider high-weight direct edges as seed
        strong_edges = [
            (u, v) for u, v, d in G.edges(data=True)
            if d.get("weight", 1.0) >= 2.0
        ]

        seen_pairs = set()
        for u, v in strong_edges:
            # BFS from u up to max_degrees
            visited = {u}
            frontier = {u}
            for depth in range(1, max_degrees + 1):
                next_frontier = set()
                for node in frontier:
                    for neighbor in G.neighbors(node):
                        if neighbor not in visited:
                            next_frontier.add(neighbor)
                            visited.add(neighbor)
                            if depth >= 2:
                                pair = tuple(sorted((u, neighbor)))
                                if pair not in seen_pairs and not G.has_edge(u, neighbor):
                                    seen_pairs.add(pair)
                                    self.engine.add_relationship(
                                        u, neighbor, "transitive_connection",
                                        is_inferred=True,
                                        inference_method="transitive",
                                        confidence=round(1.0 / depth, 2),
                                        notes=f"{depth} degrees of separation",
                                    )
                                    inferred.append({
                                        "source": u,
                                        "target": neighbor,
                                        "degrees": depth,
                                    })
                frontier = next_frontier

        logger.info("Transitive connections inferred: %d", len(inferred))
        return inferred


# ===================================================================
# 5. RedactionResolver
# ===================================================================

class RedactionResolver:
    """Tracks redacted content and attempts to resolve what (or who) was hidden."""

    def __init__(self, engine: GraphEngine):
        self.engine = engine
        self.db = engine.db
        self.kg_config = engine.kg_config.get("redaction_resolution", {})
        self.min_confidence = self.kg_config.get("min_confidence_for_suggestion", 0.3)

    def create_redaction_placeholder(
        self, redaction_id: int, context: str
    ) -> int:
        """Create a ``redacted_entity`` node linked to a redaction record."""
        entity_id = self.engine.add_entity(
            name=f"[REDACTED-{redaction_id}]",
            entity_type="redacted_entity",
            description=f"Placeholder for redaction #{redaction_id}. Context: {context[:500]}",
            is_redacted_placeholder=True,
        )
        # Link to the redaction's document
        conn = self.db.get_connection()
        try:
            red = conn.execute(
                "SELECT document_id, page_number FROM redactions WHERE id = ?",
                (redaction_id,),
            ).fetchone()
            if red:
                conn.execute(
                    """INSERT OR IGNORE INTO entity_document_links
                       (entity_id, document_id, page_number, mention_type, evidence_type, context_snippet)
                       VALUES (?, ?, ?, 'mentioned', 'other', ?)""",
                    (entity_id, red["document_id"], red["page_number"], context[:500]),
                )
                conn.commit()
        finally:
            conn.close()
        return entity_id

    def add_candidate(
        self,
        redaction_entity_id: int,
        candidate_entity_id: int,
        confidence: float,
        reasoning: str,
    ):
        """Add an inference candidate for a redacted placeholder."""
        conn = self.db.get_connection()
        try:
            row = conn.execute(
                "SELECT description FROM entities WHERE id = ?",
                (redaction_entity_id,),
            ).fetchone()
            if not row:
                return

            # Find the linked redaction record
            link = conn.execute(
                "SELECT document_id FROM entity_document_links WHERE entity_id = ? LIMIT 1",
                (redaction_entity_id,),
            ).fetchone()
            if not link:
                return

            # Update the redaction record's ai_candidates
            reds = conn.execute(
                "SELECT id, ai_candidates FROM redactions WHERE document_id = ?",
                (link["document_id"],),
            ).fetchall()

            cand_entity = conn.execute(
                "SELECT name FROM entities WHERE id = ?", (candidate_entity_id,)
            ).fetchone()
            cand_name = cand_entity["name"] if cand_entity else f"entity-{candidate_entity_id}"

            for red in reds:
                candidates = _json_loads_safe(red["ai_candidates"])
                # Don't duplicate
                if any(c.get("entity_id") == candidate_entity_id for c in candidates):
                    continue
                candidates.append({
                    "entity_id": candidate_entity_id,
                    "name": cand_name,
                    "confidence": confidence,
                    "reasoning": reasoning,
                })
                candidates.sort(key=lambda c: c["confidence"], reverse=True)
                conn.execute(
                    "UPDATE redactions SET ai_candidates = ?, status = 'inferred', updated_at = ? WHERE id = ?",
                    (json.dumps(candidates), _now_iso(), red["id"]),
                )
            conn.commit()
        finally:
            conn.close()

    def re_evaluate_all(self):
        """Re-score all unresolved redactions against the current entity list."""
        conn = self.db.get_connection()
        try:
            placeholders = conn.execute(
                "SELECT id, description FROM entities WHERE is_redacted_placeholder = 1"
            ).fetchall()

            all_entities = conn.execute(
                "SELECT id, name, canonical_name, entity_type FROM entities WHERE is_redacted_placeholder = 0"
            ).fetchall()

            for ph in placeholders:
                context = (ph["description"] or "").lower()
                if not context:
                    continue
                for ent in all_entities:
                    name_lower = (ent["name"] or "").lower()
                    canonical_lower = (ent["canonical_name"] or "").lower()
                    # Simple heuristic: if the entity name appears in the surrounding context
                    score = 0.0
                    if name_lower and name_lower in context:
                        score = 0.6
                    elif canonical_lower and canonical_lower in context:
                        score = 0.5
                    else:
                        # Token overlap
                        name_tokens = set(name_lower.split())
                        ctx_tokens = set(context.split())
                        overlap = name_tokens & ctx_tokens
                        if len(name_tokens) > 0 and len(overlap) / len(name_tokens) >= 0.5:
                            score = 0.3

                    if score >= self.min_confidence:
                        self.add_candidate(
                            ph["id"], ent["id"], score,
                            f"Re-evaluation: name overlap score {score:.2f}",
                        )

            logger.info("Re-evaluated %d redaction placeholders against %d entities.",
                        len(placeholders), len(all_entities))
        finally:
            conn.close()

    def on_new_evidence(self, entity_id: int):
        """When new evidence arrives for an entity, check if it resolves any
        pending redactions."""
        conn = self.db.get_connection()
        try:
            entity = conn.execute(
                "SELECT name, canonical_name FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()
            if not entity:
                return

            unresolved = conn.execute(
                "SELECT id, context_before, context_after FROM redactions WHERE status = 'unresolved'"
            ).fetchall()

            name_lower = (entity["name"] or "").lower()
            for red in unresolved:
                ctx = ((red["context_before"] or "") + " " + (red["context_after"] or "")).lower()
                if name_lower and name_lower in ctx:
                    # Find or create placeholder for this redaction
                    ph = conn.execute(
                        """SELECT edl.entity_id FROM entity_document_links edl
                           JOIN entities e ON e.id = edl.entity_id
                           JOIN redactions r ON r.document_id = edl.document_id
                           WHERE r.id = ? AND e.is_redacted_placeholder = 1
                           LIMIT 1""",
                        (red["id"],),
                    ).fetchone()
                    if ph:
                        self.add_candidate(
                            ph["entity_id"], entity_id, 0.55,
                            "Context match on new evidence",
                        )
        finally:
            conn.close()

    def promote_candidate(
        self, redaction_entity_id: int, confirmed_entity_id: int
    ):
        """User confirms: merge the redacted placeholder into the real entity."""
        resolver = EntityResolver(self.engine.config)
        resolver.merge_entities(confirmed_entity_id, redaction_entity_id, self.db)

        # Mark all linked redaction records as confirmed
        conn = self.db.get_connection()
        try:
            confirmed_name = conn.execute(
                "SELECT name FROM entities WHERE id = ?", (confirmed_entity_id,)
            ).fetchone()
            name = confirmed_name["name"] if confirmed_name else ""
            # Find redactions that had this entity as a candidate
            # Use json_each to match exact entity_id in JSON array, avoiding substring collisions
            conn.execute(
                """UPDATE redactions
                   SET status = 'confirmed_by_user',
                       user_confirmed_value = ?,
                       updated_at = ?
                   WHERE id IN (
                       SELECT r.id FROM redactions r, json_each(r.ai_candidates) j
                       WHERE json_extract(j.value, '$.entity_id') = ?
                   )""",
                (name, _now_iso(), confirmed_entity_id),
            )
            conn.commit()
        finally:
            conn.close()
        self.engine.invalidate_cache()


# ===================================================================
# 6. TemporalAnalyzer
# ===================================================================

class TemporalAnalyzer:
    """Time-based analysis of entity activity."""

    def __init__(self, engine: GraphEngine):
        self.engine = engine
        self.db = engine.db

    def build_timeline(self, entity_id: int) -> List[Dict[str, Any]]:
        """Chronological list of all events/documents involving an entity."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                """SELECT edl.document_id, edl.mention_type, edl.evidence_type,
                          edl.context_snippet, edl.damning_score, edl.created_at,
                          d.original_filename, d.doc_type, d.source,
                          em.email_date, em.subject
                   FROM entity_document_links edl
                   JOIN documents d ON d.id = edl.document_id
                   LEFT JOIN email_messages em ON em.document_id = d.id
                   WHERE edl.entity_id = ?
                   ORDER BY COALESCE(em.email_date, edl.created_at) ASC""",
                (entity_id,),
            ).fetchall()

            timeline = []
            for r in rows:
                event_date = r["email_date"] or r["created_at"]
                timeline.append({
                    "date": event_date,
                    "document_id": r["document_id"],
                    "filename": r["original_filename"],
                    "doc_type": r["doc_type"],
                    "mention_type": r["mention_type"],
                    "evidence_type": r["evidence_type"],
                    "email_subject": r["subject"],
                    "context": r["context_snippet"],
                    "damning_score": r["damning_score"],
                    "source": r["source"],
                })
            return timeline
        finally:
            conn.close()

    def find_activity_spikes(
        self, entity_id: int, window_days: int = 30, z_threshold: float = 2.0
    ) -> List[Dict[str, Any]]:
        """Periods of unusually high document frequency for an entity."""
        timeline = self.build_timeline(entity_id)
        if len(timeline) < 5:
            return []

        # Bucket by month
        monthly: Counter = Counter()
        for event in timeline:
            date_str = (event["date"] or "")[:7]  # YYYY-MM
            if date_str:
                monthly[date_str] += 1

        if len(monthly) < 2:
            return []

        counts = list(monthly.values())
        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 0
        if stdev == 0:
            return []

        spikes = []
        for month, count in sorted(monthly.items()):
            z = (count - mean) / stdev
            if z >= z_threshold:
                spikes.append({
                    "entity_id": entity_id,
                    "period": month,
                    "document_count": count,
                    "z_score": round(z, 2),
                    "mean": round(mean, 2),
                    "stdev": round(stdev, 2),
                })
        return spikes

    def correlate_timelines(
        self, entity_id_1: int, entity_id_2: int
    ) -> Dict[str, Any]:
        """Find periods where both entities are active simultaneously."""
        tl1 = self.build_timeline(entity_id_1)
        tl2 = self.build_timeline(entity_id_2)

        months_1: Counter = Counter()
        months_2: Counter = Counter()
        for e in tl1:
            m = (e["date"] or "")[:7]
            if m:
                months_1[m] += 1
        for e in tl2:
            m = (e["date"] or "")[:7]
            if m:
                months_2[m] += 1

        overlap_months = set(months_1.keys()) & set(months_2.keys())
        all_months = set(months_1.keys()) | set(months_2.keys())

        overlap_score = len(overlap_months) / len(all_months) if all_months else 0.0

        # Pearson-style correlation on overlapping months
        if len(overlap_months) >= 3:
            vals1 = [months_1[m] for m in sorted(overlap_months)]
            vals2 = [months_2[m] for m in sorted(overlap_months)]
            try:
                mean1 = statistics.mean(vals1)
                mean2 = statistics.mean(vals2)
                num = sum((a - mean1) * (b - mean2) for a, b in zip(vals1, vals2))
                den1 = math.sqrt(sum((a - mean1) ** 2 for a in vals1))
                den2 = math.sqrt(sum((b - mean2) ** 2 for b in vals2))
                correlation = num / (den1 * den2) if den1 * den2 > 0 else 0.0
            except (statistics.StatisticsError, ZeroDivisionError):
                correlation = 0.0
        else:
            correlation = 0.0

        return {
            "entity_id_1": entity_id_1,
            "entity_id_2": entity_id_2,
            "overlap_months": sorted(overlap_months),
            "overlap_ratio": round(overlap_score, 3),
            "correlation": round(correlation, 3),
            "entity_1_months": len(months_1),
            "entity_2_months": len(months_2),
        }

    def get_event_cluster(
        self,
        date_start: str,
        date_end: str,
        location: str = None,
    ) -> List[Dict[str, Any]]:
        """All entities active in a time window, optionally at a location."""
        conn = self.db.get_connection()
        try:
            if location:
                rows = conn.execute(
                    """SELECT DISTINCT edl.entity_id, e.name, e.entity_type,
                              e.implication_score, edl.document_id,
                              COALESCE(em.email_date, edl.created_at) AS event_date
                       FROM entity_document_links edl
                       JOIN entities e ON e.id = edl.entity_id
                       JOIN documents d ON d.id = edl.document_id
                       LEFT JOIN email_messages em ON em.document_id = d.id
                       WHERE COALESCE(em.email_date, edl.created_at) BETWEEN ? AND ?
                         AND (edl.context_snippet LIKE ? ESCAPE '\\' OR d.original_filename LIKE ? ESCAPE '\\')
                       ORDER BY event_date""",
                    (date_start, date_end, f"%{_escape_like(location)}%", f"%{_escape_like(location)}%"),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT DISTINCT edl.entity_id, e.name, e.entity_type,
                              e.implication_score, edl.document_id,
                              COALESCE(em.email_date, edl.created_at) AS event_date
                       FROM entity_document_links edl
                       JOIN entities e ON e.id = edl.entity_id
                       LEFT JOIN email_messages em ON em.document_id = edl.document_id
                       WHERE COALESCE(em.email_date, edl.created_at) BETWEEN ? AND ?
                       ORDER BY event_date""",
                    (date_start, date_end),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ===================================================================
# 7. EvidenceScorer
# ===================================================================

class EvidenceScorer:
    """Scores evidence items and computes aggregate implication scores."""

    # Mapping from evidence_type / doc_type to config key
    _TYPE_MAP = {
        "flight_log": "flight_log",
        "email": "email_coordination",
        "financial": "financial_link",
        "testimony": "eyewitness_testimony",
        "court_filing": "direct_admission",
        "photo_video": "photo_video",
        "other": "general_cooccurrence",
    }

    def __init__(self, engine: GraphEngine):
        self.engine = engine
        self.db = engine.db
        self.weights = engine.evidence_config

    def score_evidence_item(
        self,
        entity_id: int,
        document_id: int,
        evidence_type: str,
        context: str = "",
    ) -> int:
        """Compute a 0-100 damning score for a single evidence link.

        Uses the scoring weights from settings.yaml and adjusts based on
        contextual signals in the snippet text.
        """
        config_key = self._TYPE_MAP.get(evidence_type, "general_cooccurrence")
        base_score = self.weights.get(config_key, 5)

        # Context modifiers
        modifier = 0
        ctx_lower = context.lower() if context else ""

        # Boost for redaction proximity
        if "redact" in ctx_lower or "[redacted]" in ctx_lower:
            modifier += self.weights.get("redaction_concealment", 15)

        # Boost if victim-related language
        victim_terms = ["victim", "minor", "underage", "assault", "abuse", "trafficking"]
        if any(t in ctx_lower for t in victim_terms):
            modifier += 10

        # Boost for direct naming
        conn = self.db.get_connection()
        try:
            ent = conn.execute("SELECT name FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if ent and ent["name"].lower() in ctx_lower:
                modifier += 5

            # Boost for removed-from-source documents
            doc = conn.execute(
                "SELECT is_removed_from_source FROM documents WHERE id = ?",
                (document_id,),
            ).fetchone()
            if doc and doc["is_removed_from_source"]:
                modifier += 15
        finally:
            conn.close()

        raw = base_score + modifier
        final = max(0, min(100, raw))

        # Persist
        conn = self.db.get_connection()
        try:
            conn.execute(
                """UPDATE entity_document_links
                   SET damning_score = ?, score_reasoning = ?, evidence_type = ?
                   WHERE entity_id = ? AND document_id = ?
                     AND user_score_locked = 0""",
                (
                    final,
                    json.dumps({"base": base_score, "modifier": modifier, "config_key": config_key}),
                    evidence_type,
                    entity_id, document_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        return final

    def recalculate_entity_score(self, entity_id: int) -> float:
        """Aggregate all evidence scores into an overall implication_score.

        Formula: weighted average of top evidence, boosted by evidence count
        and relationship strength.
        """
        conn = self.db.get_connection()
        try:
            # Check user lock
            ent = conn.execute(
                "SELECT user_score_locked, user_score FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()
            if ent and ent["user_score_locked"]:
                return ent["user_score"] or 0.0

            evidence = conn.execute(
                """SELECT damning_score FROM entity_document_links
                   WHERE entity_id = ? AND damning_score > 0
                   ORDER BY damning_score DESC""",
                (entity_id,),
            ).fetchall()

            if not evidence:
                conn.execute(
                    "UPDATE entities SET implication_score = 0, evidence_count = 0, updated_at = ? WHERE id = ?",
                    (_now_iso(), entity_id),
                )
                conn.commit()
                return 0.0

            scores = [r["damning_score"] for r in evidence]
            evidence_count = len(scores)

            # Weighted average: top items count more (exponential decay)
            total_weight = 0.0
            weighted_sum = 0.0
            for i, s in enumerate(scores):
                w = math.exp(-0.15 * i)  # top item w=1.0, 5th w~0.47, 10th w~0.22
                weighted_sum += s * w
                total_weight += w

            avg_score = weighted_sum / total_weight if total_weight > 0 else 0.0

            # Count boost: more evidence = higher confidence (capped)
            count_boost = min(20, math.log2(evidence_count + 1) * 5)

            # Relationship weight boost
            rel_rows = conn.execute(
                """SELECT SUM(weight) AS total_weight FROM relationships
                   WHERE source_entity_id = ? OR target_entity_id = ?""",
                (entity_id, entity_id),
            ).fetchone()
            rel_weight = rel_rows["total_weight"] or 0.0
            rel_boost = min(15, rel_weight * 0.5)

            # Document count
            doc_count_row = conn.execute(
                "SELECT COUNT(DISTINCT document_id) FROM entity_document_links WHERE entity_id = ?",
                (entity_id,),
            ).fetchone()
            doc_count = doc_count_row[0] if doc_count_row else 0

            final = min(100.0, avg_score + count_boost + rel_boost)
            final = round(final, 2)

            conn.execute(
                """UPDATE entities
                   SET implication_score = ?, evidence_count = ?, document_count = ?, updated_at = ?
                   WHERE id = ?""",
                (final, evidence_count, doc_count, _now_iso(), entity_id),
            )
            conn.commit()
            self.engine.invalidate_cache()
            return final
        finally:
            conn.close()

    def get_top_evidence(
        self, entity_id: int, n: int = 5
    ) -> List[Dict[str, Any]]:
        """Return the N highest-scored evidence items."""
        return self.engine.get_entity_evidence(entity_id, sort_by="damning_score", limit=n)

    def user_override_score(
        self, entity_id: int, document_id: int, score: int
    ):
        """User manually sets a score and locks it from being overwritten."""
        conn = self.db.get_connection()
        try:
            conn.execute(
                """UPDATE entity_document_links
                   SET user_damning_score = ?, damning_score = ?,
                       user_score_locked = 1
                   WHERE entity_id = ? AND document_id = ?""",
                (score, score, entity_id, document_id),
            )
            conn.commit()
        finally:
            conn.close()


# ===================================================================
# 8. GraphExporter
# ===================================================================

class GraphExporter:
    """Exports the knowledge graph to various formats for visualisation and
    public sharing."""

    def __init__(self, engine: GraphEngine):
        self.engine = engine
        self.db = engine.db
        self.export_config = engine.config.get("export", {})

    def export_for_d3(
        self, filters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """JSON format for D3.js force-directed graph.

        Returns ``{nodes: [...], links: [...], metadata: {...}}``.
        """
        conn = self.db.get_connection()
        try:
            entity_sql = """
                SELECT id, name, canonical_name, entity_type, implication_score,
                       evidence_count, document_count, role, is_victim
                FROM entities
                WHERE is_victim = 0
            """
            params: list = []
            if filters:
                if filters.get("entity_type"):
                    entity_sql += " AND entity_type = ?"
                    params.append(filters["entity_type"])
                if filters.get("min_score") is not None:
                    entity_sql += " AND implication_score >= ?"
                    params.append(filters["min_score"])
                if filters.get("max_entities"):
                    entity_sql += " ORDER BY implication_score DESC LIMIT ?"
                    params.append(filters["max_entities"])
                else:
                    entity_sql += " ORDER BY implication_score DESC"
            else:
                entity_sql += " ORDER BY implication_score DESC"

            entities = conn.execute(entity_sql, params).fetchall()
            entity_ids = {e["id"] for e in entities}

            nodes = []
            for e in entities:
                nodes.append({
                    "id": e["id"],
                    "name": e["name"],
                    "type": e["entity_type"],
                    "score": e["implication_score"] or 0,
                    "evidence_count": e["evidence_count"] or 0,
                    "role": e["role"],
                    "radius": self._node_radius(e["implication_score"] or 0),
                    "color": self._type_color(e["entity_type"]),
                })

            # Get relationships between included nodes
            rel_sql = """
                SELECT source_entity_id, target_entity_id, relationship_type,
                       weight, confidence, evidence_count, is_inferred
                FROM relationships
            """
            rels = conn.execute(rel_sql).fetchall()

            links = []
            for r in rels:
                if r["source_entity_id"] in entity_ids and r["target_entity_id"] in entity_ids:
                    links.append({
                        "source": r["source_entity_id"],
                        "target": r["target_entity_id"],
                        "type": r["relationship_type"],
                        "weight": r["weight"] or 1.0,
                        "confidence": r["confidence"] or 1.0,
                        "evidence_count": r["evidence_count"] or 1,
                        "inferred": bool(r["is_inferred"]),
                        "width": self._edge_width(r["weight"] or 1.0),
                    })

            return {
                "nodes": nodes,
                "links": links,
                "metadata": {
                    "node_count": len(nodes),
                    "link_count": len(links),
                    "generated_at": _now_iso(),
                    "filters_applied": filters or {},
                },
            }
        finally:
            conn.close()

    def export_for_public_viewer(
        self, min_score: int = 50
    ) -> Dict[str, Any]:
        """Filtered export for GitHub Pages: strips raw text, excludes victims,
        excludes AI-only inferences per config."""
        pub_config = self.export_config.get("public_viewer", {})
        effective_min = max(
            min_score,
            pub_config.get("min_score_for_inclusion", 50),
        )
        exclude_inferences = pub_config.get("exclude_ai_inferences", True)

        data = self.export_for_d3(filters={"min_score": effective_min})

        if exclude_inferences:
            data["links"] = [
                lnk for lnk in data["links"] if not lnk.get("inferred")
            ]

        # Strip any context snippets (raw text) from nodes
        for node in data["nodes"]:
            node.pop("context", None)

        # Re-strip victims (belt and suspenders)
        conn = self.db.get_connection()
        try:
            victim_ids = {
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM entities WHERE is_victim = 1 OR is_minor = 1"
                ).fetchall()
            }
        finally:
            conn.close()

        data["nodes"] = [n for n in data["nodes"] if n["id"] not in victim_ids]
        data["links"] = [
            lnk for lnk in data["links"]
            if lnk["source"] not in victim_ids and lnk["target"] not in victim_ids
        ]
        data["metadata"]["public"] = True
        data["metadata"]["min_score"] = effective_min
        data["metadata"]["node_count"] = len(data["nodes"])
        data["metadata"]["link_count"] = len(data["links"])
        return data

    def export_entity_card(self, entity_id: int) -> Dict[str, Any]:
        """Full JSON for entity evidence-card rendering."""
        entity = self.engine.get_entity(entity_id)
        if entity is None:
            return {"error": "entity_not_found", "entity_id": entity_id}

        scorer = EvidenceScorer(self.engine)
        top_evidence = scorer.get_top_evidence(entity_id, n=10)

        analyzer = TemporalAnalyzer(self.engine)
        timeline = analyzer.build_timeline(entity_id)
        spikes = analyzer.find_activity_spikes(entity_id)

        connections = self.engine.get_entity_connections(entity_id, degrees=1)

        card = {
            "entity": {
                "id": entity["id"],
                "name": entity["name"],
                "canonical_name": entity["canonical_name"],
                "type": entity["entity_type"],
                "role": entity.get("role"),
                "title": entity.get("title"),
                "organization": entity.get("organization"),
                "description": entity.get("description"),
                "implication_score": entity["implication_score"],
                "evidence_count": entity["evidence_count"],
                "document_count": entity["document_count"],
                "aliases": entity.get("aliases", []),
                "google_url": entity.get("google_url"),
                "wikipedia_url": entity.get("wikipedia_url"),
                "external_links": entity.get("external_links", []),
            },
            "top_evidence": top_evidence,
            "timeline_summary": {
                "total_events": len(timeline),
                "first_event": timeline[0]["date"] if timeline else None,
                "last_event": timeline[-1]["date"] if timeline else None,
                "activity_spikes": spikes,
            },
            "connections": {
                "direct_connections": len(connections.get("nodes", [])) - 1,  # exclude self
                "nodes": connections.get("nodes", []),
                "edges": connections.get("edges", []),
            },
            "generated_at": _now_iso(),
        }
        return card

    # Visual-encoding helpers
    @staticmethod
    def _node_radius(score: float) -> float:
        """Map implication_score to node radius for D3."""
        return 4.0 + (score / 100.0) * 26.0  # 4px to 30px

    @staticmethod
    def _edge_width(weight: float) -> float:
        """Map edge weight to stroke width."""
        return max(0.5, min(8.0, weight * 0.8))

    @staticmethod
    def _type_color(entity_type: str) -> str:
        """Consistent colour palette for entity types."""
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


# ===================================================================
# Full Rebuild Orchestrator
# ===================================================================

def rebuild_graph(config_path: str = None):
    """Rebuild the entire knowledge graph from scratch.

    1. Recalculate all entity scores.
    2. Remap all document connections.
    3. Run all pattern detectors.
    """
    engine = GraphEngine(config_path)
    scorer = EvidenceScorer(engine)
    mapper = ConnectionMapper(engine)
    detector = PatternDetector(engine)
    redaction = RedactionResolver(engine)

    conn = engine.db.get_connection()
    try:
        # 1. Score every evidence item
        logger.info("[rebuild] Scoring all evidence items...")
        links = conn.execute(
            """SELECT edl.entity_id, edl.document_id, edl.evidence_type,
                      edl.context_snippet
               FROM entity_document_links edl"""
        ).fetchall()
    finally:
        conn.close()

    for lnk in links:
        scorer.score_evidence_item(
            lnk["entity_id"],
            lnk["document_id"],
            lnk["evidence_type"] or "other",
            lnk["context_snippet"] or "",
        )

    # 2. Map document connections
    logger.info("[rebuild] Mapping document connections...")
    conn = engine.db.get_connection()
    try:
        docs = conn.execute("SELECT id FROM documents WHERE analysis_completed = 1").fetchall()
    finally:
        conn.close()
    for doc in docs:
        mapper.map_document_connections(doc["id"])

    # 3. Recalculate all entity scores
    logger.info("[rebuild] Recalculating entity implication scores...")
    conn = engine.db.get_connection()
    try:
        entities = conn.execute("SELECT id FROM entities").fetchall()
    finally:
        conn.close()
    for ent in entities:
        scorer.recalculate_entity_score(ent["id"])

    # 4. Detect patterns
    logger.info("[rebuild] Running pattern detectors...")
    detector.detect_all()

    # 5. Re-evaluate redactions
    logger.info("[rebuild] Re-evaluating redaction candidates...")
    redaction.re_evaluate_all()

    engine.invalidate_cache()
    logger.info("[rebuild] Knowledge graph rebuild complete.")
    engine.db.log_action("graph_rebuild", "Full knowledge graph rebuild completed.", user_initiated=False)


# ===================================================================
# __main__ CLI
# ===================================================================

def _cli():
    parser = argparse.ArgumentParser(
        prog="knowledge_graph.graph_engine",
        description="EpsteinAnalyzer - Spiderweb Engine CLI",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Rebuild the entire knowledge graph from current data.",
    )
    parser.add_argument(
        "--detect-patterns",
        action="store_true",
        help="Run all pattern detectors on the current graph.",
    )
    parser.add_argument(
        "--export-d3",
        type=str,
        nargs="?",
        const="knowledge_graph_d3.json",
        metavar="OUTPUT_FILE",
        help="Export the graph as D3.js JSON (default: knowledge_graph_d3.json).",
    )
    parser.add_argument(
        "--export-public",
        type=str,
        nargs="?",
        const="knowledge_graph_public.json",
        metavar="OUTPUT_FILE",
        help="Export a filtered public-viewer JSON.",
    )
    parser.add_argument(
        "--rankings",
        type=int,
        nargs="?",
        const=50,
        metavar="LIMIT",
        help="Print the top-N implication rankings.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to settings.yaml (default: auto-detect).",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.rebuild:
        rebuild_graph(args.config)
        return

    engine = GraphEngine(args.config)

    if args.detect_patterns:
        detector = PatternDetector(engine)
        detector.detect_all()
        return

    if args.export_d3:
        exporter = GraphExporter(engine)
        data = exporter.export_for_d3()
        out_path = Path(args.export_d3)
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("D3 export written to %s  (%d nodes, %d links)",
                     out_path, data["metadata"]["node_count"], data["metadata"]["link_count"])
        return

    if args.export_public:
        exporter = GraphExporter(engine)
        data = exporter.export_for_public_viewer()
        out_path = Path(args.export_public)
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Public export written to %s  (%d nodes, %d links)",
                     out_path, data["metadata"]["node_count"], data["metadata"]["link_count"])
        return

    if args.rankings:
        rankings = engine.get_implication_rankings(limit=args.rankings)
        print(f"\n{'Rank':<6}{'Name':<35}{'Type':<15}{'Score':<10}{'Evidence':<10}{'Docs':<8}")
        print("-" * 84)
        for i, ent in enumerate(rankings, 1):
            print(
                f"{i:<6}{ent['name'][:34]:<35}{ent['entity_type']:<15}"
                f"{ent['implication_score'] or 0:<10.1f}"
                f"{ent['evidence_count'] or 0:<10}{ent['document_count'] or 0:<8}"
            )
        return

    parser.print_help()


if __name__ == "__main__":
    _cli()
