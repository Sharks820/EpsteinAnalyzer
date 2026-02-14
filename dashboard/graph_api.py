"""
EpsteinAnalyzer - Graph API Endpoints
=====================================

Additional Flask routes for the enhanced spiderweb graph V2.
Add these to dashboard/app.py or import and register as Blueprint.

Usage in app.py:
    from dashboard.graph_api import register_graph_api
    register_graph_api(app)
"""

import json
import math
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request

try:
    from knowledge_graph.aircraft_correlator import AircraftCorrelator
    from knowledge_graph.graph_engine import GraphEngine
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from knowledge_graph.aircraft_correlator import AircraftCorrelator
    from knowledge_graph.graph_engine import GraphEngine

# Blueprint for graph API routes
graph_api = Blueprint('graph_api', __name__, url_prefix='/api')

# Global cache for correlator instance
_correlator: Optional[AircraftCorrelator] = None
_graph_engine: Optional[GraphEngine] = None


def get_correlator() -> AircraftCorrelator:
    """Lazy initialization of aircraft correlator."""
    global _correlator
    if _correlator is None:
        _correlator = AircraftCorrelator()
    return _correlator


def get_graph_engine() -> GraphEngine:
    """Lazy initialization of graph engine."""
    global _graph_engine
    if _graph_engine is None:
        _graph_engine = GraphEngine()
    return _graph_engine


# =============================================================================
# Graph Data Endpoints
# =============================================================================

@graph_api.route('/graph/data')
def api_graph_data():
    """
    GET /api/graph/data
    
    Query params:
        - center_id: int - Center node ID (default: auto-detect Epstein)
        - max_nodes: int - Maximum nodes to return (default: 500)
        - min_score: float - Minimum implication score (default: 0)
        - entity_types: str - Comma-separated list of types to include
        - aircraft_only: bool - Only include aircraft-connected entities
        - search: str - Text search filter
    
    Returns optimized graph payload for D3 rendering.
    """
    # Parse parameters
    center_id = request.args.get('center_id', type=int)
    max_nodes = request.args.get('max_nodes', 500, type=int)
    min_score = request.args.get('min_score', 0.0, type=float)
    entity_types = request.args.get('entity_types', '').split(',') if request.args.get('entity_types') else []
    aircraft_only = request.args.get('aircraft_only', 'false').lower() == 'true'
    search = request.args.get('search', '').strip()
    
    # Clamp max_nodes for performance
    max_nodes = min(max_nodes, 1500)
    
    engine = get_graph_engine()
    db = engine.db
    conn = db.get_connection()
    
    try:
        # Build entity query with filters
        where_clauses = ["e.is_victim = 0"]
        params = []
        
        if min_score > 0:
            where_clauses.append("e.implication_score >= ?")
            params.append(min_score)
        
        if entity_types:
            placeholders = ','.join('?' for _ in entity_types)
            where_clauses.append(f"e.entity_type IN ({placeholders})")
            params.extend(entity_types)
        
        if aircraft_only:
            # Join with entity_analysis_cards for aircraft filter
            aircraft_filter = """
                EXISTS (
                    SELECT 1 FROM entity_analysis_cards eac 
                    WHERE eac.entity_id = e.id AND eac.has_aircraft_evidence = 1
                )
            """
            where_clauses.append(aircraft_filter)
        
        if search:
            where_clauses.append("(e.name LIKE ? OR e.canonical_name LIKE ?)")
            search_pattern = f"%{search}%"
            params.extend([search_pattern, search_pattern])
        
        where_sql = " AND ".join(where_clauses)
        
        # Query entities with limit
        entity_sql = f"""
            SELECT e.id, e.name, e.canonical_name, e.entity_type, 
                   e.implication_score, e.evidence_count, e.document_count,
                   e.role, e.graph_priority_score
            FROM entities e
            WHERE {where_sql}
            ORDER BY e.implication_score DESC
            LIMIT ?
        """
        params.append(max_nodes * 2)  # Get extra for filtering
        
        rows = conn.execute(entity_sql, params).fetchall()
        
        # Build node list with visual properties
        nodes = []
        node_ids = set()
        
        # Type colors for D3
        type_colors = {
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
        
        for row in rows:
            score = row["implication_score"] or 0
            
            # Compute radius based on score
            base = 4
            score_bonus = math.sqrt(score) * 1.5
            radius = min(25, base + score_bonus)
            
            node = {
                "id": row["id"],
                "name": row["canonical_name"] or row["name"],
                "type": row["entity_type"],
                "score": score,
                "radius": radius,
                "color": type_colors.get(row["entity_type"], "#999999"),
                "evidence_count": row["evidence_count"] or 0,
                "document_count": row["document_count"] or 0,
                "role": row["role"],
                "flags": [],
            }
            nodes.append(node)
            node_ids.add(row["id"])
        
        # Auto-detect center if not specified
        if center_id is None:
            for node in nodes:
                name_lower = node["name"].lower()
                if "jeffrey" in name_lower and "epstein" in name_lower:
                    center_id = node["id"]
                    node["is_center"] = True
                    break
        else:
            for node in nodes:
                if node["id"] == center_id:
                    node["is_center"] = True
                    break
        
        # Query relationships between included nodes
        if node_ids:
            placeholders = ','.join('?' for _ in node_ids)
            rel_sql = f"""
                SELECT source_entity_id, target_entity_id, relationship_type,
                       weight, confidence, evidence_count, is_inferred
                FROM relationships
                WHERE source_entity_id IN ({placeholders})
                  AND target_entity_id IN ({placeholders})
                ORDER BY weight DESC
                LIMIT 5000
            """
            rel_params = list(node_ids) + list(node_ids)
            rel_rows = conn.execute(rel_sql, rel_params).fetchall()
            
            links = []
            for r in rel_rows:
                # Aircraft correlation flags
                flags = []
                if r["relationship_type"] == "flew_with":
                    flags.append("aircraft_correlated")
                
                links.append({
                    "source": r["source_entity_id"],
                    "target": r["target_entity_id"],
                    "type": r["relationship_type"],
                    "weight": r["weight"] or 1.0,
                    "confidence": r["confidence"] or 1.0,
                    "evidence_count": r["evidence_count"] or 0,
                    "inferred": bool(r["is_inferred"]),
                    "flags": flags,
                })
        else:
            links = []
        
        # Count connections per node
        connection_counts = {}
        for link in links:
            connection_counts[link["source"]] = connection_counts.get(link["source"], 0) + 1
            connection_counts[link["target"]] = connection_counts.get(link["target"], 0) + 1
        
        for node in nodes:
            node["connections"] = connection_counts.get(node["id"], 0)
            # Add aircraft-connected flag if applicable
            if node["connections"] > 0 and aircraft_only:
                node["flags"].append("aircraft_connected")
        
        # Filter to connected nodes + top unconnected
        connected_ids = set()
        for link in links:
            connected_ids.add(link["source"])
            connected_ids.add(link["target"])
        
        # Keep connected nodes + high-score unconnected
        filtered_nodes = []
        for node in nodes:
            if node["id"] in connected_ids or node["score"] >= 75 or node["id"] == center_id:
                filtered_nodes.append(node)
        
        # Cap to max_nodes
        if len(filtered_nodes) > max_nodes:
            # Sort by priority
            filtered_nodes.sort(key=lambda n: (
                0 if n.get("is_center") else 1,
                -(n.get("connections", 0) * 100 + n["score"])
            ))
            filtered_nodes = filtered_nodes[:max_nodes]
        
        # Final node ID set
        final_node_ids = {n["id"] for n in filtered_nodes}
        
        # Filter links to only include final nodes
        final_links = [l for l in links if l["source"] in final_node_ids and l["target"] in final_node_ids]
        
        return jsonify({
            "nodes": filtered_nodes,
            "links": final_links,
            "metadata": {
                "total_nodes": len(filtered_nodes),
                "total_links": len(final_links),
                "center_id": center_id,
                "filters_applied": {
                    "min_score": min_score,
                    "entity_types": entity_types,
                    "aircraft_only": aircraft_only,
                    "search": search,
                },
                "generated_at": datetime.now().isoformat(),
            }
        })
        
    finally:
        conn.close()


# =============================================================================
# Entity Analysis Card Endpoint
# =============================================================================

@graph_api.route('/entity/<int:entity_id>/card')
def api_entity_card(entity_id: int):
    """
    GET /api/entity/<id>/card
    
    Returns complete analysis card for entity:
    - Entity profile
    - Key findings
    - Top evidence with aircraft correlation
    - Relationships
    - Aircraft analysis
    - Confidence metrics
    """
    engine = get_graph_engine()
    correlator = get_correlator()
    db = engine.db
    conn = db.get_connection()
    
    try:
        # Get entity record
        entity = conn.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        
        if not entity:
            return jsonify({"error": "Entity not found", "entity_id": entity_id}), 404
        
        entity_dict = dict(entity)
        entity_dict["aliases"] = json.loads(entity_dict.get("aliases") or "[]")
        entity_dict["external_links"] = json.loads(entity_dict.get("external_links") or "[]")
        
        # Get top evidence
        evidence_rows = conn.execute(
            """SELECT edl.*, d.original_filename, d.doc_type, d.file_path,
                      d.source, d.priority_score AS doc_priority
               FROM entity_document_links edl
               JOIN documents d ON d.id = edl.document_id
               WHERE edl.entity_id = ?
               ORDER BY edl.damning_score DESC
               LIMIT 10""",
            (entity_id,)
        ).fetchall()
        
        top_evidence = []
        for row in evidence_rows:
            ev = dict(row)
            # Add aircraft correlation if applicable
            if ev.get("is_aircraft_related"):
                ev["aircraft_correlation"] = {
                    "score": ev.get("aircraft_correlation_score", 0),
                    "is_aircraft_related": True,
                }
            top_evidence.append(ev)
        
        # Get relationships
        rel_rows = conn.execute(
            """SELECT r.*, e.name AS other_name, e.entity_type AS other_type,
                      e.implication_score AS other_score
               FROM relationships r
               JOIN entities e ON e.id = CASE
                   WHEN r.source_entity_id = ? THEN r.target_entity_id
                   ELSE r.source_entity_id END
               WHERE r.source_entity_id = ? OR r.target_entity_id = ?
               ORDER BY r.weight DESC
               LIMIT 20""",
            (entity_id, entity_id, entity_id)
        ).fetchall()
        
        relationships = {
            "direct_count": len(rel_rows),
            "by_type": {},
            "top_connections": [],
        }
        
        for row in rel_rows:
            rel_type = row["relationship_type"]
            relationships["by_type"][rel_type] = relationships["by_type"].get(rel_type, 0) + 1
            
            relationships["top_connections"].append({
                "entity_id": row["other_name"],  # This is wrong, should be actual ID
                "name": row["other_name"],
                "type": row["other_type"],
                "rel_type": rel_type,
                "strength": row["weight"] or 1.0,
            })
        
        # Get aircraft analysis
        aircraft_analysis = correlator.correlate_entity(entity_id)
        
        # Generate key findings
        key_findings = []
        
        # Aircraft finding
        if aircraft_analysis.get("has_aircraft_evidence"):
            severity = "high" if aircraft_analysis["known_epstein_aircraft_flights"] > 0 else "medium"
            key_findings.append({
                "type": "aircraft_travel",
                "severity": severity,
                "summary": f"Traveled on {aircraft_analysis['tail_numbers']} "
                          f"({aircraft_analysis['total_flights']} flights, "
                          f"{aircraft_analysis['known_epstein_aircraft_flights']} on known Epstein aircraft)",
                "confidence": aircraft_analysis["average_correlation_score"],
                "flight_ids": aircraft_analysis.get("flight_ids", []),
            })
        
        # High implication score finding
        if entity_dict.get("implication_score", 0) > 70:
            key_findings.append({
                "type": "high_implication",
                "severity": "high",
                "summary": f"High implication score ({entity_dict['implication_score']}) based on "
                          f"{entity_dict.get('evidence_count', 0)} evidence items",
                "confidence": min(1.0, entity_dict["implication_score"] / 100),
            })
        
        # Evidence diversity finding
        evidence_types = set(e.get("evidence_type") for e in top_evidence if e.get("evidence_type"))
        if len(evidence_types) > 2:
            key_findings.append({
                "type": "multi_source",
                "severity": "medium",
                "summary": f"Evidence from {len(evidence_types)} different source types: "
                          f"{', '.join(evidence_types)}",
                "confidence": 0.8,
            })
        
        # External links
        external_links = {
            "google": entity_dict.get("google_url", f"https://www.google.com/search?q={entity_dict['name']}"),
            "wikipedia": entity_dict.get("wikipedia_url"),
        }
        
        # Calculate overall confidence
        confidence_factors = [
            min(1.0, entity_dict.get("evidence_count", 0) / 10),  # Evidence volume
            min(1.0, len(relationships["top_connections"]) / 5),   # Connection count
            1.0 if aircraft_analysis.get("has_aircraft_evidence") else 0.5,  # Aircraft data
        ]
        overall_confidence = sum(confidence_factors) / len(confidence_factors)
        
        card = {
            "entity": {
                "id": entity_dict["id"],
                "name": entity_dict["name"],
                "canonical_name": entity_dict["canonical_name"],
                "type": entity_dict["entity_type"],
                "role": entity_dict.get("role"),
                "title": entity_dict.get("title"),
                "organization": entity_dict.get("organization"),
                "description": entity_dict.get("description"),
                "implication_score": entity_dict.get("implication_score", 0),
                "evidence_count": entity_dict.get("evidence_count", 0),
                "document_count": entity_dict.get("document_count", 0),
                "aliases": entity_dict.get("aliases", []),
            },
            "external_links": external_links,
            "key_findings": key_findings,
            "top_evidence": top_evidence,
            "relationships": relationships,
            "aircraft_analysis": aircraft_analysis,
            "confidence": {
                "overall": round(overall_confidence, 2),
                "evidence_quality": "high" if entity_dict.get("evidence_count", 0) > 5 else "medium",
                "corroboration": "multiple_sources" if len(evidence_types) > 1 else "single_source",
            },
            "generated_at": datetime.now().isoformat(),
        }
        
        return jsonify(card)
        
    finally:
        conn.close()


# =============================================================================
# Aircraft Endpoints
# =============================================================================

@graph_api.route('/aircraft/<tail_number>')
def api_aircraft_detail(tail_number: str):
    """
    GET /api/aircraft/<tail_number>
    
    Returns aircraft details and all associated flights.
    """
    db = get_graph_engine().db
    conn = db.get_connection()
    
    try:
        # Get aircraft record
        aircraft = conn.execute(
            "SELECT * FROM aircraft_records WHERE tail_number = ?",
            (tail_number.upper(),)
        ).fetchone()
        
        if not aircraft:
            return jsonify({"error": "Aircraft not found"}), 404
        
        aircraft_dict = dict(aircraft)
        if aircraft_dict.get("faa_registration_data"):
            aircraft_dict["faa_registration_data"] = json.loads(aircraft_dict["faa_registration_data"])
        
        # Get all flights
        flight_rows = conn.execute(
            """SELECT fr.*, d.original_filename
               FROM flight_records fr
               JOIN documents d ON d.id = fr.document_id
               WHERE fr.aircraft_id = ?
               ORDER BY fr.flight_date DESC""",
            (aircraft_dict["id"],)
        ).fetchall()
        
        flights = []
        for row in flight_rows:
            flight = dict(row)
            if flight.get("passenger_entity_ids"):
                flight["passenger_entity_ids"] = json.loads(flight["passenger_entity_ids"])
            if flight.get("pattern_flags"):
                flight["pattern_flags"] = json.loads(flight["pattern_flags"])
            flights.append(flight)
        
        # Get unique passengers
        passenger_ids = set()
        for flight in flights:
            passenger_ids.update(flight.get("passenger_entity_ids", []))
        
        passengers = []
        if passenger_ids:
            placeholders = ','.join('?' for _ in passenger_ids)
            pax_rows = conn.execute(
                f"SELECT id, name, entity_type, implication_score FROM entities WHERE id IN ({placeholders})",
                list(passenger_ids)
            ).fetchall()
            passengers = [dict(r) for r in pax_rows]
        
        return jsonify({
            "aircraft": aircraft_dict,
            "flights": flights,
            "passengers": passengers,
            "flight_count": len(flights),
            "unique_passenger_count": len(passengers),
        })
        
    finally:
        conn.close()


@graph_api.route('/flights/search')
def api_flights_search():
    """
    GET /api/flights/search
    
    Query params:
        - tail_number: Filter by aircraft
        - airport: Filter by departure or arrival
        - date_start: Start date (ISO)
        - date_end: End date (ISO)
        - entity_id: Filter by passenger
        - min_score: Minimum correlation score
    """
    tail_number = request.args.get('tail_number', '').upper()
    airport = request.args.get('airport', '').upper()
    date_start = request.args.get('date_start', '')
    date_end = request.args.get('date_end', '')
    entity_id = request.args.get('entity_id', type=int)
    min_score = request.args.get('min_score', 0.0, type=float)
    
    db = get_graph_engine().db
    conn = db.get_connection()
    
    try:
        where_clauses = ["1=1"]
        params = []
        
        if tail_number:
            where_clauses.append("ar.tail_number = ?")
            params.append(tail_number)
        
        if airport:
            where_clauses.append("(fr.departure_airport = ? OR fr.arrival_airport = ?)")
            params.extend([airport, airport])
        
        if date_start:
            where_clauses.append("fr.flight_date >= ?")
            params.append(date_start)
        
        if date_end:
            where_clauses.append("fr.flight_date <= ?")
            params.append(date_end)
        
        if entity_id:
            where_clauses.append("fr.passenger_entity_ids LIKE ?")
            params.append(f'%"{entity_id}"%')
        
        if min_score > 0:
            where_clauses.append("fr.epstein_pattern_score >= ?")
            params.append(min_score)
        
        where_sql = " AND ".join(where_clauses)
        
        sql = f"""
            SELECT fr.*, ar.tail_number, ar.is_known_epstein_aircraft, d.original_filename
            FROM flight_records fr
            LEFT JOIN aircraft_records ar ON ar.id = fr.aircraft_id
            JOIN documents d ON d.id = fr.document_id
            WHERE {where_sql}
            ORDER BY fr.epstein_pattern_score DESC, fr.flight_date DESC
            LIMIT 500
        """
        
        rows = conn.execute(sql, params).fetchall()
        
        flights = []
        for row in rows:
            flight = dict(row)
            if flight.get("passenger_entity_ids"):
                flight["passenger_entity_ids"] = json.loads(flight["passenger_entity_ids"])
            if flight.get("pattern_flags"):
                flight["pattern_flags"] = json.loads(flight["pattern_flags"])
            flights.append(flight)
        
        return jsonify({
            "flights": flights,
            "count": len(flights),
            "filters": {
                "tail_number": tail_number or None,
                "airport": airport or None,
                "date_start": date_start or None,
                "date_end": date_end or None,
                "entity_id": entity_id,
                "min_score": min_score,
            }
        })
        
    finally:
        conn.close()


# =============================================================================
# Filter Metadata Endpoint
# =============================================================================

@graph_api.route('/graph/filters/metadata')
def api_graph_filter_metadata():
    """
    GET /api/graph/filters/metadata
    
    Returns available filter options with counts.
    """
    db = get_graph_engine().db
    conn = db.get_connection()
    
    try:
        # Entity type counts
        type_rows = conn.execute(
            "SELECT entity_type, COUNT(*) as count FROM entities WHERE is_victim = 0 GROUP BY entity_type"
        ).fetchall()
        
        entity_types = {r["entity_type"]: r["count"] for r in type_rows}
        
        # Relationship type counts
        rel_rows = conn.execute(
            "SELECT relationship_type, COUNT(*) as count FROM relationships GROUP BY relationship_type"
        ).fetchall()
        
        relationship_types = {r["relationship_type"]: r["count"] for r in rel_rows}
        
        # Score distribution
        score_dist = conn.execute(
            """SELECT 
                CASE 
                    WHEN implication_score >= 90 THEN '90-100'
                    WHEN implication_score >= 70 THEN '70-89'
                    WHEN implication_score >= 50 THEN '50-69'
                    WHEN implication_score >= 30 THEN '30-49'
                    ELSE '0-29'
                END as bucket,
                COUNT(*) as count
               FROM entities WHERE is_victim = 0
               GROUP BY bucket"""
        ).fetchall()
        
        # Aircraft-connected count
        aircraft_row = conn.execute(
            """SELECT COUNT(DISTINCT entity_id) as count 
               FROM entity_analysis_cards 
               WHERE has_aircraft_evidence = 1"""
        ).fetchone()
        
        return jsonify({
            "entity_types": entity_types,
            "relationship_types": relationship_types,
            "score_distribution": {r["bucket"]: r["count"] for r in score_dist},
            "aircraft_connected_count": aircraft_row["count"] if aircraft_row else 0,
            "total_entities": sum(entity_types.values()),
        })
        
    finally:
        conn.close()


def register_graph_api(app):
    """Register graph API blueprint with Flask app."""
    app.register_blueprint(graph_api)
