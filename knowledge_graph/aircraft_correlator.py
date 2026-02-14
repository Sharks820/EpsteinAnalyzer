"""
EpsteinAnalyzer - Aircraft Correlation Engine
=============================================

Calculates correlation scores between flight records/entities and known
Epstein travel patterns. Provides scoring, flagging, and analysis capabilities.

Usage:
    from knowledge_graph.aircraft_correlator import AircraftCorrelator
    
    correlator = AircraftCorrelator()
    
    # Score a flight record
    result = correlator.score_flight(flight_data)
    
    # Correlate entity
    entity_score = correlator.correlate_entity(entity_id)
    
    # Batch process
    correlator.run_batch_correlation()
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import sys
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.db import DatabaseManager

logger = logging.getLogger("knowledge_graph.aircraft_correlator")


class AircraftCorrelator:
    """
    Calculates correlation scores between flights/entities and known Epstein patterns.
    
    Uses a weighted composite scoring system:
    - Aircraft match: 40% weight
    - Route match: 25% weight
    - Date overlap: 20% weight
    - Passenger correlation: 15% weight
    """
    
    # Known Epstein aircraft with confidence scores
    KNOWN_AIRCRAFT: Dict[str, float] = {
        "N908JE": 1.0,    # Gulfstream G-1159B - Primary aircraft
        "N474AW": 0.95,   # Cessna Citation 680 - Secondary
        "N221DG": 0.90,   # Cessna 421C - Tertiary
    }
    
    # Known Epstein travel routes (airport pairs)
    KNOWN_ROUTES: List[Tuple[str, str]] = [
        ("LMM", "TEB"),   # Little St. James to Teterboro
        ("TEB", "LMM"),   # Return
        ("PBI", "LMM"),   # Palm Beach to Little St. James
        ("LMM", "PBI"),   # Return
        ("APF", "LMM"),   # Naples to Little St. James
        ("LMM", "APF"),   # Return
    ]
    
    # Key airports in Epstein network
    KEY_AIRPORTS: Set[str] = {"LMM", "TEB", "PBI", "APF", "SXM", "OST"}
    
    # Active date ranges
    ACTIVE_DATE_RANGES: List[Tuple[str, str]] = [
        ("1998-01-01", "2019-07-01"),  # Main activity period
    ]
    
    # Score weights
    WEIGHTS = {
        "aircraft": 0.40,
        "route": 0.25,
        "date": 0.20,
        "passenger": 0.15,
    }
    
    def __init__(self, config_path: str = None):
        self.db = DatabaseManager(config_path)
        self._load_known_patterns()
    
    def _load_known_patterns(self):
        """Load patterns from database, overriding defaults if present."""
        conn = self.db.get_connection()
        try:
            rows = conn.execute(
                "SELECT pattern_type, tail_numbers, airports, date_start, date_end, confidence "
                "FROM known_epstein_patterns"
            ).fetchall()
            
            for row in rows:
                if row["pattern_type"] == "aircraft" and row["tail_numbers"]:
                    tails = json.loads(row["tail_numbers"])
                    for tail in tails:
                        self.KNOWN_AIRCRAFT[tail] = row["confidence"]
                        
                elif row["pattern_type"] == "route" and row["airports"]:
                    airports = json.loads(row["airports"])
                    if len(airports) >= 2:
                        route = (airports[0], airports[1])
                        if route not in self.KNOWN_ROUTES:
                            self.KNOWN_ROUTES.append(route)
                            
        except Exception as e:
            logger.warning(f"Could not load patterns from DB: {e}")
        finally:
            conn.close()
    
    def score_flight(self, flight_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate composite correlation score for a flight record.
        
        Args:
            flight_record: Dict with keys:
                - tail_number: Aircraft registration
                - departure_airport: Origin airport code
                - arrival_airport: Destination airport code
                - flight_date: ISO date string
                - passenger_entity_ids: List of entity IDs
        
        Returns:
            Dict with composite_score, component_scores, pattern_flags, confidence_level
        """
        scores = {
            "aircraft": self._score_aircraft(flight_record),
            "route": self._score_route(flight_record),
            "date": self._score_date(flight_record),
            "passenger": self._score_passenger_correlation(flight_record),
        }
        
        # Weighted composite
        composite = sum(scores[k] * self.WEIGHTS[k] for k in scores)
        
        # Generate pattern flags
        flags = self._generate_flags(scores, composite)
        
        return {
            "composite_score": round(composite, 3),
            "component_scores": {k: round(v, 3) for k, v in scores.items()},
            "pattern_flags": flags,
            "confidence_level": self._confidence_level(composite),
            "matches": self._get_detailed_matches(flight_record, scores),
        }
    
    def _score_aircraft(self, flight: Dict[str, Any]) -> float:
        """Score based on aircraft tail number match."""
        tail = (flight.get("tail_number") or "").upper().strip()
        if not tail:
            return 0.0
        
        # Direct match
        if tail in self.KNOWN_AIRCRAFT:
            return self.KNOWN_AIRCRAFT[tail]
        
        # Pattern match for similar N-numbers (possible related aircraft)
        if tail.startswith("N") and len(tail) == 6:
            # Check if tail number follows Epstein registration pattern
            if tail.startswith("N9"):  # Gulfstream pattern
                return 0.25
            if tail.startswith("N4"):  # Citation pattern
                return 0.20
                
        return 0.0
    
    def _score_route(self, flight: Dict[str, Any]) -> float:
        """Score based on departure/arrival airports."""
        dep = (flight.get("departure_airport") or "").upper()
        arr = (flight.get("arrival_airport") or "").upper()
        
        if not dep or not arr:
            return 0.0
        
        # Direct route match
        if (dep, arr) in self.KNOWN_ROUTES:
            return 1.0
        
        # Reverse route match (same airports, opposite direction)
        if (arr, dep) in self.KNOWN_ROUTES:
            return 0.95
        
        # Partial match - one airport is key Epstein location
        dep_is_key = dep in self.KEY_AIRPORTS
        arr_is_key = arr in self.KEY_AIRPORTS
        
        if dep_is_key and arr_is_key:
            return 0.75  # Both airports in Epstein network
        elif dep_is_key or arr_is_key:
            return 0.40  # One airport in network
            
        return 0.0
    
    def _score_date(self, flight: Dict[str, Any]) -> float:
        """Score based on date falling in known active periods."""
        flight_date = flight.get("flight_date")
        if not flight_date:
            return 0.0
        
        try:
            # Parse various date formats
            if isinstance(flight_date, str):
                flight_date = flight_date.replace("Z", "+00:00")
                try:
                    fd = datetime.fromisoformat(flight_date)
                except ValueError:
                    # Try YYYY-MM-DD format
                    fd = datetime.strptime(flight_date[:10], "%Y-%m-%d")
            else:
                return 0.0
            
            for start_str, end_str in self.ACTIVE_DATE_RANGES:
                sd = datetime.fromisoformat(start_str)
                ed = datetime.fromisoformat(end_str)
                if sd <= fd <= ed:
                    return 1.0
                    
            return 0.0
        except Exception as e:
            logger.debug(f"Date parsing error: {e}")
            return 0.0
    
    def _score_passenger_correlation(self, flight: Dict[str, Any]) -> float:
        """Score based on known Epstein associates on same flight."""
        passenger_ids = flight.get("passenger_entity_ids", [])
        if not passenger_ids:
            return 0.0
        
        # Query for high-implication passengers on this flight
        high_signal_count = self._count_high_signal_passengers(passenger_ids)
        
        # Score based on how many high-signal passengers
        # 3+ = full score, 2 = 0.66, 1 = 0.33
        return min(1.0, high_signal_count / 3.0)
    
    def _count_high_signal_passengers(self, entity_ids: List[int]) -> int:
        """Count how many passengers have high implication scores."""
        if not entity_ids:
            return 0
            
        conn = self.db.get_connection()
        try:
            placeholders = ",".join("?" for _ in entity_ids)
            row = conn.execute(
                f"SELECT COUNT(*) as count FROM entities "
                f"WHERE id IN ({placeholders}) AND implication_score >= 70",
                entity_ids
            ).fetchone()
            return row["count"] if row else 0
        finally:
            conn.close()
    
    def _generate_flags(self, scores: Dict[str, float], composite: float) -> List[str]:
        """Generate pattern flags based on scores."""
        flags = []
        
        if scores["aircraft"] >= 0.7:
            flags.append("known_aircraft")
        elif scores["aircraft"] >= 0.2:
            flags.append("possible_aircraft")
            
        if scores["route"] >= 0.7:
            flags.append("epstein_route")
        elif scores["route"] >= 0.4:
            flags.append("epstein_airport")
            
        if scores["date"] >= 0.7:
            flags.append("date_overlap")
            
        if composite >= 0.85:
            flags.append("high_correlation")
        elif composite >= 0.60:
            flags.append("medium_correlation")
            
        return flags
    
    def _get_detailed_matches(self, flight: Dict[str, Any], scores: Dict[str, float]) -> Dict[str, Any]:
        """Get detailed match information for UI display."""
        matches = {
            "aircraft": None,
            "route": None,
            "date_range": None,
        }
        
        # Aircraft match details
        tail = (flight.get("tail_number") or "").upper()
        if tail in self.KNOWN_AIRCRAFT:
            matches["aircraft"] = {
                "tail_number": tail,
                "confidence": self.KNOWN_AIRCRAFT[tail],
            }
        
        # Route match details
        dep = (flight.get("departure_airport") or "").upper()
        arr = (flight.get("arrival_airport") or "").upper()
        if (dep, arr) in self.KNOWN_ROUTES:
            matches["route"] = {
                "departure": dep,
                "arrival": arr,
                "is_known_route": True,
            }
        elif (arr, dep) in self.KNOWN_ROUTES:
            matches["route"] = {
                "departure": dep,
                "arrival": arr,
                "is_known_route": True,
                "is_reverse": True,
            }
        
        return matches
    
    def _confidence_level(self, score: float) -> str:
        """Convert score to confidence level string."""
        if score >= 0.85:
            return "very_high"
        if score >= 0.70:
            return "high"
        if score >= 0.50:
            return "medium"
        if score >= 0.30:
            return "low"
        return "very_low"
    
    def correlate_flight_record(self, flight_id: int) -> Dict[str, Any]:
        """
        Correlate an existing flight record and update database.
        
        Args:
            flight_id: ID of flight_records row
            
        Returns:
            Correlation result dict
        """
        conn = self.db.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM flight_records WHERE id = ?", (flight_id,)
            ).fetchone()
            
            if not row:
                return {"error": "Flight not found"}
            
            flight_data = dict(row)
            # Parse JSON fields
            if flight_data.get("passenger_entity_ids"):
                flight_data["passenger_entity_ids"] = json.loads(flight_data["passenger_entity_ids"])
            else:
                flight_data["passenger_entity_ids"] = []
            
            result = self.score_flight(flight_data)
            
            # Update database
            conn.execute(
                """UPDATE flight_records 
                   SET epstein_pattern_score = ?, pattern_flags = ?, updated_at = ?
                   WHERE id = ?""",
                (result["composite_score"], json.dumps(result["pattern_flags"]), 
                 datetime.now().isoformat(), flight_id)
            )
            conn.commit()
            
            return result
            
        finally:
            conn.close()
    
    def correlate_entity(self, entity_id: int) -> Dict[str, Any]:
        """
        Calculate aircraft correlation summary for an entity.
        
        Returns aggregated stats across all flights entity appears on.
        """
        conn = self.db.get_connection()
        try:
            # Find all flights with this entity as passenger
            rows = conn.execute(
                """SELECT fr.*, ar.tail_number, ar.is_known_epstein_aircraft
                   FROM flight_records fr
                   LEFT JOIN aircraft_records ar ON ar.id = fr.aircraft_id
                   WHERE fr.passenger_entity_ids LIKE ?
                   ORDER BY fr.epstein_pattern_score DESC""",
                (f'%"{entity_id}"%',)
            ).fetchall()
            
            flights = []
            total_score = 0
            known_aircraft_flights = 0
            tail_numbers = set()
            
            for row in rows:
                flight_data = dict(row)
                if flight_data.get("passenger_entity_ids"):
                    passengers = json.loads(flight_data["passenger_entity_ids"])
                    if entity_id in passengers:
                        flights.append(flight_data)
                        total_score += flight_data.get("epstein_pattern_score", 0)
                        if flight_data.get("is_known_epstein_aircraft"):
                            known_aircraft_flights += 1
                        if flight_data.get("tail_number"):
                            tail_numbers.add(flight_data["tail_number"])
            
            if not flights:
                return {
                    "total_flights": 0,
                    "known_epstein_aircraft_flights": 0,
                    "average_correlation_score": 0,
                    "has_aircraft_evidence": False,
                }
            
            avg_score = total_score / len(flights)
            max_score_flight = flights[0] if flights else None
            
            # Determine date overlap confidence
            if len(flights) >= 3 and avg_score > 0.7:
                date_confidence = "high"
            elif len(flights) >= 2 and avg_score > 0.5:
                date_confidence = "medium"
            elif flights:
                date_confidence = "low"
            else:
                date_confidence = "none"
            
            return {
                "total_flights": len(flights),
                "known_epstein_aircraft_flights": known_aircraft_flights,
                "average_correlation_score": round(avg_score, 3),
                "max_correlation_score": round(max_score_flight["epstein_pattern_score"], 3) if max_score_flight else 0,
                "tail_numbers": sorted(tail_numbers),
                "route_pattern": self._infer_route_pattern(flights),
                "date_overlap_confidence": date_confidence,
                "has_aircraft_evidence": True,
                "flight_ids": [f["id"] for f in flights[:10]],  # Top 10
            }
            
        finally:
            conn.close()
    
    def _infer_route_pattern(self, flights: List[Dict]) -> Optional[str]:
        """Infer common route pattern from flights."""
        if not flights:
            return None
        
        routes = []
        for f in flights:
            dep = f.get("departure_airport")
            arr = f.get("arrival_airport")
            if dep and arr:
                routes.append(f"{dep}-{arr}")
        
        if not routes:
            return None
        
        # Find most common route
        from collections import Counter
        most_common = Counter(routes).most_common(1)[0]
        
        # Check if it's an Epstein route
        route = most_common[0]
        parts = route.split("-")
        if len(parts) == 2 and (parts[0], parts[1]) in self.KNOWN_ROUTES:
            return f"{route} (Epstein route)"
        return route
    
    def run_batch_correlation(self, entity_id: int = None) -> Dict[str, int]:
        """
        Run correlation on all unprocessed flight records.
        
        Args:
            entity_id: If provided, only re-correlate flights for this entity
            
        Returns:
            Stats dict with processed counts
        """
        conn = self.db.get_connection()
        try:
            if entity_id:
                # Find flights with this entity
                rows = conn.execute(
                    "SELECT id FROM flight_records WHERE passenger_entity_ids LIKE ?",
                    (f'%"{entity_id}"%',)
                ).fetchall()
            else:
                # Find uncorrelated flights (score = 0)
                rows = conn.execute(
                    "SELECT id FROM flight_records WHERE epstein_pattern_score = 0"
                ).fetchall()
            
            processed = 0
            errors = 0
            
            for row in rows:
                try:
                    self.correlate_flight_record(row["id"])
                    processed += 1
                    if processed % 100 == 0:
                        logger.info(f"Correlated {processed} flights...")
                except Exception as e:
                    logger.error(f"Error correlating flight {row['id']}: {e}")
                    errors += 1
            
            logger.info(f"Batch correlation complete: {processed} processed, {errors} errors")
            return {"processed": processed, "errors": errors}
            
        finally:
            conn.close()
    
    def update_entity_aircraft_flags(self, entity_id: int):
        """Update entity_document_links with aircraft correlation flags."""
        correlation = self.correlate_entity(entity_id)
        
        conn = self.db.get_connection()
        try:
            # Update all aircraft-related evidence for this entity
            if correlation["has_aircraft_evidence"]:
                conn.execute(
                    """UPDATE entity_document_links 
                       SET is_aircraft_related = 1,
                           aircraft_correlation_score = ?
                       WHERE entity_id = ? AND evidence_type = 'flight_log'""",
                    (correlation["average_correlation_score"], entity_id)
                )
                conn.commit()
        finally:
            conn.close()


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Aircraft Correlation Engine")
    parser.add_argument("--correlate-flight", type=int, help="Correlate specific flight ID")
    parser.add_argument("--correlate-entity", type=int, help="Correlate specific entity ID")
    parser.add_argument("--batch", action="store_true", help="Run batch correlation")
    parser.add_argument("--config", help="Path to settings.yaml")
    
    args = parser.parse_args()
    
    correlator = AircraftCorrelator(args.config)
    
    if args.correlate_flight:
        result = correlator.correlate_flight_record(args.correlate_flight)
        print(json.dumps(result, indent=2))
    elif args.correlate_entity:
        result = correlator.correlate_entity(args.correlate_entity)
        print(json.dumps(result, indent=2))
    elif args.batch:
        stats = correlator.run_batch_correlation()
        print(f"Batch complete: {stats}")
    else:
        parser.print_help()
