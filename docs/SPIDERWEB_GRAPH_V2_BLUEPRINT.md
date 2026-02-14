# EpsteinAnalyzer Spiderweb Graph V2 - Implementation Blueprint

## Executive Summary

This blueprint details a complete overhaul of the investigative spiderweb graph UI to transform it from a passive visualization into an active investigation tool with:

1. **Interactive Node Analysis Cards** - Right-side panel with entity intelligence
2. **Aircraft-Travel Correlation Engine** - Automatic pattern detection and flagging
3. **High-Performance Filtering** - Sub-100ms filtering for 1k+ nodes
4. **Visual Signal Hierarchy** - Clear prominence for high-value entities

---

## 1. Data Model Additions

### 1.1 New Tables

```sql
-- ================================================
-- AIRCRAFT CORRELATION TRACKING
-- ================================================

CREATE TABLE IF NOT EXISTS aircraft_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tail_number TEXT NOT NULL,  -- N-number or registration
    aircraft_type TEXT,         -- Gulfstream, Boeing, etc.
    make_model TEXT,
    serial_number TEXT,
    -- Known Epstein fleet association
    is_known_epstein_aircraft BOOLEAN DEFAULT 0,
    epstein_association_confidence REAL DEFAULT 0.0,  -- 0.0 to 1.0
    epstein_association_notes TEXT,
    -- External lookup data
    faa_registration_data TEXT,  -- JSON: owner history, registration dates
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tail_number)
);

CREATE INDEX IF NOT EXISTS idx_aircraft_tail ON aircraft_records(tail_number);
CREATE INDEX IF NOT EXISTS idx_aircraft_epstein ON aircraft_records(is_known_epstein_aircraft);

-- ================================================
-- FLIGHT RECORDS WITH CORRELATION SCORING
-- ================================================

CREATE TABLE IF NOT EXISTS flight_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER REFERENCES documents(id),
    aircraft_id INTEGER REFERENCES aircraft_records(id),
    -- Parsed flight data
    flight_date TEXT,           -- ISO date
    departure_airport TEXT,
    arrival_airport TEXT,
    departure_time TEXT,
    arrival_time TEXT,
    -- Passengers as JSON array of entity IDs
    passenger_entity_ids TEXT,  -- JSON: [123, 456, 789]
    passenger_count INTEGER DEFAULT 0,
    -- Crew
    pilot_entity_ids TEXT,      -- JSON: [123]
    -- Scoring
    epstein_pattern_score REAL DEFAULT 0.0,  -- Composite score (see scoring section)
    pattern_flags TEXT,         -- JSON: ["known_aircraft", "epstein_route", "date_overlap"]
    -- Raw extracted text for verification
    raw_text_excerpt TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_flight_aircraft ON flight_records(aircraft_id);
CREATE INDEX IF NOT EXISTS idx_flight_date ON flight_records(flight_date);
CREATE INDEX IF NOT EXISTS idx_flight_score ON flight_records(epstein_pattern_score DESC);
CREATE INDEX IF NOT EXISTS idx_flight_doc ON flight_records(document_id);

-- FTS for flight text search
CREATE VIRTUAL TABLE IF NOT EXISTS flight_records_fts USING fts5(
    flight_date,
    departure_airport,
    arrival_airport,
    raw_text_excerpt,
    content='flight_records',
    content_rowid='id'
);

-- Triggers for FTS sync
CREATE TRIGGER IF NOT EXISTS flight_records_ai AFTER INSERT ON flight_records BEGIN
    INSERT INTO flight_records_fts(rowid, flight_date, departure_airport, arrival_airport, raw_text_excerpt)
    VALUES (new.id, new.flight_date, new.departure_airport, new.arrival_airport, new.raw_text_excerpt);
END;
CREATE TRIGGER IF NOT EXISTS flight_records_ad AFTER DELETE ON flight_records BEGIN
    INSERT INTO flight_records_fts(flight_records_fts, rowid, flight_date, departure_airport, arrival_airport, raw_text_excerpt)
    VALUES ('delete', old.id, old.flight_date, old.departure_airport, old.arrival_airport, old.raw_text_excerpt);
END;
CREATE TRIGGER IF NOT EXISTS flight_records_au AFTER UPDATE ON flight_records BEGIN
    INSERT INTO flight_records_fts(flight_records_fts, rowid, flight_date, departure_airport, arrival_airport, raw_text_excerpt)
    VALUES ('delete', old.id, old.flight_date, old.departure_airport, old.arrival_airport, old.raw_text_excerpt);
    INSERT INTO flight_records_fts(rowid, flight_date, departure_airport, arrival_airport, raw_text_excerpt)
    VALUES (new.id, new.flight_date, new.departure_airport, new.arrival_airport, new.raw_text_excerpt);
END;

-- ================================================
-- KNOWN EPSTEIN TRAVEL PATTERNS (Reference Data)
-- ================================================

CREATE TABLE IF NOT EXISTS known_epstein_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT NOT NULL CHECK(pattern_type IN ('aircraft', 'route', 'location', 'date_range')),
    -- Aircraft patterns
    tail_numbers TEXT,          -- JSON: ["N908JE", "N474AW"]
    -- Route patterns
    airports TEXT,              -- JSON: ["LMM", "TEB", "PBI", "SXM", "OST"]
    -- Date patterns (known active periods)
    date_start TEXT,
    date_end TEXT,
    -- Context
    description TEXT,
    source_document TEXT,       -- Which doc established this pattern
    confidence REAL DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed data for known Epstein aircraft
INSERT INTO known_epstein_patterns (pattern_type, tail_numbers, description, confidence) VALUES
('aircraft', '["N908JE"]', 'Epstein Gulfstream G-1159B, primary aircraft', 1.0),
('aircraft', '["N474AW"]', 'Epstein Cessna Citation, secondary aircraft', 0.95),
('route', '["LMM", "TEB"]', 'Little St. James to Teterboro (NY area)', 0.9),
('route', '["PBI", "LMM"]', 'Palm Beach to Little St. James', 0.9);

-- ================================================
-- ENTITY ANALYSIS CARDS CACHE
-- Fast lookup for right-panel analysis cards
-- ================================================

CREATE TABLE IF NOT EXISTS entity_analysis_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    -- Pre-computed card data (JSON)
    card_data TEXT NOT NULL,    -- Full card JSON (see schema below)
    -- Quick filter fields
    has_aircraft_evidence BOOLEAN DEFAULT 0,
    has_financial_evidence BOOLEAN DEFAULT 0,
    max_damning_score INTEGER DEFAULT 0,
    connection_count INTEGER DEFAULT 0,
    -- Cache freshness
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_updated_at TIMESTAMP,  -- For invalidation check
    -- Single entity per card
    UNIQUE(entity_id)
);

CREATE INDEX IF NOT EXISTS idx_eac_entity ON entity_analysis_cards(entity_id);
CREATE INDEX IF NOT EXISTS idx_eac_aircraft ON entity_analysis_cards(has_aircraft_evidence);
CREATE INDEX IF NOT EXISTS idx_eac_score ON entity_analysis_cards(max_damning_score DESC);

-- ================================================
-- GRAPH VIEW SESSIONS
-- For preserving user filter state
-- ================================================

CREATE TABLE IF NOT EXISTS graph_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT UNIQUE NOT NULL,  -- Browser session
    filter_settings TEXT,       -- JSON: active filters
    viewport_state TEXT,        -- JSON: zoom, pan, selected nodes
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_graph_session_token ON graph_sessions(session_token);
```

### 1.2 Existing Table Alterations

```sql
-- Add aircraft correlation fields to entity_document_links
ALTER TABLE entity_document_links ADD COLUMN flight_record_id INTEGER REFERENCES flight_records(id);
ALTER TABLE entity_document_links ADD COLUMN is_aircraft_related BOOLEAN DEFAULT 0;
ALTER TABLE entity_document_links ADD COLUMN aircraft_correlation_score REAL DEFAULT 0.0;

-- Add graph visualization priority to entities
ALTER TABLE entities ADD COLUMN graph_priority_score REAL DEFAULT 0.0;  -- Computed for visual hierarchy
ALTER TABLE entities ADD COLUMN is_graph_anchor BOOLEAN DEFAULT 0;       -- Force-include in graph

-- Add quick lookup for entity types with evidence
CREATE INDEX IF NOT EXISTS idx_edl_aircraft ON entity_document_links(is_aircraft_related);
```

---

## 2. Backend Endpoints

### 2.1 Core Graph Data Endpoint

```python
# GET /api/graph/data
# Query params: ?center_id=&min_score=&max_nodes=&filters={}
def api_graph_data():
    """
    Returns optimized graph payload with:
    - Nodes: id, name, type, score, radius, color, flags
    - Links: source, target, type, weight, flags
    - Metadata: total counts, filter summary
    
    Performance: <100ms for 1k nodes via pre-computed card table
    """
    pass
```

**Response Schema:**
```json
{
  "nodes": [
    {
      "id": 123,
      "name": "John Doe",
      "type": "person",
      "score": 87.5,
      "radius": 8.5,
      "color": "#e63946",
      "flags": ["high_signal", "aircraft_connected"],
      "card_summary": {
        "top_evidence_count": 5,
        "has_aircraft_evidence": true,
        "connection_count": 12
      }
    }
  ],
  "links": [
    {
      "source": 123,
      "target": 456,
      "type": "flew_with",
      "weight": 3.5,
      "flags": ["aircraft_correlated"],
      "aircraft_ids": [5, 8]
    }
  ],
  "metadata": {
    "total_nodes": 350,
    "total_links": 420,
    "center_id": 1,
    "filters_applied": {...}
  }
}
```

### 2.2 Entity Analysis Card Endpoint

```python
# GET /api/entity/<id>/card
def api_entity_card(entity_id):
    """
    Returns complete analysis card for right-panel display:
    - Entity profile (name, aliases, external links)
    - Key findings summary (top 5 evidence items)
    - Document evidence list with damning scores
    - Relationships summary
    - Aircraft/travel correlation data
    - Confidence metrics
    """
    pass
```

**Response Schema:**
```json
{
  "entity": {
    "id": 123,
    "name": "John Doe",
    "canonical_name": "DOE, JOHN",
    "type": "person",
    "role": "Business Executive",
    "implication_score": 87.5,
    "evidence_count": 24,
    "document_count": 8
  },
  "external_links": {
    "google": "https://...",
    "wikipedia": "https://...",
    "opencorporates": "https://..."
  },
  "key_findings": [
    {
      "type": "aircraft_travel",
      "severity": "high",
      "summary": "Traveled on N908JE 3 times (2002-2004)",
      "confidence": 0.95,
      "flight_ids": [45, 67, 89]
    },
    {
      "type": "financial",
      "severity": "medium", 
      "summary": "Payment received within 14 days of island visit",
      "confidence": 0.72
    }
  ],
  "top_evidence": [
    {
      "document_id": 456,
      "filename": "flight_log_2002.pdf",
      "page": 12,
      "damning_score": 85,
      "context": "...",
      "is_aircraft_related": true,
      "aircraft_correlation": {
        "tail_number": "N908JE",
        "is_known_epstein_aircraft": true,
        "pattern_match_score": 0.95
      }
    }
  ],
  "relationships": {
    "direct_count": 12,
    "by_type": {
      "flew_with": 5,
      "emailed": 3,
      "financially_linked": 2
    },
    "top_connections": [
      {"entity_id": 456, "name": "Jeffrey Epstein", "type": "flew_with", "strength": 5.0}
    ]
  },
  "aircraft_analysis": {
    "total_flights": 3,
    "known_epstein_aircraft_flights": 3,
    "route_pattern": "LMM-TEB (Epstein primary route)",
    "date_overlap_confidence": "high",
    "tail_numbers": ["N908JE"]
  },
  "confidence": {
    "overall": 0.89,
    "evidence_quality": "high",
    "corroboration": "multiple_sources"
  }
}
```

### 2.3 Aircraft Correlation Endpoints

```python
# GET /api/aircraft/<tail_number>/details
def api_aircraft_details(tail_number):
    """Returns aircraft info + all associated flights + entity passengers."""
    pass

# GET /api/flights/search
# Query: ?tail_number=&airport=&date_start=&date_end=&entity_id=
def api_flights_search():
    """Search flights with correlation scoring."""
    pass

# POST /api/aircraft/correlate
# Body: { "entity_id": 123 }
def api_aircraft_correlate():
    """Trigger re-correlation for entity (admin/researcher use)."""
    pass
```

### 2.4 Graph Filter Endpoints

```python
# GET /api/graph/filters/metadata
def api_graph_filter_metadata():
    """
    Returns available filter options:
    - Entity types with counts
    - Relationship types with counts
    - Score ranges
    - Aircraft flags
    """
    pass

# POST /api/graph/filters/apply
# Body: { filters object }
def api_graph_apply_filters():
    """
    Returns filtered node IDs for fast client-side filtering.
    Uses pre-computed entity_analysis_cards for speed.
    """
    pass
```

### 2.5 WebSocket for Real-time Updates

```python
# Socket.IO events for graph
@socketio.on('graph_subscribe')
def handle_graph_subscribe(entity_id):
    """Subscribe to updates for specific entity."""
    pass

@socketio.on('graph_viewport_update')  
def handle_viewport_update(data):
    """Save user's current view state."""
    pass
```

---

## 3. Aircraft-Travel Correlation Scoring Logic

### 3.1 Score Components

```python
class AircraftCorrelationScorer:
    """
    Calculates correlation score (0.0 - 1.0) between a flight/entity
    and known Epstein travel patterns.
    """
    
    # Known Epstein aircraft tail numbers with confidence
    KNOWN_AIRCRAFT = {
        "N908JE": 1.0,   # Gulfstream, primary
        "N474AW": 0.95,  # Cessna Citation
        "N221DG": 0.85,  # Previously associated
    }
    
    # Known route patterns (airport codes)
    KNOWN_ROUTES = [
        ("LMM", "TEB"),  # Little St. James to Teterboro
        ("PBI", "LMM"),  # Palm Beach to Little St. James
        ("TEB", "LMM"),  # Return route
    ]
    
    # Known active date ranges
    ACTIVE_DATE_RANGES = [
        ("1998-01-01", "2005-12-31"),  # Primary period
    ]
    
    def score_flight(self, flight_record: dict) -> dict:
        """
        Calculate composite correlation score.
        
        Score components (weighted):
        - Aircraft match: 40% weight
        - Route match: 25% weight  
        - Date overlap: 20% weight
        - Passenger correlation: 15% weight
        """
        scores = {
            "aircraft": self._score_aircraft(flight_record),
            "route": self._score_route(flight_record),
            "date": self._score_date(flight_record),
            "passenger": self._score_passenger_correlation(flight_record),
        }
        
        # Weighted composite
        weights = {"aircraft": 0.40, "route": 0.25, "date": 0.20, "passenger": 0.15}
        composite = sum(scores[k] * weights[k] for k in scores)
        
        # Generate flags
        flags = []
        if scores["aircraft"] > 0.7:
            flags.append("known_aircraft")
        if scores["route"] > 0.7:
            flags.append("epstein_route")
        if scores["date"] > 0.7:
            flags.append("date_overlap")
        if composite > 0.8:
            flags.append("high_correlation")
            
        return {
            "composite_score": round(composite, 3),
            "component_scores": scores,
            "pattern_flags": flags,
            "confidence_level": self._confidence_level(composite)
        }
    
    def _score_aircraft(self, flight: dict) -> float:
        """Score based on aircraft tail number match."""
        tail = (flight.get("tail_number") or "").upper().strip()
        if not tail:
            return 0.0
        # Direct match
        if tail in self.KNOWN_AIRCRAFT:
            return self.KNOWN_AIRCRAFT[tail]
        # Pattern match (similar registration patterns)
        if tail.startswith("N9") and len(tail) == 6:
            return 0.3  # Possible related aircraft
        return 0.0
    
    def _score_route(self, flight: dict) -> float:
        """Score based on departure/arrival airports."""
        dep = (flight.get("departure_airport") or "").upper()
        arr = (flight.get("arrival_airport") or "").upper()
        
        if not dep or not arr:
            return 0.0
            
        # Direct route match
        if (dep, arr) in self.KNOWN_ROUTES or (arr, dep) in self.KNOWN_ROUTES:
            return 1.0
            
        # Partial match (one airport known)
        known_airports = set()
        for r in self.KNOWN_ROUTES:
            known_airports.update(r)
        
        matches = sum(1 for a in [dep, arr] if a in known_airports)
        return matches * 0.4  # 0.4 for one, 0.8 for both
    
    def _score_date(self, flight: dict) -> float:
        """Score based on date falling in known active periods."""
        flight_date = flight.get("flight_date")
        if not flight_date:
            return 0.0
            
        try:
            from datetime import datetime
            fd = datetime.fromisoformat(flight_date.replace("Z", "+00:00"))
            
            for start, end in self.ACTIVE_DATE_RANGES:
                sd = datetime.fromisoformat(start)
                ed = datetime.fromisoformat(end)
                if sd <= fd <= ed:
                    return 1.0
            return 0.0
        except:
            return 0.0
    
    def _score_passenger_correlation(self, flight: dict) -> float:
        """Score based on known Epstein associates on same flight."""
        passenger_ids = flight.get("passenger_entity_ids", [])
        if not passenger_ids:
            return 0.0
            
        # Query for high-implication passengers
        # Simplified: count passengers with score > 70
        high_signal_count = self._count_high_signal_passengers(passenger_ids)
        return min(1.0, high_signal_count / 3.0)  # 3+ high-signal = full score
    
    def _confidence_level(self, score: float) -> str:
        if score >= 0.85: return "very_high"
        if score >= 0.70: return "high"
        if score >= 0.50: return "medium"
        if score >= 0.30: return "low"
        return "very_low"
```

### 3.2 Batch Correlation Job

```python
def run_aircraft_correlation_batch(entity_id: int = None):
    """
    Background job to correlate flights.
    If entity_id provided, only re-score that entity's flights.
    """
    pass
```

---

## 4. Frontend Components

### 4.1 File Structure

```
dashboard/
├── static/
│   ├── js/
│   │   ├── graph/
│   │   │   ├── spiderweb-graph.js      # Main D3 visualization
│   │   │   ├── node-card-panel.js      # Right-side analysis card
│   │   │   ├── filter-panel.js         # Left-side filter controls
│   │   │   ├── aircraft-overlay.js     # Aircraft correlation visualization
│   │   │   ├── force-simulation.js     # D3 force layout optimized
│   │   │   └── graph-state.js          # State management
│   │   └── utils.js
│   └── css/
│       └── graph-v2.css
├── templates/
│   └── graph-v2.html
```

### 4.2 Main Graph Component (spiderweb-graph.js)

```javascript
class SpiderwebGraph {
  constructor(containerId, options = {}) {
    this.container = d3.select(`#${containerId}`);
    this.width = options.width || 1200;
    this.height = options.height || 800;
    
    // Performance settings for 1k+ nodes
    this.maxNodesRender = options.maxNodes || 1000;
    this.useWebWorker = true;  // Off-screen force simulation
    this.levelOfDetail = true;  // Simplified rendering at distance
    
    // State
    this.nodes = [];
    this.links = [];
    this.selectedNodeId = null;
    this.transform = d3.zoomIdentity;
    
    // Initialize
    this._initSvg();
    this._initSimulation();
    this._initInteractions();
  }
  
  _initSvg() {
    this.svg = this.container.append("svg")
      .attr("viewBox", [0, 0, this.width, this.height])
      .attr("width", "100%")
      .attr("height", "100%");
      
    // Layers for z-ordering
    this.layers = {
      links: this.svg.append("g").attr("class", "links"),
      nodes: this.svg.append("g").attr("class", "nodes"),
      labels: this.svg.append("g").attr("class", "labels"),
      highlights: this.svg.append("g").attr("class", "highlights")
    };
    
    // Zoom behavior
    this.zoom = d3.zoom()
      .scaleExtent([0.1, 8])
      .on("zoom", (e) => this._onZoom(e));
    this.svg.call(this.zoom);
  }
  
  _initSimulation() {
    // Optimized force parameters for large graphs
    this.simulation = d3.forceSimulation()
      .force("link", d3.forceLink().id(d => d.id).distance(d => 100 / (d.weight || 1)))
      .force("charge", d3.forceManyBody().strength(d => -30 - (d.connections || 0) * 5))
      .force("center", d3.forceCenter(this.width / 2, this.height / 2))
      .force("collision", d3.forceCollide().radius(d => (d.radius || 5) + 2))
      .force("x", d3.forceX().strength(0.05))
      .force("y", d3.forceY().strength(0.05));
      
    // Alpha decay for faster settling
    this.simulation.alphaDecay(0.02);
  }
  
  loadData(url) {
    // Stream large datasets
    fetch(url)
      .then(r => r.json())
      .then(data => this._processData(data))
      .then(processed => this._render(processed));
  }
  
  _processData(raw) {
    // Pre-compute visual properties
    const nodes = raw.nodes.map(n => ({
      ...n,
      // Visual hierarchy: high-score nodes get more space
      radius: this._computeRadius(n),
      // LOD level based on importance
      lod: this._computeLOD(n)
    }));
    
    const links = raw.links.map(l => ({
      ...l,
      // Stroke width based on weight
      strokeWidth: Math.max(0.5, Math.min(4, l.weight * 0.8))
    }));
    
    return { nodes, links };
  }
  
  _computeRadius(node) {
    // Base radius on implication score with diminishing returns
    const base = 4;
    const scoreBonus = Math.sqrt(node.score || 0) * 1.5;
    const connectionBonus = Math.log2((node.connections || 0) + 1) * 2;
    return Math.min(25, base + scoreBonus + connectionBonus);
  }
  
  _computeLOD(node) {
    // Level of detail for performance
    if (node.score >= 80) return "high";
    if (node.score >= 50) return "medium";
    return "low";
  }
  
  _render({ nodes, links }) {
    this.nodes = nodes;
    this.links = links;
    
    // Render links
    const linkSel = this.layers.links
      .selectAll("line")
      .data(links, d => `${d.source}-${d.target}`);
      
    linkSel.enter()
      .append("line")
      .attr("stroke", d => this._linkColor(d))
      .attr("stroke-width", d => d.strokeWidth)
      .attr("stroke-opacity", 0.6);
      
    // Render nodes with aircraft correlation highlighting
    const nodeSel = this.layers.nodes
      .selectAll("circle")
      .data(nodes, d => d.id);
      
    const nodeEnter = nodeSel.enter()
      .append("circle")
      .attr("r", d => d.radius)
      .attr("fill", d => d.color)
      .attr("stroke", d => this._nodeStroke(d))
      .attr("stroke-width", d => d.flags?.includes("aircraft_connected") ? 3 : 1)
      .on("click", (e, d) => this._onNodeClick(d))
      .on("mouseover", (e, d) => this._onNodeHover(d));
      
    // Aircraft correlation badges
    nodeEnter.filter(d => d.flags?.includes("aircraft_connected"))
      .append("text")
      .attr("class", "aircraft-badge")
      .attr("dy", d => -d.radius - 5)
      .text("✈");
      
    // Update simulation
    this.simulation.nodes(nodes);
    this.simulation.force("link").links(links);
    this.simulation.alpha(1).restart();
    
    // Tick handler
    this.simulation.on("tick", () => this._onTick());
  }
  
  _onNodeClick(node) {
    this.selectedNodeId = node.id;
    
    // Highlight selected node
    this.layers.highlights.selectAll("*").remove();
    this.layers.highlights
      .append("circle")
      .attr("cx", node.x)
      .attr("cy", node.y)
      .attr("r", node.radius + 8)
      .attr("fill", "none")
      .attr("stroke", "#fbbf24")
      .attr("stroke-width", 3)
      .attr("stroke-dasharray", "5,5");
      
    // Emit event for card panel
    this._emit("nodeSelect", node);
  }
  
  // ... additional methods
}
```

### 4.3 Node Analysis Card Panel (node-card-panel.js)

```javascript
class NodeCardPanel {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.currentEntityId = null;
    this.cache = new Map();  // LRU cache for card data
  }
  
  async loadEntity(entityId) {
    if (this.currentEntityId === entityId) return;
    
    // Show loading state
    this._showLoading();
    
    // Check cache
    if (this.cache.has(entityId)) {
      this._render(this.cache.get(entityId));
      return;
    }
    
    // Fetch from API
    const data = await fetch(`/api/entity/${entityId}/card`).then(r => r.json());
    
    // Cache result
    this.cache.set(entityId, data);
    if (this.cache.size > 50) {
      // LRU eviction
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this._render(data);
  }
  
  _render(data) {
    this.currentEntityId = data.entity.id;
    
    const html = `
      <div class="entity-card">
        <header class="card-header">
          <h2>${this._escape(data.entity.name)}</h2>
          <span class="entity-type-badge ${data.entity.type}">${data.entity.type}</span>
        </header>
        
        <div class="score-section">
          <div class="implication-score">
            <span class="score-value">${data.entity.implication_score.toFixed(1)}</span>
            <span class="score-label">Implication Score</span>
          </div>
          <div class="confidence-badge ${data.confidence.overall > 0.8 ? 'high' : 'medium'}">
            ${(data.confidence.overall * 100).toFixed(0)}% confidence
          </div>
        </div>
        
        <!-- Aircraft Analysis Section (prominent if applicable) -->
        ${data.aircraft_analysis?.total_flights > 0 ? `
          <section class="aircraft-section priority-section">
            <h3>✈️ Aircraft Travel Analysis</h3>
            <div class="alert ${data.aircraft_analysis.known_epstein_aircraft_flights > 0 ? 'alert-critical' : 'alert-info'}">
              <strong>${data.aircraft_analysis.known_epstein_aircraft_flights} flights</strong> 
              on known Epstein aircraft
            </div>
            <div class="flight-details">
              <p><strong>Tail Numbers:</strong> ${data.aircraft_analysis.tail_numbers.join(", ")}</p>
              <p><strong>Primary Route:</strong> ${data.aircraft_analysis.route_pattern}</p>
              <p><strong>Date Correlation:</strong> 
                <span class="correlation-badge ${data.aircraft_analysis.date_overlap_confidence}">
                  ${data.aircraft_analysis.date_overlap_confidence}
                </span>
              </p>
            </div>
            <button class="btn btn-sm" onclick="viewFlightDetails(${data.entity.id})">
              View Flight Records
            </button>
          </section>
        ` : ''}
        
        <!-- Key Findings -->
        <section class="findings-section">
          <h3>🔍 Key Findings</h3>
          ${data.key_findings.map(f => `
            <div class="finding-item ${f.severity}">
              <span class="finding-type">${this._formatFindingType(f.type)}</span>
              <p>${f.summary}</p>
              <span class="confidence-tag">${(f.confidence * 100).toFixed(0)}% confidence</span>
            </div>
          `).join('')}
        </section>
        
        <!-- Top Evidence -->
        <section class="evidence-section">
          <h3>📄 Top Evidence (${data.top_evidence.length})</h3>
          ${data.top_evidence.map(e => `
            <div class="evidence-item ${e.is_aircraft_related ? 'aircraft-evidence' : ''}">
              <div class="evidence-header">
                <a href="/document/${e.document_id}?page=${e.page}" target="_blank">
                  ${this._escape(e.filename)}
                </a>
                <span class="damning-score">${e.damning_score}</span>
              </div>
              ${e.aircraft_correlation ? `
                <div class="aircraft-correlation-badge">
                  ✈️ ${e.aircraft_correlation.tail_number}
                  ${e.aircraft_correlation.is_known_epstein_aircraft ? '(Known Epstein)' : ''}
                </div>
              ` : ''}
              <p class="context-snippet">${this._escape(e.context.substring(0, 200))}...</p>
            </div>
          `).join('')}
        </section>
        
        <!-- Relationships -->
        <section class="relationships-section">
          <h3>🔗 Connections (${data.relationships.direct_count})</h3>
          ${data.relationships.top_connections.map(r => `
            <div class="relationship-item" data-entity-id="${r.entity_id}">
              <span class="connection-name">${this._escape(r.name)}</span>
              <span class="connection-type">${r.type}</span>
              <span class="connection-strength">${"█".repeat(Math.round(r.strength))}</span>
            </div>
          `).join('')}
        </section>
        
        <!-- External Links -->
        <section class="external-links">
          <a href="${data.external_links.google}" target="_blank" class="btn btn-sm">Google</a>
          ${data.external_links.wikipedia ? `
            <a href="${data.external_links.wikipedia}" target="_blank" class="btn btn-sm">Wikipedia</a>
          ` : ''}
        </section>
      </div>
    `;
    
    this.container.innerHTML = html;
  }
}
```

### 4.4 Filter Panel (filter-panel.js)

```javascript
class FilterPanel {
  constructor(containerId, onFilterChange) {
    this.container = document.getElementById(containerId);
    this.onFilterChange = onFilterChange;
    this.filters = {
      entityTypes: [],
      minScore: 0,
      maxScore: 100,
      relationshipTypes: [],
      aircraftOnly: false,
      highConfidenceOnly: false,
      searchText: ""
    };
    
    this._init();
  }
  
  _init() {
    this._render();
    this._bindEvents();
    this._loadMetadata();
  }
  
  async _loadMetadata() {
    const meta = await fetch("/api/graph/filters/metadata").then(r => r.json());
    this._updateCounts(meta);
  }
  
  _render() {
    this.container.innerHTML = `
      <div class="filter-panel">
        <h3>🔍 Filters</h3>
        
        <!-- Quick Presets -->
        <div class="filter-presets">
          <button class="preset-btn" data-preset="aircraft">✈️ Aircraft Connected</button>
          <button class="preset-btn" data-preset="high-signal">⚡ High Signal Only</button>
          <button class="preset-btn" data-preset="epstein-core">🎯 Epstein Core Network</button>
        </div>
        
        <!-- Entity Type Filter -->
        <div class="filter-group">
          <label>Entity Types</label>
          <div class="checkbox-list">
            ${['person', 'organization', 'location', 'aircraft', 'financial'].map(t => `
              <label class="checkbox-label">
                <input type="checkbox" name="entityType" value="${t}" checked>
                <span class="type-dot" style="background: ${this._typeColor(t)}"></span>
                ${t}
                <span class="count" data-type="${t}">-</span>
              </label>
            `).join('')}
          </div>
        </div>
        
        <!-- Score Range -->
        <div class="filter-group">
          <label>Implication Score</label>
          <div class="range-slider">
            <input type="range" id="minScore" min="0" max="100" value="0">
            <input type="range" id="maxScore" min="0" max="100" value="100">
            <div class="range-labels">
              <span id="minScoreLabel">0</span>
              <span id="maxScoreLabel">100</span>
            </div>
          </div>
        </div>
        
        <!-- Aircraft Correlation -->
        <div class="filter-group">
          <label class="checkbox-label highlight">
            <input type="checkbox" id="aircraftOnly">
            <span>✈️ Aircraft-connected only</span>
          </label>
        </div>
        
        <!-- Search -->
        <div class="filter-group">
          <input type="search" id="searchFilter" placeholder="Search entities...">
        </div>
        
        <div class="filter-actions">
          <button id="applyFilters" class="btn btn-primary">Apply</button>
          <button id="resetFilters" class="btn btn-sm">Reset</button>
        </div>
        
        <div class="filter-stats">
          Showing <span id="filteredCount">-</span> of <span id="totalCount">-</span>
        </div>
      </div>
    `;
  }
  
  _bindEvents() {
    // Debounced filter application
    const debouncedApply = this._debounce(() => this._apply(), 150);
    
    this.container.querySelectorAll('input').forEach(el => {
      el.addEventListener('change', debouncedApply);
      el.addEventListener('input', debouncedApply);
    });
    
    // Preset buttons
    this.container.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this._applyPreset(e.target.dataset.preset));
    });
  }
  
  _apply() {
    // Collect filter state
    this.filters.entityTypes = Array.from(
      this.container.querySelectorAll('input[name="entityType"]:checked')
    ).map(el => el.value);
    
    this.filters.minScore = parseInt(this.container.querySelector('#minScore').value);
    this.filters.maxScore = parseInt(this.container.querySelector('#maxScore').value);
    this.filters.aircraftOnly = this.container.querySelector('#aircraftOnly').checked;
    this.filters.searchText = this.container.querySelector('#searchFilter').value;
    
    // Emit to parent
    this.onFilterChange(this.filters);
  }
  
  _applyPreset(preset) {
    switch(preset) {
      case 'aircraft':
        this.filters = { ...this.filters, aircraftOnly: true, minScore: 30 };
        break;
      case 'high-signal':
        this.filters = { ...this.filters, minScore: 70, highConfidenceOnly: true };
        break;
      case 'epstein-core':
        this.filters = { 
          ...this.filters, 
          minScore: 50, 
          entityTypes: ['person'],
          aircraftOnly: true 
        };
        break;
    }
    this._syncUI();
    this._apply();
  }
  
  _debounce(fn, ms) {
    let timeout;
    return (...args) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => fn(...args), ms);
    };
  }
}
```

---

## 5. Performance Strategy for 1k+ Nodes

### 5.1 Database Optimization

```sql
-- Pre-computed materialized view for graph queries
CREATE TABLE IF NOT EXISTS graph_node_cache (
    entity_id INTEGER PRIMARY KEY,
    -- All fields needed for graph rendering
    display_data TEXT,  -- JSON with all visual properties
    -- Filter indices
    score_bucket INTEGER,  -- 0-10, 10-20, etc for fast range queries
    has_aircraft_flag BOOLEAN,
    connection_count INTEGER,
    -- Last update for cache invalidation
    computed_at TIMESTAMP
);

-- Covering index for common filter combination
CREATE INDEX idx_graph_filter ON graph_node_cache(
    score_bucket, 
    has_aircraft_flag, 
    connection_count DESC
);
```

### 5.2 Frontend Performance

```javascript
// Level-of-detail rendering
class LODRenderer {
  constructor(svg) {
    this.svg = svg;
    this.zoomLevel = 1;
    this.nodeVisibilityThreshold = 0.3;  // Hide labels below this zoom
  }
  
  updateZoom(scale) {
    this.zoomLevel = scale;
    
    // Adjust detail level based on zoom
    if (scale < 0.3) {
      this._setDetailLevel('minimal');
    } else if (scale < 0.7) {
      this._setDetailLevel('low');
    } else {
      this._setDetailLevel('full');
    }
  }
  
  _setDetailLevel(level) {
    // Toggle label visibility
    this.svg.selectAll('.node-label')
      .style('display', level === 'minimal' ? 'none' : null);
      
    // Simplify nodes at distance
    this.svg.selectAll('.node-detail')
      .style('opacity', level === 'full' ? 1 : 0.3);
  }
}

// Web Worker for force simulation
// worker-force.js
self.importScripts('https://d3js.org/d3-collection.v1.min.js');
// ... d3-force modules

let simulation = d3.forceSimulation();

self.onmessage = (event) => {
  const { nodes, links, alpha } = event.data;
  
  simulation
    .nodes(nodes)
    .force('link', d3.forceLink(links).id(d => d.id))
    .alpha(alpha)
    .on('tick', () => {
      self.postMessage({ type: 'tick', nodes, links });
    })
    .on('end', () => {
      self.postMessage({ type: 'end', nodes, links });
    });
};
```

### 5.3 API Pagination for Large Graphs

```python
# GET /api/graph/data?viewport=x,y,w,h&zoom=1.5
def api_graph_data_viewport():
    """
    Return only nodes visible in current viewport.
    Client requests viewport, server returns visible + buffer nodes.
    """
    pass
```

---

## 6. Phased Implementation Order

### Phase 1: Foundation (Week 1-2)

1. **Database Schema**
   - Create `aircraft_records`, `flight_records`, `known_epstein_patterns` tables
   - Add indices and FTS
   - Migration script for existing data

2. **Backend Core**
   - Aircraft correlation scorer class
   - `/api/entity/<id>/card` endpoint
   - Enhanced `/api/graph/data` with aircraft flags

3. **Frontend Foundation**
   - Refactor graph to component-based architecture
   - Basic node card panel (right side)
   - Basic filter panel (left side)

### Phase 2: Aircraft Intelligence (Week 3-4)

1. **Scoring Engine**
   - Implement all scoring components
   - Batch correlation job
   - Backfill existing flight records

2. **Aircraft Visualization**
   - Aircraft badges on nodes
   - Aircraft section in node cards
   - Aircraft filter preset

3. **Flight Records UI**
   - Flight detail modal
   - Aircraft search interface
   - Route visualization

### Phase 3: Performance & Polish (Week 5-6)

1. **Performance Optimization**
   - Implement graph_node_cache
   - Web Worker force simulation
   - Level-of-detail rendering
   - Viewport-based loading

2. **Advanced Filtering**
   - Fast client-side filtering
   - Filter state persistence
   - URL-based filter sharing

3. **UI Polish**
   - Animations and transitions
   - Keyboard shortcuts
   - Mobile responsiveness

### Phase 4: Integration & Testing (Week 7-8)

1. **Integration**
   - Pipeline integration (auto-correlate new flights)
   - Export functionality
   - Public viewer updates

2. **Testing**
   - Load testing with 10k nodes
   - Cross-browser testing
   - User acceptance testing

---

## 7. Key Implementation Files

### New Files to Create:

```
database/migrations/006_aircraft_correlation.sql
knowledge_graph/aircraft_correlator.py
dashboard/static/js/graph/spiderweb-graph.js
dashboard/static/js/graph/node-card-panel.js
dashboard/static/js/graph/filter-panel.js
dashboard/static/js/graph/aircraft-overlay.js
dashboard/static/css/graph-v2.css
dashboard/templates/graph-v2.html
```

### Files to Modify:

```
database/schema.sql  # Add new tables
dashboard/app.py     # Add new endpoints
knowledge_graph/graph_engine.py  # Add aircraft analysis
```

---

## 8. Success Metrics

- **Performance**: Graph load < 500ms, filter application < 100ms for 1k nodes
- **Accuracy**: Aircraft correlation precision > 90% on known test cases
- **Usability**: Node analysis card provides actionable intelligence within 3 seconds
- **Coverage**: > 95% of entities with flight evidence have aircraft correlation score

---

## Appendix: Visual Hierarchy Guidelines

| Score Range | Radius | Stroke | Label | Priority |
|-------------|--------|--------|-------|----------|
| 90-100 | 20px | 3px gold | Always | Critical |
| 70-89 | 15px | 2px | Zoom < 0.5 | High |
| 50-69 | 10px | 1px | Zoom < 0.8 | Medium |
| 30-49 | 7px | 1px | Zoom < 1.2 | Low |
| < 30 | 5px | none | Zoom > 1.5 | Minimal |

**Aircraft-connected nodes**: Add ✈️ badge and orange stroke ring
**Epstein center node**: Always visible, larger radius, special styling
