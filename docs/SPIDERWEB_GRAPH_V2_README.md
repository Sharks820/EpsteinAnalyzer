# EpsteinAnalyzer Spiderweb Graph V2 - Implementation Guide

## Overview

This is a complete blueprint and partial implementation for an enhanced investigative spiderweb graph UI that transforms the existing graph visualization into an active investigation tool.

## What's Included

### 1. Database Schema (`database/migrations/006_aircraft_correlation.sql`)
- `aircraft_records` - Registry of aircraft with Epstein association flags
- `flight_records` - Flight records with correlation scoring
- `known_epstein_patterns` - Reference data for known patterns
- `entity_analysis_cards` - Pre-computed cache for fast card loading
- `graph_node_cache` - Performance cache for graph queries
- Enhanced indices for fast filtering

### 2. Backend Components (`knowledge_graph/aircraft_correlator.py`)
- `AircraftCorrelator` class with weighted scoring algorithm
- Correlates flights/entities against known Epstein patterns
- Batch processing capabilities
- CLI interface for manual correlation

### 3. API Endpoints (`dashboard/graph_api.py`)
- `GET /api/graph/data` - Optimized graph data with filtering
- `GET /api/entity/<id>/card` - Complete entity analysis card
- `GET /api/aircraft/<tail_number>` - Aircraft details
- `GET /api/flights/search` - Flight search with filters
- `GET /api/graph/filters/metadata` - Filter options with counts

### 4. Frontend Components

#### `dashboard/static/js/graph/spiderweb-graph.js`
- Optimized D3.js force-directed graph
- Level-of-detail rendering for 1k+ nodes
- Aircraft correlation highlighting
- Interactive node selection
- Fast filtering support

#### `dashboard/static/js/graph/node-card-panel.js`
- Right-side analysis card panel
- LRU caching for performance
- Aircraft travel analysis section
- Key findings and evidence display
- Relationship visualization

#### `dashboard/static/css/graph-v2.css`
- Complete styling for all components
- Responsive design
- Dark theme matching existing UI
- Aircraft correlation visual indicators

#### `dashboard/templates/graph-v2.html`
- Complete template integrating all components
- Three-panel layout (filters, graph, cards)
- Toolbar with zoom/center/export controls
- Legend and status indicators

## Integration Steps

### Step 1: Apply Database Migration

```bash
cd C:\Users\Conner\EpsteinAnalyzer
sqlite3 data/epstein_analyzer.db < database/migrations/006_aircraft_correlation.sql
```

### Step 2: Register API Routes

In `dashboard/app.py`, add:

```python
from dashboard.graph_api import register_graph_api

# After app creation
register_graph_api(app)
```

Or manually add the routes from `dashboard/graph_api.py` to your existing route handlers.

### Step 3: Add Route for V2 Graph Page

In `dashboard/app.py`, add:

```python
@app.route("/graph-v2")
def graph_v2():
    return render_template_string(open("dashboard/templates/graph-v2.html").read())
```

Or if using Flask's template loader:

```python
@app.route("/graph-v2")
def graph_v2():
    return render_template("graph-v2.html")
```

### Step 4: Run Aircraft Correlation

Populate correlation scores for existing flight data:

```bash
python -m knowledge_graph.aircraft_correlator --batch
```

### Step 5: Access the New Graph

Navigate to: `http://127.0.0.1:8080/graph-v2`

## Key Features

### 1. Interactive Node Cards
- Click any node to open right-side analysis panel
- Shows implication score, evidence count, key findings
- Aircraft travel analysis with correlation scores
- Top evidence items with context snippets
- Direct links to documents and external research

### 2. Aircraft Correlation
- Automatic detection of known Epstein aircraft (N908JE, N474AW, N221DG)
- Route pattern matching (LMM-TEB, PBI-LMM)
- Date overlap analysis
- Composite scoring (0-1) with confidence levels
- Visual badges on graph nodes

### 3. Fast Filtering
- Entity type filters
- Implication score range slider
- "Aircraft-connected only" toggle
- Real-time search
- Filter presets (Aircraft Connected, High Signal, Epstein Core)

### 4. Performance for 1k+ Nodes
- Level-of-detail rendering (hide labels at distance)
- Pre-computed entity analysis cards
- Database indices for fast filtering
- Efficient D3.js force simulation

## Aircraft Correlation Scoring

The correlation algorithm uses weighted components:

| Component | Weight | Description |
|-----------|--------|-------------|
| Aircraft Match | 40% | Tail number matches known Epstein aircraft |
| Route Match | 25% | Flight route matches known Epstein routes |
| Date Overlap | 20% | Flight date falls in active period (1998-2019) |
| Passenger Correlation | 15% | High-signal passengers on same flight |

**Score Interpretation:**
- 0.85-1.0: Very High (known aircraft + route + date)
- 0.70-0.84: High (multiple strong indicators)
- 0.50-0.69: Medium (some indicators)
- 0.30-0.49: Low (weak indicators)
- < 0.30: Very Low (no significant correlation)

## Customization

### Adding Known Aircraft

Edit `database/migrations/006_aircraft_correlation.sql`:

```sql
INSERT INTO aircraft_records (tail_number, aircraft_type, is_known_epstein_aircraft, ...) 
VALUES ('NEW_TAIL', 'Type', 1, ...);
```

Or via the API (to be implemented).

### Adding Route Patterns

```sql
INSERT INTO known_epstein_patterns (pattern_type, airports, description, confidence)
VALUES ('route', '["NEW", "ROUTE"]', 'Description', 0.9);
```

### Adjusting Score Weights

Edit `knowledge_graph/aircraft_correlator.py`:

```python
WEIGHTS = {
    "aircraft": 0.50,  # Increase aircraft weight
    "route": 0.20,
    "date": 0.20,
    "passenger": 0.10,
}
```

## Performance Tuning

### Database
- Ensure `graph_node_cache` table is populated
- Run `ANALYZE` after large imports
- Consider materialized views for complex queries

### Frontend
- Adjust `maxNodes` in graph initialization
- Modify LOD thresholds for your data
- Use Web Worker for force simulation (future enhancement)

## Future Enhancements

### Phase 2+ Ideas
1. **Temporal Graph** - Animate graph over time
2. **Geographic Overlay** - Map view of flight routes
3. **AI-Powered Suggestions** - Auto-suggest related entities
4. **Collaborative Annotations** - User notes on entities
5. **Pattern Detection Alerts** - Auto-flag suspicious patterns
6. **Export Formats** - GEXF, GraphML, Cypher

## Troubleshooting

### Graph not loading
- Check browser console for JS errors
- Verify `/api/graph/data` returns valid JSON
- Ensure D3.js is loaded (`/static/d3.v7.min.js`)

### Aircraft correlation not showing
- Run batch correlation: `python -m knowledge_graph.aircraft_correlator --batch`
- Check `flight_records` table has data
- Verify `aircraft_records` has known Epstein aircraft

### Slow filtering
- Check `graph_node_cache` table exists and is populated
- Ensure database indices were created
- Consider reducing `maxNodes` in graph config

## API Quick Reference

### Get Graph Data
```
GET /api/graph/data?min_score=50&aircraft_only=true&max_nodes=500
```

### Get Entity Card
```
GET /api/entity/123/card
```

### Search Flights
```
GET /api/flights/search?tail_number=N908JE&date_start=2002-01-01
```

### Get Aircraft Details
```
GET /api/aircraft/N908JE
```

## License

Same as EpsteinAnalyzer project.
