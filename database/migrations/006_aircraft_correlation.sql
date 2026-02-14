-- Migration: Aircraft Correlation Tables
-- Adds tables for aircraft tracking and flight record correlation with Epstein patterns
-- Run: sqlite3 data/epstein_analyzer.db < database/migrations/006_aircraft_correlation.sql

-- ================================================
-- AIRCRAFT REGISTRY
-- ================================================

CREATE TABLE IF NOT EXISTS aircraft_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tail_number TEXT NOT NULL,
    aircraft_type TEXT,
    make_model TEXT,
    serial_number TEXT,
    is_known_epstein_aircraft BOOLEAN DEFAULT 0,
    epstein_association_confidence REAL DEFAULT 0.0,
    epstein_association_notes TEXT,
    faa_registration_data TEXT,  -- JSON
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
    flight_date TEXT,
    departure_airport TEXT,
    arrival_airport TEXT,
    departure_time TEXT,
    arrival_time TEXT,
    passenger_entity_ids TEXT,  -- JSON: [123, 456, 789]
    passenger_count INTEGER DEFAULT 0,
    pilot_entity_ids TEXT,      -- JSON: [123]
    epstein_pattern_score REAL DEFAULT 0.0,
    pattern_flags TEXT,         -- JSON: ["known_aircraft", "epstein_route"]
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

-- FTS sync triggers
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
-- KNOWN EPSTEIN PATTERNS (REFERENCE DATA)
-- ================================================

CREATE TABLE IF NOT EXISTS known_epstein_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT NOT NULL CHECK(pattern_type IN ('aircraft', 'route', 'location', 'date_range')),
    tail_numbers TEXT,          -- JSON
    airports TEXT,              -- JSON
    date_start TEXT,
    date_end TEXT,
    description TEXT,
    source_document TEXT,
    confidence REAL DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed known Epstein aircraft and routes
INSERT OR IGNORE INTO known_epstein_patterns (pattern_type, tail_numbers, description, confidence) VALUES
('aircraft', '["N908JE"]', 'Epstein Gulfstream G-1159B, primary aircraft', 1.0),
('aircraft', '["N474AW"]', 'Epstein Cessna Citation 680, secondary aircraft', 0.95),
('aircraft', '["N221DG"]', 'Epstein Cessna 421C, tertiary aircraft', 0.90),
('route', '["LMM", "TEB"]', 'Little St. James (USVI) to Teterboro (NY area) - Primary route', 0.95),
('route', '["PBI", "LMM"]', 'Palm Beach to Little St. James', 0.90),
('route', '["TEB", "LMM"]', 'Teterboro to Little St. James - Return route', 0.95),
('route', '["APF", "LMM"]', 'Naples Municipal to Little St. James', 0.85),
('location', '["LMM"]', 'Little St. James Airport - Epstein private island', 1.0),
('location', '["TEB"]', 'Teterboro Airport - NYC area access', 0.90),
('location', '["PBI"]', 'Palm Beach International - Florida residence', 0.90),
('date_range', NULL, 'Primary Epstein flight activity period', 0.95);

-- Update the date_range record separately with dates
UPDATE known_epstein_patterns 
SET date_start = '1998-01-01', date_end = '2019-07-01'
WHERE pattern_type = 'date_range';

-- ================================================
-- ENTITY ANALYSIS CARDS CACHE
-- ================================================

CREATE TABLE IF NOT EXISTS entity_analysis_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    card_data TEXT NOT NULL,
    has_aircraft_evidence BOOLEAN DEFAULT 0,
    has_financial_evidence BOOLEAN DEFAULT 0,
    max_damning_score INTEGER DEFAULT 0,
    connection_count INTEGER DEFAULT 0,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_updated_at TIMESTAMP,
    UNIQUE(entity_id)
);

CREATE INDEX IF NOT EXISTS idx_eac_entity ON entity_analysis_cards(entity_id);
CREATE INDEX IF NOT EXISTS idx_eac_aircraft ON entity_analysis_cards(has_aircraft_evidence);
CREATE INDEX IF NOT EXISTS idx_eac_score ON entity_analysis_cards(max_damning_score DESC);

-- ================================================
-- ALTER EXISTING TABLES
-- ================================================

-- Add aircraft correlation fields to entity_document_links
ALTER TABLE entity_document_links ADD COLUMN flight_record_id INTEGER REFERENCES flight_records(id);
ALTER TABLE entity_document_links ADD COLUMN is_aircraft_related BOOLEAN DEFAULT 0;
ALTER TABLE entity_document_links ADD COLUMN aircraft_correlation_score REAL DEFAULT 0.0;

-- Add graph visualization priority to entities
ALTER TABLE entities ADD COLUMN graph_priority_score REAL DEFAULT 0.0;
ALTER TABLE entities ADD COLUMN is_graph_anchor BOOLEAN DEFAULT 0;

-- Add quick lookup index
CREATE INDEX IF NOT EXISTS idx_edl_aircraft ON entity_document_links(is_aircraft_related);

-- ================================================
-- GRAPH PERFORMANCE CACHE
-- ================================================

CREATE TABLE IF NOT EXISTS graph_node_cache (
    entity_id INTEGER PRIMARY KEY,
    display_data TEXT NOT NULL,
    score_bucket INTEGER,
    has_aircraft_flag BOOLEAN,
    connection_count INTEGER,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_graph_filter ON graph_node_cache(
    score_bucket, 
    has_aircraft_flag, 
    connection_count DESC
);

-- ================================================
-- SEED KNOWN EPSTEIN AIRCRAFT
-- ================================================

INSERT OR IGNORE INTO aircraft_records (tail_number, aircraft_type, make_model, is_known_epstein_aircraft, epstein_association_confidence, epstein_association_notes) VALUES
('N908JE', 'Gulfstream', 'G-1159B', 1, 1.0, 'Primary Epstein aircraft - Gulfstream II'),
('N474AW', 'Cessna Citation', 'Citation 680 Sovereign', 1, 0.95, 'Secondary Epstein aircraft'),
('N221DG', 'Cessna', '421C Golden Eagle', 1, 0.90, 'Tertiary aircraft, used for shorter hops');

-- ================================================
-- TRIGGER: Auto-update entity_analysis_cards on evidence change
-- ================================================

CREATE TRIGGER IF NOT EXISTS invalidate_card_cache AFTER UPDATE ON entity_document_links
BEGIN
    UPDATE entity_analysis_cards 
    SET computed_at = datetime('now', '-1 day')  -- Mark as stale
    WHERE entity_id = NEW.entity_id;
END;

CREATE TRIGGER IF NOT EXISTS invalidate_card_cache_on_insert AFTER INSERT ON entity_document_links
BEGIN
    DELETE FROM entity_analysis_cards WHERE entity_id = NEW.entity_id;
END;
