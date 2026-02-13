-- EpsteinAnalyzer Database Schema
-- SQLite with FTS5 Full-Text Search
-- ================================================

-- ================================================
-- DATASETS & DOCUMENTS
-- ================================================

CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_number INTEGER UNIQUE NOT NULL,
    source TEXT NOT NULL DEFAULT 'doj',
    source_url TEXT,
    total_files INTEGER DEFAULT 0,
    processed_files INTEGER DEFAULT 0,
    downloaded_at TIMESTAMP,
    processed_at TIMESTAMP,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'downloading', 'downloaded', 'processing', 'processed', 'error')),
    size_bytes INTEGER DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER REFERENCES datasets(id),
    file_hash TEXT UNIQUE NOT NULL,  -- SHA-256 for dedup
    original_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_type TEXT DEFAULT 'pdf' CHECK(file_type IN ('pdf', 'image', 'video', 'audio', 'text', 'other')),
    doc_type TEXT CHECK(doc_type IN ('email', 'deposition', 'flight_log', 'financial', 'letter', 'memo', 'court_filing', 'photo', 'video', 'unknown')),
    page_count INTEGER DEFAULT 0,
    size_bytes INTEGER DEFAULT 0,
    source TEXT NOT NULL,  -- 'doj', 'github', 'archive_org', etc.
    source_url TEXT,
    priority_score INTEGER DEFAULT 0,
    is_removed_from_source BOOLEAN DEFAULT 0,  -- CRITICAL FLAG
    removed_detected_at TIMESTAMP,
    ocr_completed BOOLEAN DEFAULT 0,
    analysis_completed BOOLEAN DEFAULT 0,
    user_reviewed BOOLEAN DEFAULT 0,
    user_flagged BOOLEAN DEFAULT 0,
    user_notes TEXT,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'downloaded', 'ocr_processing', 'ocr_complete', 'analyzing', 'analyzed', 'reviewed', 'junk', 'deleted')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_documents_dataset ON documents(dataset_id);
CREATE INDEX IF NOT EXISTS idx_documents_priority ON documents(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_documents_removed ON documents(is_removed_from_source);
CREATE INDEX IF NOT EXISTS idx_documents_doc_type ON documents(doc_type);

-- Full-text search on extracted text
CREATE VIRTUAL TABLE IF NOT EXISTS document_text_fts USING fts5(
    document_id,
    page_number,
    text_content,
    content='document_pages',
    content_rowid='id'
);

CREATE TABLE IF NOT EXISTS document_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    page_number INTEGER NOT NULL,
    text_content TEXT,
    has_redactions BOOLEAN DEFAULT 0,
    redaction_count INTEGER DEFAULT 0,
    ocr_confidence REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(document_id, page_number)
);

-- FTS sync triggers for document_text_fts
CREATE TRIGGER IF NOT EXISTS document_pages_ai AFTER INSERT ON document_pages BEGIN
    INSERT INTO document_text_fts(rowid, document_id, page_number, text_content)
    VALUES (new.id, new.document_id, new.page_number, new.text_content);
END;
CREATE TRIGGER IF NOT EXISTS document_pages_ad AFTER DELETE ON document_pages BEGIN
    INSERT INTO document_text_fts(document_text_fts, rowid, document_id, page_number, text_content)
    VALUES ('delete', old.id, old.document_id, old.page_number, old.text_content);
END;
CREATE TRIGGER IF NOT EXISTS document_pages_au AFTER UPDATE ON document_pages BEGIN
    INSERT INTO document_text_fts(document_text_fts, rowid, document_id, page_number, text_content)
    VALUES ('delete', old.id, old.document_id, old.page_number, old.text_content);
    INSERT INTO document_text_fts(rowid, document_id, page_number, text_content)
    VALUES (new.id, new.document_id, new.page_number, new.text_content);
END;

CREATE INDEX IF NOT EXISTS idx_doc_pages_doc ON document_pages(document_id);

-- ================================================
-- REDACTIONS
-- ================================================

CREATE TABLE IF NOT EXISTS redactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    page_number INTEGER NOT NULL,
    position_x REAL,
    position_y REAL,
    width REAL,
    height REAL,
    redaction_type TEXT DEFAULT 'text' CHECK(redaction_type IN ('text', 'image', 'full_page')),
    estimated_chars INTEGER,
    context_before TEXT,  -- 500 chars before
    context_after TEXT,   -- 500 chars after
    -- Forensic recovery
    recovery_method TEXT CHECK(recovery_method IN ('text_layer', 'pdf_layer', 'metadata', 'ocr_mismatch', 'copy_paste', 'font_analysis', 'cross_document', 'ai_inference', 'unrecovered')),
    recovered_text TEXT,
    recovery_confidence REAL DEFAULT 0.0,
    is_recovered BOOLEAN DEFAULT 0,
    -- AI inference candidates (JSON array)
    ai_candidates TEXT,  -- [{"name": "...", "confidence": 0.72, "reasoning": "..."}]
    status TEXT DEFAULT 'unresolved' CHECK(status IN ('unresolved', 'recovered', 'inferred', 'confirmed_by_user')),
    user_confirmed_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_redactions_doc ON redactions(document_id);
CREATE INDEX IF NOT EXISTS idx_redactions_status ON redactions(status);
CREATE INDEX IF NOT EXISTS idx_redactions_recovered ON redactions(is_recovered);

-- ================================================
-- IMAGE EVIDENCE
-- ================================================

CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER REFERENCES documents(id),
    file_path TEXT,
    file_hash TEXT UNIQUE,
    page_number INTEGER,
    original_redacted BOOLEAN DEFAULT 0,
    recovery_attempted BOOLEAN DEFAULT 0,
    recovery_method TEXT,
    recovery_successful BOOLEAN DEFAULT 0,
    -- User review gate
    user_reviewed BOOLEAN DEFAULT 0,
    user_decision TEXT CHECK(user_decision IN ('save', 'save_redacted', 'discard_victim', 'discard_no_value', 'flagged', NULL)),
    user_applied_redactions TEXT,  -- JSON describing user-drawn redaction boxes
    -- Metadata extracted even if image discarded
    exif_data TEXT,  -- JSON
    ai_description TEXT,
    detected_entities TEXT,  -- JSON array of entity IDs
    location_clues TEXT,
    estimated_date TEXT,
    minor_detected BOOLEAN DEFAULT 0,  -- Auto-quarantine flag
    quarantined BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_images_doc ON images(document_id);
CREATE INDEX IF NOT EXISTS idx_images_quarantined ON images(quarantined);
CREATE INDEX IF NOT EXISTS idx_images_reviewed ON images(user_reviewed);

-- ================================================
-- ENTITIES (Knowledge Graph Nodes)
-- ================================================

CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('person', 'organization', 'location', 'aircraft', 'financial', 'legal_case', 'contact_info', 'event', 'redacted_entity')),
    canonical_name TEXT,  -- Normalized/resolved name
    aliases TEXT,  -- JSON array of alternate names
    -- External links
    google_url TEXT,
    wikipedia_url TEXT,
    external_links TEXT,  -- JSON array of {label, url}
    -- Profile info
    role TEXT,  -- "Government Official", "Business Executive", etc.
    title TEXT,
    organization TEXT,
    description TEXT,
    -- Scoring
    implication_score REAL DEFAULT 0.0,
    user_score REAL,  -- User override
    user_score_locked BOOLEAN DEFAULT 0,
    evidence_count INTEGER DEFAULT 0,
    document_count INTEGER DEFAULT 0,
    -- Flags
    is_redacted_placeholder BOOLEAN DEFAULT 0,
    is_victim BOOLEAN DEFAULT 0,  -- Never publish
    is_minor BOOLEAN DEFAULT 0,   -- Extra protection
    -- Metadata
    first_seen_dataset INTEGER,
    first_seen_document_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_entities_canonical ON entities(canonical_name, entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_score ON entities(implication_score DESC);
CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);

-- Full-text search on entities
CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
    name,
    canonical_name,
    aliases,
    description,
    role,
    content='entities',
    content_rowid='id'
);

-- FTS sync triggers for entities_fts
CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
    INSERT INTO entities_fts(rowid, name, canonical_name, aliases, description, role)
    VALUES (new.id, new.name, new.canonical_name, new.aliases, new.description, new.role);
END;
CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, name, canonical_name, aliases, description, role)
    VALUES ('delete', old.id, old.name, old.canonical_name, old.aliases, old.description, old.role);
END;
CREATE TRIGGER IF NOT EXISTS entities_au AFTER UPDATE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, name, canonical_name, aliases, description, role)
    VALUES ('delete', old.id, old.name, old.canonical_name, old.aliases, old.description, old.role);
    INSERT INTO entities_fts(rowid, name, canonical_name, aliases, description, role)
    VALUES (new.id, new.name, new.canonical_name, new.aliases, new.description, new.role);
END;

-- ================================================
-- RELATIONSHIPS (Knowledge Graph Edges)
-- ================================================

CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,  -- 'flew_with', 'emailed', 'employed_by', etc.
    weight REAL DEFAULT 1.0,  -- Frequency/strength
    confidence REAL DEFAULT 1.0,
    is_inferred BOOLEAN DEFAULT 0,  -- vs directly observed
    inference_method TEXT,  -- 'co_occurrence', 'transitive', 'temporal', 'ai'
    -- Evidence
    evidence_document_ids TEXT,  -- JSON array of document IDs
    evidence_count INTEGER DEFAULT 1,
    first_observed_date TEXT,
    last_observed_date TEXT,
    -- Metadata
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_entity_id, target_entity_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(relationship_type);
CREATE INDEX IF NOT EXISTS idx_rel_weight ON relationships(weight DESC);

-- ================================================
-- ENTITY-DOCUMENT ASSOCIATIONS
-- ================================================

CREATE TABLE IF NOT EXISTS entity_document_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    page_number INTEGER DEFAULT 0 NOT NULL,
    context_snippet TEXT,  -- Text around where entity appears
    mention_type TEXT DEFAULT 'mentioned' NOT NULL,  -- 'author', 'recipient', 'mentioned', 'subject', 'witness'
    -- Evidence scoring
    damning_score INTEGER DEFAULT 0,
    user_damning_score INTEGER,
    user_score_locked BOOLEAN DEFAULT 0,
    score_reasoning TEXT,
    -- Classification
    evidence_type TEXT CHECK(evidence_type IN ('email', 'flight_log', 'financial', 'testimony', 'photo_video', 'court_filing', 'other')),
    ai_analysis TEXT,  -- JSON with full AI assessment
    -- Flags
    is_top_evidence BOOLEAN DEFAULT 0,
    user_pinned BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_id, document_id, page_number, mention_type)
);

CREATE INDEX IF NOT EXISTS idx_edl_entity ON entity_document_links(entity_id);
CREATE INDEX IF NOT EXISTS idx_edl_document ON entity_document_links(document_id);
CREATE INDEX IF NOT EXISTS idx_edl_score ON entity_document_links(damning_score DESC);
CREATE INDEX IF NOT EXISTS idx_edl_pinned ON entity_document_links(user_pinned);

-- ================================================
-- EMAIL CHAINS
-- ================================================

CREATE TABLE IF NOT EXISTS email_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_identifier TEXT UNIQUE NOT NULL,  -- Generated hash
    normalized_subject TEXT,
    participants TEXT,  -- JSON array of email addresses / names
    email_count INTEGER DEFAULT 0,
    expected_email_count INTEGER,  -- If gap detection estimates more
    has_gaps BOOLEAN DEFAULT 0,
    gap_details TEXT,  -- JSON describing where gaps are
    first_email_date TIMESTAMP,
    last_email_date TIMESTAMP,
    -- Analysis
    analysis_completed BOOLEAN DEFAULT 0,
    last_analyzed_at TIMESTAMP,
    ai_summary TEXT,
    priority_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chains_subject ON email_chains(normalized_subject);
CREATE INDEX IF NOT EXISTS idx_chains_priority ON email_chains(priority_score DESC);

CREATE TABLE IF NOT EXISTS email_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id INTEGER REFERENCES email_chains(id),
    document_id INTEGER NOT NULL REFERENCES documents(id),
    position_in_chain INTEGER,  -- Order within chain
    from_address TEXT,
    from_name TEXT,
    to_addresses TEXT,  -- JSON array
    cc_addresses TEXT,  -- JSON array
    subject TEXT,
    email_date TIMESTAMP,
    body_text TEXT,
    body_new_text TEXT,  -- Only the net-new content (after dedup)
    body_hash TEXT,  -- For dedup matching
    has_attachments BOOLEAN DEFAULT 0,
    attachment_info TEXT,  -- JSON
    is_quoted_content_stripped BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_emails_chain ON email_messages(chain_id);
CREATE INDEX IF NOT EXISTS idx_emails_doc ON email_messages(document_id);
CREATE INDEX IF NOT EXISTS idx_emails_date ON email_messages(email_date);

-- ================================================
-- FINDINGS BOARD
-- ================================================

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT CHECK(category IN ('financial', 'trafficking', 'political', 'cover_up', 'fraud', 'obstruction', 'other')),
    summary TEXT,
    detailed_notes TEXT,
    -- Linked evidence
    linked_entity_ids TEXT,  -- JSON array
    linked_document_ids TEXT,  -- JSON array
    linked_chain_ids TEXT,  -- JSON array
    linked_redaction_ids TEXT,  -- JSON array
    -- Status
    confidence_level TEXT DEFAULT 'unverified' CHECK(confidence_level IN ('unverified', 'likely', 'confirmed', 'published')),
    is_published BOOLEAN DEFAULT 0,
    published_at TIMESTAMP,
    published_to TEXT,  -- JSON: {"reddit": "url", "github": "url"}
    -- Tags
    tags TEXT,  -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence_level);

-- ================================================
-- DELETION QUEUE
-- ================================================

CREATE TABLE IF NOT EXISTS deletion_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    reason TEXT NOT NULL,
    ai_assessment TEXT,  -- Full description for user review
    ai_confidence REAL,
    models_agreed INTEGER DEFAULT 0,  -- How many AI models agreed it's junk
    user_decision TEXT CHECK(user_decision IN ('keep', 'delete', 'pending')),
    decided_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_deletion_pending ON deletion_queue(user_decision);

-- ================================================
-- AI ANALYSIS RESULTS
-- ================================================

CREATE TABLE IF NOT EXISTS ai_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    model_name TEXT NOT NULL CHECK(model_name IN ('codex', 'gemini', 'claude', 'kimi')),
    -- Analysis results (JSON)
    summary TEXT,
    entities_found TEXT,  -- JSON array
    redaction_inferences TEXT,  -- JSON array
    connections_found TEXT,  -- JSON array
    evidence_scores TEXT,  -- JSON: {"entity_id": score}
    cross_references TEXT,  -- JSON array
    flags TEXT,  -- JSON array
    career_roles TEXT,  -- JSON: {"entity_name": "role"}
    raw_response TEXT,  -- Full AI response for reference
    -- Consensus
    is_consensus_processed BOOLEAN DEFAULT 0,
    processing_time_seconds REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ai_doc ON ai_analyses(document_id);
CREATE INDEX IF NOT EXISTS idx_ai_model ON ai_analyses(model_name);

CREATE TABLE IF NOT EXISTS ai_consensus (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    consensus_summary TEXT,
    consensus_entities TEXT,  -- JSON
    consensus_connections TEXT,  -- JSON
    consensus_evidence_scores TEXT,  -- JSON
    consensus_redaction_inferences TEXT,  -- JSON
    agreement_level TEXT CHECK(agreement_level IN ('full', 'majority', 'split', 'single_source')),
    models_used INTEGER DEFAULT 0,
    disagreements TEXT,  -- JSON array of items needing review
    unique_insights TEXT,  -- JSON array of single-model catches
    needs_user_review BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_consensus_doc ON ai_consensus(document_id);
CREATE INDEX IF NOT EXISTS idx_consensus_review ON ai_consensus(needs_user_review);

-- ================================================
-- SECURITY & INTEGRITY
-- ================================================

CREATE TABLE IF NOT EXISTS file_integrity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT UNIQUE NOT NULL,
    sha256_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    last_verified_at TIMESTAMP NOT NULL,
    is_honeypot BOOLEAN DEFAULT 0,
    tamper_detected BOOLEAN DEFAULT 0,
    tamper_detected_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_integrity_tamper ON file_integrity(tamper_detected);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,  -- 'login', 'view_document', 'delete', 'export', 'backup', etc.
    details TEXT,
    user_initiated BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================================
-- DISK MANAGEMENT
-- ================================================

CREATE TABLE IF NOT EXISTS disk_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_bytes INTEGER NOT NULL,
    max_bytes INTEGER NOT NULL,  -- 500GB default
    compact_threshold REAL NOT NULL DEFAULT 0.78,
    measured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================================
-- VAULT FILE MAP (encrypted file tracking)
-- ================================================

CREATE TABLE IF NOT EXISTS vault_file_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    vault_uuid TEXT UNIQUE NOT NULL,
    encrypted_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vault_original ON vault_file_map(original_path);
CREATE INDEX IF NOT EXISTS idx_vault_uuid ON vault_file_map(vault_uuid);

-- ================================================
-- REMOVED FILES TRACKING (HIGHEST PRIORITY)
-- ================================================

CREATE TABLE IF NOT EXISTS removed_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url TEXT NOT NULL,
    original_source TEXT NOT NULL,  -- 'doj', etc.
    filename TEXT,
    first_seen_at TIMESTAMP,
    removed_detected_at TIMESTAMP NOT NULL,
    -- Recovery
    found_on_mirror BOOLEAN DEFAULT 0,
    mirror_source TEXT,
    mirror_url TEXT,
    recovered BOOLEAN DEFAULT 0,
    recovered_document_id INTEGER REFERENCES documents(id),
    -- Analysis priority
    priority TEXT DEFAULT 'CRITICAL',
    investigated BOOLEAN DEFAULT 0,
    investigation_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_removed_recovered ON removed_files(recovered);
CREATE INDEX IF NOT EXISTS idx_removed_priority ON removed_files(priority);
CREATE UNIQUE INDEX IF NOT EXISTS idx_removed_url ON removed_files(original_url);
