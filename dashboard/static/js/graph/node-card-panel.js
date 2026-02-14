/**
 * NodeCardPanel - Right-side Analysis Card Panel
 * EpsteinAnalyzer Graph V2
 * 
 * Displays detailed entity analysis when a node is clicked.
 * Includes key findings, evidence, relationships, and aircraft analysis.
 */

class NodeCardPanel {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.container = document.getElementById(containerId);
    
    if (!this.container) {
      throw new Error(`Container #${containerId} not found`);
    }
    
    this.currentEntityId = null;
    this.cache = new Map();  // LRU cache
    this.cacheSize = options.cacheSize || 50;
    
    this.onViewDocument = options.onViewDocument || (() => {});
    this.onViewEntity = options.onViewEntity || (() => {});
    this.onViewFlights = options.onViewFlights || (() => {});
    
    this._init();
  }
  
  _init() {
    // Initial empty state
    this._renderEmpty();
  }
  
  _renderEmpty() {
    this.container.innerHTML = `
      <div class="node-card-empty">
        <div class="empty-icon">🔍</div>
        <p>Click on a node to view detailed analysis</p>
      </div>
    `;
  }
  
  _renderLoading() {
    this.container.innerHTML = `
      <div class="node-card-loading">
        <div class="loading-spinner"></div>
        <p>Loading analysis...</p>
      </div>
    `;
  }
  
  async loadEntity(entityId) {
    if (this.currentEntityId === entityId) return;
    
    this._renderLoading();
    
    // Check cache
    if (this.cache.has(entityId)) {
      this._render(this.cache.get(entityId));
      return;
    }
    
    try {
      const response = await fetch(`/api/entity/${entityId}/card`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      // Cache result
      this._addToCache(entityId, data);
      
      this._render(data);
    } catch (err) {
      console.error('Failed to load entity card:', err);
      this._renderError('Failed to load entity analysis');
    }
  }
  
  _addToCache(entityId, data) {
    // LRU eviction
    if (this.cache.size >= this.cacheSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(entityId, data);
  }
  
  _render(data) {
    this.currentEntityId = data.entity.id;
    
    const entity = data.entity;
    const aircraft = data.aircraft_analysis;
    const findings = data.key_findings || [];
    const evidence = data.top_evidence || [];
    const relationships = data.relationships || {};
    const confidence = data.confidence || {};
    
    // Build HTML
    this.container.innerHTML = `
      <div class="entity-card">
        ${this._renderHeader(entity, confidence)}
        ${aircraft?.has_aircraft_evidence ? this._renderAircraftSection(aircraft) : ''}
        ${findings.length ? this._renderFindings(findings) : ''}
        ${evidence.length ? this._renderEvidence(evidence) : ''}
        ${relationships.top_connections?.length ? this._renderRelationships(relationships) : ''}
        ${this._renderExternalLinks(data.external_links, entity)}
      </div>
    `;
    
    // Bind events
    this._bindEvents();
  }
  
  _renderHeader(entity, confidence) {
    const scoreColor = entity.implication_score >= 70 ? '#f85149' : 
                       entity.implication_score >= 50 ? '#f4a261' : '#58a6ff';
    
    return `
      <header class="entity-card-header">
        <div class="entity-title-row">
          <h2 class="entity-name">${this._escape(entity.name)}</h2>
          <span class="entity-type-badge ${entity.type}">${entity.type}</span>
        </div>
        ${entity.role ? `<div class="entity-role">${this._escape(entity.role)}</div>` : ''}
        ${entity.organization ? `<div class="entity-org">${this._escape(entity.organization)}</div>` : ''}
        
        <div class="score-section">
          <div class="implication-score" style="border-color: ${scoreColor}">
            <span class="score-value" style="color: ${scoreColor}">${entity.implication_score?.toFixed(1) || 0}</span>
            <span class="score-label">Implication Score</span>
          </div>
          <div class="confidence-badge ${confidence.overall > 0.8 ? 'high' : 'medium'}">
            <span class="confidence-value">${((confidence.overall || 0) * 100).toFixed(0)}%</span>
            <span class="confidence-label">confidence</span>
          </div>
        </div>
        
        <div class="entity-stats">
          <div class="stat">
            <span class="stat-value">${entity.evidence_count || 0}</span>
            <span class="stat-label">Evidence</span>
          </div>
          <div class="stat">
            <span class="stat-value">${entity.document_count || 0}</span>
            <span class="stat-label">Documents</span>
          </div>
          ${entity.aliases?.length ? `
            <div class="stat aliases">
              <span class="stat-value">${entity.aliases.length}</span>
              <span class="stat-label">Aliases</span>
            </div>
          ` : ''}
        </div>
        
        ${entity.description ? `
          <div class="entity-description">
            ${this._escape(entity.description)}
          </div>
        ` : ''}
      </header>
    `;
  }
  
  _renderAircraftSection(aircraft) {
    const isHighCorrelation = aircraft.known_epstein_aircraft_flights > 0;
    const alertClass = isHighCorrelation ? 'alert-critical' : 'alert-info';
    
    return `
      <section class="card-section aircraft-section priority-section">
        <h3 class="section-title">
          <span class="section-icon">✈️</span>
          Aircraft Travel Analysis
        </h3>
        
        <div class="alert ${alertClass}">
          <div class="alert-main">
            <strong>${aircraft.known_epstein_aircraft_flights}</strong> of 
            <strong>${aircraft.total_flights}</strong> flights on known Epstein aircraft
          </div>
          ${aircraft.average_correlation_score > 0.5 ? `
            <div class="alert-sub">
              Average correlation score: ${(aircraft.average_correlation_score * 100).toFixed(0)}%
            </div>
          ` : ''}
        </div>
        
        <div class="aircraft-details">
          ${aircraft.tail_numbers?.length ? `
            <div class="detail-row">
              <span class="detail-label">Tail Numbers:</span>
              <span class="detail-value tail-numbers">
                ${aircraft.tail_numbers.map(t => `<code>${t}</code>`).join(' ')}
              </span>
            </div>
          ` : ''}
          
          ${aircraft.route_pattern ? `
            <div class="detail-row">
              <span class="detail-label">Route Pattern:</span>
              <span class="detail-value">${aircraft.route_pattern}</span>
            </div>
          ` : ''}
          
          <div class="detail-row">
            <span class="detail-label">Date Correlation:</span>
            <span class="correlation-badge ${aircraft.date_overlap_confidence}">
              ${aircraft.date_overlap_confidence}
            </span>
          </div>
        </div>
        
        <button class="btn btn-sm btn-primary" data-action="view-flights" data-entity-id="${this.currentEntityId}">
          View Flight Records
        </button>
      </section>
    `;
  }
  
  _renderFindings(findings) {
    const severityIcons = {
      high: '🔴',
      medium: '🟡',
      low: '🟢',
    };
    
    const severityClasses = {
      high: 'severity-high',
      medium: 'severity-medium',
      low: 'severity-low',
    };
    
    return `
      <section class="card-section findings-section">
        <h3 class="section-title">
          <span class="section-icon">🔍</span>
          Key Findings
        </h3>
        
        <div class="findings-list">
          ${findings.map(f => `
            <div class="finding-item ${severityClasses[f.severity] || ''}" data-finding-type="${f.type}">
              <div class="finding-header">
                <span class="finding-icon">${severityIcons[f.severity] || '⚪'}</span>
                <span class="finding-type">${this._formatFindingType(f.type)}</span>
                <span class="confidence-pill">${(f.confidence * 100).toFixed(0)}%</span>
              </div>
              <p class="finding-summary">${this._escape(f.summary)}</p>
            </div>
          `).join('')}
        </div>
      </section>
    `;
  }
  
  _renderEvidence(evidence) {
    return `
      <section class="card-section evidence-section">
        <h3 class="section-title">
          <span class="section-icon">📄</span>
          Top Evidence (${evidence.length})
        </h3>
        
        <div class="evidence-list">
          ${evidence.map((e, i) => `
            <div class="evidence-item ${e.is_aircraft_related ? 'aircraft-evidence' : ''}" 
                 data-evidence-index="${i}">
              <div class="evidence-header">
                <a href="/document/${e.document_id}?page=${e.page || 1}" 
                   target="_blank" 
                   class="evidence-doc-link"
                   data-document-id="${e.document_id}"
                   data-page="${e.page || 1}">
                  ${this._escape(e.original_filename || 'Unknown')}
                  ${e.page ? `<span class="page-ref">p.${e.page}</span>` : ''}
                </a>
                <span class="damning-score ${this._scoreClass(e.damning_score)}">
                  ${e.damning_score}
                </span>
              </div>
              
              ${e.aircraft_correlation ? `
                <div class="aircraft-correlation-badge">
                  ✈️ ${e.aircraft_correlation.tail_number || 'Aircraft'}
                  ${e.aircraft_correlation.is_known_epstein_aircraft ? 
                    '<span class="known-aircraft-tag">Known Epstein</span>' : ''}
                </div>
              ` : ''}
              
              ${e.context_snippet ? `
                <p class="context-snippet">
                  "${this._escape(e.context_snippet.substring(0, 200))}"
                </p>
              ` : ''}
              
              <div class="evidence-meta">
                ${e.evidence_type ? `<span class="evidence-type">${e.evidence_type}</span>` : ''}
                ${e.mention_type ? `<span class="mention-type">${e.mention_type}</span>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      </section>
    `;
  }
  
  _renderRelationships(relationships) {
    const connections = relationships.top_connections || [];
    
    return `
      <section class="card-section relationships-section">
        <h3 class="section-title">
          <span class="section-icon">🔗</span>
          Connections (${relationships.direct_count})
        </h3>
        
        <div class="relationships-by-type">
          ${Object.entries(relationships.by_type || {}).map(([type, count]) => `
            <span class="rel-type-badge">
              ${this._formatRelType(type)}: ${count}
            </span>
          `).join('')}
        </div>
        
        <div class="connections-list">
          ${connections.slice(0, 10).map(r => `
            <div class="connection-item" data-entity-id="${r.entity_id}" data-rel-type="${r.rel_type}">
              <div class="connection-info">
                <span class="connection-name">${this._escape(r.name)}</span>
                <span class="connection-type">${this._formatRelType(r.rel_type)}</span>
              </div>
              <div class="connection-strength" title="Strength: ${r.strength.toFixed(1)}">
                ${this._strengthBars(r.strength)}
              </div>
            </div>
          `).join('')}
        </div>
      </section>
    `;
  }
  
  _renderExternalLinks(links, entity) {
    return `
      <section class="card-section external-links">
        <h3 class="section-title">External Research</h3>
        <div class="link-buttons">
          <a href="${links.google}" target="_blank" class="btn btn-sm">
            🔍 Google
          </a>
          ${links.wikipedia ? `
            <a href="${links.wikipedia}" target="_blank" class="btn btn-sm">
              📖 Wikipedia
            </a>
          ` : ''}
          <a href="/entity/${entity.id}" target="_blank" class="btn btn-sm btn-primary">
            Full Profile →
          </a>
        </div>
      </section>
    `;
  }
  
  _bindEvents() {
    // View flights button
    const flightsBtn = this.container.querySelector('[data-action="view-flights"]');
    if (flightsBtn) {
      flightsBtn.addEventListener('click', () => {
        const entityId = flightsBtn.dataset.entityId;
        this.onViewFlights(entityId);
      });
    }
    
    // Document links
    this.container.querySelectorAll('.evidence-doc-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const docId = link.dataset.documentId;
        const page = link.dataset.page;
        this.onViewDocument(docId, page);
      });
    });
    
    // Connection items
    this.container.querySelectorAll('.connection-item').forEach(item => {
      item.addEventListener('click', () => {
        const entityId = item.dataset.entityId;
        this.onViewEntity(entityId);
      });
    });
  }
  
  _renderError(message) {
    this.container.innerHTML = `
      <div class="node-card-error">
        <div class="error-icon">⚠️</div>
        <p>${message}</p>
        <button class="btn btn-sm" onclick="this.closest('.node-card-panel').dispatchEvent(new Event('retry'))">
          Retry
        </button>
      </div>
    `;
  }
  
  // Utility methods
  
  _escape(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
  
  _formatFindingType(type) {
    const formats = {
      aircraft_travel: 'Aircraft Travel',
      high_implication: 'High Implication',
      multi_source: 'Multi-Source Evidence',
      financial_link: 'Financial Link',
      communication: 'Communication',
    };
    return formats[type] || type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }
  
  _formatRelType(type) {
    const formats = {
      flew_with: 'Flew With',
      emailed: 'Emailed',
      financially_linked: 'Financial',
      co_occurs_with: 'Co-occurs',
      employed_by: 'Employment',
      associated_with: 'Associated',
    };
    return formats[type] || type.replace(/_/g, ' ');
  }
  
  _scoreClass(score) {
    if (score >= 70) return 'score-high';
    if (score >= 50) return 'score-medium';
    return 'score-low';
  }
  
  _strengthBars(strength) {
    const bars = Math.min(5, Math.max(1, Math.round(strength)));
    return '█'.repeat(bars) + '░'.repeat(5 - bars);
  }
  
  // Public API
  
  clear() {
    this.currentEntityId = null;
    this._renderEmpty();
  }
  
  getCurrentEntityId() {
    return this.currentEntityId;
  }
  
  invalidateCache(entityId = null) {
    if (entityId) {
      this.cache.delete(entityId);
    } else {
      this.cache.clear();
    }
  }
}

// CSS styles to be added to graph-v2.css
const CARD_PANEL_STYLES = `
.node-card-panel {
  background: #161b22;
  border-left: 1px solid #30363d;
  height: 100%;
  overflow-y: auto;
  font-size: 13px;
}

.entity-card {
  padding: 16px;
}

.entity-card-header {
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid #30363d;
}

.entity-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.entity-name {
  font-size: 18px;
  font-weight: 600;
  color: #e6edf3;
  margin: 0;
}

.entity-type-badge {
  font-size: 10px;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 500;
}

.entity-type-badge.person { background: rgba(230, 57, 70, 0.2); color: #e63946; }
.entity-type-badge.organization { background: rgba(69, 123, 157, 0.2); color: #457b9d; }
.entity-type-badge.location { background: rgba(42, 157, 143, 0.2); color: #2a9d8f; }
.entity-type-badge.aircraft { background: rgba(233, 196, 106, 0.2); color: #e9c46a; }

.score-section {
  display: flex;
  align-items: center;
  gap: 16px;
  margin: 16px 0;
}

.implication-score {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 8px 16px;
  border: 2px solid;
  border-radius: 8px;
}

.score-value {
  font-size: 24px;
  font-weight: 700;
}

.score-label {
  font-size: 10px;
  color: #8b949e;
  text-transform: uppercase;
}

.confidence-badge {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.confidence-badge.high { color: #3fb950; }
.confidence-badge.medium { color: #d29922; }

.entity-stats {
  display: flex;
  gap: 20px;
  margin-top: 12px;
}

.stat {
  display: flex;
  flex-direction: column;
}

.stat-value {
  font-size: 16px;
  font-weight: 600;
  color: #e6edf3;
}

.stat-label {
  font-size: 10px;
  color: #8b949e;
  text-transform: uppercase;
}

.card-section {
  margin-bottom: 20px;
}

.section-title {
  font-size: 13px;
  font-weight: 600;
  color: #e6edf3;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.section-icon {
  font-size: 14px;
}

.alert {
  padding: 12px;
  border-radius: 6px;
  margin-bottom: 12px;
}

.alert-critical {
  background: rgba(248, 81, 73, 0.15);
  border: 1px solid rgba(248, 81, 73, 0.3);
  color: #f85149;
}

.alert-info {
  background: rgba(88, 166, 255, 0.15);
  border: 1px solid rgba(88, 166, 255, 0.3);
  color: #58a6ff;
}

.finding-item {
  padding: 10px;
  border-radius: 6px;
  margin-bottom: 8px;
  background: #1c2333;
}

.finding-item.severity-high { border-left: 3px solid #f85149; }
.finding-item.severity-medium { border-left: 3px solid #d29922; }
.finding-item.severity-low { border-left: 3px solid #3fb950; }

.evidence-item {
  padding: 10px;
  border-radius: 6px;
  margin-bottom: 8px;
  background: #1c2333;
}

.evidence-item.aircraft-evidence {
  border-left: 3px solid #f97316;
}

.damning-score {
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}

.damning-score.score-high { background: rgba(248, 81, 73, 0.2); color: #f85149; }
.damning-score.score-medium { background: rgba(210, 153, 34, 0.2); color: #d29922; }
.damning-score.score-low { background: rgba(88, 166, 255, 0.2); color: #58a6ff; }

.aircraft-correlation-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: #f97316;
  margin-top: 6px;
}

.known-aircraft-tag {
  background: rgba(249, 115, 22, 0.2);
  padding: 1px 6px;
  border-radius: 3px;
}

.connection-item {
  padding: 8px;
  border-radius: 4px;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.connection-item:hover {
  background: #21283b;
}

.node-card-empty, .node-card-loading, .node-card-error {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #8b949e;
  text-align: center;
  padding: 40px 20px;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}
`;

// Export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { NodeCardPanel, CARD_PANEL_STYLES };
}
