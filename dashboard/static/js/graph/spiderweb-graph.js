/**
 * SpiderwebGraph - Enhanced D3.js Force-Directed Graph
 * EpsteinAnalyzer Graph V2
 * 
 * Features:
 * - Optimized rendering for 1000+ nodes
 * - Level-of-detail based on zoom/importance
 * - Aircraft correlation highlighting
 * - Interactive node selection
 * - Fast filtering
 */

class SpiderwebGraph {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.container = d3.select(`#${containerId}`);
    
    // Dimensions
    this.width = options.width || this.container.node()?.clientWidth || 1200;
    this.height = options.height || 800;
    
    // Performance settings
    this.maxNodesRender = options.maxNodes || 1000;
    this.levelOfDetail = options.levelOfDetail !== false;
    this.animationDuration = options.animationDuration || 300;
    
    // State
    this.nodes = [];
    this.links = [];
    this.selectedNodeId = null;
    this.hoveredNodeId = null;
    this.transform = d3.zoomIdentity;
    this.filterState = options.initialFilters || {};
    
    // Callbacks
    this.onNodeSelect = options.onNodeSelect || (() => {});
    this.onNodeHover = options.onNodeHover || (() => {});
    this.onFilterChange = options.onFilterChange || (() => {});
    
    // Color scheme
    this.colors = {
      person: '#e63946',
      organization: '#457b9d',
      location: '#2a9d8f',
      aircraft: '#e9c46a',
      financial: '#f4a261',
      legal_case: '#264653',
      contact_info: '#a8dadc',
      event: '#6a4c93',
      redacted_entity: '#6c757d',
      default: '#999999',
      highlight: '#fbbf24',
      aircraftStroke: '#f97316',
    };
    
    this._init();
  }
  
  _init() {
    // Clear container
    this.container.selectAll('*').remove();
    
    // Create SVG
    this.svg = this.container.append('svg')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('viewBox', [0, 0, this.width, this.height])
      .style('background', '#0d1117');
    
    // Define arrow markers for directed edges
    this.svg.append('defs').selectAll('marker')
      .data(['end'])
      .enter().append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#30363d');
    
    // Create layers for z-ordering
    this.layers = {
      links: this.svg.append('g').attr('class', 'links'),
      nodes: this.svg.append('g').attr('class', 'nodes'),
      labels: this.svg.append('g').attr('class', 'labels'),
      highlights: this.svg.append('g').attr('class', 'highlights'),
      aircraftBadges: this.svg.append('g').attr('class', 'aircraft-badges'),
    };
    
    // Zoom behavior
    this.zoom = d3.zoom()
      .scaleExtent([0.05, 8])
      .on('zoom', (e) => this._onZoom(e));
    
    this.svg.call(this.zoom);
    
    // Initialize force simulation
    this._initSimulation();
    
    // Handle window resize
    window.addEventListener('resize', () => this._onResize());
  }
  
  _initSimulation() {
    this.simulation = d3.forceSimulation()
      .force('link', d3.forceLink()
        .id(d => d.id)
        .distance(d => Math.max(50, 150 - (d.weight || 1) * 10))
      )
      .force('charge', d3.forceManyBody()
        .strength(d => -30 - (d.connections || 0) * 5)
        .distanceMax(300)
      )
      .force('center', d3.forceCenter(this.width / 2, this.height / 2))
      .force('collision', d3.forceCollide()
        .radius(d => (d.radius || 5) + 3)
        .iterations(2)
      )
      .force('x', d3.forceX(this.width / 2).strength(0.03))
      .force('y', d3.forceY(this.height / 2).strength(0.03));
    
    // Faster decay for quicker settling
    this.simulation.alphaDecay(0.02);
    this.simulation.velocityDecay(0.3);
  }
  
  async loadData(url = '/api/graph/data') {
    this._showLoading();
    
    try {
      // Build query params from filter state
      const params = new URLSearchParams();
      if (this.filterState.minScore) params.set('min_score', this.filterState.minScore);
      if (this.filterState.entityTypes?.length) params.set('entity_types', this.filterState.entityTypes.join(','));
      if (this.filterState.aircraftOnly) params.set('aircraft_only', 'true');
      if (this.filterState.search) params.set('search', this.filterState.search);
      if (this.filterState.maxNodes) params.set('max_nodes', this.filterState.maxNodes);
      
      const fullUrl = `${url}?${params.toString()}`;
      const response = await fetch(fullUrl);
      const data = await response.json();
      
      this._processAndRender(data);
    } catch (err) {
      console.error('Failed to load graph data:', err);
      this._showError('Failed to load graph data');
    }
  }
  
  setData(data) {
    this._processAndRender(data);
  }
  
  _processAndRender(data) {
    this._hideLoading();
    
    // Process nodes with visual properties
    this.nodes = data.nodes.map(n => ({
      ...n,
      radius: this._computeRadius(n),
      color: this.colors[n.type] || this.colors.default,
      lod: this._computeLOD(n),
    }));
    
    this.links = data.links.map(l => ({
      ...l,
      strokeWidth: Math.max(0.5, Math.min(4, (l.weight || 1) * 0.8)),
      strokeOpacity: l.inferred ? 0.3 : 0.6,
    }));
    
    this.metadata = data.metadata || {};
    
    this._render();
    this._emit('dataLoaded', { nodeCount: this.nodes.length, linkCount: this.links.length });
  }
  
  _computeRadius(node) {
    // Base radius on implication score with diminishing returns
    const base = 4;
    const score = node.score || 0;
    const scoreBonus = Math.sqrt(score) * 1.5;
    const connectionBonus = Math.log2((node.connections || 0) + 1) * 2;
    const centerBonus = node.is_center ? 8 : 0;
    
    return Math.min(28, base + scoreBonus + connectionBonus + centerBonus);
  }
  
  _computeLOD(node) {
    // Level of detail based on importance
    if (node.score >= 80 || node.is_center) return 'high';
    if (node.score >= 50) return 'medium';
    if (node.score >= 30) return 'low';
    return 'minimal';
  }
  
  _render() {
    // Stop any running simulation
    this.simulation.stop();
    
    // Render links
    this._renderLinks();
    
    // Render nodes
    this._renderNodes();
    
    // Render labels (based on current zoom)
    this._renderLabels();
    
    // Update simulation
    this.simulation.nodes(this.nodes);
    this.simulation.force('link').links(this.links);
    
    // Start simulation with a kick
    this.simulation.alpha(1).restart();
    
    // Tick handler
    this.simulation.on('tick', () => this._onTick());
    
    // Apply current zoom level for LOD
    this._updateLOD();
  }
  
  _renderLinks() {
    const linkSel = this.layers.links
      .selectAll('line')
      .data(this.links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);
    
    linkSel.exit()
      .transition().duration(this.animationDuration)
      .style('opacity', 0)
      .remove();
    
    const linkEnter = linkSel.enter()
      .append('line')
      .attr('stroke', d => {
        if (d.flags?.includes('aircraft_correlated')) return this.colors.aircraftStroke;
        return '#30363d';
      })
      .attr('stroke-width', d => d.strokeWidth)
      .attr('stroke-opacity', d => d.strokeOpacity)
      .style('opacity', 0);
    
    linkEnter.transition().duration(this.animationDuration).style('opacity', 1);
    
    this.linkElements = linkEnter.merge(linkSel);
  }
  
  _renderNodes() {
    const nodeSel = this.layers.nodes
      .selectAll('circle')
      .data(this.nodes, d => d.id);
    
    nodeSel.exit()
      .transition().duration(this.animationDuration)
      .attr('r', 0)
      .remove();
    
    const nodeEnter = nodeSel.enter()
      .append('circle')
      .attr('r', 0)
      .attr('fill', d => d.color)
      .attr('stroke', d => this._nodeStroke(d))
      .attr('stroke-width', d => {
        if (d.flags?.includes('aircraft_connected')) return 3;
        return d.is_center ? 3 : 1;
      })
      .style('cursor', 'pointer')
      .on('click', (e, d) => this._onNodeClick(d))
      .on('mouseover', (e, d) => this._onNodeHover(d))
      .on('mouseout', () => this._onNodeHoverOut());
    
    // Add center node glow effect
    nodeEnter.filter(d => d.is_center)
      .style('filter', 'drop-shadow(0 0 8px rgba(251, 191, 36, 0.6))');
    
    // Add aircraft badge for aircraft-connected nodes
    this._renderAircraftBadges(nodeEnter);
    
    nodeEnter.transition().duration(this.animationDuration)
      .attr('r', d => d.radius);
    
    this.nodeElements = nodeEnter.merge(nodeSel)
      .attr('fill', d => d.color)
      .attr('stroke', d => this._nodeStroke(d))
      .attr('stroke-width', d => {
        if (this.selectedNodeId === d.id) return 4;
        if (d.flags?.includes('aircraft_connected')) return 3;
        return d.is_center ? 3 : 1;
      });
  }
  
  _renderAircraftBadges(nodeSelection) {
    // Add airplane icon badge for aircraft-connected nodes
    const aircraftNodes = nodeSelection.filter(d => 
      d.flags?.includes('aircraft_connected') || d.type === 'aircraft'
    );
    
    // This will be populated after node positions are set
    this.aircraftBadgeData = aircraftNodes.data();
  }
  
  _renderAircraftBadgeIcons() {
    // Render ✈️ badges above aircraft-connected nodes
    const badges = this.layers.aircraftBadges
      .selectAll('text')
      .data(this.aircraftBadgeData || [], d => d.id);
    
    badges.exit().remove();
    
    badges.enter()
      .append('text')
      .text('✈')
      .attr('font-size', '12px')
      .attr('text-anchor', 'middle')
      .attr('fill', this.colors.aircraftStroke)
      .style('pointer-events', 'none')
      .style('text-shadow', '0 0 3px rgba(0,0,0,0.8)')
      .merge(badges)
      .attr('x', d => d.x)
      .attr('y', d => d.y - d.radius - 8);
  }
  
  _renderLabels() {
    const labelSel = this.layers.labels
      .selectAll('text')
      .data(this.nodes, d => d.id);
    
    labelSel.exit().remove();
    
    const labelEnter = labelSel.enter()
      .append('text')
      .text(d => d.name)
      .attr('font-size', d => d.is_center ? '14px' : '11px')
      .attr('font-weight', d => d.is_center ? 'bold' : 'normal')
      .attr('fill', '#e6edf3')
      .attr('text-anchor', 'middle')
      .style('pointer-events', 'none')
      .style('text-shadow', '0 1px 3px rgba(0,0,0,0.8)')
      .style('opacity', 0);
    
    this.labelElements = labelEnter.merge(labelSel);
    
    // Apply LOD based on current zoom
    this._updateLOD();
  }
  
  _updateLOD() {
    const zoom = this.transform.k;
    
    // Show/hide labels based on zoom and importance
    this.labelElements?.style('display', d => {
      if (d.is_center) return 'block';
      if (zoom < 0.3) return 'none';
      if (zoom < 0.6 && d.lod !== 'high') return 'none';
      if (zoom < 1.0 && d.lod === 'minimal') return 'none';
      return 'block';
    });
    
    // Adjust label position
    this.labelElements?.attr('y', d => d.y + d.radius + (d.is_center ? 18 : 14));
  }
  
  _nodeStroke(node) {
    if (this.selectedNodeId === node.id) return this.colors.highlight;
    if (node.flags?.includes('aircraft_connected')) return this.colors.aircraftStroke;
    if (node.is_center) return this.colors.highlight;
    return '#21283b';
  }
  
  _onTick() {
    // Update link positions
    this.linkElements
      ?.attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    
    // Update node positions
    this.nodeElements
      ?.attr('cx', d => d.x)
      .attr('cy', d => d.y);
    
    // Update label positions
    this.labelElements
      ?.attr('x', d => d.x)
      .attr('y', d => d.y + d.radius + (d.is_center ? 18 : 14));
    
    // Update aircraft badges
    this._renderAircraftBadgeIcons();
  }
  
  _onZoom(event) {
    this.transform = event.transform;
    
    // Apply transform to all layers
    Object.values(this.layers).forEach(layer => {
      layer.attr('transform', this.transform);
    });
    
    // Update LOD
    this._updateLOD();
  }
  
  _onNodeClick(node) {
    // Update selection
    this.selectedNodeId = node.id;
    
    // Update visual state
    this._updateSelection();
    
    // Highlight connections
    this._highlightConnections(node);
    
    // Emit event
    this.onNodeSelect(node);
    this._emit('nodeSelect', node);
  }
  
  _onNodeHover(node) {
    this.hoveredNodeId = node.id;
    this.onNodeHover(node);
    
    // Optional: Show tooltip
    this._showTooltip(node);
  }
  
  _onNodeHoverOut() {
    this.hoveredNodeId = null;
    this._hideTooltip();
  }
  
  _updateSelection() {
    this.nodeElements
      ?.attr('stroke', d => this._nodeStroke(d))
      .attr('stroke-width', d => {
        if (this.selectedNodeId === d.id) return 4;
        if (d.flags?.includes('aircraft_connected')) return 3;
        return d.is_center ? 3 : 1;
      });
  }
  
  _highlightConnections(centerNode) {
    // Find connected nodes
    const connectedIds = new Set();
    this.links.forEach(l => {
      if (l.source.id === centerNode.id) connectedIds.add(l.target.id);
      if (l.target.id === centerNode.id) connectedIds.add(l.source.id);
    });
    
    // Dim non-connected nodes
    this.nodeElements?.style('opacity', d => {
      if (d.id === centerNode.id) return 1;
      if (connectedIds.has(d.id)) return 1;
      return 0.2;
    });
    
    // Dim non-connected links
    this.linkElements?.style('opacity', d => {
      if (d.source.id === centerNode.id || d.target.id === centerNode.id) return 0.8;
      return 0.05;
    });
    
    // Restore after delay
    if (this.highlightTimeout) clearTimeout(this.highlightTimeout);
    this.highlightTimeout = setTimeout(() => {
      this.nodeElements?.style('opacity', 1);
      this.linkElements?.style('opacity', d => d.inferred ? 0.3 : 0.6);
    }, 3000);
  }
  
  _showTooltip(node) {
    // Simple tooltip implementation
    let tooltip = d3.select('body').select('.graph-tooltip');
    if (tooltip.empty()) {
      tooltip = d3.select('body').append('div')
        .attr('class', 'graph-tooltip')
        .style('position', 'absolute')
        .style('background', 'rgba(13, 17, 23, 0.95)')
        .style('border', '1px solid #30363d')
        .style('border-radius', '6px')
        .style('padding', '8px 12px')
        .style('color', '#e6edf3')
        .style('font-size', '12px')
        .style('pointer-events', 'none')
        .style('z-index', '1000')
        .style('box-shadow', '0 4px 12px rgba(0,0,0,0.4)');
    }
    
    const flags = [];
    if (node.is_center) flags.push('⭐ Center');
    if (node.flags?.includes('aircraft_connected')) flags.push('✈️ Aircraft');
    
    tooltip.html(`
      <div style="font-weight: bold; margin-bottom: 4px;">${node.name}</div>
      <div style="color: #8b949e; text-transform: capitalize;">${node.type}</div>
      <div style="margin-top: 4px;">Score: <span style="color: #f4a261;">${node.score?.toFixed(1) || 0}</span></div>
      <div>Connections: ${node.connections || 0}</div>
      ${flags.length ? `<div style="margin-top: 4px; color: #58a6ff;">${flags.join(' | ')}</div>` : ''}
    `);
    
    tooltip.style('display', 'block');
    
    // Position tooltip
    const event = d3.event || window.event;
    if (event) {
      tooltip
        .style('left', (event.pageX + 10) + 'px')
        .style('top', (event.pageY - 10) + 'px');
    }
  }
  
  _hideTooltip() {
    d3.select('body').select('.graph-tooltip').style('display', 'none');
  }
  
  _onResize() {
    const newWidth = this.container.node()?.clientWidth || this.width;
    const newHeight = this.container.node()?.clientHeight || this.height;
    
    if (newWidth !== this.width || newHeight !== this.height) {
      this.width = newWidth;
      this.height = newHeight;
      
      this.svg
        .attr('viewBox', [0, 0, this.width, this.height]);
      
      // Update center force
      this.simulation.force('center', d3.forceCenter(this.width / 2, this.height / 2));
      this.simulation.alpha(0.3).restart();
    }
  }
  
  _showLoading() {
    // Add loading indicator
    this.container.append('div')
      .attr('class', 'graph-loading')
      .style('position', 'absolute')
      .style('top', '50%')
      .style('left', '50%')
      .style('transform', 'translate(-50%, -50%)')
      .style('color', '#58a6ff')
      .style('font-size', '14px')
      .text('Loading graph...');
  }
  
  _hideLoading() {
    this.container.select('.graph-loading').remove();
  }
  
  _showError(message) {
    this.container.append('div')
      .attr('class', 'graph-error')
      .style('position', 'absolute')
      .style('top', '50%')
      .style('left', '50%')
      .style('transform', 'translate(-50%, -50%)')
      .style('color', '#f85149')
      .style('font-size', '14px')
      .text(message);
  }
  
  _emit(eventName, data) {
    const event = new CustomEvent(`graph:${eventName}`, { detail: data });
    window.dispatchEvent(event);
  }
  
  // Public API methods
  
  setFilter(filterKey, value) {
    this.filterState[filterKey] = value;
  }
  
  applyFilters(filters) {
    this.filterState = { ...this.filterState, ...filters };
    this.loadData();
  }
  
  resetZoom() {
    this.svg.transition().duration(750).call(
      this.zoom.transform,
      d3.zoomIdentity
    );
  }
  
  focusNode(nodeId) {
    const node = this.nodes.find(n => n.id === nodeId);
    if (!node) return;
    
    const scale = 2;
    const x = -node.x * scale + this.width / 2;
    const y = -node.y * scale + this.height / 2;
    
    this.svg.transition().duration(750).call(
      this.zoom.transform,
      d3.zoomIdentity.translate(x, y).scale(scale)
    );
    
    this._onNodeClick(node);
  }
  
  getSelectedNode() {
    return this.nodes.find(n => n.id === this.selectedNodeId);
  }
  
  exportImage() {
    const svgNode = this.svg.node();
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svgNode);
    
    const canvas = document.createElement('canvas');
    canvas.width = this.width;
    canvas.height = this.height;
    const ctx = canvas.getContext('2d');
    
    const img = new Image();
    img.onload = () => {
      ctx.fillStyle = '#0d1117';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);
      
      const link = document.createElement('a');
      link.download = 'epstein-graph.png';
      link.href = canvas.toDataURL('image/png');
      link.click();
    };
    img.src = 'data:image/svg+xml;base64,' + btoa(svgString);
  }
  
  destroy() {
    this.simulation.stop();
    this.container.selectAll('*').remove();
    window.removeEventListener('resize', () => this._onResize());
  }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SpiderwebGraph };
}
