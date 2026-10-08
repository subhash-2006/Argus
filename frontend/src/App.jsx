import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  AlertTriangle,
  Activity,
  Terminal,
  Cpu,
  Database,
  Radio,
  Zap,
  Check,
  Copy,
  ChevronRight,
  ChevronDown,
  ExternalLink,
  Flame,
  Search,
  Server,
  Plus,
  Trash2,
  Clock,
  List,
  Layers
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';
const WS_URL = 'ws://127.0.0.1:8000/ws/alerts';

const getEventId = (item) => item.incident_id || item._id || `${item.timestamp}_${item.ip}_${item.endpoint}_${item.method}`;

const dedupeEvents = (list) => {
  const map = new Map();
  for (const item of list) {
    const key = getEventId(item);
    if (!map.has(key)) {
      map.set(key, item);
    }
  }
  return Array.from(map.values());
};

// Group repeated events (same IP + endpoint + threat within 60s) into incident rows
const groupEvents = (rawLogs) => {
  const groups = [];
  for (const item of rawLogs) {
    const itemTime = new Date(item.timestamp).getTime();
    const existingGroup = groups.find(g =>
      g.ip === item.ip &&
      g.endpoint === item.endpoint &&
      (g.threat_type || 'NORMAL') === (item.threat_type || 'NORMAL') &&
      Math.abs(itemTime - g.latestTimestamp) <= 60000
    );

    if (existingGroup) {
      existingGroup.events.push(item);
      existingGroup.count += 1;
      if (itemTime > existingGroup.latestTimestamp) {
        existingGroup.latestTimestamp = itemTime;
      }
      if (itemTime < existingGroup.earliestTimestamp) {
        existingGroup.earliestTimestamp = itemTime;
      }
      if (item.severity === 'CRITICAL' || existingGroup.severity === 'CRITICAL') {
        existingGroup.severity = 'CRITICAL';
      } else if (item.severity === 'HIGH' || existingGroup.severity === 'HIGH') {
        existingGroup.severity = 'HIGH';
      } else if (item.severity === 'MEDIUM' || existingGroup.severity === 'MEDIUM') {
        existingGroup.severity = 'MEDIUM';
      }
      if (item.is_anomaly) existingGroup.is_anomaly = true;
      if (item.gemini_triage && !existingGroup.gemini_triage) existingGroup.gemini_triage = item.gemini_triage;
    } else {
      groups.push({
        groupId: getEventId(item),
        ip: item.ip,
        endpoint: item.endpoint,
        method: item.method,
        status_code: item.status_code,
        threat_type: item.threat_type,
        severity: item.severity || 'NORMAL',
        is_anomaly: item.is_anomaly,
        shannon_entropy: item.shannon_entropy,
        ml_probability: item.ml_probability,
        mitre_id: item.mitre_id,
        rule_matched: item.rule_matched,
        gemini_triage: item.gemini_triage,
        latestTimestamp: itemTime,
        earliestTimestamp: itemTime,
        count: 1,
        events: [item]
      });
    }
  }
  return groups;
};

// Count-up animation hook for metric cards
function useAnimatedCount(targetValue, duration = 300) {
  const [displayValue, setDisplayValue] = useState(targetValue);
  const prevValueRef = useRef(targetValue);

  useEffect(() => {
    const numTarget = typeof targetValue === 'number' ? targetValue : parseFloat(targetValue) || 0;
    const numStart = typeof prevValueRef.current === 'number' ? prevValueRef.current : parseFloat(prevValueRef.current) || 0;
    
    if (numStart === numTarget) {
      setDisplayValue(targetValue);
      return;
    }

    let startTime = null;
    let animFrame;

    const animate = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = numStart + (numTarget - numStart) * progress;
      
      if (typeof targetValue === 'number' && Number.isInteger(targetValue)) {
        setDisplayValue(Math.round(current));
      } else {
        setDisplayValue(current.toFixed(2));
      }

      if (progress < 1) {
        animFrame = requestAnimationFrame(animate);
      } else {
        prevValueRef.current = targetValue;
        setDisplayValue(targetValue);
      }
    };

    animFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animFrame);
  }, [targetValue, duration]);

  return displayValue;
}

const getSeverityColor = (severity, isAnomaly) => {
  if (!isAnomaly) return '#10b981';
  switch (severity) {
    case 'CRITICAL': return '#ef4444';
    case 'HIGH': return '#f97316';
    case 'MEDIUM': return '#f59e0b';
    case 'LOW': return '#3b82f6';
    default: return '#10b981';
  }
};

const getClassificationLabel = (threatType, isAnomaly) => {
  if (!isAnomaly) return 'Normal Traffic';
  switch (threatType) {
    case 'HONEYTOKEN_ACCESS': return 'Honeytrap Access';
    case 'SQL_INJECTION': return 'SQL Injection';
    case 'XSS_ATTACK': return 'Cross-Site Scripting';
    case 'BRUTE_FORCE': return 'Brute Force';
    case 'PATH_TRAVERSAL': return 'Path Traversal';
    case 'ML_CLASSIFIED_ANOMALY': return 'ML: Suspicious';
    default: return threatType ? threatType.replace(/_/g, ' ') : 'Anomaly Detected';
  }
};

export default function App() {
  const [logs, setLogs] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [filter, setFilter] = useState('ALL'); // ALL, ANOMALIES, CRITICAL
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [inspectorTab, setInspectorTab] = useState('overview'); // 'overview' | 'timeline'
  const [expandedGroups, setExpandedGroups] = useState(new Set());
  const [wsConnected, setWsConnected] = useState(false);
  const [healthStatus, setHealthStatus] = useState({ status: 'checking', mongodb: 'unknown', gemini: 'unknown' });
  const [isSimulating, setIsSimulating] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  // Manual Log Ingest Form state
  const [showManualModal, setShowManualModal] = useState(false);
  const [manualForm, setManualForm] = useState({
    ip: '192.168.1.100',
    method: 'GET',
    endpoint: '/.env',
    status_code: 500,
    user_agent: 'sqlmap/1.6.4',
    raw_log: '192.168.1.100 - - GET /.env HTTP/1.1 500'
  });

  const wsRef = useRef(null);

  // Fetch initial system health & incidents
  const fetchHealthAndIncidents = async () => {
    try {
      const hRes = await fetch(`${API_BASE}/health`);
      if (hRes.ok) {
        const hData = await hRes.json();
        setHealthStatus(hData);
      }
    } catch (e) {
      setHealthStatus({ status: 'offline', mongodb: 'error', gemini: 'error' });
    }

    try {
      const iRes = await fetch(`${API_BASE}/api/incidents?limit=25`);
      if (iRes.ok) {
        const iData = await iRes.json();
        if (iData.incidents) {
          setIncidents(dedupeEvents(iData.incidents));
          setLogs((prev) => dedupeEvents([...iData.incidents, ...prev]).slice(0, 100));
        }
      }
    } catch (e) {
      console.error("Failed to fetch initial incidents:", e);
    }
  };

  // Connect WebSocket
  useEffect(() => {
    fetchHealthAndIncidents();

    const connectWS = () => {
      try {
        const ws = new WebSocket(WS_URL);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setLogs((prev) => dedupeEvents([data, ...prev]).slice(0, 100));
            if (data.is_anomaly) {
              setIncidents((prev) => dedupeEvents([data, ...prev]).slice(0, 50));
            }
          } catch (err) {
            console.error("WS Parse error:", err);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          setTimeout(connectWS, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (err) {
        setWsConnected(false);
      }
    };

    connectWS();

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Submit manual log payload
  const handleManualSubmit = async (e) => {
    e.preventDefault();
    setIsSimulating(true);
    try {
      const payload = {
        ...manualForm,
        status_code: parseInt(manualForm.status_code, 10)
      };
      const res = await fetch(`${API_BASE}/api/ingest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.analysis) {
        setLogs((prev) => dedupeEvents([data.analysis, ...prev]).slice(0, 100));
        if (data.analysis.is_anomaly) {
          setIncidents((prev) => dedupeEvents([data.analysis, ...prev]).slice(0, 50));
          setSelectedIncident(data.analysis);
        }
      }
      setShowManualModal(false);
    } catch (err) {
      console.error("Manual log ingest error:", err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Clear All Feed Data Handler with Confirmation
  const handleClearData = async () => {
    if (!window.confirm("Are you sure you want to clear all log telemetry data?")) {
      return;
    }
    setLogs([]);
    setIncidents([]);
    setSelectedIncident(null);
    try {
      await fetch(`${API_BASE}/api/incidents`, { method: 'DELETE' });
    } catch (err) {
      console.error("Clear data error:", err);
    }
  };

  // Trigger Red-Team Scenarios
  const triggerScenario = async (scenarioNumber) => {
    setIsSimulating(true);
    try {
      const res = await fetch(`${API_BASE}/api/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioNumber })
      });
      const data = await res.json();
      if (data.analyses && data.analyses.length > 0) {
        const anomaly = data.analyses.find(a => a.is_anomaly) || data.analyses[0];
        setSelectedIncident(anomaly);
      }
    } catch (err) {
      console.error("Scenario simulation error:", err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Toggle Group Expansion
  const toggleGroupExpand = (groupId) => {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  };

  // Metrics calculation
  const totalEvents = logs.length;
  const anomalyCount = logs.filter(l => l.is_anomaly).length;
  const criticalCount = logs.filter(l => l.severity === 'CRITICAL').length;
  const honeytokenCount = logs.filter(l => l.threat_type === 'HONEYTOKEN_ACCESS').length;
  const avgEntropyNum = logs.length > 0
    ? (logs.reduce((acc, l) => acc + (l.shannon_entropy || 0), 0) / logs.length)
    : 0;

  // Animated metric values
  const animTotalEvents = useAnimatedCount(totalEvents);
  const animAnomalyCount = useAnimatedCount(anomalyCount);
  const animCriticalCount = useAnimatedCount(criticalCount);
  const animHoneytokenCount = useAnimatedCount(honeytokenCount);
  const animAvgEntropy = useAnimatedCount(avgEntropyNum);

  // Group raw logs into incidents
  const groupedIncidentRows = groupEvents(logs);

  // Filtered grouped rows
  const filteredGroups = groupedIncidentRows.filter(g => {
    if (filter === 'ANOMALIES') return g.is_anomaly;
    if (filter === 'CRITICAL') return g.severity === 'CRITICAL';
    return true;
  }).filter(g => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (g.ip && g.ip.toLowerCase().includes(q)) ||
      (g.endpoint && g.endpoint.toLowerCase().includes(q)) ||
      (g.threat_type && g.threat_type.toLowerCase().includes(q))
    );
  });

  // Related events for selected incident timeline
  const selectedIncidentEvents = selectedIncident
    ? logs.filter(l => l.ip === selectedIncident.ip || (selectedIncident.endpoint && l.endpoint === selectedIncident.endpoint))
    : [];

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div style={{ padding: '20px 28px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* Top Professional Header */}
      <header className="glass-panel" style={{ padding: '14px 20px', marginBottom: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '34px', height: '34px', borderRadius: '6px', background: '#2563eb', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={20} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '0.2px' }}>Log Sentinel</h1>
              <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)', background: '#1e2430', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border-color)' }}>v2.4</span>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Web log threat detection</p>
          </div>
        </div>

        {/* Quiet Header Actions & Status Dots */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }} className="header-actions">
          
          {/* Status Dots */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', background: '#1e2430', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' }} title="WebSocket Real-Time Stream Status">
              <span className={`status-dot ${wsConnected ? 'online' : 'warning'}`}></span>
              <span>WebSocket</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' }} title="MongoDB Atlas Store">
              <span className={`status-dot ${healthStatus.mongodb === 'connected' ? 'online' : 'warning'}`}></span>
              <span>MongoDB</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' }} title="Gemini AI Triage Engine">
              <span className="status-dot online"></span>
              <span>Gemini AI</span>
            </div>
          </div>

          {/* Action Button Group */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            
            {/* Simulate Attack Group */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '3px 6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, paddingLeft: '4px', paddingRight: '4px' }}>Simulate:</span>
              
              <button
                className="btn-secondary"
                onClick={() => triggerScenario(1)}
                disabled={isSimulating}
                style={{ fontSize: '11px', padding: '4px 8px', border: 'none', background: 'transparent' }}
                aria-label="Simulate Credential Stuffing Scenario"
              >
                Credential Stuffing
              </button>

              <button
                className="btn-secondary"
                onClick={() => triggerScenario(2)}
                disabled={isSimulating}
                style={{ fontSize: '11px', padding: '4px 8px', border: 'none', background: 'transparent' }}
                aria-label="Simulate Obfuscated SQL Injection Scenario"
              >
                Obfuscated SQLi
              </button>

              <button
                className="btn-secondary"
                onClick={() => triggerScenario(3)}
                disabled={isSimulating}
                style={{ fontSize: '11px', padding: '4px 8px', border: 'none', background: 'transparent', color: '#f97316' }}
                aria-label="Simulate Multi-Stage APT Scenario"
              >
                Multi-Stage APT
              </button>
            </div>

            {/* Primary Action Button */}
            <button
              className="btn-primary"
              onClick={() => setShowManualModal(true)}
              aria-label="Open Manual Log Ingestion Dialog"
            >
              <Plus size={14} />
              Manual Log Ingest
            </button>

            {/* Quiet Clear Data Action Button */}
            <button
              className="btn-secondary"
              onClick={handleClearData}
              style={{ color: 'var(--text-muted)', borderColor: 'var(--border-color)' }}
              aria-label="Clear telemetry data"
            >
              <Trash2 size={13} />
              Clear
            </button>
          </div>
        </div>
      </header>

      {/* Metric Cards Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', marginBottom: '20px' }}>
        <div className="glass-panel" style={{ padding: '14px 18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500, marginBottom: '6px' }}>Total Ingested Events</div>
          <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>
            {animTotalEvents}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500, marginBottom: '6px' }}>Detected Anomalies</div>
          <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: '#f59e0b' }}>
            {animAnomalyCount}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500, marginBottom: '6px' }}>Critical Threats</div>
          <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: '#ef4444' }}>
            {animCriticalCount}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500, marginBottom: '6px' }}>Honeytrap Hits</div>
          <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: '#38bdf8' }}>
            {animHoneytokenCount}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500, marginBottom: '6px' }}>Avg Shannon Entropy</div>
          <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: '#10b981' }}>
            {typeof animAvgEntropy === 'number' ? animAvgEntropy.toFixed(2) : animAvgEntropy}
          </div>
        </div>
      </div>

      {/* Main Grid: Telemetry Table + Inspector Panel */}
      <div className="dashboard-grid" style={{ display: 'grid', gridTemplateColumns: selectedIncident ? '1fr 440px' : '1fr', gap: '20px' }}>
        
        {/* Left Column: Grouped Incident Table */}
        <div className="glass-panel" style={{ padding: '20px', minHeight: '560px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)' }}>
                Live Incidents & Events
              </h2>
            </div>

            {/* Filter Tabs & Search */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <div style={{ position: 'relative' }}>
                <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  placeholder="Search IP / Endpoint / Rule..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    background: '#1e2430',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    padding: '6px 10px 6px 30px',
                    color: 'var(--text-main)',
                    fontSize: '12px',
                    outline: 'none',
                    width: '200px'
                  }}
                  aria-label="Search filter for events"
                />
              </div>

              <div style={{ display: 'flex', background: '#1e2430', padding: '2px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <button
                  onClick={() => setFilter('ALL')}
                  style={{
                    background: filter === 'ALL' ? '#2563eb' : 'transparent',
                    color: filter === 'ALL' ? '#fff' : 'var(--text-muted)',
                    border: 'none',
                    padding: '5px 10px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 500,
                    cursor: 'pointer'
                  }}
                >
                  All Logs
                </button>

                <button
                  onClick={() => setFilter('ANOMALIES')}
                  style={{
                    background: filter === 'ANOMALIES' ? '#2563eb' : 'transparent',
                    color: filter === 'ANOMALIES' ? '#fff' : 'var(--text-muted)',
                    border: 'none',
                    padding: '5px 10px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 500,
                    cursor: 'pointer'
                  }}
                >
                  Anomalies ({anomalyCount})
                </button>

                <button
                  onClick={() => setFilter('CRITICAL')}
                  style={{
                    background: filter === 'CRITICAL' ? '#2563eb' : 'transparent',
                    color: filter === 'CRITICAL' ? '#fff' : 'var(--text-muted)',
                    border: 'none',
                    padding: '5px 10px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 500,
                    cursor: 'pointer'
                  }}
                >
                  Critical ({criticalCount})
                </button>
              </div>
            </div>
          </div>

          {/* Incident Table */}
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  <th style={{ padding: '10px 12px', width: '30px' }}></th>
                  <th style={{ padding: '10px 12px' }}>Timestamp</th>
                  <th style={{ padding: '10px 12px' }}>Client IP</th>
                  <th style={{ padding: '10px 12px' }}>Endpoint</th>
                  <th style={{ padding: '10px 12px' }}>Classification</th>
                  <th style={{ padding: '10px 12px' }}>Confidence</th>
                  <th style={{ padding: '10px 12px' }}>Severity</th>
                  <th style={{ padding: '10px 12px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  /* Zero Data Empty State */
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--text-muted)' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                        <Server size={32} color="var(--text-dim)" />
                        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)' }}>No events yet</span>
                        <p style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '360px', lineHeight: '1.4' }}>
                          Select a simulation scenario above or submit a manual log entry to start tracking real-time events.
                        </p>
                        <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                          <button className="btn-secondary" onClick={() => triggerScenario(1)} style={{ fontSize: '12px', padding: '6px 12px' }}>
                            Simulate Credential Stuffing
                          </button>
                          <button className="btn-primary" onClick={() => setShowManualModal(true)} style={{ fontSize: '12px', padding: '6px 12px' }}>
                            <Plus size={13} />
                            Ingest Manual Log
                          </button>
                        </div>
                      </div>
                    </td>
                  </tr>
                ) : filteredGroups.length === 0 ? (
                  /* Contextual Empty State for Filter */
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--text-muted)' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                        <Layers size={30} color="var(--text-dim)" />
                        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)' }}>
                          {filter === 'CRITICAL' ? 'No critical events' : 'No anomaly events'}
                        </span>
                        <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          No incidents match the active filter criteria.
                        </p>
                        <button className="btn-secondary" onClick={() => setFilter('ALL')} style={{ fontSize: '12px', marginTop: '6px' }}>
                          Show all logs
                        </button>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredGroups.map((group) => {
                    const isExpanded = expandedGroups.has(group.groupId);
                    const isSelected = selectedIncident && selectedIncident.ip === group.ip && selectedIncident.endpoint === group.endpoint;
                    const severityColor = getSeverityColor(group.severity, group.is_anomaly);
                    const confidencePercent = Math.round((group.ml_probability ?? (group.is_anomaly ? 0.95 : 0.05)) * 100);

                    return (
                      <React.Fragment key={group.groupId}>
                        {/* Parent Group Row */}
                        <tr
                          className="table-row"
                          style={{
                            background: isSelected ? '#1e2430' : 'transparent',
                            cursor: 'pointer'
                          }}
                          onClick={() => setSelectedIncident(group.events[0])}
                        >
                          <td style={{ padding: '10px 12px' }}>
                            {group.count > 1 ? (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleGroupExpand(group.groupId);
                                }}
                                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
                                aria-label="Toggle grouped events expansion"
                              >
                                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                              </button>
                            ) : null}
                          </td>
                          <td className="mono" style={{ padding: '10px 12px', color: 'var(--text-muted)', fontSize: '12px' }}>
                            {new Date(group.latestTimestamp).toLocaleTimeString()}
                          </td>
                          <td className="mono" style={{ padding: '10px 12px', color: '#38bdf8', fontWeight: 600 }}>
                            {group.ip}
                          </td>
                          <td className="mono" style={{ padding: '10px 12px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={group.endpoint}>
                            <span style={{ color: group.method === 'GET' ? '#10b981' : '#f97316', marginRight: '6px', fontWeight: 600 }}>
                              {group.method}
                            </span>
                            {group.endpoint}
                          </td>
                          <td style={{ padding: '10px 12px', fontWeight: 500, color: 'var(--text-main)', fontSize: '12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span>{getClassificationLabel(group.threat_type, group.is_anomaly)}</span>
                              {group.count > 1 && (
                                <span className="mono" style={{ fontSize: '10px', background: '#232938', color: 'var(--text-muted)', padding: '1px 5px', borderRadius: '3px' }}>
                                  {group.count} events
                                </span>
                              )}
                            </div>
                          </td>
                          <td style={{ padding: '10px 12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <div style={{ width: '40px', height: '4px', borderRadius: '2px', background: '#232938', overflow: 'hidden' }}>
                                <div style={{ width: `${confidencePercent}%`, height: '100%', background: severityColor }}></div>
                              </div>
                              <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{confidencePercent}%</span>
                            </div>
                          </td>
                          <td style={{ padding: '10px 12px', fontSize: '12px', fontWeight: 600, color: severityColor }}>
                            ● {group.is_anomaly ? (group.severity || 'MEDIUM') : 'NORMAL'}
                          </td>
                          <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedIncident(group.events[0]);
                              }}
                              className="btn-secondary"
                              style={{ padding: '3px 8px', fontSize: '11px' }}
                              aria-label={`Inspect incident ${group.ip}`}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>

                        {/* Expanded Child Rows */}
                        {isExpanded && group.events.map((childEvent, cIdx) => (
                          <tr
                            key={`${group.groupId}_child_${cIdx}`}
                            style={{ background: '#11151c', borderBottom: '1px solid #1c2230' }}
                            onClick={() => setSelectedIncident(childEvent)}
                          >
                            <td></td>
                            <td className="mono" style={{ padding: '8px 12px', color: 'var(--text-dim)', fontSize: '11px', paddingLeft: '24px' }}>
                              {new Date(childEvent.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="mono" style={{ padding: '8px 12px', color: 'var(--text-muted)', fontSize: '12px' }}>
                              └ {childEvent.ip}
                            </td>
                            <td className="mono" style={{ padding: '8px 12px', fontSize: '12px', color: 'var(--text-muted)' }} title={childEvent.endpoint}>
                              {childEvent.method} {childEvent.endpoint}
                            </td>
                            <td style={{ padding: '8px 12px', fontSize: '11px', color: 'var(--text-muted)' }}>
                              Status: {childEvent.status_code}
                            </td>
                            <td className="mono" style={{ padding: '8px 12px', fontSize: '11px', color: 'var(--text-muted)' }}>
                              H: {childEvent.shannon_entropy ? childEvent.shannon_entropy.toFixed(2) : '0.00'}
                            </td>
                            <td style={{ padding: '8px 12px', fontSize: '11px', color: severityColor }}>
                              {childEvent.rule_matched || 'Anomaly Event'}
                            </td>
                            <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                              <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>Child Event #{cIdx + 1}</span>
                            </td>
                          </tr>
                        ))}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Inspector Panel (Overview / Timeline Tabs) */}
        {selectedIncident && (
          <div className="glass-panel" style={{ padding: '20px', height: 'fit-content' }}>
            
            {/* Header & Tabs */}
            <div style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-main)' }}>Incident Inspector</h3>
                <button
                  onClick={() => setSelectedIncident(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '16px' }}
                  aria-label="Close Inspector Panel"
                >
                  ✕
                </button>
              </div>

              {/* Inspector Tabs */}
              <div style={{ display: 'flex', gap: '8px', background: '#1e2430', padding: '2px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <button
                  onClick={() => setInspectorTab('overview')}
                  style={{
                    flex: 1,
                    background: inspectorTab === 'overview' ? '#2563eb' : 'transparent',
                    color: inspectorTab === 'overview' ? '#fff' : 'var(--text-muted)',
                    border: 'none',
                    padding: '5px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Overview
                </button>
                <button
                  onClick={() => setInspectorTab('timeline')}
                  style={{
                    flex: 1,
                    background: inspectorTab === 'timeline' ? '#2563eb' : 'transparent',
                    color: inspectorTab === 'timeline' ? '#fff' : 'var(--text-muted)',
                    border: 'none',
                    padding: '5px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '4px'
                  }}
                >
                  <Clock size={12} />
                  Timeline ({selectedIncidentEvents.length})
                </button>
              </div>
            </div>

            {/* Target Summary Brief */}
            <div style={{ background: '#11151c', padding: '12px', borderRadius: '6px', marginBottom: '14px', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: getSeverityColor(selectedIncident.severity, selectedIncident.is_anomaly) }}>
                  ● {selectedIncident.severity || 'MEDIUM'} SEVERITY
                </span>
                
                {/* MITRE External Link Badge */}
                <a
                  href={`https://attack.mitre.org/techniques/${(selectedIncident.mitre_id || 'T1190').replace(/\./g, '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ fontSize: '11px', color: '#38bdf8', textDecoration: 'none', background: 'rgba(56, 189, 248, 0.1)', padding: '2px 6px', borderRadius: '4px', border: '1px solid rgba(56, 189, 248, 0.3)', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                >
                  MITRE: {selectedIncident.mitre_id || 'T1190'}
                  <ExternalLink size={10} />
                </a>
              </div>

              <div className="mono" style={{ fontSize: '12px', color: '#38bdf8', wordBreak: 'break-all', fontWeight: 600 }}>
                {selectedIncident.ip} &rarr; {selectedIncident.endpoint}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Rule: {selectedIncident.rule_matched || 'Rule Engine Detection'}
              </div>
            </div>

            {/* TAB CONTENT 1: OVERVIEW */}
            {inspectorTab === 'overview' && (
              <div>
                {selectedIncident.gemini_triage ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    {/* Small Rule-based summary Tag if fallback */}
                    {selectedIncident.gemini_triage.plain_summary && selectedIncident.gemini_triage.plain_summary.toLowerCase().includes('fallback') && (
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: '#1e2430', color: '#f59e0b', padding: '3px 8px', borderRadius: '4px', fontSize: '11px', width: 'fit-content', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                        <span>Rule-based summary</span>
                      </div>
                    )}

                    <div>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
                        Threat Summary
                      </div>
                      <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.5', background: '#11151c', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                        {selectedIncident.gemini_triage.plain_english_summary || selectedIncident.gemini_triage.plain_summary || 'Anomalous traffic vector detected targeting web backend.'}
                      </p>
                    </div>

                    <div>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
                        Technical Details
                      </div>
                      <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                        {selectedIncident.gemini_triage.technical_details || 'High shannon entropy or signature matching known attack patterns.'}
                      </p>
                    </div>

                    {selectedIncident.gemini_triage.remediation_snippet && (
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontSize: '11px', fontWeight: 600, color: '#10b981' }}>Recommended Remediation</span>
                          <button
                            onClick={() => copyToClipboard(selectedIncident.gemini_triage.remediation_snippet)}
                            style={{ background: 'transparent', border: 'none', color: copiedSnippet ? '#10b981' : 'var(--text-muted)', cursor: 'pointer', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '3px' }}
                            aria-label="Copy remediation snippet"
                          >
                            {copiedSnippet ? <Check size={11} /> : <Copy size={11} />}
                            {copiedSnippet ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                        <div className="mono" style={{ background: '#090b0e', padding: '8px 10px', borderRadius: '4px', color: '#10b981', fontSize: '11px', border: '1px solid var(--border-color)', wordBreak: 'break-all' }}>
                          {selectedIncident.gemini_triage.remediation_snippet}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div className="skeleton-box" style={{ height: '14px', width: '40%' }}></div>
                    <div className="skeleton-box" style={{ height: '50px', width: '100%' }}></div>
                    <div className="skeleton-box" style={{ height: '40px', width: '100%' }}></div>
                  </div>
                )}
              </div>
            )}

            {/* TAB CONTENT 2: TIMELINE (ATTACK STORY) */}
            {inspectorTab === 'timeline' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Chronological event progression for IP <span className="mono" style={{ color: '#38bdf8' }}>{selectedIncident.ip}</span>:
                </div>

                <div style={{ position: 'relative', paddingLeft: '16px', borderLeft: '2px solid #232938' }}>
                  {selectedIncidentEvents.map((evt, idx) => (
                    <div key={`tl_${idx}`} style={{ marginBottom: '14px', position: 'relative' }}>
                      <div style={{ position: 'absolute', left: '-21px', top: '2px', width: '8px', height: '8px', borderRadius: '50%', background: getSeverityColor(evt.severity, evt.is_anomaly) }}></div>
                      
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                        <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </span>
                        <span style={{ fontSize: '10px', background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', padding: '1px 5px', borderRadius: '3px' }}>
                          {evt.mitre_id || 'T1190'}
                        </span>
                      </div>

                      <div className="mono" style={{ fontSize: '12px', color: 'var(--text-main)', fontWeight: 600 }}>
                        {evt.method} {evt.endpoint}
                      </div>

                      <div style={{ fontSize: '11px', color: getSeverityColor(evt.severity, evt.is_anomaly), marginTop: '2px' }}>
                        {getClassificationLabel(evt.threat_type, evt.is_anomaly)} (Status {evt.status_code})
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

      </div>

      {/* Manual Log Ingest Modal */}
      {showManualModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 17, 21, 0.85)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 999
        }}>
          <div className="glass-panel" style={{
            width: '100%',
            maxWidth: '500px',
            padding: '24px',
            background: '#151922'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)' }}>Manual Log Ingestion</h3>
              <button
                onClick={() => setShowManualModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: '18px', cursor: 'pointer' }}
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleManualSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Client IP</label>
                  <input
                    type="text"
                    required
                    value={manualForm.ip}
                    onChange={(e) => setManualForm({ ...manualForm, ip: e.target.value })}
                    style={{ width: '100%', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '6px 10px', color: '#38bdf8', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>HTTP Method</label>
                  <select
                    value={manualForm.method}
                    onChange={(e) => setManualForm({ ...manualForm, method: e.target.value })}
                    style={{ width: '100%', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-main)', fontSize: '12px' }}
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Target Endpoint / Query Payload</label>
                <input
                  type="text"
                  required
                  value={manualForm.endpoint}
                  onChange={(e) => setManualForm({ ...manualForm, endpoint: e.target.value })}
                  placeholder="e.g. /.env or /products?id=1 UNION SELECT..."
                  style={{ width: '100%', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '10px' }}>
                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>HTTP Status</label>
                  <input
                    type="number"
                    required
                    value={manualForm.status_code}
                    onChange={(e) => setManualForm({ ...manualForm, status_code: e.target.value })}
                    style={{ width: '100%', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>User Agent</label>
                  <input
                    type="text"
                    value={manualForm.user_agent}
                    onChange={(e) => setManualForm({ ...manualForm, user_agent: e.target.value })}
                    style={{ width: '100%', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-main)', fontSize: '12px' }}
                  />
                </div>
              </div>

              <div>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Raw Log Telemetry</label>
                <textarea
                  rows={2}
                  value={manualForm.raw_log}
                  onChange={(e) => setManualForm({ ...manualForm, raw_log: e.target.value })}
                  style={{ width: '100%', background: '#1e2430', border: '1px solid var(--border-color)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '11px', resize: 'vertical' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowManualModal(false)}
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="btn-primary"
                >
                  Ingest & Analyze
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


