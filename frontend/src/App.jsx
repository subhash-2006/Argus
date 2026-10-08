import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  AlertTriangle,
  Activity,
  Terminal,
  Cpu,
  Database,
  Radio,
  RefreshCw,
  Zap,
  Filter,
  CheckCircle,
  Copy,
  Check,
  ChevronRight,
  ExternalLink,
  Flame,
  Search,
  Server,
  Plus
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';
const WS_URL = 'ws://127.0.0.1:8000/ws/alerts';

export default function App() {
  const [logs, setLogs] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [filter, setFilter] = useState('ALL'); // ALL, ANOMALIES, CRITICAL
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
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
          setIncidents(iData.incidents);
          setLogs((prev) => {
            // merge without duplicates
            const combined = [...iData.incidents, ...prev];
            const unique = Array.from(new Set(combined.map(a => a.timestamp + a.ip + a.endpoint)))
              .map(id => combined.find(a => a.timestamp + a.ip + a.endpoint === id));
            return unique.slice(0, 100);
          });
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
            setLogs((prev) => [data, ...prev].slice(0, 100));
            if (data.is_anomaly) {
              setIncidents((prev) => [data, ...prev].slice(0, 50));
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
        setLogs((prev) => [data.analysis, ...prev].slice(0, 100));
        if (data.analysis.is_anomaly) {
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

  // Metrics calculation
  const totalEvents = logs.length;
  const anomalyCount = logs.filter(l => l.is_anomaly).length;
  const criticalCount = logs.filter(l => l.severity === 'CRITICAL').length;
  const honeytokenCount = logs.filter(l => l.threat_type === 'HONEYTOKEN_ACCESS').length;
  const sqliCount = logs.filter(l => l.threat_type === 'SQL_INJECTION').length;
  const avgEntropy = logs.length > 0
    ? (logs.reduce((acc, l) => acc + (l.shannon_entropy || 0), 0) / logs.length).toFixed(2)
    : '0.00';

  // Filtered logs
  const filteredLogs = logs.filter(l => {
    if (filter === 'ANOMALIES') return l.is_anomaly;
    if (filter === 'CRITICAL') return l.severity === 'CRITICAL';
    return true;
  }).filter(l => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (l.ip && l.ip.toLowerCase().includes(q)) ||
      (l.endpoint && l.endpoint.toLowerCase().includes(q)) ||
      (l.threat_type && l.threat_type.toLowerCase().includes(q))
    );
  });

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-info';
    }
  };

  return (
    <div style={{ padding: '24px 32px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* Top Navbar */}
      <header className="glass-panel" style={{ padding: '16px 24px', marginBottom: '24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'linear-gradient(135deg, #00f0ff 0%, #7000ff 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 16px rgba(0, 240, 255, 0.4)' }}>
            <Shield size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '22px', fontWeight: 800, letterSpacing: '0.5px' }}>LOG SENTINEL</h1>
              <span className="badge badge-critical" style={{ fontSize: '10px' }}>LIVE SOC</span>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Real-Time Anomaly Detection & Gemini AI Triage Engine</p>
          </div>
        </div>

        {/* Live System Status Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', background: 'rgba(255,255,255,0.03)', padding: '6px 14px', borderRadius: '20px', border: '1px solid var(--border-color)' }}>
            <span className={`pulse-dot ${wsConnected ? 'online' : 'warning'}`}></span>
            <span style={{ color: 'var(--text-muted)' }}>WebSocket:</span>
            <span style={{ fontWeight: 600, color: wsConnected ? '#05ffa1' : '#ff9f1c' }}>
              {wsConnected ? 'Live Telemetry' : 'Reconnecting...'}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', background: 'rgba(255,255,255,0.03)', padding: '6px 14px', borderRadius: '20px', border: '1px solid var(--border-color)' }}>
            <Database size={15} color={healthStatus.mongodb === 'connected' ? '#05ffa1' : '#ff9f1c'} />
            <span style={{ color: 'var(--text-muted)' }}>Mongo DB:</span>
            <span style={{ fontWeight: 600, color: healthStatus.mongodb === 'connected' ? '#05ffa1' : '#ff9f1c' }}>
              {healthStatus.mongodb}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', background: 'rgba(255,255,255,0.03)', padding: '6px 14px', borderRadius: '20px', border: '1px solid var(--border-color)' }}>
            <Cpu size={15} color="#00f0ff" />
            <span style={{ color: 'var(--text-muted)' }}>Gemini AI:</span>
            <span style={{ fontWeight: 600, color: '#00f0ff' }}>
              {healthStatus.gemini === 'configured' ? 'gemini-2.5-flash Ready' : healthStatus.gemini}
            </span>
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button className="btn-primary" onClick={() => setShowManualModal(true)} style={{ fontSize: '12px', padding: '8px 14px', background: 'linear-gradient(135deg, #05ffa1 0%, #00b4d8 100%)', color: '#000' }}>
              <Plus size={15} color="#000" />
              Manual Log Ingest
            </button>

            <button className="btn-secondary" onClick={() => triggerScenario(1)} disabled={isSimulating} style={{ fontSize: '12px', padding: '8px 12px' }}>
              <Flame size={14} color="#ff9f1c" />
              Scenario 1: Credential Stuffing
            </button>

            <button className="btn-secondary" onClick={() => triggerScenario(2)} disabled={isSimulating} style={{ fontSize: '12px', padding: '8px 12px' }}>
              <Terminal size={14} color="#00f0ff" />
              Scenario 2: Obfuscated SQLi
            </button>

            <button className="btn-primary" onClick={() => triggerScenario(3)} disabled={isSimulating} style={{ fontSize: '12px', padding: '8px 14px' }}>
              <Zap size={14} />
              Scenario 3: Multi-Stage APT
            </button>
          </div>
        </div>
      </header>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px', marginBottom: '24px' }}>
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 500 }}>Total Ingested Events</span>
            <Activity size={18} color="#00f0ff" />
          </div>
          <div className="mono glow-text" style={{ fontSize: '28px', fontWeight: 800, color: '#00f0ff' }}>
            {totalEvents}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>Streamed over WebSocket / HTTP</p>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 500 }}>Detected Anomalies</span>
            <AlertTriangle size={18} color="#ff9f1c" />
          </div>
          <div className="mono" style={{ fontSize: '28px', fontWeight: 800, color: '#ff9f1c' }}>
            {anomalyCount}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>Rule Engine & Shannon Heuristics</p>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 500 }}>Critical Threats</span>
            <Flame size={18} color="#ff2a6d" />
          </div>
          <div className="mono" style={{ fontSize: '28px', fontWeight: 800, color: '#ff2a6d' }}>
            {criticalCount}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>Require AI Triage & Defense</p>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 500 }}>Honeytrap Hits</span>
            <Terminal size={18} color="#7000ff" />
          </div>
          <div className="mono" style={{ fontSize: '28px', fontWeight: 800, color: '#b566ff' }}>
            {honeytokenCount}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>Decoy `/.env` & secret traps</p>
        </div>

        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 500 }}>Avg Shannon Entropy</span>
            <Radio size={18} color="#05ffa1" />
          </div>
          <div className="mono" style={{ fontSize: '28px', fontWeight: 800, color: '#05ffa1' }}>
            {avgEntropy}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>Threshold anomaly limit: &gt; 4.5</p>
        </div>
      </div>

      {/* Main Grid: Telemetry Table + Gemini Inspector Sidebar */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedIncident ? '1fr 440px' : '1fr', gap: '24px' }}>
        
        {/* Left Column: Live Telemetry Feed */}
        <div className="glass-panel" style={{ padding: '24px', minHeight: '600px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '14px' }}>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Server size={20} color="#00f0ff" />
                Live Telemetry & Anomaly Stream
              </h2>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Real-time HTTP logs & attack vectors</p>
            </div>

            {/* Filters & Search */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <div style={{ position: 'relative' }}>
                <Search size={15} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  type="text"
                  placeholder="Filter IP / Endpoint / Rule..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '8px 12px 8px 34px',
                    color: 'var(--text-main)',
                    fontSize: '13px',
                    outline: 'none',
                    width: '210px'
                  }}
                />
              </div>

              <div style={{ display: 'flex', background: 'rgba(255,255,255,0.04)', padding: '3px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                <button
                  onClick={() => setFilter('ALL')}
                  style={{
                    background: filter === 'ALL' ? 'rgba(0,240,255,0.2)' : 'transparent',
                    color: filter === 'ALL' ? '#00f0ff' : 'var(--text-muted)',
                    border: 'none',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  All Logs
                </button>

                <button
                  onClick={() => setFilter('ANOMALIES')}
                  style={{
                    background: filter === 'ANOMALIES' ? 'rgba(255,159,28,0.2)' : 'transparent',
                    color: filter === 'ANOMALIES' ? '#ff9f1c' : 'var(--text-muted)',
                    border: 'none',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Anomalies ({anomalyCount})
                </button>

                <button
                  onClick={() => setFilter('CRITICAL')}
                  style={{
                    background: filter === 'CRITICAL' ? 'rgba(255,42,109,0.2)' : 'transparent',
                    color: filter === 'CRITICAL' ? '#ff2a6d' : 'var(--text-muted)',
                    border: 'none',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Critical ({criticalCount})
                </button>
              </div>
            </div>
          </div>

          {/* Telemetry Table */}
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  <th style={{ padding: '12px' }}>Timestamp</th>
                  <th style={{ padding: '12px' }}>Client IP</th>
                  <th style={{ padding: '12px' }}>Endpoint</th>
                  <th style={{ padding: '12px' }}>HTTP Status</th>
                  <th style={{ padding: '12px' }}>Classification</th>
                  <th style={{ padding: '12px' }}>Entropy</th>
                  <th style={{ padding: '12px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
                      No events matching filter. Click "Trigger Exploit" or "Simulate Normal" above to generate traffic.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log, index) => {
                    const isSelected = selectedIncident && selectedIncident.timestamp === log.timestamp && selectedIncident.ip === log.ip;
                    return (
                      <tr
                        key={index}
                        className="new-row"
                        style={{
                          borderBottom: '1px solid rgba(255,255,255,0.04)',
                          background: isSelected ? 'rgba(0, 240, 255, 0.08)' : log.is_anomaly ? 'rgba(255, 42, 109, 0.04)' : 'transparent',
                          transition: 'background 0.15s ease'
                        }}
                      >
                        <td className="mono" style={{ padding: '12px', color: 'var(--text-dim)', fontSize: '12px' }}>
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="mono" style={{ padding: '12px', color: '#00f0ff', fontWeight: 600 }}>
                          {log.ip}
                        </td>
                        <td className="mono" style={{ padding: '12px', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.endpoint}>
                          <span style={{ color: log.method === 'GET' ? '#05ffa1' : '#ff9f1c', marginRight: '6px', fontWeight: 700 }}>
                            {log.method}
                          </span>
                          {log.endpoint}
                        </td>
                        <td style={{ padding: '12px' }}>
                          <span className="mono" style={{ color: log.status_code >= 500 ? '#ff2a6d' : log.status_code >= 400 ? '#ff9f1c' : '#05ffa1', fontWeight: 700 }}>
                            {log.status_code}
                          </span>
                        </td>
                        <td style={{ padding: '12px' }}>
                          {log.is_anomaly ? (
                            <span className={`badge ${getSeverityBadgeClass(log.severity)}`}>
                              {log.threat_type || 'ANOMALY'}
                            </span>
                          ) : (
                            <span className="badge badge-low" style={{ opacity: 0.7 }}>
                              NORMAL
                            </span>
                          )}
                        </td>
                        <td className="mono" style={{ padding: '12px', color: log.shannon_entropy > 4.5 ? '#ff2a6d' : 'var(--text-muted)' }}>
                          {log.shannon_entropy ? log.shannon_entropy.toFixed(2) : '0.00'}
                        </td>
                        <td style={{ padding: '12px', textAlign: 'right' }}>
                          {log.is_anomaly ? (
                            <button
                              onClick={() => setSelectedIncident(log)}
                              className="btn-secondary"
                              style={{ padding: '4px 10px', fontSize: '11px', gap: '4px', background: isSelected ? 'var(--primary)' : 'rgba(255,255,255,0.06)', color: isSelected ? '#000' : 'var(--text-main)' }}
                            >
                              <Cpu size={12} />
                              AI Triage
                              <ChevronRight size={12} />
                            </button>
                          ) : (
                            <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Passed</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Gemini AI Incident Inspector */}
        {selectedIncident && (
          <div className="glass-panel" style={{ padding: '24px', height: 'fit-content', border: '1px solid rgba(0, 240, 255, 0.4)', boxShadow: '0 0 30px rgba(0, 240, 255, 0.15)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid var(--border-color)', paddingBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Cpu size={22} color="#00f0ff" />
                <h3 style={{ fontSize: '16px', fontWeight: 700, letterSpacing: '0.5px' }}>GEMINI AI INCIDENT INSPECTOR</h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}
              >
                ✕
              </button>
            </div>

            {/* Target Brief */}
            <div style={{ background: 'rgba(255,255,255,0.03)', padding: '14px', borderRadius: '8px', marginBottom: '16px', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span className={`badge ${getSeverityBadgeClass(selectedIncident.severity)}`}>
                  {selectedIncident.severity} SEVERITY
                </span>
                <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  MITRE: {selectedIncident.mitre_id || 'T1190'}
                </span>
              </div>
              <div className="mono" style={{ fontSize: '13px', color: '#00f0ff', wordBreak: 'break-all', fontWeight: 600 }}>
                {selectedIncident.ip} &rarr; {selectedIncident.endpoint}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Rule: {selectedIncident.rule_matched}
              </div>
            </div>

            {/* Gemini Triage Response */}
            {selectedIncident.gemini_triage ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <h4 style={{ fontSize: '13px', textTransform: 'uppercase', color: 'var(--primary)', letterSpacing: '0.5px', marginBottom: '6px', fontWeight: 700 }}>
                    Plain-English Threat Summary
                  </h4>
                  <p style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: '1.5', background: 'rgba(0, 240, 255, 0.05)', padding: '12px', borderRadius: '8px', borderLeft: '3px solid #00f0ff' }}>
                    {selectedIncident.gemini_triage.plain_english_summary}
                  </p>
                </div>

                <div>
                  <h4 style={{ fontSize: '13px', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.5px', marginBottom: '6px', fontWeight: 700 }}>
                    Technical Breakdown
                  </h4>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: '1.5' }}>
                    {selectedIncident.gemini_triage.technical_details}
                  </p>
                </div>

                {/* Remediation Snippet */}
                {selectedIncident.gemini_triage.remediation_snippet && (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <h4 style={{ fontSize: '12px', textTransform: 'uppercase', color: '#05ffa1', letterSpacing: '0.5px', fontWeight: 700 }}>
                        Auto-Remediation Command
                      </h4>
                      <button
                        onClick={() => copyToClipboard(selectedIncident.gemini_triage.remediation_snippet)}
                        style={{ background: 'transparent', border: 'none', color: copiedSnippet ? '#05ffa1' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
                      >
                        {copiedSnippet ? <Check size={12} /> : <Copy size={12} />}
                        {copiedSnippet ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                    <div className="mono" style={{ background: '#05080E', padding: '12px', borderRadius: '8px', color: '#05ffa1', fontSize: '12px', border: '1px solid rgba(5, 255, 161, 0.3)', wordBreak: 'break-all' }}>
                      {selectedIncident.gemini_triage.remediation_snippet}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-muted)' }}>
                <Cpu size={32} color="#00f0ff" style={{ opacity: 0.6, marginBottom: '8px' }} />
                <p style={{ fontSize: '13px' }}>AI Incident analysis was logged or model is loading...</p>
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
          background: 'rgba(5, 8, 14, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 999
        }}>
          <div className="glass-panel" style={{
            width: '100%',
            maxWidth: '540px',
            padding: '28px',
            border: '1px solid rgba(5, 255, 161, 0.4)',
            boxShadow: '0 0 40px rgba(5, 255, 161, 0.15)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Plus size={22} color="#05ffa1" />
                <h3 style={{ fontSize: '18px', fontWeight: 700 }}>Manual Log Ingestion & AI Triage</h3>
              </div>
              <button
                onClick={() => setShowManualModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: '20px', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleManualSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Client IP Address</label>
                  <input
                    type="text"
                    required
                    value={manualForm.ip}
                    onChange={(e) => setManualForm({ ...manualForm, ip: e.target.value })}
                    style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: '#00f0ff', fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>HTTP Method</label>
                  <select
                    value={manualForm.method}
                    onChange={(e) => setManualForm({ ...manualForm, method: e.target.value })}
                    style={{ width: '100%', background: '#0F1623', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-main)', fontSize: '13px' }}
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Target URL Endpoint / Query Payload</label>
                <input
                  type="text"
                  required
                  value={manualForm.endpoint}
                  onChange={(e) => setManualForm({ ...manualForm, endpoint: e.target.value })}
                  placeholder="e.g. /.env or /products?id=1 UNION SELECT..."
                  style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>HTTP Status</label>
                  <input
                    type="number"
                    required
                    value={manualForm.status_code}
                    onChange={(e) => setManualForm({ ...manualForm, status_code: e.target.value })}
                    style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>User Agent String</label>
                  <input
                    type="text"
                    value={manualForm.user_agent}
                    onChange={(e) => setManualForm({ ...manualForm, user_agent: e.target.value })}
                    style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-main)', fontSize: '13px' }}
                  />
                </div>
              </div>

              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Raw Log Telemetry String</label>
                <textarea
                  rows={2}
                  value={manualForm.raw_log}
                  onChange={(e) => setManualForm({ ...manualForm, raw_log: e.target.value })}
                  style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px', color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '12px', resize: 'vertical' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
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
                  style={{ background: 'linear-gradient(135deg, #05ffa1 0%, #00b4d8 100%)', color: '#000', fontWeight: 700 }}
                >
                  <Zap size={16} color="#000" />
                  Ingest & Run CSIC ML Triage
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
