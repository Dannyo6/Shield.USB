import React, { useState, useEffect } from 'react';
import {
  Shield, Lock, Zap, Activity, Server, AlertTriangle,
  Globe, Cpu, Radio, CheckCircle, XCircle, Eye, Ban
} from 'lucide-react';

// =========================================================
// CONSTANTS
// =========================================================

const API_BASE          = 'http://localhost:5000';
const LOG_POLL_MS       = 3000;
const TELEMETRY_POLL_MS = 500;
const CONTAINMENT_POLL_MS = 4000;
const BLACKLIST_POLL_MS   = 6000;

const CPS_HUMAN_MAX  = 8;
const CPS_SUSPICIOUS = 20;
const CPS_HIGH_RISK  = 40;

// =========================================================
// HELPERS
// =========================================================

function getCpsColor(cps) {
  if (cps < CPS_HUMAN_MAX)  return '#22c55e';
  if (cps < CPS_SUSPICIOUS) return '#eab308';
  if (cps < CPS_HIGH_RISK)  return '#f97316';
  return '#ef4444';
}

function getCpsLabel(cps) {
  if (cps < CPS_HUMAN_MAX)  return 'HUMAN';
  if (cps < CPS_SUSPICIOUS) return 'SUSPICIOUS';
  if (cps < CPS_HIGH_RISK)  return 'HIGH RISK';
  return 'BADUSB';
}

function getScoreBg(score) {
  if (score < 30) return 'text-green-400';
  if (score < 60) return 'text-yellow-400';
  if (score < 80) return 'text-orange-400';
  return 'text-red-500';
}

// FIX: Added QUARANTINE and BLACKLIST_INSTANT_HIT badges
function getActionBadge(action) {
  if (!action) return { bg: 'bg-slate-500/10 text-slate-400 border-slate-500/20', icon: '○' };
  if (action.includes('BLOCKED'))
    return { bg: 'bg-red-500/10 text-red-400 border-red-500/30', icon: '✕' };
  if (action.includes('QUARANTINE'))
    return { bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30', icon: '⚑' };
  if (action.includes('MONITOR'))
    return { bg: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', icon: '◉' };
  return { bg: 'bg-green-500/10 text-green-400 border-green-500/30', icon: '✓' };
}

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString('en-US', { hour12: false });
}

function formatDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    + ' ' + d.toLocaleTimeString('en-US', { hour12: false });
}

// FIX: SQLite stores success as INTEGER 0/1, not boolean
function isSuccess(val) {
  return val === true || val === 1;
}

// =========================================================
// CPS GAUGE COMPONENT
// =========================================================

function CpsGauge({ cps, maxCps = 80 }) {
  const pct            = Math.min(cps / maxCps, 1);
  const color          = getCpsColor(cps);
  const label          = getCpsLabel(cps);
  const radius         = 52;
  const stroke         = 8;
  const circumference  = 2 * Math.PI * radius;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-36 h-36">
        <svg className="absolute inset-0 w-full h-full -rotate-[135deg]" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#1f2937"
            strokeWidth={stroke}
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeLinecap="round" />
          <circle cx="64" cy="64" r={radius} fill="none" stroke={color}
            strokeWidth={stroke}
            strokeDasharray={`${circumference * 0.75 * pct} ${circumference}`}
            strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 0.3s ease, stroke 0.3s ease' }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold font-mono" style={{ color, transition: 'color 0.3s ease' }}>
            {cps.toFixed(1)}
          </span>
          <span className="text-[9px] text-slate-500 uppercase tracking-widest">CPS</span>
        </div>
      </div>
      <span className="text-[9px] font-bold uppercase tracking-widest px-3 py-1 rounded-full border"
        style={{ color, borderColor: color + '50', backgroundColor: color + '15', transition: 'all 0.3s ease' }}>
        {label}
      </span>
    </div>
  );
}

// =========================================================
// RISK SCORE BAR
// =========================================================

function RiskBar({ score }) {
  const pct   = Math.min(score, 100);
  const color = pct < 30 ? '#22c55e' : pct < 60 ? '#eab308' : pct < 80 ? '#f97316' : '#ef4444';
  return (
    <div className="w-full">
      <div className="flex justify-between text-[9px] text-slate-500 mb-1">
        <span className="uppercase tracking-widest">Risk Score</span>
        <span className={getScoreBg(score) + ' font-bold'}>{score}/100</span>
      </div>
      <div className="h-2 bg-[#1f2937] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}

// =========================================================
// VARIANCE INDICATOR
// =========================================================

function VarianceIndicator({ varianceOk }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`w-2 h-2 rounded-full ${varianceOk ? 'bg-green-500' : 'bg-red-500 animate-pulse'}`} />
      <span className="text-[9px] text-slate-400 uppercase tracking-widest">
        {varianceOk ? 'Human Variance' : 'Bot Cadence Detected'}
      </span>
    </div>
  );
}

// =========================================================
// THREAT ALERT BANNER
// =========================================================

function ThreatBanner({ active, cps, classification }) {
  if (!active) return null;
  return (
    <div className="mb-6 p-4 rounded-xl border border-red-500/40 bg-red-500/10 flex items-center gap-4 animate-pulse-slow">
      <AlertTriangle size={20} className="text-red-400 flex-shrink-0" />
      <div>
        <p className="text-red-400 font-bold text-sm tracking-wide">
          ⚡ ACTIVE THREAT — BADUSB INJECTION DETECTED
        </p>
        <p className="text-red-500/70 text-xs mt-0.5">
          Keystroke velocity: <span className="font-bold text-red-400">{cps.toFixed(1)} CPS</span>
          {' '}· Classification: <span className="font-bold text-red-400">{classification}</span>
          {' '}· Containment triggered
        </p>
      </div>
    </div>
  );
}

// =========================================================
// CONTAINMENT PANEL
// =========================================================

function ContainmentPanel({ containmentData }) {
  const { session_records = [], contained_count = 0 } = containmentData || {};

  return (
    <div className="bg-[#16161f] rounded-2xl border border-[#262633] overflow-hidden">
      <div className="p-4 bg-[#1c1c28] border-b border-[#262633] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lock size={14} className="text-red-400" />
          <span className="text-[10px] font-bold uppercase text-slate-400 tracking-widest">
            Containment Audit
          </span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20">
          <span className="text-[10px] font-bold text-red-400">
            {contained_count} DISABLED
          </span>
        </div>
      </div>

      <div className="max-h-48 overflow-y-auto">
        {session_records.length === 0 ? (
          <div className="p-6 text-center text-slate-600 text-xs">
            No containment actions this session
          </div>
        ) : (
          <table className="w-full text-left">
            <thead className="text-[10px] uppercase text-slate-500 border-b border-[#262633] sticky top-0 bg-[#1c1c28]">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Device</th>
                <th className="p-3">CPS</th>
                <th className="p-3">Reason</th>
                <th className="p-3">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262633]">
              {session_records.map((r, i) => (
                <tr key={i} className="hover:bg-[#1f1f2e] transition-colors">
                  <td className="p-3 text-xs text-slate-500 whitespace-nowrap">{formatTime(r.timestamp)}</td>
                  <td className="p-3 text-xs text-indigo-300 font-mono font-bold">{r.vid}:{r.pid}</td>
                  {/* FIX: cps_at_block may be 0 on instant blacklist blocks */}
                  <td className="p-3 text-xs font-mono" style={{ color: getCpsColor(r.cps_at_block || 0) }}>
                    {r.cps_at_block > 0 ? r.cps_at_block.toFixed(1) : '—'}
                  </td>
                  <td className="p-3 text-[10px] text-slate-400 max-w-[120px] truncate">
                    {r.reason || 'BEHAVIORAL_DETECTION'}
                  </td>
                  {/* FIX: SQLite returns 0/1 integers — use isSuccess() */}
                  <td className="p-3">
                    {isSuccess(r.success) ? (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-green-400">
                        <CheckCircle size={10} /> DISABLED
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-red-400">
                        <XCircle size={10} /> FAILED
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// =========================================================
// BLACKLIST PANEL  (NEW — uses /api/blacklist)
// =========================================================

function BlacklistPanel({ blacklist }) {
  return (
    <div className="bg-[#16161f] rounded-2xl border border-[#262633] overflow-hidden">
      <div className="p-4 bg-[#1c1c28] border-b border-[#262633] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Ban size={14} className="text-orange-400" />
          <span className="text-[10px] font-bold uppercase text-slate-400 tracking-widest">
            Persistent Blacklist
          </span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-orange-500/10 border border-orange-500/20">
          <span className="text-[10px] font-bold text-orange-400">
            {blacklist.length} ENTRIES
          </span>
        </div>
      </div>

      <div className="max-h-48 overflow-y-auto">
        {blacklist.length === 0 ? (
          <div className="p-6 text-center text-slate-600 text-xs">
            No devices blacklisted yet
          </div>
        ) : (
          <table className="w-full text-left">
            <thead className="text-[10px] uppercase text-slate-500 border-b border-[#262633] sticky top-0 bg-[#1c1c28]">
              <tr>
                <th className="p-3">VID:PID</th>
                <th className="p-3">Device</th>
                <th className="p-3">Reason</th>
                <th className="p-3">Blocked At</th>
                <th className="p-3">Hits</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262633]">
              {blacklist.map((r, i) => (
                <tr key={i} className="hover:bg-[#1f1f2e] transition-colors">
                  <td className="p-3 text-xs text-orange-300 font-mono font-bold">{r.vid}:{r.pid}</td>
                  <td className="p-3 text-xs text-slate-300 max-w-[130px] truncate">
                    {r.device_name || '—'}
                  </td>
                  <td className="p-3 text-[10px] text-slate-400 max-w-[130px] truncate">
                    {r.reason || '—'}
                  </td>
                  <td className="p-3 text-[10px] text-slate-500 whitespace-nowrap">
                    {formatDate(r.blacklisted_at)}
                  </td>
                  <td className="p-3 text-xs font-bold text-red-400">
                    {r.insertion_count ?? 1}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// =========================================================
// MAIN APP
// =========================================================

const App = () => {
  const [logs,            setLogs]            = useState([]);
  const [telemetry,       setTelemetry]       = useState({
    cps_short: 0, cps_long: 0, anomaly_score: 0,
    threat_detected: false, classification: 'HUMAN',
    variance_ok: true, total_keys: 0, uptime_seconds: 0
  });
  const [containmentData, setContainmentData] = useState(null);
  const [blacklist,       setBlacklist]       = useState([]);
  const [stats,           setStats]           = useState({ total: 0, blocked: 0, active: true });
  const [apiOnline,       setApiOnline]       = useState(true);

  // ── Security Logs (3s) ──────────────────────────────────
  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res  = await fetch(`${API_BASE}/api/logs`);
        const data = await res.json();
        setLogs(data);
        setApiOnline(true);
        const blocked = data.filter(l => l.action_taken?.includes('BLOCKED')).length;
        setStats({ total: data.length, blocked, active: true });
      } catch {
        setApiOnline(false);
        setStats(p => ({ ...p, active: false }));
      }
    };
    fetchLogs();
    const id = setInterval(fetchLogs, LOG_POLL_MS);
    return () => clearInterval(id);
  }, []);

  // ── Telemetry (500ms) ────────────────────────────────────
  useEffect(() => {
    const fetchTelemetry = async () => {
      try {
        const res  = await fetch(`${API_BASE}/api/telemetry`);
        const data = await res.json();
        if (!data.error) setTelemetry(data);
      } catch { /* silent */ }
    };
    fetchTelemetry();
    const id = setInterval(fetchTelemetry, TELEMETRY_POLL_MS);
    return () => clearInterval(id);
  }, []);

  // ── Containment (4s) ────────────────────────────────────
  useEffect(() => {
    const fetchContainment = async () => {
      try {
        const res  = await fetch(`${API_BASE}/api/containment`);
        const data = await res.json();
        if (!data.error) setContainmentData(data);
      } catch { /* silent */ }
    };
    fetchContainment();
    const id = setInterval(fetchContainment, CONTAINMENT_POLL_MS);
    return () => clearInterval(id);
  }, []);

  // ── Blacklist (6s) ───────────────────────────────────────
  useEffect(() => {
    const fetchBlacklist = async () => {
      try {
        const res  = await fetch(`${API_BASE}/api/blacklist`);
        const data = await res.json();
        if (Array.isArray(data)) setBlacklist(data);
      } catch { /* silent */ }
    };
    fetchBlacklist();
    const id = setInterval(fetchBlacklist, BLACKLIST_POLL_MS);
    return () => clearInterval(id);
  }, []);

  // ── Derived State ────────────────────────────────────────
  const isThreat    = telemetry.threat_detected;
  const latestLog   = logs[0] || null;
  const latestScore = latestLog?.risk_score ?? 0;

  const streamText = isThreat
    ? `⚡ CRITICAL_INJECTION: CPS=${telemetry.cps_short.toFixed(1)} CLASS=${telemetry.classification} ANOMALY_SCORE=${telemetry.anomaly_score} · CONTAINMENT_TRIGGERED`
    : `◎ SHIELD.USB_ACTIVE: Monitoring HID bus · CPS=${telemetry.cps_short.toFixed(1)} · Keys=${telemetry.total_keys} · Uptime=${telemetry.uptime_seconds}s`;

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-300 font-mono transition-all duration-500"
      style={{ backgroundImage: isThreat ? 'radial-gradient(ellipse at top, rgba(239,68,68,0.05) 0%, transparent 60%)' : undefined }}>

      <div className="p-4 lg:p-8 max-w-7xl mx-auto">

        {/* ── HEADER ── */}
        <header className="flex justify-between items-center mb-6 bg-[#16161f] p-5 rounded-2xl border border-[#262633] shadow-2xl">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Shield size={30} className="text-indigo-500" />
              {isThreat && (
                <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-ping" />
              )}
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-widest">
                SHIELD<span className="text-indigo-500">.</span>USB
                <span className="text-indigo-500 ml-2 text-sm">PRO</span>
              </h1>
              <p className="text-[9px] text-slate-500 uppercase tracking-widest">
                Behavioral HID Prevention Engine · v2.1
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3 py-1.5 rounded-full border border-[#262633] flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
              <span className="text-[9px] font-bold text-white uppercase">
                {apiOnline ? 'API Online' : 'API Offline'}
              </span>
            </div>
            <div className="px-3 py-1.5 rounded-full border border-indigo-500/30 bg-indigo-500/10 flex items-center gap-2">
              <Radio size={10} className="text-indigo-400 animate-pulse" />
              <span className="text-[9px] font-bold text-indigo-400 uppercase">Telemetry Live</span>
            </div>
          </div>
        </header>

        {/* ── THREAT BANNER ── */}
        <ThreatBanner
          active={isThreat}
          cps={telemetry.cps_short}
          classification={telemetry.classification}
        />

        {/* ── STAT CARDS + CPS GAUGE ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">

          <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Events Scanned',  value: stats.total,
                color: 'text-blue-400',   icon: <Eye size={14} /> },
              { label: 'Blocked Threats', value: stats.blocked,
                color: 'text-red-400',    icon: <AlertTriangle size={14} /> },
              { label: 'Containments',
                value: containmentData?.contained_count ?? 0,
                color: 'text-purple-400', icon: <Lock size={14} /> },
              { label: 'Blacklisted',     value: blacklist.length,
                color: 'text-orange-400', icon: <Ban size={14} /> },
            ].map((card, i) => (
              <div key={i} className="bg-[#16161f] p-4 rounded-2xl border border-[#262633] flex flex-col gap-2">
                <div className="flex items-center gap-2 text-slate-500">
                  {card.icon}
                  <p className="text-[9px] uppercase tracking-widest font-bold">{card.label}</p>
                </div>
                <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
              </div>
            ))}
          </div>

          <div className="bg-[#16161f] p-5 rounded-2xl border border-[#262633] flex flex-col items-center justify-center gap-4">
            <p className="text-[9px] uppercase tracking-widest text-slate-500 font-bold flex items-center gap-2">
              <Activity size={10} className="text-indigo-400" /> Live Keystroke Velocity
            </p>
            <CpsGauge cps={telemetry.cps_short} />
            <VarianceIndicator varianceOk={telemetry.variance_ok} />
          </div>
        </div>

        {/* ── TELEMETRY DETAIL + TRAFFIC STREAM ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">

          <div className="bg-[#16161f] p-5 rounded-2xl border border-[#262633]">
            <div className="flex items-center gap-2 mb-4">
              <Cpu size={14} className="text-indigo-400" />
              <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                Telemetry Signals
              </h3>
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3 text-xs">
                {[
                  { label: 'CPS (2s window)',  value: telemetry.cps_short.toFixed(2), color: getCpsColor(telemetry.cps_short) },
                  { label: 'CPS (10s window)', value: telemetry.cps_long.toFixed(2),  color: getCpsColor(telemetry.cps_long)  },
                  { label: 'Total Keystrokes', value: telemetry.total_keys,            color: '#94a3b8' },
                  { label: 'Uptime',           value: `${telemetry.uptime_seconds}s`,  color: '#94a3b8' },
                ].map((item, i) => (
                  <div key={i} className="bg-[#0a0a0f] p-3 rounded-lg border border-[#1f2937]">
                    <p className="text-[9px] text-slate-500 uppercase tracking-widest mb-1">{item.label}</p>
                    <p className="font-bold font-mono" style={{ color: item.color }}>{item.value}</p>
                  </div>
                ))}
              </div>
              {/* Anomaly score bar */}
              <div className="w-full">
                <div className="flex justify-between text-[9px] text-slate-500 mb-1">
                  <span className="uppercase tracking-widest">Anomaly Score</span>
                  <span className={`font-bold ${telemetry.anomaly_score >= 30 ? 'text-red-400' : 'text-green-400'}`}>
                    {telemetry.anomaly_score}/50
                  </span>
                </div>
                <div className="h-2 bg-[#1f2937] rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${(telemetry.anomaly_score / 50) * 100}%`,
                      backgroundColor: telemetry.anomaly_score >= 30 ? '#ef4444' : '#22c55e'
                    }} />
                </div>
              </div>
              <RiskBar score={latestScore} />
            </div>
          </div>

          <div className="bg-[#16161f] p-5 rounded-2xl border border-[#262633] flex flex-col">
            <div className="flex items-center gap-2 mb-4">
              <Globe size={14} className="text-indigo-400" />
              <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                Live Traffic Intercept
              </h3>
            </div>
            <div className="bg-[#0a0a0f] p-4 rounded-lg border border-[#1f2937] flex-1 overflow-hidden flex items-center">
              <div key={streamText} className="whitespace-nowrap text-xs opacity-80 animate-marquee"
                style={{ color: isThreat ? '#f87171' : '#818cf8' }}>
                {streamText}&nbsp;&nbsp;&nbsp;{streamText}&nbsp;&nbsp;&nbsp;{streamText}
              </div>
            </div>
            <div className="flex gap-3 mt-4">
              {[
                { label: 'HID Monitor', on: true },
                { label: 'Telemetry',   on: true },
                { label: 'Containment', on: apiOnline },
                { label: 'Blacklist',   on: blacklist.length > 0 || apiOnline },
              ].map((s, i) => (
                <div key={i} className="flex items-center gap-1.5 text-[9px] text-slate-400 uppercase tracking-widest">
                  <div className={`w-1.5 h-1.5 rounded-full ${s.on ? 'bg-green-500' : 'bg-slate-600'}`} />
                  {s.label}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── CONTAINMENT + BLACKLIST PANELS (side by side) ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
          <ContainmentPanel containmentData={containmentData} />
          <BlacklistPanel   blacklist={blacklist} />
        </div>

        {/* ── MASTER AUDIT TRAIL ── */}
        <div className="bg-[#16161f] rounded-2xl border border-[#262633] overflow-hidden">
          <div className="p-4 bg-[#1c1c28] border-b border-[#262633] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server size={14} className="text-slate-500" />
              <span className="text-[10px] font-bold uppercase text-slate-400 tracking-widest">
                Master Audit Trail
              </span>
            </div>
            <span className="text-[10px] text-slate-600">{logs.length} records</span>
          </div>

          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-left">
              <thead className="text-[10px] uppercase text-slate-500 border-b border-[#262633] sticky top-0 bg-[#1c1c28]">
                <tr>
                  <th className="p-4 font-bold">Time</th>
                  <th className="p-4 font-bold">Device</th>
                  <th className="p-4 font-bold">Signature</th>
                  <th className="p-4 font-bold">CPS</th>
                  <th className="p-4 font-bold">Score</th>
                  <th className="p-4 font-bold">Action</th>
                  <th className="p-4 font-bold">Contained</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#262633]">
                {logs.map((log, i) => {
                  const badge = getActionBadge(log.action_taken);
                  return (
                    <tr key={log.id || i} className="hover:bg-[#1f1f2e] transition-colors">
                      <td className="p-4 text-xs text-slate-500 whitespace-nowrap">
                        {formatTime(log.timestamp)}
                      </td>
                      <td className="p-4 text-xs text-slate-300 max-w-[140px] truncate">
                        {log.device_name || '—'}
                      </td>
                      <td className="p-4 text-sm text-indigo-300 font-bold font-mono">
                        {log.vid}:{log.pid}
                      </td>
                      <td className="p-4 text-xs font-mono" style={{ color: getCpsColor(log.cps || 0) }}>
                        {log.cps ? log.cps.toFixed(1) : '—'}
                      </td>
                      <td className={`p-4 text-xs font-bold ${getScoreBg(log.risk_score)}`}>
                        {log.risk_score}
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badge.bg}`}>
                          {badge.icon} {log.action_taken}
                        </span>
                      </td>
                      <td className="p-4">
                        {log.containment_status === 'CONTAINED' ||
                         log.containment_status === 'DISABLED' ? (
                          <span className="flex items-center gap-1 text-[10px] text-green-400">
                            <CheckCircle size={10} /> DISABLED
                          </span>
                        ) : log.containment_status === 'INSTANT_BLACKLIST_HIT' ? (
                          <span className="flex items-center gap-1 text-[10px] text-orange-400">
                            <Ban size={10} /> BLACKLIST
                          </span>
                        ) : log.containment_status === 'HID_QUARANTINE' ? (
                          <span className="flex items-center gap-1 text-[10px] text-yellow-400">
                            <Eye size={10} /> QUARANTINE
                          </span>
                        ) : log.containment_status === 'FAILED' ? (
                          <span className="flex items-center gap-1 text-[10px] text-red-400">
                            <XCircle size={10} /> FAILED
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {logs.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-600 text-xs">
                      No events logged yet. Plug in a device to begin.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-[9px] text-slate-700 mt-6 uppercase tracking-widest">
          SHIELD.USB · Behavioral HID Prevention · Real-time Telemetry Engine · v2.1
        </p>

      </div>
    </div>
  );
};

export default App;
