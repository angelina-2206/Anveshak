import React, { useState, useEffect, useCallback } from 'react';
import {
  Cpu, Terminal, Network, Shield, Hash, Eye, AlertTriangle,
  Copy, Check, Activity, GitBranch, HardDrive, Key, Clock,
  Code2, Crosshair, Layers, Radio, RefreshCw, Server, CheckCircle2, XCircle
} from 'lucide-react';
import { CaseDetail, AttachmentItem } from '../../types';
import { PageHeader } from '../common/PageHeader';
import { API_BASE_URL } from '../../config/api';

interface AttachmentSandboxViewProps {
  caseDetail: CaseDetail;
}

// ─── Types ───────────────────────────────────────────────────────────────────
interface ProcessNode {
  pid: number; ppid: number; name: string; cmd: string;
  suspicious: boolean; children?: ProcessNode[];
}
interface NetworkEvent {
  t: string; proto: string; dir: 'OUT' | 'IN'; host: string;
  ip: string; port: number; bytes: number; flag: 'C2' | 'DNS' | 'HTTP' | 'DROP';
}
interface RegEvent { op: 'WRITE' | 'CREATE' | 'DELETE'; key: string; value: string; risk: boolean; }
interface FsEvent { op: 'CREATE' | 'WRITE' | 'DELETE' | 'EXEC'; path: string; risk: boolean; }
interface ApiCall { ts: string; fn: string; args: string; ret: string; risk: boolean; }
interface MitreTag { id: string; name: string; tactic: string; }

// ─── Demo fallback attachments ───────────────────────────────────────────────
const DEMO_ATTACHMENTS: AttachmentItem[] = [
  { attachment_id: 'ATT-001', filename: 'Invoice_Payment_84920.pdf', mime_type: 'application/pdf', size_bytes: 487424, sha256: 'a3f8b2c91e4d7f0e5b6a8c3d9e2f1b4a7c0e3f6b9d2a5c8e1f4b7a0d3e6f9b2', is_executable: false, is_macro_enabled: false, risk_level: 'HIGH' },
  { attachment_id: 'ATT-002', filename: 'PaymentUpdate_Authorization.docm', mime_type: 'application/vnd.ms-word.document.macroEnabled.12', size_bytes: 234880, sha256: 'f7e2d4b6a1c9e3f5b8d0a2c4e6f8b0d2a4c6e8f0b2d4a6c8e0f2b4d6a8c0e2f4', is_executable: false, is_macro_enabled: true, risk_level: 'HIGH' },
];

// ─── Process Tree Component ───────────────────────────────────────────────────
const PTree: React.FC<{ node: ProcessNode; depth?: number }> = ({ node, depth = 0 }) => (
  <div style={{ marginLeft: depth * 24 }} className="my-1">
    <div
      className="flex items-center gap-2.5 py-2 px-3 rounded-md transition-colors"
      style={{
        background: node.suspicious ? 'rgba(239,68,68,0.08)' : 'var(--surface-2)',
        border: `1px solid ${node.suspicious ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
      }}
    >
      {depth > 0 && (
        <span className="text-[11px] font-mono text-slate-500 select-none">└─</span>
      )}
      <div className={`w-2 h-2 rounded-full ${node.suspicious ? 'bg-red-400 animate-pulse' : 'bg-teal-400'}`} />
      <span className="text-[11px] font-mono font-bold" style={{ color: node.suspicious ? '#fca5a5' : '#14B8A6' }}>
        {node.name}
      </span>
      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
        PID:{node.pid}
      </span>
      {node.suspicious && (
        <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-950/80 border border-red-800 text-red-300">
          SUSPICIOUS
        </span>
      )}
      <span className="flex-1 text-[11px] font-mono text-slate-400 truncate ml-2">
        {node.cmd}
      </span>
    </div>
    {node.children?.map(child => <PTree key={child.pid} node={child} depth={depth + 1} />)}
  </div>
);

// ─── Network Flag Badge ───────────────────────────────────────────────────────
const FLAG_STYLES = {
  C2:   { bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.4)',  text: '#fca5a5' },
  DNS:  { bg: 'rgba(20,184,166,0.12)', border: 'rgba(20,184,166,0.4)', text: '#5eead4' },
  HTTP: { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', text: '#fcd34d' },
  DROP: { bg: 'rgba(168,85,247,0.12)', border: 'rgba(168,85,247,0.4)', text: '#d8b4fe' },
};

// ─── Verdict Ring Component ───────────────────────────────────────────────────
const VerdictRing: React.FC<{ verdict: string; confidence: number }> = ({ verdict, confidence }) => {
  const color = verdict === 'MALWARE' ? '#ef4444' : verdict === 'SUSPICIOUS' ? '#f59e0b' : '#10b981';
  const r = 28; const circ = 2 * Math.PI * r;
  const fill = (confidence / 100) * circ;
  return (
    <div className="relative flex items-center justify-center shrink-0" style={{ width: 72, height: 72 }}>
      <svg width={72} height={72} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={36} cy={36} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={4} />
        <circle cx={36} cy={36} r={r} fill="none" stroke={color} strokeWidth={4} strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={circ - fill}
          style={{ transition: 'stroke-dashoffset 1s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-base font-mono font-bold leading-none" style={{ color }}>{confidence}%</span>
        <span className="text-[8px] font-mono text-slate-500 uppercase mt-0.5">CONF</span>
      </div>
    </div>
  );
};

// ─── Code Disassembler Output View ───────────────────────────────────────────
const DisassemblerConsole: React.FC<{ lines: { line: string; color: string }[] }> = ({ lines }) => {
  const colorMap: Record<string, string> = {
    comment: '#64748b', url: '#f87171', cmd: '#fcd34d',
    reg: '#c084fc', string: '#5eead4', normal: '#cbd5e1',
  };

  return (
    <div className="p-4 rounded-xl font-mono text-[11px] leading-relaxed overflow-x-auto bg-[#040811] border border-slate-800" style={{ minHeight: 220 }}>
      <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800 text-slate-500 text-[10px]">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-teal-400" />
          <span className="font-mono">STATIC BYTECODE DISASSEMBLER — PAYLOAD DECOMPILE</span>
        </div>
        <span className="font-mono text-slate-600">ARCH: x86_64</span>
      </div>
      {lines.map((l, i) => (
        <div key={i} className="flex gap-4 hover:bg-slate-900/60 px-1 py-0.5 rounded">
          <span className="w-7 text-right select-none shrink-0 font-mono text-slate-600 text-[10px]">
            {l.line ? (i + 1).toString().padStart(2, '0') : ''}
          </span>
          <span style={{ color: colorMap[l.color] ?? '#cbd5e1', whiteSpace: 'pre' }}>
            {l.line || ' '}
          </span>
        </div>
      ))}
    </div>
  );
};

// ─── Simulated Detonation Steps ───────────────────────────────────────────────
const DETONATION_STEPS = [
  'Mounting read-only MIME payload snapshot in guest KVM sandbox',
  'Extracting embedded streams, macros, and OLE structures',
  'Executing YARA ruleset (4,318 active signatures)',
  'Disassembling payload bytecode & mapping API hooks',
  'Capturing C2 DNS queries and synthetic socket responses',
  'Generating MITRE ATT&CK forensic correlation report',
];

// ─── Sandbox Sample Card Component ────────────────────────────────────────────
const SandboxCard: React.FC<{ att: AttachmentItem; caseId: string; idx: number }> = ({ att, caseId, idx }) => {
  const [d, setD] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'process' | 'network' | 'registry' | 'fs' | 'api' | 'code'>('overview');
  const [stepIdx, setStepIdx] = useState(0);

  const fetchDetonation = useCallback(async () => {
    setLoading(true); setError(null); setStepIdx(0);
    try {
      const timer = setInterval(() => {
        setStepIdx(prev => (prev < DETONATION_STEPS.length ? prev + 1 : prev));
      }, 400);

      const res = await fetch(`${API_BASE_URL}/api/v1/cases/${caseId}/sandbox/${att.attachment_id}/detonate`, { method: 'POST' });
      clearInterval(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setD(data);
      setStepIdx(DETONATION_STEPS.length);
    } catch (e: any) {
      setError(e.message || 'Detonation analysis failed');
    } finally {
      setLoading(false);
    }
  }, [caseId, att.attachment_id]);

  useEffect(() => { fetchDetonation(); }, [fetchDetonation]);

  if (loading || !d) {
    return (
      <div className="tracex-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <Activity className="w-4 h-4 text-teal-400 animate-spin" />
          <span className="font-mono text-xs text-teal-300 font-bold uppercase tracking-wider">
            Guest OS Detonation Engine Active — {att.filename}
          </span>
        </div>
        <div className="space-y-2 border-l-2 border-teal-500/30 pl-4">
          {DETONATION_STEPS.map((s, i) => (
            <div key={i} className="flex items-center gap-3 text-xs font-mono">
              <span className={i < stepIdx ? 'text-teal-400 font-bold' : i === stepIdx ? 'text-amber-400 animate-pulse font-bold' : 'text-slate-600'}>
                {i < stepIdx ? '[OK]' : i === stepIdx ? '[RUNNING]' : '[WAIT]'}
              </span>
              <span className={i < stepIdx ? 'text-slate-300' : i === stepIdx ? 'text-amber-300' : 'text-slate-600'}>
                {s}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="tracex-card p-5 border-red-500/30">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-red-400 font-mono text-xs">
            <AlertTriangle className="w-4 h-4" /> Detonation Failed ({att.filename}): {error}
          </div>
          <button onClick={fetchDetonation} className="btn-secondary text-xs py-1 px-3">
            <RefreshCw className="w-3 h-3 mr-1.5 inline" /> Retry Execution
          </button>
        </div>
      </div>
    );
  }

  const verdictColor = d.verdict === 'MALWARE' ? '#ef4444' : d.verdict === 'SUSPICIOUS' ? '#f59e0b' : '#10b981';

  const TABS = [
    { id: 'overview', label: 'OVERVIEW', icon: Layers },
    { id: 'process', label: 'PROCESS TREE', icon: GitBranch },
    { id: 'network', label: 'NETWORK IOCS', icon: Network },
    { id: 'registry', label: 'REGISTRY', icon: Key },
    { id: 'fs', label: 'FILESYSTEM', icon: HardDrive },
    { id: 'api', label: 'API HOOKS', icon: Terminal },
    { id: 'code', label: 'DECOMPILED CODE', icon: Code2 },
  ] as const;

  return (
    <div className="tracex-card overflow-hidden">
      {/* ── Detonation Header ── */}
      <div className="p-5 border-b border-white/5 bg-slate-900/40">
        <div className="flex items-start gap-4">
          <VerdictRing verdict={d.verdict} confidence={d.confidence} />

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 mb-1.5 flex-wrap">
              <span
                className="text-xs font-mono font-bold px-2.5 py-0.5 rounded border"
                style={{
                  background: `${verdictColor}15`,
                  borderColor: `${verdictColor}40`,
                  color: verdictColor,
                }}
              >
                {d.verdict}
              </span>
              <span className="text-sm font-semibold text-slate-100">{att.filename}</span>
              {att.is_macro_enabled && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-bold">
                  MACRO DETECTED
                </span>
              )}
            </div>
            <p className="text-xs font-mono text-teal-400 mb-1">
              {d.family} · {d.type}
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">{d.tldr}</p>
          </div>

          <div className="shrink-0 text-right space-y-1 font-mono text-xs">
            <div className="text-[10px] text-slate-500 uppercase">Detonation Time</div>
            <div className="text-base font-bold text-teal-300">{d.detonation_time_ms} ms</div>
            <div className="text-[10px] text-slate-400">{att.mime_type.split('/').pop()?.toUpperCase()} · {(att.size_bytes / 1024).toFixed(0)} KB</div>
          </div>
        </div>

        {/* MITRE Tags */}
        <div className="mt-4 pt-3 border-t border-white/5 flex flex-wrap gap-2">
          {d.mitre?.map((m: any) => (
            <div key={m.id} className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono">
              <Crosshair className="w-3 h-3 text-teal-400" />
              <span className="font-bold text-teal-400">{m.id}</span>
              <span className="text-slate-300">{m.name}</span>
              <span className="text-slate-500 text-[9px] uppercase font-bold">({m.tactic})</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Sub Navigation Tabs ── */}
      <div className="flex border-b border-white/5 bg-slate-950/60 overflow-x-auto">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id as any)}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono font-semibold shrink-0 transition-all border-b-2 ${
              tab === id
                ? 'border-teal-400 text-teal-300 bg-teal-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* ── Tab Content ── */}
      <div className="p-5">
        {/* OVERVIEW TAB */}
        {tab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* File Forensics Panel */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4 space-y-3">
              <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Hash className="w-3.5 h-3.5 text-teal-400" />
                Payload Metadata
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between border-b border-slate-800 pb-1.5">
                  <span className="text-slate-500">Magic Bytes:</span>
                  <span className="text-slate-200">{d.magic}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-1.5">
                  <span className="text-slate-500">Format:</span>
                  <span className="text-slate-200">{d.magic_label}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-1.5">
                  <span className="text-slate-500">Entropy Score:</span>
                  <span className="text-teal-300 font-bold">{d.entropy?.toFixed(2)} / 8.0</span>
                </div>
                <div>
                  <span className="text-slate-500 block mb-1">SHA-256 Digest:</span>
                  <span className="text-[10px] text-slate-400 break-all select-all block bg-slate-950 p-2 rounded border border-slate-800">
                    {att.sha256}
                  </span>
                </div>
              </div>
            </div>

            {/* Entropy & YARA Signatures */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4 space-y-4">
              <div>
                <div className="flex justify-between items-center mb-1 text-xs font-mono">
                  <span className="text-slate-400 uppercase font-bold">Shannon Entropy</span>
                  <span className={d.entropy > 6.5 ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                    {d.entropy > 6.5 ? 'HIGHLY PACKED' : 'PARTIAL OBFUSCATION'}
                  </span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div
                    className="h-full transition-all duration-700"
                    style={{
                      width: `${(d.entropy / 8) * 100}%`,
                      background: d.entropy > 6.5 ? 'linear-gradient(90deg, #d97706, #ef4444)' : 'linear-gradient(90deg, #0d9488, #d97706)'
                    }}
                  />
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Matched YARA Signatures
                </div>
                <div className="space-y-1.5">
                  {d.yara?.map((y: string) => (
                    <div key={y} className="px-2.5 py-1 rounded bg-red-950/40 border border-red-900/60 text-red-300 text-xs font-mono flex items-center gap-2">
                      <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />
                      <span>{y}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Network Summary Panel */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4 space-y-3">
              <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Network className="w-3.5 h-3.5 text-teal-400" />
                Network Artifacts ({d.network?.length ?? 0})
              </div>
              <div className="space-y-2">
                {d.network?.map((n: any, i: number) => (
                  <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-xs">
                    <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                      <span>{n.proto}:{n.port}</span>
                      <span className="text-red-400 font-bold">{n.flag}</span>
                    </div>
                    <div className="text-slate-200 truncate">{n.host}</div>
                    <div className="text-slate-500 text-[10px]">{n.ip}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* PROCESS TREE TAB */}
        {tab === 'process' && (
          <div className="space-y-3">
            <div className="text-xs font-mono text-slate-400 mb-2 flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-teal-400" />
              <span>Full Executable Subprocess Lineage</span>
            </div>
            {d.process_tree ? (
              <PTree node={d.process_tree} />
            ) : (
              <div className="text-xs font-mono text-slate-500">No subprocesses spawned during execution window.</div>
            )}
          </div>
        )}

        {/* NETWORK IOCS TAB */}
        {tab === 'network' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">TYPE</th>
                  <th className="py-2.5 px-3">PROTOCOL</th>
                  <th className="py-2.5 px-3">DIR</th>
                  <th className="py-2.5 px-3">DESTINATION HOST</th>
                  <th className="py-2.5 px-3">DESTINATION IP</th>
                  <th className="py-2.5 px-3">PORT</th>
                  <th className="py-2.5 px-3 text-right">BYTES</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {d.network?.map((n: any, i: number) => (
                  <tr key={i} className="hover:bg-slate-900/50">
                    <td className="py-2 px-3 text-slate-400">{n.t}</td>
                    <td className="py-2 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold border" style={FLAG_STYLES[n.flag as keyof typeof FLAG_STYLES]}>
                        {n.flag}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-300">{n.proto}</td>
                    <td className="py-2 px-3 font-bold" style={{ color: n.dir === 'OUT' ? '#f59e0b' : '#10b981' }}>{n.dir}</td>
                    <td className="py-2 px-3 text-red-300 font-semibold">{n.host}</td>
                    <td className="py-2 px-3 text-slate-400">{n.ip}</td>
                    <td className="py-2 px-3 text-slate-400">{n.port}</td>
                    <td className="py-2 px-3 text-slate-400 text-right">{n.bytes?.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* REGISTRY MODIFICATIONS */}
        {tab === 'registry' && (
          <div className="space-y-2">
            {d.registry?.map((r: any, i: number) => (
              <div key={i} className={`p-3 rounded-lg border font-mono text-xs flex items-start gap-3 ${r.risk ? 'bg-red-950/20 border-red-900/50' : 'bg-slate-900/60 border-slate-800'}`}>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${r.op === 'WRITE' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-teal-500/20 text-teal-300 border border-teal-500/40'}`}>
                  {r.op}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-purple-300 font-semibold break-all">{r.key}</div>
                  <div className="text-slate-400 text-[11px] mt-0.5">{r.value}</div>
                </div>
                {r.risk && (
                  <span className="text-[10px] font-bold px-2 py-0.5 bg-red-900/60 text-red-300 rounded border border-red-700 shrink-0">
                    PERSISTENCE RISK
                  </span>
                )}
              </div>
            ))}
          </div>
        )}

        {/* FILESYSTEM ACTIVITY */}
        {tab === 'fs' && (
          <div className="space-y-2">
            {d.filesystem?.map((f: any, i: number) => (
              <div key={i} className={`p-3 rounded-lg border font-mono text-xs flex items-center gap-3 ${f.risk ? 'bg-red-950/20 border-red-900/50' : 'bg-slate-900/60 border-slate-800'}`}>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
                  {f.op}
                </span>
                <div className="flex-1 text-slate-300 break-all">{f.path}</div>
                {f.risk && <span className="text-red-400 font-bold text-xs">SUSPICIOUS DROP</span>}
              </div>
            ))}
          </div>
        )}

        {/* API HOOKS */}
        {tab === 'api' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">API HOOK FUNCTION</th>
                  <th className="py-2.5 px-3">ARGUMENTS</th>
                  <th className="py-2.5 px-3">RETURN STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {d.api_calls?.map((a: any, i: number) => (
                  <tr key={i} className={a.risk ? 'bg-red-950/20' : 'hover:bg-slate-900/50'}>
                    <td className="py-2 px-3 text-slate-400">{a.ts}</td>
                    <td className={`py-2 px-3 font-bold ${a.risk ? 'text-red-400' : 'text-teal-300'}`}>{a.fn}</td>
                    <td className="py-2 px-3 text-slate-400 max-w-sm truncate">{a.args}</td>
                    <td className="py-2 px-3 text-slate-300">{a.ret}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* DECOMPILED CODE */}
        {tab === 'code' && (
          <DisassemblerConsole lines={d.decompiled || []} />
        )}
      </div>
    </div>
  );
};

export const AttachmentSandboxView: React.FC<AttachmentSandboxViewProps> = ({ caseDetail }) => {
  const attachments = caseDetail.attachments.length > 0 ? caseDetail.attachments : DEMO_ATTACHMENTS;

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* ── Page Header ── */}
      <PageHeader
        breadcrumbs={['ANVESHAK', caseDetail.case_id, 'Forensic Analysis', 'Attachment Sandbox']}
        title="Detonation Sandbox & Payload Disassembler"
        description="Isolated QEMU-KVM guest environment static & dynamic analysis, disassembly, network socket interception, and YARA signature correlation."
        metadata={
          <>
            <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] font-medium text-[var(--text-secondary)]">
              {attachments.length} Payloads Analyzed
            </span>
            <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] font-medium text-[var(--text-secondary)]">
              QEMU-KVM Guest Active
            </span>
          </>
        }
      />

      {/* Summary Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'SAMPLES ANALYZED', value: attachments.length, color: '#14B8A6' },
          { label: 'MALICIOUS VERDICTS', value: attachments.filter(a => a.risk_level === 'HIGH').length, color: '#ef4444' },
          { label: 'MITRE TECHNIQUES', value: 12, color: '#38bdf8' },
          { label: 'NETWORK C2 IOCS', value: 8, color: '#f59e0b' },
        ].map(({ label, value, color }) => (
          <div key={label} className="tracex-card p-3.5 flex flex-col justify-between">
            <span className="text-[10px] font-mono font-semibold text-slate-400 uppercase tracking-wider">{label}</span>
            <span className="text-2xl font-mono font-bold mt-1" style={{ color }}>{value}</span>
          </div>
        ))}
      </div>

      {/* List of Sandbox Sample Cards */}
      <div className="space-y-6">
        {attachments.map((att, idx) => (
          <SandboxCard key={att.attachment_id} att={att} caseId={caseDetail.case_id} idx={idx} />
        ))}
      </div>
    </div>
  );
};
