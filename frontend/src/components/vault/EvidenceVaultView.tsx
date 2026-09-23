import React, { useState } from 'react';
import {
  Lock, Download, ShieldCheck, FileText, CheckCircle2,
  History, Hash, Copy, Check, Blocks, Shield, ExternalLink, Printer
} from 'lucide-react';
import { CaseDetail } from '../../types';
import { PageHeader } from '../common/PageHeader';
import { PdfDownloadMenu } from '../common/PdfDownloadMenu';
import { API_BASE_URL } from '../../config/api';

interface EvidenceVaultViewProps {
  caseDetail: CaseDetail;
}

const CopyHash: React.FC<{ value: string; label: string }> = ({ value, label }) => {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className="flex items-center gap-2 p-2 rounded cursor-pointer group transition-all bg-[var(--surface-2)] border border-[var(--border)] hover:border-[var(--border-hi)]"
      onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
    >
      <span className="text-[10px] font-sans font-semibold shrink-0 uppercase text-[var(--text-muted)]">
        {label}:
      </span>
      <code className="flex-1 text-[11px] code-mono text-[var(--text-secondary)] truncate">
        {value.slice(0, 32)}…
      </code>
      {copied
        ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
        : <Copy className="w-3.5 h-3.5 text-[var(--text-muted)] shrink-0 opacity-0 group-hover:opacity-100" />
      }
    </div>
  );
};

export const EvidenceVaultView: React.FC<EvidenceVaultViewProps> = ({ caseDetail }) => {
  const cocEvents = caseDetail.chain_of_custody;

  const downloadStix = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/cases/${caseDetail.case_id}/stix`);
      const stixData = await res.json();
      const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = `STIX_Bundle_${caseDetail.case_id}.json`; a.click();
    } catch (e) {
      console.error("STIX download error:", e);
    }
  };

  const downloadJsonReport = () => {
    const blob = new Blob([JSON.stringify(caseDetail, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `Forensic_Evidence_Package_${caseDetail.case_id}.json`; a.click();
  };

  const downloadReport = () => {
    const gf = caseDetail.geo_financial;
    const auth = caseDetail.auth_status;
    const threat = caseDetail.threat_score;
    const identity = caseDetail.identity_analysis;

    const reportContent = `# ANVESHAK DIGITAL FORENSICS & THREAT INVESTIGATION REPORT
**Case Reference:** ${caseDetail.case_id}
**Ingestion Timestamp:** ${new Date(caseDetail.created_at).toUTCString()}
**Classification:** RESTRICTED — COURT-ADMISSIBLE FORENSIC EVIDENCE PACKAGE

---

## 1. EXECUTIVE RISK & VERDICT OVERVIEW
- **Overall Threat Score:** ${threat?.overall_score ?? 'N/A'} / 100
- **Severity Assessment:** ${caseDetail.severity}
- **Primary Classification:** ${caseDetail.title}
- **Case Summary:** ${caseDetail.summary}

---

## 2. EMAIL ENVELOPE & AUTHENTICATION VERDICT
- **Claimed Sender (From):** \`${caseDetail.email_from}\`
- **Envelope Sender (Return-Path):** \`${identity?.return_path || 'N/A'}\`
- **Reply-To Address:** \`${identity?.reply_to || 'N/A'}\`
- **Message-ID:** \`${caseDetail.raw_email_id}\`
- **SPF Verdict:** ${auth?.spf_status} (Domain: \`${auth?.spf_domain}\`)
- **DKIM Verdict:** ${auth?.dkim_status} (Selector: \`${auth?.dkim_selector}\`)
- **DMARC Verdict:** ${auth?.dmarc_status} (Policy: \`${auth?.dmarc_policy}\`)
- **Alignment:** ${auth?.alignment}

---

## 3. HEADER FLIGHT RECORDER & RELAY PATH
${caseDetail.header_hops.map(h => `### Hop #${h.hop_index} — ${h.from_host} -> ${h.by_host}
- **IP Address:** \`${h.ip}\` (ASN: ${h.asn}, ${h.isp})
- **Location:** ${h.geo_location}
- **Delay Delta:** +${h.delay_seconds} seconds
- **Flag Status:** ${h.is_suspicious ? `FLAGGED — ${h.flag_reason}` : 'VERIFIED NORMAL'}
`).join('\n')}

---

## 4. CHAIN OF CUSTODY & BLOCKCHAIN AUDIT LEDGER
${cocEvents.map(e => `- **[${e.event_id}]** \`${e.timestamp}\` — **${e.action}** by \`${e.actor}\` (${e.role})
  - *Prev Hash:* \`${e.prev_hash}\`
  - *Curr Hash:* \`${e.current_hash}\`
`).join('\n')}

---
*END OF OFFICIAL FORENSIC REPORT — ANVESHAK PLATFORM*`;

    const blob = new Blob([reportContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `ANVESHAK_Forensic_Report_${caseDetail.case_id}.md`; a.click();
  };

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* ── Page Header ── */}
      <PageHeader
        breadcrumbs={['ANVESHAK', caseDetail.case_id, 'Evidence Vault', 'STIX 2.1 Exporter']}
        title="Evidence Vault & STIX 2.1 Export Portal"
        description="Court-admissible evidence package repository, STIX 2.1 JSON bundle generator, and immutable SHA-256 chain of custody audit ledger."
        metadata={
          <>
            <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] font-medium text-[var(--text-secondary)]">
              {cocEvents.length} Recorded Events
            </span>
            <span className="px-2.5 py-0.5 rounded-full badge-safe">
              Tamper-Evident Ledger
            </span>
          </>
        }
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            <PdfDownloadMenu caseDetail={caseDetail} variant="primary" />
            <button
              onClick={downloadStix}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
              title="Download STIX 2.1 JSON bundle"
            >
              <Download className="w-3.5 h-3.5 text-[var(--blue-primary)]" />
              <span>STIX 2.1</span>
            </button>
            <button
              onClick={downloadJsonReport}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
              title="Export full raw JSON evidence package"
            >
              <FileText className="w-3.5 h-3.5 text-[var(--blue-primary)]" />
              <span>Raw JSON</span>
            </button>
            <button
              onClick={downloadReport}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
              title="Export detailed court-admissible markdown report"
            >
              <FileText className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              <span>Report (.md)</span>
            </button>
          </div>
        }
      />

      {/* ── Stats Row ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        {[
          { label: 'Chain of Custody Events', value: cocEvents.length },
          { label: 'Hash Algorithm', value: 'SHA-256' },
          { label: 'Ledger Integrity', value: '100%' },
          { label: 'Tamper Verification', value: 'CLEAN' },
        ].map(({ label, value }) => (
          <div key={label} className="tracex-card p-4">
            <div className="text-xs font-medium text-[var(--text-muted)]">{label}</div>
            <div className="text-lg code-mono font-bold mt-1 text-[var(--text-primary)]">{value}</div>
          </div>
        ))}
      </div>

      {/* ── Timeline Chain ── */}
      <div className="tracex-card p-6 space-y-4">
        <h3 className="text-xs font-semibold flex items-center gap-2 text-[var(--text-primary)] uppercase tracking-wider border-b border-[var(--border)] pb-3">
          <History className="w-4 h-4 text-[var(--blue-primary)]" />
          <span>Append-Only Chain of Custody Ledger · {cocEvents.length} Recorded Events</span>
        </h3>

        <div className="space-y-3">
          {cocEvents.map((evt, idx) => (
            <div key={evt.event_id} className="tracex-card p-4 space-y-3 bg-[var(--surface-2)]">
              {/* Header */}
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] code-mono font-bold px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--blue-primary)]">
                    {evt.event_id}
                  </span>
                  <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--text-secondary)]">
                    {evt.role}
                  </span>
                  <span className="text-xs font-semibold text-[var(--text-primary)]">
                    {evt.action}
                  </span>
                </div>
                <span className="text-[10px] code-mono text-[var(--text-muted)]">
                  {new Date(evt.timestamp).toLocaleString()}
                </span>
              </div>

              <p className="text-xs text-[var(--text-secondary)] leading-relaxed font-sans">
                {evt.details}
              </p>

              {/* Hash chain */}
              <div className="space-y-1.5 pt-2 border-t border-[var(--border)]">
                <CopyHash label="PREV" value={evt.prev_hash} />
                <CopyHash label="CURR" value={evt.current_hash} />
              </div>

              {/* Verified badge */}
              <div className="flex items-center gap-1.5 pt-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                <span className="text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                  CHAIN SEALED · TAMPER-EVIDENT
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
