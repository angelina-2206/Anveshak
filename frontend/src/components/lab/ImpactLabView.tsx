import React, { useState, useEffect } from 'react';
import { Sliders, RefreshCw, ArrowRight, ShieldCheck, AlertTriangle } from 'lucide-react';
import { CaseDetail } from '../../types';
import { PageHeader } from '../common/PageHeader';
import { API_BASE_URL } from '../../config/api';

interface ImpactLabViewProps {
  caseDetail: CaseDetail;
}

export const ImpactLabView: React.FC<ImpactLabViewProps> = ({ caseDetail }) => {
  const [removeUrl, setRemoveUrl] = useState(false);
  const [assumeSpfPass, setAssumeSpfPass] = useState(false);
  const [disconnectCampaign, setDisconnectCampaign] = useState(false);
  const [removeReplyMismatch, setRemoveReplyMismatch] = useState(false);
  
  const [simulatedResult, setSimulatedResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const runSimulation = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/cases/${caseDetail.case_id}/impact-lab?remove_url=${removeUrl}&assume_spf_pass=${assumeSpfPass}&disconnect_campaign=${disconnectCampaign}&remove_reply_mismatch=${removeReplyMismatch}`, {
        method: 'POST'
      });
      const data = await res.json();
      setSimulatedResult(data);
    } catch (e) {
      console.error("Impact lab simulation error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runSimulation();
  }, [removeUrl, assumeSpfPass, disconnectCampaign, removeReplyMismatch, caseDetail.case_id]);

  const originalScore = caseDetail.threat_score.overall_score;

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      {/* ── Page Header ── */}
      <PageHeader
        breadcrumbs={['ANVESHAK', caseDetail.case_id, 'Risk Modeling', 'Impact Lab']}
        title="ANVESHAK Impact Lab — Counterfactual Risk Sensitivity"
        description="Simulate hypothetical counterfactual scenarios ('What if SPF passed?', 'What if suspicious URL is removed?') to isolate exact threat score drivers."
        metadata={
          <>
            <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] font-medium text-[var(--text-secondary)]">
              Baseline Score: {originalScore.toFixed(1)}/100
            </span>
            <span className="px-2.5 py-0.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] font-medium text-[var(--text-secondary)]">
              Real-time Counterfactual Engine
            </span>
          </>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Counterfactual Switches (Left 2 columns) */}
        <div className="lg:col-span-2 tracex-card p-6 space-y-5 text-xs">
          <h3 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border)] pb-2">
            Hypothetical Evidence Modifiers
          </h3>

          <div className="space-y-3">
            <div className="p-4 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-between">
              <div>
                <div className="font-semibold text-sm text-[var(--text-primary)]">Remove Suspicious URL & Redirect Chain</div>
                <div className="text-xs text-[var(--text-muted)] mt-0.5">Hypothesize email contains no external redirect links or shortened URLs.</div>
              </div>
              <input
                type="checkbox"
                checked={removeUrl}
                onChange={(e) => setRemoveUrl(e.target.checked)}
                className="w-5 h-5 accent-[var(--blue-primary)] cursor-pointer"
              />
            </div>

            <div className="p-4 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-between">
              <div>
                <div className="font-semibold text-sm text-[var(--text-primary)]">Assume SPF Authentication PASS</div>
                <div className="text-xs text-[var(--text-muted)] mt-0.5">Hypothesize sender infrastructure passed SPF domain verification.</div>
              </div>
              <input
                type="checkbox"
                checked={assumeSpfPass}
                onChange={(e) => setAssumeSpfPass(e.target.checked)}
                className="w-5 h-5 accent-[var(--blue-primary)] cursor-pointer"
              />
            </div>

            <div className="p-4 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-between">
              <div>
                <div className="font-semibold text-sm text-[var(--text-primary)]">Disconnect Historical Campaign Correlation</div>
                <div className="text-xs text-[var(--text-muted)] mt-0.5">Hypothesize case has no historical campaign memory overlap or shared ASN.</div>
              </div>
              <input
                type="checkbox"
                checked={disconnectCampaign}
                onChange={(e) => setDisconnectCampaign(e.target.checked)}
                className="w-5 h-5 accent-[var(--blue-primary)] cursor-pointer"
              />
            </div>

            <div className="p-4 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-between">
              <div>
                <div className="font-semibold text-sm text-[var(--text-primary)]">Align Reply-To Domain with Visible Sender</div>
                <div className="text-xs text-[var(--text-muted)] mt-0.5">Hypothesize Reply-To domain perfectly matches visible From header.</div>
              </div>
              <input
                type="checkbox"
                checked={removeReplyMismatch}
                onChange={(e) => setRemoveReplyMismatch(e.target.checked)}
                className="w-5 h-5 accent-[var(--blue-primary)] cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Dynamic Threat Score Delta Display (Right column) */}
        <div className="tracex-card p-6 flex flex-col justify-between text-xs">
          <div>
            <h3 className="text-xs font-semibold text-[var(--blue-primary)] uppercase tracking-wider border-b border-[var(--border)] pb-2">
              Simulated Threat Score Delta
            </h3>

            <div className="py-8 space-y-5 text-center">
              <div className="flex items-center justify-center space-x-6">
                <div>
                  <div className="text-[10px] uppercase font-bold text-[var(--text-muted)]">Actual Score</div>
                  <div className="text-3xl font-bold code-mono text-rose-600 dark:text-rose-400 mt-1">
                    {originalScore.toFixed(1)}
                  </div>
                </div>

                <ArrowRight className="w-6 h-6 text-[var(--text-muted)]" />

                <div>
                  <div className="text-[10px] uppercase font-bold text-[var(--text-muted)]">Simulated Score</div>
                  <div className="text-3xl font-bold code-mono text-[var(--blue-primary)] mt-1">
                    {simulatedResult ? simulatedResult.simulated_score.toFixed(1) : originalScore.toFixed(1)}
                  </div>
                </div>
              </div>

              {simulatedResult && (
                <div className="p-4 rounded-lg bg-[var(--surface-2)] border border-[var(--border)]">
                  <div className="text-xs font-medium text-[var(--text-muted)] uppercase">Net Risk Impact</div>
                  <div className="text-lg font-bold code-mono text-emerald-600 dark:text-emerald-400 mt-1">
                    {(simulatedResult.simulated_score - originalScore).toFixed(1)} Points
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
