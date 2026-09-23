import React, { useState, useEffect } from 'react';
import { TopNav } from './components/layout/TopNav';
import { CaseDesk } from './components/case/CaseDesk';
import { EmailForensics } from './components/forensics/EmailForensics';
import { HeaderFlightRecorder } from './components/forensics/HeaderFlightRecorder';
import { IdentityDeceptionView } from './components/forensics/IdentityDeceptionView';
import { SocialEngineeringView } from './components/forensics/SocialEngineeringView';
import { UrlRedirectTracer } from './components/forensics/UrlRedirectTracer';
import { AttackGraphView } from './components/graph/AttackGraphView';
import { CampaignIntelligenceView } from './components/campaign/CampaignIntelligenceView';
import { GeoFinancialMapView } from './components/geo/GeoFinancialMapView';
import { ImpactLabView } from './components/lab/ImpactLabView';
import { ForensicRagCopilotView } from './components/ai/ForensicRagCopilotView';
import { EvidenceVaultView } from './components/vault/EvidenceVaultView';
import { ExecutiveRiskView } from './components/executive/ExecutiveRiskView';
import { BlockchainProofView } from './components/blockchain/BlockchainProofView';
import { AttachmentSandboxView } from './components/sandbox/AttachmentSandboxView';
import { InvestigationDrawer, EntityDetail } from './components/layout/InvestigationDrawer';
import { CaseTimelineBar } from './components/layout/CaseTimelineBar';
import { LandingPage } from './components/layout/LandingPage';
import { CaseDetail, UserRole } from './types';
import { ThemeProvider } from './context/ThemeContext';

import { API_BASE_URL } from './config/api';

const MainApp: React.FC = () => {
  const [showLanding, setShowLanding] = useState<boolean>(true);
  const [cases, setCases] = useState<CaseDetail[]>([]);
  const [activeCase, setActiveCase] = useState<CaseDetail | null>(null);
  const [activeTab, setActiveTab] = useState<string>('case_desk');
  const [currentRole, setCurrentRole] = useState<UserRole>('SOC_ANALYST');
  const [voiceActive, setVoiceActive] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedEntity, setSelectedEntity] = useState<EntityDetail | null>(null);

  const fetchCases = async () => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const deepLinkCaseId = urlParams.get('case') || urlParams.get('investigate');
      const deepLinkTab = urlParams.get('tab');

      const res = await fetch(`${API_BASE_URL}/api/v1/cases`);
      const summaries = await res.json();
      
      if (summaries.length > 0) {
        const allDetails = await Promise.all(
          summaries.map((s: any) => fetch(`${API_BASE_URL}/api/v1/cases/${s.case_id}`).then(r => r.json()))
        );
        setCases(allDetails);

        if (deepLinkCaseId) {
          const matched = allDetails.find((c: CaseDetail) => c.case_id.toLowerCase() === deepLinkCaseId.toLowerCase());
          if (matched) {
            setActiveCase(matched);
            setShowLanding(false);
            if (deepLinkTab) setActiveTab(deepLinkTab);
            else setActiveTab('email_forensics');
            return;
          } else {
            // Fetch case directly in case it was just captured by extension
            try {
              const singleRes = await fetch(`${API_BASE_URL}/api/v1/cases/${deepLinkCaseId.toUpperCase()}`);
              if (singleRes.ok) {
                const singleDetail = await singleRes.json();
                setActiveCase(singleDetail);
                setCases(prev => [singleDetail, ...prev.filter(c => c.case_id !== singleDetail.case_id)]);
                setShowLanding(false);
                if (deepLinkTab) setActiveTab(deepLinkTab);
                else setActiveTab('email_forensics');
                return;
              }
            } catch (err) {
              console.error("Deep link fetch error:", err);
            }
          }
        }
        
        if (deepLinkTab) {
          setShowLanding(false);
          setActiveTab(deepLinkTab);
        }

        if (!activeCase) {
          setActiveCase(allDetails[0]);
        }
      }
    } catch (e) {
      console.error("Error fetching cases:", e);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleSelectCase = (c: CaseDetail) => {
    setActiveCase(c);
    setActiveTab('email_forensics');
  };

  const handleIngestNewEmail = async (file: File | null, rawText: string) => {
    setLoading(true);
    try {
      const textContent = file ? await file.text() : rawText;
      const res = await fetch(`${API_BASE_URL}/api/v1/ingest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eml_content: textContent }),
      });
      const result = await res.json();
      await fetchCases();
      if (result.case_id) {
        const newDetailRes = await fetch(`${API_BASE_URL}/api/v1/cases/${result.case_id}`);
        const newDetail = await newDetailRes.json();
        setActiveCase(newDetail);
        setActiveTab('email_forensics');
      }
    } catch (e) {
      console.error("Ingest failed:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleEnterWorkspace = (initialTab?: string, initialRole?: UserRole) => {
    setShowLanding(false);
    if (initialRole) {
      setCurrentRole(initialRole);
    }
    if (initialTab) {
      setActiveTab(initialTab);
    }
  };

  if (showLanding) {
    return <LandingPage onEnterWorkspace={handleEnterWorkspace} />;
  }

  return (
    <div className="min-h-screen flex flex-col font-sans antialiased bg-[var(--canvas-bg)] text-[var(--text-primary)] relative overflow-x-hidden">
      <TopNav
        currentRole={currentRole}
        setCurrentRole={setCurrentRole}
        activeCase={activeCase}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        voiceActive={voiceActive}
        setVoiceActive={setVoiceActive}
      />

      <div className="flex-1 flex flex-col min-h-0 relative z-10">
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 flex flex-col min-h-0">
            {/* Active Case Header Strip */}
            {activeCase && (
              <div className="bg-[var(--surface-2)] border-b border-[var(--border)] px-6 py-2 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <span className="font-semibold text-[var(--text-primary)]">{activeCase.case_id}</span>
                  <span className="text-[var(--text-muted)]">•</span>
                  <span className="text-[var(--text-secondary)] font-medium truncate max-w-xl">
                    {activeCase.email_subject || activeCase.case_id}
                  </span>
                </div>
                <button
                  onClick={() => setActiveTab('case_desk')}
                  className="text-xs text-[var(--blue-primary)] hover:underline font-semibold"
                >
                  Switch Active Case
                </button>
              </div>
            )}

            {/* Investigation View Canvas */}
            <main className="flex-1 overflow-y-auto p-6 md:p-8 max-w-7xl mx-auto w-full">
              <div key={activeTab} className="animate-fade-in h-full">
                {activeTab === 'case_desk' && (
                  <CaseDesk
                    cases={cases}
                    activeCase={activeCase}
                    onSelectCase={handleSelectCase}
                    onIngestNewEmail={handleIngestNewEmail}
                    loading={loading}
                    onSelectTab={setActiveTab}
                  />
                )}

                {(() => {
                  const currentCase = activeCase || cases[0];
                  if (!currentCase) return null;

                  return (
                    <>
                      {activeTab === 'email_forensics' && <EmailForensics caseDetail={currentCase} onSelectTab={setActiveTab} />}
                      {activeTab === 'header_recorder' && <HeaderFlightRecorder caseDetail={currentCase} />}
                      {activeTab === 'identity_deception' && <IdentityDeceptionView caseDetail={currentCase} />}
                      {activeTab === 'social_engineering' && <SocialEngineeringView caseDetail={currentCase} />}
                      {activeTab === 'url_tracer' && <UrlRedirectTracer caseDetail={currentCase} />}
                      {activeTab === 'attachment_sandbox' && <AttachmentSandboxView caseDetail={currentCase} />}
                      {activeTab === 'attack_graph' && <AttackGraphView caseDetail={currentCase} />}
                      {activeTab === 'campaign_intel' && <CampaignIntelligenceView caseDetail={currentCase} onSelectTab={setActiveTab} />}
                      {activeTab === 'geo_financial' && <GeoFinancialMapView caseDetail={currentCase} />}
                      {activeTab === 'impact_lab' && <ImpactLabView caseDetail={currentCase} />}
                      {activeTab === 'ai_copilot' && <ForensicRagCopilotView caseDetail={currentCase} voiceActive={voiceActive} />}
                      {activeTab === 'blockchain_proof' && <BlockchainProofView caseDetail={currentCase} />}
                      {activeTab === 'evidence_vault' && <EvidenceVaultView caseDetail={currentCase} />}
                      {activeTab === 'executive_risk' && <ExecutiveRiskView caseDetail={currentCase} />}
                    </>
                  );
                })()}
              </div>
            </main>

            {activeCase && (
              <CaseTimelineBar
                activeCase={activeCase}
                onNavigateToTab={setActiveTab}
              />
            )}
          </div>
        </div>
      </div>

      <InvestigationDrawer
        entity={selectedEntity}
        onClose={() => setSelectedEntity(null)}
        onNavigateToModule={setActiveTab}
      />
    </div>
  );
};

export const App: React.FC = () => (
  <ThemeProvider>
    <MainApp />
  </ThemeProvider>
);

export default App;
