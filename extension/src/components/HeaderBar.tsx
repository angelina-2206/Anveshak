import React from 'react';
import { ExternalLink } from 'lucide-react';
import { checkLocalhostRunning, LOCAL_WEB_BASE, PROD_WEB_BASE } from '../api/tracex-client';

interface HeaderBarProps {
  online?: boolean;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({ online = true }) => {
  const handleOpenWorkstation = async (e: React.MouseEvent) => {
    e.preventDefault();
    const isLocal = await checkLocalhostRunning();
    const targetUrl = isLocal ? LOCAL_WEB_BASE : PROD_WEB_BASE;
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  };

  return (
    <header className="flex items-center justify-between px-3.5 py-2.5 bg-white border-b border-slate-200 select-none shadow-[0_1px_2px_rgba(0,0,0,0.03)]">
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 flex items-center justify-center">
          <img src="/anveshak-logo.png" alt="ANVESHAK" className="w-full h-full object-contain" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-bold text-slate-900 tracking-wide">ANVESHAK</span>
            <span className="text-[10px] text-teal-700 font-sans font-semibold">Sensor</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1.5 text-[10px] text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
          <span className={`w-1.5 h-1.5 rounded-full ${online ? 'bg-emerald-500' : 'bg-rose-500'}`} />
          <span>{online ? 'Active' : 'Offline'}</span>
        </div>
        <a
          href="https://anveshak-xi.vercel.app/"
          onClick={handleOpenWorkstation}
          target="_blank"
          rel="noopener noreferrer"
          title="Open Anveshak Workstation"
          className="text-slate-500 hover:text-slate-900 transition-colors p-1 rounded hover:bg-slate-100"
        >
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>
    </header>
  );
};

