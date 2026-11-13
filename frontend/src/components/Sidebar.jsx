import React, { useState, useEffect } from 'react';
import { 
  Shield, LayoutDashboard, Terminal, Brain, Mail, Globe, 
  AlertOctagon, Target, Search, ShieldCheck, Bot, GitFork, 
  CheckSquare, Lock, Menu, X, ChevronRight, Activity
} from 'lucide-react';

const disabledModules = [
  { id: 2, name: 'AI Anomaly Detection', phase: 'Phase 2', icon: Brain },
  { id: 3, name: 'Phishing Protection', phase: 'Phase 3', icon: Mail },
  { id: 4, name: 'Malicious URL Intelligence', phase: 'Phase 4', icon: Globe },
  { id: 5, name: 'Cyber Risk Prediction', phase: 'Phase 6', icon: AlertOctagon },
  { id: 6, name: 'Vulnerability Prioritization', phase: 'Phase 4', icon: Target },
  { id: 7, name: 'Explainable Threat Analysis', phase: 'Phase 5', icon: Search },
  { id: 8, name: 'SOC Incident Management', phase: 'Phase 5', icon: ShieldCheck },
  { id: 9, name: 'AI Security Copilot', phase: 'Phase 7', icon: Bot },
  { id: 10, name: 'Attack Path Visualization', phase: 'Phase 6', icon: GitFork },
  { id: 11, name: 'Security Assumption Validation', phase: 'Phase 7', icon: CheckSquare },
];

export default function Sidebar({ currentSection = 'overview', onNavigate }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [activeSection, setActiveSection] = useState(currentSection);

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '') || 'overview';
      setActiveSection(hash);
    };

    window.addEventListener('hashchange', handleHashChange);
    handleHashChange();

    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleLinkClick = (section) => {
    setActiveSection(section);
    if (onNavigate) onNavigate(section);
    setMobileOpen(false);
  };

  return (
    <>
      {/* Mobile Toggle Button (Visible only on small screens) */}
      <button
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label="Toggle Navigation Sidebar"
        className="md:hidden fixed bottom-4 left-4 z-50 p-3 rounded-full bg-slate-900 border border-slate-700 text-cyan-400 shadow-xl shadow-cyan-950/50 hover:bg-slate-800 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
      >
        {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Mobile Backdrop Overlay */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 md:hidden"
        />
      )}

      {/* Fixed SOC Sidebar */}
      <aside
        className={`fixed top-0 left-0 bottom-0 w-64 bg-[#0c1322] border-r border-slate-800/90 z-40 flex flex-col justify-between transition-transform duration-200 ease-in-out md:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand / Logo Area */}
        <div>
          <div className="h-16 px-5 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="flex items-center space-x-1.5">
                  <span className="text-lg font-bold tracking-tight text-white">
                    Threat<span className="text-cyan-400">IQ</span>
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                    SOC
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 font-medium tracking-wide uppercase">Intelligence Console</p>
              </div>
            </div>

            <button
              onClick={() => setMobileOpen(false)}
              className="md:hidden text-slate-400 hover:text-white p-1 rounded-md"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Links */}
          <div className="px-3 py-4 space-y-6 overflow-y-auto max-h-[calc(100vh-8.5rem)]">
            {/* Active Operations Section */}
            <div>
              <div className="px-3 mb-2 flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <span>Operations</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              </div>

              <nav className="space-y-1">
                {/* Dashboard Link */}
                <a
                  href="#overview"
                  onClick={() => handleLinkClick('overview')}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    activeSection === 'overview'
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <LayoutDashboard className={`w-4 h-4 ${activeSection === 'overview' ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>Dashboard</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                    Live
                  </span>
                </a>

                {/* Log Monitoring Link */}
                <a
                  href="#events"
                  onClick={() => handleLinkClick('events')}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    activeSection === 'events'
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <Terminal className={`w-4 h-4 ${activeSection === 'events' ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>Log Monitoring</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-mono">
                    RFC 5424
                  </span>
                </a>
              </nav>
            </div>

            {/* Platform Modules (10 Disabled Modules) */}
            <div>
              <div className="px-3 mb-2 flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <span>Modules (Planned)</span>
                <span className="text-[10px] font-mono text-slate-600">10 Disabled</span>
              </div>

              <div className="space-y-1">
                {disabledModules.map((module) => {
                  const Icon = module.icon;
                  return (
                    <div
                      key={module.id}
                      aria-disabled="true"
                      title={`${module.name} (${module.phase}) — Planned for future development`}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-500 bg-slate-900/30 border border-transparent cursor-not-allowed select-none opacity-60"
                    >
                      <div className="flex items-center space-x-2.5 truncate mr-2">
                        <Icon className="w-4 h-4 text-slate-600 shrink-0" />
                        <span className="truncate">{module.name}</span>
                      </div>
                      <div className="flex items-center space-x-1 shrink-0">
                        <Lock className="w-3 h-3 text-slate-600" />
                        <span className="text-[9px] px-1 py-0.5 rounded bg-slate-800/80 text-slate-500 font-mono">
                          {module.phase}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer / Telemetry Status */}
        <div className="p-3 border-t border-slate-800/80 bg-[#090e18]">
          <div className="px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-800 text-[11px] space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center space-x-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>Syslog Ingest</span>
              </span>
              <span className="font-mono text-cyan-400 text-[10px]">UDP:5514</span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
              <span>Platform</span>
              <span className="text-slate-400">dev/foundation</span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}

