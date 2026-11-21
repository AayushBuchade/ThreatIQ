import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import SystemHealthCard from './components/SystemHealthCard';
import ModuleStatusGrid from './components/ModuleStatusGrid';
import TelemetryFeed from './components/TelemetryFeed';
import LiveMonitoring from './components/LiveMonitoring';
import { fetchHealth, fetchSystemStatus, fetchModules, fetchEventSummary } from './services/api';
import { AlertCircle, RefreshCw } from 'lucide-react';

function useSection() {
  const read = () => window.location.hash.replace('#', '') || 'overview';
  const [section, setSection] = useState(read);

  useEffect(() => {
    const onChange = () => setSection(read());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  return section;
}

export default function App() {
  const section = useSection();
  const [healthData, setHealthData] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [modules, setModules] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadOverview = async () => {
    setLoading(true);
    setError(null);
    try {
      const [hData, sData, mData, summaryData] = await Promise.all([
        fetchHealth().catch(e => ({ status: 'error', error: e.message })),
        fetchSystemStatus().catch(() => null),
        fetchModules().catch(() => ({ modules: [] })),
        fetchEventSummary().catch(() => null),
      ]);

      setHealthData(hData);
      setSystemStatus(sData);
      setModules(mData?.modules || []);
      setSummary(summaryData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
    const interval = setInterval(loadOverview, 15000);
    return () => clearInterval(interval);
  }, []);

  const breakdown = summary?.by_severity || {};

  return (
    <div className="min-h-screen bg-[#0a0f1d] flex text-slate-200">
      <Sidebar />

      <div className="flex-1 flex flex-col min-w-0 md:pl-64">
        <Navbar systemHealthy={healthData?.status === 'ok'} />

        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {section === 'events' && <LiveMonitoring />}

          {section === 'developer' && (
            <section className="space-y-4">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">Developer verification</h1>
                <p className="text-sm text-slate-400 mt-1">
                  Test-event controls stay off the live monitoring view. Submitted events are real database rows and appear in Live Monitoring.
                </p>
              </div>
              <TelemetryFeed onEventCreated={loadOverview} />
            </section>
          )}

          {section !== 'events' && section !== 'developer' && (
            <div className="space-y-6">
              <div id="overview" className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4 scroll-mt-20">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                    SOC Intelligence Dashboard
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                      Phase 1
                    </span>
                  </h1>
                  <p className="text-sm text-slate-400 mt-1">
                    ThreatIQ detection and monitoring console. Open Live Monitoring for the event table.
                  </p>
                </div>

                <button
                  onClick={loadOverview}
                  disabled={loading}
                  className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors border border-slate-700"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                  <span>Sync Status</span>
                </button>
              </div>

              {error && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>Connection error: {error}</span>
                </div>
              )}

              <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
                {[
                  ['Stored events', summary ? summary.total : '—', 'text-cyan-300'],
                  ['Critical', summary ? breakdown.critical ?? 0 : '—', 'text-rose-300'],
                  ['High', summary ? breakdown.high ?? 0 : '—', 'text-orange-300'],
                  ['Medium', summary ? breakdown.medium ?? 0 : '—', 'text-amber-200'],
                  ['Low', summary ? breakdown.low ?? 0 : '—', 'text-slate-200'],
                ].map(([label, value, color]) => (
                  <div key={label} className="bg-[#111827] border border-slate-800 rounded-xl p-4">
                    <p className="text-[11px] uppercase tracking-wide text-slate-400">{label}</p>
                    <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
                    <p className="text-[10px] text-slate-500 mt-1">Database total</p>
                  </div>
                ))}
              </div>

              <SystemHealthCard
                healthData={healthData}
                systemStatus={systemStatus}
                loading={loading}
                onRefresh={loadOverview}
              />

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-slate-800 rounded-xl px-5 py-4">
                <div>
                  <p className="text-sm text-white font-medium">Live event monitoring</p>
                  <p className="text-xs text-slate-400 mt-1">Search, filter, and investigate stored events. The table refreshes every 5 seconds.</p>
                </div>
                <a
                  href="#events"
                  className="inline-flex justify-center px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium text-white"
                >
                  Open Live Monitoring
                </a>
              </div>

              <ModuleStatusGrid modules={modules} />
            </div>
          )}
        </main>

        <footer className="border-t border-slate-800/80 bg-[#0c1322]/50 py-4 text-center text-xs text-slate-500">
          ThreatIQ Platform Foundation • Branch: <code className="text-cyan-400">dev/foundation</code> • Built with FastAPI, PostgreSQL, React & Tailwind
        </footer>
      </div>
    </div>
  );
}
