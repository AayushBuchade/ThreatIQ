import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import SystemHealthCard from './components/SystemHealthCard';
import ModuleStatusGrid from './components/ModuleStatusGrid';
import TelemetryFeed from './components/TelemetryFeed';
import { fetchHealth, fetchSystemStatus, fetchModules, fetchRecentEvents } from './services/api';
import { Shield, Layers, ListFilter, AlertCircle, RefreshCw } from 'lucide-react';

export default function App() {
  const [healthData, setHealthData] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [modules, setModules] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadAllData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [hData, sData, mData, eData] = await Promise.all([
        fetchHealth().catch(e => ({ status: 'error', error: e.message })),
        fetchSystemStatus().catch(e => null),
        fetchModules().catch(e => ({ modules: [] })),
        fetchRecentEvents().catch(e => ({ events: [] }))
      ]);

      setHealthData(hData);
      setSystemStatus(sData);
      setModules(mData?.modules || []);
      setRecentEvents(eData?.events || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0f1d] flex text-slate-200">
      <Sidebar />

      <div className="flex-1 flex flex-col min-w-0 md:pl-64">
        <Navbar systemHealthy={healthData?.status === 'ok'} />

        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
          {/* Header Banner */}
          <div id="overview" className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4 scroll-mt-20">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                SOC Intelligence Dashboard
                <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  Phase 0 Verified
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-1">
                ThreatIQ Unified AI-Powered Cybersecurity Detection & SOC Intelligence Foundation
              </p>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={loadAllData}
                disabled={loading}
                className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors border border-slate-700"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                <span>Sync Status</span>
              </button>
            </div>
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>Connection error: {error}</span>
            </div>
          )}

          {/* System Health */}
          <SystemHealthCard
            healthData={healthData}
            systemStatus={systemStatus}
            loading={loading}
            onRefresh={loadAllData}
          />

          {/* Full-Stack Telemetry Verification Test Card */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <TelemetryFeed onEventCreated={loadAllData} />

            {/* Recent Ingested Events Card */}
            <div id="events" className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-sm scroll-mt-20">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                  <ListFilter className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-base font-semibold text-white">Live Event Log (PostgreSQL)</h2>
                </div>
                <span className="text-xs font-mono text-slate-500">{recentEvents.length} Recent Records</span>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Real records persisted in PostgreSQL via SQLAlchemy 2.0 ORM:
              </p>

              <div className="space-y-2 max-h-[185px] overflow-y-auto pr-1">
                {recentEvents.length === 0 ? (
                  <div className="text-center py-8 text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                    No telemetry events dispatched yet. Use the console on the left to send an event.
                  </div>
                ) : (
                  recentEvents.map((evt) => (
                    <div
                      key={evt.id}
                      className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-cyan-400">{evt.event_type}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            evt.severity === 'critical' ? 'bg-rose-500/20 text-rose-400' :
                            evt.severity === 'high' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>
                            {evt.severity}
                          </span>
                        </div>
                        <div className="text-slate-400 text-[11px] mt-0.5">
                          Source: {evt.source_ip || 'N/A'} — {evt.message}
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(evt.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* 12 Platform Modules Grid */}
          <ModuleStatusGrid modules={modules} />
        </main>

        {/* Footer */}
        <footer className="border-t border-slate-800/80 bg-[#0c1322]/50 py-4 text-center text-xs text-slate-500">
          ThreatIQ Platform Foundation • Branch: <code className="text-cyan-400">dev/foundation</code> • Built with FastAPI, PostgreSQL, React & Tailwind
        </footer>
      </div>
    </div>
  );
}

