import React from 'react';
import { Shield, Activity, Terminal, Database } from 'lucide-react';

export default function Navbar({ systemHealthy }) {
  return (
    <header className="border-b border-slate-800 bg-[#0c1322]/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xl font-bold tracking-tight text-white">Threat<span className="text-cyan-400">IQ</span></span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">v0.1.0</span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">AI Cybersecurity Detection & SOC Intelligence</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800">
            <span className="text-slate-400">Phase:</span>
            <span className="font-semibold text-cyan-400">Phase 0 (Foundation)</span>
          </div>

          <div className="flex items-center space-x-2">
            <span className="relative flex h-2.5 w-2.5">
              {systemHealthy ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                </>
              ) : (
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-500"></span>
              )}
            </span>
            <span className="text-xs font-medium text-slate-300">
              {systemHealthy ? 'SOC Online' : 'Connecting...'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
