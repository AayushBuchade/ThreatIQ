import React from 'react';
import { Server, Database, Activity, Cpu, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function SystemHealthCard({ healthData, systemStatus, loading, onRefresh }) {
  const isHealthy = healthData?.status === 'ok';
  const dbConnected = healthData?.database === 'connected';

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-white">System Infrastructure Health</h2>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors disabled:opacity-50"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Backend Status */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400">FastAPI Gateway</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-center space-x-1.5 mt-2">
            {isHealthy ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
            <span className="text-sm font-semibold text-white">
              {isHealthy ? 'Operational' : 'Unavailable'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">REST & ASGI Engine</p>
        </div>

        {/* Database Status */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400">PostgreSQL Relational DB</span>
            <Database className="w-4 h-4 text-blue-400" />
          </div>
          <div className="flex items-center space-x-1.5 mt-2">
            {dbConnected ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
            <span className="text-sm font-semibold text-white">
              {dbConnected ? 'Connected & Verified' : 'Checking Connection'}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">SQLAlchemy 2.0 / Alembic</p>
        </div>

        {/* Environment */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400">Target Environment</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-sm font-semibold text-white mt-2 capitalize">
            {systemStatus?.environment || 'Development'}
          </div>
          <p className="text-xs text-slate-500 mt-1">Branch: dev/foundation</p>
        </div>

        {/* Uptime */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400">System Uptime</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-sm font-semibold text-white mt-2">
            {systemStatus?.uptime_seconds ? `${Math.floor(systemStatus.uptime_seconds)} sec` : 'Active'}
          </div>
          <p className="text-xs text-slate-500 mt-1">Latency: {healthData?.response_time_ms ? `${healthData.response_time_ms}ms` : '< 5ms'}</p>
        </div>
      </div>
    </div>
  );
}

