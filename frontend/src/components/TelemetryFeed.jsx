import React, { useState } from 'react';
import { Send, CheckCircle2, AlertCircle, Database, ArrowRight } from 'lucide-react';
import { sendTelemetryPing } from '../services/api';

export default function TelemetryFeed({ onEventCreated }) {
  const [eventType, setEventType] = useState('auth.login.failed');
  const [severity, setSeverity] = useState('medium');
  const [sourceIp, setSourceIp] = useState('192.168.1.105');
  const [statusMsg, setStatusMsg] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setStatusMsg(null);

    const payload = {
      event_type: eventType,
      severity: severity,
      source_ip: sourceIp,
      message: `Simulated ${eventType} trigger from SOC telemetry test console`,
      attributes: {
        user_agent: 'ThreatIQ-UI/1.0',
        origin: 'frontend-test-console'
      }
    };

    try {
      const result = await sendTelemetryPing(payload);
      setStatusMsg({
        success: true,
        message: `Event successfully committed to PostgreSQL database! ID: ${result.event_id} (Roundtrip: ${result.db_roundtrip_ms}ms)`
      });
      if (onEventCreated) onEventCreated();
    } catch (err) {
      setStatusMsg({
        success: false,
        message: `Integration ping failed: ${err.message}`
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-sm">
      <div className="flex items-center space-x-2 mb-2">
        <Database className="w-5 h-5 text-cyan-400" />
        <h2 className="text-base font-semibold text-white">Full-Stack Integration Verification</h2>
      </div>
      <p className="text-xs text-slate-400 mb-4">
        Dispatch a test telemetry event: React Frontend <span className="text-cyan-400">→</span> FastAPI Gateway <span className="text-cyan-400">→</span> PostgreSQL Database.
      </p>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Event Type</label>
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full text-xs bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="auth.login.failed">auth.login.failed</option>
              <option value="network.port_scan">network.port_scan</option>
              <option value="endpoint.malware_heuristic">endpoint.malware_heuristic</option>
              <option value="email.phishing_suspicion">email.phishing_suspicion</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full text-xs bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Source IP</label>
            <input
              type="text"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              className="w-full text-xs bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              placeholder="192.168.1.1"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={isSubmitting}
          className="inline-flex items-center space-x-2 text-xs font-medium px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors disabled:opacity-50"
        >
          <Send className="w-3.5 h-3.5" />
          <span>{isSubmitting ? 'Transmitting to Database...' : 'Dispatch End-to-End Test Event'}</span>
        </button>
      </form>

      {statusMsg && (
        <div className={`mt-4 p-3 rounded-lg border text-xs flex items-start space-x-2 ${
          statusMsg.success 
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
            : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
        }`}>
          {statusMsg.success ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          )}
          <span>{statusMsg.message}</span>
        </div>
      )}
    </div>
  );
}
