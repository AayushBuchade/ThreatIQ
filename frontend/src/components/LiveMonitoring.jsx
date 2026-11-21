import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AlertCircle, Pause, Play, RefreshCw, Search, X } from 'lucide-react';
import { fetchEventAnomaly, fetchEventSummary, fetchRecentEvents } from '../services/api';

const PAGE_LIMIT = 100;
const REFRESH_MS = 5000;
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

const severityClass = {
  critical: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-200 border-amber-500/40',
  low: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
};

function formatTimestamp(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function SeverityPill({ severity }) {
  const style = severityClass[severity] || severityClass.low;
  return (
    <span className={`inline-flex px-2 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide ${style}`}>
      {severity || 'unknown'}
    </span>
  );
}

function CountCard({ label, value, tone, hint }) {
  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 min-w-0">
      <p className="text-[11px] uppercase tracking-wide text-slate-400">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${tone}`}>{value}</p>
      {hint && <p className="text-[10px] text-slate-500 mt-1">{hint}</p>}
    </div>
  );
}

export default function LiveMonitoring() {
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [events, setEvents] = useState([]);
  const [stored, setStored] = useState(null);
  const [matching, setMatching] = useState(null);
  const [selected, setSelected] = useState(null);
  const [paused, setPaused] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [assessments, setAssessments] = useState({});
  const assessmentsRef = useRef({});
  const anomalyRequests = useRef(new Set());
  useEffect(() => {
    assessmentsRef.current = assessments;
  }, [assessments]);

  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput.trim()), 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setRefreshing(true);
    try {
      const filters = {
        severity: severity || undefined,
        eventType: eventType.trim() || undefined,
        sourceIp: sourceIp.trim() || undefined,
        q: search || undefined,
      };
      const [storedSummary, matchSummary, recent] = await Promise.all([
        fetchEventSummary(),
        fetchEventSummary(filters),
        fetchRecentEvents({ ...filters, limit: PAGE_LIMIT }),
      ]);
      setStored(storedSummary);
      setMatching(matchSummary);
      setEvents(recent?.events || []);
      setError(null);
      setUpdatedAt(new Date());
      setSelected((current) => {
        if (!current) return current;
        return (recent?.events || []).find((event) => event.event_id === current.event_id) || current;
      });
    } catch (err) {
      setError(err.message || 'Unable to load events');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [severity, eventType, sourceIp, search]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (paused) return undefined;
    const timer = setInterval(() => load({ silent: true }), REFRESH_MS);
    return () => clearInterval(timer);
  }, [paused, load]);

  useEffect(() => {
    if (!selected) return undefined;
    const onKey = (event) => {
      if (event.key === 'Escape') setSelected(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selected]);

  useEffect(() => {
    const eventId = selected?.event_id;
    if (!eventId) return undefined;
    if (assessmentsRef.current[eventId] || anomalyRequests.current.has(eventId)) return undefined;
    anomalyRequests.current.add(eventId);
    setAssessments((current) => ({ ...current, [eventId]: { status: 'loading', evaluated: false } }));
    fetchEventAnomaly(eventId)
      .then((result) => {
        setAssessments((current) => ({ ...current, [eventId]: result }));
      })
      .catch((err) => {
        setAssessments((current) => ({
          ...current,
          [eventId]: { status: 'error', evaluated: false, detail: err.message },
        }));
      })
      .finally(() => {
        anomalyRequests.current.delete(eventId);
      });
    return undefined;
  }, [selected]);

  const filtersActive = Boolean(severity || eventType.trim() || sourceIp.trim() || search);
  const countsReady = stored !== null && matching !== null;
  const storedTotal = stored?.total ?? 0;
  const matchTotal = matching?.total ?? 0;
  const breakdown = stored?.by_severity || {};
  const pageNote = !countsReady
    ? 'Loading stored counts.'
    : matchTotal > events.length
      ? `Showing ${events.length} most recent of ${matchTotal} matching events. Older matches are not in this page.`
      : `Showing ${events.length} matching event${events.length === 1 ? '' : 's'}.`;
  const inventoryNote = !countsReady
    ? ''
    : filtersActive
      ? `${matchTotal} stored event${matchTotal === 1 ? ' matches' : 's match'} the current filters. `
      : `${storedTotal} stored event${storedTotal === 1 ? '' : 's'}. `;

  return (
    <section id="events" className="space-y-5 scroll-mt-20">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Live Monitoring</h1>
          <p className="text-sm text-slate-400 mt-1">
            Stored security events from the ingestion pipeline. Counts are database totals, not the size of this page.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-mono text-slate-500">
            {updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : 'Waiting for data'}
          </span>
          <button
            type="button"
            onClick={() => setPaused((value) => !value)}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700"
          >
            {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            onClick={() => load()}
            disabled={refreshing}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs text-white disabled:opacity-60"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-200 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}. The last successful table is still shown.</span>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <CountCard label="Stored events" value={loading && !stored ? '—' : storedTotal} tone="text-cyan-300" hint="All rows in the database" />
        <CountCard label="Critical" value={loading && !stored ? '—' : breakdown.critical ?? 0} tone="text-rose-300" hint="Stored inventory" />
        <CountCard label="High" value={loading && !stored ? '—' : breakdown.high ?? 0} tone="text-orange-300" hint="Stored inventory" />
        <CountCard label="Medium" value={loading && !stored ? '—' : breakdown.medium ?? 0} tone="text-amber-200" hint="Stored inventory" />
        <CountCard label="Low" value={loading && !stored ? '—' : breakdown.low ?? 0} tone="text-slate-200" hint="Stored inventory" />
      </div>

      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <label className="block text-xs text-slate-400">
            Search
            <span className="mt-1 flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2">
              <Search className="w-3.5 h-3.5 text-slate-500" />
              <input
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Message, event ID, type, or IP"
                className="w-full bg-transparent text-xs text-white focus:outline-none"
              />
            </span>
          </label>
          <label className="block text-xs text-slate-400">
            Severity
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              className="mt-1 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">All severities</option>
              {SEVERITIES.map((level) => (
                <option key={level} value={level}>{level}</option>
              ))}
            </select>
          </label>
          <label className="block text-xs text-slate-400">
            Event type
            <input
              value={eventType}
              onChange={(event) => setEventType(event.target.value)}
              placeholder="Contains, for example auth"
              className="mt-1 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            />
          </label>
          <label className="block text-xs text-slate-400">
            Source IP
            <input
              value={sourceIp}
              onChange={(event) => setSourceIp(event.target.value)}
              placeholder="Exact address"
              className="mt-1 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            />
          </label>
        </div>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-400">
          <p>
            {inventoryNote}
            {pageNote}
            {paused ? ' Auto-refresh is paused.' : ' Auto-refresh is every 5 seconds.'}
          </p>
          {filtersActive && (
            <button
              type="button"
              onClick={() => {
                setSeverity('');
                setEventType('');
                setSourceIp('');
                setSearchInput('');
                setSearch('');
              }}
              className="text-cyan-300 hover:text-cyan-200"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="hidden md:block overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Event type</th>
                <th className="px-4 py-3 font-medium">Source IP</th>
                <th className="px-4 py-3 font-medium">Message</th>
                <th className="px-4 py-3 font-medium">Event ID</th>
                <th className="px-4 py-3 font-medium">Anomaly</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-slate-500">
                    {loading ? 'Loading stored events…' : 'No stored events match these filters.'}
                  </td>
                </tr>
              ) : events.map((event) => (
                <tr
                  key={event.event_id}
                  onClick={() => setSelected(event)}
                  className="border-t border-slate-800 hover:bg-slate-800/50 cursor-pointer"
                >
                  <td className="px-4 py-3 whitespace-nowrap text-slate-300">{formatTimestamp(event.created_at)}</td>
                  <td className="px-4 py-3"><SeverityPill severity={event.severity} /></td>
                  <td className="px-4 py-3 font-mono text-cyan-300">{event.event_type}</td>
                  <td className="px-4 py-3 font-mono text-slate-300">{event.source_ip || '—'}</td>
                  <td className="px-4 py-3 text-slate-300 max-w-xs truncate">{event.message}</td>
                  <td className="px-4 py-3 font-mono text-slate-500">{event.event_id}</td>
                  <td className="px-4 py-3"><AnomalyPill assessment={assessments[event.event_id]} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="md:hidden divide-y divide-slate-800">
          {events.length === 0 ? (
            <p className="px-4 py-10 text-center text-xs text-slate-500">
              {loading ? 'Loading stored events…' : 'No stored events match these filters.'}
            </p>
          ) : events.map((event) => (
            <button
              key={event.event_id}
              type="button"
              onClick={() => setSelected(event)}
              className="w-full text-left px-4 py-3 space-y-1 hover:bg-slate-800/50"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-cyan-300">{event.event_type}</span>
                <SeverityPill severity={event.severity} />
              </div>
              <p className="text-xs text-slate-300">{event.message}</p>
              <p className="text-[11px] text-slate-500">{event.source_ip || 'No source IP'} · {formatTimestamp(event.created_at)}</p>
              <AnomalyPill assessment={assessments[event.event_id]} />
            </button>
          ))}
        </div>
      </div>

      {selected && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <button
            type="button"
            aria-label="Close investigation"
            className="absolute inset-0 bg-black/60"
            onClick={() => setSelected(null)}
          />
          <aside className="relative h-full w-full max-w-md bg-[#0c1322] border-l border-slate-800 shadow-2xl overflow-y-auto">
            <div className="sticky top-0 bg-[#0c1322]/95 backdrop-blur border-b border-slate-800 px-5 py-4 flex items-start justify-between gap-3">
              <div>
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Investigation</p>
                <h2 className="text-base font-semibold text-white mt-1">Event detail</h2>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4 text-sm">
              <div className="flex items-center gap-2">
                <SeverityPill severity={selected.severity} />
                <span className="font-mono text-xs text-cyan-300">{selected.event_type}</span>
              </div>
              <Detail label="Event ID" value={selected.event_id} mono />
              <Detail label="Database ID" value={String(selected.id)} mono />
              <Detail label="Status" value={selected.status || '—'} />
              <Detail label="Source IP" value={selected.source_ip || '—'} mono />
              <Detail label="Destination IP" value={selected.destination_ip || '—'} mono />
              <Detail
                label="Stored threat score"
                value={selected.threat_score === null || selected.threat_score === undefined ? '—' : String(selected.threat_score)}
              />
              <p className="text-[11px] text-slate-500 -mt-2">Saved at ingest. This is not the Isolation Forest score.</p>
              <AnomalyPanel assessment={assessments[selected.event_id]} />
              <Detail label="Created" value={formatTimestamp(selected.created_at)} />
              <Detail label="Updated" value={formatTimestamp(selected.updated_at)} />
              <div>
                <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Message</p>
                <p className="text-sm text-slate-200 whitespace-pre-wrap">{selected.message}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Attributes</p>
                {selected.attributes && Object.keys(selected.attributes).length > 0 ? (
                  <pre className="text-[11px] leading-relaxed font-mono text-slate-300 bg-slate-950 border border-slate-800 rounded-lg p-3 overflow-x-auto">
                    {JSON.stringify(selected.attributes, null, 2)}
                  </pre>
                ) : (
                  <p className="text-xs text-slate-500">No attributes stored.</p>
                )}
              </div>
            </div>
          </aside>
        </div>
      )}
    </section>
  );
}

function anomalyLabel(assessment) {
  if (!assessment || assessment.status === 'loading') return { text: 'Not evaluated', tone: 'bg-slate-800 text-slate-400 border-slate-700' };
  if (assessment.status === 'error') return { text: 'Not evaluated', tone: 'bg-slate-800 text-slate-400 border-slate-700' };
  if (!assessment.evaluated || assessment.status === 'insufficient_data') {
    return { text: 'Not evaluated', tone: 'bg-slate-800 text-slate-300 border-slate-600' };
  }
  if (assessment.status === 'anomalous') return { text: 'Anomalous', tone: 'bg-rose-500/15 text-rose-300 border-rose-500/40' };
  if (assessment.status === 'normal') return { text: 'Normal', tone: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40' };
  return { text: 'Not evaluated', tone: 'bg-slate-800 text-slate-400 border-slate-700' };
}

function AnomalyPill({ assessment }) {
  const label = anomalyLabel(assessment);
  return (
    <span className={`inline-flex px-2 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide ${label.tone}`}>
      {label.text}
    </span>
  );
}

function AnomalyPanel({ assessment }) {
  const label = anomalyLabel(assessment);
  const evaluated = Boolean(assessment?.evaluated);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] uppercase tracking-wide text-slate-500">Isolation Forest</p>
        <AnomalyPill assessment={assessment} />
      </div>
      <p className="text-xs text-slate-300">
        {evaluated ? 'Evaluated against earlier events only.' : 'Not evaluated. No anomaly decision was made.'}
      </p>
      {!assessment || assessment.status === 'loading' ? (
        <p className="text-xs text-slate-500">Scoring this event against stored history…</p>
      ) : null}
      {assessment?.status === 'error' ? (
        <p className="text-xs text-rose-300">{assessment.detail}</p>
      ) : null}
      {assessment && assessment.status !== 'loading' && assessment.status !== 'error' ? (
        <div className="space-y-2">
          <p className="text-xs text-slate-400">{assessment.detail}</p>
          <p className="text-[11px] font-mono text-slate-500">
            Model {assessment.model_version} · training events {assessment.training_events}/{assessment.minimum_training_events}
            {evaluated ? ` · score ${assessment.model_score}` : ''}
          </p>
          {evaluated && assessment.feature_evidence?.length > 0 ? (
            <div className="max-h-48 overflow-y-auto border border-slate-800 rounded-md">
              <table className="w-full text-left text-[11px]">
                <thead className="text-slate-500">
                  <tr>
                    <th className="px-2 py-1 font-medium">Feature</th>
                    <th className="px-2 py-1 font-medium">Value</th>
                    <th className="px-2 py-1 font-medium">Train mean</th>
                    <th className="px-2 py-1 font-medium">z</th>
                  </tr>
                </thead>
                <tbody>
                  {assessment.feature_evidence.map((feature) => (
                    <tr key={feature.name} className="border-t border-slate-800 text-slate-300">
                      <td className="px-2 py-1 font-mono">{feature.name}</td>
                      <td className="px-2 py-1 font-mono">{feature.value}</td>
                      <td className="px-2 py-1 font-mono">{feature.training_mean}</td>
                      <td className="px-2 py-1 font-mono">{feature.z_score === null || feature.z_score === undefined ? '—' : feature.z_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}
      <p className={`text-[10px] ${label.text === 'Anomalous' ? 'text-rose-300' : 'text-slate-500'}`}>
        This model result does not change severity or the stored threat score.
      </p>
    </div>
  );
}

function Detail({ label, value, mono = false }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`text-sm text-slate-200 break-all ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  );
}
