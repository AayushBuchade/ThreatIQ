import React, { useState } from 'react';
import { AlertCircle, Mail } from 'lucide-react';
import { analyzeEmail } from '../services/api';

export default function PhishingAnalysis() {
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [body, setBody] = useState('');
  const [record, setRecord] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    if (!body.trim()) {
      setError('Email body is empty.');
      setResult(null);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const data = await analyzeEmail({
        subject,
        sender,
        body,
        record,
      });
      setResult(data);
    } catch (err) {
      setResult(null);
      setError(err.message || 'Email analysis failed. No prediction was returned.');
    } finally {
      setBusy(false);
    }
  };

  const phishing = result?.prediction === 'phishing';

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Email analysis</h1>
        <p className="text-sm text-slate-400 mt-1">
          Local PHISHGUARD classifier. The number shown is the calibrated phishing probability, not a separate confidence score. The mail extension at extension/mail uses this same API.
        </p>
      </div>

      <form onSubmit={submit} className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label className="block text-xs text-slate-400">
            Subject
            <input
              value={subject}
              onChange={(event) => setSubject(event.target.value)}
              className="mt-1 w-full rounded-lg bg-[#0a0f1d] border border-slate-700 px-3 py-2 text-sm text-slate-100"
            />
          </label>
          <label className="block text-xs text-slate-400">
            Sender
            <input
              value={sender}
              onChange={(event) => setSender(event.target.value)}
              className="mt-1 w-full rounded-lg bg-[#0a0f1d] border border-slate-700 px-3 py-2 text-sm text-slate-100"
            />
          </label>
        </div>
        <label className="block text-xs text-slate-400">
          Body
          <textarea
            value={body}
            onChange={(event) => setBody(event.target.value)}
            rows={8}
            required
            className="mt-1 w-full rounded-lg bg-[#0a0f1d] border border-slate-700 px-3 py-2 text-sm text-slate-100"
          />
        </label>
        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={record}
            onChange={(event) => setRecord(event.target.checked)}
            className="accent-cyan-500"
          />
          Record this analysis in security events
        </label>
        <button
          type="submit"
          disabled={busy}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-60 text-sm font-medium text-white"
        >
          <Mail className="w-4 h-4" />
          {busy ? 'Analyzing…' : 'Analyze email'}
        </button>
      </form>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm flex items-start gap-2">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Model prediction</p>
              <p className={`text-xl font-semibold mt-1 ${phishing ? 'text-rose-300' : 'text-emerald-300'}`}>
                {result.prediction}
              </p>
            </div>
            <div className="text-right">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Phishing probability</p>
              <p className="text-xl font-mono text-slate-100 mt-1">{result.phishing_probability}</p>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Model {result.model_version} · {result.model_name} · scikit-learn {result.sklearn_version}
          </p>
          <p className="text-xs text-slate-500">{result.attribution_note}</p>
          {result.token_contributions?.length > 0 && (
            <div>
              <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Largest linear token contributions</p>
              <ul className="space-y-1">
                {result.token_contributions.map((item) => (
                  <li key={item.token} className="flex items-center justify-between text-xs font-mono text-slate-300">
                    <span>{item.token}</span>
                    <span className={item.contribution > 0 ? 'text-rose-300' : 'text-emerald-300'}>
                      {item.contribution}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {result.event_id && (
            <p className="text-xs text-slate-400">
              {result.duplicate
                ? `Already recorded as ${result.event_id}. No second event was created.`
                : `Recorded as ${result.event_id}.`}
            </p>
          )}
          {result.record_error && <p className="text-xs text-rose-300">{result.record_error}</p>}
        </div>
      )}
    </section>
  );
}
