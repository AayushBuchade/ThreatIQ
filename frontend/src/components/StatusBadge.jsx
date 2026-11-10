import React from 'react';

const statusStyles = {
  'Completed': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  'In Progress': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse',
  'Upcoming': 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  'Blocked': 'bg-rose-500/10 text-rose-400 border-rose-500/30',
};

export default function StatusBadge({ status }) {
  const style = statusStyles[status] || statusStyles['Upcoming'];

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${style}`}>
      <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}

