import React from 'react';
import StatusBadge from './StatusBadge';
import { 
  FileText, Brain, Mail, Globe, AlertOctagon, 
  Target, Search, ShieldCheck, Bot, GitFork, 
  CheckSquare, TrendingUp 
} from 'lucide-react';

const moduleIcons = {
  1: FileText,
  2: Brain,
  3: Mail,
  4: Globe,
  5: AlertOctagon,
  6: Target,
  7: Search,
  8: ShieldCheck,
  9: Bot,
  10: GitFork,
  11: CheckSquare,
  12: TrendingUp,
};

export default function ModuleStatusGrid({ modules }) {
  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-semibold text-white">ThreatIQ 12 Platform Modules</h2>
          <p className="text-xs text-slate-400">Roadmap and implementation lifecycle status across platform tiers</p>
        </div>
        <span className="text-xs text-cyan-400 font-mono">12 Total Modules</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modules.map((m) => {
          const Icon = moduleIcons[m.id] || FileText;
          return (
            <div 
              key={m.id}
              className="p-4 rounded-lg bg-slate-900/70 border border-slate-800/80 hover:border-slate-700 transition-colors flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between mb-2">
                  <div className="w-8 h-8 rounded bg-slate-800 flex items-center justify-center text-cyan-400">
                    <Icon className="w-4 h-4" />
                  </div>
                  <StatusBadge status={m.status} />
                </div>
                <h3 className="text-sm font-semibold text-white mb-1">
                  {m.id}. {m.name}
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-3">
                  {m.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                <span>Phase {m.target_phase}</span>
                <span>{m.tech_scope}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
