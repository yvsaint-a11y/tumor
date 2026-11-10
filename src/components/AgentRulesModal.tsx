import React from 'react';
import { X, CheckCircle2, Shield, Lock, FileSearch, Scale, FileText, Ban } from 'lucide-react';

interface AgentRulesModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AgentRulesModal: React.FC<AgentRulesModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const rules = [
    {
      num: 1,
      title: 'Read-only in v1',
      desc: 'The scanner never modifies your repository, pushes commits, or executes any scripts.',
      icon: <Lock className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 2,
      title: 'Evidence or nothing',
      desc: 'Every finding cites an exact file path, line number, and verified code snippet. Zero phantom claims.',
      icon: <FileSearch className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 3,
      title: "The LLM can't alter findings",
      desc: 'Deterministic scanners find the problems; the LLM only translates them into plain English and cannot add or downgrade issues.',
      icon: <Ban className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 4,
      title: 'Secrets stay masked',
      desc: 'Live API keys, passwords, and tokens are strictly masked (e.g. sk-live••••) before display or LLM processing.',
      icon: <Shield className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 5,
      title: 'Never execute scanned code',
      desc: 'Your repository is read strictly as static text data. No build commands, evaluations, or npm scripts are ever run.',
      icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 6,
      title: 'Plain English',
      desc: 'Every issue explains the real-world business risk in simple language without engineering jargon, plus the next step.',
      icon: <FileText className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 7,
      title: 'Fixed severity rubric',
      desc: 'Scoring (0-100 and A-F grade) is computed by a mathematical formula (-25 crit, -15 high, -8 med, -3 low), not by AI whim. Vulnerabilities in dev dependencies deduct one severity level lower than runtime dependencies (e.g. High becomes Medium: -8 pts).',
      icon: <Scale className="w-4 h-4 text-emerald-400" />,
    },
    {
      num: 8,
      title: 'Limits & Safety caps',
      desc: 'Scans are capped at 120 key files and 100KB per file to ensure safe, deterministic execution.',
      icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div className="bg-[#1D1713] border border-[#382D25] rounded-2xl max-w-xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-[#A39382] hover:text-[#F2E9DF] rounded-lg hover:bg-[#382D25]/40 transition"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-xl bg-[#382D25]/40 border border-[#382D25] text-[#F2E9DF]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-[#F2E9DF]">Non-negotiable agent rules</h3>
            <p className="text-xs text-[#A39382]">Architectural guarantees baked into every scan</p>
          </div>
        </div>

        <div className="space-y-2.5 mt-4">
          {rules.map((r) => (
            <div key={r.num} className="p-3 rounded-xl bg-[#14100D] border border-[#382D25] flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-[#1D1713] text-[#A39382] mt-0.5">{r.icon}</div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-[#A39382]">Rule #{r.num}</span>
                  <span className="text-sm font-semibold text-[#F2E9DF]">{r.title}</span>
                </div>
                <p className="text-xs text-[#A39382] mt-1 leading-relaxed">{r.desc}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 pt-4 border-t border-[#382D25] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium rounded-xl bg-[#F2E9DF] hover:bg-[#F2E9DF]/90 text-[#14100D] transition"
          >
            Got it, close
          </button>
        </div>
      </div>
    </div>
  );
};
