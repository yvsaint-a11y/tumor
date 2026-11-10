import React from 'react';
import { DownloadCloud, Layers, Cpu, Calculator, Sparkles, Check } from 'lucide-react';

interface PipelineProgressProps {
  currentStage: number; // 0 to 4
  statusText?: string;
}

export const PipelineProgress: React.FC<PipelineProgressProps> = ({ currentStage, statusText }) => {
  const steps = [
    {
      title: 'Fetching repo',
      subtitle: 'Static text read',
      icon: <DownloadCloud className="w-4 h-4" />,
    },
    {
      title: 'Detecting stack',
      subtitle: 'React and Python',
      icon: <Layers className="w-4 h-4" />,
    },
    {
      title: 'Checking code',
      subtitle: 'Deps, secrets, code (no AI)',
      icon: <Cpu className="w-4 h-4" />,
    },
    {
      title: 'Scoring',
      subtitle: 'Fixed deduction rubric',
      icon: <Calculator className="w-4 h-4" />,
    },
    {
      title: 'Writing report',
      subtitle: 'Plain-English explanations',
      icon: <Sparkles className="w-4 h-4" />,
    },
  ];

  return (
    <div className="p-6 rounded-lg bg-[#1D1713] border border-[#382D25] shadow-lg my-6 max-w-2xl mx-auto panel-corner-glow">
      <div className="flex items-center justify-between gap-4 mb-4">
        <div>
          <h4 className="text-sm font-medium text-[#F2E9DF]">Scanning repository</h4>
          <p className="text-xs text-[#A39382] mt-0.5">{statusText || 'Analyzing code and dependencies...'}</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[#F2E9DF]/40 animate-pulse" />
          <span className="text-xs text-[#A39382]">In progress</span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 mt-4">
        {steps.map((step, idx) => {
          const isDone = idx < currentStage;
          const isCurrent = idx === currentStage;

          return (
            <div
              key={step.title}
              className={`p-3 rounded-md border text-left transition-all ${
                isDone
                  ? 'bg-[#14100D] border-[#382D25] text-[#A39382]'
                  : isCurrent
                  ? 'bg-[#14100D] border-[#F2E9DF]/40 text-[#F2E9DF]'
                  : 'bg-[#14100D]/40 border-[#382D25]/40 text-[#A39382]/40'
              }`}
            >
              <div className="mb-2">
                <div
                  className={`w-6 h-6 rounded flex items-center justify-center text-xs ${
                    isDone
                      ? 'text-[#F2E9DF]'
                      : isCurrent
                      ? 'text-[#F2E9DF]'
                      : 'text-[#A39382]/40'
                  }`}
                >
                  {isDone ? <Check className="w-3.5 h-3.5 text-[#F2E9DF]" /> : step.icon}
                </div>
              </div>
              <p className="text-xs font-medium leading-tight">{step.title}</p>
              <p className="text-[11px] text-[#A39382] mt-0.5 leading-snug">{step.subtitle}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
