import React, { useState } from 'react';
import { Copy, Check, Info } from 'lucide-react';

interface ExecutiveSummaryProps {
  overview: string;
  topThreeFixes: string[];
  vibeAppInsight: string;
  repoName: string;
  usedFallback?: boolean;
  geminiModelUsed?: string;
}

export const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({
  overview,
  topThreeFixes,
  vibeAppInsight,
  repoName,
  usedFallback,
  geminiModelUsed,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopySummary = () => {
    const text = `VIBE CODE HEALTH AUDIT - ${repoName}\n\nOVERVIEW:\n${overview}\n\nTOP 3 ACTION ITEMS:\n${topThreeFixes
      .map((f, i) => `${i + 1}. ${f}`)
      .join('\n')}\n\nAI INSIGHT:\n${vibeAppInsight}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-6 rounded-xl bg-[#1D1713] border border-[#382D25] my-6">
      <div className="flex items-center justify-between gap-4 mb-4 pb-3 border-b border-[#382D25]">
        <div>
          <h3 className="text-base font-headline font-medium text-[#F2E9DF]">
            Executive summary
          </h3>
          <p className="text-xs text-[#A39382] mt-0.5">
            Plain-English overview for non-technical founders
          </p>
        </div>

        <button
          onClick={handleCopySummary}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md text-[#F2E9DF] hover:text-white bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/50 transition cursor-pointer shrink-0"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-[#F2E9DF]" /> : <Copy className="w-3.5 h-3.5 text-[#A39382]" />}
          <span>{copied ? 'Copied' : 'Copy summary'}</span>
        </button>
      </div>

      {/* Calm notice when AI explanations are temporarily unavailable */}
      {usedFallback && (
        <div className="mb-4 p-3 rounded-lg bg-[#14100D] border border-[#382D25] flex items-center gap-2.5 text-xs text-[#A39382]">
          <Info className="w-4 h-4 shrink-0 text-[#A39382]" />
          <span>AI explanations are temporarily unavailable; showing built-in explanations.</span>
        </div>
      )}

      <p className="text-sm text-[#F2E9DF] leading-relaxed mb-6 font-sans">
        {overview}
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Fix these first: top three findings, short */}
        <div className="p-4 rounded-lg bg-[#14100D] border border-[#382D25]">
          <h4 className="text-xs font-medium text-[#F2E9DF] mb-3">
            Fix these first
          </h4>
          {topThreeFixes && topThreeFixes.length > 0 ? (
            <ol className="space-y-2 text-xs text-[#A39382]">
              {topThreeFixes.slice(0, 3).map((fix, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-[#F2E9DF] font-medium shrink-0">
                    {idx + 1}.
                  </span>
                  <span className="leading-snug text-[#F2E9DF]">{fix}</span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-xs text-[#A39382]">No urgent fixes identified.</p>
          )}
        </div>

        {/* AI insight on vibe-coding patterns */}
        <div className="p-4 rounded-lg bg-[#14100D] border border-[#382D25]">
          <h4 className="text-xs font-medium text-[#F2E9DF] mb-2">
            Why the AI wrote it this way
          </h4>
          <p className="text-xs text-[#A39382] leading-relaxed">
            {vibeAppInsight}
          </p>
        </div>
      </div>
    </div>
  );
};
