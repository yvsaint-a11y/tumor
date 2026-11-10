import React, { useState } from 'react';
import { Finding } from '../types/scanner.js';
import {
  OctagonAlert,
  TriangleAlert,
  CircleAlert,
  Info,
  ChevronDown,
  Copy,
  Check,
  ExternalLink,
} from 'lucide-react';

interface FindingCardProps {
  finding: Finding;
  repoUrl?: string;
  commitSha?: string;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding, repoUrl, commitSha }) => {
  const [isEvidenceOpen, setIsEvidenceOpen] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [copiedEvidence, setCopiedEvidence] = useState(false);

  const getSeverity = (severity: string) => {
    switch (severity) {
      case 'critical':
        return {
          icon: OctagonAlert,
          label: 'Critical',
          textColor: 'text-[#E5484D]',
        };
      case 'high':
        return {
          icon: TriangleAlert,
          label: 'High',
          textColor: 'text-[#F2874B]',
        };
      case 'medium':
        return {
          icon: CircleAlert,
          label: 'Medium',
          textColor: 'text-[#D9B84A]',
        };
      case 'low':
        return {
          icon: Info,
          label: 'Low',
          textColor: 'text-[#7FA6C9]',
        };
      case 'info':
      default:
        return {
          icon: Info,
          label: 'Info',
          textColor: 'text-[#8C8379]',
        };
    }
  };

  const effectiveSev = finding.effectiveSeverity || finding.severity;
  const sev = getSeverity(effectiveSev);
  const SevIcon = sev.icon;

  const handleCopyPrompt = () => {
    const prompt =
      finding.explanation?.aiFixPrompt ||
      `Please fix the issue in ${finding.file} at line ${finding.line}: ${finding.title}.`;
    navigator.clipboard.writeText(prompt);
    setCopiedPrompt(true);
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  const handleCopyEvidence = () => {
    navigator.clipboard.writeText(finding.evidence);
    setCopiedEvidence(true);
    setTimeout(() => setCopiedEvidence(false), 2000);
  };

  // GitHub commit permalink when repository URL is real
  const getGitHubFileUrl = () => {
    if (!repoUrl || !repoUrl.startsWith('https://github.com')) return null;
    const cleanRepo = repoUrl.replace(/\/$/, '');
    const sha = commitSha || 'main';
    return `${cleanRepo}/blob/${sha}/${finding.file}#L${finding.line}`;
  };

  const gitHubUrl = getGitHubFileUrl();

  return (
    <div className="p-4 sm:p-5 rounded-lg bg-[#1D1713] border border-[#382D25] text-left">
      {/* Top Header: Severity + Quiet Inline Meta (no badges) */}
      <div className="flex flex-wrap items-center justify-between gap-y-1.5 gap-x-3 mb-2 font-sans">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Severity label with distinct icon shape, never color alone */}
          <div className={`flex items-center gap-1.5 text-xs font-medium ${sev.textColor}`}>
            <SevIcon className="w-3.5 h-3.5 shrink-0" />
            <span>{sev.label}</span>
          </div>

          {/* Quiet inline metadata */}
          <div className="flex items-center gap-2.5 text-xs text-[#A39382] flex-wrap font-sans">
            {finding.confidence && (
              <span>
                {finding.confidence === 'high'
                  ? 'high confidence'
                  : finding.confidence === 'medium'
                  ? 'medium confidence'
                  : 'low confidence'}
              </span>
            )}

            {finding.depScope && (
              <span>
                {finding.depScope === 'dev'
                  ? finding.effectiveSeverity && finding.effectiveSeverity !== finding.severity
                    ? `dev dependency (${finding.severity} → ${finding.effectiveSeverity})`
                    : 'dev dependency'
                  : 'runtime dependency'}
              </span>
            )}

            <span>
              {finding.explanation?.source === 'gemini'
                ? 'AI explanation'
                : 'built-in explanation'}
            </span>

            <span>rule: {finding.ruleId}</span>
          </div>
        </div>

        {/* File and line */}
        <div className="text-xs text-[#A39382] font-mono">
          <span>{finding.file}</span>
          <span>:</span>
          <span className="text-[#F2E9DF]">{finding.line}</span>
        </div>
      </div>

      {/* Plain-English title */}
      <h4 className="text-sm sm:text-base font-headline font-medium text-[#F2E9DF] mt-1">
        {finding.title}
      </h4>

      {/* What could happen */}
      {finding.explanation?.plainEnglishRisk && (
        <div className="mt-2.5">
          <p className="text-xs text-[#A39382] font-sans">What could happen:</p>
          <p className="text-xs text-[#F2E9DF] mt-0.5 leading-relaxed font-sans">
            {finding.explanation.plainEnglishRisk}
          </p>
        </div>
      )}

      {/* What to do */}
      {finding.explanation?.nextStep && (
        <div className="mt-2.5">
          <p className="text-xs text-[#A39382] font-sans">What to do:</p>
          <p className="text-xs text-[#F2E9DF] mt-0.5 leading-relaxed font-sans">
            {finding.explanation.nextStep}
          </p>
        </div>
      )}

      {/* Collapsed Evidence Section */}
      <div className="mt-3 pt-3 border-t border-[#382D25]">
        <button
          type="button"
          onClick={() => setIsEvidenceOpen(!isEvidenceOpen)}
          className="flex items-center gap-1.5 text-xs text-[#A39382] hover:text-[#F2E9DF] transition cursor-pointer font-sans"
        >
          <span>Evidence</span>
          <ChevronDown
            className={`w-3.5 h-3.5 transition-transform duration-200 ${
              isEvidenceOpen ? 'rotate-180' : ''
            }`}
          />
        </button>

        {isEvidenceOpen && (
          <div className="mt-3 space-y-2.5">
            {/* File location with link to GitHub at commit if available */}
            <div className="flex items-center justify-between gap-2 text-xs font-mono text-[#A39382]">
              <div className="flex items-center gap-1.5 truncate">
                <span>Location:</span>
                {gitHubUrl ? (
                  <a
                    href={gitHubUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#F2E9DF] hover:underline flex items-center gap-1 truncate"
                  >
                    <span>
                      {finding.file}:{finding.line}
                    </span>
                    <ExternalLink className="w-3 h-3 shrink-0" />
                  </a>
                ) : (
                  <span className="text-[#F2E9DF]">
                    {finding.file}:{finding.line}
                  </span>
                )}
              </div>

              <button
                type="button"
                onClick={handleCopyEvidence}
                className="flex items-center gap-1 text-[#A39382] hover:text-[#F2E9DF] transition cursor-pointer shrink-0"
              >
                {copiedEvidence ? (
                  <Check className="w-3 h-3 text-[#F2E9DF]" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>{copiedEvidence ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Masked code snippet in mono */}
            <div className="p-3 rounded-md bg-[#14100D] border border-[#382D25] font-mono text-xs text-[#F2E9DF] overflow-x-auto">
              <code>
                <span className="text-[#A39382] mr-2 select-none">{finding.line} |</span>
                {finding.evidence}
              </code>
            </div>

            {/* Copy fix prompt button */}
            {finding.explanation?.aiFixPrompt && (
              <div className="flex items-center justify-between gap-3 pt-1">
                <span className="text-[11px] text-[#A39382] font-sans">
                  Prompt for Cursor, Lovable, or Bolt
                </span>
                <button
                  type="button"
                  onClick={handleCopyPrompt}
                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/50 text-[#F2E9DF] transition cursor-pointer shrink-0 font-sans"
                >
                  {copiedPrompt ? (
                    <Check className="w-3 h-3 text-[#F2E9DF]" />
                  ) : (
                    <Copy className="w-3 h-3 text-[#A39382]" />
                  )}
                  <span>{copiedPrompt ? 'Copied' : 'Copy fix prompt'}</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
