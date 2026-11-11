import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar.js';
import { AgentRulesModal } from './components/AgentRulesModal.js';
import { ExportModal } from './components/ExportModal.js';
import { HistoryModal } from './components/HistoryModal.js';
import { PipelineProgress } from './components/PipelineProgress.js';
import { ScoreGauge } from './components/ScoreGauge.js';
import { ExecutiveSummary } from './components/ExecutiveSummary.js';
import { FindingCard } from './components/FindingCard.js';
import { ScanReport, FindingSeverity, FindingCategory } from './types/scanner.js';
import {
  Search,
  RefreshCw,
  Download,
  AlertCircle,
  AlertTriangle,
  Lock,
  OctagonAlert,
  TriangleAlert,
  CircleAlert,
  Info,
  CheckCircle2,
  FileCode,
  ArrowLeft
} from 'lucide-react';

interface SampleApp {
  id: string;
  name: string;
  displayName: string;
  description: string;
  stackTag: string;
  repoUrl: string;
  fileCount: number;
}

interface ScanErrorInfo {
  type: 'invalid_url' | 'not_found' | 'github_rate_limit' | 'scan_limit' | 'server_error';
  title: string;
  whatHappened: string;
  whatNext: string;
  actionText: string;
  actionType: 'sample' | 'retry' | 'history';
}

function classifyScanError(rawError: string, status?: number): ScanErrorInfo {
  const errLower = rawError.toLowerCase();

  // 1. Scan limit (our 10 per hour limit)
  if (
    status === 429 ||
    errLower.includes('maximum of 10 scans') ||
    errLower.includes('10 scans per hour') ||
    errLower.includes('10 scans this hour')
  ) {
    return {
      type: 'scan_limit',
      title: 'Scan limit reached',
      whatHappened: "You've reached 10 scans this hour. Try again later.",
      whatNext: 'To keep this tool fast and available for everyone, scans are limited to 10 per hour per IP. You can review saved scans in your history.',
      actionText: 'View scan history',
      actionType: 'history',
    };
  }

  // 2. Invalid URL
  if (
    errLower.includes('valid public github url') ||
    errLower.includes("doesn't look like a github") ||
    errLower.includes('invalid url') ||
    errLower.includes('please enter a valid')
  ) {
    return {
      type: 'invalid_url',
      title: 'Invalid repository link',
      whatHappened: "That doesn't look like a GitHub repo link. Try https://github.com/owner/repo.",
      whatNext: 'Make sure the link starts with https://github.com/ followed by the repository owner and name.',
      actionText: 'Try a sample app',
      actionType: 'sample',
    };
  }

  // 3. Repo not found or private
  if (
    status === 404 ||
    errLower.includes('not found') ||
    errLower.includes('private') ||
    errLower.includes('make sure the repository is public')
  ) {
    return {
      type: 'not_found',
      title: 'Repository not found or private',
      whatHappened: "We couldn't find that repo. If it's private, this tool can't scan it yet; v1 only reads public repos.",
      whatNext: 'Double-check that the repository URL exists and has public visibility on GitHub.',
      actionText: 'Try a sample app',
      actionType: 'sample',
    };
  }

  // 4. GitHub rate limit
  if (
    errLower.includes('github api rate limit') ||
    errLower.includes('ratelimit') ||
    errLower.includes('limit: 60') ||
    errLower.includes('rate limit exceeded')
  ) {
    const resetMatch = rawError.match(/Resets in ([^.]+)\./i);
    const resetDetail = resetMatch
      ? `It resets in ${resetMatch[1]}.`
      : 'Unauthenticated GitHub API rate limits reset at the top of each hour.';
    return {
      type: 'github_rate_limit',
      title: 'GitHub API rate limit',
      whatHappened: `GitHub API rate limit exceeded. ${resetDetail}`,
      whatNext: 'Wait until the limit resets, or run an instant scan on one of our pre-loaded sample repositories.',
      actionText: 'Try a sample app',
      actionType: 'sample',
    };
  }

  // 5. Server busy (HTTP 503)
  if (
    status === 503 ||
    errLower.includes("we're busy") ||
    errLower.includes('busy, try again')
  ) {
    return {
      type: 'server_error',
      title: "We're busy, try again in a minute.",
      whatHappened: 'Other scans are currently in progress and the queue is at capacity.',
      whatNext: 'Please wait a minute for current scans to finish and try running your scan again.',
      actionText: 'Try again',
      actionType: 'retry',
    };
  }

  // 6. Scan timed out (HTTP 408)
  if (status === 408 || errLower.includes('timed out') || errLower.includes('60 seconds')) {
    return {
      type: 'server_error',
      title: 'Scan timed out',
      whatHappened: 'The repository scan took longer than the 60-second limit.',
      whatNext: 'Try scanning a smaller repository or choose one of our instant sample apps.',
      actionText: 'Try a sample app',
      actionType: 'sample',
    };
  }

  // 7. Network or general server error
  return {
    type: 'server_error',
    title: 'Server error',
    whatHappened: 'Something went wrong on our side. Try again in a minute.',
    whatNext: 'The scan server encountered an issue processing the repository.',
    actionText: 'Try again',
    actionType: 'retry',
  };
}

export default function App() {
  const [urlInput, setUrlInput] = useState('');
  const [samples, setSamples] = useState<SampleApp[]>([]);
  const [isLoadingSamples, setIsLoadingSamples] = useState(false);
  
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState(0);
  const [scanStatusText, setScanStatusText] = useState('');
  const [scanErrorInfo, setScanErrorInfo] = useState<ScanErrorInfo | null>(null);
  const [lastScanParams, setLastScanParams] = useState<{ repoUrl?: string; sampleId?: string; forceFresh?: boolean } | null>(null);

  const [activeReport, setActiveReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanReport[]>([]);

  // Modals
  const [showRulesModal, setShowRulesModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  // Findings Filters
  const [severityFilter, setSeverityFilter] = useState<'all' | FindingSeverity>('all');
  const [categoryFilter, setCategoryFilter] = useState<'all' | FindingCategory>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Group pagination limits (5 per group initially)
  const [fixNowLimit, setFixNowLimit] = useState(5);
  const [fixSoonLimit, setFixSoonLimit] = useState(5);
  const [worthKnowingLimit, setWorthKnowingLimit] = useState(5);

  // Load history from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('vibe_scan_history');
      if (saved) {
        setHistory(JSON.parse(saved));
      }
    } catch {
      // ignore
    }
  }, []);

  // Fetch samples from server
  useEffect(() => {
    async function fetchSamples() {
      setIsLoadingSamples(true);
      try {
        const res = await fetch('/api/samples');
        if (res.ok) {
          const data = await res.json();
          setSamples(data.samples || []);
        }
      } catch (e) {
        console.error('Failed to load sample repos:', e);
      } finally {
        setIsLoadingSamples(false);
      }
    }
    fetchSamples();
  }, []);

  const saveReportToHistory = (newReport: ScanReport) => {
    setHistory((prev) => {
      const filtered = prev.filter((r) => r.repoUrl !== newReport.repoUrl);
      const updated = [newReport, ...filtered].slice(0, 15);
      try {
        localStorage.setItem('vibe_scan_history', JSON.stringify(updated));
      } catch {
        // storage quota
      }
      return updated;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('vibe_scan_history');
    } catch {
      // ignore
    }
  };

  const triggerScan = async (params: { repoUrl?: string; sampleId?: string; forceFresh?: boolean }) => {
    setScanErrorInfo(null);
    setLastScanParams(params);
    setIsScanning(true);
    setScanStage(0);
    setScanStatusText('Fetching the repo');
    setFixNowLimit(5);
    setFixSoonLimit(5);
    setWorthKnowingLimit(5);

    // Progress animation timers (honest stage names, no AI scanning claims)
    const timer1 = setTimeout(() => {
      setScanStage(1);
      setScanStatusText('Checking dependencies, secrets and code (no AI involved)');
    }, 600);

    const timer2 = setTimeout(() => {
      setScanStage(2);
      setScanStatusText('Checking dependencies, secrets and code (no AI involved)');
    }, 1500);

    const timer3 = setTimeout(() => {
      setScanStage(3);
      setScanStatusText('Scoring');
    }, 2800);

    const timer4 = setTimeout(() => {
      setScanStage(4);
      setScanStatusText('Writing plain-English explanations');
    }, 3800);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });

      const data = await res.json();
      if (!res.ok) {
        setScanErrorInfo(classifyScanError(data.error || '', res.status));
        return;
      }

      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);

      setActiveReport(data.report);
      saveReportToHistory(data.report);
    } catch (err: any) {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);
      setScanErrorInfo(classifyScanError(err.message || ''));
    } finally {
      setIsScanning(false);
    }
  };

  const handleSubmitUrl = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = urlInput.trim();
    if (!clean) return;

    // Validate that input looks like a GitHub link
    const isGitHub =
      /^https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(\/.*)?$/i.test(clean) ||
      /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(clean);

    if (!isGitHub) {
      setScanErrorInfo({
        type: 'invalid_url',
        title: 'Invalid repository link',
        whatHappened: "That doesn't look like a GitHub repo link. Try https://github.com/owner/repo.",
        whatNext: 'Make sure the link starts with https://github.com/ followed by the repository owner and name.',
        actionText: 'Try a sample app',
        actionType: 'sample',
      });
      return;
    }

    triggerScan({ repoUrl: clean });
  };

  const handleSelectSample = (sampleId: string) => {
    const sample = samples.find((s) => s.id === sampleId);
    if (sample) {
      setUrlInput(sample.repoUrl);
    }
    triggerScan({ sampleId });
  };

  // Filter findings
  const filteredFindings = (activeReport?.findings || []).filter((f) => {
    const effectiveSev = f.effectiveSeverity || f.severity;
    if (severityFilter !== 'all' && effectiveSev !== severityFilter) return false;
    if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchFile = f.file.toLowerCase().includes(q);
      const matchEvidence = f.evidence.toLowerCase().includes(q);
      const matchRule = f.ruleId.toLowerCase().includes(q);
      if (!matchTitle && !matchFile && !matchEvidence && !matchRule) return false;
    }
    return true;
  });

  const fixNowFindings = filteredFindings.filter(
    (f) => (f.effectiveSeverity || f.severity) === 'critical' || (f.effectiveSeverity || f.severity) === 'high'
  );
  const fixSoonFindings = filteredFindings.filter((f) => (f.effectiveSeverity || f.severity) === 'medium');
  const worthKnowingFindings = filteredFindings.filter(
    (f) => (f.effectiveSeverity || f.severity) === 'low' || (f.effectiveSeverity || f.severity) === 'info'
  );

  return (
    <div className="min-h-screen bg-[#14100D] text-[#F2E9DF] flex flex-col font-sans selection:bg-[#F2E9DF] selection:text-[#14100D]">
      <Navbar
        onOpenRules={() => setShowRulesModal(true)}
        onOpenHistory={() => setShowHistoryModal(true)}
        historyCount={history.length}
        onGoHome={() => setActiveReport(null)}
      />

      <main className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 py-8">
        {/* Error State Banner */}
        {scanErrorInfo && (
          <div className="max-w-xl mx-auto p-4 sm:p-5 rounded-xl bg-[#1D1713] border border-[#382D25] text-left font-sans mb-6 shadow-md animate-fade-in">
            <div className="flex items-start gap-3">
              <div className="p-1.5 rounded-lg bg-[#382D25]/40 text-[#A39382] shrink-0 mt-0.5">
                <CircleAlert className="w-4 h-4 text-[#D96B43]" />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-medium text-[#F2E9DF] leading-snug">
                  {scanErrorInfo.title}
                </h3>
                <p className="text-xs text-[#F2E9DF] mt-1 leading-relaxed">
                  {scanErrorInfo.whatHappened}
                </p>
                <p className="text-xs text-[#A39382] mt-1 leading-relaxed">
                  {scanErrorInfo.whatNext}
                </p>
                <div className="mt-3.5 flex flex-wrap items-center gap-3 pt-0.5">
                  <button
                    type="button"
                    onClick={() => {
                      if (scanErrorInfo.actionType === 'sample') {
                        setScanErrorInfo(null);
                        handleSelectSample('bolt-vibe-saas');
                      } else if (scanErrorInfo.actionType === 'history') {
                        setScanErrorInfo(null);
                        setShowHistoryModal(true);
                      } else if (scanErrorInfo.actionType === 'retry') {
                        setScanErrorInfo(null);
                        if (lastScanParams) {
                          triggerScan(lastScanParams);
                        } else {
                          handleSelectSample('bolt-vibe-saas');
                        }
                      }
                    }}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-[#F2E9DF] text-[#14100D] hover:bg-[#F2E9DF]/90 transition cursor-pointer"
                  >
                    {scanErrorInfo.actionText}
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanErrorInfo(null)}
                    className="text-xs text-[#A39382] hover:text-[#F2E9DF] transition cursor-pointer px-1 py-1"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Live Pipeline Progress Indicator */}
        {isScanning && (
          <PipelineProgress currentStage={scanStage} statusText={scanStatusText} />
        )}

        {/* Home Screen (Shown when no active report and not scanning) */}
        {!activeReport && !isScanning && (
          <div className="relative">
            <div className="absolute inset-0 hero-radial-glow pointer-events-none -z-10" />

            {/* 1. Headline & Subhead */}
            <section className="text-center max-w-2xl mx-auto pt-4 pb-4 sm:pt-8 sm:pb-6 px-2">
              <h1 className="text-3xl sm:text-5xl font-headline font-normal tracking-tight text-[#F2E9DF] leading-[1.15]">
                Find out what's broken in your AI-built app
              </h1>
              <p className="mt-3.5 text-sm sm:text-base font-sans text-[#A39382] max-w-lg mx-auto leading-relaxed">
                Paste a public GitHub link. Get a plain-English health report in about a minute.
              </p>
            </section>

            {/* 2. The memorable element: large hero repo URL input + primary button */}
            <section className="max-w-xl mx-auto mb-10 px-2">
              <form onSubmit={handleSubmitUrl}>
                <div className="p-2 sm:p-2.5 rounded-xl bg-[#1D1713] border border-[#382D25] focus-within:border-[#A39382]/60 shadow-lg transition flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <div className="flex items-center gap-2.5 flex-1 px-2.5">
                    <Search className="w-4 h-4 text-[#A39382] shrink-0" />
                    <input
                      type="text"
                      placeholder="https://github.com/owner/repository"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      disabled={isScanning}
                      className="w-full bg-transparent py-1.5 text-sm sm:text-base text-[#F2E9DF] placeholder:text-[#A39382]/50 focus:outline-none font-sans"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isScanning || !urlInput.trim()}
                    className={`px-5 py-3 rounded-lg text-xs sm:text-sm font-medium transition shrink-0 text-center ${
                      urlInput.trim() && !isScanning
                        ? 'bg-[#F2E9DF] text-[#14100D] hover:bg-[#F2E9DF]/90 cursor-pointer'
                        : 'bg-[#382D25] text-[#A39382] cursor-not-allowed opacity-80'
                    }`}
                  >
                    {isScanning ? (
                      <span className="flex items-center justify-center gap-2">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Scanning repo...</span>
                      </span>
                    ) : (
                      'Scan this repo'
                    )}
                  </button>
                </div>
              </form>
              <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-1 mt-3 text-xs text-[#A39382] text-center font-sans">
                <span>Read-only</span>
                <span>Never runs your code</span>
                <span>Secrets are masked</span>
              </div>
            </section>

            {/* 3. Try a sample: simple text buttons with 1-line description, no card background */}
            <section className="max-w-2xl mx-auto mb-12 px-2">
              <div className="flex items-baseline justify-between mb-3 px-0.5 pb-2 border-b border-[#382D25]">
                <h2 className="text-sm font-medium text-[#F2E9DF]">Try a sample</h2>
                <span className="text-xs text-[#A39382]">Inspect pre-loaded repos</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 pt-1">
                <button
                  type="button"
                  onClick={() => handleSelectSample('bolt-vibe-saas')}
                  disabled={isScanning}
                  className="text-left p-0 transition group disabled:opacity-50 cursor-pointer bg-transparent border-0"
                >
                  <p className="text-xs font-medium text-[#F2E9DF] group-hover:underline underline-offset-2">
                    Bolt / Lovable React SaaS
                  </p>
                  <p className="text-xs text-[#A39382] mt-1 leading-snug">
                    React frontend with exposed Supabase key, fake packages, and missing error boundary.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleSelectSample('cursor-python-api')}
                  disabled={isScanning}
                  className="text-left p-0 transition group disabled:opacity-50 cursor-pointer bg-transparent border-0"
                >
                  <p className="text-xs font-medium text-[#F2E9DF] group-hover:underline underline-offset-2">
                    Cursor Python API
                  </p>
                  <p className="text-xs text-[#A39382] mt-1 leading-snug">
                    FastAPI backend with hardcoded secret key, debug mode, and unpinned dependencies.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleSelectSample('fullstack-vibe-store')}
                  disabled={isScanning}
                  className="text-left p-0 transition group disabled:opacity-50 cursor-pointer bg-transparent border-0"
                >
                  <p className="text-xs font-medium text-[#F2E9DF] group-hover:underline underline-offset-2">
                    Fullstack Store
                  </p>
                  <p className="text-xs text-[#A39382] mt-1 leading-snug">
                    Next.js frontend and Python worker monorepo with cross-stack issues.
                  </p>
                </button>
              </div>

              <div className="mt-4 text-right">
                <button
                  type="button"
                  onClick={() => handleSelectSample('prompt-injection-test')}
                  disabled={isScanning}
                  className="text-xs text-[#A39382] hover:text-[#F2E9DF] transition cursor-pointer underline decoration-[#382D25] hover:decoration-[#A39382]"
                >
                  Prompt injection fixture (adversarial prompt defense test)
                </button>
              </div>
            </section>

            {/* 4. Real sample report preview built from the Bolt demo result */}
            <section className="max-w-2xl mx-auto mb-14 px-2">
              <div className="p-6 rounded-xl bg-[#1D1713] border border-[#382D25] panel-corner-glow">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-[#382D25]">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-sm font-medium text-[#F2E9DF]">Sample: demo app</h2>
                      <span className="text-xs text-[#A39382]">Bolt / Lovable React SaaS</span>
                    </div>
                    <p className="text-xs text-[#A39382] mt-0.5">
                      What a completed health report looks like before you scan.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleSelectSample('bolt-vibe-saas')}
                    disabled={isScanning}
                    className="text-xs font-medium text-[#F2E9DF] hover:text-white bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/50 px-3 py-1.5 rounded-md transition cursor-pointer self-start sm:self-auto"
                  >
                    Open full sample report
                  </button>
                </div>

                {/* Grade and verdict */}
                <div className="flex items-center gap-5 py-5 border-b border-[#382D25]">
                  <div className="w-16 h-16 rounded-lg bg-[#14100D] border border-[#382D25] flex items-center justify-center shrink-0">
                    <span className="text-4xl font-headline font-semibold text-[#E5484D]">F</span>
                  </div>
                  <div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-lg font-headline font-medium text-[#F2E9DF]">
                        Critical security risks require immediate action
                      </span>
                      <span className="text-xs text-[#A39382] font-mono">0/100</span>
                    </div>
                    <p className="text-xs text-[#A39382] mt-1 font-sans">
                      53 issues identified across 5 files • Secrets exposed in client build and fake dependencies installed.
                    </p>
                  </div>
                </div>

                {/* 3 Real Findings from Bolt demo */}
                <div className="pt-4 space-y-3">
                  <p className="text-xs font-medium text-[#F2E9DF]">Top issues from this scan</p>

                  <div className="p-3 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-1.5 text-xs font-medium text-[#E5484D]">
                        <OctagonAlert className="w-3.5 h-3.5 shrink-0" />
                        <span>Critical</span>
                        <span className="text-[#A39382] font-normal">• Exposed secret key</span>
                      </div>
                      <span className="text-[11px] font-mono text-[#A39382]">.env:60</span>
                    </div>
                    <p className="text-xs text-[#F2E9DF] font-medium">Supabase service role key exposed with VITE_ prefix</p>
                    <p className="text-[11px] text-[#A39382] mt-0.5">
                      Client bundle bundles administrative credentials, allowing any visitor full database read/write access.
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-1.5 text-xs font-medium text-[#F2874B]">
                        <TriangleAlert className="w-3.5 h-3.5 shrink-0" />
                        <span>High</span>
                        <span className="text-[#A39382] font-normal">• Hallucinated package</span>
                      </div>
                      <span className="text-[11px] font-mono text-[#A39382]">package.json:40</span>
                    </div>
                    <p className="text-xs text-[#F2E9DF] font-medium">Nonexistent npm packages installed</p>
                    <p className="text-[11px] text-[#A39382] mt-0.5">
                      lucide-react-pro-icons and tailwind-auth-kit were invented by the AI and do not exist on the public registry.
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-1.5 text-xs font-medium text-[#F2874B]">
                        <TriangleAlert className="w-3.5 h-3.5 shrink-0" />
                        <span>High</span>
                        <span className="text-[#A39382] font-normal">• React code safety</span>
                      </div>
                      <span className="text-[11px] font-mono text-[#A39382]">src/App.tsx:98</span>
                    </div>
                    <p className="text-xs text-[#F2E9DF] font-medium">Unsanitized HTML rendered with dangerouslySetInnerHTML</p>
                    <p className="text-[11px] text-[#A39382] mt-0.5">
                      Raw user input passed directly to the browser DOM without sanitization allows cross-site scripting (XSS).
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* 5. What we check: 2-column plain list, NOT a card grid */}
            <section className="max-w-2xl mx-auto mb-14 px-2">
              <h2 className="text-base font-headline font-medium text-[#F2E9DF] mb-4">What we check</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4 pt-3 border-t border-[#382D25]">
                <div className="space-y-4">
                  <div>
                    <p className="text-xs font-medium text-[#F2E9DF]">Dependencies</p>
                    <p className="text-xs text-[#A39382] mt-0.5 leading-relaxed font-sans">
                      Known security vulnerabilities in npm and PyPI libraries matched against OSV.dev advisories, with semver resolution.
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-[#F2E9DF]">Fake packages</p>
                    <p className="text-xs text-[#A39382] mt-0.5 leading-relaxed font-sans">
                      Packages generated by the AI model that do not exist on npm or PyPI, leaving the application open to supply-chain attacks.
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-[#F2E9DF]">Exposed secrets</p>
                    <p className="text-xs text-[#A39382] mt-0.5 leading-relaxed font-sans">
                      Live API keys, database URLs, and signing secrets committed in code or exposed in frontend environment variables.
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <p className="text-xs font-medium text-[#F2E9DF]">React safety</p>
                    <p className="text-xs text-[#A39382] mt-0.5 leading-relaxed font-sans">
                      Unsanitized HTML injection vectors (dangerouslySetInnerHTML) and missing top-level error boundaries that cause total blank screens.
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-[#F2E9DF]">Python safety</p>
                    <p className="text-xs text-[#A39382] mt-0.5 leading-relaxed font-sans">
                      Active debug mode in production, hardcoded cryptographic keys, and permissive wildcard CORS configurations.
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-[#F2E9DF]">Test hygiene</p>
                    <p className="text-xs text-[#A39382] mt-0.5 leading-relaxed font-sans">
                      Verification of automated test files across the repository to verify that core application logic is tested.
                    </p>
                  </div>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* Report Output View */}
        {activeReport && !isScanning && (
          <div className="mt-6 space-y-6 animate-fade-in">
            {/* Top Bar: repo name, branch, short commit SHA, scan time, "Scan again", "Export" */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#382D25]">
              <div className="flex items-center gap-4 sm:gap-6 text-xs text-[#A39382] flex-wrap font-sans">
                <button
                  onClick={() => setActiveReport(null)}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs text-[#A39382] hover:text-[#F2E9DF] bg-[#1D1713] border border-[#382D25] hover:border-[#A39382]/40 transition cursor-pointer"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back</span>
                </button>
                <span className="font-medium text-[#F2E9DF] font-sans text-sm">{activeReport.repoName}</span>
                <span className="font-sans text-[#A39382]">branch: {activeReport.branch || 'main'}</span>
                <span className="font-sans text-[#A39382]">
                  commit: <code className="text-[#F2E9DF] font-mono">{activeReport.commitSha ? activeReport.commitSha.substring(0, 7) : 'latest'}</code>
                </span>
                <span className="font-sans text-[#A39382]">{new Date(activeReport.scannedAt).toLocaleTimeString()}</span>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() =>
                    triggerScan({
                      repoUrl: activeReport.repoUrl,
                      sampleId: activeReport.isSampleRepo
                        ? samples.find((s) => s.name === activeReport.repoName)?.id
                        : undefined,
                      forceFresh: true,
                    })
                  }
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-[#1D1713] border border-[#382D25] hover:border-[#A39382]/50 text-[#F2E9DF] transition cursor-pointer font-sans"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-[#A39382]" />
                  <span>Scan again</span>
                </button>
                <button
                  onClick={() => setShowExportModal(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-[#1D1713] border border-[#382D25] hover:border-[#A39382]/50 text-[#F2E9DF] transition cursor-pointer font-sans"
                >
                  <Download className="w-3.5 h-3.5 text-[#A39382]" />
                  <span>Export</span>
                </button>
              </div>
            </div>

            {/* Score & Rubric Breakdown with Coverage */}
            <ScoreGauge
              rubric={activeReport.rubric}
              stack={activeReport.stack}
              coverage={activeReport.coverage}
              repoName={activeReport.repoName}
              isSampleRepo={activeReport.isSampleRepo}
            />

            {/* Plain English Executive Summary */}
            <ExecutiveSummary
              overview={activeReport.executiveSummary.overview}
              topThreeFixes={activeReport.executiveSummary.topThreeFixes}
              vibeAppInsight={activeReport.executiveSummary.vibeAppInsight}
              repoName={activeReport.repoName}
              usedFallback={activeReport.executiveSummary.usedFallback}
              geminiModelUsed={activeReport.executiveSummary.geminiModelUsed}
            />

            {/* Findings Explorer or Clean Repo State */}
            {activeReport.findings.length === 0 ? (
              <div className="p-8 rounded-xl bg-[#1D1713] border border-[#382D25] text-center font-sans">
                <div className="w-10 h-10 mx-auto mb-3 rounded-full bg-[#382D25]/40 flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                </div>
                <h3 className="text-base font-headline font-medium text-[#F2E9DF]">
                  No issues found in scanned files
                </h3>
                <p className="text-xs text-[#A39382] mt-1.5 max-w-md mx-auto leading-relaxed">
                  Automated checks for vulnerable dependencies, fake packages, leaked secrets, code safety, and test hygiene passed cleanly.
                </p>
                <div className="mt-5">
                  <button
                    type="button"
                    onClick={() => setActiveReport(null)}
                    className="px-4 py-2 rounded-lg text-xs font-medium bg-[#F2E9DF] text-[#14100D] hover:bg-[#F2E9DF]/90 transition cursor-pointer"
                  >
                    Scan another repo
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-6 rounded-xl bg-[#1D1713] border border-[#382D25] text-left">
              {/* Header and Search */}
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-6">
                <div>
                  <h3 className="text-base sm:text-lg font-headline font-medium text-[#F2E9DF] flex items-center gap-2">
                    <span>Audit findings</span>
                    <span className="text-xs text-[#A39382] font-sans">
                      ({filteredFindings.length} total)
                    </span>
                  </h3>
                  <p className="text-xs text-[#A39382] mt-0.5 font-sans">
                    Every issue cites exact file, line number, and verified code evidence.
                  </p>
                </div>

                {/* Search Bar */}
                <div className="w-full md:w-64">
                  <input
                    type="text"
                    placeholder="Filter findings..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-[#14100D] border border-[#382D25] rounded-md px-3 py-1.5 text-xs text-[#F2E9DF] placeholder:text-[#A39382]/50 focus:outline-none focus:border-[#A39382]/50 font-sans"
                  />
                </div>
              </div>

              {/* Filter Tabs (Quiet styling, no loud pills) */}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 mb-6 pb-4 border-b border-[#382D25] text-xs font-sans">
                {/* Severity Filters */}
                <div className="flex items-center gap-1 flex-wrap">
                  <button
                    onClick={() => setSeverityFilter('all')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      severityFilter === 'all'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    All severities ({activeReport.findings.length})
                  </button>
                  <button
                    onClick={() => setSeverityFilter('critical')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      severityFilter === 'critical'
                        ? 'text-[#E5484D] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Critical ({activeReport.rubric.counts.critical})
                  </button>
                  <button
                    onClick={() => setSeverityFilter('high')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      severityFilter === 'high'
                        ? 'text-[#F2874B] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    High ({activeReport.rubric.counts.high})
                  </button>
                  <button
                    onClick={() => setSeverityFilter('medium')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      severityFilter === 'medium'
                        ? 'text-[#D9B84A] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Medium ({activeReport.rubric.counts.medium})
                  </button>
                </div>

                <div className="h-4 w-px bg-[#382D25] hidden sm:block" />

                {/* Category Filters */}
                <div className="flex items-center gap-1 flex-wrap">
                  <button
                    onClick={() => setCategoryFilter('all')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      categoryFilter === 'all'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    All categories
                  </button>
                  <button
                    onClick={() => setCategoryFilter('secret')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      categoryFilter === 'secret'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Secrets
                  </button>
                  <button
                    onClick={() => setCategoryFilter('hallucination')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      categoryFilter === 'hallucination'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Fake packages
                  </button>
                  <button
                    onClick={() => setCategoryFilter('dependency')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      categoryFilter === 'dependency'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Dependencies
                  </button>
                  <button
                    onClick={() => setCategoryFilter('code_quality')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      categoryFilter === 'code_quality'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Code safety
                  </button>
                  <button
                    onClick={() => setCategoryFilter('testing')}
                    className={`px-2.5 py-1 rounded-md transition cursor-pointer ${
                      categoryFilter === 'testing'
                        ? 'text-[#F2E9DF] bg-[#14100D] border border-[#382D25]'
                        : 'text-[#A39382] hover:text-[#F2E9DF]'
                    }`}
                  >
                    Tests
                  </button>
                </div>
              </div>

              {/* Grouped Findings or Empty Filter State */}
              {filteredFindings.length === 0 ? (
                <div className="py-12 text-center font-sans">
                  <p className="text-sm font-medium text-[#F2E9DF]">No findings match this filter</p>
                  <p className="text-xs text-[#A39382] mt-1">
                    Try resetting the filter or search query.
                  </p>
                  <button
                    type="button"
                    onClick={() => {
                      setSeverityFilter('all');
                      setCategoryFilter('all');
                      setSearchQuery('');
                    }}
                    className="mt-3 px-3.5 py-1.5 rounded-lg text-xs font-medium bg-[#14100D] border border-[#382D25] text-[#F2E9DF] hover:bg-[#382D25]/40 transition cursor-pointer"
                  >
                    Clear filters
                  </button>
                </div>
              ) : (
                <div className="space-y-8">
                  {/* Group 1: Fix now (Critical, High) */}
                  {fixNowFindings.length > 0 && (
                    <section className="space-y-3">
                      <div className="pb-1 border-b border-[#382D25] flex items-baseline justify-between">
                        <div>
                          <h4 className="text-sm font-headline font-medium text-[#F2E9DF]">
                            Fix now{' '}
                            <span className="text-xs text-[#A39382] font-sans font-normal">
                              ({fixNowFindings.length})
                            </span>
                          </h4>
                          <p className="text-xs text-[#A39382] font-sans mt-0.5">
                            Critical and high risk issues that should be addressed immediately.
                          </p>
                        </div>
                      </div>
                      <div className="space-y-3">
                        {fixNowFindings.slice(0, fixNowLimit).map((finding) => (
                          <FindingCard
                            key={finding.id}
                            finding={finding}
                            repoUrl={activeReport.repoUrl}
                            commitSha={activeReport.commitSha}
                          />
                        ))}
                      </div>
                      {fixNowFindings.length > fixNowLimit && (
                        <div className="pt-2 text-center">
                          <button
                            type="button"
                            onClick={() => setFixNowLimit((prev) => prev + 10)}
                            className="text-xs text-[#A39382] hover:text-[#F2E9DF] bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/50 px-4 py-2 rounded-md transition cursor-pointer font-sans"
                          >
                            Show {fixNowFindings.length - fixNowLimit} more in Fix now
                          </button>
                        </div>
                      )}
                    </section>
                  )}

                  {/* Group 2: Fix soon (Medium) */}
                  {fixSoonFindings.length > 0 && (
                    <section className="space-y-3">
                      <div className="pb-1 border-b border-[#382D25] flex items-baseline justify-between">
                        <div>
                          <h4 className="text-sm font-headline font-medium text-[#F2E9DF]">
                            Fix soon{' '}
                            <span className="text-xs text-[#A39382] font-sans font-normal">
                              ({fixSoonFindings.length})
                            </span>
                          </h4>
                          <p className="text-xs text-[#A39382] font-sans mt-0.5">
                            Moderate risk items and dependency updates to schedule.
                          </p>
                        </div>
                      </div>
                      <div className="space-y-3">
                        {fixSoonFindings.slice(0, fixSoonLimit).map((finding) => (
                          <FindingCard
                            key={finding.id}
                            finding={finding}
                            repoUrl={activeReport.repoUrl}
                            commitSha={activeReport.commitSha}
                          />
                        ))}
                      </div>
                      {fixSoonFindings.length > fixSoonLimit && (
                        <div className="pt-2 text-center">
                          <button
                            type="button"
                            onClick={() => setFixSoonLimit((prev) => prev + 10)}
                            className="text-xs text-[#A39382] hover:text-[#F2E9DF] bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/50 px-4 py-2 rounded-md transition cursor-pointer font-sans"
                          >
                            Show {fixSoonFindings.length - fixSoonLimit} more in Fix soon
                          </button>
                        </div>
                      )}
                    </section>
                  )}

                  {/* Group 3: Worth knowing (Low, Info) */}
                  {worthKnowingFindings.length > 0 && (
                    <section className="space-y-3">
                      <div className="pb-1 border-b border-[#382D25] flex items-baseline justify-between">
                        <div>
                          <h4 className="text-sm font-headline font-medium text-[#F2E9DF]">
                            Worth knowing{' '}
                            <span className="text-xs text-[#A39382] font-sans font-normal">
                              ({worthKnowingFindings.length})
                            </span>
                          </h4>
                          <p className="text-xs text-[#A39382] font-sans mt-0.5">
                            Low risk observations and code hygiene improvements.
                          </p>
                        </div>
                      </div>
                      <div className="space-y-3">
                        {worthKnowingFindings.slice(0, worthKnowingLimit).map((finding) => (
                          <FindingCard
                            key={finding.id}
                            finding={finding}
                            repoUrl={activeReport.repoUrl}
                            commitSha={activeReport.commitSha}
                          />
                        ))}
                      </div>
                      {worthKnowingFindings.length > worthKnowingLimit && (
                        <div className="pt-2 text-center">
                          <button
                            type="button"
                            onClick={() => setWorthKnowingLimit((prev) => prev + 10)}
                            className="text-xs text-[#A39382] hover:text-[#F2E9DF] bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/50 px-4 py-2 rounded-md transition cursor-pointer font-sans"
                          >
                            Show {worthKnowingFindings.length - worthKnowingLimit} more in Worth knowing
                          </button>
                        </div>
                      )}
                    </section>
                  )}
                </div>
              )}
            </div>
          )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#382D25] bg-[#14100D] py-6 mt-12 text-center text-xs text-[#A39382]">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p>
            Tumorr • Deterministic inspection for vibe-coded applications
          </p>
          <div className="flex items-center gap-4 text-[#A39382]">
            <button
              onClick={() => setShowRulesModal(true)}
              className="hover:text-[#F2E9DF] transition cursor-pointer"
            >
              Agent rules
            </button>
            <span className="text-[#382D25]">•</span>
            <span>OSV.dev + npm + PyPI</span>
            <span className="text-[#382D25]">•</span>
            <span>Read-only inspection</span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <AgentRulesModal isOpen={showRulesModal} onClose={() => setShowRulesModal(false)} />
      <ExportModal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        report={activeReport}
      />
      <HistoryModal
        isOpen={showHistoryModal}
        onClose={() => setShowHistoryModal(false)}
        history={history}
        onSelectReport={(rep) => setActiveReport(rep)}
        onClearHistory={handleClearHistory}
        onGoHome={() => setActiveReport(null)}
      />
    </div>
  );
}
