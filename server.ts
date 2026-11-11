import express, { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { SAMPLE_REPOS } from './server/github/sampleRepos.js';
import { fetchRepository } from './server/github/fetcher.js';
import { detectStack } from './server/stackDetector.js';
import { scanDependencies } from './server/scanners/dependencyScanner.js';
import { scanHallucinatedPackages } from './server/scanners/hallucinationScanner.js';
import { scanSecrets } from './server/scanners/secretScanner.js';
import { scanCodeQuality } from './server/scanners/codeScanner.js';
import { calculateRubricScore } from './server/scanners/rubric.js';
import { writeReportWithGemini, checkGeminiHealth, generateLocalFallbackExplanation } from './server/llm/reportWriter.js';
import { ScanReport, Finding } from './src/types/scanner.js';
import { BoundedLruCache } from './server/cache.js';
import fs from 'fs';
import {
  saveSharedReport,
  fetchSharedReport,
  keepaliveSharedReports,
  isSharingEnabled,
} from './server/supabase.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper to sanitize strings from credentials in logs and errors
function redactSecrets(msg: string): string {
  if (!msg || typeof msg !== 'string') return '';
  return msg
    .replace(/AIza[a-zA-Z0-9_\-]{30,}/g, '[REDACTED_API_KEY]')
    .replace(/ghp_[a-zA-Z0-9]{30,}/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/github_pat_[a-zA-Z0-9_\-]{30,}/g, '[REDACTED_GITHUB_PAT]')
    .replace(/sk-[a-zA-Z0-9_\-]{20,}/g, '[REDACTED_SECRET]')
    .replace(/sk_live_[a-zA-Z0-9_\-]{20,}/g, '[REDACTED_STRIPE]');
}

// Requirement 3: Process crash safety handlers that log without secrets and keep the server alive
process.on('unhandledRejection', (reason: any) => {
  const errStr = redactSecrets(reason?.stack || reason?.message || String(reason));
  console.error('[Process Kept Alive] Unhandled Rejection:', errStr);
});

process.on('uncaughtException', (err: Error) => {
  const errStr = redactSecrets(err?.stack || err?.message || String(err));
  console.error('[Process Kept Alive] Uncaught Exception:', errStr);
});

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Trust 1st fronting reverse proxy for Render / Cloud Run
app.set('trust proxy', 1);

// Requirement 9 & Requirement 7: /healthz liveness probe endpoint
// Returns {"ok": true} with HTTP 200, no external calls, exempt from rate limits, queue, body parsing, and logging
app.get('/healthz', (_req: Request, res: Response) => {
  res.status(200).json({ ok: true });
});

// Disable X-Powered-By header
app.disable('x-powered-by');

// Requirement 7: Helmet with sensible CSP
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: [
          "'self'",
          'https://api.github.com',
          'https://raw.githubusercontent.com',
          'https://registry.npmjs.org',
          'https://pypi.org',
          'https://api.osv.dev',
          'https://generativelanguage.googleapis.com',
        ],
      },
    },
  })
);

// Requirement 7: Body parser capped at 10kb
app.use(express.json({ limit: '10kb' }));

// Requirement 7: General rate limit on all /api routes: 60 req/min per IP
const isLoopback = (ip?: string) => ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';

const apiGeneralRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req: Request) =>
    Boolean((process.env.LOAD_TEST === '1' || req.headers['x-load-test'] === '1') && isLoopback(req.ip || req.socket.remoteAddress)),
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error: 'Too many requests. Please slow down.',
    });
  },
});
app.use('/api', apiGeneralRateLimiter);

// Scan rate limit: 10 scans per hour per real client IP
const scanRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 scans per hour
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req: Request) =>
    Boolean((process.env.LOAD_TEST === '1' || req.headers['x-load-test'] === '1') && isLoopback(req.ip || req.socket.remoteAddress)),
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error: 'Rate limit exceeded: You have reached the maximum of 10 scans per hour. Please wait before running another scan.',
      rateLimited: true,
    });
  },
});

// Rate-limited health check for Gemini model (30 reqs/min)
const healthRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

// Requirement 8: In production, /api/health returns only { ok, model }
app.get('/api/health', healthRateLimiter, async (_req: Request, res: Response) => {
  const result = await checkGeminiHealth();
  const isProd = process.env.NODE_ENV === 'production';
  if (isProd) {
    return res.status(result.ok ? 200 : 503).json({
      ok: result.ok,
      model: result.model,
    });
  }
  res.status(result.ok ? 200 : 503).json(result);
});

// Requirement 4: Bounded LRU report cache (max 50 entries, 1 hour TTL)
const commitShaCache = new BoundedLruCache<string, ScanReport>(50, 60 * 60 * 1000);
const reportIdCache = new BoundedLruCache<string, ScanReport>(50, 60 * 60 * 1000);

// Requirement 6: Bounded cache to limit forceFresh to once per repo per 5 min per IP in production
const forceFreshLimiter = new BoundedLruCache<string, number>(50, 5 * 60 * 1000);

// Requirement 1: Scan Queue (allow at most 2 concurrent scans server-wide; extra scans wait in queue of max 5; beyond that HTTP 503)
interface QueueItem {
  id: string;
  run: () => Promise<void>;
  reject: (err: any) => void;
}

class ServerScanQueue {
  private maxConcurrent = 2;
  private maxQueue = 5;
  private running = 0;
  private queue: QueueItem[] = [];

  enqueue<T>(task: () => Promise<T>): Promise<T> {
    if (this.queue.length >= this.maxQueue) {
      const err: any = new Error("We're busy, try again in a minute.");
      err.status = 503;
      return Promise.reject(err);
    }

    return new Promise<T>((resolve, reject) => {
      const item: QueueItem = {
        id: Math.random().toString(36).substring(2, 9),
        run: async () => {
          this.running++;
          try {
            const result = await task();
            resolve(result);
          } catch (e) {
            reject(e);
          } finally {
            this.running--;
            this.processNext();
          }
        },
        reject,
      };

      this.queue.push(item);
      if (this.running < this.maxConcurrent) {
        this.processNext();
      }
    });
  }

  private processNext(): void {
    if (this.running >= this.maxConcurrent || this.queue.length === 0) {
      return;
    }
    const nextItem = this.queue.shift();
    if (nextItem) {
      nextItem.run();
    }
  }

  get stats() {
    return {
      running: this.running,
      queued: this.queue.length,
    };
  }
}

const scanQueue = new ServerScanQueue();

// 1. Get available sample repositories
app.get('/api/samples', (_req: Request, res: Response) => {
  const list = Object.values(SAMPLE_REPOS).map((s) => ({
    id: s.id,
    name: s.name,
    displayName: s.displayName,
    description: s.description,
    stackTag: s.stackTag,
    repoUrl: s.repoUrl,
    fileCount: s.files.length,
  }));
  res.json({ samples: list });
});

// 2. Fetch specific saved report by ID
app.get('/api/reports/:id', (req: Request, res: Response) => {
  const report = reportIdCache.get(req.params.id);
  if (!report) {
    return res.status(404).json({ error: 'Report not found' });
  }
  res.json({ report });
});

// Requirement 4: Rate limit 60 per minute per IP for GET /api/shared/:id
const sharedRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req: Request) =>
    Boolean((process.env.LOAD_TEST === '1' || req.headers['x-load-test'] === '1') && isLoopback(req.ip || req.socket.remoteAddress)),
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error: 'Too many requests. Please slow down.',
    });
  },
});

// Requirement 4: Add GET /api/shared/:id
app.get('/api/shared/:id', sharedRateLimiter, async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');

  const result = await fetchSharedReport(req.params.id);
  if (result.status === 200) {
    return res.status(200).json({ report: result.report });
  }
  return res.status(result.status).json({ error: result.error });
});

// Requirement 6: GET /api/shared-keepalive rate limited to 10 per hour per IP
const sharedKeepaliveLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 per hour
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req: Request) =>
    Boolean((process.env.LOAD_TEST === '1' || req.headers['x-load-test'] === '1') && isLoopback(req.ip || req.socket.remoteAddress)),
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error: 'Rate limit exceeded: 10 keepalive pings per hour.',
    });
  },
});

app.get('/api/shared-keepalive', sharedKeepaliveLimiter, async (_req: Request, res: Response) => {
  const result = await keepaliveSharedReports();
  res.status(200).json({ ok: result.ok });
});

// Requirement 5: GET /r/:id serving the SPA in production so deep links work, with a noindex meta tag
app.get('/r/:id', (req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Robots-Tag', 'noindex');
  const isProd = process.env.NODE_ENV === 'production';
  const indexPath = isProd
    ? path.resolve(__dirname, 'dist', 'index.html')
    : path.resolve(__dirname, 'index.html');

  if (fs.existsSync(indexPath)) {
    const html = fs.readFileSync(indexPath, 'utf8');
    const noindexHtml = html.includes('name="robots"')
      ? html
      : html.replace('<head>', '<head>\n    <meta name="robots" content="noindex" />');
    return res.status(200).send(noindexHtml);
  }
  next();
});

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function mergeFindingsByRuleAndFile(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const f of findings) {
    let key: string;
    const isOsv =
      f.ruleId === 'DEP-OSV-BATCH-CVE' ||
      f.ruleId === 'DEP-VULNERABLE-PACKAGE' ||
      Boolean(f.advisoryId);

    if (isOsv) {
      const pkgKey = `${f.packageName || ''}@${f.resolvedVersion || ''}`;
      key = `OSV:::${f.file}:::${pkgKey}`;
    } else if (f.ruleId === 'REACT-UNHANDLED-EFFECT-ERROR') {
      key = `EFFECT:::${f.file}`;
    } else if (f.packageName) {
      key = `${f.ruleId}:::${f.file}:::pkg:${f.packageName}`;
    } else {
      key = `${f.ruleId}:::${f.file}:::id:${f.id}`;
    }

    const list = groups.get(key) || [];
    list.push(f);
    groups.set(key, list);
  }

  const merged: Finding[] = [];
  let mergedCounter = 0;

  for (const list of groups.values()) {
    if (list.length === 1) {
      merged.push(list[0]);
    } else {
      mergedCounter++;
      list.sort((a, b) => {
        const diff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
        return diff !== 0 ? diff : a.line - b.line;
      });

      const primary = list[0];
      const highestSev = primary.severity;
      const isOsv = list.some((f) => f.ruleId === 'DEP-OSV-BATCH-CVE' || f.advisoryId);

      if (isOsv) {
        const allAdvisories = Array.from(new Set(list.map((f) => f.advisoryId).filter(Boolean))) as string[];
        const count = allAdvisories.length || list.length;
        const vulnWord = count === 1 ? 'known vulnerability' : 'known vulnerabilities';
        const newTitle = `${primary.packageName}@${primary.resolvedVersion}: ${count} ${vulnWord}`;

        let evidenceAdvisories = '';
        if (allAdvisories.length <= 5) {
          evidenceAdvisories = allAdvisories.join(', ');
        } else {
          const first5 = allAdvisories.slice(0, 5).join(', ');
          const remaining = allAdvisories.length - 5;
          evidenceAdvisories = `${first5}, and ${remaining} more`;
        }

        const newDescription = `${primary.packageName}@${primary.resolvedVersion} is affected by ${count} ${vulnWord}: ${evidenceAdvisories}.`;

        const mergedFinding: Finding = {
          ...primary,
          id: `${primary.id}-m${mergedCounter}`,
          title: newTitle,
          severity: highestSev,
          evidence: evidenceAdvisories,
          descriptionRaw: newDescription,
          advisoryId: allAdvisories.join(', '),
          explanation: primary.explanation
            ? {
                ...primary.explanation,
                plainEnglishRisk: `This package contains ${count} security ${vulnWord} (${evidenceAdvisories}) with severity up to ${highestSev}.`,
                nextStep: primary.explanation.nextStep,
                aiFixPrompt: primary.explanation.aiFixPrompt,
              }
            : undefined,
        };
        merged.push(mergedFinding);
      } else {
        const uniqueLines = Array.from(new Set(list.map((f) => f.line))).sort((a, b) => a - b);
        const count = uniqueLines.length > 1 ? uniqueLines.length : list.length;
        const baseTitle = primary.title.replace(/\s*\(\d+\s*places.*?\)/i, '');
        const newTitle = `${baseTitle} (${count} places)`;
        const linesListStr = uniqueLines.join(', ');

        const evidenceLines = Array.from(new Set(list.map((f) => `Line ${f.line}: ${f.evidence}`)));
        const combinedEvidence = evidenceLines.join('\n');

        const mergedFinding: Finding = {
          ...primary,
          id: `${primary.id}-m${mergedCounter}`,
          title: newTitle,
          severity: highestSev,
          line: uniqueLines[0],
          evidence: combinedEvidence,
          descriptionRaw: `${primary.descriptionRaw} (Found in ${count} places: lines ${linesListStr}).`,
          explanation: primary.explanation
            ? {
                ...primary.explanation,
                nextStep: `${primary.explanation.nextStep} (Check all ${count} occurrences at lines: ${linesListStr}).`,
                aiFixPrompt: primary.explanation.aiFixPrompt
                  ? `In ${primary.file}, resolve the ${primary.title} issue occurring in ${count} places (lines ${linesListStr}).`
                  : undefined,
              }
            : undefined,
        };
        merged.push(mergedFinding);
      }
    }
  }

  return merged;
}

// 3. Main Scan Pipeline endpoint with rate limiting & queueing
app.post('/api/scan', scanRateLimiter, async (req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now();
  let { repoUrl, sampleId, forceFresh, skipLlm } = req.body;

  if (!repoUrl && !sampleId) {
    return res.status(400).json({ error: 'Either repoUrl or sampleId must be provided' });
  }

  // Requirement 6: When NODE_ENV === 'production', ignore forceFresh and skipLlm from request bodies
  // (forceFresh allowed only once per repo per 5 min per IP)
  const isProd = process.env.NODE_ENV === 'production';
  if (isProd) {
    skipLlm = false;

    if (forceFresh) {
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown-ip';
      const repoKey = `${clientIp}:::${repoUrl || sampleId}`;
      const lastFreshTime = forceFreshLimiter.get(repoKey);
      if (lastFreshTime && Date.now() - lastFreshTime < 5 * 60 * 1000) {
        forceFresh = false;
      } else {
        forceFreshLimiter.set(repoKey, Date.now());
      }
    }
  }

  try {
    const report = await scanQueue.enqueue(async () => {
      // Requirement 2: 60s overall limit per scan (abort fetches and return a clear error)
      const scanAbortController = new AbortController();
      const timeoutId = setTimeout(() => {
        scanAbortController.abort(new Error('Scan timed out after 60 seconds'));
      }, 60000);

      try {
        // Step 1: Fetch repository files (enforces file caps, text-only, priority order)
        const fetchResult = await fetchRepository(repoUrl || '', sampleId, scanAbortController.signal);

        // Check cache by repo + branch commit SHA
        const cacheKey = `${fetchResult.repoUrl}#${fetchResult.commitSha || 'latest'}`;
        if (!forceFresh && commitShaCache.has(cacheKey)) {
          const cached = commitShaCache.get(cacheKey)!;
          return { report: cached, fromCache: true, shareId: cached.shareId };
        }

        // Step 2: Stack detector
        const stack = detectStack(fetchResult.files, fetchResult.allRepoPaths);

        // Step 3: Run 4 deterministic scanners in parallel
        const [depFindings, halFindings, secretFindings, codeFindings] = await Promise.all([
          scanDependencies(fetchResult.files, fetchResult.allRepoPaths, fetchResult.coverage.notes),
          scanHallucinatedPackages(fetchResult.files),
          scanSecrets(fetchResult.files),
          scanCodeQuality(fetchResult.files, fetchResult.allRepoPaths),
        ]);

        // Step 4: Collect all findings in shared format and merge by rule & file
        const rawFindings = [...secretFindings, ...halFindings, ...depFindings, ...codeFindings];
        const allFindings = mergeFindingsByRuleAndFile(rawFindings);

        // Step 5: Deterministic Rubric Score - CRITICAL: computed BEFORE LLM is called and never altered
        const rubric = calculateRubricScore(allFindings);

        // Runtime consistency check: total === findings.length and score === max(0, 100 - sum of deductions)
        if (rubric.counts.total !== allFindings.length) {
          console.error(
            `[Pipeline Consistency Mismatch] rubric.counts.total (${rubric.counts.total}) !== allFindings.length (${allFindings.length})`
          );
        }
        const sumDeductions =
          rubric.deductions.critical +
          rubric.deductions.high +
          rubric.deductions.medium +
          rubric.deductions.low;
        if (rubric.score !== Math.max(0, 100 - sumDeductions)) {
          console.error(
            `[Pipeline Consistency Mismatch] rubric.score (${rubric.score}) !== max(0, 100 - sum of deductions) (${Math.max(
              0,
              100 - sumDeductions
            )})`
          );
        }

        // Step 6: LLM writes the plain-English report (strictly explains findings only)
        const llmReport = skipLlm
          ? generateLocalFallbackExplanation(
              fetchResult.repoName,
              stack,
              rubric,
              allFindings,
              'Deterministic fallback analysis requested',
              'fallback'
            )
          : await writeReportWithGemini(
              fetchResult.repoName,
              stack,
              rubric,
              allFindings
            );

        // Attach verified explanations and AI fix prompts to findings
        for (const f of allFindings) {
          if (llmReport.findingExplanations[f.id]) {
            f.explanation = {
              plainEnglishRisk: llmReport.findingExplanations[f.id].plainEnglishRisk,
              nextStep: llmReport.findingExplanations[f.id].nextStep,
              aiFixPrompt: llmReport.findingExplanations[f.id].aiFixPrompt,
              source: llmReport.findingExplanations[f.id].source,
            };
          }
        }

        const reportId = `rep-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
        const finalReport: ScanReport = {
          id: reportId,
          repoUrl: fetchResult.repoUrl,
          repoName: fetchResult.repoName,
          branch: fetchResult.branch,
          commitSha: fetchResult.commitSha,
          scannedAt: new Date().toISOString(),
          coverage: fetchResult.coverage,
          stack,
          rubric,
          findings: allFindings,
          executiveSummary: {
            overview: llmReport.overview,
            topThreeFixes: llmReport.topThreeFixes,
            vibeAppInsight: llmReport.vibeAppInsight,
            usedFallback: llmReport.usedFallback,
            geminiModelUsed: llmReport.geminiModelUsed,
          },
          agentRulesCompliant: true,
          scanDurationMs: Date.now() - startTime,
          isSampleRepo: fetchResult.isSampleRepo,
        };

        // Requirement 3: After a successful real scan (not sample demos), when sharing is enabled, save the final masked report and return shareId
        let shareId: string | undefined = undefined;
        if (!fetchResult.isSampleRepo && isSharingEnabled()) {
          try {
            const savedId = await saveSharedReport(finalReport);
            if (savedId) {
              shareId = savedId;
              finalReport.shareId = savedId;
            }
          } catch (shareErr: any) {
            console.warn('[Shareable Report] Failed to save shared report:', shareErr?.message || shareErr);
          }
        }

        // Store in bounded LRU caches
        commitShaCache.set(cacheKey, finalReport);
        reportIdCache.set(reportId, finalReport);

        return { report: finalReport, fromCache: false, shareId };
      } finally {
        clearTimeout(timeoutId);
      }
    });

    res.json(report);
  } catch (error: any) {
    if (error.status === 503 || error.message?.includes("We're busy")) {
      return res.status(503).json({
        error: "We're busy, try again in a minute.",
      });
    }

    if (error.name === 'AbortError' || error.message?.includes('timed out') || error.message?.includes('60 seconds')) {
      return res.status(408).json({
        error: 'Scan timed out after 60 seconds. Please try scanning a smaller repository or choose a sample app.',
      });
    }

    if (error.message?.includes('15 MB payload limit')) {
      return res.status(413).json({
        error: 'Repository size exceeded the 15 MB payload limit.',
      });
    }

    next(error);
  }
});

// Start Express server and mount Vite middleware in development
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  // Requirement 3: Express error middleware returning friendly JSON with no stack traces
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const safeMsg = redactSecrets(err.message || 'An unexpected error occurred while scanning.');
    console.error(`[Express Error Handler] Status ${status}:`, safeMsg);
    res.status(status).json({
      error: status === 500 ? 'Something went wrong on our side. Try again in a minute.' : safeMsg,
    });
  });

  app.listen(PORT, '0.0.0.0', () => {
    const hasGithubToken = Boolean(process.env.GITHUB_TOKEN && process.env.GITHUB_TOKEN.trim().length > 0);
    console.log(`[Startup] GITHUB_TOKEN configured: ${hasGithubToken}`);
    console.log(`[Startup] Supabase sharing configured: ${isSharingEnabled()}`);
    console.log(`Tumorr server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
