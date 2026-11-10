import express, { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
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

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Task 3: Configure trust proxy to 1 (trust 1st fronting reverse proxy like Cloud Run / Nginx / Vercel)
// This ensures req.ip resolves to the true client IP from X-Forwarded-For rather than the load balancer
app.set('trust proxy', 1);

app.use(express.json({ limit: '10mb' }));

// Task 2: express-rate-limit - 10 scans per hour per real client IP
const scanRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 scans per hour
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error: 'Rate limit exceeded: You have reached the maximum of 10 scans per hour. Please wait before running another scan.',
      rateLimited: true,
    });
  },
});

// Task 5: Rate-limited health check for Gemini model (30 reqs/min)
const healthRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 req/min
  standardHeaders: true,
  legacyHeaders: false,
});

// Task 5: Health check endpoint testing one tiny call to configured Gemini model
app.get('/api/health', healthRateLimiter, async (_req: Request, res: Response) => {
  const result = await checkGeminiHealth();
  res.status(result.ok ? 200 : 503).json(result);
});

// Task 2: Cache reports by repo + branch commit SHA
const commitShaCache = new Map<string, ScanReport>();
const reportIdCache = new Map<string, ScanReport>();

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

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// Requirement 1: Merge keys - only merge findings with the same rule AND the same file AND the same package or identifier.
// For OSV findings, group all advisories for the same package and version into ONE finding listing every advisory ID,
// with severity = the highest in the group and one deduction at that severity. Never merge across different packages.
// Merging same-file useEffect findings is fine.
export function mergeFindingsByRuleAndFile(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const f of findings) {
    let key: string;
    const isOsv =
      f.ruleId === 'DEP-OSV-BATCH-CVE' ||
      f.ruleId === 'DEP-VULNERABLE-PACKAGE' ||
      Boolean(f.advisoryId);

    if (isOsv) {
      // Group all advisories for the same package and version into ONE finding
      const pkgKey = `${f.packageName || ''}@${f.resolvedVersion || ''}`;
      key = `OSV:::${f.file}:::${pkgKey}`;
    } else if (f.ruleId === 'REACT-UNHANDLED-EFFECT-ERROR') {
      // Merging same-file useEffect findings is fine
      key = `EFFECT:::${f.file}`;
    } else if (f.packageName) {
      key = `${f.ruleId}:::${f.file}:::pkg:${f.packageName}`;
    } else {
      // Only merge if sharing same rule, file, and identifier. If no identifier, keep distinct
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
      // Sort list by severity descending (highest severity first), then by line ascending
      list.sort((a, b) => {
        const diff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
        return diff !== 0 ? diff : a.line - b.line;
      });

      const primary = list[0];
      const highestSev = primary.severity;
      const isOsv = list.some((f) => f.ruleId === 'DEP-OSV-BATCH-CVE' || f.advisoryId);

      if (isOsv) {
        // Collect every advisory ID
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

// 3. Main Scan Pipeline endpoint with rate limiting
app.post('/api/scan', scanRateLimiter, async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { repoUrl, sampleId, forceFresh, skipLlm } = req.body;

  if (!repoUrl && !sampleId) {
    return res.status(400).json({ error: 'Either repoUrl or sampleId must be provided' });
  }

  try {
    // Step 1: Fetch repository files (enforces file caps, text-only, priority order)
    const fetchResult = await fetchRepository(repoUrl || '', sampleId);

    // Task 2: Check cache by repo + branch commit SHA
    const cacheKey = `${fetchResult.repoUrl}#${fetchResult.commitSha || 'latest'}`;
    if (!forceFresh && commitShaCache.has(cacheKey)) {
      const cached = commitShaCache.get(cacheKey)!;
      return res.json({ report: cached, fromCache: true });
    }

    // Step 2: Stack detector (Task 1: checks full tree allRepoPaths for tests)
    const stack = detectStack(fetchResult.files, fetchResult.allRepoPaths);

    // Step 3: Run 4 deterministic scanners in parallel (Task 1: codeScanner checks full tree for tests)
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
    // Exactly one deduction per merged finding
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
    const report: ScanReport = {
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

    // Store in caches
    commitShaCache.set(cacheKey, report);
    reportIdCache.set(reportId, report);

    res.json({ report });
  } catch (error: any) {
    console.error('Scan pipeline error:', error.message || error);
    res.status(500).json({
      error: error.message || 'An unexpected error occurred while scanning the repository.',
    });
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

  app.listen(PORT, '0.0.0.0', () => {
    const hasGithubToken = Boolean(process.env.GITHUB_TOKEN && process.env.GITHUB_TOKEN.trim().length > 0);
    console.log(`[Startup] GITHUB_TOKEN configured: ${hasGithubToken}`);
    console.log(`Tumorr server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
