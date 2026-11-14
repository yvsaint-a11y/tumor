import { fetchRepository } from '../server/github/fetcher.js';
import { detectStack } from '../server/stackDetector.js';
import { scanDependencies } from '../server/scanners/dependencyScanner.js';
import { scanHallucinatedPackages } from '../server/scanners/hallucinationScanner.js';
import { scanSecrets } from '../server/scanners/secretScanner.js';
import { scanCodeQuality } from '../server/scanners/codeScanner.js';
import { calculateRubricScore } from '../server/scanners/rubric.js';
import { mergeFindingsByRuleAndFile } from '../server/scanners/mergeFindings.js';
import {
  setMockSupabaseClient,
  fetchSharedReport,
  saveSharedReport,
  keepaliveSharedReports,
} from '../server/supabase.js';
import {
  GITHUB_ISSUES_REPO,
  buildFalsePositiveIssueUrl,
  buildRemovalIssueUrl,
} from '../src/config.js';
import { ScanReport } from '../src/types/scanner.js';

async function verifyDemoScans() {
  console.log('\n--- 1. VERIFYING 4 DEMO SCANS (skipLlm = true) ---');
  const demos = [
    { id: 'prompt-injection-test', expectedScore: 29, expectedGrade: 'F' },
    { id: 'bolt-vibe-saas', expectedScore: 0, expectedGrade: 'F' },
    { id: 'cursor-python-api', expectedScore: 0, expectedGrade: 'F' },
    { id: 'fullstack-vibe-store', expectedScore: 0, expectedGrade: 'F' },
  ];

  for (const demo of demos) {
    const fetchResult = await fetchRepository('', demo.id);
    const stack = detectStack(fetchResult.files, fetchResult.allRepoPaths);
    const [depFindings, halFindings, secretFindings, codeFindings] = await Promise.all([
      scanDependencies(fetchResult.files, fetchResult.allRepoPaths, fetchResult.coverage.notes),
      scanHallucinatedPackages(fetchResult.files),
      scanSecrets(fetchResult.files),
      scanCodeQuality(fetchResult.files, fetchResult.allRepoPaths),
    ]);

    const rawFindings = [...secretFindings, ...halFindings, ...depFindings, ...codeFindings];
    const allFindings = mergeFindingsByRuleAndFile(rawFindings);
    const rubric = calculateRubricScore(allFindings);

    const sumDeductions =
      rubric.deductions.critical +
      rubric.deductions.high +
      rubric.deductions.medium +
      rubric.deductions.low;

    console.log(
      `Demo [${demo.id}]: Score=${rubric.score}/${rubric.grade} (Expected ${demo.expectedScore}/${demo.expectedGrade}), Total Findings=${allFindings.length}, Sum Deductions=${sumDeductions}`
    );
    console.log(
      `  Counts: Crit=${rubric.counts.critical}, High=${rubric.counts.high}, Med=${rubric.counts.medium}, Low=${rubric.counts.low}, Info=${rubric.counts.info}`
    );
    console.log(
      `  Deductions: Crit=-${rubric.deductions.critical}, High=-${rubric.deductions.high}, Med=-${rubric.deductions.medium}, Low=-${rubric.deductions.low}`
    );

    if (rubric.score !== demo.expectedScore || rubric.grade !== demo.expectedGrade) {
      throw new Error(`Mismatch in ${demo.id}: got ${rubric.score}/${rubric.grade}, expected ${demo.expectedScore}/${demo.expectedGrade}`);
    }

    if (rubric.counts.total !== allFindings.length) {
      throw new Error(`Total count mismatch in ${demo.id}: total ${rubric.counts.total} !== findings length ${allFindings.length}`);
    }

    if (rubric.score !== Math.max(0, 100 - sumDeductions)) {
      throw new Error(`Score reconciliation mismatch in ${demo.id}: score ${rubric.score} !== max(0, 100 - ${sumDeductions})`);
    }
  }
  console.log('✓ All 4 demo scans reconciled perfectly and scores match expected values.');
}

async function verifySharedReportStates() {
  console.log('\n--- 2. VERIFYING SHARED REPORT STATES (Mock Supabase) ---');

  // Test State 1: Invalid ID format (400)
  const badIdRes = await fetchSharedReport('too-short');
  console.log('State: Invalid ID format -> Status:', badIdRes.status);
  if (badIdRes.status !== 400) throw new Error('Expected 400 for bad ID');

  // Test State 2: 404 Not Found when ID does not exist
  const mockDb = new Map<string, any>();
  const mockSupabase = {
    from: (table: string) => ({
      select: (_cols?: string) => ({
        eq: (col: string, val: string) => ({
          single: async () => {
            const row = mockDb.get(val);
            if (!row) return { data: null, error: new Error('Row not found') };
            return { data: row, error: null };
          },
        }),
        limit: async (_n: number) => ({ data: [{ id: 'dummy' }], error: null }),
        lt: (_col: string, val: string) => ({
          limit: async (lim: number) => {
            const expired: any[] = [];
            for (const [id, row] of mockDb.entries()) {
              if (row.expires_at && row.expires_at < val) {
                expired.push({ id });
                if (expired.length >= lim) break;
              }
            }
            return { data: expired, error: null };
          },
        }),
      }),
      insert: async (payload: any) => {
        mockDb.set(payload.id, payload);
        return { error: null };
      },
      update: (_updates: any) => ({
        eq: (col: string, val: string) => {
          const row = mockDb.get(val);
          if (row) Object.assign(row, _updates);
          return Promise.resolve({ error: null });
        },
      }),
      delete: () => ({
        in: async (col: string, ids: string[]) => {
          for (const id of ids) {
            mockDb.delete(id);
          }
          return { error: null };
        },
      }),
    }),
  };

  setMockSupabaseClient(mockSupabase);

  // State 2: 404 Not Found
  const notFoundRes = await fetchSharedReport('123456789012');
  console.log('State: 404 Not Found -> Status:', notFoundRes.status);
  if (notFoundRes.status !== 404) throw new Error('Expected 404 for missing ID');

  // State 3: 410 Expired
  const expiredId = 'exp123456789';
  mockDb.set(expiredId, {
    id: expiredId,
    expires_at: new Date(Date.now() - 10000).toISOString(),
    report: { id: 'test-rep' },
    view_count: 0,
  });
  const expiredRes = await fetchSharedReport(expiredId);
  console.log('State: 410 Expired -> Status:', expiredRes.status);
  if (expiredRes.status !== 410) throw new Error('Expected 410 for expired report');

  // State 4: 200 Success
  const validReport: ScanReport = {
    id: 'rep-test-1',
    repoUrl: 'https://github.com/example/valid-repo',
    repoName: 'example/valid-repo',
    branch: 'main',
    commitSha: 'abcdef123456789',
    scannedAt: new Date().toISOString(),
    coverage: {
      totalFilesInRepo: 10,
      filesScanned: 10,
      totalScannableFiles: 10,
      nonScannableSkipped: 0,
      isPartial: false,
      skippedSummary: { overCap: 0, tooLarge: 0, binary: 0, ignoredFolder: 0 },
    },
    stack: {
      languages: ['typescript'],
      frameworks: ['react'],
      manifests: ['package.json'],
      hasTests: true,
      hasLockfile: true,
      totalFilesScanned: 10,
      totalLinesScanned: 500,
    },
    rubric: {
      score: 95,
      grade: 'A',
      verdict: 'Healthy',
      summary: 'Clean repository',
      counts: { critical: 0, high: 0, medium: 1, low: 0, info: 0, total: 1 },
      deductions: { critical: 0, high: 0, medium: 5, low: 0 },
    },
    findings: [],
    executiveSummary: {
      overview: 'Healthy codebase',
      topThreeFixes: [],
      vibeAppInsight: 'Well built',
    },
    agentRulesCompliant: true,
    scanDurationMs: 450,
  };

  const savedId = await saveSharedReport(validReport);
  console.log('Saved Report ID:', savedId);
  if (!savedId) throw new Error('Expected savedId from mock save');

  const fetchSuccess = await fetchSharedReport(savedId);
  console.log('State: 200 Success -> Status:', fetchSuccess.status);
  if (fetchSuccess.status !== 200 || !fetchSuccess.report) {
    throw new Error('Expected 200 with report');
  }

  // State 5: Keepalive Cleanup of expired rows (up to 500)
  console.log('Checking Keepalive cleanup: expired rows currently in DB...');
  const keepaliveResult = await keepaliveSharedReports();
  console.log('Keepalive Result:', keepaliveResult);
  if (!keepaliveResult.ok) throw new Error('Expected keepalive ok: true');
  if (mockDb.has(expiredId)) {
    throw new Error('Expired ID was not cleaned up by keepalive');
  }
  console.log('✓ Expired ID was automatically cleaned up by keepaliveSharedReports.');

  // State 6: Save timeout behavior
  const slowMockSupabase = {
    from: () => ({
      insert: () => new Promise((resolve) => setTimeout(resolve, 3500)),
    }),
  };
  setMockSupabaseClient(slowMockSupabase);
  const timeoutStart = Date.now();
  const timedOutId = await saveSharedReport(validReport);
  const timeoutElapsed = Date.now() - timeoutStart;
  console.log(`Save 3-second timeout test: returned ${timedOutId} in ${timeoutElapsed}ms`);
  if (timedOutId !== null) {
    throw new Error('Expected null on timeout');
  }
  if (timeoutElapsed > 3500) {
    throw new Error('Timeout took longer than expected');
  }
  console.log('✓ saveSharedReport cleanly timed out and returned null without throwing.');
}

function verifyIssueUrlBuilders() {
  console.log('\n--- 3. VERIFYING ISSUE URL BUILDERS ---');
  console.log('GITHUB_ISSUES_REPO:', GITHUB_ISSUES_REPO);
  if (GITHUB_ISSUES_REPO !== 'yvsaint-a11y/tumor') {
    throw new Error('GITHUB_ISSUES_REPO must be yvsaint-a11y/tumor');
  }

  const fpUrl = buildFalsePositiveIssueUrl({
    ruleId: 'SEC-OPENAI_KEY',
    repoName: 'test-owner/test-app',
    findingTitle: 'Exposed secret key',
    repoUrl: 'https://github.com/test-owner/test-app',
    commitSha: '1234567890abcdef',
    file: 'src/config.ts',
    line: 42,
    scannedAt: '2026-11-11T00:00:00.000Z',
  });
  const parsedFpUrl = new URL(fpUrl);
  const fpBody = parsedFpUrl.searchParams.get('body') || '';
  console.log('Sample False Positive URL:', fpUrl);
  console.log('False Positive Body Length:', fpBody.length);
  if (!fpUrl.includes('https://github.com/yvsaint-a11y/tumor/issues/new')) {
    throw new Error('Invalid base URL for false positive');
  }
  if (!fpUrl.includes('False+positive%3A+SEC-OPENAI_KEY+in+test-owner%2Ftest-app')) {
    throw new Error('Invalid title in false positive URL');
  }
  if (fpBody.length > 1500) {
    throw new Error(`False positive body exceeded 1500 chars: ${fpBody.length}`);
  }
  if (/evidence|```/i.test(fpBody)) {
    throw new Error('False positive body should not contain code snippet or evidence');
  }

  const rmUrl = buildRemovalIssueUrl('abc123xyz789');
  console.log('Sample Removal Request URL:', rmUrl);
  if (!rmUrl.includes('Remove+shared+report+abc123xyz789')) {
    throw new Error('Invalid title in removal request URL');
  }
  console.log('✓ Issue URL builders verified.');
}

async function main() {
  await verifyDemoScans();
  await verifySharedReportStates();
  verifyIssueUrlBuilders();
  console.log('\n=======================================');
  console.log('ALL VERIFICATIONS PASSED SUCCESSFULLY');
  console.log('=======================================');
}

main().catch((err) => {
  console.error('VERIFICATION FAILED:', err);
  process.exit(1);
});
