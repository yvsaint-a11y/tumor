import { RepoFile, SAMPLE_REPOS } from './sampleRepos.js';
import { ScanCoverage } from '../../src/types/scanner.js';

export interface FetchResult {
  repoUrl: string;
  repoName: string;
  branch: string;
  commitSha: string;
  files: RepoFile[];
  allRepoPaths: string[]; // Full repo file tree paths, including skipped files (Task 1)
  totalLines: number;
  isSampleRepo: boolean;
  coverage: ScanCoverage;
  warnings?: string[];
}

const MAX_FILES = 300;
const MAX_SOURCE_FILE_SIZE_BYTES = 100 * 1024; // 100KB per source/config file
const MAX_MANIFEST_LOCK_SIZE_BYTES = 5 * 1024 * 1024; // 5MB cap for manifests & lockfiles

const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.pyw',
  '.json', '.jsonc',
  '.toml', '.yaml', '.yml'
]);

const MANIFEST_AND_LOCK_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'bun.lock',
  'bun.lockb',
  'npm-shrinkwrap.json',
  'requirements.txt',
  'pyproject.toml',
  'pipfile',
  'pipfile.lock',
  'setup.py',
  'setup.cfg'
]);

const IGNORED_PATHS = [
  'node_modules/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '.turbo/',
  '__pycache__/',
  '.pytest_cache/',
  '.venv/',
  'venv/',
  'coverage/',
  '.ds_store'
];

export function isIgnoredPath(path: string): boolean {
  const lower = path.toLowerCase();
  return IGNORED_PATHS.some((ignored) => lower.includes(ignored) || lower.startsWith(ignored));
}

export function isManifestOrLock(path: string): boolean {
  const filename = path.toLowerCase().split('/').pop() || '';
  return MANIFEST_AND_LOCK_NAMES.has(filename);
}

export function isEnvFile(path: string): boolean {
  const filename = path.toLowerCase().split('/').pop() || '';
  return filename.startsWith('.env');
}

export function isScannableFile(path: string): boolean {
  if (isIgnoredPath(path)) return false;
  const lower = path.toLowerCase();

  if (isManifestOrLock(path) || isEnvFile(path)) return true;

  for (const ext of SCANNABLE_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }

  return false;
}

export const ALLOWED_OUTBOUND_HOSTS = new Set([
  'api.github.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  'pypi.org',
  'api.osv.dev',
  'generativelanguage.googleapis.com',
]);

export function assertAllowedOutboundHost(urlStr: string): void {
  try {
    const parsed = new URL(urlStr);
    if (!ALLOWED_OUTBOUND_HOSTS.has(parsed.hostname.toLowerCase())) {
      throw new Error(`Outbound network call to unauthorized host "${parsed.hostname}" is blocked.`);
    }
  } catch (err: any) {
    if (err.message.includes('blocked')) throw err;
    throw new Error(`Invalid outbound URL: ${urlStr}`);
  }
}

const IDENTIFIER_REGEX = /^[a-zA-Z0-9_.-]+$/;

export function parseGitHubUrl(input: string): { owner: string; repo: string } | null {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();
  // Enforce max 200 characters
  if (trimmed.length > 200 || trimmed.length === 0) return null;

  // Handle owner/repo shorthand
  if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(trimmed)) {
    const [o, r] = trimmed.split('/');
    if (IDENTIFIER_REGEX.test(o) && IDENTIFIER_REGEX.test(r)) {
      return { owner: o, repo: r };
    }
    return null;
  }

  // Strict URL regex for github.com/<owner>/<repo>(.git)?(/tree/<branch>)?(/)?
  const urlMatch = trimmed.match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:\/tree\/[^\/\s]+)?\/?$/i
  );

  if (urlMatch) {
    const owner = urlMatch[1];
    const repo = urlMatch[2].replace(/\.git$/i, '');
    if (IDENTIFIER_REGEX.test(owner) && IDENTIFIER_REGEX.test(repo)) {
      return { owner, repo };
    }
  }

  return null;
}

function computeFilePriority(path: string): number {
  const lower = path.toLowerCase();
  const filename = lower.split('/').pop() || '';

  // 1. Manifests (Highest priority)
  if (
    filename === 'package.json' ||
    filename === 'requirements.txt' ||
    filename === 'pyproject.toml' ||
    filename === 'pipfile' ||
    filename === 'setup.py'
  ) {
    return 1;
  }

  // 2. Lockfiles
  if (
    filename === 'package-lock.json' ||
    filename === 'pnpm-lock.yaml' ||
    filename === 'yarn.lock' ||
    filename === 'bun.lock' ||
    filename === 'bun.lockb' ||
    filename === 'npm-shrinkwrap.json' ||
    filename === 'poetry.lock' ||
    filename === 'pipfile.lock'
  ) {
    return 2;
  }

  // 3. Environment files
  if (filename.startsWith('.env')) {
    return 3;
  }

  // 6. Tests and docs (Lowest priority - skipped first when cap is reached)
  if (
    lower.includes('/tests/') ||
    lower.includes('/__tests__/') ||
    lower.includes('/test/') ||
    lower.startsWith('test/') ||
    lower.startsWith('tests/') ||
    lower.includes('.test.') ||
    lower.includes('.spec.') ||
    lower.startsWith('test_') ||
    lower.endsWith('_test.py') ||
    lower.endsWith('.test.js') ||
    lower.endsWith('.test.ts') ||
    lower.endsWith('.spec.js') ||
    lower.endsWith('.spec.ts') ||
    lower.includes('/docs/') ||
    lower.startsWith('docs/') ||
    lower.endsWith('.md')
  ) {
    return 6;
  }

  // 4. Source folders
  if (
    lower.startsWith('src/') ||
    lower.startsWith('app/') ||
    lower.startsWith('server/') ||
    lower.startsWith('api/') ||
    lower.startsWith('lib/') ||
    lower.includes('/src/') ||
    lower.includes('/app/')
  ) {
    return 4;
  }

  // 5. Everything else
  return 5;
}

function handleGitHubRateLimit(headers: Headers): string {
  const remaining = headers.get('x-ratelimit-remaining');
  const resetEpoch = headers.get('x-ratelimit-reset');
  const limit = headers.get('x-ratelimit-limit');

  if (remaining === '0' || resetEpoch) {
    let resetMsg = '';
    if (resetEpoch) {
      const resetTime = new Date(parseInt(resetEpoch, 10) * 1000);
      const minutesRemaining = Math.max(1, Math.round((resetTime.getTime() - Date.now()) / 60000));
      resetMsg = ` Resets in ${minutesRemaining} minute(s) at ${resetTime.toLocaleTimeString()} UTC.`;
    }
    return `GitHub API rate limit exceeded (Limit: ${limit || '60'} reqs/hr).${resetMsg} You can configure a server GITHUB_TOKEN or test instantly with one of the sample apps!`;
  }
  return 'GitHub API rate limit encountered.';
}

export async function fetchRepository(
  repoInput: string,
  sampleId?: string,
  signal?: AbortSignal
): Promise<FetchResult> {
  // Check if sample repo was requested
  if (sampleId && SAMPLE_REPOS[sampleId]) {
    const sample = SAMPLE_REPOS[sampleId];
    let totalLines = 0;
    for (const f of sample.files) {
      totalLines += f.content.split('\n').length;
    }
    return {
      repoUrl: sample.repoUrl,
      repoName: sample.name,
      branch: 'main',
      commitSha: sample.commitSha,
      files: sample.files,
      allRepoPaths: sample.files.map((f) => f.path),
      totalLines,
      isSampleRepo: true,
      coverage: {
        totalFilesInRepo: sample.files.length,
        filesScanned: sample.files.length,
        totalScannableFiles: sample.files.length,
        nonScannableSkipped: 0,
        isPartial: false,
        skippedSummary: {
          overCap: 0,
          tooLarge: 0,
          binary: 0,
          ignoredFolder: 0,
        },
      },
    };
  }

  const parsed = parseGitHubUrl(repoInput);
  if (!parsed) {
    throw new Error('Please enter a valid public GitHub URL (e.g. https://github.com/owner/repo) or choose a sample app.');
  }

  const { owner, repo } = parsed;
  const warnings: string[] = [];

  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'Tumorr/1.0',
  };

  const hasToken = Boolean(process.env.GITHUB_TOKEN && process.env.GITHUB_TOKEN.trim().length > 0);
  // Read server-side GITHUB_TOKEN if configured (never logged or sent to client)
  if (hasToken) {
    headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN!.trim()}`;
  }

  let defaultBranch = 'main';
  let commitSha = '';

  try {
    const repoInfoUrl = `https://api.github.com/repos/${owner}/${repo}`;
    assertAllowedOutboundHost(repoInfoUrl);
    const repoInfoRes = await fetch(repoInfoUrl, { headers, signal });
    console.log(
      `[GitHub API] GET /repos/${owner}/${repo} | GITHUB_TOKEN present: ${hasToken} | x-ratelimit-limit: ${
        repoInfoRes.headers.get('x-ratelimit-limit') || 'unknown'
      }`
    );

    if (!repoInfoRes.ok) {
      if (repoInfoRes.status === 403) {
        throw new Error(handleGitHubRateLimit(repoInfoRes.headers));
      }
      if (repoInfoRes.status === 404) {
        throw new Error(`GitHub repository "${owner}/${repo}" was not found or is private. Make sure the repository is public.`);
      }
      throw new Error(`GitHub API error (${repoInfoRes.status}): ${repoInfoRes.statusText}`);
    }
    const repoInfo = (await repoInfoRes.json()) as any;
    defaultBranch = repoInfo.default_branch || 'main';
  } catch (err: any) {
    if (signal?.aborted) throw err;
    if (err.message.includes('rate limit') || err.message.includes('not found')) {
      throw err;
    }
    defaultBranch = 'main';
  }

  // Fetch branch commit SHA for caching
  try {
    const branchUrl = `https://api.github.com/repos/${owner}/${repo}/branches/${defaultBranch}`;
    assertAllowedOutboundHost(branchUrl);
    const branchRes = await fetch(branchUrl, { headers, signal });
    console.log(
      `[GitHub API] GET /repos/${owner}/${repo}/branches/${defaultBranch} | GITHUB_TOKEN present: ${hasToken} | x-ratelimit-limit: ${
        branchRes.headers.get('x-ratelimit-limit') || 'unknown'
      }`
    );

    if (branchRes.ok) {
      const branchData = (await branchRes.json()) as any;
      commitSha = branchData.commit?.sha || '';
    }
  } catch (err: any) {
    if (signal?.aborted) throw err;
    commitSha = '';
  }

  // Fetch Git Tree recursively
  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`;
  assertAllowedOutboundHost(treeUrl);
  const treeRes = await fetch(treeUrl, { headers, signal });
  console.log(
    `[GitHub API] GET /repos/${owner}/${repo}/git/trees/${defaultBranch} | GITHUB_TOKEN present: ${hasToken} | x-ratelimit-limit: ${
      treeRes.headers.get('x-ratelimit-limit') || 'unknown'
    }`
  );

  if (!treeRes.ok) {
    if (treeRes.status === 403) {
      throw new Error(handleGitHubRateLimit(treeRes.headers));
    }
    // Try master fallback
    if (defaultBranch === 'main') {
      const fallbackUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`;
      assertAllowedOutboundHost(fallbackUrl);
      const fallbackRes = await fetch(fallbackUrl, { headers, signal });
      console.log(
        `[GitHub API] GET /repos/${owner}/${repo}/git/trees/master (fallback) | GITHUB_TOKEN present: ${hasToken} | x-ratelimit-limit: ${
          fallbackRes.headers.get('x-ratelimit-limit') || 'unknown'
        }`
      );
      if (fallbackRes.ok) {
        return processGitTree(owner, repo, 'master', commitSha || 'master-head', await fallbackRes.json(), headers, warnings, signal);
      }
    }
    throw new Error(`Failed to read repository tree: ${treeRes.statusText}`);
  }

  const treeData = (await treeRes.json()) as any;
  if (!commitSha) {
    commitSha = treeData.sha || `${owner}/${repo}/${defaultBranch}`;
  }

  return processGitTree(owner, repo, defaultBranch, commitSha, treeData, headers, warnings, signal);
}

async function processGitTree(
  owner: string,
  repo: string,
  branch: string,
  commitSha: string,
  treeData: any,
  headers: Record<string, string>,
  warnings: string[],
  signal?: AbortSignal
): Promise<FetchResult> {
  const treeNodes: Array<{ path: string; size?: number; url: string; type: string }> = treeData.tree || [];
  const allBlobs = treeNodes.filter((n) => n.type === 'blob');
  const totalFilesInRepo = allBlobs.length;
  const allRepoPaths = treeNodes.map((n) => n.path);

  let skippedIgnoredFolder = 0;
  let skippedNonScannable = 0;
  let skippedTooLarge = 0;
  let totalScannableFiles = 0;
  const coverageNotes: string[] = [];

  const scannableCandidates: Array<{ path: string; size?: number; url: string; type: string; priority: number }> = [];

  for (const node of allBlobs) {
    const path = node.path;

    // 1. Check if path is in an ignored folder (node_modules, dist, build, .git, etc.)
    if (isIgnoredPath(path)) {
      skippedIgnoredFolder++;
      continue;
    }

    // 2. Check if scannable (source, config, manifests, lockfiles)
    if (!isScannableFile(path)) {
      skippedNonScannable++;
      continue;
    }

    totalScannableFiles++;

    // 3. Check file size cap: 5MB for manifests and lockfiles, 100KB for other source/config
    const isManifestLock = isManifestOrLock(path);
    const sizeCap = isManifestLock ? MAX_MANIFEST_LOCK_SIZE_BYTES : MAX_SOURCE_FILE_SIZE_BYTES;

    if (node.size && node.size > sizeCap) {
      skippedTooLarge++;
      if (
        isManifestLock &&
        (path.toLowerCase().endsWith('lock.json') ||
          path.toLowerCase().endsWith('.lock') ||
          path.toLowerCase().endsWith('lock.yaml'))
      ) {
        coverageNotes.push(
          `Lockfile "${path}" (${Math.round(node.size / 1024)}KB) exceeded the 5MB size limit and could not be parsed.`
        );
      }
      continue;
    }

    scannableCandidates.push({
      ...node,
      priority: computeFilePriority(path),
    });
  }

  // Sort scannable candidates by priority (1 to 6), then alphabetically
  scannableCandidates.sort((a, b) => {
    if (a.priority !== b.priority) {
      return a.priority - b.priority;
    }
    return a.path.localeCompare(b.path);
  });

  const selected = scannableCandidates.slice(0, MAX_FILES);
  const skippedOverCap = Math.max(0, scannableCandidates.length - MAX_FILES);

  // If a lockfile existed in allRepoPaths but was not selected (e.g. over cap), record a note
  const lockfileNames = [
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'bun.lock',
    'bun.lockb',
    'npm-shrinkwrap.json',
    'poetry.lock',
    'pipfile.lock',
  ];
  for (const p of allRepoPaths) {
    const lower = p.toLowerCase();
    if (lockfileNames.some((name) => lower.endsWith(name))) {
      const isSelected = selected.some((s) => s.path === p);
      if (!isSelected && !coverageNotes.some((n) => n.includes(p))) {
        coverageNotes.push(`Lockfile "${p}" was detected in repository but was not parsed.`);
      }
    }
  }

  // Rule 2: coverage.isPartial is true ONLY when scannable files were skipped because of the file-count cap or the size cap.
  const isPartial = skippedOverCap > 0 || skippedTooLarge > 0;

  if (isPartial) {
    if (skippedTooLarge > 0 && skippedOverCap > 0) {
      warnings.push(
        `Scanned ${selected.length} of ${totalScannableFiles} scannable files (${skippedOverCap} over cap, ${skippedTooLarge} over size limit). This score may be too optimistic.`
      );
    } else if (skippedTooLarge > 0) {
      warnings.push(
        `Scanned ${selected.length} of ${totalScannableFiles} scannable files (${skippedTooLarge} source file${skippedTooLarge === 1 ? '' : 's'} skipped because of the size limit). This score may be too optimistic.`
      );
    } else {
      warnings.push(
        `Scanned ${selected.length} of ${totalScannableFiles} scannable files (${skippedOverCap} source file${skippedOverCap === 1 ? '' : 's'} skipped because of the file cap). This score may be too optimistic.`
      );
    }
  }

  // Cap total bytes fetched across scan at 15 MB
  const MAX_SCAN_BYTES = 15 * 1024 * 1024;
  let totalBytesFetched = 0;

  // Fetch contents in parallel batches of 8 (Requirement 2: cap parallel fetches at 8)
  const files: RepoFile[] = [];
  let totalLines = 0;
  const batchSize = 8;

  for (let i = 0; i < selected.length; i += batchSize) {
    signal?.throwIfAborted();
    const batch = selected.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (item) => {
        try {
          signal?.throwIfAborted();
          const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${item.path}`;
          assertAllowedOutboundHost(rawUrl);
          const rawHeaders: Record<string, string> = { 'User-Agent': 'Tumorr/1.0' };
          if (headers['Authorization']) {
            rawHeaders['Authorization'] = headers['Authorization'];
          }
          const rawRes = await fetch(rawUrl, {
            headers: rawHeaders,
            signal,
          });

          if (rawRes.ok) {
            const text = await rawRes.text();
            return { path: item.path, content: text };
          }

          // Fallback to blob API
          assertAllowedOutboundHost(item.url);
          const blobRes = await fetch(item.url, { headers, signal });
          if (blobRes.ok) {
            const blobData = (await blobRes.json()) as any;
            if (blobData.encoding === 'base64') {
              const text = Buffer.from(blobData.content, 'base64').toString('utf8');
              return { path: item.path, content: text };
            }
          }
          return null;
        } catch (err: any) {
          if (signal?.aborted) throw err;
          return null;
        }
      })
    );

    for (const res of results) {
      if (res && res.content) {
        const byteLen = Buffer.byteLength(res.content, 'utf8');
        totalBytesFetched += byteLen;
        if (totalBytesFetched > MAX_SCAN_BYTES) {
          throw new Error('Repository scan exceeded the 15 MB payload limit.');
        }
        files.push(res);
        totalLines += res.content.split('\n').length;
      }
    }
  }

  return {
    repoUrl: `https://github.com/${owner}/${repo}`,
    repoName: `${owner}/${repo}`,
    branch,
    commitSha,
    files,
    allRepoPaths,
    totalLines,
    isSampleRepo: false,
    coverage: {
      totalFilesInRepo,
      filesScanned: files.length,
      totalScannableFiles,
      nonScannableSkipped: skippedIgnoredFolder + skippedNonScannable,
      isPartial,
      notes: coverageNotes.length > 0 ? coverageNotes : undefined,
      skippedSummary: {
        overCap: skippedOverCap,
        tooLarge: skippedTooLarge,
        binary: skippedNonScannable,
        ignoredFolder: skippedIgnoredFolder,
      },
    },
    warnings,
  };
}
