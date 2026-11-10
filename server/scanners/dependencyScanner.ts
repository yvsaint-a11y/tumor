import semver from 'semver';
import path from 'path';
import { Finding } from '../../src/types/scanner.js';
import { RepoFile } from '../github/sampleRepos.js';

interface ResolvedPackage {
  name: string;
  version: string;
  declaredRange?: string;
  ecosystem: 'npm' | 'PyPI';
  sourceFile: string;
  line: number;
  evidence: string;
  fromLockfile: boolean;
  confidence: 'high' | 'medium' | 'low';
  depScope: 'runtime' | 'dev';
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  modified?: string;
}

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type: string;
  events: OsvEvent[];
}

interface OsvAffectedPackage {
  package?: {
    name?: string;
    ecosystem?: string;
    purl?: string;
  };
  ranges?: OsvRange[];
  versions?: string[];
  ecosystem_specific?: {
    severity?: string;
    [key: string]: any;
  };
  database_specific?: {
    severity?: string;
    [key: string]: any;
  };
}

interface OsvSeverityItem {
  type: string;
  score: string | number;
}

interface OsvVulnDetail {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: {
    severity?: string;
    [key: string]: any;
  };
  severity?: OsvSeverityItem[];
  affected?: OsvAffectedPackage[];
}

interface OsvBatchResponse {
  results?: Array<{
    vulns?: OsvVuln[];
  }>;
}

// In-memory caches to prevent repeated network registry and advisory calls
const npmVersionsCache = new Map<string, string[]>();
const pypiVersionsCache = new Map<string, string[]>();
const osvVulnDetailCache = new Map<string, OsvVulnDetail>();

async function fetchOsvDetail(vulnId: string): Promise<OsvVulnDetail | null> {
  const cached = osvVulnDetailCache.get(vulnId);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(vulnId)}`, {
      headers: { 'User-Agent': 'VibeCodeHealthScanner/2.0' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = (await res.json()) as OsvVulnDetail;
      osvVulnDetailCache.set(vulnId, data);
      return data;
    }
  } catch {
    // Network or timeout failure
  }
  return null;
}

function calcCvss3(vector: string): number | null {
  try {
    const parts: Record<string, string> = {};
    for (const item of vector.split('/')) {
      const [k, v] = item.split(':');
      if (k && v) parts[k.trim()] = v.trim();
    }
    const avMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
    const acMap: Record<string, number> = { L: 0.77, H: 0.44 };
    const uiMap: Record<string, number> = { N: 0.85, R: 0.62 };
    const cMap: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };
    const iMap: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };
    const aMap: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

    const s = parts['S'] || 'U';
    const isChanged = s === 'C';
    const prMap: Record<string, number> = isChanged
      ? { N: 0.85, L: 0.68, H: 0.50 }
      : { N: 0.85, L: 0.62, H: 0.27 };

    const av = avMap[parts['AV']] ?? 0.85;
    const ac = acMap[parts['AC']] ?? 0.77;
    const pr = prMap[parts['PR']] ?? 0.85;
    const ui = uiMap[parts['UI']] ?? 0.85;
    const c = cMap[parts['C']] ?? 0;
    const i = iMap[parts['I']] ?? 0;
    const a = aMap[parts['A']] ?? 0;

    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    let impact = 0;
    if (isChanged) {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    } else {
      impact = 6.42 * iss;
    }
    const exploitability = 8.22 * av * ac * pr * ui;

    if (impact <= 0) return 0;
    let score = 0;
    if (isChanged) {
      score = Math.min(1.08 * (impact + exploitability), 10);
    } else {
      score = Math.min(impact + exploitability, 10);
    }
    return Math.ceil(Math.round(score * 100000) / 10000) / 10;
  } catch {
    return null;
  }
}

function parseCvssScore(scoreVal: string | number): number | null {
  if (typeof scoreVal === 'number' && !isNaN(scoreVal)) {
    return scoreVal;
  }
  if (typeof scoreVal === 'string') {
    const num = parseFloat(scoreVal);
    if (!isNaN(num) && /^\d+(\.\d+)?$/.test(scoreVal.trim())) {
      return num;
    }
    if (scoreVal.startsWith('CVSS:3.')) {
      return calcCvss3(scoreVal);
    }
  }
  return null;
}

function mapOsvSeverity(
  detail: OsvVulnDetail | null
): { severity: 'critical' | 'high' | 'medium' | 'low'; confidence: 'high' | 'low' } {
  if (!detail) {
    return { severity: 'medium', confidence: 'low' };
  }

  // 1. database_specific.severity
  const dbSev = detail.database_specific?.severity;
  if (typeof dbSev === 'string') {
    const s = dbSev.trim().toUpperCase();
    if (s === 'CRITICAL') return { severity: 'critical', confidence: 'high' };
    if (s === 'HIGH') return { severity: 'high', confidence: 'high' };
    if (s === 'MODERATE' || s === 'MEDIUM') return { severity: 'medium', confidence: 'high' };
    if (s === 'LOW') return { severity: 'low', confidence: 'high' };
  }

  // 2. ecosystem_specific or database_specific inside affected entries
  if (Array.isArray(detail.affected)) {
    for (const aff of detail.affected) {
      const ecoSev = aff.ecosystem_specific?.severity || aff.database_specific?.severity;
      if (typeof ecoSev === 'string') {
        const s = ecoSev.trim().toUpperCase();
        if (s === 'CRITICAL') return { severity: 'critical', confidence: 'high' };
        if (s === 'HIGH') return { severity: 'high', confidence: 'high' };
        if (s === 'MODERATE' || s === 'MEDIUM') return { severity: 'medium', confidence: 'high' };
        if (s === 'LOW') return { severity: 'low', confidence: 'high' };
      }
    }
  }

  // 3. CVSS score in severity array
  if (Array.isArray(detail.severity)) {
    for (const item of detail.severity) {
      if (item && item.score) {
        const cvss = parseCvssScore(item.score);
        if (cvss !== null) {
          if (cvss >= 9.0) return { severity: 'critical', confidence: 'high' };
          if (cvss >= 7.0) return { severity: 'high', confidence: 'high' };
          if (cvss >= 4.0) return { severity: 'medium', confidence: 'high' };
          return { severity: 'low', confidence: 'high' };
        }
      }
    }
  }

  // 4. Missing severity data -> Medium with confidence low
  return { severity: 'medium', confidence: 'low' };
}

function isVersionAffected(
  resolvedVersion: string,
  affectedItems: OsvAffectedPackage[] | undefined,
  pkgName: string
): boolean {
  if (!affectedItems || affectedItems.length === 0) return true;

  const relevant = affectedItems.filter(
    (a) => !a.package?.name || a.package.name.toLowerCase() === pkgName.toLowerCase()
  );
  if (relevant.length === 0) return true;

  const cleanVer = semver.clean(resolvedVersion) || semver.valid(semver.coerce(resolvedVersion));
  if (!cleanVer) return true;

  for (const item of relevant) {
    // 1. Explicit versions list
    if (Array.isArray(item.versions) && item.versions.length > 0) {
      if (
        item.versions.some((v) => {
          const cv = semver.clean(v) || semver.valid(semver.coerce(v));
          return cv ? semver.eq(cv, cleanVer) : v === resolvedVersion;
        })
      ) {
        return true;
      }
    }

    // 2. Ranges
    if (Array.isArray(item.ranges) && item.ranges.length > 0) {
      for (const r of item.ranges) {
        if (!Array.isArray(r.events) || r.events.length === 0) continue;

        let currentIntroduced: string | null = null;
        for (const evt of r.events) {
          if (evt.introduced !== undefined) {
            currentIntroduced = evt.introduced;
          }
          if (evt.fixed !== undefined) {
            const intro = currentIntroduced;
            const fixed = evt.fixed;
            currentIntroduced = null;

            const introVer =
              intro && intro !== '0' ? semver.clean(intro) || semver.coerce(intro) : '0.0.0';
            const introOk =
              !intro || intro === '0' || (introVer ? semver.gte(cleanVer, introVer) : true);
            const fixedVer = semver.clean(fixed) || semver.coerce(fixed);
            const fixedOk = fixedVer ? semver.lt(cleanVer, fixedVer) : true;

            if (introOk && fixedOk) {
              return true;
            }
          }
          if (evt.last_affected !== undefined) {
            const intro = currentIntroduced;
            const last = evt.last_affected;
            currentIntroduced = null;

            const introVer =
              intro && intro !== '0' ? semver.clean(intro) || semver.coerce(intro) : '0.0.0';
            const introOk =
              !intro || intro === '0' || (introVer ? semver.gte(cleanVer, introVer) : true);
            const lastVer = semver.clean(last) || semver.coerce(last);
            const lastOk = lastVer ? semver.lte(cleanVer, lastVer) : true;

            if (introOk && lastOk) {
              return true;
            }
          }
        }

        if (currentIntroduced !== null) {
          const introVer =
            currentIntroduced !== '0'
              ? semver.clean(currentIntroduced) || semver.coerce(currentIntroduced)
              : '0.0.0';
          const introOk =
            currentIntroduced === '0' || (introVer ? semver.gte(cleanVer, introVer) : true);
          if (introOk) return true;
        }
      }
    }
  }

  return false;
}

function getFixedVersion(detail: OsvVulnDetail | null, pkgName: string): string | null {
  if (!detail?.affected) return null;
  const relevant = detail.affected.filter(
    (a) => !a.package?.name || a.package.name.toLowerCase() === pkgName.toLowerCase()
  );
  for (const item of relevant) {
    if (Array.isArray(item.ranges)) {
      for (const r of item.ranges) {
        if (Array.isArray(r.events)) {
          for (const evt of r.events) {
            if (evt.fixed) {
              return evt.fixed;
            }
          }
        }
      }
    }
  }
  return null;
}

function extractLowestVersion(versionSpec: string): string {
  const match = versionSpec.match(/(\d+\.\d+(?:\.\d+)?)/);
  return match ? match[1] : versionSpec.replace(/[\^~>=<]/g, '').trim();
}

// Task 2: Resolve npm range to HIGHEST published satisfying version
async function resolveNpmRange(
  pkgName: string,
  range: string
): Promise<{ resolved: string; confidence: 'medium' | 'low' }> {
  const fallbackLowest = extractLowestVersion(range);
  try {
    let versions = npmVersionsCache.get(pkgName);
    if (!versions) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`, {
        headers: {
          Accept: 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8',
          'User-Agent': 'VibeCodeHealthScanner/2.0',
        },
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (res.ok) {
        const data = (await res.json()) as any;
        if (data.versions && typeof data.versions === 'object') {
          versions = Object.keys(data.versions);
          npmVersionsCache.set(pkgName, versions);
        }
      }
    }

    if (versions && versions.length > 0) {
      const maxSatisfying = semver.maxSatisfying(versions, range);
      if (maxSatisfying) {
        return { resolved: maxSatisfying, confidence: 'medium' };
      }
    }
  } catch {
    // Network/timeout error fallback
  }

  return { resolved: fallbackLowest, confidence: 'low' };
}

// Task 2: Resolve PyPI spec to HIGHEST published satisfying version
async function resolvePypiRange(
  pkgName: string,
  spec: string
): Promise<{ resolved: string; confidence: 'medium' | 'low' }> {
  const fallbackLowest = extractLowestVersion(spec);
  try {
    let versions = pypiVersionsCache.get(pkgName.toLowerCase());
    if (!versions) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(pkgName)}/json`, {
        headers: { 'User-Agent': 'VibeCodeHealthScanner/2.0' },
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (res.ok) {
        const data = (await res.json()) as any;
        if (data.releases && typeof data.releases === 'object') {
          versions = Object.keys(data.releases);
          pypiVersionsCache.set(pkgName.toLowerCase(), versions);
        }
      }
    }

    if (versions && versions.length > 0) {
      const validVersions = versions.filter((v) => semver.valid(semver.coerce(v)));
      const specWithoutPkg = spec.toLowerCase().startsWith(pkgName.toLowerCase())
        ? spec.slice(pkgName.length).trim()
        : spec.trim();
      const npmLikeRange =
        !specWithoutPkg || specWithoutPkg === '*' || specWithoutPkg === 'latest'
          ? '*'
          : specWithoutPkg.replace(/~=/g, '^').replace(/==/g, '');
      const maxSatisfying = semver.maxSatisfying(validVersions, npmLikeRange);
      if (maxSatisfying) {
        return { resolved: maxSatisfying, confidence: 'medium' };
      }
      if (!specWithoutPkg && validVersions.length > 0) {
        const sorted = semver.rsort(validVersions.map((v) => semver.clean(v) || semver.coerce(v)!.version));
        return { resolved: sorted[0], confidence: 'medium' };
      }
    }
  } catch {
    // Fallback
  }

  return { resolved: fallbackLowest, confidence: 'low' };
}

// 1. Parse package-lock.json (handles npm v1, v2, v3 formats with devScope labeling)
function parsePackageLock(content: string, filePath: string): ResolvedPackage[] {
  const resolved: ResolvedPackage[] = [];
  try {
    const lock = JSON.parse(content);
    // npm v2/v3 packages object
    if (lock.packages && typeof lock.packages === 'object') {
      for (const [pkgPath, info] of Object.entries<any>(lock.packages)) {
        if (!pkgPath || pkgPath === '' || !info || !info.version) continue;
        const name = pkgPath.replace(/^node_modules\//, '');
        if (name && !name.includes('node_modules/')) {
          const isDev = Boolean(info.dev === true);
          resolved.push({
            name,
            version: info.version,
            ecosystem: 'npm',
            sourceFile: filePath,
            line: 1,
            evidence: `"${name}": "${info.version}" (locked in package-lock.json)`,
            fromLockfile: true,
            confidence: 'high',
            depScope: isDev ? 'dev' : 'runtime',
          });
        }
      }
    } else if (lock.dependencies && typeof lock.dependencies === 'object') {
      // npm v1 dependencies object
      for (const [name, info] of Object.entries<any>(lock.dependencies)) {
        if (info && info.version) {
          const isDev = Boolean(info.dev === true);
          resolved.push({
            name,
            version: info.version,
            ecosystem: 'npm',
            sourceFile: filePath,
            line: 1,
            evidence: `"${name}": "${info.version}" (locked in package-lock.json)`,
            fromLockfile: true,
            confidence: 'high',
            depScope: isDev ? 'dev' : 'runtime',
          });
        }
      }
    }
  } catch {
    // Malformed lockfile
  }
  return resolved;
}

// 2. Parse yarn.lock
function parseYarnLock(content: string, filePath: string): ResolvedPackage[] {
  const resolved: ResolvedPackage[] = [];
  const lines = content.split('\n');
  let currentPkg = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('"') || (line && !line.startsWith(' ') && line.includes('@'))) {
      const match = line.match(/^"?(@?[^@\s]+)@/);
      if (match) currentPkg = match[1];
    } else if (line.trim().startsWith('version ') && currentPkg) {
      const verMatch = line.match(/version\s+"?([^"\s]+)"?/);
      if (verMatch) {
        resolved.push({
          name: currentPkg,
          version: verMatch[1],
          ecosystem: 'npm',
          sourceFile: filePath,
          line: i + 1,
          evidence: `${currentPkg}@${verMatch[1]} (locked in yarn.lock)`,
          fromLockfile: true,
          confidence: 'high',
          depScope: 'runtime',
        });
        currentPkg = '';
      }
    }
  }
  return resolved;
}

// 3. Parse Pipfile.lock
function parsePipfileLock(content: string, filePath: string): ResolvedPackage[] {
  const resolved: ResolvedPackage[] = [];
  try {
    const lock = JSON.parse(content);
    const sections: Array<{ name: string; scope: 'runtime' | 'dev' }> = [
      { name: 'default', scope: 'runtime' },
      { name: 'develop', scope: 'dev' },
    ];
    for (const sec of sections) {
      if (lock[sec.name] && typeof lock[sec.name] === 'object') {
        for (const [name, info] of Object.entries<any>(lock[sec.name])) {
          if (info && info.version) {
            const ver = info.version.replace(/^==/, '').trim();
            resolved.push({
              name,
              version: ver,
              ecosystem: 'PyPI',
              sourceFile: filePath,
              line: 1,
              evidence: `${name}==${ver} (locked in Pipfile.lock)`,
              fromLockfile: true,
              confidence: 'high',
              depScope: sec.scope,
            });
          }
        }
      }
    }
  } catch {
    // Malformed lockfile
  }
  return resolved;
}

// 4. Parse poetry.lock
function parsePoetryLock(content: string, filePath: string): ResolvedPackage[] {
  const resolved: ResolvedPackage[] = [];
  const lines = content.split('\n');
  let currentName = '';
  let currentCategory = 'main';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '[[package]]') {
      currentName = '';
      currentCategory = 'main';
    } else if (line.startsWith('name = ')) {
      currentName = line.replace(/name\s*=\s*"([^"]+)"/, '$1');
    } else if (line.startsWith('category = ')) {
      currentCategory = line.replace(/category\s*=\s*"([^"]+)"/, '$1').toLowerCase();
    } else if (line.startsWith('version = ') && currentName) {
      const ver = line.replace(/version\s*=\s*"([^"]+)"/, '$1');
      resolved.push({
        name: currentName,
        version: ver,
        ecosystem: 'PyPI',
        sourceFile: filePath,
        line: i + 1,
        evidence: `${currentName}==${ver} (locked in poetry.lock)`,
        fromLockfile: true,
        confidence: 'high',
        depScope: currentCategory === 'dev' ? 'dev' : 'runtime',
      });
      currentName = '';
    }
  }
  return resolved;
}

// Query OSV.dev batch endpoint
async function queryOsvBatch(
  packages: ResolvedPackage[]
): Promise<Map<string, OsvVuln[]>> {
  const resultsMap = new Map<string, OsvVuln[]>();
  if (packages.length === 0) return resultsMap;

  const chunkSize = 100;
  for (let i = 0; i < packages.length; i += chunkSize) {
    const chunk = packages.slice(i, i + chunkSize);
    const queries = chunk.map((pkg) => ({
      package: {
        name: pkg.name,
        ecosystem: pkg.ecosystem,
      },
      version: pkg.version,
    }));

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6000);

      const res = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (res.ok) {
        const data = (await res.json()) as OsvBatchResponse;
        if (data.results && Array.isArray(data.results)) {
          for (let j = 0; j < data.results.length; j++) {
            const item = data.results[j];
            if (item && item.vulns && item.vulns.length > 0) {
              const pkgKey = `${chunk[j].ecosystem}:${chunk[j].name}:${chunk[j].version}`;
              resultsMap.set(pkgKey, item.vulns);
            }
          }
        }
      }
    } catch {
      // Fallback
    }
  }

  return resultsMap;
}

function isPublishedJsLibrary(pkgJson: any, files?: RepoFile[]): boolean {
  if (!pkgJson || typeof pkgJson !== 'object') return false;

  if (pkgJson.private === true) return false;

  const hasRootIndex = files
    ? files.some((f) => f.path.toLowerCase() === 'index.js' || f.path.toLowerCase() === 'index.ts')
    : false;
  const hasEntrypoint = Boolean(
    pkgJson.main ||
      pkgJson.exports ||
      pkgJson.module ||
      pkgJson.types ||
      pkgJson.typings ||
      (Array.isArray(pkgJson.files) && pkgJson.files.length > 0) ||
      hasRootIndex
  );

  const allDeps = { ...(pkgJson.dependencies || {}), ...(pkgJson.devDependencies || {}) };
  const hasAppFramework = Boolean(
    allDeps['next'] ||
      allDeps['react-scripts'] ||
      allDeps['vite'] ||
      allDeps['remix'] ||
      allDeps['@remix-run/react'] ||
      allDeps['gatsby'] ||
      allDeps['astro'] ||
      allDeps['nuxt'] ||
      allDeps['@angular/core'] ||
      allDeps['electron']
  );

  return hasEntrypoint && !hasAppFramework;
}

function isPublishedPythonLibrary(files: RepoFile[]): boolean {
  let hasBuildBackend = false;
  let hasAppFramework = false;

  for (const f of files) {
    const p = f.path.toLowerCase();
    if (p.endsWith('pyproject.toml')) {
      const c = f.content.toLowerCase();
      if (
        c.includes('[build-system]') ||
        c.includes('build-backend') ||
        c.includes('setuptools') ||
        c.includes('flit') ||
        c.includes('hatchling') ||
        c.includes('poetry.core')
      ) {
        hasBuildBackend = true;
      }
      if (c.includes('fastapi') || c.includes('flask') || c.includes('django') || c.includes('streamlit')) {
        hasAppFramework = true;
      }
    }
    if (p.endsWith('setup.py') || p.endsWith('setup.cfg')) {
      hasBuildBackend = true;
    }
    if (p.endsWith('requirements.txt')) {
      const c = f.content.toLowerCase();
      if (c.includes('fastapi') || c.includes('flask') || c.includes('django') || c.includes('streamlit')) {
        hasAppFramework = true;
      }
    }
  }

  return hasBuildBackend && !hasAppFramework;
}

export async function scanDependencies(
  files: RepoFile[],
  allRepoPaths?: string[],
  coverageNotes?: string[]
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let counter = 0;

  const pathsToCheck = allRepoPaths && allRepoPaths.length > 0 ? allRepoPaths : files.map((f) => f.path);

  // Requirement 5: Check if lockfile exists in full repository tree
  // Recognize package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, bun.lockb, npm-shrinkwrap.json
  const jsLockfileInTree = pathsToCheck.find((p) => {
    const l = p.toLowerCase();
    return (
      l.endsWith('package-lock.json') ||
      l.endsWith('yarn.lock') ||
      l.endsWith('pnpm-lock.yaml') ||
      l.endsWith('bun.lock') ||
      l.endsWith('bun.lockb') ||
      l.endsWith('npm-shrinkwrap.json')
    );
  });

  const pyLockfileInTree = pathsToCheck.find((p) => {
    const l = p.toLowerCase();
    return l.endsWith('poetry.lock') || l.endsWith('pipfile.lock');
  });

  let hasJsLockfile = false;
  let hasPyLockfile = false;
  let packageJsonFile: RepoFile | null = null;
  let requirementsFile: RepoFile | null = null;

  const resolvedPackages: ResolvedPackage[] = [];

  // Phase 1: Parse any present lockfiles from the scanned files
  for (const file of files) {
    const pathLower = file.path.toLowerCase();

    if (pathLower.endsWith('package-lock.json')) {
      hasJsLockfile = true;
      resolvedPackages.push(...parsePackageLock(file.content, file.path));
    } else if (pathLower.endsWith('yarn.lock')) {
      hasJsLockfile = true;
      resolvedPackages.push(...parseYarnLock(file.content, file.path));
    } else if (
      pathLower.endsWith('pnpm-lock.yaml') ||
      pathLower.endsWith('bun.lock') ||
      pathLower.endsWith('bun.lockb') ||
      pathLower.endsWith('npm-shrinkwrap.json')
    ) {
      hasJsLockfile = true;
    } else if (pathLower.endsWith('pipfile.lock')) {
      hasPyLockfile = true;
      resolvedPackages.push(...parsePipfileLock(file.content, file.path));
    } else if (pathLower.endsWith('poetry.lock')) {
      hasPyLockfile = true;
      resolvedPackages.push(...parsePoetryLock(file.content, file.path));
    }

    if (pathLower.endsWith('package.json')) packageJsonFile = file;
    if (pathLower.endsWith('requirements.txt')) requirementsFile = file;
  }

  // Phase 2: If no JS lockfile found, resolve ranges via npm registry with proper semver max satisfying
  if (!hasJsLockfile && packageJsonFile) {
    try {
      const parsed = JSON.parse(packageJsonFile.content);
      const lines = packageJsonFile.content.split('\n');

      const sections: Array<{ name: string; scope: 'runtime' | 'dev' }> = [
        { name: 'dependencies', scope: 'runtime' },
        { name: 'devDependencies', scope: 'dev' },
      ];

      const allDepEntries: Array<{
        pkgName: string;
        versionRange: string;
        scope: 'runtime' | 'dev';
        lineNum: number;
      }> = [];

      for (const sec of sections) {
        const deps = parsed[sec.name];
        if (!deps || typeof deps !== 'object') continue;

        for (const [pkgName, versionRange] of Object.entries(deps)) {
          if (typeof versionRange !== 'string') continue;

          let lineNum = 1;
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes(`"${pkgName}"`)) {
              lineNum = i + 1;
              break;
            }
          }
          allDepEntries.push({ pkgName, versionRange, scope: sec.scope, lineNum });
        }
      }

      // Batch lookups with Promise.all in chunks of 15
      const NPM_BATCH_SIZE = 15;
      for (let i = 0; i < allDepEntries.length; i += NPM_BATCH_SIZE) {
        const chunk = allDepEntries.slice(i, i + NPM_BATCH_SIZE);
        const resolvedChunk = await Promise.all(
          chunk.map(async (item) => {
            const { resolved, confidence } = await resolveNpmRange(item.pkgName, item.versionRange);
            const evidence =
              confidence === 'medium'
                ? `"${item.pkgName}": "${item.versionRange}" (resolved: ${resolved})`
                : `"${item.pkgName}": "${item.versionRange}" (range minimum: ${resolved})`;

            return {
              name: item.pkgName,
              version: resolved,
              declaredRange: item.versionRange,
              ecosystem: 'npm' as const,
              sourceFile: packageJsonFile!.path,
              line: item.lineNum,
              evidence,
              fromLockfile: false,
              confidence,
              depScope: item.scope,
            };
          })
        );
        resolvedPackages.push(...resolvedChunk);
      }

      if (jsLockfileInTree) {
        if (coverageNotes && !coverageNotes.some((n) => n.includes(jsLockfileInTree))) {
          coverageNotes.push(`Lockfile "${jsLockfileInTree}" was detected in repository but was not parsed.`);
        }
      } else {
        const isLibrary = isPublishedJsLibrary(parsed, files);
        counter++;
        findings.push({
          id: `dep-no-lock-js-${counter}`,
          severity: isLibrary ? 'info' : 'medium',
          category: 'dependency',
          ruleId: 'DEP-NO-LOCKFILE',
          title: isLibrary
            ? 'Published Library: No Lockfile Committed (Standard Practice)'
            : 'Missing Lockfile (package-lock.json / yarn.lock)',
          file: packageJsonFile.path,
          line: 1,
          evidence: `"dependencies": { ... } without lockfile`,
          descriptionRaw: isLibrary
            ? 'Repository appears to be a published library (has main/exports/types without an app framework). Omitting a lockfile is standard for npm libraries so downstream apps manage their own dependency trees.'
            : 'No lockfile (package-lock.json or yarn.lock) found. Builds are non-deterministic and can pull unverified upstream updates.',
          confidence: 'high',
          explanation: {
            plainEnglishRisk: isLibrary
              ? 'For published packages (like Express or utility libraries), omitting a lockfile is standard npm convention so consuming applications resolve their own compatible versions.'
              : 'Without a lockfile, every time you or your hosting platform deploys, npm might download slightly different versions. A surprise update or compromised package can break your live site overnight.',
            nextStep: isLibrary
              ? 'No action required if this repo is published as an npm package library. If it is a deployed application, commit package-lock.json.'
              : "Run 'npm install' locally and commit the generated package-lock.json to Git.",
            aiFixPrompt: isLibrary
              ? 'No fix needed: omitting lockfiles is standard for published npm packages.'
              : "Please run 'npm install' to create a package-lock.json file, and commit it to git so all builds use exact pinned dependencies.",
            source: 'fallback',
          },
        });
      }
    } catch {
      // Malformed package.json
    }
  }

  // Phase 3: If no Python lockfile found, resolve ranges via PyPI JSON API
  if (!hasPyLockfile && requirementsFile) {
    const lines = requirementsFile.content.split('\n');
    let hasRequirements = false;
    const isDevFile =
      requirementsFile.path.toLowerCase().includes('dev') ||
      requirementsFile.path.toLowerCase().includes('test');

    const pyEntries: Array<{ pkgName: string; cleanSpec: string; lineNum: number }> = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;

      hasRequirements = true;
      const cleanSpec = line.split('#')[0].trim();
      const parts = cleanSpec.split(/==|>=|<=|~=/);
      const pkgName = parts[0]?.trim();

      if (pkgName) {
        pyEntries.push({ pkgName, cleanSpec, lineNum: i + 1 });
      }
    }

    const PY_BATCH_SIZE = 15;
    for (let i = 0; i < pyEntries.length; i += PY_BATCH_SIZE) {
      const chunk = pyEntries.slice(i, i + PY_BATCH_SIZE);
      const resolvedChunk = await Promise.all(
        chunk.map(async (item) => {
          const { resolved, confidence } = await resolvePypiRange(item.pkgName, item.cleanSpec);
          const evidence =
            confidence === 'medium'
              ? `${item.cleanSpec} (resolved: ${resolved})`
              : `${item.cleanSpec} (range minimum: ${resolved})`;

          return {
            name: item.pkgName,
            version: resolved,
            declaredRange: item.cleanSpec,
            ecosystem: 'PyPI' as const,
            sourceFile: requirementsFile!.path,
            line: item.lineNum,
            evidence,
            fromLockfile: false,
            confidence,
            depScope: isDevFile ? ('dev' as const) : ('runtime' as const),
          };
        })
      );
      resolvedPackages.push(...resolvedChunk);
    }

    if (hasRequirements) {
      if (pyLockfileInTree) {
        if (coverageNotes && !coverageNotes.some((n) => n.includes(pyLockfileInTree))) {
          coverageNotes.push(`Python lockfile "${pyLockfileInTree}" was detected in repository but was not parsed.`);
        }
      } else {
        const isPyLib = isPublishedPythonLibrary(files);
        counter++;
        findings.push({
          id: `dep-no-lock-py-${counter}`,
          severity: isPyLib ? 'info' : 'low',
          category: 'dependency',
          ruleId: 'DEP-NO-PY-LOCKFILE',
          title: isPyLib
            ? 'Published Python Library: No Lockfile Committed (Standard Practice)'
            : 'Missing Python Lockfile (poetry.lock / Pipfile.lock)',
          file: requirementsFile.path,
          line: 1,
          evidence: `# requirements.txt without poetry.lock or Pipfile.lock`,
          descriptionRaw: isPyLib
            ? 'Repository appears to be a published Python library with a build backend. Omitting lockfiles is standard for Python libraries.'
            : 'No Python lockfile detected. Consider Poetry or pip-tools to guarantee deterministic dependency resolution.',
          confidence: 'high',
          explanation: {
            plainEnglishRisk: isPyLib
              ? 'Libraries published on PyPI typically omit lockfiles so client applications resolve compatible dependency trees.'
              : 'Python packages without locked sub-dependencies can install incompatible sub-modules at deploy time.',
            nextStep: isPyLib
              ? 'No action needed for published libraries.'
              : 'Use poetry or pip-tools (pip-compile) to generate locked sub-dependencies.',
            aiFixPrompt: isPyLib
              ? 'No action required.'
              : 'Generate a locked dependency file or pin all sub-dependencies in requirements.txt to prevent deployment drifts.',
            source: 'fallback',
          },
        });
      }
    }
  }

  // Phase 4: Query OSV.dev batch endpoint
  // Deduplicate packages by ecosystem + name + version
  const uniqueMap = new Map<string, ResolvedPackage>();
  for (const pkg of resolvedPackages) {
    const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, pkg);
    }
  }
  const uniquePackages = Array.from(uniqueMap.values());

  const osvResults = await queryOsvBatch(uniquePackages);

  // Collect all unique vuln IDs to fetch full advisory details concurrently
  const allVulnIds = new Set<string>();
  for (const vulns of osvResults.values()) {
    for (const v of vulns) {
      if (v.id) allVulnIds.add(v.id);
    }
  }

  const idList = Array.from(allVulnIds);
  const detailChunkSize = 10;
  for (let i = 0; i < idList.length; i += detailChunkSize) {
    const chunk = idList.slice(i, i + detailChunkSize);
    await Promise.all(chunk.map((id) => fetchOsvDetail(id)));
  }

  for (const pkg of uniquePackages) {
    const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
    const vulns = osvResults.get(key);

    if (vulns && vulns.length > 0) {
      for (const vuln of vulns) {
        const vulnId = vuln.id || 'CVE-UNKNOWN';
        const detail = osvVulnDetailCache.get(vulnId) || null;

        // Requirement 3: Check affected versions against resolved version using ranges in the OSV record.
        // If the resolved version is outside every affected range, do not raise the finding.
        if (detail && !isVersionAffected(pkg.version, detail.affected, pkg.name)) {
          continue;
        }

        counter++;
        // Requirement 2: Take each vulnerability's severity from the OSV record and map it
        // Never default to High. If severity data is missing, use Medium with confidence "low".
        const mappedSev = mapOsvSeverity(detail);
        const finalSeverity = mappedSev.severity;
        const finalConfidence =
          mappedSev.confidence === 'low' || pkg.confidence === 'low'
            ? 'low'
            : pkg.confidence === 'medium'
            ? 'medium'
            : 'high';

        // Requirement 4: If an advisory lists no fixed version, do not tell the user to upgrade
        const fixedVersion = getFixedVersion(detail, pkg.name);
        const hasFix = Boolean(fixedVersion);

        const vulnSummary =
          detail?.summary || vuln.summary || 'Known security vulnerability identified in OSV database';
        const scopeBadgeText = pkg.depScope === 'dev' ? 'dev dependency' : 'runtime dependency';

        findings.push({
          id: `dep-batch-vuln-${counter}`,
          severity: finalSeverity,
          category: 'dependency',
          ruleId: 'DEP-OSV-BATCH-CVE',
          title: `Vulnerable ${pkg.ecosystem} Package: ${pkg.name}@${pkg.version} (${vulnId})`,
          file: pkg.sourceFile,
          line: pkg.line,
          evidence: pkg.evidence,
          descriptionRaw: `${pkg.name}@${pkg.version} (${scopeBadgeText}) is affected by ${vulnId}: ${vulnSummary}. (${
            pkg.fromLockfile
              ? 'Locked in ' + path.basename(pkg.sourceFile)
              : pkg.confidence === 'medium'
              ? 'Resolved via registry max satisfying'
              : 'Inferred from range minimum'
          }).`,
          confidence: finalConfidence,
          depScope: pkg.depScope,
          packageName: pkg.name,
          resolvedVersion: pkg.version,
          advisoryId: vulnId,
          explanation: {
            plainEnglishRisk: `This ${scopeBadgeText} (${pkg.name}@${pkg.version}) contains an active security vulnerability (${vulnId}) cataloged in the OSV database that could compromise your application.`,
            nextStep: hasFix
              ? `Upgrade ${pkg.name} to version ${fixedVersion} or later and regenerate your lockfile.`
              : `No fix is available yet for ${pkg.name}. Review how this package is used in your code to mitigate exposure, or consider replacing it with an actively maintained alternative.`,
            aiFixPrompt: hasFix
              ? `Update ${pkg.name} in ${pkg.sourceFile} to version ${fixedVersion} or later to resolve ${vulnId}.`
              : `No fix is currently available for ${pkg.name} (${vulnId}). Review how ${pkg.name} is used in your codebase to restrict untrusted input, or replace it with a secure alternative.`,
            source: 'fallback',
          },
        });
      }
    }
  }

  return findings;
}
