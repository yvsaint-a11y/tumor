import { Finding } from '../../src/types/scanner.js';
import { RepoFile } from '../github/sampleRepos.js';

// Cache known valid/invalid packages to prevent repeated HTTP calls
const registryCache = new Map<string, boolean>();

// Prepopulate standard known packages to speed up common checks
const KNOWN_GOOD = new Set([
  'react', 'react-dom', 'next', 'vite', 'tailwindcss', 'typescript', 'axios', 'lodash',
  'lucide-react', 'express', 'dotenv', 'cors', 'motion', '@types/react', '@types/node',
  '@supabase/supabase-js', 'fastapi', 'uvicorn', 'requests', 'pydantic', 'sqlalchemy',
  'flask', 'flask-cors', 'pytest', 'django', 'numpy', 'pandas', 'scipy', 'celery'
]);

for (const pkg of KNOWN_GOOD) {
  registryCache.set(`npm:${pkg}`, true);
  registryCache.set(`pypi:${pkg}`, true);
}

async function packageExistsOnNpm(pkgName: string): Promise<boolean> {
  const cacheKey = `npm:${pkgName}`;
  if (registryCache.has(cacheKey)) return registryCache.get(cacheKey)!;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`, {
      method: 'HEAD',
      signal: controller.signal,
      headers: { 'User-Agent': 'VibeCodeHealthScanner/1.0' },
    });
    clearTimeout(timeout);

    const exists = res.status === 200;
    registryCache.set(cacheKey, exists);
    return exists;
  } catch {
    // If request fails or times out, assume it exists to avoid false positives
    return true;
  }
}

async function packageExistsOnPyPI(pkgName: string): Promise<boolean> {
  const cacheKey = `pypi:${pkgName.toLowerCase()}`;
  if (registryCache.has(cacheKey)) return registryCache.get(cacheKey)!;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(pkgName)}/json`, {
      method: 'HEAD',
      signal: controller.signal,
      headers: { 'User-Agent': 'VibeCodeHealthScanner/1.0' },
    });
    clearTimeout(timeout);

    const exists = res.status === 200;
    registryCache.set(cacheKey, exists);
    return exists;
  } catch {
    return true;
  }
}

export async function scanHallucinatedPackages(files: RepoFile[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  let counter = 0;

  for (const file of files) {
    const pathLower = file.path.toLowerCase();

    // 1. Scan package.json files
    if (pathLower.endsWith('package.json')) {
      const lines = file.content.split('\n');
      try {
        const parsed = JSON.parse(file.content);
        const depSections = ['dependencies', 'devDependencies', 'peerDependencies'];

        for (const section of depSections) {
          const deps = parsed[section];
          if (!deps || typeof deps !== 'object') continue;

          for (const pkgName of Object.keys(deps)) {
            // Find line number in original file content
            let lineNum = 1;
            let exactEvidence = `"${pkgName}": "${deps[pkgName]}"`;
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].includes(`"${pkgName}"`)) {
                lineNum = i + 1;
                exactEvidence = lines[i].trim();
                break;
              }
            }

            const exists = await packageExistsOnNpm(pkgName);
            if (!exists) {
              counter++;
              findings.push({
                id: `hal-npm-${counter}`,
                severity: 'high',
                category: 'hallucination',
                ruleId: 'HAL-NPM-NONEXISTENT',
                title: `Hallucinated npm Package: "${pkgName}"`,
                file: file.path,
                line: lineNum,
                evidence: exactEvidence,
                descriptionRaw: `Package "${pkgName}" declared in ${section} does not exist in the official npm registry.`,
                confidence: 'high',
                explanation: {
                  plainEnglishRisk: `Your AI code generator made up a package name ("${pkgName}") that does not exist on npm. Anyone could register this fake name on npm and inject malicious code into your app (a "dependency confusion" attack). It also causes build or install failures.`,
                  nextStep: `Remove "${pkgName}" from your package.json and replace it with an established, real library or write the helper function directly.`,
                  aiFixPrompt: `In package.json at line ${lineNum}, the package "${pkgName}" is hallucinated and does not exist on npm. Please remove it and replace any features it was supposed to provide with standard code or a verified popular npm alternative.`,
                  source: 'fallback',
                },
              });
            }
          }
        }
      } catch {
        // Skip unparseable JSON
      }
    }

    // 2. Scan requirements.txt files
    if (pathLower.endsWith('requirements.txt')) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#') || line.startsWith('-')) continue;

        // Strip comments and version specifiers (e.g. "fastapi>=0.95.0 # comment" -> "fastapi")
        const cleanSpec = line.split('#')[0].trim();
        const pkgMatch = cleanSpec.match(/^([a-zA-Z0-9_\-\.]+)/);
        if (!pkgMatch) continue;

        const pkgName = pkgMatch[1];
        const exists = await packageExistsOnPyPI(pkgName);
        if (!exists) {
          counter++;
          findings.push({
            id: `hal-pypi-${counter}`,
            severity: 'high',
            category: 'hallucination',
            ruleId: 'HAL-PYPI-NONEXISTENT',
            title: `Hallucinated Python Package: "${pkgName}"`,
            file: file.path,
            line: i + 1,
            evidence: line,
            descriptionRaw: `Declared Python package "${pkgName}" does not exist in the PyPI package index.`,
            confidence: 'high',
            explanation: {
              plainEnglishRisk: `Your AI assistant invented a Python package name ("${pkgName}") that does not exist on PyPI. Running 'pip install' will crash, and an attacker could register this name on PyPI with malicious code.`,
              nextStep: `Remove "${pkgName}" from requirements.txt and use a verified package from the official Python package index.`,
              aiFixPrompt: `In requirements.txt line ${i + 1}, the package "${pkgName}" is hallucinated and does not exist on PyPI. Please remove it and replace it with legitimate Python libraries.`,
              source: 'fallback',
            },
          });
        }
      }
    }
  }

  return findings;
}
