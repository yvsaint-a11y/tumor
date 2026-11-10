import { StackDetection } from '../src/types/scanner.js';
import { RepoFile } from './github/sampleRepos.js';

export function detectStack(files: RepoFile[], allRepoPaths?: string[]): StackDetection {
  const languagesSet = new Set<'javascript' | 'typescript' | 'python'>();
  const frameworksSet = new Set<string>();
  const manifests: string[] = [];
  let hasTests = false;
  let hasLockfile = false;
  let totalLinesScanned = 0;

  // Task 1: Check full repo file tree for tests and lockfiles, including files skipped by the cap
  if (allRepoPaths && allRepoPaths.length > 0) {
    for (const rawPath of allRepoPaths) {
      const p = rawPath.toLowerCase();
      if (
        p.endsWith('package-lock.json') ||
        p.endsWith('yarn.lock') ||
        p.endsWith('pnpm-lock.yaml') ||
        p.endsWith('bun.lock') ||
        p.endsWith('bun.lockb') ||
        p.endsWith('npm-shrinkwrap.json') ||
        p.endsWith('poetry.lock') ||
        p.endsWith('pipfile.lock')
      ) {
        hasLockfile = true;
      }
      if (
        p.includes('/test/') ||
        p.includes('/tests/') ||
        p.includes('/__tests__/') ||
        p.startsWith('test/') ||
        p.startsWith('tests/') ||
        p.includes('.test.') ||
        p.includes('.spec.') ||
        p.startsWith('test_') ||
        p.endsWith('_test.py') ||
        p.endsWith('.test.js') ||
        p.endsWith('.test.ts')
      ) {
        hasTests = true;
      }
    }
  }

  for (const file of files) {
    totalLinesScanned += file.content.split('\n').length;
    const path = file.path.toLowerCase();

    // Check for tests in scanned files if not already found in full tree
    if (
      !hasTests &&
      (path.includes('.test.') ||
        path.includes('.spec.') ||
        path.includes('__tests__') ||
        path.includes('tests/') ||
        path.includes('test/') ||
        path.startsWith('test_') ||
        path.endsWith('_test.py'))
    ) {
      hasTests = true;
    }

    // Check for lockfiles
    if (
      path.endsWith('package-lock.json') ||
      path.endsWith('yarn.lock') ||
      path.endsWith('pnpm-lock.yaml') ||
      path.endsWith('bun.lock') ||
      path.endsWith('bun.lockb') ||
      path.endsWith('npm-shrinkwrap.json') ||
      path.endsWith('poetry.lock') ||
      path.endsWith('pipfile.lock')
    ) {
      hasLockfile = true;
    }

    // Manifests
    if (path.endsWith('package.json')) manifests.push(file.path);
    if (path.endsWith('requirements.txt')) manifests.push(file.path);
    if (path.endsWith('pyproject.toml')) manifests.push(file.path);
    if (path.endsWith('pipfile')) manifests.push(file.path);
    if (path.endsWith('setup.py')) manifests.push(file.path);

    // Language identification by extension
    if (path.endsWith('.ts') || path.endsWith('.tsx')) {
      languagesSet.add('typescript');
    }
    if (path.endsWith('.js') || path.endsWith('.jsx') || path.endsWith('.mjs') || path.endsWith('.cjs')) {
      languagesSet.add('javascript');
    }
    if (path.endsWith('.py') || path.endsWith('.pyw')) {
      languagesSet.add('python');
    }

    // Inspect package.json for frameworks and testing libraries
    if (path.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(file.content);
        const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

        if (allDeps['next']) frameworksSet.add('Next.js');
        if (allDeps['react']) frameworksSet.add('React');
        if (allDeps['vite']) frameworksSet.add('Vite');
        if (allDeps['vue']) frameworksSet.add('Vue');
        if (allDeps['express']) frameworksSet.add('Express');
        if (allDeps['tailwindcss']) frameworksSet.add('Tailwind CSS');
        if (allDeps['@supabase/supabase-js']) frameworksSet.add('Supabase');
        if (allDeps['firebase']) frameworksSet.add('Firebase');

        if (allDeps['jest'] || allDeps['vitest'] || allDeps['mocha'] || allDeps['playwright'] || allDeps['cypress']) {
          hasTests = true;
        }
      } catch {
        // ignore malformed JSON
      }
    }

    // Inspect Python files and manifests
    if (path.endsWith('requirements.txt') || path.endsWith('pyproject.toml') || path.endsWith('pipfile')) {
      languagesSet.add('python');
      const content = file.content.toLowerCase();
      if (content.includes('fastapi')) frameworksSet.add('FastAPI');
      if (content.includes('flask')) frameworksSet.add('Flask');
      if (content.includes('django')) frameworksSet.add('Django');
      if (content.includes('streamlit')) frameworksSet.add('Streamlit');
      if (content.includes('pytest') || content.includes('unittest')) hasTests = true;
    }

    if (path.endsWith('.py')) {
      const content = file.content;
      if (content.includes('from fastapi import') || content.includes('import fastapi')) frameworksSet.add('FastAPI');
      if (content.includes('from flask import') || content.includes('import flask')) frameworksSet.add('Flask');
      if (content.includes('django.')) frameworksSet.add('Django');
      if (content.includes('import pytest') || content.includes('import unittest')) hasTests = true;
    }
  }

  const languages = Array.from(languagesSet);
  if (languages.length === 0) {
    languages.push('javascript');
  }

  return {
    languages,
    frameworks: Array.from(frameworksSet),
    manifests,
    hasTests,
    hasLockfile,
    totalFilesScanned: files.length,
    totalLinesScanned,
  };
}
