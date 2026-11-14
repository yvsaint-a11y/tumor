// Client configuration constants and issue URL builders
export const GITHUB_ISSUES_REPO = 'yvsaint-a11y/tumor';
export const GITHUB_ISSUES_BASE_URL = `https://github.com/${GITHUB_ISSUES_REPO}/issues/new`;

export interface FalsePositiveParams {
  ruleId: string;
  repoName?: string;
  findingTitle: string;
  repoUrl?: string;
  commitSha?: string;
  file: string;
  line: number;
  scannedAt?: string;
}

export function buildFalsePositiveIssueUrl(params: FalsePositiveParams): string {
  const repoName = params.repoName || 'repository';
  const title = `False positive: ${params.ruleId} in ${repoName}`;

  const shortSha = params.commitSha ? params.commitSha.substring(0, 7) : 'latest';
  const scanDate = params.scannedAt ? new Date(params.scannedAt).toUTCString() : new Date().toUTCString();

  let body = [
    `### Finding Details`,
    `- **Rule ID:** ${params.ruleId}`,
    `- **Finding Title:** ${params.findingTitle}`,
    `- **Repository URL:** ${params.repoUrl || 'N/A'}`,
    `- **Commit SHA:** ${shortSha}`,
    `- **File Location:** ${params.file}:${params.line}`,
    `- **Scan Date:** ${scanDate}`,
    ``,
    `### What is wrong?`,
    ``,
  ].join('\n');

  // Cap the body at 1500 characters
  if (body.length > 1500) {
    body = body.slice(0, 1500);
  }

  const url = new URL(GITHUB_ISSUES_BASE_URL);
  url.searchParams.set('title', title);
  url.searchParams.set('body', body);
  return url.toString();
}

export function buildRemovalIssueUrl(shareId: string): string {
  const title = `Remove shared report ${shareId}`;
  let body = [
    `### Shared Report Removal Request`,
    `- **Report Share ID:** ${shareId}`,
    `- **URL:** ${typeof window !== 'undefined' ? window.location.href : `/r/${shareId}`}`,
    ``,
    `Please remove this shared report from public access.`,
  ].join('\n');

  if (body.length > 1500) {
    body = body.slice(0, 1500);
  }

  const url = new URL(GITHUB_ISSUES_BASE_URL);
  url.searchParams.set('title', title);
  url.searchParams.set('body', body);
  return url.toString();
}
