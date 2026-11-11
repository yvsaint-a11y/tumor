import { createClient, SupabaseClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { ScanReport } from '../src/types/scanner.js';
import { hasUnmaskedSecrets } from './scanners/secretScanner.js';

let mockClient: any = null;

export function setMockSupabaseClient(client: any): void {
  mockClient = client;
}

export function getSupabaseClient(): SupabaseClient | any | null {
  if (mockClient) return mockClient;

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key || url.trim() === '' || key.trim() === '') {
    return null;
  }

  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

export function isSharingEnabled(): boolean {
  return getSupabaseClient() !== null;
}

export const SHARE_ID_REGEX = /^[A-Za-z0-9_-]{12}$/;

export function generateShareId(): string {
  return crypto.randomBytes(9).toString('base64url');
}

export async function saveSharedReport(report: ScanReport): Promise<string | null> {
  const client = getSupabaseClient();
  if (!client) {
    return null;
  }

  // Store only the report object, never source files
  const reportToSave: ScanReport = {
    id: report.id,
    repoUrl: report.repoUrl,
    repoName: report.repoName,
    branch: report.branch,
    commitSha: report.commitSha,
    scannedAt: report.scannedAt,
    coverage: report.coverage,
    stack: report.stack,
    rubric: report.rubric,
    findings: report.findings,
    executiveSummary: report.executiveSummary,
    agentRulesCompliant: report.agentRulesCompliant,
    scanDurationMs: report.scanDurationMs,
    isSampleRepo: report.isSampleRepo,
  };

  const jsonString = JSON.stringify(reportToSave);

  // Requirement 3: Skip sharing if the report exceeds 500 KB
  const byteLength = Buffer.byteLength(jsonString, 'utf8');
  if (byteLength > 500 * 1024) {
    console.warn(`[Shareable Report] Report size (${byteLength} bytes) exceeds 500 KB limit. Skipping sharing.`);
    return null;
  }

  // Requirement 3: Before saving, scan the JSON string with the secret scanner's own patterns and refuse to save if anything matches
  if (hasUnmaskedSecrets(jsonString)) {
    console.warn('[Shareable Report] Refusing to save shared report: unmasked secret detected by secret scanner patterns.');
    return null;
  }

  const id = generateShareId();
  // Requirement 3: Expiry 30 days
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const { error } = await client.from('shared_reports').insert({
    id,
    repo_url: report.repoUrl,
    commit_sha: report.commitSha || 'latest',
    expires_at: expiresAt,
    report: reportToSave,
    view_count: 0,
  });

  if (error) {
    console.error('[Shareable Report Error] Failed to insert shared report into Supabase:', error.message || error);
    return null;
  }

  return id;
}

export type FetchSharedResult =
  | { status: 200; report: ScanReport }
  | { status: 400; error: string }
  | { status: 404; error: string }
  | { status: 410; error: string }
  | { status: 500; error: string };

export async function fetchSharedReport(id: string): Promise<FetchSharedResult> {
  // Requirement 4: validate the id (^[A-Za-z0-9_-]{12}$)
  if (!id || !SHARE_ID_REGEX.test(id)) {
    return { status: 400, error: 'Invalid share ID format. Must be 12 URL-safe characters.' };
  }

  const client = getSupabaseClient();
  if (!client) {
    return { status: 404, error: 'Report sharing is not configured.' };
  }

  const { data, error } = await client
    .from('shared_reports')
    .select('id, expires_at, report, view_count')
    .eq('id', id)
    .single();

  if (error || !data) {
    return { status: 404, error: 'Shared report not found.' };
  }

  // Requirement 4: 410 if expired
  if (data.expires_at) {
    const expiryDate = new Date(data.expires_at);
    if (!isNaN(expiryDate.getTime()) && Date.now() > expiryDate.getTime()) {
      return { status: 410, error: 'This shared report has expired.' };
    }
  }

  // Requirement 4: increment view_count
  try {
    const currentCount = typeof data.view_count === 'number' ? data.view_count : 0;
    await client
      .from('shared_reports')
      .update({ view_count: currentCount + 1 })
      .eq('id', id);
  } catch (updateErr: any) {
    console.warn('[Shareable Report] Failed to increment view_count:', updateErr?.message || updateErr);
  }

  return { status: 200, report: data.report };
}

export async function keepaliveSharedReports(): Promise<{ ok: boolean }> {
  const client = getSupabaseClient();
  if (!client) {
    return { ok: true };
  }

  try {
    // Requirement 6: running a trivial query so an external cron can keep the Supabase project active
    await client.from('shared_reports').select('id').limit(1);
    return { ok: true };
  } catch (err: any) {
    console.warn('[Shareable Report Keepalive] Query error:', err?.message || err);
    return { ok: true };
  }
}
