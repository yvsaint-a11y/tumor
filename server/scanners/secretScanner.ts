import { Finding } from '../../src/types/scanner.js';
import { RepoFile } from '../github/sampleRepos.js';

export function maskSecret(secret: string): string {
  if (!secret) return '';
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return '***MASKED***';
  }
  const prefixLen = Math.min(6, Math.floor(trimmed.length / 4));
  const suffixLen = Math.min(4, Math.floor(trimmed.length / 4));
  const prefix = trimmed.slice(0, prefixLen);
  const suffix = trimmed.slice(-suffixLen);
  return `${prefix}••••••••[MASKED-SECRET]••••••••${suffix}`;
}

// Shannon entropy calculation to detect high-randomness tokens
function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isPlaceholderValue(val: string): boolean {
  if (!val) return true;
  const trimmed = val.trim();
  if (trimmed.length === 0) return true;

  const lower = trimmed.toLowerCase();

  // 1. Passwords equal to "password", "secret", "pass"
  if (lower === 'password' || lower === 'secret' || lower === 'pass') {
    return true;
  }

  // 2. Contains template indicators: "your", "example", "changeme", "placeholder", "xxx", "<...>", "${...}", "dummy", "sample"
  if (
    lower.includes('your') ||
    lower.includes('example') ||
    lower.includes('changeme') ||
    lower.includes('change_me') ||
    lower.includes('placeholder') ||
    lower.includes('xxx') ||
    lower.includes('dummy') ||
    lower.includes('sample') ||
    lower.includes('${') ||
    (lower.includes('<') && lower.includes('>'))
  ) {
    return true;
  }

  // 3. user:password@ style (common template / local default)
  if (
    lower.startsWith('user:password@') ||
    lower.startsWith('username:password@') ||
    lower.startsWith('root:root@') ||
    lower.startsWith('root:password@') ||
    lower.startsWith('postgres:postgres@') ||
    lower.startsWith('admin:admin@') ||
    lower.startsWith('user:pass@')
  ) {
    return true;
  }

  // 4. Hosts like localhost, 127.0.0.1, or containing "your"
  if (
    lower === 'localhost' ||
    lower === '127.0.0.1' ||
    lower === '0.0.0.0' ||
    lower.includes('localhost') ||
    lower.includes('127.0.0.1')
  ) {
    return true;
  }

  // 5. Repeated characters (e.g. "aaaaa", "111111", "xxxxxx", "******", ".......")
  if (/^(.)\1{4,}$/.test(trimmed)) {
    return true;
  }

  return false;
}

export function evaluateDatabaseUrl(url: string): { isSecret: boolean; reason: string; user?: string; password?: string; host?: string } {
  const match = url.match(/(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/([^:]+):([^@\s]+)@([^/:\s]+)(?::\d+)?(?:\/([^\s?]*))?/i);
  if (!match) {
    return { isSecret: false, reason: 'Does not match standard database connection URI with credentials' };
  }

  const user = match[1];
  const password = match[2];
  const host = match[3];

  const hostLower = host.toLowerCase();
  const pwdLower = password.toLowerCase();

  // Evaluate host separately:
  const isLocalOrTemplateHost =
    hostLower === 'localhost' ||
    hostLower === '127.0.0.1' ||
    hostLower === '0.0.0.0' ||
    hostLower.includes('your') ||
    hostLower.includes('example') ||
    hostLower.includes('localhost') ||
    hostLower.includes('127.0.0.1');

  if (isLocalOrTemplateHost) {
    return { isSecret: false, reason: `Host "${host}" is local or template/placeholder`, user, password, host };
  }

  // Evaluate password separately:
  if (isPlaceholderValue(password) || pwdLower === user.toLowerCase()) {
    return { isSecret: false, reason: `Password "${password}" matches template or placeholder pattern`, user, password, host };
  }

  return { isSecret: true, reason: `Remote host "${host}" with non-placeholder embedded password`, user, password, host };
}

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: 'critical' | 'high';
  title: string;
  description: string;
  isKnownTokenFormat?: boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'openai_key',
    regex: /(sk-(?:proj-)?[a-zA-Z0-9_\-]{24,})/g,
    severity: 'critical',
    title: 'Exposed OpenAI API Key',
    description: 'A value matching the OpenAI key format was found in source code or repository configuration.',
    isKnownTokenFormat: true,
  },
  {
    name: 'stripe_secret',
    regex: /(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})/g,
    severity: 'critical',
    title: 'Exposed Stripe Live Secret Key',
    description: 'A value matching the Stripe key format was found.',
    isKnownTokenFormat: true,
  },
  {
    name: 'aws_access_key',
    regex: /(AKIA[0-9A-Z]{16})/g,
    severity: 'critical',
    title: 'Exposed AWS Access Key ID',
    description: 'A value matching the AWS key format was found committed in the repository.',
    isKnownTokenFormat: true,
  },
  {
    name: 'github_pat',
    regex: /(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})/g,
    severity: 'critical',
    title: 'Exposed GitHub Personal Access Token',
    description: 'A value matching the GitHub key format was found in repository files.',
    isKnownTokenFormat: true,
  },
  {
    name: 'google_api_key',
    regex: /(AIzaSy[a-zA-Z0-9_\-]{33})/g,
    severity: 'high',
    title: 'Exposed Google / Gemini API Key',
    description: 'A value matching the Google key format was found committed in code.',
    isKnownTokenFormat: true,
  },
  {
    name: 'database_url_password',
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:]+:[^@\s]+@[^/:\s]+(?::\d+)?(?:\/[^\s?]*)?/g,
    severity: 'critical',
    title: 'Database Connection String With Embedded Password',
    description: 'A database connection URI containing plaintext database credentials was detected.',
    isKnownTokenFormat: false,
  },
  {
    name: 'private_key_header',
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,
    severity: 'critical',
    title: 'Committed Cryptographic Private Key',
    description: 'An asymmetric cryptographic private key file or header was detected in the repository.',
    isKnownTokenFormat: true,
  },
  {
    name: 'supabase_service_role',
    regex: /(?:SUPABASE_SERVICE_ROLE_KEY|service_role)\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["']?/g,
    severity: 'critical',
    title: 'Exposed Supabase Service Role (Master Admin) Key',
    description: 'The Supabase service_role key bypasses all Row Level Security (RLS) policies and allows full database admin privileges.',
    isKnownTokenFormat: true,
  },
];

export function hasUnmaskedSecrets(text: string): boolean {
  if (!text) return false;
  for (const pattern of SECRET_PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    const match = re.exec(text);
    if (match) {
      if (pattern.name === 'database_url_password') {
        const evalRes = evaluateDatabaseUrl(match[0]);
        if (evalRes.isSecret) return true;
      } else {
        const val = match[1] || match[0];
        if (!isPlaceholderValue(val)) {
          return true;
        }
      }
    }
  }
  return false;
}

export function scanSecrets(files: RepoFile[]): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;

  for (const file of files) {
    const lines = file.content.split('\n');
    const pathLower = file.path.toLowerCase();

    const isTemplateEnvFile =
      pathLower.includes('.env.example') ||
      pathLower.includes('.env.sample') ||
      pathLower.includes('.env.template');

    // Check if committed file is a live .env file (not .example)
    const isCommittedEnv =
      (pathLower.endsWith('.env') ||
        pathLower.endsWith('.env.local') ||
        pathLower.endsWith('.env.production') ||
        pathLower.endsWith('.env.development')) &&
      !isTemplateEnvFile;

    // Scan lines in env files
    if (isCommittedEnv || isTemplateEnvFile) {
      for (let i = 0; i < lines.length; i++) {
        const lineContent = lines[i].trim();
        if (!lineContent || lineContent.startsWith('#')) continue;

        const match = lineContent.match(/^([A-Za-z0-9_]+)\s*=\s*(.+)$/);
        if (match) {
          const varName = match[1];
          const rawVal = match[2].trim().replace(/^["']|["']$/g, '');

          // Check for placeholder secrets
          if (isPlaceholderValue(rawVal)) {
            continue;
          }

          // Special check if variable is a DATABASE_URL
          if (varName.toUpperCase().includes('DATABASE_URL') || varName.toUpperCase().includes('DB_URL')) {
            const dbCheck = evaluateDatabaseUrl(rawVal);
            if (!dbCheck.isSecret) {
              continue;
            }
          }

          // In .env.example, .env.sample, .env.template files:
          // ONLY flag values that look real (known token formats, or high entropy AND no placeholder words)
          if (isTemplateEnvFile) {
            const hasKnownFormat = SECRET_PATTERNS.some((p) => {
              if (!p.isKnownTokenFormat) return false;
              p.regex.lastIndex = 0;
              return p.regex.test(rawVal);
            });
            const entropy = calculateEntropy(rawVal);
            const looksRealInTemplate = hasKnownFormat || (entropy > 4.5 && rawVal.length >= 24);

            if (!looksRealInTemplate) {
              continue;
            }
          }

          if (rawVal.length > 8) {
            const isSensitiveVar = /KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|PRIVATE|SALT|DATABASE_URL/i.test(varName);
            if (isSensitiveVar) {
              const hasKnownTokenFormat = SECRET_PATTERNS.some((p) => {
                if (!p.isKnownTokenFormat) return false;
                p.regex.lastIndex = 0;
                return p.regex.test(rawVal);
              });

              const maskedEvidence = `${varName}=${maskSecret(rawVal)}`;
              counter++;
              findings.push({
                id: `sec-${counter}`,
                severity: 'critical',
                category: 'secret',
                ruleId: 'SEC-COMMITTED-ENV-VALUE',
                title: `Committed Secret in ${file.path}: ${varName}`,
                file: file.path,
                line: i + 1,
                evidence: maskedEvidence,
                descriptionRaw: `Sensitive environment variable ${varName} is committed directly to source control in ${file.path}.`,
                confidence: hasKnownTokenFormat ? 'high' : 'medium',
                explanation: {
                  plainEnglishRisk: `Anyone who can view this repository may access your ${varName}. If this key controls your database, payments, or AI account, unauthorized users may read private customer records or incur charges.`,
                  nextStep: `Rotate or revoke the key in your provider dashboard. Add ${file.path} to .gitignore and switch to local environment variables or hosted platform secrets.`,
                  aiFixPrompt: `Help me secure this repo: remove the secret value from ${file.path}, add ${file.path} to .gitignore, create a safe .env.example with dummy placeholders, and guide me on how to revoke the exposed key.`,
                  source: 'fallback',
                },
              });
            }
          }
        }
      }
    }

    // Pattern-based scanning across all files
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      if (lineText.length > 500) continue; // Skip minified bundle lines

      for (const pattern of SECRET_PATTERNS) {
        // Reset lastIndex for global regex
        pattern.regex.lastIndex = 0;
        const match = pattern.regex.exec(lineText);
        if (match) {
          const matchedSecret = match[1] || match[0];

          // Skip known sample or dummy placeholders
          if (isPlaceholderValue(matchedSecret)) {
            continue;
          }

          // Special evaluation for database connection strings: evaluate password and host separately
          if (pattern.name === 'database_url_password') {
            const dbCheck = evaluateDatabaseUrl(matchedSecret);
            if (!dbCheck.isSecret) {
              continue;
            }
          }

          // In .env.example / template files: only flag known real token formats or high entropy
          if (isTemplateEnvFile && !pattern.isKnownTokenFormat) {
            continue;
          }

          const maskedLine = lineText.replace(matchedSecret, maskSecret(matchedSecret)).trim();
          counter++;
          findings.push({
            id: `sec-pat-${counter}`,
            severity: pattern.severity,
            category: 'secret',
            ruleId: `SEC-${pattern.name.toUpperCase()}`,
            title: pattern.title,
            file: file.path,
            line: i + 1,
            evidence: maskedLine,
            descriptionRaw: `${pattern.description} (Matched rule: ${pattern.name}).`,
            confidence: pattern.isKnownTokenFormat ? 'high' : 'medium',
            explanation: {
              plainEnglishRisk: `This credential appears hardcoded in your repository files. If deployed or committed to GitHub, bots may scrape it and gain unauthorized access to your connected services.`,
              nextStep: `Revoke this secret immediately. Move it to a secure environment variable on your server or hosting platform.`,
              aiFixPrompt: `Refactor ${file.path} at line ${i + 1} to load this secret from an environment variable instead of hardcoding it, and ensure secrets are never stored in client code.`,
              source: 'fallback',
            },
          });
        }
      }

      // Shannon entropy check for high-entropy assignment tokens
      if (!isCommittedEnv && !isTemplateEnvFile && /secret|token|apikey|api_key|password|jwt_secret/i.test(lineText)) {
        const assignMatch = lineText.match(/(?:const|let|var|\$)?\s*([a-zA-Z0-9_]+)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{24,})["']/);
        if (assignMatch) {
          const varName = assignMatch[1];
          const token = assignMatch[2];

          if (isPlaceholderValue(token)) {
            continue;
          }

          const entropy = calculateEntropy(token);

          // Random token threshold typically > 4.2
          if (entropy > 4.2 && !token.includes(' ')) {
            const maskedEvidence = lineText.replace(token, maskSecret(token)).trim();
            counter++;
            findings.push({
              id: `sec-entropy-${counter}`,
              severity: 'high',
              category: 'secret',
              ruleId: 'SEC-HIGH-ENTROPY-TOKEN',
              title: `High-Entropy Secret Assigned to "${varName}"`,
              file: file.path,
              line: i + 1,
              evidence: maskedEvidence,
              descriptionRaw: `Variable "${varName}" is assigned a high-entropy string (${entropy.toFixed(2)} bits/char) indicating a hardcoded private token or key.`,
              confidence: 'medium',
              explanation: {
                plainEnglishRisk: `This looks like a private password or token in your code. Anyone inspecting your repository or built files may read it.`,
                nextStep: `Move this value out of your source code and into your hosting environment's secret settings.`,
                aiFixPrompt: `Update ${file.path} to read ${varName} from process.env or an environment variable file instead of hardcoding the secret string.`,
                source: 'fallback',
              },
            });
          }
        }
      }
    }
  }

  return deduplicateSecretFindings(findings);
}

function deduplicateSecretFindings(findings: Finding[]): Finding[] {
  const lineGroups = new Map<string, Finding[]>();

  for (const f of findings) {
    const key = `${f.file}:${f.line}`;
    const list = lineGroups.get(key) || [];
    list.push(f);
    lineGroups.set(key, list);
  }

  const result: Finding[] = [];

  for (const group of lineGroups.values()) {
    if (group.length === 1) {
      result.push(group[0]);
    } else {
      // Specificity rank:
      // Known pattern rules (SEC-OPENAI_KEY, SEC-STRIPE_SECRET, etc.) > SEC-HIGH-ENTROPY-TOKEN > SEC-COMMITTED-ENV-VALUE
      const getSpecificity = (ruleId: string): number => {
        if (ruleId === 'SEC-COMMITTED-ENV-VALUE') return 1;
        if (ruleId === 'SEC-HIGH-ENTROPY-TOKEN') return 2;
        return 3;
      };

      group.sort((a, b) => getSpecificity(b.ruleId) - getSpecificity(a.ruleId));

      const primary = group[0];
      const otherRules = Array.from(new Set(group.slice(1).map((f) => f.ruleId)));

      const mergedFinding: Finding = {
        ...primary,
        descriptionRaw: `${primary.descriptionRaw} (Also matched rule: ${otherRules.join(', ')}).`,
      };

      result.push(mergedFinding);
    }
  }

  return result;
}
