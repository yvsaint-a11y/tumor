import { Finding } from '../../src/types/scanner.js';
import { RepoFile } from '../github/sampleRepos.js';

function extractBalancedBlock(text: string, openBraceIdx: number): { block: string; endIdx: number } | null {
  if (text[openBraceIdx] !== '{') return null;
  let depth = 0;
  let inString: string | null = null;
  let inComment: 'line' | 'block' | null = null;

  for (let i = openBraceIdx; i < text.length; i++) {
    const ch = text[i];
    const prev = i > 0 ? text[i - 1] : '';

    if (inComment === 'line') {
      if (ch === '\n') inComment = null;
      continue;
    }
    if (inComment === 'block') {
      if (ch === '/' && prev === '*') inComment = null;
      continue;
    }
    if (inString) {
      if (ch === inString && prev !== '\\') {
        inString = null;
      }
      continue;
    }

    if (ch === '/' && text[i + 1] === '/') {
      inComment = 'line';
      i++;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      inComment = 'block';
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inString = ch;
      continue;
    }

    if (ch === '{') {
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0) {
        return { block: text.slice(openBraceIdx, i + 1), endIdx: i };
      }
    }
  }
  return null;
}

function findLocalFunctionBody(fileContent: string, fnName: string): string | null {
  const fnDeclRegex = new RegExp(`(?:async\\s+)?function\\s+${fnName}\\s*\\([^)]*\\)\\s*\\{`, 'g');
  let match = fnDeclRegex.exec(fileContent);
  if (match) {
    const openBraceIdx = match.index + match[0].length - 1;
    const blockRes = extractBalancedBlock(fileContent, openBraceIdx);
    if (blockRes) return blockRes.block;
  }

  const arrowRegex = new RegExp(`(?:const|let|var)\\s+${fnName}\\s*=\\s*(?:async\\s*)?(?:\\([^)]*\\)|[a-zA-Z0-9_$]+)\\s*=>\\s*\\{`, 'g');
  match = arrowRegex.exec(fileContent);
  if (match) {
    const openBraceIdx = match.index + match[0].length - 1;
    const blockRes = extractBalancedBlock(fileContent, openBraceIdx);
    if (blockRes) return blockRes.block;
  }

  const callbackRegex = new RegExp(`(?:const|let|var)\\s+${fnName}\\s*=\\s*useCallback\\s*\\(\\s*(?:async\\s*)?(?:\\([^)]*\\)|[a-zA-Z0-9_$]+)\\s*=>\\s*\\{`, 'g');
  match = callbackRegex.exec(fileContent);
  if (match) {
    const openBraceIdx = match.index + match[0].length - 1;
    const blockRes = extractBalancedBlock(fileContent, openBraceIdx);
    if (blockRes) return blockRes.block;
  }

  return null;
}

function hasSecondArgumentInThen(code: string): boolean {
  const thenRegex = /\.then\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = thenRegex.exec(code)) !== null) {
    const startParen = match.index + match[0].length - 1;
    let depth = 0;
    let inString: string | null = null;
    let foundCommaAtTopLevel = false;

    for (let i = startParen; i < code.length; i++) {
      const ch = code[i];
      const prev = i > 0 ? code[i - 1] : '';

      if (inString) {
        if (ch === inString && prev !== '\\') inString = null;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') {
        inString = ch;
        continue;
      }

      if (ch === '(' || ch === '{' || ch === '[') {
        depth++;
      } else if (ch === ')' || ch === '}' || ch === ']') {
        depth--;
        if (depth === 0) break;
      } else if (ch === ',' && depth === 1) {
        foundCommaAtTopLevel = true;
        break;
      }
    }

    if (foundCommaAtTopLevel) return true;
  }
  return false;
}

function hasDestructuredErrorHandling(code: string): boolean {
  const destructureRegex = /\{\s*[^}]*\b(error|err)(?:\s*:\s*([a-zA-Z0-9_$]+))?[^}]*\}/g;
  let match: RegExpExecArray | null;
  while ((match = destructureRegex.exec(code)) !== null) {
    const errorVar = match[2] || match[1];
    if (!errorVar) continue;

    const codeAfter = code.slice(match.index + match[0].length);
    const checks = [
      new RegExp(`\\bif\\s*\\([^)]*\\b${errorVar}\\b`),
      new RegExp(`\\bconsole\\.(?:error|warn|log)\\([^)]*\\b${errorVar}\\b`),
      new RegExp(`\\bset[A-Z][a-zA-Z0-9_$]*\\([^)]*\\b${errorVar}\\b`),
      new RegExp(`\\bthrow\\b[^;]*\\b${errorVar}\\b`),
      new RegExp(`\\b${errorVar}\\.(?:message|status|code|details)\\b`),
      new RegExp(`\\b${errorVar}\\s*\\?`),
      new RegExp(`\\b${errorVar}\\s*&&`),
    ];

    if (checks.some((re) => re.test(codeAfter))) {
      return true;
    }
  }
  return false;
}

export function scanCodeQuality(files: RepoFile[], allRepoPaths?: string[]): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;

  let hasTestFrameworkOrFiles = false;
  let packageJsonPath = '';
  let requirementsPath = '';

  // Task 1: Check full repo file tree for test files (including files skipped by the cap)
  if (allRepoPaths && allRepoPaths.length > 0) {
    for (const rawPath of allRepoPaths) {
      const p = rawPath.toLowerCase();
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
        hasTestFrameworkOrFiles = true;
        break;
      }
    }
  }

  for (const file of files) {
    const pathLower = file.path.toLowerCase();
    const lines = file.content.split('\n');

    if (pathLower.endsWith('package.json')) packageJsonPath = file.path;
    if (pathLower.endsWith('requirements.txt')) requirementsPath = file.path;

    // Check for tests
    if (
      !hasTestFrameworkOrFiles &&
      (pathLower.includes('.test.') ||
        pathLower.includes('.spec.') ||
        pathLower.includes('__tests__') ||
        pathLower.includes('tests/') ||
        pathLower.includes('test/') ||
        pathLower.startsWith('test_') ||
        pathLower.endsWith('_test.py'))
    ) {
      hasTestFrameworkOrFiles = true;
    }

    // 1. React / Next.js checks
    if (
      pathLower.endsWith('.tsx') ||
      pathLower.endsWith('.jsx') ||
      pathLower.endsWith('.ts') ||
      pathLower.endsWith('.js')
    ) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check A: dangerouslySetInnerHTML
        if (line.includes('dangerouslySetInnerHTML')) {
          counter++;
          findings.push({
            id: `code-react-${counter}`,
            severity: 'high',
            category: 'code_quality',
            ruleId: 'REACT-DANGEROUSLY-SET-INNER-HTML',
            title: 'Unsafe HTML Injection (dangerouslySetInnerHTML)',
            file: file.path,
            line: i + 1,
            evidence: line.trim(),
            descriptionRaw: 'Direct use of dangerouslySetInnerHTML without HTML sanitization enables Cross-Site Scripting (XSS).',
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `This allows unverified content to be rendered directly into the web page. If user input or external data passes through here, a malicious actor may run arbitrary JavaScript in your users' browsers and access their sessions or stored tokens.`,
              nextStep: `Use standard React text rendering, or sanitize the HTML with DOMPurify before displaying it.`,
              aiFixPrompt: `In ${file.path} at line ${i + 1}, replace dangerouslySetInnerHTML with DOMPurify sanitization or standard React element rendering.`,
              source: 'fallback',
            },
          });
        }

        // Check B: Sensitive secrets inside client-exposed environment variables (VITE_ / NEXT_PUBLIC_)
        const clientSecretMatch = line.match(/(NEXT_PUBLIC_[A-Za-z0-9_]*?(?:SECRET|SERVICE_ROLE|PRIVATE|ADMIN)[A-Za-z0-9_]*|VITE_[A-Za-z0-9_]*?(?:SECRET|SERVICE_ROLE|PRIVATE|ADMIN)[A-Za-z0-9_]*)/i);
        if (clientSecretMatch) {
          counter++;
          findings.push({
            id: `code-client-secret-${counter}`,
            severity: 'critical',
            category: 'secret',
            ruleId: 'REACT-CLIENT-EXPOSED-SECRET-PREFIX',
            title: `Master/Private Secret Exposed to Browser: ${clientSecretMatch[1]}`,
            file: file.path,
            line: i + 1,
            evidence: line.trim(),
            descriptionRaw: `Environment variable prefix ${clientSecretMatch[1]} embeds this private key into public client-side JavaScript bundles.`,
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `Any variable starting with VITE_ or NEXT_PUBLIC_ is compiled into public browser code. Any visitor can open DevTools and view your service role or master admin key to access your database or API account.`,
              nextStep: `Remove the VITE_ or NEXT_PUBLIC_ prefix. Move any operation that requires this key into a backend server route (API route or Edge Function) so it never touches the user's browser.`,
              aiFixPrompt: `Fix security issue in ${file.path} at line ${i + 1}: remove ${clientSecretMatch[1]} from client code and create a backend API route to handle this securely on the server without exposing master keys.`,
              source: 'fallback',
            },
          });
        }

        // Check C: Unhandled promise / missing error handling in useEffect
        // Analyze the whole useEffect callback body (use brace matching), not just the line with the call
        if (line.includes('useEffect(') || line.includes('useEffect (')) {
          const effectIndex = file.content.indexOf(line);
          const searchStartIndex = effectIndex !== -1 ? effectIndex : 0;
          const openParenIdx = file.content.indexOf('(', searchStartIndex);

          let effectBody = '';
          let effectEndIndex = -1;

          if (openParenIdx !== -1) {
            // Find opening brace of the effect callback
            const firstBraceIdx = file.content.indexOf('{', openParenIdx);
            // Verify the brace belongs to the effect callback (before the closing dependency array bracket or semicolon)
            if (firstBraceIdx !== -1 && firstBraceIdx - openParenIdx < 120) {
              const blockRes = extractBalancedBlock(file.content, firstBraceIdx);
              if (blockRes) {
                effectBody = blockRes.block;
                effectEndIndex = blockRes.endIdx;
              }
            }
          }

          // Fallback if no brace block found (e.g. arrow expression without braces)
          if (!effectBody) {
            const lookahead = lines.slice(i, Math.min(lines.length, i + 30)).join('\n');
            effectBody = lookahead;
          }

          // Check if effect calls any named function defined in the same file (one level only)
          const localFnBodies: string[] = [];
          const callRegex = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g;
          let callMatch: RegExpExecArray | null;
          const seenFns = new Set<string>();

          while ((callMatch = callRegex.exec(effectBody)) !== null) {
            const fnName = callMatch[1];
            if (
              !seenFns.has(fnName) &&
              !['if', 'for', 'while', 'switch', 'catch', 'then', 'finally', 'useEffect', 'useState', 'useCallback', 'useMemo', 'useRef', 'fetch', 'axios', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'console', 'Boolean', 'String', 'Number', 'Array', 'Object', 'Promise', 'JSON', 'resolve', 'reject', 'require', 'import'].includes(fnName)
            ) {
              seenFns.add(fnName);
              const fnBody = findLocalFunctionBody(file.content, fnName);
              if (fnBody) {
                localFnBodies.push(fnBody);
              }
            }
          }

          const combinedCode = effectBody + '\n' + localFnBodies.join('\n');

          // Check if network call is present
          const hasFetch = /\b(?:fetch|window\.fetch)\s*\(/.test(combinedCode);
          const hasAxios = /\baxios(?:\.[a-zA-Z0-9_$]+|\s*\()/.test(combinedCode);
          const hasSupabase = /\bsupabase(?:\.[a-zA-Z0-9_$]+)+/.test(combinedCode);

          if (hasFetch || hasAxios || hasSupabase) {
            // Check if network call is HANDLED:
            // 1. try/catch around the awaited call
            const hasTryCatch = /\btry\s*\{[\s\S]*?\}\s*catch\b/.test(combinedCode);
            // 2. .catch( chained on the promise chain
            const hasCatchChain = /\.catch\s*\(/.test(combinedCode);
            // 3. .then() with a second rejection-handler argument
            const hasThenRejection = hasSecondArgumentInThen(combinedCode);
            // 4. For supabase and similar clients returning { data, error }, destructured error value referenced later
            const hasErrorDestructure = hasDestructuredErrorHandling(combinedCode);

            const isHandled = hasTryCatch || hasCatchChain || hasThenRejection || hasErrorDestructure;

            if (!isHandled) {
              // Locate the exact call line
              let targetCallLine = i + 1;
              let targetCallEvidence = line.trim();

              const effectLines = effectBody.split('\n');
              for (let el = 0; el < effectLines.length; el++) {
                const eLine = effectLines[el];
                if (
                  eLine.includes('fetch(') ||
                  eLine.includes('fetch (') ||
                  eLine.includes('axios.') ||
                  eLine.includes('axios(') ||
                  eLine.includes('supabase.')
                ) {
                  targetCallLine = i + el + 1;
                  targetCallEvidence = eLine.trim();
                  break;
                }
              }

              counter++;
              findings.push({
                id: `code-err-${counter}`,
                severity: 'medium',
                category: 'code_quality',
                ruleId: 'REACT-UNHANDLED-EFFECT-ERROR',
                title: 'Network Request in useEffect Lacks Error Handling',
                file: file.path,
                line: targetCallLine,
                evidence: targetCallEvidence,
                descriptionRaw: 'API call (fetch/axios/supabase) inside useEffect does not handle rejection or errors with try/catch, .catch(), or destructured error checks.',
                confidence: 'medium',
                explanation: {
                  plainEnglishRisk: `If the user loses internet connection or your API returns an error, the screen may freeze or crash without giving the user any message or retry option.`,
                  nextStep: `Wrap the API call in a try/catch block or attach .catch(), and set an error state to show a friendly error banner to users.`,
                  aiFixPrompt: `In ${file.path} around line ${targetCallLine}, wrap the network call in useEffect with a try/catch block or .catch() handler.`,
                  source: 'fallback',
                },
              });
            }
          }
        }
      }
    }

    // 2. Python web checks
    if (pathLower.endsWith('.py')) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check A: debug=True
        if (/debug\s*=\s*True/i.test(line)) {
          counter++;
          findings.push({
            id: `code-py-debug-${counter}`,
            severity: 'critical',
            category: 'code_quality',
            ruleId: 'PY-DEBUG-MODE-ENABLED',
            title: 'Debug Mode Enabled (debug=True)',
            file: file.path,
            line: i + 1,
            evidence: line.trim(),
            descriptionRaw: 'Running web applications with debug=True in production exposes interactive debuggers, stack traces, and environment variables.',
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `Debug mode reveals your app's entire inner code, passwords, and file paths whenever an error happens. In frameworks like Flask, it provides an interactive console where an attacker may execute arbitrary code on your server.`,
              nextStep: `Set debug mode from an environment variable (e.g. os.getenv("DEBUG", "False").lower() == "true") and default to False for production.`,
              aiFixPrompt: `In ${file.path} at line ${i + 1}, replace hardcoded debug=True with an environment variable check that defaults to False in production.`,
              source: 'fallback',
            },
          });
        }

        // Check B: Hardcoded SECRET_KEY
        if (
          /(?:SECRET_KEY|secret_key)\s*=\s*["'][a-zA-Z0-9_\-!@#$%^&*()+=]{8,}["']/i.test(line) &&
          !line.includes('os.environ') &&
          !line.includes('os.getenv')
        ) {
          counter++;
          findings.push({
            id: `code-py-secretkey-${counter}`,
            severity: 'critical',
            category: 'secret',
            ruleId: 'PY-HARDCODED-SECRET-KEY',
            title: 'Hardcoded Flask/Django/JWT SECRET_KEY in Code',
            file: file.path,
            line: i + 1,
            evidence: line.trim(),
            descriptionRaw: 'Cryptographic SECRET_KEY is hardcoded in source code instead of loaded from secure environment variables.',
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `Anyone reading this repository may forge user session cookies or sign fake JWT tokens to log in as an administrator on your app.`,
              nextStep: `Change this to read from an environment variable: os.getenv("SECRET_KEY") and fail if the key is not set in production.`,
              aiFixPrompt: `In ${file.path} at line ${i + 1}, load SECRET_KEY from os.environ.get("SECRET_KEY") instead of hardcoding the secret string.`,
              source: 'fallback',
            },
          });
        }

        // Check C: Wide-open CORS with credentials
        if (
          (line.includes('allow_origins=["*"]') || line.includes("allow_origins=['*']") || line.includes('"origins": "*"')) &&
          file.content.includes('allow_credentials=True')
        ) {
          counter++;
          findings.push({
            id: `code-py-cors-${counter}`,
            severity: 'high',
            category: 'code_quality',
            ruleId: 'PY-PERMISSIVE-CORS-CREDENTIALS',
            title: 'Wide-Open CORS Configured with Credentials Allowed',
            file: file.path,
            line: i + 1,
            evidence: line.trim(),
            descriptionRaw: 'CORS policy allows all origins (*) while simultaneously permitting user authentication credentials.',
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `A malicious website may send cross-domain requests on behalf of your logged-in users and read back their private response data.`,
              nextStep: `Restrict allowed origins to your specific production and development domain URLs.`,
              aiFixPrompt: `In ${file.path} at line ${i + 1}, change allow_origins to a whitelist of your actual frontend domain URLs instead of "*".`,
              source: 'fallback',
            },
          });
        }

        // Check D: eval() or exec() usage
        if (/\b(?:eval|exec)\s*\(/i.test(line)) {
          counter++;
          findings.push({
            id: `code-py-eval-${counter}`,
            severity: 'critical',
            category: 'code_quality',
            ruleId: 'PY-DANGEROUS-EVAL-EXEC',
            title: 'Dangerous eval() or exec() Call',
            file: file.path,
            line: i + 1,
            evidence: line.trim(),
            descriptionRaw: 'Dynamic code execution via eval() or exec() can allow remote code execution if user inputs are evaluated.',
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `Calling eval() runs text as live Python code. If an attacker passes custom input into this endpoint, they may gain full shell access to your server.`,
              nextStep: `Remove eval() and parse safe expressions using ast.literal_eval or dedicated parsers.`,
              aiFixPrompt: `In ${file.path} at line ${i + 1}, remove eval() and replace it with safe validation or ast.literal_eval.`,
              source: 'fallback',
            },
          });
        }
      }
    }

    // 3. Unpinned requirements in requirements.txt
    if (pathLower.endsWith('requirements.txt')) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#') || line.startsWith('-')) continue;

        // Check if package has no version constraint at all (e.g. "fastapi", "flask", "requests")
        if (/^[a-zA-Z0-9_\-\.]+$/.test(line)) {
          counter++;
          findings.push({
            id: `code-unpinned-${counter}`,
            severity: 'low',
            category: 'dependency',
            ruleId: 'DEP-UNPINNED-PYTHON-PACKAGE',
            title: `Unpinned Python Dependency: "${line}"`,
            file: file.path,
            line: i + 1,
            evidence: line,
            descriptionRaw: `Dependency "${line}" has no pinned version (e.g., ==X.Y.Z). Builds may spontaneously break when new major versions release.`,
            confidence: 'medium',
            explanation: {
              plainEnglishRisk: `Without a fixed version, every time you or your hosting service builds your app, it will download whatever version is newest that day. A surprise breaking update from a package author may take down your site.`,
              nextStep: `Pin exact or compatible versions (e.g., ${line}==1.0.0 or ~=1.0) in requirements.txt.`,
              aiFixPrompt: `In requirements.txt line ${i + 1}, pin "${line}" to a specific stable version (e.g. ${line}==X.Y.Z) to prevent unexpected production outages.`,
              source: 'fallback',
            },
          });
        }
      }
    }
  }

  // 4. Missing Test Suite check
  if (!hasTestFrameworkOrFiles) {
    const targetFile = packageJsonPath || requirementsPath || (files[0] ? files[0].path : 'repository');
    findings.push({
      id: `test-missing-1`,
      severity: 'medium',
      category: 'testing',
      ruleId: 'TEST-NO-AUTOMATED-TESTS',
      title: 'No Automated Test Suite Detected',
      file: targetFile,
      line: 1,
      evidence: '// No test directories (__tests__, tests/) or test runners (jest/vitest/pytest) found',
      descriptionRaw: 'Repository does not have any automated unit or integration tests configured.',
      confidence: 'medium',
      explanation: {
        plainEnglishRisk: `When prompt-engineering or vibe-coding new features, AI tools may break existing functions without you knowing. With zero tests, bugs may not be discovered until real users hit them.`,
        nextStep: `Add Vitest (for React) or Pytest (for Python) with at least 2-3 smoke tests verifying core user flows.`,
        aiFixPrompt: `Setup a simple test suite using ${packageJsonPath ? 'Vitest for React' : 'Pytest for Python'} with tests verifying that our main components and routes render properly without crashing.`,
        source: 'fallback',
      },
    });
  }

  return findings;
}
