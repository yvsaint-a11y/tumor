import { Finding, FindingSeverity, RubricScore } from '../../src/types/scanner.js';

export function getEffectiveSeverity(severity: FindingSeverity, depScope?: 'runtime' | 'dev'): FindingSeverity {
  if (depScope === 'dev') {
    switch (severity) {
      case 'critical':
        return 'high';
      case 'high':
        return 'medium';
      case 'medium':
        return 'low';
      case 'low':
      case 'info':
        return 'info';
    }
  }
  return severity;
}

export function calculateRubricScore(findings: Finding[]): RubricScore {
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;

  let critDeduction = 0;
  let highDeduction = 0;
  let medDeduction = 0;
  let lowDeduction = 0;

  for (const f of findings) {
    // Deductions and score tile counts defined by EFFECTIVE severity:
    // Standard: Critical (-25 pts), High (-15 pts), Medium (-8 pts), Low (-3 pts)
    // Rule: Vulnerabilities in dev dependencies deduct one severity level lower:
    // Critical -> High (-15), High -> Medium (-8), Medium -> Low (-3), Low -> Info (0)
    const effectiveSev = getEffectiveSeverity(f.severity, f.depScope);
    f.effectiveSeverity = effectiveSev;

    switch (effectiveSev) {
      case 'critical':
        criticalCount++;
        critDeduction += 25;
        break;
      case 'high':
        highCount++;
        highDeduction += 15;
        break;
      case 'medium':
        mediumCount++;
        medDeduction += 8;
        break;
      case 'low':
        lowCount++;
        lowDeduction += 3;
        break;
      case 'info':
        infoCount++;
        break;
    }
  }

  const totalDeductions = critDeduction + highDeduction + medDeduction + lowDeduction;
  const rawScore = 100 - totalDeductions;
  const score = Math.max(0, Math.min(100, rawScore));

  // Runtime consistency check: total === findings.length and score === max(0, 100 - sum of deductions)
  const totalCount = criticalCount + highCount + mediumCount + lowCount + infoCount;
  if (totalCount !== findings.length) {
    console.error(`[Rubric Consistency Mismatch] Total count (${totalCount}) !== findings.length (${findings.length})`);
  }
  const expectedScore = Math.max(0, 100 - totalDeductions);
  if (score !== expectedScore) {
    console.error(`[Rubric Consistency Mismatch] Score (${score}) !== max(0, 100 - sum of deductions) (${expectedScore})`);
  }

  let grade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
  let verdict: 'Healthy' | 'Moderate Risk' | 'Substantial Risk' | 'High Risk' | 'Critical Risk' = 'Healthy';
  let summary = 'Repository appears healthy with minimal or no security risks detected.';

  if (score >= 90) {
    grade = 'A';
    verdict = 'Healthy';
    summary = 'Great shape! Code conforms to safe defaults with low exposure.';
  } else if (score >= 75) {
    grade = 'B';
    verdict = 'Moderate Risk';
    summary = 'Moderate attention required. Minor security or dependency hygiene issues found.';
  } else if (score >= 55) {
    grade = 'C';
    verdict = 'Substantial Risk';
    summary = 'Substantial risks detected. Address high priority issues before taking real user data.';
  } else if (score >= 35) {
    grade = 'D';
    verdict = 'High Risk';
    summary = 'High risk posture. Contains multiple critical issues, exposed secrets, or severe vulnerabilities.';
  } else {
    grade = 'F';
    verdict = 'Critical Risk';
    summary = 'Critical security posture. Unsafe to deploy to production. Master credentials or fatal bugs present.';
  }

  return {
    score,
    grade,
    verdict,
    summary,
    counts: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      info: infoCount,
      total: findings.length,
    },
    deductions: {
      critical: critDeduction,
      high: highDeduction,
      medium: medDeduction,
      low: lowDeduction,
    },
  };
}
