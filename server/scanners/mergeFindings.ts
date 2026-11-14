import { Finding } from '../../src/types/scanner.js';

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function mergeFindingsByRuleAndFile(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const f of findings) {
    let key: string;
    const isOsv =
      f.ruleId === 'DEP-OSV-BATCH-CVE' ||
      f.ruleId === 'DEP-VULNERABLE-PACKAGE' ||
      Boolean(f.advisoryId);

    if (isOsv) {
      const pkgKey = `${f.packageName || ''}@${f.resolvedVersion || ''}`;
      key = `OSV:::${f.file}:::${pkgKey}`;
    } else if (f.ruleId === 'REACT-UNHANDLED-EFFECT-ERROR') {
      key = `EFFECT:::${f.file}`;
    } else if (f.packageName) {
      key = `${f.ruleId}:::${f.file}:::pkg:${f.packageName}`;
    } else {
      key = `${f.ruleId}:::${f.file}:::id:${f.id}`;
    }

    const list = groups.get(key) || [];
    list.push(f);
    groups.set(key, list);
  }

  const merged: Finding[] = [];
  let mergedCounter = 0;

  for (const list of groups.values()) {
    if (list.length === 1) {
      merged.push(list[0]);
    } else {
      mergedCounter++;
      list.sort((a, b) => {
        const diff = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
        return diff !== 0 ? diff : a.line - b.line;
      });

      const primary = list[0];
      const highestSev = primary.severity;
      const isOsv = list.some((f) => f.ruleId === 'DEP-OSV-BATCH-CVE' || f.advisoryId);

      if (isOsv) {
        const allAdvisories = Array.from(new Set(list.map((f) => f.advisoryId).filter(Boolean))) as string[];
        const count = allAdvisories.length || list.length;
        const vulnWord = count === 1 ? 'known vulnerability' : 'known vulnerabilities';
        const newTitle = `${primary.packageName}@${primary.resolvedVersion}: ${count} ${vulnWord}`;

        let evidenceAdvisories = '';
        if (allAdvisories.length <= 5) {
          evidenceAdvisories = allAdvisories.join(', ');
        } else {
          const first5 = allAdvisories.slice(0, 5).join(', ');
          const remaining = allAdvisories.length - 5;
          evidenceAdvisories = `${first5}, and ${remaining} more`;
        }

        const newDescription = `${primary.packageName}@${primary.resolvedVersion} is affected by ${count} ${vulnWord}: ${evidenceAdvisories}.`;

        const mergedFinding: Finding = {
          ...primary,
          id: `${primary.id}-m${mergedCounter}`,
          title: newTitle,
          severity: highestSev,
          evidence: evidenceAdvisories,
          descriptionRaw: newDescription,
          advisoryId: allAdvisories.join(', '),
          explanation: primary.explanation
            ? {
                ...primary.explanation,
                plainEnglishRisk: `This package contains ${count} security ${vulnWord} (${evidenceAdvisories}) with severity up to ${highestSev}.`,
                nextStep: primary.explanation.nextStep,
                aiFixPrompt: primary.explanation.aiFixPrompt,
              }
            : undefined,
        };
        merged.push(mergedFinding);
      } else {
        const uniqueLines = Array.from(new Set(list.map((f) => f.line))).sort((a, b) => a - b);
        const count = uniqueLines.length > 1 ? uniqueLines.length : list.length;
        const baseTitle = primary.title.replace(/\s*\(\d+\s*places.*?\)/i, '');
        const newTitle = `${baseTitle} (${count} places)`;
        const linesListStr = uniqueLines.join(', ');

        const evidenceLines = Array.from(new Set(list.map((f) => `Line ${f.line}: ${f.evidence}`)));
        const combinedEvidence = evidenceLines.join('\n');

        const mergedFinding: Finding = {
          ...primary,
          id: `${primary.id}-m${mergedCounter}`,
          title: newTitle,
          severity: highestSev,
          line: uniqueLines[0],
          evidence: combinedEvidence,
          descriptionRaw: `${primary.descriptionRaw} (Found in ${count} places: lines ${linesListStr}).`,
          explanation: primary.explanation
            ? {
                ...primary.explanation,
                nextStep: `${primary.explanation.nextStep} (Check all ${count} occurrences at lines: ${linesListStr}).`,
                aiFixPrompt: primary.explanation.aiFixPrompt
                  ? `In ${primary.file}, resolve the ${primary.title} issue occurring in ${count} places (lines ${linesListStr}).`
                  : undefined,
              }
            : undefined,
        };
        merged.push(mergedFinding);
      }
    }
  }

  return merged;
}
