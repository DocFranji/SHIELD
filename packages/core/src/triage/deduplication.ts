import type { AnyFinding, FindingGroup, DeduplicationResult } from '@shield/shared';

function getGroupKey(finding: AnyFinding): string {
  if (finding.scanner === 'sca') {
    // Group by CVE (same CVE in multiple lockfiles)
    return `sca:cve:${finding.cve}`;
  }

  if (finding.scanner === 'secrets') {
    // Group by secret type + masked value (same secret in multiple files)
    const secretFinding = finding;
    return `secrets:${secretFinding.secretType}:${secretFinding.value ?? 'unknown'}`;
  }

  // For SAST and IaC, group by same file+line (multiple scanners)
  return `${finding.scanner}:${finding.file}:${finding.line}:${finding.rule}`;
}

function selectPrimary(findings: AnyFinding[]): AnyFinding {
  // Prefer higher severity, then higher confidence
  const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const confidenceOrder = { high: 3, medium: 2, low: 1 };

  return findings.reduce((best, current) => {
    const bestScore =
      (severityOrder[best.severity] || 0) * 10 +
      (confidenceOrder[best.confidence] || 0);
    const currentScore =
      (severityOrder[current.severity] || 0) * 10 +
      (confidenceOrder[current.confidence] || 0);
    return currentScore > bestScore ? current : best;
  });
}

export function deduplicateFindings(findings: AnyFinding[]): DeduplicationResult {
  const groups = new Map<string, AnyFinding[]>();

  for (const finding of findings) {
    const key = getGroupKey(finding);
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(finding);
  }

  const findingGroups: FindingGroup[] = [];

  for (const [, groupFindings] of groups) {
    const primary = selectPrimary(groupFindings);
    const related = groupFindings.filter(f => f.id !== primary.id);

    // Mark duplicates
    for (const related of groupFindings) {
      if (related.id !== primary.id) {
        related.isDuplicate = true;
        related.duplicateOf = primary.id;
      }
    }

    findingGroups.push({
      primary,
      related,
      totalCount: groupFindings.length,
    });
  }

  const totalOriginal = findings.length;
  const totalAfterDedup = findingGroups.length;
  const reductionPercent = totalOriginal > 0
    ? Math.round(((totalOriginal - totalAfterDedup) / totalOriginal) * 100)
    : 0;

  return {
    groups: findingGroups,
    totalOriginal,
    totalAfterDedup,
    reductionPercent,
  };
}

export function flattenDeduplicationResult(result: DeduplicationResult): AnyFinding[] {
  return result.groups.map(g => g.primary);
}
