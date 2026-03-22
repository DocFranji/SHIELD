import type { AnyFinding, DependencyVulnerability, Severity } from '@shield/shared';

export interface PrioritizedFinding extends AnyFinding {
  priorityScore: number;
  priorityFactors: {
    severityScore: number;
    exploitabilityScore: number;
    reachabilityScore: number;
    businessImpactScore: number;
  };
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
  info: 5,
};

const CONFIDENCE_MULTIPLIER: Record<string, number> = {
  high: 1.0,
  medium: 0.85,
  low: 0.65,
};

const SCANNER_BUSINESS_IMPACT: Record<string, number> = {
  secrets: 100,  // Immediate credential exposure
  sast: 80,      // Code-level vulnerabilities
  sca: 60,       // Dependency vulnerabilities
  iac: 50,       // Configuration issues
  quality: 30,   // Code quality
};

function getSeverityScore(finding: AnyFinding): number {
  const effectiveSeverity = finding.contextualSeverity || finding.severity;
  return SEVERITY_WEIGHTS[effectiveSeverity] || 0;
}

function getExploitabilityScore(finding: AnyFinding): number {
  if (finding.scanner === 'sca') {
    const dep = finding as DependencyVulnerability;
    let score = (dep.cvssScore / 10) * 100;
    if (dep.exploitAvailable) score = Math.min(100, score * 1.3);
    return score;
  }

  if (finding.scanner === 'secrets') {
    return 90; // Secrets are immediately exploitable
  }

  if (finding.scanner === 'sast') {
    // Injection vulnerabilities are highly exploitable
    if (finding.rule.includes('sql-injection') || finding.rule.includes('command-injection')) {
      return 90;
    }
    if (finding.rule.includes('xss')) return 75;
    if (finding.rule.includes('path-traversal')) return 70;
    if (finding.rule.includes('idor')) return 65;
    if (finding.rule.includes('hardcoded')) return 80;
    return 50;
  }

  if (finding.scanner === 'iac') {
    if (finding.rule.includes('secret') || finding.rule.includes('env')) return 85;
    if (finding.rule.includes('privileged')) return 80;
    if (finding.rule.includes('root')) return 70;
    return 40;
  }

  return 50;
}

function getReachabilityScore(finding: AnyFinding): number {
  if (finding.isReachable === undefined) {
    // Unknown reachability — assume reachable for non-SCA findings
    return finding.scanner === 'sca' ? 60 : 80;
  }
  return finding.isReachable ? 100 : 10;
}

function getBusinessImpactScore(finding: AnyFinding): number {
  const baseScore = SCANNER_BUSINESS_IMPACT[finding.scanner] || 50;
  const confidenceMultiplier = CONFIDENCE_MULTIPLIER[finding.confidence] || 0.7;

  // Boost if explicitly marked as critical context
  let multiplier = confidenceMultiplier;
  if (finding.contextualSeverity === 'critical' && finding.severity !== 'critical') {
    multiplier *= 1.2;
  }

  return Math.min(100, baseScore * multiplier);
}

export function computePriorityScore(finding: AnyFinding): number {
  const severityScore = getSeverityScore(finding);
  const exploitabilityScore = getExploitabilityScore(finding);
  const reachabilityScore = getReachabilityScore(finding);
  const businessImpactScore = getBusinessImpactScore(finding);

  // Weighted formula: severity 40%, exploitability 25%, reachability 20%, business impact 15%
  const score =
    severityScore * 0.40 +
    exploitabilityScore * 0.25 +
    reachabilityScore * 0.20 +
    businessImpactScore * 0.15;

  return Math.round(Math.min(100, Math.max(0, score)));
}

export function prioritizeFindings(findings: AnyFinding[]): PrioritizedFinding[] {
  const prioritized: PrioritizedFinding[] = findings
    .filter(f => !f.autoIgnored && !f.isDuplicate)
    .map(finding => {
      const severityScore = getSeverityScore(finding);
      const exploitabilityScore = getExploitabilityScore(finding);
      const reachabilityScore = getReachabilityScore(finding);
      const businessImpactScore = getBusinessImpactScore(finding);

      const priorityScore =
        severityScore * 0.40 +
        exploitabilityScore * 0.25 +
        reachabilityScore * 0.20 +
        businessImpactScore * 0.15;

      return {
        ...finding,
        priorityScore: Math.round(Math.min(100, Math.max(0, priorityScore))),
        priorityFactors: {
          severityScore: Math.round(severityScore),
          exploitabilityScore: Math.round(exploitabilityScore),
          reachabilityScore: Math.round(reachabilityScore),
          businessImpactScore: Math.round(businessImpactScore),
        },
      } as PrioritizedFinding;
    });

  // Sort by priority score descending
  return prioritized.sort((a, b) => b.priorityScore - a.priorityScore);
}
