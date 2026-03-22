import type { ScanResult, AnyFinding, Severity } from '@shield/shared';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function getGrade(score: number): string {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

function pluralize(count: number, word: string): string {
  return `${count} ${word}${count !== 1 ? 's' : ''}`;
}

function countBySeverity(findings: AnyFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts[f.contextualSeverity || f.severity]++;
  }
  return counts;
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

export function calculateSecurityScore(result: Omit<ScanResult, 'securityScore' | 'noiseReductionPercent'>): number {
  const findings = result.triagedFindings.filter(f => !f.autoIgnored && !f.isDuplicate);
  const counts = countBySeverity(findings);

  // Deductions per severity level
  const deductions =
    counts.critical * 20 +
    counts.high * 10 +
    counts.medium * 3 +
    counts.low * 1 +
    counts.info * 0.5;

  const score = Math.max(0, Math.min(100, 100 - deductions));
  return Math.round(score);
}

export function generateConsoleReport(result: ScanResult): string {
  const lines: string[] = [];
  const triaged = result.triagedFindings.filter(f => !f.autoIgnored && !f.isDuplicate);
  const counts = countBySeverity(triaged);
  const grade = getGrade(result.securityScore);

  // Header
  lines.push('');
  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push('║            SHIELD Security Scan Results                      ║');
  lines.push('╚══════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push(`  Project:     ${result.projectName}`);
  lines.push(`  Scanned:     ${result.timestamp}`);
  lines.push(`  Duration:    ${(result.duration / 1000).toFixed(2)}s`);
  lines.push(`  Files:       ${result.filesScanned} files scanned`);
  lines.push(`  Deps:        ${result.dependenciesChecked} dependencies checked`);
  lines.push('');

  // Score
  lines.push('  ┌─────────────────────────────────────────────┐');
  lines.push(`  │  Security Score: ${result.securityScore}/100  (Grade: ${grade})  │`);
  lines.push('  └─────────────────────────────────────────────┘');
  lines.push('');

  // Severity summary
  lines.push('  FINDINGS SUMMARY');
  lines.push('  ─────────────────────────────────────────');
  lines.push(`  CRITICAL  ${counts.critical.toString().padStart(4)}  ${'█'.repeat(Math.min(counts.critical, 20))}`);
  lines.push(`  HIGH      ${counts.high.toString().padStart(4)}  ${'█'.repeat(Math.min(counts.high, 20))}`);
  lines.push(`  MEDIUM    ${counts.medium.toString().padStart(4)}  ${'█'.repeat(Math.min(counts.medium, 20))}`);
  lines.push(`  LOW       ${counts.low.toString().padStart(4)}  ${'█'.repeat(Math.min(counts.low, 20))}`);
  lines.push(`  INFO      ${counts.info.toString().padStart(4)}  ${'█'.repeat(Math.min(counts.info, 20))}`);
  lines.push('  ─────────────────────────────────────────');
  lines.push(`  TOTAL     ${triaged.length.toString().padStart(4)}  (${result.noiseReductionPercent}% noise reduced)`);
  lines.push('');

  // Findings table
  if (triaged.length > 0) {
    lines.push('  FINDINGS');
    lines.push('  ' + '─'.repeat(100));
    lines.push(`  ${'SEV'.padEnd(10)} ${'SCANNER'.padEnd(10)} ${'RULE'.padEnd(30)} ${'FILE'.padEnd(35)} ${'LINE'.padEnd(6)}`);
    lines.push('  ' + '─'.repeat(100));

    const sortedFindings = [...triaged].sort((a, b) =>
      SEVERITY_ORDER[b.contextualSeverity || b.severity] - SEVERITY_ORDER[a.contextualSeverity || a.severity]
    );

    for (const finding of sortedFindings.slice(0, 50)) {
      const sev = (finding.contextualSeverity || finding.severity).toUpperCase();
      const scanner = finding.scanner.toUpperCase();
      const rule = truncate(finding.rule, 28);
      const fileName = truncate(finding.file.split('/').slice(-2).join('/'), 33);
      lines.push(`  ${sev.padEnd(10)} ${scanner.padEnd(10)} ${rule.padEnd(30)} ${fileName.padEnd(35)} ${finding.line}`);
    }

    if (sortedFindings.length > 50) {
      lines.push(`  ... and ${sortedFindings.length - 50} more findings`);
    }
    lines.push('  ' + '─'.repeat(100));
  }

  // Auto-ignored
  if (result.autoIgnored.length > 0) {
    lines.push('');
    lines.push(`  AUTO-IGNORED: ${pluralize(result.autoIgnored.length, 'finding')} suppressed as likely false positives`);
  }

  lines.push('');

  return lines.join('\n');
}

export function generateJSONReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function generateMarkdownReport(result: ScanResult): string {
  const lines: string[] = [];
  const triaged = result.triagedFindings.filter(f => !f.autoIgnored && !f.isDuplicate);
  const counts = countBySeverity(triaged);
  const grade = getGrade(result.securityScore);

  lines.push('# SHIELD Security Scan Report');
  lines.push('');
  lines.push(`**Project:** ${result.projectName}  `);
  lines.push(`**Scanned:** ${result.timestamp}  `);
  lines.push(`**Duration:** ${(result.duration / 1000).toFixed(2)}s  `);
  lines.push('');
  lines.push('## Security Score');
  lines.push('');
  lines.push(`### ${result.securityScore}/100 — Grade ${grade}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| 🔴 Critical | ${counts.critical} |`);
  lines.push(`| 🟠 High | ${counts.high} |`);
  lines.push(`| 🟡 Medium | ${counts.medium} |`);
  lines.push(`| 🔵 Low | ${counts.low} |`);
  lines.push(`| ⚪ Info | ${counts.info} |`);
  lines.push(`| **Total** | **${triaged.length}** |`);
  lines.push('');
  lines.push(`> ${result.noiseReductionPercent}% noise reduction applied — ${result.autoIgnored.length} findings auto-suppressed`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  lines.push('| Severity | Scanner | Rule | File | Line | Message |');
  lines.push('|----------|---------|------|------|------|---------|');

  const sortedFindings = [...triaged].sort((a, b) =>
    SEVERITY_ORDER[b.contextualSeverity || b.severity] - SEVERITY_ORDER[a.contextualSeverity || a.severity]
  );

  for (const finding of sortedFindings) {
    const sev = finding.contextualSeverity || finding.severity;
    const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[sev] || '';
    const filePath = finding.file.split('/').slice(-2).join('/');
    lines.push(`| ${sevEmoji} ${sev} | ${finding.scanner} | \`${finding.rule}\` | \`${filePath}\` | ${finding.line} | ${finding.message} |`);
  }

  lines.push('');
  lines.push('## Details');
  lines.push('');

  for (const finding of sortedFindings.slice(0, 20)) {
    const sev = finding.contextualSeverity || finding.severity;
    lines.push(`### ${finding.rule}`);
    lines.push('');
    lines.push(`**Severity:** ${sev}  `);
    lines.push(`**File:** \`${finding.file}:${finding.line}\`  `);
    lines.push(`**CWE:** ${finding.cwe || 'N/A'}  `);
    lines.push('');
    lines.push(finding.message);
    lines.push('');
    if (finding.snippet) {
      lines.push('```');
      lines.push(finding.snippet);
      lines.push('```');
      lines.push('');
    }
    if (finding.fixSuggestion) {
      lines.push(`**Fix:** ${finding.fixSuggestion}`);
      lines.push('');
    }
    lines.push('---');
    lines.push('');
  }

  return lines.join('\n');
}
