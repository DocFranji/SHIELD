import chalk from 'chalk';
import ora from 'ora';
import { runScan, generateConsoleReport, generateJSONReport, generateMarkdownReport } from '@shield/core';
import type { ScanOptions, ScanResult } from '@shield/shared';
import * as fs from 'fs';
import * as path from 'path';

const SEVERITY_COLORS: Record<string, chalk.Chalk> = {
  critical: chalk.hex('#FF3D57').bold,
  high: chalk.hex('#FF8C00').bold,
  medium: chalk.hex('#FFD700'),
  low: chalk.hex('#00C8FF'),
  info: chalk.gray,
};

function colorSeverity(sev: string): string {
  const colorFn = SEVERITY_COLORS[sev.toLowerCase()];
  return colorFn ? colorFn(sev.toUpperCase()) : sev.toUpperCase();
}

function printShieldLogo(): void {
  const logo = chalk.hex('#3D5AFE').bold(`
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ███████╗███████║██║█████╗  ██║     ██║  ██║
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ `);
  console.log(logo);
  console.log(chalk.hex('#8899CC')('  Enterprise-grade security for the indie developer era'));
  console.log(chalk.hex('#1E2D6B')('  ─────────────────────────────────────────────────────'));
  console.log('');
}

export async function runScanCommand(
  targetPath: string,
  options: {
    quick?: boolean;
    format?: string;
    output?: string;
    ci?: boolean;
    verbose?: boolean;
  }
): Promise<void> {
  printShieldLogo();

  const resolvedPath = path.resolve(targetPath || process.cwd());

  if (!fs.existsSync(resolvedPath)) {
    console.error(chalk.red(`Error: Path does not exist: ${resolvedPath}`));
    process.exit(1);
  }

  const scanOptions: ScanOptions = {
    quick: options.quick,
    outputFormat: (options.format as ScanOptions['outputFormat']) || 'console',
    ciMode: options.ci,
    verbose: options.verbose,
  };

  const spinner = ora({
    text: chalk.hex('#8899CC')('Initializing SHIELD scanners...'),
    color: 'blue',
  }).start();

  const spinnerMessages = [
    options.quick
      ? 'Running quick scan (secrets + dependencies)...'
      : 'Running SAST analysis...',
    'Checking dependencies against OSV database...',
    'Scanning for leaked secrets...',
    options.quick ? 'Finalizing results...' : 'Analyzing IaC configurations...',
    'Applying intelligent triage...',
    'Deduplicating findings...',
    'Calculating security score...',
  ];

  let msgIdx = 0;
  const msgInterval = setInterval(() => {
    if (msgIdx < spinnerMessages.length) {
      spinner.text = chalk.hex('#8899CC')(spinnerMessages[msgIdx++]);
    }
  }, 1200);

  let result: ScanResult;
  try {
    result = await runScan(resolvedPath, scanOptions);
    clearInterval(msgInterval);
    spinner.succeed(chalk.hex('#00E676')('Scan complete!'));
  } catch (err) {
    clearInterval(msgInterval);
    spinner.fail(chalk.red('Scan failed'));
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  const format = options.format || 'console';

  if (format === 'json') {
    const output = generateJSONReport(result);
    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      console.log(chalk.green(`JSON report written to ${options.output}`));
    } else {
      console.log(output);
    }
    return;
  }

  if (format === 'markdown') {
    const output = generateMarkdownReport(result);
    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      console.log(chalk.green(`Markdown report written to ${options.output}`));
    } else {
      console.log(output);
    }
    return;
  }

  // Console output
  const triaged = result.triagedFindings.filter(f => !f.autoIgnored && !f.isDuplicate);
  const criticalCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'critical').length;
  const highCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'high').length;
  const mediumCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'medium').length;
  const lowCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'low').length;

  console.log('');

  // Score card
  const scoreColor = result.securityScore >= 80 ? '#00E676'
    : result.securityScore >= 60 ? '#FFD700'
    : result.securityScore >= 40 ? '#FF8C00'
    : '#FF3D57';

  console.log(chalk.hex('#1E2D6B')('  ┌─────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#1E2D6B')('  │') + chalk.hex('#8899CC')('  Security Score: ') +
    chalk.hex(scoreColor).bold(`${result.securityScore}/100`) +
    chalk.hex('#8899CC')(`  Grade: `) +
    chalk.hex(scoreColor).bold(getGrade(result.securityScore)) +
    chalk.hex('#1E2D6B')('                    │'));
  console.log(chalk.hex('#1E2D6B')('  └─────────────────────────────────────────────────────────┘'));
  console.log('');

  // Stats
  console.log(chalk.hex('#8899CC')('  FINDINGS'));
  console.log(chalk.hex('#1E2D6B')('  ────────────────────────────────'));
  console.log(`  ${SEVERITY_COLORS.critical('CRITICAL')}  ${chalk.white(criticalCount.toString().padStart(4))}`);
  console.log(`  ${SEVERITY_COLORS.high('HIGH    ')}  ${chalk.white(highCount.toString().padStart(4))}`);
  console.log(`  ${SEVERITY_COLORS.medium('MEDIUM  ')}  ${chalk.white(mediumCount.toString().padStart(4))}`);
  console.log(`  ${SEVERITY_COLORS.low('LOW     ')}  ${chalk.white(lowCount.toString().padStart(4))}`);
  console.log(chalk.hex('#1E2D6B')('  ────────────────────────────────'));
  console.log(`  ${'TOTAL   '}  ${chalk.white(triaged.length.toString().padStart(4))}  ${chalk.hex('#8899CC')(`(${result.noiseReductionPercent}% noise reduced)`)}`);
  console.log('');

  if (triaged.length > 0) {
    console.log(chalk.hex('#8899CC')('  TOP FINDINGS'));
    console.log(chalk.hex('#1E2D6B')('  ' + '─'.repeat(90)));

    const SEVERITY_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const sorted = [...triaged].sort((a, b) =>
      SEVERITY_ORDER[b.contextualSeverity || b.severity] - SEVERITY_ORDER[a.contextualSeverity || a.severity]
    );

    for (const finding of sorted.slice(0, 20)) {
      const sev = finding.contextualSeverity || finding.severity;
      const sevText = colorSeverity(sev).padEnd(18);
      const scanner = chalk.hex('#3D5AFE')(finding.scanner.toUpperCase().padEnd(10));
      const file = chalk.hex('#8899CC')(finding.file.split('/').slice(-2).join('/'));
      const line = chalk.hex('#4A5A8A')(`:${finding.line}`);
      console.log(`  ${sevText} ${scanner} ${chalk.white(finding.message.slice(0, 55).padEnd(58))} ${file}${line}`);
    }

    if (sorted.length > 20) {
      console.log(chalk.hex('#4A5A8A')(`  ... and ${sorted.length - 20} more findings. Run with --format json for full output.`));
    }

    console.log(chalk.hex('#1E2D6B')('  ' + '─'.repeat(90)));
  } else {
    console.log(chalk.hex('#00E676')('  No actionable findings detected!'));
  }

  console.log('');

  if (result.autoIgnored.length > 0) {
    console.log(chalk.hex('#4A5A8A')(`  Auto-suppressed ${result.autoIgnored.length} likely false positives`));
    console.log('');
  }

  // Context info
  console.log(chalk.hex('#8899CC')('  PROJECT CONTEXT'));
  console.log(`  Frameworks: ${chalk.hex('#3D5AFE')(result.context.frameworks.join(', ') || 'unknown')}`);
  console.log(`  Deploy:     ${chalk.hex('#3D5AFE')(result.context.deployTarget)}`);
  console.log(`  Has DB:     ${result.context.hasDatabase ? chalk.green('Yes') : chalk.gray('No')}`);
  console.log(`  Has Auth:   ${result.context.hasAuthentication ? chalk.green('Yes') : chalk.gray('No')}`);
  console.log('');

  // CI mode exit codes
  if (options.ci) {
    if (criticalCount > 0 || highCount > 0) {
      console.error(chalk.red(`  CI: Failing due to ${criticalCount} critical and ${highCount} high severity findings`));
      process.exit(1);
    } else {
      console.log(chalk.green('  CI: All checks passed'));
    }
  }
}

function getGrade(score: number): string {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}
