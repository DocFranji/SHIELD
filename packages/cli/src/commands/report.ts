import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import { generateJSONReport, generateMarkdownReport } from '@shield/core';
import type { ScanResult } from '@shield/shared';

export async function runReportCommand(options: {
  format?: string;
  output?: string;
  input?: string;
}): Promise<void> {
  const cacheFile = options.input || path.join(process.cwd(), '.shield-cache', 'last-scan.json');

  if (!fs.existsSync(cacheFile)) {
    console.log(chalk.yellow('  No scan results found. Run `shield scan` first.'));
    return;
  }

  let scanResult: ScanResult;
  try {
    scanResult = JSON.parse(fs.readFileSync(cacheFile, 'utf-8')) as ScanResult;
  } catch {
    console.log(chalk.red('  Failed to read scan results.'));
    return;
  }

  const format = options.format || 'markdown';

  let output: string;
  if (format === 'json') {
    output = generateJSONReport(scanResult);
  } else if (format === 'markdown') {
    output = generateMarkdownReport(scanResult);
  } else {
    console.log(chalk.red(`  Unknown format: ${format}. Use 'json' or 'markdown'.`));
    return;
  }

  if (options.output) {
    fs.writeFileSync(options.output, output, 'utf-8');
    console.log(chalk.green(`  Report written to ${options.output}`));
  } else {
    const defaultFile = `shield-report-${new Date().toISOString().split('T')[0]}.${format === 'json' ? 'json' : 'md'}`;
    fs.writeFileSync(defaultFile, output, 'utf-8');
    console.log(chalk.green(`  Report written to ${defaultFile}`));
  }
}
