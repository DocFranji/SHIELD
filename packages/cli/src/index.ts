#!/usr/bin/env node
import { Command } from 'commander';
import { runScanCommand } from './commands/scan.js';
import { runInitCommand } from './commands/init.js';
import { runFixCommand } from './commands/fix.js';
import { runReportCommand } from './commands/report.js';

const program = new Command();

program
  .name('shield')
  .description('SHIELD — Enterprise-grade security scanner for developers')
  .version('1.0.0');

// scan command
program
  .command('scan [path]')
  .description('Scan a project for security vulnerabilities')
  .option('-q, --quick', 'Quick scan: secrets + SCA only (faster)')
  .option('-f, --format <format>', 'Output format: console, json, markdown', 'console')
  .option('-o, --output <file>', 'Write output to file')
  .option('--ci', 'CI mode: exit code 1 if critical/high findings')
  .option('-v, --verbose', 'Verbose output')
  .action(async (targetPath: string | undefined, options: {
    quick?: boolean;
    format?: string;
    output?: string;
    ci?: boolean;
    verbose?: boolean;
  }) => {
    await runScanCommand(targetPath || '.', options);
  });

// init command
program
  .command('init [path]')
  .description('Initialize SHIELD configuration in a project')
  .action(async (targetPath: string | undefined) => {
    await runInitCommand(targetPath);
  });

// fix command
program
  .command('fix <id>')
  .description('Show detailed fix guidance for a specific finding')
  .action(async (id: string, options: Record<string, unknown>) => {
    await runFixCommand(id, options);
  });

// report command
program
  .command('report')
  .description('Generate a security report from the last scan')
  .option('-f, --format <format>', 'Output format: json, markdown', 'markdown')
  .option('-o, --output <file>', 'Write report to file')
  .option('-i, --input <file>', 'Read scan results from file')
  .action(async (options: { format?: string; output?: string; input?: string }) => {
    await runReportCommand(options);
  });

// mcp command
program
  .command('mcp')
  .description('Start the SHIELD MCP server for AI assistant integration')
  .action(async () => {
    try {
      const { startMCPServer } = await import('@shield/mcp-server');
      await startMCPServer();
    } catch {
      console.error('MCP server not available. Install @shield/mcp-server package.');
      process.exit(1);
    }
  });

// ci command (shorthand for scan --ci)
program
  .command('ci [path]')
  .description('Run scan in CI mode (exit 1 on critical/high findings)')
  .option('-q, --quick', 'Quick scan mode')
  .action(async (targetPath: string | undefined, options: { quick?: boolean }) => {
    await runScanCommand(targetPath || '.', { ...options, ci: true });
  });

program.parse(process.argv);
