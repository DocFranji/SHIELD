import { scanSASTFile, checkPackage, scanSecretsFile, scanIaC, runScan } from '@shield/core';
import { getGuardrails, renderGuardrailsMarkdown } from '../guardrails/generator.js';
import type { Framework } from '../guardrails/generator.js';
import * as fs from 'fs';

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, { type: string; description: string; enum?: string[] }>;
    required: string[];
  };
}

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: 'shield_scan_file',
    description: 'Scan a specific file for security vulnerabilities using SAST analysis. Detects SQL injection, XSS, command injection, path traversal, hardcoded credentials, and more.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string', description: 'Absolute path to the file to scan' },
        content: { type: 'string', description: 'Optional file content (if not reading from disk)' },
      },
      required: ['filePath'],
    },
  },
  {
    name: 'shield_check_dependency',
    description: 'Check if a specific npm or PyPI package version has known vulnerabilities using the OSV database.',
    inputSchema: {
      type: 'object',
      properties: {
        packageName: { type: 'string', description: 'Package name (e.g., "lodash", "flask")' },
        version: { type: 'string', description: 'Package version (e.g., "4.17.19")' },
        ecosystem: { type: 'string', description: 'Package ecosystem', enum: ['npm', 'PyPI'] },
      },
      required: ['packageName', 'version', 'ecosystem'],
    },
  },
  {
    name: 'shield_get_guardrails',
    description: 'Get security guardrails and best practices for a specific framework. Returns actionable DO/DONT rules with code examples.',
    inputSchema: {
      type: 'object',
      properties: {
        framework: {
          type: 'string',
          description: 'The framework to get guardrails for',
          enum: ['nextjs', 'express', 'flask', 'fastapi', 'generic'],
        },
      },
      required: ['framework'],
    },
  },
  {
    name: 'shield_validate_env',
    description: 'Check a .env file content or string for exposed secrets and security issues.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Content of the .env file or environment variable string' },
        filePath: { type: 'string', description: 'Optional path to .env file' },
      },
      required: ['content'],
    },
  },
  {
    name: 'shield_scan_project',
    description: 'Run a full security scan on a project directory. Returns findings grouped by severity.',
    inputSchema: {
      type: 'object',
      properties: {
        projectPath: { type: 'string', description: 'Absolute path to project directory' },
        quick: { type: 'string', description: 'Set to "true" for quick scan (secrets + deps only)' },
      },
      required: ['projectPath'],
    },
  },
];

export async function executeTool(
  toolName: string,
  args: Record<string, string>
): Promise<{ content: Array<{ type: string; text: string }> }> {
  try {
    switch (toolName) {
      case 'shield_scan_file': {
        const findings = await scanSASTFile(args.filePath, args.content);
        const secretFindings = args.filePath ? await scanSecretsFile(args.filePath) : [];
        const allFindings = [...findings, ...secretFindings];

        if (allFindings.length === 0) {
          return {
            content: [{
              type: 'text',
              text: `No security issues found in ${args.filePath}`,
            }],
          };
        }

        const summary = allFindings.map(f =>
          `[${(f.contextualSeverity || f.severity).toUpperCase()}] ${f.rule}: ${f.message} (line ${f.line})`
        ).join('\n');

        return {
          content: [{
            type: 'text',
            text: `Found ${allFindings.length} security issue(s) in ${args.filePath}:\n\n${summary}`,
          }],
        };
      }

      case 'shield_check_dependency': {
        const ecosystem = (args.ecosystem || 'npm') as 'npm' | 'PyPI';
        const vulns = await checkPackage(args.packageName, args.version, ecosystem);

        if (vulns.length === 0) {
          return {
            content: [{
              type: 'text',
              text: `✅ ${args.packageName}@${args.version} has no known vulnerabilities`,
            }],
          };
        }

        const summary = vulns.map(v =>
          `[${v.severity.toUpperCase()}] ${v.cve} (CVSS: ${v.cvssScore})\n  ${v.message}\n  Fix: ${v.fixSuggestion}`
        ).join('\n\n');

        return {
          content: [{
            type: 'text',
            text: `⚠️ Found ${vulns.length} vulnerability(ies) in ${args.packageName}@${args.version}:\n\n${summary}`,
          }],
        };
      }

      case 'shield_get_guardrails': {
        const framework = (args.framework || 'generic') as Framework;
        const guardrails = getGuardrails(framework);
        const markdown = renderGuardrailsMarkdown(guardrails);
        return {
          content: [{
            type: 'text',
            text: markdown,
          }],
        };
      }

      case 'shield_validate_env': {
        let content = args.content;

        if (args.filePath && fs.existsSync(args.filePath)) {
          content = fs.readFileSync(args.filePath, 'utf-8');
        }

        const issues: string[] = [];
        const lines = content.split('\n');

        const patterns = [
          { re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/, name: 'OpenAI API Key', severity: 'CRITICAL' },
          { re: /sk-ant-[A-Za-z0-9\-_]{40,}/, name: 'Anthropic API Key', severity: 'CRITICAL' },
          { re: /sk_live_[A-Za-z0-9]{24,}/, name: 'Stripe Live Secret Key', severity: 'CRITICAL' },
          { re: /(AKIA|ASIA)[A-Z0-9]{16}/, name: 'AWS Access Key ID', severity: 'CRITICAL' },
          { re: /ghp_[A-Za-z0-9]{36}/, name: 'GitHub PAT', severity: 'CRITICAL' },
          { re: /(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@/, name: 'Database URL with credentials', severity: 'CRITICAL' },
          { re: /-----BEGIN.*PRIVATE KEY-----/, name: 'Private Key', severity: 'CRITICAL' },
          { re: /(?:PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\w{8,}/i, name: 'Potential credential', severity: 'HIGH' },
        ];

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.trim().startsWith('#') || !line.includes('=')) continue;

          for (const pattern of patterns) {
            if (pattern.re.test(line)) {
              const key = line.split('=')[0].trim();
              issues.push(`Line ${i + 1}: [${pattern.severity}] ${pattern.name} detected in ${key}`);
            }
          }
        }

        if (issues.length === 0) {
          return {
            content: [{
              type: 'text',
              text: '✅ No obvious secrets detected in the environment configuration.\n\nReminder: Ensure this file is in .gitignore and never committed to version control.',
            }],
          };
        }

        return {
          content: [{
            type: 'text',
            text: `⚠️ Found ${issues.length} potential secret(s):\n\n${issues.join('\n')}\n\n⚡ Action: Rotate these credentials immediately if this file has been committed to git.`,
          }],
        };
      }

      case 'shield_scan_project': {
        const result = await runScan(args.projectPath, {
          quick: args.quick === 'true',
        });

        const triaged = result.triagedFindings.filter(f => !f.autoIgnored && !f.isDuplicate);
        const criticalCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'critical').length;
        const highCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'high').length;
        const mediumCount = triaged.filter(f => (f.contextualSeverity || f.severity) === 'medium').length;

        const topFindings = triaged.slice(0, 10).map(f =>
          `[${(f.contextualSeverity || f.severity).toUpperCase()}] ${f.rule}: ${f.message} (${f.file}:${f.line})`
        ).join('\n');

        return {
          content: [{
            type: 'text',
            text: `SHIELD Scan Results for ${result.projectName}:
Security Score: ${result.securityScore}/100
Findings: ${triaged.length} total (${criticalCount} critical, ${highCount} high, ${mediumCount} medium)
Noise Reduction: ${result.noiseReductionPercent}%
Duration: ${(result.duration / 1000).toFixed(2)}s

Top Findings:
${topFindings || 'None'}

Frameworks detected: ${result.context.frameworks.join(', ') || 'unknown'}`,
          }],
        };
      }

      default:
        return {
          content: [{
            type: 'text',
            text: `Unknown tool: ${toolName}`,
          }],
        };
    }
  } catch (err) {
    return {
      content: [{
        type: 'text',
        text: `Error executing tool '${toolName}': ${String(err)}`,
      }],
    };
  }
}
