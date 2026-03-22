import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import { detectProjectContext } from '@shield/core';

const DEFAULT_CONFIG = `# SHIELD Configuration
# https://github.com/shield-security/shield

version: "1"

scan:
  # Scanners to run (sast, sca, secrets, iac)
  scanners:
    - sast
    - sca
    - secrets
    - iac

  # Minimum severity to report (critical, high, medium, low, info)
  minSeverity: low

triage:
  # Auto-ignore findings in test files
  ignoreTestFiles: true

  # Auto-ignore dev dependencies with CVSS < 4.0
  ignoreDevDepsLowCVSS: true

  # Maximum CVSS score to auto-ignore (requires no exploit and not reachable)
  autoIgnoreCVSSThreshold: 3.0

  # Files/paths to exclude from scanning
  exclude:
    - "**/*.test.ts"
    - "**/*.spec.ts"
    - "**/__tests__/**"
    - "**/test-fixtures/**"

output:
  # Output format: console, json, markdown
  format: console

  # Fail CI on these severities
  failOn:
    - critical
    - high

integrations:
  # Slack webhook for notifications (optional)
  # slackWebhook: \${SHIELD_SLACK_WEBHOOK}

  # GitHub token for PR comments (optional)
  # githubToken: \${GITHUB_TOKEN}
`;

export async function runInitCommand(targetPath?: string): Promise<void> {
  const resolvedPath = path.resolve(targetPath || process.cwd());
  const configPath = path.join(resolvedPath, '.shield.yml');

  if (fs.existsSync(configPath)) {
    console.log(chalk.yellow(`  .shield.yml already exists at ${configPath}`));
    return;
  }

  // Detect project context to customize config
  const context = detectProjectContext(resolvedPath);

  console.log(chalk.hex('#3D5AFE').bold('\n  Initializing SHIELD...\n'));

  console.log(`  Detected project:`);
  console.log(`  - Frameworks: ${chalk.cyan(context.frameworks.join(', ') || 'unknown')}`);
  console.log(`  - Language: ${chalk.cyan(context.language.join(', ') || 'unknown')}`);
  console.log(`  - Deploy target: ${chalk.cyan(context.deployTarget)}`);
  console.log('');

  fs.writeFileSync(configPath, DEFAULT_CONFIG, 'utf-8');

  // Add to .gitignore if it doesn't already ignore shield config
  const gitignorePath = path.join(resolvedPath, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
    if (!gitignoreContent.includes('.shield')) {
      fs.appendFileSync(gitignorePath, '\n# SHIELD security scanner\n.shield-cache/\n');
    }
  }

  console.log(chalk.green(`  Created .shield.yml`));
  console.log('');
  console.log(chalk.hex('#8899CC')('  Next steps:'));
  console.log(`    1. Review ${chalk.cyan('.shield.yml')} and customize settings`);
  console.log(`    2. Run ${chalk.cyan('shield scan')} to perform your first scan`);
  console.log(`    3. Run ${chalk.cyan('shield scan --ci')} in CI/CD pipelines`);
  console.log('');
}
