import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';

export async function runFixCommand(findingId: string, _options: Record<string, unknown>): Promise<void> {
  // Look for cached scan result
  const cacheFile = path.join(process.cwd(), '.shield-cache', 'last-scan.json');

  if (!fs.existsSync(cacheFile)) {
    console.log(chalk.yellow('  No scan results found. Run `shield scan` first.'));
    return;
  }

  let scanResult: Record<string, unknown>;
  try {
    scanResult = JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
  } catch {
    console.log(chalk.red('  Failed to read scan results.'));
    return;
  }

  const allFindings = [
    ...((scanResult.rawFindings as unknown[]) || []),
    ...((scanResult.triagedFindings as unknown[]) || []),
  ] as Array<Record<string, unknown>>;

  const finding = allFindings.find(f => f.id === findingId);

  if (!finding) {
    console.log(chalk.yellow(`  Finding '${findingId}' not found. Check the ID and try again.`));
    return;
  }

  console.log(chalk.hex('#3D5AFE').bold('\n  SHIELD Fix Advisor\n'));
  console.log(`  Finding: ${chalk.white(finding.rule as string)}`);
  console.log(`  Severity: ${colorSeverity(finding.severity as string)}`);
  console.log(`  File: ${chalk.cyan(`${finding.file}:${finding.line}`)}`);
  console.log('');

  console.log(chalk.hex('#8899CC')('  DESCRIPTION'));
  console.log(`  ${finding.message}`);
  console.log('');

  if (finding.cwe) {
    console.log(chalk.hex('#8899CC')('  VULNERABILITY CLASS'));
    console.log(`  ${finding.cwe} | ${finding.owasp || 'N/A'}`);
    console.log('');
  }

  if (finding.snippet) {
    console.log(chalk.hex('#8899CC')('  VULNERABLE CODE'));
    const snippetLines = (finding.snippet as string).split('\n');
    for (const line of snippetLines) {
      console.log(`  ${chalk.hex('#FF3D57')(line)}`);
    }
    console.log('');
  }

  if (finding.fixSuggestion) {
    console.log(chalk.hex('#8899CC')('  HOW TO FIX'));
    console.log(`  ${chalk.hex('#00E676')(finding.fixSuggestion as string)}`);
    console.log('');
  }

  // Show additional resources based on CWE
  const resources = getCWEResources(finding.cwe as string);
  if (resources.length > 0) {
    console.log(chalk.hex('#8899CC')('  RESOURCES'));
    for (const resource of resources) {
      console.log(`  ${chalk.hex('#3D5AFE')('→')} ${resource}`);
    }
    console.log('');
  }
}

function colorSeverity(sev: string): string {
  const colors: Record<string, string> = {
    critical: '#FF3D57',
    high: '#FF8C00',
    medium: '#FFD700',
    low: '#00C8FF',
    info: '#9E9E9E',
  };
  const color = colors[sev.toLowerCase()] || '#FFFFFF';
  return chalk.hex(color).bold(sev.toUpperCase());
}

function getCWEResources(cwe: string): string[] {
  const resources: Record<string, string[]> = {
    'CWE-89': [
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      'https://owasp.org/www-community/attacks/SQL_Injection',
    ],
    'CWE-79': [
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    ],
    'CWE-78': [
      'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
    ],
    'CWE-22': [
      'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
    ],
    'CWE-798': [
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    ],
    'CWE-639': [
      'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
    ],
  };
  return resources[cwe] || [];
}
