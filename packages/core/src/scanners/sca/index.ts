import * as fs from 'fs';
import * as path from 'path';
import type { DependencyVulnerability } from '@shield/shared';

let findingIdCounter = 0;
function generateId(): string {
  return `sca-${Date.now()}-${++findingIdCounter}`;
}

interface PackageInfo {
  name: string;
  version: string;
  isDev: boolean;
  isDirect: boolean;
  ecosystem: 'npm' | 'PyPI';
}

interface OSVVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string; cvss_score?: number; cwe_ids?: string[] };
}

interface OSVQueryResult {
  vulns?: OSVVulnerability[];
}

interface OSVBatchResponse {
  results: OSVQueryResult[];
}

function parsePackageJson(filePath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  try {
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    const deps = content.dependencies || {};
    const devDeps = content.devDependencies || {};

    for (const [name, version] of Object.entries(deps)) {
      const cleanVersion = (version as string).replace(/^[\^~>=<]/, '').split(' ')[0];
      if (cleanVersion && cleanVersion !== '*') {
        packages.push({ name, version: cleanVersion, isDev: false, isDirect: true, ecosystem: 'npm' });
      }
    }
    for (const [name, version] of Object.entries(devDeps)) {
      const cleanVersion = (version as string).replace(/^[\^~>=<]/, '').split(' ')[0];
      if (cleanVersion && cleanVersion !== '*') {
        packages.push({ name, version: cleanVersion, isDev: true, isDirect: true, ecosystem: 'npm' });
      }
    }
  } catch {
    // ignore parse errors
  }
  return packages;
}

function parseRequirementsTxt(filePath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
      const match = trimmed.match(/^([A-Za-z0-9_\-.]+)[=><~!]+([0-9.]+)/);
      if (match) {
        packages.push({ name: match[1], version: match[2], isDev: false, isDirect: true, ecosystem: 'PyPI' });
      }
    }
  } catch {
    // ignore parse errors
  }
  return packages;
}

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function queryOSVBatch(packages: PackageInfo[], retries = 3): Promise<Map<string, OSVVulnerability[]>> {
  const results = new Map<string, OSVVulnerability[]>();
  const BATCH_SIZE = 1000;

  for (let batchStart = 0; batchStart < packages.length; batchStart += BATCH_SIZE) {
    const batch = packages.slice(batchStart, batchStart + BATCH_SIZE);
    const queries = batch.map(pkg => ({
      package: { name: pkg.name, ecosystem: pkg.ecosystem },
      version: pkg.version,
    }));

    let lastError: Error | null = null;
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const response = await fetch('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries }),
          signal: AbortSignal.timeout(15000),
        });

        if (!response.ok) {
          if (response.status === 429) {
            await sleep(2000 * (attempt + 1));
            continue;
          }
          throw new Error(`OSV API error: ${response.status}`);
        }

        const data = (await response.json()) as OSVBatchResponse;
        data.results.forEach((result, idx) => {
          const pkg = batch[idx];
          const key = `${pkg.name}@${pkg.version}`;
          results.set(key, result.vulns || []);
        });
        break;
      } catch (err) {
        lastError = err as Error;
        if (attempt < retries - 1) {
          await sleep(1000 * (attempt + 1));
        }
      }
    }

    if (lastError && results.size === 0) {
      // Return empty results on failure
      for (const pkg of batch) {
        results.set(`${pkg.name}@${pkg.version}`, []);
      }
    }
  }

  return results;
}

function getCVSSScore(vuln: OSVVulnerability): number {
  if (vuln.database_specific?.cvss_score) return vuln.database_specific.cvss_score;
  if (vuln.severity) {
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3' || sev.type === 'CVSS_V2') {
        // Parse CVSS score from vector string
        const match = sev.score.match(/(\d+\.\d+)$/);
        if (match) return parseFloat(match[1]);
        // Try to find base score in vector
        const baseMatch = sev.score.match(/AV:[^\/]+\/AC:[^\/]+\/[^\/]+\/[^\/]+\/[^\/]+\/[^\/]+\/[^\/]+\/[^\/]+:([0-9.]+)/);
        if (baseMatch) return parseFloat(baseMatch[1]);
      }
    }
  }
  return 5.0; // Default medium
}

function getFixedVersion(vuln: OSVVulnerability, packageName: string): string | null {
  if (!vuln.affected) return null;
  for (const affected of vuln.affected) {
    if (affected.package.name.toLowerCase() === packageName.toLowerCase()) {
      for (const range of (affected.ranges || [])) {
        for (const event of range.events) {
          if (event.fixed) return event.fixed;
        }
      }
    }
  }
  return null;
}

function getVulnerableRange(vuln: OSVVulnerability, packageName: string): string {
  if (!vuln.affected) return '< *';
  for (const affected of vuln.affected) {
    if (affected.package.name.toLowerCase() === packageName.toLowerCase()) {
      const ranges: string[] = [];
      for (const range of (affected.ranges || [])) {
        let introduced = '';
        let fixed = '';
        for (const event of range.events) {
          if (event.introduced) introduced = event.introduced;
          if (event.fixed) fixed = event.fixed;
        }
        if (introduced && fixed) ranges.push(`>= ${introduced}, < ${fixed}`);
        else if (introduced) ranges.push(`>= ${introduced}`);
        else if (fixed) ranges.push(`< ${fixed}`);
      }
      if (ranges.length) return ranges.join(' || ');
    }
  }
  return '< *';
}

function getSeverityFromCVSS(cvss: number): DependencyVulnerability['severity'] {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss >= 0.1) return 'low';
  return 'info';
}

function hasExploit(vuln: OSVVulnerability): boolean {
  return (vuln.references || []).some(r =>
    r.type === 'EVIDENCE' ||
    r.url.includes('exploit') ||
    r.url.includes('metasploit') ||
    r.url.includes('packetstorm') ||
    r.url.includes('exploit-db')
  );
}

function osvToFinding(
  vuln: OSVVulnerability,
  pkg: PackageInfo,
  projectPath: string
): DependencyVulnerability {
  const cvss = getCVSSScore(vuln);
  const severity = getSeverityFromCVSS(cvss);
  const cve = vuln.aliases?.find(a => a.startsWith('CVE-')) || vuln.id;
  const fixedVersion = getFixedVersion(vuln, pkg.name);
  const vulnerableRange = getVulnerableRange(vuln, pkg.name);
  const cwe = vuln.database_specific?.cwe_ids?.[0] || 'CWE-1035';

  return {
    id: generateId(),
    scanner: 'sca',
    rule: 'vulnerable-dependency',
    severity,
    file: path.join(projectPath, 'package.json'),
    line: 1,
    message: `${pkg.name}@${pkg.version} has known vulnerability: ${vuln.summary || vuln.id}`,
    cwe,
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    fixSuggestion: fixedVersion
      ? `Upgrade ${pkg.name} to version ${fixedVersion} or later`
      : `No fix available yet. Consider replacing ${pkg.name} or adding mitigations`,
    confidence: 'high',
    packageName: pkg.name,
    installedVersion: pkg.version,
    vulnerableRange,
    fixedVersion,
    cve,
    cvssScore: cvss,
    description: vuln.details || vuln.summary || `Vulnerability in ${pkg.name}`,
    isDevDependency: pkg.isDev,
    isDirect: pkg.isDirect,
    isReachable: !pkg.isDev,
    exploitAvailable: hasExploit(vuln),
  };
}

export async function scanDependencies(projectPath: string): Promise<DependencyVulnerability[]> {
  const allPackages: PackageInfo[] = [];

  // Check for package.json
  const pkgJsonPath = path.join(projectPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    allPackages.push(...parsePackageJson(pkgJsonPath));
  }

  // Check for requirements.txt
  const reqTxtPath = path.join(projectPath, 'requirements.txt');
  if (fs.existsSync(reqTxtPath)) {
    allPackages.push(...parseRequirementsTxt(reqTxtPath));
  }

  if (allPackages.length === 0) return [];

  const osvResults = await queryOSVBatch(allPackages);
  const findings: DependencyVulnerability[] = [];

  for (const pkg of allPackages) {
    const key = `${pkg.name}@${pkg.version}`;
    const vulns = osvResults.get(key) || [];
    for (const vuln of vulns) {
      findings.push(osvToFinding(vuln, pkg, projectPath));
    }
  }

  return findings;
}

export async function checkPackage(
  name: string,
  version: string,
  ecosystem: 'npm' | 'PyPI'
): Promise<DependencyVulnerability[]> {
  const pkg: PackageInfo = { name, version, isDev: false, isDirect: true, ecosystem };
  const results = await queryOSVBatch([pkg]);
  const vulns = results.get(`${name}@${version}`) || [];
  return vulns.map(v => osvToFinding(v, pkg, process.cwd()));
}
