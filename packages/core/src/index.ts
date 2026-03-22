import * as path from 'path';
import * as fs from 'fs';
import { scanDirectory as sastScan } from './scanners/sast/index.js';
import { scanDependencies } from './scanners/sca/index.js';
import { scanDirectory as secretsScan } from './scanners/secrets/index.js';
import { scanIaC } from './scanners/iac/index.js';
import { analyzeReachability } from './triage/reachability.js';
import { deduplicateFindings, flattenDeduplicationResult } from './triage/deduplication.js';
import { detectProjectContext, applyContextualTriage } from './triage/contextual.js';
import { prioritizeFindings } from './triage/priority.js';
import { calculateSecurityScore } from './reporters/index.js';
import type { ScanResult, ScanOptions, AnyFinding, DependencyVulnerability } from '@shield/shared';

export { generateConsoleReport, generateJSONReport, generateMarkdownReport } from './reporters/index.js';
export { detectProjectContext } from './triage/contextual.js';

export type { ScanResult, ScanOptions } from '@shield/shared';

function countFiles(dirPath: string): number {
  let count = 0;
  try {
    const items = fs.readdirSync(dirPath);
    for (const item of items) {
      if (item === 'node_modules' || item === '.git' || item === 'dist') continue;
      const itemPath = path.join(dirPath, item);
      const stat = fs.statSync(itemPath);
      if (stat.isDirectory()) {
        count += countFiles(itemPath);
      } else if (/\.(js|jsx|ts|tsx|py|go|rs|java)$/.test(item)) {
        count++;
      }
    }
  } catch {
    // ignore
  }
  return count;
}

export async function runScan(projectPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startTime = Date.now();
  const resolvedPath = path.resolve(projectPath);

  // Detect project context
  const context = detectProjectContext(resolvedPath);
  const projectName = path.basename(resolvedPath);

  const scanners = options.scanners || ['sast', 'sca', 'secrets', 'iac'];
  const allRawFindings: AnyFinding[] = [];

  // Run scanners in parallel
  const scanPromises: Promise<AnyFinding[]>[] = [];

  if (!options.quick && scanners.includes('sast')) {
    scanPromises.push(
      sastScan(resolvedPath, options).catch(() => [])
    );
  }

  if (scanners.includes('sca')) {
    scanPromises.push(
      scanDependencies(resolvedPath).catch(() => [])
    );
  }

  if (scanners.includes('secrets')) {
    scanPromises.push(
      secretsScan(resolvedPath).catch(() => [])
    );
  }

  if (!options.quick && scanners.includes('iac')) {
    scanPromises.push(
      scanIaC(resolvedPath).catch(() => [])
    );
  }

  const results = await Promise.all(scanPromises);
  for (const result of results) {
    allRawFindings.push(...result);
  }

  // Analyze reachability for SCA findings
  const scaFindings = allRawFindings.filter(f => f.scanner === 'sca') as DependencyVulnerability[];
  if (scaFindings.length > 0) {
    const reachabilityMap = await analyzeReachability(scaFindings, resolvedPath).catch(() => new Map());
    for (const finding of scaFindings) {
      const result = reachabilityMap.get(finding.id);
      if (result) {
        (finding as DependencyVulnerability).isReachable = result.reachable;
        finding.isReachable = result.reachable;
      }
    }
  }

  // Apply contextual triage
  const contextualFindings = applyContextualTriage(allRawFindings, context);

  // Deduplication
  const dedupResult = deduplicateFindings(contextualFindings);
  const deduplicatedFindings = flattenDeduplicationResult(dedupResult);

  // Prioritize
  const prioritizedFindings = prioritizeFindings(deduplicatedFindings);

  // Separate auto-ignored
  const autoIgnored = contextualFindings.filter(f => f.autoIgnored);
  const triaged = contextualFindings.filter(f => !f.isDuplicate);

  const filesScanned = countFiles(resolvedPath);

  // Count dependencies
  let dependenciesChecked = 0;
  try {
    const pkgPath = path.join(resolvedPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const deps = Object.keys(pkg.dependencies || {}).length;
      const devDeps = Object.keys(pkg.devDependencies || {}).length;
      dependenciesChecked = deps + devDeps;
    }
  } catch {
    // ignore
  }

  const noiseReductionPercent = allRawFindings.length > 0
    ? Math.round(((allRawFindings.length - prioritizedFindings.length) / allRawFindings.length) * 100)
    : 0;

  const partialResult = {
    projectPath: resolvedPath,
    projectName,
    timestamp: new Date().toISOString(),
    duration: Date.now() - startTime,
    filesScanned,
    dependenciesChecked,
    rawFindings: allRawFindings,
    triagedFindings: triaged,
    autoIgnored,
    noiseReductionPercent,
    context,
  };

  const securityScore = calculateSecurityScore(partialResult);

  return {
    ...partialResult,
    securityScore,
  };
}

// Export individual scanner functions for MCP server use
export { scanFile as scanSASTFile } from './scanners/sast/index.js';
export { checkPackage } from './scanners/sca/index.js';
export { scanFile as scanSecretsFile } from './scanners/secrets/index.js';
export { scanIaC } from './scanners/iac/index.js';
