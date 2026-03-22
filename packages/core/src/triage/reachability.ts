import * as fs from 'fs';
import * as path from 'path';
import fg from 'fast-glob';
import type { DependencyVulnerability, ReachabilityResult } from '@shield/shared';

interface ImportMap {
  // packageName -> list of files that import it
  [packageName: string]: string[];
}

async function buildImportMap(projectPath: string): Promise<ImportMap> {
  const importMap: ImportMap = {};

  const files = await fg(['**/*.{js,jsx,ts,tsx,mjs,cjs}'], {
    cwd: projectPath,
    ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.next/**'],
    absolute: true,
    followSymbolicLinks: false,
  });

  // Regex patterns for imports and requires
  const importPatterns = [
    // ES module imports: import ... from 'pkg'
    /import\s+(?:[^'"]*?\s+from\s+)?['"]([^'"./][^'"]*)['"]/g,
    // Dynamic imports: import('pkg')
    /import\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
    // CommonJS requires: require('pkg')
    /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
  ];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of importPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const packageName = match[1];
        // Normalize scoped packages and sub-paths
        const normalizedName = packageName.startsWith('@')
          ? packageName.split('/').slice(0, 2).join('/')
          : packageName.split('/')[0];

        if (!importMap[normalizedName]) {
          importMap[normalizedName] = [];
        }
        if (!importMap[normalizedName].includes(file)) {
          importMap[normalizedName].push(file);
        }
      }
    }
  }

  return importMap;
}

// Vulnerable function usage patterns for well-known CVEs
const VULNERABLE_FUNCTION_PATTERNS: Record<string, RegExp[]> = {
  lodash: [
    /\.(merge|mergeWith|defaultsDeep)\s*\(/g,  // Prototype pollution
    /\.(template)\s*\(/g,  // Template injection
  ],
  axios: [
    /axios\./g,
  ],
  express: [
    /express\s*\(\)/g,
  ],
  minimist: [
    /minimist\s*\(/g,
  ],
  'node-fetch': [
    /fetch\s*\(/g,
  ],
};

function checkFunctionUsage(packageName: string, files: string[]): string[] {
  const patterns = VULNERABLE_FUNCTION_PATTERNS[packageName] || [];
  if (patterns.length === 0) return files; // Assume reachable if no specific patterns

  const usedIn: string[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of patterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      if (regex.test(content)) {
        usedIn.push(file);
        break;
      }
    }
  }

  return usedIn;
}

const importMapCache = new Map<string, { map: ImportMap; timestamp: number }>();
const CACHE_TTL = 30000; // 30 seconds

export async function checkReachability(
  vulnerability: DependencyVulnerability,
  projectPath: string
): Promise<ReachabilityResult> {
  // Dev dependencies in production are less concerning
  if (vulnerability.isDevDependency) {
    return {
      reachable: false,
      reason: 'Package is a dev dependency and not used in production builds',
    };
  }

  // Build or retrieve cached import map
  const cacheKey = projectPath;
  const cached = importMapCache.get(cacheKey);
  let importMap: ImportMap;

  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    importMap = cached.map;
  } else {
    importMap = await buildImportMap(projectPath);
    importMapCache.set(cacheKey, { map: importMap, timestamp: Date.now() });
  }

  const packageName = vulnerability.packageName;
  const importedIn = importMap[packageName];

  if (!importedIn || importedIn.length === 0) {
    return {
      reachable: false,
      reason: `Package '${packageName}' is not directly imported in any source file`,
    };
  }

  // Check if specific vulnerable functions are used
  const usedIn = checkFunctionUsage(packageName, importedIn);

  if (usedIn.length === 0 && VULNERABLE_FUNCTION_PATTERNS[packageName]) {
    return {
      reachable: false,
      reason: `Package '${packageName}' is imported but vulnerable functions are not called`,
      usedIn: importedIn,
    };
  }

  return {
    reachable: true,
    reason: `Package '${packageName}' is actively used in ${usedIn.length || importedIn.length} file(s)`,
    usedIn: usedIn.length > 0 ? usedIn : importedIn,
  };
}

export async function analyzeReachability(
  vulnerabilities: DependencyVulnerability[],
  projectPath: string
): Promise<Map<string, ReachabilityResult>> {
  const results = new Map<string, ReachabilityResult>();

  // Build import map once
  const importMap = await buildImportMap(projectPath);
  importMapCache.set(projectPath, { map: importMap, timestamp: Date.now() });

  await Promise.all(
    vulnerabilities.map(async (vuln) => {
      const result = await checkReachability(vuln, projectPath);
      results.set(vuln.id, result);
    })
  );

  return results;
}
