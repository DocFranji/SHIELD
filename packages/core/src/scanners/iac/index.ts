import * as fs from 'fs';
import * as path from 'path';
import fg from 'fast-glob';
import yaml from 'js-yaml';
import type { IaCFinding } from '@shield/shared';

let findingIdCounter = 0;
function generateId(): string {
  return `iac-${Date.now()}-${++findingIdCounter}`;
}

function makeFinding(
  rule: string,
  severity: IaCFinding['severity'],
  message: string,
  filePath: string,
  line: number,
  fixSuggestion: string,
  cwe = 'CWE-16',
  confidence: IaCFinding['confidence'] = 'high'
): IaCFinding {
  return {
    id: generateId(),
    scanner: 'iac',
    rule,
    severity,
    file: filePath,
    line,
    message,
    cwe,
    owasp: 'A05:2021 – Security Misconfiguration',
    fixSuggestion,
    confidence,
    configFile: path.basename(filePath),
  };
}

function analyzeDockerfile(filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = [];
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');
  let hasUserInstruction = false;
  let hasHealthCheck = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim().toUpperCase();

    // Root user check
    if (trimmed.startsWith('USER ')) {
      const userPart = line.trim().slice(5).trim().toLowerCase();
      if (userPart === 'root' || userPart === '0') {
        findings.push(makeFinding(
          'dockerfile-root-user',
          'high',
          'Dockerfile explicitly sets USER to root, running containers as root is a security risk',
          filePath,
          lineNum,
          'Create a non-root user: RUN adduser --disabled-password appuser && USER appuser',
          'CWE-250'
        ));
      } else {
        hasUserInstruction = true;
      }
    }

    // Latest tag usage
    const fromMatch = line.match(/^FROM\s+([^\s]+)/i);
    if (fromMatch) {
      const image = fromMatch[1];
      if (image.includes(':latest') || (!image.includes(':') && !image.startsWith('scratch'))) {
        findings.push(makeFinding(
          'dockerfile-latest-tag',
          'medium',
          `Dockerfile uses unstable image tag '${image}'. Using :latest or no tag is not reproducible`,
          filePath,
          lineNum,
          'Pin to a specific version digest: FROM node:20.11-alpine3.19@sha256:...',
          'CWE-1104'
        ));
      }
    }

    // Secrets in ENV
    const envMatch = line.match(/^ENV\s+(.+)/i);
    if (envMatch) {
      const envPart = envMatch[1];
      const secretPatterns = /(password|secret|key|token|api_key|apikey|auth)\s*[=\s]+\S+/i;
      if (secretPatterns.test(envPart)) {
        findings.push(makeFinding(
          'dockerfile-secret-in-env',
          'critical',
          'Dockerfile hardcodes a secret in an ENV instruction — it will be exposed in image layers and metadata',
          filePath,
          lineNum,
          'Use Docker BuildKit secrets or runtime environment injection instead of hardcoding in ENV',
          'CWE-798'
        ));
      }
    }

    // COPY .env
    if (/^COPY\s+.*\.env/.test(line.trim())) {
      findings.push(makeFinding(
        'dockerfile-copy-env',
        'critical',
        'Dockerfile copies .env file into image — secrets will be embedded in the image layer',
        filePath,
        lineNum,
        'Remove COPY .env from Dockerfile. Use Docker secrets or environment variables at runtime',
        'CWE-798'
      ));
    }

    // wget/curl downloading from untrusted source without verification
    if (/RUN.*(wget|curl).*http:\/\//i.test(line)) {
      findings.push(makeFinding(
        'dockerfile-insecure-download',
        'medium',
        'Dockerfile downloads over HTTP (not HTTPS), vulnerable to MITM attacks',
        filePath,
        lineNum,
        'Use HTTPS URLs for all downloads and verify checksums',
        'CWE-829'
      ));
    }

    // HEALTHCHECK
    if (trimmed.startsWith('HEALTHCHECK')) {
      hasHealthCheck = true;
    }
  }

  // No USER instruction at all (implicit root)
  if (!hasUserInstruction) {
    findings.push(makeFinding(
      'dockerfile-no-user',
      'high',
      'Dockerfile does not specify a non-root USER — container runs as root by default',
      filePath,
      1,
      'Add a non-root user: RUN addgroup -S appgroup && adduser -S appuser -G appgroup && USER appuser',
      'CWE-250'
    ));
  }

  return findings;
}

function analyzeDockerCompose(filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = [];
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = yaml.load(content) as Record<string, unknown>;
  } catch {
    return findings;
  }

  const services = (parsed?.services as Record<string, unknown>) || {};
  const lines = content.split('\n');

  for (const [serviceName, serviceConfig] of Object.entries(services)) {
    const service = serviceConfig as Record<string, unknown>;

    // Privileged mode
    if (service?.privileged === true) {
      const lineNum = lines.findIndex(l => l.includes('privileged: true')) + 1;
      findings.push(makeFinding(
        'compose-privileged-container',
        'critical',
        `Service '${serviceName}' runs in privileged mode — full host access is granted`,
        filePath,
        lineNum || 1,
        'Remove privileged: true. Use specific Linux capabilities instead: cap_add: [NET_ADMIN]',
        'CWE-250'
      ));
    }

    // Port exposure (0.0.0.0 binding)
    const ports = service?.ports as string[] | undefined;
    if (ports) {
      for (const port of ports) {
        const portStr = String(port);
        if (portStr.startsWith('0.0.0.0:') || !portStr.includes(':')) {
          const lineNum = lines.findIndex(l => l.includes(portStr)) + 1;
          // Skip common public ports
          if (!portStr.includes('80:') && !portStr.includes('443:')) {
            findings.push(makeFinding(
              'compose-port-exposure',
              'medium',
              `Service '${serviceName}' exposes port ${portStr} on all interfaces (0.0.0.0)`,
              filePath,
              lineNum || 1,
              'Bind to specific interface: "127.0.0.1:5432:5432" to limit exposure',
              'CWE-16',
              'medium'
            ));
          }
        }
      }
    }

    // Hardcoded passwords in environment
    const environment = service?.environment as string[] | Record<string, string> | undefined;
    if (environment) {
      const envEntries = Array.isArray(environment)
        ? environment.map(e => String(e))
        : Object.entries(environment).map(([k, v]) => `${k}=${v}`);

      for (const envEntry of envEntries) {
        const secretPatterns = /(PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=\s*\S+/i;
        if (secretPatterns.test(envEntry) && !envEntry.includes('${')) {
          const lineNum = lines.findIndex(l => l.includes(envEntry.split('=')[0])) + 1;
          findings.push(makeFinding(
            'compose-hardcoded-secret',
            'high',
            `Service '${serviceName}' has hardcoded secret in environment variable`,
            filePath,
            lineNum || 1,
            'Use Docker secrets or reference .env file with variable substitution: POSTGRES_PASSWORD=${POSTGRES_PASSWORD}',
            'CWE-798'
          ));
        }
      }
    }
  }

  return findings;
}

function analyzeNextConfig(filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = [];
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // CORS wildcard
    if (line.includes("'*'") || line.includes('"*"')) {
      if (lines.slice(Math.max(0, i - 3), i + 3).some(l => l.includes('cors') || l.includes('Access-Control') || l.includes('headers'))) {
        findings.push(makeFinding(
          'nextjs-cors-wildcard',
          'medium',
          'Next.js config uses CORS wildcard (*) allowing requests from any origin',
          filePath,
          lineNum,
          'Restrict CORS to specific trusted origins instead of using wildcard',
          'CWE-942'
        ));
      }
    }

    // Exposed env vars in public config
    if (line.match(/NEXT_PUBLIC_.*(?:SECRET|KEY|TOKEN|PASSWORD)/i)) {
      findings.push(makeFinding(
        'nextjs-public-secret',
        'high',
        'Secret/sensitive value exposed as NEXT_PUBLIC_ env var — visible in client-side bundle',
        filePath,
        lineNum,
        'Never prefix secrets with NEXT_PUBLIC_. Only public values (like API endpoints) should use this prefix',
        'CWE-312'
      ));
    }

    // dangerouslyAllowSVG
    if (line.includes('dangerouslyAllowSVG: true')) {
      findings.push(makeFinding(
        'nextjs-dangerous-svg',
        'medium',
        'Next.js Image component has dangerouslyAllowSVG enabled which can lead to XSS',
        filePath,
        lineNum,
        'Add contentSecurityPolicy option when enabling dangerouslyAllowSVG',
        'CWE-79'
      ));
    }
  }

  return findings;
}

function analyzeVercelJson(filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = [];
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return findings;
  }

  const headers = parsed?.headers as Array<{ source: string; headers: Array<{ key: string; value: string }> }> | undefined;
  if (headers) {
    for (const headerConfig of headers) {
      for (const header of (headerConfig.headers || [])) {
        if (header.key === 'Access-Control-Allow-Origin' && header.value === '*') {
          findings.push(makeFinding(
            'vercel-cors-wildcard',
            'medium',
            'vercel.json sets CORS Access-Control-Allow-Origin to wildcard (*)',
            filePath,
            1,
            'Replace * with specific allowed origins',
            'CWE-942'
          ));
        }
      }
    }
  }

  return findings;
}

function analyzeDotEnv(filePath: string, projectPath: string): IaCFinding[] {
  const findings: IaCFinding[] = [];

  // Check if this .env file is in .gitignore
  const gitignorePath = path.join(projectPath, '.gitignore');
  let isGitIgnored = false;

  if (fs.existsSync(gitignorePath)) {
    const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
    const gitignoreLines = gitignoreContent.split('\n').map(l => l.trim());
    const envFileName = path.basename(filePath);
    isGitIgnored = gitignoreLines.some(line =>
      line === '.env' || line === `/${envFileName}` || line === envFileName ||
      line === '*.env' || line === '.env*'
    );
  }

  if (!isGitIgnored) {
    findings.push(makeFinding(
      'env-not-gitignored',
      'critical',
      `${path.basename(filePath)} is not listed in .gitignore — secrets may be committed to git`,
      filePath,
      1,
      'Add .env to .gitignore immediately. Rotate any secrets that may have been exposed. Use .env.example for templates.',
      'CWE-312'
    ));
  }

  return findings;
}

export async function scanIaC(projectPath: string): Promise<IaCFinding[]> {
  const allFindings: IaCFinding[] = [];

  const patterns = [
    '**/Dockerfile',
    '**/Dockerfile.*',
    '**/docker-compose*.yml',
    '**/docker-compose*.yaml',
    '**/next.config.js',
    '**/next.config.ts',
    '**/next.config.mjs',
    '**/vercel.json',
    '**/.env',
    '**/.env.local',
    '**/.env.production',
    '**/.env.development',
    '**/netlify.toml',
    '**/fly.toml',
    '**/railway.json',
  ];

  const ignore = [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/.next/**',
    '**/coverage/**',
    '**/.env.example',
    '**/.env.sample',
    '**/.env.template',
  ];

  const files = await fg(patterns, {
    cwd: projectPath,
    ignore,
    absolute: true,
    followSymbolicLinks: false,
    dot: true,
  });

  for (const file of files) {
    const basename = path.basename(file);
    const dirBase = path.dirname(file);

    if (basename === 'Dockerfile' || basename.startsWith('Dockerfile.')) {
      allFindings.push(...analyzeDockerfile(file));
    } else if (basename.startsWith('docker-compose')) {
      allFindings.push(...analyzeDockerCompose(file));
    } else if (basename.startsWith('next.config')) {
      allFindings.push(...analyzeNextConfig(file));
    } else if (basename === 'vercel.json') {
      allFindings.push(...analyzeVercelJson(file));
    } else if (basename.startsWith('.env')) {
      allFindings.push(...analyzeDotEnv(file, projectPath));
    }
  }

  return allFindings;
}
