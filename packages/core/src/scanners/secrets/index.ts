import * as fs from 'fs';
import * as path from 'path';
import fg from 'fast-glob';
import type { SecretFinding } from '@shield/shared';

let findingIdCounter = 0;
function generateId(): string {
  return `secrets-${Date.now()}-${++findingIdCounter}`;
}

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: SecretFinding['severity'];
  entropyThreshold?: number;
  description: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'aws-access-key-id',
    pattern: /\b(AKIA|ASIA|AROA|AGPA|AIDA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/,
    severity: 'critical',
    description: 'AWS Access Key ID',
  },
  {
    name: 'aws-secret-access-key',
    pattern: /(?:aws.{0,20})?(?:secret.{0,20})?['"` ]([A-Za-z0-9+/]{40})(?:['"` ]|$)/i,
    severity: 'critical',
    entropyThreshold: 4.5,
    description: 'AWS Secret Access Key',
  },
  {
    name: 'github-token',
    pattern: /\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/,
    severity: 'critical',
    description: 'GitHub Personal Access Token',
  },
  {
    name: 'stripe-secret-key',
    pattern: /\b(sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,})\b/,
    severity: 'critical',
    description: 'Stripe Secret Key (live)',
  },
  {
    name: 'stripe-publishable-key',
    pattern: /\b(pk_live_[A-Za-z0-9]{24,})\b/,
    severity: 'high',
    description: 'Stripe Publishable Key (live)',
  },
  {
    name: 'openai-api-key',
    pattern: /\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-proj-[A-Za-z0-9\-_]{80,})\b/,
    severity: 'critical',
    description: 'OpenAI API Key',
  },
  {
    name: 'anthropic-api-key',
    pattern: /\b(sk-ant-[A-Za-z0-9\-_]{80,})\b/,
    severity: 'critical',
    description: 'Anthropic API Key',
  },
  {
    name: 'supabase-service-key',
    pattern: /\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9+/=._-]{50,})\b/,
    severity: 'critical',
    description: 'Supabase/JWT Service Key',
  },
  {
    name: 'slack-token',
    pattern: /\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/,
    severity: 'high',
    description: 'Slack API Token',
  },
  {
    name: 'slack-webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    severity: 'high',
    description: 'Slack Webhook URL',
  },
  {
    name: 'firebase-config',
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    severity: 'high',
    description: 'Firebase API Key',
  },
  {
    name: 'vercel-token',
    pattern: /\b([A-Za-z0-9]{24}[A-Za-z0-9]{0,})\b.*vercel/i,
    severity: 'high',
    description: 'Vercel Token',
  },
  {
    name: 'npm-token',
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/,
    severity: 'high',
    description: 'NPM Access Token',
  },
  {
    name: 'database-url',
    pattern: /(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^:]+:[^@]+@[^\s'"]+/i,
    severity: 'critical',
    description: 'Database Connection URL with credentials',
  },
  {
    name: 'private-key-pem',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
    description: 'Private Key (PEM format)',
  },
  {
    name: 'sendgrid-api-key',
    pattern: /\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b/,
    severity: 'high',
    description: 'SendGrid API Key',
  },
  {
    name: 'twilio-account-sid',
    pattern: /\b(AC[A-Za-z0-9]{32})\b/,
    severity: 'high',
    description: 'Twilio Account SID',
  },
  {
    name: 'generic-api-key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?secret)\s*[=:]\s*['"]([A-Za-z0-9\-_]{16,})['"]/i,
    severity: 'high',
    entropyThreshold: 4.0,
    description: 'Generic API Key/Secret',
  },
  {
    name: 'jwt-secret',
    pattern: /(?:jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*['"]([^'"]{8,})['"]/i,
    severity: 'high',
    description: 'JWT Secret',
  },
  {
    name: 'google-oauth-client-secret',
    pattern: /GOCSPX-[A-Za-z0-9_\-]{28}/,
    severity: 'high',
    description: 'Google OAuth Client Secret',
  },
];

// Shannon entropy calculation
function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function maskValue(value: string): string {
  if (value.length <= 8) return '****';
  const first = value.slice(0, 4);
  const last = value.slice(-4);
  return `${first}${'*'.repeat(Math.min(value.length - 8, 20))}${last}`;
}

function isPlaceholder(value: string): boolean {
  const placeholders = [
    'xxx', 'yyy', 'zzz', 'placeholder', 'changeme', 'your-', 'your_',
    'example', 'sample', '<', '>', '${', '#{', 'insert', 'replace',
    'todo', 'fixme', 'test-', '-test', '_test', 'fake', 'dummy',
    'abc123', '12345', 'password', 'secret123', 'qwerty', 'localhost',
  ];
  const lower = value.toLowerCase();
  return placeholders.some(p => lower.includes(p));
}

const SKIP_FILES = [
  /node_modules/,
  /\.git\//,
  /dist\//,
  /build\//,
  /coverage\//,
  /\.next\//,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.env\.example$/,
  /\.env\.sample$/,
  /\.env\.template$/,
  /\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|tar|gz)$/i,
];

function shouldSkipFile(filePath: string): boolean {
  return SKIP_FILES.some(p => p.test(filePath));
}

export async function scanFile(filePath: string): Promise<SecretFinding[]> {
  if (shouldSkipFile(filePath)) return [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  // Skip binary files
  if (content.includes('\0')) return [];

  const findings: SecretFinding[] = [];
  const lines = content.split('\n');
  const fileName = path.basename(filePath);

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    // Skip commented lines (// or #)
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#!')) continue;

    for (const secretPattern of SECRET_PATTERNS) {
      const match = line.match(secretPattern.pattern);
      if (!match) continue;

      const matchedValue = match[1] || match[0];

      // Skip if it looks like a placeholder
      if (isPlaceholder(matchedValue)) continue;

      // Check entropy if required
      if (secretPattern.entropyThreshold) {
        const entropy = calculateEntropy(matchedValue);
        if (entropy < secretPattern.entropyThreshold) continue;
      }

      const entropy = calculateEntropy(matchedValue);

      findings.push({
        id: generateId(),
        scanner: 'secrets',
        rule: secretPattern.name,
        severity: secretPattern.severity,
        file: filePath,
        line: lineNum,
        column: line.indexOf(match[0]),
        message: `${secretPattern.description} found in ${fileName}`,
        cwe: 'CWE-798',
        owasp: 'A07:2021 – Identification and Authentication Failures',
        fixSuggestion: `Remove the secret from source code. Add to .env file and reference via process.env. Rotate the credential immediately if committed to git history.`,
        confidence: entropy > 4.5 ? 'high' : 'medium',
        secretType: secretPattern.description,
        entropy,
        value: maskValue(matchedValue),
        snippet: line.trim().slice(0, 120),
      });

      break; // Only report once per line per first match
    }
  }

  return findings;
}

export async function scanDirectory(dirPath: string): Promise<SecretFinding[]> {
  const patterns = ['**/*'];
  const ignore = [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/build/**',
    '**/.next/**',
    '**/coverage/**',
    '**/*.min.js',
  ];

  let files: string[];
  try {
    files = await fg(patterns, {
      cwd: dirPath,
      ignore,
      absolute: true,
      followSymbolicLinks: false,
      dot: true, // Include .env files
      onlyFiles: true,
    });
  } catch {
    return [];
  }

  const allFindings: SecretFinding[] = [];

  await Promise.all(
    files.map(async (file) => {
      const findings = await scanFile(file);
      allFindings.push(...findings);
    })
  );

  return allFindings;
}
