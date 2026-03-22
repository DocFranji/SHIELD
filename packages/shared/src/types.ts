export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type ScannerType = 'sast' | 'sca' | 'secrets' | 'iac' | 'quality';

export interface Finding {
  id: string;
  scanner: ScannerType;
  rule: string;
  severity: Severity;
  file: string;
  line: number;
  column?: number;
  message: string;
  cwe?: string;
  owasp?: string;
  snippet?: string;
  fixSuggestion?: string;
  confidence: Confidence;
  autoIgnored?: boolean;
  autoIgnoreReason?: string;
  // Triage fields
  isReachable?: boolean;
  isDuplicate?: boolean;
  duplicateOf?: string;
  contextualSeverity?: Severity;
}

export interface SASTFinding extends Finding {
  scanner: 'sast';
  cwe: string;
  owasp: string;
  snippet: string;
  fixSuggestion: string;
}

export interface DependencyVulnerability extends Finding {
  scanner: 'sca';
  packageName: string;
  installedVersion: string;
  vulnerableRange: string;
  fixedVersion: string | null;
  cve: string;
  cvssScore: number;
  description: string;
  isDevDependency: boolean;
  isDirect: boolean;
  isReachable: boolean;
  exploitAvailable: boolean;
}

export interface SecretFinding extends Finding {
  scanner: 'secrets';
  secretType: string;
  entropy?: number;
  value?: string; // masked
}

export interface IaCFinding extends Finding {
  scanner: 'iac';
  configFile: string;
}

export type AnyFinding = SASTFinding | DependencyVulnerability | SecretFinding | IaCFinding;

export interface ScanResult {
  projectPath: string;
  projectName: string;
  timestamp: string;
  duration: number;
  filesScanned: number;
  dependenciesChecked: number;
  rawFindings: AnyFinding[];
  triagedFindings: AnyFinding[];
  autoIgnored: AnyFinding[];
  securityScore: number;
  noiseReductionPercent: number;
  context: ProjectContext;
}

export interface ProjectContext {
  hasDatabase: boolean;
  hasAuthentication: boolean;
  isPubliclyDeployed: boolean;
  frameworks: string[];
  isMonorepo: boolean;
  hasTests: boolean;
  deployTarget: 'vercel' | 'netlify' | 'cloudflare' | 'aws' | 'docker' | 'unknown';
  language: string[];
}

export interface ReachabilityResult {
  reachable: boolean;
  reason?: string;
  usedIn?: string[];
}

export interface FindingGroup {
  primary: AnyFinding;
  related: AnyFinding[];
  totalCount: number;
}

export interface DeduplicationResult {
  groups: FindingGroup[];
  totalOriginal: number;
  totalAfterDedup: number;
  reductionPercent: number;
}

export interface ScanOptions {
  quick?: boolean;
  scanners?: ScannerType[];
  outputFormat?: 'console' | 'json' | 'markdown';
  outputFile?: string;
  ignoreFile?: string;
  minSeverity?: Severity;
  ciMode?: boolean;
  verbose?: boolean;
}
