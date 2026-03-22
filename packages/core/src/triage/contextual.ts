import * as fs from 'fs';
import * as path from 'path';
import type { AnyFinding, ProjectContext, DependencyVulnerability, Severity } from '@shield/shared';

export function detectProjectContext(projectPath: string): ProjectContext {
  const context: ProjectContext = {
    hasDatabase: false,
    hasAuthentication: false,
    isPubliclyDeployed: false,
    frameworks: [],
    isMonorepo: false,
    hasTests: false,
    deployTarget: 'unknown',
    language: [],
  };

  // Read package.json
  const pkgPath = path.join(projectPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      // Detect frameworks
      if (allDeps.next) context.frameworks.push('nextjs');
      if (allDeps.react) context.frameworks.push('react');
      if (allDeps.express) context.frameworks.push('express');
      if (allDeps.fastify) context.frameworks.push('fastify');
      if (allDeps.koa) context.frameworks.push('koa');
      if (allDeps['@nestjs/core']) context.frameworks.push('nestjs');
      if (allDeps.nuxt) context.frameworks.push('nuxt');
      if (allDeps.vue) context.frameworks.push('vue');
      if (allDeps.svelte) context.frameworks.push('svelte');
      if (allDeps['remix']) context.frameworks.push('remix');

      // Detect database usage
      if (allDeps.prisma || allDeps['@prisma/client'] ||
        allDeps.mongoose || allDeps.sequelize || allDeps.typeorm ||
        allDeps.pg || allDeps.mysql2 || allDeps.mongodb ||
        allDeps['better-sqlite3'] || allDeps.sqlite3) {
        context.hasDatabase = true;
      }

      // Detect authentication
      if (allDeps['next-auth'] || allDeps['@auth/core'] ||
        allDeps.passport || allDeps['passport-jwt'] ||
        allDeps['jsonwebtoken'] || allDeps['@supabase/supabase-js'] ||
        allDeps['@clerk/nextjs'] || allDeps['@clerk/clerk-sdk-node'] ||
        allDeps.auth0 || allDeps['jose']) {
        context.hasAuthentication = true;
      }

      // Detect monorepo
      if (pkg.workspaces || fs.existsSync(path.join(projectPath, 'turbo.json')) ||
        fs.existsSync(path.join(projectPath, 'pnpm-workspace.yaml'))) {
        context.isMonorepo = true;
      }

      // Language detection
      if (allDeps.typescript || pkg.devDependencies?.typescript) {
        context.language.push('typescript');
      }
      context.language.push('javascript');
    } catch {
      // ignore
    }
  }

  // Check for Python
  if (fs.existsSync(path.join(projectPath, 'requirements.txt')) ||
    fs.existsSync(path.join(projectPath, 'pyproject.toml')) ||
    fs.existsSync(path.join(projectPath, 'setup.py'))) {
    context.language.push('python');
  }

  // Check deploy targets
  if (fs.existsSync(path.join(projectPath, 'vercel.json')) ||
    fs.existsSync(path.join(projectPath, '.vercel'))) {
    context.deployTarget = 'vercel';
    context.isPubliclyDeployed = true;
  } else if (fs.existsSync(path.join(projectPath, 'netlify.toml'))) {
    context.deployTarget = 'netlify';
    context.isPubliclyDeployed = true;
  } else if (fs.existsSync(path.join(projectPath, 'fly.toml'))) {
    context.deployTarget = 'aws';
    context.isPubliclyDeployed = true;
  } else if (fs.existsSync(path.join(projectPath, 'Dockerfile'))) {
    context.deployTarget = 'docker';
  } else if (fs.existsSync(path.join(projectPath, 'railway.json'))) {
    context.deployTarget = 'aws';
    context.isPubliclyDeployed = true;
  }

  // Check for tests
  if (fs.existsSync(path.join(projectPath, '__tests__')) ||
    fs.existsSync(path.join(projectPath, 'test')) ||
    fs.existsSync(path.join(projectPath, 'tests')) ||
    fs.existsSync(path.join(projectPath, 'spec'))) {
    context.hasTests = true;
  }

  return context;
}

function isTestFile(filePath: string): boolean {
  return /\.(test|spec)\.(ts|tsx|js|jsx)$/.test(filePath) ||
    filePath.includes('__tests__') ||
    filePath.includes('/test/') ||
    filePath.includes('/tests/') ||
    filePath.includes('/spec/');
}

function isFrontendOnly(context: ProjectContext): boolean {
  return context.frameworks.some(f => ['react', 'vue', 'svelte'].includes(f)) &&
    !context.frameworks.some(f => ['express', 'fastify', 'koa', 'nestjs', 'nextjs', 'remix'].includes(f));
}

export function applyContextualTriage(
  findings: AnyFinding[],
  context: ProjectContext
): AnyFinding[] {
  return findings.map(finding => {
    const updated = { ...finding };

    // Auto-ignore: secrets in test files
    if (finding.scanner === 'secrets' && isTestFile(finding.file)) {
      updated.autoIgnored = true;
      updated.autoIgnoreReason = 'Secret found in test file — likely test fixture or mock value';
      return updated;
    }

    // Auto-ignore: dev dependency vulns with CVSS < 4.0 and no exploit
    if (finding.scanner === 'sca') {
      const depFinding = finding as DependencyVulnerability;
      if (depFinding.isDevDependency && depFinding.cvssScore < 4.0 && !depFinding.exploitAvailable) {
        updated.autoIgnored = true;
        updated.autoIgnoreReason = 'Low severity vulnerability in dev-only dependency without known exploit';
        return updated;
      }

      // Auto-ignore unreachable dev dependencies
      if (depFinding.isDevDependency && !depFinding.isReachable) {
        updated.autoIgnored = true;
        updated.autoIgnoreReason = 'Vulnerability in dev dependency that is not reachable in production';
        return updated;
      }
    }

    // Auto-ignore: SQL injection in frontend-only projects
    if (finding.scanner === 'sast' && finding.rule === 'sql-injection-template-literal') {
      if (isFrontendOnly(context)) {
        updated.autoIgnored = true;
        updated.autoIgnoreReason = 'SQL injection detected in frontend-only project — may be false positive';
        return updated;
      }
    }

    // Downgrade severity: missing auth in projects without public deployment
    if (finding.scanner === 'sast' && finding.rule === 'missing-auth-middleware') {
      if (!context.isPubliclyDeployed) {
        updated.contextualSeverity = 'medium';
      }
    }

    // Upgrade severity: SQL injection in projects with database
    if (finding.scanner === 'sast' && finding.rule.includes('sql-injection')) {
      if (context.hasDatabase) {
        // Keep or upgrade severity
        updated.contextualSeverity = 'critical';
      }
    }

    // Upgrade severity: hardcoded credentials in publicly deployed project
    if (finding.scanner === 'secrets' || finding.rule === 'hardcoded-credentials') {
      if (context.isPubliclyDeployed) {
        updated.contextualSeverity = 'critical';
      }
    }

    // Auto-ignore very low severity findings in CVEs
    if (finding.scanner === 'sca') {
      const depFinding = finding as DependencyVulnerability;
      if (depFinding.cvssScore < 3.0 && !depFinding.exploitAvailable && !depFinding.isReachable) {
        updated.autoIgnored = true;
        updated.autoIgnoreReason = 'Very low CVSS score, no known exploit, and package is not reachable';
        return updated;
      }
    }

    return updated;
  });
}

export function getEffectiveSeverity(finding: AnyFinding): Severity {
  return finding.contextualSeverity || finding.severity;
}
