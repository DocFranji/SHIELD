import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import * as fs from 'fs';
import * as path from 'path';
import fg from 'fast-glob';
import type { SASTFinding, ScanOptions } from '@shield/shared';

let findingIdCounter = 0;
function generateId(prefix = 'sast'): string {
  return `${prefix}-${Date.now()}-${++findingIdCounter}`;
}

interface RuleMatch {
  rule: string;
  severity: SASTFinding['severity'];
  message: string;
  cwe: string;
  owasp: string;
  fixSuggestion: string;
  confidence: SASTFinding['confidence'];
  line: number;
  column: number;
  snippet: string;
}

function getSnippet(lines: string[], lineNum: number, context = 2): string {
  const start = Math.max(0, lineNum - 1 - context);
  const end = Math.min(lines.length, lineNum + context);
  return lines.slice(start, end).join('\n');
}

function isUserInputExpression(node: t.Node): boolean {
  if (t.isMemberExpression(node)) {
    const obj = node.object;
    const prop = node.property;
    if (t.isIdentifier(obj) && ['req', 'request', 'ctx', 'context'].includes(obj.name)) {
      return true;
    }
    if (t.isMemberExpression(obj) && t.isIdentifier(obj.object) &&
      ['req', 'request'].includes((obj.object as t.Identifier).name)) {
      return true;
    }
    if (t.isIdentifier(prop) && ['body', 'params', 'query', 'headers', 'cookies'].includes(prop.name)) {
      return true;
    }
  }
  if (t.isIdentifier(node)) {
    const name = node.name.toLowerCase();
    if (['userInput', 'input', 'data', 'payload', 'params', 'body', 'query'].includes(name)) {
      return true;
    }
  }
  return false;
}

function hasUserInputInTemplateLiteral(node: t.TemplateLiteral): boolean {
  return node.expressions.some(expr => {
    if (isUserInputExpression(expr)) return true;
    if (t.isMemberExpression(expr)) {
      return isUserInputExpression(expr.object) || isUserInputExpression(expr);
    }
    return false;
  });
}

export async function scanFile(filePath: string, content?: string): Promise<SASTFinding[]> {
  const findings: SASTFinding[] = [];
  const code = content ?? fs.readFileSync(filePath, 'utf-8');
  const lines = code.split('\n');
  const fileName = path.basename(filePath);

  // Skip test files, mocks, fixtures
  const isTestFile = /\.(test|spec)\.(ts|tsx|js|jsx)$/.test(fileName) ||
    filePath.includes('__tests__') ||
    filePath.includes('__mocks__');

  let ast: parser.ParseResult<t.File>;
  try {
    ast = parser.parse(code, {
      sourceType: 'module',
      errorRecovery: true,
      plugins: [
        'typescript',
        'jsx',
        ['decorators', { decoratorsBeforeExport: true }],
        'classProperties',
        'objectRestSpread',
        'optionalChaining',
        'nullishCoalescingOperator',
        'dynamicImport',
        'importMeta',
      ],
    });
  } catch {
    // Try again as script
    try {
      ast = parser.parse(code, {
        sourceType: 'script',
        errorRecovery: true,
        plugins: ['jsx', 'objectRestSpread', 'optionalChaining'],
      });
    } catch {
      return findings;
    }
  }

  const matches: RuleMatch[] = [];
  const authMiddlewareNames = new Set<string>(['auth', 'authenticate', 'requireAuth', 'isAuthenticated',
    'verifyToken', 'checkAuth', 'authMiddleware', 'protect', 'ensureAuth', 'jwtMiddleware']);

  traverse(ast, {
    // SQL Injection - $queryRawUnsafe
    CallExpression(nodePath) {
      const node = nodePath.node;
      const loc = node.loc?.start;
      if (!loc) return;

      // Prisma $queryRawUnsafe
      if (t.isMemberExpression(node.callee)) {
        const prop = node.callee.property;
        if (t.isIdentifier(prop) && prop.name === '$queryRawUnsafe') {
          const arg = node.arguments[0];
          if (arg && (t.isTemplateLiteral(arg) || t.isBinaryExpression(arg))) {
            matches.push({
              rule: 'sql-injection-raw-unsafe',
              severity: 'critical',
              message: 'SQL injection via Prisma $queryRawUnsafe with dynamic query construction',
              cwe: 'CWE-89',
              owasp: 'A03:2021 – Injection',
              fixSuggestion: 'Use $queryRaw with tagged template literals or parameterized queries: prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`',
              confidence: 'high',
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(lines, loc.line),
            });
          }
        }

        // db.query / sequelize.query with template literals
        if (t.isIdentifier(prop) && prop.name === 'query') {
          const arg = node.arguments[0];
          if (arg && t.isTemplateLiteral(arg) && hasUserInputInTemplateLiteral(arg)) {
            matches.push({
              rule: 'sql-injection-template-literal',
              severity: 'critical',
              message: 'SQL injection via template literal interpolation in database query',
              cwe: 'CWE-89',
              owasp: 'A03:2021 – Injection',
              fixSuggestion: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId])',
              confidence: 'high',
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(lines, loc.line),
            });
          }
        }
      }

      // Command injection - exec/execSync/spawn
      if (t.isMemberExpression(node.callee)) {
        const obj = node.callee.object;
        const prop = node.callee.property;
        const isExecCall = t.isIdentifier(prop) && ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync'].includes(prop.name);
        if (isExecCall) {
          const arg = node.arguments[0];
          if (arg) {
            const hasUserInput = (t.isTemplateLiteral(arg) && hasUserInputInTemplateLiteral(arg)) ||
              isUserInputExpression(arg) ||
              (t.isBinaryExpression(arg));
            if (hasUserInput) {
              matches.push({
                rule: 'command-injection',
                severity: 'critical',
                message: `Command injection via child_process.${t.isIdentifier(prop) ? prop.name : 'exec'} with user-controlled input`,
                cwe: 'CWE-78',
                owasp: 'A03:2021 – Injection',
                fixSuggestion: 'Use execFile with an array of arguments instead of string interpolation, or use a whitelist of allowed commands',
                confidence: 'high',
                line: loc.line,
                column: loc.column,
                snippet: getSnippet(lines, loc.line),
              });
            }
          }
        }
      }

      // Also catch bare exec() calls (after destructuring)
      if (t.isIdentifier(node.callee) && ['exec', 'execSync'].includes(node.callee.name)) {
        const arg = node.arguments[0];
        if (arg && (
          (t.isTemplateLiteral(arg) && hasUserInputInTemplateLiteral(arg)) ||
          isUserInputExpression(arg)
        )) {
          matches.push({
            rule: 'command-injection',
            severity: 'critical',
            message: 'Command injection via exec() with user-controlled input',
            cwe: 'CWE-78',
            owasp: 'A03:2021 – Injection',
            fixSuggestion: 'Use execFile with an array of arguments, or sanitize input with a strict allowlist',
            confidence: 'high',
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(lines, loc.line),
          });
        }
      }

      // eval() - unsafe deserialization / code injection
      if (t.isIdentifier(node.callee) && node.callee.name === 'eval') {
        const arg = node.arguments[0];
        if (arg && !t.isStringLiteral(arg)) {
          matches.push({
            rule: 'unsafe-eval',
            severity: 'critical',
            message: 'Use of eval() with dynamic content allows arbitrary code execution',
            cwe: 'CWE-94',
            owasp: 'A03:2021 – Injection',
            fixSuggestion: 'Avoid eval() entirely. Use JSON.parse() for data, or specific APIs for dynamic behavior',
            confidence: 'high',
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(lines, loc.line),
          });
        }
      }

      // Function constructor - code injection
      if (t.isNewExpression(node) && t.isIdentifier(node.callee) && node.callee.name === 'Function') {
        if (node.arguments.length > 0 && !node.arguments.every(a => t.isStringLiteral(a))) {
          matches.push({
            rule: 'function-constructor-injection',
            severity: 'high',
            message: 'Dynamic Function() constructor can execute arbitrary code',
            cwe: 'CWE-94',
            owasp: 'A03:2021 – Injection',
            fixSuggestion: 'Avoid the Function constructor with dynamic arguments. Refactor to use explicit function declarations',
            confidence: 'medium',
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(lines, loc.line),
          });
        }
      }

      // Path traversal - fs.readFile/writeFile with req.params
      if (t.isMemberExpression(node.callee)) {
        const obj = node.callee.object;
        const prop = node.callee.property;
        const isFsCall = t.isIdentifier(obj) && obj.name === 'fs' &&
          t.isIdentifier(prop) && ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream'].includes(prop.name);
        if (isFsCall) {
          const pathArg = node.arguments[0];
          if (pathArg) {
            let hasTraversal = false;
            // Check if path.join is used with user input
            if (t.isCallExpression(pathArg) && t.isMemberExpression(pathArg.callee)) {
              const pathProp = pathArg.callee.property;
              if (t.isIdentifier(pathProp) && ['join', 'resolve'].includes(pathProp.name)) {
                hasTraversal = pathArg.arguments.some(a => isUserInputExpression(a));
              }
            }
            hasTraversal = hasTraversal || isUserInputExpression(pathArg) ||
              (t.isTemplateLiteral(pathArg) && hasUserInputInTemplateLiteral(pathArg));
            if (hasTraversal) {
              matches.push({
                rule: 'path-traversal',
                severity: 'high',
                message: 'Path traversal vulnerability: file system access with user-controlled path',
                cwe: 'CWE-22',
                owasp: 'A01:2021 – Broken Access Control',
                fixSuggestion: 'Validate and sanitize file paths. Use path.resolve() and verify the result starts with an allowed base directory',
                confidence: 'high',
                line: loc.line,
                column: loc.column,
                snippet: getSnippet(lines, loc.line),
              });
            }
          }
        }
      }

      // NoSQL injection - Model.find(req.body)
      if (t.isMemberExpression(node.callee)) {
        const prop = node.callee.property;
        if (t.isIdentifier(prop) && ['find', 'findOne', 'findById', 'where', 'update', 'updateOne', 'deleteOne', 'remove'].includes(prop.name)) {
          const arg = node.arguments[0];
          if (arg && isUserInputExpression(arg)) {
            matches.push({
              rule: 'nosql-injection',
              severity: 'high',
              message: 'NoSQL injection: MongoDB query built directly from user input without sanitization',
              cwe: 'CWE-943',
              owasp: 'A03:2021 – Injection',
              fixSuggestion: 'Sanitize query inputs. Use a schema validation library (e.g., Zod) and only extract expected fields from user input',
              confidence: 'medium',
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(lines, loc.line),
            });
          }
        }
      }

      // IDOR - req.params.id used directly in db query
      if (t.isMemberExpression(node.callee)) {
        const prop = node.callee.property;
        if (t.isIdentifier(prop) && ['findById', 'findOne', 'find'].includes(prop.name)) {
          const arg = node.arguments[0];
          if (arg && t.isMemberExpression(arg)) {
            // Check for req.params.id pattern
            let current: t.Node = arg;
            let depth = 0;
            let foundParams = false;
            while (t.isMemberExpression(current) && depth < 4) {
              if (t.isIdentifier((current as t.MemberExpression).property) &&
                (current as t.MemberExpression).property && 'name' in (current as t.MemberExpression).property &&
                ((current as t.MemberExpression).property as t.Identifier).name === 'params') {
                foundParams = true;
                break;
              }
              current = (current as t.MemberExpression).object;
              depth++;
            }
            if (foundParams) {
              matches.push({
                rule: 'idor',
                severity: 'high',
                message: 'IDOR: Database query using req.params.id without ownership verification',
                cwe: 'CWE-639',
                owasp: 'A01:2021 – Broken Access Control',
                fixSuggestion: 'Verify the authenticated user owns the requested resource before returning data',
                confidence: 'medium',
                line: loc.line,
                column: loc.column,
                snippet: getSnippet(lines, loc.line),
              });
            }
          }
        }
      }

      // Prototype pollution - Object.assign with external input
      if (t.isMemberExpression(node.callee)) {
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (t.isIdentifier(obj) && obj.name === 'Object' &&
          t.isIdentifier(prop) && prop.name === 'assign') {
          const hasExternalInput = node.arguments.some((arg, idx) => idx > 0 && isUserInputExpression(arg));
          if (hasExternalInput) {
            matches.push({
              rule: 'prototype-pollution',
              severity: 'high',
              message: 'Prototype pollution: Object.assign() with external user input may pollute Object prototype',
              cwe: 'CWE-1321',
              owasp: 'A08:2021 – Software and Data Integrity Failures',
              fixSuggestion: 'Use Object.create(null) for safe merge targets, or validate input with a schema before merging',
              confidence: 'medium',
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(lines, loc.line),
            });
          }
        }
      }

      // Missing auth on Express routes
      if (t.isMemberExpression(node.callee)) {
        const obj = node.callee.object;
        const prop = node.callee.property;
        const httpMethods = ['get', 'post', 'put', 'delete', 'patch'];
        if (t.isIdentifier(obj) && ['app', 'router', 'api'].includes(obj.name) &&
          t.isIdentifier(prop) && httpMethods.includes(prop.name)) {
          // Last argument should be a handler, check for auth middleware in middle args
          const args = node.arguments;
          if (args.length >= 2) {
            const middlewares = args.slice(1, -1);
            const hasAuth = middlewares.some(m => {
              if (t.isIdentifier(m)) return authMiddlewareNames.has(m.name);
              if (t.isMemberExpression(m) && t.isIdentifier(m.property)) {
                return authMiddlewareNames.has((m.property as t.Identifier).name);
              }
              return false;
            });

            const routePath = t.isStringLiteral(args[0]) ? args[0].value : '';
            const isSensitiveRoute = /\/(admin|user|account|profile|payment|order|secret|private|api\/v\d)/.test(routePath);

            if (!hasAuth && isSensitiveRoute && !isTestFile) {
              matches.push({
                rule: 'missing-auth-middleware',
                severity: 'high',
                message: `Sensitive route '${routePath}' lacks authentication middleware`,
                cwe: 'CWE-306',
                owasp: 'A07:2021 – Identification and Authentication Failures',
                fixSuggestion: `Add authentication middleware: app.${t.isIdentifier(prop) ? prop.name : 'get'}('${routePath}', authenticate, handler)`,
                confidence: 'medium',
                line: loc.line,
                column: loc.column,
                snippet: getSnippet(lines, loc.line),
              });
            }
          }
        }
      }
    },

    // XSS - dangerouslySetInnerHTML
    JSXAttribute(nodePath) {
      const node = nodePath.node;
      const loc = node.loc?.start;
      if (!loc) return;

      if (t.isJSXIdentifier(node.name) && node.name.name === 'dangerouslySetInnerHTML') {
        const value = node.value;
        let hasDynamicContent = false;

        if (t.isJSXExpressionContainer(value)) {
          const expr = value.expression;
          // Check if the value has __html with a dynamic expression
          if (t.isObjectExpression(expr)) {
            const htmlProp = expr.properties.find(p =>
              t.isObjectProperty(p) &&
              t.isIdentifier((p as t.ObjectProperty).key) &&
              ((p as t.ObjectProperty).key as t.Identifier).name === '__html'
            ) as t.ObjectProperty | undefined;
            if (htmlProp) {
              const htmlValue = htmlProp.value;
              hasDynamicContent = !t.isStringLiteral(htmlValue);
            }
          } else if (!t.isNullLiteral(expr)) {
            hasDynamicContent = true;
          }
        }

        if (hasDynamicContent) {
          matches.push({
            rule: 'xss-dangerous-inner-html',
            severity: 'high',
            message: 'XSS vulnerability: dangerouslySetInnerHTML used without sanitization',
            cwe: 'CWE-79',
            owasp: 'A03:2021 – Injection',
            fixSuggestion: 'Sanitize HTML content using DOMPurify before setting innerHTML: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}',
            confidence: 'high',
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(lines, loc.line),
          });
        }
      }
    },

    // Hardcoded credentials
    AssignmentExpression(nodePath) {
      const node = nodePath.node;
      const loc = node.loc?.start;
      if (!loc) return;

      if (t.isStringLiteral(node.right) && node.right.value.length > 4) {
        const leftStr = (() => {
          if (t.isIdentifier(node.left)) return node.left.name.toLowerCase();
          if (t.isMemberExpression(node.left) && t.isIdentifier(node.left.property)) {
            return (node.left.property as t.Identifier).name.toLowerCase();
          }
          return '';
        })();

        const credPatterns = ['password', 'passwd', 'secret', 'apikey', 'api_key', 'token',
          'accesstoken', 'access_token', 'privatekey', 'private_key', 'authtoken'];
        if (credPatterns.some(p => leftStr.includes(p))) {
          const val = node.right.value;
          // Exclude obvious placeholders
          if (!['', 'xxx', 'placeholder', 'changeme', 'your-secret', 'your_secret', 'example'].some(placeholder => val.toLowerCase().includes(placeholder))) {
            matches.push({
              rule: 'hardcoded-credentials',
              severity: 'high',
              message: `Hardcoded credential detected in variable '${leftStr}'`,
              cwe: 'CWE-798',
              owasp: 'A07:2021 – Identification and Authentication Failures',
              fixSuggestion: 'Move secrets to environment variables: process.env.SECRET_KEY',
              confidence: 'high',
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(lines, loc.line),
            });
          }
        }
      }
    },

    // Hardcoded credentials in variable declarations
    VariableDeclarator(nodePath) {
      const node = nodePath.node;
      const loc = node.loc?.start;
      if (!loc) return;

      if (t.isIdentifier(node.id) && node.init && t.isStringLiteral(node.init)) {
        const name = node.id.name.toLowerCase();
        const credPatterns = ['password', 'passwd', 'secret', 'apikey', 'api_key', 'token',
          'accesstoken', 'access_token', 'privatekey', 'private_key', 'authtoken', 'jwtsecret', 'jwt_secret'];
        if (credPatterns.some(p => name.includes(p))) {
          const val = node.init.value;
          if (val.length > 4 && !['', 'xxx', 'placeholder', 'changeme', 'your-secret', 'example', 'test', 'development'].some(p => val.toLowerCase().includes(p))) {
            matches.push({
              rule: 'hardcoded-credentials',
              severity: 'high',
              message: `Hardcoded credential detected in variable '${node.id.name}'`,
              cwe: 'CWE-798',
              owasp: 'A07:2021 – Identification and Authentication Failures',
              fixSuggestion: 'Move secrets to environment variables and use process.env.SECRET_KEY',
              confidence: 'high',
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(lines, loc.line),
            });
          }
        }
      }
    },
  });

  // Convert matches to SASTFindings
  for (const match of matches) {
    findings.push({
      id: generateId(),
      scanner: 'sast',
      rule: match.rule,
      severity: match.severity,
      file: filePath,
      line: match.line,
      column: match.column,
      message: match.message,
      cwe: match.cwe,
      owasp: match.owasp,
      snippet: match.snippet,
      fixSuggestion: match.fixSuggestion,
      confidence: match.confidence,
    });
  }

  return findings;
}

export async function scanDirectory(dirPath: string, options?: ScanOptions): Promise<SASTFinding[]> {
  const patterns = [
    '**/*.{js,jsx,ts,tsx}',
  ];

  const ignore = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.next/**',
    '**/coverage/**',
    '**/*.min.js',
    '**/vendor/**',
    '**/*.d.ts',
  ];

  const files = await fg(patterns, {
    cwd: dirPath,
    ignore,
    absolute: true,
    followSymbolicLinks: false,
  });

  const allFindings: SASTFinding[] = [];

  await Promise.all(
    files.map(async (file) => {
      try {
        const findings = await scanFile(file);
        allFindings.push(...findings);
      } catch {
        // Skip files that can't be parsed
      }
    })
  );

  return allFindings;
}
