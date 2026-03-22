export type Framework = 'nextjs' | 'express' | 'flask' | 'fastapi' | 'generic';

export interface GuardrailSection {
  title: string;
  rules: Array<{
    do?: string;
    dont?: string;
    example?: string;
  }>;
}

export interface Guardrails {
  framework: Framework;
  title: string;
  sections: GuardrailSection[];
}

const NEXTJS_GUARDRAILS: Guardrails = {
  framework: 'nextjs',
  title: 'Next.js Security Guardrails',
  sections: [
    {
      title: 'API Routes & Server Actions',
      rules: [
        {
          do: 'Always validate and authenticate in every API route handler',
          example: `import { getServerSession } from 'next-auth';
export async function GET(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response('Unauthorized', { status: 401 });
  // ... handler logic
}`,
        },
        {
          dont: 'Never expose internal IDs directly — use ownership checks',
          example: `// BAD: Direct ID lookup without auth check
const data = await db.user.findById(params.id);

// GOOD: Verify ownership
const data = await db.user.findFirst({
  where: { id: params.id, ownerId: session.user.id }
});`,
        },
        {
          do: 'Use Zod for input validation in API routes',
          example: `import { z } from 'zod';
const schema = z.object({ name: z.string().min(1).max(100) });
const body = schema.parse(await request.json());`,
        },
        {
          dont: 'Never use req.body directly without validation',
        },
        {
          dont: 'Never prefix sensitive values with NEXT_PUBLIC_',
          example: `// BAD: Exposes secret to client bundle
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...

// GOOD: Keep secrets server-side only
STRIPE_SECRET_KEY=sk_live_...`,
        },
      ],
    },
    {
      title: 'Server Components & Data Fetching',
      rules: [
        {
          do: 'Use server components for sensitive data fetching',
          example: `// Server Component — runs on server only
async function UserProfile({ userId }: { userId: string }) {
  const user = await db.user.findById(userId); // Safe: not exposed to client
  return <div>{user.name}</div>;
}`,
        },
        {
          dont: 'Never pass sensitive data as props to client components',
        },
        {
          do: 'Use next/headers cookies() for server-side auth state',
        },
      ],
    },
    {
      title: 'Content Security',
      rules: [
        {
          dont: 'Never use dangerouslySetInnerHTML without DOMPurify sanitization',
          example: `// BAD
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// GOOD
import DOMPurify from 'isomorphic-dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />`,
        },
        {
          do: 'Configure Content Security Policy headers in next.config.js',
          example: `// next.config.js
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
];`,
        },
      ],
    },
    {
      title: 'Environment & Secrets',
      rules: [
        {
          do: 'Store all secrets in .env.local (never commit to git)',
        },
        {
          dont: 'Never hardcode API keys, passwords, or tokens in source code',
        },
        {
          do: 'Use a secrets manager (Vercel env vars, AWS Secrets Manager) in production',
        },
        {
          dont: 'Never log sensitive user data or tokens',
        },
      ],
    },
  ],
};

const EXPRESS_GUARDRAILS: Guardrails = {
  framework: 'express',
  title: 'Express.js Security Guardrails',
  sections: [
    {
      title: 'Input Validation & Sanitization',
      rules: [
        {
          do: 'Use express-validator or Zod for all route input validation',
          example: `import { body, validationResult } from 'express-validator';
app.post('/users', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
});`,
        },
        {
          dont: 'Never use req.body/params/query directly in database queries',
        },
        {
          do: 'Use parameterized queries for all database operations',
          example: `// BAD
db.query(\`SELECT * FROM users WHERE id = '\${req.params.id}'\`);

// GOOD
db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);`,
        },
      ],
    },
    {
      title: 'Authentication & Authorization',
      rules: [
        {
          do: 'Apply authentication middleware to all non-public routes',
          example: `const auth = require('./middleware/auth');
app.use('/api/admin', auth, adminRouter);
app.use('/api/user', auth, userRouter);`,
        },
        {
          dont: 'Never store sessions or JWTs in URL parameters',
        },
        {
          do: 'Use bcrypt with cost factor >= 12 for password hashing',
        },
        {
          dont: 'Never use MD5 or SHA1 for password storage',
        },
      ],
    },
    {
      title: 'Security Headers & Middleware',
      rules: [
        {
          do: 'Use Helmet.js for security headers',
          example: `import helmet from 'helmet';
app.use(helmet());
app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } }));`,
        },
        {
          do: 'Use express-rate-limit on authentication endpoints',
          example: `import rateLimit from 'express-rate-limit';
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.post('/auth/login', authLimiter, loginHandler);`,
        },
        {
          dont: 'Never disable CSRF protection for state-changing operations',
        },
      ],
    },
    {
      title: 'Error Handling',
      rules: [
        {
          dont: 'Never expose stack traces or internal errors to clients',
          example: `// BAD
app.use((err, req, res, next) => res.status(500).json({ error: err.stack }));

// GOOD
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal server error' });
});`,
        },
      ],
    },
  ],
};

const FLASK_GUARDRAILS: Guardrails = {
  framework: 'flask',
  title: 'Flask/FastAPI Security Guardrails',
  sections: [
    {
      title: 'Input Validation',
      rules: [
        {
          do: 'Use Pydantic models for request validation in FastAPI',
          example: `from pydantic import BaseModel, validator
class UserCreate(BaseModel):
    email: str
    password: str
    @validator('password')
    def password_length(cls, v):
        if len(v) < 8: raise ValueError('Password too short')
        return v`,
        },
        {
          dont: 'Never use string formatting for SQL queries',
          example: `# BAD
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# GOOD
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
        },
      ],
    },
    {
      title: 'Authentication',
      rules: [
        {
          do: 'Use Flask-Login or FastAPI dependencies for auth',
        },
        {
          dont: 'Never store passwords in plaintext — use bcrypt or argon2',
        },
        {
          do: 'Set secure, httponly, samesite flags on session cookies',
        },
      ],
    },
  ],
};

const GENERIC_GUARDRAILS: Guardrails = {
  framework: 'generic',
  title: 'Universal Security Guardrails',
  sections: [
    {
      title: 'Injection Prevention',
      rules: [
        { dont: 'Never interpolate user input directly into SQL, shell commands, or LDAP queries' },
        { do: 'Always use parameterized queries or ORMs for database access' },
        { dont: 'Never use eval() or Function() constructor with user input' },
      ],
    },
    {
      title: 'Authentication & Session Management',
      rules: [
        { do: 'Use battle-tested auth libraries rather than rolling your own' },
        { dont: 'Never store sensitive data in localStorage — use httpOnly cookies' },
        { do: 'Implement proper session expiration and rotation' },
        { do: 'Enforce MFA for privileged accounts' },
      ],
    },
    {
      title: 'Secrets Management',
      rules: [
        { dont: 'Never commit secrets to version control' },
        { do: 'Use environment variables or secrets managers (Vault, AWS Secrets Manager)' },
        { do: 'Rotate secrets regularly and after any potential exposure' },
        { dont: 'Never log secrets, tokens, or passwords' },
      ],
    },
    {
      title: 'Dependency Management',
      rules: [
        { do: 'Run `shield scan --quick` on every pull request' },
        { do: 'Keep dependencies updated — aim for <= 30 days behind latest stable' },
        { dont: 'Never use packages that have been abandoned for > 2 years without vetting' },
      ],
    },
    {
      title: 'Error Handling & Logging',
      rules: [
        { dont: 'Never expose stack traces or internal errors to end users' },
        { do: 'Log security events (auth failures, permission denials) with correlation IDs' },
        { dont: 'Never log sensitive data (passwords, PII, credit cards)' },
      ],
    },
  ],
};

export function getGuardrails(framework: Framework): Guardrails {
  switch (framework) {
    case 'nextjs': return NEXTJS_GUARDRAILS;
    case 'express': return EXPRESS_GUARDRAILS;
    case 'flask':
    case 'fastapi': return FLASK_GUARDRAILS;
    default: return GENERIC_GUARDRAILS;
  }
}

export function renderGuardrailsMarkdown(guardrails: Guardrails): string {
  const lines: string[] = [];
  lines.push(`# ${guardrails.title}`);
  lines.push('');
  lines.push('> Generated by SHIELD Security Platform');
  lines.push('');

  for (const section of guardrails.sections) {
    lines.push(`## ${section.title}`);
    lines.push('');

    for (const rule of section.rules) {
      if (rule.do) {
        lines.push(`### ✅ DO: ${rule.do}`);
      } else if (rule.dont) {
        lines.push(`### ❌ DON'T: ${rule.dont}`);
      }

      if (rule.example) {
        lines.push('');
        lines.push('```typescript');
        lines.push(rule.example);
        lines.push('```');
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

export function detectFrameworkFromContext(files: string[]): Framework {
  for (const file of files) {
    if (file.includes('next.config') || file.includes('pages/') || file.includes('app/')) {
      return 'nextjs';
    }
    if (file.includes('express')) return 'express';
    if (file.includes('flask') || file.includes('app.py')) return 'flask';
    if (file.includes('fastapi') || file.includes('main.py')) return 'fastapi';
  }
  return 'generic';
}
