/**
 * SHIELD Test Fixture — Vulnerable Next.js API Routes
 * DO NOT USE IN PRODUCTION — contains intentional vulnerabilities
 */
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import prisma from '@/lib/prisma';

// CWE-798: Hardcoded API key
const openaiApiKey = 'sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012345678';
const stripeSecretKey = 'sk_live_[SHIELD-TEST-FIXTURE-NOT-A-REAL-KEY]';
const anthropicKey = 'sk-ant-api03-xXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx';

// CWE-639: IDOR — accessing user data by URL param without ownership check
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  // BAD: no session check, directly queries by URL param
  const user = await prisma.user.findById(params.id);
  return NextResponse.json(user);
}

// CWE-943: NoSQL injection via direct req.body
export async function POST(request: NextRequest) {
  const body = await request.json();
  // BAD: directly passing req.body to MongoDB/Prisma query
  const users = await prisma.user.find(body);
  return NextResponse.json(users);
}

// CWE-79: XSS via dangerouslySetInnerHTML
function UserBio({ content }: { content: string }) {
  return (
    <div
      className="user-bio"
      // BAD: no sanitization
      dangerouslySetInnerHTML={{ __html: content }}
    />
  );
}

// CWE-79: another XSS pattern
function RenderMarkdown({ html }: { html: string }) {
  return (
    <article dangerouslySetInnerHTML={{ __html: html }} />
  );
}

// Missing rate limiting on authentication endpoint
export async function loginHandler(request: NextRequest) {
  // BAD: no rate limiting, allows brute force
  const { email, password } = await request.json();

  const user = await prisma.user.findFirst({
    where: { email }
  });

  if (!user || user.password !== password) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  return NextResponse.json({ token: generateToken(user) });
}

// CWE-89: SQL injection via prisma.$queryRawUnsafe
export async function searchProducts(searchTerm: string) {
  // BAD: $queryRawUnsafe with template literal
  const products = await prisma.$queryRawUnsafe(
    `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`
  );
  return products;
}

// CWE-89: SQL injection — another raw query pattern
export async function getUserByEmail(email: string) {
  // BAD: concatenation in raw query
  const result = await prisma.$queryRawUnsafe(
    "SELECT * FROM users WHERE email = '" + email + "'"
  );
  return result;
}

// CWE-94: Function constructor with dynamic content
function createValidator(ruleString: string) {
  // BAD: dynamic Function constructor
  const validatorFn = new Function('value', `return ${ruleString}`);
  return validatorFn;
}

function generateToken(user: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(user)).toString('base64');
}
