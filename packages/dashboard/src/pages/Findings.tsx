import React, { useState } from 'react'
import { AlertTriangle, Download, Filter } from 'lucide-react'
import FindingsTable from '../components/FindingsTable.tsx'
import type { MockFinding } from '../components/FindingsTable.tsx'

const ALL_FINDINGS: MockFinding[] = [
  { id: '1',  scanner: 'sast',    rule: 'sql-injection-raw-unsafe',  severity: 'critical', file: 'src/api/users.ts',              line: 42, message: 'SQL injection via Prisma $queryRawUnsafe with dynamic query',            cwe: 'CWE-89',   status: 'open',    fixSuggestion: 'Use prisma.$queryRaw with tagged template literals for parameterized queries' },
  { id: '2',  scanner: 'secrets', rule: 'database-url',              severity: 'critical', file: '.env.local',                    line: 3,  message: 'Database connection URL with embedded credentials detected',              cwe: 'CWE-798',  status: 'open',    fixSuggestion: 'Move to a secrets manager or ensure .env.local is in .gitignore' },
  { id: '3',  scanner: 'sast',    rule: 'command-injection',         severity: 'critical', file: 'src/api/deploy.ts',             line: 87, message: 'Command injection via child_process.exec() with user-controlled input',  cwe: 'CWE-78',   status: 'open',    fixSuggestion: 'Use execFile() with array arguments instead of exec() with string interpolation' },
  { id: '4',  scanner: 'iac',     rule: 'env-not-gitignored',        severity: 'critical', file: '.env',                          line: 1,  message: '.env is not listed in .gitignore — secrets may be committed to git',      cwe: 'CWE-312',  status: 'ignored', fixSuggestion: 'Add .env to .gitignore immediately and rotate any potentially exposed credentials' },
  { id: '5',  scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'high',     file: 'package.json',                  line: 1,  message: 'lodash@4.17.19 — Prototype Pollution via merge (CVE-2021-23337)',         cwe: 'CWE-1321', status: 'open',    fixSuggestion: 'Upgrade lodash to 4.17.21 or later' },
  { id: '6',  scanner: 'sast',    rule: 'xss-dangerous-inner-html',  severity: 'high',     file: 'src/components/UserProfile.tsx', line: 33, message: 'XSS via dangerouslySetInnerHTML without DOMPurify sanitization',        cwe: 'CWE-79',   status: 'open',    fixSuggestion: 'Wrap content with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML' },
  { id: '7',  scanner: 'iac',     rule: 'dockerfile-no-user',        severity: 'high',     file: 'Dockerfile',                    line: 1,  message: 'Dockerfile has no USER directive — container runs as root by default',    cwe: 'CWE-250',  status: 'open',    fixSuggestion: 'Add: RUN adduser --disabled-password appuser && USER appuser before CMD' },
  { id: '8',  scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'high',     file: 'package.json',                  line: 1,  message: 'axios@0.21.1 — Server-Side Request Forgery via redirect (CVE-2021-3749)', cwe: 'CWE-918', status: 'open',    fixSuggestion: 'Upgrade axios to 0.27.2 or later' },
  { id: '9',  scanner: 'sast',    rule: 'idor',                      severity: 'high',     file: 'src/api/orders.ts',             line: 24, message: 'IDOR: DB query uses req.params.id without user ownership check',         cwe: 'CWE-639',  status: 'open',    fixSuggestion: 'Add ownership verification: include { userId: session.user.id } in the query filter' },
  { id: '10', scanner: 'sast',    rule: 'hardcoded-credentials',     severity: 'high',     file: 'src/lib/stripe.ts',             line: 7,  message: 'Hardcoded credential detected in variable "stripeSecret"',              cwe: 'CWE-798',  status: 'open',    fixSuggestion: 'Replace with: process.env.STRIPE_SECRET_KEY' },
  { id: '11', scanner: 'sast',    rule: 'missing-auth-middleware',   severity: 'high',     file: 'src/api/admin.ts',              line: 15, message: "Admin route '/api/admin/users' has no authentication middleware",        cwe: 'CWE-306',  status: 'open',    fixSuggestion: 'Add authenticate middleware as second argument to the route' },
  { id: '12', scanner: 'secrets', rule: 'jwt-secret',                severity: 'high',     file: 'src/auth/config.ts',            line: 12, message: 'JWT signing secret hardcoded in source file',                           cwe: 'CWE-798',  status: 'fixed',   fixSuggestion: 'Use process.env.JWT_SECRET with minimum 32 characters' },
  { id: '13', scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'medium',   file: 'package.json',                  line: 1,  message: 'express@4.17.1 — Open Redirect (CVE-2022-24999, CVSS 6.1)',             cwe: 'CWE-601',  status: 'open',    fixSuggestion: 'Upgrade express to 4.18.2 or later' },
  { id: '14', scanner: 'iac',     rule: 'dockerfile-latest-tag',     severity: 'medium',   file: 'Dockerfile',                    line: 1,  message: 'Docker image uses :latest tag — builds are not reproducible',            cwe: 'CWE-1104', status: 'open',    fixSuggestion: 'Pin to specific version: FROM node:20.11-alpine3.19' },
  { id: '15', scanner: 'sast',    rule: 'prototype-pollution',       severity: 'medium',   file: 'src/utils/merge.ts',            line: 18, message: 'Potential prototype pollution via Object.assign() with external input',  cwe: 'CWE-1321', status: 'open',    fixSuggestion: 'Use Object.create(null) as merge target or validate input with Zod schema first' },
  { id: '16', scanner: 'sast',    rule: 'nosql-injection',           severity: 'medium',   file: 'src/api/search.ts',             line: 31, message: 'NoSQL injection: MongoDB query built from unvalidated req.body',        cwe: 'CWE-943',  status: 'open',    fixSuggestion: 'Extract only expected fields from req.body using Zod or a whitelist before querying' },
  { id: '17', scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'medium',   file: 'package.json',                  line: 1,  message: 'minimist@1.2.0 — Prototype Pollution (CVE-2021-44906, CVSS 5.6)',       cwe: 'CWE-1321', status: 'open',    fixSuggestion: 'Upgrade minimist to 1.2.6 or later' },
  { id: '18', scanner: 'iac',     rule: 'compose-port-exposure',     severity: 'medium',   file: 'docker-compose.yml',            line: 22, message: 'Service "db" exposes port 5432 on all interfaces (0.0.0.0)',            cwe: 'CWE-16',   status: 'open',    fixSuggestion: 'Bind to loopback: "127.0.0.1:5432:5432" to restrict network exposure' },
  { id: '19', scanner: 'sast',    rule: 'path-traversal',            severity: 'high',     file: 'src/api/files.ts',             line: 56, message: 'Path traversal: fs.readFile() with user-controlled path via req.params',  cwe: 'CWE-22',   status: 'open',    fixSuggestion: 'Resolve path and verify it starts with the allowed base directory using path.resolve()' },
  { id: '20', scanner: 'sast',    rule: 'unsafe-eval',               severity: 'high',     file: 'src/plugins/template.ts',       line: 44, message: 'eval() called with dynamic content — allows arbitrary code execution',   cwe: 'CWE-94',   status: 'open',    fixSuggestion: 'Eliminate eval() entirely. Use JSON.parse() for data or explicit function maps' },
]

const labelStyle: React.CSSProperties = {
  fontFamily: 'Chakra Petch, sans-serif',
  fontSize: '9px',
  letterSpacing: '2px',
  textTransform: 'uppercase' as const,
}

export default function Findings() {
  const [activeTab, setActiveTab] = useState<'all' | 'open' | 'ignored' | 'fixed'>('open')

  const tabFindings = {
    all:     ALL_FINDINGS,
    open:    ALL_FINDINGS.filter(f => f.status === 'open'),
    ignored: ALL_FINDINGS.filter(f => f.status === 'ignored'),
    fixed:   ALL_FINDINGS.filter(f => f.status === 'fixed'),
  }

  const displayed     = tabFindings[activeTab]
  const criticalCount = ALL_FINDINGS.filter(f => f.severity === 'critical' && f.status === 'open').length
  const highCount     = ALL_FINDINGS.filter(f => f.severity === 'high'     && f.status === 'open').length
  const mediumCount   = ALL_FINDINGS.filter(f => f.severity === 'medium'   && f.status === 'open').length

  const SUMMARY = [
    { label: 'Critical',   count: criticalCount,         color: '#ff3344', bg: 'rgba(255,51,68,0.08)',    border: 'rgba(255,51,68,0.3)' },
    { label: 'High',       count: highCount,             color: '#ff8844', bg: 'rgba(255,136,68,0.08)',   border: 'rgba(255,136,68,0.3)' },
    { label: 'Medium',     count: mediumCount,           color: '#ffcc00', bg: 'rgba(255,204,0,0.08)',    border: 'rgba(255,204,0,0.3)' },
    { label: 'Total Open', count: tabFindings.open.length, color: '#4d6a9a', bg: '#071428',               border: '#0c2350' },
  ]

  return (
    <div className="flex flex-col gap-6">
      {/* Summary bar */}
      <div className="grid grid-cols-4 gap-3">
        {SUMMARY.map(({ label, count, color, bg, border }) => (
          <div
            key={label}
            className="flex items-center gap-3 p-4 border relative overflow-hidden"
            style={{ background: bg, borderColor: border }}
          >
            <div className="absolute top-0 left-0 w-0 h-0 border-solid"
              style={{ borderWidth: '16px 16px 0 0', borderColor: `${color} transparent transparent transparent`, opacity: 0.5 }} />
            <AlertTriangle size={15} style={{ color }} />
            <div>
              <div style={{ fontFamily: 'Goldman, sans-serif', fontSize: '22px', color, lineHeight: 1 }}>{count}</div>
              <div style={{ ...labelStyle, color: '#1a2d4a', marginTop: '2px' }}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Findings panel */}
      <div className="border overflow-hidden" style={{ background: '#050d20', borderColor: '#0c2350' }}>
        {/* Tabs + export */}
        <div className="flex items-center justify-between px-5 pt-4 pb-0 border-b" style={{ borderColor: '#0c2350' }}>
          <div className="flex gap-0">
            {(['open', 'all', 'fixed', 'ignored'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className="px-4 py-2.5 transition-colors border-b-2 capitalize"
                style={{
                  fontFamily: 'Chakra Petch, sans-serif',
                  fontSize: '10px',
                  letterSpacing: '1.5px',
                  textTransform: 'uppercase',
                  color: activeTab === tab ? '#1562f0' : '#4d6a9a',
                  borderBottomColor: activeTab === tab ? '#1562f0' : 'transparent',
                }}
              >
                {tab}
                <span style={{ marginLeft: '6px', color: '#1a2d4a', fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px' }}>
                  ({tabFindings[tab].length})
                </span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 pb-2">
            <button
              className="flex items-center gap-1.5 px-3 py-1.5 border transition-colors"
              style={{
                borderColor: '#0c2350',
                fontFamily: 'Chakra Petch, sans-serif',
                fontSize: '9px',
                letterSpacing: '1.5px',
                color: '#4d6a9a',
                background: 'transparent',
              }}
            >
              <Download size={11} />
              Export CSV
            </button>
          </div>
        </div>

        <div className="p-5">
          <FindingsTable findings={displayed} showFilters />
        </div>
      </div>

      {/* Noise reduction notice */}
      <div
        className="border p-4 flex items-start gap-3"
        style={{ background: '#050d20', borderColor: '#0c2350' }}
      >
        <div
          className="p-2 border shrink-0"
          style={{ background: 'rgba(0,255,136,0.08)', borderColor: 'rgba(0,255,136,0.2)' }}
        >
          <Filter size={13} style={{ color: '#00ff88' }} />
        </div>
        <div>
          <p style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '1.5px', color: '#c0d4f0', textTransform: 'uppercase', marginBottom: '4px' }}>
            Intelligent Noise Reduction Active
          </p>
          <p style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '12px', color: '#4d6a9a', lineHeight: 1.7 }}>
            SHIELD automatically suppressed{' '}
            <span style={{ color: '#c0d4f0', fontFamily: 'Chakra Petch, sans-serif' }}>12 findings</span>
            {' '}(44% reduction): 8 dev dependency CVEs with CVSS &lt; 4.0, 3 secrets in test fixtures, 1 low severity in CI-only dep.
          </p>
        </div>
      </div>
    </div>
  )
}
