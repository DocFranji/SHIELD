import React from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Shield, AlertTriangle, ShieldCheck, Zap, FileCode, Package, Key, Server, TrendingDown, ArrowRight } from 'lucide-react'
import SecurityScore from '../components/SecurityScore.tsx'
import FindingsTable from '../components/FindingsTable.tsx'
import DependencyHealth from '../components/DependencyHealth.tsx'
import type { MockFinding } from '../components/FindingsTable.tsx'

const TREND_DATA = [
  { date: 'Mar 1',  critical: 8, high: 14, medium: 22, score: 41 },
  { date: 'Mar 5',  critical: 7, high: 12, medium: 20, score: 48 },
  { date: 'Mar 8',  critical: 6, high: 11, medium: 19, score: 52 },
  { date: 'Mar 11', critical: 5, high: 10, medium: 18, score: 57 },
  { date: 'Mar 14', critical: 5, high: 9,  medium: 16, score: 61 },
  { date: 'Mar 17', critical: 4, high: 8,  medium: 15, score: 67 },
  { date: 'Mar 21', critical: 3, high: 8,  medium: 14, score: 72 },
]

const MOCK_FINDINGS: MockFinding[] = [
  { id: '1',  scanner: 'sast',    rule: 'sql-injection-raw-unsafe',  severity: 'critical', file: 'src/api/users.ts',           line: 42, message: 'SQL injection via Prisma $queryRawUnsafe with dynamic query',          cwe: 'CWE-89',   status: 'open', fixSuggestion: 'Use prisma.$queryRaw with tagged template literals' },
  { id: '2',  scanner: 'secrets', rule: 'database-url',              severity: 'critical', file: '.env.local',                  line: 3,  message: 'Database connection URL with credentials detected',                    cwe: 'CWE-798',  status: 'open', fixSuggestion: 'Move to a secrets manager or ensure .env.local is gitignored' },
  { id: '3',  scanner: 'sast',    rule: 'command-injection',         severity: 'critical', file: 'src/api/deploy.ts',           line: 87, message: 'Command injection via child_process.exec with user-controlled input',  cwe: 'CWE-78',   status: 'open', fixSuggestion: 'Use execFile with array arguments instead of exec with string interpolation' },
  { id: '4',  scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'high',     file: 'package.json',               line: 1,  message: 'lodash@4.17.19 — Prototype Pollution (CVE-2021-23337)',              cwe: 'CWE-1321', status: 'open', fixSuggestion: 'Upgrade lodash to 4.17.21 or later' },
  { id: '5',  scanner: 'sast',    rule: 'xss-dangerous-inner-html',  severity: 'high',     file: 'src/components/UserProfile.tsx', line: 33, message: 'XSS via dangerouslySetInnerHTML without sanitization',           cwe: 'CWE-79',   status: 'open', fixSuggestion: 'Sanitize with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML' },
  { id: '6',  scanner: 'iac',     rule: 'dockerfile-no-user',        severity: 'high',     file: 'Dockerfile',                 line: 1,  message: 'Dockerfile does not specify a non-root USER',                         cwe: 'CWE-250',  status: 'open', fixSuggestion: 'Add: RUN adduser --disabled-password appuser && USER appuser' },
  { id: '7',  scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'high',     file: 'package.json',               line: 1,  message: 'axios@0.21.1 — Server-Side Request Forgery (CVE-2021-3749)',          cwe: 'CWE-918',  status: 'open', fixSuggestion: 'Upgrade axios to 0.27.2 or later' },
  { id: '8',  scanner: 'sast',    rule: 'idor',                      severity: 'high',     file: 'src/api/orders.ts',          line: 24, message: 'IDOR: DB query using req.params.id without ownership verification',    cwe: 'CWE-639',  status: 'open', fixSuggestion: 'Check that the authenticated user owns the requested resource' },
  { id: '9',  scanner: 'sast',    rule: 'hardcoded-credentials',     severity: 'high',     file: 'src/lib/stripe.ts',          line: 7,  message: 'Hardcoded credential detected in variable "stripeSecret"',            cwe: 'CWE-798',  status: 'open', fixSuggestion: 'Move to environment variable: process.env.STRIPE_SECRET_KEY' },
  { id: '10', scanner: 'sast',    rule: 'missing-auth-middleware',   severity: 'high',     file: 'src/api/admin.ts',           line: 15, message: "Sensitive route '/api/admin/users' lacks authentication middleware",  cwe: 'CWE-306',  status: 'open', fixSuggestion: 'Add authenticate middleware to the route handler' },
  { id: '11', scanner: 'sca',     rule: 'vulnerable-dependency',     severity: 'medium',   file: 'package.json',               line: 1,  message: 'express@4.17.1 — Open Redirect (CVE-2022-24999)',                    cwe: 'CWE-601',  status: 'open', fixSuggestion: 'Upgrade express to 4.18.2 or later' },
  { id: '12', scanner: 'iac',     rule: 'dockerfile-latest-tag',     severity: 'medium',   file: 'Dockerfile',                 line: 1,  message: 'Dockerfile uses unstable :latest tag',                                cwe: 'CWE-1104', status: 'open', fixSuggestion: 'Pin to specific version: FROM node:20.11-alpine3.19' },
  { id: '13', scanner: 'secrets', rule: 'jwt-secret',                severity: 'high',     file: 'src/auth/config.ts',         line: 12, message: 'JWT secret hardcoded in source — rotate immediately',                 cwe: 'CWE-798',  status: 'fixed', fixSuggestion: 'Use process.env.JWT_SECRET and ensure it is > 32 chars' },
  { id: '14', scanner: 'sast',    rule: 'prototype-pollution',       severity: 'medium',   file: 'src/utils/merge.ts',         line: 18, message: 'Prototype pollution via Object.assign() with external user input',    cwe: 'CWE-1321', status: 'open', fixSuggestion: 'Use Object.create(null) as merge target' },
  { id: '15', scanner: 'iac',     rule: 'env-not-gitignored',        severity: 'critical', file: '.env',                       line: 1,  message: '.env is not listed in .gitignore — secrets may be committed',         cwe: 'CWE-312',  status: 'ignored', fixSuggestion: 'Add .env to .gitignore and rotate any exposed secrets' },
]

const MOCK_VULNERABLE_DEPS = [
  { name: 'lodash',     version: '4.17.19', severity: 'high'   as const, cve: 'CVE-2021-23337', fixedVersion: '4.17.21' },
  { name: 'axios',      version: '0.21.1',  severity: 'high'   as const, cve: 'CVE-2021-3749',  fixedVersion: '0.27.2' },
  { name: 'express',    version: '4.17.1',  severity: 'medium' as const, cve: 'CVE-2022-24999', fixedVersion: '4.18.2' },
  { name: 'minimist',   version: '1.2.0',   severity: 'medium' as const, cve: 'CVE-2021-44906', fixedVersion: '1.2.6' },
  { name: 'node-fetch', version: '2.6.0',   severity: 'medium' as const, cve: 'CVE-2022-0235',  fixedVersion: '2.6.7' },
]

const labelStyle: React.CSSProperties = {
  fontFamily: 'Chakra Petch, sans-serif',
  fontSize: '9px',
  letterSpacing: '2px',
  textTransform: 'uppercase' as const,
}

const CustomTooltip = ({ active, payload, label }: {
  active?: boolean
  payload?: Array<{ color: string; name: string; value: number }>
  label?: string
}) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#050d20', border: '1px solid #0c2350', padding: '10px 14px', borderRadius: '2px' }}>
      <p style={{ ...labelStyle, color: '#4d6a9a', marginBottom: '6px' }}>{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color, fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px' }}>
          {p.name}: <span style={{ fontWeight: 700 }}>{p.value}</span>
        </p>
      ))}
    </div>
  )
}

function StatCard({ label, value, color, icon, sublabel }: {
  label: string; value: number | string; color: string; icon: React.ReactNode; sublabel?: string
}) {
  return (
    <div
      className="card-hover flex items-center gap-3 p-4 border relative overflow-hidden"
      style={{ background: '#050d20', borderColor: '#0c2350' }}
    >
      <div className="absolute top-0 left-0 w-0 h-0 border-solid"
        style={{ borderWidth: '20px 20px 0 0', borderColor: `${color} transparent transparent transparent`, opacity: 0.6 }} />
      <div className="p-2 border shrink-0" style={{ background: `${color}15`, borderColor: `${color}30` }}>
        <div style={{ color }}>{icon}</div>
      </div>
      <div>
        <div style={{ color, fontFamily: 'Goldman, sans-serif', fontSize: '24px', lineHeight: 1 }}>{value}</div>
        <div style={{ ...labelStyle, color: '#1a2d4a', marginTop: '2px' }}>{label}</div>
        {sublabel && <div style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '11px', color: '#4d6a9a', marginTop: '2px' }}>{sublabel}</div>}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const openFindings   = MOCK_FINDINGS.filter(f => f.status === 'open')
  const criticalCount  = openFindings.filter(f => f.severity === 'critical').length
  const highCount      = openFindings.filter(f => f.severity === 'high').length
  const mediumCount    = openFindings.filter(f => f.severity === 'medium').length
  const autoIgnoredCount = 12

  const sectionTag = (text: string) => (
    <p style={{ ...labelStyle, color: '#00ccff', marginBottom: '4px' }}>// {text}</p>
  )

  return (
    <div className="flex flex-col gap-6">

      {/* Welcome banner */}
      <div
        className="relative overflow-hidden p-6 border"
        style={{ background: 'linear-gradient(145deg, #050d20, #071428)', borderColor: '#0c2350' }}
      >
        <div className="scan-line" />
        <div className="absolute right-6 top-4 opacity-10">
          <img src="/shield-logo.png" alt="SHIELD" style={{ width: 90, height: 90, objectFit: 'contain' }} />
        </div>
        <div className="relative z-10">
          {sectionTag('Project Security Overview')}
          <h2 style={{ fontFamily: 'Goldman, sans-serif', fontSize: '22px', letterSpacing: '4px', color: '#fff', marginBottom: '8px' }}>
            PROJECT SECURITY OVERVIEW
          </h2>
          <p style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '13px', color: '#4d6a9a' }}>
            Scanned{' '}
            <span style={{ color: '#c0d4f0', fontFamily: 'Chakra Petch, sans-serif' }}>128 files</span>
            {' · '}
            <span style={{ color: '#c0d4f0', fontFamily: 'Chakra Petch, sans-serif' }}>47 dependencies</span>
            {' · '}
            <span style={{ color: '#00ff88', fontFamily: 'Chakra Petch, sans-serif' }}>{autoIgnoredCount} findings auto-suppressed</span>
          </p>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <div
          className="card-hover flex items-center gap-3 p-4 border relative overflow-hidden lg:col-span-1"
          style={{ background: '#050d20', borderColor: '#0c2350' }}
        >
          <div className="absolute top-0 left-0 w-0 h-0 border-solid"
            style={{ borderWidth: '20px 20px 0 0', borderColor: '#1562f0 transparent transparent transparent', opacity: 0.7 }} />
          <div className="p-2 border" style={{ background: 'rgba(21,98,240,0.12)', borderColor: 'rgba(21,98,240,0.25)' }}>
            <Shield size={17} style={{ color: '#1562f0' }} />
          </div>
          <div>
            <div style={{ fontFamily: 'Goldman, sans-serif', fontSize: '24px', color: '#c0d4f0', lineHeight: 1 }}>
              {openFindings.length}
            </div>
            <div style={{ ...labelStyle, color: '#1a2d4a', marginTop: '2px' }}>Total Open</div>
          </div>
        </div>
        <StatCard label="Critical" value={criticalCount}    color="#ff3344" icon={<AlertTriangle size={17} />} />
        <StatCard label="High"     value={highCount}        color="#ff8844" icon={<AlertTriangle size={17} />} />
        <StatCard label="Medium"   value={mediumCount}      color="#ffcc00" icon={<AlertTriangle size={17} />} />
        <div
          className="card-hover flex items-center gap-3 p-4 border relative overflow-hidden lg:col-span-1"
          style={{ background: '#050d20', borderColor: '#0c2350' }}
        >
          <div className="absolute top-0 left-0 w-0 h-0 border-solid"
            style={{ borderWidth: '20px 20px 0 0', borderColor: '#00ff88 transparent transparent transparent', opacity: 0.4 }} />
          <div className="p-2 border" style={{ background: 'rgba(0,255,136,0.08)', borderColor: 'rgba(0,255,136,0.2)' }}>
            <TrendingDown size={17} style={{ color: '#00ff88' }} />
          </div>
          <div>
            <div style={{ fontFamily: 'Goldman, sans-serif', fontSize: '24px', color: '#00ff88', lineHeight: 1 }}>
              {autoIgnoredCount}
            </div>
            <div style={{ ...labelStyle, color: '#1a2d4a', marginTop: '2px' }}>Auto-Ignored</div>
            <div style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', color: '#00ff88', letterSpacing: '1px' }}>
              44% noise cut
            </div>
          </div>
        </div>
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left: score + scanner breakdown + dep health */}
        <div className="flex flex-col gap-4">

          {/* Security score */}
          <div
            className="border flex flex-col items-center p-6 relative overflow-hidden"
            style={{ background: '#050d20', borderColor: '#0c2350' }}
          >
            <div className="step-bar" />
            <SecurityScore score={72} size={180} animated />
            <div className="mt-4 grid grid-cols-2 gap-2 w-full">
              {[
                { label: 'SAST',    count: 7,  icon: FileCode, color: '#b388ff' },
                { label: 'SCA',     count: 5,  icon: Package,  color: '#4d8fff' },
                { label: 'Secrets', count: 2,  icon: Key,      color: '#ff3344' },
                { label: 'IaC',     count: 3,  icon: Server,   color: '#ff8844' },
              ].map(({ label, count, icon: Icon, color }) => (
                <div
                  key={label}
                  className="flex items-center gap-2 p-2 border"
                  style={{ background: '#010812', borderColor: '#0c2350' }}
                >
                  <Icon size={11} style={{ color }} />
                  <span style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1px', color: '#4d6a9a', flex: 1 }}>
                    {label}
                  </span>
                  <span style={{ fontFamily: 'Goldman, sans-serif', fontSize: '14px', color }}>
                    {count}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Dependency health */}
          <div className="border p-5" style={{ background: '#050d20', borderColor: '#0c2350' }}>
            <h3 className="flex items-center gap-2 mb-4" style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '2.5px', color: '#c0d4f0', textTransform: 'uppercase' }}>
              <Package size={13} style={{ color: '#1562f0' }} />
              Dependency Health
            </h3>
            <DependencyHealth totalDeps={47} vulnerableDeps={MOCK_VULNERABLE_DEPS} />
          </div>
        </div>

        {/* Center + right: trend + findings + actions */}
        <div className="lg:col-span-2 flex flex-col gap-4">

          {/* Trend chart */}
          <div className="border p-5" style={{ background: '#050d20', borderColor: '#0c2350' }}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <p style={{ ...labelStyle, color: '#00ccff' }}>// Security Trend</p>
                <h3 style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '2px', color: '#c0d4f0', textTransform: 'uppercase' }}>
                  Last 3 Weeks
                </h3>
              </div>
              <span className="flex items-center gap-1" style={{ color: '#00ff88', fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1px' }}>
                <TrendingDown size={10} />
                Improving
              </span>
            </div>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={TREND_DATA}>
                  <defs>
                    <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ff3344" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ff3344" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ff8844" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ff8844" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="medGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ffcc00" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#ffcc00" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#0c2350" opacity={0.6} />
                  <XAxis dataKey="date" stroke="#1a2d4a" tick={{ fontSize: 10, fontFamily: 'Chakra Petch, sans-serif', fill: '#1a2d4a', letterSpacing: 1 }} />
                  <YAxis stroke="#1a2d4a" tick={{ fontSize: 10, fontFamily: 'Chakra Petch, sans-serif', fill: '#1a2d4a' }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="critical" stroke="#ff3344" strokeWidth={2} fill="url(#critGrad)" name="Critical" />
                  <Area type="monotone" dataKey="high"     stroke="#ff8844" strokeWidth={2} fill="url(#highGrad)" name="High" />
                  <Area type="monotone" dataKey="medium"   stroke="#ffcc00" strokeWidth={1.5} fill="url(#medGrad)"  name="Medium" strokeDasharray="4 2" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top priority findings */}
          <div className="border p-5" style={{ background: '#050d20', borderColor: '#0c2350' }}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <p style={{ ...labelStyle, color: '#00ccff' }}>// Findings</p>
                <h3 style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '2px', color: '#c0d4f0', textTransform: 'uppercase' }}>
                  Top Priority
                </h3>
              </div>
              <a
                href="/findings"
                className="flex items-center gap-1 transition-colors"
                style={{ color: '#1562f0', fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1.5px' }}
              >
                View all <ArrowRight size={10} />
              </a>
            </div>
            <FindingsTable
              findings={MOCK_FINDINGS.filter(f => f.status === 'open').slice(0, 6)}
              compact
              showFilters={false}
            />
          </div>

          {/* Quick actions */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { icon: Zap,        label: 'Quick Scan',  sublabel: 'Secrets + SCA', color: '#1562f0' },
              { icon: FileCode,   label: 'Full SAST',   sublabel: 'AST analysis',  color: '#b388ff' },
              { icon: ShieldCheck,label: 'Fix Report',  sublabel: 'AI-guided',     color: '#00ff88' },
            ].map(({ icon: Icon, label, sublabel, color }) => (
              <button
                key={label}
                className="p-4 border card-hover text-left relative overflow-hidden"
                style={{ background: '#050d20', borderColor: '#0c2350' }}
              >
                <div className="absolute top-0 left-0 w-0 h-0 border-solid"
                  style={{ borderWidth: '16px 16px 0 0', borderColor: `${color} transparent transparent transparent`, opacity: 0.5 }} />
                <div className="p-2 border w-fit mb-2" style={{ background: `${color}12`, borderColor: `${color}25` }}>
                  <Icon size={15} style={{ color }} />
                </div>
                <div style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1.5px', color: '#c0d4f0', textTransform: 'uppercase' }}>
                  {label}
                </div>
                <div style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '11px', color: '#1a2d4a', marginTop: '2px' }}>
                  {sublabel}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
