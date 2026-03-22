import React, { useState } from 'react'
import { Search, ChevronDown } from 'lucide-react'
import clsx from 'clsx'

export interface MockFinding {
  id: string
  scanner: string
  rule: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  file: string
  line: number
  message: string
  cwe?: string
  status: 'open' | 'ignored' | 'fixed'
  fixSuggestion?: string
}

const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const SEVERITY_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  critical: { bg: 'rgba(255,51,68,0.1)',   color: '#ff3344', border: 'rgba(255,51,68,0.35)' },
  high:     { bg: 'rgba(255,136,68,0.1)',  color: '#ff8844', border: 'rgba(255,136,68,0.35)' },
  medium:   { bg: 'rgba(255,204,0,0.1)',   color: '#ffcc00', border: 'rgba(255,204,0,0.35)' },
  low:      { bg: 'rgba(0,204,255,0.1)',   color: '#00ccff', border: 'rgba(0,204,255,0.35)' },
  info:     { bg: 'rgba(77,106,154,0.15)', color: '#4d6a9a', border: 'rgba(77,106,154,0.3)' },
}

const SCANNER_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  sast:    { bg: 'rgba(138,75,255,0.12)', color: '#b388ff', border: 'rgba(138,75,255,0.25)' },
  sca:     { bg: 'rgba(21,98,240,0.12)',  color: '#4d8fff', border: 'rgba(21,98,240,0.25)' },
  secrets: { bg: 'rgba(255,51,68,0.12)',  color: '#ff6677', border: 'rgba(255,51,68,0.25)' },
  iac:     { bg: 'rgba(255,136,68,0.12)', color: '#ffaa66', border: 'rgba(255,136,68,0.25)' },
}

const STATUS_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  open:    { bg: 'rgba(255,51,68,0.1)',   color: '#ff6677', border: 'rgba(255,51,68,0.3)' },
  ignored: { bg: 'rgba(30,45,107,0.3)',   color: '#4d6a9a', border: 'rgba(30,45,107,0.4)' },
  fixed:   { bg: 'rgba(0,255,136,0.08)',  color: '#00ff88', border: 'rgba(0,255,136,0.25)' },
}

function Badge({ label, colors }: { label: string; colors: { bg: string; color: string; border: string } }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 uppercase"
      style={{
        background: colors.bg,
        color: colors.color,
        border: `1px solid ${colors.border}`,
        fontFamily: 'Chakra Petch, sans-serif',
        fontSize: '9px',
        letterSpacing: '1.5px',
        borderRadius: '2px',
      }}
    >
      {label}
    </span>
  )
}

interface FindingsTableProps {
  findings: MockFinding[]
  compact?: boolean
  showFilters?: boolean
}

export default function FindingsTable({ findings, compact = false, showFilters = true }: FindingsTableProps) {
  const [search, setSearch]               = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [scannerFilter, setScannerFilter]   = useState<string>('all')
  const [expandedId, setExpandedId]         = useState<string | null>(null)

  const filtered = findings
    .filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false
      if (scannerFilter  !== 'all' && f.scanner  !== scannerFilter)  return false
      if (search) {
        const q = search.toLowerCase()
        return f.message.toLowerCase().includes(q) ||
          f.rule.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q)
      }
      return true
    })
    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])

  const inputStyle: React.CSSProperties = {
    background: '#010812',
    border: '1px solid #0c2350',
    color: '#c0d4f0',
    fontFamily: 'Chakra Petch, sans-serif',
    fontSize: '11px',
    letterSpacing: '1px',
    padding: '7px 12px',
    outline: 'none',
    borderRadius: '2px',
    width: '100%',
  }

  return (
    <div className="flex flex-col gap-3">
      {showFilters && (
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative flex-1 min-w-48">
            <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-shield-text-dim" />
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ ...inputStyle, paddingLeft: '32px' }}
            />
          </div>

          {/* Severity filter */}
          <div className="relative">
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              style={{ ...inputStyle, width: 'auto', paddingRight: '28px', cursor: 'pointer', appearance: 'none' }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <ChevronDown size={11} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-shield-text-dim pointer-events-none" />
          </div>

          {/* Scanner filter */}
          <div className="relative">
            <select
              value={scannerFilter}
              onChange={e => setScannerFilter(e.target.value)}
              style={{ ...inputStyle, width: 'auto', paddingRight: '28px', cursor: 'pointer', appearance: 'none' }}
            >
              <option value="all">All Scanners</option>
              <option value="sast">SAST</option>
              <option value="sca">SCA</option>
              <option value="secrets">Secrets</option>
              <option value="iac">IaC</option>
            </select>
            <ChevronDown size={11} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-shield-text-dim pointer-events-none" />
          </div>

          <span
            className="text-shield-text-dim ml-auto"
            style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1px' }}
          >
            {filtered.length} finding{filtered.length !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      {/* Table */}
      <div
        className="overflow-x-auto border"
        style={{ background: 'rgba(5,13,32,0.5)', borderColor: '#0c2350' }}
      >
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b" style={{ borderColor: '#0c2350', background: 'rgba(5,13,32,0.8)' }}>
              {['Severity', 'Scanner', 'Issue', ...(!compact ? ['File'] : []), 'Status'].map(h => (
                <th
                  key={h}
                  className="text-left px-4 py-3 text-shield-text-dim"
                  style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2px', textTransform: 'uppercase' }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="text-center py-12 text-shield-text-dim"
                  style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '1px' }}
                >
                  No findings match your filters
                </td>
              </tr>
            )}
            {filtered.map((finding) => (
              <React.Fragment key={finding.id}>
                <tr
                  className="border-b cursor-pointer transition-colors"
                  style={{ borderColor: 'rgba(12,35,80,0.5)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = '#071428')}
                  onMouseLeave={e => (e.currentTarget.style.background = expandedId === finding.id ? '#071428' : 'transparent')}
                  onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                >
                  <td className="px-4 py-3">
                    <Badge label={finding.severity} colors={SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info} />
                  </td>
                  <td className="px-4 py-3">
                    <Badge label={finding.scanner} colors={SCANNER_COLORS[finding.scanner] || SCANNER_COLORS.sast} />
                  </td>
                  <td className="px-4 py-3">
                    <div>
                      <p className="text-shield-text truncate max-w-xs" style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '12px' }}>
                        {finding.message}
                      </p>
                      <p className="text-shield-text-dim mt-0.5" style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '0.5px' }}>
                        {finding.rule}
                      </p>
                    </div>
                  </td>
                  {!compact && (
                    <td className="px-4 py-3 text-shield-text-muted">
                      <span className="truncate max-w-xs block" style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px' }}>
                        {finding.file.split('/').slice(-2).join('/')}
                      </span>
                      <span className="text-shield-text-dim" style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px' }}>
                        :{finding.line}
                      </span>
                    </td>
                  )}
                  <td className="px-4 py-3">
                    <Badge label={finding.status} colors={STATUS_COLORS[finding.status] || STATUS_COLORS.open} />
                  </td>
                </tr>

                {expandedId === finding.id && (
                  <tr className="border-b" style={{ background: 'rgba(1,8,18,0.6)', borderColor: 'rgba(12,35,80,0.5)' }}>
                    <td colSpan={5} className="px-4 py-4">
                      <div className="flex flex-col gap-2">
                        {finding.cwe && (
                          <div className="flex items-center gap-2">
                            <span
                              className="text-shield-text-dim uppercase"
                              style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2px' }}
                            >
                              CWE:
                            </span>
                            <span style={{ color: '#4d8fff', fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px' }}>
                              {finding.cwe}
                            </span>
                          </div>
                        )}
                        <div className="flex items-start gap-2">
                          <span
                            className="text-shield-text-dim uppercase shrink-0"
                            style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2px' }}
                          >
                            File:
                          </span>
                          <span className="text-shield-text-muted" style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px' }}>
                            {finding.file}:{finding.line}
                          </span>
                        </div>
                        {finding.fixSuggestion && (
                          <div
                            className="mt-1 p-3 border-l-2"
                            style={{ background: 'rgba(0,255,136,0.05)', borderColor: '#00ff88', borderLeftWidth: '2px' }}
                          >
                            <p
                              className="uppercase mb-1"
                              style={{ color: '#00ff88', fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2px' }}
                            >
                              Suggested Fix
                            </p>
                            <p className="text-shield-text-muted" style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '12px' }}>
                              {finding.fixSuggestion}
                            </p>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
