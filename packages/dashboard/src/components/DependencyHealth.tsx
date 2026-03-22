import React from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { Package, ShieldCheck } from 'lucide-react'

interface VulnerableDep {
  name: string
  version: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cve: string
  fixedVersion: string | null
}

interface DependencyHealthProps {
  totalDeps: number
  vulnerableDeps: VulnerableDep[]
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff3344',
  high:     '#ff8844',
  medium:   '#ffcc00',
  low:      '#00ccff',
}

export default function DependencyHealth({ totalDeps, vulnerableDeps }: DependencyHealthProps) {
  const safeDeps     = totalDeps - vulnerableDeps.length
  const criticalCount = vulnerableDeps.filter(d => d.severity === 'critical').length
  const highCount    = vulnerableDeps.filter(d => d.severity === 'high').length
  const mediumCount  = vulnerableDeps.filter(d => d.severity === 'medium').length
  const lowCount     = vulnerableDeps.filter(d => d.severity === 'low').length
  const healthPercent = Math.round((safeDeps / totalDeps) * 100)

  const pieData = [
    ...(criticalCount > 0 ? [{ name: 'Critical', value: criticalCount, color: '#ff3344' }] : []),
    ...(highCount     > 0 ? [{ name: 'High',     value: highCount,     color: '#ff8844' }] : []),
    ...(mediumCount   > 0 ? [{ name: 'Medium',   value: mediumCount,   color: '#ffcc00' }] : []),
    ...(lowCount      > 0 ? [{ name: 'Low',      value: lowCount,      color: '#00ccff' }] : []),
    { name: 'Safe', value: safeDeps, color: '#00ff88' },
  ]

  const scoreColor = healthPercent > 80 ? '#00ff88' : healthPercent > 60 ? '#ffcc00' : '#ff3344'
  const labelStyle: React.CSSProperties = {
    fontFamily: 'Chakra Petch, sans-serif',
    fontSize: '9px',
    letterSpacing: '1.5px',
    textTransform: 'uppercase' as const,
    color: '#1a2d4a',
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Summary stats */}
      <div className="flex items-center gap-4">
        {[
          { label: 'Total',      value: totalDeps,            color: '#c0d4f0' },
          { label: 'Vulnerable', value: vulnerableDeps.length, color: '#ff3344' },
          { label: 'Safe',       value: safeDeps,              color: '#00ff88' },
        ].map(({ label, value, color }) => (
          <div key={label} className="flex-1 text-center">
            <div
              className="font-bold"
              style={{ color, fontFamily: 'Goldman, sans-serif', fontSize: '22px' }}
            >
              {value}
            </div>
            <div style={labelStyle}>{label}</div>
          </div>
        ))}
      </div>

      {/* Donut chart */}
      <div className="h-36 relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={pieData}
              cx="50%" cy="50%"
              innerRadius={42} outerRadius={60}
              paddingAngle={2}
              dataKey="value"
              strokeWidth={0}
            >
              {pieData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#050d20',
                border: '1px solid #0c2350',
                borderRadius: '2px',
                color: '#c0d4f0',
                fontFamily: 'Chakra Petch, sans-serif',
                fontSize: '11px',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <div
              className="font-bold"
              style={{ color: scoreColor, fontFamily: 'Goldman, sans-serif', fontSize: '18px' }}
            >
              {healthPercent}%
            </div>
            <div style={labelStyle}>Healthy</div>
          </div>
        </div>
      </div>

      {/* Vulnerable packages list */}
      <div>
        <p
          className="uppercase mb-2"
          style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2.5px', color: '#1a2d4a' }}
        >
          Top Vulnerable
        </p>
        <div className="flex flex-col gap-1.5">
          {vulnerableDeps.slice(0, 5).map(dep => (
            <div
              key={dep.cve}
              className="flex items-center justify-between gap-2 p-2 border"
              style={{ background: '#010812', borderColor: '#0c2350' }}
            >
              <div className="flex items-center gap-2 min-w-0">
                <Package size={11} className="text-shield-text-dim shrink-0" />
                <span
                  className="text-shield-text truncate"
                  style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px' }}
                >
                  {dep.name}
                </span>
                <span
                  className="text-shield-text-dim shrink-0"
                  style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px' }}
                >
                  @{dep.version}
                </span>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <span
                  className="font-semibold uppercase"
                  style={{
                    color: SEVERITY_COLORS[dep.severity],
                    fontFamily: 'Chakra Petch, sans-serif',
                    fontSize: '9px',
                    letterSpacing: '1px',
                  }}
                >
                  {dep.severity}
                </span>
                {dep.fixedVersion && (
                  <span
                    className="text-shield-text-dim"
                    style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px' }}
                  >
                    → {dep.fixedVersion}
                  </span>
                )}
              </div>
            </div>
          ))}
          {vulnerableDeps.length === 0 && (
            <div
              className="flex items-center gap-2 p-3 border"
              style={{ background: 'rgba(0,255,136,0.05)', borderColor: 'rgba(0,255,136,0.2)' }}
            >
              <ShieldCheck size={13} style={{ color: '#00ff88' }} />
              <span
                style={{ color: '#00ff88', fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '1px' }}
              >
                All dependencies safe!
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
