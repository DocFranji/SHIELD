import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  AlertTriangle,
  Settings,
  Shield,
  Terminal,
  Box,
  Cpu,
} from 'lucide-react'
import clsx from 'clsx'

const NAV_ITEMS = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/findings', icon: AlertTriangle, label: 'Findings' },
  { path: '/settings', icon: Settings, label: 'Settings' },
]

const STAT_ITEMS = [
  { label: 'Critical', value: 3, color: '#ff3344' },
  { label: 'High',     value: 8, color: '#ff8844' },
  { label: 'Medium',   value: 14, color: '#ffcc00' },
]

export default function Sidebar() {
  const location = useLocation()

  return (
    <aside className="w-56 flex flex-col bg-shield-surface border-r border-shield-border shrink-0">
      {/* Logo header */}
      <div className="p-4 border-b border-shield-border">
        <div className="flex items-center gap-3">
          <img src="/shield-logo.png" alt="SHIELD" style={{ width: 32, height: 32, objectFit: 'contain' }} />
          <div>
            <div
              className="text-shield-text font-bold text-base tracking-widest"
              style={{ fontFamily: 'Goldman, sans-serif', letterSpacing: '4px' }}
            >
              SHIELD
            </div>
            <div
              className="text-shield-text-dim text-xs tracking-widest uppercase"
              style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2px' }}
            >
              Security Platform
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 flex flex-col gap-1">
        <p
          className="text-shield-text-dim uppercase px-2 pt-2 pb-1"
          style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '3px' }}
        >
          Navigation
        </p>
        {NAV_ITEMS.map(({ path, icon: Icon, label }) => (
          <NavLink
            key={path}
            to={path}
            end={path === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 text-xs font-medium transition-all duration-150 relative overflow-hidden',
                'border',
                isActive
                  ? 'bg-shield-primary/15 text-shield-primary-l border-shield-primary/40 shadow-glow'
                  : 'text-shield-text-muted border-transparent hover:text-shield-text hover:bg-shield-surface-2 hover:border-shield-border'
              )
            }
            style={{ fontFamily: 'Chakra Petch, sans-serif', letterSpacing: '1.5px' }}
          >
            {({ isActive }) => (
              <>
                {isActive && <span className="card-cut" style={{ borderWidth: '16px 16px 0 0' }} />}
                <Icon size={14} className="relative z-10" />
                <span className="relative z-10">{label}</span>
              </>
            )}
          </NavLink>
        ))}

        <div className="mt-4">
          <p
            className="text-shield-text-dim uppercase px-2 pb-1"
            style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '3px' }}
          >
            Scanners
          </p>
          {[
            { icon: Cpu,      label: 'SAST',    status: 'active' },
            { icon: Box,      label: 'SCA',     status: 'active' },
            { icon: Shield,   label: 'Secrets', status: 'active' },
            { icon: Terminal, label: 'IaC',     status: 'active' },
          ].map(({ icon: Icon, label }) => (
            <div
              key={label}
              className="flex items-center gap-3 px-3 py-2 text-shield-text-muted"
              style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '1px' }}
            >
              <Icon size={13} className="text-shield-text-dim" />
              <span className="flex-1">{label}</span>
              <span className="w-1.5 h-1.5 rounded-full bg-severity-safe" style={{ boxShadow: '0 0 6px #00ff88' }} />
            </div>
          ))}
        </div>
      </nav>

      {/* Security score mini */}
      <div className="p-3 border-t border-shield-border">
        <div className="bg-shield-bg border border-shield-border p-3 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-0 h-0 border-solid"
            style={{ borderWidth: '20px 20px 0 0', borderColor: '#1562f0 transparent transparent transparent' }} />
          <div className="flex items-center justify-between mb-2">
            <span
              className="text-shield-text-dim uppercase"
              style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '2px' }}
            >
              Security Score
            </span>
            <span
              className="font-bold"
              style={{ color: '#ffcc00', fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px' }}
            >
              72/100
            </span>
          </div>

          <div className="h-1 bg-shield-border overflow-hidden" style={{ borderRadius: '1px' }}>
            <div
              className="h-full transition-all duration-1000"
              style={{
                width: '72%',
                background: 'linear-gradient(90deg, #ff8844, #ffcc00)',
              }}
            />
          </div>

          <div className="flex justify-between mt-2">
            {STAT_ITEMS.map(({ label, value, color }) => (
              <div key={label} className="text-center">
                <div
                  className="font-bold"
                  style={{ color, fontFamily: 'Chakra Petch, sans-serif', fontSize: '13px' }}
                >
                  {value}
                </div>
                <div
                  className="text-shield-text-dim"
                  style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '1px' }}
                >
                  {label}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-center mt-2 gap-1">
          <span
            className="text-shield-text-dim"
            style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '1px' }}
          >
            v1.0.0
          </span>
          <span className="text-shield-text-dim">·</span>
          <span
            className="text-shield-accent"
            style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '9px', letterSpacing: '1px', color: '#00ccff' }}
          >
            Open Source
          </span>
        </div>
      </div>
    </aside>
  )
}
