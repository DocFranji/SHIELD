import React, { useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Play, RefreshCw, Clock, AlertTriangle, Bell } from 'lucide-react'
import clsx from 'clsx'

const PAGE_TITLES: Record<string, string> = {
  '/':          'Dashboard',
  '/findings':  'Security Findings',
  '/settings':  'Settings',
}

export default function Header() {
  const location = useLocation()
  const [scanning, setScanning] = useState(false)

  const title = PAGE_TITLES[location.pathname] || 'SHIELD'

  const handleScan = async () => {
    setScanning(true)
    await new Promise(r => setTimeout(r, 2500))
    setScanning(false)
  }

  return (
    <header className="h-16 flex items-center justify-between px-6 bg-shield-surface border-b border-shield-border shrink-0 relative overflow-hidden">
      {/* Subtle scan line */}
      <div className="scan-line" />

      {/* Page title */}
      <div className="relative z-10">
        <h1
          className="text-shield-text"
          style={{ fontFamily: 'Goldman, sans-serif', fontSize: '16px', letterSpacing: '4px' }}
        >
          {title.toUpperCase()}
        </h1>
        <p
          className="text-shield-text-dim flex items-center gap-1"
          style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1.5px' }}
        >
          <Clock size={9} />
          LAST SCAN: 2 MINUTES AGO
        </p>
      </div>

      {/* Right side controls */}
      <div className="flex items-center gap-3 relative z-10">
        {/* Quick stats */}
        <div className="hidden md:flex items-center gap-2 mr-2">
          <div
            className="flex items-center gap-1.5 px-3 py-1.5 border"
            style={{ background: 'rgba(255,51,68,0.08)', borderColor: 'rgba(255,51,68,0.3)' }}
          >
            <AlertTriangle size={11} style={{ color: '#ff3344' }} />
            <span
              className="font-semibold"
              style={{ color: '#ff3344', fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1px' }}
            >
              3 CRITICAL
            </span>
          </div>
          <div
            className="flex items-center gap-1.5 px-3 py-1.5 border"
            style={{ background: 'rgba(255,136,68,0.08)', borderColor: 'rgba(255,136,68,0.3)' }}
          >
            <AlertTriangle size={11} style={{ color: '#ff8844' }} />
            <span
              className="font-semibold"
              style={{ color: '#ff8844', fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '1px' }}
            >
              8 HIGH
            </span>
          </div>
        </div>

        {/* Notifications */}
        <button className="relative p-2 text-shield-text-muted hover:text-shield-text transition-colors border border-transparent hover:border-shield-border">
          <Bell size={15} />
          <span
            className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full"
            style={{ background: '#ff3344', boxShadow: '0 0 6px #ff3344' }}
          />
        </button>

        {/* Run scan button */}
        <button
          onClick={handleScan}
          disabled={scanning}
          className={clsx(
            'flex items-center gap-2 px-5 py-2 text-xs font-semibold transition-all duration-200 border scan-pulse',
            scanning
              ? 'border-shield-border text-shield-text-muted cursor-not-allowed'
              : 'border-shield-primary text-white'
          )}
          style={{
            fontFamily: 'Chakra Petch, sans-serif',
            letterSpacing: '2px',
            background: scanning ? 'transparent' : '#1562f0',
          }}
        >
          {scanning ? (
            <>
              <RefreshCw size={12} className="animate-spin" />
              SCANNING...
            </>
          ) : (
            <>
              <Play size={12} />
              RUN SCAN
            </>
          )}
        </button>
      </div>
    </header>
  )
}
