import React from 'react'

interface ShieldLogoProps {
  size?: number
  className?: string
  animated?: boolean
}

export default function ShieldLogo({ size = 48, className = '', animated = false }: ShieldLogoProps) {
  return (
    <svg
      viewBox="0 0 512 560"
      width={size}
      height={size * (560 / 512)}
      className={`${animated ? 'animate-float' : ''} ${className}`}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <filter id="logoGlow">
          <feGaussianBlur stdDeviation="6" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="outerGlow">
          <feGaussianBlur stdDeviation="10" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Shield base (dark navy) */}
      <path
        d="M256,14 L492,96 L492,358 C492,468 382,516 256,544 C130,516 20,468 20,358 L20,96 Z"
        fill="#010812"
        stroke="#1562f0"
        strokeWidth="3"
        filter="url(#outerGlow)"
      />

      {/* Left wing panel (bright blue) */}
      <path
        d="M20,96 L256,14 L256,122 L134,186 Z"
        fill="#1562f0"
      />

      {/* Right wing panel (bright blue, mirrored) */}
      <path
        d="M256,14 L492,96 L378,186 L256,122 Z"
        fill="#1562f0"
      />

      {/* Center diamond (bright blue, pointing down) */}
      <path
        d="M134,186 L256,122 L378,186 L256,330 Z"
        fill="#1562f0"
      />

      {/* Subtle shading: darker overlay on left wing edge */}
      <path
        d="M20,96 L256,14 L256,122 L134,186 Z"
        fill="rgba(0,0,0,0.15)"
      />

      {/* Subtle shading: slightly lighter on center diamond top half */}
      <path
        d="M134,186 L256,122 L378,186 L256,258 Z"
        fill="rgba(255,255,255,0.06)"
      />

      {/* White separator lines — form the "W" / double chevron */}
      <g stroke="white" strokeWidth="3.5" strokeLinecap="round" opacity="0.95">
        {/* Left diagonal: apex → inner-left */}
        <line x1="256" y1="14"  x2="134" y2="186" />
        {/* Right diagonal: apex → inner-right */}
        <line x1="256" y1="14"  x2="378" y2="186" />
        {/* Left outer: top-left corner → inner-left */}
        <line x1="20"  y1="96"  x2="134" y2="186" />
        {/* Right outer: top-right corner → inner-right */}
        <line x1="492" y1="96"  x2="378" y2="186" />
        {/* Left diamond edge: inner-left → bottom tip */}
        <line x1="134" y1="186" x2="256" y2="330" />
        {/* Right diamond edge: inner-right → bottom tip */}
        <line x1="378" y1="186" x2="256" y2="330" />
      </g>
    </svg>
  )
}
