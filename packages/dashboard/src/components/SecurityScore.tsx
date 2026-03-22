import React, { useEffect, useState } from 'react'

interface SecurityScoreProps {
  score: number
  size?: number
  showLabel?: boolean
  animated?: boolean
}

function getGrade(score: number): string {
  if (score >= 90) return 'A+'
  if (score >= 80) return 'A'
  if (score >= 70) return 'B'
  if (score >= 60) return 'C'
  if (score >= 50) return 'D'
  return 'F'
}

function getColor(score: number): { stroke: string; glow: string; text: string } {
  if (score >= 80) return { stroke: '#00ff88', glow: 'rgba(0,255,136,0.4)',  text: '#00ff88' }
  if (score >= 60) return { stroke: '#ffcc00', glow: 'rgba(255,204,0,0.4)',  text: '#ffcc00' }
  if (score >= 40) return { stroke: '#ff8844', glow: 'rgba(255,136,68,0.4)', text: '#ff8844' }
  return               { stroke: '#ff3344', glow: 'rgba(255,51,68,0.4)',  text: '#ff3344' }
}

export default function SecurityScore({ score, size = 200, showLabel = true, animated = true }: SecurityScoreProps) {
  const [displayScore, setDisplayScore] = useState(animated ? 0 : score)
  const [progress, setProgress]         = useState(animated ? 0 : score / 100)

  useEffect(() => {
    if (!animated) {
      setDisplayScore(score)
      setProgress(score / 100)
      return
    }
    let frame = 0
    const totalFrames = 60
    const animate = () => {
      frame++
      const eased = 1 - Math.pow(1 - frame / totalFrames, 3)
      setDisplayScore(Math.round(score * eased))
      setProgress(eased * (score / 100))
      if (frame < totalFrames) requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)
  }, [score, animated])

  const colors      = getColor(score)
  const grade       = getGrade(score)
  const cx          = size / 2
  const cy          = size / 2
  const radius      = (size / 2) - 16
  const strokeWidth = size > 150 ? 8 : 6
  const circumference = 2 * Math.PI * radius
  const dashOffset    = circumference * (1 - progress)

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {/* Track */}
          <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#0c2350" strokeWidth={strokeWidth} />

          {/* Progress arc */}
          <circle
            cx={cx} cy={cy} r={radius}
            fill="none"
            stroke={colors.stroke}
            strokeWidth={strokeWidth}
            strokeLinecap="square"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{
              transform: 'rotate(-90deg)',
              transformOrigin: `${cx}px ${cy}px`,
              filter: `drop-shadow(0 0 6px ${colors.glow})`,
            }}
          />

          {/* Inner ring */}
          <circle cx={cx} cy={cy} r={radius - strokeWidth} fill="none" stroke={colors.stroke} strokeWidth={1} opacity={0.08} />

          {/* Score number */}
          <text
            x={cx} y={cy - (size > 150 ? 12 : 8)}
            textAnchor="middle"
            fill={colors.text}
            fontSize={size > 150 ? 44 : 32}
            fontWeight="700"
            fontFamily="Goldman, sans-serif"
          >
            {displayScore}
          </text>

          {/* /100 */}
          <text
            x={cx} y={cy + (size > 150 ? 14 : 10)}
            textAnchor="middle"
            fill="#1a2d4a"
            fontSize={size > 150 ? 12 : 9}
            fontFamily="Chakra Petch, sans-serif"
            letterSpacing="2"
          >
            / 100
          </text>

          {/* Grade */}
          <text
            x={cx} y={cy + (size > 150 ? 38 : 28)}
            textAnchor="middle"
            fill={colors.text}
            fontSize={size > 150 ? 18 : 14}
            fontWeight="600"
            fontFamily="Chakra Petch, sans-serif"
            letterSpacing="3"
            opacity={0.85}
          >
            GRADE {grade}
          </text>
        </svg>

        {/* Radial glow */}
        <div
          className="absolute inset-0 rounded-full pointer-events-none"
          style={{ background: `radial-gradient(circle, ${colors.glow} 0%, transparent 70%)`, opacity: 0.12 }}
        />
      </div>

      {showLabel && (
        <div className="text-center">
          <p
            className="text-shield-text-muted uppercase"
            style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', letterSpacing: '3px' }}
          >
            Security Score
          </p>
        </div>
      )}
    </div>
  )
}
