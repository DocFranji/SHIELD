import React, { useState } from 'react'
import { Shield, Bell, Cpu, Package, Key, Server, GitBranch, Globe, Save, Check, ToggleLeft, ToggleRight } from 'lucide-react'

const labelStyle: React.CSSProperties = {
  fontFamily: 'Chakra Petch, sans-serif',
  fontSize: '9px',
  letterSpacing: '2px',
  textTransform: 'uppercase' as const,
  color: '#1a2d4a',
}

const inputStyle: React.CSSProperties = {
  background: '#010812',
  border: '1px solid #0c2350',
  color: '#c0d4f0',
  fontFamily: 'Chakra Petch, sans-serif',
  fontSize: '11px',
  letterSpacing: '1px',
  padding: '6px 12px',
  outline: 'none',
  borderRadius: '2px',
  transition: 'border-color 0.2s',
}

function Toggle({ enabled, onToggle, label }: { enabled: boolean; onToggle: () => void; label: string }) {
  return (
    <button onClick={onToggle} aria-label={label} className="focus:outline-none">
      {enabled
        ? <ToggleRight size={22} style={{ color: '#1562f0' }} />
        : <ToggleLeft  size={22} style={{ color: '#1a2d4a' }} />
      }
    </button>
  )
}

function SettingRow({ label, description, children }: { label: string; description?: string; children: React.ReactNode }) {
  return (
    <div
      className="flex items-start justify-between gap-4 py-4 border-b last:border-0"
      style={{ borderColor: 'rgba(12,35,80,0.5)' }}
    >
      <div className="flex-1 min-w-0">
        <p style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '12px', letterSpacing: '1px', color: '#c0d4f0' }}>
          {label}
        </p>
        {description && (
          <p style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '12px', color: '#4d6a9a', marginTop: '3px', lineHeight: 1.6 }}>
            {description}
          </p>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  )
}

function Section({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) {
  return (
    <div className="border overflow-hidden" style={{ background: '#050d20', borderColor: '#0c2350' }}>
      <div
        className="flex items-center gap-2 px-5 py-4 border-b relative overflow-hidden"
        style={{ borderColor: '#0c2350', background: 'rgba(5,13,32,0.8)' }}
      >
        <div className="absolute top-0 left-0 w-0 h-0 border-solid"
          style={{ borderWidth: '24px 24px 0 0', borderColor: '#1562f0 transparent transparent transparent', opacity: 0.5 }} />
        <Icon size={14} style={{ color: '#1562f0' }} />
        <h2 style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '11px', letterSpacing: '2.5px', color: '#c0d4f0', textTransform: 'uppercase' }}>
          {title}
        </h2>
      </div>
      <div className="px-5">{children}</div>
    </div>
  )
}

export default function Settings() {
  const [saved, setSaved] = useState(false)

  const [sastEnabled,    setSastEnabled]    = useState(true)
  const [scaEnabled,     setScaEnabled]     = useState(true)
  const [secretsEnabled, setSecretsEnabled] = useState(true)
  const [iacEnabled,     setIacEnabled]     = useState(true)
  const [minSeverity,    setMinSeverity]    = useState('low')

  const [ignoreTestFiles,       setIgnoreTestFiles]       = useState(true)
  const [ignoreDevDeps,         setIgnoreDevDeps]         = useState(true)
  const [noiseReduction,        setNoiseReduction]        = useState(true)
  const [autoIgnoreThreshold,   setAutoIgnoreThreshold]   = useState('3.0')

  const [failOnCritical, setFailOnCritical] = useState(true)
  const [failOnHigh,     setFailOnHigh]     = useState(true)
  const [failOnMedium,   setFailOnMedium]   = useState(false)
  const [blockPRs,       setBlockPRs]       = useState(true)

  const [slackEnabled,  setSlackEnabled]  = useState(false)
  const [emailEnabled,  setEmailEnabled]  = useState(true)
  const [slackWebhook,  setSlackWebhook]  = useState('')
  const [notifyEmail,   setNotifyEmail]   = useState('security@mycompany.com')

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const codeStyle: React.CSSProperties = {
    background: '#010812',
    border: '1px solid #0c2350',
    borderLeft: '3px solid #1562f0',
    padding: '12px 14px',
    fontFamily: 'Chakra Petch, monospace',
    fontSize: '11px',
    color: '#4d8fff',
    overflow: 'auto',
    display: 'block',
    whiteSpace: 'pre',
    lineHeight: 1.7,
    borderRadius: '2px',
  }

  return (
    <div className="flex flex-col gap-6 max-w-3xl">
      <Section icon={Shield} title="Scanner Configuration">
        <SettingRow label="SAST Analysis" description="AST-based static analysis for injection, XSS, auth vulnerabilities">
          <Toggle enabled={sastEnabled}    onToggle={() => setSastEnabled(!sastEnabled)}       label="SAST" />
        </SettingRow>
        <SettingRow label="SCA — Dependency Scanning" description="Check npm/PyPI packages against the OSV vulnerability database">
          <Toggle enabled={scaEnabled}     onToggle={() => setScaEnabled(!scaEnabled)}         label="SCA" />
        </SettingRow>
        <SettingRow label="Secrets Detection" description="18+ patterns for AWS keys, Stripe, OpenAI, GitHub tokens, and more">
          <Toggle enabled={secretsEnabled} onToggle={() => setSecretsEnabled(!secretsEnabled)} label="Secrets" />
        </SettingRow>
        <SettingRow label="IaC Analysis" description="Analyze Dockerfile, docker-compose.yml, next.config.js, vercel.json">
          <Toggle enabled={iacEnabled}     onToggle={() => setIacEnabled(!iacEnabled)}         label="IaC" />
        </SettingRow>
        <SettingRow label="Minimum Severity to Report" description="Findings below this severity will be hidden">
          <select
            value={minSeverity}
            onChange={e => setMinSeverity(e.target.value)}
            style={{ ...inputStyle, cursor: 'pointer' }}
          >
            <option value="info">Info (all)</option>
            <option value="low">Low+</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical only</option>
          </select>
        </SettingRow>
      </Section>

      <Section icon={Cpu} title="Intelligent Triage">
        <SettingRow label="Auto-ignore secrets in test files" description="Secrets in *.test.ts, *.spec.ts, __tests__/ are likely mock data">
          <Toggle enabled={ignoreTestFiles} onToggle={() => setIgnoreTestFiles(!ignoreTestFiles)} label="Ignore test secrets" />
        </SettingRow>
        <SettingRow label="Auto-ignore dev-only CVEs with CVSS < 4.0" description="Low severity vulnerabilities in devDependencies without exploit are suppressed">
          <Toggle enabled={ignoreDevDeps}   onToggle={() => setIgnoreDevDeps(!ignoreDevDeps)}     label="Ignore dev deps" />
        </SettingRow>
        <SettingRow label="Contextual noise reduction" description="Adjust severity based on project context (public deployment, database presence, etc.)">
          <Toggle enabled={noiseReduction}  onToggle={() => setNoiseReduction(!noiseReduction)}   label="Noise reduction" />
        </SettingRow>
        <SettingRow label="CVSS auto-ignore threshold" description="Automatically ignore CVEs with CVSS score below this value (when unreachable + no exploit)">
          <div className="flex items-center gap-2">
            <input
              type="number" min="0" max="5" step="0.5"
              value={autoIgnoreThreshold}
              onChange={e => setAutoIgnoreThreshold(e.target.value)}
              style={{ ...inputStyle, width: '72px', textAlign: 'center' }}
            />
            <span style={{ fontFamily: 'Chakra Petch, sans-serif', fontSize: '10px', color: '#1a2d4a', letterSpacing: '1px' }}>/ 10</span>
          </div>
        </SettingRow>
      </Section>

      <Section icon={GitBranch} title="CI/CD Integration">
        <SettingRow label="Fail pipeline on Critical findings" description="Exit code 1 if any critical severity findings are present">
          <Toggle enabled={failOnCritical} onToggle={() => setFailOnCritical(!failOnCritical)} label="Fail critical" />
        </SettingRow>
        <SettingRow label="Fail pipeline on High findings" description="Exit code 1 if any high severity findings are present">
          <Toggle enabled={failOnHigh}     onToggle={() => setFailOnHigh(!failOnHigh)}         label="Fail high" />
        </SettingRow>
        <SettingRow label="Fail pipeline on Medium findings" description="Exit code 1 if any medium severity findings are present">
          <Toggle enabled={failOnMedium}   onToggle={() => setFailOnMedium(!failOnMedium)}     label="Fail medium" />
        </SettingRow>
        <SettingRow label="Block pull requests with new critical findings" description="Requires GitHub/GitLab integration">
          <Toggle enabled={blockPRs}       onToggle={() => setBlockPRs(!blockPRs)}             label="Block PRs" />
        </SettingRow>
        <div className="py-4">
          <p style={{ ...labelStyle, marginBottom: '8px' }}>GitHub Actions snippet:</p>
          <code style={codeStyle}>{`- name: SHIELD Security Scan
  run: npx @shield/cli ci --format json
  env:
    SHIELD_TOKEN: \${{ secrets.SHIELD_TOKEN }}`}</code>
        </div>
      </Section>

      <Section icon={Bell} title="Notifications">
        <SettingRow label="Email notifications" description="Receive daily digest of new findings">
          <Toggle enabled={emailEnabled} onToggle={() => setEmailEnabled(!emailEnabled)} label="Email" />
        </SettingRow>
        {emailEnabled && (
          <SettingRow label="Notification email">
            <input
              type="email"
              value={notifyEmail}
              onChange={e => setNotifyEmail(e.target.value)}
              style={{ ...inputStyle, width: '260px' }}
            />
          </SettingRow>
        )}
        <SettingRow label="Slack notifications" description="Post new critical/high findings to Slack">
          <Toggle enabled={slackEnabled} onToggle={() => setSlackEnabled(!slackEnabled)} label="Slack" />
        </SettingRow>
        {slackEnabled && (
          <SettingRow label="Slack webhook URL">
            <input
              type="url"
              value={slackWebhook}
              onChange={e => setSlackWebhook(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              style={{ ...inputStyle, width: '280px' }}
            />
          </SettingRow>
        )}
      </Section>

      <Section icon={Globe} title="MCP Server (AI Integration)">
        <div className="py-4">
          <p style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '13px', color: '#4d6a9a', marginBottom: '12px', lineHeight: 1.7 }}>
            Add SHIELD to your AI assistant (Claude Code, Cursor, etc.) via the Model Context Protocol.
          </p>
          <p style={{ ...labelStyle, marginBottom: '8px' }}>Claude Desktop config (~/.claude/claude_desktop_config.json):</p>
          <code style={codeStyle}>{`{
  "mcpServers": {
    "shield": {
      "command": "npx",
      "args": ["@shield/mcp-server"]
    }
  }
}`}</code>
          <p style={{ fontFamily: 'Electrolize, sans-serif', fontSize: '11px', color: '#1a2d4a', marginTop: '10px' }}>
            Available tools:{' '}
            <span style={{ fontFamily: 'Chakra Petch, monospace', fontSize: '11px', color: '#4d6a9a' }}>
              shield_scan_file, shield_check_dependency, shield_get_guardrails, shield_validate_env, shield_scan_project
            </span>
          </p>
        </div>
      </Section>

      {/* Save button */}
      <div className="flex items-center justify-end gap-3 pb-4">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-2.5 border transition-all duration-200"
          style={{
            fontFamily: 'Chakra Petch, sans-serif',
            fontSize: '11px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            background: saved ? 'rgba(0,255,136,0.08)' : '#1562f0',
            color: saved ? '#00ff88' : '#fff',
            borderColor: saved ? 'rgba(0,255,136,0.3)' : '#1562f0',
            borderRadius: '2px',
          }}
        >
          {saved ? <><Check size={14} />Saved!</> : <><Save size={14} />Save Settings</>}
        </button>
      </div>
    </div>
  )
}
