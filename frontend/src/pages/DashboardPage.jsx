import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import AppNavigation from '../components/AppNavigation.jsx'
import StatusCard from '../components/StatusCard.jsx'
import { useAuth } from '../hooks/useAuth.js'
import { api } from '../services/api.js'

function Distribution({ title, values }) {
  const entries = Object.entries(values || {})
  const total = entries.reduce((sum, [, count]) => sum + count, 0)
  return <section className="file-panel dashboard-section">
    <h2>{title}</h2>
    {total === 0 ? <p className="muted">No files to summarize yet.</p> : entries.map(([label, count]) =>
      <div className="distribution-row" key={label}>
        <span>{label.replaceAll('_', ' ')}</span>
        <div className="distribution-track" role="img" aria-label={`${label}: ${count} of ${total}`}>
          <div style={{ width: `${count / total * 100}%` }} />
        </div>
        <strong>{count}</strong>
      </div>)}
  </section>
}

export default function DashboardPage() {
  const { user } = useAuth()
  const [summary, setSummary] = useState(null)
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError('')
    const [aggregate, health] = await Promise.allSettled([
      api.getDashboardSummary(), api.getSystemStatus(),
    ])
    if (aggregate.status === 'fulfilled') setSummary(aggregate.value)
    else setError(aggregate.reason.message || 'Dashboard data could not be loaded.')
    setStatus(health.status === 'fulfilled' ? health.value : null)
    setLoading(false)
  }, [])

  useEffect(() => { refresh() }, [refresh])
  const cards = summary ? [
    ['My Files', summary.my_files, '/files'],
    ['Shared With Me', summary.shared_with_me, '/shared-with-me'],
    ['Shared By Me', summary.shared_by_me, '/shared-by-me'],
    ['Active Shares Sent', summary.active_shares, '/shared-by-me'],
    ['Revoked Shares Sent', summary.revoked_shares, '/shared-by-me'],
  ] : []
  return <main className="page-shell">
    <AppNavigation />
    <section className="page-heading page-heading--row">
      <div><p className="eyebrow">Your secure workspace</p><h1>Dashboard</h1><p className="scope-note">Welcome, {user.name}. A snapshot of your files, access, and security choices.</p></div>
      <button type="button" onClick={refresh} disabled={loading}>Refresh</button>
    </section>
    {loading && <p role="status">Loading dashboard…</p>}
    {error && <p role="alert" className="form-message form-message--error">{error}</p>}
    <section aria-label="System health" className="dashboard-health">
      <StatusCard label="Backend" state={status?.backend === 'ok' ? 'online' : 'unavailable'} />
      <StatusCard label="Database" state={status?.database === 'ok' ? 'connected' : 'unavailable'} />
      <StatusCard label="Post-quantum providers" state={status?.provider_availability?.kem?.length ? 'configured' : 'unavailable'} />
    </section>
    {summary && <>
      <section className="dashboard-metrics" aria-label="Your file and share counts">
        {cards.map(([label, value, link]) => <Link className="metric-card" to={link} key={label}><span>{label}</span><strong>{value}</strong></Link>)}
      </section>
      <div className="dashboard-two-column">
        <section className="file-panel dashboard-section">
          <h2>Key readiness</h2>
          <p className="muted">Active keys for your account; no key material is shown.</p>
          {Object.entries(summary.key_readiness).map(([name, ready]) =>
            <p className="readiness-row" key={name}><span>{name}</span><strong>{ready ? 'Ready' : 'Setup required'}</strong></p>)}
          <Link to="/security">View security settings</Link>
        </section>
        <section className="file-panel dashboard-section">
          <h2>Security overview</h2>
          <p>AES-256-GCM content encryption</p><p>ML-KEM-512 / 768 / 1024 key establishment</p>
          <p>Optional X25519 + ML-KEM hybrid key establishment</p><p>ML-DSA sender signatures</p>
          <p className="muted">Signature validity is checked on individual files and shares, not inferred from key readiness.</p>
        </section>
      </div>
      <div className="dashboard-three-column">
        <Distribution title="Security levels" values={summary.security_levels} />
        <Distribution title="Protection architecture" values={summary.architectures} />
        <Distribution title="Selection modes" values={summary.selection_modes} />
      </div>
      <div className="dashboard-two-column">
        <section className="file-panel dashboard-section"><h2>Recent activity</h2>
          {summary.recent_activity.length ? <ul className="compact-list">{summary.recent_activity.map((event, index) => <li key={index}>{event.event_type.replaceAll('_', ' ')} · {event.role} · {new Date(event.created_at).toLocaleString()}</li>)}</ul> : <p className="muted">No share or deletion events yet.</p>}
        </section>
        <section className="file-panel dashboard-section"><h2>Adaptive security decisions</h2>
          {summary.recent_decisions.length ? <ul className="compact-list">{summary.recent_decisions.map((item, index) => <li key={index}>
            <strong>{item.filename}</strong> · {item.mode || 'Legacy'} · {item.level || 'Unknown'} · {item.suite || 'Legacy'}
            {item.reasons?.length > 0 && <details><summary>Why this level?</summary><p>Sensitivity: {item.sensitivity || 'Not specified'}</p><ul>{item.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></details>}
          </li>)}</ul> : <p className="muted">Upload a file to see security decisions.</p>}
        </section>
      </div>
    </>}
  </main>
}
