import { useEffect, useState } from 'react'

import AppNavigation from '../components/AppNavigation.jsx'
import { api } from '../services/api.js'

export default function SecurityPage() {
  const [keys, setKeys] = useState([])
  const [suites, setSuites] = useState([])
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    Promise.allSettled([api.getMyCryptoKey(), api.getCryptoSuites(), api.getSystemStatus()])
      .then(([keyResult, suiteResult, healthResult]) => {
        if (!active) return
        if (keyResult.status === 'fulfilled') setKeys(keyResult.value)
        else if (keyResult.reason?.status !== 404) setError('Cryptographic key status could not be loaded.')
        if (suiteResult.status === 'fulfilled') setSuites(suiteResult.value)
        else setError('Supported crypto suites could not be loaded.')
        if (healthResult.status === 'fulfilled') setStatus(healthResult.value)
      }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  return <main className="page-shell"><AppNavigation />
    <section className="page-heading"><p className="eyebrow">Security architecture</p><h1>Security</h1>
      <p className="scope-note">Your active keys and supported suites. Private keys are never displayed.</p></section>
    {loading && <p role="status">Checking security…</p>}
    {error && <p role="alert" className="form-message form-message--error">{error}</p>}
    <div className="dashboard-two-column">
      <section className="file-panel dashboard-section"><h2>My cryptographic keys</h2>
        {keys.length ? <div className="benchmark-table-wrap"><table className="benchmark-table"><thead><tr><th>Purpose</th><th>Algorithm</th><th>Version</th><th>Status</th><th>Created</th></tr></thead><tbody>
          {keys.map((key) => <tr key={key.id}><td>{key.key_purpose.replaceAll('_', ' ')}</td><td>{key.algorithm}</td><td>v{key.key_version}</td><td>{key.is_active ? 'Active' : 'Inactive'}</td><td>{new Date(key.created_at).toLocaleString()}</td></tr>)}
        </tbody></table></div> : !loading && <p className="muted">No active keys configured. Registration normally provisions the key set.</p>}
      </section>
      <section className="file-panel dashboard-section"><h2>System availability</h2>
        <p>Backend: {status?.backend === 'ok' ? 'Online' : 'Unavailable'}</p>
        <p>Database: {status?.database === 'ok' ? 'Available' : 'Unavailable'}</p>
        <p>Post-quantum providers: {status?.provider_availability?.kem?.length ? 'Available' : 'Unavailable'}</p>
        <p>Hybrid key agreement: {status?.provider_availability?.key_agreement?.includes('X25519') ? 'Available' : 'Unavailable'}</p>
        <p>Signature key: {keys.some((key) => key.key_purpose === 'SIGNATURE') ? 'Ready' : 'Setup required'}</p>
      </section>
    </div>
    <section className="file-panel dashboard-section"><h2>Supported crypto suites</h2>
      {suites.length ? <div className="suite-grid">{suites.map((suite) => <article className="suite-card" key={suite.suite_id}>
        <h3>{suite.suite_id}</h3><p>{suite.security_level} · {suite.architecture === 'HYBRID' ? 'Hybrid' : 'PQ only'}</p>
        <p>{suite.content_aead} · {suite.classical_algorithm ? `${suite.classical_algorithm} + ` : ''}{suite.kem} · {suite.kdf}</p>
        <small>{suite.description}</small>
      </article>)}</div> : !loading && <p className="muted">No suite information available.</p>}
    </section>
    <section className="file-panel dashboard-section"><h2>What the terms mean</h2>
      <p><strong>ML-KEM:</strong> post-quantum key establishment used to protect access to a file’s encryption key.</p>
      <p><strong>Hybrid:</strong> X25519 and ML-KEM are combined before deriving the key protecting the file AES key. This is not double file encryption.</p>
      <p><strong>ML-DSA:</strong> digital signatures that help verify sender authenticity.</p>
      <h3>Important limitations</h3>
      <p>Private cryptographic keys are server-managed and protected by the application master key. QuantumShield is not a zero-knowledge system.</p>
      <p>Revocation prevents future downloads through QuantumShield; it cannot erase copies already downloaded.</p>
      <p>Adaptive selection is rule-based, using metadata and user-provided classification. File contents are not inspected for classification.</p>
    </section>
  </main>
}
