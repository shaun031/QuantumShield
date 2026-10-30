import { useCallback, useEffect, useState } from 'react'

import AppNavigation from '../components/AppNavigation.jsx'
import { api } from '../services/api.js'

function formatBytes(bytes) {
  if (bytes === 0) return '0 bytes'
  const units = ['bytes', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 3)
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function startBrowserDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export default function SharedFilesPage({ mode }) {
  const received = mode === 'received'
  const [shares, setShares] = useState([])
  const [loading, setLoading] = useState(true)
  const [workingId, setWorkingId] = useState(null)
  const [error, setError] = useState('')
  const [verification, setVerification] = useState({})
  const [page, setPage] = useState(0)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [personSearch, setPersonSearch] = useState('')
  const [notice, setNotice] = useState('')

  const loadShares = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const loaded = received ? await api.getReceivedShares({ limit: 20, offset: page * 20 }) : await api.getSentShares({ limit: 20, offset: page * 20 })
      setShares(loaded)
      const results = await Promise.all(loaded.map(async (item) => {
        try {
          return [item.id, await api.verifyShare(item.id)]
        } catch {
          return [item.id, { status: 'UNAVAILABLE' }]
        }
      }))
      setVerification(Object.fromEntries(results))
    } catch (requestError) {
      setError(requestError.message || 'Shares could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [received, page])

  useEffect(() => {
    loadShares()
  }, [loadShares])

  async function download(share) {
    setWorkingId(share.id)
    setError('')
    try {
      const result = await api.downloadSharedFile(share.id)
      startBrowserDownload(result.blob, result.filename || share.file.original_filename)
    } catch (requestError) {
      setError(requestError.message || 'The shared file could not be downloaded.')
    } finally {
      setWorkingId(null)
    }
  }

  async function revoke(share) {
    const warning = `Revoke ${share.recipient.name}'s future access to ${share.file.original_filename}?\n\n` +
      'They will no longer be able to download it through QuantumShield. ' +
      'This cannot remove copies they already downloaded.'
    if (!window.confirm(warning)) return
    setWorkingId(share.id)
    setError('')
    try {
      const updated = await api.revokeShare(share.id)
      setShares((current) => current.map((item) => item.id === share.id ? updated : item))
      setNotice(`Access revoked for ${share.recipient.name}. Future downloads through QuantumShield are blocked.`)
    } catch (requestError) {
      setError(requestError.message || 'Access could not be revoked.')
    } finally {
      setWorkingId(null)
    }
  }

  const filtered = shares.filter((share) =>
    (statusFilter === 'ALL' || share.status === statusFilter) &&
    (received ? share.sender : share.recipient).name.toLowerCase().includes(personSearch.toLowerCase()))

  return (
    <main className="page-shell">
      <AppNavigation />
      <section className="page-heading">
        <p className="eyebrow">Read-only secure sharing</p>
        <h1>{received ? 'Shared With Me' : 'Shared By Me'}</h1>
        {!received && (
          <p className="scope-note">
            Revocation prevents future downloads through QuantumShield. It cannot remove files already downloaded by the recipient.
          </p>
        )}
      </section>

      {error && <p className="form-message form-message--error" role="alert">{error}</p>}
      {notice && <p className="form-message form-message--success" role="status">{notice}</p>}
      <section className="filter-bar" aria-label="Share filters">
        <label>{received ? 'Search sender' : 'Search recipient'}<input value={personSearch} onChange={(event) => setPersonSearch(event.target.value)} /></label>
        <label>Status<select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option>ALL</option><option>ACTIVE</option><option>REVOKED</option></select></label>
      </section>

      <section className="file-panel" aria-live="polite">
        {loading ? (
          <p>Loading shares…</p>
        ) : shares.length === 0 ? (
          <div className="empty-state">
            <h2>No shares yet</h2>
            <p>{received ? 'Files shared with you will appear here.' : 'Files you share will appear here.'}</p>
          </div>
        ) : (
          <div className="file-list">
            {filtered.length === 0 && <p>No shares on this page match the filters.</p>}
            {filtered.map((share) => (
              <article className="file-row" key={share.id}>
                <div className="file-row__details">
                  <h2>{share.file.original_filename}</h2>
                  <p>
                    {formatBytes(share.file.file_size)} · {received ? `From ${share.sender.name}` : `To ${share.recipient.name}`} ·{' '}
                    {new Date(share.created_at).toLocaleString()}
                  </p>
                  {verification[share.id]?.status === 'INVALID' && (
                    <p className="form-message form-message--error" role="alert">
                      Signature verification failed. This file cannot be trusted.
                    </p>
                  )}
                  <p className="encryption-status">
                    <span className={`security-badge ${share.status === 'REVOKED' ? 'security-badge--warning' : ''}`}>
                      {share.status === 'REVOKED' ? 'Access revoked' : 'Active access'}
                    </span>
                    {share.revoked_at ? ` · Revoked ${new Date(share.revoked_at).toLocaleString()}` : ''}
                  </p>
                  {!received && share.revoke_reason && <p className="encryption-status">Reason: {share.revoke_reason}</p>}
                  <p className="encryption-status">
                    <span className={`security-badge ${verification[share.id]?.status === 'VALID' ? '' : 'security-badge--warning'}`}>
                      {verification[share.id]?.status === 'VALID' ? `Sender verified · ${verification[share.id].algorithm}` :
                        verification[share.id]?.status === 'LEGACY_UNSIGNED' ? 'Legacy unsigned' :
                          verification[share.id]?.status === 'INVALID' ? 'Signature invalid' : 'Verification unavailable'}
                    </span>
                  </p>
                  <p className="encryption-status">
                    <span className="security-badge">Post-quantum shared</span>{' '}
                    {share.security_architecture || 'PQ_ONLY'} · {share.security_level} · {share.crypto_suite_id} · {share.kem_algorithm}{share.classical_algorithm ? ` + ${share.classical_algorithm}` : ''} · {share.permission}
                  </p>
                  <details className="security-details"><summary>Security Details</summary>
                    <p>Encryption: AES-256-GCM · {share.security_architecture} key establishment · {share.crypto_suite_id}</p>
                    <p>Security: {share.security_level} · {share.kem_algorithm}{share.classical_algorithm ? ` + ${share.classical_algorithm}` : ''}</p>
                    <p>Signature status: {verification[share.id]?.status || 'Unavailable'}</p>
                  </details>
                </div>
                {received && (
                  <button
                    type="button"
                    disabled={share.status !== 'ACTIVE' || workingId === share.id || !['VALID', 'LEGACY_UNSIGNED'].includes(verification[share.id]?.status)}
                    onClick={() => download(share)}
                  >
                    {workingId === share.id ? 'Decrypting…' : 'Download'}
                  </button>
                )}
                {!received && share.status === 'ACTIVE' && (
                  <button className="button-danger" type="button"
                    disabled={workingId === share.id} onClick={() => revoke(share)}>
                    {workingId === share.id ? 'Revoking…' : 'Revoke Access'}
                  </button>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
      <nav className="pagination" aria-label="Share pages"><button type="button" disabled={page === 0 || loading} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1}</span><button type="button" disabled={shares.length < 20 || loading} onClick={() => setPage(page + 1)}>Next</button></nav>
    </main>
  )
}
