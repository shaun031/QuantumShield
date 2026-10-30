import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

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

export default function MyFilesPage() {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [workingId, setWorkingId] = useState(null)
  const [error, setError] = useState('')
  const [expandedDecisionId, setExpandedDecisionId] = useState(null)
  const [verification, setVerification] = useState({})
  const [shareCounts, setShareCounts] = useState({})
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('ALL')
  const [architecture, setArchitecture] = useState('ALL')
  const [mode, setMode] = useState('ALL')
  const [sort, setSort] = useState('NEWEST')

  const loadFiles = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const loaded = await api.getMyFiles({ limit: 20, offset: page * 20 })
      setFiles(loaded)
      setShareCounts(await api.getFileShareCounts(loaded.map((item) => item.id)).catch(() => null))
      const results = await Promise.all(loaded.map(async (item) => {
        try {
          return [item.id, await api.verifyFile(item.id)]
        } catch {
          return [item.id, { status: 'UNAVAILABLE' }]
        }
      }))
      setVerification(Object.fromEntries(results))
    } catch (requestError) {
      setError(requestError.message || 'Your files could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    loadFiles()
  }, [loadFiles])

  async function download(file) {
    setWorkingId(file.id)
    setError('')
    try {
      const result = await api.downloadFile(file.id)
      startBrowserDownload(result.blob, result.filename || file.original_filename)
    } catch (requestError) {
      setError(requestError.message || 'The file could not be downloaded.')
    } finally {
      setWorkingId(null)
    }
  }

  async function remove(file) {
    if (!window.confirm(`Delete ${file.original_filename}? This removes future access for all current recipients through QuantumShield. It cannot erase copies already downloaded.`)) return
    setWorkingId(file.id)
    setError('')
    try {
      await api.deleteFile(file.id)
      setFiles((current) => current.filter((item) => item.id !== file.id))
    } catch (requestError) {
      setError(requestError.message || 'The file could not be deleted.')
    } finally {
      setWorkingId(null)
    }
  }

  const filtered = files.filter((file) =>
    file.original_filename.toLowerCase().includes(search.toLowerCase()) &&
    (level === 'ALL' || file.security_level === level) &&
    (architecture === 'ALL' || file.security_architecture === architecture) &&
    (mode === 'ALL' || file.selection_mode === mode))
    .sort((a, b) => sort === 'FILENAME' ? a.original_filename.localeCompare(b.original_filename) :
      sort === 'SIZE' ? b.file_size - a.file_size :
      sort === 'OLDEST' ? new Date(a.created_at) - new Date(b.created_at) :
      new Date(b.created_at) - new Date(a.created_at))

  return (
    <main className="page-shell">
      <AppNavigation />
      <section className="page-heading page-heading--row">
        <div>
          <p className="eyebrow">Owner-only access</p>
          <h1>My Files</h1>
        </div>
        <Link className="link-button" to="/upload">
          Upload a file
        </Link>
      </section>

      {error && (
        <p className="form-message form-message--error" role="alert">
          {error}
        </p>
      )}

      <section className="filter-bar" aria-label="File filters">
        <label>Search filename<input value={search} onChange={(event) => setSearch(event.target.value)} /></label>
        <label>Security level<select value={level} onChange={(event) => setLevel(event.target.value)}><option>ALL</option><option>LOW</option><option>STANDARD</option><option>HIGH</option></select></label>
        <label>Architecture<select value={architecture} onChange={(event) => setArchitecture(event.target.value)}><option>ALL</option><option>PQ_ONLY</option><option>HYBRID</option></select></label>
        <label>Mode<select value={mode} onChange={(event) => setMode(event.target.value)}><option>ALL</option><option>MANUAL</option><option>RECOMMEND</option><option>AUTO</option></select></label>
        <label>Sort<select value={sort} onChange={(event) => setSort(event.target.value)}><option value="NEWEST">Newest</option><option value="OLDEST">Oldest</option><option value="FILENAME">Filename</option><option value="SIZE">File size</option></select></label>
      </section>

      <section className="file-panel" aria-live="polite">
        {loading ? (
          <p>Loading your files…</p>
        ) : files.length === 0 ? (
          <div className="empty-state">
            <h2>No files yet</h2>
            <p>Upload a file to use AES-256-GCM and recipient-specific ML-KEM protection.</p>
          </div>
        ) : (
          <div className="file-list">
            {filtered.length === 0 && <p>No files on this page match the filters.</p>}
            {filtered.map((file) => (
              <article className="file-row" key={file.id}>
                <div className="file-row__details">
                  <h2>{file.original_filename}</h2>
                  <p>
                    {file.mime_type} · {formatBytes(file.file_size)} · Uploaded{' '}
                    {new Date(file.created_at).toLocaleString()}
                  </p>
                  {verification[file.id]?.status === 'INVALID' && (
                    <p className="form-message form-message--error" role="alert">
                      Signature verification failed. This file cannot be trusted.
                    </p>
                  )}
                  <p className="encryption-status">
                    <span className={`security-badge ${verification[file.id]?.status === 'VALID' ? '' : 'security-badge--warning'}`}>
                      {verification[file.id]?.status === 'VALID' ? `Sender verified · ${verification[file.id].algorithm}` :
                        verification[file.id]?.status === 'LEGACY_UNSIGNED' ? 'Legacy unsigned' :
                          verification[file.id]?.status === 'INVALID' ? 'Signature invalid' : 'Verification unavailable'}
                    </span>
                  </p>
                  <p className="encryption-status">
                    {file.post_quantum_protected ? (
                      <>
                        <span className="security-badge">Post-quantum protected</span>{' '}
                        {file.security_architecture || 'PQ_ONLY'} · {file.security_level} · {file.crypto_suite_id} · {file.encryption_algorithm} · {file.kem_algorithm}{file.classical_algorithm ? ` + ${file.classical_algorithm}` : ''}
                      </>
                    ) : file.is_encrypted ? (
                      <>
                        <span className="security-badge security-badge--legacy">
                          Phase 4 encrypted
                        </span>{' '}
                        {file.encryption_algorithm}
                      </>
                    ) : (
                      <span className="security-badge security-badge--warning">
                        Legacy plaintext · migration required
                      </span>
                    )}
                  </p>
                  {file.selection_mode && (
                    <p>
                      Mode: {file.selection_mode} · Sensitivity:{' '}
                      {file.sensitivity || 'Not specified'} · Recommended:{' '}
                      {file.recommended_security_level}
                      {file.user_override ? ' · User increased protection' : ''}
                    </p>
                  )}
                  <p>Active shares: {shareCounts === null ? 'Unavailable' : shareCounts[file.id] || 0}</p>
                  <details className="security-details"><summary>Security Details</summary>
                    <dl><dt>Encryption</dt><dd>{file.encryption_algorithm || 'Not encrypted'}</dd>
                      <dt>Security level</dt><dd>{file.security_level || 'Legacy'}</dd>
                      <dt>Selection mode</dt><dd>{file.selection_mode || 'Legacy'}</dd>
                      <dt>Crypto suite</dt><dd>{file.crypto_suite_id || 'Legacy'}</dd>
                      <dt>Key establishment</dt><dd>{file.classical_algorithm ? `${file.classical_algorithm} + ` : ''}{file.kem_algorithm || 'Legacy'}</dd>
                      <dt>KDF</dt><dd>{file.post_quantum_protected ? 'HKDF-SHA256' : 'Not applicable'}</dd>
                      <dt>Signature</dt><dd>{verification[file.id]?.algorithm || 'Not available'}</dd>
                      <dt>Signature status</dt><dd>{verification[file.id]?.status || 'Unavailable'}</dd>
                      <dt>Policy version</dt><dd>{file.policy_version || 'Not recorded'}</dd></dl>
                  </details>
                  {file.decision_reasons?.length > 0 && (
                    <>
                      <button
                        className="decision-toggle"
                        type="button"
                        onClick={() => setExpandedDecisionId((current) => (
                          current === file.id ? null : file.id
                        ))}
                      >
                        {expandedDecisionId === file.id ? 'Hide reason' : 'View reason'}
                      </button>
                      {expandedDecisionId === file.id && (
                        <div className="decision-panel">
                          <strong>Policy {file.policy_version}</strong>
                          <ul className="decision-reasons">
                            {file.decision_reasons.map((reason) => (
                              <li key={reason}>{reason}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </>
                  )}
                </div>
                <div className="file-row__actions">
                  <Link
                    className="inline-link-button"
                    to={`/files/${encodeURIComponent(file.id)}/share`}
                  >
                    Share
                  </Link>
                  <button
                    type="button"
                    disabled={workingId === file.id || !['VALID', 'LEGACY_UNSIGNED'].includes(verification[file.id]?.status)}
                    onClick={() => download(file)}
                  >
                    Download
                  </button>
                  <button
                    className="button-danger"
                    type="button"
                    disabled={workingId === file.id}
                    onClick={() => remove(file)}
                  >
                    Delete
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
      <nav className="pagination" aria-label="My Files pages"><button type="button" disabled={page === 0 || loading} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1}</span><button type="button" disabled={files.length < 20 || loading} onClick={() => setPage(page + 1)}>Next</button></nav>
    </main>
  )
}
