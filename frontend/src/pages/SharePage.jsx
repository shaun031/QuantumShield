import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import AppNavigation from '../components/AppNavigation.jsx'
import { api } from '../services/api.js'

export default function SharePage() {
  const { fileId } = useParams()
  const [file, setFile] = useState(null)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [searching, setSearching] = useState(false)
  const [workingId, setWorkingId] = useState(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    let active = true
    api
      .getFile(fileId)
      .then((result) => {
        if (active) setFile(result)
      })
      .catch((requestError) => {
        if (active) setError(requestError.message || 'The file could not be loaded.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [fileId])

  async function search(event) {
    event.preventDefault()
    const normalized = query.trim()
    if (normalized.length < 3) {
      setError('Enter at least 3 characters to search.')
      return
    }
    setSearching(true)
    setError('')
    setSuccess('')
    try {
      setResults(await api.searchUsers(normalized))
    } catch (requestError) {
      setError(requestError.message || 'Users could not be searched.')
    } finally {
      setSearching(false)
    }
  }

  async function shareWith(user) {
    setWorkingId(user.id)
    setError('')
    setSuccess('')
    try {
      await api.shareFile(fileId, user.id)
      setSuccess(`${file.original_filename} is now shared with ${user.name}.`)
      setResults((current) => current.filter((candidate) => candidate.id !== user.id))
    } catch (requestError) {
      setError(requestError.message || 'The file could not be shared.')
    } finally {
      setWorkingId(null)
    }
  }

  return (
    <main className="page-shell">
      <AppNavigation />
      <section className="page-heading">
        <p className="eyebrow">Recipient-specific post-quantum access</p>
        <h1>Share File</h1>
        <p className="scope-note">
          {loading
            ? 'Loading file…'
            : file
              ? `Choose a registered recipient for ${file.original_filename}.`
              : 'The selected file is unavailable.'}
        </p>
        {file && (
          <p className="security-summary">
            File encryption: <strong>AES-256-GCM</strong> · Recipient key protection:{' '}
            <strong>{file.kem_algorithm}</strong> · File security:{' '}
            <strong>{file.security_level}</strong>
          </p>
        )}
      </section>

      {error && <p className="form-message form-message--error" role="alert">{error}</p>}
      {success && <p className="form-message form-message--success" role="status">{success}</p>}

      <section className="file-panel">
        <form className="share-search" onSubmit={search}>
          <label htmlFor="recipient-search">
            Search by name or email
            <input
              id="recipient-search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              minLength={3}
              maxLength={100}
              placeholder="At least 3 characters"
              autoComplete="off"
            />
          </label>
          <button className="button-primary" type="submit" disabled={searching || !file}>
            {searching ? 'Searching…' : 'Search'}
          </button>
        </form>

        <div className="file-list" aria-live="polite">
          {results.map((user) => {
            const hasRequiredKey = user.supported_kem_algorithms.includes(file.kem_algorithm)
            const hasHybridKey = file.security_architecture !== 'HYBRID' || user.supported_key_algorithms?.includes('X25519')
            return (
            <article className="file-row" key={user.id}>
              <div className="file-row__details">
                <h2>{user.name}</h2>
                <p>{user.email}</p>
                <p className="encryption-status">
                  {hasRequiredKey
                    ? `${file.kem_algorithm} key ready`
                    : `${file.kem_algorithm} key required`}
                </p>
                {file.security_architecture === 'HYBRID' && <p>X25519: {hasHybridKey ? 'Ready' : 'Required'}</p>}
                <p>Recipient signing key: {user.supported_key_algorithms?.some((algorithm) => algorithm.startsWith('ML-DSA-')) ? 'Ready' : 'Not configured'} (sender signs the share)</p>
              </div>
              <button
                type="button"
                disabled={!hasRequiredKey || !hasHybridKey || workingId === user.id}
                onClick={() => shareWith(user)}
              >
                {workingId === user.id ? 'Sharing…' : 'Share securely'}
              </button>
            </article>
            )
          })}
          {!searching && query.trim().length >= 3 && results.length === 0 && !success && (
            <p className="empty-state">No matching recipients.</p>
          )}
        </div>
        <p className="panel-footer"><Link to="/files">Back to My Files</Link></p>
      </section>
    </main>
  )
}
