import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import AppNavigation from '../components/AppNavigation.jsx'
import { api } from '../services/api.js'

const configuredLimit = Number(import.meta.env.VITE_MAX_UPLOAD_SIZE_MB || 25)
const MAX_UPLOAD_SIZE_MB = Number.isFinite(configuredLimit) ? configuredLimit : 25

function formatBytes(bytes) {
  if (bytes === 0) return '0 bytes'
  const units = ['bytes', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 3)
  const value = bytes / 1024 ** index
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function displayValue(value) {
  return value
    .toLowerCase()
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

export default function UploadPage() {
  const [file, setFile] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [recommending, setRecommending] = useState(false)
  const [error, setError] = useState('')
  const [uploaded, setUploaded] = useState(null)
  const [options, setOptions] = useState(null)
  const [suites, setSuites] = useState([])
  const [selectionMode, setSelectionMode] = useState('MANUAL')
  const [securityLevel, setSecurityLevel] = useState('STANDARD')
  const [securityArchitecture, setSecurityArchitecture] = useState('PQ_ONLY')
  const [sensitivity, setSensitivity] = useState('')
  const [documentCategory, setDocumentCategory] = useState('')
  const [recommendation, setRecommendation] = useState(null)

  useEffect(() => {
    Promise.all([api.getSecurityOptions(), api.getCryptoSuites()])
      .then(([available, approvedSuites]) => {
        setOptions(available)
        setSuites(approvedSuites)
        const configuredDefault = available.security_levels.find((choice) => choice.is_default)
        if (configuredDefault) setSecurityLevel(configuredDefault.security_level)
      })
      .catch((requestError) => {
        setError(requestError.message || 'Security policy options could not be loaded.')
      })
  }, [])

  const minimumRank = useMemo(() => {
    if (!recommendation || !options) return 0
    return (
      options.security_levels.find(
        (choice) => choice.security_level === recommendation.minimum_required_level,
      )?.rank || 0
    )
  }, [options, recommendation])

  function resetRecommendation() {
    setRecommendation(null)
    setUploaded(null)
  }

  function selectFile(event) {
    const selected = event.target.files?.[0] ?? null
    setError('')
    resetRecommendation()

    if (selected && selected.size > MAX_UPLOAD_SIZE_MB * 1024 * 1024) {
      setFile(null)
      event.target.value = ''
      setError(`Choose a file no larger than ${MAX_UPLOAD_SIZE_MB} MB.`)
      return
    }
    setFile(selected)
  }

  function assessment() {
    return {
      file_name: file.name,
      file_size: file.size,
      mime_type: file.type || 'application/octet-stream',
      sensitivity: sensitivity || null,
      document_category: documentCategory || null,
      security_architecture: securityArchitecture,
    }
  }

  async function getRecommendation() {
    setError('')
    setUploaded(null)
    if (!file) {
      setError('Choose a file before requesting a recommendation.')
      return
    }
    setRecommending(true)
    try {
      const result = await api.recommendSecurity(assessment())
      setRecommendation(result)
      setSecurityLevel(result.recommended_level)
    } catch (requestError) {
      setError(requestError.message || 'A recommendation could not be generated.')
    } finally {
      setRecommending(false)
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    const formElement = event.currentTarget
    setError('')
    setUploaded(null)

    if (!file) {
      setError('Choose a file before uploading.')
      return
    }
    if (selectionMode === 'RECOMMEND' && !recommendation) {
      setError('Get a recommendation before confirming the final level.')
      return
    }

    const decision = {
      selection_mode: selectionMode,
      security_level: selectionMode === 'AUTO' ? null : securityLevel,
      sensitivity: selectionMode === 'MANUAL' ? null : sensitivity || null,
      document_category:
        selectionMode === 'MANUAL' ? null : documentCategory || null,
      security_architecture: securityArchitecture,
    }

    setSubmitting(true)
    try {
      setUploaded(await api.uploadFile(file, decision))
      setFile(null)
      setRecommendation(null)
      formElement.querySelector('input[type="file"]').value = ''
    } catch (requestError) {
      setError(requestError.message || 'The file could not be uploaded.')
    } finally {
      setSubmitting(false)
    }
  }

  const levels = options?.security_levels || []
  const suiteIdForLevel = (chosenLevel) => suites.find((suite) =>
    suite.security_level === chosenLevel && suite.architecture === securityArchitecture)?.suite_id || 'Backend selects suite'

  return (
    <main className="page-shell">
      <AppNavigation />
      <section className="page-heading">
        <p className="eyebrow">
          Crypto-agile adaptive security · {options?.policy_version || 'Phase 9'}
        </p>
        <h1>Upload File</h1>
        <p className="scope-note">
          Choose manually, request an explainable recommendation, or let the
          deterministic project policy select a level automatically.
        </p>
      </section>

      <section className="file-panel" aria-labelledby="upload-title">
        <h2 id="upload-title">Choose one file</h2>
        <p className="field-hint">
          Maximum size: {MAX_UPLOAD_SIZE_MB} MB. File contents are not inspected
          for classification.
        </p>

        {error && (
          <p className="form-message form-message--error" role="alert">{error}</p>
        )}
        {uploaded && (
          <div className="form-message form-message--success" role="status">
            <strong>Upload successful: {uploaded.original_filename}</strong>
            <p>Encrypted: {uploaded.encryption_algorithm} · Security: {uploaded.security_level} · Architecture: {uploaded.security_architecture}</p>
            <p>Post-quantum protected: {uploaded.post_quantum_protected ? 'Yes' : 'No'} · Suite: {uploaded.crypto_suite_id}</p>
            <p>Signature: {uploaded.signature_required ? 'Created (verify on My Files)' : 'Not recorded'}</p>
            <p><Link to="/files">View file</Link> · <Link to={`/files/${encodeURIComponent(uploaded.id)}/share`}>Share file</Link> · <Link to="/dashboard">Back to dashboard</Link></p>
            {uploaded.decision_reasons?.length > 0 && (
              <ul className="decision-reasons">
                {uploaded.decision_reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <form className="upload-form" onSubmit={handleSubmit}>
          <p className="upload-steps">1. Select file → 2. Choose architecture and mode → 3. Review → 4. Upload</p>
          <label>
            File
            <input type="file" name="file" onChange={selectFile} />
          </label>
          {file && (
            <p className="selected-file">
              <strong>{file.name}</strong><span>{formatBytes(file.size)}</span>
            </p>
          )}

          <fieldset className="security-mode-picker">
            <legend>Security Mode</legend>
            {(options?.selection_modes || ['MANUAL', 'RECOMMEND', 'AUTO']).map((mode) => (
              <label key={mode}>
                <input
                  type="radio"
                  name="selection-mode"
                  value={mode}
                  checked={selectionMode === mode}
                  onChange={(event) => {
                    setSelectionMode(event.target.value)
                    resetRecommendation()
                  }}
                />
                <span><strong>{displayValue(mode)}</strong></span>
              </label>
            ))}
          </fieldset>

          <fieldset className="security-mode-picker">
            <legend>Key establishment architecture</legend>
            {(options?.security_architectures || ['PQ_ONLY', 'HYBRID']).map((architecture) => (
              <label key={architecture}>
                <input type="radio" name="security-architecture" value={architecture}
                  checked={securityArchitecture === architecture}
                  onChange={(event) => {
                    setSecurityArchitecture(event.target.value)
                    resetRecommendation()
                  }} />
                <span><strong>{architecture === 'HYBRID' ? 'Hybrid (X25519 + ML-KEM)' : 'Post-quantum only (ML-KEM)'}</strong></span>
              </label>
            ))}
          </fieldset>

          <p className="field-hint">
            Hybrid mode combines X25519 with ML-KEM before deriving the key that protects the file’s AES key.
            Post-quantum only remains the default; the selected security level is unchanged.
          </p>

          {selectionMode !== 'MANUAL' && (
            <div className="policy-fields">
              <label>
                Sensitivity
                <select
                  value={sensitivity}
                  onChange={(event) => {
                    setSensitivity(event.target.value)
                    resetRecommendation()
                  }}
                >
                  <option value="">Not specified</option>
                  {(options?.sensitivities || []).map((value) => (
                    <option key={value} value={value}>{displayValue(value)}</option>
                  ))}
                </select>
              </label>
              <label>
                Document Category
                <select
                  value={documentCategory}
                  onChange={(event) => {
                    setDocumentCategory(event.target.value)
                    resetRecommendation()
                  }}
                >
                  <option value="">Not specified</option>
                  {(options?.document_categories || []).map((value) => (
                    <option key={value} value={value}>{displayValue(value)}</option>
                  ))}
                </select>
              </label>
            </div>
          )}

          {selectionMode !== 'MANUAL' && (
            <button type="button" onClick={getRecommendation} disabled={recommending}>
              {recommending ? 'Evaluating…' : selectionMode === 'AUTO' ? 'Preview adaptive selection' : 'Get recommendation'}
            </button>
          )}

          {(selectionMode === 'MANUAL' || (selectionMode === 'RECOMMEND' && recommendation)) && (
            <fieldset className="security-level-picker">
              <legend>
                {selectionMode === 'MANUAL' ? 'Security Level' : 'Confirm Final Level'}
              </legend>
              {levels.map((choice) => (
                <label key={choice.security_level}>
                  <input
                    type="radio"
                    name="security-level"
                    value={choice.security_level}
                    disabled={selectionMode === 'RECOMMEND' && choice.rank < minimumRank}
                    checked={securityLevel === choice.security_level}
                    onChange={(event) => setSecurityLevel(event.target.value)}
                  />
                  <span>
                    <strong>{choice.security_level}</strong> · {choice.algorithm}
                    <small>{suiteIdForLevel(choice.security_level)} · {choice.description}</small>
                  </span>
                </label>
              ))}
            </fieldset>
          )}

          {recommendation && (
            <section className="decision-panel" aria-live="polite">
              <p className="eyebrow">Recommended Security</p>
              <h3>{recommendation.recommended_level} · {recommendation.crypto_suite_id}</h3>
              <p>{recommendation.security_architecture} · {recommendation.kem_algorithm}{recommendation.security_architecture === 'HYBRID' ? ' + X25519' : ''}</p>
              <p>Minimum allowed: {recommendation.minimum_required_level}</p>
              <ul className="decision-reasons">
                {recommendation.reasons.map((reason) => <li key={reason}>{reason}</li>)}
              </ul>
            </section>
          )}

          {selectionMode === 'AUTO' && (
            <p className="field-hint">
              The backend will select and return the strongest applicable level.
              With no policy signals, it safely defaults to STANDARD.
            </p>
          )}

          {file && <section className="decision-panel" aria-label="Upload review">
            <p className="eyebrow">Review before upload</p><h3>{file.name}</h3>
            <p>{formatBytes(file.size)} · {displayValue(selectionMode)} · {securityArchitecture === 'HYBRID' ? 'Hybrid' : 'PQ only'}</p>
            <p>Selected level: {selectionMode === 'AUTO' ? recommendation?.selected_level || 'Backend decides at upload' : securityLevel}</p>
            <p>Suite: {selectionMode === 'AUTO' ? recommendation?.crypto_suite_id || 'Backend decides at upload' : suiteIdForLevel(securityLevel)}</p>
          </section>}

          <button className="button-primary" type="submit" disabled={submitting || !options}>
            {submitting ? 'Uploading…' : 'Upload file'}
          </button>
        </form>
      </section>
    </main>
  )
}
