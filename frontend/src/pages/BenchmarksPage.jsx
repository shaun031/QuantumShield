import { useEffect, useMemo, useState } from 'react'

import AppNavigation from '../components/AppNavigation.jsx'
import { api } from '../services/api.js'

function formatMs(value) {
  return typeof value === 'number' ? value.toFixed(3) : '—'
}

function formatBytes(value) {
  if (typeof value !== 'number') return '—'
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(1)} GB`
}

function BarChart({ title, rows, label }) {
  const maximum = rows.reduce((largest, row) => Math.max(largest, row.mean_ms), 0)
  return (
    <section className="benchmark-card" aria-label={title}>
      <h2>{title}</h2>
      <p className="benchmark-note">Mean wall time (ms); bars start at zero. {label}</p>
      <div className="benchmark-bars">
        {rows.map((row) => (
          <div className="benchmark-bar-row" key={row.scenario_id}>
            <span title={row.suite_id || row.algorithm}>{row.suite_id || row.algorithm}</span>
            <div className="benchmark-bar-track">
              <div style={{ width: `${maximum ? (row.mean_ms / maximum) * 100 : 0}%` }} />
            </div>
            <strong>{formatMs(row.mean_ms)}</strong>
          </div>
        ))}
      </div>
    </section>
  )
}

export default function BenchmarksPage() {
  const [run, setRun] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    api.getLatestBenchmark().then((latest) => { if (active) setRun(latest) })
      .catch((caught) => { if (active && caught.status !== 404) setError(caught.message) })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  async function loadFile(event) {
    setRun(null)
    setError('')
    const file = event.target.files?.[0]
    if (!file) return
    if (file.size > 10 * 1024 * 1024) {
      setError('The benchmark JSON file must be 10 MB or smaller.')
      return
    }
    try {
      const parsed = JSON.parse(await file.text())
      if (parsed.benchmark_schema_version !== 1 || !Array.isArray(parsed.results) ||
          typeof parsed.run_id !== 'string' || !parsed.environment || !parsed.methodology) {
        throw new Error('This is not a supported QuantumShield benchmark export.')
      }
      if (parsed.results.some((row) => typeof row.mean_ms !== 'number' ||
          !Number.isFinite(row.mean_ms) || row.mean_ms < 0 ||
          typeof row.benchmark_type !== 'string' || typeof row.operation !== 'string' ||
          typeof row.scenario_id !== 'string')) {
        throw new Error('The benchmark export contains invalid timing rows.')
      }
      setRun(parsed)
    } catch (caught) {
      setError(caught.message || 'The benchmark file could not be read.')
    }
  }

  const data = useMemo(() => {
    const rows = run?.results || []
    return {
      suites: rows.filter((row) => row.benchmark_type === 'CRYPTO_SUITE' && row.operation === 'protect'),
      encapsulate: rows.filter((row) => row.benchmark_type === 'CRYPTO_PRIMITIVE' && row.operation === 'encapsulate'),
      decapsulate: rows.filter((row) => row.benchmark_type === 'CRYPTO_PRIMITIVE' && row.operation === 'decapsulate'),
      files: rows.filter((row) => row.benchmark_type === 'FILE_CRYPTO' && row.operation === 'encrypt'),
      shares: rows.filter((row) => row.benchmark_type === 'SHARE_CRYPTO'),
      transfers: rows.filter((row) => row.benchmark_type === 'END_TO_END' &&
        ['upload_total', 'download_total'].includes(row.operation)),
    }
  }, [run])
  const fastest = data.encapsulate.length ? [...data.encapsulate].sort((a, b) => a.mean_ms - b.mean_ms)[0] : null
  const productionSuites = data.suites.filter((row) => row.suite_id?.startsWith('QS-'))
  const smallest = productionSuites.length ? [...productionSuites].sort((a, b) => (a.metadata_overhead_bytes ?? Infinity) - (b.metadata_overhead_bytes ?? Infinity))[0] : null
  const aesAverage = data.files.length ? data.files.reduce((sum, row) => sum + row.mean_ms, 0) / data.files.length : null

  return (
    <main className="page-shell">
      <AppNavigation />
      <section className="page-heading">
        <p className="eyebrow">Phase 13 · Synthetic research measurements</p>
        <h1>Benchmarks</h1>
        <p className="scope-note">Latest completed Phase 13 export from this backend, or import another real export. Results are machine-specific synthetic measurements, not universal application latency.</p>
      </section>
      <section className="file-panel benchmark-import">
        <label htmlFor="benchmark-file">QuantumShield results.json</label>
        <input id="benchmark-file" type="file" accept=".json,application/json" onChange={loadFile} />
        {error && <p role="alert" className="form-message form-message--error">{error}</p>}
        {loading && <p role="status">Fetching benchmark results…</p>}
        {!loading && !run && <p>No benchmark results available. Run the benchmark suite from the backend CLI.</p>}
      </section>
      {run && (
        <>
          <section className="file-panel">
            <h2>Run context</h2>
            <p>Run {run.run_id} · {run.profile} · {new Date(run.timestamp).toLocaleString()}</p>
            <p>{run.environment.os} · Python {run.environment.python} · cryptography {run.environment.cryptography} · mlkem {run.environment.mlkem}</p>
            <p className="benchmark-note">{run.methodology.scope}. {run.methodology.iterations} measured iterations, {run.methodology.warmups} warmups; no outliers removed. The classical baseline is not post-quantum resistant.</p>
          </section>
          <section className="dashboard-metrics" aria-label="Benchmark highlights">
            <div className="metric-card"><span>Fastest measured KEM encapsulation</span><strong>{fastest ? `${fastest.algorithm} · ${formatMs(fastest.mean_ms)} ms` : 'No data'}</strong></div>
            <div className="metric-card"><span>Lowest approved-suite metadata overhead</span><strong>{smallest ? `${smallest.suite_id} · ${formatBytes(smallest.metadata_overhead_bytes)}` : 'No data'}</strong></div>
            <div className="metric-card"><span>Mean AES encryption across tested sizes</span><strong>{aesAverage === null ? 'No data' : `${formatMs(aesAverage)} ms`}</strong></div>
            <div className="metric-card"><span>Benchmark runs loaded</span><strong>1</strong></div>
          </section>
          <BarChart title="KEM encapsulation" rows={data.encapsulate} label="Primitive timing." />
          <BarChart title="KEM decapsulation" rows={data.decapsulate} label="Primitive timing." />
          <BarChart title="Key protection by suite" rows={data.suites} label="Crypto-only; excludes DB and HTTP." />
          <BarChart title="AES file encryption by size" rows={data.files.map((row) => ({ ...row, suite_id: formatBytes(row.file_size_bytes) }))} label="In-memory plaintext." />
          <section className="file-panel benchmark-table-wrap">
            <h2>Suite timing and key sizes</h2>
            <table className="benchmark-table">
              <thead><tr><th>Suite</th><th>PQ resistant</th><th>Mean / median / p95 (ms)</th><th>Public key</th><th>Private key</th><th>KEM ciphertext</th><th>Recipient metadata</th></tr></thead>
              <tbody>{data.suites.map((row) => <tr key={row.scenario_id}>
                <th scope="row">{row.suite_id}</th><td>{row.post_quantum_resistant ? 'Yes' : 'No'}</td>
                <td>{formatMs(row.mean_ms)} / {formatMs(row.median_ms)} / {formatMs(row.p95_ms)}</td>
                <td>{formatBytes(row.public_key_bytes)}</td><td>{formatBytes(row.private_key_bytes)}</td>
                <td>{formatBytes(row.kem_ciphertext_bytes)}</td><td>{formatBytes(row.metadata_overhead_bytes)}</td>
              </tr>)}</tbody>
            </table>
          </section>
          <section className="file-panel benchmark-table-wrap">
            <h2>File-size scaling</h2>
            <table className="benchmark-table"><thead><tr><th>File size</th><th>AES mean</th><th>Ciphertext</th><th>Total file package</th><th>Overhead</th></tr></thead>
              <tbody>{data.files.map((row) => <tr key={row.scenario_id}>
                <th scope="row">{formatBytes(row.file_size_bytes)}</th><td>{formatMs(row.mean_ms)} ms</td>
                <td>{formatBytes(row.ciphertext_bytes)}</td><td>{formatBytes(row.total_package_bytes)}</td>
                <td>{row.overhead_bytes ?? '—'} B ({typeof row.overhead_percent === 'number' ? row.overhead_percent.toFixed(2) : '—'}%)</td>
              </tr>)}</tbody></table>
          </section>
          <section className="file-panel benchmark-table-wrap">
            <h2>Multi-recipient share creation</h2>
            <p className="benchmark-note">Crypto-only creation and signing; validation happens outside the timed window. No whole-file re-encryption.</p>
            <table className="benchmark-table"><thead><tr><th>Suite</th><th>Recipients</th><th>Total mean</th><th>Per recipient</th><th>Metadata</th></tr></thead>
              <tbody>{data.shares.map((row) => <tr key={row.scenario_id}>
                <th scope="row">{row.suite_id}</th><td>{row.recipient_count}</td><td>{formatMs(row.mean_ms)} ms</td>
                <td>{formatMs(row.mean_ms / row.recipient_count)} ms</td><td>{formatBytes(row.metadata_overhead_bytes)}</td>
              </tr>)}</tbody></table>
          </section>
          <section className="file-panel benchmark-table-wrap">
            <h2>Synthetic local transfer</h2>
            <p className="benchmark-note">Includes local storage I/O and ML-DSA; excludes HTTP, authentication, and database work.</p>
            <table className="benchmark-table"><thead><tr><th>Suite</th><th>File</th><th>Operation</th><th>Mean</th><th>P95</th><th>Total package</th></tr></thead>
              <tbody>{data.transfers.map((row) => <tr key={row.scenario_id}>
                <th scope="row">{row.suite_id}</th><td>{formatBytes(row.file_size_bytes)}</td><td>{row.operation}</td>
                <td>{formatMs(row.mean_ms)} ms</td><td>{formatMs(row.p95_ms)} ms</td>
                <td>{formatBytes(row.total_package_bytes)}</td>
              </tr>)}</tbody></table>
          </section>
        </>
      )}
    </main>
  )
}
