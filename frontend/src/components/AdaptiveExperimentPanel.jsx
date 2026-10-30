import { useEffect, useState } from 'react'
import { api } from '../services/api.js'

function ms(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(3) : '—'
}

function pct(value) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(2)}%` : '—'
}

function size(bytes) {
  return typeof bytes === 'number' && Number.isFinite(bytes) ? `${bytes.toLocaleString()} B` : '—'
}

function PairBars({ row, max }) {
  const adaptive = row.crypto_total.adaptive.mean_ms
  const fixed = row.crypto_total.fixed_high.mean_ms
  return (
    <div className="experiment-pair-bars" aria-label={`${row.scenario_id}: adaptive ${ms(adaptive)} milliseconds, fixed ${ms(fixed)} milliseconds`}>
      <div><span>Adaptive</span><div className="benchmark-bar-track"><div style={{ width: `${max ? adaptive / max * 100 : 0}%` }} /></div><strong>{ms(adaptive)}</strong></div>
      <div><span>Fixed HIGH</span><div className="benchmark-bar-track"><div style={{ width: `${max ? fixed / max * 100 : 0}%` }} /></div><strong>{ms(fixed)}</strong></div>
    </div>
  )
}

function SavingsBar({ value, scale }) {
  const width = Math.min(50, Math.abs(value) / scale * 50)
  const left = value < 0 ? 50 - width : 50
  return (
    <div className="experiment-savings-track" aria-label={`Time savings ${pct(value)}`}>
      <span className="experiment-savings-zero" />
      <span className={`experiment-savings-fill ${value < 0 ? 'experiment-savings-fill--negative' : ''}`}
        style={{ left: `${left}%`, width: `${width}%` }} />
    </div>
  )
}

export default function AdaptiveExperimentPanel() {
  const [experiment, setExperiment] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    api.getLatestAdaptiveExperiment().then((latest) => { if (active) setExperiment(latest) })
      .catch((caught) => { if (active && caught.status !== 404) setError(caught.message) })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  async function loadExperiment(event) {
    setExperiment(null)
    setError('')
    const file = event.target.files?.[0]
    if (!file) return
    if (file.size > 20 * 1024 * 1024) {
      setError('The experiment JSON file must be 20 MB or smaller.')
      return
    }
    try {
      const parsed = JSON.parse(await file.text())
      if (parsed.experiment_schema_version !== 1 || parsed.status !== 'COMPLETED' ||
          !Array.isArray(parsed.comparisons) || !parsed.aggregate?.overall ||
          !parsed.aggregate?.by_architecture || typeof parsed.experiment_run_id !== 'string' ||
          parsed.comparisons.some((row) => typeof row.scenario_id !== 'string' ||
            typeof row.crypto_total?.adaptive?.mean_ms !== 'number' ||
            typeof row.crypto_total?.fixed_high?.mean_ms !== 'number' ||
            !Number.isFinite(row.crypto_total.adaptive.mean_ms) ||
            !Number.isFinite(row.crypto_total.fixed_high.mean_ms) ||
            !Number.isFinite(row.crypto_total.savings_percent) ||
            !Number.isFinite(row.metadata_bytes?.adaptive) ||
            !Number.isFinite(row.metadata_bytes?.fixed_high) ||
            !Number.isFinite(row.metadata_bytes?.savings_percent)) ||
          Object.values(parsed.aggregate.by_architecture).some((group) => !group ||
            !Number.isFinite(group.adaptive_mean_crypto_ms) ||
            !Number.isFinite(group.fixed_mean_crypto_ms))) {
        throw new Error('This is not a complete Phase 14 experiment export.')
      }
      setExperiment(parsed)
    } catch (caught) {
      setError(caught.message || 'The experiment file could not be read.')
    }
  }

  const overall = experiment?.aggregate.overall
  const maxTime = experiment?.comparisons.reduce((maximum, row) => Math.max(maximum,
    row.crypto_total.adaptive.mean_ms, row.crypto_total.fixed_high.mean_ms), 0) || 0
  const maxSavings = experiment?.comparisons.reduce((maximum, row) => Math.max(maximum,
    Math.abs(row.crypto_total.savings_percent)), 1) || 1
  const sizeGroups = Object.entries(experiment?.aggregate.by_architecture_and_file_size || {})

  return (
    <section className="experiment-section" aria-labelledby="experiment-title">
      <div className="page-heading">
        <p className="eyebrow">Phase 14 · Paired synthetic evaluation</p>
        <h1 id="experiment-title">Adaptive vs Fixed HIGH</h1>
        <p className="scope-note">Latest completed Phase 14 run from this backend, or import another completed export. This page never starts or changes measurements.</p>
      </div>
      <div className="file-panel benchmark-import">
        <label htmlFor="experiment-file">adaptive_vs_fixed.json</label>
        <input id="experiment-file" type="file" accept=".json,application/json" onChange={loadExperiment} />
        {error && <p role="alert" className="form-message form-message--error">{error}</p>}
        {loading && <p role="status">Fetching adaptive evaluation results…</p>}
        {!loading && !experiment && <p>Run Phase 14 experiment to generate results.</p>}
      </div>
      {experiment && <>
        <div className="file-panel">
          <h3>Run context</h3>
          <p>{experiment.experiment_run_id} · {experiment.profile} · dataset {experiment.scenario_dataset_version} · policy {experiment.adaptive_policy_version}</p>
          <p>Phase 13 reference: {experiment.phase13_reference?.run_id || 'unavailable'} · {experiment.methodology?.iterations} measured pairs per scenario · {experiment.methodology?.warmups} warmups</p>
          <p className="benchmark-note">{experiment.methodology?.scope}. Positive savings favor Adaptive; negative savings mean Adaptive was slower. Crypto time is the sum of timed stages, not HTTP request latency.</p>
        </div>
        <div className="experiment-summary-grid">
          <div className="file-panel"><h3>Mean crypto time savings</h3><p className="experiment-number">{pct(overall.time_savings_percent)}</p><p>{ms(overall.adaptive_mean_crypto_ms)} vs {ms(overall.fixed_mean_crypto_ms)} ms</p></div>
          <div className="file-panel"><h3>Metadata savings</h3><p className="experiment-number">{pct(overall.metadata_savings_percent)}</p><p>{size(overall.adaptive_metadata_bytes)} vs {size(overall.fixed_metadata_bytes)}</p></div>
          <div className="file-panel"><h3>Policy compliance</h3><p className="experiment-number">{pct(overall.policy_compliance_rate * 100)}</p><p>{overall.scenario_count} paired scenarios</p></div>
        </div>
        <section className="file-panel dashboard-section"><h3>Research summary</h3>
          <p>The adaptive policy selected {Object.entries(experiment.aggregate.adaptive_level_distribution || {}).map(([level, item]) => `${level} in ${pct(item.percent)} of scenarios`).join(', ')}.</p>
          <p>Compared with Fixed HIGH, mean crypto time changed by {pct(overall.time_savings_percent)} and metadata by {pct(overall.metadata_savings_percent)}. Positive savings favor Adaptive; negative values mean Adaptive was slower.</p>
          <p className="benchmark-note">These are synthetic measurements from this run’s environment. Small or negative differences should not be generalized.</p>
        </section>
        {overall.policy_compliance_rate < 1 && <p role="alert" className="form-message form-message--error">Policy compliance is below 100%. Do not interpret efficiency results as valid.</p>}
        <div className="file-panel benchmark-table-wrap">
          <h3>Architecture-specific comparison</h3>
          <table className="benchmark-table"><thead><tr><th>Architecture</th><th>Scenarios</th><th>Adaptive mean</th><th>Fixed mean</th><th>Time savings</th><th>Metadata savings</th></tr></thead>
            <tbody>{Object.entries(experiment.aggregate.by_architecture).map(([name, group]) => <tr key={name}>
              <th scope="row">{name}</th><td>{group.scenario_count}</td><td>{ms(group.adaptive_mean_crypto_ms)} ms</td>
              <td>{ms(group.fixed_mean_crypto_ms)} ms</td><td>{pct(group.time_savings_percent)}</td>
              <td>{pct(group.metadata_savings_percent)}</td>
            </tr>)}</tbody></table>
        </div>
        <div className="file-panel benchmark-table-wrap">
          <h3>Adaptive level and suite distribution</h3>
          <div className="benchmark-bars">
            {Object.entries(experiment.aggregate.adaptive_level_distribution || {}).map(([level, item]) =>
              <div className="benchmark-bar-row" key={level}><span>{level}</span><div className="benchmark-bar-track" role="img" aria-label={`${level}: ${item.count} scenarios, ${pct(item.percent)}`}><div style={{ width: `${item.percent}%` }} /></div><strong>{pct(item.percent)}</strong></div>)}
          </div>
          <table className="benchmark-table"><thead><tr><th>Level</th><th>Scenarios</th><th>Share</th><th>Mean time savings</th><th>Metadata savings</th></tr></thead>
            <tbody>{Object.entries(experiment.aggregate.adaptive_level_distribution || {}).map(([level, item]) => <tr key={level}>
              <th scope="row">{level}</th><td>{item.count}</td><td>{pct(item.percent)}</td>
              <td>{pct(experiment.aggregate.by_adaptive_level?.[level]?.time_savings_percent)}</td>
              <td>{pct(experiment.aggregate.by_adaptive_level?.[level]?.metadata_savings_percent)}</td>
            </tr>)}</tbody></table>
          <p className="benchmark-note">Suites: {Object.entries(experiment.aggregate.adaptive_suite_distribution || {}).map(([name, count]) => `${name}: ${count}`).join(' · ')}</p>
        </div>
        <div className="file-panel benchmark-table-wrap">
          <h3>Paired scenario timing</h3>
          <p className="benchmark-note">Mean crypto time (ms); both bars start at zero. Savings use a separate zero-centered scale.</p>
          {experiment.comparisons.map((row) => <div className="experiment-scenario" key={row.scenario_id}>
            <div><strong>{row.scenario_id}</strong><span>{row.adaptive_level} · {row.adaptive_suite} vs {row.fixed_suite} · {row.recipient_count} recipient(s)</span></div>
            <PairBars row={row} max={maxTime} />
            <div className="experiment-savings"><span>Time savings {pct(row.crypto_total.savings_percent)}</span><SavingsBar value={row.crypto_total.savings_percent} scale={maxSavings} /></div>
            <p>Metadata: {size(row.metadata_bytes.adaptive)} vs {size(row.metadata_bytes.fixed_high)} ({pct(row.metadata_bytes.savings_percent)} savings)</p>
          </div>)}
        </div>
        <div className="file-panel benchmark-table-wrap">
          <h3>Scenario comparison</h3>
          <table className="benchmark-table"><thead><tr><th>Scenario</th><th>Architecture</th><th>Level</th><th>Adaptive suite</th><th>Fixed suite</th><th>Adaptive time</th><th>Fixed time</th><th>Savings</th><th>Policy</th></tr></thead><tbody>
            {experiment.comparisons.map((row) => <tr key={row.scenario_id}><th scope="row">{row.scenario_id}</th><td>{row.architecture}</td><td>{row.adaptive_level}</td><td>{row.adaptive_suite}</td><td>{row.fixed_suite}</td><td>{ms(row.crypto_total.adaptive.mean_ms)} ms</td><td>{ms(row.crypto_total.fixed_high.mean_ms)} ms</td><td>{pct(row.crypto_total.savings_percent)}</td><td>{row.policy_compliant ? 'Compliant' : 'Not compliant'}</td></tr>)}
          </tbody></table>
        </div>
        <div className="file-panel benchmark-table-wrap"><h3>Metadata bytes by scenario</h3>
          <p className="benchmark-note">Measured bytes; paired bars share a zero-based scale within each scenario.</p>
          {experiment.comparisons.map((row) => {
            const maximum = Math.max(row.metadata_bytes.adaptive, row.metadata_bytes.fixed_high)
            return <div className="experiment-scenario" key={row.scenario_id}>
              <strong>{row.scenario_id}</strong>
              <div className="experiment-pair-bars" aria-label={`${row.scenario_id} metadata: adaptive ${row.metadata_bytes.adaptive} bytes, fixed ${row.metadata_bytes.fixed_high} bytes`}>
                <div><span>Adaptive</span><div className="benchmark-bar-track"><div style={{ width: `${maximum ? row.metadata_bytes.adaptive / maximum * 100 : 0}%` }} /></div><strong>{size(row.metadata_bytes.adaptive)}</strong></div>
                <div><span>Fixed HIGH</span><div className="benchmark-bar-track"><div style={{ width: `${maximum ? row.metadata_bytes.fixed_high / maximum * 100 : 0}%` }} /></div><strong>{size(row.metadata_bytes.fixed_high)}</strong></div>
              </div>
            </div>
          })}
          <table className="benchmark-table"><thead><tr><th>Scenario</th><th>Adaptive</th><th>Fixed HIGH</th><th>Savings</th></tr></thead><tbody>
            {experiment.comparisons.map((row) => <tr key={row.scenario_id}><th scope="row">{row.scenario_id}</th><td>{size(row.metadata_bytes.adaptive)}</td><td>{size(row.metadata_bytes.fixed_high)}</td><td>{pct(row.metadata_bytes.savings_percent)}</td></tr>)}
          </tbody></table>
        </div>
        <div className="file-panel benchmark-table-wrap">
          <h3>File-size scaling, by architecture</h3>
          <table className="benchmark-table"><thead><tr><th>Architecture</th><th>File size</th><th>Scenarios</th><th>Adaptive mean</th><th>Fixed mean</th><th>Savings</th></tr></thead>
            <tbody>{sizeGroups.map(([key, group]) => {
              const [architecture, bytes] = key.split(':')
              return <tr key={key}><th scope="row">{architecture}</th><td>{size(Number(bytes))}</td>
                <td>{group.scenario_count}</td><td>{ms(group.adaptive_mean_crypto_ms)} ms</td>
                <td>{ms(group.fixed_mean_crypto_ms)} ms</td><td>{pct(group.time_savings_percent)}</td></tr>
            })}</tbody></table>
        </div>
      </>}
    </section>
  )
}
