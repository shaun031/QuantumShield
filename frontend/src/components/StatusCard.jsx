const stateLabels = {
  checking: 'Checking…',
  online: 'Online',
  connected: 'Connected',
  configured: 'Available',
  offline: 'Offline',
  unavailable: 'Unavailable',
}

export default function StatusCard({ label, state }) {
  const displayState = stateLabels[state] ?? 'Unknown'

  return (
    <article className={`status-card status-card--${state}`}>
      <span className="status-card__label">{label}</span>
      <span className="status-card__value">
        <span className="status-card__dot" aria-hidden="true" />
        {displayState}
      </span>
    </article>
  )
}

