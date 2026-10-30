import { NavLink, useNavigate } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth.js'

export default function AppNavigation() {
  const navigate = useNavigate()
  const { logout } = useAuth()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <header className="app-navigation">
      <NavLink className="app-brand" to="/dashboard">
        QuantumShield
      </NavLink>
      <nav aria-label="Primary navigation">
        <NavLink to="/dashboard">Dashboard</NavLink>
        <NavLink to="/upload">Upload File</NavLink>
        <NavLink to="/files">My Files</NavLink>
        <NavLink to="/shared-with-me">Shared With Me</NavLink>
        <NavLink to="/shared-by-me">Shared By Me</NavLink>
        <NavLink to="/security">Security</NavLink>
        <NavLink to="/benchmarks">Benchmarks</NavLink>
        <NavLink to="/adaptive-evaluation">Adaptive Evaluation</NavLink>
      </nav>
      <button type="button" onClick={handleLogout}>
        Logout
      </button>
    </header>
  )
}
