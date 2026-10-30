import { Navigate, Outlet } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth.js'

export default function PublicOnlyRoute() {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return <main className="loading-screen">Restoring your session…</main>
  }

  return isAuthenticated ? <Navigate to="/dashboard" replace /> : <Outlet />
}

