import { Navigate, Outlet, useLocation } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth.js'

export default function ProtectedRoute() {
  const { isAuthenticated, loading, sessionExpired } = useAuth()
  const location = useLocation()

  if (loading) {
    return <main className="loading-screen">Restoring your session…</main>
  }

  return isAuthenticated ? (
    <Outlet />
  ) : (
    <Navigate to="/login" replace state={{
      from: location.pathname,
      ...(sessionExpired ? { message: 'Your session expired. Please sign in again.' } : {}),
    }} />
  )
}

