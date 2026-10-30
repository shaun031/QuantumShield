import { useCallback, useEffect, useMemo, useState } from 'react'

import { api } from '../services/api.js'
import {
  clearAccessToken,
  getAccessToken,
  setAccessToken as persistAccessToken,
} from '../services/tokenStorage.js'
import { AuthContext } from './authContext.js'

export default function AuthProvider({ children }) {
  const [accessToken, setAccessToken] = useState(() => getAccessToken())
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(Boolean(accessToken))
  const [sessionExpired, setSessionExpired] = useState(false)

  const logout = useCallback(() => {
    clearAccessToken()
    setAccessToken(null)
    setUser(null)
    setLoading(false)
  }, [])

  const expireSession = useCallback(() => {
    setSessionExpired(true)
    logout()
  }, [logout])

  useEffect(() => {
    window.addEventListener('quantumshield:session-expired', expireSession)
    return () => window.removeEventListener('quantumshield:session-expired', expireSession)
  }, [expireSession])

  useEffect(() => {
    let active = true

    if (!accessToken) {
      setUser(null)
      setLoading(false)
      return () => {
        active = false
      }
    }

    setLoading(true)
    api
      .getCurrentUser(accessToken)
      .then((currentUser) => {
        if (active) setUser(currentUser)
      })
      .catch(() => {
        if (active) logout()
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [accessToken, logout])

  const login = useCallback(async (credentials) => {
    const tokenResponse = await api.login(credentials)
    const currentUser = await api.getCurrentUser(tokenResponse.access_token)
    setSessionExpired(false)
    persistAccessToken(tokenResponse.access_token)
    setAccessToken(tokenResponse.access_token)
    setUser(currentUser)
    setLoading(false)
    return currentUser
  }, [])

  const register = useCallback((registration) => api.register(registration), [])

  const value = useMemo(
    () => ({
      accessToken,
      user,
      loading,
      isAuthenticated: Boolean(accessToken && user),
      sessionExpired,
      login,
      logout,
      register,
    }),
    [accessToken, loading, login, logout, register, sessionExpired, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

