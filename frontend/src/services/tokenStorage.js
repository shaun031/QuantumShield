const ACCESS_TOKEN_KEY = 'quantumshield.access_token'

function browserStorage() {
  return typeof window === 'undefined' ? null : window.sessionStorage
}

export function getAccessToken() {
  return browserStorage()?.getItem(ACCESS_TOKEN_KEY) ?? null
}

export function setAccessToken(token) {
  browserStorage()?.setItem(ACCESS_TOKEN_KEY, token)
}

export function clearAccessToken() {
  browserStorage()?.removeItem(ACCESS_TOKEN_KEY)
}

