import { getAccessToken } from './tokenStorage.js'

const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000/api'

export const API_BASE_URL = (
  import.meta.env?.VITE_API_BASE_URL || DEFAULT_API_BASE_URL
).replace(/\/$/, '')

export class ApiError extends Error {
  constructor(message, status = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request(path, options = {}) {
  const {
    acceptableStatuses = [200],
    headers = {},
    responseType = 'json',
    token = getAccessToken(),
    ...fetchOptions
  } = options

  let response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...fetchOptions,
      headers: {
        Accept: 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
    })
  } catch {
    throw new ApiError('The backend is unavailable.')
  }

  if (!acceptableStatuses.includes(response.status)) {
    if (response.status === 401 && token && path !== '/auth/login') {
      window.dispatchEvent(new Event('quantumshield:session-expired'))
      throw new ApiError('Your session expired. Please sign in again.', 401)
    }
    let payload = null
    try {
      payload = await response.json()
    } catch {
      // A malformed or empty response is handled by the generic safe error below.
    }
    const message =
      typeof payload?.detail === 'string'
        ? payload.detail
        : 'The request could not be completed.'
    throw new ApiError(message, response.status)
  }

  if (responseType === 'blob') {
    return {
      blob: await response.blob(),
      contentDisposition: response.headers.get('Content-Disposition'),
    }
  }

  if (response.status === 204) return null

  try {
    return await response.json()
  } catch {
    throw new ApiError('The backend returned an invalid response.', response.status)
  }
}

function filenameFromContentDisposition(value) {
  const encoded = value?.match(/filename\*=utf-8''([^;]+)/i)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded)
    } catch {
      // Continue to the quoted filename fallback.
    }
  }
  return value?.match(/filename="?([^";]+)"?/i)?.[1] || 'download'
}

export const api = {
  getDashboardSummary() {
    return request('/dashboard/summary')
  },

  getFileShareCounts(fileIds) {
    if (!fileIds.length) return Promise.resolve({})
    return request(`/dashboard/file-share-counts?${fileIds.map((id) => `file_ids=${encodeURIComponent(id)}`).join('&')}`)
  },

  getLatestBenchmark() {
    return request('/research/benchmarks/latest')
  },

  getLatestAdaptiveExperiment() {
    return request('/research/adaptive/latest')
  },

  register(registration) {
    return request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registration),
      acceptableStatuses: [201],
      token: null,
    })
  },

  login(credentials) {
    return request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
      token: null,
    })
  },

  getCurrentUser(token) {
    return request('/users/me', { token })
  },

  searchUsers(query, limit = 10) {
    return request(
      `/users/search?q=${encodeURIComponent(query)}&limit=${encodeURIComponent(limit)}`,
    )
  },

  getSystemStatus() {
    return request('/system/status', {
      acceptableStatuses: [200, 503],
      token: null,
    })
  },

  getMyCryptoKey() {
    return request('/crypto/keys/me')
  },

  getCryptoAlgorithms() {
    return request('/crypto/algorithms')
  },

  getCryptoSuites() {
    return request('/crypto/suites')
  },

  getSecurityOptions() {
    return request('/security/options')
  },

  recommendSecurity(assessment) {
    return request('/security/recommend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(assessment),
    })
  },

  ensureCryptoKeys() {
    return request('/crypto/keys/ensure', { method: 'POST' })
  },

  uploadFile(file, security = { selection_mode: 'MANUAL', security_level: 'STANDARD' }) {
    const decision =
      typeof security === 'string'
        ? { selection_mode: 'MANUAL', security_level: security }
        : security
    const body = new FormData()
    body.append('file', file)
    body.append('selection_mode', decision.selection_mode || 'MANUAL')
    body.append('security_architecture', decision.security_architecture || 'PQ_ONLY')
    if (decision.security_level) body.append('security_level', decision.security_level)
    if (decision.sensitivity) body.append('sensitivity', decision.sensitivity)
    if (decision.document_category) {
      body.append('document_category', decision.document_category)
    }
    return request('/files/upload', {
      method: 'POST',
      body,
      acceptableStatuses: [201],
    })
  },

  getMyFiles({ limit = 100, offset = 0 } = {}) {
    return request(`/files?limit=${limit}&offset=${offset}`)
  },

  getFile(fileId) {
    return request(`/files/${encodeURIComponent(fileId)}`)
  },

  getFileSecurityDecision(fileId) {
    return request(`/files/${encodeURIComponent(fileId)}/security-decision`)
  },

  verifyFile(fileId) {
    return request(`/files/${encodeURIComponent(fileId)}/verify`)
  },

  shareFile(fileId, recipientId) {
    return request(`/files/${encodeURIComponent(fileId)}/share`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient_id: recipientId }),
      acceptableStatuses: [201],
    })
  },

  getReceivedShares({ limit = 100, offset = 0 } = {}) {
    return request(`/shares/received?limit=${limit}&offset=${offset}`)
  },

  getSentShares({ limit = 100, offset = 0 } = {}) {
    return request(`/shares/sent?limit=${limit}&offset=${offset}`)
  },

  getShare(shareId) {
    return request(`/shares/${encodeURIComponent(shareId)}`)
  },

  verifyShare(shareId) {
    return request(`/shares/${encodeURIComponent(shareId)}/verify`)
  },

  revokeShare(shareId, reason = null) {
    return request(`/shares/${encodeURIComponent(shareId)}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    })
  },

  async downloadSharedFile(shareId) {
    const result = await request(
      `/shares/${encodeURIComponent(shareId)}/download`,
      { responseType: 'blob' },
    )
    return {
      blob: result.blob,
      filename: filenameFromContentDisposition(result.contentDisposition),
    }
  },

  async downloadFile(fileId) {
    const result = await request(
      `/files/${encodeURIComponent(fileId)}/download`,
      { responseType: 'blob' },
    )
    return {
      blob: result.blob,
      filename: filenameFromContentDisposition(result.contentDisposition),
    }
  },

  deleteFile(fileId) {
    return request(`/files/${encodeURIComponent(fileId)}`, {
      method: 'DELETE',
      acceptableStatuses: [204],
    })
  },
}

