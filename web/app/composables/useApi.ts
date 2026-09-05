import type { ApiError } from '~/types/api'

/**
 * ApiRequestError carries the parsed backend error so callers can branch on
 * the machine-readable code rather than matching on message text.
 */
export class ApiRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, string>,
  ) {
    super(message)
    this.name = 'ApiRequestError'
  }

  /** The CA needs a passphrase before this request can proceed. */
  get needsPassphrase(): boolean {
    return this.status === 428 || this.code === 'passphrase_required'
  }

  get isUnauthorized(): boolean {
    return this.status === 401
  }

  get isForbidden(): boolean {
    return this.status === 403
  }
}

/**
 * useApi returns a thin typed wrapper around $fetch that attaches the bearer
 * token, normalises errors and signs the user out on a 401.
 */
export function useApi() {
  const config = useRuntimeConfig()
  const base = config.public.apiBase as string

  async function request<T>(path: string, options: Record<string, unknown> = {}): Promise<T> {
    const auth = useAuthStore()

    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...((options.headers as Record<string, string>) ?? {}),
    }
    if (auth.accessToken) {
      headers.Authorization = `Bearer ${auth.accessToken}`
    }

    try {
      return await $fetch<T>(`${base}${path}`, {
        ...options,
        headers,
        // The session cookie is the fallback when the in-memory token is gone
        // after a page reload.
        credentials: 'include',
      })
    } catch (err: unknown) {
      throw toApiError(err, auth)
    }
  }

  /**
   * download fetches a binary export and hands the browser a file. It bypasses
   * the JSON wrapper because these endpoints return PEM, DER, ZIP or PKCS#12.
   */
  async function download(path: string, filename?: string): Promise<void> {
    const auth = useAuthStore()

    const res = await fetch(`${base}${path}`, {
      headers: auth.accessToken ? { Authorization: `Bearer ${auth.accessToken}` } : {},
      credentials: 'include',
    })

    if (!res.ok) {
      let payload: ApiError = { error: 'download_failed' }
      try {
        payload = (await res.json()) as ApiError
      } catch {
        // A non-JSON error body is still an error; fall through to the default.
      }
      throw new ApiRequestError(
        res.status,
        payload.error ?? 'download_failed',
        payload.message ?? `download failed with status ${res.status}`,
      )
    }

    const blob = await res.blob()
    const name = filename ?? filenameFromDisposition(res.headers.get('Content-Disposition')) ?? 'download'

    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = name
    document.body.appendChild(link)
    link.click()
    link.remove()
    // Revoking immediately can cancel the download in some browsers.
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return {
    get: <T>(path: string, query?: Record<string, unknown>) =>
      request<T>(path, { method: 'GET', query: pruneEmpty(query) }),
    post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
    put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
    patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
    del: <T>(path: string, query?: Record<string, unknown>) =>
      request<T>(path, { method: 'DELETE', query: pruneEmpty(query) }),
    download,
    base,
  }
}

/** toApiError normalises anything $fetch throws into an ApiRequestError. */
function toApiError(err: unknown, auth: ReturnType<typeof useAuthStore>): ApiRequestError {
  const e = err as { status?: number; statusCode?: number; data?: ApiError; message?: string }
  const status = e.status ?? e.statusCode ?? 0
  const payload = e.data

  if (status === 401) {
    // clearSession, not logout: logout() calls the API, which would 401 again.
    auth.clearSession()
    if (import.meta.client && !window.location.pathname.startsWith('/login')) {
      navigateTo('/login')
    }
  }

  return new ApiRequestError(
    status,
    payload?.error ?? 'request_failed',
    payload?.message ?? e.message ?? 'the request failed',
    payload?.details,
  )
}

/** pruneEmpty drops undefined, null and '' so they never reach the query string. */
function pruneEmpty(query?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!query) return undefined
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      out[key] = value
    }
  }
  return out
}

/** filenameFromDisposition reads the server-suggested download name. */
function filenameFromDisposition(header: string | null): string | undefined {
  if (!header) return undefined
  const match = /filename="?([^";]+)"?/.exec(header)
  return match?.[1]
}
