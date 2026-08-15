import type { Severity } from '~/types/api'

/**
 * useFormat holds the presentation rules shared across pages, so a status
 * colour or a date format is defined once rather than in every template.
 */
export function useFormat() {
  const dateFormatter = new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
  const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })

  function date(value?: string | null): string {
    if (!value) return '—'
    return dateFormatter.format(new Date(value))
  }

  function dateTime(value?: string | null): string {
    if (!value) return '—'
    return dateTimeFormatter.format(new Date(value))
  }

  /** relative renders "in 12 days" / "3 hours ago" without a date library. */
  function relative(value?: string | null): string {
    if (!value) return '—'
    const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
    const diffMs = new Date(value).getTime() - Date.now()
    const units: [Intl.RelativeTimeFormatUnit, number][] = [
      ['year', 365 * 24 * 3600e3],
      ['month', 30 * 24 * 3600e3],
      ['day', 24 * 3600e3],
      ['hour', 3600e3],
      ['minute', 60e3],
    ]
    for (const [unit, ms] of units) {
      if (Math.abs(diffMs) >= ms) {
        return rtf.format(Math.round(diffMs / ms), unit)
      }
    }
    return rtf.format(Math.round(diffMs / 1000), 'second')
  }

  /** days renders a remaining-days count, made readable when it is negative. */
  function days(remaining: number): string {
    if (remaining < 0) return `expired ${Math.abs(remaining)}d ago`
    if (remaining === 0) return 'expires today'
    return `${remaining}d`
  }

  /** severityClass maps a severity onto the badge variant. */
  function severityClass(severity: Severity): string {
    switch (severity) {
      case 'ok': return 'badge-success'
      case 'warning': return 'badge-warning'
      case 'critical': return 'badge-danger'
      default: return 'badge-neutral'
    }
  }

  /** statusClass maps a lifecycle status onto the badge variant. */
  function statusClass(status: string): string {
    switch (status) {
      case 'active': return 'badge-success'
      case 'expiring': return 'badge-warning'
      case 'expired': return 'badge-neutral'
      case 'revoked': return 'badge-danger'
      case 'disabled': return 'badge-neutral'
      default: return 'badge-secondary'
    }
  }

  /** shortFingerprint keeps a 64-character hex digest readable in a table. */
  function shortFingerprint(value?: string): string {
    if (!value) return '—'
    return value.length > 20 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value
  }

  /** initials builds the two-letter avatar label. */
  function initials(value?: string): string {
    if (!value) return '?'
    const cleaned = value.replace(/^\*\./, '')
    const parts = cleaned.split(/[\s@.-]+/).filter(Boolean)
    if (parts.length === 0) return '?'
    if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase()
    return (parts[0]![0]! + parts[1]![0]!).toUpperCase()
  }

  /** actionLabel turns an audit action code into readable text. */
  function actionLabel(action: string): string {
    const map: Record<string, string> = {
      'auth.login': 'signed in',
      'auth.login_failed': 'failed sign-in',
      'auth.logout': 'signed out',
      'auth.token_issued': 'issued an API token',
      'auth.token_revoked': 'revoked an API token',
      'auth.2fa_enabled': 'enabled two-factor authentication',
      'auth.2fa_disabled': 'disabled two-factor authentication',
      'auth.2fa_failed': 'failed a two-factor check',
      'auth.2fa_reset': 'reset an account’s two-factor authentication',
      'auth.recovery_code_used': 'signed in with a recovery code',
      'auth.recovery_codes_renewed': 'issued new recovery codes',
      'ca.create': 'created a CA',
      'ca.import': 'imported a CA',
      'ca.update': 'updated a CA',
      'ca.delete': 'deleted a CA',
      'ca.renew': 'renewed a CA',
      'ca.crl_issued': 'published a CRL',
      'cert.issue': 'issued a certificate',
      'cert.sign_csr': 'signed a CSR',
      'cert.renew': 'renewed a certificate',
      'cert.revoke': 'revoked a certificate',
      'cert.delete': 'deleted a certificate',
      'cert.update': 'updated a certificate',
      'cert.key_download': 'downloaded a private key',
      'cert.key_download_denied': 'was denied a key download',
      'user.create': 'created an account',
      'user.update': 'updated an account',
      'user.delete': 'deleted an account',
      'setting.update': 'changed settings',
    }
    return map[action] ?? action
  }

  return {
    date, dateTime, relative, days,
    severityClass, statusClass, shortFingerprint, initials, actionLabel,
  }
}
