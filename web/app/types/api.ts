// Types mirroring internal/server/dto. They are hand-written rather than
// generated so the dashboard stays buildable without a codegen step; the
// OpenAPI document at /openapi.json remains the authority.

export type Role = 'admin' | 'operator' | 'viewer'
export type Status = 'active' | 'expiring' | 'expired' | 'revoked' | 'disabled'
export type Severity = 'ok' | 'warning' | 'critical' | 'expired'
export type SANType = 'dns' | 'ip' | 'email' | 'uri'
export type Profile = 'server' | 'client' | 'peer' | 'code-signing' | 'intermediate' | 'root'

export interface ApiError {
  error: string
  message?: string
  details?: Record<string, string>
}

export interface PageMeta {
  total: number
  page: number
  limit: number
  total_pages: number
}

export interface User {
  id: string
  email: string
  name: string
  role: Role
  status: string
  two_factor_enabled: boolean
  last_login_at?: string
  created_at: string
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  expires_at: string
  user: User
}

/**
 * LoginResponse carries either a session or a two-factor challenge, never
 * both. `two_factor_required` is the discriminator.
 */
export interface LoginResponse {
  two_factor_required: boolean
  challenge_token?: string
  challenge_expires_in?: number

  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  expires_at?: string
  user?: User

  used_recovery_code?: boolean
  recovery_codes_remaining?: number
}

export interface TwoFactorStatus {
  enabled: boolean
  /** A secret has been generated but never confirmed, so nothing is enforced. */
  pending: boolean
  enabled_at?: string
  recovery_codes_remaining: number
}

export interface TwoFactorSetup {
  /** The base32 shared secret, spaced for manual entry. */
  secret: string
  /** The otpauth:// URL the QR code encodes. */
  uri: string
  /** A PNG data URI, rendered by the server. */
  qr_code: string
  issuer: string
  account: string
}

export interface RecoveryCodes {
  recovery_codes: string[]
  warning: string
}

export interface Subject {
  common_name: string
  country?: string
  province?: string
  locality?: string
  organization?: string
  organizational_unit?: string
  email?: string
}

export interface SAN {
  type: SANType
  value: string
}

export interface Authority {
  id: string
  name: string
  slug: string
  type: 'root' | 'intermediate'
  parent_id?: string
  description?: string
  subject: Subject
  subject_dn: string
  key_algorithm: string
  serial_number: string
  not_before: string
  not_after: string
  days_remaining: number
  path_len_constraint?: number
  passphrase_protected: boolean
  status: Status
  fingerprint_sha256: string
  crl_url?: string
  ocsp_url?: string
  crl_number: number
  next_crl_update?: string
  certificate_count: number
  cert_pem?: string
  root_url?: string
  chain_url?: string
  created_at: string
  updated_at: string
}

export interface Certificate {
  id: string
  ca_id: string
  ca_name?: string
  common_name: string
  subject: Subject
  subject_dn: string
  profile: Profile
  key_algorithm: string
  serial_number: string
  sans: SAN[]
  key_usage: string[]
  ext_key_usage: string[]
  not_before: string
  not_after: string
  validity_days: number
  days_remaining: number
  fingerprint_sha256: string
  status: Status
  severity: Severity
  has_private_key: boolean
  key_download_count: number
  auto_renew: boolean
  renew_before_days: number
  renewed_from_id?: string
  labels: Record<string, string>
  notes?: string
  cert_pem?: string
  csr_pem?: string
  created_at: string
  updated_at: string
}

export interface IssueResult {
  certificate: Certificate
  cert_pem: string
  fullchain_pem: string
  chain_pem?: string
  private_key_pem?: string
  warning?: string
}

export interface ChainLink {
  subject: string
  issuer: string
  serial_number: string
  not_before: string
  not_after: string
  is_ca: boolean
  self_signed: boolean
  valid: boolean
  problem?: string
  days_remaining: number
  pem: string
}

export interface ChainResponse {
  links: ChainLink[]
  valid: boolean
}

export interface CountSummary {
  total: number
  active: number
  expiring: number
  expired: number
  revoked: number
}

export interface ExpiryEntry {
  id: string
  common_name: string
  ca_id: string
  ca_name: string
  not_before: string
  not_after: string
  days_remaining: number
  percent_elapsed: number
  status: Status
  severity: Severity
  auto_renew: boolean
}

export interface AuditEntry {
  id: string
  created_at: string
  actor_type: string
  actor_id?: string
  actor_name?: string
  action: string
  resource_type?: string
  resource_id?: string
  resource_name?: string
  metadata?: Record<string, unknown>
  ip?: string
  success: boolean
  error?: string
}

export interface Job {
  id: string
  kind: string
  status: string
  payload?: Record<string, unknown>
  result?: Record<string, unknown>
  error?: string
  started_at?: string
  finished_at?: string
  created_at: string
}

export interface DashboardStats {
  authorities: CountSummary
  certificates: CountSummary
  expiring_soon: ExpiryEntry[]
  timeline: ExpiryEntry[]
  revocations: number
  by_profile: Record<string, number>
  recent_activity: AuditEntry[]
  last_job?: Job
  generated_at: string
}

export interface ProfileInfo {
  name: string
  description: string
  key_usage: string[]
  ext_key_usage: string[]
  default_validity_days: number
  is_ca: boolean
}

export interface Meta {
  profiles: ProfileInfo[]
  key_algorithms: string[]
  export_formats: string[]
  revocation_reasons: { code: number; name: string }[]
  san_types: SANType[]
  max_leaf_validity_days: number
  key_download_policy: 'once' | 'always' | 'never'
  version: string
}

export interface TrustInstruction {
  platform: string
  title: string
  commands: string
  note?: string
}

export interface TrustGuide {
  authority: Authority
  root_url: string
  chain_url: string
  crl_url: string
  fingerprint_sha256: string
  instructions: TrustInstruction[]
}

export interface ApiToken {
  id: string
  name: string
  user_id: string
  prefix: string
  scopes: string[]
  expires_at?: string
  last_used_at?: string
  revoked_at?: string
  created_at: string
}

export interface TokenScope {
  name: string
  description: string
}

export interface NameConstraints {
  permitted_dns?: string[]
  excluded_dns?: string[]
  permitted_ip?: string[]
  excluded_ip?: string[]
  permitted_email?: string[]
  excluded_email?: string[]
  permitted_uri?: string[]
  excluded_uri?: string[]
}

export interface DeploymentTarget {
  id: string
  name: string
  kind: 'kubernetes' | 'ssh' | 'webhook'
  selector?: Record<string, string>
  common_name?: string
  enabled: boolean
  last_run_at?: string
  last_success_at?: string
  last_error?: string
  last_serial?: string
  created_at: string
}

export interface DeployResult {
  target_id: string
  target_name: string
  kind: string
  destination: string
  certificate?: string
  skipped: boolean
  error?: string
}

export interface ExternalAccount {
  id: string
  kid: string
  description?: string
  allowed_domains?: string[]
  enabled: boolean
  expires_at?: string
  last_used_at?: string
  created_at: string
}

export interface AcmeAccount {
  id: string
  key_thumbprint: string
  contact?: string[]
  status: string
  external_account_id?: string
  last_used_at?: string
  created_at: string
}

export interface Notification {
  id: string
  name: string
  channel: 'webhook' | 'smtp' | 'slack' | 'telegram'
  events: string[]
  enabled: boolean
  last_sent_at?: string
  last_error?: string
  created_at: string
}

export interface Settings {
  default_organization: string
  default_country: string
  default_key_algorithm: string
  default_validity_days: number
  expiry_warn_days: number
  key_download_policy: string
  base_url: string
  scheduler_enabled: boolean
}

export interface BulkResult {
  id: string
  success: boolean
  new_id?: string
  error?: string
}

export interface BulkResponse {
  succeeded: number
  failed: number
  results: BulkResult[]
}

export interface CertificateDetails {
  kind: string
  subject: Subject
  subject_dn: string
  issuer: Subject
  issuer_dn: string
  serial_number: string
  not_before: string
  not_after: string
  days_remaining: number
  expired: boolean
  self_signed: boolean
  is_ca: boolean
  max_path_len?: number
  sans: SAN[]
  key_algorithm: string
  key_size?: number
  signature_algorithm: string
  key_usage: string[]
  ext_key_usage: string[]
  fingerprint_sha256: string
  fingerprint_sha1: string
  subject_key_id?: string
  authority_key_id?: string
  crl_distribution_points?: string[]
  ocsp_servers?: string[]
  profile: string
  pem: string
}

export interface InspectResult {
  kind: 'certificate' | 'csr' | 'private_key' | 'crl' | 'public_key'
  certificate?: CertificateDetails
  csr?: {
    subject: Subject
    sans: SAN[]
    key_algorithm: string
    key_size?: number
    signature_algorithm: string
    dn: string
  }
  key?: { kind: string; key_algorithm: string; key_size?: number; public_key_pem: string }
  crl?: {
    kind: string
    issuer: string
    number: string
    this_update: string
    next_update: string
    entries: { serial_number: string; revoked_at: string; reason: string; reason_code: number }[]
  }
  chain?: CertificateDetails[]
}

export interface About {
  name: string
  tagline: string
  description: string

  version: string
  commit?: string
  build_date?: string
  go_version: string
  platform: string

  license: string
  license_url: string
  repository: string
  documentation: string
  issues_url: string

  started_at: string
  uptime: string

  instance: {
    base_url?: string
    database_driver: string
    tls: boolean
    docs_enabled: boolean
    scheduler_enabled: boolean
    key_download_policy: string
    expiry_warn_days: number
    access_token_ttl: string
    refresh_token_ttl: string
  }
}
