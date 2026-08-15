<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useAuthStore } from '~/stores/auth'
import { useToast } from '~/composables/useToast'
import { ApiRequestError } from '~/composables/useApi'
import type { Certificate, ChainResponse, IssueResult } from '~/types/api'

const route = useRoute()
const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { date, dateTime, days, statusClass } = useFormat()

const id = computed(() => route.params.id as string)

const cert = ref<Certificate | null>(null)
const chain = ref<ChainResponse | null>(null)
const history = ref<Certificate[]>([])
const loading = ref(true)
const tab = ref<'overview' | 'chain' | 'pem' | 'history'>('overview')

const renewOpen = ref(false)
const revokeOpen = ref(false)
const deleteOpen = ref(false)
const busy = ref(false)

const renewForm = ref({ rekey: false, validity_days: 0, ca_passphrase: '' })
const revokeForm = ref({ reason_code: 4, ca_passphrase: '' })

useHead(() => ({ title: cert.value ? `${cert.value.common_name} · Certio` : 'Certificate · Certio' }))

async function load() {
  loading.value = true
  try {
    cert.value = await api.get<Certificate>(`/certificates/${id.value}`)
    renewForm.value.validity_days = cert.value.validity_days
    // The chain and lineage are secondary; a failure there must not blank the page.
    const [chainResult, historyResult] = await Promise.allSettled([
      api.get<ChainResponse>(`/certificates/${id.value}/chain`),
      api.get<{ items: Certificate[] }>(`/certificates/${id.value}/history`),
    ])
    if (chainResult.status === 'fulfilled') chain.value = chainResult.value
    if (historyResult.status === 'fulfilled') history.value = historyResult.value.items ?? []
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load the certificate')
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function toggleAutoRenew() {
  if (!cert.value) return
  const next = !cert.value.auto_renew
  try {
    cert.value = await api.patch<Certificate>(`/certificates/${id.value}`, { auto_renew: next })
    toast.success(next ? 'Auto-renew enabled' : 'Auto-renew disabled')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not update the certificate')
  }
}

async function renew() {
  busy.value = true
  try {
    const result = await api.post<IssueResult>(`/certificates/${id.value}/renew`, {
      rekey: renewForm.value.rekey,
      validity_days: renewForm.value.validity_days || undefined,
      ca_passphrase: renewForm.value.ca_passphrase || undefined,
    })
    toast.success('Renewed — this is a new certificate; deploy it to take effect')
    renewOpen.value = false
    await navigateTo(`/certificates/${result.certificate.id}`)
  } catch (err) {
    if (err instanceof ApiRequestError && err.needsPassphrase) {
      toast.warning('This CA is passphrase-protected. Enter it to renew.')
    } else {
      toast.error(err instanceof Error ? err.message : 'the renewal failed')
    }
  } finally {
    busy.value = false
  }
}

async function revoke() {
  busy.value = true
  try {
    await api.post(`/certificates/${id.value}/revoke`, {
      reason_code: revokeForm.value.reason_code,
      ca_passphrase: revokeForm.value.ca_passphrase || undefined,
    })
    toast.success('Revoked and published on the CRL')
    revokeOpen.value = false
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the revocation failed')
  } finally {
    busy.value = false
  }
}

async function remove() {
  busy.value = true
  try {
    await api.del(`/certificates/${id.value}`)
    toast.success('Certificate deleted')
    await navigateTo('/certificates')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the deletion failed')
  } finally {
    busy.value = false
  }
}

const catalog = useCatalogStore()
const reasons = computed(() => catalog.meta?.revocation_reasons ?? [])
const isRevoked = computed(() => cert.value?.status === 'revoked')
/** A hold is the one revocation RFC 5280 lets you take back, so it gets its own
 *  state rather than being folded into "revoked". */
const isHeld = computed(() => cert.value?.status === 'held')

async function releaseHold() {
  busy.value = true
  try {
    await api.post(`/certificates/${id.value}/hold/release`, {
      ca_passphrase: revokeForm.value.ca_passphrase || undefined,
    })
    toast.success('Hold lifted and the CRL republished without it')
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not lift the hold')
  } finally {
    busy.value = false
  }
}

async function deployNow() {
  busy.value = true
  try {
    const payload = await api.post<{ results: { target_name: string; error?: string }[] }>(
      `/certificates/${id.value}/deploy?force=true`,
    )
    const results = payload.results ?? []
    const failed = results.filter((r) => r.error)
    if (!results.length) {
      toast.warning('No deployment target selects this certificate')
    } else if (failed.length) {
      toast.error(`${failed.length} of ${results.length} target(s) failed: ${failed[0]?.error}`)
    } else {
      toast.success(`Deployed to ${results.length} target(s)`)
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the deployment failed')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div>
    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else-if="cert">
      <div class="breadcrumb">
        <NuxtLink to="/certificates">Certificates</NuxtLink>
        <span class="mdi mdi-chevron-right" />
        <span>{{ cert.common_name }}</span>
      </div>

      <div class="page-header">
        <div class="min-w-0">
          <h1 class="cert-title">{{ cert.common_name }}</h1>
          <div class="cert-subline">
            <span class="badge badge-dot" :class="statusClass(cert.status)">{{ cert.status }}</span>
            <span class="badge badge-secondary">{{ cert.profile }}</span>
            <span class="text-muted text-sm">
              issued by {{ cert.ca_name || catalog.authorityName(cert.ca_id) }}
            </span>
          </div>
        </div>

        <div class="page-header-actions">
          <CertDownloadMenu :certificate="cert" />
          <template v-if="auth.canWrite && isHeld">
            <button class="btn btn-secondary" :disabled="busy" @click="releaseHold">
              <span class="mdi mdi-lock-open-variant-outline" />
              Lift hold
            </button>
            <button class="btn btn-danger" @click="revokeOpen = true">
              <span class="mdi mdi-close-octagon-outline" />
              Revoke for good
            </button>
          </template>
          <template v-else-if="auth.canWrite && !isRevoked">
            <button class="btn btn-secondary" :disabled="busy" @click="deployNow">
              <span class="mdi mdi-rocket-launch-outline" />
              Deploy
            </button>
            <button class="btn btn-secondary" @click="renewOpen = true">
              <span class="mdi mdi-autorenew" />
              Renew
            </button>
            <button class="btn btn-danger" @click="revokeOpen = true">
              <span class="mdi mdi-close-octagon-outline" />
              Revoke
            </button>
          </template>
        </div>
      </div>

      <!-- Expiry is the single most actionable fact on this page. -->
      <div
        v-if="cert.severity !== 'ok' || isRevoked || isHeld"
        class="app-banner mb-6"
        :class="isRevoked ? 'app-banner--danger'
          : cert.severity === 'critical' || cert.severity === 'expired' ? 'app-banner--danger' : 'app-banner--warning'"
      >
        <span class="app-banner-icon mdi" :class="isRevoked ? 'mdi-close-octagon' : 'mdi-clock-alert-outline'" />
        <div class="app-banner-content">
          <p class="app-banner-title">
            <template v-if="isRevoked">This certificate is revoked</template>
            <template v-else-if="cert.days_remaining < 0">Expired {{ Math.abs(cert.days_remaining) }} days ago</template>
            <template v-else>Expires in {{ cert.days_remaining }} days</template>
          </p>
          <p class="app-banner-text">
            <template v-if="isRevoked">
              It is listed on the issuing CA's CRL. Clients that check revocation will reject it.
            </template>
            <template v-else>
              Valid until {{ date(cert.not_after) }}.
              {{ cert.auto_renew ? 'Auto-renew is on; the scheduler will handle it.' : 'Renew it before then.' }}
            </template>
          </p>
        </div>
        <div v-if="!isRevoked && auth.canWrite && !cert.auto_renew" class="app-banner-actions">
          <button class="btn btn-warning btn-sm" @click="renewOpen = true">Renew now</button>
        </div>
      </div>

      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'overview' }" @click="tab = 'overview'">Overview</button>
        <button class="tab" :class="{ active: tab === 'chain' }" @click="tab = 'chain'">
          Chain
          <span v-if="chain && !chain.valid" class="mdi mdi-alert-circle tab-alert" />
        </button>
        <button class="tab" :class="{ active: tab === 'pem' }" @click="tab = 'pem'">PEM</button>
        <button class="tab" :class="{ active: tab === 'history' }" @click="tab = 'history'">
          History <span v-if="history.length > 1" class="tab-count">{{ history.length }}</span>
        </button>
      </div>

      <!-- Overview -->
      <div v-if="tab === 'overview'" class="detail-columns">
        <div class="card">
          <div class="card-header"><h2>Identity</h2></div>
          <div class="card-body">
            <div class="detail-grid">
              <span class="detail-label">Common name</span>
              <span class="detail-value">{{ cert.common_name }}</span>

              <span class="detail-label">Subject</span>
              <span class="detail-value font-mono text-sm">{{ cert.subject_dn }}</span>

              <span class="detail-label">SANs</span>
              <span class="detail-value">
                <span v-for="san in cert.sans" :key="`${san.type}:${san.value}`" class="chip san-chip">
                  <span class="chip-type">{{ san.type }}</span>
                  <span class="chip-value">{{ san.value }}</span>
                </span>
              </span>

              <span class="detail-label">Serial</span>
              <span class="detail-value">
                <span class="mono-value">{{ cert.serial_number }}</span>
              </span>

              <span class="detail-label">SHA-256</span>
              <span class="detail-value fingerprint-row">
                <span class="mono-value">{{ cert.fingerprint_sha256 }}</span>
                <UiCopyButton :value="cert.fingerprint_sha256" icon label="Copy fingerprint" />
              </span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header"><h2>Validity and key</h2></div>
          <div class="card-body">
            <CertExpiryBar
              class="mb-4"
              :not-before="cert.not_before"
              :not-after="cert.not_after"
              :days-remaining="cert.days_remaining"
              :severity="cert.severity"
            />
            <div class="detail-grid">
              <span class="detail-label">Valid from</span>
              <span class="detail-value">{{ dateTime(cert.not_before) }}</span>

              <span class="detail-label">Valid until</span>
              <span class="detail-value">
                {{ dateTime(cert.not_after) }}
                <span class="text-muted text-sm">({{ days(cert.days_remaining) }})</span>
              </span>

              <span class="detail-label">Key</span>
              <span class="detail-value">{{ cert.key_algorithm }}</span>

              <span class="detail-label">Private key</span>
              <span class="detail-value">
                <template v-if="cert.has_private_key">
                  Held by Certio, encrypted at rest
                  <span v-if="cert.key_download_count" class="text-muted text-sm">
                    · downloaded {{ cert.key_download_count }}×
                  </span>
                </template>
                <template v-else>
                  Not held — this certificate was signed from an external CSR
                </template>
              </span>

              <span class="detail-label">Key usage</span>
              <span class="detail-value text-sm">{{ cert.key_usage.join(', ') || '—' }}</span>

              <span class="detail-label">Extended usage</span>
              <span class="detail-value text-sm">{{ cert.ext_key_usage.join(', ') || '—' }}</span>

              <span class="detail-label">Auto-renew</span>
              <span class="detail-value">
                <label v-if="auth.canWrite && !isRevoked" class="checkbox-label">
                  <input type="checkbox" :checked="cert.auto_renew" @change="toggleAutoRenew">
                  {{ cert.auto_renew ? `on — ${cert.renew_before_days} days before expiry` : 'off' }}
                </label>
                <template v-else>{{ cert.auto_renew ? 'on' : 'off' }}</template>
              </span>
            </div>

            <div v-if="cert.notes" class="notes-box">
              <span class="detail-label">Notes</span>
              <p class="mt-2">{{ cert.notes }}</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Chain -->
      <div v-else-if="tab === 'chain'" class="card">
        <div class="card-body">
          <CertChainViewer v-if="chain" :links="chain.links" :valid="chain.valid" />
          <UiEmptyState v-else icon="link-off" title="The chain could not be loaded" />
        </div>
      </div>

      <!-- PEM -->
      <div v-else-if="tab === 'pem'" class="card">
        <div class="card-body pem-stack">
          <CertPemViewer
            v-if="cert.cert_pem"
            :pem="cert.cert_pem"
            label="Certificate"
            :collapsed="false"
          />
          <CertPemViewer v-if="cert.csr_pem" :pem="cert.csr_pem" label="Original CSR" />
          <p class="form-hint">
            The private key is never shown here. Use the download menu, which enforces this
            instance's key download policy and records the download in the audit log.
          </p>
        </div>
      </div>

      <!-- History -->
      <div v-else class="card">
        <div class="card-body">
          <UiEmptyState
            v-if="history.length <= 1"
            icon="history"
            title="No renewals yet"
            message="Renewing creates a new certificate linked to this one, so the lineage stays visible here."
          />
          <ol v-else class="history-list">
            <li v-for="(entry, index) in history" :key="entry.id" class="history-item">
              <span class="history-marker" :class="{ current: entry.id === cert.id }" />
              <div class="min-w-0">
                <div class="history-head">
                  <NuxtLink :to="`/certificates/${entry.id}`" class="history-serial">
                    {{ entry.serial_number }}
                  </NuxtLink>
                  <span v-if="entry.id === cert.id" class="badge badge-info">current</span>
                  <span v-else-if="index === 0" class="badge badge-neutral">newest</span>
                  <span class="badge badge-dot" :class="statusClass(entry.status)">{{ entry.status }}</span>
                </div>
                <div class="history-meta">
                  issued {{ date(entry.created_at) }} · expires {{ date(entry.not_after) }} ·
                  {{ entry.key_algorithm }}
                </div>
              </div>
            </li>
          </ol>
        </div>
      </div>

      <!-- Danger zone -->
      <div v-if="auth.canWrite" class="danger-zone">
        <div>
          <strong>Delete this record</strong>
          <p class="text-sm text-muted">
            Deleting is not revoking. If this certificate is still deployed, clients keep
            accepting it until it expires — revoke it first.
          </p>
        </div>
        <button class="btn btn-ghost btn-sm delete-btn" @click="deleteOpen = true">
          <span class="mdi mdi-delete-outline" />
          Delete
        </button>
      </div>

      <!-- ─── Dialogs ─── -->
      <UiBaseModal v-if="renewOpen" title="Renew certificate" :busy="busy" @close="renewOpen = false">
        <p class="text-secondary mb-4">
          This creates a <strong>new</strong> certificate linked to this one. The current
          certificate stays valid and downloadable until it expires or you revoke it.
        </p>

        <div class="form-group">
          <label class="form-label">Validity (days)</label>
          <input v-model.number="renewForm.validity_days" type="number" class="form-input" min="1">
        </div>

        <div class="form-group">
          <label class="checkbox-label">
            <input v-model="renewForm.rekey" type="checkbox" :disabled="!cert.has_private_key">
            Generate a new key pair
          </label>
          <p class="form-hint">
            <template v-if="!cert.has_private_key">
              Required here: Certio does not hold the original key, so it cannot re-sign it.
            </template>
            <template v-else>
              Leave this off to keep the same key — anything pinning the public key keeps working.
            </template>
          </p>
        </div>

        <div v-if="cert.ca_id" class="form-group">
          <label class="form-label">CA passphrase (if required)</label>
          <input v-model="renewForm.ca_passphrase" type="password" class="form-input" autocomplete="off">
        </div>

        <template #footer>
          <button class="btn btn-secondary" :disabled="busy" @click="renewOpen = false">Cancel</button>
          <button class="btn btn-primary" :disabled="busy" @click="renew">
            <span v-if="busy" class="spinner" />
            Renew
          </button>
        </template>
      </UiBaseModal>

      <UiBaseModal v-if="revokeOpen" title="Revoke certificate" :busy="busy" @close="revokeOpen = false">
        <div class="app-banner app-banner--danger mb-4">
          <span class="app-banner-icon mdi mdi-alert-outline" />
          <div class="app-banner-content">
            <p class="app-banner-text">
              Revocation is permanent. The serial is added to the CA's CRL immediately and cannot
              be taken back — issue a replacement instead.
            </p>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Reason</label>
          <select v-model.number="revokeForm.reason_code" class="form-select">
            <option v-for="reason in reasons" :key="reason.code" :value="reason.code">
              {{ reason.name }} ({{ reason.code }})
            </option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">CA passphrase (if required)</label>
          <input v-model="revokeForm.ca_passphrase" type="password" class="form-input" autocomplete="off">
        </div>

        <template #footer>
          <button class="btn btn-secondary" :disabled="busy" @click="revokeOpen = false">Cancel</button>
          <button class="btn btn-danger" :disabled="busy" @click="revoke">
            <span v-if="busy" class="spinner" />
            Revoke
          </button>
        </template>
      </UiBaseModal>

      <UiConfirmDialog
        v-if="deleteOpen"
        title="Delete this certificate record?"
        :message="`This removes ${cert.common_name} from Certio. If it is still deployed anywhere, clients will keep accepting it until ${date(cert.not_after)} — revoke it instead if that matters.`"
        confirm-label="Delete"
        danger
        :busy="busy"
        @cancel="deleteOpen = false"
        @confirm="remove"
      />
    </template>

    <UiEmptyState v-else icon="file-remove-outline" title="Certificate not found">
      <NuxtLink to="/certificates" class="btn btn-secondary">Back to certificates</NuxtLink>
    </UiEmptyState>
  </div>
</template>

<style scoped>
.breadcrumb {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: var(--text-muted);
  margin-bottom: 12px;
}
.breadcrumb a { color: var(--text-muted); }
.breadcrumb a:hover { color: var(--primary-600); }

.cert-title { word-break: break-all; }
.cert-subline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 6px; }
.min-w-0 { min-width: 0; }

.tab-alert { color: var(--danger-500); font-size: 13px; margin-left: 4px; }
.tab-count {
  background: var(--bg-tertiary);
  border-radius: 9999px;
  padding: 0 6px;
  font-size: 11px;
  margin-left: 4px;
}

.detail-columns {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 18px;
  align-items: start;
}

.san-chip { margin: 0 6px 6px 0; }
.fingerprint-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

.notes-box {
  margin-top: 20px;
  padding-top: 16px;
  border-top: 1px dashed var(--border-primary);
}

.pem-stack { display: flex; flex-direction: column; gap: 14px; }

.history-list { list-style: none; display: flex; flex-direction: column; gap: 18px; }
.history-item { display: flex; gap: 12px; align-items: flex-start; }
.history-marker {
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--border-input);
  margin-top: 6px;
  flex-shrink: 0;
}
.history-marker.current { background: var(--primary-600); box-shadow: 0 0 0 3px var(--primary-100); }
.history-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.history-serial { font-family: var(--font-mono); font-size: 13px; }
.history-meta { font-size: 12.5px; color: var(--text-muted); margin-top: 2px; }

.danger-zone {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-top: 24px;
  padding: 16px 20px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg);
  background: var(--bg-primary);
  flex-wrap: wrap;
}
.delete-btn { color: var(--danger-600); border-color: color-mix(in srgb, var(--danger-500) 35%, transparent); }
.delete-btn:hover { background: var(--danger-50); }
</style>
