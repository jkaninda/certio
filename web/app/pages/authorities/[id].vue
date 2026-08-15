<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useAuthStore } from '~/stores/auth'
import { useCatalogStore } from '~/stores/catalog'
import { useToast } from '~/composables/useToast'
import type { Authority, Certificate, TrustGuide } from '~/types/api'

const route = useRoute()
const api = useApi()
const auth = useAuthStore()
const catalog = useCatalogStore()
const toast = useToast()
const { date, dateTime, days, statusClass } = useFormat()

const id = computed(() => route.params.id as string)

const ca = ref<Authority | null>(null)
const certificates = ref<Certificate[]>([])
const trust = ref<TrustGuide | null>(null)
const loading = ref(true)
const tab = ref<'overview' | 'certificates' | 'trust' | 'pem'>('overview')
const activePlatform = ref('')

const deleteOpen = ref(false)
const renewOpen = ref(false)
const busy = ref(false)
const renewForm = ref({ validity_days: 0, passphrase: '', parent_passphrase: '' })

useHead(() => ({ title: ca.value ? `${ca.value.name} · Certio` : 'Authority · Certio' }))

async function load() {
  loading.value = true
  try {
    ca.value = await api.get<Authority>(`/authorities/${id.value}`)
    renewForm.value.validity_days = Math.round(
      (new Date(ca.value.not_after).getTime() - new Date(ca.value.not_before).getTime()) / 86400000,
    )
    const [certResult, trustResult] = await Promise.allSettled([
      api.get<{ items: Certificate[] }>(`/authorities/${id.value}/certificates`, { limit: 100 }),
      api.get<TrustGuide>(`/authorities/${id.value}/trust`),
    ])
    if (certResult.status === 'fulfilled') certificates.value = certResult.value.items ?? []
    if (trustResult.status === 'fulfilled') {
      trust.value = trustResult.value
      activePlatform.value = trust.value.instructions[0]?.platform ?? ''
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load the authority')
  } finally {
    loading.value = false
  }
}

onMounted(load)

const activeInstruction = computed(
  () => trust.value?.instructions.find((i) => i.platform === activePlatform.value) ?? null,
)

async function regenerateCRL() {
  busy.value = true
  try {
    await api.post(`/authorities/${id.value}/crl`, {})
    toast.success('CRL regenerated and published')
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not regenerate the CRL')
  } finally {
    busy.value = false
  }
}

async function renew() {
  busy.value = true
  try {
    await api.post(`/authorities/${id.value}/renew`, {
      validity_days: renewForm.value.validity_days || undefined,
      passphrase: renewForm.value.passphrase || undefined,
      parent_passphrase: renewForm.value.parent_passphrase || undefined,
    })
    toast.success('Authority renewed — redistribute the root to clients')
    renewOpen.value = false
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the renewal failed')
  } finally {
    busy.value = false
  }
}

async function remove(force: boolean) {
  busy.value = true
  try {
    await api.del(`/authorities/${id.value}`, force ? { force: 'true' } : undefined)
    await catalog.refreshAuthorities()
    toast.success('Authority deleted')
    await navigateTo('/authorities')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the deletion failed')
  } finally {
    busy.value = false
    deleteOpen.value = false
  }
}

function downloadRoot() {
  if (!ca.value) return
  window.open(`/ca/${ca.value.id}/root.crt`, '_blank')
}
</script>

<template>
  <div>
    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else-if="ca">
      <div class="breadcrumb">
        <NuxtLink to="/authorities">Authorities</NuxtLink>
        <span class="mdi mdi-chevron-right" />
        <span>{{ ca.name }}</span>
      </div>

      <div class="page-header">
        <div class="min-w-0">
          <h1>{{ ca.name }}</h1>
          <div class="ca-subline">
            <span class="badge badge-dot" :class="statusClass(ca.status)">{{ ca.status }}</span>
            <span class="badge badge-secondary">{{ ca.type }}</span>
            <span v-if="ca.passphrase_protected" class="badge badge-warning">
              <span class="mdi mdi-lock-outline" /> passphrase-protected
            </span>
          </div>
        </div>

        <div class="page-header-actions">
          <button class="btn btn-secondary" @click="downloadRoot">
            <span class="mdi mdi-download" />
            Root certificate
          </button>
          <NuxtLink :to="`/certificates/new?ca=${ca.id}`" class="btn btn-primary">
            <span class="mdi mdi-plus" />
            Issue from this CA
          </NuxtLink>
        </div>
      </div>

      <div v-if="ca.days_remaining < 180" class="app-banner app-banner--warning mb-6">
        <span class="app-banner-icon mdi mdi-clock-alert-outline" />
        <div class="app-banner-content">
          <p class="app-banner-title">
            This authority expires in {{ ca.days_remaining }} days
          </p>
          <p class="app-banner-text">
            When a CA expires, <strong>every certificate it issued stops verifying</strong> — regardless
            of their own expiry dates. Renew it before renewing anything beneath it.
          </p>
        </div>
        <div v-if="auth.isAdmin" class="app-banner-actions">
          <button class="btn btn-warning btn-sm" @click="renewOpen = true">Renew CA</button>
        </div>
      </div>

      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'overview' }" @click="tab = 'overview'">Overview</button>
        <button class="tab" :class="{ active: tab === 'certificates' }" @click="tab = 'certificates'">
          Certificates <span class="tab-count">{{ ca.certificate_count }}</span>
        </button>
        <button class="tab" :class="{ active: tab === 'trust' }" @click="tab = 'trust'">Distribute trust</button>
        <button class="tab" :class="{ active: tab === 'pem' }" @click="tab = 'pem'">PEM</button>
      </div>

      <!-- Overview -->
      <div v-if="tab === 'overview'" class="detail-columns">
        <div class="card">
          <div class="card-header"><h2>Identity</h2></div>
          <div class="card-body">
            <div class="detail-grid">
              <span class="detail-label">Subject</span>
              <span class="detail-value font-mono text-sm">{{ ca.subject_dn }}</span>

              <span class="detail-label">Slug</span>
              <span class="detail-value font-mono text-sm">{{ ca.slug }}</span>

              <span class="detail-label">Serial</span>
              <span class="detail-value"><span class="mono-value">{{ ca.serial_number }}</span></span>

              <span class="detail-label">SHA-256</span>
              <span class="detail-value fingerprint-row">
                <span class="mono-value">{{ ca.fingerprint_sha256 }}</span>
                <UiCopyButton :value="ca.fingerprint_sha256" icon label="Copy fingerprint" />
              </span>

              <span class="detail-label">Key</span>
              <span class="detail-value">{{ ca.key_algorithm }}</span>

              <template v-if="ca.path_len_constraint !== undefined && ca.path_len_constraint !== null">
                <span class="detail-label">Path length</span>
                <span class="detail-value">
                  {{ ca.path_len_constraint }}
                  <span class="text-muted text-sm">
                    ({{ ca.path_len_constraint === 0 ? 'leaves only' : `${ca.path_len_constraint} CA level(s) below` }})
                  </span>
                </span>
              </template>

              <span class="detail-label">Valid from</span>
              <span class="detail-value">{{ dateTime(ca.not_before) }}</span>

              <span class="detail-label">Valid until</span>
              <span class="detail-value">
                {{ dateTime(ca.not_after) }}
                <span class="text-muted text-sm">({{ days(ca.days_remaining) }})</span>
              </span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div>
              <h2>Revocation list</h2>
              <span class="card-subtitle">Published unauthenticated so clients can fetch it</span>
            </div>
            <button
              v-if="auth.canWrite"
              class="btn btn-secondary btn-sm"
              :disabled="busy"
              @click="regenerateCRL"
            >
              <span v-if="busy" class="spinner" />
              <span v-else class="mdi mdi-refresh" />
              Regenerate
            </button>
          </div>
          <div class="card-body">
            <div class="detail-grid">
              <span class="detail-label">CRL number</span>
              <span class="detail-value">{{ ca.crl_number }}</span>

              <span class="detail-label">Next update</span>
              <span class="detail-value">
                {{ ca.next_crl_update ? dateTime(ca.next_crl_update) : 'not published yet' }}
              </span>

              <span class="detail-label">PEM</span>
              <span class="detail-value url-row">
                <a :href="`/ca/${ca.id}/crl.pem`" target="_blank" class="font-mono text-sm">/ca/{{ ca.id }}/crl.pem</a>
                <UiCopyButton :value="ca.crl_url || ''" icon label="Copy CRL URL" />
              </span>

              <span class="detail-label">DER</span>
              <span class="detail-value">
                <a :href="`/ca/${ca.id}/crl.der`" target="_blank" class="font-mono text-sm">/ca/{{ ca.id }}/crl.der</a>
              </span>
            </div>

            <p v-if="ca.passphrase_protected" class="form-hint mt-4">
              This CA needs its passphrase to sign, so the scheduler cannot refresh its CRL
              automatically. Regenerate it here after each revocation.
            </p>
          </div>
        </div>
      </div>

      <!-- Certificates -->
      <div v-else-if="tab === 'certificates'" class="card">
        <UiEmptyState
          v-if="!certificates.length"
          icon="file-certificate-outline"
          title="Nothing issued yet"
          message="Certificates signed by this authority appear here."
        >
          <NuxtLink :to="`/certificates/new?ca=${ca.id}`" class="btn btn-primary">Issue one</NuxtLink>
        </UiEmptyState>

        <div v-else class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Common name</th>
                <th>Profile</th>
                <th>Expires</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="cert in certificates"
                :key="cert.id"
                class="row-clickable"
                @click="navigateTo(`/certificates/${cert.id}`)"
              >
                <td class="cell-title">{{ cert.common_name }}</td>
                <td><span class="badge badge-secondary">{{ cert.profile }}</span></td>
                <td class="text-sm">{{ date(cert.not_after) }} <span class="text-muted">({{ days(cert.days_remaining) }})</span></td>
                <td><span class="badge badge-dot" :class="statusClass(cert.status)">{{ cert.status }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Trust distribution -->
      <div v-else-if="tab === 'trust'" class="card">
        <div class="card-header">
          <div>
            <h2>Install this root on your clients</h2>
            <span class="card-subtitle">
              Until this certificate is trusted, everything below it is "self-signed" to a client
            </span>
          </div>
        </div>
        <div class="card-body">
          <div class="trust-urls">
            <div class="trust-url">
              <span class="detail-label">Root certificate</span>
              <div class="url-row">
                <a :href="trust?.root_url" target="_blank" class="mono-value">{{ trust?.root_url }}</a>
                <UiCopyButton :value="trust?.root_url ?? ''" icon label="Copy URL" />
              </div>
            </div>
            <div class="trust-url">
              <span class="detail-label">Fingerprint to verify</span>
              <div class="url-row">
                <span class="mono-value">{{ trust?.fingerprint_sha256 }}</span>
                <UiCopyButton :value="trust?.fingerprint_sha256 ?? ''" icon label="Copy fingerprint" />
              </div>
            </div>
          </div>

          <p class="trust-warning">
            <span class="mdi mdi-shield-alert-outline" />
            Check the fingerprint against this page before trusting a downloaded root. Installing a
            CA root means trusting it for <em>every</em> hostname.
          </p>

          <div class="tabs platform-tabs">
            <button
              v-for="instruction in trust?.instructions ?? []"
              :key="instruction.platform"
              class="tab"
              :class="{ active: activePlatform === instruction.platform }"
              @click="activePlatform = instruction.platform"
            >
              {{ instruction.title }}
            </button>
          </div>

          <div v-if="activeInstruction">
            <div class="code-header">
              <span>{{ activeInstruction.title }}</span>
              <UiCopyButton :value="activeInstruction.commands" label="Copy commands" />
            </div>
            <pre class="code-block">{{ activeInstruction.commands }}</pre>
            <p v-if="activeInstruction.note" class="form-hint mt-2">
              <span class="mdi mdi-information-outline" /> {{ activeInstruction.note }}
            </p>
          </div>
        </div>
      </div>

      <!-- PEM -->
      <div v-else class="card">
        <div class="card-body pem-stack">
          <CertPemViewer
            v-if="ca.cert_pem"
            :pem="ca.cert_pem"
            label="CA certificate"
            :collapsed="false"
            :filename="`${ca.slug}-root.crt`"
          />
          <p class="form-hint">
            The CA private key is never exposed over the API or the dashboard. It stays
            AES-256-GCM encrypted in the database and is only decrypted in memory to sign.
          </p>
        </div>
      </div>

      <!-- Danger zone -->
      <div v-if="auth.isAdmin" class="danger-zone">
        <div>
          <strong>Delete this authority</strong>
          <p class="text-sm text-muted">
            <template v-if="ca.certificate_count > 0">
              {{ ca.certificate_count }} certificate(s) were issued by this CA. Deleting it removes
              them from Certio too — and none of them will verify afterwards.
            </template>
            <template v-else>
              This CA has issued nothing, so deleting it is safe.
            </template>
          </p>
        </div>
        <button class="btn btn-ghost btn-sm delete-btn" @click="deleteOpen = true">
          <span class="mdi mdi-delete-outline" />
          Delete
        </button>
      </div>

      <!-- ─── Dialogs ─── -->
      <UiConfirmDialog
        v-if="deleteOpen"
        title="Delete this certificate authority?"
        :message="ca.certificate_count > 0
          ? `${ca.name} has issued ${ca.certificate_count} certificate(s). Deleting it removes those records as well, and any deployed certificate signed by it will stop verifying once clients drop the root.`
          : `${ca.name} will be permanently removed, along with its encrypted private key.`"
        :confirm-phrase="ca.certificate_count > 0 ? ca.slug : undefined"
        confirm-label="Delete authority"
        danger
        :busy="busy"
        @cancel="deleteOpen = false"
        @confirm="remove(ca.certificate_count > 0)"
      />

      <UiBaseModal v-if="renewOpen" title="Renew certificate authority" :busy="busy" @close="renewOpen = false">
        <p class="text-secondary mb-4">
          The CA is re-signed with the <strong>same key</strong>, so every certificate it has
          already issued keeps verifying. Clients that pinned the old certificate bytes will need
          the new root.
        </p>

        <div class="form-group">
          <label class="form-label">Validity (days)</label>
          <input v-model.number="renewForm.validity_days" type="number" class="form-input" min="1">
        </div>

        <div v-if="ca.passphrase_protected" class="form-group">
          <label class="form-label">This CA's passphrase <span class="required">*</span></label>
          <input v-model="renewForm.passphrase" type="password" class="form-input" autocomplete="off">
        </div>

        <div v-if="ca.parent_id" class="form-group">
          <label class="form-label">Parent CA passphrase (if required)</label>
          <input v-model="renewForm.parent_passphrase" type="password" class="form-input" autocomplete="off">
        </div>

        <template #footer>
          <button class="btn btn-secondary" :disabled="busy" @click="renewOpen = false">Cancel</button>
          <button class="btn btn-primary" :disabled="busy" @click="renew">
            <span v-if="busy" class="spinner" />
            Renew
          </button>
        </template>
      </UiBaseModal>
    </template>

    <UiEmptyState v-else icon="shield-off-outline" title="Authority not found">
      <NuxtLink to="/authorities" class="btn btn-secondary">Back to authorities</NuxtLink>
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

.ca-subline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 6px; }
.min-w-0 { min-width: 0; }
.tab-count {
  background: var(--bg-primary);
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

.fingerprint-row, .url-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

.trust-urls { display: grid; gap: 14px; margin-bottom: 16px; }
.trust-url { display: flex; flex-direction: column; gap: 6px; }
.trust-warning {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 12.5px;
  color: var(--warning-600);
  margin-bottom: 20px;
  line-height: 1.5;
}
.platform-tabs { margin-bottom: 16px; }

.code-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
}

.pem-stack { display: flex; flex-direction: column; gap: 14px; }

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
