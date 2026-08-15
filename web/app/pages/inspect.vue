<script setup lang="ts">
import { ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { InspectResult } from '~/types/api'

useHead({ title: 'Inspect · Certio' })

const api = useApi()
const toast = useToast()
const { dateTime, days } = useFormat()

const pem = ref('')
const result = ref<InspectResult | null>(null)
const busy = ref(false)
const error = ref('')

async function inspect() {
  if (!pem.value.trim()) return
  busy.value = true
  error.value = ''
  result.value = null
  try {
    result.value = await api.post<InspectResult>('/certificates/inspect', { pem: pem.value })
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'could not decode that input'
  } finally {
    busy.value = false
  }
}

async function onFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  pem.value = await file.text()
  await inspect()
}

function clear() {
  pem.value = ''
  result.value = null
  error.value = ''
}

/** Dropping a file onto the textarea is the fastest path for most people. */
async function onDrop(event: DragEvent) {
  const file = event.dataTransfer?.files?.[0]
  if (!file) return
  pem.value = await file.text()
  await inspect()
}

const kindLabel: Record<string, string> = {
  certificate: 'Certificate',
  csr: 'Certificate signing request',
  private_key: 'Private key',
  crl: 'Certificate revocation list',
  public_key: 'Public key',
}
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1>Inspect</h1>
        <p class="page-subtitle">
          Decode any PEM — a certificate, a full chain, a CSR, a key or a CRL. Nothing is stored.
        </p>
      </div>
      <div v-if="pem || result" class="page-header-actions">
        <button class="btn btn-ghost" @click="clear">
          <span class="mdi mdi-close" />
          Clear
        </button>
      </div>
    </div>

    <div class="inspect-grid">
      <div class="card">
        <div class="card-header">
          <h2>Input</h2>
          <label class="btn btn-secondary btn-sm file-btn">
            <span class="mdi mdi-file-upload-outline" />
            Open a file
            <input type="file" accept=".pem,.crt,.cer,.csr,.key,.crl,.der" hidden @change="onFile">
          </label>
        </div>
        <div class="card-body">
          <textarea
            v-model="pem"
            class="form-textarea inspect-input"
            rows="16"
            spellcheck="false"
            placeholder="Paste a PEM block here, or drop a file anywhere in this box.&#10;&#10;-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
            @drop.prevent="onDrop"
            @dragover.prevent
          />
          <p class="form-hint">
            The equivalent of <code>openssl x509 -text -noout</code>, without needing to remember
            which subcommand matches which file.
          </p>
          <button class="btn btn-primary mt-4" :disabled="busy || !pem.trim()" @click="inspect">
            <span v-if="busy" class="spinner" />
            <span v-else class="mdi mdi-magnify-scan" />
            Decode
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Result</h2>
          <span v-if="result" class="badge badge-info">{{ kindLabel[result.kind] ?? result.kind }}</span>
        </div>
        <div class="card-body">
          <div v-if="error" class="app-banner app-banner--danger">
            <span class="app-banner-icon mdi mdi-alert-circle-outline" />
            <div class="app-banner-content">
              <p class="app-banner-title">Could not decode that</p>
              <p class="app-banner-text">{{ error }}</p>
            </div>
          </div>

          <UiEmptyState
            v-else-if="!result"
            icon="text-search"
            title="Nothing decoded yet"
            message="Paste something on the left and the parsed details appear here."
          />

          <!-- Certificate -->
          <template v-else-if="result.certificate">
            <div class="detail-grid">
              <span class="detail-label">Subject</span>
              <span class="detail-value font-mono text-sm">{{ result.certificate.subject_dn }}</span>

              <span class="detail-label">Issuer</span>
              <span class="detail-value font-mono text-sm">
                {{ result.certificate.issuer_dn }}
                <span v-if="result.certificate.self_signed" class="badge badge-neutral">self-signed</span>
              </span>

              <span class="detail-label">Serial</span>
              <span class="detail-value"><span class="mono-value">{{ result.certificate.serial_number }}</span></span>

              <span class="detail-label">Valid</span>
              <span class="detail-value">
                {{ dateTime(result.certificate.not_before) }} → {{ dateTime(result.certificate.not_after) }}
                <span
                  class="badge"
                  :class="result.certificate.expired ? 'badge-danger' : 'badge-success'"
                >
                  {{ result.certificate.expired ? 'expired' : days(result.certificate.days_remaining) }}
                </span>
              </span>

              <span class="detail-label">Type</span>
              <span class="detail-value">
                {{ result.certificate.is_ca ? 'Certificate authority' : 'End-entity certificate' }}
                <span class="badge badge-secondary">{{ result.certificate.profile }}</span>
              </span>

              <span class="detail-label">SANs</span>
              <span class="detail-value">
                <template v-if="result.certificate.sans.length">
                  <span v-for="san in result.certificate.sans" :key="`${san.type}:${san.value}`" class="chip san-chip">
                    <span class="chip-type">{{ san.type }}</span>
                    <span class="chip-value">{{ san.value }}</span>
                  </span>
                </template>
                <span v-else class="text-muted">none — clients will reject this for any hostname</span>
              </span>

              <span class="detail-label">Key</span>
              <span class="detail-value">{{ result.certificate.key_algorithm }}</span>

              <span class="detail-label">Signature</span>
              <span class="detail-value">{{ result.certificate.signature_algorithm }}</span>

              <span class="detail-label">Key usage</span>
              <span class="detail-value text-sm">{{ result.certificate.key_usage.join(', ') || '—' }}</span>

              <span class="detail-label">Extended usage</span>
              <span class="detail-value text-sm">{{ result.certificate.ext_key_usage.join(', ') || '—' }}</span>

              <span class="detail-label">SHA-256</span>
              <span class="detail-value">
                <span class="mono-value">{{ result.certificate.fingerprint_sha256 }}</span>
              </span>

              <span class="detail-label">SHA-1</span>
              <span class="detail-value">
                <span class="mono-value">{{ result.certificate.fingerprint_sha1 }}</span>
              </span>

              <template v-if="result.certificate.crl_distribution_points?.length">
                <span class="detail-label">CRL</span>
                <span class="detail-value text-sm break-all">
                  {{ result.certificate.crl_distribution_points.join(', ') }}
                </span>
              </template>
            </div>

            <div v-if="result.chain?.length" class="chain-section">
              <h3 class="section-title">Chain ({{ result.chain.length }} more)</h3>
              <div
                v-for="link in result.chain"
                :key="link.serial_number"
                class="chain-summary"
              >
                <span class="mdi mdi-shield-outline" />
                <div class="min-w-0">
                  <div class="cell-title">{{ link.subject.common_name || link.subject_dn }}</div>
                  <div class="cell-sub">
                    {{ link.is_ca ? 'CA' : 'leaf' }} · expires {{ dateTime(link.not_after) }}
                  </div>
                </div>
              </div>
            </div>
          </template>

          <!-- CSR -->
          <template v-else-if="result.csr">
            <div class="detail-grid">
              <span class="detail-label">Subject</span>
              <span class="detail-value font-mono text-sm">{{ result.csr.dn }}</span>

              <span class="detail-label">Key</span>
              <span class="detail-value">{{ result.csr.key_algorithm }}</span>

              <span class="detail-label">Signature</span>
              <span class="detail-value">{{ result.csr.signature_algorithm }}</span>

              <span class="detail-label">SANs</span>
              <span class="detail-value">
                <span v-for="san in result.csr.sans" :key="`${san.type}:${san.value}`" class="chip san-chip">
                  <span class="chip-type">{{ san.type }}</span>
                  <span class="chip-value">{{ san.value }}</span>
                </span>
              </span>
            </div>

            <div class="app-banner app-banner--success mt-4">
              <span class="app-banner-icon mdi mdi-check-decagram" />
              <div class="app-banner-content">
                <p class="app-banner-text">
                  The self-signature verifies, so the requester holds the matching private key.
                </p>
              </div>
            </div>

            <NuxtLink to="/certificates/new" class="btn btn-primary mt-4">
              <span class="mdi mdi-file-sign" />
              Sign this CSR
            </NuxtLink>
          </template>

          <!-- Private key -->
          <template v-else-if="result.key">
            <div class="detail-grid">
              <span class="detail-label">Algorithm</span>
              <span class="detail-value">{{ result.key.key_algorithm }}</span>
            </div>
            <div class="app-banner app-banner--info mt-4">
              <span class="app-banner-icon mdi mdi-key-outline" />
              <div class="app-banner-content">
                <p class="app-banner-text">
                  Only the derived public key is shown. The private half was parsed to read the
                  algorithm and then discarded — it is never stored or echoed back.
                </p>
              </div>
            </div>
            <CertPemViewer :pem="result.key.public_key_pem" label="Public key" class="mt-4" />
          </template>

          <!-- CRL -->
          <template v-else-if="result.crl">
            <div class="detail-grid">
              <span class="detail-label">Issuer</span>
              <span class="detail-value font-mono text-sm">{{ result.crl.issuer }}</span>

              <span class="detail-label">CRL number</span>
              <span class="detail-value">{{ result.crl.number }}</span>

              <span class="detail-label">This update</span>
              <span class="detail-value">{{ dateTime(result.crl.this_update) }}</span>

              <span class="detail-label">Next update</span>
              <span class="detail-value">{{ dateTime(result.crl.next_update) }}</span>

              <span class="detail-label">Revoked</span>
              <span class="detail-value">{{ result.crl.entries.length }} certificate(s)</span>
            </div>

            <div v-if="result.crl.entries.length" class="table-wrapper mt-4">
              <table>
                <thead>
                  <tr><th>Serial</th><th>Revoked</th><th>Reason</th></tr>
                </thead>
                <tbody>
                  <tr v-for="entry in result.crl.entries" :key="entry.serial_number">
                    <td class="cell-mono">{{ entry.serial_number }}</td>
                    <td class="text-sm">{{ dateTime(entry.revoked_at) }}</td>
                    <td><span class="badge badge-neutral">{{ entry.reason }}</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.inspect-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 18px;
  align-items: start;
}
.inspect-input { min-height: 320px; }
.file-btn { position: relative; overflow: hidden; }
.san-chip { margin: 0 6px 6px 0; }
.min-w-0 { min-width: 0; }

.section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
  margin: 20px 0 10px;
}
.chain-section { border-top: 1px dashed var(--border-primary); margin-top: 20px; }
.chain-summary {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 0;
  border-bottom: 1px solid var(--border-secondary);
}
.chain-summary:last-child { border-bottom: none; }
.chain-summary .mdi { font-size: 18px; color: var(--primary-600); }

.form-hint code {
  background: var(--bg-tertiary);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11.5px;
}
</style>
