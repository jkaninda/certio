<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useCatalogStore } from '~/stores/catalog'
import { useToast } from '~/composables/useToast'
import { ApiRequestError } from '~/composables/useApi'
import type { IssueResult, SAN } from '~/types/api'

useHead({ title: 'Issue a certificate · Certio' })

const api = useApi()
const route = useRoute()
const catalog = useCatalogStore()
const toast = useToast()

type Mode = 'managed' | 'csr'
const mode = ref<Mode>('managed')

const steps = ['Authority', 'Profile', 'Identity', 'Key & validity', 'Review'] as const
const step = ref(0)

const form = reactive({
  ca_id: '',
  profile: 'server',
  subject: {
    common_name: '',
    organization: '',
    organizational_unit: '',
    country: '',
    province: '',
    locality: '',
    email: '',
  },
  sans: [] as SAN[],
  key_algorithm: '',
  validity_days: 397,
  auto_renew: false,
  renew_before_days: 30,
  notes: '',
  ca_passphrase: '',
  csr_pem: '',
})

const busy = ref(false)
const result = ref<IssueResult | null>(null)
const needsPassphrase = ref(false)

onMounted(async () => {
  await catalog.load()
  form.ca_id =
    (route.query.ca as string) ||
    catalog.activeAuthorityId ||
    catalog.issuableAuthorities[0]?.id ||
    ''
  form.key_algorithm = catalog.meta?.key_algorithms?.[0] ?? 'ecdsa-p256'
  form.subject.organization = ''
})

const selectedCA = computed(() => catalog.authorities.find((c) => c.id === form.ca_id) ?? null)
const selectedProfile = computed(
  () => catalog.meta?.profiles.find((p) => p.name === form.profile) ?? null,
)

/** Leaf profiles only: creating a CA belongs on the authorities page. */
const leafProfiles = computed(
  () => catalog.meta?.profiles.filter((p) => !p.is_ca) ?? [],
)

// The profile carries a default validity; adopt it unless the user has moved
// the field themselves.
const validityTouched = ref(false)
watch(() => form.profile, () => {
  if (!validityTouched.value && selectedProfile.value) {
    form.validity_days = selectedProfile.value.default_validity_days
  }
})

/** The CA's own expiry is a hard ceiling on anything it signs. */
const caMaxDays = computed(() => selectedCA.value?.days_remaining ?? 0)
const exceedsCA = computed(() => caMaxDays.value > 0 && form.validity_days > caMaxDays.value)
const exceedsBrowserMax = computed(
  () => form.validity_days > (catalog.meta?.max_leaf_validity_days ?? 397),
)

const canAdvance = computed(() => {
  switch (step.value) {
    case 0: return !!form.ca_id
    case 1: return !!form.profile
    case 2:
      if (mode.value === 'csr') return form.csr_pem.trim().length > 0
      return !!form.subject.common_name && form.sans.length > 0
    case 3: return form.validity_days > 0 && !exceedsCA.value
    default: return true
  }
})

function next() {
  if (canAdvance.value && step.value < steps.length - 1) step.value++
}
function back() {
  if (step.value > 0) step.value--
}
function goTo(index: number) {
  // Only backwards, or one step forward when the current one is complete.
  if (index < step.value || (index === step.value + 1 && canAdvance.value)) step.value = index
}

/**
 * opensslEquivalent shows the commands this form replaces. The tool should
 * teach the underlying operation rather than hide it.
 */
const opensslEquivalent = computed(() => {
  const cn = form.subject.common_name || 'example.com'
  const subjectParts = [
    form.subject.country && `/C=${form.subject.country}`,
    form.subject.province && `/ST=${form.subject.province}`,
    form.subject.locality && `/L=${form.subject.locality}`,
    form.subject.organization && `/O=${form.subject.organization}`,
    form.subject.organizational_unit && `/OU=${form.subject.organizational_unit}`,
    `/CN=${cn}`,
  ].filter(Boolean).join('')

  const sanLine = form.sans
    .map((s) => {
      if (s.type === 'dns') return `DNS:${s.value}`
      if (s.type === 'ip') return `IP:${s.value}`
      if (s.type === 'email') return `email:${s.value}`
      return `URI:${s.value}`
    })
    .join(',')

  const algo = form.key_algorithm.startsWith('rsa')
    ? `-algorithm RSA -pkeyopt rsa_keygen_bits:${form.key_algorithm.split('-')[1]}`
    : form.key_algorithm === 'ed25519'
      ? '-algorithm ED25519'
      : `-algorithm EC -pkeyopt ec_paramgen_curve:${form.key_algorithm.replace('ecdsa-p', 'P-')}`

  return [
    '# 1. generate the private key',
    `openssl genpkey ${algo} -out ${cn.replace(/\*/g, 'wildcard')}.key`,
    '',
    '# 2. create the signing request',
    `openssl req -new -key ${cn.replace(/\*/g, 'wildcard')}.key -out request.csr \\`,
    `  -subj "${subjectParts}"`,
    '',
    '# 3. sign it with the CA, carrying the SANs across',
    'openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -CAcreateserial \\',
    `  -days ${form.validity_days} -sha256 -out ${cn.replace(/\*/g, 'wildcard')}.crt \\`,
    `  -extfile <(printf "subjectAltName=${sanLine}\\nbasicConstraints=CA:FALSE")`,
  ].join('\n')
})

async function submit() {
  busy.value = true
  needsPassphrase.value = false
  try {
    const payload = mode.value === 'csr'
      ? await api.post<IssueResult>('/certificates/sign-csr', {
          ca_id: form.ca_id,
          csr_pem: form.csr_pem,
          profile: form.profile,
          validity_days: form.validity_days,
          notes: form.notes,
          ca_passphrase: form.ca_passphrase || undefined,
        })
      : await api.post<IssueResult>('/certificates', {
          ca_id: form.ca_id,
          subject: form.subject,
          sans: form.sans,
          profile: form.profile,
          key_algorithm: form.key_algorithm,
          validity_days: form.validity_days,
          auto_renew: form.auto_renew,
          renew_before_days: form.renew_before_days,
          notes: form.notes,
          ca_passphrase: form.ca_passphrase || undefined,
        })

    result.value = payload
    toast.success(`Issued ${payload.certificate.common_name}`)
  } catch (err) {
    if (err instanceof ApiRequestError && err.needsPassphrase) {
      needsPassphrase.value = true
      toast.warning('This CA is passphrase-protected. Enter it to sign.')
    } else {
      toast.error(err instanceof Error ? err.message : 'issuance failed')
    }
  } finally {
    busy.value = false
  }
}

function downloadText(content: string, filename: string, type = 'application/x-pem-file') {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

const safeName = computed(
  () => (result.value?.certificate.common_name ?? 'certificate').replace(/^\*\./, '').replace(/[^a-z0-9.-]/gi, '-'),
)
</script>

<template>
  <div class="wizard-page">
    <!-- ─── Success view ─── -->
    <template v-if="result">
      <div class="page-header">
        <div>
          <h1>Certificate issued</h1>
          <p class="page-subtitle">{{ result.certificate.common_name }}</p>
        </div>
        <div class="page-header-actions">
          <NuxtLink :to="`/certificates/${result.certificate.id}`" class="btn btn-primary">
            Open certificate
          </NuxtLink>
        </div>
      </div>

      <div v-if="result.private_key_pem" class="app-banner app-banner--warning mb-4">
        <span class="app-banner-icon mdi mdi-key-alert-outline" />
        <div class="app-banner-content">
          <p class="app-banner-title">Save the private key now</p>
          <p class="app-banner-text">
            {{ result.warning || 'Depending on this instance\'s key download policy, it may not be retrievable again.' }}
          </p>
        </div>
        <div class="app-banner-actions">
          <button class="btn btn-warning btn-sm" @click="downloadText(result.private_key_pem!, `${safeName}.key`)">
            <span class="mdi mdi-download" />
            Download key
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h2>Files</h2></div>
        <div class="card-body result-files">
          <CertPemViewer
            :pem="result.fullchain_pem"
            label="fullchain.pem"
            :filename="`${safeName}-fullchain.pem`"
          />
          <CertPemViewer :pem="result.cert_pem" :label="`${safeName}.crt`" :filename="`${safeName}.crt`" />
          <CertPemViewer
            v-if="result.private_key_pem"
            :pem="result.private_key_pem"
            :label="`${safeName}.key — private key`"
            :filename="`${safeName}.key`"
          />
        </div>
      </div>

      <div class="flex gap-2 mt-4">
        <button class="btn btn-secondary" @click="result = null; step = 0">
          <span class="mdi mdi-plus" />
          Issue another
        </button>
        <NuxtLink to="/certificates" class="btn btn-ghost">Back to certificates</NuxtLink>
      </div>
    </template>

    <!-- ─── Wizard ─── -->
    <template v-else>
      <div class="page-header">
        <div>
          <h1>Issue a certificate</h1>
          <p class="page-subtitle">
            {{ mode === 'managed'
              ? 'Certio generates the key and signs the certificate.'
              : 'You keep the private key; Certio only signs your request.' }}
          </p>
        </div>
      </div>

      <div class="tabs">
        <button class="tab" :class="{ active: mode === 'managed' }" @click="mode = 'managed'">
          Managed key
        </button>
        <button class="tab" :class="{ active: mode === 'csr' }" @click="mode = 'csr'">
          Sign a CSR
        </button>
      </div>

      <div class="wizard-steps">
        <template v-for="(label, index) in steps" :key="label">
          <button
            class="wizard-step"
            :class="{
              active: step === index,
              done: step > index,
              clickable: index < step || (index === step + 1 && canAdvance),
            }"
            @click="goTo(index)"
          >
            <span class="wizard-step-number">
              <span v-if="step > index" class="mdi mdi-check" />
              <template v-else>{{ index + 1 }}</template>
            </span>
            {{ label }}
          </button>
          <span v-if="index < steps.length - 1" class="wizard-divider" />
        </template>
      </div>

      <div class="card">
        <div class="card-body">
          <!-- Step 1: authority -->
          <div v-if="step === 0">
            <h2 class="step-title">Which authority signs this?</h2>
            <p class="step-help">
              The certificate inherits its trust — and its maximum lifetime — from this CA.
            </p>

            <UiEmptyState
              v-if="!catalog.issuableAuthorities.length"
              icon="shield-alert-outline"
              title="No usable authority"
              message="Every CA is expired or revoked. Create or renew one before issuing."
            >
              <NuxtLink to="/authorities/new" class="btn btn-primary">Create an authority</NuxtLink>
            </UiEmptyState>

            <div v-else class="option-grid">
              <button
                v-for="ca in catalog.issuableAuthorities"
                :key="ca.id"
                class="option-card"
                :class="{ selected: form.ca_id === ca.id }"
                @click="form.ca_id = ca.id"
              >
                <span class="option-icon mdi mdi-certificate-outline" />
                <span class="option-body">
                  <span class="option-title">{{ ca.name }}</span>
                  <span class="option-hint">
                    {{ ca.type }} · {{ ca.key_algorithm }} · expires in {{ ca.days_remaining }}d
                  </span>
                </span>
                <span v-if="ca.passphrase_protected" class="mdi mdi-lock-outline option-lock" title="Passphrase-protected" />
              </button>
            </div>
          </div>

          <!-- Step 2: profile -->
          <div v-else-if="step === 1">
            <h2 class="step-title">What is this certificate for?</h2>
            <p class="step-help">
              The profile presets key usage and extended key usage, so you do not have to know
              the extension names.
            </p>

            <div class="option-grid">
              <button
                v-for="profile in leafProfiles"
                :key="profile.name"
                class="option-card"
                :class="{ selected: form.profile === profile.name }"
                @click="form.profile = profile.name"
              >
                <span
                  class="option-icon mdi"
                  :class="profile.name === 'server' ? 'mdi-server-network'
                    : profile.name === 'client' ? 'mdi-account-key-outline'
                      : profile.name === 'peer' ? 'mdi-swap-horizontal-bold' : 'mdi-file-sign'"
                />
                <span class="option-body">
                  <span class="option-title">{{ profile.name }}</span>
                  <span class="option-hint">{{ profile.description }}</span>
                  <span class="option-tags">
                    <span v-for="usage in profile.ext_key_usage" :key="usage" class="badge badge-neutral">
                      {{ usage }}
                    </span>
                  </span>
                </span>
              </button>
            </div>
          </div>

          <!-- Step 3: identity -->
          <div v-else-if="step === 2">
            <template v-if="mode === 'csr'">
              <h2 class="step-title">Paste the signing request</h2>
              <p class="step-help">
                Certio reads the subject and SANs out of the CSR. The private key never leaves
                whoever generated it.
              </p>
              <textarea
                v-model="form.csr_pem"
                class="form-textarea"
                rows="12"
                placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;…&#10;-----END CERTIFICATE REQUEST-----"
                spellcheck="false"
              />
              <p class="form-hint">
                Generate one with:
                <code>openssl req -new -key server.key -out server.csr</code>
              </p>
            </template>

            <template v-else>
              <h2 class="step-title">Who is this certificate for?</h2>
              <p class="step-help">
                The Common Name is legacy — the Subject Alternative Names are what clients
                actually check.
              </p>

              <div class="form-group">
                <label class="form-label">Common name <span class="required">*</span></label>
                <input
                  v-model="form.subject.common_name"
                  class="form-input"
                  placeholder="*.example.com"
                  spellcheck="false"
                >
              </div>

              <div class="form-group">
                <label class="form-label">Subject alternative names <span class="required">*</span></label>
                <CertSanInput v-model="form.sans" :common-name="form.subject.common_name" />
              </div>

              <details class="subject-details">
                <summary>Organization details (optional)</summary>
                <div class="form-row mt-4">
                  <div class="form-group">
                    <label class="form-label">Organization</label>
                    <input v-model="form.subject.organization" class="form-input" placeholder="Example Ltd">
                  </div>
                  <div class="form-group">
                    <label class="form-label">Organizational unit</label>
                    <input v-model="form.subject.organizational_unit" class="form-input" placeholder="Platform">
                  </div>
                  <div class="form-group">
                    <label class="form-label">Country</label>
                    <input v-model="form.subject.country" class="form-input" maxlength="2" placeholder="CD">
                  </div>
                  <div class="form-group">
                    <label class="form-label">State / province</label>
                    <input v-model="form.subject.province" class="form-input">
                  </div>
                  <div class="form-group">
                    <label class="form-label">Locality</label>
                    <input v-model="form.subject.locality" class="form-input">
                  </div>
                  <div class="form-group">
                    <label class="form-label">Email</label>
                    <input v-model="form.subject.email" class="form-input" type="email">
                  </div>
                </div>
              </details>
            </template>
          </div>

          <!-- Step 4: key and validity -->
          <div v-else-if="step === 3">
            <h2 class="step-title">Key and lifetime</h2>

            <div v-if="mode === 'managed'" class="form-group">
              <label class="form-label">Key algorithm</label>
              <select v-model="form.key_algorithm" class="form-select">
                <option v-for="algo in catalog.meta?.key_algorithms ?? []" :key="algo" :value="algo">
                  {{ algo }}
                </option>
              </select>
              <p class="form-hint">
                ECDSA P-256 is the sensible default: smaller, faster, and universally supported.
                Choose RSA only when something in the path still requires it.
              </p>
            </div>

            <div class="form-group">
              <label class="form-label">Validity (days)</label>
              <input
                v-model.number="form.validity_days"
                type="number"
                class="form-input"
                min="1"
                :max="caMaxDays || 36500"
                @input="validityTouched = true"
              >
              <p v-if="exceedsCA" class="form-error">
                {{ selectedCA?.name }} expires in {{ caMaxDays }} days. A certificate cannot outlive
                its issuer — shorten this, or renew the CA first.
              </p>
              <p v-else-if="exceedsBrowserMax" class="form-hint warning-hint">
                Above the {{ catalog.meta?.max_leaf_validity_days }}-day CA/Browser Forum maximum.
                Fine for a private CA; public clients would reject it.
              </p>
              <p v-else class="form-hint">
                {{ selectedProfile?.default_validity_days }} days is this profile's default.
              </p>
            </div>

            <div v-if="mode === 'managed'" class="form-group">
              <label class="checkbox-label">
                <input v-model="form.auto_renew" type="checkbox">
                Renew this certificate automatically
              </label>
              <p class="form-hint">
                The scheduler re-signs it before it expires and keeps the same key, so anything
                pinning the public key keeps working.
              </p>
            </div>

            <div v-if="form.auto_renew" class="form-group">
              <label class="form-label">Renew this many days before expiry</label>
              <input v-model.number="form.renew_before_days" type="number" class="form-input" min="1" max="365">
            </div>

            <div class="form-group">
              <label class="form-label">Notes</label>
              <input v-model="form.notes" class="form-input" placeholder="Where this is deployed, who owns it…">
            </div>
          </div>

          <!-- Step 5: review -->
          <div v-else>
            <h2 class="step-title">Review</h2>

            <div class="detail-grid review-grid">
              <span class="detail-label">Authority</span>
              <span class="detail-value">{{ selectedCA?.name }}</span>

              <span class="detail-label">Profile</span>
              <span class="detail-value">
                {{ form.profile }}
                <span class="text-muted text-sm"> — {{ selectedProfile?.description }}</span>
              </span>

              <template v-if="mode === 'managed'">
                <span class="detail-label">Common name</span>
                <span class="detail-value">{{ form.subject.common_name }}</span>

                <span class="detail-label">SANs</span>
                <span class="detail-value">
                  <span v-for="san in form.sans" :key="`${san.type}:${san.value}`" class="chip review-chip">
                    <span class="chip-type">{{ san.type }}</span>
                    <span class="chip-value">{{ san.value }}</span>
                  </span>
                </span>

                <span class="detail-label">Key</span>
                <span class="detail-value">{{ form.key_algorithm }}</span>
              </template>
              <template v-else>
                <span class="detail-label">Source</span>
                <span class="detail-value">External CSR — Certio will not hold the private key</span>
              </template>

              <span class="detail-label">Validity</span>
              <span class="detail-value">{{ form.validity_days }} days</span>

              <span class="detail-label">Auto-renew</span>
              <span class="detail-value">{{ form.auto_renew ? `yes, ${form.renew_before_days}d before expiry` : 'no' }}</span>
            </div>

            <div v-if="needsPassphrase || selectedCA?.passphrase_protected" class="form-group mt-6">
              <label class="form-label">CA passphrase <span class="required">*</span></label>
              <input
                v-model="form.ca_passphrase"
                type="password"
                class="form-input"
                autocomplete="off"
                placeholder="Required to unlock this authority's key"
              >
              <p class="form-hint">Never stored — it is used for this signature only.</p>
            </div>

            <details v-if="mode === 'managed'" class="openssl-box">
              <summary>
                <span class="mdi mdi-console" />
                The equivalent openssl commands
              </summary>
              <p class="form-hint mt-2">
                Certio runs none of this — it uses Go's crypto/x509 directly. This is here so the
                tool teaches the operation rather than hiding it.
              </p>
              <pre class="code-block code-block-sm mt-2">{{ opensslEquivalent }}</pre>
            </details>
          </div>
        </div>

        <div class="card-footer">
          <button v-if="step > 0" class="btn btn-secondary" :disabled="busy" @click="back">
            <span class="mdi mdi-arrow-left" />
            Back
          </button>
          <button
            v-if="step < steps.length - 1"
            class="btn btn-primary"
            :disabled="!canAdvance"
            @click="next"
          >
            Continue
            <span class="mdi mdi-arrow-right" />
          </button>
          <button v-else class="btn btn-primary" :disabled="busy" @click="submit">
            <span v-if="busy" class="spinner" />
            <span v-else class="mdi mdi-check" />
            {{ busy ? 'Signing…' : 'Issue certificate' }}
          </button>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.wizard-page { max-width: 880px; }
.step-title { font-size: 16px; font-weight: 600; margin-bottom: 4px; }
.step-help { font-size: 13.5px; color: var(--text-muted); margin-bottom: 20px; line-height: 1.55; }

.option-grid { display: grid; gap: 10px; }
.option-card {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 14px 16px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  background: var(--bg-primary);
  cursor: pointer;
  text-align: left;
  font-family: inherit;
  transition: border-color var(--transition), background var(--transition);
}
.option-card:hover { border-color: var(--primary-400); background: var(--bg-hover); }
.option-card.selected {
  border-color: var(--primary-600);
  background: var(--primary-50);
  box-shadow: var(--shadow-focus);
}
.option-icon {
  font-size: 22px;
  color: var(--primary-600);
  flex-shrink: 0;
  margin-top: 2px;
}
.option-body { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.option-title { font-weight: 600; color: var(--text-primary); text-transform: capitalize; }
.option-hint { font-size: 12.5px; color: var(--text-muted); line-height: 1.45; }
.option-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
.option-lock { margin-left: auto; color: var(--warning-600); font-size: 16px; }

.subject-details { margin-top: 8px; }
.subject-details summary {
  cursor: pointer;
  font-size: 13px;
  color: var(--primary-600);
  user-select: none;
}

.review-grid { margin-bottom: 8px; }
.review-chip { margin: 0 6px 6px 0; }

.warning-hint { color: var(--warning-600); }

.openssl-box {
  margin-top: 24px;
  padding-top: 18px;
  border-top: 1px dashed var(--border-primary);
}
.openssl-box summary {
  cursor: pointer;
  font-size: 13px;
  color: var(--primary-600);
  user-select: none;
  display: flex;
  align-items: center;
  gap: 6px;
}

.card-footer { justify-content: space-between; }
.card-footer button:only-child { margin-left: auto; }
</style>
