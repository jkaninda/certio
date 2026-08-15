<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useCatalogStore } from '~/stores/catalog'
import { useToast } from '~/composables/useToast'
import { ApiRequestError } from '~/composables/useApi'
import type { Authority } from '~/types/api'

useHead({ title: 'New authority · Certio' })

const api = useApi()
const route = useRoute()
const catalog = useCatalogStore()
const toast = useToast()

type Mode = 'create' | 'import'
const mode = ref<Mode>((route.query.mode as Mode) === 'import' ? 'import' : 'create')

const form = reactive({
  name: '',
  type: 'root' as 'root' | 'intermediate',
  parent_id: '',
  subject: {
    common_name: '',
    organization: '',
    organizational_unit: '',
    country: '',
    province: '',
    locality: '',
  },
  key_algorithm: 'ecdsa-p256',
  validity_days: 3650,
  passphrase: '',
  passphrase_confirm: '',
  parent_passphrase: '',
  permitted_dns: '',
  permitted_ip: '',
  excluded_dns: '',
  description: '',
  // Import fields
  cert_pem: '',
  key_pem: '',
})

const busy = ref(false)
const usePassphrase = ref(false)

onMounted(async () => {
  await catalog.load()
  form.key_algorithm = catalog.meta?.key_algorithms?.[0] ?? 'ecdsa-p256'
})

const rootAuthorities = computed(() =>
  catalog.authorities.filter((ca) => ca.status !== 'expired' && ca.status !== 'revoked'),
)

// A root defaults to ten years, an intermediate to five: the intermediate is
// the one that rotates.
function onTypeChange() {
  form.validity_days = form.type === 'root' ? 3650 : 1825
}

/** Name constraints are sent only when something was typed: an empty object
 *  would mark the extension present and constrain nothing. */
const nameConstraints = computed(() => {
  const split = (value: string) =>
    value.split(',').map((entry) => entry.trim()).filter(Boolean)

  const constraints = {
    permitted_dns: split(form.permitted_dns),
    permitted_ip: split(form.permitted_ip),
    excluded_dns: split(form.excluded_dns),
  }
  const empty = Object.values(constraints).every((list) => list.length === 0)
  return empty ? undefined : constraints
})

const passphraseMismatch = computed(
  () => usePassphrase.value && form.passphrase !== form.passphrase_confirm,
)

const canSubmit = computed(() => {
  if (busy.value) return false
  if (mode.value === 'import') return !!form.cert_pem.trim() && !!form.key_pem.trim()
  if (!form.subject.common_name) return false
  if (form.type === 'intermediate' && !form.parent_id) return false
  if (usePassphrase.value && (!form.passphrase || passphraseMismatch.value)) return false
  return true
})

async function submit() {
  busy.value = true
  try {
    const created = mode.value === 'import'
      ? await api.post<Authority>('/authorities/import', {
          name: form.name || undefined,
          description: form.description || undefined,
          cert_pem: form.cert_pem,
          key_pem: form.key_pem,
          passphrase: usePassphrase.value ? form.passphrase : undefined,
        })
      : await api.post<Authority>('/authorities', {
          name: form.name || form.subject.common_name,
          description: form.description || undefined,
          type: form.type,
          parent_id: form.type === 'intermediate' ? form.parent_id : undefined,
          subject: form.subject,
          key_algorithm: form.key_algorithm,
          validity_days: form.validity_days,
          name_constraints: nameConstraints.value,
          passphrase: usePassphrase.value ? form.passphrase : undefined,
          parent_passphrase: form.parent_passphrase || undefined,
        })

    await catalog.refreshAuthorities()
    toast.success(mode.value === 'import' ? 'Authority imported' : 'Authority created')
    await navigateTo(`/authorities/${created.id}`)
  } catch (err) {
    if (err instanceof ApiRequestError && err.needsPassphrase) {
      toast.warning('The parent CA is passphrase-protected. Enter it to sign this intermediate.')
    } else {
      toast.error(err instanceof Error ? err.message : 'the request failed')
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="form-page">
    <div class="breadcrumb">
      <NuxtLink to="/authorities">Authorities</NuxtLink>
      <span class="mdi mdi-chevron-right" />
      <span>{{ mode === 'import' ? 'Import' : 'New' }}</span>
    </div>

    <div class="page-header">
      <div>
        <h1>{{ mode === 'import' ? 'Import a certificate authority' : 'New certificate authority' }}</h1>
        <p class="page-subtitle">
          {{ mode === 'import'
            ? 'Adopt a CA you already manage. Nothing is re-issued — the existing certificate and key are taken as they are.'
            : 'Certio generates the key, self-signs a root or has a parent sign an intermediate, and stores the key encrypted.' }}
        </p>
      </div>
    </div>

    <div class="tabs">
      <button class="tab" :class="{ active: mode === 'create' }" @click="mode = 'create'">Create new</button>
      <button class="tab" :class="{ active: mode === 'import' }" @click="mode = 'import'">Import existing</button>
    </div>

    <div class="card">
      <div class="card-body">
        <!-- ─── Import ─── -->
        <template v-if="mode === 'import'">
          <div class="app-banner app-banner--info mb-6">
            <span class="app-banner-icon mdi mdi-information-outline" />
            <div class="app-banner-content">
              <p class="app-banner-text">
                Certio checks that the key matches the certificate and that the certificate is
                actually a CA before accepting it. The key is re-encrypted with this instance's
                master key on the way in.
              </p>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Certificate (PEM) <span class="required">*</span></label>
            <textarea
              v-model="form.cert_pem"
              class="form-textarea"
              rows="8"
              spellcheck="false"
              placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
            />
          </div>

          <div class="form-group">
            <label class="form-label">Private key (PEM) <span class="required">*</span></label>
            <textarea
              v-model="form.key_pem"
              class="form-textarea"
              rows="8"
              spellcheck="false"
              placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"
            />
            <p class="form-hint">
              PKCS#8, PKCS#1 or SEC 1. A passphrase-encrypted key must be decrypted first:
              <code>openssl pkey -in ca.key -out ca-plain.key</code>
            </p>
          </div>

          <div class="form-group">
            <label class="form-label">Display name</label>
            <input v-model="form.name" class="form-input" placeholder="Defaults to the certificate's common name">
          </div>
        </template>

        <!-- ─── Create ─── -->
        <template v-else>
          <div class="form-group">
            <label class="form-label">Type</label>
            <div class="type-choice">
              <button
                class="option-card"
                :class="{ selected: form.type === 'root' }"
                @click="form.type = 'root'; onTypeChange()"
              >
                <span class="option-icon mdi mdi-shield-crown-outline" />
                <span class="option-body">
                  <span class="option-title">Root CA</span>
                  <span class="option-hint">
                    Self-signed trust anchor. Install it on clients once; keep it long-lived.
                  </span>
                </span>
              </button>
              <button
                class="option-card"
                :class="{ selected: form.type === 'intermediate' }"
                :disabled="!rootAuthorities.length"
                @click="form.type = 'intermediate'; onTypeChange()"
              >
                <span class="option-icon mdi mdi-shield-link-variant-outline" />
                <span class="option-body">
                  <span class="option-title">Intermediate CA</span>
                  <span class="option-hint">
                    Signed by a root and used for day-to-day issuance, so the root can stay offline.
                  </span>
                </span>
              </button>
            </div>
          </div>

          <div v-if="form.type === 'intermediate'" class="form-group">
            <label class="form-label">Parent authority <span class="required">*</span></label>
            <select v-model="form.parent_id" class="form-select">
              <option value="">Choose the signing CA…</option>
              <option v-for="ca in rootAuthorities" :key="ca.id" :value="ca.id">
                {{ ca.name }} ({{ ca.type }})
              </option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Common name <span class="required">*</span></label>
            <input
              v-model="form.subject.common_name"
              class="form-input"
              placeholder="Example Root CA"
            >
            <p class="form-hint">
              A label, not a hostname — this is how the CA identifies itself in every chain.
            </p>
          </div>

          <div class="form-group">
            <label class="form-label">Display name</label>
            <input v-model="form.name" class="form-input" placeholder="Defaults to the common name">
          </div>

          <div class="constraints-block">
            <label class="form-label">Name constraints</label>
            <p class="form-hint mb-2">
              What this CA is allowed to certify. A root installed in a trust store and left
              unconstrained can mint a certificate for <em>any</em> name on the internet — so a
              stolen key stops being an internal problem. Empty means no limit.
            </p>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label form-label-sm">Permitted domains</label>
                <input v-model="form.permitted_dns" class="form-input" placeholder="corp.example.com, lab.example.com">
                <p class="form-hint">Comma-separated. Subdomains are included.</p>
              </div>
              <div class="form-group">
                <label class="form-label form-label-sm">Permitted IP ranges</label>
                <input v-model="form.permitted_ip" class="form-input" placeholder="10.0.0.0/8">
                <p class="form-hint">CIDR notation.</p>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label form-label-sm">Excluded domains</label>
              <input v-model="form.excluded_dns" class="form-input" placeholder="secret.corp.example.com">
              <p class="form-hint">Always wins over a permission.</p>
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Organization</label>
              <input v-model="form.subject.organization" class="form-input">
            </div>
            <div class="form-group">
              <label class="form-label">Organizational unit</label>
              <input v-model="form.subject.organizational_unit" class="form-input">
            </div>
            <div class="form-group">
              <label class="form-label">Country</label>
              <input v-model="form.subject.country" class="form-input" maxlength="2" placeholder="CD">
            </div>
            <div class="form-group">
              <label class="form-label">State / province</label>
              <input v-model="form.subject.province" class="form-input">
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Key algorithm</label>
              <select v-model="form.key_algorithm" class="form-select">
                <option v-for="algo in catalog.meta?.key_algorithms ?? []" :key="algo" :value="algo">
                  {{ algo }}
                </option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Validity (days)</label>
              <input v-model.number="form.validity_days" type="number" class="form-input" min="1">
              <p class="form-hint">
                {{ form.type === 'root' ? '10 years is typical for a root.' : '5 years is typical for an intermediate.' }}
              </p>
            </div>
          </div>

          <div v-if="form.type === 'intermediate'" class="form-group">
            <label class="form-label">Parent CA passphrase (if required)</label>
            <input v-model="form.parent_passphrase" type="password" class="form-input" autocomplete="off">
          </div>
        </template>

        <!-- ─── Shared ─── -->
        <div class="form-group">
          <label class="checkbox-label">
            <input v-model="usePassphrase" type="checkbox">
            Protect this CA's key with a passphrase
          </label>
          <p class="form-hint">
            Adds a second factor on top of the master key. The passphrase is never stored, so it
            must be supplied every time this CA signs — including for automatic CRL refresh, which
            will be skipped for this CA.
          </p>
        </div>

        <div v-if="usePassphrase" class="form-row">
          <div class="form-group">
            <label class="form-label">Passphrase <span class="required">*</span></label>
            <input v-model="form.passphrase" type="password" class="form-input" autocomplete="new-password">
          </div>
          <div class="form-group">
            <label class="form-label">Confirm passphrase</label>
            <input v-model="form.passphrase_confirm" type="password" class="form-input" autocomplete="new-password">
            <p v-if="passphraseMismatch" class="form-error">The passphrases do not match.</p>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Description</label>
          <input v-model="form.description" class="form-input" placeholder="What this CA is for">
        </div>
      </div>

      <div class="card-footer">
        <NuxtLink to="/authorities" class="btn btn-secondary">Cancel</NuxtLink>
        <button class="btn btn-primary" :disabled="!canSubmit" @click="submit">
          <span v-if="busy" class="spinner" />
          {{ mode === 'import' ? 'Import authority' : 'Create authority' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.form-page { max-width: 780px; }
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

.type-choice { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; }

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
.option-card:hover:not(:disabled) { border-color: var(--primary-400); background: var(--bg-hover); }
.option-card:disabled { opacity: 0.5; cursor: not-allowed; }
.option-card.selected {
  border-color: var(--primary-600);
  background: var(--primary-50);
  box-shadow: var(--shadow-focus);
}
.option-icon { font-size: 22px; color: var(--primary-600); flex-shrink: 0; margin-top: 2px; }
.option-body { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.option-title { font-weight: 600; color: var(--text-primary); }
.option-hint { font-size: 12.5px; color: var(--text-muted); line-height: 1.45; }

.form-hint code {
  background: var(--bg-tertiary);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11.5px;
}

.constraints-block {
  padding: 14px 16px;
  margin-bottom: 16px;
  border: 1px dashed var(--border-primary);
  border-radius: var(--radius);
  background: var(--bg-secondary);
}
.form-label-sm { font-size: 12.5px; font-weight: 500; }
.mb-2 { margin-bottom: 8px; }
</style>
