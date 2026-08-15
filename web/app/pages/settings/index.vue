<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useCatalogStore } from '~/stores/catalog'
import { useToast } from '~/composables/useToast'
import type { Settings } from '~/types/api'

useHead({ title: 'Settings · Certio' })

const api = useApi()
const catalog = useCatalogStore()
const toast = useToast()

const settings = ref<Settings | null>(null)
const loading = ref(true)
const busy = ref(false)

const form = reactive({
  default_organization: '',
  default_country: '',
  default_key_algorithm: '',
  default_validity_days: 397,
  expiry_warn_days: 30,
})

onMounted(async () => {
  await catalog.load()
  try {
    settings.value = await api.get<Settings>('/settings')
    Object.assign(form, {
      default_organization: settings.value.default_organization,
      default_country: settings.value.default_country,
      default_key_algorithm: settings.value.default_key_algorithm,
      default_validity_days: settings.value.default_validity_days,
      expiry_warn_days: settings.value.expiry_warn_days,
    })
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load settings')
  } finally {
    loading.value = false
  }
})

async function save() {
  busy.value = true
  try {
    settings.value = await api.patch<Settings>('/settings', form)
    toast.success('Settings saved')
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not save settings')
  } finally {
    busy.value = false
  }
}

const policyText: Record<string, string> = {
  always: 'Private keys can be downloaded as often as needed.',
  once: 'Each private key can be downloaded exactly once, then never again.',
  never: 'Private keys can never be downloaded through the API or dashboard.',
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>Settings</h1>
        <p class="page-subtitle">Instance defaults. Changes apply immediately — no restart needed.</p>
      </div>
    </div>

    <SettingsNav />

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else>
      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Issuance defaults</h2>
            <span class="card-subtitle">Pre-filled on every new certificate and authority</span>
          </div>
        </div>
        <div class="card-body">
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Default organization</label>
              <input v-model="form.default_organization" class="form-input" placeholder="Example Ltd">
              <p class="form-hint">Used when a request leaves the O field blank.</p>
            </div>
            <div class="form-group">
              <label class="form-label">Default country</label>
              <input v-model="form.default_country" class="form-input" maxlength="2" placeholder="CD">
            </div>
          </div>

          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Default key algorithm</label>
              <select v-model="form.default_key_algorithm" class="form-select">
                <option v-for="algo in catalog.meta?.key_algorithms ?? []" :key="algo" :value="algo">
                  {{ algo }}
                </option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Default validity (days)</label>
              <input v-model.number="form.default_validity_days" type="number" class="form-input" min="1">
              <p class="form-hint">
                397 is the CA/Browser Forum maximum for public certificates.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Expiry and renewal</h2>
            <span class="card-subtitle">When Certio starts warning you</span>
          </div>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label class="form-label">Warn this many days before expiry</label>
            <input v-model.number="form.expiry_warn_days" type="number" class="form-input" min="1" max="365">
            <p class="form-hint">
              Certificates inside this window are marked <em>expiring</em>, appear on the dashboard
              and trigger notifications.
            </p>
          </div>

          <div class="detail-grid mt-4">
            <span class="detail-label">Scheduler</span>
            <span class="detail-value">
              <span class="badge" :class="settings?.scheduler_enabled ? 'badge-success' : 'badge-neutral'">
                {{ settings?.scheduler_enabled ? 'running' : 'disabled' }}
              </span>
              <span v-if="!settings?.scheduler_enabled" class="text-muted text-sm">
                — auto-renewal and CRL refresh will not run. Set CERTIO_SCHEDULER_ENABLED=true.
              </span>
            </span>
          </div>
        </div>
      </div>

      <div class="card mb-6">
        <div class="card-header">
          <div>
            <h2>Read-only configuration</h2>
            <span class="card-subtitle">Set through the environment, not the dashboard</span>
          </div>
        </div>
        <div class="card-body">
          <div class="detail-grid">
            <span class="detail-label">Base URL</span>
            <span class="detail-value">
              <span class="mono-value">{{ settings?.base_url }}</span>
              <p class="form-hint">
                Baked into the CRL distribution point of every certificate issued from now on.
                Changing it does not rewrite already-issued certificates.
              </p>
            </span>

            <span class="detail-label">Key download policy</span>
            <span class="detail-value">
              <span class="badge badge-info">{{ settings?.key_download_policy }}</span>
              <p class="form-hint">{{ policyText[settings?.key_download_policy ?? ''] }}</p>
            </span>
          </div>
        </div>
      </div>

      <div class="flex justify-end">
        <button class="btn btn-primary" :disabled="busy" @click="save">
          <span v-if="busy" class="spinner" />
          Save changes
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.settings-page { max-width: 860px; }
</style>
