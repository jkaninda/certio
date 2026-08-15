<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { AuditEntry, PageMeta } from '~/types/api'

useHead({ title: 'Audit log · Certio' })

const api = useApi()
const toast = useToast()
const { dateTime, relative, actionLabel } = useFormat()

const items = ref<AuditEntry[]>([])
const meta = ref<PageMeta>({ total: 0, page: 1, limit: 25, total_pages: 0 })
const loading = ref(true)
const page = ref(1)
const search = ref('')
const actionFilter = ref('')
const expanded = ref<Set<string>>(new Set())

let timer: ReturnType<typeof setTimeout> | undefined

const actions = [
  { value: '', label: 'All actions' },
  { value: 'cert.issue', label: 'Certificate issued' },
  { value: 'cert.renew', label: 'Certificate renewed' },
  { value: 'cert.revoke', label: 'Certificate revoked' },
  { value: 'cert.key_download', label: 'Key downloaded' },
  { value: 'cert.key_download_denied', label: 'Key download denied' },
  { value: 'ca.create', label: 'CA created' },
  { value: 'ca.delete', label: 'CA deleted' },
  { value: 'auth.login', label: 'Sign-in' },
  { value: 'auth.login_failed', label: 'Failed sign-in' },
]

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: AuditEntry[] } & PageMeta>('/audit-logs', {
      q: search.value,
      action: actionFilter.value,
      page: page.value,
      limit: 25,
    })
    items.value = payload.items ?? []
    meta.value = {
      total: payload.total, page: payload.page,
      limit: payload.limit, total_pages: payload.total_pages,
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load the audit log')
  } finally {
    loading.value = false
  }
}

watch(search, () => {
  clearTimeout(timer)
  timer = setTimeout(() => { page.value = 1; load() }, 300)
})
watch(actionFilter, () => { page.value = 1; load() })
watch(page, load)

onMounted(load)

function toggle(id: string) {
  const next = new Set(expanded.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expanded.value = next
}

function hasDetail(entry: AuditEntry): boolean {
  return !!entry.error || Object.keys(entry.metadata ?? {}).length > 0
}
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1>Audit log</h1>
        <p class="page-subtitle">
          Every mutation, append-only. There is no endpoint to edit or delete these records.
        </p>
      </div>
    </div>

    <div class="toolbar">
      <input v-model="search" class="form-input search-input" type="search" placeholder="Search action, resource or actor…">
      <select v-model="actionFilter" class="form-select">
        <option v-for="option in actions" :key="option.value" :value="option.value">{{ option.label }}</option>
      </select>
    </div>

    <div class="card">
      <div v-if="loading" class="loading-page">
        <span class="spinner spinner-lg" />
      </div>

      <UiEmptyState
        v-else-if="!items.length"
        icon="text-box-search-outline"
        title="Nothing recorded yet"
        message="Audit entries appear as soon as anything is created, renewed or revoked."
      />

      <template v-else>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
                <th>Resource</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <template v-for="entry in items" :key="entry.id">
                <tr :class="{ 'row-clickable': hasDetail(entry) }" @click="hasDetail(entry) && toggle(entry.id)">
                  <td class="text-sm nowrap" :title="dateTime(entry.created_at)">
                    {{ relative(entry.created_at) }}
                  </td>
                  <td>
                    <div class="cell-text">
                      <span class="cell-title">{{ entry.actor_name || 'system' }}</span>
                      <span class="cell-sub">{{ entry.actor_type }}{{ entry.ip ? ` · ${entry.ip}` : '' }}</span>
                    </div>
                  </td>
                  <td>
                    <span class="badge badge-dot" :class="entry.success ? 'badge-success' : 'badge-danger'">
                      {{ actionLabel(entry.action) }}
                    </span>
                  </td>
                  <td class="text-sm">
                    <span v-if="entry.resource_name" class="resource-name">{{ entry.resource_name }}</span>
                    <span v-else class="text-muted">—</span>
                  </td>
                  <td class="table-actions">
                    <span
                      v-if="hasDetail(entry)"
                      class="mdi"
                      :class="expanded.has(entry.id) ? 'mdi-chevron-up' : 'mdi-chevron-down'"
                    />
                  </td>
                </tr>
                <tr v-if="expanded.has(entry.id)" :key="`${entry.id}-detail`" class="detail-row">
                  <td colspan="5">
                    <div v-if="entry.error" class="audit-error">
                      <span class="mdi mdi-alert-circle-outline" />
                      {{ entry.error }}
                    </div>
                    <pre v-if="entry.metadata" class="code-block code-block-sm">{{ JSON.stringify(entry.metadata, null, 2) }}</pre>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <UiPagination
          :page="meta.page"
          :limit="meta.limit"
          :total="meta.total"
          :total-pages="meta.total_pages"
          @update:page="page = $event"
        />
      </template>
    </div>
  </div>
</template>

<style scoped>
.nowrap { white-space: nowrap; }
.resource-name { font-family: var(--font-mono); font-size: 12.5px; color: var(--text-primary); }
.detail-row td { background: var(--bg-secondary); padding: 14px 16px; }
.audit-error {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--danger-600);
  font-size: 13px;
  margin-bottom: 10px;
}
</style>
