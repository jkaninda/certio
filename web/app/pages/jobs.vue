<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { Job, PageMeta } from '~/types/api'

useHead({ title: 'Jobs · Certio' })

const api = useApi()
const toast = useToast()
const { dateTime, relative } = useFormat()

const items = ref<Job[]>([])
const meta = ref<PageMeta>({ total: 0, page: 1, limit: 25, total_pages: 0 })
const loading = ref(true)
const page = ref(1)
const kind = ref('')

const kinds = [
  { value: '', label: 'All jobs' },
  { value: 'expiry_scan', label: 'Expiry scan' },
  { value: 'auto_renew', label: 'Auto-renewal' },
  { value: 'crl_refresh', label: 'CRL refresh' },
]

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: Job[] } & PageMeta>('/jobs', {
      kind: kind.value, page: page.value, limit: 25,
    })
    items.value = payload.items ?? []
    meta.value = {
      total: payload.total, page: payload.page,
      limit: payload.limit, total_pages: payload.total_pages,
    }
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load the job history')
  } finally {
    loading.value = false
  }
}

watch(kind, () => { page.value = 1; load() })
watch(page, load)
onMounted(load)

function duration(job: Job): string {
  if (!job.started_at || !job.finished_at) return '—'
  const ms = new Date(job.finished_at).getTime() - new Date(job.started_at).getTime()
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

function statusBadge(status: string): string {
  switch (status) {
    case 'succeeded': return 'badge-success'
    case 'failed': return 'badge-danger'
    case 'running': return 'badge-info'
    default: return 'badge-neutral'
  }
}

/** summary renders a result map as the short sentence an operator wants. */
function summary(job: Job): string {
  const result = job.result
  if (!result || Object.keys(result).length === 0) return '—'
  return Object.entries(result)
    .filter(([, value]) => value !== 0)
    .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${value}`)
    .join(' · ') || 'nothing to do'
}
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1>Scheduled jobs</h1>
        <p class="page-subtitle">
          What the in-process scheduler has been doing — expiry scans, auto-renewals and CRL refreshes.
        </p>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-secondary" :disabled="loading" @click="load">
          <span class="mdi mdi-refresh" />
          Refresh
        </button>
      </div>
    </div>

    <div class="toolbar">
      <select v-model="kind" class="form-select">
        <option v-for="option in kinds" :key="option.value" :value="option.value">{{ option.label }}</option>
      </select>
    </div>

    <div class="card">
      <div v-if="loading" class="loading-page">
        <span class="spinner spinner-lg" />
      </div>

      <UiEmptyState
        v-else-if="!items.length"
        icon="timer-sand-empty"
        title="The scheduler has not run yet"
        message="It runs once at startup and then on its interval. If this stays empty, check that the scheduler is enabled."
      />

      <template v-else>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Result</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="job in items" :key="job.id">
                <td class="cell-title">{{ job.kind.replace(/_/g, ' ') }}</td>
                <td class="text-sm nowrap" :title="dateTime(job.started_at || job.created_at)">
                  {{ relative(job.started_at || job.created_at) }}
                </td>
                <td class="text-sm cell-num">{{ duration(job) }}</td>
                <td class="text-sm">
                  <span v-if="job.error" class="job-error">{{ job.error }}</span>
                  <span v-else>{{ summary(job) }}</span>
                </td>
                <td><span class="badge badge-dot" :class="statusBadge(job.status)">{{ job.status }}</span></td>
              </tr>
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
.job-error { color: var(--danger-600); }
</style>
