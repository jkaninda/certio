<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import type { DashboardStats } from '~/types/api'

useHead({ title: 'Dashboard · Certio' })

const api = useApi()
const { date, relative, days, actionLabel } = useFormat()

const stats = ref<DashboardStats | null>(null)
const loading = ref(true)

onMounted(async () => {
  try {
    stats.value = await api.get<DashboardStats>('/dashboard/stats')
  } finally {
    loading.value = false
  }
})

const hasAnything = computed(
  () => (stats.value?.authorities.total ?? 0) > 0 || (stats.value?.certificates.total ?? 0) > 0,
)

/** The headline number is "needs attention", not "total" — that is the one
    that should make someone act. */
const needsAttention = computed(() => {
  const c = stats.value?.certificates
  return (c?.expiring ?? 0) + (c?.expired ?? 0)
})

function severityClassFor(severity: string) {
  return severity
}
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1>Dashboard</h1>
        <p class="page-subtitle">Every certificate you manage, and what expires next.</p>
      </div>
      <div class="page-header-actions">
        <NuxtLink to="/authorities/new" class="btn btn-secondary">
          <span class="mdi mdi-certificate-outline" />
          New authority
        </NuxtLink>
        <NuxtLink to="/certificates/new" class="btn btn-primary">
          <span class="mdi mdi-plus" />
          Issue certificate
        </NuxtLink>
      </div>
    </div>

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <template v-else-if="stats">
      <!-- First run: point at the one thing that has to happen first. -->
      <div v-if="!hasAnything" class="card">
        <UiEmptyState
          icon="shield-plus-outline"
          title="No certificate authority yet"
          message="Certio needs a CA before it can issue anything. Create a root — or import the CA you already
                   manage with openssl, keys and all."
        >
          <div class="flex gap-2 justify-center">
            <NuxtLink to="/authorities/new" class="btn btn-primary">Create a root CA</NuxtLink>
            <NuxtLink to="/authorities/new?mode=import" class="btn btn-secondary">Import an existing CA</NuxtLink>
          </div>
        </UiEmptyState>
      </div>

      <template v-else>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-label">Certificates</span>
              <span class="stat-icon stat-icon-primary mdi mdi-file-certificate-outline" />
            </div>
            <div class="stat-value">{{ stats.certificates.total }}</div>
            <div class="stat-sub">{{ stats.certificates.active }} active</div>
          </div>

          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-label">Needs attention</span>
              <span
                class="stat-icon mdi mdi-clock-alert-outline"
                :class="needsAttention > 0 ? 'stat-icon-warning' : 'stat-icon-secondary'"
              />
            </div>
            <div class="stat-value">{{ needsAttention }}</div>
            <div class="stat-sub">
              {{ stats.certificates.expiring }} expiring · {{ stats.certificates.expired }} expired
            </div>
          </div>

          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-label">Authorities</span>
              <span class="stat-icon stat-icon-secondary mdi mdi-certificate-outline" />
            </div>
            <div class="stat-value">{{ stats.authorities.total }}</div>
            <div class="stat-sub">{{ stats.authorities.active }} active</div>
          </div>

          <div class="stat-card">
            <div class="stat-header">
              <span class="stat-label">Revoked</span>
              <span
                class="stat-icon mdi mdi-close-octagon-outline"
                :class="stats.revocations > 0 ? 'stat-icon-danger' : 'stat-icon-secondary'"
              />
            </div>
            <div class="stat-value">{{ stats.revocations }}</div>
            <div class="stat-sub">published on each CA's CRL</div>
          </div>
        </div>

        <div class="dashboard-grid">
          <!-- Expiry timeline -->
          <div class="card">
            <div class="card-header">
              <div>
                <h2>Expiry timeline</h2>
                <span class="card-subtitle">Closest to expiry first</span>
              </div>
              <NuxtLink to="/certificates?sort=not_after" class="btn btn-ghost btn-sm">
                View all
              </NuxtLink>
            </div>
            <div class="card-body">
              <UiEmptyState
                v-if="!stats.timeline.length"
                icon="calendar-check-outline"
                title="Nothing issued yet"
                message="Certificates appear here as soon as you issue them."
              />
              <div v-else>
                <NuxtLink
                  v-for="entry in stats.timeline"
                  :key="entry.id"
                  :to="`/certificates/${entry.id}`"
                  class="expiry-row expiry-link"
                >
                  <div class="min-w-0">
                    <div class="expiry-name truncate">
                      {{ entry.common_name }}
                      <span v-if="entry.auto_renew" class="mdi mdi-autorenew auto-renew-icon" title="Auto-renew is on" />
                    </div>
                    <div class="expiry-meta truncate">
                      {{ entry.ca_name }} · expires {{ date(entry.not_after) }}
                    </div>
                    <CertExpiryBar
                      class="mt-2"
                      :not-before="entry.not_before"
                      :not-after="entry.not_after"
                      :days-remaining="entry.days_remaining"
                      :severity="entry.severity"
                      :percent-elapsed="entry.percent_elapsed"
                    />
                  </div>
                  <div class="expiry-days" :class="severityClassFor(entry.severity)">
                    {{ days(entry.days_remaining) }}
                  </div>
                </NuxtLink>
              </div>
            </div>
          </div>

          <!-- Recent activity -->
          <div class="card">
            <div class="card-header">
              <div>
                <h2>Recent activity</h2>
                <span class="card-subtitle">From the audit log</span>
              </div>
            </div>
            <div class="card-body">
              <UiEmptyState
                v-if="!stats.recent_activity.length"
                icon="history"
                title="No activity yet"
              />
              <ul v-else class="activity-list">
                <li v-for="entry in stats.recent_activity" :key="entry.id" class="activity-item">
                  <span
                    class="activity-dot"
                    :class="entry.success ? 'activity-dot-ok' : 'activity-dot-fail'"
                  />
                  <div class="min-w-0">
                    <div class="activity-text">
                      <strong>{{ entry.actor_name || 'system' }}</strong>
                      {{ actionLabel(entry.action) }}
                      <span v-if="entry.resource_name" class="activity-resource">{{ entry.resource_name }}</span>
                    </div>
                    <div class="activity-meta">{{ relative(entry.created_at) }}</div>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <!-- Scheduler status: silent failure here is what lets certificates lapse. -->
        <div v-if="stats.last_job" class="scheduler-note">
          <span class="mdi" :class="stats.last_job.status === 'failed' ? 'mdi-alert-circle-outline' : 'mdi-check-circle-outline'" />
          Last expiry scan {{ relative(stats.last_job.finished_at || stats.last_job.created_at) }} —
          <strong>{{ stats.last_job.status }}</strong>
          <span v-if="stats.last_job.error"> · {{ stats.last_job.error }}</span>
        </div>
      </template>
    </template>
  </div>
</template>

<style scoped>
.dashboard-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.5fr) minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}
@media (max-width: 1000px) {
  .dashboard-grid { grid-template-columns: 1fr; }
}

.min-w-0 { min-width: 0; }

.expiry-link {
  color: inherit;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 90px;
  gap: 12px 16px;
  align-items: center;
}
.expiry-link:hover { color: inherit; }
.expiry-link:hover .expiry-name { color: var(--primary-600); }

.auto-renew-icon { font-size: 13px; color: var(--success-600); margin-left: 4px; }

.activity-list { list-style: none; display: flex; flex-direction: column; gap: 14px; }
.activity-item { display: flex; gap: 10px; align-items: flex-start; }
.activity-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  margin-top: 7px;
  flex-shrink: 0;
}
.activity-dot-ok { background: var(--success-500); }
.activity-dot-fail { background: var(--danger-500); }
.activity-text { font-size: 13.5px; color: var(--text-secondary); line-height: 1.45; }
.activity-text strong { color: var(--text-primary); font-weight: 600; }
.activity-resource { color: var(--text-primary); font-family: var(--font-mono); font-size: 12.5px; }
.activity-meta { font-size: 12px; color: var(--text-muted); margin-top: 1px; }

.scheduler-note {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 18px;
  font-size: 12.5px;
  color: var(--text-muted);
}
.scheduler-note strong { color: var(--text-secondary); }
</style>
