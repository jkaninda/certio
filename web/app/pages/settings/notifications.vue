<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useToast } from '~/composables/useToast'
import type { Notification } from '~/types/api'

useHead({ title: 'Notifications · Certio' })

const api = useApi()
const toast = useToast()
const { relative } = useFormat()

const items = ref<Notification[]>([])
const loading = ref(true)
const busy = ref(false)
const testing = ref<string | null>(null)

const createOpen = ref(false)
const deleting = ref<Notification | null>(null)

const form = reactive({
  name: '',
  channel: 'webhook' as 'webhook' | 'smtp' | 'slack' | 'telegram',
  enabled: true,
  events: ['*'] as string[],
  config: {} as Record<string, string>,
})

const allEvents = [
  { value: 'certificate.expiring', label: 'Certificate expiring' },
  { value: 'certificate.expired', label: 'Certificate expired' },
  { value: 'certificate.renewed', label: 'Certificate renewed' },
  { value: 'certificate.revoked', label: 'Certificate revoked' },
  { value: 'authority.expiring', label: 'Authority expiring' },
  { value: 'renewal.failed', label: 'Auto-renewal failed' },
]

const allEventsSelected = computed(() => form.events.includes('*'))

/** Each channel declares the fields it needs, so the form is data-driven. */
const channelFields: Record<string, { key: string; label: string; type?: string; hint?: string; placeholder?: string }[]> = {
  webhook: [
    { key: 'url', label: 'Webhook URL', placeholder: 'https://hooks.example.com/certio' },
    { key: 'secret', label: 'Shared secret', type: 'password', hint: 'Sent as the X-Certio-Token header so the receiver can verify the caller.' },
  ],
  slack: [
    { key: 'webhook_url', label: 'Incoming webhook URL', placeholder: 'https://hooks.slack.com/services/…' },
    { key: 'channel', label: 'Channel override', placeholder: '#infrastructure' },
    { key: 'username', label: 'Bot username', placeholder: 'certio' },
  ],
  telegram: [
    { key: 'bot_token', label: 'Bot token', type: 'password', hint: 'From @BotFather.', placeholder: '123456:ABC-DEF…' },
    { key: 'chat_id', label: 'Chat ID', hint: 'A user, group or channel id — the bot must be a member.', placeholder: '-1001234567890' },
    { key: 'message_thread_id', label: 'Topic ID', hint: 'Optional. Targets one topic in a forum group.' },
  ],
  smtp: [
    { key: 'host', label: 'SMTP host', placeholder: 'smtp.example.com' },
    { key: 'port', label: 'Port', placeholder: '587' },
    { key: 'username', label: 'Username' },
    { key: 'password', label: 'Password', type: 'password' },
    { key: 'from', label: 'From address', placeholder: 'certio@example.com' },
    { key: 'to', label: 'Recipients', hint: 'Comma-separated.', placeholder: 'ops@example.com, sre@example.com' },
    { key: 'tls', label: 'TLS mode', hint: 'starttls (default), tls for implicit TLS, or none.', placeholder: 'starttls' },
  ],
}

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: Notification[] }>('/notifications')
    items.value = payload.items ?? []
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load notification channels')
  } finally {
    loading.value = false
  }
}

onMounted(load)

function resetForm() {
  Object.assign(form, {
    name: '', channel: 'webhook', enabled: true, events: ['*'], config: {},
  })
}

function toggleAllEvents() {
  form.events = allEventsSelected.value ? [] : ['*']
}

function toggleEvent(value: string) {
  const next = form.events.filter((e) => e !== '*')
  form.events = next.includes(value) ? next.filter((e) => e !== value) : [...next, value]
}

async function create() {
  busy.value = true
  try {
    await api.post('/notifications', {
      name: form.name,
      channel: form.channel,
      config: form.config,
      events: form.events.length ? form.events : ['*'],
      enabled: form.enabled,
    })
    toast.success('Channel added')
    createOpen.value = false
    resetForm()
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not add the channel')
  } finally {
    busy.value = false
  }
}

async function toggleEnabled(channel: Notification) {
  try {
    await api.patch(`/notifications/${channel.id}`, { enabled: !channel.enabled })
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not update the channel')
  }
}

async function test(channel: Notification) {
  testing.value = channel.id
  try {
    await api.post(`/notifications/${channel.id}/test`)
    toast.success(`Test sent through ${channel.name}`)
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'the test failed')
  } finally {
    testing.value = null
    await load()
  }
}

async function remove() {
  if (!deleting.value) return
  busy.value = true
  try {
    await api.del(`/notifications/${deleting.value.id}`)
    toast.success('Channel deleted')
    deleting.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not delete the channel')
  } finally {
    busy.value = false
  }
}

const channelIcon: Record<string, string> = {
  webhook: 'webhook',
  slack: 'slack',
  telegram: 'telegram',
  smtp: 'email-outline',
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>Notifications</h1>
        <p class="page-subtitle">
          Where expiry warnings and renewal failures go. Delivery settings are encrypted at rest.
        </p>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-primary" @click="createOpen = true">
          <span class="mdi mdi-bell-plus-outline" />
          Add channel
        </button>
      </div>
    </div>

    <SettingsNav />

    <div v-if="loading" class="loading-page">
      <span class="spinner spinner-lg" />
    </div>

    <div v-else-if="!items.length" class="card">
      <UiEmptyState
        icon="bell-off-outline"
        title="No channels configured"
        message="Without one, an expiring certificate is only visible if someone opens this dashboard.
                 A webhook or an email is what turns that into something you notice."
      >
        <button class="btn btn-primary" @click="createOpen = true">Add a channel</button>
      </UiEmptyState>
    </div>

    <div v-else class="channel-list">
      <div v-for="channel in items" :key="channel.id" class="card channel-card">
        <div class="channel-head">
          <span class="channel-icon mdi" :class="`mdi-${channelIcon[channel.channel] ?? 'bell-outline'}`" />
          <div class="flex-1 min-w-0">
            <div class="channel-name">
              {{ channel.name }}
              <span class="badge badge-secondary">{{ channel.channel }}</span>
              <span class="badge" :class="channel.enabled ? 'badge-success' : 'badge-neutral'">
                {{ channel.enabled ? 'enabled' : 'disabled' }}
              </span>
            </div>
            <div class="channel-meta">
              {{ channel.events.includes('*') ? 'all events' : channel.events.join(', ') }}
              <template v-if="channel.last_sent_at"> · last sent {{ relative(channel.last_sent_at) }}</template>
            </div>
          </div>

          <div class="channel-actions">
            <button class="btn btn-ghost btn-sm" :disabled="testing === channel.id" @click="test(channel)">
              <span v-if="testing === channel.id" class="spinner" />
              <span v-else class="mdi mdi-send-outline" />
              Test
            </button>
            <button class="btn btn-icon btn-icon-muted" :title="channel.enabled ? 'Disable' : 'Enable'" @click="toggleEnabled(channel)">
              <span class="mdi" :class="channel.enabled ? 'mdi-bell-off-outline' : 'mdi-bell-outline'" />
            </button>
            <button class="btn btn-icon btn-icon-danger" title="Delete" @click="deleting = channel">
              <span class="mdi mdi-delete-outline" />
            </button>
          </div>
        </div>

        <p v-if="channel.last_error" class="channel-error">
          <span class="mdi mdi-alert-circle-outline" />
          Last delivery failed: {{ channel.last_error }}
        </p>
      </div>
    </div>

    <!-- Create -->
    <UiBaseModal v-if="createOpen" title="Add a notification channel" wide :busy="busy" @close="createOpen = false">
      <div class="form-group">
        <label class="form-label">Name <span class="required">*</span></label>
        <input v-model="form.name" class="form-input" placeholder="Ops on-call">
      </div>

      <div class="form-group">
        <label class="form-label">Channel</label>
        <div class="channel-choice">
          <button
            v-for="option in ['webhook', 'slack', 'telegram', 'smtp'] as const"
            :key="option"
            class="channel-option"
            :class="{ selected: form.channel === option }"
            @click="form.channel = option; form.config = {}"
          >
            <span class="mdi" :class="`mdi-${channelIcon[option]}`" />
            {{ option }}
          </button>
        </div>
      </div>

      <div v-for="field in channelFields[form.channel]" :key="field.key" class="form-group">
        <label class="form-label">{{ field.label }}</label>
        <input
          v-model="form.config[field.key]"
          :type="field.type ?? 'text'"
          class="form-input"
          :placeholder="field.placeholder"
          autocomplete="off"
        >
        <p v-if="field.hint" class="form-hint">{{ field.hint }}</p>
      </div>

      <div class="form-group">
        <label class="form-label">Events</label>
        <label class="checkbox-label mb-2">
          <input type="checkbox" :checked="allEventsSelected" @change="toggleAllEvents">
          All events
        </label>
        <div v-if="!allEventsSelected" class="event-grid">
          <label v-for="event in allEvents" :key="event.value" class="checkbox-label">
            <input
              type="checkbox"
              :checked="form.events.includes(event.value)"
              @change="toggleEvent(event.value)"
            >
            {{ event.label }}
          </label>
        </div>
      </div>

      <div class="form-group">
        <label class="checkbox-label">
          <input v-model="form.enabled" type="checkbox">
          Enabled
        </label>
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="createOpen = false">Cancel</button>
        <button class="btn btn-primary" :disabled="busy || !form.name" @click="create">
          <span v-if="busy" class="spinner" />
          Add channel
        </button>
      </template>
    </UiBaseModal>

    <UiConfirmDialog
      v-if="deleting"
      title="Delete this channel?"
      :message="`${deleting.name} will stop receiving expiry warnings and renewal failures.`"
      confirm-label="Delete"
      danger
      :busy="busy"
      @cancel="deleting = null"
      @confirm="remove"
    />
  </div>
</template>

<style scoped>
.settings-page { max-width: 900px; }
.channel-list { display: flex; flex-direction: column; gap: 12px; }
.channel-card { padding: 16px 20px; }
.channel-head { display: flex; align-items: center; gap: 14px; }
.channel-icon { font-size: 24px; color: var(--primary-600); flex-shrink: 0; }
.channel-name {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  color: var(--text-primary);
  flex-wrap: wrap;
}
.channel-meta { font-size: 12.5px; color: var(--text-muted); margin-top: 2px; }
.channel-actions { display: flex; align-items: center; gap: 4px; flex-shrink: 0; }
.channel-error {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px dashed var(--border-primary);
  font-size: 12.5px;
  color: var(--danger-600);
}

.channel-choice { display: flex; gap: 8px; flex-wrap: wrap; }
.channel-option {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 16px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  background: var(--bg-primary);
  cursor: pointer;
  font-family: inherit;
  font-size: 13.5px;
  color: var(--text-secondary);
  text-transform: capitalize;
  transition: all var(--transition);
}
.channel-option:hover { border-color: var(--primary-400); }
.channel-option.selected {
  border-color: var(--primary-600);
  background: var(--primary-50);
  color: var(--primary-700);
  font-weight: 500;
}
[data-theme="dark"] .channel-option.selected { color: var(--primary-300); }

.event-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; }
.flex-1 { flex: 1; }
.min-w-0 { min-width: 0; }
</style>
