<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useFormat } from '~/composables/useFormat'
import { useAuthStore } from '~/stores/auth'
import { useToast } from '~/composables/useToast'
import type { User } from '~/types/api'

useHead({ title: 'Users · Certio' })

const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { dateTime, relative, statusClass } = useFormat()

const items = ref<User[]>([])
const loading = ref(true)
const busy = ref(false)

const createOpen = ref(false)
const editing = ref<User | null>(null)
const deleting = ref<User | null>(null)
const resetting2fa = ref<User | null>(null)

const createForm = reactive({ email: '', name: '', password: '', role: 'viewer' })
const editForm = reactive({ name: '', role: 'viewer', status: 'active', password: '' })

const roles = [
  { value: 'admin', label: 'Admin', hint: 'Everything, including users and deleting CAs' },
  { value: 'operator', label: 'Operator', hint: 'Issue, renew and revoke certificates' },
  { value: 'viewer', label: 'Viewer', hint: 'Read-only; no private key downloads' },
]

async function load() {
  loading.value = true
  try {
    const payload = await api.get<{ items: User[] }>('/users', { limit: 200 })
    items.value = payload.items ?? []
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not load accounts')
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function create() {
  busy.value = true
  try {
    await api.post('/users', createForm)
    toast.success('Account created')
    createOpen.value = false
    Object.assign(createForm, { email: '', name: '', password: '', role: 'viewer' })
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not create the account')
  } finally {
    busy.value = false
  }
}

function startEdit(user: User) {
  editing.value = user
  Object.assign(editForm, { name: user.name, role: user.role, status: user.status, password: '' })
}

async function saveEdit() {
  if (!editing.value) return
  busy.value = true
  try {
    await api.patch(`/users/${editing.value.id}`, {
      name: editForm.name,
      role: editForm.role,
      status: editForm.status,
      ...(editForm.password ? { password: editForm.password } : {}),
    })
    toast.success('Account updated')
    editing.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not update the account')
  } finally {
    busy.value = false
  }
}

async function remove() {
  if (!deleting.value) return
  busy.value = true
  try {
    await api.del(`/users/${deleting.value.id}`)
    toast.success('Account deleted')
    deleting.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not delete the account')
  } finally {
    busy.value = false
  }
}

async function resetTwoFactor() {
  if (!resetting2fa.value) return
  busy.value = true
  try {
    await api.del(`/users/${resetting2fa.value.id}/2fa`)
    toast.success('Two-factor authentication reset')
    resetting2fa.value = null
    await load()
  } catch (err) {
    toast.error(err instanceof Error ? err.message : 'could not reset two-factor authentication')
  } finally {
    busy.value = false
  }
}

function roleBadge(role: string): string {
  return role === 'admin' ? 'badge-info' : role === 'operator' ? 'badge-secondary' : 'badge-neutral'
}
</script>

<template>
  <div class="settings-page">
    <div class="page-header">
      <div>
        <h1>Users</h1>
        <p class="page-subtitle">Who can sign in, and what they are allowed to do.</p>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-primary" @click="createOpen = true">
          <span class="mdi mdi-account-plus-outline" />
          New account
        </button>
      </div>
    </div>

    <SettingsNav />

    <div class="card">
      <div v-if="loading" class="loading-page">
        <span class="spinner spinner-lg" />
      </div>

      <div v-else class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Account</th>
              <th>Role</th>
              <th>Status</th>
              <th>2FA</th>
              <th>Last sign-in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in items" :key="user.id">
              <td>
                <div class="cell-id">
                  <span class="avatar avatar-sm">{{ (user.name || user.email).charAt(0) }}</span>
                  <span class="cell-text">
                    <span class="cell-title">
                      {{ user.name || user.email }}
                      <span v-if="user.id === auth.user?.id" class="badge badge-neutral you-badge">you</span>
                    </span>
                    <span class="cell-sub">{{ user.email }}</span>
                  </span>
                </div>
              </td>
              <td><span class="badge" :class="roleBadge(user.role)">{{ user.role }}</span></td>
              <td><span class="badge badge-dot" :class="statusClass(user.status)">{{ user.status }}</span></td>
              <td>
                <span class="badge" :class="user.two_factor_enabled ? 'badge-success' : 'badge-neutral'">
                  {{ user.two_factor_enabled ? 'on' : 'off' }}
                </span>
              </td>
              <td class="text-sm" :title="user.last_login_at ? dateTime(user.last_login_at) : ''">
                {{ user.last_login_at ? relative(user.last_login_at) : 'never' }}
              </td>
              <td class="table-actions">
                <button class="btn btn-icon btn-icon-muted" title="Edit" @click="startEdit(user)">
                  <span class="mdi mdi-pencil-outline" />
                </button>
                <button
                  class="btn btn-icon btn-icon-muted"
                  title="Reset two-factor authentication"
                  :disabled="!user.two_factor_enabled"
                  @click="resetting2fa = user"
                >
                  <span class="mdi mdi-shield-off-outline" />
                </button>
                <button
                  class="btn btn-icon btn-icon-danger"
                  title="Delete"
                  :disabled="user.id === auth.user?.id"
                  @click="deleting = user"
                >
                  <span class="mdi mdi-delete-outline" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create -->
    <UiBaseModal v-if="createOpen" title="New account" :busy="busy" @close="createOpen = false">
      <div class="form-group">
        <label class="form-label">Email <span class="required">*</span></label>
        <input v-model="createForm.email" type="email" class="form-input" autocomplete="off">
      </div>
      <div class="form-group">
        <label class="form-label">Name</label>
        <input v-model="createForm.name" class="form-input">
      </div>
      <div class="form-group">
        <label class="form-label">Password <span class="required">*</span></label>
        <input v-model="createForm.password" type="password" class="form-input" autocomplete="new-password">
        <p class="form-hint">At least 12 characters.</p>
      </div>
      <div class="form-group">
        <label class="form-label">Role</label>
        <div class="role-options">
          <label v-for="role in roles" :key="role.value" class="role-option" :class="{ selected: createForm.role === role.value }">
            <input v-model="createForm.role" type="radio" :value="role.value" class="role-radio">
            <span class="role-body">
              <span class="role-title">{{ role.label }}</span>
              <span class="role-hint">{{ role.hint }}</span>
            </span>
          </label>
        </div>
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="createOpen = false">Cancel</button>
        <button
          class="btn btn-primary"
          :disabled="busy || !createForm.email || createForm.password.length < 12"
          @click="create"
        >
          <span v-if="busy" class="spinner" />
          Create account
        </button>
      </template>
    </UiBaseModal>

    <!-- Edit -->
    <UiBaseModal v-if="editing" :title="`Edit ${editing.email}`" :busy="busy" @close="editing = null">
      <div class="form-group">
        <label class="form-label">Name</label>
        <input v-model="editForm.name" class="form-input">
      </div>
      <div class="form-group">
        <label class="form-label">Role</label>
        <select v-model="editForm.role" class="form-select">
          <option v-for="role in roles" :key="role.value" :value="role.value">{{ role.label }}</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Status</label>
        <select v-model="editForm.status" class="form-select">
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
        </select>
        <p class="form-hint">The last active administrator cannot be demoted or disabled.</p>
      </div>
      <div class="form-group">
        <label class="form-label">New password</label>
        <input v-model="editForm.password" type="password" class="form-input" autocomplete="new-password" placeholder="Leave blank to keep it">
      </div>

      <template #footer>
        <button class="btn btn-secondary" :disabled="busy" @click="editing = null">Cancel</button>
        <button class="btn btn-primary" :disabled="busy" @click="saveEdit">
          <span v-if="busy" class="spinner" />
          Save
        </button>
      </template>
    </UiBaseModal>

    <UiConfirmDialog
      v-if="resetting2fa"
      title="Reset two-factor authentication?"
      :message="`${resetting2fa.email} will be able to sign in with their password alone until they enrol a new device. Do this only when you are sure who you are talking to — it is the one step that removes a factor without proving possession of it. The reset is audited.`"
      confirm-label="Reset second factor"
      danger
      :busy="busy"
      @cancel="resetting2fa = null"
      @confirm="resetTwoFactor"
    />

    <UiConfirmDialog
      v-if="deleting"
      title="Delete this account?"
      :message="`${deleting.email} will lose access immediately. Their API tokens are deleted too. Audit entries they created are kept.`"
      confirm-label="Delete account"
      danger
      :busy="busy"
      @cancel="deleting = null"
      @confirm="remove"
    />
  </div>
</template>

<style scoped>
.settings-page { max-width: 900px; }
.you-badge { margin-left: 6px; font-size: 10px; }

.role-options { display: flex; flex-direction: column; gap: 8px; }
.role-option {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  cursor: pointer;
  transition: border-color var(--transition), background var(--transition);
}
.role-option:hover { border-color: var(--primary-400); }
.role-option.selected { border-color: var(--primary-600); background: var(--primary-50); }
.role-radio { margin-top: 3px; accent-color: var(--primary-600); }
.role-body { display: flex; flex-direction: column; gap: 2px; }
.role-title { font-weight: 550; color: var(--text-primary); font-size: 13.5px; }
.role-hint { font-size: 12px; color: var(--text-muted); }
</style>
