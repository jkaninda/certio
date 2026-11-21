<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Certio - Self-signed PKI and TLS certificate management
  Copyright (C) 2026 Jonas Kaninda

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->

<script setup lang="ts">
import { computed, ref } from 'vue'

const props = withDefaults(defineProps<{
  title: string
  message: string
  confirmLabel?: string
  danger?: boolean
  busy?: boolean
  /** When set, the user must type this exact value to enable the button.
      Reserved for genuinely irreversible actions like deleting a CA. */
  confirmPhrase?: string
}>(), { confirmLabel: 'Confirm', danger: false, busy: false })

const emit = defineEmits<{ confirm: []; cancel: [] }>()

const typed = ref('')
const canConfirm = computed(() => !props.confirmPhrase || typed.value === props.confirmPhrase)
</script>

<template>
  <UiBaseModal :title="title" :busy="busy" @close="emit('cancel')">
    <p class="confirm-message">{{ message }}</p>

    <slot />

    <div v-if="confirmPhrase" class="form-group confirm-phrase">
      <label class="form-label">
        Type <code>{{ confirmPhrase }}</code> to confirm
      </label>
      <input v-model="typed" class="form-input" autocomplete="off" spellcheck="false">
    </div>

    <template #footer>
      <button class="btn btn-secondary" :disabled="busy" @click="emit('cancel')">Cancel</button>
      <button
        class="btn"
        :class="danger ? 'btn-danger' : 'btn-primary'"
        :disabled="busy || !canConfirm"
        @click="emit('confirm')"
      >
        <span v-if="busy" class="spinner" />
        {{ confirmLabel }}
      </button>
    </template>
  </UiBaseModal>
</template>

<style scoped>
.confirm-message { color: var(--text-secondary); line-height: 1.55; }
.confirm-phrase { margin-top: 18px; margin-bottom: 0; }
.confirm-phrase code {
  background: var(--bg-tertiary);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 12.5px;
  color: var(--text-primary);
}
</style>
