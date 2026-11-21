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
import { onBeforeUnmount, onMounted } from 'vue'

const props = withDefaults(defineProps<{
  title: string
  /** Widens the dialog for content like PEM blocks and wizards. */
  wide?: boolean
  /** Disables closing while a request is in flight. */
  busy?: boolean
}>(), { wide: false, busy: false })

const emit = defineEmits<{ close: [] }>()

function close() {
  if (!props.busy) emit('close')
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') close()
}

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  // Stop the page behind the dialog from scrolling with it.
  document.body.style.overflow = 'hidden'
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKeydown)
  document.body.style.overflow = ''
})
</script>

<template>
  <Teleport to="body">
    <div class="modal-overlay" @click.self="close">
      <div class="modal" :class="{ 'modal-lg': wide }" role="dialog" aria-modal="true">
        <div class="modal-header">
          <h3>{{ title }}</h3>
          <button class="btn btn-icon btn-icon-muted" aria-label="Close" :disabled="busy" @click="close">
            <span class="mdi mdi-close" />
          </button>
        </div>
        <div class="modal-body">
          <slot />
        </div>
        <div v-if="$slots.footer" class="modal-footer">
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>
