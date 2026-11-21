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
import { ref } from 'vue'

const props = withDefaults(defineProps<{
  value: string
  label?: string
  /** Renders as a bare icon rather than a labelled button. */
  icon?: boolean
}>(), { label: 'Copy', icon: false })

const copied = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
  } catch {
    // navigator.clipboard needs a secure context. On plain HTTP — which a
    // private PKI dashboard often runs on before its own certificate is
    // installed — fall back to the legacy path rather than silently failing.
    const area = document.createElement('textarea')
    area.value = props.value
    area.style.position = 'fixed'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    document.execCommand('copy')
    area.remove()
  }
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <button
    class="btn btn-ghost"
    :class="icon ? 'btn-icon btn-icon-muted' : 'btn-xs'"
    :title="copied ? 'Copied' : label"
    :aria-label="label"
    @click.stop="copy"
  >
    <span class="mdi" :class="copied ? 'mdi-check' : 'mdi-content-copy'" />
    <span v-if="!icon">{{ copied ? 'Copied' : label }}</span>
  </button>
</template>
