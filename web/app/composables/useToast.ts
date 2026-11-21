// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Certio - Self-signed PKI and TLS certificate management
// Copyright (C) 2026 Jonas Kaninda
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { ref } from 'vue'

export type ToastKind = 'success' | 'error' | 'info' | 'warning'

export interface Toast {
  id: number
  kind: ToastKind
  message: string
}

// Module-level state so every component shares one queue.
const toasts = ref<Toast[]>([])
let nextId = 1

export function useToast() {
  function push(kind: ToastKind, message: string, timeout = 5000) {
    const id = nextId++
    toasts.value.push({ id, kind, message })
    if (timeout > 0) {
      setTimeout(() => dismiss(id), timeout)
    }
    return id
  }

  function dismiss(id: number) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }

  return {
    toasts,
    dismiss,
    success: (message: string) => push('success', message),
    // Errors stay a little longer: they usually carry something to act on.
    error: (message: string) => push('error', message, 8000),
    info: (message: string) => push('info', message),
    warning: (message: string) => push('warning', message, 7000),
  }
}
