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
