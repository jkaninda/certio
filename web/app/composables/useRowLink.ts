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

/**
 * openRow makes a whole table row a click target for the link it contains.
 *
 * The row's own link is what keyboard users, screen readers and "open in new
 * tab" use; this only widens the mouse target. It stands aside when the click
 * landed on something interactive (so a Ctrl-click on the link does not also
 * navigate this tab) or when the user was selecting text to copy.
 */
export function useRowLink() {
  function openRow(event: MouseEvent, path: string) {
    const target = event.target as HTMLElement | null
    if (target?.closest('a, button, input, select, textarea, label')) return
    if (window.getSelection()?.toString()) return
    if (event.metaKey || event.ctrlKey || event.shiftKey) {
      window.open(path, '_blank', 'noopener')
      return
    }
    navigateTo(path)
  }
  return { openRow }
}
