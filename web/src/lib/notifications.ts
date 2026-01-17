/**
 * Browser push notification utilities for HITL approvals.
 */

import type { PendingApproval } from '@/types/api'

/**
 * Request notification permission from the user.
 * Returns true if permission is granted.
 */
export async function requestNotificationPermission(): Promise<boolean> {
  if (!('Notification' in window)) return false
  if (Notification.permission === 'granted') return true
  if (Notification.permission === 'denied') return false

  try {
    const result = await Notification.requestPermission()
    return result === 'granted'
  } catch {
    // Permission request can fail in insecure contexts or unsupported browsers
    return false
  }
}

/**
 * Show a browser notification for a pending approval.
 * Only shows if permission is granted and tab is not focused.
 */
export function showApprovalNotification(approval: PendingApproval): void {
  if (Notification.permission !== 'granted') return
  if (document.hasFocus()) return // Don't notify if tab is focused

  try {
    const notification = new Notification('Pending Approval', {
      body: `${approval.tool_name}: ${approval.path || 'No path'}`,
      icon: '/favicon.ico',
      tag: approval.id, // Prevents duplicate notifications for same approval
      requireInteraction: true, // Don't auto-dismiss
    })

    notification.onclick = () => {
      window.focus()
      notification.close()
    }
  } catch {
    // Notification can fail in some contexts - fail silently
  }
}
