import { Toaster as Sonner, toast as sonnerToast, type ExternalToast } from 'sonner'

type ToasterProps = React.ComponentProps<typeof Sonner>

// Toast durations by type (in milliseconds)
const TOAST_DURATION = {
  success: 3000,    // 3s - quick acknowledgment
  info: 4000,       // 4s - slightly longer to read
  warning: 6000,    // 6s - important, needs attention
  error: 8000,      // 8s - needs to be noticed and read
}

// Wrapped toast with automatic durations per type
export const toast = {
  success: (message: string, options?: ExternalToast) =>
    sonnerToast.success(message, { duration: TOAST_DURATION.success, ...options }),
  info: (message: string, options?: ExternalToast) =>
    sonnerToast.info(message, { duration: TOAST_DURATION.info, ...options }),
  warning: (message: string, options?: ExternalToast) =>
    sonnerToast.warning(message, { duration: TOAST_DURATION.warning, ...options }),
  error: (message: string, options?: ExternalToast) =>
    sonnerToast.error(message, { duration: TOAST_DURATION.error, ...options }),
  dismiss: sonnerToast.dismiss,
}

function Toaster({ ...props }: ToasterProps) {
  return (
    <Sonner
      theme="dark"
      className="toaster group"
      duration={TOAST_DURATION.info}  // Default duration
      toastOptions={{
        classNames: {
          toast:
            'group toast group-[.toaster]:bg-base-900 group-[.toaster]:text-foreground group-[.toaster]:border-base-700 group-[.toaster]:shadow-lg',
          description: 'group-[.toast]:text-muted-foreground',
          actionButton:
            'group-[.toast]:bg-primary group-[.toast]:text-primary-foreground',
          cancelButton:
            'group-[.toast]:bg-muted group-[.toast]:text-muted-foreground',
          success: 'group-[.toaster]:border-success/30 group-[.toaster]:text-success-muted',
          error: 'group-[.toaster]:bg-red-950 group-[.toaster]:border-red-500/40 group-[.toaster]:text-red-200',
          info: 'group-[.toaster]:border-base-600 group-[.toaster]:text-base-200',
        },
      }}
      {...props}
    />
  )
}

export { Toaster }
