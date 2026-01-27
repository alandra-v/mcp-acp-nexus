import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { ConnectionStatusBanner } from '@/components/ConnectionStatusBanner'
import { Toaster } from '@/components/ui/sonner'
import { AppStateProvider } from '@/context/AppStateContext'
import { IncidentsProvider } from '@/context/IncidentsContext'
import { ProxyListPage } from '@/pages/ProxyListPage'
import { ProxyDetailPage } from '@/pages/ProxyDetailPage'
import { IncidentsPage } from '@/pages/IncidentsPage'
import { AuthPage } from '@/pages/AuthPage'

export function App() {
  return (
    <ErrorBoundary>
      <AppStateProvider>
        <IncidentsProvider>
          <ConnectionStatusBanner />
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<ProxyListPage />} />
              <Route path="/proxy/:name" element={<ProxyDetailPage />} />
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/auth" element={<AuthPage />} />
            </Routes>
          </BrowserRouter>
          <Toaster position="bottom-right" />
        </IncidentsProvider>
      </AppStateProvider>
    </ErrorBoundary>
  )
}
