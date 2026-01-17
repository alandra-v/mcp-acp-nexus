import { apiGet, apiPost } from './client'

export interface AuthStatus {
  authenticated: boolean
  subject_id: string | null
  email: string | null
  name: string | null
  token_expires_in_hours: number | null
  has_refresh_token: boolean | null
  storage_backend: string | null
  provider: string | null
}

export interface DeviceFlowStart {
  user_code: string
  verification_uri: string
  verification_uri_complete: string | null
  expires_in: number
  interval: number
  poll_endpoint: string
}

export interface DeviceFlowPoll {
  status: 'pending' | 'complete' | 'expired' | 'denied' | 'error'
  message: string | null
}

export interface LogoutResponse {
  status: string
  message: string
}

export interface FederatedLogoutResponse {
  status: string
  logout_url: string
  message: string
}

export async function getAuthStatus(): Promise<AuthStatus> {
  return apiGet<AuthStatus>('/auth/status')
}

export async function startLogin(): Promise<DeviceFlowStart> {
  return apiPost<DeviceFlowStart>('/auth/login')
}

export async function pollLogin(code: string): Promise<DeviceFlowPoll> {
  return apiGet<DeviceFlowPoll>(`/auth/login/poll?code=${encodeURIComponent(code)}`)
}

export async function logout(): Promise<LogoutResponse> {
  return apiPost<LogoutResponse>('/auth/logout')
}

export async function logoutFederated(): Promise<FederatedLogoutResponse> {
  return apiPost<FederatedLogoutResponse>('/auth/logout-federated')
}
