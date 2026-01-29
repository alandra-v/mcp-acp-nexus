import { apiGet, apiPost } from './client'

export interface AuthStatus {
  configured: boolean
  authenticated: boolean
  subject_id: string | null
  email: string | null
  name: string | null
  provider: string | null
  client_id: string | null
  audience: string | null
  scopes: string[] | null
  token_expires_in_hours: number | null
  has_refresh_token: boolean | null
  storage_backend: string | null
}

export interface DeviceFlowStart {
  user_code: string
  verification_uri: string
  verification_uri_complete: string | null
  expires_in: number
  interval: number
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
  return apiGet<AuthStatus>('/manager/auth/status')
}

export async function startLogin(): Promise<DeviceFlowStart> {
  return apiPost<DeviceFlowStart>('/manager/auth/login')
}

export async function logout(): Promise<LogoutResponse> {
  return apiPost<LogoutResponse>('/manager/auth/logout')
}

export async function logoutFederated(): Promise<FederatedLogoutResponse> {
  return apiPost<FederatedLogoutResponse>('/manager/auth/logout-federated')
}
