import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('e8_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Redirect to login on 401
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('e8_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function login(username: string, password: string): Promise<string> {
  const params = new URLSearchParams({ username, password })
  const { data } = await api.post('/auth/token', params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data.access_token
}

export async function getMe() {
  const { data } = await api.get('/auth/me')
  return data
}

// ── Machines ──────────────────────────────────────────────────────────────────

export async function getMachines() {
  const { data } = await api.get('/machines/')
  return data
}

export async function getMachine(machineUuid: string) {
  const { data } = await api.get(`/machines/${machineUuid}`)
  return data
}

export async function deleteMachine(machineUuid: string) {
  await api.delete(`/machines/${machineUuid}`)
}

// ── Assessments ───────────────────────────────────────────────────────────────

export async function listAssessments(machineId?: string) {
  const params = machineId ? { machine_id: machineId } : {}
  const { data } = await api.get('/assessments/', { params })
  return data
}

export async function getAssessment(id: number) {
  const { data } = await api.get(`/assessments/${id}`)
  return data
}

export async function getMachineHistory(machineUuid: string) {
  const { data } = await api.get(`/assessments/history/${machineUuid}`)
  return data
}

export async function uploadReport(file: File) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/assessments/upload', form)
  return data
}

// ── Reports ───────────────────────────────────────────────────────────────────

export async function getDashboardSummary() {
  const { data } = await api.get('/reports/dashboard/summary')
  return data
}

export function reportHtmlUrl(assessmentId: number) {
  return `/api/reports/${assessmentId}/html`
}
