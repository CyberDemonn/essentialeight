import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Machines from './pages/Machines'
import AssessmentDetail from './pages/AssessmentDetail'
import Remediation from './pages/Remediation'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('e8_token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="machines" element={<Machines />} />
          <Route path="assessments/:id" element={<AssessmentDetail />} />
          <Route path="remediation/:id" element={<Remediation />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
