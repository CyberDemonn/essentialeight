import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { ShieldCheck, LayoutDashboard, Monitor, LogOut, Upload } from 'lucide-react'
import { useRef } from 'react'
import { uploadReport } from '../api'

export default function Layout() {
  const navigate = useNavigate()
  const fileRef = useRef<HTMLInputElement>(null)

  function logout() {
    localStorage.removeItem('e8_token')
    navigate('/login')
  }

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      await uploadReport(file)
      alert('Report uploaded successfully.')
      navigate('/')
    } catch {
      alert('Upload failed — check the file format.')
    }
    e.target.value = ''
  }

  const navClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
      isActive
        ? 'bg-navy-700 text-white'
        : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
    }`

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-gray-200 flex flex-col">
        <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-200">
          <ShieldCheck className="text-navy-700" size={28} />
          <div>
            <p className="font-bold text-navy-700 text-sm leading-tight">Essential Eight</p>
            <p className="text-xs text-gray-400">Compliance Tool</p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          <NavLink to="/" end className={navClass}>
            <LayoutDashboard size={18} /> Dashboard
          </NavLink>
          <NavLink to="/machines" className={navClass}>
            <Monitor size={18} /> Machines
          </NavLink>
        </nav>

        <div className="p-4 border-t border-gray-200 space-y-2">
          <button
            onClick={() => fileRef.current?.click()}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium
                       text-gray-600 hover:bg-gray-100 hover:text-gray-900 transition-colors"
          >
            <Upload size={18} /> Upload Report
          </button>
          <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={handleUpload} />

          <button
            onClick={logout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium
                       text-red-500 hover:bg-red-50 transition-colors"
          >
            <LogOut size={18} /> Logout
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
