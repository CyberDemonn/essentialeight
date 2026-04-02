import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getMachines, deleteMachine } from '../api'
import MaturityBadge from '../components/MaturityBadge'
import { Trash2, ExternalLink, Monitor } from 'lucide-react'

export default function Machines() {
  const [machines, setMachines] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  async function load() {
    const data = await getMachines()
    setMachines(data)
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  async function handleDelete(uuid: string, label: string) {
    if (!confirm(`Delete machine "${label}" and all its assessments?`)) return
    await deleteMachine(uuid)
    setMachines((prev) => prev.filter((m) => m.machine_id !== uuid))
  }

  if (loading) return <div className="p-8 text-gray-500">Loading machines...</div>

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Machines</h1>
          <p className="text-gray-500 text-sm mt-1">{machines.length} machine(s) registered</p>
        </div>
      </div>

      {machines.length === 0 ? (
        <div className="card text-center py-16 text-gray-400">
          <Monitor size={48} className="mx-auto mb-4 opacity-30" />
          <p className="font-medium">No machines assessed yet</p>
          <p className="text-sm mt-1">Run the agent on a machine or upload a standalone report.</p>
        </div>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 text-gray-500 text-left">
                <th className="px-6 py-3 font-medium">Machine</th>
                <th className="px-6 py-3 font-medium">OS</th>
                <th className="px-6 py-3 font-medium">Last Seen</th>
                <th className="px-6 py-3 font-medium">Latest Maturity</th>
                <th className="px-6 py-3 font-medium">Gaps</th>
                <th className="px-6 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {machines.map((m) => {
                const a = m.latest_assessment
                return (
                  <tr key={m.machine_id} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="px-6 py-3">
                      <p className="font-medium text-gray-900">{m.machine_label}</p>
                      <p className="text-gray-400 text-xs">{m.fqdn || m.machine_id}</p>
                    </td>
                    <td className="px-6 py-3 text-gray-500">
                      {m.os_name} {m.os_release}
                    </td>
                    <td className="px-6 py-3 text-gray-500">
                      {m.last_seen
                        ? new Date(m.last_seen).toLocaleDateString('en-AU', { dateStyle: 'medium' })
                        : '—'}
                    </td>
                    <td className="px-6 py-3">
                      {a ? <MaturityBadge level={a.overall_maturity} size="sm" /> : <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-6 py-3 text-gray-500">{a ? `${a.gap_count} control(s)` : '—'}</td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex items-center justify-end gap-3">
                        {a && (
                          <Link
                            to={`/assessments/${a.id}`}
                            className="text-navy-700 hover:underline text-xs font-medium inline-flex items-center gap-1"
                          >
                            <ExternalLink size={13} /> View
                          </Link>
                        )}
                        <button
                          onClick={() => handleDelete(m.machine_id, m.machine_label)}
                          className="text-red-400 hover:text-red-600 transition-colors"
                          title="Delete machine"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
