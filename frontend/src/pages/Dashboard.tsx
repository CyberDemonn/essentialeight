import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getDashboardSummary, listAssessments } from '../api'
import MaturityBadge from '../components/MaturityBadge'
import ComplianceRadar from '../components/ComplianceRadar'
import { Monitor, AlertTriangle, CheckCircle2, Activity } from 'lucide-react'

const CONTROL_NAMES: Record<string, string> = {
  'E8-1': 'Application Control',
  'E8-2': 'Patch Applications',
  'E8-3': 'Office Macro Settings',
  'E8-4': 'User App Hardening',
  'E8-5': 'Restrict Admin Privileges',
  'E8-6': 'Patch Operating Systems',
  'E8-7': 'Multi-Factor Authentication',
  'E8-8': 'Regular Backups',
}

export default function Dashboard() {
  const [summary, setSummary] = useState<any>(null)
  const [recent, setRecent] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([getDashboardSummary(), listAssessments()])
      .then(([s, a]) => {
        setSummary(s)
        setRecent(a.slice(0, 10))
      })
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8 text-gray-500">Loading dashboard...</div>
  if (!summary) return <div className="p-8 text-red-500">Failed to load data.</div>

  const overallMl = Math.floor(summary.average_maturity ?? 0)

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Compliance Dashboard</h1>
        <p className="text-gray-500 text-sm mt-1">ACSC Essential Eight — Maturity Level Overview</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={<Monitor size={20} className="text-navy-700" />}
          label="Machines Assessed"
          value={summary.assessed_machines ?? 0}
          sub={`of ${summary.total_machines} registered`}
        />
        <StatCard
          icon={<Activity size={20} className="text-navy-700" />}
          label="Avg. Overall Maturity"
          value={summary.average_maturity !== null ? `ML${overallMl}` : '—'}
          sub={<MaturityBadge level={overallMl} size="sm" />}
        />
        <StatCard
          icon={<CheckCircle2 size={20} className="text-green-600" />}
          label="Fully Compliant"
          value={summary.fully_compliant ?? 0}
          sub="machines at ML3"
        />
        <StatCard
          icon={<AlertTriangle size={20} className="text-orange-500" />}
          label="Machines with Gaps"
          value={(summary.assessed_machines ?? 0) - (summary.fully_compliant ?? 0)}
          sub="below ML3"
        />
      </div>

      {/* Radar + control table */}
      {summary.controls && Object.keys(summary.controls).length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <h2 className="font-semibold text-gray-800 mb-4">Control Maturity Radar</h2>
            <ComplianceRadar controls={summary.controls} />
            <p className="text-xs text-gray-400 text-center mt-2">Average across all assessed machines</p>
          </div>

          <div className="card">
            <h2 className="font-semibold text-gray-800 mb-4">Per-Control Average</h2>
            <div className="space-y-3">
              {Object.entries(summary.controls as Record<string, number>)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([id, avg]) => {
                  const level = Math.floor(avg)
                  const pct = Math.round((avg / 3) * 100)
                  const barColor = ['bg-red-400', 'bg-orange-400', 'bg-yellow-400', 'bg-green-500'][level]
                  return (
                    <div key={id}>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-gray-700 font-medium">{CONTROL_NAMES[id] ?? id}</span>
                        <MaturityBadge level={level} size="sm" />
                      </div>
                      <div className="w-full bg-gray-100 rounded-full h-2">
                        <div className={`${barColor} h-2 rounded-full transition-all`} style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  )
                })}
            </div>
          </div>
        </div>
      )}

      {/* Recent assessments */}
      <div className="card">
        <h2 className="font-semibold text-gray-800 mb-4">Recent Assessments</h2>
        {recent.length === 0 ? (
          <p className="text-gray-400 text-sm">
            No assessments yet. Run the agent on a machine or upload a report.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 text-gray-500 text-left">
                  <th className="pb-2 font-medium">Machine</th>
                  <th className="pb-2 font-medium">Assessed</th>
                  <th className="pb-2 font-medium">Overall</th>
                  <th className="pb-2 font-medium">Gaps</th>
                  <th className="pb-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {recent.map((a) => (
                  <tr key={a.id} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-2.5 font-medium text-gray-900">{a.machine_label}</td>
                    <td className="py-2.5 text-gray-500">
                      {new Date(a.assessed_at).toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' })}
                    </td>
                    <td className="py-2.5">
                      <MaturityBadge level={a.overall_maturity} size="sm" />
                    </td>
                    <td className="py-2.5 text-gray-500">{a.gap_count} control(s)</td>
                    <td className="py-2.5 text-right">
                      <Link
                        to={`/assessments/${a.id}`}
                        className="text-navy-700 hover:underline text-xs font-medium"
                      >
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: React.ReactNode; sub: React.ReactNode }) {
  return (
    <div className="card flex flex-col gap-1">
      <div className="flex items-center gap-2 text-gray-500 text-xs font-medium mb-1">
        {icon} {label}
      </div>
      <div className="text-3xl font-bold text-gray-900">{value}</div>
      <div className="text-xs text-gray-400">{sub}</div>
    </div>
  )
}
