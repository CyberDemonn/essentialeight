import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getAssessment, getMachineHistory, reportHtmlUrl } from '../api'
import MaturityBadge from '../components/MaturityBadge'
import TrendChart from '../components/TrendChart'
import { ChevronDown, ChevronRight, ExternalLink, FileText } from 'lucide-react'

const CONTROL_ORDER = ['E8-1','E8-2','E8-3','E8-4','E8-5','E8-6','E8-7','E8-8']

export default function AssessmentDetail() {
  const { id } = useParams<{ id: string }>()
  const [assessment, setAssessment] = useState<any>(null)
  const [history, setHistory] = useState<any[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAssessment(Number(id)).then(async (a) => {
      setAssessment(a)
      try {
        const h = await getMachineHistory(a.machine_id)
        setHistory(h.history.map((x: any) => ({ date: x.assessed_at, overall_maturity: x.overall_maturity })))
      } catch {}
      setLoading(false)
    })
  }, [id])

  function toggle(cid: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(cid) ? next.delete(cid) : next.add(cid)
      return next
    })
  }

  if (loading) return <div className="p-8 text-gray-500">Loading assessment...</div>
  if (!assessment) return <div className="p-8 text-red-500">Assessment not found.</div>

  const controls = [...(assessment.controls || [])].sort(
    (a: any, b: any) => CONTROL_ORDER.indexOf(a.control_id) - CONTROL_ORDER.indexOf(b.control_id)
  )

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{assessment.machine_label}</h1>
          <p className="text-gray-500 text-sm mt-1">
            Assessed {new Date(assessment.assessed_at).toLocaleString('en-AU', { dateStyle: 'long', timeStyle: 'short' })}
            {' '}· Target ML{assessment.target_level}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <a
            href={reportHtmlUrl(assessment.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary inline-flex items-center gap-2 text-sm"
          >
            <FileText size={15} /> HTML Report
          </a>
          <Link
            to={`/remediation/${assessment.id}`}
            className="btn-primary inline-flex items-center gap-2 text-sm"
          >
            Remediation Steps
          </Link>
        </div>
      </div>

      {/* Overall + trend */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card flex flex-col justify-center">
          <p className="text-sm text-gray-500 font-medium mb-2">Overall Maturity</p>
          <MaturityBadge level={assessment.overall_maturity} size="lg" />
          <p className="text-gray-500 text-sm mt-3">{assessment.gap_count} control(s) below ML3</p>
        </div>
        {history.length > 1 && (
          <div className="card">
            <p className="text-sm font-medium text-gray-700 mb-3">Maturity Trend</p>
            <TrendChart data={history} />
          </div>
        )}
      </div>

      {/* Control results */}
      <div className="card p-0 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="font-semibold text-gray-800">Control Results</h2>
        </div>
        <div className="divide-y divide-gray-50">
          {controls.map((ctrl: any) => {
            const isOpen = expanded.has(ctrl.control_id)
            const hasDetail = (ctrl.gaps?.length > 0) || (ctrl.findings?.length > 0)
            return (
              <div key={ctrl.control_id}>
                <button
                  onClick={() => hasDetail && toggle(ctrl.control_id)}
                  className="w-full flex items-center gap-4 px-6 py-4 hover:bg-gray-50 transition-colors text-left"
                >
                  {hasDetail ? (
                    isOpen ? <ChevronDown size={16} className="text-gray-400 shrink-0" /> : <ChevronRight size={16} className="text-gray-400 shrink-0" />
                  ) : <span className="w-4" />}
                  <span className="text-xs font-mono text-gray-400 w-10 shrink-0">{ctrl.control_id}</span>
                  <span className="flex-1 font-medium text-gray-800 text-sm">{ctrl.control_name}</span>
                  <MaturityBadge level={ctrl.maturity_level} size="sm" />
                </button>
                {isOpen && (
                  <div className="px-6 pb-4 ml-14 space-y-3">
                    {ctrl.findings?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Findings</p>
                        <ul className="space-y-1">
                          {ctrl.findings.map((f: string, i: number) => (
                            <li key={i} className="text-sm text-gray-600 flex gap-2">
                              <span className="text-green-500 mt-0.5">✓</span> {f}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {ctrl.gaps?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Gaps</p>
                        <ul className="space-y-1">
                          {ctrl.gaps.map((g: string, i: number) => (
                            <li key={i} className="text-sm text-orange-700 flex gap-2">
                              <span className="mt-0.5">⚠</span> {g}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {ctrl.error && (
                      <p className="text-sm text-red-500 bg-red-50 rounded px-3 py-2">Error: {ctrl.error}</p>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
