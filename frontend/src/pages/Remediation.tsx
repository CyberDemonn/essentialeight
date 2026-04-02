import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getAssessment } from '../api'
import MaturityBadge from '../components/MaturityBadge'
import { Copy, Check, ExternalLink, ArrowLeft } from 'lucide-react'

const PRIORITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 }
const PRIORITY_STYLE: Record<string, string> = {
  high: 'bg-red-100 text-red-700 border-red-200',
  medium: 'bg-orange-100 text-orange-700 border-orange-200',
  low: 'bg-gray-100 text-gray-600 border-gray-200',
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      title="Copy to clipboard"
      className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  )
}

export default function Remediation() {
  const { id } = useParams<{ id: string }>()
  const [assessment, setAssessment] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAssessment(Number(id)).then((a) => {
      setAssessment(a)
      setLoading(false)
    })
  }, [id])

  if (loading) return <div className="p-8 text-gray-500">Loading remediation steps...</div>
  if (!assessment) return <div className="p-8 text-red-500">Assessment not found.</div>

  // Flatten all remediation steps, tagged with control info
  interface Step {
    control_id: string
    control_name: string
    current_level: number
    description: string
    script: string
    script_type: string
    acsc_reference: string
    priority: string
    target_level: number
  }

  const steps: Step[] = []
  for (const ctrl of assessment.controls || []) {
    for (const r of ctrl.remediation || []) {
      steps.push({
        control_id: ctrl.control_id,
        control_name: ctrl.control_name,
        current_level: ctrl.maturity_level,
        ...r,
      })
    }
  }

  steps.sort((a, b) => (PRIORITY_ORDER[a.priority] ?? 9) - (PRIORITY_ORDER[b.priority] ?? 9))

  const highCount = steps.filter((s) => s.priority === 'high').length
  const medCount = steps.filter((s) => s.priority === 'medium').length

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <Link
            to={`/assessments/${id}`}
            className="text-sm text-gray-500 hover:text-navy-700 inline-flex items-center gap-1 mb-2"
          >
            <ArrowLeft size={14} /> Back to assessment
          </Link>
          <h1 className="text-2xl font-bold text-gray-900">Remediation Steps</h1>
          <p className="text-gray-500 text-sm mt-1">
            {assessment.machine_label} ·{' '}
            {highCount > 0 && <span className="text-red-600 font-medium">{highCount} high priority</span>}
            {highCount > 0 && medCount > 0 && ', '}
            {medCount > 0 && <span className="text-orange-600 font-medium">{medCount} medium priority</span>}
            {steps.length === 0 && 'No remediation steps — system is fully compliant!'}
          </p>
        </div>
      </div>

      {steps.length === 0 && (
        <div className="card text-center py-16 text-green-600">
          <Check size={48} className="mx-auto mb-4 opacity-60" />
          <p className="font-semibold text-lg">All controls at ML3</p>
          <p className="text-sm text-gray-400 mt-1">No remediation required.</p>
        </div>
      )}

      <div className="space-y-4">
        {steps.map((step, idx) => (
          <div key={idx} className="card space-y-3">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <span
                  className={`inline-block text-xs font-semibold px-2 py-0.5 rounded border uppercase tracking-wide ${PRIORITY_STYLE[step.priority] ?? PRIORITY_STYLE.low}`}
                >
                  {step.priority}
                </span>
                <div>
                  <p className="font-semibold text-gray-900 text-sm">{step.description}</p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {step.control_id} · {step.control_name} · Currently{' '}
                    <MaturityBadge level={step.current_level} size="sm" /> → Target{' '}
                    <MaturityBadge level={step.target_level} size="sm" />
                  </p>
                </div>
              </div>
              <a
                href={step.acsc_reference}
                target="_blank"
                rel="noopener noreferrer"
                className="text-navy-700 hover:underline text-xs inline-flex items-center gap-1 shrink-0"
              >
                ACSC Guidance <ExternalLink size={11} />
              </a>
            </div>

            {/* Script block */}
            {step.script && (
              <div className="relative">
                <div className="flex items-center justify-between bg-gray-800 rounded-t-lg px-4 py-2">
                  <span className="text-xs font-mono text-gray-400">{step.script_type}</span>
                  <CopyButton text={step.script} />
                </div>
                <pre className="bg-gray-900 text-green-300 text-xs font-mono p-4 rounded-b-lg overflow-x-auto leading-relaxed">
                  {step.script}
                </pre>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
