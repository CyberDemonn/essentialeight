import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'

const CONTROL_SHORT: Record<string, string> = {
  'E8-1': 'App Control',
  'E8-2': 'Patch Apps',
  'E8-3': 'Office Macros',
  'E8-4': 'User Hardening',
  'E8-5': 'Restrict Admin',
  'E8-6': 'Patch OS',
  'E8-7': 'MFA',
  'E8-8': 'Backups',
}

interface Props {
  controls: Record<string, number>
}

export default function ComplianceRadar({ controls }: Props) {
  const data = Object.entries(controls).map(([id, level]) => ({
    control: CONTROL_SHORT[id] ?? id,
    maturity: level,
    fullMark: 3,
  }))

  return (
    <ResponsiveContainer width="100%" height={320}>
      <RadarChart data={data}>
        <PolarGrid stroke="#e5e7eb" />
        <PolarAngleAxis dataKey="control" tick={{ fontSize: 12, fill: '#4b5563' }} />
        <Radar
          name="Maturity"
          dataKey="maturity"
          stroke="#1e3a5f"
          fill="#1e3a5f"
          fillOpacity={0.25}
          strokeWidth={2}
        />
        <Tooltip
          formatter={(value: number) => [`ML${value}`, 'Maturity']}
          contentStyle={{ borderRadius: 8, fontSize: 13 }}
        />
      </RadarChart>
    </ResponsiveContainer>
  )
}
