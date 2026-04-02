import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts'

interface DataPoint {
  date: string
  overall_maturity: number
}

interface Props {
  data: DataPoint[]
}

export default function TrendChart({ data }: Props) {
  const formatted = data.map((d) => ({
    ...d,
    date: new Date(d.date).toLocaleDateString('en-AU', { month: 'short', day: 'numeric' }),
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={formatted} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
        <XAxis dataKey="date" tick={{ fontSize: 12, fill: '#6b7280' }} />
        <YAxis domain={[0, 3]} ticks={[0, 1, 2, 3]} tick={{ fontSize: 12, fill: '#6b7280' }} />
        <Tooltip
          formatter={(v: number) => [`ML${v}`, 'Overall Maturity']}
          contentStyle={{ borderRadius: 8, fontSize: 13 }}
        />
        <ReferenceLine y={3} stroke="#16a34a" strokeDasharray="4 4" label={{ value: 'ML3 Target', position: 'right', fontSize: 11, fill: '#16a34a' }} />
        <Line
          type="monotone"
          dataKey="overall_maturity"
          stroke="#1e3a5f"
          strokeWidth={2.5}
          dot={{ fill: '#1e3a5f', r: 4 }}
          activeDot={{ r: 6 }}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}
