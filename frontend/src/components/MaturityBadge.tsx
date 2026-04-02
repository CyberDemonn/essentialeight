const COLORS: Record<number, string> = {
  0: 'bg-red-100 text-red-700 border-red-200',
  1: 'bg-orange-100 text-orange-700 border-orange-200',
  2: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  3: 'bg-green-100 text-green-700 border-green-200',
}

const DOT_COLORS: Record<number, string> = {
  0: 'bg-red-500',
  1: 'bg-orange-500',
  2: 'bg-yellow-500',
  3: 'bg-green-500',
}

interface Props {
  level: number
  label?: string
  size?: 'sm' | 'md' | 'lg'
}

export default function MaturityBadge({ level, label, size = 'md' }: Props) {
  const colorClass = COLORS[level] ?? COLORS[0]
  const dotColor = DOT_COLORS[level] ?? DOT_COLORS[0]
  const sizeClass = size === 'sm' ? 'text-xs px-2 py-0.5' : size === 'lg' ? 'text-base px-4 py-1.5' : 'text-sm px-3 py-1'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-semibold ${colorClass} ${sizeClass}`}>
      <span className={`w-2 h-2 rounded-full ${dotColor}`} />
      ML{level}{label ? ` — ${label}` : ''}
    </span>
  )
}
