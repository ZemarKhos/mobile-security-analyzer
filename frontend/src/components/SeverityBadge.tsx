import { cn, getSeverityColor } from '@/lib/utils';
import type { SeverityLevel } from '@/types/api';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
}

export default function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase border',
        getSeverityColor(severity),
        className
      )}
    >
      {severity}
    </span>
  );
}
