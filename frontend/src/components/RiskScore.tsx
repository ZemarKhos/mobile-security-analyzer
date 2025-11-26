import { cn, getRiskScoreColor, getRiskScoreLabel } from '@/lib/utils';

interface RiskScoreProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export default function RiskScore({ score, size = 'md', showLabel = true }: RiskScoreProps) {
  const sizeClasses = {
    sm: 'h-16 w-16 text-lg',
    md: 'h-24 w-24 text-2xl',
    lg: 'h-32 w-32 text-3xl',
  };

  const radius = size === 'sm' ? 28 : size === 'md' ? 44 : 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className={cn('relative', sizeClasses[size])}>
        <svg className="transform -rotate-90 w-full h-full" viewBox="0 0 128 128">
          {/* Background circle */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke="#e5e7eb"
            strokeWidth="8"
          />
          {/* Progress circle */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke={score >= 75 ? '#DC2626' : score >= 50 ? '#EA580C' : score >= 25 ? '#CA8A04' : '#16A34A'}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className="transition-all duration-500"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={cn('font-bold', getRiskScoreColor(score))}>{score}</span>
        </div>
      </div>
      {showLabel && (
        <p className={cn('mt-2 font-medium', getRiskScoreColor(score))}>
          {getRiskScoreLabel(score)}
        </p>
      )}
    </div>
  );
}
