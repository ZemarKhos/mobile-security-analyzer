import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { SeverityLevel, Finding } from '@/types/api';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleString('tr-TR', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function getSeverityColor(severity: SeverityLevel): string {
  const colors: Record<SeverityLevel, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-800 border-gray-200',
  };
  return colors[severity] || colors.info;
}

export function getSeverityBgColor(severity: SeverityLevel): string {
  const colors: Record<SeverityLevel, string> = {
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#CA8A04',
    low: '#2563EB',
    info: '#6B7280',
  };
  return colors[severity] || colors.info;
}

export function getRiskScoreColor(score: number): string {
  if (score >= 75) return 'text-red-600';
  if (score >= 50) return 'text-orange-600';
  if (score >= 25) return 'text-yellow-600';
  return 'text-green-600';
}

export function getRiskScoreLabel(score: number): string {
  if (score >= 75) return 'Critical Risk';
  if (score >= 50) return 'High Risk';
  if (score >= 25) return 'Medium Risk';
  return 'Low Risk';
}

/**
 * Estimate severity from finding type when backend doesn't provide it
 * This matches MobSF-like severity mapping
 */
export function estimateSeverity(finding: Finding): SeverityLevel {
  // If severity is already set and valid, use it
  if (finding.severity && ['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity)) {
    return finding.severity;
  }

  const type = finding.type?.toLowerCase() || '';
  
  // Critical severity patterns
  const criticalPatterns = [
    'hardcoded_secret',
    'cert_pinning_bypass',
    'certificate_validation_bypass',
  ];
  
  // High severity patterns
  const highPatterns = [
    'sql_injection',
    'insecure_http',
    'weak_crypto',
    'webview_file_access',
    'webview_js_interface',
    'insecure_sharedprefs',
    'runtime_exec',
    'command_execution',
    'debuggable_app',
    'cleartext_traffic',
    'exported_provider',
    'debug_certificate',
    'path_traversal',
  ];
  
  // Medium severity patterns
  const mediumPatterns = [
    'dangerous_permission',
    'exported_component',
    'exported_service',
    'sensitive_logging',
    'webview_js_enabled',
    'insecure_random',
    'external_storage',
    'clipboard_sensitive',
    'unprotected_broadcast',
    'backup_enabled',
    'expired_certificate',
    'dynamic_loading',
  ];
  
  // Low severity patterns
  const lowPatterns = [
    'implicit_intent',
    'temp_file',
  ];
  
  if (criticalPatterns.some(p => type.includes(p))) return 'critical';
  if (highPatterns.some(p => type.includes(p))) return 'high';
  if (mediumPatterns.some(p => type.includes(p))) return 'medium';
  if (lowPatterns.some(p => type.includes(p))) return 'low';
  
  return 'info';
}

/**
 * Process findings to ensure all have valid severity
 */
export function processFindingsWithSeverity(findings: Finding[]): Finding[] {
  return findings.map(finding => ({
    ...finding,
    severity: estimateSeverity(finding),
  }));
}

export function truncateString(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

export function getTypeDisplayName(type: string): string {
  return type
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}
