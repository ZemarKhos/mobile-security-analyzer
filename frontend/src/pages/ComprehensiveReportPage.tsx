/**
 * Comprehensive Report Page
 * MobSF-style dashboard with tabs for different analysis sections
 * Uses Progressive Loading for large finding sets
 */

import { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Shield, FileText, Lock, Cpu, Code, AlertCircle, 
  CheckCircle, ArrowLeft, RefreshCw, Bot, Loader2, Copy, Download
} from 'lucide-react';
import { getReport, fetchAllFindings, getReportStatus, getSecurityScan, generateFridaScript, getAIConfig } from '@/lib/api';
import type { ReportDetail, Finding } from '@/types/api';
import type { SecurityScanResult, AIConfig } from '@/lib/api';
import { formatDate, formatBytes, cn, getSeverityBgColor } from '@/lib/utils';
import LoadingSpinner from '@/components/LoadingSpinner';
import RiskScore from '@/components/RiskScore';
import SeverityBadge from '@/components/SeverityBadge';
import FindingsDataTable from '@/components/FindingsDataTable';

type TabId = 'dashboard' | 'manifest' | 'certificate' | 'binary' | 'code' | 'security';

export default function ComprehensiveReportPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  
  // Progressive loading state for findings
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsProgress, setFindingsProgress] = useState({ loaded: 0, total: 0 });
  
  // Polling state for processing reports
  const [, setPolling] = useState(false);

  // Load report data
  useEffect(() => {
    if (!id) return;
    loadReport(parseInt(id));
  }, [id]);

  // Poll for status if processing
  useEffect(() => {
    if (!report || report.status !== 'processing') return;
    
    setPolling(true);
    const interval = setInterval(async () => {
      try {
        const status = await getReportStatus(parseInt(id!));
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(interval);
          setPolling(false);
          loadReport(parseInt(id!));
        }
      } catch (err) {
        console.error('Status poll failed:', err);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [report?.status, id]);

  // Load findings progressively when Code tab is active
  useEffect(() => {
    if (activeTab === 'code' && report && allFindings.length === 0 && !findingsLoading) {
      loadAllFindings();
    }
  }, [activeTab, report]);

  const loadReport = async (reportId: number) => {
    try {
      setLoading(true);
      setError(null);
      const data = await getReport(reportId);
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load report');
    } finally {
      setLoading(false);
    }
  };

  const loadAllFindings = useCallback(async () => {
    if (!id) return;
    
    try {
      setFindingsLoading(true);
      const findings = await fetchAllFindings(
        parseInt(id),
        100,
        (loaded, total) => setFindingsProgress({ loaded, total })
      );
      setAllFindings(findings);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setFindingsLoading(false);
    }
  }, [id]);

  const tabs: { id: TabId; label: string; icon: React.ElementType }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield },
    { id: 'manifest', label: 'Manifest', icon: FileText },
    { id: 'certificate', label: 'Certificate', icon: Lock },
    { id: 'binary', label: 'Binary', icon: Cpu },
    { id: 'code', label: 'Code Analysis', icon: Code },
    { id: 'security', label: 'Security Bypass', icon: Bot },
  ];

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" text="Loading report..." />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
        <AlertCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <p className="text-red-700">{error || 'Report not found'}</p>
        <Link to="/reports" className="mt-4 inline-block text-blue-600 hover:underline">
          ← Back to Reports
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link to="/reports" className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{report.app_name}</h1>
            <p className="text-gray-500 dark:text-gray-400">{report.package_name}</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          {report.status === 'processing' && (
            <div className="flex items-center text-blue-600">
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              <span>Analyzing...</span>
            </div>
          )}
          {report.status === 'completed' && (
            <div className="flex items-center text-green-600">
              <CheckCircle className="h-4 w-4 mr-2" />
              <span>Completed</span>
            </div>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex space-x-8">
          {tabs.map(({ id: tabId, label, icon: Icon }) => (
            <button
              key={tabId}
              onClick={() => setActiveTab(tabId)}
              className={cn(
                'flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors',
                activeTab === tabId
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300 dark:hover:border-gray-600'
              )}
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
              {tabId === 'code' && report.findings_summary.total > 0 && (
                <span className="ml-2 bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full text-xs dark:bg-gray-700 dark:text-gray-300">
                  {report.findings_summary.total}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="min-h-[500px]">
        {activeTab === 'dashboard' && <DashboardTab report={report} />}
        {activeTab === 'manifest' && <ManifestTab report={report} />}
        {activeTab === 'certificate' && <CertificateTab report={report} />}
        {activeTab === 'binary' && <BinaryTab report={report} />}
        {activeTab === 'code' && (
          <CodeTab 
            report={report} 
            findings={allFindings}
            loading={findingsLoading}
            progress={findingsProgress}
          />
        )}
        {activeTab === 'security' && <SecurityBypassTab reportId={parseInt(id!)} />}
      </div>
    </div>
  );
}

// ==================== Dashboard Tab ====================
function DashboardTab({ report }: { report: ReportDetail }) {
  const summary = report.findings_summary;
  
  const severityData = [
    { label: 'Critical', count: summary.critical, color: getSeverityBgColor('critical') },
    { label: 'High', count: summary.high, color: getSeverityBgColor('high') },
    { label: 'Medium', count: summary.medium, color: getSeverityBgColor('medium') },
    { label: 'Low', count: summary.low, color: getSeverityBgColor('low') },
    { label: 'Info', count: summary.info, color: getSeverityBgColor('info') },
  ];

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      {/* Risk Score Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 flex flex-col items-center justify-center">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Security Score</h3>
        <RiskScore score={report.risk_score} size="lg" />
      </div>

      {/* Findings Summary Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Findings Summary</h3>
        <div className="space-y-3">
          {severityData.map(({ label, count, color }) => (
            <div key={label} className="flex items-center justify-between">
              <div className="flex items-center">
                <div 
                  className="w-3 h-3 rounded-full mr-3" 
                  style={{ backgroundColor: color }}
                />
                <span className="text-gray-600 dark:text-gray-400">{label}</span>
              </div>
              <span className="font-semibold dark:text-white">{count}</span>
            </div>
          ))}
          <div className="border-t dark:border-gray-700 pt-3 mt-3">
            <div className="flex items-center justify-between font-semibold dark:text-white">
              <span>Total</span>
              <span>{summary.total}</span>
            </div>
          </div>
        </div>
      </div>

      {/* App Info Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Application Info</h3>
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">Package</dt>
            <dd className="font-mono text-gray-900 dark:text-white">{report.package_name}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">Version</dt>
            <dd className="text-gray-900 dark:text-white">{report.version_name || '-'}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">Size</dt>
            <dd className="text-gray-900 dark:text-white">{formatBytes(report.file_size)}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">Analyzed</dt>
            <dd className="text-gray-900 dark:text-white">{formatDate(report.created_at)}</dd>
          </div>
        </dl>
      </div>

      {/* Hashes Card */}
      <div className="lg:col-span-3 bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">File Hashes</h3>
        <div className="grid md:grid-cols-3 gap-4">
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">MD5</p>
            <p className="font-mono text-sm break-all dark:text-white">{report.md5_hash}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">SHA1</p>
            <p className="font-mono text-sm break-all dark:text-white">{report.sha1_hash}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">SHA256</p>
            <p className="font-mono text-sm break-all dark:text-white">{report.sha256_hash}</p>
          </div>
        </div>
      </div>

      {/* Top Finding Types */}
      {Object.keys(summary.by_type).length > 0 && (
        <div className="lg:col-span-3 bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Top Finding Types</h3>
          <div className="grid md:grid-cols-4 gap-4">
            {Object.entries(summary.by_type)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 8)
              .map(([type, count]) => (
                <div key={type} className="bg-gray-50 dark:bg-gray-700 rounded p-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400 capitalize">
                    {type.replace(/_/g, ' ')}
                  </p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{count}</p>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ==================== Manifest Tab ====================
function ManifestTab({ report }: { report: ReportDetail }) {
  const manifest = report.manifest_analysis;
  
  if (!manifest) {
    return (
      <div className="text-center py-12 text-gray-500">
        <FileText className="h-12 w-12 mx-auto mb-4 text-gray-300" />
        <p>Manifest analysis not available</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* SDK Info */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">SDK Information</h3>
        <div className="grid md:grid-cols-4 gap-4">
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Min SDK</p>
            <p className="text-2xl font-bold dark:text-white">{manifest.min_sdk || '-'}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Target SDK</p>
            <p className="text-2xl font-bold dark:text-white">{manifest.target_sdk || '-'}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Debuggable</p>
            <p className={cn("text-2xl font-bold", manifest.is_debuggable ? "text-red-600" : "text-green-600")}>
              {manifest.is_debuggable ? 'Yes' : 'No'}
            </p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Backup Allowed</p>
            <p className={cn("text-2xl font-bold", manifest.allows_backup ? "text-yellow-600" : "text-green-600")}>
              {manifest.allows_backup ? 'Yes' : 'No'}
            </p>
          </div>
        </div>
      </div>

      {/* Permissions */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">
          Permissions ({manifest.permissions.length})
        </h3>
        {manifest.permissions.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Permission</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {manifest.permissions.map((perm, idx) => (
                  <tr key={idx} className={perm.is_dangerous ? 'bg-red-50 dark:bg-red-900/30' : ''}>
                    <td className="px-4 py-3 font-mono text-sm dark:text-white">{perm.name}</td>
                    <td className="px-4 py-3">
                      {perm.is_dangerous ? (
                        <SeverityBadge severity="high" />
                      ) : (
                        <span className="text-green-600 text-sm">Normal</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">{perm.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500 dark:text-gray-400 text-center py-4">No permissions declared</p>
        )}
      </div>

      {/* Components */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Activities */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">
            Activities ({manifest.activities.length})
          </h3>
          <div className="max-h-64 overflow-y-auto space-y-2">
            {manifest.activities.map((activity, idx) => (
              <div key={idx} className={cn(
                "p-2 rounded text-sm font-mono dark:text-white",
                activity.exported ? "bg-yellow-50 border border-yellow-200 dark:bg-yellow-900/30 dark:border-yellow-700" : "bg-gray-50 dark:bg-gray-700"
              )}>
                <span className="break-all">{activity.name}</span>
                {activity.exported && (
                  <span className="ml-2 text-xs text-yellow-600">exported</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Services */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">
            Services ({manifest.services.length})
          </h3>
          <div className="max-h-64 overflow-y-auto space-y-2">
            {manifest.services.map((service, idx) => (
              <div key={idx} className={cn(
                "p-2 rounded text-sm font-mono dark:text-white",
                service.exported ? "bg-yellow-50 border border-yellow-200 dark:bg-yellow-900/30 dark:border-yellow-700" : "bg-gray-50 dark:bg-gray-700"
              )}>
                <span className="break-all">{service.name}</span>
                {service.exported && (
                  <span className="ml-2 text-xs text-yellow-600">exported</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Receivers */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">
            Receivers ({manifest.receivers.length})
          </h3>
          <div className="max-h-64 overflow-y-auto space-y-2">
            {manifest.receivers.map((receiver, idx) => (
              <div key={idx} className={cn(
                "p-2 rounded text-sm font-mono dark:text-white",
                receiver.exported ? "bg-yellow-50 border border-yellow-200 dark:bg-yellow-900/30 dark:border-yellow-700" : "bg-gray-50 dark:bg-gray-700"
              )}>
                <span className="break-all">{receiver.name}</span>
                {receiver.exported && (
                  <span className="ml-2 text-xs text-yellow-600">exported</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Providers */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">
            Content Providers ({manifest.providers.length})
          </h3>
          <div className="max-h-64 overflow-y-auto space-y-2">
            {manifest.providers.map((provider, idx) => (
              <div key={idx} className={cn(
                "p-2 rounded text-sm font-mono dark:text-white",
                provider.exported ? "bg-red-50 border border-red-200 dark:bg-red-900/30 dark:border-red-700" : "bg-gray-50 dark:bg-gray-700"
              )}>
                <span className="break-all">{provider.name}</span>
                {provider.exported && (
                  <span className="ml-2 text-xs text-red-600">exported</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== Certificate Tab ====================
function CertificateTab({ report }: { report: ReportDetail }) {
  const cert = report.certificate_analysis;
  
  if (!cert) {
    return (
      <div className="text-center py-12 text-gray-500">
        <Lock className="h-12 w-12 mx-auto mb-4 text-gray-300" />
        <p>Certificate analysis not available</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Certificate Status */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Certificate Status</h3>
        <div className="grid md:grid-cols-3 gap-4">
          <div className={cn(
            "p-4 rounded-lg border",
            cert.is_debug_signed ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200"
          )}>
            <p className="text-sm text-gray-600">Debug Signed</p>
            <p className={cn("text-xl font-bold", cert.is_debug_signed ? "text-red-600" : "text-green-600")}>
              {cert.is_debug_signed ? 'Yes ⚠️' : 'No ✓'}
            </p>
          </div>
          <div className={cn(
            "p-4 rounded-lg border",
            cert.is_expired ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200"
          )}>
            <p className="text-sm text-gray-600">Expired</p>
            <p className={cn("text-xl font-bold", cert.is_expired ? "text-red-600" : "text-green-600")}>
              {cert.is_expired ? 'Yes ⚠️' : 'No ✓'}
            </p>
          </div>
          <div className={cn(
            "p-4 rounded-lg border",
            cert.is_self_signed ? "bg-yellow-50 border-yellow-200" : "bg-gray-50 border-gray-200"
          )}>
            <p className="text-sm text-gray-600">Self Signed</p>
            <p className={cn("text-xl font-bold", cert.is_self_signed ? "text-yellow-600" : "text-gray-600")}>
              {cert.is_self_signed ? 'Yes' : 'No'}
            </p>
          </div>
        </div>
      </div>

      {/* Certificate Details */}
      {cert.certificates.map((certificate, idx) => (
        <div key={idx} className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Certificate #{idx + 1}</h3>
          <div className="grid md:grid-cols-2 gap-6">
            {/* Subject */}
            <div>
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Subject</h4>
              <dl className="space-y-1 text-sm">
                {Object.entries(certificate.subject).map(([key, value]) => (
                  <div key={key} className="flex">
                    <dt className="w-32 text-gray-500 dark:text-gray-400">{key}:</dt>
                    <dd className="text-gray-900 dark:text-white">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>

            {/* Issuer */}
            <div>
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Issuer</h4>
              <dl className="space-y-1 text-sm">
                {Object.entries(certificate.issuer).map(([key, value]) => (
                  <div key={key} className="flex">
                    <dt className="w-32 text-gray-500 dark:text-gray-400">{key}:</dt>
                    <dd className="text-gray-900 dark:text-white">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>

          {/* Validity */}
          <div className="mt-4 pt-4 border-t dark:border-gray-700">
            <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Validity</h4>
            <div className="grid md:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-500 dark:text-gray-400">Valid From:</span>{' '}
                <span className="text-gray-900 dark:text-white">{certificate.valid_from || '-'}</span>
              </div>
              <div>
                <span className="text-gray-500 dark:text-gray-400">Valid Until:</span>{' '}
                <span className="text-gray-900 dark:text-white">{certificate.valid_until || '-'}</span>
              </div>
            </div>
          </div>

          {/* Fingerprints */}
          {certificate.sha256_fingerprint && (
            <div className="mt-4 pt-4 border-t dark:border-gray-700">
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">SHA256 Fingerprint</h4>
              <p className="font-mono text-sm break-all bg-gray-50 dark:bg-gray-700 dark:text-white p-2 rounded">
                {certificate.sha256_fingerprint}
              </p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ==================== Binary Tab ====================
function BinaryTab({ report }: { report: ReportDetail }) {
  const binary = report.binary_analysis;
  
  if (!binary) {
    return (
      <div className="text-center py-12 text-gray-500">
        <Cpu className="h-12 w-12 mx-auto mb-4 text-gray-300" />
        <p>Binary analysis not available</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Binary Info */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Binary Information</h3>
        <div className="grid md:grid-cols-4 gap-4">
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">APK Size</p>
            <p className="text-2xl font-bold dark:text-white">{formatBytes(binary.apk_size)}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">DEX Files</p>
            <p className="text-2xl font-bold dark:text-white">{binary.dex_count}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Native Libraries</p>
            <p className="text-2xl font-bold dark:text-white">{binary.native_libraries.length}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
            <p className="text-sm text-gray-500 dark:text-gray-400">Architectures</p>
            <p className="text-xl font-bold dark:text-white">{binary.architectures.join(', ') || '-'}</p>
          </div>
        </div>
      </div>

      {/* Protections */}
      {binary.protections.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Security Protections</h3>
          <div className="space-y-3">
            {binary.protections.map((protection, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded">
                <div>
                  <p className="font-medium dark:text-white">{protection.name}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{protection.description}</p>
                </div>
                <span className={cn(
                  "px-3 py-1 rounded-full text-sm font-medium",
                  protection.is_enabled ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300" : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
                )}>
                  {protection.is_enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Native Libraries */}
      {binary.native_libraries.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Native Libraries</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Name</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Architecture</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Path</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {binary.native_libraries.map((lib, idx) => (
                  <tr key={idx}>
                    <td className="px-4 py-3 font-mono text-sm dark:text-white">{lib.name}</td>
                    <td className="px-4 py-3 text-sm dark:text-gray-300">{lib.architecture}</td>
                    <td className="px-4 py-3 font-mono text-sm text-gray-500 dark:text-gray-400">{lib.path}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ==================== Code Tab ====================
interface CodeTabProps {
  report: ReportDetail;
  findings: Finding[];
  loading: boolean;
  progress: { loaded: number; total: number };
}

function CodeTab({ report, findings, loading, progress }: CodeTabProps) {
  const codeAnalysis = report.code_analysis;
  
  return (
    <div className="space-y-6">
      {/* Code Stats */}
      {codeAnalysis && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">Code Statistics</h3>
          <div className="grid md:grid-cols-5 gap-4">
            <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Files</p>
              <p className="text-2xl font-bold dark:text-white">{codeAnalysis.total_files}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Lines</p>
              <p className="text-2xl font-bold dark:text-white">{codeAnalysis.total_lines.toLocaleString()}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Java Files</p>
              <p className="text-2xl font-bold dark:text-white">{codeAnalysis.java_files}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Kotlin Files</p>
              <p className="text-2xl font-bold dark:text-white">{codeAnalysis.kotlin_files}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-700 rounded p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Smali Files</p>
              <p className="text-2xl font-bold dark:text-white">{codeAnalysis.smali_files}</p>
            </div>
          </div>
        </div>
      )}

      {/* Findings DataTable */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-200 mb-4">
          Security Findings
          {!loading && findings.length > 0 && (
            <span className="ml-2 text-sm font-normal text-gray-500 dark:text-gray-400">
              ({findings.length} total)
            </span>
          )}
        </h3>
        
        <FindingsDataTable 
          findings={findings}
          loading={loading}
          loadingProgress={progress}
        />
      </div>
    </div>
  );
}

// ==================== Security Bypass Tab ====================
function SecurityBypassTab({ reportId }: { reportId: number }) {
  const [scanResult, setScanResult] = useState<SecurityScanResult | null>(null);
  const [aiConfig, setAiConfig] = useState<AIConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [fridaScript, setFridaScript] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadData();
  }, [reportId]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [scan, config] = await Promise.all([
        getSecurityScan(reportId),
        getAIConfig(),
      ]);
      
      setScanResult(scan);
      setAiConfig(config);
    } catch (err: any) {
      setError(err.message || 'Failed to load security scan');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateFrida = async () => {
    try {
      setGenerating(true);
      setError(null);
      
      const result = await generateFridaScript(reportId);
      
      if (result.success && result.script) {
        setFridaScript(result.script);
      } else {
        setError(result.error || 'Failed to generate script');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to generate Frida script');
    } finally {
      setGenerating(false);
    }
  };

  const copyToClipboard = async () => {
    if (!fridaScript) return;
    await navigator.clipboard.writeText(fridaScript);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadScript = () => {
    if (!fridaScript) return;
    const blob = new Blob([fridaScript], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `frida_bypass_${reportId}.js`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" text="Scanning for security mechanisms..." />
      </div>
    );
  }

  if (error && !scanResult) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
        <AlertCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <p className="text-red-700">{error}</p>
      </div>
    );
  }

  const summary = scanResult?.summary;

  return (
    <div className="space-y-6">
      {/* AI Configuration Status */}
      <div className={`p-4 rounded-lg ${aiConfig?.configured ? 'bg-green-50 border border-green-200' : 'bg-yellow-50 border border-yellow-200'}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {aiConfig?.configured ? (
              <>
                <CheckCircle className="w-5 h-5 text-green-600" />
                <span className="text-green-800">
                  AI Configured: {aiConfig.provider} / {aiConfig.model}
                </span>
              </>
            ) : (
              <>
                <AlertCircle className="w-5 h-5 text-yellow-600" />
                <span className="text-yellow-800">
                  AI not configured. Configure in AI Settings to generate bypass scripts.
                </span>
              </>
            )}
          </div>
          {!aiConfig?.configured && (
            <Link 
              to="/settings/ai"
              className="text-blue-600 hover:underline text-sm"
            >
              Configure AI →
            </Link>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Root Detection</p>
          <p className="text-2xl font-bold text-red-600">{summary?.root_detection_count || 0}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">SSL Pinning</p>
          <p className="text-2xl font-bold text-orange-600">{summary?.ssl_pinning_count || 0}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Native Protection</p>
          <p className="text-2xl font-bold text-purple-600">{summary?.native_protection_count || 0}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Bypass Difficulty</p>
          <p className={`text-2xl font-bold ${
            summary?.overall_bypass_difficulty === 'hard' ? 'text-red-600' :
            summary?.overall_bypass_difficulty === 'medium' ? 'text-yellow-600' :
            'text-green-600'
          }`}>
            {summary?.overall_bypass_difficulty || 'N/A'}
          </p>
        </div>
      </div>

      {/* Generate Frida Button */}
      {(summary?.total_findings || 0) > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Generate Frida Bypass Script</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                AI will analyze detected mechanisms and generate a comprehensive bypass script
              </p>
            </div>
            <button
              onClick={handleGenerateFrida}
              disabled={!aiConfig?.configured || generating}
              className="px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {generating ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Bot className="w-5 h-5" />
                  Send to AI for Frida Script
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded p-3 text-red-700 text-sm mb-4">
              {error}
            </div>
          )}

          {fridaScript && (
            <div className="mt-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-medium text-gray-700 dark:text-gray-300">Generated Frida Script</h4>
                <div className="flex gap-2">
                  <button
                    onClick={copyToClipboard}
                    className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded flex items-center gap-1"
                  >
                    <Copy className="w-4 h-4" />
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                  <button
                    onClick={downloadScript}
                    className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded flex items-center gap-1"
                  >
                    <Download className="w-4 h-4" />
                    Download
                  </button>
                </div>
              </div>
              <pre className="bg-gray-900 text-green-400 font-mono text-sm p-4 rounded-lg overflow-x-auto max-h-[500px] overflow-y-auto">
                {fridaScript}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Detection Details */}
      {scanResult && (
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Root Detection Findings */}
          {scanResult.root_detection.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-500" />
                Root Detection ({scanResult.root_detection.length})
              </h3>
              <div className="space-y-3 max-h-[400px] overflow-y-auto">
                {scanResult.root_detection.map((finding, idx) => (
                  <div key={idx} className="border dark:border-gray-700 rounded p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-gray-900 dark:text-white">{finding.category}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        finding.bypass_difficulty === 'hard' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' :
                        finding.bypass_difficulty === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300' :
                        'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                      }`}>
                        {finding.bypass_difficulty}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{finding.description}</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 font-mono truncate">{finding.file_path}:{finding.line_number}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SSL Pinning Findings */}
          {scanResult.ssl_pinning.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <Lock className="w-5 h-5 text-orange-500" />
                SSL Pinning ({scanResult.ssl_pinning.length})
              </h3>
              <div className="space-y-3 max-h-[400px] overflow-y-auto">
                {scanResult.ssl_pinning.map((finding, idx) => (
                  <div key={idx} className="border dark:border-gray-700 rounded p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-gray-900 dark:text-white">{finding.category}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        finding.bypass_difficulty === 'hard' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' :
                        finding.bypass_difficulty === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300' :
                        'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                      }`}>
                        {finding.bypass_difficulty}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{finding.description}</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 font-mono truncate">{finding.file_path}:{finding.line_number}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Native Protection Findings */}
          {scanResult.native_protection.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 lg:col-span-2">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <Cpu className="w-5 h-5 text-purple-500" />
                Native Protection ({scanResult.native_protection.length})
              </h3>
              <div className="grid md:grid-cols-2 gap-3 max-h-[400px] overflow-y-auto">
                {scanResult.native_protection.map((finding, idx) => (
                  <div key={idx} className="border dark:border-gray-700 rounded p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-gray-900 dark:text-white">{finding.category}</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">
                        {finding.bypass_difficulty}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{finding.description}</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 font-mono truncate">{finding.file_path}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* No Findings */}
      {(summary?.total_findings || 0) === 0 && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-8 text-center">
          <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-green-800">No Security Mechanisms Detected</h3>
          <p className="text-green-600 mt-2">
            This APK doesn't appear to have root detection or SSL pinning implemented.
          </p>
        </div>
      )}
    </div>
  );
}
