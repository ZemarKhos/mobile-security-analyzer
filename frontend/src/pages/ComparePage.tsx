import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Minus,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  GitCompare,
  Shield,
  Lock,
  AlertCircle,
} from 'lucide-react';
import { findSimilarReports, compareReports } from '@/lib/api';
import type { ReportComparison } from '@/types/api';

export default function ComparePage() {
  const { id } = useParams<{ id: string }>();
  const reportId = parseInt(id || '0');

  const [similarReports, setSimilarReports] = useState<{
    id: number;
    app_name: string;
    version_name: string;
    risk_score: number;
    created_at: string;
  }[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<number | null>(null);
  const [comparison, setComparison] = useState<ReportComparison | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isComparing, setIsComparing] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadSimilarReports();
  }, [reportId]);

  const loadSimilarReports = async () => {
    try {
      const data = await findSimilarReports(reportId);
      setSimilarReports(data.similar_reports);
    } catch (err) {
      setError('Failed to load similar reports');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCompare = async () => {
    if (!selectedReportId) return;

    setIsComparing(true);
    setError('');

    try {
      const data = await compareReports(selectedReportId, reportId);
      setComparison(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Comparison failed');
    } finally {
      setIsComparing(false);
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'significantly_improved':
      case 'improved':
        return <TrendingDown className="h-5 w-5 text-green-500" />;
      case 'significantly_degraded':
      case 'degraded':
        return <TrendingUp className="h-5 w-5 text-red-500" />;
      default:
        return <Minus className="h-5 w-5 text-gray-500" />;
    }
  };

  const getTrendColor = (trend: string) => {
    switch (trend) {
      case 'significantly_improved':
      case 'improved':
        return 'text-green-600 dark:text-green-400';
      case 'significantly_degraded':
      case 'degraded':
        return 'text-red-600 dark:text-red-400';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          to={`/reports/${reportId}`}
          className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
        >
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <GitCompare className="h-6 w-6" />
            Version Comparison
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Compare security analysis between app versions
          </p>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-red-600 dark:text-red-400" />
          <p className="text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}

      {/* Version Selector */}
      {!comparison && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Select Version to Compare
          </h2>

          {similarReports.length === 0 ? (
            <p className="text-gray-600 dark:text-gray-400">
              No other versions found for this app. Upload another version to compare.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-3">
                {similarReports.map((report) => (
                  <button
                    key={report.id}
                    onClick={() => setSelectedReportId(report.id)}
                    className={`p-4 rounded-lg border text-left transition-colors ${
                      selectedReportId === report.id
                        ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                        : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                    }`}
                  >
                    <div className="flex justify-between items-center">
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {report.app_name}
                        </p>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Version: {report.version_name || 'N/A'}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-500">
                          {new Date(report.created_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="text-right">
                        <span
                          className={`text-lg font-bold ${
                            report.risk_score >= 70
                              ? 'text-red-600'
                              : report.risk_score >= 40
                              ? 'text-orange-600'
                              : 'text-green-600'
                          }`}
                        >
                          {report.risk_score}
                        </span>
                        <p className="text-xs text-gray-500">Risk Score</p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              <button
                onClick={handleCompare}
                disabled={!selectedReportId || isComparing}
                className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isComparing ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Comparing...
                  </>
                ) : (
                  <>
                    <GitCompare className="h-4 w-4" />
                    Compare Versions
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Baseline Report */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">Baseline (Older)</p>
              <p className="font-medium text-gray-900 dark:text-white">
                {comparison.metadata.baseline_report.app_name}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                v{comparison.metadata.baseline_report.version || 'N/A'}
              </p>
              <div className="mt-2 flex items-center gap-2">
                <Shield className="h-4 w-4 text-gray-500" />
                <span className="font-bold">{comparison.metadata.baseline_report.risk_score}</span>
              </div>
            </div>

            {/* Compared Report */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">Current (Newer)</p>
              <p className="font-medium text-gray-900 dark:text-white">
                {comparison.metadata.compared_report.app_name}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                v{comparison.metadata.compared_report.version || 'N/A'}
              </p>
              <div className="mt-2 flex items-center gap-2">
                <Shield className="h-4 w-4 text-gray-500" />
                <span className="font-bold">{comparison.metadata.compared_report.risk_score}</span>
              </div>
            </div>
          </div>

          {/* Security Trend */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {getTrendIcon(comparison.security_trend.trend)}
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    Security Trend
                  </h3>
                  <p className={getTrendColor(comparison.security_trend.trend)}>
                    {comparison.security_trend.description}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold">
                  {comparison.security_trend.risk_score_change > 0 ? '+' : ''}
                  {comparison.security_trend.risk_score_change}
                </p>
                <p className="text-sm text-gray-500">Risk Score Change</p>
              </div>
            </div>
          </div>

          {/* Findings Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-600" />
                <span className="font-medium text-red-900 dark:text-red-300">New Issues</span>
              </div>
              <p className="text-3xl font-bold text-red-600">
                {comparison.summary.new_findings_count}
              </p>
            </div>

            <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <span className="font-medium text-green-900 dark:text-green-300">Fixed Issues</span>
              </div>
              <p className="text-3xl font-bold text-green-600">
                {comparison.summary.fixed_findings_count}
              </p>
            </div>

            <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Minus className="h-5 w-5 text-gray-600" />
                <span className="font-medium text-gray-900 dark:text-gray-300">Unchanged</span>
              </div>
              <p className="text-3xl font-bold text-gray-600 dark:text-gray-400">
                {comparison.summary.unchanged_findings_count}
              </p>
            </div>
          </div>

          {/* Permission Changes */}
          {(comparison.permissions_comparison.added.length > 0 ||
            comparison.permissions_comparison.removed.length > 0) && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Permission Changes
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {comparison.permissions_comparison.added.length > 0 && (
                  <div>
                    <p className="text-sm font-medium text-red-600 mb-2">
                      Added Permissions ({comparison.permissions_comparison.added.length})
                    </p>
                    <ul className="space-y-1">
                      {comparison.permissions_comparison.added.slice(0, 5).map((perm, i) => (
                        <li key={i} className="text-sm text-gray-600 dark:text-gray-400 flex items-center gap-1">
                          <span className="text-red-500">+</span>
                          {perm.split('.').pop()}
                        </li>
                      ))}
                      {comparison.permissions_comparison.added.length > 5 && (
                        <li className="text-sm text-gray-500">
                          +{comparison.permissions_comparison.added.length - 5} more
                        </li>
                      )}
                    </ul>
                  </div>
                )}

                {comparison.permissions_comparison.removed.length > 0 && (
                  <div>
                    <p className="text-sm font-medium text-green-600 mb-2">
                      Removed Permissions ({comparison.permissions_comparison.removed.length})
                    </p>
                    <ul className="space-y-1">
                      {comparison.permissions_comparison.removed.slice(0, 5).map((perm, i) => (
                        <li key={i} className="text-sm text-gray-600 dark:text-gray-400 flex items-center gap-1">
                          <span className="text-green-500">-</span>
                          {perm.split('.').pop()}
                        </li>
                      ))}
                      {comparison.permissions_comparison.removed.length > 5 && (
                        <li className="text-sm text-gray-500">
                          +{comparison.permissions_comparison.removed.length - 5} more
                        </li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* New Findings */}
          {comparison.findings_comparison.new.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <XCircle className="h-5 w-5 text-red-500" />
                New Security Issues ({comparison.findings_comparison.new.length})
              </h3>

              <div className="space-y-3 max-h-96 overflow-y-auto">
                {comparison.findings_comparison.new.slice(0, 10).map((finding, i) => (
                  <div
                    key={i}
                    className="p-3 bg-red-50 dark:bg-red-900/10 rounded-lg border border-red-200 dark:border-red-800"
                  >
                    <div className="flex items-start justify-between">
                      <p className="font-medium text-gray-900 dark:text-white">
                        {finding.title}
                      </p>
                      <span
                        className={`text-xs px-2 py-1 rounded-full ${
                          finding.severity === 'critical'
                            ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                            : finding.severity === 'high'
                            ? 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
                            : finding.severity === 'medium'
                            ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                            : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                        }`}
                      >
                        {finding.severity}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      {finding.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Fixed Findings */}
          {comparison.findings_comparison.fixed.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-500" />
                Fixed Security Issues ({comparison.findings_comparison.fixed.length})
              </h3>

              <div className="space-y-3 max-h-96 overflow-y-auto">
                {comparison.findings_comparison.fixed.slice(0, 10).map((finding, i) => (
                  <div
                    key={i}
                    className="p-3 bg-green-50 dark:bg-green-900/10 rounded-lg border border-green-200 dark:border-green-800"
                  >
                    <div className="flex items-start justify-between">
                      <p className="font-medium text-gray-900 dark:text-white line-through opacity-75">
                        {finding.title}
                      </p>
                      <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                        Fixed
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1 opacity-75">
                      {finding.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Compare Another */}
          <button
            onClick={() => setComparison(null)}
            className="w-full py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
          >
            Compare Another Version
          </button>
        </div>
      )}
    </div>
  );
}
