/**
 * Findings DataTable Component
 * Simple table with client-side pagination, search and sort
 * No external DataTables dependency - pure React implementation
 */

import { useEffect, useMemo, useState } from 'react';
import type { Finding } from '@/types/api';
import { processFindingsWithSeverity, getTypeDisplayName, truncateString } from '@/lib/utils';
import SeverityBadge from './SeverityBadge';

interface FindingsDataTableProps {
  findings: Finding[];
  loading?: boolean;
  loadingProgress?: { loaded: number; total: number };
}

const PAGE_SIZES = [10, 25, 50, 100];

export default function FindingsDataTable({ 
  findings, 
  loading = false,
  loadingProgress 
}: FindingsDataTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [pageSize, setPageSize] = useState(25);
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState<string>('severity');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Process findings to ensure all have valid severity
  const processedFindings = useMemo(() => {
    return processFindingsWithSeverity(findings);
  }, [findings]);

  // Severity order for sorting
  const severityOrder: Record<string, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    info: 5,
  };

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let result = [...processedFindings];

    // Search filter
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(f => 
        f.title.toLowerCase().includes(term) ||
        f.type.toLowerCase().includes(term) ||
        f.description.toLowerCase().includes(term) ||
        (f.file_path && f.file_path.toLowerCase().includes(term)) ||
        (f.cwe_id && f.cwe_id.toLowerCase().includes(term))
      );
    }

    // Sort
    result.sort((a, b) => {
      let comparison = 0;
      
      if (sortField === 'severity') {
        comparison = (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
      } else if (sortField === 'type') {
        comparison = a.type.localeCompare(b.type);
      } else if (sortField === 'title') {
        comparison = a.title.localeCompare(b.title);
      } else if (sortField === 'file_path') {
        comparison = (a.file_path || '').localeCompare(b.file_path || '');
      } else if (sortField === 'line_number') {
        comparison = (a.line_number || 0) - (b.line_number || 0);
      }

      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return result;
  }, [processedFindings, searchTerm, sortField, sortDirection]);

  // Pagination
  const totalPages = Math.ceil(filteredFindings.length / pageSize);
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredFindings.slice(start, start + pageSize);
  }, [filteredFindings, currentPage, pageSize]);

  // Reset page when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, pageSize]);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const SortIcon = ({ field }: { field: string }) => {
    if (sortField !== field) return <span className="text-gray-300 ml-1">↕</span>;
    return <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>;
  };

  // Export to CSV
  const exportToCsv = () => {
    const headers = ['Severity', 'Type', 'Title', 'File', 'Line', 'CWE', 'Description'];
    const rows = filteredFindings.map(f => [
      f.severity,
      f.type,
      f.title,
      f.file_path || '',
      f.line_number?.toString() || '',
      f.cwe_id || '',
      f.description.replace(/"/g, '""')
    ]);

    const csv = [
      headers.join(','),
      ...rows.map(r => r.map(c => `"${c}"`).join(','))
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'findings.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-gray-200 border-t-blue-600 mb-4"></div>
        <p className="text-gray-600">Loading findings...</p>
        {loadingProgress && loadingProgress.total > 0 && (
          <p className="text-sm text-gray-500 mt-2">
            {loadingProgress.loaded} / {loadingProgress.total} loaded
          </p>
        )}
      </div>
    );
  }

  if (processedFindings.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <p className="text-lg">No security findings detected</p>
        <p className="text-sm mt-2">The analyzed APK appears to be clean</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-600">Show</label>
            <select
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
              className="border rounded px-2 py-1 text-sm"
            >
              {PAGE_SIZES.map(size => (
                <option key={size} value={size}>{size}</option>
              ))}
            </select>
            <span className="text-sm text-gray-600">entries</span>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <input
            type="text"
            placeholder="Search findings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="border rounded px-3 py-1.5 text-sm w-64"
          />
          <button
            onClick={exportToCsv}
            className="px-3 py-1.5 bg-gray-100 hover:bg-gray-200 rounded text-sm font-medium"
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto border rounded-lg">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('severity')}
              >
                Severity <SortIcon field="severity" />
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('type')}
              >
                Type <SortIcon field="type" />
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('title')}
              >
                Title <SortIcon field="title" />
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('file_path')}
              >
                File <SortIcon field="file_path" />
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase cursor-pointer hover:bg-gray-100"
                onClick={() => handleSort('line_number')}
              >
                Line <SortIcon field="line_number" />
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                CWE
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                Details
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 bg-white">
            {paginatedFindings.map((finding, idx) => (
              <tr key={idx} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <SeverityBadge severity={finding.severity} />
                </td>
                <td className="px-4 py-3 text-sm">
                  {getTypeDisplayName(finding.type)}
                </td>
                <td className="px-4 py-3 text-sm font-medium text-gray-900">
                  {truncateString(finding.title, 50)}
                </td>
                <td className="px-4 py-3 text-sm text-gray-500 font-mono">
                  {finding.file_path ? truncateString(finding.file_path, 30) : '-'}
                </td>
                <td className="px-4 py-3 text-sm text-gray-500">
                  {finding.line_number || '-'}
                </td>
                <td className="px-4 py-3 text-sm">
                  {finding.cwe_id ? (
                    <a 
                      href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline"
                    >
                      {finding.cwe_id}
                    </a>
                  ) : '-'}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => setSelectedFinding(finding)}
                    className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-gray-600">
        <div>
          Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, filteredFindings.length)} of {filteredFindings.length} entries
          {searchTerm && ` (filtered from ${processedFindings.length} total)`}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage(1)}
            disabled={currentPage === 1}
            className="px-3 py-1 border rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
          >
            First
          </button>
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="px-3 py-1 border rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
          >
            Previous
          </button>
          <span className="px-3">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="px-3 py-1 border rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
          >
            Next
          </button>
          <button
            onClick={() => setCurrentPage(totalPages)}
            disabled={currentPage === totalPages}
            className="px-3 py-1 border rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
          >
            Last
          </button>
        </div>
      </div>

      {/* Finding Details Modal */}
      {selectedFinding && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          onClick={() => setSelectedFinding(null)}
        >
          <div 
            className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <SeverityBadge severity={selectedFinding.severity} />
                  <h3 className="text-lg font-semibold mt-2">{selectedFinding.title}</h3>
                </div>
                <button 
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-400 hover:text-gray-600 text-2xl leading-none"
                >
                  ×
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-700">Type</h4>
                  <p className="text-gray-600 mt-1">{getTypeDisplayName(selectedFinding.type)}</p>
                </div>
                
                <div>
                  <h4 className="font-medium text-gray-700">Description</h4>
                  <p className="text-gray-600 mt-1">{selectedFinding.description}</p>
                </div>
                
                {selectedFinding.file_path && (
                  <div>
                    <h4 className="font-medium text-gray-700">Location</h4>
                    <p className="text-gray-600 mt-1 font-mono text-sm bg-gray-50 p-2 rounded">
                      {selectedFinding.file_path}
                      {selectedFinding.line_number && `:${selectedFinding.line_number}`}
                    </p>
                  </div>
                )}
                
                {selectedFinding.code_snippet && (
                  <div>
                    <h4 className="font-medium text-gray-700">Code Snippet</h4>
                    <pre className="bg-gray-900 text-green-400 font-mono text-xs p-3 rounded mt-1 overflow-x-auto">
                      {selectedFinding.code_snippet}
                    </pre>
                  </div>
                )}
                
                {selectedFinding.recommendation && (
                  <div>
                    <h4 className="font-medium text-gray-700">Recommendation</h4>
                    <p className="text-gray-600 mt-1">{selectedFinding.recommendation}</p>
                  </div>
                )}
                
                <div className="flex gap-4 text-sm pt-2 border-t">
                  {selectedFinding.cwe_id && (
                    <a 
                      href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe_id.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline"
                    >
                      {selectedFinding.cwe_id}
                    </a>
                  )}
                  {selectedFinding.owasp_category && (
                    <span className="text-gray-500">
                      OWASP: {selectedFinding.owasp_category}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
