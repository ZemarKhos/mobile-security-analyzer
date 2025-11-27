/**
 * API Service for Mobile Analyzer
 */

import type {
  ReportSummary,
  ReportDetail,
  PaginatedFindings,
  FindingsSummary,
  UploadResponse,
  HealthResponse,
  AuthTokens,
  User,
  LoginRequest,
  RegisterRequest,
  ReportComparison,
  CVEMatch,
  CVESearchResult,
  ReportCVEMatches,
  AppConfig,
} from '@/types/api';

const API_BASE = '/api';

// Token storage
let accessToken: string | null = localStorage.getItem('access_token');
let refreshToken: string | null = localStorage.getItem('refresh_token');

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

// Token management
export function setTokens(access: string, refresh: string) {
  accessToken = access;
  refreshToken = refresh;
  localStorage.setItem('access_token', access);
  localStorage.setItem('refresh_token', refresh);
}

export function clearTokens() {
  accessToken = null;
  refreshToken = null;
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function isAuthenticated(): boolean {
  return !!accessToken;
}

async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit,
  skipAuth = false
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  // Add auth header if we have a token
  if (accessToken && !skipAuth) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  // Handle 401 - try to refresh token
  if (response.status === 401 && refreshToken && !endpoint.includes('/auth/')) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      // Retry the request with new token
      headers['Authorization'] = `Bearer ${accessToken}`;
      const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
      });
      if (retryResponse.ok) {
        return retryResponse.json();
      }
    }
    clearTokens();
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new ApiError(response.status, error.detail || 'Request failed');
  }

  return response.json();
}

async function tryRefreshToken(): Promise<boolean> {
  if (!refreshToken) return false;

  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (response.ok) {
      const data: AuthTokens = await response.json();
      setTokens(data.access_token, data.refresh_token);
      return true;
    }
  } catch {
    // Refresh failed
  }
  return false;
}

// Health Check
export async function checkHealth(): Promise<HealthResponse> {
  return fetchApi<HealthResponse>('/health');
}

// Reports
export async function getReports(limit = 50, offset = 0): Promise<ReportSummary[]> {
  return fetchApi<ReportSummary[]>(`/reports/?limit=${limit}&offset=${offset}`);
}

export async function getReport(id: number): Promise<ReportDetail> {
  return fetchApi<ReportDetail>(`/reports/${id}`);
}

export async function deleteReport(id: number): Promise<void> {
  await fetchApi<void>(`/reports/${id}`, { method: 'DELETE' });
}

// Findings - Pagination API
export async function getReportFindings(
  reportId: number,
  page = 1,
  pageSize = 100,
  severity?: string,
  type?: string
): Promise<PaginatedFindings> {
  const params = new URLSearchParams({
    page: page.toString(),
    page_size: pageSize.toString(),
  });
  
  if (severity) params.append('severity', severity);
  if (type) params.append('type', type);
  
  return fetchApi<PaginatedFindings>(`/reports/${reportId}/findings?${params}`);
}

export async function getFindingsSummary(reportId: number): Promise<FindingsSummary> {
  return fetchApi<FindingsSummary>(`/reports/${reportId}/findings/summary`);
}

// Upload
export async function uploadApk(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
    throw new ApiError(response.status, error.detail || 'Upload failed');
  }

  return response.json();
}

// Report Status Polling
export async function getReportStatus(
  id: number
): Promise<{ report_id: number; status: string; created_at: string; completed_at?: string }> {
  return fetchApi(`/reports/${id}/status`);
}

// Utility: Fetch all findings with pagination
export async function fetchAllFindings(
  reportId: number,
  pageSize = 100,
  onProgress?: (loaded: number, total: number) => void
): Promise<import('@/types/api').Finding[]> {
  const allFindings: import('@/types/api').Finding[] = [];
  let page = 1;
  let totalPages = 1;
  
  do {
    const result = await getReportFindings(reportId, page, pageSize);
    allFindings.push(...result.findings);
    totalPages = result.total_pages;
    
    if (onProgress) {
      onProgress(allFindings.length, result.total);
    }
    
    page++;
  } while (page <= totalPages);
  
  return allFindings;
}

// ============================================
// AI Integration API
// ============================================

export interface AIProvider {
  id: string;
  name: string;
  description: string;
  requires_api_key: boolean;
  requires_base_url: boolean;
  default_base_url?: string;
  default_model: string;
  models: string[];
}

export interface AIConfig {
  configured: boolean;
  provider?: string;
  model?: string;
  base_url?: string;
}

export interface AIConfigRequest {
  provider: string;
  api_key?: string;
  base_url?: string;
  model: string;
  temperature?: number;
  max_tokens?: number;
}

export interface SecurityMechanismFinding {
  type: string;
  category: string;
  file_path: string;
  line_number: number;
  code_snippet: string;
  pattern_matched: string;
  severity: string;
  description: string;
  bypass_difficulty: string;
}

export interface SecurityScanResult {
  summary: {
    total_findings: number;
    root_detection_count: number;
    ssl_pinning_count: number;
    native_protection_count: number;
    overall_bypass_difficulty: string;
    root_detection_categories: Record<string, number>;
    ssl_pinning_categories: Record<string, number>;
  };
  root_detection: SecurityMechanismFinding[];
  ssl_pinning: SecurityMechanismFinding[];
  native_protection: SecurityMechanismFinding[];
  all_findings: SecurityMechanismFinding[];
}

export interface FridaScriptResponse {
  success: boolean;
  script?: string;
  error?: string;
  provider?: string;
  model?: string;
}

// Get available AI providers
export async function getAIProviders(): Promise<{ providers: AIProvider[] }> {
  return fetchApi<{ providers: AIProvider[] }>('/ai/providers');
}

// Get current AI configuration
export async function getAIConfig(): Promise<AIConfig> {
  return fetchApi<AIConfig>('/ai/config');
}

// Update AI configuration
export async function updateAIConfig(config: AIConfigRequest): Promise<{ success: boolean; message: string }> {
  return fetchApi<{ success: boolean; message: string }>('/ai/config', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

// Delete AI configuration
export async function deleteAIConfig(): Promise<{ success: boolean; message: string }> {
  return fetchApi<{ success: boolean; message: string }>('/ai/config', {
    method: 'DELETE',
  });
}

// Test AI connection
export async function testAIConnection(): Promise<{ success: boolean; message: string; response?: string }> {
  return fetchApi<{ success: boolean; message: string; response?: string }>('/ai/test', {
    method: 'POST',
  });
}

// Get security mechanism scan results
export async function getSecurityScan(reportId: number): Promise<SecurityScanResult> {
  return fetchApi<SecurityScanResult>(`/ai/security-scan/${reportId}`);
}

// Generate Frida bypass script
export async function generateFridaScript(
  reportId: number,
  customPrompt?: string
): Promise<FridaScriptResponse> {
  return fetchApi<FridaScriptResponse>(`/ai/generate-frida/${reportId}`, {
    method: 'POST',
    body: JSON.stringify(customPrompt || null),
  });
}

// ============================================
// Security Rules API
// ============================================

import type {
  SecurityRule,
  RulesListResponse,
  RuleCreate,
  RuleUpdate,
  RuleType,
} from '@/types/api';

// Get all rules
export async function getRules(
  type?: RuleType,
  platform?: 'android' | 'ios' | 'both',
  enabled_only?: boolean
): Promise<RulesListResponse> {
  const params = new URLSearchParams();
  if (type) params.append('type', type);
  if (platform) params.append('platform', platform);
  if (enabled_only !== undefined) params.append('enabled_only', String(enabled_only));
  
  const query = params.toString();
  return fetchApi<RulesListResponse>(`/rules${query ? `?${query}` : ''}`);
}

// Get single rule
export async function getRule(id: number): Promise<SecurityRule> {
  return fetchApi<SecurityRule>(`/rules/${id}`);
}

// Create new rule
export async function createRule(rule: RuleCreate): Promise<SecurityRule> {
  return fetchApi<SecurityRule>('/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  });
}

// Update rule
export async function updateRule(id: number, rule: RuleUpdate): Promise<SecurityRule> {
  return fetchApi<SecurityRule>(`/rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(rule),
  });
}

// Delete rule
export async function deleteRule(id: number): Promise<{ message: string }> {
  return fetchApi<{ message: string }>(`/rules/${id}`, {
    method: 'DELETE',
  });
}

// Toggle rule enabled status
export async function toggleRule(id: number): Promise<{ is_enabled: boolean; message: string }> {
  return fetchApi<{ is_enabled: boolean; message: string }>(`/rules/${id}/toggle`, {
    method: 'POST',
  });
}

// Seed default rules
export async function seedDefaultRules(): Promise<{ message: string; seeded: number }> {
  return fetchApi<{ message: string; seeded: number }>('/rules/seed', {
    method: 'POST',
  });
}

// Get rule categories
export async function getRuleCategories(): Promise<{ categories: Record<RuleType, string[]> }> {
  return fetchApi<{ categories: Record<RuleType, string[]> }>('/rules/categories/list');
}

// ============================================
// Authentication API
// ============================================

// Register new user
export async function register(data: RegisterRequest): Promise<AuthTokens> {
  const response = await fetchApi<AuthTokens>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  }, true);
  setTokens(response.access_token, response.refresh_token);
  return response;
}

// Login
export async function login(data: LoginRequest): Promise<AuthTokens> {
  const response = await fetchApi<AuthTokens>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(data),
  }, true);
  setTokens(response.access_token, response.refresh_token);
  return response;
}

// Logout
export async function logout(): Promise<void> {
  try {
    await fetchApi('/auth/logout', { method: 'POST' });
  } finally {
    clearTokens();
  }
}

// Get current user
export async function getCurrentUser(): Promise<User> {
  return fetchApi<User>('/auth/me');
}

// Change password
export async function changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
  return fetchApi<{ message: string }>('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

// List users (admin only)
export async function listUsers(limit = 100, offset = 0): Promise<User[]> {
  return fetchApi<User[]>(`/auth/users?limit=${limit}&offset=${offset}`);
}

// Update user role (admin only)
export async function updateUserRole(userId: number, role: string): Promise<{ message: string }> {
  return fetchApi<{ message: string }>(`/auth/users/${userId}/role?role=${role}`, {
    method: 'PUT',
  });
}

// Toggle user active status (admin only)
export async function toggleUserActive(userId: number): Promise<{ message: string; is_active: boolean }> {
  return fetchApi<{ message: string; is_active: boolean }>(`/auth/users/${userId}/toggle-active`, {
    method: 'POST',
  });
}

// ============================================
// Export API
// ============================================

// Export report to PDF
export function getExportPdfUrl(reportId: number): string {
  return `${API_BASE}/export/reports/${reportId}/pdf`;
}

// Export findings to CSV
export function getExportCsvUrl(reportId: number): string {
  return `${API_BASE}/export/reports/${reportId}/csv`;
}

// Export report to JSON
export function getExportJsonUrl(reportId: number): string {
  return `${API_BASE}/export/reports/${reportId}/json`;
}

// Download export with auth
export async function downloadExport(url: string, filename: string): Promise<void> {
  const headers: Record<string, string> = {};
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new ApiError(response.status, 'Export failed');
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  document.body.removeChild(a);
}

// ============================================
// CVE API
// ============================================

// Search CVEs
export async function searchCVEs(keyword: string, limit = 20): Promise<{ keyword: string; count: number; results: CVESearchResult[] }> {
  return fetchApi(`/cve/search?keyword=${encodeURIComponent(keyword)}&limit=${limit}`);
}

// Get CVE details
export async function getCVEDetails(cveId: string): Promise<CVESearchResult> {
  return fetchApi(`/cve/details/${cveId}`);
}

// Match report findings to CVEs
export async function matchReportCVEs(reportId: number): Promise<{ report_id: number; findings_analyzed: number; matches_found: number; matches: CVEMatch[] }> {
  return fetchApi(`/cve/reports/${reportId}/match`, { method: 'POST' });
}

// Get report CVE matches
export async function getReportCVEMatches(reportId: number): Promise<ReportCVEMatches> {
  return fetchApi(`/cve/reports/${reportId}/matches`);
}

// Get known library CVEs
export async function getKnownLibraryCVEs(): Promise<{ total_libraries: number; total_cves: number; libraries: { library: string; cve_count: number; cves: CVEMatch[] }[] }> {
  return fetchApi('/cve/known-libraries');
}

// ============================================
// Report Comparison API
// ============================================

// Compare two reports
export async function compareReports(baselineId: number, comparedId: number): Promise<ReportComparison> {
  return fetchApi('/compare', {
    method: 'POST',
    body: JSON.stringify({ baseline_report_id: baselineId, compared_report_id: comparedId }),
  });
}

// Find similar reports for comparison
export async function findSimilarReports(reportId: number): Promise<{ report_id: number; package_name: string; similar_reports: { id: number; app_name: string; version_name: string; status: string; risk_score: number; created_at: string }[] }> {
  return fetchApi(`/compare/reports/${reportId}/similar`);
}

// Quick comparison
export async function quickCompare(baselineId: number, comparedId: number): Promise<{ baseline: { id: number; version: string; risk_score: number; total_findings: number }; compared: { id: number; version: string; risk_score: number; total_findings: number }; risk_score_change: number; findings_change: number; trend: string }> {
  return fetchApi(`/compare/quick?baseline_id=${baselineId}&compared_id=${comparedId}`);
}

// ============================================
// Config API
// ============================================

// Get app config
export async function getAppConfig(): Promise<AppConfig> {
  return fetchApi('/config');
}

// ============================================
// DAST/Frida API
// ============================================

import type { FridaTemplate, GeneratedScript, CustomHookRequest } from '@/types/api';

// Get all Frida templates
export async function getFridaTemplates(category?: string, platform?: string): Promise<FridaTemplate[]> {
  const params = new URLSearchParams();
  if (category) params.append('category', category);
  if (platform) params.append('platform', platform);
  const query = params.toString();
  return fetchApi(`/dast/templates${query ? `?${query}` : ''}`);
}

// Get specific template with script
export async function getFridaTemplate(templateId: string): Promise<FridaTemplate> {
  return fetchApi(`/dast/templates/${templateId}`);
}

// Get template categories
export async function getFridaCategories(): Promise<{ categories: { id: string; name: string; count: number }[] }> {
  return fetchApi('/dast/templates/categories/list');
}

// Combine multiple templates
export async function combineFridaTemplates(templateIds: string[]): Promise<{ templates_used: string[]; script: string }> {
  return fetchApi('/dast/templates/combine', {
    method: 'POST',
    body: JSON.stringify({ template_ids: templateIds }),
  });
}

// Generate bypass script for report
export async function generateBypassScript(reportId: number): Promise<GeneratedScript> {
  return fetchApi(`/dast/generate/${reportId}`, { method: 'POST' });
}

// Generate custom hook
export async function generateCustomHook(request: CustomHookRequest): Promise<{ class_name: string; method_name: string; platform: string; script: string }> {
  return fetchApi('/dast/hooks/generate', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

// Get crypto trace script
export async function getCryptoTraceScript(platform: string): Promise<{ platform: string; description: string; script: string }> {
  return fetchApi(`/dast/trace/crypto/${platform}`);
}

// Get network trace script
export async function getNetworkTraceScript(platform: string): Promise<{ platform: string; description: string; script: string }> {
  return fetchApi(`/dast/trace/network/${platform}`);
}

// Get quickstart script
export async function getQuickstartScript(platform: string, bypassType: string = 'all'): Promise<{
  platform: string;
  bypass_type: string;
  template_name: string;
  description: string;
  script: string;
  usage: string;
  tips: string[];
}> {
  return fetchApi(`/dast/quickstart/${platform}?bypass_type=${bypassType}`);
}

// Get ultimate bypass script (all bypasses combined)
export async function getUltimateBypassScript(platform: string): Promise<{
  platform: string;
  name: string;
  description: string;
  templates_included: string[];
  features: string[];
  script: string;
  usage: string;
  warnings: string[];
}> {
  return fetchApi(`/dast/ultimate/${platform}`);
}
