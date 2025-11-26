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
} from '@/types/api';

const API_BASE = '/api';

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new ApiError(response.status, error.detail || 'Request failed');
  }

  return response.json();
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
