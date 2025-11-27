/**
 * API Types for Mobile Analyzer
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AnalysisStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type Platform = 'android' | 'ios';

export interface Finding {
  id?: number;
  type: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  recommendation?: string;
  cwe_id?: string;
  owasp_category?: string;
}

export interface FindingsSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  by_type: Record<string, number>;
}

export interface PaginatedFindings {
  findings: Finding[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface Permission {
  name: string;
  protection_level?: string;
  description?: string;
  is_dangerous: boolean;
}

export interface Activity {
  name: string;
  exported: boolean;
  permission?: string;
  intent_filters: string[];
}

export interface Service {
  name: string;
  exported: boolean;
  permission?: string;
}

export interface Receiver {
  name: string;
  exported: boolean;
  permission?: string;
  intent_filters: string[];
}

export interface Provider {
  name: string;
  exported: boolean;
  permission?: string;
  read_permission?: string;
  write_permission?: string;
  authorities?: string;
}

export interface ManifestAnalysis {
  package_name: string;
  version_name?: string;
  version_code?: number;
  min_sdk?: number;
  target_sdk?: number;
  permissions: Permission[];
  activities: Activity[];
  services: Service[];
  receivers: Receiver[];
  providers: Provider[];
  is_debuggable: boolean;
  allows_backup: boolean;
  uses_cleartext_traffic: boolean;
  findings: Finding[];
}

export interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  serial_number?: string;
  valid_from?: string;
  valid_until?: string;
  signature_algorithm?: string;
  md5_fingerprint?: string;
  sha1_fingerprint?: string;
  sha256_fingerprint?: string;
}

export interface CertificateAnalysis {
  certificates: CertificateInfo[];
  is_debug_signed: boolean;
  is_expired: boolean;
  is_self_signed: boolean;
  findings: Finding[];
}

export interface LibraryInfo {
  name: string;
  path: string;
  architecture?: string;
  is_stripped: boolean;
}

export interface BinaryProtection {
  name: string;
  description: string;
  is_enabled: boolean;
  severity: SeverityLevel;
}

export interface BinaryAnalysis {
  apk_size: number;
  dex_count: number;
  native_libraries: LibraryInfo[];
  architectures: string[];
  protections: BinaryProtection[];
  findings: Finding[];
}

export interface CodeAnalysis {
  total_files: number;
  total_lines: number;
  java_files: number;
  kotlin_files: number;
  smali_files: number;
  findings_summary: FindingsSummary;
  findings: Finding[];
}

export interface ReportSummary {
  id: number;
  app_name: string;
  package_name: string;
  version_name?: string;
  file_name: string;
  platform: Platform;
  status: AnalysisStatus;
  risk_score: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  created_at: string;
  completed_at?: string;
}

export interface ReportDetail {
  id: number;
  app_name: string;
  package_name: string;
  version_name?: string;
  version_code?: number;
  file_name: string;
  file_size: number;
  md5_hash: string;
  sha1_hash: string;
  sha256_hash: string;
  platform: Platform;
  status: AnalysisStatus;
  risk_score: number;
  created_at: string;
  completed_at?: string;
  manifest_analysis?: ManifestAnalysis;
  certificate_analysis?: CertificateAnalysis;
  binary_analysis?: BinaryAnalysis;
  code_analysis?: CodeAnalysis;
  findings_summary: FindingsSummary;
}

export interface UploadResponse {
  report_id: number;
  message: string;
  status: AnalysisStatus;
  platform: Platform;
}

export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

// Security Rules Types
export type RuleType = 
  | 'root_detection' 
  | 'ssl_pinning' 
  | 'anti_tampering' 
  | 'ios_jailbreak' 
  | 'ios_ssl_pinning';

export interface SecurityRule {
  id: number;
  name: string;
  type: RuleType;
  category: string;
  pattern: string;
  is_regex: boolean;
  case_sensitive: boolean;
  description: string;
  severity: SeverityLevel;
  bypass_difficulty: 'easy' | 'medium' | 'hard';
  platform: 'android' | 'ios' | 'both';
  is_enabled: boolean;
  is_builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface RulesListResponse {
  rules: SecurityRule[];
  total: number;
  by_type: Record<RuleType, number>;
}

export interface RuleCreate {
  name: string;
  type: RuleType;
  category: string;
  pattern: string;
  is_regex?: boolean;
  case_sensitive?: boolean;
  description?: string;
  severity?: SeverityLevel;
  bypass_difficulty?: 'easy' | 'medium' | 'hard';
  platform?: 'android' | 'ios' | 'both';
}

export interface RuleUpdate {
  name?: string;
  type?: RuleType;
  category?: string;
  pattern?: string;
  is_regex?: boolean;
  case_sensitive?: boolean;
  description?: string;
  severity?: SeverityLevel;
  bypass_difficulty?: 'easy' | 'medium' | 'hard';
  platform?: 'android' | 'ios' | 'both';
}

// Authentication Types
export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

// CVE Types
export interface CVEMatch {
  finding_id?: number;
  finding_title?: string;
  cve_id: string;
  description?: string;
  cve_description?: string;
  cve_category?: string;
  severity: string;
  cvss_score?: number;
  match_type?: string;
  match_confidence?: string;
  recommendation?: string;
  note?: string;
  affected_library?: string;
}

export interface CVESearchResult {
  cve_id: string;
  description: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  published?: string;
  lastModified?: string;
}

export interface ReportCVEMatches {
  report_id: number;
  total_matches: number;
  severity_breakdown: Record<string, number>;
  matches: CVEMatch[];
}

// Report Comparison Types
export interface ComparisonSummary {
  new_findings_count: number;
  fixed_findings_count: number;
  unchanged_findings_count: number;
  permissions_added: number;
  permissions_removed: number;
  security_flag_changes: number;
  risk_score_change: number;
}

export interface SecurityTrend {
  trend: 'significantly_improved' | 'improved' | 'unchanged' | 'degraded' | 'significantly_degraded';
  description: string;
  risk_score_change: number;
  old_risk_score: number;
  new_risk_score: number;
}

export interface ReportComparison {
  metadata: {
    baseline_report: {
      id: number;
      app_name: string;
      version?: string;
      package_name: string;
      platform: Platform;
      analyzed_at: string;
      risk_score: number;
    };
    compared_report: {
      id: number;
      app_name: string;
      version?: string;
      package_name: string;
      platform: Platform;
      analyzed_at: string;
      risk_score: number;
    };
    comparison_date: string;
  };
  security_trend: SecurityTrend;
  findings_comparison: {
    new: Finding[];
    fixed: Finding[];
    unchanged: Finding[];
  };
  severity_comparison: Record<string, {
    old: number;
    new: number;
    difference: number;
    change: string;
  }>;
  permissions_comparison: {
    added: string[];
    removed: string[];
    unchanged_count: number;
  };
  summary: ComparisonSummary;
}

// Config Types
export interface AppConfig {
  max_file_size_mb: number;
  supported_formats: string[];
  version: string;
  features: {
    authentication: boolean;
    pdf_export: boolean;
    csv_export: boolean;
    cve_matching: boolean;
    report_comparison: boolean;
    ai_integration: boolean;
  };
}

// DAST/Frida Types
export interface FridaTemplate {
  id: string;
  name: string;
  category: string;
  platform: string;
  description: string;
  targets: string[];
  difficulty: string;
  script?: string;
}

export interface GeneratedScript {
  report_id: number;
  platform: string;
  app_name: string;
  templates_used: string[];
  detection_summary: {
    root_detection: number;
    ssl_pinning: number;
    jailbreak: number;
  };
  script: string;
  usage: {
    android: string;
    ios: string;
  };
}

export interface CustomHookRequest {
  class_name: string;
  method_name: string;
  platform: string;
  log_arguments: boolean;
  log_return_value: boolean;
  modify_return?: string;
}
