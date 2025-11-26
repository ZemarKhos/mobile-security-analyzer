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
