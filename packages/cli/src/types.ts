/**
 * Core type definitions for VibeSafe scan results, findings, and configuration.
 * These types flow through scanners, output formatters, and the fix pipeline.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  | 'sast'
  | 'secret'
  | 'dependency'
  | 'config';

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  code_snippet: string;
  rule_id: string;
  owasp?: string;
  cve?: string;
  fix_suggestion?: string;
  fix_patch?: string;
  references: string[];
}

export interface DependencyFinding extends Finding {
  package_name: string;
  installed_version: string;
  patched_version: string;
  ecosystem: 'npm' | 'pip' | 'cargo';
}

export interface ScanResult {
  meta: {
    repo_path: string;
    scanned_at: string;
    duration_ms: number;
    project_type: string[];
    vibesafe_version: string;
    commit_sha?: string;
    branch?: string;
  };
  findings: Finding[];
  summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_category: Record<FindingCategory, number>;
  };
  score: SafetyScore;
}

export interface SafetyScore {
  value: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  label: string;
  breakdown: {
    secrets: { score: number; issues: number };
    sast: { score: number; issues: number };
    dependencies: { score: number; issues: number };
    config: { score: number; issues: number };
  };
}

export interface VibeSafeConfig {
  scanners: {
    sast: boolean;
    secrets: boolean;
    dependencies: boolean;
    config: boolean;
  };
  minSeverity: Severity;
  failOn: Severity | 'none';
  customRules: string[];
  llm: {
    provider: 'groq' | 'openai' | 'anthropic';
    model?: string;
    maxTokens?: number;
  };
  exclude: string[];
}

export type ProjectType = 'nodejs' | 'python' | 'rust' | 'go' | 'unknown';
