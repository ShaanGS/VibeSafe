import type { Finding } from '../types.js';

/**
 * LLM client for Groq/OpenAI fix generation.
 * Stub — will be implemented in Prompt 6.
 */
export interface FixResponse {
  fixed_code: string;
  explanation: string;
  pr_description: string;
}

/**
 * Builds the LLM prompt for a given finding and file context.
 * Stub — returns empty template until Prompt 6.
 */
export function buildFixPrompt(_finding: Finding, _fileContent: string): string {
  return '';
}

/**
 * Calls the configured LLM provider to generate a fix for a finding.
 * Stub — throws until API client is wired in Prompt 6.
 */
export async function generateFix(
  _finding: Finding,
  _fileContent: string,
): Promise<FixResponse> {
  throw new Error('LLM fix generation is not yet implemented');
}
