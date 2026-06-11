import type { ScanResult } from '../types.js';

/**
 * Serialises scan results to JSON for CI and `--json` output mode.
 * Stub — will be implemented in Prompt 5.
 */
export function formatJsonOutput(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
