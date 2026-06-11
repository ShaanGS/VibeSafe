import type { Finding } from '../types.js';

/**
 * Represents a file patch produced by the fix pipeline.
 */
export interface Patch {
  file: string;
  newContent: string;
  findingTitle: string;
  existingFileSha?: string;
}

/**
 * Applies generated fixes to files on disk.
 * Stub — will be implemented in Prompt 6.
 */
export async function applyPatches(_patches: Patch[]): Promise<void> {
  // Intentionally empty until patcher is built.
}

/**
 * Builds Patch objects from LLM fix responses for a set of findings.
 * Stub — returns empty array until Prompt 6.
 */
export async function buildPatches(_findings: Finding[]): Promise<Patch[]> {
  return [];
}
