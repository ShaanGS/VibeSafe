import type { Finding } from '../types.js';
import type { Patch } from './patcher.js';
import type { RepoInfo } from '../utils/git.js';

/**
 * Creates a GitHub pull request with VibeSafe-generated fixes.
 * Stub — will be implemented in Prompt 7.
 */
export async function createFixPR(
  _findings: Finding[],
  _patches: Patch[],
  _repoInfo: RepoInfo,
): Promise<string> {
  throw new Error('GitHub PR creation is not yet implemented');
}
