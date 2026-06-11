/**
 * Git helpers for branch, remote URL, and commit SHA detection.
 * Stub — will be implemented for GitHub PR creation in Prompt 7.
 */
export interface RepoInfo {
  owner: string;
  repo: string;
  currentSha: string;
  defaultBranch: string;
}

/**
 * Parses the GitHub owner/repo from `git remote get-url origin`.
 * Stub — returns placeholder values until Prompt 7.
 */
export async function getRepoInfo(_repoPath: string): Promise<RepoInfo | null> {
  return null;
}
