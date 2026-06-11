import { access, readdir } from 'fs/promises';
import { join } from 'path';
import type { ProjectType } from '../types.js';

const PYTHON_MARKERS = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py'] as const;

/** Directories skipped when searching one level deep — avoids false positives in deps folders. */
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__']);

/**
 * Returns true when the path exists and is readable.
 */
async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await access(targetPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Checks the repo root and immediate child directories for a marker file.
 */
async function markerExists(repoPath: string, marker: string): Promise<boolean> {
  if (await pathExists(join(repoPath, marker))) {
    return true;
  }

  let entries;
  try {
    entries = await readdir(repoPath, { withFileTypes: true });
  } catch {
    return false;
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) {
      continue;
    }
    if (await pathExists(join(repoPath, entry.name, marker))) {
      return true;
    }
  }

  return false;
}

/**
 * Detects project types (Node.js, Python, etc.) from repo marker files.
 * Checks the repo root and one subdirectory level deep.
 */
export async function detectProjectType(repoPath: string): Promise<ProjectType[]> {
  const types: ProjectType[] = [];

  if (await markerExists(repoPath, 'package.json')) {
    types.push('nodejs');
  }

  for (const marker of PYTHON_MARKERS) {
    if (await markerExists(repoPath, marker)) {
      types.push('python');
      break;
    }
  }

  if (await markerExists(repoPath, 'Cargo.toml')) {
    types.push('rust');
  }

  if (await markerExists(repoPath, 'go.mod')) {
    types.push('go');
  }

  if (types.length === 0) {
    return ['unknown'];
  }

  return types;
}
