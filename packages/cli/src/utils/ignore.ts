import { readFile } from 'fs/promises';
import { join } from 'path';

/** Always excluded — merged with .vibesafeignore entries from the repo root. */
const BUILTIN_IGNORE_PATTERNS: readonly string[] = [
  'node_modules/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '__pycache__/',
  '.env',
  '*.lock',
  'pnpm-lock.yaml',
  'package-lock.json',
];

/**
 * Parses .vibesafeignore content (gitignore-style: one pattern per line, # comments).
 */
function parseIgnoreFile(content: string): string[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

/**
 * Returns built-in ignore patterns plus any entries from .vibesafeignore at the repo root.
 */
export async function getIgnorePatterns(repoPath: string): Promise<string[]> {
  const patterns: string[] = [...BUILTIN_IGNORE_PATTERNS];

  try {
    const content = await readFile(join(repoPath, '.vibesafeignore'), 'utf-8');
    patterns.push(...parseIgnoreFile(content));
  } catch {
    // .vibesafeignore is optional — built-in patterns still apply
  }

  return patterns;
}
