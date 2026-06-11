import type { VibeSafeConfig } from '../types.js';
import { DEFAULT_CONFIG } from './defaults.js';

/**
 * Loads vibesafe.config.js from the repo root, merging with defaults.
 * Stub — returns defaults until config loader is built.
 */
export async function loadConfig(_repoPath: string): Promise<VibeSafeConfig> {
  return DEFAULT_CONFIG;
}
