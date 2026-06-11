import type { VibeSafeConfig } from '../types.js';

/**
 * Default configuration applied when no vibesafe.config.js exists.
 * All scanners enabled; LLM defaults to Groq's fast free-tier model.
 */
export const DEFAULT_CONFIG: VibeSafeConfig = {
  scanners: {
    sast: true,
    secrets: true,
    dependencies: true,
    config: true,
  },
  minSeverity: 'low',
  failOn: 'none',
  customRules: [],
  llm: {
    provider: 'groq',
    model: 'llama-3.3-70b-versatile',
  },
  exclude: [],
};
