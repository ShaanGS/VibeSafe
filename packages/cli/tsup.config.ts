import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs'],
  dts: true,
  clean: true,
  // figlet loads font files from disk at runtime — must not be bundled
  external: ['figlet'],
  banner: {
    js: '#!/usr/bin/env node',
  },
});
