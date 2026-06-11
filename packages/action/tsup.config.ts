import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/main.ts' },
  format: ['cjs'],
  dts: true,
  clean: true,
});
