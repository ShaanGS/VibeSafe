import { mkdtemp, mkdir, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { detectProjectType } from '../src/utils/detect.js';

describe('detectProjectType', () => {
  const tempDirs: string[] = [];

  /**
   * Creates an isolated temp directory cleaned up after each test.
   */
  async function createTempDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'vibesafe-detect-'));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(async () => {
    await Promise.all(
      tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
    );
  });

  it('returns nodejs when only package.json exists', async () => {
    const dir = await createTempDir();
    await writeFile(join(dir, 'package.json'), '{}');

    await expect(detectProjectType(dir)).resolves.toEqual(['nodejs']);
  });

  it('returns python when only requirements.txt exists', async () => {
    const dir = await createTempDir();
    await writeFile(join(dir, 'requirements.txt'), 'requests\n');

    await expect(detectProjectType(dir)).resolves.toEqual(['python']);
  });

  it('returns both nodejs and python when both markers exist', async () => {
    const dir = await createTempDir();
    await writeFile(join(dir, 'package.json'), '{}');
    await writeFile(join(dir, 'requirements.txt'), 'requests\n');

    await expect(detectProjectType(dir)).resolves.toEqual(['nodejs', 'python']);
  });

  it('returns unknown for an empty directory', async () => {
    const dir = await createTempDir();

    await expect(detectProjectType(dir)).resolves.toEqual(['unknown']);
  });

  it('detects nodejs one level deep in a subdirectory', async () => {
    const dir = await createTempDir();
    await mkdir(join(dir, 'frontend'));
    await writeFile(join(dir, 'frontend', 'package.json'), '{}');

    await expect(detectProjectType(dir)).resolves.toEqual(['nodejs']);
  });
});
