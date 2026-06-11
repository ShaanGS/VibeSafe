import * as core from '@actions/core';

/**
 * GitHub Action entrypoint for VibeSafe security scans.
 * Stub — will invoke the CLI scan pipeline in a later sprint.
 */
async function run(): Promise<void> {
  try {
    const failOn = core.getInput('fail-on');
    const postComment = core.getInput('post-comment');
    const path = core.getInput('path');

    core.info(`VibeSafe action — not yet implemented (fail-on=${failOn}, post-comment=${postComment}, path=${path})`);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    core.setFailed(message);
  }
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  core.setFailed(message);
});
