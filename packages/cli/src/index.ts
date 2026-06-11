import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { fixCommand } from './commands/fix.js';
import { initCommand } from './commands/init.js';

const program = new Command();

program
  .name('vibesafe')
  .description('Security co-pilot for vibe-coded and AI-generated apps')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a repository for security issues')
  .argument('[path]', 'Path to scan', '.')
  .option('--json', 'Output results as JSON')
  .action(async (path: string, opts: { json?: boolean }) => {
    try {
      await scanCommand(path, { json: opts.json });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${message}\n`);
      process.exit(2);
    }
  });

program
  .command('fix')
  .description('Generate and apply security fixes')
  .argument('[path]', 'Path to fix', '.')
  .action(async (path: string) => {
    try {
      await fixCommand(path);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${message}\n`);
      process.exit(2);
    }
  });

program
  .command('init')
  .description('Create a vibesafe.config.js file')
  .action(async () => {
    try {
      await initCommand();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${message}\n`);
      process.exit(2);
    }
  });

program.parse();
