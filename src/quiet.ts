/**
 * Suppresses Node's `ExperimentalWarning` for node:sqlite, and nothing else.
 *
 * The warning is accurate but unactionable — that module is a deliberate
 * dependency — and it prints on every start of every entry point. On the MCP
 * server it lands in the client's error log where it reads like a fault, and
 * an operator who learns to ignore warnings from this process is worse off
 * than one who never saw this one.
 *
 * Overriding `process.emitWarning` does not work here: warnings are delivered
 * asynchronously through the process `warning` event, and the built-in module
 * is instantiated before any of this code runs. Replacing the listener is the
 * approach that actually catches it.
 *
 * Every other warning is re-emitted, so this cannot quietly hide a real one.
 */

process.removeAllListeners('warning');

process.on('warning', (warning: Error) => {
  if (warning.name === 'ExperimentalWarning' && warning.message.includes('SQLite')) return;

  console.error(`${warning.name}: ${warning.message}`);
  if (warning.stack !== undefined) {
    console.error(warning.stack.split('\n').slice(1).join('\n'));
  }
});
