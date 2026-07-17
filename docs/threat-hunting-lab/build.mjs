import { build } from 'esbuild';
import { copyFile, mkdir, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
await mkdir(join(root, 'assets/vendor'), { recursive: true });
await build({ absWorkingDir: root, entryPoints: ['./src/app.js'], bundle: true, format: 'esm', minify: true, outfile: join(root, 'assets/app.js'), target: ['es2022'] });
for (const file of [
  'duckdb-mvp.wasm',
  'duckdb-eh.wasm',
  'duckdb-browser-mvp.worker.js',
  'duckdb-browser-eh.worker.js'
]) {
  const source = join(root, `node_modules/@duckdb/duckdb-wasm/dist/${file}`);
  const destination = join(root, `assets/vendor/${file}`);
  let unchanged = false;
  try { unchanged = (await stat(source)).size === (await stat(destination)).size; } catch {}
  if (!unchanged) await copyFile(source, destination);
}
console.log('Static DuckDB-Wasm lab built.');
