import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

async function build() {
  console.log("⚡ Compiling Worker with esbuild...");
  if (!fs.existsSync('dist')) fs.mkdirSync('dist');

  // 1. Build Pure JS Worker (Default)
  // We mark the Wasm module as 'external' to prevent bundling it.
  // Since the code path is guarded by WASM_ENABLED=false, the import will never execute.
  console.log("   - Building Pure JS Worker (Default)...");
  await esbuild.build({
    entryPoints: ['src/worker/index.js'],
    bundle: true,
    outfile: 'dist/worker.pure.bundle.js',
    format: 'esm',
    minify: true,
    target: 'es2020',
    define: { 'process.env.WASM_ENABLED': '"false"' },
    external: ['../core/repair_wasm.js']
  });

  // 2. Build Wasm/Pro Worker (Opt-in)
  console.log("   - Building Pro (Wasm) Worker...");
  await esbuild.build({
    entryPoints: ['src/worker/index.js'],
    bundle: true,
    outfile: 'dist/worker.pro.bundle.js',
    format: 'esm',
    minify: true,
    target: 'es2020',
    define: { 'process.env.WASM_ENABLED': '"true"' }
  });

  // 3. Inject Pure JS Worker into useAIGuard.js (Default)
  injectWorker('dist/worker.pure.bundle.js', 'src/react/useAIGuard.js', 'dist/useAIGuard.js');

  // 4. Inject Pro Worker into useAIGuardPro.js (Opt-in)
  injectWorker('dist/worker.pro.bundle.js', 'src/react/useAIGuard.js', 'dist/useAIGuardPro.js');

  // Copy other files
  copyFile('src/react/useStreamingJson.js', 'dist/useStreamingJson.js');
  copyFile('src/core/scanner.js', 'dist/scanner.js');
  copyFile('src/core/repair.js', 'dist/repair.js');
  copyFile('src/core/registry.js', 'dist/registry.js');

  // Generate Entry Points
  const indexContent = `/**
 * react-ai-guard (Standard)
 * Pure JS Bundle (Default)
 */
export { useAIGuard } from './useAIGuard.js';
export { useStreamingJson, useTypedStream, useVercelStream } from './useStreamingJson.js';
export { scanText } from './scanner.js';
export { repairJSON, extractJSON } from './repair.js';
export { registerProfile, getProfile } from './registry.js';
`;

  const indexProContent = `/**
 * react-ai-guard (Pro)
 * C/Wasm Bundle
 */
export { useAIGuard } from './useAIGuardPro.js';
export { useStreamingJson, useTypedStream, useVercelStream } from './useStreamingJson.js';
export { scanText } from './scanner.js';
export { repairJSON, extractJSON } from './repair.js';
export { registerProfile, getProfile } from './registry.js';
`;

  fs.writeFileSync('dist/index.js', indexContent);
  fs.writeFileSync('dist/index-pro.js', indexProContent);

  if (fs.existsSync('src/index.d.ts')) copyFile('src/index.d.ts', 'dist/index.d.ts');

  console.log("✅ Build Complete.");
  console.log("   - Default: dist/index.js -> dist/useAIGuard.js (Pure JS)");
  console.log("   - Pro:     dist/index-pro.js -> dist/useAIGuardPro.js (Wasm Enabled)");
}

function injectWorker(workerPath, templatePath, outputPath) {
  const workerCode = fs.readFileSync(workerPath, 'utf8');
  const hookTemplate = fs.readFileSync(templatePath, 'utf8');

  // Robust injection that handles backticks/dollars in the minified code
  const escapedWorkerCode = workerCode
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$/g, '\\$');

  const finalHook = hookTemplate.replace(
    /const INLINE_WORKER_CODE = `[\s\S]*?`;/,
    `const INLINE_WORKER_CODE = \`${escapedWorkerCode}\`;`
  );

  fs.writeFileSync(outputPath, finalHook);
}

function copyFile(src, dest) {
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
  }
}

build().catch((e) => {
  console.error(e);
  process.exit(1);
});
