import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

function fixImports(content) {
  return content
    // Replace ../core/, ../schema/, ../react/ with ./
    .replace(/from\s+['"]\.\.\/(core|schema|react)\/([^'"]+)['"]/g, "from './$2'")
    // Handle specific file imports that might not match the general regex due to extensions or specific paths
    .replace(/from\s+['"]\.\.\/core\/scanner\.js['"]/g, "from './scanner.js'")
    .replace(/from\s+['"]\.\.\/schema\/SchemaEngine\.js['"]/g, "from './SchemaEngine.js'")
    // Ensure we don't break relative imports that are already local (unlikely in this flat structure but good practice)
    ;
}

async function build() {
  console.log("⚡ Compiling Worker with esbuild...");
  if (!fs.existsSync('dist')) fs.mkdirSync('dist');

  // 1. Build Pure JS Worker (Default)
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

  // 5. Copy & Fix other source files
  copyAndFix('src/react/useStreamingJson.js', 'dist/useStreamingJson.js');
  copyAndFix('src/core/scanner.js', 'dist/scanner.js');
  copyAndFix('src/core/repair.js', 'dist/repair.js');
  copyAndFix('src/core/registry.js', 'dist/registry.js');

  // NEW: Feature files
  copyAndFix('src/react/useGuard.js', 'dist/useGuard.js');
  copyAndFix('src/schema/SchemaEngine.js', 'dist/SchemaEngine.js');

  // 6. Generate Entry Points
  const indexContent = `/**
 * react-ai-guard (Standard)
 * Pure JS Bundle (Default)
 */
export { useAIGuard } from './useAIGuard.js';
export { useStreamingJson, useTypedStream, useVercelStream } from './useStreamingJson.js';
export { scanText } from './scanner.js';
export { repairJSON, extractJSON } from './repair.js';
export { registerProfile, getProfile } from './registry.js';
// NEW EXPORTS
export { useGuard } from './useGuard.js';
export { SchemaEngine } from './SchemaEngine.js';
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
// NEW EXPORTS
export { useGuard } from './useGuard.js';
export { SchemaEngine } from './SchemaEngine.js';
`;

  fs.writeFileSync('dist/index.js', indexContent);
  fs.writeFileSync('dist/index-pro.js', indexProContent);

  if (fs.existsSync('src/index.d.ts')) copyAndFix('src/index.d.ts', 'dist/index.d.ts');

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

  let finalHook = hookTemplate.replace(
    /const INLINE_WORKER_CODE = `[\s\S]*?`;/,
    `const INLINE_WORKER_CODE = \`${escapedWorkerCode}\`;`
  );

  // Apply Import Flattening Fix to the Hook file as well
  finalHook = fixImports(finalHook);

  fs.writeFileSync(outputPath, finalHook);
}

function copyAndFix(src, dest) {
  if (fs.existsSync(src)) {
    const content = fs.readFileSync(src, 'utf8');
    const fixedContent = fixImports(content);
    fs.writeFileSync(dest, fixedContent);
  } else {
    console.warn(`Warning: Source file ${src} not found.`);
  }
}

build().catch((e) => {
  console.error(e);
  process.exit(1);
});
